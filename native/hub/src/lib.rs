//! FlatDrop Core Hub
//!
//! This is the core Rust library that powers all FlatDrop platforms.
//! It uses Protobuf for message passing and UniFFi for bindings.

use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use std::{
    future::Future,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    runtime::Runtime,
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};

mod discovery;
mod iroh_engine;
mod portal;
mod database;
mod crypto;

mod types;
mod hub;
mod handoff;
pub mod ffi;

pub use types::*;

const MAX_CONFIG_SIZE: usize = 1024 * 1024;
const MAX_COMMAND_SIZE: usize = 16 * 1024 * 1024;
const MAX_WORKER_THREADS: usize = 8;
const CONTROLLER_CHANNEL_CAPACITY: usize = 256;
const DEFAULT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_POLL_TIMEOUT: Duration = Duration::from_secs(5);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

static RUNTIME: OnceCell<Runtime> = OnceCell::new();
static HUB_CONTROLLER: Mutex<Option<ControllerHandle>> = Mutex::new(None);

struct ControllerHandle {
    cmd_tx: mpsc::Sender<ControllerCmd>,
    event_tx: mpsc::Sender<EventReq>,
    _cmd_task: JoinHandle<()>,
    _event_task: JoinHandle<()>,
}

enum ControllerCmd {
    Start {
        config_bytes: Vec<u8>,
        allowed_paths: Vec<PathBuf>,
        resp: oneshot::Sender<Result<String, String>>,
    },
    Stop {
        resp: oneshot::Sender<Result<(), String>>,
    },
    IsInitialized {
        resp: oneshot::Sender<bool>,
    },
    SendCommand {
        command_bytes: Vec<u8>,
        resp: oneshot::Sender<Result<Vec<u8>, String>>,
    },
}

struct EventReq {
    timeout_duration: Duration,
    resp: oneshot::Sender<Vec<u8>>,
}

fn init_runtime() -> Result<(), String> {
    RUNTIME.get_or_try_init(|| {
        let cpus = std::cmp::min(std::cmp::max(2, num_cpus::get()), MAX_WORKER_THREADS);
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(cpus)
            .max_blocking_threads(16)
            .thread_name("flatdrop-worker")
            .build()
            .map_err(|e| format!("Failed to create runtime: {e}"))
    })?;
    Ok(())
}

fn block_on<T>(fut: impl Future<Output = T>) -> Result<T, String> {
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err(
            "hub API called from within a Tokio runtime thread; call from a non-async/FFI thread"
                .to_string(),
        );
    }
    let rt = RUNTIME
        .get()
        .ok_or_else(|| "Runtime not initialized".to_string())?;
    Ok(rt.block_on(fut))
}

fn ensure_controller() -> Result<(mpsc::Sender<ControllerCmd>, mpsc::Sender<EventReq>), String> {
    let mut guard = HUB_CONTROLLER.lock();

    if let Some(handle) = guard.as_ref() {
        if !handle.cmd_tx.is_closed() && !handle.event_tx.is_closed() {
            return Ok((handle.cmd_tx.clone(), handle.event_tx.clone()));
        }
        tracing::warn!("controller detected dead, respawning");
        *guard = None;
    }

    let rt = RUNTIME
        .get()
        .ok_or_else(|| "Runtime not initialized".to_string())?;

    let (cmd_tx, cmd_rx) = mpsc::channel::<ControllerCmd>(CONTROLLER_CHANNEL_CAPACITY);
    let (event_tx, event_rx) = mpsc::channel::<EventReq>(CONTROLLER_CHANNEL_CAPACITY);

    let hub_state: Arc<tokio::sync::Mutex<Option<Arc<hub::FlatDropHub>>>> =
        Arc::new(tokio::sync::Mutex::new(None));

    let cmd_hub = hub_state.clone();
    let cmd_task = rt.handle().spawn(cmd_controller(cmd_rx, cmd_hub));

    let event_hub = hub_state.clone();
    let event_task = rt.handle().spawn(event_controller(event_rx, event_hub));

    *guard = Some(ControllerHandle {
        cmd_tx: cmd_tx.clone(),
        event_tx: event_tx.clone(),
        _cmd_task: cmd_task,
        _event_task: event_task,
    });

    Ok((cmd_tx, event_tx))
}

async fn cmd_controller(
    mut rx: mpsc::Receiver<ControllerCmd>,
    hub_state: Arc<tokio::sync::Mutex<Option<Arc<hub::FlatDropHub>>>>,
) {
    while let Some(cmd) = rx.recv().await {
        match cmd {
            ControllerCmd::Start {
                config_bytes,
                allowed_paths,
                resp,
            } => {
                let result = handle_start(&hub_state, config_bytes, allowed_paths).await;
                let _ = resp.send(result);
            }

            ControllerCmd::Stop { resp } => {
                let result = handle_stop(&hub_state).await;
                let _ = resp.send(result);
            }

            ControllerCmd::IsInitialized { resp } => {
                let guard = hub_state.lock().await;
                let _ = resp.send(guard.is_some());
            }

            ControllerCmd::SendCommand {
                command_bytes,
                resp,
            } => {
                let result = {
                    let guard = hub_state.lock().await;
                    match guard.as_ref() {
                        Some(h) => h.handle_command(command_bytes).await.map_err(|e| e.to_string()),
                        None => Err("Hub not initialized".to_string()),
                    }
                };
                let _ = resp.send(result);
            }
        }
    }

    handle_stop(&hub_state).await.ok();
    tracing::info!("command controller exited");
}

async fn handle_start(
    hub_state: &Arc<tokio::sync::Mutex<Option<Arc<hub::FlatDropHub>>>>,
    config_bytes: Vec<u8>,
    allowed_paths: Vec<PathBuf>,
) -> Result<String, String> {
    let mut guard = hub_state.lock().await;

    if let Some(existing) = guard.take() {
        let _ = timeout(SHUTDOWN_TIMEOUT, existing.shutdown()).await;
    }

    let hub = hub::FlatDropHub::new(config_bytes, allowed_paths)
        .await
        .map_err(|e| format!("Hub creation failed: {e}"))?;

    let node_id = hub
        .engine
        .endpoint
        .node_addr()
        .await
        .map(|addr| addr.node_id.to_string())
        .map_err(|e| format!("Failed to get node address: {e}"))?;

    if node_id.is_empty() {
        return Err("Node ID resolved to empty string".to_string());
    }

    *guard = Some(hub);
    Ok(node_id)
}

async fn handle_stop(
    hub_state: &Arc<tokio::sync::Mutex<Option<Arc<hub::FlatDropHub>>>>,
) -> Result<(), String> {
    let mut guard = hub_state.lock().await;
    if let Some(h) = guard.take() {
        match timeout(SHUTDOWN_TIMEOUT, h.shutdown()).await {
            Ok(Ok(())) => {
                tracing::info!("hub shut down cleanly");
                Ok(())
            }
            Ok(Err(e)) => {
                tracing::error!("hub shutdown error: {e}");
                Err(format!("Shutdown error: {e}"))
            }
            Err(_) => {
                tracing::error!("hub shutdown timed out");
                Err("Shutdown timed out".to_string())
            }
        }
    } else {
        Ok(())
    }
}

async fn event_controller(
    mut rx: mpsc::Receiver<EventReq>,
    hub_state: Arc<tokio::sync::Mutex<Option<Arc<hub::FlatDropHub>>>>,
) {
    while let Some(req) = rx.recv().await {
        let out = {
            let guard = hub_state.lock().await;
            match guard.as_ref() {
                Some(h) => timeout(req.timeout_duration, h.poll_event_blocking(req.timeout_duration))
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or_default(),
                None => Vec::new(),
            }
        };
        let _ = req.resp.send(out);
    }

    tracing::info!("event controller exited");
}

fn default_allowed_paths() -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    if let Some(d) = dirs::download_dir() {
        if d.exists() {
            out.push(d);
        }
    }
    if out.is_empty() {
        return Err("No valid allowed paths found; refusing to start".to_string());
    }
    Ok(out)
}

pub fn hub_start(config_bytes: Vec<u8>) -> Vec<u8> {
    if config_bytes.len() > MAX_CONFIG_SIZE {
        return create_error_response("validation", "Config exceeds maximum allowed size");
    }

    if let Err(e) = init_runtime() {
        return create_error_response("init_runtime", &e);
    }

    let result = block_on(async {
        let (cmd_tx, _) = ensure_controller().map_err(|e| e.to_string())?;

        let allowed_paths = default_allowed_paths()?;

        let (resp_tx, resp_rx) = oneshot::channel();
        cmd_tx
            .send(ControllerCmd::Start {
                config_bytes,
                allowed_paths,
                resp: resp_tx,
            })
            .await
            .map_err(|_| "Controller unavailable".to_string())?;

        timeout(DEFAULT_RESPONSE_TIMEOUT, resp_rx)
            .await
            .map_err(|_| "Start request timed out".to_string())?
            .map_err(|_| "Controller dropped response".to_string())?
    });

    match result {
        Ok(Ok(node_id)) => create_success_response(&node_id),
        Ok(Err(e)) => create_error_response("hub_start", &e),
        Err(e) => create_error_response("hub_start", &e),
    }
}

pub fn hub_stop() -> Vec<u8> {
    if RUNTIME.get().is_none() {
        return create_error_response("hub_stop", "Runtime not initialized");
    }

    let result = block_on(async {
        let (cmd_tx, _) = ensure_controller().map_err(|e| e.to_string())?;

        let (resp_tx, resp_rx) = oneshot::channel();
        cmd_tx
            .send(ControllerCmd::Stop { resp: resp_tx })
            .await
            .map_err(|_| "Controller unavailable".to_string())?;

        timeout(DEFAULT_RESPONSE_TIMEOUT + SHUTDOWN_TIMEOUT, resp_rx)
            .await
            .map_err(|_| "Stop request timed out".to_string())?
            .map_err(|_| "Controller dropped response".to_string())?
    });

    match result {
        Ok(Ok(())) => {
            use prost::Message;
            let resp = types::InitializeResponse {
                success: true,
                error_message: String::new(),
                node_id: String::new(),
            };
            let mut buf = Vec::with_capacity(resp.encoded_len());
            resp.encode(&mut buf).expect("encoding InitializeResponse cannot fail");
            buf
        }
        Ok(Err(e)) => create_error_response("hub_stop", &e),
        Err(e) => create_error_response("hub_stop", &e),
    }
}

pub fn hub_is_initialized() -> bool {
    if RUNTIME.get().is_none() {
        return false;
    }

    block_on(async {
        let (cmd_tx, _) = match ensure_controller() {
            Ok(t) => t,
            Err(_) => return false,
        };

        let (resp_tx, resp_rx) = oneshot::channel();
        if cmd_tx
            .send(ControllerCmd::IsInitialized { resp: resp_tx })
            .await
            .is_err()
        {
            return false;
        }

        timeout(DEFAULT_RESPONSE_TIMEOUT, resp_rx)
            .await
            .ok()
            .and_then(|r| r.ok())
            .unwrap_or(false)
    })
    .unwrap_or(false)
}

pub fn hub_send_command(command_bytes: Vec<u8>) -> Vec<u8> {
    if command_bytes.len() > MAX_COMMAND_SIZE {
        return encode_command_response(types::CommandResponse {
            success: false,
            error_message: "Command exceeds maximum allowed size".to_string(),
            data: Vec::new(),
        });
    }

    if RUNTIME.get().is_none() {
        return encode_command_response(types::CommandResponse {
            success: false,
            error_message: "Runtime not initialized".to_string(),
            data: Vec::new(),
        });
    }

    let result = block_on(async {
        let (cmd_tx, _) = ensure_controller().map_err(|e| e.to_string())?;

        let (resp_tx, resp_rx) = oneshot::channel();
        cmd_tx
            .send(ControllerCmd::SendCommand {
                command_bytes,
                resp: resp_tx,
            })
            .await
            .map_err(|_| "Controller unavailable".to_string())?;

        timeout(DEFAULT_RESPONSE_TIMEOUT, resp_rx)
            .await
            .map_err(|_| "Command timed out".to_string())?
            .map_err(|_| "Controller dropped response".to_string())?
    });

    let response = match result {
        Ok(Ok(data)) => types::CommandResponse {
            success: true,
            error_message: String::new(),
            data,
        },
        Ok(Err(e)) => types::CommandResponse {
            success: false,
            error_message: e,
            data: Vec::new(),
        },
        Err(e) => types::CommandResponse {
            success: false,
            error_message: e,
            data: Vec::new(),
        },
    };

    encode_command_response(response)
}

pub fn hub_poll_event(timeout_ms: u64) -> Vec<u8> {
    if RUNTIME.get().is_none() {
        return encode_event_response(false, "Runtime not initialized", Vec::new());
    }

    let poll_timeout = Duration::from_millis(timeout_ms.min(30_000));

    let result = block_on(async {
        let (_, event_tx) = ensure_controller().map_err(|e| e.to_string())?;

        let (resp_tx, resp_rx) = oneshot::channel();
        event_tx
            .send(EventReq {
                timeout_duration: poll_timeout,
                resp: resp_tx,
            })
            .await
            .map_err(|_| "Event controller unavailable".to_string())?;

        let total_timeout = poll_timeout + Duration::from_secs(5);
        timeout(total_timeout, resp_rx)
            .await
            .map_err(|_| "Poll timed out".to_string())?
            .map_err(|_| "Event controller dropped response".to_string())
    });

    match result {
        Ok(Ok(data)) => encode_event_response(true, "", data),
        Ok(Err(e)) => encode_event_response(false, &e, Vec::new()),
        Err(e) => encode_event_response(false, &e, Vec::new()),
    }
}

pub fn hub_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn hub_destroy() -> Vec<u8> {
    {
        let mut guard = HUB_CONTROLLER.lock();
        if let Some(handle) = guard.take() {
            drop(handle.cmd_tx);
            drop(handle.event_tx);
        }
    }

    use prost::Message;
    let resp = types::InitializeResponse {
        success: true,
        error_message: String::new(),
        node_id: String::new(),
    };
    let mut buf = Vec::with_capacity(resp.encoded_len());
    resp.encode(&mut buf).expect("encoding InitializeResponse cannot fail");
    buf
}

fn encode_command_response(resp: types::CommandResponse) -> Vec<u8> {
    use prost::Message;
    let mut buf = Vec::with_capacity(resp.encoded_len());
    resp.encode(&mut buf).expect("encoding CommandResponse cannot fail");
    buf
}

fn encode_event_response(has_data: bool, error: &str, data: Vec<u8>) -> Vec<u8> {
    use prost::Message;
    let resp = types::EventResponse {
        has_data,
        error_message: error.to_string(),
        data,
    };
    let mut buf = Vec::with_capacity(resp.encoded_len());
    resp.encode(&mut buf).expect("encoding EventResponse cannot fail");
    buf
}

fn create_success_response(node_id: &str) -> Vec<u8> {
    use prost::Message;
    let response = types::InitializeResponse {
        success: true,
        error_message: String::new(),
        node_id: node_id.to_string(),
    };
    let mut buf = Vec::with_capacity(response.encoded_len());
    response.encode(&mut buf).expect("encoding InitializeResponse cannot fail");
    buf
}

fn create_error_response(code: &str, message: &str) -> Vec<u8> {
    use prost::Message;
    let response = types::InitializeResponse {
        success: false,
        error_message: format!("[{code}] {message}"),
        node_id: String::new(),
    };
    let mut buf = Vec::with_capacity(response.encoded_len());
    response.encode(&mut buf).expect("encoding InitializeResponse cannot fail");
    buf
}