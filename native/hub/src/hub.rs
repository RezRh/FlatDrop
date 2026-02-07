//! FlatDrop Hub - Core Logic
//! Coordinates all components: discovery, transfers, database, portal
//! AirDrop-Class Background Transfer Architecture:
//! - Rust emits TransferStateChanged signals
//! - Native shells handle OS background policies (ForegroundService, URLSession, etc.)

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use parking_lot::RwLock;
use prost::Message;
use tokio::sync::{mpsc, oneshot, watch, Semaphore};
use tokio::task::JoinHandle;

use crate::database::{CheckpointStatus, HistoryDB, TransferCheckpoint};
use crate::discovery::DiscoveryManager;
use crate::handoff::{self, HandoffServer};
use crate::iroh_engine::IrohEngine;
use crate::types::*;

const MAX_EVENT_QUEUE_SIZE: usize = 10_000;
const MAX_CONCURRENT_TRANSFERS: usize = 50;
const MAX_FILE_SIZE_BYTES: u64 = 100 * 1024 * 1024 * 1024;
const MIN_FILE_SIZE_BYTES: u64 = 1;
const CHECKPOINT_INTERVAL_BYTES: u64 = 10 * 1024 * 1024;
const EVENT_CHANNEL_CAPACITY: usize = 256;
const PROGRESS_CHANNEL_CAPACITY: usize = 512;
const SHUTDOWN_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransferPhase {
    Preparing,
    InProgress,
    Paused,
    Finished,
    Failed,
    Cancelled,
}

impl TransferPhase {
    fn to_proto(self) -> i32 {
        match self {
            Self::Preparing => transfer_state_changed::State::Preparing as i32,
            Self::InProgress => transfer_state_changed::State::InProgress as i32,
            Self::Paused => transfer_state_changed::State::Paused as i32,
            Self::Finished => transfer_state_changed::State::Finished as i32,
            Self::Failed => transfer_state_changed::State::Failed as i32,
            Self::Cancelled => transfer_state_changed::State::Cancelled as i32,
        }
    }

    fn is_terminal(self) -> bool {
        matches!(self, Self::Finished | Self::Failed | Self::Cancelled)
    }
}

struct ActiveTransfer {
    id: String,
    file_name: String,
    file_path: PathBuf,
    total_bytes: u64,
    bytes_transferred: AtomicU64,
    direction: TransferDirection,
    phase: RwLock<TransferPhase>,
    target_device_id: String,
    handoff_file_id: Option<String>,
    ticket: Option<String>,
    peer_name: Option<String>,
    cancel_tx: watch::Sender<bool>,
    started_at: Instant,
}

impl ActiveTransfer {
    fn is_cancelled(&self) -> bool {
        *self.cancel_tx.borrow()
    }

    fn current_bytes(&self) -> u64 {
        self.bytes_transferred.load(Ordering::Relaxed)
    }

    fn progress(&self) -> f64 {
        let total = self.total_bytes;
        if total == 0 {
            return 0.0;
        }
        let transferred = self.current_bytes();
        (transferred as f64 / total as f64).clamp(0.0, 1.0)
    }
}

struct IncomingOffer {
    sender_name: String,
    sender_id: String,
    file_name: String,
    file_size: u64,
    ticket: String,
    mime_type: String,
}

struct BackgroundTasks {
    progress_handler: JoinHandle<()>,
    discovery_handler: Option<JoinHandle<()>>,
    cleanup_task: JoinHandle<()>,
}

pub struct FlatDropHub {
    event_tx: mpsc::Sender<RustEvent>,
    event_rx: tokio::sync::Mutex<mpsc::Receiver<RustEvent>>,

    discovery: RwLock<Option<DiscoveryManager>>,
    discovery_event_tx: mpsc::Sender<crate::discovery::DiscoveryEvent>,

    pub(crate) engine: Arc<IrohEngine>,
    db: Arc<HistoryDB>,
    config: HubConfig,

    active_transfers: RwLock<HashMap<String, Arc<ActiveTransfer>>>,
    incoming_offers: RwLock<HashMap<String, IncomingOffer>>,
    transfer_semaphore: Arc<Semaphore>,

    handoff_registry: handoff::SharedRegistry,
    handoff_server: RwLock<Option<HandoffServer>>,

    allowed_paths: Vec<PathBuf>,
    shutdown: AtomicBool,
    background_tasks: RwLock<Option<BackgroundTasks>>,

    portal_shutdown: RwLock<Option<oneshot::Sender<()>>>,
}

impl FlatDropHub {
    pub async fn new(config_bytes: Vec<u8>, allowed_paths: Vec<PathBuf>) -> Result<Arc<Self>> {
        let request = InitializeRequest::decode(&*config_bytes)
            .context("failed to parse config")?;

        let config = request.config.context("config is required")?;

        if allowed_paths.is_empty() {
            bail!("at least one allowed path required");
        }

        let canonical_paths: Vec<PathBuf> = allowed_paths
            .into_iter()
            .filter_map(|p| p.canonicalize().ok())
            .collect();

        if canonical_paths.is_empty() {
            bail!("no valid allowed paths");
        }

        let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (progress_tx, progress_rx) =
            mpsc::channel::<crate::iroh_engine::TransferProgress>(PROGRESS_CHANNEL_CAPACITY);
        let (discovery_event_tx, discovery_event_rx) =
            mpsc::channel::<crate::discovery::DiscoveryEvent>(EVENT_CHANNEL_CAPACITY);

        // Usage: Use the first allowed path to store blobs, or a "blobs" subdir in it.
        // In production, we might want a dedicated cache dir.
        let blob_dir = canonical_paths[0].join(".flatdrop_blobs");
        let engine = Arc::new(IrohEngine::new(progress_tx, blob_dir).await?);

        let db_path = if config.database_url.is_empty() {
            PathBuf::from("flatdrop_history.db")
        } else {
            PathBuf::from(&config.database_url)
        };

        let db = Arc::new(HistoryDB::new(db_path, None).await?);

        let handoff_registry = Arc::new(handoff::HandoffRegistry::new(canonical_paths.clone())?);

        // Auto-start handoff server on ephemeral port
        let handoff_server = match HandoffServer::start(0, handoff_registry.clone()).await {
            Ok(server) => {
                tracing::info!(port = server.port(), "Handoff server started");
                Some(server)
            },
            Err(e) => {
                tracing::warn!(error = %e, "Failed to start handoff server");
                None
            }
        };

        let hub = Arc::new(Self {
            event_tx,
            event_rx: tokio::sync::Mutex::new(event_rx),
            discovery: RwLock::new(None),
            discovery_event_tx,
            engine,
            db,
            config,
            active_transfers: RwLock::new(HashMap::with_capacity(32)),
            incoming_offers: RwLock::new(HashMap::new()),
            transfer_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_TRANSFERS)),
            handoff_registry,
            handoff_server: RwLock::new(handoff_server),
            allowed_paths: canonical_paths,
            shutdown: AtomicBool::new(false),
            background_tasks: RwLock::new(None),
            portal_shutdown: RwLock::new(None),
        });

        let tasks = hub.spawn_background_tasks(progress_rx, discovery_event_rx);
        *hub.background_tasks.write() = Some(tasks);

        Ok(hub)
    }

    pub async fn register_incoming_offer(
        &self,
        transfer_id: String,
        sender_name: String,
        sender_id: String,
        file_name: String,
        file_size: u64,
        ticket: String,
        mime_type: String,
    ) -> Result<()> {
        {
            let mut offers = self.incoming_offers.write();
            offers.insert(
                transfer_id.clone(),
                IncomingOffer {
                    sender_name: sender_name.clone(),
                    sender_id: sender_id.clone(),
                    file_name: file_name.clone(),
                    file_size,
                    ticket: ticket.clone(),
                    mime_type: mime_type.clone(),
                },
            );
        }

        let event = RustEvent {
            event: Some(rust_event::Event::IncomingRequest(IncomingFileRequest {
                transfer_id,
                sender_name,
                sender_id,
                file_name,
                file_size,
                ticket,
                mime_type,
            })),
        };

        self.emit_event(event).await;
        Ok(())
    }

    fn spawn_background_tasks(
        self: &Arc<Self>,
        mut progress_rx: mpsc::Receiver<crate::iroh_engine::TransferProgress>,
        mut discovery_rx: mpsc::Receiver<crate::discovery::DiscoveryEvent>,
    ) -> BackgroundTasks {
        let hub = Arc::clone(self);
        let progress_handler = tokio::spawn(async move {
            while let Some(progress) = progress_rx.recv().await {
                if hub.shutdown.load(Ordering::Acquire) {
                    break;
                }
                hub.handle_progress_update(progress).await;
            }
        });

        let hub = Arc::clone(self);
        let discovery_handler = tokio::spawn(async move {
            while let Some(event) = discovery_rx.recv().await {
                if hub.shutdown.load(Ordering::Acquire) {
                    break;
                }
                hub.handle_discovery_event(event).await;
            }
        });

        let hub = Arc::clone(self);
        let cleanup_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;
                if hub.shutdown.load(Ordering::Acquire) {
                    break;
                }
                hub.cleanup_stale_transfers().await;
            }
        });

        BackgroundTasks {
            progress_handler,
            discovery_handler: Some(discovery_handler),
            cleanup_task,
        }
    }

    async fn handle_progress_update(&self, progress: crate::iroh_engine::TransferProgress) {
        let event = {
            let transfers = self.active_transfers.read();
            if let Some(transfer) = transfers.get(&progress.transfer_id) {
                transfer
                    .bytes_transferred
                    .store(progress.bytes_transferred, Ordering::Relaxed);

                let phase = match progress.status {
                    s if s == TransferStatus::InProgress as i32 => TransferPhase::InProgress,
                    s if s == TransferStatus::Completed as i32 => TransferPhase::Finished,
                    s if s == TransferStatus::Failed as i32 => TransferPhase::Failed,
                    s if s == TransferStatus::Cancelled as i32 => TransferPhase::Cancelled,
                    _ => TransferPhase::InProgress,
                };

                *transfer.phase.write() = phase;

                Some(self.build_transfer_event(transfer, None))
            } else {
                None
            }
        };

        if let Some(event) = event {
            self.emit_event(event).await;
        }
    }

    async fn handle_discovery_event(&self, event: crate::discovery::DiscoveryEvent) {
        let rust_event = match event {
            crate::discovery::DiscoveryEvent::DeviceFound(device) => RustEvent {
                event: Some(rust_event::Event::Discovery(DiscoveryEvent {
                    event_type: DiscoveryEventType::DeviceFound as i32,
                    device: Some(DeviceInfo {
                        name: device.name,
                        id: device.id.clone(),
                        ip: device
                            .addresses
                            .first()
                            .map(|a| a.to_string())
                            .unwrap_or_default(),
                        port: device.port as u32,
                        properties: device.properties,
                    }),
                    device_id: device.id,
                    error_message: String::new(),
                })),
            },
            crate::discovery::DiscoveryEvent::DeviceLost(id) => RustEvent {
                event: Some(rust_event::Event::Discovery(DiscoveryEvent {
                    event_type: DiscoveryEventType::DeviceLost as i32,
                    device: None,
                    device_id: id,
                    error_message: String::new(),
                })),
            },
            crate::discovery::DiscoveryEvent::Error(err) => RustEvent {
                event: Some(rust_event::Event::Discovery(DiscoveryEvent {
                    event_type: DiscoveryEventType::Error as i32,
                    device: None,
                    device_id: String::new(),
                    error_message: err.to_string(),
                })),
            },
            _ => return,
        };

        self.emit_event(rust_event).await;
    }

    async fn cleanup_stale_transfers(&self) {
        let stale_threshold = Duration::from_secs(3600);
        let now = Instant::now();

        let mut transfers = self.active_transfers.write();
        let stale: Vec<String> = transfers
            .iter()
            .filter(|(_, t)| {
                t.phase.read().is_terminal() && now.duration_since(t.started_at) > stale_threshold
            })
            .map(|(k, _)| k.clone())
            .collect();

        for id in stale {
            transfers.remove(&id);
        }
    }

    fn build_transfer_event(
        &self,
        transfer: &ActiveTransfer,
        error: Option<String>,
    ) -> RustEvent {
        let phase = *transfer.phase.read();
        RustEvent {
            event: Some(rust_event::Event::TransferStateChanged(
                TransferStateChanged {
                    state: phase.to_proto(),
                    transfer_id: transfer.id.clone(),
                    description: match phase {
                        TransferPhase::Preparing => format!("Preparing {}", transfer.file_name),
                        TransferPhase::InProgress => format!("Transferring {}", transfer.file_name),
                        TransferPhase::Paused => format!("Paused {}", transfer.file_name),
                        TransferPhase::Finished => format!("Completed {}", transfer.file_name),
                        TransferPhase::Failed => format!("Failed {}", transfer.file_name),
                        TransferPhase::Cancelled => format!("Cancelled {}", transfer.file_name),
                    },
                    file_name: transfer.file_name.clone(),
                    total_bytes: transfer.total_bytes,
                    bytes_transferred: transfer.current_bytes(),
                    progress: transfer.progress(),
                    error_message: error.unwrap_or_default(),
                    direction: transfer.direction as i32,
                    platform_handle: String::new(),
                },
            )),
        }
    }

    async fn emit_event(&self, event: RustEvent) {
        // Determine if event is critical and MUST be delivered
        let is_critical = match &event.event {
            Some(rust_event::Event::TransferStateChanged(change)) => {
                match transfer_state_changed::State::from_i32(change.state) {
                    Some(transfer_state_changed::State::Finished) | 
                    Some(transfer_state_changed::State::Failed) | 
                    Some(transfer_state_changed::State::Cancelled) => true,
                    _ => false,
                }
            },
            Some(rust_event::Event::IncomingRequest(_)) => true,
            _ => false,
        };

        // If not critical and channel is full, drop it to avoid backpressure
        if !is_critical && self.event_tx.capacity() == 0 {
            tracing::warn!("event channel full, dropping non-critical event");
            return;
        }

        // Send event (blocking wait if channel full, ensuring delivery for critical events)
        if let Err(e) = self.event_tx.send(event).await {
            tracing::warn!("failed to send event: {}", e);
        }
    }

    fn is_path_allowed(&self, path: &PathBuf) -> Result<PathBuf> {
        let canonical = path.canonicalize().context("path does not exist")?;

        let allowed = self
            .allowed_paths
            .iter()
            .any(|base| canonical.starts_with(base));

        if !allowed {
            bail!("path not in allowed directories");
        }

        Ok(canonical)
    }

    pub async fn handle_command(&self, command_bytes: Vec<u8>) -> Result<Vec<u8>> {
        if self.shutdown.load(Ordering::Acquire) {
            bail!("hub is shutting down");
        }

        let command =
            UiCommand::decode(&*command_bytes).context("failed to parse command")?;

        match command.command {
            Some(ui_command::Command::Discovery(req)) => {
                self.cmd_discovery(req).await?;
                Ok(Vec::new())
            }
            Some(ui_command::Command::SendFile(req)) => {
                self.cmd_send_file(req).await?;
                Ok(Vec::new())
            }
            Some(ui_command::Command::AcceptFile(req)) => {
                self.cmd_accept_file(req).await?;
                Ok(Vec::new())
            }
            Some(ui_command::Command::GetHistory(req)) => self.cmd_get_history(req).await,
            Some(ui_command::Command::Portal(req)) => {
                self.cmd_portal(req).await?;
                Ok(Vec::new())
            }
            Some(ui_command::Command::PauseTransfer(req)) => {
                self.cmd_pause_transfer(req).await?;
                Ok(Vec::new())
            }
            Some(ui_command::Command::ResumeTransfer(req)) => {
                self.cmd_resume_transfer(req).await?;
                Ok(Vec::new())
            }
            None => bail!("unknown command"),
        }
    }

    pub async fn poll_event(&self) -> Option<Vec<u8>> {
        let mut rx = self.event_rx.lock().await;

        match rx.try_recv() {
            Ok(event) => {
                let mut buf = Vec::with_capacity(256);
                if event.encode(&mut buf).is_ok() {
                    Some(buf)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    pub async fn poll_event_blocking(&self, timeout: Duration) -> Option<Vec<u8>> {
        let mut rx = self.event_rx.lock().await;

        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(event)) => {
                let mut buf = Vec::with_capacity(256);
                if event.encode(&mut buf).is_ok() {
                    Some(buf)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    async fn cmd_discovery(&self, req: DiscoveryRequest) -> Result<()> {
        match req.action() {
            DiscoveryAction::Start => {
                {
                    let discovery_guard = self.discovery.read();
                    if discovery_guard.is_some() {
                        bail!("discovery already running");
                    }
                }

                let node_addr = self
                    .engine
                    .endpoint
                    .node_addr()
                    .await
                    .context("failed to get node address")?;

                let node_id = node_addr.node_id.to_string();
                let secret_key = self.engine.endpoint.secret_key();

                let discovery = DiscoveryManager::new(
                    node_id,
                    &secret_key.to_bytes(),
                    self.discovery_event_tx.clone(),
                )?;

                discovery.start(0, HashMap::new())?;

                let mut discovery_guard = self.discovery.write();
                *discovery_guard = Some(discovery);
                tracing::info!("discovery started");
                Ok(())
            }
            DiscoveryAction::Stop => {
                let mut discovery_guard = self.discovery.write();
                if let Some(discovery) = discovery_guard.take() {
                    discovery.stop()?;
                    tracing::info!("discovery stopped");
                }
                Ok(())
            }
            _ => bail!("invalid discovery action"),
        }
    }

    async fn cmd_send_file(&self, req: SendFileRequest) -> Result<()> {
        let file_path = PathBuf::from(&req.file_path);
        let canonical_path = self.is_path_allowed(&file_path)?;

        let metadata = tokio::fs::metadata(&canonical_path)
            .await
            .context("failed to read file metadata")?;

        if !metadata.is_file() {
            bail!("not a regular file");
        }

        let total_bytes = metadata.len();
        if total_bytes < MIN_FILE_SIZE_BYTES {
            bail!("file is empty");
        }
        if total_bytes > MAX_FILE_SIZE_BYTES {
            bail!(
                "file too large: {} bytes (max {} GB)",
                total_bytes,
                MAX_FILE_SIZE_BYTES / (1024 * 1024 * 1024)
            );
        }

        let permit = self
            .transfer_semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("too many concurrent transfers"))?;

        let file_name = canonical_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();

        let transfer_id = uuid::Uuid::new_v4().to_string();
        let (cancel_tx, mut cancel_rx) = watch::channel(false);

        let handoff_file_id = if self.handoff_server.read().is_some() {
            Some(
                handoff::register_file(&self.handoff_registry, canonical_path.clone())
                    .await
                    .context("failed to register for handoff")?,
            )
        } else {
            None
        };

        let transfer = Arc::new(ActiveTransfer {
            id: transfer_id.clone(),
            file_name: file_name.clone(),
            file_path: canonical_path.clone(),
            total_bytes,
            bytes_transferred: AtomicU64::new(0),
            direction: TransferDirection::Outgoing,
            phase: RwLock::new(TransferPhase::Preparing),
            target_device_id: req.target_device_id.clone(),
            handoff_file_id: handoff_file_id.clone(),
            ticket: None,
            peer_name: None,
            cancel_tx,
            started_at: Instant::now(),
        });

        {
            let mut transfers = self.active_transfers.write();
            transfers.insert(transfer_id.clone(), Arc::clone(&transfer));
        }

        let checkpoint = TransferCheckpoint {
            transfer_id: transfer_id.clone(),
            file_path: canonical_path.clone(),
            file_name: file_name.clone(),
            total_bytes,
            bytes_transferred: 0,
            target_device_id: req.target_device_id.clone(),
            direction: crate::database::TransferDirection::Outgoing,
            status: crate::database::CheckpointStatus::InProgress,
            created_at_unix_ms: chrono::Utc::now().timestamp_millis(),
            updated_at_unix_ms: chrono::Utc::now().timestamp_millis(),
            chunk_size: CHECKPOINT_INTERVAL_BYTES,
            completed_chunks: Vec::new(),
        };

        self.db.save_checkpoint(&checkpoint).await?;

        let event = self.build_transfer_event(&transfer, None);
        self.emit_event(event).await;

        let engine = Arc::clone(&self.engine);
        let db = Arc::clone(&self.db);
        let event_tx = self.event_tx.clone();
        let handoff_registry = Arc::clone(&self.handoff_registry);
        let transfer_for_task = Arc::clone(&transfer);

        let handle = tokio::spawn(async move {
            let _permit = permit;
            let result =
                Self::execute_transfer(engine, Arc::clone(&transfer_for_task), cancel_rx, db.clone()).await;

            {
                let mut phase = transfer_for_task.phase.write();
                *phase = match &result {
                    Ok(_) => TransferPhase::Finished,
                    Err(_) if transfer_for_task.is_cancelled() && *phase == TransferPhase::Paused => {
                        TransferPhase::Paused
                    }
                    Err(_) if transfer_for_task.is_cancelled() => TransferPhase::Cancelled,
                    Err(_) => TransferPhase::Failed,
                };
            }

            if let Some(ref fid) = transfer_for_task.handoff_file_id {
                handoff::unregister_file(&handoff_registry, fid);
            }

            match &result {
                Ok(_) => {
                    let _ = db.delete_checkpoint(&transfer_for_task.id).await;
                }
                Err(_) => {
                    let _ = db
                        .update_checkpoint_status(
                            &transfer_for_task.id,
                            crate::database::CheckpointStatus::Failed,
                            transfer_for_task.current_bytes(),
                        )
                        .await;
                }
            }

            let error_msg = result.err().map(|e| e.to_string());
            let event = RustEvent {
                event: Some(rust_event::Event::TransferStateChanged(
                    TransferStateChanged {
                        state: transfer_for_task.phase.read().to_proto(),
                        transfer_id: transfer_for_task.id.clone(),
                        description: String::new(),
                        file_name: transfer_for_task.file_name.clone(),
                        total_bytes: transfer_for_task.total_bytes,
                        bytes_transferred: transfer_for_task.current_bytes(),
                        progress: transfer_for_task.progress(),
                        error_message: error_msg.unwrap_or_default(),
                        direction: transfer_for_task.direction as i32,
                        platform_handle: String::new(),
                    },
                )),
            };

            let _ = event_tx.send(event).await;
        });

        Ok(())
    }

    async fn execute_transfer(
        engine: Arc<IrohEngine>,
        transfer: Arc<ActiveTransfer>,
        mut cancel_rx: watch::Receiver<bool>,
        _db: Arc<HistoryDB>,
    ) -> Result<String> {
        *transfer.phase.write() = TransferPhase::InProgress;

        let cancel_check = async {
            loop {
                if cancel_rx.changed().await.is_err() {
                    return;
                }
                if *cancel_rx.borrow() {
                    return;
                }
            }
        };

        let send_op = engine.send_file(transfer.id.clone(), transfer.file_path.clone());

        tokio::select! {
            biased;

            _ = cancel_check => {
                bail!("transfer cancelled");
            }

            result = send_op => {
                result.context("send failed")
            }
        }
    }

    async fn cmd_accept_file(&self, req: AcceptFileRequest) -> Result<()> {
        if !req.accept {
            {
                let mut offers = self.incoming_offers.write();
                offers.remove(&req.transfer_id);
            }

            {
                let transfers = self.active_transfers.read();
                if let Some(transfer) = transfers.get(&req.transfer_id) {
                    let _ = transfer.cancel_tx.send(true);
                }
            }

            let _ = self.db.delete_checkpoint(&req.transfer_id).await;
            return Ok(());
        }

        if req.download_path.is_empty() {
            bail!("download_path is required");
        }

        let offer = {
            let mut offers = self.incoming_offers.write();
            offers.remove(&req.transfer_id)
        }
        .context("unknown incoming transfer")?;

        let download_dir = PathBuf::from(&req.download_path);
        let canonical_dir = download_dir
            .canonicalize()
            .context("download_path does not exist")?;

        let allowed = self
            .allowed_paths
            .iter()
            .any(|base| canonical_dir.starts_with(base));
        if !allowed {
            bail!("download_path not in allowed directories");
        }

        let transfer_id = req.transfer_id.clone();
        let (cancel_tx, cancel_rx) = watch::channel(false);

        let transfer = Arc::new(ActiveTransfer {
            id: transfer_id.clone(),
            file_name: offer.file_name.clone(),
            file_path: canonical_dir.clone(),
            total_bytes: offer.file_size,
            bytes_transferred: AtomicU64::new(0),
            direction: TransferDirection::Incoming,
            phase: RwLock::new(TransferPhase::Preparing),
            target_device_id: offer.sender_id.clone(),
            handoff_file_id: None,
            ticket: Some(offer.ticket.clone()),
            peer_name: Some(offer.sender_name.clone()),
            cancel_tx,
            started_at: Instant::now(),
        });

        {
            let mut transfers = self.active_transfers.write();
            transfers.insert(transfer_id.clone(), Arc::clone(&transfer));
        }

        let event = self.build_transfer_event(&transfer, None);
        self.emit_event(event).await;

        let engine = Arc::clone(&self.engine);
        let db = Arc::clone(&self.db);
        let event_tx = self.event_tx.clone();
        let transfer_semaphore = Arc::clone(&self.transfer_semaphore);
        let transfer_for_task = Arc::clone(&transfer);
        let ticket = offer.ticket.clone();
        let output_dir = canonical_dir;
        let sender_name = offer.sender_name.clone();

        let handle = tokio::spawn(async move {
            let mut cancel_rx = cancel_rx;
            let permit = match transfer_semaphore.try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    *transfer_for_task.phase.write() = TransferPhase::Failed;
                    let event = RustEvent {
                        event: Some(rust_event::Event::TransferStateChanged(
                            TransferStateChanged {
                                state: transfer_for_task.phase.read().to_proto(),
                                transfer_id: transfer_for_task.id.clone(),
                                description: String::new(),
                                file_name: transfer_for_task.file_name.clone(),
                                total_bytes: transfer_for_task.total_bytes,
                                bytes_transferred: transfer_for_task.current_bytes(),
                                progress: transfer_for_task.progress(),
                                error_message: "too many concurrent transfers".to_string(),
                                direction: transfer_for_task.direction as i32,
                                platform_handle: String::new(),
                            },
                        )),
                    };
                    let _ = event_tx.send(event).await;
                    return;
                }
            };

            let cancel_check = async {
                loop {
                    if cancel_rx.changed().await.is_err() {
                        return;
                    }
                    if *cancel_rx.borrow() {
                        return;
                    }
                }
            };

            let recv_op = engine.receive_file(
                transfer_for_task.id.clone(),
                ticket,
                output_dir.clone(),
            );

            let result = tokio::select! {
                biased;
                _ = cancel_check => Err(anyhow::anyhow!("transfer cancelled")),
                res = recv_op => res.context("receive failed"),
            };

            drop(permit);

            let mut error_msg = None;

            match result {
                Ok(path) => {
                    if let Ok(meta) = tokio::fs::metadata(&path).await {
                        transfer_for_task
                            .bytes_transferred
                            .store(meta.len(), Ordering::Relaxed);
                    }
                    *transfer_for_task.phase.write() = TransferPhase::Finished;

                    let timestamp = chrono::Utc::now().to_rfc3339();
                    let entry = HistoryEntry {
                        id: transfer_for_task.id.clone(),
                        file_name: transfer_for_task.file_name.clone(),
                        size_bytes: transfer_for_task.current_bytes(),
                        sender_receiver: sender_name,
                        timestamp,
                        direction: TransferDirection::Incoming as i32,
                        status: CheckpointStatus::Completed as i32,
                        file_path: path.to_string_lossy().to_string(),
                    };
                    let _ = db.add_entry(entry).await;
                }
                Err(e) => {
                    if transfer_for_task.is_cancelled() {
                        let mut phase = transfer_for_task.phase.write();
                        if *phase == TransferPhase::Paused {
                            *phase = TransferPhase::Paused;
                        } else {
                            *phase = TransferPhase::Cancelled;
                        }
                    } else {
                        *transfer_for_task.phase.write() = TransferPhase::Failed;
                    }
                    error_msg = Some(e.to_string());
                }
            }

            let event = RustEvent {
                event: Some(rust_event::Event::TransferStateChanged(
                    TransferStateChanged {
                        state: transfer_for_task.phase.read().to_proto(),
                        transfer_id: transfer_for_task.id.clone(),
                        description: String::new(),
                        file_name: transfer_for_task.file_name.clone(),
                        total_bytes: transfer_for_task.total_bytes,
                        bytes_transferred: transfer_for_task.current_bytes(),
                        progress: transfer_for_task.progress(),
                        error_message: error_msg.unwrap_or_default(),
                        direction: transfer_for_task.direction as i32,
                        platform_handle: String::new(),
                    },
                )),
            };

            let _ = event_tx.send(event).await;
        });

        Ok(())
    }

    async fn cmd_pause_transfer(&self, req: PauseTransferRequest) -> Result<()> {
        let transfer = {
            let transfers = self.active_transfers.read();
            transfers.get(&req.transfer_id).cloned()
        }
        .context("unknown transfer_id")?;

        if transfer.phase.read().is_terminal() {
            bail!("transfer is not active");
        }

        *transfer.phase.write() = TransferPhase::Paused;

        let _ = transfer.cancel_tx.send(true);

        let _ = self
            .db
            .update_checkpoint_status(
                &transfer.id,
                CheckpointStatus::Paused,
                transfer.current_bytes(),
            )
            .await;

        let event = self.build_transfer_event(&transfer, None);
        self.emit_event(event).await;

        Ok(())
    }

    async fn cmd_resume_transfer(&self, req: ResumeTransferRequest) -> Result<()> {
        let transfer = {
            let transfers = self.active_transfers.read();
            transfers.get(&req.transfer_id).cloned()
        }
        .context("unknown transfer_id")?;

        {
            let mut phase = transfer.phase.write();
            if *phase != TransferPhase::Paused {
                bail!("transfer is not paused");
            }
            *phase = TransferPhase::InProgress;
        }

        if transfer.direction != TransferDirection::Incoming {
            bail!("resume only supported for incoming transfers");
        }

        let ticket = transfer.ticket.clone().context("missing ticket for transfer")?;
        let output_dir = transfer.file_path.clone();
        let sender_name = transfer
            .peer_name
            .clone()
            .unwrap_or_else(|| transfer.target_device_id.clone());

        let engine = Arc::clone(&self.engine);
        let db = Arc::clone(&self.db);
        let event_tx = self.event_tx.clone();
        let transfer_semaphore = Arc::clone(&self.transfer_semaphore);
        let transfer_for_task = Arc::clone(&transfer);
        let mut cancel_rx = transfer.cancel_tx.subscribe();

        tokio::spawn(async move {
            let permit = match transfer_semaphore.try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    *transfer_for_task.phase.write() = TransferPhase::Failed;
                    let event = RustEvent {
                        event: Some(rust_event::Event::TransferStateChanged(
                            TransferStateChanged {
                                state: transfer_for_task.phase.read().to_proto(),
                                transfer_id: transfer_for_task.id.clone(),
                                description: String::new(),
                                file_name: transfer_for_task.file_name.clone(),
                                total_bytes: transfer_for_task.total_bytes,
                                bytes_transferred: transfer_for_task.current_bytes(),
                                progress: transfer_for_task.progress(),
                                error_message: "too many concurrent transfers".to_string(),
                                direction: transfer_for_task.direction as i32,
                                platform_handle: String::new(),
                            },
                        )),
                    };
                    let _ = event_tx.send(event).await;
                    return;
                }
            };

            let cancel_check = async {
                loop {
                    if cancel_rx.changed().await.is_err() {
                        return;
                    }
                    if *cancel_rx.borrow() {
                        return;
                    }
                }
            };

            let recv_op = engine.receive_file(
                transfer_for_task.id.clone(),
                ticket,
                output_dir.clone(),
            );

            let result = tokio::select! {
                biased;
                _ = cancel_check => Err(anyhow::anyhow!("transfer cancelled")),
                res = recv_op => res.context("receive failed"),
            };

            drop(permit);

            let mut error_msg = None;

            match result {
                Ok(path) => {
                    if let Ok(meta) = tokio::fs::metadata(&path).await {
                        transfer_for_task
                            .bytes_transferred
                            .store(meta.len(), Ordering::Relaxed);
                    }
                    *transfer_for_task.phase.write() = TransferPhase::Finished;

                    let timestamp = chrono::Utc::now().to_rfc3339();
                    let entry = HistoryEntry {
                        id: transfer_for_task.id.clone(),
                        file_name: transfer_for_task.file_name.clone(),
                        size_bytes: transfer_for_task.current_bytes(),
                        sender_receiver: sender_name,
                        timestamp,
                        direction: TransferDirection::Incoming as i32,
                        status: CheckpointStatus::Completed as i32,
                        file_path: path.to_string_lossy().to_string(),
                    };
                    let _ = db.add_entry(entry).await;
                }
                Err(e) => {
                    if transfer_for_task.is_cancelled() {
                        let mut phase = transfer_for_task.phase.write();
                        if *phase == TransferPhase::Paused {
                            *phase = TransferPhase::Paused;
                        } else {
                            *phase = TransferPhase::Cancelled;
                        }
                    } else {
                        *transfer_for_task.phase.write() = TransferPhase::Failed;
                    }
                    error_msg = Some(e.to_string());
                }
            }

            let event = RustEvent {
                event: Some(rust_event::Event::TransferStateChanged(
                    TransferStateChanged {
                        state: transfer_for_task.phase.read().to_proto(),
                        transfer_id: transfer_for_task.id.clone(),
                        description: String::new(),
                        file_name: transfer_for_task.file_name.clone(),
                        total_bytes: transfer_for_task.total_bytes,
                        bytes_transferred: transfer_for_task.current_bytes(),
                        progress: transfer_for_task.progress(),
                        error_message: error_msg.unwrap_or_default(),
                        direction: transfer_for_task.direction as i32,
                        platform_handle: String::new(),
                    },
                )),
            };

            let _ = event_tx.send(event).await;
        });

        let event = self.build_transfer_event(&transfer, None);
        self.emit_event(event).await;

        Ok(())
    }

    async fn cmd_get_history(&self, req: GetHistoryRequest) -> Result<Vec<u8>> {
        let limit = if req.limit > 0 && req.limit <= 1000 {
            req.limit as usize
        } else {
            100
        };

        let entries = self.db.get_entries_paginated(0, limit).await?;
        
        let mut buf = Vec::with_capacity(entries.len() * 128 + 64);
        let response = GetHistoryResponse { entries };
        response.encode(&mut buf)?;

        Ok(buf)
    }

    async fn cmd_portal(&self, req: PortalRequest) -> Result<()> {
        if req.start {
            {
                let portal_guard = self.portal_shutdown.read();
                if portal_guard.is_some() {
                    bail!("portal already running");
                }
            }

            let port = if req.port > 0 && req.port < 65535 {
                req.port as u16
            } else {
                8080
            };

            if port < 1024 && port != 0 {
                bail!("privileged port requires elevated permissions");
            }

            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            {
                let mut portal_guard = self.portal_shutdown.write();
                *portal_guard = Some(shutdown_tx);
            }

            let engine = Arc::clone(&self.engine);
            let (started_tx, started_rx) = oneshot::channel();

            // Build portal config
            let portal_config = crate::portal::PortalConfig {
                bind_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                port,
                identity_path: dirs::data_local_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                    .join("flatdrop")
                    .join("portal_identity.bin"),
                identity_password: "flatdrop-portal-default".to_string(), // TODO: Make configurable
                tls: crate::portal::TlsMode::SelfSigned,
            };

            tokio::spawn(async move {
                if let Err(e) = crate::portal::start_portal(portal_config, engine, shutdown_rx, started_tx).await {
                    tracing::error!(error = %e, "portal failed");
                }
            });

            // Wait for portal to start and report port/pairing code
            match tokio::time::timeout(Duration::from_secs(5), started_rx).await {
                Ok(Ok((actual_port, pairing_code))) => {
                    let event = RustEvent {
                        event: Some(rust_event::Event::PortalStatus(PortalStatus {
                            is_running: true,
                            address: format!("https://127.0.0.1:{} (code: {})", actual_port, pairing_code),
                            port: actual_port as u32,
                        })),
                    };
                    self.emit_event(event).await;
                }
                _ => {
                    tracing::error!("Portal timed out or failed to start");
                    // Clean up
                    let mut guard = self.portal_shutdown.write();
                    *guard = None;
                    // TODO: Emit error event?
                }
            }
        } else {
            {
                let mut portal_guard = self.portal_shutdown.write();
                if let Some(tx) = portal_guard.take() {
                    let _ = tx.send(());
                }
            }

            let event = RustEvent {
                event: Some(rust_event::Event::PortalStatus(PortalStatus {
                    is_running: false,
                    address: String::new(),
                    port: 0,
                })),
            };
            self.emit_event(event).await;
        }

        Ok(())
    }

    pub async fn shutdown(&self) -> Result<()> {
        if self.shutdown.swap(true, Ordering::AcqRel) {
            return Ok(());
        }

        tracing::info!("hub shutdown initiated");

        {
            let transfers = self.active_transfers.read();
            for (_, transfer) in transfers.iter() {
                let _ = transfer.cancel_tx.send(true);
            }
        }

        {
            let mut portal = self.portal_shutdown.write();
            if let Some(tx) = portal.take() {
                let _ = tx.send(());
            }
        }

        {
            let mut discovery = self.discovery.write();
            if let Some(d) = discovery.take() {
                let _ = d.stop();
            }
        }

        {
            let mut server = self.handoff_server.write();
            if let Some(s) = server.take() {
                s.shutdown();
            }
        }

        if let Some(tasks) = self.background_tasks.write().take() {
            tasks.progress_handler.abort();
            tasks.cleanup_task.abort();
            if let Some(h) = tasks.discovery_handler {
                h.abort();
            }
        }

        tracing::info!("hub shutdown complete");
        Ok(())
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    pub fn active_transfer_count(&self) -> usize {
        self.active_transfers.read().len()
    }
}

impl Drop for FlatDropHub {
    fn drop(&mut self) {
        if !self.shutdown.load(Ordering::Acquire) {
            tracing::error!("hub dropped without shutdown");
        }
    }
}
