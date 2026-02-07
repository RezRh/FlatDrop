use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use axum::body::Body;
use axum::extract::{Path as AxumPath, State};
use axum::http::header::{ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use parking_lot::RwLock;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_util::io::ReaderStream;
use tower::ServiceBuilder;
use tower_http::timeout::TimeoutLayer;

const MAX_REGISTERED_FILES: usize = 100;
const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024 * 1024;
const MIN_FILE_SIZE: u64 = 1;
const REGISTRATION_TTL_SECS: u64 = 3600;
const MAX_CONCURRENT_DOWNLOADS: usize = 10;
const REQUEST_TIMEOUT_SECS: u64 = 300;
const CLEANUP_INTERVAL_SECS: u64 = 60;
const STREAM_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone)]
struct RegisteredFile {
    path: PathBuf,
    size: u64,
    registered_at: Instant,
    access_count: Arc<AtomicU64>,
}

impl RegisteredFile {
    fn is_expired(&self) -> bool {
        self.registered_at.elapsed() > Duration::from_secs(REGISTRATION_TTL_SECS)
    }
}

pub struct HandoffRegistry {
    files: RwLock<HashMap<String, RegisteredFile>>,
    allowed_base_paths: Vec<PathBuf>,
    download_semaphore: Arc<Semaphore>,
}

impl HandoffRegistry {
    pub fn new(allowed_base_paths: Vec<PathBuf>) -> Result<Self> {
        if allowed_base_paths.is_empty() {
            bail!("at least one allowed base path required");
        }

        let canonical: Vec<PathBuf> = allowed_base_paths
            .into_iter()
            .filter_map(|p| p.canonicalize().ok())
            .collect();

        if canonical.is_empty() {
            bail!("no valid allowed base paths");
        }

        Ok(Self {
            files: RwLock::new(HashMap::with_capacity(32)),
            allowed_base_paths: canonical,
            download_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_DOWNLOADS)),
        })
    }

    fn is_path_allowed(&self, path: &Path) -> bool {
        self.allowed_base_paths.iter().any(|base| path.starts_with(base))
    }
}

pub type SharedRegistry = Arc<HandoffRegistry>;

#[derive(Clone)]
struct HandoffState {
    registry: SharedRegistry,
    shutdown: Arc<AtomicBool>,
}

pub struct HandoffServer {
    registry: SharedRegistry,
    shutdown: Arc<AtomicBool>,
    port: u16,
}

impl HandoffServer {
    pub async fn start(port: u16, registry: SharedRegistry) -> Result<Self> {
        let shutdown = Arc::new(AtomicBool::new(false));
        
        let state = HandoffState {
            registry: Arc::clone(&registry),
            shutdown: Arc::clone(&shutdown),
        };

        let app = Router::new()
            .route("/handoff/:file_id", get(handle_file_request))
            .with_state(state.clone())
            .layer(
                ServiceBuilder::new()
                    .layer(TimeoutLayer::new(Duration::from_secs(REQUEST_TIMEOUT_SECS))),
            );

        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let listener = TcpListener::bind(addr)
            .await
            .context("failed to bind handoff server")?;

        let actual_port = listener.local_addr()?.port();

        let server_shutdown = Arc::clone(&shutdown);
        tokio::spawn(async move {
            let graceful = axum::serve(listener, app).with_graceful_shutdown(async move {
                loop {
                    if server_shutdown.load(Ordering::Acquire) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            });

            if let Err(e) = graceful.await {
                tracing::error!(error = %e, "handoff server terminated with error");
            }
        });

        let cleanup_registry = Arc::clone(&registry);
        let cleanup_shutdown = Arc::clone(&shutdown);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;
                if cleanup_shutdown.load(Ordering::Acquire) {
                    break;
                }
                evict_expired(&cleanup_registry);
            }
        });

        tracing::info!(port = actual_port, "handoff server started");

        Ok(Self {
            registry,
            shutdown,
            port: actual_port,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        tracing::info!("handoff server shutdown initiated");
    }

    pub fn is_running(&self) -> bool {
        !self.shutdown.load(Ordering::Acquire)
    }
}

impl Drop for HandoffServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn evict_expired(registry: &SharedRegistry) {
    let mut files = registry.files.write();
    let before = files.len();
    files.retain(|_, f| !f.is_expired());
    let evicted = before - files.len();
    if evicted > 0 {
        tracing::debug!(evicted, "expired handoff registrations removed");
    }
}

async fn handle_file_request(
    AxumPath(file_id): AxumPath<String>,
    headers: HeaderMap,
    State(state): State<HandoffState>,
) -> Response {
    if state.shutdown.load(Ordering::Acquire) {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "server shutting down");
    }

    if uuid::Uuid::parse_str(&file_id).is_err() {
        return error_response(StatusCode::BAD_REQUEST, "invalid file id format");
    }

    let registered = {
        let files = state.registry.files.read();
        files.get(&file_id).cloned()
    };

    let registered = match registered {
        Some(r) if !r.is_expired() => r,
        Some(_) => {
            let mut files = state.registry.files.write();
            files.remove(&file_id);
            return error_response(StatusCode::GONE, "registration expired");
        }
        None => {
            return error_response(StatusCode::NOT_FOUND, "file not registered");
        }
    };

    let permit = match state.registry.download_semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return error_response(StatusCode::TOO_MANY_REQUESTS, "too many concurrent downloads");
        }
    };

    registered.access_count.fetch_add(1, Ordering::Relaxed);

    match serve_file(&registered.path, registered.size, &headers, permit).await {
        Ok(response) => response,
        Err(e) => {
            tracing::warn!(file_id = %file_id, error = %e, "failed to serve file");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "file transfer failed")
        }
    }
}

async fn serve_file(
    path: &Path,
    expected_size: u64,
    headers: &HeaderMap,
    _permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<Response> {
    let meta = tokio::fs::symlink_metadata(path)
        .await
        .context("failed to stat file")?;

    if meta.file_type().is_symlink() {
        bail!("symlink detected at serve time");
    }

    let mut file = File::open(path).await.context("failed to open file")?;

    let metadata = file.metadata().await.context("failed to get metadata")?;

    if !metadata.is_file() {
        bail!("not a regular file");
    }

    let actual_size = metadata.len();
    if actual_size != expected_size {
        bail!(
            "file size changed: expected {}, got {}",
            expected_size,
            actual_size
        );
    }

    let range = parse_range_header(headers, actual_size);

    let (start, end, is_partial) = match range {
        Some((s, e)) => (s, e, true),
        None => (0, actual_size.saturating_sub(1), false),
    };

    let length = end - start + 1;

    if start > 0 {
        file.seek(std::io::SeekFrom::Start(start))
            .await
            .context("failed to seek")?;
    }

    let limited = file.take(length);
    let stream = ReaderStream::with_capacity(limited, STREAM_BUFFER_SIZE);
    let body = Body::from_stream(stream);

    let mut response = Response::builder()
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_LENGTH, length)
        .header(ACCEPT_RANGES, "bytes");

    if is_partial {
        response = response
            .status(StatusCode::PARTIAL_CONTENT)
            .header(
                CONTENT_RANGE,
                format!("bytes {}-{}/{}", start, end, actual_size),
            );
    } else {
        response = response.status(StatusCode::OK);
    }

    Ok(response.body(body).unwrap())
}

fn parse_range_header(headers: &HeaderMap, file_size: u64) -> Option<(u64, u64)> {
    let range_str = headers.get("range")?.to_str().ok()?;

    if !range_str.starts_with("bytes=") {
        return None;
    }

    let range_spec = &range_str[6..];

    if range_spec.contains(',') {
        return None;
    }

    let parts: Vec<&str> = range_spec.split('-').collect();
    if parts.len() != 2 {
        return None;
    }

    let (start, end) = if parts[0].is_empty() {
        let suffix_len: u64 = parts[1].parse().ok()?;
        if suffix_len == 0 {
            return None;
        }
        let start = file_size.saturating_sub(suffix_len);
        let end = file_size.saturating_sub(1);
        (start, end)
    } else {
        let start: u64 = parts[0].parse().ok()?;
        let end = if parts[1].is_empty() {
            file_size.saturating_sub(1)
        } else {
            parts[1].parse::<u64>().ok()?.min(file_size.saturating_sub(1))
        };
        (start, end)
    };

    if start > end || start >= file_size {
        return None;
    }

    Some((start, end))
}

fn error_response(status: StatusCode, message: &'static str) -> Response {
    (status, message).into_response()
}

pub async fn register_file(registry: &SharedRegistry, file_path: PathBuf) -> Result<String> {
    let canonical = file_path
        .canonicalize()
        .context("failed to canonicalize path")?;

    if !registry.is_path_allowed(&canonical) {
        bail!("path not in allowed directories");
    }

    let metadata = tokio::fs::metadata(&canonical)
        .await
        .context("failed to read metadata")?;

    if !metadata.is_file() {
        bail!("not a regular file");
    }

    if metadata.file_type().is_symlink() {
        bail!("symlinks not allowed");
    }

    let size = metadata.len();
    if size < MIN_FILE_SIZE {
        bail!("file too small");
    }
    if size > MAX_FILE_SIZE {
        bail!("file too large: {} bytes", size);
    }

    #[cfg(unix)]
    {
        let mode = metadata.mode();
        if (mode & 0o170000) != 0o100000 {
            bail!("not a regular file (mode check)");
        }
    }

    let file_id = uuid::Uuid::new_v4().to_string();

    {
        let mut files = registry.files.write();

        if files.len() >= MAX_REGISTERED_FILES {
            let oldest = files
                .iter()
                .min_by_key(|(_, f)| f.registered_at)
                .map(|(k, _)| k.clone());

            if let Some(key) = oldest {
                files.remove(&key);
                tracing::debug!(evicted = %key, "evicted oldest registration");
            }
        }

        if files.contains_key(&file_id) {
            bail!("uuid collision");
        }

        files.insert(
            file_id.clone(),
            RegisteredFile {
                path: canonical,
                size,
                registered_at: Instant::now(),
                access_count: Arc::new(AtomicU64::new(0)),
            },
        );
    }

    tracing::info!(file_id = %file_id, size, "file registered for handoff");

    Ok(file_id)
}

pub fn unregister_file(registry: &SharedRegistry, file_id: &str) -> bool {
    let mut files = registry.files.write();
    let removed = files.remove(file_id).is_some();
    if removed {
        tracing::info!(file_id = %file_id, "file unregistered from handoff");
    }
    removed
}

pub fn is_file_registered(registry: &SharedRegistry, file_id: &str) -> bool {
    let files = registry.files.read();
    files.get(file_id).map(|f| !f.is_expired()).unwrap_or(false)
}

pub fn get_registered_count(registry: &SharedRegistry) -> usize {
    registry.files.read().len()
}

pub fn construct_handoff_url(port: u16, file_id: &str) -> String {
    format!("http://127.0.0.1:{}/handoff/{}", port, file_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::io::AsyncWriteExt;

    async fn test_registry() -> (SharedRegistry, TempDir) {
        let dir = TempDir::new().unwrap();
        let registry = Arc::new(
            HandoffRegistry::new(vec![dir.path().to_path_buf()]).unwrap(),
        );
        (registry, dir)
    }

    #[tokio::test]
    async fn test_register_unregister() {
        let (registry, dir): (SharedRegistry, TempDir) = test_registry().await;

        let file_path = dir.path().join("test.bin");
        let mut file: File = File::create(&file_path).await.unwrap();
        file.write_all(&[0u8; 1024]).await.unwrap();
        file.sync_all().await.unwrap();
        drop(file);

        let file_id = register_file(&registry, file_path).await.unwrap();
        assert!(is_file_registered(&registry, &file_id));

        assert!(unregister_file(&registry, &file_id));
        assert!(!is_file_registered(&registry, &file_id));
    }

    #[tokio::test]
    async fn test_rejects_path_outside_allowed() {
        let (registry, _dir): (SharedRegistry, TempDir) = test_registry().await;

        let result = register_file(&registry, PathBuf::from("/etc/passwd")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_rejects_empty_file() {
        let (registry, dir): (SharedRegistry, TempDir) = test_registry().await;

        let file_path = dir.path().join("empty.bin");
        let _file: File = File::create(&file_path).await.unwrap();

        let result = register_file(&registry, file_path).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_range() {
        let mut headers = HeaderMap::new();

        headers.insert("range", "bytes=0-499".parse().unwrap());
        assert_eq!(parse_range_header(&headers, 1000), Some((0, 499)));

        headers.insert("range", "bytes=500-".parse().unwrap());
        assert_eq!(parse_range_header(&headers, 1000), Some((500, 999)));

        headers.insert("range", "bytes=-100".parse().unwrap());
        assert_eq!(parse_range_header(&headers, 1000), Some((900, 999)));

        headers.insert("range", "bytes=0-0".parse().unwrap());
        assert_eq!(parse_range_header(&headers, 1000), Some((0, 0)));

        headers.insert("range", "bytes=999-999".parse().unwrap());
        assert_eq!(parse_range_header(&headers, 1000), Some((999, 999)));

        headers.insert("range", "bytes=1000-".parse().unwrap());
        assert_eq!(parse_range_header(&headers, 1000), None);
    }

    #[tokio::test]
    async fn test_max_registrations() {
        let (registry, dir): (SharedRegistry, TempDir) = test_registry().await;

        for i in 0..MAX_REGISTERED_FILES + 5 {
            let file_path = dir.path().join(format!("file{}.bin", i));
            let mut file: File = File::create(&file_path).await.unwrap();
            file.write_all(&[0u8; 100]).await.unwrap();
            drop(file);
            let _ = register_file(&registry, file_path).await;
        }

        assert!(get_registered_count(&registry) <= MAX_REGISTERED_FILES);
    }
}
