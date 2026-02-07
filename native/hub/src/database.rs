use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use libsql::{Builder, Connection, Database};
use tokio::sync::{Mutex, Semaphore};
use zeroize::Zeroizing;

use crate::types::HistoryEntry;

const MAX_FIELD_LENGTH: usize = 4096;
const MAX_FILE_PATH_LENGTH: usize = 32768;
const MAX_COMPLETED_CHUNKS: usize = 100_000;
const DEFAULT_PAGE_SIZE: usize = 100;
const MAX_PAGE_SIZE: usize = 1000;
const WRITE_SEMAPHORE_PERMITS: usize = 1;
const READ_SEMAPHORE_PERMITS: usize = 10;
const SCHEMA_VERSION: i64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum CheckpointStatus {
    Pending = 1,
    InProgress = 2,
    Paused = 3,
    Completed = 4,
    Failed = 5,
    Cancelled = 6,
}

impl CheckpointStatus {
    fn from_i32(v: i32) -> Option<Self> {
        match v {
            1 => Some(Self::Pending),
            2 => Some(Self::InProgress),
            3 => Some(Self::Paused),
            4 => Some(Self::Completed),
            5 => Some(Self::Failed),
            6 => Some(Self::Cancelled),
            _ => None,
        }
    }

    fn is_resumable(self) -> bool {
        matches!(self, Self::InProgress | Self::Paused)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum TransferDirection {
    Incoming = 0,
    Outgoing = 1,
}

impl TransferDirection {
    fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Incoming),
            1 => Some(Self::Outgoing),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TransferCheckpoint {
    pub transfer_id: String,
    pub file_path: PathBuf,
    pub file_name: String,
    pub total_bytes: u64,
    pub bytes_transferred: u64,
    pub target_device_id: String,
    pub direction: TransferDirection,
    pub status: CheckpointStatus,
    pub created_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
    pub chunk_size: u64,
    pub completed_chunks: Vec<u64>,
}

impl TransferCheckpoint {
    fn validate(&self) -> Result<()> {
        if self.transfer_id.is_empty() || self.transfer_id.len() > MAX_FIELD_LENGTH {
            bail!("invalid transfer_id length");
        }
        if self.file_name.is_empty() || self.file_name.len() > MAX_FIELD_LENGTH {
            bail!("invalid file_name length");
        }
        if self.file_path.as_os_str().len() > MAX_FILE_PATH_LENGTH {
            bail!("file_path too long");
        }
        if self.target_device_id.len() > MAX_FIELD_LENGTH {
            bail!("target_device_id too long");
        }
        if self.completed_chunks.len() > MAX_COMPLETED_CHUNKS {
            bail!("too many completed_chunks");
        }
        if self.bytes_transferred > self.total_bytes {
            bail!("bytes_transferred exceeds total_bytes");
        }
        if self.chunk_size == 0 {
            bail!("chunk_size cannot be zero");
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ValidatedHistoryEntry {
    pub id: String,
    pub file_name: String,
    pub size_bytes: u64,
    pub sender_receiver: String,
    pub timestamp_unix_ms: i64,
    pub direction: TransferDirection,
    pub status: CheckpointStatus,
    pub file_path: Option<PathBuf>,
}

impl ValidatedHistoryEntry {
    pub fn new(entry: HistoryEntry) -> Result<Self> {
        if entry.id.is_empty() || entry.id.len() > MAX_FIELD_LENGTH {
            bail!("invalid id length");
        }
        if entry.file_name.is_empty() || entry.file_name.len() > MAX_FIELD_LENGTH {
            bail!("invalid file_name length");
        }
        if entry.sender_receiver.len() > MAX_FIELD_LENGTH {
            bail!("sender_receiver too long");
        }

        let direction = TransferDirection::from_i32(entry.direction)
            .context("invalid direction value")?;
        let status = CheckpointStatus::from_i32(entry.status)
            .context("invalid status value")?;

        let file_path = if entry.file_path.is_empty() {
            None
        } else {
            if entry.file_path.len() > MAX_FILE_PATH_LENGTH {
                bail!("file_path too long");
            }
            Some(PathBuf::from(&entry.file_path))
        };

        let timestamp_unix_ms = chrono::DateTime::parse_from_rfc3339(&entry.timestamp)
            .context("invalid timestamp format")?
            .timestamp_millis();

        Ok(Self {
            id: entry.id,
            file_name: entry.file_name,
            size_bytes: entry.size_bytes,
            sender_receiver: entry.sender_receiver,
            timestamp_unix_ms,
            direction,
            status,
            file_path,
        })
    }
}

pub struct HistoryDB {
    db: Database,
    conn: Mutex<Connection>,
    write_sem: Semaphore,
    read_sem: Semaphore,
    db_path: PathBuf,
}

impl HistoryDB {
    pub async fn new(db_path: PathBuf, remote_config: Option<RemoteConfig>) -> Result<Self> {
        let canonical_path = if db_path.exists() {
            db_path.canonicalize().context("failed to canonicalize db path")?
        } else {
            let parent = db_path.parent().context("db path has no parent")?;
            if !parent.exists() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .context("failed to create db directory")?;
            }
            let canonical_parent = parent.canonicalize().context("failed to canonicalize parent")?;
            canonical_parent.join(db_path.file_name().context("db path has no filename")?)
        };

        let path_str = canonical_path
            .to_str()
            .context("db path is not valid UTF-8")?;

        if let Some(cfg) = &remote_config {
            if !cfg.url.starts_with("https://") {
                bail!("remote database_url must start with https://");
            }
        }

        let db = match remote_config {
            Some(cfg) => {
                let token = Zeroizing::new(cfg.token);
                Builder::new_remote_replica(path_str, cfg.url, token.as_str().to_string())
                    .build()
                    .await
                    .context("failed to connect to remote replica")?
            }
            None => {
                Builder::new_local(path_str)
                    .build()
                    .await
                    .context("failed to open local database")?
            }
        };

        let conn = db.connect().context("failed to create connection")?;

        let instance = Self {
            db,
            conn: Mutex::new(conn),
            write_sem: Semaphore::new(WRITE_SEMAPHORE_PERMITS),
            read_sem: Semaphore::new(READ_SEMAPHORE_PERMITS),
            db_path: canonical_path,
        };

        instance.init_schema().await?;

        Ok(instance)
    }

    async fn init_schema(&self) -> Result<()> {
        let _permit = self.write_sem.acquire().await?;
        let conn = self.conn.lock().await;

        if let Err(e) = conn.execute("PRAGMA journal_mode=WAL", ()).await {
            tracing::warn!(error = %e, "failed to enable WAL mode");
        }

        if let Err(e) = conn.execute("PRAGMA synchronous=NORMAL", ()).await {
            tracing::warn!(error = %e, "failed to set synchronous mode");
        }

        if let Err(e) = conn.execute("PRAGMA foreign_keys=ON", ()).await {
            tracing::warn!(error = %e, "failed to enable foreign keys");
        }

        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            )",
            (),
        )
        .await?;

        let mut rows = conn.query("SELECT version FROM schema_version LIMIT 1", ()).await?;
        let current_version: i64 = if let Some(row) = rows.next().await? {
            row.get(0)?
        } else {
            0
        };
        drop(rows);

        if current_version < SCHEMA_VERSION {
            self.run_migrations(&conn, current_version).await?;
        }

        Ok(())
    }

    async fn run_migrations(&self, conn: &Connection, from_version: i64) -> Result<()> {
        if from_version < 1 {
            conn.execute(
                "CREATE TABLE IF NOT EXISTS history (
                    id TEXT PRIMARY KEY NOT NULL CHECK(length(id) > 0 AND length(id) <= 4096),
                    file_name TEXT NOT NULL CHECK(length(file_name) > 0 AND length(file_name) <= 4096),
                    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
                    sender_receiver TEXT NOT NULL CHECK(length(sender_receiver) <= 4096),
                    timestamp_unix_ms INTEGER NOT NULL,
                    direction INTEGER NOT NULL CHECK(direction IN (0, 1)),
                    status INTEGER NOT NULL CHECK(status IN (1, 2, 3, 4, 5, 6)),
                    file_path TEXT CHECK(file_path IS NULL OR length(file_path) <= 32768)
                )",
                (),
            )
            .await?;

            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_history_timestamp ON history(timestamp_unix_ms DESC)",
                (),
            )
            .await?;

            conn.execute(
                "CREATE TABLE IF NOT EXISTS checkpoints (
                    transfer_id TEXT PRIMARY KEY NOT NULL CHECK(length(transfer_id) > 0 AND length(transfer_id) <= 4096),
                    file_path TEXT NOT NULL CHECK(length(file_path) <= 32768),
                    file_name TEXT NOT NULL CHECK(length(file_name) > 0 AND length(file_name) <= 4096),
                    total_bytes INTEGER NOT NULL CHECK(total_bytes >= 0),
                    bytes_transferred INTEGER NOT NULL CHECK(bytes_transferred >= 0),
                    target_device_id TEXT NOT NULL CHECK(length(target_device_id) <= 4096),
                    direction INTEGER NOT NULL CHECK(direction IN (0, 1)),
                    status INTEGER NOT NULL CHECK(status IN (1, 2, 3, 4, 5, 6)),
                    created_at_unix_ms INTEGER NOT NULL,
                    updated_at_unix_ms INTEGER NOT NULL,
                    chunk_size INTEGER NOT NULL CHECK(chunk_size > 0),
                    completed_chunks BLOB NOT NULL,
                    CHECK(bytes_transferred <= total_bytes)
                )",
                (),
            )
            .await?;

            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_checkpoints_status ON checkpoints(status)",
                (),
            )
            .await?;

            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_checkpoints_updated ON checkpoints(updated_at_unix_ms DESC)",
                (),
            )
            .await?;
        }

        conn.execute("DELETE FROM schema_version", ()).await?;
        conn.execute(
            "INSERT INTO schema_version (version) VALUES (?)",
            [SCHEMA_VERSION],
        )
        .await?;

        Ok(())
    }

    pub async fn add_entry(&self, entry: HistoryEntry) -> Result<()> {
        let validated = ValidatedHistoryEntry::new(entry)?;
        let _permit = self.write_sem.acquire().await?;
        let conn = self.conn.lock().await;

        let file_path_str = validated
            .file_path
            .as_ref()
            .and_then(|p| p.to_str())
            .map(|s| s.to_owned());

        conn.execute(
            "INSERT INTO history (id, file_name, size_bytes, sender_receiver, timestamp_unix_ms, direction, status, file_path)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            libsql::params![
                validated.id,
                validated.file_name,
                validated.size_bytes as i64,
                validated.sender_receiver,
                validated.timestamp_unix_ms,
                validated.direction as i32,
                validated.status as i32,
                file_path_str,
            ],
        )
        .await
        .context("failed to insert history entry")?;

        Ok(())
    }

    pub async fn get_entries_paginated(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<HistoryEntry>> {
        let limit = limit.min(MAX_PAGE_SIZE);
        let _permit = self.read_sem.acquire().await?;
        let conn = self.conn.lock().await;

        let mut rows = conn
            .query(
                "SELECT id, file_name, size_bytes, sender_receiver, timestamp_unix_ms, direction, status, file_path
                 FROM history
                 ORDER BY timestamp_unix_ms DESC
                 LIMIT ? OFFSET ?",
                libsql::params![limit as i64, offset as i64],
            )
            .await?;

        let mut entries = Vec::with_capacity(limit);
        while let Some(row) = rows.next().await? {
            let entry = self.row_to_history_entry(&row)?;
            entries.push(entry);
        }

        Ok(entries)
    }

    pub async fn get_all_entries(&self) -> Result<Vec<HistoryEntry>> {
        self.get_entries_paginated(0, MAX_PAGE_SIZE).await
    }

    fn row_to_history_entry(&self, row: &libsql::Row) -> Result<HistoryEntry> {
        let size_bytes_i64: i64 = row.get(2)?;
        if size_bytes_i64 < 0 {
            bail!("corrupted data: negative size_bytes");
        }

        let timestamp_unix_ms: i64 = row.get(4)?;
        let timestamp = chrono::DateTime::from_timestamp_millis(timestamp_unix_ms)
            .context("invalid timestamp")?
            .to_rfc3339();

        let direction_i32: i32 = row.get::<i64>(5)? as i32;
        let status_i32: i32 = row.get::<i64>(6)? as i32;

        TransferDirection::from_i32(direction_i32).context("invalid direction in db")?;
        CheckpointStatus::from_i32(status_i32).context("invalid status in db")?;

        let file_path: Option<String> = row.get(7)?;

        Ok(HistoryEntry {
            id: row.get(0)?,
            file_name: row.get(1)?,
            size_bytes: size_bytes_i64 as u64,
            sender_receiver: row.get(3)?,
            timestamp,
            direction: direction_i32,
            status: status_i32,
            file_path: file_path.unwrap_or_default(),
        })
    }

    pub async fn clear_all(&self) -> Result<()> {
        let _permit = self.write_sem.acquire().await?;
        let conn = self.conn.lock().await;

        conn.execute("DELETE FROM history", ()).await?;
        conn.execute("DELETE FROM checkpoints", ()).await?;

        Ok(())
    }

    pub async fn save_checkpoint(&self, checkpoint: &TransferCheckpoint) -> Result<()> {
        checkpoint.validate()?;

        let chunks_blob = self.encode_chunks(&checkpoint.completed_chunks)?;
        let file_path_str = checkpoint
            .file_path
            .to_str()
            .context("file_path is not valid UTF-8")?;

        let _permit = self.write_sem.acquire().await?;
        let conn = self.conn.lock().await;

        conn.execute(
            "INSERT INTO checkpoints
             (transfer_id, file_path, file_name, total_bytes, bytes_transferred,
              target_device_id, direction, status, created_at_unix_ms, updated_at_unix_ms,
              chunk_size, completed_chunks)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(transfer_id) DO UPDATE SET
                bytes_transferred = CASE 
                    WHEN excluded.bytes_transferred >= checkpoints.bytes_transferred 
                    THEN excluded.bytes_transferred 
                    ELSE checkpoints.bytes_transferred 
                END,
                status = excluded.status,
                updated_at_unix_ms = excluded.updated_at_unix_ms,
                completed_chunks = CASE 
                    WHEN excluded.bytes_transferred >= checkpoints.bytes_transferred 
                    THEN excluded.completed_chunks 
                    ELSE checkpoints.completed_chunks 
                END",
            libsql::params![
                checkpoint.transfer_id.clone(),
                file_path_str,
                checkpoint.file_name.clone(),
                checkpoint.total_bytes as i64,
                checkpoint.bytes_transferred as i64,
                checkpoint.target_device_id.clone(),
                checkpoint.direction as i32,
                checkpoint.status as i32,
                checkpoint.created_at_unix_ms,
                checkpoint.updated_at_unix_ms,
                checkpoint.chunk_size as i64,
                chunks_blob,
            ],
        )
        .await
        .context("failed to save checkpoint")?;

        Ok(())
    }

    fn encode_chunks(&self, chunks: &[u64]) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(chunks.len() * 8);
        for &chunk in chunks {
            buf.extend_from_slice(&chunk.to_le_bytes());
        }
        Ok(buf)
    }

    pub async fn delete_checkpoint(&self, transfer_id: &str) -> Result<bool> {
        if transfer_id.len() > MAX_FIELD_LENGTH {
            bail!("transfer_id too long");
        }

        let _permit = self.write_sem.acquire().await?;
        let conn = self.conn.lock().await;

        let affected = conn
            .execute(
                "DELETE FROM checkpoints WHERE transfer_id = ?",
                [transfer_id.to_string()],
            )
            .await?;

        Ok(affected > 0)
    }

    pub async fn update_checkpoint_status(
        &self,
        transfer_id: &str,
        status: CheckpointStatus,
        bytes_transferred: u64,
    ) -> Result<bool> {
        if transfer_id.len() > MAX_FIELD_LENGTH {
            bail!("transfer_id too long");
        }

        let now_ms = chrono::Utc::now().timestamp_millis();

        let _permit = self.write_sem.acquire().await?;
        let conn = self.conn.lock().await;

        let affected = conn
            .execute(
                "UPDATE checkpoints
                 SET status = ?,
                 bytes_transferred = CASE WHEN ? >= bytes_transferred THEN ? ELSE bytes_transferred END,
                 updated_at_unix_ms = ?
                 WHERE transfer_id = ?",
                libsql::params![
                    status as i32,
                    bytes_transferred as i64,
                    bytes_transferred as i64,
                    now_ms,
                    transfer_id,
                ],
            )
            .await?;

        Ok(affected > 0)
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }
}

pub struct RemoteConfig {
    pub url: String,
    pub token: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn test_db() -> (HistoryDB, TempDir) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = HistoryDB::new(path, None::<RemoteConfig>).await.unwrap();
        (db, dir)
    }

    #[tokio::test]
    async fn test_entry_roundtrip() {
        let (db, _dir) = test_db().await;

        let entry = HistoryEntry {
            id: "test-1".into(),
            file_name: "file.txt".into(),
            size_bytes: 1024,
            sender_receiver: "peer-1".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            direction: TransferDirection::Outgoing as i32,
            status: CheckpointStatus::Completed as i32,
            file_path: "/tmp/file.txt".into(),
        };

        db.add_entry(entry.clone()).await.unwrap();

        let entries = db.get_all_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "test-1");
    }

    #[tokio::test]
    async fn test_rejects_invalid_entry() {
        let (db, _dir) = test_db().await;

        let entry = HistoryEntry {
            id: "".into(),
            file_name: "file.txt".into(),
            size_bytes: 1024,
            sender_receiver: "peer".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            direction: 0,
            status: 1,
            file_path: String::new(),
        };

        assert!(db.add_entry(entry).await.is_err());
    }

    #[tokio::test]
    async fn test_checkpoint_monotonic_progress() {
        let (db, _dir) = test_db().await;
        let now = chrono::Utc::now().timestamp_millis();

        let cp = TransferCheckpoint {
            transfer_id: "xfer-1".into(),
            file_path: "/tmp/big.bin".into(),
            file_name: "big.bin".into(),
            total_bytes: 1_000_000,
            bytes_transferred: 500_000,
            target_device_id: "peer-1".into(),
            direction: TransferDirection::Outgoing,
            status: CheckpointStatus::InProgress,
            created_at_unix_ms: now,
            updated_at_unix_ms: now,
            chunk_size: 10 * 1024 * 1024,
            completed_chunks: vec![0, 1, 2, 3, 4],
        };

        db.save_checkpoint(&cp).await.unwrap();

        db.update_checkpoint_status("xfer-1", CheckpointStatus::InProgress, 100_000)
            .await
            .unwrap();

        let loaded_bytes = {
            let _permit = db.read_sem.acquire().await.unwrap();
            let conn = db.conn.lock().await;
            let mut rows = conn
                .query(
                    "SELECT bytes_transferred FROM checkpoints WHERE transfer_id = ?",
                    ["xfer-1".to_string()],
                )
                .await
                .unwrap();
            if let Some(row) = rows.next().await.unwrap() {
                let val: i64 = row.get(0).unwrap();
                val as u64
            } else {
                0
            }
        };
        assert_eq!(loaded_bytes, 500_000);
    }
}
