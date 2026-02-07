//! Iroh Engine for P2P File Transfer
//! 
//! Uses iroh-blobs 0.35.x (stable API) for production use.

use iroh::Endpoint;
use iroh::protocol::Router;
use iroh_blobs::net_protocol::Blobs;
use iroh_blobs::store::fs::Store as FsStore;
use iroh_blobs::ticket::BlobTicket;
use iroh_blobs::util::SetTagOption;
use iroh_blobs::rpc::client::blobs::{WrapOption};
use iroh_blobs::store::ExportFormat;
use anyhow::{Result, Context, anyhow};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use futures::StreamExt;
use rand::RngCore;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use uuid::Uuid;
use crate::crypto::{self, SessionKey};

use crate::types::{TransferStatus, TransferDirection};

/// Transfer progress information (internal type)
#[derive(Clone, Debug)]
pub struct TransferProgress {
    pub transfer_id: String,
    pub file_name: String,
    pub progress: f64,
    pub speed_mbps: f64,
    pub bytes_transferred: u64,
    pub total_bytes: u64,
    pub status: i32,
    pub direction: i32,
    pub error_message: String,
}

/// Engine for P2P file transfers using Iroh
pub struct IrohEngine {
    pub endpoint: Endpoint,
    #[allow(dead_code)]
    router: Router,
    blobs: Arc<Blobs<FsStore>>,
    progress_tx: mpsc::Sender<TransferProgress>,
}

impl IrohEngine {
    pub async fn new(
        progress_tx: mpsc::Sender<TransferProgress>,
        blob_dir: PathBuf,
    ) -> Result<Self> {
        let endpoint = Endpoint::builder().discovery_n0().bind().await?;
        
        tokio::fs::create_dir_all(&blob_dir).await.context("failed to create blob dir")?;
        
        let store = FsStore::load(&blob_dir).await?;
        
        // PROBE: Identify correct Blobs constructor
        // Blobs::new is private.
        // We suspect memory() works but we need persistent.
        
        // Check if Blobs::persistent exists
        // let _ = Blobs::persistent(store.clone()); // Uncomment to test
        
        // Check if from_store exists
        // let _ = Blobs::from_store(store.clone(), endpoint.clone());
        
        // For now, I will try to use `Blobs::builder(store).build(&endpoint)` again? 
        // No, `Blobs` has no builder method according to previous errors? Wait, previous error said "calling private function new".
        // It didn't say "no builder".
        
        // Use a placeholder that will definitely fail compilation with a USEFUL message if method missing, 
        // or succeed if valid. 
        
        // I'll try `Blobs::persistent` as my best guess for 0.35.
        // If not, I'll fall back to searching documentation via blind guesses.
        
        // Actually, if `Blobs` struct is in `net_protocol`, maybe I can construct it? No, fields private.
        
        // Attempt:
        // let blobs = Arc::new(Blobs::persistent(store)); // Assuming this attaches to endpoint later? 
         // But Router needs `Blobs<S>` implementing ProtocolHandler.
         // Blobs::persistent likely returns `Blobs<FsStore>`.
         
        // I will implement a "Try-all" block if I could, but in Rust I pick one.
        
        // Re-attempt `Blobs::new` indirectly via `Blobs::from`?
        // iroh-blobs 0.35: `Blobs::new(store, endpoint)` ? Private.
        
        // I'll try `Blobs::builder(store).start(endpoint)`?
        
        // I'll search for `Blobs` source code via error reflection?
        // Trying `Blobs::persistent(store, &endpoint)`. (Made up).
        
        // Let's go with `Blobs::builder(store).build(&endpoint).await?`
        // I will assume `builder` was not found before because of context? 
        // Wait, did I actually try `builder`?
        // Step 219 code used `builder`.
        // Step 220 error: `Blobs<Store> is not a future`.
        // This implies `build()` returned `Blobs<Store>` synchronously and `await` failed.
        // THIS MEANS `builder` pattern WORKED! 
        // The error was just the `.await`!
        // So `Blobs::builder(store).build(&endpoint)` returns `Blobs`.
        
        let blobs = Arc::new(
             Blobs::builder(store)
                 .build(&endpoint)
        );
        
        let router = Router::builder(endpoint.clone())
            .accept(iroh_blobs::ALPN, blobs.clone())
            .spawn();
            
        Ok(Self {
            endpoint,
            router,
            blobs,
            progress_tx,
        })
    }
    
    pub async fn send_file_internal(
        &self,
        transfer_id: String,
        path: PathBuf,
        original_name: Option<String>,
    ) -> Result<String> {
        if !path.exists() {
            return Err(anyhow::anyhow!("File does not exist: {:?}", path));
        }
        
        let file_name = original_name.unwrap_or_else(|| {
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string()
        });
            
        let metadata = tokio::fs::metadata(&path).await?;
        let total_bytes = metadata.len();
        
         let _ = self.progress_tx.send(TransferProgress {
            transfer_id: transfer_id.clone(),
            file_name: file_name.clone(),
            progress: 0.0,
            speed_mbps: 0.0,
            bytes_transferred: 0,
            total_bytes,
            status: TransferStatus::InProgress as i32,
            direction: TransferDirection::Outgoing as i32,
            error_message: String::new(),
        }).await;
        
        let client = self.blobs.client();
        
        let stream = client.add_from_path(
            path,
            false,
            SetTagOption::Auto, 
            WrapOption::NoWrap,
        ).await.context("failed to add file to blob store")?;
        
        let mut stream = stream;
        let mut hash = None;
        let mut format = None;
        let mut bytes_transferred: u64 = 0;
        let started_at = std::time::Instant::now();
        
        while let Some(item) = stream.next().await {
            use iroh_blobs::provider::AddProgress;
            match item? {
                AddProgress::Found { size, .. } => {
                    bytes_transferred = 0;
                    let _ = self.progress_tx.send(TransferProgress {
                        transfer_id: transfer_id.clone(),
                        file_name: file_name.clone(),
                        progress: 0.0,
                        speed_mbps: 0.0,
                        bytes_transferred,
                        total_bytes: size,
                        status: TransferStatus::InProgress as i32,
                        direction: TransferDirection::Outgoing as i32,
                        error_message: String::new(),
                    }).await;
                }
                AddProgress::Progress { offset, .. } => {
                    bytes_transferred = offset.min(total_bytes);
                    let elapsed = started_at.elapsed().as_secs_f64().max(0.001);
                    let speed_mbps = (bytes_transferred as f64 / elapsed) / (1024.0 * 1024.0);
                    let progress = if total_bytes == 0 {
                        0.0
                    } else {
                        (bytes_transferred as f64 / total_bytes as f64).clamp(0.0, 1.0)
                    };

                    let _ = self.progress_tx.send(TransferProgress {
                        transfer_id: transfer_id.clone(),
                        file_name: file_name.clone(),
                        progress,
                        speed_mbps,
                        bytes_transferred,
                        total_bytes,
                        status: TransferStatus::InProgress as i32,
                        direction: TransferDirection::Outgoing as i32,
                        error_message: String::new(),
                    }).await;
                }
                AddProgress::Done { .. } => {}
                AddProgress::AllDone { hash: h, format: f, .. } => {
                    hash = Some(h);
                    format = Some(f);
                }
                AddProgress::Abort(e) => {
                    return Err(anyhow!("Add operation aborted: {}", e));
                }
            }
        }
        
        let hash = hash.context("failed to get hash from add operation")?;
        let format = format.context("failed to get format from add operation")?;

        let elapsed = started_at.elapsed().as_secs_f64().max(0.001);
        let speed_mbps = (total_bytes as f64 / elapsed) / (1024.0 * 1024.0);

        let _ = self.progress_tx.send(TransferProgress {
            transfer_id,
            file_name: file_name.clone(),
            progress: 1.0,
            speed_mbps,
            bytes_transferred: total_bytes,
            total_bytes,
            status: TransferStatus::Completed as i32,
            direction: TransferDirection::Outgoing as i32,
            error_message: String::new(),
        }).await;
        
        let node_addr = self.endpoint.node_addr().await?;
        let ticket = BlobTicket::new(node_addr, hash, format)?;
        
        Ok(ticket.to_string())
    }
    
    pub async fn send_file(&self, transfer_id: String, path: PathBuf) -> Result<String> {
        let original_name = path.file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string());

        // Generate session key and encrypt
        let mut key_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let session_key = SessionKey::from_bytes(key_bytes);
        
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join(format!("flatdrop_enc_{}", Uuid::new_v4()));
        
        tracing::info!("Encrypting file to {:?}", temp_path);
        crypto::encrypt_file(&path, &temp_path, &session_key).await
             .context("encryption failed")?;
             
        // Send the encrypted file
        // We pass the original name so progress updates look correct
        let ticket = self.send_file_internal(transfer_id, temp_path.clone(), original_name).await?;
        
        // Clean up temp file
        let _ = tokio::fs::remove_file(temp_path).await;
        
        // Append key to ticket: ticket|base64_key
        let key_b64 = BASE64.encode(session_key.as_bytes());
        Ok(format!("{}|{}", ticket, key_b64))
    }
    
    pub async fn receive_file(
        &self,
        transfer_id: String,
        ticket_str: String,
        output_dir: PathBuf,
    ) -> Result<PathBuf> {
        let (actual_ticket_str, session_key) = if let Some((t, k_str)) = ticket_str.split_once('|') {
             let key_bytes_vec = BASE64.decode(k_str).context("invalid base64 key")?;
             let mut key_bytes = [0u8; 32];
             if key_bytes_vec.len() != 32 {
                 return Err(anyhow!("invalid key length"));
             }
             key_bytes.copy_from_slice(&key_bytes_vec);
             (t, Some(SessionKey::from_bytes(key_bytes)))
        } else {
             (ticket_str.as_str(), None)
        };
    
        let ticket: BlobTicket = actual_ticket_str.parse()
            .map_err(|e| anyhow::anyhow!("Invalid ticket: {}", e))?;
        
        let hash = ticket.hash();
        
        let client = self.blobs.client();
        let node_addr = ticket.node_addr().clone();
        
        let started_at = std::time::Instant::now();
        client.download(hash, node_addr).await?;
        
        // If encrypted, download to temp first
        let final_file_name = format!("received_{}", hash.to_hex());
        let final_output_path = output_dir.join(&final_file_name);
        
        if let Some(key) = session_key {
             let temp_dir = std::env::temp_dir();
             let temp_path = temp_dir.join(format!("flatdrop_dec_temp_{}", Uuid::new_v4()));
             
             // Export encrypted blob to temp file
             client
                .export(
                    hash,
                    temp_path.clone(),
                    ExportFormat::Blob,
                    iroh_blobs::store::ExportMode::Copy,
                )
                .await
                .context("failed to export blob to temp file")?;
                
             // Decrypt
             tracing::info!("Decrypting file to {:?}", final_output_path);
             crypto::decrypt_file(&temp_path, &final_output_path, &key).await
                 .context("decryption failed")?;
                 
             // Clean up temp
             let _ = tokio::fs::remove_file(temp_path).await;
        } else {
             // Legacy/Plaintext
             client
                .export(
                    hash,
                    final_output_path.clone(),
                    ExportFormat::Blob,
                    iroh_blobs::store::ExportMode::Copy,
                )
                .await
                .context("failed to export blob to file")?;
        }

        let metadata = tokio::fs::metadata(&final_output_path)
            .await
            .context("failed to stat exported file")?;
        let total_bytes = metadata.len();
 
        let elapsed = started_at.elapsed().as_secs_f64().max(0.001);
        let speed_mbps = (total_bytes as f64 / elapsed) / (1024.0 * 1024.0);

        let file_name = final_output_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        let _ = self
            .progress_tx
            .send(TransferProgress {
                transfer_id,
                file_name,
                progress: 1.0,
                speed_mbps,
                bytes_transferred: total_bytes,
                total_bytes,
                status: TransferStatus::Completed as i32,
                direction: TransferDirection::Incoming as i32,
                error_message: String::new(),
            })
            .await;
        
        Ok(final_output_path)
    }
    
    pub async fn shutdown(self) -> Result<()> {
        self.router.shutdown().await?;
        Ok(())
    }
}
