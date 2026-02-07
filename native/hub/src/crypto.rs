//! P2P Encryption for FlatDrop file transfers
//!
//! End-to-End Encryption (E2EE) using modern cryptographic primitives:
//! - X25519 for ephemeral Diffie-Hellman key exchange (Forward Secrecy)
//! - HKDF-SHA256 for session key derivation with public key binding
//! - XChaCha20-Poly1305 for authenticated encryption with AAD
//! - Stream-level authentication preventing truncation and reordering
//! - Protocol versioning for forward compatibility

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    Key, Tag, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::sync::Semaphore;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::{Zeroize, Zeroizing};

pub const PROTOCOL_VERSION: u8 = 1;
pub const NONCE_SIZE: usize = 24;
pub const TAG_SIZE: usize = 16;
pub const STREAM_NONCE_PREFIX_SIZE: usize = 16;
pub const ENCRYPTION_CHUNK_SIZE: usize = 64 * 1024;
pub const MAX_CHUNK_SIZE: usize = ENCRYPTION_CHUNK_SIZE + TAG_SIZE;
pub const MAX_CHUNKS: u64 = 1_000_000;
pub const MAX_FILE_SIZE: u64 = MAX_CHUNKS * ENCRYPTION_CHUNK_SIZE as u64;
pub const MAX_MESSAGE_SIZE: usize = 65536;
pub const MAX_ENCRYPTED_MESSAGE_SIZE: usize = MAX_MESSAGE_SIZE + NONCE_SIZE + TAG_SIZE;

const DEFAULT_MAX_CONCURRENT_FILE_OPS: usize = 64;
const HKDF_INFO: &[u8] = b"flatdrop-p2p-file-transfer-v1";
const STREAM_MAGIC: &[u8; 8] = b"FLATDROP";

const SMALL_ORDER_POINTS: [[u8; 32]; 12] = [
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae,
     0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
     0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd,
     0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00],
    [0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24,
     0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
     0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86,
     0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57],
    [0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    [0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    [0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    [0xd9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    [0xda, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    [0xdb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    [0xdc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    [0xdd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
];

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("invalid public key: {reason}")]
    InvalidPublicKey { reason: &'static str },

    #[error("key derivation failed")]
    KeyDerivationFailed,

    #[error("encryption failed")]
    EncryptionFailed,

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("invalid stream format: {reason}")]
    InvalidStreamFormat { reason: &'static str },

    #[error("stream was truncated")]
    StreamTruncated,

    #[error("resource limit exceeded: {reason}")]
    LimitExceeded { reason: &'static str },

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("async task failed")]
    TaskFailed,

    #[error("stream already finalized")]
    AlreadyFinalized,

    #[error("entropy source unavailable")]
    EntropyFailure,

    #[error("operation cancelled")]
    Cancelled,
}

pub type Result<T> = std::result::Result<T, CryptoError>;

pub struct CryptoConfig {
    pub max_concurrent_ops: usize,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            max_concurrent_ops: DEFAULT_MAX_CONCURRENT_FILE_OPS,
        }
    }
}

pub struct CryptoRuntime {
    semaphore: Arc<Semaphore>,
}

impl CryptoRuntime {
    pub fn new(config: CryptoConfig) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(config.max_concurrent_ops)),
        }
    }

    pub fn semaphore(&self) -> &Arc<Semaphore> {
        &self.semaphore
    }
}

impl Default for CryptoRuntime {
    fn default() -> Self {
        Self::new(CryptoConfig::default())
    }
}

pub struct EphemeralKeyPair {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl EphemeralKeyPair {
    pub fn generate() -> Result<Self> {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Ok(Self { secret, public })
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    pub fn public_key_b64(&self) -> String {
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            self.public.as_bytes(),
        )
    }

    pub fn derive_shared_key(self, their_public_b64: &str) -> Result<SessionKey> {
        let their_public_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            their_public_b64,
        )
        .map_err(|_| CryptoError::InvalidPublicKey {
            reason: "invalid base64 encoding",
        })?;

        if their_public_bytes.len() != 32 {
            return Err(CryptoError::InvalidPublicKey {
                reason: "invalid key length",
            });
        }

        let mut their_bytes = [0u8; 32];
        their_bytes.copy_from_slice(&their_public_bytes);

        validate_public_key(&their_bytes)?;

        let their_public = PublicKey::from(their_bytes);
        let our_public_bytes = *self.public.as_bytes();

        let shared_secret = self.secret.diffie_hellman(&their_public);
        let mut ss_bytes = Zeroizing::new([0u8; 32]);
        ss_bytes.copy_from_slice(shared_secret.as_bytes());

        let is_zero = ss_bytes.iter().fold(0u8, |acc, &b| acc | b);
        if is_zero == 0 {
            return Err(CryptoError::InvalidPublicKey {
                reason: "degenerate shared secret",
            });
        }

        let (first_pub, second_pub) = if our_public_bytes < their_bytes {
            (&our_public_bytes, &their_bytes)
        } else {
            (&their_bytes, &our_public_bytes)
        };

        let mut ikm = Zeroizing::new(Vec::with_capacity(96));
        ikm.extend_from_slice(&*ss_bytes);
        ikm.extend_from_slice(first_pub);
        ikm.extend_from_slice(second_pub);

        let salt = Sha256::digest(b"flatdrop-session-salt-v1");

        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut session_key_bytes = Zeroizing::new([0u8; 32]);
        hk.expand(HKDF_INFO, session_key_bytes.as_mut())
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        Ok(SessionKey::new(*session_key_bytes))
    }
}

fn validate_public_key(key: &[u8; 32]) -> Result<()> {
    let mut is_bad = 0u8;
    for bad_point in &SMALL_ORDER_POINTS {
        is_bad |= key.ct_eq(bad_point).unwrap_u8();
    }
    if is_bad != 0 {
        return Err(CryptoError::InvalidPublicKey {
            reason: "rejected small-order point",
        });
    }
    Ok(())
}

pub struct SessionKey {
    key: Zeroizing<[u8; 32]>,
}

impl SessionKey {
    fn new(bytes: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(bytes),
        }
    }

    #[cfg(all(feature = "dangerous-raw-keys", debug_assertions))]
    pub fn from_bytes_unchecked(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }

    #[cfg(test)]
    pub fn from_bytes_unchecked(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }

    pub fn encryptor(&self) -> Result<StreamEncryptor> {
        StreamEncryptor::new(&self.key)
    }

    pub fn decryptor(&self) -> StreamDecryptor {
        StreamDecryptor::new(&self.key)
    }

    pub fn encrypt_message(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_MESSAGE_SIZE {
            return Err(CryptoError::LimitExceeded {
                reason: "message exceeds 64KB limit",
            });
        }

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&*self.key));

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng
            .try_fill_bytes(&mut nonce_bytes)
            .map_err(|_| CryptoError::EntropyFailure)?;
        let nonce = XNonce::from_slice(&nonce_bytes);

        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce, &[], &mut buffer)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        let mut combined = Vec::with_capacity(NONCE_SIZE + buffer.len() + TAG_SIZE);
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&buffer);
        combined.extend_from_slice(&tag);
        Ok(combined)
    }

    pub fn decrypt_message(&self, combined: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if combined.len() < NONCE_SIZE + TAG_SIZE {
            return Err(CryptoError::DecryptionFailed);
        }

        if combined.len() > MAX_ENCRYPTED_MESSAGE_SIZE {
            return Err(CryptoError::LimitExceeded {
                reason: "message exceeds maximum size",
            });
        }

        let nonce_bytes = &combined[..NONCE_SIZE];
        let ciphertext = &combined[NONCE_SIZE..combined.len() - TAG_SIZE];
        let tag_bytes = &combined[combined.len() - TAG_SIZE..];

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&*self.key));
        let nonce = XNonce::from_slice(nonce_bytes);
        let tag = Tag::from_slice(tag_bytes);

        let mut buffer = Zeroizing::new(ciphertext.to_vec());
        cipher
            .decrypt_in_place_detached(nonce, &[], &mut buffer, tag)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        Ok(buffer)
    }
}

#[derive(Clone)]
struct StreamHeader {
    version: u8,
    nonce_prefix: [u8; STREAM_NONCE_PREFIX_SIZE],
}

impl StreamHeader {
    const SIZE: usize = 8 + 1 + STREAM_NONCE_PREFIX_SIZE + 3;

    fn generate() -> Result<Self> {
        let mut nonce_prefix = [0u8; STREAM_NONCE_PREFIX_SIZE];
        OsRng
            .try_fill_bytes(&mut nonce_prefix)
            .map_err(|_| CryptoError::EntropyFailure)?;
        Ok(Self {
            version: PROTOCOL_VERSION,
            nonce_prefix,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let mut header = [0u8; Self::SIZE];
        header[0..8].copy_from_slice(STREAM_MAGIC);
        header[8] = self.version;
        header[9..25].copy_from_slice(&self.nonce_prefix);
        writer.write_all(&header)?;
        Ok(())
    }

    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let mut header = [0u8; Self::SIZE];
        reader.read_exact(&mut header).map_err(|_| CryptoError::DecryptionFailed)?;

        let mut magic_match = 0u8;
        for (a, b) in header[0..8].iter().zip(STREAM_MAGIC.iter()) {
            magic_match |= a ^ b;
        }
        if magic_match != 0 {
            return Err(CryptoError::DecryptionFailed);
        }

        let version = header[8];
        if version != PROTOCOL_VERSION {
            return Err(CryptoError::DecryptionFailed);
        }

        let mut nonce_prefix = [0u8; STREAM_NONCE_PREFIX_SIZE];
        nonce_prefix.copy_from_slice(&header[9..25]);

        let mut reserved_check = 0u8;
        for &b in &header[25..28] {
            reserved_check |= b;
        }
        if reserved_check != 0 {
            return Err(CryptoError::DecryptionFailed);
        }

        Ok(Self {
            version,
            nonce_prefix,
        })
    }
}

#[derive(Clone, Copy)]
struct ChunkAad {
    chunk_index: u64,
    is_final: bool,
    version: u8,
}

impl ChunkAad {
    const SIZE: usize = 10;

    fn new(chunk_index: u64, is_final: bool, version: u8) -> Self {
        Self {
            chunk_index,
            is_final,
            version,
        }
    }

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut aad = [0u8; Self::SIZE];
        aad[..8].copy_from_slice(&self.chunk_index.to_le_bytes());
        aad[8] = if self.is_final { 1 } else { 0 };
        aad[9] = self.version;
        aad
    }
}

pub struct StreamEncryptor {
    key: Zeroizing<[u8; 32]>,
    header: StreamHeader,
    chunk_counter: u64,
    total_plaintext_bytes: u64,
    finalized: bool,
}

impl Drop for StreamEncryptor {
    fn drop(&mut self) {
        self.header.nonce_prefix.zeroize();
    }
}

impl StreamEncryptor {
    fn new(key: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            key: Zeroizing::new(*key),
            header: StreamHeader::generate()?,
            chunk_counter: 0,
            total_plaintext_bytes: 0,
            finalized: false,
        })
    }

    fn build_nonce(&self) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[..STREAM_NONCE_PREFIX_SIZE].copy_from_slice(&self.header.nonce_prefix);
        nonce[STREAM_NONCE_PREFIX_SIZE..].copy_from_slice(&self.chunk_counter.to_le_bytes());
        nonce
    }

    fn encrypt_chunk_into(
        &mut self,
        plaintext: &[u8],
        is_final: bool,
        output: &mut Vec<u8>,
    ) -> Result<()> {
        if self.finalized {
            return Err(CryptoError::AlreadyFinalized);
        }

        if self.chunk_counter >= MAX_CHUNKS {
            return Err(CryptoError::LimitExceeded {
                reason: "maximum chunk count exceeded",
            });
        }

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&*self.key));
        let nonce_bytes = self.build_nonce();
        let nonce = XNonce::from_slice(&nonce_bytes);
        let aad = ChunkAad::new(self.chunk_counter, is_final, PROTOCOL_VERSION);

        let len_offset = output.len();
        output.extend_from_slice(&[0u8; 4]);
        let data_offset = output.len();
        output.extend_from_slice(plaintext);

        let tag = cipher
            .encrypt_in_place_detached(nonce, &aad.to_bytes(), &mut output[data_offset..])
            .map_err(|_| CryptoError::EncryptionFailed)?;

        output.extend_from_slice(&tag);

        let chunk_len = (output.len() - data_offset) as u32;
        output[len_offset..len_offset + 4].copy_from_slice(&chunk_len.to_le_bytes());

        self.chunk_counter += 1;
        self.total_plaintext_bytes += plaintext.len() as u64;

        if is_final {
            self.finalized = true;
        }

        Ok(())
    }

    pub fn encrypt_stream<R: Read, W: Write>(
        &mut self,
        mut reader: R,
        mut writer: W,
    ) -> Result<u64> {
        self.encrypt_stream_cancellable(&mut reader, &mut writer, None)
    }

    pub fn encrypt_stream_cancellable<R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        cancel: Option<&AtomicBool>,
    ) -> Result<u64> {
        self.header.write_to(writer)?;

        let mut plaintext_buf = Zeroizing::new(vec![0u8; ENCRYPTION_CHUNK_SIZE]);
        let mut write_buf = Vec::with_capacity(4 + MAX_CHUNK_SIZE);

        loop {
            if let Some(c) = cancel {
                if c.load(Ordering::Relaxed) {
                    return Err(CryptoError::Cancelled);
                }
            }

            let bytes_read = read_full(reader, &mut plaintext_buf)?;

            if bytes_read == 0 {
                write_buf.clear();
                self.encrypt_chunk_into(&[], true, &mut write_buf)?;
                writer.write_all(&write_buf)?;
                break;
            }

            if self.total_plaintext_bytes + bytes_read as u64 > MAX_FILE_SIZE {
                return Err(CryptoError::LimitExceeded {
                    reason: "maximum file size exceeded",
                });
            }

            write_buf.clear();
            self.encrypt_chunk_into(&plaintext_buf[..bytes_read], false, &mut write_buf)?;
            writer.write_all(&write_buf)?;
        }

        writer.flush()?;
        Ok(self.total_plaintext_bytes)
    }

    pub fn chunks_written(&self) -> u64 {
        self.chunk_counter
    }

    pub fn bytes_written(&self) -> u64 {
        self.total_plaintext_bytes
    }
}

pub struct StreamDecryptor {
    key: Zeroizing<[u8; 32]>,
    header: Option<StreamHeader>,
    chunk_counter: u64,
    total_plaintext_bytes: u64,
    finalized: bool,
}

impl Drop for StreamDecryptor {
    fn drop(&mut self) {
        if let Some(ref mut h) = self.header {
            h.nonce_prefix.zeroize();
        }
    }
}

impl StreamDecryptor {
    fn new(key: &[u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(*key),
            header: None,
            chunk_counter: 0,
            total_plaintext_bytes: 0,
            finalized: false,
        }
    }

    fn build_nonce(&self) -> [u8; NONCE_SIZE] {
        let header = self.header.as_ref().expect("header must be read first");
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[..STREAM_NONCE_PREFIX_SIZE].copy_from_slice(&header.nonce_prefix);
        nonce[STREAM_NONCE_PREFIX_SIZE..].copy_from_slice(&self.chunk_counter.to_le_bytes());
        nonce
    }

    fn decrypt_chunk_internal(
        &mut self,
        ciphertext: &[u8],
        is_final: bool,
        output: &mut Zeroizing<Vec<u8>>,
    ) -> Result<()> {
        if self.finalized {
            return Err(CryptoError::AlreadyFinalized);
        }

        if self.chunk_counter >= MAX_CHUNKS {
            return Err(CryptoError::LimitExceeded {
                reason: "maximum chunk count exceeded",
            });
        }

        if ciphertext.len() < TAG_SIZE {
            return Err(CryptoError::DecryptionFailed);
        }

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&*self.key));
        let nonce_bytes = self.build_nonce();
        let nonce = XNonce::from_slice(&nonce_bytes);
        let aad = ChunkAad::new(self.chunk_counter, is_final, PROTOCOL_VERSION);

        let (data, tag_bytes) = ciphertext.split_at(ciphertext.len() - TAG_SIZE);
        let tag = Tag::from_slice(tag_bytes);

        let start = output.len();
        output.extend_from_slice(data);

        cipher
            .decrypt_in_place_detached(nonce, &aad.to_bytes(), &mut output[start..], tag)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        self.chunk_counter += 1;
        self.total_plaintext_bytes += (ciphertext.len() - TAG_SIZE) as u64;

        if is_final {
            self.finalized = true;
        }

        Ok(())
    }

    pub fn decrypt_stream<R: Read, W: Write>(
        &mut self,
        mut reader: R,
        mut writer: W,
    ) -> Result<u64> {
        self.decrypt_stream_cancellable(&mut reader, &mut writer, None)
    }

    pub fn decrypt_stream_cancellable<R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        cancel: Option<&AtomicBool>,
    ) -> Result<u64> {
        self.header = Some(StreamHeader::read_from(reader)?);

        let mut len_buf = [0u8; 4];
        let mut chunk_buf = Zeroizing::new(Vec::with_capacity(MAX_CHUNK_SIZE));
        let mut plaintext_buf = Zeroizing::new(Vec::with_capacity(ENCRYPTION_CHUNK_SIZE));

        loop {
            if let Some(c) = cancel {
                if c.load(Ordering::Relaxed) {
                    return Err(CryptoError::Cancelled);
                }
            }

            if reader.read_exact(&mut len_buf).is_err() {
                return Err(CryptoError::DecryptionFailed);
            }

            let chunk_len = u32::from_le_bytes(len_buf) as usize;

            if chunk_len > MAX_CHUNK_SIZE {
                return Err(CryptoError::LimitExceeded {
                    reason: "chunk size exceeds maximum",
                });
            }

            chunk_buf.resize(chunk_len, 0);
            if reader.read_exact(&mut chunk_buf).is_err() {
                return Err(CryptoError::DecryptionFailed);
            }

            let is_final = chunk_len == TAG_SIZE;

            plaintext_buf.clear();
            self.decrypt_chunk_internal(&chunk_buf, is_final, &mut plaintext_buf)?;

            if is_final {
                if !plaintext_buf.is_empty() {
                    return Err(CryptoError::DecryptionFailed);
                }
                break;
            }

            writer.write_all(&plaintext_buf)?;

            if self.total_plaintext_bytes > MAX_FILE_SIZE {
                return Err(CryptoError::LimitExceeded {
                    reason: "maximum file size exceeded",
                });
            }
        }

        if !self.finalized {
            return Err(CryptoError::DecryptionFailed);
        }

        writer.flush()?;
        Ok(self.total_plaintext_bytes)
    }

    pub fn chunks_read(&self) -> u64 {
        self.chunk_counter
    }

    pub fn bytes_read(&self) -> u64 {
        self.total_plaintext_bytes
    }
}

fn generate_temp_path(output_path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut unique_id = [0u8; 16];
    let _ = OsRng.try_fill_bytes(&mut unique_id);
    let id_hex = hex::encode(unique_id);

    let file_name = output_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());

    output_path.with_file_name(format!(".{}.{}.{}", file_name, id_hex, suffix))
}

pub async fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    session_key: &SessionKey,
    runtime: &CryptoRuntime,
    cancel: Option<Arc<AtomicBool>>,
) -> Result<u64> {
    let _permit = runtime
        .semaphore()
        .acquire()
        .await
        .map_err(|_| CryptoError::TaskFailed)?;

    let input_path = input_path.to_path_buf();
    let output_path = output_path.to_path_buf();
    let temp_path = generate_temp_path(&output_path, "tmp.enc");
    let temp_path_for_task = temp_path.clone();
    let temp_path_for_rename = temp_path.clone();
    let temp_path_for_cleanup = temp_path.clone();
    let output_path_for_rename = output_path.clone();

    let mut encryptor = session_key.encryptor()?;

    let result = tokio::task::spawn_blocking(move || {
        let input_file = std::fs::File::open(&input_path)?;
        let input = BufReader::with_capacity(ENCRYPTION_CHUNK_SIZE, input_file);

        let output_file = std::fs::File::create(&temp_path_for_task)?;
        let mut output = BufWriter::with_capacity(ENCRYPTION_CHUNK_SIZE, output_file);

        let bytes = encryptor.encrypt_stream_cancellable(
            &mut BufReader::new(input),
            &mut output,
            cancel.as_ref().map(|a| a.as_ref()),
        )?;

        let inner = output.into_inner().map_err(|e| e.into_error())?;
        inner.sync_all()?;

        Ok::<u64, CryptoError>(bytes)
    })
    .await
    .map_err(|_| CryptoError::TaskFailed)?;

    match result {
        Ok(bytes) => {
            tokio::fs::rename(&temp_path_for_rename, &output_path_for_rename).await?;
            Ok(bytes)
        }
        Err(e) => {
            let _ = tokio::fs::remove_file(&temp_path_for_cleanup).await;
            Err(e)
        }
    }
}

pub async fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    session_key: &SessionKey,
    runtime: &CryptoRuntime,
    cancel: Option<Arc<AtomicBool>>,
) -> Result<u64> {
    let _permit = runtime
        .semaphore()
        .acquire()
        .await
        .map_err(|_| CryptoError::TaskFailed)?;

    let input_path = input_path.to_path_buf();
    let output_path = output_path.to_path_buf();
    let temp_path = generate_temp_path(&output_path, "tmp.dec");
    let temp_path_for_task = temp_path.clone();
    let temp_path_for_rename = temp_path.clone();
    let temp_path_for_cleanup = temp_path.clone();
    let output_path_for_rename = output_path.clone();

    let mut decryptor = session_key.decryptor();

    let result = tokio::task::spawn_blocking(move || {
        let input_file = std::fs::File::open(&input_path)?;
        let input = BufReader::with_capacity(ENCRYPTION_CHUNK_SIZE, input_file);

        let output_file = std::fs::File::create(&temp_path_for_task)?;
        let mut output = BufWriter::with_capacity(ENCRYPTION_CHUNK_SIZE, output_file);

        let bytes = decryptor.decrypt_stream_cancellable(
            &mut BufReader::new(input),
            &mut output,
            cancel.as_ref().map(|a| a.as_ref()),
        )?;

        let inner = output.into_inner().map_err(|e| e.into_error())?;
        inner.sync_all()?;

        Ok::<u64, CryptoError>(bytes)
    })
    .await
    .map_err(|_| CryptoError::TaskFailed)?;

    match result {
        Ok(bytes) => {
            tokio::fs::rename(&temp_path_for_rename, &output_path_for_rename).await?;
            Ok(bytes)
        }
        Err(e) => {
            let _ = tokio::fs::remove_file(&temp_path_for_cleanup).await;
            Err(e)
        }
    }
}

fn read_full<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<usize> {
    let mut total = 0;
    while total < buffer.len() {
        match reader.read(&mut buffer[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(CryptoError::IoError(e)),
        }
    }
    Ok(total)
}

#[cfg(all(feature = "dangerous-raw-keys", not(debug_assertions)))]
compile_error!("dangerous-raw-keys feature must not be used in release builds");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange_symmetric() {
        let alice = EphemeralKeyPair::generate().unwrap();
        let bob = EphemeralKeyPair::generate().unwrap();

        let alice_pub = alice.public_key_b64();
        let bob_pub = bob.public_key_b64();

        let alice_key = alice.derive_shared_key(&bob_pub).unwrap();
        let bob_key = bob.derive_shared_key(&alice_pub).unwrap();

        assert_eq!(*alice_key.key, *bob_key.key);
    }

    #[test]
    fn test_reject_zero_public_key() {
        let alice = EphemeralKeyPair::generate().unwrap();
        let zero = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &[0u8; 32],
        );

        let result = alice.derive_shared_key(&zero);
        assert!(matches!(result, Err(CryptoError::InvalidPublicKey { .. })));
    }

    #[test]
    fn test_reject_all_small_order_points() {
        for point in &SMALL_ORDER_POINTS {
            let result = validate_public_key(point);
            assert!(
                matches!(result, Err(CryptoError::InvalidPublicKey { .. })),
                "Failed to reject small-order point: {:?}",
                point
            );
        }
    }

    #[test]
    fn test_reject_invalid_base64() {
        let alice = EphemeralKeyPair::generate().unwrap();
        let result = alice.derive_shared_key("not-valid-base64!!!");
        assert!(matches!(result, Err(CryptoError::InvalidPublicKey { .. })));
    }

    #[test]
    fn test_reject_wrong_length_key() {
        let alice = EphemeralKeyPair::generate().unwrap();
        let short = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &[0u8; 16],
        );
        let result = alice.derive_shared_key(&short);
        assert!(matches!(result, Err(CryptoError::InvalidPublicKey { .. })));
    }

    #[test]
    fn test_encryptors_use_different_nonces() {
        let key = SessionKey::from_bytes_unchecked([42u8; 32]);
        let plaintext = b"identical message";

        let mut enc1 = key.encryptor().unwrap();
        let mut enc2 = key.encryptor().unwrap();

        let mut ct1 = Vec::new();
        let mut ct2 = Vec::new();
        enc1.encrypt_chunk_into(plaintext, true, &mut ct1).unwrap();
        enc2.encrypt_chunk_into(plaintext, true, &mut ct2).unwrap();

        assert_ne!(ct1, ct2, "CRITICAL: Nonce reuse detected!");
    }

    #[test]
    fn test_nonce_prefix_is_random() {
        let key = SessionKey::from_bytes_unchecked([42u8; 32]);

        let enc1 = key.encryptor().unwrap();
        let enc2 = key.encryptor().unwrap();

        assert_ne!(
            enc1.header.nonce_prefix, enc2.header.nonce_prefix,
            "Nonce prefixes must be random"
        );
    }

    #[test]
    fn test_roundtrip_empty() {
        let key = SessionKey::from_bytes_unchecked([1u8; 32]);
        let input: &[u8] = &[];
        let mut encrypted = Vec::new();

        key.encryptor()
            .unwrap()
            .encrypt_stream(input, &mut encrypted)
            .unwrap();

        let mut decrypted = Vec::new();
        key.decryptor()
            .decrypt_stream(&encrypted[..], &mut decrypted)
            .unwrap();

        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_roundtrip_small() {
        let key = SessionKey::from_bytes_unchecked([2u8; 32]);
        let input = b"Hello, World!";
        let mut encrypted = Vec::new();

        key.encryptor()
            .unwrap()
            .encrypt_stream(&input[..], &mut encrypted)
            .unwrap();

        let mut decrypted = Vec::new();
        key.decryptor()
            .decrypt_stream(&encrypted[..], &mut decrypted)
            .unwrap();

        assert_eq!(input.to_vec(), decrypted);
    }

    #[test]
    fn test_roundtrip_multi_chunk() {
        let key = SessionKey::from_bytes_unchecked([3u8; 32]);
        let input = vec![0xAB; ENCRYPTION_CHUNK_SIZE * 3 + ENCRYPTION_CHUNK_SIZE / 2];
        let mut encrypted = Vec::new();

        let bytes_enc = key
            .encryptor()
            .unwrap()
            .encrypt_stream(&input[..], &mut encrypted)
            .unwrap();
        assert_eq!(bytes_enc, input.len() as u64);

        let mut decrypted = Vec::new();
        let bytes_dec = key
            .decryptor()
            .decrypt_stream(&encrypted[..], &mut decrypted)
            .unwrap();
        assert_eq!(bytes_dec, input.len() as u64);
        assert_eq!(input, decrypted);
    }

    #[test]
    fn test_roundtrip_exact_chunk_boundary() {
        let key = SessionKey::from_bytes_unchecked([4u8; 32]);
        let input = vec![0xCD; ENCRYPTION_CHUNK_SIZE * 2];
        let mut encrypted = Vec::new();

        key.encryptor()
            .unwrap()
            .encrypt_stream(&input[..], &mut encrypted)
            .unwrap();

        let mut decrypted = Vec::new();
        key.decryptor()
            .decrypt_stream(&encrypted[..], &mut decrypted)
            .unwrap();

        assert_eq!(input, decrypted);
    }

    #[test]
    fn test_truncation_attack_fails() {
        let key = SessionKey::from_bytes_unchecked([5u8; 32]);
        let input = b"sensitive data".repeat(100);
        let mut encrypted = Vec::new();

        key.encryptor()
            .unwrap()
            .encrypt_stream(&input[..], &mut encrypted)
            .unwrap();

        let truncated = &encrypted[..encrypted.len() - 20];

        let mut decrypted = Vec::new();
        let result = key
            .decryptor()
            .decrypt_stream(truncated, &mut decrypted);

        assert!(result.is_err());
    }

    #[test]
    fn test_bit_flip_attack_fails() {
        let key = SessionKey::from_bytes_unchecked([7u8; 32]);
        let input = b"authenticated data";
        let mut encrypted = Vec::new();

        key.encryptor()
            .unwrap()
            .encrypt_stream(&input[..], &mut encrypted)
            .unwrap();

        let flip_pos = StreamHeader::SIZE + 4 + 10;
        encrypted[flip_pos] ^= 0x01;

        let mut decrypted = Vec::new();
        let result = key
            .decryptor()
            .decrypt_stream(&encrypted[..], &mut decrypted);

        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_header_corruption_fails() {
        let key = SessionKey::from_bytes_unchecked([8u8; 32]);
        let input = b"test";
        let mut encrypted = Vec::new();

        key.encryptor()
            .unwrap()
            .encrypt_stream(&input[..], &mut encrypted)
            .unwrap();

        encrypted[0] ^= 0xFF;

        let mut decrypted = Vec::new();
        let result = key
            .decryptor()
            .decrypt_stream(&encrypted[..], &mut decrypted);

        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = SessionKey::from_bytes_unchecked([9u8; 32]);
        let key2 = SessionKey::from_bytes_unchecked([10u8; 32]);

        let input = b"secret message";
        let mut encrypted = Vec::new();

        key1.encryptor()
            .unwrap()
            .encrypt_stream(&input[..], &mut encrypted)
            .unwrap();

        let mut decrypted = Vec::new();
        let result = key2
            .decryptor()
            .decrypt_stream(&encrypted[..], &mut decrypted);

        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_chunk_count_limit() {
        let key = SessionKey::from_bytes_unchecked([11u8; 32]);
        let mut enc = key.encryptor().unwrap();

        enc.chunk_counter = MAX_CHUNKS;

        let mut output = Vec::new();
        let result = enc.encrypt_chunk_into(b"test", false, &mut output);
        assert!(matches!(result, Err(CryptoError::LimitExceeded { .. })));
    }

    #[test]
    fn test_oversized_chunk_rejected() {
        let key = SessionKey::from_bytes_unchecked([12u8; 32]);

        let mut malicious = Vec::new();
        StreamHeader::generate().unwrap().write_to(&mut malicious).unwrap();

        let bad_len = (MAX_CHUNK_SIZE + 1000) as u32;
        malicious.extend_from_slice(&bad_len.to_le_bytes());
        malicious.extend(vec![0u8; bad_len as usize]);

        let mut decrypted = Vec::new();
        let result = key
            .decryptor()
            .decrypt_stream(&malicious[..], &mut decrypted);

        assert!(matches!(result, Err(CryptoError::LimitExceeded { .. })));
    }

    #[test]
    fn test_message_roundtrip() {
        let key = SessionKey::from_bytes_unchecked([13u8; 32]);
        let msg = b"metadata payload";

        let ct = key.encrypt_message(msg).unwrap();
        let pt = key.decrypt_message(&ct).unwrap();

        assert_eq!(msg.to_vec(), *pt);
    }

    #[test]
    fn test_message_too_large() {
        let key = SessionKey::from_bytes_unchecked([14u8; 32]);
        let big = vec![0u8; 70000];

        let result = key.encrypt_message(&big);
        assert!(matches!(result, Err(CryptoError::LimitExceeded { .. })));
    }

    #[test]
    fn test_decrypt_message_too_large() {
        let key = SessionKey::from_bytes_unchecked([14u8; 32]);
        let big = vec![0u8; MAX_ENCRYPTED_MESSAGE_SIZE + 1];

        let result = key.decrypt_message(&big);
        assert!(matches!(result, Err(CryptoError::LimitExceeded { .. })));
    }

    #[test]
    fn test_message_tamper_fails() {
        let key = SessionKey::from_bytes_unchecked([15u8; 32]);
        let msg = b"authentic";

        let mut ct = key.encrypt_message(msg).unwrap();
        ct[NONCE_SIZE + 3] ^= 0x01;

        let result = key.decrypt_message(&ct);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_finalized_encryptor_rejects_more_data() {
        let key = SessionKey::from_bytes_unchecked([16u8; 32]);
        let mut enc = key.encryptor().unwrap();

        let mut out = Vec::new();
        enc.encrypt_chunk_into(b"data", false, &mut out).unwrap();
        out.clear();
        enc.encrypt_chunk_into(&[], true, &mut out).unwrap();

        let mut more = Vec::new();
        let result = enc.encrypt_chunk_into(b"more", false, &mut more);
        assert!(matches!(result, Err(CryptoError::AlreadyFinalized)));
    }

    #[test]
    fn test_finalized_decryptor_rejects_more_data() {
        let key = SessionKey::from_bytes_unchecked([17u8; 32]);

        let mut encrypted = Vec::new();
        key.encryptor()
            .unwrap()
            .encrypt_stream(b"test".as_slice(), &mut encrypted)
            .unwrap();

        let mut dec = key.decryptor();
        let mut output = Vec::new();
        dec.decrypt_stream(&encrypted[..], &mut output).unwrap();

        let mut more = Zeroizing::new(Vec::new());
        let result = dec.decrypt_chunk_internal(&[0u8; TAG_SIZE], false, &mut more);
        assert!(matches!(result, Err(CryptoError::AlreadyFinalized)));
    }

    #[test]
    fn test_wrong_version_rejected() {
        let key = SessionKey::from_bytes_unchecked([18u8; 32]);
        let input = b"test";
        let mut encrypted = Vec::new();

        key.encryptor()
            .unwrap()
            .encrypt_stream(&input[..], &mut encrypted)
            .unwrap();

        encrypted[8] = PROTOCOL_VERSION + 1;

        let mut decrypted = Vec::new();
        let result = key
            .decryptor()
            .decrypt_stream(&encrypted[..], &mut decrypted);

        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_cancellation() {
        let key = SessionKey::from_bytes_unchecked([19u8; 32]);
        let input = vec![0xAB; ENCRYPTION_CHUNK_SIZE * 10];
        let cancel = AtomicBool::new(true);

        let mut encrypted = Vec::new();
        let result = key.encryptor().unwrap().encrypt_stream_cancellable(
            &mut input.as_slice(),
            &mut encrypted,
            Some(&cancel),
        );

        assert!(matches!(result, Err(CryptoError::Cancelled)));
    }

    #[test]
    fn test_configurable_runtime() {
        let config = CryptoConfig {
            max_concurrent_ops: 128,
        };
        let runtime = CryptoRuntime::new(config);
        assert_eq!(runtime.semaphore().available_permits(), 128);
    }
}