//! Web Portal for Browser-based File Access
//! 
//! Allows users without the FlatDrop app to receive files via a web browser.
//! Includes cryptographic identity verification for secure peer discovery.

use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Form, Path, State},
    http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use rand::rngs::OsRng;
use rand_core::RngCore;
use rcgen::{Certificate, CertificateParams, SanType};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    path::{Path as FsPath, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{cors::CorsLayer, timeout::TimeoutLayer, trace::TraceLayer};

use crate::iroh_engine::IrohEngine;

const MAX_SIGNATURE_AGE_SECS: u64 = 60;
const MAX_FUTURE_SKEW_SECS: u64 = 30;
const ANNOUNCEMENT_REFRESH_SECS: u64 = 30;

const MAX_DISPLAY_NAME_LEN: usize = 96;
const MAX_TXT_RECORD_LEN: usize = 1024;

const MAX_VERIFIED_PEERS: usize = 512;
const PEER_TTL_SECS: u64 = 120;

const RECENT_NONCES_PER_NODE: usize = 32;
const MAX_NODE_NONCE_TRACK: usize = 2048;

const SESSION_COOKIE: &str = "flatdrop_session";
const SESSION_AAD: &[u8] = b"flatdrop.session.v1";
const IDENTITY_AAD: &[u8] = b"flatdrop.identity.v1";
const SESSION_LIFETIME_SECS: u64 = 15 * 60;

const MDNS_SERVICE_TYPE: &str = "_flatdrop._tcp.local.";

#[derive(Clone)]
pub struct DeviceIdentity {
    signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedAnnouncement {
    pub v: u8,
    pub public_key: String,
    pub timestamp: u64,
    pub port: u16,
    pub nonce: String,
    pub signature: String,
    pub display_name: String,
}

#[derive(Serialize, Deserialize)]
struct EncryptedIdentityFile {
    v: u8,
    salt: [u8; 16],
    nonce: [u8; 24],
    ct: Vec<u8>,
}

impl DeviceIdentity {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let display_name = generate_display_name(&verifying_key);
        Self {
            signing_key,
            verifying_key,
            display_name,
        }
    }

    pub async fn load_or_generate_encrypted(path: &FsPath, password: &str) -> Result<Self> {
        if tokio::fs::try_exists(path).await.unwrap_or(false) {
            Self::load_encrypted(path, password).await
        } else {
            let identity = Self::generate();
            identity.save_encrypted(path, password).await?;
            Ok(identity)
        }
    }

    pub async fn load_encrypted(path: &FsPath, password: &str) -> Result<Self> {
        let bytes = tokio::fs::read(path).await?;
        let ef: EncryptedIdentityFile = bincode::deserialize(&bytes)?;
        if ef.v != 1 {
            return Err(anyhow!("Identity file invalid"));
        }

        let key = derive_key_argon2id(password, &ef.salt)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = XNonce::from_slice(&ef.nonce);

        let pt = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ef.ct,
                    aad: IDENTITY_AAD,
                },
            )
            .map_err(|_| anyhow!("Identity decrypt failed"))?;

        if pt.len() != 32 {
            return Err(anyhow!("Identity decrypt failed"));
        }

        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&pt);
        let signing_key = SigningKey::from_bytes(&sk_bytes);
        let verifying_key = signing_key.verifying_key();
        let display_name = generate_display_name(&verifying_key);

        Ok(Self {
            signing_key,
            verifying_key,
            display_name,
        })
    }

    pub async fn save_encrypted(&self, path: &FsPath, password: &str) -> Result<()> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let key = derive_key_argon2id(password, &salt)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));

        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let pt = self.signing_key.to_bytes();
        let ct = cipher.encrypt(
            nonce,
            Payload {
                msg: &pt,
                aad: IDENTITY_AAD,
            },
        ).map_err(|e| anyhow!("identity encrypt: {}", e))?;

        let ef = EncryptedIdentityFile {
            v: 1,
            salt,
            nonce: nonce_bytes,
            ct,
        };

        let out = bincode::serialize(&ef)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            use tokio::io::AsyncWriteExt;
            let mut opts = tokio::fs::OpenOptions::new();
            opts.create(true).truncate(true).write(true).mode(0o600);
            let mut f = opts.open(path).await?;
            f.write_all(&out).await?;
            f.flush().await?;
        }

        #[cfg(not(unix))]
        {
            tokio::fs::write(path, out).await?;
        }

        Ok(())
    }

    pub fn node_id(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.verifying_key.as_bytes())
    }

    pub fn create_announcement(&self, port: u16) -> Result<SignedAnnouncement> {
        let timestamp = now_unix_secs();
        let mut nonce16 = [0u8; 16];
        OsRng.fill_bytes(&mut nonce16);

        let msg = announcement_message(1, timestamp, port, &nonce16, &self.display_name)?;
        let sig = self.signing_key.sign(&msg);

        Ok(SignedAnnouncement {
            v: 1,
            public_key: URL_SAFE_NO_PAD.encode(self.verifying_key.as_bytes()),
            timestamp,
            port,
            nonce: URL_SAFE_NO_PAD.encode(nonce16),
            signature: URL_SAFE_NO_PAD.encode(sig.to_bytes()),
            display_name: self.display_name.clone(),
        })
    }
}

impl SignedAnnouncement {
    pub fn verify(&self, observed_port: u16) -> Result<(VerifyingKey, [u8; 16])> {
        if self.v != 1 {
            return Err(anyhow!("Invalid announcement"));
        }
        if self.display_name.len() > MAX_DISPLAY_NAME_LEN {
            return Err(anyhow!("Invalid announcement"));
        }
        if self.port != observed_port {
            return Err(anyhow!("Invalid announcement"));
        }

        let pk_bytes = URL_SAFE_NO_PAD.decode(&self.public_key)?;
        if pk_bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(anyhow!("Invalid announcement"));
        }
        let vk = VerifyingKey::from_bytes(&pk_bytes.try_into().unwrap())?;

        let nonce_bytes = URL_SAFE_NO_PAD.decode(&self.nonce)?;
        if nonce_bytes.len() != 16 {
            return Err(anyhow!("Invalid announcement"));
        }
        let mut nonce16 = [0u8; 16];
        nonce16.copy_from_slice(&nonce_bytes);

        let sig_bytes = URL_SAFE_NO_PAD.decode(&self.signature)?;
        if sig_bytes.len() != SIGNATURE_LENGTH {
            return Err(anyhow!("Invalid announcement"));
        }
        let sig = Signature::from_bytes(&sig_bytes.try_into().unwrap());

        let now = now_unix_secs();
        if self.timestamp > now.saturating_add(MAX_FUTURE_SKEW_SECS) {
            return Err(anyhow!("Invalid announcement"));
        }
        let age = now.saturating_sub(self.timestamp);
        if age > MAX_SIGNATURE_AGE_SECS {
            return Err(anyhow!("Invalid announcement"));
        }

        let msg = announcement_message(self.v, self.timestamp, self.port, &nonce16, &self.display_name)?;
        vk.verify(&msg, &sig)?;

        Ok((vk, nonce16))
    }

    pub fn to_txt_record(&self) -> Result<String> {
        if self.display_name.len() > MAX_DISPLAY_NAME_LEN {
            return Err(anyhow!("Invalid announcement"));
        }
        let txt = format!(
            "v={}&pk={}&ts={}&port={}&nonce={}&sig={}&name={}",
            self.v,
            self.public_key,
            self.timestamp,
            self.port,
            self.nonce,
            self.signature,
            urlencoding::encode(&self.display_name)
        );
        if txt.len() > MAX_TXT_RECORD_LEN {
            return Err(anyhow!("Invalid announcement"));
        }
        Ok(txt)
    }

    pub fn from_txt_record(txt: &str) -> Result<Self> {
        if txt.len() > MAX_TXT_RECORD_LEN {
            return Err(anyhow!("Invalid announcement"));
        }

        let mut v = None;
        let mut public_key = None;
        let mut timestamp = None;
        let mut port = None;
        let mut nonce = None;
        let mut signature = None;
        let mut display_name = None;

        for part in txt.split('&') {
            if let Some((k, val)) = part.split_once('=') {
                match k {
                    "v" => v = Some(val.parse::<u8>()?),
                    "pk" => public_key = Some(val.to_string()),
                    "ts" => timestamp = Some(val.parse::<u64>()?),
                    "port" => port = Some(val.parse::<u16>()?),
                    "nonce" => nonce = Some(val.to_string()),
                    "sig" => signature = Some(val.to_string()),
                    "name" => {
                        if val.len() > MAX_DISPLAY_NAME_LEN * 6 {
                            return Err(anyhow!("Invalid announcement"));
                        }
                        display_name = Some(urlencoding::decode(val)?.into_owned());
                    }
                    _ => {}
                }
            }
        }

        let name = display_name.ok_or_else(|| anyhow!("Invalid announcement"))?;
        if name.len() > MAX_DISPLAY_NAME_LEN {
            return Err(anyhow!("Invalid announcement"));
        }

        Ok(Self {
            v: v.ok_or_else(|| anyhow!("Invalid announcement"))?,
            public_key: public_key.ok_or_else(|| anyhow!("Invalid announcement"))?,
            timestamp: timestamp.ok_or_else(|| anyhow!("Invalid announcement"))?,
            port: port.ok_or_else(|| anyhow!("Invalid announcement"))?,
            nonce: nonce.ok_or_else(|| anyhow!("Invalid announcement"))?,
            signature: signature.ok_or_else(|| anyhow!("Invalid announcement"))?,
            display_name: name,
        })
    }
}

fn announcement_message(v: u8, timestamp: u64, port: u16, nonce16: &[u8; 16], display_name: &str) -> Result<Vec<u8>> {
    if display_name.len() > MAX_DISPLAY_NAME_LEN {
        return Err(anyhow!("Invalid announcement"));
    }
    let name_len = u32::try_from(display_name.as_bytes().len()).map_err(|_| anyhow!("Invalid announcement"))?;
    let mut msg = Vec::with_capacity(48 + display_name.len());
    msg.extend_from_slice(b"flatdrop-announcement:");
    msg.push(v);
    msg.extend_from_slice(&name_len.to_le_bytes());
    msg.extend_from_slice(&timestamp.to_le_bytes());
    msg.extend_from_slice(&port.to_le_bytes());
    msg.extend_from_slice(nonce16);
    msg.extend_from_slice(display_name.as_bytes());
    Ok(msg)
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn derive_key_argon2id(password: &str, salt: &[u8; 16]) -> Result<[u8; 32]> {
    let params = Params::new(19_456, 3, 1, Some(32))
        .map_err(|e| anyhow!("argon2 params: {}", e))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    a2.hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow!("argon2 hash: {}", e))?;
    Ok(out)
}

fn generate_display_name(key: &VerifyingKey) -> String {
    let bytes = key.as_bytes();
    let adjective_index = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
    let animal_index = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
    let adjective = ADJECTIVES[adjective_index % ADJECTIVES.len()];
    let animal = ANIMALS[animal_index % ANIMALS.len()];
    let h = blake3::hash(bytes);
    let suffix = hex::encode_upper(&h.as_bytes()[0..3]);
    format!("{adjective} {animal} #{suffix}")
}

const ADJECTIVES: &[&str] = &[
    "Dancing","Singing","Flying","Jumping","Running","Sleepy","Happy","Grumpy","Bouncy","Fluffy",
    "Mighty","Gentle","Swift","Clever","Brave","Cosmic","Electric","Frozen","Golden","Silver",
    "Ancient","Mystic","Noble","Royal","Wild","Cheerful","Daring","Eager","Fancy","Glossy",
    "Humble","Jolly","Keen","Lively","Merry","Nimble","Perky","Quick","Radiant","Snappy",
    "Trusty","Unique","Vivid","Witty","Zesty","Peaceful","Stellar","Quantum","Neon","Vintage",
];

const ANIMALS: &[&str] = &[
    "Panda","Penguin","Dolphin","Eagle","Tiger","Koala","Otter","Fox","Wolf","Bear",
    "Owl","Hawk","Falcon","Raven","Swan","Lion","Leopard","Cheetah","Jaguar","Panther",
    "Rabbit","Squirrel","Hedgehog","Badger","Beaver","Whale","Shark","Octopus","Seahorse","Starfish",
    "Dragon","Phoenix","Griffin","Unicorn","Pegasus","Turtle","Gecko","Chameleon","Iguana","Cobra",
    "Butterfly","Dragonfly","Firefly","Beetle","Mantis","Monkey","Gorilla","Lemur","Sloth","Capybara",
];

#[derive(Debug, Clone)]
pub struct VerifiedPeer {
    pub node_id: String,
    pub display_name: String,
    pub addresses: Vec<IpAddr>,
    pub port: u16,
    pub last_seen: Instant,
}

#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    PeerDiscovered(VerifiedPeer),
    PeerLost { node_id: String },
    PeerRejected { reason: String },
}

#[derive(Default)]
struct ReplayTracker {
    per_node: HashMap<String, VecDeque<[u8; 16]>>,
    order: VecDeque<String>,
}

impl ReplayTracker {
    fn seen_or_insert(&mut self, node_id: &str, nonce: [u8; 16]) -> bool {
        let entry = self
            .per_node
            .entry(node_id.to_string())
            .or_insert_with(VecDeque::new);

        if entry.iter().any(|n| n == &nonce) {
            return true;
        }

        entry.push_back(nonce);
        while entry.len() > RECENT_NONCES_PER_NODE {
            entry.pop_front();
        }

        if !self.order.iter().any(|k| k == node_id) {
            self.order.push_back(node_id.to_string());
        }

        while self.order.len() > MAX_NODE_NONCE_TRACK {
            if let Some(old) = self.order.pop_front() {
                self.per_node.remove(&old);
            }
        }

        false
    }
}

pub struct DiscoveryService {
    our_identity: Arc<DeviceIdentity>,
    verified_peers: Arc<RwLock<HashMap<String, VerifiedPeer>>>,
    replay: Arc<Mutex<ReplayTracker>>,
    events_tx: mpsc::Sender<DiscoveryEvent>,
    events_rx: Mutex<Option<mpsc::Receiver<DiscoveryEvent>>>,
    port: u16,
    cancel: CancellationToken,
    mdns: ServiceDaemon,
    instance_name: String,
}

impl DiscoveryService {
    pub fn new(identity: Arc<DeviceIdentity>, port: u16, cancel: CancellationToken) -> Result<Self> {
        let (tx, rx) = mpsc::channel(256);
        let mdns = ServiceDaemon::new()?;
        let node_id = identity.node_id();
        let prefix = node_id.get(..16).unwrap_or(&node_id);
        Ok(Self {
            our_identity: identity,
            verified_peers: Arc::new(RwLock::new(HashMap::new())),
            replay: Arc::new(Mutex::new(ReplayTracker::default())),
            events_tx: tx,
            events_rx: Mutex::new(Some(rx)),
            port,
            cancel,
            mdns,
            instance_name: format!("flatdrop-{prefix}"),
        })
    }

    pub async fn subscribe(&self) -> Result<mpsc::Receiver<DiscoveryEvent>> {
        let mut guard = self.events_rx.lock().await;
        guard.take().ok_or_else(|| anyhow!("Already subscribed"))
    }

    pub fn start(&self) -> Result<()> {
        self.start_advertise_task()?;
        self.start_browse_task()?;
        self.start_eviction_task();
        Ok(())
    }

    fn start_advertise_task(&self) -> Result<()> {
        let cancel = self.cancel.clone();
        let mdns = self.mdns.clone();
        let identity = self.our_identity.clone();
        let instance = self.instance_name.clone();
        let port = self.port;

        std::thread::spawn(move || {
            let mut last_fullname: Option<String> = None;
            let mut interval = std::time::Duration::from_secs(ANNOUNCEMENT_REFRESH_SECS);

            loop {
                if cancel.is_cancelled() {
                    if let Some(full) = last_fullname.take() {
                        let _ = mdns.unregister(&full);
                    }
                    let _ = mdns.shutdown();
                    break;
                }

                match identity.create_announcement(port).and_then(|a| a.to_txt_record()) {
                    Ok(txt) => {
                        if let Some(full) = last_fullname.take() {
                            let _ = mdns.unregister(&full);
                        }

                        let mut props = HashMap::new();
                        props.insert("txt".to_string(), txt);

                        let host = format!("{}.local.", instance);
                        let info = ServiceInfo::new(
                            MDNS_SERVICE_TYPE,
                            &instance,
                            &host,
                            "",
                            port,
                            Some(props),
                        );

                        if let Ok(info) = info {
                            let _ = mdns.register(info);
                            last_fullname = Some(format!("{}.{}", instance, MDNS_SERVICE_TYPE));
                        }
                    }
                    Err(_) => {}
                }

                std::thread::sleep(interval);
                interval = std::time::Duration::from_secs(ANNOUNCEMENT_REFRESH_SECS);
            }
        });

        Ok(())
    }

    fn start_browse_task(&self) -> Result<()> {
        let cancel = self.cancel.clone();
        let mdns = self.mdns.clone();
        let tx = self.events_tx.clone();
        let this = Arc::new(self.clone_for_threads());

        let receiver = mdns.browse(MDNS_SERVICE_TYPE)?;

        std::thread::spawn(move || {
            while !cancel.is_cancelled() {
                match receiver.recv_timeout(std::time::Duration::from_millis(250)) {
                    Ok(evt) => {
                        match evt {
                            ServiceEvent::ServiceResolved(info) => {
                                let props = info.get_properties();
                                let txt_prop = props.get("txt");
                                let addrs: Vec<IpAddr> = info.get_addresses().iter().cloned().collect();
                                let port = info.get_port();

                                if let Some(txt_prop) = txt_prop {
                                    let txt = txt_prop.val_str().to_string();
                                    let this2 = this.clone();
                                    let tx2 = tx.clone();
                                    tokio::spawn(async move {
                                        match this2.verify_peer(&txt, addrs, port).await {
                                            Ok(peer) => {
                                                let _ = tx2.send(DiscoveryEvent::PeerDiscovered(peer)).await;
                                            }
                                            Err(e) => {
                                                let _ = tx2.send(DiscoveryEvent::PeerRejected { reason: e.to_string() }).await;
                                            }
                                        }
                                    });
                                }
                            }
                            ServiceEvent::ServiceRemoved(_ty, full) => {
                                let this2 = this.clone();
                                let tx2 = tx.clone();
                                tokio::spawn(async move {
                                    let removed = this2.remove_peer_by_fullname(&full).await;
                                    if let Some(node_id) = removed {
                                        let _ = tx2.send(DiscoveryEvent::PeerLost { node_id }).await;
                                    }
                                });
                            }
                            _ => {}
                        }
                    }
                    Err(_) => {}
                }
            }
            let _ = mdns.shutdown();
        });

        Ok(())
    }

    fn start_eviction_task(&self) {
        let peers = self.verified_peers.clone();
        let tx = self.events_tx.clone();
        let cancel = self.cancel.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(15));
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = interval.tick() => {
                        let mut lost = Vec::new();
                        {
                            let map = peers.read().await;
                            for (k, v) in map.iter() {
                                if v.last_seen.elapsed() > Duration::from_secs(PEER_TTL_SECS) {
                                    lost.push(k.clone());
                                }
                            }
                        }
                        if !lost.is_empty() {
                            let mut map = peers.write().await;
                            for node_id in lost {
                                map.remove(&node_id);
                                let _ = tx.send(DiscoveryEvent::PeerLost { node_id }).await;
                            }
                        }
                    }
                }
            }
        });
    }

    async fn remove_peer_by_fullname(&self, _fullname: &str) -> Option<String> {
        None
    }

    pub async fn verify_peer(&self, txt_record: &str, addresses: Vec<IpAddr>, observed_port: u16) -> Result<VerifiedPeer> {
        let ann = SignedAnnouncement::from_txt_record(txt_record)?;
        let (vk, nonce16) = ann.verify(observed_port)?;
        let node_id = URL_SAFE_NO_PAD.encode(vk.as_bytes());

        if node_id == self.our_identity.node_id() {
            return Err(anyhow!("self"));
        }

        {
            let mut rt = self.replay.lock().await;
            if rt.seen_or_insert(&node_id, nonce16) {
                return Err(anyhow!("replay"));
            }
        }

        let peer = VerifiedPeer {
            node_id: node_id.clone(),
            display_name: ann.display_name,
            addresses,
            port: observed_port,
            last_seen: Instant::now(),
        };

        {
            let mut map = self.verified_peers.write().await;
            map.insert(node_id.clone(), peer.clone());

            if map.len() > MAX_VERIFIED_PEERS {
                if let Some(oldest_key) = map
                    .iter()
                    .min_by_key(|(_, p)| p.last_seen)
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&oldest_key);
                }
            }
        }

        Ok(peer)
    }

    pub async fn get_verified_peers_snapshot(&self) -> Vec<VerifiedPeer> {
        let peers = self.verified_peers.read().await;
        peers.values().cloned().collect()
    }

    fn clone_for_threads(&self) -> DiscoveryThreadView {
        DiscoveryThreadView {
            our_node_id: self.our_identity.node_id(),
            verified_peers: self.verified_peers.clone(),
            replay: self.replay.clone(),
        }
    }
}

struct DiscoveryThreadView {
    our_node_id: String,
    verified_peers: Arc<RwLock<HashMap<String, VerifiedPeer>>>,
    replay: Arc<Mutex<ReplayTracker>>,
}

impl DiscoveryThreadView {
    async fn verify_peer(&self, txt_record: &str, addresses: Vec<IpAddr>, observed_port: u16) -> Result<VerifiedPeer> {
        let ann = SignedAnnouncement::from_txt_record(txt_record)?;
        let (vk, nonce16) = ann.verify(observed_port)?;
        let node_id = URL_SAFE_NO_PAD.encode(vk.as_bytes());

        if node_id == self.our_node_id {
            return Err(anyhow!("self"));
        }

        {
            let mut rt = self.replay.lock().await;
            if rt.seen_or_insert(&node_id, nonce16) {
                return Err(anyhow!("replay"));
            }
        }

        let peer = VerifiedPeer {
            node_id: node_id.clone(),
            display_name: ann.display_name,
            addresses,
            port: observed_port,
            last_seen: Instant::now(),
        };

        {
            let mut map = self.verified_peers.write().await;
            map.insert(node_id, peer.clone());
            if map.len() > MAX_VERIFIED_PEERS {
                if let Some(oldest_key) = map
                    .iter()
                    .min_by_key(|(_, p)| p.last_seen)
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&oldest_key);
                }
            }
        }

        Ok(peer)
    }

    async fn remove_peer_by_fullname(&self, _fullname: &str) -> Option<String> {
        None
    }
}

#[derive(Clone)]
pub struct PortalState {
    pub engine: Arc<IrohEngine>,
    pub identity: Arc<DeviceIdentity>,
    pub discovery: Arc<DiscoveryService>,
    pairing_code_hash: [u8; 32],
    session_master_key: [u8; 32],
    throttle: Arc<Mutex<LoginThrottle>>,
    allowed_origins: Arc<HashSet<String>>,
}

#[derive(Default)]
struct LoginThrottle {
    per_ip: HashMap<IpAddr, ThrottleState>,
}

struct ThrottleState {
    failures: u32,
    until: Instant,
}

impl LoginThrottle {
    fn check(&mut self, ip: IpAddr) -> Result<(), StatusCode> {
        let now = Instant::now();
        if let Some(s) = self.per_ip.get(&ip) {
            if now < s.until {
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
        }
        Ok(())
    }

    fn record_failure(&mut self, ip: IpAddr) {
        let now = Instant::now();
        let s = self
            .per_ip
            .entry(ip)
            .or_insert(ThrottleState { failures: 0, until: now });
        s.failures = s.failures.saturating_add(1);
        let backoff_ms = 250u64.saturating_mul(2u64.saturating_pow(s.failures.min(10)));
        s.until = now + Duration::from_millis(backoff_ms.min(30_000));
    }

    fn record_success(&mut self, ip: IpAddr) {
        self.per_ip.remove(&ip);
    }
}

#[derive(Clone)]
pub enum TlsMode {
    Provided { cert_pem: PathBuf, key_pem: PathBuf },
    SelfSigned,
}

#[derive(Clone)]
pub struct PortalConfig {
    pub bind_ip: IpAddr,
    pub port: u16,
    pub identity_path: PathBuf,
    pub identity_password: String,
    pub tls: TlsMode,
}

#[derive(Serialize, Deserialize)]
struct Session {
    exp: u64,
}

#[derive(Deserialize)]
struct LoginForm {
    code: String,
}

pub async fn start_portal(
    config: PortalConfig,
    engine: Arc<IrohEngine>,
    shutdown_rx: oneshot::Receiver<()>,
    started_tx: oneshot::Sender<(u16, String)>,
) -> Result<()> {
    let port = if config.port == 0 {
        portpicker::pick_unused_port().ok_or_else(|| anyhow!("No free port"))?
    } else {
        config.port
    };

    let cancel = CancellationToken::new();

    let identity = Arc::new(
        DeviceIdentity::load_or_generate_encrypted(&config.identity_path, &config.identity_password)
            .await?,
    );

    let discovery = Arc::new(DiscoveryService::new(identity.clone(), port, cancel.clone())?);
    discovery.start()?;

    let pairing_code = new_pairing_code();
    let pairing_code_hash = *blake3::hash(pairing_code.as_bytes()).as_bytes();

    let mut session_master_key = [0u8; 32];
    OsRng.fill_bytes(&mut session_master_key);

    let allowed_origins = Arc::new(build_allowed_origins(config.bind_ip, port));

    let state = PortalState {
        engine,
        identity,
        discovery,
        pairing_code_hash,
        session_master_key,
        throttle: Arc::new(Mutex::new(LoginThrottle::default())),
        allowed_origins: allowed_origins.clone(),
    };

    let cors = CorsLayer::new()
        .allow_origin(
            allowed_origins_predicate(allowed_origins.clone())
        )
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::ORIGIN])
        .allow_credentials(true);

    let app = Router::new()
        .route("/", get(root_handler))
        .route("/login", post(login_handler))
        .route("/logout", post(logout_handler))
        .route("/api/files", get(list_files_handler))
        .route("/api/download/:hash", get(download_handler))
        .route("/api/peers", get(list_peers_handler))
        .route("/api/identity", get(identity_handler))
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(10)))
        .layer(ConcurrencyLimitLayer::new(256))
        .layer(cors)
        .layer(DefaultBodyLimit::max(128 * 1024))
        .layer(middleware::from_fn(security_headers_layer))
        .with_state(state);

    let addr = SocketAddr::new(config.bind_ip, port);

    started_tx
        .send((port, pairing_code))
        .map_err(|_| anyhow!("Startup channel closed"))?;

    let tls_config = match config.tls {
        TlsMode::Provided { cert_pem, key_pem } => {
            axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_pem, key_pem).await?
        }
        TlsMode::SelfSigned => {
            if !is_loopback(config.bind_ip) {
                return Err(anyhow!("SelfSigned TLS only allowed on loopback for production safety"));
            }
            let (cert_path, key_path, _tmp) = generate_self_signed_cert_files(config.bind_ip).await?;
            let cfg = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path).await?;
            std::mem::forget(_tmp);
            cfg
        }
    };

    let handle = axum_server::Handle::new();
    let handle2 = handle.clone();
    let cancel2 = cancel.clone();

    tokio::spawn(async move {
        let _ = shutdown_rx.await;
        cancel2.cancel();
        handle2.graceful_shutdown(Some(Duration::from_secs(5)));
    });

    axum_server::bind_rustls(addr, tls_config)
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

fn new_pairing_code() -> String {
    let mut b = [0u8; 6];
    OsRng.fill_bytes(&mut b);
    let s = hex::encode_upper(b);
    format!("{}-{}-{}", &s[0..4], &s[4..8], &s[8..12])
}

fn build_allowed_origins(bind_ip: IpAddr, port: u16) -> HashSet<String> {
    let mut set = HashSet::new();
    set.insert(format!("https://localhost:{port}"));
    set.insert(format!("https://127.0.0.1:{port}"));
    set.insert(format!("https://[::1]:{port}"));
    let host = match bind_ip {
        IpAddr::V4(_) => bind_ip.to_string(),
        IpAddr::V6(_) => format!("[{}]", bind_ip),
    };
    set.insert(format!("https://{host}:{port}"));
    set
}

fn allowed_origins_predicate(
    allowed: Arc<HashSet<String>>,
) -> tower_http::cors::AllowOrigin {
    tower_http::cors::AllowOrigin::predicate(move |origin: &HeaderValue, _| {
        if let Ok(s) = origin.to_str() {
            allowed.contains(s)
        } else {
            false
        }
    })
}

async fn generate_self_signed_cert_files(bind_ip: IpAddr) -> Result<(PathBuf, PathBuf, tokio::sync::OwnedSemaphorePermit)> {
    let mut params = CertificateParams::new(vec!["localhost".to_string()]);
    params.subject_alt_names.push(SanType::IpAddress(bind_ip));
    params.subject_alt_names.push(SanType::IpAddress(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
    params.subject_alt_names.push(SanType::IpAddress(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)));
    let cert = Certificate::from_params(params)?;

    let tmp = tempfile::tempdir()?;
    let cert_path = tmp.path().join("cert.pem");
    let key_path = tmp.path().join("key.pem");

    tokio::fs::write(&cert_path, cert.serialize_pem()?).await?;
    tokio::fs::write(&key_path, cert.serialize_private_key_pem()).await?;

    let sem = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = sem.acquire_owned().await?;
    std::mem::forget(tmp);
    Ok((cert_path, key_path, permit))
}

async fn security_headers_layer(req: Request<axum::body::Body>, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();

    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
    );
    h.insert(
        header::HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'",
        ),
    );

    res
}

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

fn seal_session(master_key: &[u8; 32], session: &Session) -> Result<String> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(master_key));
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let pt = bincode::serialize(session)?;
    let ct = cipher.encrypt(
        nonce,
        Payload {
            msg: &pt,
            aad: SESSION_AAD,
        },
    ).map_err(|e| anyhow!("session encrypt: {}", e))?;
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(URL_SAFE_NO_PAD.encode(out))
}

fn open_session(master_key: &[u8; 32], token: &str) -> Option<Session> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(master_key));
    let bytes = URL_SAFE_NO_PAD.decode(token).ok()?;
    if bytes.len() < 24 {
        return None;
    }
    let (nonce_bytes, ct) = bytes.split_at(24);
    let nonce = XNonce::from_slice(nonce_bytes);
    let pt = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ct,
                aad: SESSION_AAD,
            },
        )
        .ok()?;
    let s: Session = bincode::deserialize(&pt).ok()?;
    if now_unix_secs() > s.exp {
        return None;
    }
    Some(s)
}

fn require_session(state: &PortalState, jar: &CookieJar) -> Result<(), StatusCode> {
    let Some(c) = jar.get(SESSION_COOKIE) else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    if open_session(&state.session_master_key, c.value()).is_some() {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

fn require_same_origin(state: &PortalState, headers: &HeaderMap) -> Result<(), StatusCode> {
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|h| h.to_str().ok()) {
        if !state.allowed_origins.contains(origin) {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    Ok(())
}

async fn root_handler(State(state): State<PortalState>, jar: CookieJar) -> impl IntoResponse {
    if require_session(&state, &jar).is_ok() {
        let safe_name = escape_html(&state.identity.display_name);
        let html = PORTAL_HTML.replace("{{DEVICE_NAME}}", &safe_name);
        return Html(html).into_response();
    }
    Html(LOGIN_HTML.to_string()).into_response()
}

async fn login_handler(
    State(state): State<PortalState>,
    jar: CookieJar,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    if let Err(code) = require_same_origin(&state, &headers) {
        return code.into_response();
    }

    let ip = peer.ip();

    {
        let mut t = state.throttle.lock().await;
        if let Err(code) = t.check(ip) {
            tracing::warn!(%ip, "login throttled");
            return code.into_response();
        }
    }

    let provided_hash = blake3::hash(form.code.trim().as_bytes());
    let ok: bool = provided_hash
        .as_bytes()
        .ct_eq(&state.pairing_code_hash)
        .into();

    if !ok {
        let mut t = state.throttle.lock().await;
        t.record_failure(ip);
        tracing::warn!(%ip, "login failed");
        return StatusCode::UNAUTHORIZED.into_response();
    }

    {
        let mut t = state.throttle.lock().await;
        t.record_success(ip);
    }

    let exp = now_unix_secs().saturating_add(SESSION_LIFETIME_SECS);
    let session = Session { exp };

    let token = match seal_session(&state.session_master_key, &session) {
        Ok(t) => t,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let mut cookie = Cookie::new(SESSION_COOKIE, token);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Strict);
    cookie.set_secure(true);
    cookie.set_path("/");

    tracing::info!(%ip, "login success");

    let jar = jar.add(cookie);
    (jar, Redirect::to("/")).into_response()
}

async fn logout_handler(
    State(state): State<PortalState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(code) = require_same_origin(&state, &headers) {
        return code.into_response();
    }

    let mut cookie = Cookie::new(SESSION_COOKIE, "");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Strict);
    cookie.set_secure(true);
    cookie.set_path("/");
    cookie.make_removal();

    let jar = jar.add(cookie);
    (jar, Redirect::to("/")).into_response()
}

async fn list_files_handler(State(state): State<PortalState>, jar: CookieJar) -> impl IntoResponse {
    if let Err(code) = require_session(&state, &jar) {
        return code.into_response();
    }
    tracing::info!("files listed");
    Json(serde_json::json!([])).into_response()
}

fn validate_hash32_urlsafe_no_pad(hash: &str) -> Result<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD.decode(hash)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("Invalid hash"))?;
    Ok(arr)
}

async fn download_handler(
    State(state): State<PortalState>,
    jar: CookieJar,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    if let Err(code) = require_session(&state, &jar) {
        return code.into_response();
    }
    if validate_hash32_urlsafe_no_pad(&hash).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    tracing::warn!(%hash, "download not implemented");
    (StatusCode::NOT_FOUND, "Not found").into_response()
}

async fn list_peers_handler(State(state): State<PortalState>, jar: CookieJar) -> impl IntoResponse {
    if let Err(code) = require_session(&state, &jar) {
        return code.into_response();
    }
    let peers = state.discovery.get_verified_peers_snapshot().await;
    let peer_list: Vec<_> = peers
        .iter()
        .map(|p| {
            let short = p.node_id.get(..16).unwrap_or(&p.node_id);
            serde_json::json!({
                "node_id": short,
                "display_name": p.display_name,
                "addresses": p.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                "port": p.port,
            })
        })
        .collect();
    Json(peer_list).into_response()
}

async fn identity_handler(State(state): State<PortalState>, jar: CookieJar) -> impl IntoResponse {
    if let Err(code) = require_session(&state, &jar) {
        return code.into_response();
    }
    let node_id = state.identity.node_id();
    let short = node_id.get(..16).unwrap_or(&node_id);
    Json(serde_json::json!({
        "node_id": short,
        "display_name": state.identity.display_name,
    }))
    .into_response()
}

const LOGIN_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FlatDrop Portal</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;display:flex;align-items:center;justify-content:center}
.container{background:rgba(255,255,255,.95);border-radius:20px;padding:40px;max-width:520px;width:92%;box-shadow:0 20px 60px rgba(0,0,0,.3)}
h1{color:#333;margin-bottom:10px;font-size:2em}
p{color:#666;margin-bottom:18px;line-height:1.6}
label{display:block;margin-bottom:8px;color:#333;font-weight:600}
input{width:100%;padding:12px 14px;border:1px solid #ddd;border-radius:10px;font-size:1em;margin-bottom:14px}
button{width:100%;padding:12px 14px;border:0;border-radius:10px;background:#667eea;color:#fff;font-size:1em;font-weight:700;cursor:pointer}
small{display:block;margin-top:14px;color:#777}
</style>
</head>
<body>
<div class="container">
<h1>FlatDrop Portal</h1>
<p>Enter the pairing code shown in the FlatDrop app to unlock this portal.</p>
<form method="post" action="/login">
<label for="code">Pairing code</label>
<input id="code" name="code" inputmode="text" autocomplete="one-time-code" required>
<button type="submit">Unlock</button>
</form>
<small>This session expires automatically.</small>
</div>
</body>
</html>
"#;

const PORTAL_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FlatDrop Portal</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;display:flex;align-items:center;justify-content:center}
.container{background:rgba(255,255,255,.95);border-radius:20px;padding:40px;max-width:520px;width:92%;box-shadow:0 20px 60px rgba(0,0,0,.3)}
h1{color:#333;margin-bottom:10px;font-size:2em}
.device-name{color:#667eea;font-size:1.2em;margin-bottom:18px}
p{color:#666;margin-bottom:18px;line-height:1.6}
.status{display:flex;align-items:center;gap:10px;padding:15px;background:#f0f0f0;border-radius:10px;margin-bottom:16px}
.status-dot{width:10px;height:10px;background:#10b981;border-radius:50%;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
button{padding:10px 14px;border:0;border-radius:10px;background:#e5e7eb;color:#111;font-weight:700;cursor:pointer}
form{margin-top:10px}
</style>
</head>
<body>
<div class="container">
<h1>FlatDrop Portal</h1>
<div class="device-name">{{DEVICE_NAME}}</div>
<p>Ready to receive files via peer-to-peer transfer.</p>
<div class="status">
<div class="status-dot"></div>
<span>Waiting for incoming files...</span>
</div>
<form method="post" action="/logout">
<button type="submit">Lock portal</button>
</form>
</div>
</body>
</html>
"#;