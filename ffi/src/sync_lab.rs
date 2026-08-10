//! Lab/debug UniFFI surface for cross-device Offer/Want/Have/Ack.
//!
//! Uses the same length-prefixed sync frames as `/derooms/sync/1.0.0`
//! (`rooms-proto` / `rooms-sync`) over TCP. Host IT covers the libp2p
//! request-response path via `two_node_sync_over_libp2p_streams` (requires
//! dual-swarm `sync_rpc` polling in one process). Cross-device lab uses TCP
//! so each phone can drive its own socket independently.
//!
//! Optional TCP `rooms-relay` fallback (same DRRL handshake as
//! `rooms_transport::dial_via_relay`) when LAN dial fails — not libp2p circuit v2.

use rooms_identity::verifying_key_from_bytes;
use rooms_proto::{decode_message_event_wire_v1, Cid};
use rooms_storage::{KvStore, MemoryKvStore, Namespace, SledKvStore, StorageError};
use rooms_sync::{
    ack_bytes_from_have, have_bytes_from_want, want_bytes_from_offer, EventStore, Outbox,
    SyncReplica,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};

const MAX_FRAME: usize = 16 * 1024 * 1024;
/// Same magic as `rooms_transport::tcp_relay` (`DRRL`).
const RELAY_MAGIC: &[u8; 4] = b"DRRL";
const RELAY_VERSION: u8 = 1;

enum Cmd {
    Listen {
        bind: String,
        advertise_ip: String,
        timeout: Duration,
        reply: oneshot::Sender<String>,
    },
    ConfigureRelay {
        relay_host_port: String,
        token_hex: String,
        reply: oneshot::Sender<String>,
    },
    Push {
        room: [u8; 32],
        wire: Vec<u8>,
        peer_multiaddr: String,
        timeout: Duration,
        reply: oneshot::Sender<String>,
    },
    Pull {
        room: [u8; 32],
        author_vk: [u8; 32],
        timeout: Duration,
        reply: oneshot::Sender<Vec<u8>>,
    },
    RememberPeerVk {
        author_vk: [u8; 32],
        reply: oneshot::Sender<String>,
    },
    ReleaseListen {
        reply: oneshot::Sender<String>,
    },
    Shutdown,
}

/// Shared TCP session so the listener can Send on the scanner's existing
/// connection (reverse) without a second listen/dial.
#[derive(Clone)]
struct SessionShare {
    parked: Arc<AsyncMutex<Option<TcpStream>>>,
    peer_vk: Arc<Mutex<Option<[u8; 32]>>>,
    inbound_tx: mpsc::UnboundedSender<Vec<u8>>,
    inbound_rx: Arc<AsyncMutex<mpsc::UnboundedReceiver<Vec<u8>>>>,
    /// Abort an in-flight relay inbox dial so a local Send cannot splice with
    /// our own pull (same token, complementary roles).
    pull_abort: Arc<tokio::sync::Notify>,
}

impl SessionShare {
    fn new() -> Self {
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        Self {
            parked: Arc::new(AsyncMutex::new(None)),
            peer_vk: Arc::new(Mutex::new(None)),
            inbound_tx,
            inbound_rx: Arc::new(AsyncMutex::new(inbound_rx)),
            pull_abort: Arc::new(tokio::sync::Notify::new()),
        }
    }
}

#[derive(Clone, Default)]
struct RelayConfig {
    addr: Option<String>,
    /// Token used when we Push (role A).
    push_token: Option<Vec<u8>>,
    /// Token used when we Pull (role B). Directional so our inbox cannot
    /// splice with our own send on a role-aware relay.
    pull_token: Option<Vec<u8>>,
}

impl RelayConfig {
    fn configured(&self) -> bool {
        self.addr.is_some() && (self.push_token.is_some() || self.pull_token.is_some())
    }

    fn token_for(&self, role_b: bool) -> Option<&Vec<u8>> {
        if role_b {
            self.pull_token.as_ref().or(self.push_token.as_ref())
        } else {
            self.push_token.as_ref().or(self.pull_token.as_ref())
        }
    }
}

/// Opaque lab node: TCP listen/dial + event store (memory or sled).
pub struct SyncLabNode {
    rt: tokio::runtime::Runtime,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    /// Stable lab id (not a libp2p peer id) — hex of random 32 bytes at construct.
    peer_id: String,
    listen_dial_addr: Mutex<Option<String>>,
    last_tip: Arc<Mutex<String>>,
}

enum LabKv {
    Memory(MemoryKvStore),
    Sled(SledKvStore),
}

impl KvStore for LabKv {
    fn put(&mut self, ns: Namespace, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        match self {
            Self::Memory(s) => s.put(ns, key, value),
            Self::Sled(s) => s.put(ns, key, value),
        }
    }

    fn get(&self, ns: Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        match self {
            Self::Memory(s) => s.get(ns, key),
            Self::Sled(s) => s.get(ns, key),
        }
    }

    fn delete(&mut self, ns: Namespace, key: &[u8]) -> Result<(), StorageError> {
        match self {
            Self::Memory(s) => s.delete(ns, key),
            Self::Sled(s) => s.delete(ns, key),
        }
    }
}

fn open_lab_kv(store_dir: &str) -> LabKv {
    let path = store_dir.trim();
    if path.is_empty() {
        return LabKv::Memory(MemoryKvStore::new());
    }
    // Non-empty path must be sled. Silent Memory fallback hid persist failures.
    std::fs::create_dir_all(path).unwrap_or_else(|e| {
        panic!("synclab store dir {path}: {e}");
    });
    match SledKvStore::open(path) {
        Ok(s) => LabKv::Sled(s),
        Err(e) => panic!("synclab sled open {path}: {e:?}"),
    }
}

impl SyncLabNode {
    /// Construct a lab node (spawns a background TCP/sync driver). In-memory store.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self::new_inner(String::new())
    }

    /// Persist EventStore/Outbox under `store_dir` via sled (Android filesDir).
    pub fn with_store_dir(store_dir: String) -> Self {
        Self::new_inner(store_dir)
    }

    fn new_inner(store_dir: String) -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("derooms-synclab")
            .worker_threads(2)
            .build()
            .expect("tokio runtime for SyncLabNode");

        let peer_id = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            std::time::SystemTime::now().hash(&mut h);
            format!("{:016x}", h.finish())
        };

        let last_tip = Arc::new(Mutex::new(String::new()));
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<Cmd>();
        rt.spawn(drive(cmd_rx, store_dir, Arc::clone(&last_tip)));

        Self {
            rt,
            cmd_tx,
            peer_id,
            listen_dial_addr: Mutex::new(None),
            last_tip,
        }
    }

    pub fn local_peer_id(&self) -> String {
        self.peer_id.clone()
    }

    /// Listen TCP. `bind_multiaddr` like `/ip4/0.0.0.0/tcp/44001`.
    /// Returns dialable `/ip4/<advertise_ip>/tcp/<port>/p2p/<lab_id>`.
    pub fn listen_tcp(
        &self,
        bind_multiaddr: String,
        advertise_ip: String,
        timeout_ms: u32,
    ) -> String {
        let (reply_tx, reply_rx) = oneshot::channel();
        let timeout = Duration::from_millis(u64::from(timeout_ms.max(1)));
        if self
            .cmd_tx
            .send(Cmd::Listen {
                bind: bind_multiaddr,
                advertise_ip,
                timeout,
                reply: reply_tx,
            })
            .is_err()
        {
            return "ERROR:driver_gone".into();
        }
        match self.rt.block_on(reply_rx) {
            Ok(addr) => {
                if !addr.starts_with("ERROR:") {
                    *self.listen_dial_addr.lock().expect("lock") = Some(addr.clone());
                }
                addr
            }
            Err(_) => "ERROR:listen_cancelled".into(),
        }
    }

    pub fn listen_dial_addr(&self) -> String {
        self.listen_dial_addr
            .lock()
            .expect("lock")
            .clone()
            .unwrap_or_default()
    }

    /// Release the TCP bind without dropping the driver or store.
    pub fn release_listen(&self) -> String {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(Cmd::ReleaseListen { reply: reply_tx })
            .is_err()
        {
            return "ERROR:driver_gone".into();
        }
        match self.rt.block_on(reply_rx) {
            Ok(s) => {
                *self.listen_dial_addr.lock().expect("lock") = None;
                s
            }
            Err(_) => "ERROR:release_cancelled".into(),
        }
    }

    /// Last pushed or pulled event id hex (empty if none this process).
    pub fn last_tip_hex(&self) -> String {
        self.last_tip.lock().expect("lock").clone()
    }

    /// Store the peer device verifying key used to verify reverse-path events
    /// on a reused TCP session (listener → scanner after one-way QR).
    pub fn remember_peer_device_vk(&self, author_device_pubkey: Vec<u8>) -> String {
        if author_device_pubkey.len() != 32 {
            return "ERROR:bad_vk".into();
        }
        let mut author_vk = [0u8; 32];
        author_vk.copy_from_slice(&author_device_pubkey);
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(Cmd::RememberPeerVk {
                author_vk,
                reply: reply_tx,
            })
            .is_err()
        {
            return "ERROR:driver_gone".into();
        }
        match self.rt.block_on(reply_rx) {
            Ok(s) => s,
            Err(_) => "ERROR:vk_cancelled".into(),
        }
    }

    /// Configure TCP rooms-relay fallback (`host:port` + shared token hex). Empty host clears.
    pub fn configure_relay(&self, relay_host_port: String, token_hex: String) -> String {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(Cmd::ConfigureRelay {
                relay_host_port,
                token_hex,
                reply: reply_tx,
            })
            .is_err()
        {
            return "ERROR:driver_gone".into();
        }
        match self.rt.block_on(reply_rx) {
            Ok(s) => s,
            Err(_) => "ERROR:relay_cfg_cancelled".into(),
        }
    }

    pub fn sync_push_signed_event(
        &self,
        _secret_blob: Vec<u8>,
        room_id: Vec<u8>,
        wire_envelope: Vec<u8>,
        peer_multiaddr: String,
        timeout_ms: u32,
    ) -> String {
        if room_id.len() != 32 {
            return "ERROR:bad_room_id".into();
        }
        let mut room = [0u8; 32];
        room.copy_from_slice(&room_id);
        let (reply_tx, reply_rx) = oneshot::channel();
        let timeout = Duration::from_millis(u64::from(timeout_ms.max(1)));
        if self
            .cmd_tx
            .send(Cmd::Push {
                room,
                wire: wire_envelope,
                peer_multiaddr,
                timeout,
                reply: reply_tx,
            })
            .is_err()
        {
            return "ERROR:driver_gone".into();
        }
        match self.rt.block_on(reply_rx) {
            Ok(s) => s,
            Err(_) => "ERROR:push_cancelled".into(),
        }
    }

    pub fn sync_pull_one_event(
        &self,
        room_id: Vec<u8>,
        author_device_pubkey: Vec<u8>,
        timeout_ms: u32,
    ) -> Vec<u8> {
        if room_id.len() != 32 || author_device_pubkey.len() != 32 {
            return b"ERR:bad_args".to_vec();
        }
        let mut room = [0u8; 32];
        room.copy_from_slice(&room_id);
        let mut author_vk = [0u8; 32];
        author_vk.copy_from_slice(&author_device_pubkey);
        let (reply_tx, reply_rx) = oneshot::channel();
        let timeout = Duration::from_millis(u64::from(timeout_ms.max(1)));
        if self
            .cmd_tx
            .send(Cmd::Pull {
                room,
                author_vk,
                timeout,
                reply: reply_tx,
            })
            .is_err()
        {
            return b"ERR:driver_gone".to_vec();
        }
        match self.rt.block_on(reply_rx) {
            Ok(v) => v,
            Err(_) => b"ERR:pull_cancelled".to_vec(),
        }
    }
}

impl Drop for SyncLabNode {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(Cmd::Shutdown);
    }
}

struct LabState {
    listener: Option<Arc<TcpListener>>,
    store: Arc<AsyncMutex<LabKv>>,
    peer_id: String,
    relay: RelayConfig,
    session: SessionShare,
}

async fn drive(
    mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    store_dir: String,
    last_tip: Arc<Mutex<String>>,
) {
    let mut state = LabState {
        listener: None,
        store: Arc::new(AsyncMutex::new(open_lab_kv(&store_dir))),
        peer_id: String::new(),
        relay: RelayConfig::default(),
        session: SessionShare::new(),
    };
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            Cmd::Shutdown => break,
            Cmd::ReleaseListen { reply } => {
                state.listener = None;
                *state.session.parked.lock().await = None;
                let _ = reply.send("ok".into());
            }
            Cmd::Listen {
                bind,
                advertise_ip,
                timeout,
                reply,
            } => {
                let out = match listen_bind(&bind, &advertise_ip, timeout).await {
                    Ok((listener, dial, pid)) => {
                        state.listener = Some(Arc::new(listener));
                        state.peer_id = pid;
                        dial
                    }
                    Err(e) => e,
                };
                let _ = reply.send(out);
            }
            Cmd::ConfigureRelay {
                relay_host_port,
                token_hex,
                reply,
            } => {
                let out = apply_relay_config(&mut state.relay, &relay_host_port, &token_hex);
                let _ = reply.send(out);
            }
            Cmd::RememberPeerVk { author_vk, reply } => {
                if let Ok(mut g) = state.session.peer_vk.lock() {
                    *g = Some(author_vk);
                }
                let _ = reply.send("ok".into());
            }
            // Push/Pull must not serialize on the drive loop: a blocking inbox
            // accept previously starved outbound send (and deadlocked when both
            // phones were mid-pull). Spawn so dial + accept can overlap.
            Cmd::Push {
                room,
                wire,
                peer_multiaddr,
                timeout,
                reply,
            } => {
                let store = Arc::clone(&state.store);
                let relay = state.relay.clone();
                let last_tip = Arc::clone(&last_tip);
                let session = state.session.clone();
                tokio::spawn(async move {
                    let out = push_event(
                        store,
                        room,
                        wire,
                        &peer_multiaddr,
                        timeout,
                        &relay,
                        session,
                        Arc::clone(&last_tip),
                    )
                    .await;
                    if !out.starts_with("ERROR:") && out.len() == 64 {
                        if let Ok(mut g) = last_tip.lock() {
                            *g = out.clone();
                        }
                    }
                    let _ = reply.send(out);
                });
            }
            Cmd::Pull {
                room,
                author_vk,
                timeout,
                reply,
            } => {
                if let Ok(mut g) = state.session.peer_vk.lock() {
                    *g = Some(author_vk);
                }
                let listener = state.listener.clone();
                let store = Arc::clone(&state.store);
                let relay = state.relay.clone();
                let last_tip = Arc::clone(&last_tip);
                let session = state.session.clone();
                tokio::spawn(async move {
                    let out = pull_event(
                        listener,
                        store,
                        room,
                        author_vk,
                        timeout,
                        &relay,
                        &last_tip,
                        session,
                    )
                    .await;
                    let _ = reply.send(out);
                });
            }
        }
    }
}

fn parse_relay_tokens(token_hex: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let raw = token_hex.trim();
    if raw.is_empty() {
        return Err("empty".into());
    }
    // `pushHex:pullHex` — directional so our Send cannot splice with our inbox.
    // Single hex keeps the old shared-token behaviour.
    let (push_hex, pull_hex) = match raw.split_once(':') {
        Some((a, b)) => (a.trim(), b.trim()),
        None => (raw, raw),
    };
    let push = hex_decode(push_hex)?;
    let pull = hex_decode(pull_hex)?;
    if push.is_empty() || pull.is_empty() || push.len() > 256 || pull.len() > 256 {
        return Err("token_len".into());
    }
    Ok((push, pull))
}

fn apply_relay_config(cfg: &mut RelayConfig, host_port: &str, token_hex: &str) -> String {
    let host = host_port.trim();
    if host.is_empty() {
        cfg.addr = None;
        cfg.push_token = None;
        cfg.pull_token = None;
        return "ok".into();
    }
    if !host.contains(':') {
        return "ERROR:relay_addr_need_host_port".into();
    }
    let (push, pull) = match parse_relay_tokens(token_hex) {
        Ok(t) => t,
        Err(e) => return format!("ERROR:relay_token:{e}"),
    };
    cfg.addr = Some(host.to_string());
    cfg.push_token = Some(push);
    cfg.pull_token = Some(pull);
    "ok".into()
}

async fn listen_bind(
    bind_multiaddr: &str,
    advertise_ip: &str,
    timeout: Duration,
) -> Result<(TcpListener, String, String), String> {
    let sock = parse_tcp_multiaddr(bind_multiaddr).map_err(|e| format!("ERROR:bad_bind:{e}"))?;
    let listen_fut = TcpListener::bind(sock);
    let listener = tokio::time::timeout(timeout, listen_fut)
        .await
        .map_err(|_| "ERROR:listen_timeout".to_string())?
        .map_err(|e| format!("ERROR:listen:{e}"))?;
    let local = listener
        .local_addr()
        .map_err(|e| format!("ERROR:local_addr:{e}"))?;
    let port = local.port();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    use std::hash::{Hash, Hasher};
    local.hash(&mut h);
    let pid = format!("{:016x}", h.finish());
    let dial = format!("/ip4/{advertise_ip}/tcp/{port}/p2p/{pid}");
    Ok((listener, dial, pid))
}

const REVERSE_IDLE: Duration = Duration::from_secs(180);

#[allow(clippy::too_many_arguments)]
async fn push_event(
    store: Arc<AsyncMutex<LabKv>>,
    room: [u8; 32],
    wire: Vec<u8>,
    peer_multiaddr: &str,
    timeout: Duration,
    relay: &RelayConfig,
    session: SessionShare,
    last_tip: Arc<Mutex<String>>,
) -> String {
    let event = match decode_message_event_wire_v1(&wire) {
        Ok(e) => e,
        Err(e) => return format!("ERROR:decode_wire:{e:?}"),
    };
    if event.room_id.0 != room {
        return "ERROR:room_mismatch".into();
    }
    {
        let mut store = store.lock().await;
        if let Err(e) = EventStore::new(&mut *store).put_event(&event) {
            return format!("ERROR:put_event:{e:?}");
        }
        if let Err(e) = Outbox::new(&mut *store).enqueue(&event) {
            return format!("ERROR:enqueue:{e:?}");
        }
    }
    let mut replica = SyncReplica::new(Cid(room));
    replica.tips.push(event.id);
    replica.vv.counters.push((event.author_device_id, 1));

    session.pull_abort.notify_waiters();

    let parked_stream = session.parked.lock().await.take();
    if let Some(mut stream) = parked_stream {
        let _ = stream.set_nodelay(true);
        let out = provider_sync_on_stream(
            Arc::clone(&store),
            &mut replica,
            &event,
            &mut stream,
            timeout,
        )
        .await;
        if !out.starts_with("ERROR:") && out.len() == 64 {
            spawn_turnaround(store, room, session, last_tip, stream);
            return out;
        }
        // Stale reverse socket — fall through to a fresh dial.
    }

    let direct_timeout = timeout.min(Duration::from_secs(8));
    let mut used_relay = false;
    let mut stream = if !lan_dialable(peer_multiaddr) {
        used_relay = true;
        match try_relay_dial(relay, false, timeout).await {
            Ok(s) => s,
            Err(relay_err) => {
                return format!("ERROR:connect:no_lan;relay:{relay_err}");
            }
        }
    } else {
        match try_direct_dial(peer_multiaddr, direct_timeout).await {
            Ok(s) => s,
            Err(direct_err) => {
                used_relay = true;
                match try_relay_dial(relay, false, timeout).await {
                    Ok(s) => s,
                    Err(relay_err) => {
                        return format!("ERROR:connect:{direct_err};relay:{relay_err}");
                    }
                }
            }
        }
    };
    let _ = stream.set_nodelay(true);

    let out = provider_sync_on_stream(store.clone(), &mut replica, &event, &mut stream, timeout)
        .await;
    if !out.starts_with("ERROR:") && out.len() == 64 {
        spawn_turnaround(store, room, session, last_tip, stream);
        if used_relay {
            return format!("{out}+relay");
        }
    }
    out
}

fn spawn_turnaround(
    store: Arc<AsyncMutex<LabKv>>,
    room: [u8; 32],
    session: SessionShare,
    last_tip: Arc<Mutex<String>>,
    mut stream: TcpStream,
) {
    tokio::spawn(async move {
        loop {
            let offer = match tokio::time::timeout(REVERSE_IDLE, read_frame(&mut stream)).await {
                Ok(Ok(b)) => b,
                _ => break,
            };
            let vk_bytes = match session.peer_vk.lock() {
                Ok(g) => *g,
                Err(_) => break,
            };
            let Some(vk_bytes) = vk_bytes else {
                break;
            };
            let Ok(vk) = verifying_key_from_bytes(&vk_bytes) else {
                break;
            };
            let ct = consumer_sync_after_offer(
                Arc::clone(&store),
                room,
                &vk,
                &mut stream,
                REVERSE_IDLE,
                &last_tip,
                offer,
            )
            .await;
            if ct.starts_with(b"ERR:") {
                break;
            }
            if session.inbound_tx.send(ct).is_err() {
                break;
            }
        }
    });
}

async fn try_direct_dial(peer_multiaddr: &str, timeout: Duration) -> Result<TcpStream, String> {
    let addr = parse_tcp_multiaddr(peer_multiaddr).map_err(|e| format!("bad_dial:{e}"))?;
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(format!("connect:{e}")),
        Err(_) => Err("connect_timeout".into()),
    }
}

async fn try_relay_dial(
    relay: &RelayConfig,
    role_b: bool,
    timeout: Duration,
) -> Result<TcpStream, String> {
    let (Some(addr), Some(token)) = (relay.addr.as_ref(), relay.token_for(role_b)) else {
        return Err("relay_not_configured".into());
    };
    tokio::time::timeout(timeout, dial_via_relay(addr, token, role_b))
        .await
        .map_err(|_| "relay_timeout".to_string())?
}

/// TCP rooms-relay client (DRRL) — mirrors `rooms_transport::dial_via_relay`.
async fn dial_via_relay(relay_addr: &str, token: &[u8], role_b: bool) -> Result<TcpStream, String> {
    let mut stream = TcpStream::connect(relay_addr)
        .await
        .map_err(|e| format!("relay_connect:{e}"))?;
    let _ = stream.set_nodelay(true);
    let mut reg = Vec::with_capacity(4 + 1 + 2 + token.len() + 1);
    reg.extend_from_slice(RELAY_MAGIC);
    reg.push(RELAY_VERSION);
    reg.extend_from_slice(&(token.len() as u16).to_le_bytes());
    reg.extend_from_slice(token);
    reg.push(if role_b { 1 } else { 0 });
    stream
        .write_all(&reg)
        .await
        .map_err(|e| format!("relay_reg:{e}"))?;
    let mut ack = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(90), stream.read_exact(&mut ack))
        .await
        .map_err(|_| "relay_ack_timeout".to_string())?
        .map_err(|e| format!("relay_ack:{e}"))?;
    if ack[0] != 0x01 {
        return Err("relay_bad_ack".into());
    }
    Ok(stream)
}

async fn provider_sync_on_stream(
    store: Arc<AsyncMutex<LabKv>>,
    replica: &mut SyncReplica,
    event: &rooms_proto::MessageEvent,
    stream: &mut TcpStream,
    timeout: Duration,
) -> String {
    let offer = match replica.build_offer().encode_v1() {
        Ok(b) => b,
        Err(e) => return format!("ERROR:offer:{e:?}"),
    };
    if let Err(e) = write_frame(stream, &offer).await {
        return format!("ERROR:write_offer:{e}");
    }
    let want_bytes = match tokio::time::timeout(timeout, read_frame(stream)).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => return format!("ERROR:want:{e}"),
        Err(_) => return "ERROR:want_timeout".into(),
    };
    let have = {
        let store = store.lock().await;
        match have_bytes_from_want(&*store, &want_bytes) {
            Ok(b) => b,
            Err(e) => return format!("ERROR:have:{e:?}"),
        }
    };
    if let Err(e) = write_frame(stream, &have).await {
        return format!("ERROR:write_have:{e}");
    }
    let ack_bytes = match tokio::time::timeout(timeout, read_frame(stream)).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => return format!("ERROR:ack:{e}"),
        Err(_) => return "ERROR:ack_timeout".into(),
    };
    let ack = match rooms_proto::decode_sync_ack_v1(&ack_bytes) {
        Ok(a) => a,
        Err(e) => return format!("ERROR:decode_ack:{e:?}"),
    };
    if !ack.applied_tips.iter().any(|tip| *tip == event.id) {
        return "ERROR:ack_tips_mismatch".into();
    }
    let mut store = store.lock().await;
    match Outbox::new(&mut *store).apply_ack(&ack) {
        Ok(n) if n >= 1 => hex_encode(&event.id.0),
        Ok(_) => "ERROR:ack_removed:0".into(),
        Err(e) => format!("ERROR:apply_ack:{e:?}"),
    }
}

async fn pull_event(
    listener: Option<Arc<TcpListener>>,
    store: Arc<AsyncMutex<LabKv>>,
    room: [u8; 32],
    author_vk_bytes: [u8; 32],
    timeout: Duration,
    relay: &RelayConfig,
    last_tip: &Arc<Mutex<String>>,
    session: SessionShare,
) -> Vec<u8> {
    let Ok(vk) = verifying_key_from_bytes(&author_vk_bytes) else {
        return err_bytes("bad_vk");
    };

    {
        let mut rx = session.inbound_rx.lock().await;
        match rx.try_recv() {
            Ok(ct) => return ct,
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                return err_bytes("inbox_closed");
            }
        }
    }

    let inbound_wait = async {
        session.inbound_rx.lock().await.recv().await
    };

    if listener.is_none() && !relay.configured() {
        return match tokio::time::timeout(timeout, inbound_wait).await {
            Ok(Some(ct)) => ct,
            Ok(None) => err_bytes("inbox_closed"),
            Err(_) => err_bytes("accept_timeout"),
        };
    }

    let accept_fut = async {
        accept_or_relay(listener.as_ref(), relay, timeout, session.clone()).await
    };

    tokio::select! {
        queued = inbound_wait => match queued {
            Some(ct) => ct,
            None => err_bytes("inbox_closed"),
        },
        acc = accept_fut => match acc {
            Ok(mut stream) => {
                let _ = stream.set_nodelay(true);
                let ct = consumer_sync_on_stream(
                    Arc::clone(&store),
                    room,
                    &vk,
                    &mut stream,
                    timeout,
                    last_tip,
                )
                .await;
                if !ct.starts_with(b"ERR:") {
                    *session.parked.lock().await = Some(stream);
                }
                ct
            }
            Err(e) => err_bytes(&e),
        },
    }
}

async fn accept_or_relay(
    listener: Option<&Arc<TcpListener>>,
    relay: &RelayConfig,
    timeout: Duration,
    session: SessionShare,
) -> Result<TcpStream, String> {
    match (listener, relay.configured()) {
        (Some(listener), true) => {
            let relay_cfg = relay.clone();
            let accept_fut = async {
                match tokio::time::timeout(timeout, listener.accept()).await {
                    Ok(Ok((s, _))) => Ok(s),
                    Ok(Err(e)) => Err(format!("accept:{e}")),
                    Err(_) => Err("accept_timeout".into()),
                }
            };
            let relay_fut = async { try_relay_dial(&relay_cfg, true, timeout).await };
            let abort = session.pull_abort.notified();
            tokio::select! {
                r = accept_fut => r,
                r = relay_fut => r,
                _ = abort => Err("pull_aborted_for_send".into()),
            }
        }
        (Some(listener), false) => match tokio::time::timeout(timeout, listener.accept()).await {
            Ok(Ok((s, _))) => Ok(s),
            Ok(Err(e)) => Err(format!("accept:{e}")),
            Err(_) => Err("accept_timeout".into()),
        },
        (None, true) => {
            let relay_fut = try_relay_dial(relay, true, timeout);
            let abort = session.pull_abort.notified();
            tokio::select! {
                r = relay_fut => r,
                _ = abort => Err("pull_aborted_for_send".into()),
            }
        }
        (None, false) => Err("not_listening".into()),
    }
}

fn err_bytes(msg: &str) -> Vec<u8> {
    format!("ERR:{msg}").into_bytes()
}

async fn consumer_sync_on_stream(
    store: Arc<AsyncMutex<LabKv>>,
    room: [u8; 32],
    vk: &ed25519_dalek::VerifyingKey,
    stream: &mut TcpStream,
    timeout: Duration,
    last_tip: &Arc<Mutex<String>>,
) -> Vec<u8> {
    let offer = match tokio::time::timeout(timeout, read_frame(stream)).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => return err_bytes(&format!("offer:{e}")),
        Err(_) => return err_bytes("offer_timeout"),
    };
    consumer_sync_after_offer(store, room, vk, stream, timeout, last_tip, offer).await
}

async fn consumer_sync_after_offer(
    store: Arc<AsyncMutex<LabKv>>,
    room: [u8; 32],
    vk: &ed25519_dalek::VerifyingKey,
    stream: &mut TcpStream,
    timeout: Duration,
    last_tip: &Arc<Mutex<String>>,
    offer: Vec<u8>,
) -> Vec<u8> {
    let mut replica = SyncReplica::new(Cid(room));

    let want = match want_bytes_from_offer(&replica, &offer) {
        Ok(b) => b,
        Err(e) => return err_bytes(&format!("want:{e:?}")),
    };
    if let Err(e) = write_frame(stream, &want).await {
        return err_bytes(&format!("write_want:{e}"));
    }

    let have = match tokio::time::timeout(timeout, read_frame(stream)).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => return err_bytes(&format!("have:{e}")),
        Err(_) => return err_bytes("have_timeout"),
    };
    let (applied, ack) = {
        let mut store = store.lock().await;
        match ack_bytes_from_have(&mut *store, &mut replica, &have, vk) {
            Ok(v) => v,
            Err(e) => return err_bytes(&format!("ack:{e:?}")),
        }
    };
    // Always write ACK so the provider does not see `ERROR:ack:early eof`
    // when every Have object is skipped (verify fail / empty Have).
    if let Err(e) = write_frame(stream, &ack).await {
        return err_bytes(&format!("write_ack:{e}"));
    }
    if applied == 0 {
        return err_bytes("applied0");
    }

    let tip = match replica.tips.first() {
        Some(t) => *t,
        None => return err_bytes("no_tip"),
    };
    if let Ok(mut g) = last_tip.lock() {
        *g = hex_encode(&tip.0);
    }
    let store = store.lock().await;
    match store.get(Namespace::Events, &tip.0) {
        Ok(Some(wire)) => match decode_message_event_wire_v1(&wire) {
            Ok(ev) => ev.ciphertext,
            Err(e) => err_bytes(&format!("decode:{e:?}")),
        },
        Ok(None) => err_bytes("missing_event"),
        Err(e) => err_bytes(&format!("store:{e:?}")),
    }
}

async fn write_frame(stream: &mut TcpStream, data: &[u8]) -> Result<(), String> {
    if data.len() > MAX_FRAME {
        return Err("frame too large".into());
    }
    let len = (data.len() as u32).to_le_bytes();
    stream.write_all(&len).await.map_err(|e| e.to_string())?;
    stream.write_all(data).await.map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| e.to_string())?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err("frame too large".into());
    }
    let mut buf = vec![0u8; len];
    if len > 0 {
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(buf)
}

/// Parse `/ip4/A.B.C.D/tcp/PORT` (optional trailing `/p2p/...`).
fn parse_tcp_multiaddr(s: &str) -> Result<std::net::SocketAddr, String> {
    let parts: Vec<&str> = s.split('/').filter(|p| !p.is_empty()).collect();
    // ip4, ADDR, tcp, PORT, ...
    if parts.len() < 4 || parts[0] != "ip4" || parts[2] != "tcp" {
        return Err(format!("expected /ip4/…/tcp/… got {s}"));
    }
    let ip: std::net::IpAddr = parts[1].parse().map_err(|e| format!("ip:{e}"))?;
    let port: u16 = parts[3].parse().map_err(|e| format!("port:{e}"))?;
    Ok(std::net::SocketAddr::new(ip, port))
}

/// BLE-only / empty listen addrs skip the ~8s LAN dial and go straight to relay.
fn lan_dialable(peer_multiaddr: &str) -> bool {
    let s = peer_multiaddr.trim();
    if s.is_empty() || s.starts_with("ble://") {
        return false;
    }
    parse_tcp_multiaddr(s).is_ok()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    let clean = hex.trim();
    if clean.is_empty() || clean.len() % 2 != 0 {
        return Err("odd_or_empty".into());
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    for i in 0..(clean.len() / 2) {
        let b = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).map_err(|e| format!("hex:{e}"))?;
        out.push(b);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rooms_identity::create_identity_osrng;
    use rooms_proto::ContentType;
    use rooms_sync::{create_signed_message_event, verify_message_event};
    use std::thread;
    use std::time::Duration as StdDuration;

    #[test]
    fn parse_multiaddr_strips_p2p() {
        let a = parse_tcp_multiaddr("/ip4/192.168.1.5/tcp/44001/p2p/abc").unwrap();
        assert_eq!(a.port(), 44001);
    }

    #[test]
    fn ble_listen_is_not_lan_dialable() {
        assert!(!lan_dialable("ble://offline"));
        assert!(!lan_dialable(""));
        assert!(lan_dialable("/ip4/192.168.1.8/tcp/44001/p2p/dead"));
    }

    #[test]
    fn two_lab_nodes_sync_localhost() {
        let alice = create_identity_osrng();
        let room = [0xE2u8; 32];
        let sealed = b"\x02lab-opaque-ct".to_vec();
        let event = create_signed_message_event(
            Cid(room),
            alice.device_id().0,
            alice.identity_id().0,
            vec![],
            0,
            ContentType::Text,
            sealed.clone(),
            &alice.device,
        );
        verify_message_event(&event, &alice.device.verifying_key()).unwrap();
        let wire = rooms_proto::encode_message_event_wire_v1(&event).unwrap();

        let consumer = SyncLabNode::new();
        let provider = SyncLabNode::new();
        let dial = consumer.listen_tcp("/ip4/127.0.0.1/tcp/0".into(), "127.0.0.1".into(), 5_000);
        eprintln!("dial_addr={dial}");
        assert!(dial.starts_with("/ip4/127.0.0.1/"), "dial={dial}");
        assert!(!dial.starts_with("ERROR:"), "{dial}");

        let vk = alice.device.verifying_key().to_bytes().to_vec();
        let room_v = room.to_vec();
        let pull = thread::spawn(move || consumer.sync_pull_one_event(room_v, vk, 10_000));

        thread::sleep(StdDuration::from_millis(200));

        let tip = provider.sync_push_signed_event(Vec::new(), room.to_vec(), wire, dial, 10_000);
        eprintln!("push_tip={tip}");
        assert_eq!(tip.len(), 64, "tip={tip}");
        assert!(!tip.starts_with("ERROR:"), "{tip}");

        let ct = pull.join().expect("join");
        assert!(
            !ct.starts_with(b"ERR:"),
            "pull err {}",
            String::from_utf8_lossy(&ct)
        );
        assert_eq!(ct, sealed);
        assert_eq!(provider.last_tip_hex(), tip);
    }

    #[test]
    fn two_sequential_pushes_same_direction() {
        let alice = create_identity_osrng();
        let room = [0xE5u8; 32];
        let first = b"\x02first".to_vec();
        let second = b"\x02second".to_vec();
        let wire1 = lab_signed(&alice, room, &first);
        let wire2 = lab_signed(&alice, room, &second);
        let vk = alice.device.verifying_key().to_bytes().to_vec();
        let consumer = SyncLabNode::new();
        let provider = SyncLabNode::new();
        let dial = consumer.listen_tcp("/ip4/127.0.0.1/tcp/0".into(), "127.0.0.1".into(), 5_000);
        assert!(!dial.starts_with("ERROR:"), "{dial}");

        std::thread::scope(|s| {
            let pull1 = s.spawn(|| consumer.sync_pull_one_event(room.to_vec(), vk.clone(), 10_000));
            thread::sleep(StdDuration::from_millis(200));
            let tip1 = provider.sync_push_signed_event(
                Vec::new(),
                room.to_vec(),
                wire1,
                dial.clone(),
                10_000,
            );
            assert!(!tip1.starts_with("ERROR:"), "first {tip1}");
            assert_eq!(pull1.join().expect("join"), first);
        });

        std::thread::scope(|s| {
            let pull2 = s.spawn(|| consumer.sync_pull_one_event(room.to_vec(), vk.clone(), 10_000));
            thread::sleep(StdDuration::from_millis(200));
            let tip2 = provider.sync_push_signed_event(
                Vec::new(),
                room.to_vec(),
                wire2,
                dial,
                10_000,
            );
            assert!(!tip2.starts_with("ERROR:"), "second {tip2}");
            assert_eq!(pull2.join().expect("join"), second);
        });
    }

    fn lab_signed(
        id: &rooms_identity::GeneratedIdentity,
        room: [u8; 32],
        sealed: &[u8],
    ) -> Vec<u8> {
        let event = create_signed_message_event(
            Cid(room),
            id.device_id().0,
            id.identity_id().0,
            vec![],
            0,
            ContentType::Text,
            sealed.to_vec(),
            &id.device,
        );
        rooms_proto::encode_message_event_wire_v1(&event).unwrap()
    }

    #[test]
    fn two_lab_nodes_sync_both_directions() {
        let alice = create_identity_osrng();
        let bob = create_identity_osrng();
        let room = [0xE2u8; 32];
        let a_ct = b"\x02alice-to-bob".to_vec();
        let b_ct = b"\x02bob-to-alice".to_vec();
        let a_wire = lab_signed(&alice, room, &a_ct);
        let b_wire = lab_signed(&bob, room, &b_ct);
        let a_vk = alice.device.verifying_key().to_bytes().to_vec();
        let b_vk = bob.device.verifying_key().to_bytes().to_vec();

        let a = SyncLabNode::new();
        let b = SyncLabNode::new();
        let a_dial = a.listen_tcp("/ip4/127.0.0.1/tcp/0".into(), "127.0.0.1".into(), 5_000);
        let b_dial = b.listen_tcp("/ip4/127.0.0.1/tcp/0".into(), "127.0.0.1".into(), 5_000);
        assert!(!a_dial.starts_with("ERROR:"), "{a_dial}");
        assert!(!b_dial.starts_with("ERROR:"), "{b_dial}");
        assert_eq!(a.remember_peer_device_vk(b_vk.clone()), "ok");
        assert_eq!(b.remember_peer_device_vk(a_vk.clone()), "ok");

        std::thread::scope(|s| {
            let pull = s.spawn(|| b.sync_pull_one_event(room.to_vec(), a_vk.clone(), 10_000));
            thread::sleep(StdDuration::from_millis(200));
            let tip = a.sync_push_signed_event(
                Vec::new(),
                room.to_vec(),
                a_wire.clone(),
                b_dial.clone(),
                10_000,
            );
            assert!(!tip.starts_with("ERROR:"), "a→b {tip}");
            let got = pull.join().expect("join");
            assert_eq!(got, a_ct, "a→b {}", String::from_utf8_lossy(&got));
        });

        std::thread::scope(|s| {
            let pull = s.spawn(|| a.sync_pull_one_event(room.to_vec(), b_vk.clone(), 10_000));
            thread::sleep(StdDuration::from_millis(200));
            let tip = b.sync_push_signed_event(
                Vec::new(),
                room.to_vec(),
                b_wire,
                a_dial,
                10_000,
            );
            assert!(!tip.starts_with("ERROR:"), "b→a {tip}");
            let got = pull.join().expect("join");
            assert_eq!(got, b_ct, "b→a {}", String::from_utf8_lossy(&got));
        });
    }

    #[test]
    fn reverse_send_reuses_tcp_without_second_listen() {
        let scanner_id = create_identity_osrng();
        let listener_id = create_identity_osrng();
        let room = [0xE4u8; 32];
        let scan_ct = b"\x02scanner-first".to_vec();
        let listen_ct = b"\x02listener-reply".to_vec();
        let scan_wire = lab_signed(&scanner_id, room, &scan_ct);
        let listen_wire = lab_signed(&listener_id, room, &listen_ct);
        let scan_vk = scanner_id.device.verifying_key().to_bytes().to_vec();
        let listen_vk = listener_id.device.verifying_key().to_bytes().to_vec();

        let scanner = SyncLabNode::new();
        let listener = SyncLabNode::new();
        let listener_dial =
            listener.listen_tcp("/ip4/127.0.0.1/tcp/0".into(), "127.0.0.1".into(), 5_000);
        assert!(!listener_dial.starts_with("ERROR:"), "{listener_dial}");
        assert_eq!(scanner.remember_peer_device_vk(listen_vk.clone()), "ok");
        assert_eq!(listener.remember_peer_device_vk(scan_vk.clone()), "ok");

        std::thread::scope(|s| {
            let pull = s.spawn(|| listener.sync_pull_one_event(room.to_vec(), scan_vk.clone(), 10_000));
            thread::sleep(StdDuration::from_millis(200));
            let tip = scanner.sync_push_signed_event(
                Vec::new(),
                room.to_vec(),
                scan_wire,
                listener_dial,
                10_000,
            );
            assert!(!tip.starts_with("ERROR:"), "scanner→listener {tip}");
            let got = pull.join().expect("join");
            assert_eq!(got, scan_ct, "{}", String::from_utf8_lossy(&got));
        });

        std::thread::scope(|s| {
            let pull = s.spawn(|| scanner.sync_pull_one_event(room.to_vec(), listen_vk.clone(), 10_000));
            thread::sleep(StdDuration::from_millis(200));
            let tip = listener.sync_push_signed_event(
                Vec::new(),
                room.to_vec(),
                listen_wire,
                "/ip4/127.0.0.1/tcp/1".into(),
                10_000,
            );
            assert!(
                !tip.starts_with("ERROR:"),
                "listener→scanner reverse {tip}"
            );
            assert!(!tip.contains("early eof"), "{tip}");
            let got = pull.join().expect("join");
            assert_eq!(got, listen_ct, "{}", String::from_utf8_lossy(&got));
        });
    }

    #[test]
    fn wrong_vk_acks_instead_of_early_eof() {
        let alice = create_identity_osrng();
        let bob = create_identity_osrng();
        let room = [0xE5u8; 32];
        let wire = lab_signed(&alice, room, b"\x02nope");
        let wrong_vk = bob.device.verifying_key().to_bytes().to_vec();

        let consumer = SyncLabNode::new();
        let provider = SyncLabNode::new();
        let dial = consumer.listen_tcp("/ip4/127.0.0.1/tcp/0".into(), "127.0.0.1".into(), 5_000);
        assert!(!dial.starts_with("ERROR:"), "{dial}");

        std::thread::scope(|s| {
            let pull = s.spawn(|| consumer.sync_pull_one_event(room.to_vec(), wrong_vk, 10_000));
            thread::sleep(StdDuration::from_millis(200));
            let tip = provider.sync_push_signed_event(Vec::new(), room.to_vec(), wire, dial, 10_000);
            let pulled = pull.join().expect("join");
            assert!(
                !tip.contains("early eof"),
                "provider should not see ACK EOF, got {tip}"
            );
            assert!(
                tip.contains("ack_tips_mismatch") || tip.starts_with("ERROR:ack"),
                "expected verify/ack mismatch, got {tip}"
            );
            let text = String::from_utf8_lossy(&pulled);
            assert!(text.contains("applied0") || text.starts_with("ERR:"), "{text}");
        });
    }

    #[test]
    fn sled_store_survives_drop_and_release_listen() {
        let dir = std::env::temp_dir().join(format!(
            "derooms-synclab-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let alice = create_identity_osrng();
        let room = [0xE3u8; 32];
        let sealed = b"\x02persist-ct".to_vec();
        let event = create_signed_message_event(
            Cid(room),
            alice.device_id().0,
            alice.identity_id().0,
            vec![],
            0,
            ContentType::Text,
            sealed.clone(),
            &alice.device,
        );
        let wire = rooms_proto::encode_message_event_wire_v1(&event).unwrap();

        let consumer = SyncLabNode::with_store_dir(dir.to_string_lossy().into_owned());
        let provider = SyncLabNode::new();
        let dial = consumer.listen_tcp("/ip4/127.0.0.1/tcp/0".into(), "127.0.0.1".into(), 5_000);
        assert!(!dial.starts_with("ERROR:"), "{dial}");

        let vk = alice.device.verifying_key().to_bytes().to_vec();
        let room_v = room.to_vec();
        let pull = thread::spawn(move || consumer.sync_pull_one_event(room_v, vk, 10_000));
        thread::sleep(StdDuration::from_millis(200));
        let tip = provider.sync_push_signed_event(Vec::new(), room.to_vec(), wire, dial, 10_000);
        assert_eq!(tip.len(), 64, "tip={tip}");
        let ct = pull.join().expect("join");
        assert_eq!(ct, sealed);
        drop(provider);

        thread::sleep(StdDuration::from_millis(200));
        let store = SledKvStore::open(&dir).expect("reopen sled");
        let tip_bytes = hex_decode(&tip).expect("tip hex");
        let got = store
            .get(Namespace::Events, &tip_bytes)
            .expect("get")
            .expect("event persisted");
        assert!(!got.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_lab_nodes_sync_via_relay_fallback() {
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::Mutex as TokioMutex;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let pending: Arc<TokioMutex<HashMap<Vec<u8>, TcpStream>>> =
            Arc::new(TokioMutex::new(HashMap::new()));
        let listener = rt
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let relay_addr = listener.local_addr().unwrap().to_string();
        let pending_c = pending.clone();
        rt.spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    continue;
                };
                let pending = pending_c.clone();
                tokio::spawn(async move {
                    let mut hdr = [0u8; 7];
                    if stream.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    let token_len = u16::from_le_bytes([hdr[5], hdr[6]]) as usize;
                    let mut rest = vec![0u8; token_len + 1];
                    if stream.read_exact(&mut rest).await.is_err() {
                        return;
                    }
                    let token = rest[..token_len].to_vec();
                    let maybe = {
                        let mut map = pending.lock().await;
                        map.remove(&token)
                    };
                    if let Some(mut first) = maybe {
                        let _ = first.write_all(&[0x01]).await;
                        let _ = stream.write_all(&[0x01]).await;
                        let (mut ar, mut aw) = first.into_split();
                        let (mut br, mut bw) = stream.into_split();
                        let ab = tokio::spawn(async move {
                            let _ = tokio::io::copy(&mut ar, &mut bw).await;
                        });
                        let ba = tokio::spawn(async move {
                            let _ = tokio::io::copy(&mut br, &mut aw).await;
                        });
                        let _ = tokio::join!(ab, ba);
                    } else {
                        pending.lock().await.insert(token, stream);
                    }
                });
            }
        });

        let alice = create_identity_osrng();
        let room = [0xE2u8; 32];
        let sealed = b"\x02relay-opaque-ct".to_vec();
        let event = create_signed_message_event(
            Cid(room),
            alice.device_id().0,
            alice.identity_id().0,
            vec![],
            0,
            ContentType::Text,
            sealed.clone(),
            &alice.device,
        );
        let wire = rooms_proto::encode_message_event_wire_v1(&event).unwrap();
        let token_hex = "a1b2c3d4e5f60708";

        let consumer = SyncLabNode::new();
        let provider = SyncLabNode::new();
        assert_eq!(
            consumer.configure_relay(relay_addr.clone(), token_hex.into()),
            "ok"
        );
        assert_eq!(
            provider.configure_relay(relay_addr.clone(), token_hex.into()),
            "ok"
        );
        // Unreachable peer → forces relay fallback on push; pull races relay.
        let _ = consumer.listen_tcp("/ip4/127.0.0.1/tcp/0".into(), "127.0.0.1".into(), 5_000);
        let bad_dial = "/ip4/127.0.0.1/tcp/1/p2p/dead".to_string();

        let vk = alice.device.verifying_key().to_bytes().to_vec();
        let room_v = room.to_vec();
        let pull = thread::spawn(move || consumer.sync_pull_one_event(room_v, vk, 15_000));
        thread::sleep(StdDuration::from_millis(300));
        let tip =
            provider.sync_push_signed_event(Vec::new(), room.to_vec(), wire, bad_dial, 15_000);
        let (hex, via_relay) = if tip.ends_with("+relay") {
            (tip.trim_end_matches("+relay").to_string(), true)
        } else {
            (tip.clone(), false)
        };
        assert_eq!(hex.len(), 64, "tip={tip}");
        assert!(via_relay, "LAN-fail path should mark +relay, tip={tip}");
        let ct = pull.join().expect("join");
        assert!(
            !ct.starts_with(b"ERR:"),
            "pull err {}",
            String::from_utf8_lossy(&ct)
        );
        assert_eq!(ct, sealed);
    }

    #[test]
    fn two_lab_nodes_sync_via_relay_without_lan_listen() {
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::Mutex as TokioMutex;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let pending: Arc<TokioMutex<HashMap<Vec<u8>, TcpStream>>> =
            Arc::new(TokioMutex::new(HashMap::new()));
        let listener = rt
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let relay_addr = listener.local_addr().unwrap().to_string();
        let pending_c = pending.clone();
        rt.spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    continue;
                };
                let pending = pending_c.clone();
                tokio::spawn(async move {
                    let mut hdr = [0u8; 7];
                    if stream.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    let token_len = u16::from_le_bytes([hdr[5], hdr[6]]) as usize;
                    let mut rest = vec![0u8; token_len + 1];
                    if stream.read_exact(&mut rest).await.is_err() {
                        return;
                    }
                    let token = rest[..token_len].to_vec();
                    let maybe = {
                        let mut map = pending.lock().await;
                        map.remove(&token)
                    };
                    if let Some(mut first) = maybe {
                        let _ = first.write_all(&[0x01]).await;
                        let _ = stream.write_all(&[0x01]).await;
                        let (mut ar, mut aw) = first.into_split();
                        let (mut br, mut bw) = stream.into_split();
                        let ab = tokio::spawn(async move {
                            let _ = tokio::io::copy(&mut ar, &mut bw).await;
                        });
                        let ba = tokio::spawn(async move {
                            let _ = tokio::io::copy(&mut br, &mut aw).await;
                        });
                        let _ = tokio::join!(ab, ba);
                    } else {
                        pending.lock().await.insert(token, stream);
                    }
                });
            }
        });

        let alice = create_identity_osrng();
        let room = [0xE2u8; 32];
        let sealed = b"\x02relay-ble-only".to_vec();
        let event = create_signed_message_event(
            Cid(room),
            alice.device_id().0,
            alice.identity_id().0,
            vec![],
            0,
            ContentType::Text,
            sealed.clone(),
            &alice.device,
        );
        let wire = rooms_proto::encode_message_event_wire_v1(&event).unwrap();
        let token_hex = "b1c2d3e4f5060708";

        let consumer = SyncLabNode::new();
        let provider = SyncLabNode::new();
        assert_eq!(
            consumer.configure_relay(relay_addr.clone(), token_hex.into()),
            "ok"
        );
        assert_eq!(
            provider.configure_relay(relay_addr.clone(), token_hex.into()),
            "ok"
        );
        // BLE-only listen: no listen_tcp. Pull must still race the relay.
        let vk = alice.device.verifying_key().to_bytes().to_vec();
        let room_v = room.to_vec();
        let pull = thread::spawn(move || consumer.sync_pull_one_event(room_v, vk, 15_000));
        thread::sleep(StdDuration::from_millis(300));
        let tip = provider.sync_push_signed_event(
            Vec::new(),
            room.to_vec(),
            wire,
            "ble://offline".into(),
            15_000,
        );
        assert!(
            tip.ends_with("+relay"),
            "ble listen should skip LAN and mark +relay, tip={tip}"
        );
        let hex = tip.trim_end_matches("+relay");
        assert_eq!(hex.len(), 64, "tip={tip}");
        let ct = pull.join().expect("join");
        assert!(
            !ct.starts_with(b"ERR:"),
            "pull err {}",
            String::from_utf8_lossy(&ct)
        );
        assert_eq!(ct, sealed);
    }
}
