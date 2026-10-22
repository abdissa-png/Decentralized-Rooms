//! Minimal TCP circuit relay for NAT / no shared LAN (Gate 1 residual / WBS 4.4.3).
//!
//! Two clients register with the same session token; the relay ACKs both then splices
//! bidirectional byte streams. This is **not** libp2p relay v2 — see `docs/relay-nat.md`.
//! Payload confidentiality remains end-to-end; the relay sees ciphertext only.
//!
//! Hardening (Phase 2): pending-session TTL, max concurrent pending, empty-token
//! reject, stale waiter eviction, multi-session (independent tokens), reconnect
//! after splice ends (token reusable once the pair disconnects), register
//! read timeout, splice idle timeout, host:port normalize helper.
//!
//! This is the **primary** NAT helper for Gate 2. libp2p circuit relay v2 remains
//! deferred (see `docs/relay-nat.md`) — enabling the Cargo `relay` feature alone
//! is not enough without on-device circuit dial/listen plumbing.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// Magic for relay handshake (`DRRL`).
pub const RELAY_MAGIC: &[u8; 4] = b"DRRL";
/// Handshake version.
pub const RELAY_VERSION: u8 = 1;

/// How long a lone waiter may sit before being dropped.
pub const PENDING_TTL: Duration = Duration::from_secs(120);
/// Cap on simultaneous unpaired waiters (DoS / resource bound).
pub const MAX_PENDING_SESSIONS: usize = 64;
/// Cap on concurrent active splices (paired byte-forwarding sessions).
pub const MAX_ACTIVE_SPLICES: usize = 32;
/// Client wait for peer ACK before timing out the dial.
pub const DIAL_ACK_TIMEOUT: Duration = Duration::from_secs(90);
/// Server-side timeout reading the register frame (slowloris guard).
pub const REGISTER_READ_TIMEOUT: Duration = Duration::from_secs(20);
/// Idle timeout on each splice half (no bytes either direction → drop).
pub const SPLICE_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Errors from the TCP relay helper.
#[derive(Clone, Debug)]
pub enum RelayError {
    Io(String),
    Protocol(String),
    Timeout,
    PeerGone,
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) | Self::Protocol(s) => write!(f, "{s}"),
            Self::Timeout => write!(f, "timeout"),
            Self::PeerGone => write!(f, "peer gone"),
        }
    }
}

struct PendingSlot {
    stream: TcpStream,
    since: Instant,
}

/// Waiters keyed by (token, waiter role_b). Complementary roles splice;
/// two inbox pulls (both role B) must not pair with each other.
type PendingMap = HashMap<(Vec<u8>, bool), VecDeque<PendingSlot>>;

fn pending_count(map: &PendingMap) -> usize {
    map.values().map(VecDeque::len).sum()
}

/// Encode a register frame: magic | ver | token_len | token | role (0=a,1=b).
pub fn encode_register(token: &[u8], role_b: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + 2 + token.len() + 1);
    out.extend_from_slice(RELAY_MAGIC);
    out.push(RELAY_VERSION);
    out.extend_from_slice(&(token.len() as u16).to_le_bytes());
    out.extend_from_slice(token);
    out.push(if role_b { 1 } else { 0 });
    out
}

/// Parse register frame; returns (token, role_b).
pub fn decode_register(bytes: &[u8]) -> Result<(Vec<u8>, bool), RelayError> {
    if bytes.len() < 4 + 1 + 2 + 1 {
        return Err(RelayError::Protocol("register truncated".into()));
    }
    if &bytes[0..4] != RELAY_MAGIC || bytes[4] != RELAY_VERSION {
        return Err(RelayError::Protocol("bad magic/version".into()));
    }
    let len = u16::from_le_bytes([bytes[5], bytes[6]]) as usize;
    if len > 256 || 7 + len + 1 > bytes.len() {
        return Err(RelayError::Protocol("bad token len".into()));
    }
    let token = bytes[7..7 + len].to_vec();
    if token.is_empty() {
        return Err(RelayError::Protocol("empty token".into()));
    }
    let role_b = bytes[7 + len] != 0;
    Ok((token, role_b))
}

/// In-process / host TCP relay server (one listen port).
pub struct TcpRelayServer {
    pending: Arc<Mutex<PendingMap>>,
    active_splices: Arc<Mutex<usize>>,
}

impl Default for TcpRelayServer {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpRelayServer {
    pub fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
            active_splices: Arc::new(Mutex::new(0usize)),
        }
    }

    /// Bind and serve forever (spawned). Returns the local listen address string.
    pub async fn serve(self, bind: &str) -> Result<String, RelayError> {
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|e| RelayError::Io(e.to_string()))?;
        let addr = listener
            .local_addr()
            .map_err(|e| RelayError::Io(e.to_string()))?
            .to_string();
        let pending = self.pending;
        let active = self.active_splices;
        // Background reaper for stale waiters.
        let reaper_map = pending.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(15)).await;
                evict_stale(&reaper_map).await;
            }
        });
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let pending = pending.clone();
                let active = active.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, pending, active).await {
                        eprintln!("rooms-relay client: {e}");
                    }
                });
            }
        });
        Ok(addr)
    }
}

async fn evict_stale(pending: &Arc<Mutex<PendingMap>>) {
    let mut map = pending.lock().await;
    let now = Instant::now();
    let mut dropped = 0usize;
    for q in map.values_mut() {
        let mut keep = VecDeque::new();
        while let Some(slot) = q.pop_front() {
            if now.duration_since(slot.since) > PENDING_TTL {
                drop(slot.stream);
                dropped += 1;
            } else {
                keep.push_back(slot);
            }
        }
        *q = keep;
    }
    map.retain(|_, q| !q.is_empty());
    if dropped > 0 {
        eprintln!("rooms-relay: evicted {dropped} stale pending session(s)");
    }
}

async fn read_register(stream: &mut TcpStream) -> Result<(Vec<u8>, bool), RelayError> {
    let fut = async {
        let mut hdr = [0u8; 7];
        stream
            .read_exact(&mut hdr)
            .await
            .map_err(|e| RelayError::Io(e.to_string()))?;
        if &hdr[0..4] != RELAY_MAGIC || hdr[4] != RELAY_VERSION {
            return Err(RelayError::Protocol("bad magic".into()));
        }
        let token_len = u16::from_le_bytes([hdr[5], hdr[6]]) as usize;
        if token_len == 0 || token_len > 256 {
            return Err(RelayError::Protocol("token len".into()));
        }
        let mut rest = vec![0u8; token_len + 1];
        stream
            .read_exact(&mut rest)
            .await
            .map_err(|e| RelayError::Io(e.to_string()))?;
        let token = rest[..token_len].to_vec();
        let role_b = rest[token_len] != 0;
        Ok((token, role_b))
    };
    tokio::time::timeout(REGISTER_READ_TIMEOUT, fut)
        .await
        .map_err(|_| RelayError::Timeout)?
}

fn queue_waiter(map: &mut PendingMap, token: Vec<u8>, role_b: bool, stream: TcpStream) {
    map.entry((token, role_b))
        .or_default()
        .push_back(PendingSlot {
            stream,
            since: Instant::now(),
        });
}

async fn handle_client(
    mut stream: TcpStream,
    pending: Arc<Mutex<PendingMap>>,
    active_splices: Arc<Mutex<usize>>,
) -> Result<(), RelayError> {
    let _ = stream.set_nodelay(true);
    let (token, role_b) = read_register(&mut stream).await?;
    if token.is_empty() {
        return Err(RelayError::Protocol("empty token".into()));
    }
    evict_stale(&pending).await;
    // Pair complementary roles only (push role A ↔ inbox role B).
    let complementary = !role_b;
    let maybe_peer = {
        let mut map = pending.lock().await;
        map.get_mut(&(token.clone(), complementary))
            .and_then(VecDeque::pop_front)
    };
    if let Some(slot) = maybe_peer {
        {
            let mut n = active_splices.lock().await;
            if *n >= MAX_ACTIVE_SPLICES {
                drop(n);
                let mut map = pending.lock().await;
                queue_waiter(&mut map, token, complementary, slot.stream);
                return Err(RelayError::Protocol("too many active splices".into()));
            }
            *n += 1;
        }
        let mut first = slot.stream;
        let token_prefix = hex_prefix(&token);
        eprintln!("rooms-relay: splice start token={token_prefix}… joiner_role_b={role_b}");
        // Second peer arrived — ACK both, then splice.
        // If the first waiter is already dead (client ACK timeout), demote
        // this joiner to the new pending waiter instead of failing both.
        let ack_first = first.write_all(&[0x01]).await;
        if ack_first.is_err() {
            {
                let mut n = active_splices.lock().await;
                *n = n.saturating_sub(1);
            }
            drop(first);
            let mut map = pending.lock().await;
            if pending_count(&map) < MAX_PENDING_SESSIONS {
                queue_waiter(&mut map, token, role_b, stream);
                eprintln!("rooms-relay: replaced dead waiter token={token_prefix}…");
                return Ok(());
            }
            return Err(RelayError::PeerGone);
        }
        let result = async {
            stream
                .write_all(&[0x01])
                .await
                .map_err(|e| RelayError::Io(e.to_string()))?;
            splice(first, stream).await
        }
        .await;
        {
            let mut n = active_splices.lock().await;
            *n = n.saturating_sub(1);
        }
        eprintln!(
            "rooms-relay: splice end token={token_prefix}… ok={}",
            result.is_ok()
        );
        result
        // Token slot is free after splice ends → reconnect / multi-round OK.
    } else {
        let mut map = pending.lock().await;
        if pending_count(&map) >= MAX_PENDING_SESSIONS {
            return Err(RelayError::Protocol("too many pending sessions".into()));
        }
        queue_waiter(&mut map, token, role_b, stream);
        Ok(())
    }
}

fn hex_prefix(token: &[u8]) -> String {
    token
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

async fn splice(a: TcpStream, b: TcpStream) -> Result<(), RelayError> {
    let (mut ar, mut aw) = a.into_split();
    let (mut br, mut bw) = b.into_split();
    let ab = tokio::spawn(async move {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match tokio::time::timeout(SPLICE_IDLE_TIMEOUT, ar.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) | Ok(Err(_)) => break,
                Ok(Ok(n)) => {
                    if bw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    let ba = tokio::spawn(async move {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match tokio::time::timeout(SPLICE_IDLE_TIMEOUT, br.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) | Ok(Err(_)) => break,
                Ok(Ok(n)) => {
                    if aw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    let _ = tokio::join!(ab, ba);
    Ok(())
}

/// Dial relay, register with `token`, and wait until the peer joins (ACK 0x01).
pub async fn dial_via_relay(
    relay_addr: &str,
    token: &[u8],
    role_b: bool,
) -> Result<TcpStream, RelayError> {
    if token.is_empty() {
        return Err(RelayError::Protocol("empty token".into()));
    }
    let mut stream = TcpStream::connect(relay_addr)
        .await
        .map_err(|e| RelayError::Io(e.to_string()))?;
    let _ = stream.set_nodelay(true);
    let reg = encode_register(token, role_b);
    stream
        .write_all(&reg)
        .await
        .map_err(|e| RelayError::Io(e.to_string()))?;
    let mut ack = [0u8; 1];
    tokio::time::timeout(DIAL_ACK_TIMEOUT, stream.read_exact(&mut ack))
        .await
        .map_err(|_| RelayError::Timeout)?
        .map_err(|e| RelayError::Io(e.to_string()))?;
    if ack[0] != 0x01 {
        return Err(RelayError::Protocol("bad ack".into()));
    }
    Ok(stream)
}

/// Dial with a simple reconnect budget (useful when peer arrives late / NAT flake).
pub async fn dial_via_relay_with_retry(
    relay_addr: &str,
    token: &[u8],
    role_b: bool,
    attempts: u32,
    delay: Duration,
) -> Result<TcpStream, RelayError> {
    let mut last = RelayError::Timeout;
    for i in 0..attempts.max(1) {
        match dial_via_relay(relay_addr, token, role_b).await {
            Ok(s) => return Ok(s),
            Err(e) => {
                last = e;
                if i + 1 < attempts {
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
    Err(last)
}

/// Build multiaddr-like hint string for docs / UI (not a full libp2p circuit).
pub fn relay_dial_hint(relay_host: &str, relay_port: u16, token_hex: &str) -> String {
    format!("relay:{relay_host}:{relay_port}/token/{token_hex}")
}

/// Normalize a user/invite `host:port` string for dial / configure_relay.
///
/// Accepts optional `relay=` / `tcp://` / `relay://` prefixes. Returns `None`
/// when empty or malformed (missing port, bad port range).
pub fn normalize_relay_host_port(raw: &str) -> Option<String> {
    let mut s = raw.trim().to_string();
    if s.is_empty() {
        return None;
    }
    for prefix in ["relay://", "tcp://", "http://", "https://"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.to_string();
        }
    }
    if let Some(rest) = s.strip_prefix("relay=") {
        s = rest.trim().to_string();
    }
    if let Some((hostport, _)) = s.split_once('/') {
        s = hostport.to_string();
    }
    if let Some((hostport, _)) = s.split_once('?') {
        s = hostport.to_string();
    }
    let s = s.trim();
    let colon = s.rfind(':')?;
    if colon == 0 || colon + 1 >= s.len() {
        return None;
    }
    let port: u16 = s[colon + 1..].parse().ok()?;
    if port == 0 {
        return None;
    }
    let host = s[..colon].trim();
    if host.is_empty() {
        return None;
    }
    Some(format!("{host}:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn two_clients_exchange_via_relay() {
        let server = TcpRelayServer::new();
        let addr = server.serve("127.0.0.1:0").await.expect("serve");
        let token = b"session-token-1".to_vec();

        let token_a = token.clone();
        let addr_a = addr.clone();
        let a = tokio::spawn(async move { dial_via_relay(&addr_a, &token_a, false).await });
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let token_b = token.clone();
        let addr_b = addr.clone();
        let b = tokio::spawn(async move { dial_via_relay(&addr_b, &token_b, true).await });

        let mut sa = a.await.unwrap().expect("a");
        let mut sb = b.await.unwrap().expect("b");
        sa.write_all(b"hello-via-relay").await.unwrap();
        let mut buf = [0u8; 15];
        sb.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello-via-relay");
        sb.write_all(b"pong").await.unwrap();
        let mut buf2 = [0u8; 4];
        sa.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"pong");
    }

    #[tokio::test]
    async fn same_role_waiters_do_not_splice() {
        let server = TcpRelayServer::new();
        let addr = server.serve("127.0.0.1:0").await.expect("serve");
        let token = b"role-aware-tok".to_vec();

        let addr_b1 = addr.clone();
        let t_b1 = token.clone();
        let b1 = tokio::spawn(async move { dial_via_relay(&addr_b1, &t_b1, true).await });
        let addr_b2 = addr.clone();
        let t_b2 = token.clone();
        let b2 = tokio::spawn(async move { dial_via_relay(&addr_b2, &t_b2, true).await });
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(
            !b1.is_finished(),
            "two inbox (role B) waiters must not pair"
        );
        assert!(
            !b2.is_finished(),
            "two inbox (role B) waiters must not pair"
        );

        let addr_a1 = addr.clone();
        let t_a1 = token.clone();
        let a1 = tokio::spawn(async move { dial_via_relay(&addr_a1, &t_a1, false).await });
        let mut sa1 = a1.await.unwrap().expect("a1");
        let mut sb1 = b1.await.unwrap().expect("b1");
        sa1.write_all(b"first").await.unwrap();
        let mut buf = [0u8; 5];
        sb1.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"first");
        assert!(!b2.is_finished(), "second role-B waiter still pending");

        let addr_a2 = addr.clone();
        let t_a2 = token.clone();
        let a2 = tokio::spawn(async move { dial_via_relay(&addr_a2, &t_a2, false).await });
        let mut sa2 = a2.await.unwrap().expect("a2");
        let mut sb2 = b2.await.unwrap().expect("b2");
        sa2.write_all(b"second").await.unwrap();
        let mut buf2 = [0u8; 6];
        sb2.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"second");
    }

    #[tokio::test]
    async fn multi_session_independent_tokens() {
        let server = TcpRelayServer::new();
        let addr = server.serve("127.0.0.1:0").await.expect("serve");

        let t1 = b"tok-aaa".to_vec();
        let t2 = b"tok-bbb".to_vec();
        let a1 = {
            let addr = addr.clone();
            let t = t1.clone();
            tokio::spawn(async move { dial_via_relay(&addr, &t, false).await })
        };
        let a2 = {
            let addr = addr.clone();
            let t = t2.clone();
            tokio::spawn(async move { dial_via_relay(&addr, &t, false).await })
        };
        tokio::time::sleep(Duration::from_millis(60)).await;
        let b1 = {
            let addr = addr.clone();
            let t = t1.clone();
            tokio::spawn(async move { dial_via_relay(&addr, &t, true).await })
        };
        let b2 = {
            let addr = addr.clone();
            let t = t2.clone();
            tokio::spawn(async move { dial_via_relay(&addr, &t, true).await })
        };

        let mut s1a = a1.await.unwrap().unwrap();
        let mut s1b = b1.await.unwrap().unwrap();
        let mut s2a = a2.await.unwrap().unwrap();
        let mut s2b = b2.await.unwrap().unwrap();

        s1a.write_all(b"one").await.unwrap();
        s2a.write_all(b"two").await.unwrap();
        let mut b1buf = [0u8; 3];
        let mut b2buf = [0u8; 3];
        s1b.read_exact(&mut b1buf).await.unwrap();
        s2b.read_exact(&mut b2buf).await.unwrap();
        assert_eq!(&b1buf, b"one");
        assert_eq!(&b2buf, b"two");
    }

    #[tokio::test]
    async fn reconnect_after_splice_reuses_token() {
        let server = TcpRelayServer::new();
        let addr = server.serve("127.0.0.1:0").await.expect("serve");
        let token = b"reconnect-tok".to_vec();

        for round in 0..2u8 {
            let token_a = token.clone();
            let addr_a = addr.clone();
            let a = tokio::spawn(async move { dial_via_relay(&addr_a, &token_a, false).await });
            tokio::time::sleep(Duration::from_millis(40)).await;
            let token_b = token.clone();
            let addr_b = addr.clone();
            let b = tokio::spawn(async move { dial_via_relay(&addr_b, &token_b, true).await });
            let mut sa = a.await.unwrap().unwrap();
            let mut sb = b.await.unwrap().unwrap();
            let msg = [b'r', round];
            sa.write_all(&msg).await.unwrap();
            let mut buf = [0u8; 2];
            sb.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, msg);
            // Drop both ends so splice finishes and token slot frees.
            drop(sa);
            drop(sb);
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    }

    #[test]
    fn register_codec_round_trip() {
        let enc = encode_register(b"tok", true);
        let (t, role) = decode_register(&enc).unwrap();
        assert_eq!(t, b"tok");
        assert!(role);
    }

    #[test]
    fn empty_token_rejected() {
        assert!(decode_register(&encode_register(b"", false)).is_err());
    }

    #[tokio::test]
    async fn dial_rejects_empty_token() {
        let err = dial_via_relay("127.0.0.1:9", b"", false).await;
        assert!(matches!(err, Err(RelayError::Protocol(_))));
    }

    #[test]
    fn splice_and_pending_caps_are_positive() {
        assert!(MAX_ACTIVE_SPLICES > 0);
        assert!(MAX_PENDING_SESSIONS > 0);
        assert!(DIAL_ACK_TIMEOUT.as_secs() >= 30);
        assert!(REGISTER_READ_TIMEOUT.as_secs() >= 5);
        assert!(SPLICE_IDLE_TIMEOUT.as_secs() >= 60);
    }

    #[test]
    fn normalize_relay_host_port_accepts_common_forms() {
        assert_eq!(
            normalize_relay_host_port("192.168.1.10:44099").as_deref(),
            Some("192.168.1.10:44099")
        );
        assert_eq!(
            normalize_relay_host_port("relay=10.0.0.2:44099").as_deref(),
            Some("10.0.0.2:44099")
        );
        assert_eq!(
            normalize_relay_host_port("tcp://gateway.local:44100/path").as_deref(),
            Some("gateway.local:44100")
        );
        assert!(normalize_relay_host_port("").is_none());
        assert!(normalize_relay_host_port("no-port").is_none());
        assert!(normalize_relay_host_port("host:99999").is_none());
    }
}
