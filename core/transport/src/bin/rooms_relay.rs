//! Minimal TCP circuit relay binary for NAT / no shared LAN labs.
//!
//! Usage:
//!   cargo run -p rooms-transport --bin rooms-relay -- 0.0.0.0:44099
//!
//! LAN gateway / VPS tip: bind `0.0.0.0:44099`, open the port on the host firewall,
//! then paste `HOST:44099` into Android Direct message → Manage → Public / NAT relay
//! (or put `relay=HOST:44099` on the peer invite). Self-host only — there is no
//! public DeRooms DRRL fleet. See `docs/relay-nat.md`.
//!
//! Clients: `rooms_transport::dial_via_relay(addr, token, role_b)`.
//! Hardening: pending TTL, max pending sessions, multi-token, reconnect.
//! See `docs/relay-nat.md`.

use rooms_transport::{TcpRelayServer, MAX_PENDING_SESSIONS, PENDING_TTL};

#[tokio::main]
async fn main() {
    let bind = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:44099".to_string());
    let server = TcpRelayServer::new();
    match server.serve(&bind).await {
        Ok(addr) => {
            eprintln!("rooms-relay listening on {addr}");
            eprintln!(
                "pending_ttl={}s max_pending={} (multi-session by token)",
                PENDING_TTL.as_secs(),
                MAX_PENDING_SESSIONS
            );
            eprintln!("Clients register with the same token via dial_via_relay().");
            eprintln!("Docs: docs/relay-nat.md · script: ./scripts/run-relay.sh");
            // Keep process alive.
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            }
        }
        Err(e) => {
            eprintln!("rooms-relay failed: {e}");
            std::process::exit(1);
        }
    }
}
