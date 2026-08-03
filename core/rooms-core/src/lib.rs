//! Decentralized Encrypted Rooms — core facade.
//!
//! Re-exports the layered Rust stack so consumers (FFI, seeds, tests) can depend
//! on a single crate while modules remain independently versionable.
//!
//! Layer map (architecture §3.1 / §11):
//! - [`rooms_identity`] — keys, cross-sign, revoke (identity ≠ device)
//! - [`rooms_room`] — membership CRDT / policies
//! - [`rooms_sync`] — version vectors, want/have
//! - [`rooms_storage`] — local CID / blob persistence
//! - [`rooms_discovery`] — invites, DHT, local ads
//! - [`rooms_transport`] — QUIC / mesh streams
//! - [`rooms_proto`] — canonical encodings
//!
//! Crypto glue: [`rooms_signal`] (1:1) and [`rooms_mls`] (rooms) — **no custom crypto**.
//!
//! Gate 1 sync: libp2p protocol `/derooms/sync/1.0.0` (see `rooms-transport`).
//! Phase 2: per-room VV + room-scoped CID diff helpers in [`rooms_sync`].

pub use rooms_discovery as discovery;
pub use rooms_identity as identity;
pub use rooms_mls as mls;
pub use rooms_proto as proto;
pub use rooms_room as room;
pub use rooms_signal as signal;
pub use rooms_storage as storage;
pub use rooms_sync as sync;
pub use rooms_transport as transport;

/// Workspace crate versions share `0.1.0` during Phase 0 bootstrap.
pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Re-export protocol draft version for FFI consumers.
pub use rooms_proto::PROTO_DRAFT_VERSION;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facade_exports_proto_hash() {
        let h = proto::blake3_hash(b"rooms-core");
        assert_eq!(h.as_bytes().len(), 32);
    }

    #[test]
    fn version_is_nonzero_semver() {
        assert!(!CORE_VERSION.is_empty());
    }
}
