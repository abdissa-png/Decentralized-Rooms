//! Spike 2.7 — libsignal 1:1 hello (bindings survey + intended API surface).
//!
//! Official Signal Protocol for production is **libsignal-client** (Java/Swift/Rust
//! monorepo). A full send/receive integration is intentionally deferred: the
//! crates.io `libsignal-protocol` package is an abandoned FFI to C; vendored
//! forks exist but pull AGPL and a large dependency tree.
//!
//! This module documents findings and exposes a **compile-checked stub** of the
//! Phase 1 `signal-glue` API we expect to wrap around real libsignal later.
//! See `spikes/README.md` §2.7 for the ADR-style note.

use thiserror::Error;

pub const SPIKE_NAME: &str = "libsignal";
pub const WBS: &str = "2.7";

/// Survey outcome for Phase 0 Gate 0 decision log.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BindingPath {
    /// Official `libsignal` workspace / `libsignal-protocol` crate from Signal —
    /// not published as a small crates.io dependency; consume via git path or
    /// JNI/UniFFI from the Android build of libsignal-client.
    OfficialLibsignalClient,
    /// crates.io `libsignal-protocol` 0.1 — unmaintained C FFI wrapper; reject.
    AbandonedCratesIoFfi,
    /// Community vendored forks (e.g. `libsignal-protocol-syft`) — AGPL, heavy.
    VendoredFork,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SurveyFindings {
    pub recommended: BindingPath,
    pub android_ffi: &'static str,
    pub phase1_approach: &'static str,
}

/// Static survey results (kept in code so tests can assert the decision).
pub fn survey() -> SurveyFindings {
    SurveyFindings {
        recommended: BindingPath::OfficialLibsignalClient,
        android_ffi: "Prefer Signal's Android AAR / JNI for libsignal-client on \
             device; UniFFI the Rust core for room/sync APIs, and call native \
             Signal crypto from Kotlin for 1:1 until a maintained Rust crate \
             path is vendored under project license review.",
        phase1_approach: "Phase 1: wrap Double Ratchet behind `SignalSession` \
             trait (this stub). Integrate official libsignal via Android JNI \
             first for the hello app; optionally vendor `rust/protocol` from \
             signalapp/libsignal behind a Cargo git dependency after license \
             and build-complexity review. Do not invent X3DH/DR.",
    }
}

/// Opaque session handle — production will hold libsignal `SessionRecord`.
#[derive(Debug, Clone, Default)]
pub struct SignalSession {
    pub remote_identity: Vec<u8>,
    established: bool,
}

/// Sealed 1:1 ciphertext envelope (stub — not real Signal wire format).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SealedMessage {
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum SignalSpikeError {
    #[error("session not established")]
    NotEstablished,
}

impl SignalSession {
    pub fn new(remote_identity: Vec<u8>) -> Self {
        Self {
            remote_identity,
            established: false,
        }
    }

    /// Placeholder for X3DH + first DR message. Marks the session established.
    pub fn establish_stub(&mut self) {
        self.established = true;
    }

    pub fn is_established(&self) -> bool {
        self.established
    }

    /// Stub seal: XOR with a fixed pad — **not cryptography**. Exists so the
    /// API surface compiles and tests can exercise call flow.
    pub fn seal_stub(&self, plaintext: &[u8]) -> Result<SealedMessage, SignalSpikeError> {
        if !self.established {
            return Err(SignalSpikeError::NotEstablished);
        }
        let ciphertext: Vec<u8> = plaintext.iter().map(|b| b ^ 0xA5).collect();
        Ok(SealedMessage { ciphertext })
    }

    pub fn open_stub(&self, sealed: &SealedMessage) -> Result<Vec<u8>, SignalSpikeError> {
        if !self.established {
            return Err(SignalSpikeError::NotEstablished);
        }
        Ok(sealed.ciphertext.iter().map(|b| b ^ 0xA5).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn survey_recommends_official_path() {
        let s = survey();
        assert_eq!(s.recommended, BindingPath::OfficialLibsignalClient);
        assert!(!s.android_ffi.is_empty());
        assert!(s.phase1_approach.contains("Do not invent"));
    }

    #[test]
    fn stub_session_roundtrip_api() {
        let mut session = SignalSession::new(vec![1, 2, 3]);
        assert!(session.seal_stub(b"x").is_err());
        session.establish_stub();
        let sealed = session.seal_stub(b"hello signal").unwrap();
        let plain = session.open_stub(&sealed).unwrap();
        assert_eq!(plain, b"hello signal");
    }
}
