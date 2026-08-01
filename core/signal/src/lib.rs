//! 1:1 application-layer crypto glue for Decentralized Encrypted Rooms.
//!
//! **Architecture:** Signal Protocol (X3DH + Double Ratchet) seals 1:1 payloads.
//! Transport uses **Noise** (libp2p / `snow`) — that is a separate layer; do not
//! confuse Noise session helpers with this trait.
//!
//! # Production path (Phase 1)
//! Official **libsignal-client** via Android JNI/Kotlin. Pure-Rust crates.io
//! `libsignal-protocol` 0.1 is abandoned; AGPL forks are out of scope until a
//! license ADR. See `docs/libsignal-android-plan.md` and ADR-0003.
//!
//! # Hard rule
//! No novel Double Ratchet / X3DH implementations. The default
//! [`PendingAndroidSignalSession`] refuses encrypt/decrypt so CI cannot
//! accidentally ship a toy as crypto.

use thiserror::Error;

/// Opaque sealed 1:1 ciphertext (libsignal wire format in production).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedMessage {
    pub ciphertext: Vec<u8>,
}

/// Errors from [`SignalSession`] operations.
#[derive(Debug, Error)]
pub enum SignalError {
    #[error("session not established")]
    NotEstablished,
    #[error(
        "Signal Protocol encrypt/decrypt is not available in this Rust build; \
         use Android libsignal-client JNI (see docs/libsignal-android-plan.md)"
    )]
    PendingAndroidIntegration,
    #[error("dev-session feature required for InsecureDevSession")]
    DevSessionDisabled,
    #[error("session error: {0}")]
    Other(String),
}

/// Application-layer 1:1 session: establish, encrypt, decrypt.
///
/// Implementors must be real Signal Protocol (libsignal-client) or an
/// explicitly gated non-production stand-in (`dev-session`).
pub trait SignalSession {
    /// Establish (or load) a session toward `remote_identity` using prekey /
    /// invite material. Exact bytes are opaque until libsignal glue lands.
    fn establish(
        &mut self,
        remote_identity: &[u8],
        handshake_material: &[u8],
    ) -> Result<(), SignalError>;

    fn is_established(&self) -> bool;

    /// Seal an application plaintext (e.g. chat body before MessageEvent wrap).
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<SealedMessage, SignalError>;

    /// Open a sealed message from the peer.
    fn decrypt(&mut self, sealed: &SealedMessage) -> Result<Vec<u8>, SignalError>;
}

/// Default stub: records establish intent but **never** encrypts or decrypts.
///
/// Production encrypt/decrypt happens in Kotlin via libsignal-client; Rust
/// sync/DAG APIs treat ciphertext as opaque bytes.
#[derive(Debug, Default)]
pub struct PendingAndroidSignalSession {
    remote_identity: Vec<u8>,
    established: bool,
}

impl PendingAndroidSignalSession {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SignalSession for PendingAndroidSignalSession {
    fn establish(
        &mut self,
        remote_identity: &[u8],
        _handshake_material: &[u8],
    ) -> Result<(), SignalError> {
        self.remote_identity = remote_identity.to_vec();
        self.established = true;
        Ok(())
    }

    fn is_established(&self) -> bool {
        self.established
    }

    fn encrypt(&mut self, _plaintext: &[u8]) -> Result<SealedMessage, SignalError> {
        if !self.established {
            return Err(SignalError::NotEstablished);
        }
        Err(SignalError::PendingAndroidIntegration)
    }

    fn decrypt(&mut self, _sealed: &SealedMessage) -> Result<Vec<u8>, SignalError> {
        if !self.established {
            return Err(SignalError::NotEstablished);
        }
        Err(SignalError::PendingAndroidIntegration)
    }
}

impl PendingAndroidSignalSession {
    pub fn remote_identity(&self) -> &[u8] {
        &self.remote_identity
    }
}

/// **NOT CRYPTOGRAPHY.** XOR pad for call-flow unit tests only.
///
/// Enabled solely via Cargo feature `dev-session` (never default). Must not be
/// linked into production Android / release builds.
#[cfg(feature = "dev-session")]
#[derive(Debug, Default)]
pub struct InsecureDevSession {
    established: bool,
}

#[cfg(feature = "dev-session")]
impl InsecureDevSession {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(feature = "dev-session")]
impl SignalSession for InsecureDevSession {
    fn establish(
        &mut self,
        _remote_identity: &[u8],
        _handshake_material: &[u8],
    ) -> Result<(), SignalError> {
        self.established = true;
        Ok(())
    }

    fn is_established(&self) -> bool {
        self.established
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<SealedMessage, SignalError> {
        if !self.established {
            return Err(SignalError::NotEstablished);
        }
        let ciphertext: Vec<u8> = plaintext.iter().map(|b| b ^ 0xA5).collect();
        Ok(SealedMessage { ciphertext })
    }

    fn decrypt(&mut self, sealed: &SealedMessage) -> Result<Vec<u8>, SignalError> {
        if !self.established {
            return Err(SignalError::NotEstablished);
        }
        Ok(sealed.ciphertext.iter().map(|b| b ^ 0xA5).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_session_refuses_crypto() {
        let mut s = PendingAndroidSignalSession::new();
        assert!(!s.is_established());
        assert!(matches!(s.encrypt(b"x"), Err(SignalError::NotEstablished)));
        s.establish(b"remote", b"prekey").unwrap();
        assert!(s.is_established());
        assert!(matches!(
            s.encrypt(b"hello"),
            Err(SignalError::PendingAndroidIntegration)
        ));
        assert!(matches!(
            s.decrypt(&SealedMessage {
                ciphertext: vec![1, 2, 3]
            }),
            Err(SignalError::PendingAndroidIntegration)
        ));
    }

    #[cfg(feature = "dev-session")]
    #[test]
    fn insecure_dev_session_roundtrip_is_not_signal() {
        let mut s = InsecureDevSession::new();
        s.establish(b"peer", &[]).unwrap();
        let sealed = s.encrypt(b"hello").unwrap();
        assert_ne!(sealed.ciphertext, b"hello");
        assert_eq!(s.decrypt(&sealed).unwrap(), b"hello");
    }
}
