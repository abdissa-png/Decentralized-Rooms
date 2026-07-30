//! Noise XX transport-session helpers via `snow`.
//!
//! This is **transport** crypto (ADR-0003), not Signal Protocol. Production
//! libp2p streams already negotiate Noise; these helpers exercise the same
//! pattern (`Noise_XX_25519_ChaChaPoly_SHA256`) for unit tests and byte demos.

use snow::{Builder, TransportState};
use thiserror::Error;

/// Noise XX with X25519 / ChaChaPoly / SHA256 (libp2p-compatible suite).
pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

#[derive(Debug, Error)]
pub enum NoiseSessionError {
    #[error("snow: {0}")]
    Snow(String),
    #[error("handshake incomplete")]
    HandshakeIncomplete,
    #[error("payload mismatch after decrypt")]
    PayloadMismatch,
}

impl From<snow::Error> for NoiseSessionError {
    fn from(value: snow::Error) -> Self {
        Self::Snow(value.to_string())
    }
}

/// Completed Noise XX initiator + responder transport states.
pub struct NoiseXxPair {
    pub initiator: TransportState,
    pub responder: TransportState,
}

/// Full Noise XX handshake over in-memory buffers.
pub fn noise_xx_handshake() -> Result<NoiseXxPair, NoiseSessionError> {
    let params: snow::params::NoiseParams = NOISE_PATTERN.parse()?;

    let initiator_kp = Builder::new(params.clone()).generate_keypair()?;
    let responder_kp = Builder::new(params.clone()).generate_keypair()?;

    let mut initiator = Builder::new(params.clone())
        .local_private_key(&initiator_kp.private)?
        .build_initiator()?;
    let mut responder = Builder::new(params)
        .local_private_key(&responder_kp.private)?
        .build_responder()?;

    let mut buf_a = [0u8; 65535];
    let mut buf_b = [0u8; 65535];

    // -> e
    let len = initiator.write_message(&[], &mut buf_a)?;
    let _ = responder.read_message(&buf_a[..len], &mut buf_b)?;

    // <- e, ee, s, es
    let len = responder.write_message(&[], &mut buf_a)?;
    let _ = initiator.read_message(&buf_a[..len], &mut buf_b)?;

    // -> s, se
    let len = initiator.write_message(&[], &mut buf_a)?;
    let _ = responder.read_message(&buf_a[..len], &mut buf_b)?;

    if !initiator.is_handshake_finished() || !responder.is_handshake_finished() {
        return Err(NoiseSessionError::HandshakeIncomplete);
    }

    Ok(NoiseXxPair {
        initiator: initiator.into_transport_mode()?,
        responder: responder.into_transport_mode()?,
    })
}

/// Encrypt `plaintext` initiator → responder and decrypt (round-trip check).
pub fn noise_xx_roundtrip(
    pair: &mut NoiseXxPair,
    plaintext: &[u8],
) -> Result<Vec<u8>, NoiseSessionError> {
    let mut cipher_buf = vec![0u8; plaintext.len() + 16 + 64];
    let mut plain_buf = vec![0u8; plaintext.len() + 64];

    let clen = pair.initiator.write_message(plaintext, &mut cipher_buf)?;
    let plen = pair
        .responder
        .read_message(&cipher_buf[..clen], &mut plain_buf)?;

    if &plain_buf[..plen] != plaintext {
        return Err(NoiseSessionError::PayloadMismatch);
    }
    Ok(plain_buf[..plen].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_and_message() {
        let mut pair = noise_xx_handshake().expect("handshake");
        let recovered = noise_xx_roundtrip(&mut pair, b"hello rooms").expect("roundtrip");
        assert_eq!(recovered, b"hello rooms");
    }

    #[test]
    fn aead_empty_and_large_payload() {
        let mut pair = noise_xx_handshake().expect("handshake");
        assert_eq!(noise_xx_roundtrip(&mut pair, b"").unwrap(), b"");
        let big = vec![0x5Au8; 4096];
        assert_eq!(noise_xx_roundtrip(&mut pair, &big).unwrap(), big);
    }

    #[test]
    fn aead_tamper_fails_closed() {
        let mut pair = noise_xx_handshake().expect("handshake");
        let mut cipher = vec![0u8; 256];
        let clen = pair
            .initiator
            .write_message(b"transport-aead", &mut cipher)
            .expect("enc");
        cipher[clen / 2] ^= 0x5a;
        let mut plain = vec![0u8; 256];
        assert!(pair
            .responder
            .read_message(&cipher[..clen], &mut plain)
            .is_err());
    }

    #[test]
    fn pattern_string_is_libp2p_compatible_suite() {
        assert_eq!(NOISE_PATTERN, "Noise_XX_25519_ChaChaPoly_SHA256");
    }
}
