//! Spike 2.2 — Noise XX handshake via the `snow` crate.
//!
//! In-memory initiator/responder handshake, then one encrypted application
//! message. Production transport will use libp2p Noise — this spike only
//! teaches the XX transcript and session keys.

use snow::{error::Error as SnowError, Builder, TransportState};
use thiserror::Error;

pub const SPIKE_NAME: &str = "noise-xx";
pub const WBS: &str = "2.2";

/// Noise XX with X25519 / ChaChaPoly / SHA256 (common libp2p-compatible suite).
pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

#[derive(Debug, Error)]
pub enum NoiseSpikeError {
    #[error("snow: {0}")]
    Snow(#[from] SnowError),
    #[error("handshake incomplete")]
    HandshakeIncomplete,
    #[error("payload mismatch after decrypt")]
    PayloadMismatch,
}

/// Completed Noise XX session pair (initiator + responder transport states).
pub struct NoiseXxSession {
    pub initiator: TransportState,
    pub responder: TransportState,
}

/// Run a full Noise XX handshake over in-memory buffers and return transport
/// states for both peers.
pub fn handshake_xx() -> Result<NoiseXxSession, NoiseSpikeError> {
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
        return Err(NoiseSpikeError::HandshakeIncomplete);
    }

    Ok(NoiseXxSession {
        initiator: initiator.into_transport_mode()?,
        responder: responder.into_transport_mode()?,
    })
}

/// Encrypt `plaintext` from initiator → responder after a successful handshake.
pub fn roundtrip_message(
    session: &mut NoiseXxSession,
    plaintext: &[u8],
) -> Result<Vec<u8>, NoiseSpikeError> {
    let mut cipher_buf = vec![0u8; plaintext.len() + 16 + 64];
    let mut plain_buf = vec![0u8; plaintext.len() + 64];

    let clen = session
        .initiator
        .write_message(plaintext, &mut cipher_buf)?;
    let plen = session
        .responder
        .read_message(&cipher_buf[..clen], &mut plain_buf)?;

    if &plain_buf[..plen] != plaintext {
        return Err(NoiseSpikeError::PayloadMismatch);
    }
    Ok(plain_buf[..plen].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noise_xx_handshake_and_message() {
        let mut session = handshake_xx().expect("handshake");
        let recovered = roundtrip_message(&mut session, b"hello rooms").expect("encrypt/decrypt");
        assert_eq!(recovered, b"hello rooms");
    }

    #[test]
    fn remote_static_keys_known_after_handshake() {
        let params: snow::params::NoiseParams = NOISE_PATTERN.parse().unwrap();
        let i_kp = Builder::new(params.clone()).generate_keypair().unwrap();
        let r_kp = Builder::new(params.clone()).generate_keypair().unwrap();

        let mut initiator = Builder::new(params.clone())
            .local_private_key(&i_kp.private)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut responder = Builder::new(params)
            .local_private_key(&r_kp.private)
            .unwrap()
            .build_responder()
            .unwrap();

        let mut a = [0u8; 1024];
        let mut b = [0u8; 1024];

        let n = initiator.write_message(&[], &mut a).unwrap();
        responder.read_message(&a[..n], &mut b).unwrap();
        let n = responder.write_message(&[], &mut a).unwrap();
        initiator.read_message(&a[..n], &mut b).unwrap();
        let n = initiator.write_message(&[], &mut a).unwrap();
        responder.read_message(&a[..n], &mut b).unwrap();

        assert_eq!(
            initiator.get_remote_static().unwrap(),
            r_kp.public.as_slice()
        );
        assert_eq!(
            responder.get_remote_static().unwrap(),
            i_kp.public.as_slice()
        );
    }
}
