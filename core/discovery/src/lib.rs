//! Peer discovery and invite routing for Decentralized Encrypted Rooms.
//!
//! Owns invite-token parse, DHT lookups, rendezvous, and mDNS/BLE ads.
//! Does **not** own message semantics (architecture §11.2).
//!
//! MVP discovery is **invite-only** — no public room directory (SRS `FR-DISC-*`).
//! Spec: `docs/protocol/invite-token.md`.
//!
//! # Status
//! Phase 1: binary invite v1 encode/decode; authenticity bind + device signature;
//! URI helper stub.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rooms_identity::IdentityId;
use rooms_proto::{
    decode_invite_token_v1, encode_invite_auth_bind_v1, encode_invite_token_v1, Cid, CodecError,
    InviteTokenV1, INVITE_TOKEN_VERSION_V1, INVITE_URI_SCHEME, INVITE_WILDCARD_INVITEE,
};

/// Versioned invite token (PROTO-INVITE-001).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InviteToken {
    pub version: u8,
    pub room_id: Cid,
    /// Authenticity material (signature / capability).
    pub authenticity: Vec<u8>,
    /// Optional bootstrap multiaddrs / peer hints.
    pub bootstrap_hints: Vec<String>,
    pub inviter: IdentityId,
}

impl InviteToken {
    pub fn new(room_id: Cid, inviter: IdentityId) -> Self {
        Self {
            version: INVITE_TOKEN_VERSION_V1,
            room_id,
            authenticity: Vec::new(),
            bootstrap_hints: Vec::new(),
            inviter,
        }
    }

    pub fn to_v1(&self) -> InviteTokenV1 {
        InviteTokenV1 {
            room_id: self.room_id,
            inviter_identity_id: self.inviter.0,
            authenticity: self.authenticity.clone(),
            bootstrap_hints: self.bootstrap_hints.clone(),
        }
    }

    pub fn from_v1(v1: InviteTokenV1) -> Self {
        Self {
            version: INVITE_TOKEN_VERSION_V1,
            room_id: v1.room_id,
            authenticity: v1.authenticity,
            bootstrap_hints: v1.bootstrap_hints,
            inviter: IdentityId(v1.inviter_identity_id),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, InviteError> {
        if self.version != INVITE_TOKEN_VERSION_V1 {
            return Err(InviteError::UnsupportedVersion);
        }
        encode_invite_token_v1(&self.to_v1()).map_err(InviteError::from)
    }
}

/// Parse a binary invite token (fail-closed on unknown version).
pub fn parse_invite(bytes: &[u8]) -> Result<InviteToken, InviteError> {
    let v1 = decode_invite_token_v1(bytes).map_err(InviteError::from)?;
    Ok(InviteToken::from_v1(v1))
}

/// Provisional deep-link prefix: `derooms://invite/v1/` (brand TBD).
pub fn invite_uri_prefix() -> String {
    format!("{INVITE_URI_SCHEME}://invite/v1/")
}

/// Canonical bind bytes for invite authenticity (invite-token.md §3.2).
pub fn invite_auth_bind(
    room_id: &Cid,
    invitee_or_wildcard: &[u8; 32],
    expiry_unix_secs: u64,
) -> Vec<u8> {
    encode_invite_auth_bind_v1(room_id, invitee_or_wildcard, expiry_unix_secs)
}

/// Sign invite authenticity with the inviter **device** key (open invite = wildcard).
pub fn sign_invite_authenticity(
    room_id: &Cid,
    invitee_or_wildcard: &[u8; 32],
    expiry_unix_secs: u64,
    inviter_device_key: &SigningKey,
) -> Vec<u8> {
    let bind = invite_auth_bind(room_id, invitee_or_wildcard, expiry_unix_secs);
    inviter_device_key.sign(&bind).to_bytes().to_vec()
}

/// Build an invite with authenticity filled (open / wildcard invitee by default).
pub fn create_signed_invite(
    room_id: Cid,
    inviter: IdentityId,
    expiry_unix_secs: u64,
    inviter_device_key: &SigningKey,
    bootstrap_hints: Vec<String>,
) -> InviteToken {
    let authenticity = sign_invite_authenticity(
        &room_id,
        &INVITE_WILDCARD_INVITEE,
        expiry_unix_secs,
        inviter_device_key,
    );
    InviteToken {
        version: INVITE_TOKEN_VERSION_V1,
        room_id,
        authenticity,
        bootstrap_hints,
        inviter,
    }
}

/// Verify authenticity against inviter device verifying key (wildcard bind).
pub fn verify_invite_authenticity(
    token: &InviteToken,
    expiry_unix_secs: u64,
    inviter_device_vk: &VerifyingKey,
) -> Result<(), InviteError> {
    verify_invite_authenticity_for_invitee(
        token,
        &INVITE_WILDCARD_INVITEE,
        expiry_unix_secs,
        inviter_device_vk,
    )
}

/// Verify authenticity for a specific invitee (or [`INVITE_WILDCARD_INVITEE`]).
pub fn verify_invite_authenticity_for_invitee(
    token: &InviteToken,
    invitee_or_wildcard: &[u8; 32],
    expiry_unix_secs: u64,
    inviter_device_vk: &VerifyingKey,
) -> Result<(), InviteError> {
    if token.authenticity.len() != 64 {
        return Err(InviteError::BadAuthenticity);
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&token.authenticity);
    let sig = Signature::from_bytes(&sig_bytes);
    let bind = invite_auth_bind(&token.room_id, invitee_or_wildcard, expiry_unix_secs);
    inviter_device_vk
        .verify(&bind, &sig)
        .map_err(|_| InviteError::BadAuthenticity)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InviteError {
    UnsupportedVersion,
    Malformed,
    EmptyRoomId,
    BadAuthenticity,
}

impl From<CodecError> for InviteError {
    fn from(value: CodecError) -> Self {
        match value {
            CodecError::UnsupportedVersion => Self::UnsupportedVersion,
            CodecError::EmptyRoomId => Self::EmptyRoomId,
            _ => Self::Malformed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};

    #[test]
    fn invite_round_trip() {
        let mut token = InviteToken::new(Cid([4u8; 32]), IdentityId([5u8; 32]));
        token.bootstrap_hints.push("hint".into());
        token.authenticity = b"sig".to_vec();
        let bytes = token.encode().unwrap();
        let parsed = parse_invite(&bytes).unwrap();
        assert_eq!(parsed, token);
        assert!(invite_uri_prefix().starts_with("derooms://"));
    }

    #[test]
    fn unknown_version_fails_closed() {
        let mut bytes = InviteToken::new(Cid([4u8; 32]), IdentityId([5u8; 32]))
            .encode()
            .unwrap();
        bytes[0] = 9;
        assert_eq!(parse_invite(&bytes), Err(InviteError::UnsupportedVersion));
    }

    /// Property / fuzz-style smoke: random blobs and wrong versions fail closed.
    /// (`cargo-fuzz` needs nightly — not required for this Gate 1 precursor.)
    #[test]
    fn invite_decode_fail_closed_fuzz_smoke() {
        let mut rng = StdRng::seed_from_u64(0x696e7631); // "inv1"
        for _ in 0..512 {
            let len = (rng.next_u32() as usize) % 256;
            let mut bytes = vec![0u8; len];
            rng.fill_bytes(&mut bytes);
            match parse_invite(&bytes) {
                Err(
                    InviteError::UnsupportedVersion
                    | InviteError::Malformed
                    | InviteError::EmptyRoomId
                    | InviteError::BadAuthenticity,
                ) => {}
                Ok(token) => {
                    // Extremely unlikely for random data; if it parses, re-encode must match.
                    let again = token.encode().expect("re-encode");
                    assert_eq!(again, bytes);
                }
            }
        }

        // Explicit wrong-version corpus
        for version in [0u8, 2, 3, 255] {
            let mut bytes = InviteToken::new(Cid([9u8; 32]), IdentityId([8u8; 32]))
                .encode()
                .unwrap();
            bytes[0] = version;
            assert_eq!(parse_invite(&bytes), Err(InviteError::UnsupportedVersion));
        }

        // Truncated valid prefix
        let full = InviteToken::new(Cid([1u8; 32]), IdentityId([2u8; 32]))
            .encode()
            .unwrap();
        assert!(parse_invite(&full[..10]).is_err());
        assert!(parse_invite(&[]).is_err());
        assert!(parse_invite(&[INVITE_TOKEN_VERSION_V1]).is_err());
    }

    /// Structured property: mutate each byte of a valid invite → fail or round-trip.
    #[test]
    fn invite_bit_flip_fail_closed() {
        let mut token = InviteToken::new(Cid([0x44; 32]), IdentityId([0x55; 32]));
        token.authenticity = vec![0xAB; 64];
        token.bootstrap_hints.push("/ip4/127.0.0.1/tcp/9".into());
        let original = token.encode().unwrap();
        let mut rng = StdRng::seed_from_u64(0x666c6970);
        for _ in 0..64 {
            let mut bytes = original.clone();
            let idx = (rng.next_u32() as usize) % bytes.len();
            bytes[idx] ^= 1 + (rng.next_u32() as u8 % 255);
            match parse_invite(&bytes) {
                Err(_) => {}
                Ok(t) => {
                    let again = t.encode().unwrap();
                    assert_eq!(again, bytes, "parsed mutant must re-encode identically");
                }
            }
        }
    }

    #[test]
    fn invite_authenticity_bind_round_trip() {
        let mut rng = StdRng::seed_from_u64(4242);
        let sk = SigningKey::generate(&mut rng);
        let vk = sk.verifying_key();
        let room = Cid([0x7A; 32]);
        let inviter = IdentityId([0x7B; 32]);

        let token = create_signed_invite(
            room,
            inviter,
            0,
            &sk,
            vec!["/ip4/127.0.0.1/tcp/4001".into()],
        );
        assert_eq!(token.authenticity.len(), 64);
        verify_invite_authenticity(&token, 0, &vk).expect("auth ok");

        let bytes = token.encode().unwrap();
        let parsed = parse_invite(&bytes).unwrap();
        assert_eq!(parsed.authenticity, token.authenticity);
        assert_eq!(parsed.bootstrap_hints, token.bootstrap_hints);
        verify_invite_authenticity(&parsed, 0, &vk).unwrap();

        // Tamper authenticity → fail
        let mut bad = parsed.clone();
        bad.authenticity[0] ^= 0xff;
        assert_eq!(
            verify_invite_authenticity(&bad, 0, &vk),
            Err(InviteError::BadAuthenticity)
        );

        // Wrong expiry in bind → fail
        assert_eq!(
            verify_invite_authenticity(&parsed, 99, &vk),
            Err(InviteError::BadAuthenticity)
        );
    }
}
