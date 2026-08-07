//! UniFFI surface for Decentralized Encrypted Rooms (WBS 2.13 / Phase 1 identity).
//!
//! Exposes version strings, identity create / Keystore-oriented secret blob
//! export, for the Android hello module. Does not require the Android SDK to
//! `cargo build` / `cargo test`. **Never log secret blobs.**

// Generated UniFFI scaffolding trips empty_line_after_doc_comments.
#![allow(clippy::empty_line_after_doc_comments)]

use rooms_identity::{
    create_identity_osrng, export_identity_secret_blob, identity_id_hex_from_master_pubkey,
    import_identity_secret_blob, IdentitySecretBlob,
};
use rooms_proto::{
    blake3_hash, encode_invite_token_v1, encode_key_package_bind_v1, encode_key_package_bind_wire_v1,
    encode_message_event_wire_v1, Cid, ContentType, InviteTokenV1, KeyPackageBindV1,
    INVITE_TOKEN_VERSION_V1, PROTO_DRAFT_VERSION,
};
use rooms_sync::create_signed_message_event;

mod mls_ffi;
mod room_ffi;
mod sync_lab;
pub use mls_ffi::{MlsAddResult, MlsGroupSession, MlsSyncObjects};
pub use room_ffi::{
    create_founding_room, join_room_from_invite, local_room_session_from_state_blob, FoundedRoom,
    LocalRoomSession,
};
pub use sync_lab::SyncLabNode;

/// Restore MLS session from persisted blob (UniFFI free function).
pub fn mls_session_from_state_blob(blob: Vec<u8>) -> std::sync::Arc<MlsGroupSession> {
    MlsGroupSession::from_state_blob(blob)
}

uniffi::include_scaffolding!("rooms");

/// Proto draft version (`docs/protocol`).
pub fn proto_draft_version() -> String {
    PROTO_DRAFT_VERSION.to_string()
}

/// `rooms-core` facade version.
pub fn core_version() -> String {
    rooms_core::CORE_VERSION.to_string()
}

/// Identity stub greeting for FFI smoke tests.
pub fn identity_hello() -> String {
    format!(
        "rooms-identity; identity≠device; draft={}",
        PROTO_DRAFT_VERSION
    )
}

/// Encode a throwaway invite and return the version byte as hex (`01`).
pub fn invite_token_version_byte_hex() -> String {
    let token = InviteTokenV1 {
        room_id: Cid([0x42; 32]),
        inviter_identity_id: [0x07; 32],
        authenticity: Vec::new(),
        bootstrap_hints: Vec::new(),
    };
    let bytes = encode_invite_token_v1(&token).expect("invite encode");
    assert_eq!(bytes[0], INVITE_TOKEN_VERSION_V1);
    format!("{:02x}", bytes[0])
}

/// Public fields returned to Kotlin after `create_identity`.
pub struct CreatedIdentity {
    pub identity_id_hex: String,
    pub device_id_hex: String,
    pub master_pubkey_hex: String,
    pub device_pubkey_hex: String,
}

/// Public identity + opaque secret blob for Android Keystore wrapping.
pub struct CreatedIdentityBundle {
    pub public_identity: CreatedIdentity,
    pub secret_blob: Vec<u8>,
}

/// Generate a new identity (OS CSPRNG); returns public ids/keys only.
pub fn create_identity() -> CreatedIdentity {
    let generated = create_identity_osrng();
    CreatedIdentity {
        identity_id_hex: generated.identity_id().to_hex(),
        device_id_hex: generated.device_id().to_hex(),
        master_pubkey_hex: hex_encode(generated.document.master_pubkey.as_slice()),
        device_pubkey_hex: hex_encode(generated.device.verifying_key().as_bytes()),
    }
}

/// Generate identity and export an opaque secret blob (wrap with Keystore on Android).
pub fn create_identity_bundle() -> CreatedIdentityBundle {
    let generated = create_identity_osrng();
    let blob = export_identity_secret_blob(&generated).expect("export secret blob");
    CreatedIdentityBundle {
        public_identity: CreatedIdentity {
            identity_id_hex: generated.identity_id().to_hex(),
            device_id_hex: generated.device_id().to_hex(),
            master_pubkey_hex: hex_encode(generated.document.master_pubkey.as_slice()),
            device_pubkey_hex: hex_encode(generated.device.verifying_key().as_bytes()),
        },
        secret_blob: blob.into_bytes(),
    }
}

/// Import a Keystore-unwrapped secret blob and return `identity_id` hex.
pub fn identity_id_hex_from_secret_blob(secret_blob: Vec<u8>) -> String {
    let blob = IdentitySecretBlob::from_bytes(secret_blob);
    match import_identity_secret_blob(&blob) {
        Ok(generated) => generated.identity_id().to_hex(),
        Err(_) => String::new(),
    }
}

/// Import a Keystore-unwrapped secret blob and return device verifying-key hex.
pub fn device_pubkey_hex_from_secret_blob(secret_blob: Vec<u8>) -> String {
    let blob = IdentitySecretBlob::from_bytes(secret_blob);
    match import_identity_secret_blob(&blob) {
        Ok(generated) => hex_encode(generated.device.verifying_key().as_bytes()),
        Err(_) => String::new(),
    }
}

/// `identity_id = BLAKE3(master_pubkey)` as hex (master_pubkey is 64 hex chars).
pub fn identity_id_hex(master_pubkey_hex: String) -> String {
    let bytes = hex_decode_32(&master_pubkey_hex).unwrap_or([0u8; 32]);
    identity_id_hex_from_master_pubkey(&bytes).unwrap_or_else(|_| String::new())
}

/// Sign KeyPackage TLS bytes with device ed25519 (answers.md §58 KeyPackageBind).
pub fn sign_key_package_bind_hex(
    secret_blob: Vec<u8>,
    room_id_hex: String,
    key_package_hex: String,
) -> String {
    let blob = IdentitySecretBlob::from_bytes(secret_blob);
    let Ok(generated) = import_identity_secret_blob(&blob) else {
        return String::new();
    };
    let Some(room_bytes) = hex_decode_32(&room_id_hex) else {
        return String::new();
    };
    let Some(kp) = hex_decode_flex(&key_package_hex) else {
        return String::new();
    };
    let room_id = Cid(room_bytes);
    let identity_id = generated.identity_id().0;
    let device_id = generated.device_id().0;
    let kp_hash = *blake3_hash(&kp).as_bytes();
    let message = encode_key_package_bind_v1(&identity_id, &device_id, &room_id, &kp_hash);
    use ed25519_dalek::Signer;
    let sig = generated.device.sign(&message);
    let bind = KeyPackageBindV1 {
        identity_id,
        device_id,
        room_id,
        key_package_tls: kp,
        device_signature: sig.to_bytes(),
    };
    match encode_key_package_bind_wire_v1(&bind) {
        Ok(bytes) => hex_encode(&bytes),
        Err(_) => String::new(),
    }
}

/// Signed MessageEvent wire produced from Keystore-unwrapped secret + opaque ciphertext.
pub struct SignedMessageEventWire {
    pub wire_envelope: Vec<u8>,
    pub event_id_hex: String,
}

/// Create a signed text MessageEvent whose ciphertext was pre-sealed (libsignal JNI).
///
/// Fail-closed: returns empty `wire_envelope` / empty hex on malformed inputs.
/// Invalid parent hex entries are skipped (fail-open on junk, not on crypto).
pub fn create_signed_text_event(
    secret_blob: Vec<u8>,
    room_id: Vec<u8>,
    ciphertext: Vec<u8>,
    causal_parent_hexes: Vec<String>,
) -> SignedMessageEventWire {
    let empty = SignedMessageEventWire {
        wire_envelope: Vec::new(),
        event_id_hex: String::new(),
    };
    if room_id.len() != 32 {
        return empty;
    }
    let blob = IdentitySecretBlob::from_bytes(secret_blob);
    let Ok(generated) = import_identity_secret_blob(&blob) else {
        return empty;
    };
    let mut room = [0u8; 32];
    room.copy_from_slice(&room_id);
    let event = create_signed_message_event(
        Cid(room),
        generated.device_id().0,
        generated.identity_id().0,
        cids_from_hexes(causal_parent_hexes),
        0,
        ContentType::Text,
        ciphertext,
        &generated.device,
    );
    let Ok(wire) = encode_message_event_wire_v1(&event) else {
        return empty;
    };
    SignedMessageEventWire {
        wire_envelope: wire,
        event_id_hex: hex_encode(&event.id.0),
    }
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Parse 64-char hex CIDs; skip malformed entries.
pub(crate) fn cids_from_hexes(hexes: Vec<String>) -> Vec<Cid> {
    hexes
        .into_iter()
        .filter_map(|h| hex_decode_32(h.trim()).map(Cid))
        .collect()
}

pub(crate) fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
        out[i] = byte;
    }
    Some(out)
}

pub(crate) fn hex_decode_flex(s: &str) -> Option<Vec<u8>> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    for i in (0..clean.len()).step_by(2) {
        let byte = u8::from_str_radix(&clean[i..i + 2], 16).ok()?;
        out.push(byte);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_strings_nonempty() {
        assert!(!proto_draft_version().is_empty());
        assert!(!core_version().is_empty());
        assert!(identity_hello().contains("identity"));
        assert_eq!(invite_token_version_byte_hex(), "01");
    }

    #[test]
    fn create_identity_ffi_round_trip_ids() {
        let created = create_identity();
        assert_eq!(created.identity_id_hex.len(), 64);
        assert_eq!(created.device_id_hex.len(), 64);
        assert_ne!(created.identity_id_hex, created.device_id_hex);
        let derived = identity_id_hex(created.master_pubkey_hex.clone());
        assert_eq!(derived, created.identity_id_hex);
    }

    #[test]
    fn create_identity_bundle_secret_round_trip() {
        let bundle = create_identity_bundle();
        assert!(!bundle.secret_blob.is_empty());
        let id = identity_id_hex_from_secret_blob(bundle.secret_blob.clone());
        assert_eq!(id, bundle.public_identity.identity_id_hex);
        assert!(identity_id_hex_from_secret_blob(vec![0, 1, 2]).is_empty());
    }

    #[test]
    fn create_signed_text_event_accepts_opaque_ciphertext() {
        let bundle = create_identity_bundle();
        let room = vec![0x11u8; 32];
        // Opaque bytes standing in for libsignal ciphertext (seal happens in Kotlin).
        let sealed = b"libsignal-opaque-ct-fixture".to_vec();
        let out = create_signed_text_event(
            bundle.secret_blob.clone(),
            room.clone(),
            sealed.clone(),
            Vec::new(),
        );
        assert!(!out.wire_envelope.is_empty());
        assert_eq!(out.event_id_hex.len(), 64);
        let bad = create_signed_text_event(vec![1, 2, 3], vec![0u8; 32], sealed.clone(), Vec::new());
        assert!(bad.wire_envelope.is_empty());
    }

    #[test]
    fn create_signed_text_event_chains_causal_parents() {
        let bundle = create_identity_bundle();
        let room = vec![0x22u8; 32];
        let first = create_signed_text_event(
            bundle.secret_blob.clone(),
            room.clone(),
            b"ct-1".to_vec(),
            Vec::new(),
        );
        assert_eq!(first.event_id_hex.len(), 64);
        let second = create_signed_text_event(
            bundle.secret_blob.clone(),
            room,
            b"ct-2".to_vec(),
            vec![first.event_id_hex.clone()],
        );
        assert_ne!(second.event_id_hex, first.event_id_hex);
        let ev = rooms_proto::decode_message_event_wire_v1(&second.wire_envelope).unwrap();
        assert_eq!(ev.causal_parents.len(), 1);
        assert_eq!(hex_encode(&ev.causal_parents[0].0), first.event_id_hex);
    }
}
