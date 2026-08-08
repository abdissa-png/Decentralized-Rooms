//! UniFFI MLS group session — OpenMLS create / welcome / seal / open on device.
//!
//! Wraps `rooms-mls` with hex/byte APIs for Android. Group state can be exported
//! to a blob and restored (MemoryStorage dump). No novel crypto.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rooms_mls::{
    add_member_bytes, create_group, epoch, export_persisted_state, group_id_bytes,
    import_persisted_state, join_from_welcome_bytes, member_count, open_application_bytes,
    process_protocol_message_bytes, remove_member_bytes, seal_application_bytes, MlsGroup,
    MlsMember, MAX_ROOM_MEMBERS,
};
use rooms_proto::{
    blake3_hash, decode_key_package_bind_wire_v1, encode_key_package_bind_v1,
    encode_sync_object_v1, sync_object_cid_v1, SyncObjectType,
};
use std::sync::Mutex;

/// Result of adding a member (commit for existing members + welcome for joiner).
pub struct MlsAddResult {
    pub commit_hex: String,
    pub welcome_hex: String,
    pub epoch: u64,
    pub member_count: u32,
    pub error: String,
}

/// Welcome + Commit packaged as typed DRSO sync objects (Slice C).
pub struct MlsSyncObjects {
    pub welcome_object_hex: String,
    pub welcome_cid_hex: String,
    pub commit_object_hex: String,
    pub commit_cid_hex: String,
    pub error: String,
}

/// In-process OpenMLS group session for one local member.
pub struct MlsGroupSession {
    inner: Mutex<Option<MlsInner>>,
}

struct MlsInner {
    member: MlsMember,
    group: Option<MlsGroup>,
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 2 != 0 {
        return Err(());
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    for i in (0..clean.len()).step_by(2) {
        let byte = u8::from_str_radix(&clean[i..i + 2], 16).map_err(|_| ())?;
        out.push(byte);
    }
    Ok(out)
}

impl MlsGroupSession {
    /// Create a local MLS member labeled by `credential_label` (typically identity_id hex).
    /// Does not create a group until [`Self::create_group`].
    #[allow(clippy::new_without_default)]
    pub fn new(credential_label: String) -> Self {
        let Ok(member) = MlsMember::new(credential_label.as_bytes()) else {
            return Self {
                inner: Mutex::new(None),
            };
        };
        Self {
            inner: Mutex::new(Some(MlsInner {
                member,
                group: None,
            })),
        }
    }

    /// Restore from [`Self::export_state_blob`]. Fail-closed empty session on error.
    pub fn from_state_blob(blob: Vec<u8>) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::from_state_blob_inner(blob))
    }

    fn from_state_blob_inner(blob: Vec<u8>) -> Self {
        match import_persisted_state(&blob) {
            Ok((member, group)) => Self {
                inner: Mutex::new(Some(MlsInner {
                    member,
                    group: Some(group),
                })),
            },
            Err(_) => Self {
                inner: Mutex::new(None),
            },
        }
    }

    pub fn is_ready(&self) -> bool {
        self.inner
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|_| ()))
            .is_some()
    }

    pub fn has_group(&self) -> bool {
        self.inner
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|i| i.group.is_some()))
            .unwrap_or(false)
    }

    pub fn credential_label(&self) -> String {
        let Ok(g) = self.inner.lock() else {
            return String::new();
        };
        match g.as_ref() {
            Some(i) => String::from_utf8_lossy(&i.member.credential_bytes).into_owned(),
            None => String::new(),
        }
    }

    /// Export a fresh KeyPackage as hex (for founder to add this member).
    pub fn export_key_package_hex(&self) -> String {
        let Ok(g) = self.inner.lock() else {
            return String::new();
        };
        let Some(inner) = g.as_ref() else {
            return String::new();
        };
        match inner.member.key_package_bytes() {
            Ok(b) => hex_encode(&b),
            Err(_) => String::new(),
        }
    }

    /// Create a new MLS group (founder). Returns group_id hex or empty on failure.
    pub fn create_group(&self) -> String {
        let Ok(mut g) = self.inner.lock() else {
            return String::new();
        };
        let Some(inner) = g.as_mut() else {
            return String::new();
        };
        match create_group(&inner.member) {
            Ok(group) => {
                let id = hex_encode(&group_id_bytes(&group));
                inner.group = Some(group);
                id
            }
            Err(_) => String::new(),
        }
    }

    pub fn group_id_hex(&self) -> String {
        let Ok(g) = self.inner.lock() else {
            return String::new();
        };
        match g.as_ref().and_then(|i| i.group.as_ref()) {
            Some(group) => hex_encode(&group_id_bytes(group)),
            None => String::new(),
        }
    }

    pub fn epoch(&self) -> u64 {
        let Ok(g) = self.inner.lock() else {
            return 0;
        };
        match g.as_ref().and_then(|i| i.group.as_ref()) {
            Some(group) => epoch(group),
            None => 0,
        }
    }

    pub fn member_count(&self) -> u32 {
        let Ok(g) = self.inner.lock() else {
            return 0;
        };
        match g.as_ref().and_then(|i| i.group.as_ref()) {
            Some(group) => member_count(group) as u32,
            None => 0,
        }
    }

    pub fn max_members(&self) -> u32 {
        MAX_ROOM_MEMBERS as u32
    }

    /// Founder: add joiner from their KeyPackage hex. Returns commit + welcome hex.
    pub fn add_member_key_package_hex(&self, key_package_hex: String) -> MlsAddResult {
        let empty = |err: &str| MlsAddResult {
            commit_hex: String::new(),
            welcome_hex: String::new(),
            epoch: 0,
            member_count: 0,
            error: err.to_string(),
        };
        let Ok(kp) = hex_decode(&key_package_hex) else {
            return empty("bad key package hex");
        };
        let Ok(mut g) = self.inner.lock() else {
            return empty("lock poisoned");
        };
        let Some(inner) = g.as_mut() else {
            return empty("session not ready");
        };
        let Some(group) = inner.group.as_mut() else {
            return empty("no group — create_group first");
        };
        if member_count(group) >= MAX_ROOM_MEMBERS {
            return empty("member limit exceeded (max 50)");
        }
        match add_member_bytes(group, &inner.member, &kp) {
            Ok((commit, welcome)) => MlsAddResult {
                commit_hex: hex_encode(&commit),
                welcome_hex: hex_encode(&welcome),
                epoch: epoch(group),
                member_count: member_count(group) as u32,
                error: String::new(),
            },
            Err(e) => empty(&e.to_string()),
        }
    }

    /// Add member only after verifying KeyPackageBind under invitee device VK.
    pub fn add_member_key_package_bind_hex(
        &self,
        bind_hex: String,
        device_vk_hex: String,
    ) -> MlsAddResult {
        let empty = |err: &str| MlsAddResult {
            commit_hex: String::new(),
            welcome_hex: String::new(),
            epoch: 0,
            member_count: 0,
            error: err.to_string(),
        };
        let Ok(bind_bytes) = hex_decode(&bind_hex) else {
            return empty("bad bind hex");
        };
        let Ok(bind) = decode_key_package_bind_wire_v1(&bind_bytes) else {
            return empty("bad bind wire");
        };
        let Ok(vk_bytes) = hex_decode(&device_vk_hex) else {
            return empty("bad device vk hex");
        };
        if vk_bytes.len() != 32 {
            return empty("device vk must be 32 bytes");
        }
        let mut vk_arr = [0u8; 32];
        vk_arr.copy_from_slice(&vk_bytes);
        let Ok(vk) = VerifyingKey::from_bytes(&vk_arr) else {
            return empty("bad device vk");
        };
        let expected_device_id = *blake3_hash(&vk_arr).as_bytes();
        if bind.device_id != expected_device_id {
            return empty("device_id mismatch");
        }
        let kp_hash = *blake3_hash(&bind.key_package_tls).as_bytes();
        let message =
            encode_key_package_bind_v1(&bind.identity_id, &bind.device_id, &bind.room_id, &kp_hash);
        let Ok(sig) = Signature::from_slice(&bind.device_signature) else {
            return empty("bad signature");
        };
        if vk.verify(&message, &sig).is_err() {
            return empty("KeyPackageBind signature invalid");
        }
        self.add_member_key_package_hex(hex_encode(&bind.key_package_tls))
    }

    /// Wrap Welcome/Commit TLS bytes as DRSO objects for Offer/Want/Have.
    pub fn package_welcome_commit_objects(
        &self,
        welcome_hex: String,
        commit_hex: String,
    ) -> MlsSyncObjects {
        let empty = |err: &str| MlsSyncObjects {
            welcome_object_hex: String::new(),
            welcome_cid_hex: String::new(),
            commit_object_hex: String::new(),
            commit_cid_hex: String::new(),
            error: err.to_string(),
        };
        let Ok(welcome) = hex_decode(&welcome_hex) else {
            return empty("bad welcome hex");
        };
        let Ok(commit) = hex_decode(&commit_hex) else {
            return empty("bad commit hex");
        };
        let w_wire = encode_sync_object_v1(SyncObjectType::MlsWelcome, &welcome);
        let c_wire = encode_sync_object_v1(SyncObjectType::MlsCommit, &commit);
        let w_cid = sync_object_cid_v1(SyncObjectType::MlsWelcome, &welcome);
        let c_cid = sync_object_cid_v1(SyncObjectType::MlsCommit, &commit);
        let _ = self;
        MlsSyncObjects {
            welcome_object_hex: hex_encode(&w_wire),
            welcome_cid_hex: hex_encode(&w_cid.0),
            commit_object_hex: hex_encode(&c_wire),
            commit_cid_hex: hex_encode(&c_cid.0),
            error: String::new(),
        }
    }

    /// Joiner: join from Welcome hex. Returns true on success.
    pub fn join_from_welcome_hex(&self, welcome_hex: String) -> bool {
        let Ok(bytes) = hex_decode(&welcome_hex) else {
            return false;
        };
        let Ok(mut g) = self.inner.lock() else {
            return false;
        };
        let Some(inner) = g.as_mut() else {
            return false;
        };
        match join_from_welcome_bytes(&inner.member, &bytes) {
            Ok(group) => {
                inner.group = Some(group);
                true
            }
            Err(_) => false,
        }
    }

    /// Process a Commit (or other protocol) message hex; merges epoch.
    pub fn process_commit_hex(&self, commit_hex: String) -> bool {
        let Ok(bytes) = hex_decode(&commit_hex) else {
            return false;
        };
        let Ok(mut g) = self.inner.lock() else {
            return false;
        };
        let Some(inner) = g.as_mut() else {
            return false;
        };
        let Some(group) = inner.group.as_mut() else {
            return false;
        };
        process_protocol_message_bytes(group, &inner.member, &bytes).is_ok()
    }

    /// Seal plaintext under current epoch → ciphertext message hex.
    pub fn seal_text(&self, plaintext: String) -> String {
        let Ok(mut g) = self.inner.lock() else {
            return String::new();
        };
        let Some(inner) = g.as_mut() else {
            return String::new();
        };
        let Some(group) = inner.group.as_mut() else {
            return String::new();
        };
        match seal_application_bytes(group, &inner.member, plaintext.as_bytes()) {
            Ok(b) => hex_encode(&b),
            Err(_) => String::new(),
        }
    }

    /// Open MLS application message hex → UTF-8 plaintext (empty on failure).
    pub fn open_message_hex(&self, message_hex: String) -> String {
        let Ok(bytes) = hex_decode(&message_hex) else {
            return String::new();
        };
        let Ok(mut g) = self.inner.lock() else {
            return String::new();
        };
        let Some(inner) = g.as_mut() else {
            return String::new();
        };
        let Some(group) = inner.group.as_mut() else {
            return String::new();
        };
        match open_application_bytes(group, &inner.member, &bytes) {
            Ok(pt) => String::from_utf8_lossy(&pt).into_owned(),
            Err(_) => String::new(),
        }
    }

    /// Remove member by credential label; returns commit hex (empty on failure).
    pub fn remove_member_label(&self, credential_label: String) -> String {
        let Ok(mut g) = self.inner.lock() else {
            return String::new();
        };
        let Some(inner) = g.as_mut() else {
            return String::new();
        };
        let Some(group) = inner.group.as_mut() else {
            return String::new();
        };
        match remove_member_bytes(group, &inner.member, credential_label.as_bytes()) {
            Ok(b) => hex_encode(&b),
            Err(_) => String::new(),
        }
    }

    /// Persist group + provider storage for device files / KvStore.
    pub fn export_state_blob(&self) -> Vec<u8> {
        let Ok(g) = self.inner.lock() else {
            return Vec::new();
        };
        let Some(inner) = g.as_ref() else {
            return Vec::new();
        };
        let Some(group) = inner.group.as_ref() else {
            return Vec::new();
        };
        export_persisted_state(&inner.member, group).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_three_member_round_trip() {
        let alice = MlsGroupSession::new("alice".into());
        let bob = MlsGroupSession::new("bob".into());
        let charlie = MlsGroupSession::new("charlie".into());
        assert!(alice.is_ready());
        let gid = alice.create_group();
        assert_eq!(gid.len(), 32); // 16 bytes hex

        let add_bob = alice.add_member_key_package_hex(bob.export_key_package_hex());
        assert!(add_bob.error.is_empty(), "{}", add_bob.error);
        assert!(bob.join_from_welcome_hex(add_bob.welcome_hex));
        assert_eq!(alice.member_count(), 2);

        let add_c = alice.add_member_key_package_hex(charlie.export_key_package_hex());
        assert!(add_c.error.is_empty(), "{}", add_c.error);
        assert!(bob.process_commit_hex(add_c.commit_hex.clone()));
        assert!(charlie.join_from_welcome_hex(add_c.welcome_hex));
        assert_eq!(alice.member_count(), 3);

        let sealed = alice.seal_text("hello room".into());
        assert!(!sealed.is_empty());
        assert_eq!(bob.open_message_hex(sealed.clone()), "hello room");
        assert_eq!(charlie.open_message_hex(sealed), "hello room");

        let blob = bob.export_state_blob();
        assert!(!blob.is_empty());
        let bob2 = MlsGroupSession::from_state_blob(blob);
        assert!(bob2.has_group());
        assert_eq!(bob2.epoch(), bob.epoch());
    }
}
