//! OpenMLS glue for Decentralized Encrypted Rooms (WBS 4.1.1).
//!
//! Wraps OpenMLS **0.6** + `openmls_rust_crypto` + `openmls_basic_credential`.
//! **No novel crypto** — application messages and TreeKEM commits only through OpenMLS.
//!
//! Informed by `rooms-spikes` `openmls` hello-group; this crate is the production path.
//! Byte-oriented helpers + MemoryStorage dump/restore support UniFFI / on-device use.

use openmls::prelude::{tls_codec::Deserialize, tls_codec::Serialize, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use std::collections::HashMap;
use thiserror::Error;

/// Re-export group handle for UniFFI session storage.
pub use openmls::prelude::MlsGroup;

/// Ciphersuite locked by ADR-0003 / Phase 0 spike.
pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

/// Soft/hard room size bound (SRS FR-RM-005). Enforced by callers in `rooms-room`;
/// MLS glue exposes member count for checks.
pub const MAX_ROOM_MEMBERS: usize = 50;

/// Magic for persisted MLS provider blobs (`DRMS` + version).
pub const PERSIST_MAGIC: &[u8; 4] = b"DRMS";
/// Persist blob format version.
pub const PERSIST_VERSION: u8 = 1;

/// Errors from the OpenMLS wrapper.
#[derive(Debug, Error)]
pub enum MlsError {
    #[error("openmls: {0}")]
    OpenMls(String),
    #[error("member limit exceeded (max {MAX_ROOM_MEMBERS})")]
    MemberLimitExceeded,
    #[error("expected Welcome message")]
    ExpectedWelcome,
    #[error("expected staged commit")]
    ExpectedStagedCommit,
    #[error("expected application message")]
    ExpectedApplicationMessage,
    #[error("leaf not found for credential")]
    LeafNotFound,
    #[error("persist: {0}")]
    Persist(String),
    #[error("group not loaded")]
    GroupNotLoaded,
}

fn map_err<E: std::fmt::Debug>(e: E) -> MlsError {
    MlsError::OpenMls(format!("{e:?}"))
}

/// Serialize outbound MLS message to inbound form (local DS stand-in for tests).
pub fn deliver(out: MlsMessageOut) -> Result<MlsMessageIn, MlsError> {
    let bytes = out.to_bytes().map_err(map_err)?;
    MlsMessageIn::tls_deserialize_exact(bytes.as_slice()).map_err(map_err)
}

/// TLS-serialize an outbound MLS message to bytes (shareable Welcome/Commit/App).
pub fn message_out_to_bytes(out: &MlsMessageOut) -> Result<Vec<u8>, MlsError> {
    out.to_bytes().map_err(map_err)
}

/// Parse wire bytes as [`MlsMessageIn`].
pub fn message_in_from_bytes(bytes: &[u8]) -> Result<MlsMessageIn, MlsError> {
    MlsMessageIn::tls_deserialize_exact(bytes).map_err(map_err)
}

fn extract_welcome(out: MlsMessageOut) -> Result<Welcome, MlsError> {
    match deliver(out)?.extract() {
        MlsMessageBodyIn::Welcome(w) => Ok(w),
        _ => Err(MlsError::ExpectedWelcome),
    }
}

fn extract_welcome_from_bytes(bytes: &[u8]) -> Result<Welcome, MlsError> {
    match message_in_from_bytes(bytes)?.extract() {
        MlsMessageBodyIn::Welcome(w) => Ok(w),
        _ => Err(MlsError::ExpectedWelcome),
    }
}

/// Local MLS identity material for one group member.
pub struct MlsMember {
    pub provider: OpenMlsRustCrypto,
    pub signer: SignatureKeyPair,
    pub credential_with_key: CredentialWithKey,
    /// Basic credential identity bytes (e.g. identity id hex or label).
    pub credential_bytes: Vec<u8>,
}

impl MlsMember {
    /// Create a new member with a basic credential labeled by `name`.
    pub fn new(name: &[u8]) -> Result<Self, MlsError> {
        let provider = OpenMlsRustCrypto::default();
        let credential = BasicCredential::new(name.to_vec());
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(map_err)?;
        signer.store(provider.storage()).map_err(map_err)?;
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.to_public_vec().into(),
        };
        Ok(Self {
            provider,
            signer,
            credential_with_key,
            credential_bytes: name.to_vec(),
        })
    }

    /// Signature public key bytes (for persistence / restore).
    pub fn signature_public_key(&self) -> Vec<u8> {
        self.signer.to_public_vec()
    }

    /// Generate a KeyPackage for invitations.
    pub fn key_package(&self) -> Result<KeyPackage, MlsError> {
        Ok(KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential_with_key.clone(),
            )
            .map_err(map_err)?
            .key_package()
            .clone())
    }

    /// TLS-serialize a fresh KeyPackage.
    pub fn key_package_bytes(&self) -> Result<Vec<u8>, MlsError> {
        let kp = self.key_package()?;
        kp.tls_serialize_detached().map_err(map_err)
    }
}

/// Validate + deserialize a KeyPackage from TLS bytes.
pub fn key_package_from_bytes(
    provider: &OpenMlsRustCrypto,
    bytes: &[u8],
) -> Result<KeyPackage, MlsError> {
    let kpi = KeyPackageIn::tls_deserialize(&mut &*bytes).map_err(map_err)?;
    kpi.validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(map_err)
}

/// Default group create/join config (ratchet tree in extensions for Welcome joins).
pub fn group_create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build()
}

/// Create a new MLS group owned by `creator`.
pub fn create_group(creator: &MlsMember) -> Result<MlsGroup, MlsError> {
    MlsGroup::new(
        &creator.provider,
        &creator.signer,
        &group_create_config(),
        creator.credential_with_key.clone(),
    )
    .map_err(map_err)
}

/// Current epoch as u64.
pub fn epoch(group: &MlsGroup) -> u64 {
    group.epoch().as_u64()
}

/// Member count in the group (including self).
pub fn member_count(group: &MlsGroup) -> usize {
    group.members().count()
}

/// Group id bytes.
pub fn group_id_bytes(group: &MlsGroup) -> Vec<u8> {
    group.group_id().to_vec()
}

/// Add a member via KeyPackage; returns (commit for existing members, welcome for joiner).
///
/// Enforces [`MAX_ROOM_MEMBERS`] before committing.
pub fn add_member(
    group: &mut MlsGroup,
    adder: &MlsMember,
    key_package: KeyPackage,
) -> Result<(MlsMessageOut, MlsMessageOut), MlsError> {
    if member_count(group) + 1 > MAX_ROOM_MEMBERS {
        return Err(MlsError::MemberLimitExceeded);
    }
    let (commit, welcome, _gi) = group
        .add_members(&adder.provider, &adder.signer, &[key_package])
        .map_err(map_err)?;
    group
        .merge_pending_commit(&adder.provider)
        .map_err(map_err)?;
    Ok((commit, welcome))
}

/// Add from KeyPackage TLS bytes; returns (commit_bytes, welcome_bytes).
pub fn add_member_bytes(
    group: &mut MlsGroup,
    adder: &MlsMember,
    key_package_bytes: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), MlsError> {
    let kp = key_package_from_bytes(&adder.provider, key_package_bytes)?;
    let (commit, welcome) = add_member(group, adder, kp)?;
    Ok((
        message_out_to_bytes(&commit)?,
        message_out_to_bytes(&welcome)?,
    ))
}

/// Join a group from a Welcome message.
pub fn join_from_welcome(joiner: &MlsMember, welcome: MlsMessageOut) -> Result<MlsGroup, MlsError> {
    let welcome = extract_welcome(welcome)?;
    StagedWelcome::new_from_welcome(
        &joiner.provider,
        group_create_config().join_config(),
        welcome,
        None,
    )
    .map_err(map_err)?
    .into_group(&joiner.provider)
    .map_err(map_err)
}

/// Join from Welcome TLS bytes.
pub fn join_from_welcome_bytes(
    joiner: &MlsMember,
    welcome_bytes: &[u8],
) -> Result<MlsGroup, MlsError> {
    let welcome = extract_welcome_from_bytes(welcome_bytes)?;
    StagedWelcome::new_from_welcome(
        &joiner.provider,
        group_create_config().join_config(),
        welcome,
        None,
    )
    .map_err(map_err)?
    .into_group(&joiner.provider)
    .map_err(map_err)
}

/// Process a commit/protocol message into `group` (merge staged commit when present).
pub fn process_protocol_message(
    group: &mut MlsGroup,
    member: &MlsMember,
    message: MlsMessageOut,
) -> Result<Option<Vec<u8>>, MlsError> {
    let processed = group
        .process_message(
            &member.provider,
            deliver(message)?
                .try_into_protocol_message()
                .map_err(map_err)?,
        )
        .map_err(map_err)?;
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => Ok(Some(app.into_bytes())),
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            group
                .merge_staged_commit(&member.provider, *staged)
                .map_err(map_err)?;
            Ok(None)
        }
        _ => Ok(None),
    }
}

/// Process protocol message from TLS bytes.
pub fn process_protocol_message_bytes(
    group: &mut MlsGroup,
    member: &MlsMember,
    message_bytes: &[u8],
) -> Result<Option<Vec<u8>>, MlsError> {
    let processed = group
        .process_message(
            &member.provider,
            message_in_from_bytes(message_bytes)?
                .try_into_protocol_message()
                .map_err(map_err)?,
        )
        .map_err(map_err)?;
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => Ok(Some(app.into_bytes())),
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            group
                .merge_staged_commit(&member.provider, *staged)
                .map_err(map_err)?;
            Ok(None)
        }
        _ => Ok(None),
    }
}

/// Seal an application plaintext under the current epoch.
pub fn create_application_message(
    group: &mut MlsGroup,
    sender: &MlsMember,
    plaintext: &[u8],
) -> Result<MlsMessageOut, MlsError> {
    group
        .create_message(&sender.provider, &sender.signer, plaintext)
        .map_err(map_err)
}

/// Seal plaintext → TLS message bytes.
pub fn seal_application_bytes(
    group: &mut MlsGroup,
    sender: &MlsMember,
    plaintext: &[u8],
) -> Result<Vec<u8>, MlsError> {
    let msg = create_application_message(group, sender, plaintext)?;
    message_out_to_bytes(&msg)
}

/// Find leaf index by basic-credential identity bytes.
pub fn leaf_index_for_credential(
    group: &MlsGroup,
    credential_bytes: &[u8],
) -> Result<LeafNodeIndex, MlsError> {
    group
        .members()
        .find(|m| m.credential.serialized_content() == credential_bytes)
        .map(|m| m.index)
        .ok_or(MlsError::LeafNotFound)
}

/// Remove a member by credential identity bytes; returns commit for remaining members.
pub fn remove_member(
    group: &mut MlsGroup,
    remover: &MlsMember,
    credential_bytes: &[u8],
) -> Result<MlsMessageOut, MlsError> {
    let index = group
        .members()
        .find(|m| m.credential.serialized_content() == credential_bytes)
        .map(|m| m.index)
        .ok_or(MlsError::LeafNotFound)?;
    let (commit, _welcome, _gi) = group
        .remove_members(&remover.provider, &remover.signer, &[index])
        .map_err(map_err)?;
    group
        .merge_pending_commit(&remover.provider)
        .map_err(map_err)?;
    Ok(commit)
}

/// Remove member; return commit TLS bytes.
pub fn remove_member_bytes(
    group: &mut MlsGroup,
    remover: &MlsMember,
    credential_bytes: &[u8],
) -> Result<Vec<u8>, MlsError> {
    let commit = remove_member(group, remover, credential_bytes)?;
    message_out_to_bytes(&commit)
}

/// Decrypt an application message (returns plaintext bytes).
pub fn open_application_message(
    group: &mut MlsGroup,
    member: &MlsMember,
    message: MlsMessageOut,
) -> Result<Vec<u8>, MlsError> {
    match process_protocol_message(group, member, message)? {
        Some(pt) => Ok(pt),
        None => Err(MlsError::ExpectedApplicationMessage),
    }
}

/// Decrypt application message from TLS bytes.
pub fn open_application_bytes(
    group: &mut MlsGroup,
    member: &MlsMember,
    message_bytes: &[u8],
) -> Result<Vec<u8>, MlsError> {
    match process_protocol_message_bytes(group, member, message_bytes)? {
        Some(pt) => Ok(pt),
        None => Err(MlsError::ExpectedApplicationMessage),
    }
}

/// Dump [`MemoryStorage`] key/value map to a compact blob.
pub fn dump_storage(provider: &OpenMlsRustCrypto) -> Result<Vec<u8>, MlsError> {
    let values = provider
        .storage()
        .values
        .read()
        .map_err(|e| MlsError::Persist(e.to_string()))?;
    let mut out = Vec::new();
    out.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for (k, v) in values.iter() {
        out.extend_from_slice(&(k.len() as u64).to_be_bytes());
        out.extend_from_slice(&(v.len() as u64).to_be_bytes());
        out.extend_from_slice(k);
        out.extend_from_slice(v);
    }
    Ok(out)
}

/// Replace provider storage contents from [`dump_storage`] blob.
pub fn restore_storage(provider: &OpenMlsRustCrypto, blob: &[u8]) -> Result<(), MlsError> {
    let map = parse_storage_blob(blob)?;
    let mut values = provider
        .storage()
        .values
        .write()
        .map_err(|e| MlsError::Persist(e.to_string()))?;
    *values = map;
    Ok(())
}

fn parse_storage_blob(blob: &[u8]) -> Result<HashMap<Vec<u8>, Vec<u8>>, MlsError> {
    if blob.len() < 8 {
        return Err(MlsError::Persist("storage blob too short".into()));
    }
    let mut off = 0usize;
    let read_u64 = |data: &[u8], off: &mut usize| -> Result<u64, MlsError> {
        if *off + 8 > data.len() {
            return Err(MlsError::Persist("truncated storage blob".into()));
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&data[*off..*off + 8]);
        *off += 8;
        Ok(u64::from_be_bytes(b))
    };
    let count = read_u64(blob, &mut off)? as usize;
    if count > 100_000 {
        return Err(MlsError::Persist(
            "storage blob entry count too large".into(),
        ));
    }
    let mut map = HashMap::with_capacity(count);
    for _ in 0..count {
        let k_len = read_u64(blob, &mut off)? as usize;
        let v_len = read_u64(blob, &mut off)? as usize;
        if k_len > 1_000_000 || v_len > 10_000_000 || off + k_len + v_len > blob.len() {
            return Err(MlsError::Persist("storage blob truncated kv".into()));
        }
        let k = blob[off..off + k_len].to_vec();
        off += k_len;
        let v = blob[off..off + v_len].to_vec();
        off += v_len;
        map.insert(k, v);
    }
    Ok(map)
}

/// Persist member + group: magic, credential, sig pubkey, group_id, storage dump.
pub fn export_persisted_state(member: &MlsMember, group: &MlsGroup) -> Result<Vec<u8>, MlsError> {
    let storage = dump_storage(&member.provider)?;
    let cred = &member.credential_bytes;
    let pk = member.signature_public_key();
    let gid = group_id_bytes(group);
    let mut out = Vec::new();
    out.extend_from_slice(PERSIST_MAGIC);
    out.push(PERSIST_VERSION);
    out.extend_from_slice(&(cred.len() as u32).to_le_bytes());
    out.extend_from_slice(cred);
    out.extend_from_slice(&(pk.len() as u32).to_le_bytes());
    out.extend_from_slice(&pk);
    out.extend_from_slice(&(gid.len() as u32).to_le_bytes());
    out.extend_from_slice(&gid);
    out.extend_from_slice(&(storage.len() as u32).to_le_bytes());
    out.extend_from_slice(&storage);
    Ok(out)
}

/// Restore member + group from [`export_persisted_state`].
pub fn import_persisted_state(blob: &[u8]) -> Result<(MlsMember, MlsGroup), MlsError> {
    if blob.len() < 5 + 16 || &blob[0..4] != PERSIST_MAGIC || blob[4] != PERSIST_VERSION {
        return Err(MlsError::Persist("bad persist magic/version".into()));
    }
    let mut off = 5usize;
    let read_len_pref = |data: &[u8], off: &mut usize| -> Result<Vec<u8>, MlsError> {
        if *off + 4 > data.len() {
            return Err(MlsError::Persist("truncated persist".into()));
        }
        let len = u32::from_le_bytes(data[*off..*off + 4].try_into().unwrap()) as usize;
        *off += 4;
        if len > 50_000_000 || *off + len > data.len() {
            return Err(MlsError::Persist("persist field too large".into()));
        }
        let v = data[*off..*off + len].to_vec();
        *off += len;
        Ok(v)
    };
    let credential_bytes = read_len_pref(blob, &mut off)?;
    let public_key = read_len_pref(blob, &mut off)?;
    let group_id = read_len_pref(blob, &mut off)?;
    let storage_blob = read_len_pref(blob, &mut off)?;

    let provider = OpenMlsRustCrypto::default();
    restore_storage(&provider, &storage_blob)?;
    let signer = SignatureKeyPair::read(
        provider.storage(),
        &public_key,
        CIPHERSUITE.signature_algorithm(),
    )
    .ok_or_else(|| MlsError::Persist("signature key missing in storage".into()))?;
    let credential = BasicCredential::new(credential_bytes.clone());
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.to_public_vec().into(),
    };
    let member = MlsMember {
        provider,
        signer,
        credential_with_key,
        credential_bytes,
    };
    let gid = GroupId::from_slice(&group_id);
    let group = MlsGroup::load(member.provider.storage(), &gid)
        .map_err(map_err)?
        .ok_or(MlsError::GroupNotLoaded)?;
    Ok((member, group))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_add_message_remove_epochs() {
        let alice = MlsMember::new(b"alice").unwrap();
        let bob = MlsMember::new(b"bob").unwrap();
        let charlie = MlsMember::new(b"charlie").unwrap();

        let mut alice_group = create_group(&alice).unwrap();
        let epoch_create = epoch(&alice_group);
        assert_eq!(member_count(&alice_group), 1);

        let (_commit, welcome) =
            add_member(&mut alice_group, &alice, bob.key_package().unwrap()).unwrap();
        let epoch_bob = epoch(&alice_group);
        assert!(epoch_bob > epoch_create);

        let mut bob_group = join_from_welcome(&bob, welcome).unwrap();
        assert_eq!(epoch(&bob_group), epoch_bob);

        let (commit, welcome) =
            add_member(&mut alice_group, &alice, charlie.key_package().unwrap()).unwrap();
        let epoch_charlie = epoch(&alice_group);
        assert!(epoch_charlie > epoch_bob);

        process_protocol_message(&mut bob_group, &bob, commit).unwrap();
        let mut charlie_group = join_from_welcome(&charlie, welcome).unwrap();
        assert_eq!(member_count(&alice_group), 3);

        let plaintext = b"hello mls room";
        let msg = create_application_message(&mut alice_group, &alice, plaintext).unwrap();
        let opened = open_application_message(&mut charlie_group, &charlie, msg).unwrap();
        assert_eq!(opened, plaintext);

        let commit = remove_member(&mut alice_group, &alice, b"bob").unwrap();
        let epoch_remove = epoch(&alice_group);
        assert!(epoch_remove > epoch_charlie);
        process_protocol_message(&mut charlie_group, &charlie, commit).unwrap();
        assert_eq!(member_count(&alice_group), 2);
        assert_eq!(epoch(&charlie_group), epoch_remove);
    }

    #[test]
    fn member_limit_constant_is_fifty() {
        assert_eq!(MAX_ROOM_MEMBERS, 50);
    }

    #[test]
    fn add_succeeds_under_member_limit() {
        let alice = MlsMember::new(b"alice").unwrap();
        let mut group = create_group(&alice).unwrap();
        let bob = MlsMember::new(b"bob").unwrap();
        add_member(&mut group, &alice, bob.key_package().unwrap()).unwrap();
        assert_eq!(member_count(&group), 2);
        assert!(member_count(&group) <= MAX_ROOM_MEMBERS);
    }

    #[test]
    fn byte_path_three_member_seal_open() {
        let alice = MlsMember::new(b"alice").unwrap();
        let bob = MlsMember::new(b"bob").unwrap();
        let charlie = MlsMember::new(b"charlie").unwrap();
        let mut alice_g = create_group(&alice).unwrap();
        let bob_kp = bob.key_package_bytes().unwrap();
        let (_c1, welcome_bob) = add_member_bytes(&mut alice_g, &alice, &bob_kp).unwrap();
        let mut bob_g = join_from_welcome_bytes(&bob, &welcome_bob).unwrap();
        let charlie_kp = charlie.key_package_bytes().unwrap();
        let (commit, welcome_c) = add_member_bytes(&mut alice_g, &alice, &charlie_kp).unwrap();
        process_protocol_message_bytes(&mut bob_g, &bob, &commit).unwrap();
        let mut charlie_g = join_from_welcome_bytes(&charlie, &welcome_c).unwrap();
        assert_eq!(member_count(&alice_g), 3);
        let sealed = seal_application_bytes(&mut alice_g, &alice, b"mls-on-device").unwrap();
        let pt = open_application_bytes(&mut bob_g, &bob, &sealed).unwrap();
        assert_eq!(pt, b"mls-on-device");
        let pt2 = open_application_bytes(&mut charlie_g, &charlie, &sealed).unwrap();
        assert_eq!(pt2, b"mls-on-device");
    }

    #[test]
    fn persist_round_trip_preserves_epoch_and_decrypt() {
        let alice = MlsMember::new(b"alice").unwrap();
        let bob = MlsMember::new(b"bob").unwrap();
        let mut alice_g = create_group(&alice).unwrap();
        let (_c, welcome) =
            add_member_bytes(&mut alice_g, &alice, &bob.key_package_bytes().unwrap()).unwrap();
        let bob_g = join_from_welcome_bytes(&bob, &welcome).unwrap();
        let sealed = seal_application_bytes(&mut alice_g, &alice, b"after-persist").unwrap();
        let blob = export_persisted_state(&bob, &bob_g).unwrap();
        let (bob2, mut bob_g2) = import_persisted_state(&blob).unwrap();
        assert_eq!(epoch(&bob_g2), epoch(&bob_g));
        let pt = open_application_bytes(&mut bob_g2, &bob2, &sealed).unwrap();
        assert_eq!(pt, b"after-persist");
    }

    /// Gate 2 nameplate: CRYPTO-MLS-VEC (create → welcome → seal → remove).
    #[test]
    fn crypto_mls_vec_create_welcome_commit_remove() {
        // Same coverage as create_add_message_remove_epochs — explicit Gate 2 nameplate.
        let alice = MlsMember::new(b"alice").unwrap();
        let bob = MlsMember::new(b"bob").unwrap();
        let charlie = MlsMember::new(b"charlie").unwrap();
        let mut alice_group = create_group(&alice).unwrap();
        let (_c, welcome) =
            add_member(&mut alice_group, &alice, bob.key_package().unwrap()).unwrap();
        let mut bob_group = join_from_welcome(&bob, welcome).unwrap();
        let (commit, welcome) =
            add_member(&mut alice_group, &alice, charlie.key_package().unwrap()).unwrap();
        process_protocol_message(&mut bob_group, &bob, commit).unwrap();
        let mut charlie_group = join_from_welcome(&charlie, welcome).unwrap();
        let msg = create_application_message(&mut alice_group, &alice, b"vec").unwrap();
        assert_eq!(
            open_application_message(&mut charlie_group, &charlie, msg).unwrap(),
            b"vec"
        );
        let rem = remove_member(&mut alice_group, &alice, b"bob").unwrap();
        process_protocol_message(&mut charlie_group, &charlie, rem).unwrap();
    }

    /// Gate 2 nameplate: CRYPTO-EPOCH advances on each Commit.
    #[test]
    fn crypto_epoch_advances_on_add_and_remove() {
        let alice = MlsMember::new(b"alice").unwrap();
        let bob = MlsMember::new(b"bob").unwrap();
        let mut g = create_group(&alice).unwrap();
        let e0 = epoch(&g);
        let (_c, w) = add_member_bytes(&mut g, &alice, &bob.key_package_bytes().unwrap()).unwrap();
        let e1 = epoch(&g);
        assert!(e1 > e0);
        let _ = join_from_welcome_bytes(&bob, &w).unwrap();
        let commit = remove_member_bytes(&mut g, &alice, b"bob").unwrap();
        assert!(!commit.is_empty());
        let e2 = epoch(&g);
        assert!(e2 > e1);
    }
}
