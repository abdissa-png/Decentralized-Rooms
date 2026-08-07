//! Phase 2 UniFFI surface: room founding + membership invite/join + invite stub.
//!
//! OpenMLS group seal/open stays in `rooms-mls` (host CI). This module exposes
//! founding `room_id`, creator membership, InviteToken / join material, Accept
//! receipts, and signing a MessageEvent over opaque ciphertext (libsignal/MLS
//! seal happens off-FFI).

use rooms_identity::{
    import_identity_secret_blob, verifying_key_from_bytes, GeneratedIdentity, IdentityId,
    IdentitySecretBlob,
};
use rooms_proto::{
    encode_invite_token_v1, encode_message_event_wire_v1, Cid, ContentType, InviteTokenV1,
};
use rooms_room::{
    create_room, FoundingEvent, HistoryBackfillPolicy, MemberRole, MembershipAction,
    MembershipEvent, RoomId, RoomPolicy, RoomState,
};
use rooms_sync::create_signed_message_event;
use std::sync::Mutex;

use crate::{cids_from_hexes, hex_encode, SignedMessageEventWire};

/// Public founding result for Android room UI.
pub struct FoundedRoom {
    pub room_id_hex: String,
    pub creator_identity_id_hex: String,
    pub active_member_id_hexes: Vec<String>,
    pub active_member_count: u32,
}

/// In-process founded/joined room for Compose UI (no MLS group on device).
pub struct LocalRoomSession {
    inner: Mutex<Option<LocalRoomInner>>,
}

struct LocalRoomInner {
    secret: GeneratedIdentity,
    room: RoomState,
    /// Device verifying keys known for membership event verification (hex → bytes).
    known_device_vks: Vec<[u8; 32]>,
    /// Last signed MessageEvent ids used as causal parents when caller passes none.
    last_tips: Vec<Cid>,
    /// Optional MLS Welcome CID from DRIM v2 invite (joiner Want seed).
    welcome_cid: Option<Cid>,
    /// Optional MLS Commit CID from DRIM v2 invite.
    commit_cid: Option<Cid>,
}

const INVITE_MAT_MAGIC: &[u8; 4] = b"DRIM";
const ACCEPT_MAT_MAGIC: &[u8; 4] = b"DRAM";
const ROOM_STATE_MAGIC: &[u8; 4] = b"DRRS";
const MAT_VERSION: u8 = 1;
const MAT_VERSION_V2: u8 = 2;

impl LocalRoomSession {
    /// Found a room with the identity from a Keystore-unwrapped secret blob.
    /// Fail-closed: empty `room_id_hex` / members when the blob is malformed.
    #[allow(clippy::new_without_default)]
    pub fn new(secret_blob: Vec<u8>, created_unix_secs: u64) -> Self {
        let blob = IdentitySecretBlob::from_bytes(secret_blob);
        let Ok(secret) = import_identity_secret_blob(&blob) else {
            return Self {
                inner: Mutex::new(None),
            };
        };
        let creator = secret.identity_id();
        let (_room_id, founding) = create_room(
            creator,
            created_unix_secs,
            RoomPolicy::default(),
            &secret.device,
        );
        let room = RoomState::from_founding(founding);
        let vk = *secret.device.verifying_key().as_bytes();
        Self {
            inner: Mutex::new(Some(LocalRoomInner {
                secret,
                room,
                known_device_vks: vec![vk],
                last_tips: Vec::new(),
                welcome_cid: None,
                commit_cid: None,
            })),
        }
    }

    pub fn room_id_hex(&self) -> String {
        let Ok(g) = self.inner.lock() else {
            return String::new();
        };
        match g.as_ref() {
            Some(inner) => hex_encode(&inner.room.room_id.0 .0),
            None => String::new(),
        }
    }

    pub fn creator_identity_id_hex(&self) -> String {
        let Ok(g) = self.inner.lock() else {
            return String::new();
        };
        match g.as_ref() {
            Some(inner) => inner.room.creator_id.to_hex(),
            None => String::new(),
        }
    }

    pub fn active_member_id_hexes(&self) -> Vec<String> {
        let Ok(g) = self.inner.lock() else {
            return Vec::new();
        };
        let Some(inner) = g.as_ref() else {
            return Vec::new();
        };
        inner
            .room
            .resolved_membership()
            .active_members()
            .into_iter()
            .map(|(id, _)| id.to_hex())
            .collect()
    }

    pub fn active_member_count(&self) -> u32 {
        self.active_member_id_hexes().len() as u32
    }

    /// Encode an InviteTokenV1 stub (no MLS Welcome). Empty string on failure.
    pub fn invite_token_hex(&self, invitee_identity_id_hex: String) -> String {
        let Ok(g) = self.inner.lock() else {
            return String::new();
        };
        let Some(inner) = g.as_ref() else {
            return String::new();
        };
        if invitee_identity_id_hex.len() != 64 {
            return String::new();
        }
        let token = InviteTokenV1 {
            room_id: inner.room.room_id.0,
            inviter_identity_id: inner.secret.identity_id().0,
            authenticity: Vec::new(),
            bootstrap_hints: Vec::new(),
        };
        match encode_invite_token_v1(&token) {
            Ok(bytes) => hex_encode(&bytes),
            Err(_) => String::new(),
        }
    }

    /// Build copyable join material: founding + Invite membership + inviter device VK.
    ///
    /// No MLS Welcome. Empty on failure.
    pub fn invite_material_hex(&self, invitee_identity_id_hex: String) -> String {
        let Ok(mut g) = self.inner.lock() else {
            return String::new();
        };
        let Some(inner) = g.as_mut() else {
            return String::new();
        };
        let Ok(invitee) = parse_identity_id(&invitee_identity_id_hex) else {
            return String::new();
        };
        let parents = inner.room.membership.tips();
        let invite = MembershipEvent::create_signed(
            inner.room.room_id,
            inner.secret.identity_id(),
            MembershipAction::Invite,
            invitee,
            Some(MemberRole::Member),
            parents,
            &inner.secret.device,
        );
        let inviter_vk = *inner.secret.device.verifying_key().as_bytes();
        if inner
            .room
            .append_membership(invite.clone(), &inner.secret.device.verifying_key())
            .is_err()
        {
            return String::new();
        }
        let mut out = Vec::new();
        out.extend_from_slice(INVITE_MAT_MAGIC);
        out.push(MAT_VERSION);
        encode_founding(&mut out, &inner.room.founding, &inviter_vk);
        encode_membership(&mut out, &invite);
        out.extend_from_slice(&inviter_vk);
        hex_encode(&out)
    }

    /// Founder: invite material with MLS Welcome/Commit CIDs (DRIM v2).
    /// Empty welcome/commit hex → zeros (absent). Empty string on failure.
    pub fn invite_material_with_welcome_hex(
        &self,
        invitee_identity_id_hex: String,
        welcome_cid_hex: String,
        commit_cid_hex: String,
    ) -> String {
        let Ok(mut g) = self.inner.lock() else {
            return String::new();
        };
        let Some(inner) = g.as_mut() else {
            return String::new();
        };
        let Ok(invitee) = parse_identity_id(&invitee_identity_id_hex) else {
            return String::new();
        };
        let welcome_cid = parse_optional_cid(&welcome_cid_hex);
        let commit_cid = parse_optional_cid(&commit_cid_hex);
        let parents = inner.room.membership.tips();
        let invite = MembershipEvent::create_signed(
            inner.room.room_id,
            inner.secret.identity_id(),
            MembershipAction::Invite,
            invitee,
            Some(MemberRole::Member),
            parents,
            &inner.secret.device,
        );
        let inviter_vk = *inner.secret.device.verifying_key().as_bytes();
        if inner
            .room
            .append_membership(invite.clone(), &inner.secret.device.verifying_key())
            .is_err()
        {
            return String::new();
        }
        let mut out = Vec::new();
        out.extend_from_slice(INVITE_MAT_MAGIC);
        out.push(MAT_VERSION_V2);
        encode_founding(&mut out, &inner.room.founding, &inviter_vk);
        encode_membership(&mut out, &invite);
        out.extend_from_slice(&inviter_vk);
        out.extend_from_slice(&welcome_cid.unwrap_or(Cid([0u8; 32])).0);
        out.extend_from_slice(&commit_cid.unwrap_or(Cid([0u8; 32])).0);
        hex_encode(&out)
    }

    /// Joiner: Welcome CID hex from DRIM v2 (empty if absent / v1).
    pub fn welcome_cid_hex(&self) -> String {
        let Ok(g) = self.inner.lock() else {
            return String::new();
        };
        match g.as_ref().and_then(|i| i.welcome_cid.as_ref()) {
            Some(c) => hex_encode(&c.0),
            None => String::new(),
        }
    }

    /// Joiner: Commit CID hex from DRIM v2 (empty if absent / v1).
    pub fn commit_cid_hex(&self) -> String {
        let Ok(g) = self.inner.lock() else {
            return String::new();
        };
        match g.as_ref().and_then(|i| i.commit_cid.as_ref()) {
            Some(c) => hex_encode(&c.0),
            None => String::new(),
        }
    }

    /// Admin remove/promote/demote or self leave. Returns signed membership event hex.
    /// Empty on unauthorized / parse failure (`authorize_mutation`).
    pub fn membership_mutation_hex(
        &self,
        action: String,
        target_identity_id_hex: String,
    ) -> String {
        let Ok(mut g) = self.inner.lock() else {
            return String::new();
        };
        let Some(inner) = g.as_mut() else {
            return String::new();
        };
        let Ok(target) = parse_identity_id(&target_identity_id_hex) else {
            return String::new();
        };
        let action = match action.to_ascii_lowercase().as_str() {
            "remove" => MembershipAction::Remove,
            "promote" => MembershipAction::Promote,
            "demote" => MembershipAction::Demote,
            "leave" => MembershipAction::Leave,
            _ => return String::new(),
        };
        let role = match action {
            MembershipAction::Promote => Some(MemberRole::Admin),
            MembershipAction::Demote => Some(MemberRole::Member),
            _ => None,
        };
        let parents = inner.room.membership.tips();
        let event = MembershipEvent::create_signed(
            inner.room.room_id,
            inner.secret.identity_id(),
            action,
            target,
            role,
            parents,
            &inner.secret.device,
        );
        if inner
            .room
            .append_membership(event.clone(), &inner.secret.device.verifying_key())
            .is_err()
        {
            return String::new();
        }
        let mut out = Vec::new();
        encode_membership(&mut out, &event);
        hex_encode(&out)
    }

    /// Apply a remote signed membership event hex (gossip). Returns false on failure.
    pub fn apply_membership_event_hex(&self, event_hex: String) -> bool {
        let Ok(bytes) = hex_decode(&event_hex) else {
            return false;
        };
        let Ok((event, rest)) = decode_membership(&bytes) else {
            return false;
        };
        if !rest.is_empty() {
            return false;
        }
        let Ok(mut g) = self.inner.lock() else {
            return false;
        };
        let Some(inner) = g.as_mut() else {
            return false;
        };
        for vk_bytes in &inner.known_device_vks.clone() {
            if let Ok(vk) = verifying_key_from_bytes(vk_bytes) {
                if inner.room.append_membership(event.clone(), &vk).is_ok() {
                    return true;
                }
            }
        }
        false
    }

    /// After joining, produce an Accept receipt the founder can apply.
    pub fn accept_receipt_hex(&self) -> String {
        let Ok(g) = self.inner.lock() else {
            return String::new();
        };
        let Some(inner) = g.as_ref() else {
            return String::new();
        };
        let me = inner.secret.identity_id();
        let accept = inner.room.membership.events().find(|e| {
            e.action == MembershipAction::Accept && e.target_id == me && e.author_id == me
        });
        let Some(accept) = accept.cloned() else {
            return String::new();
        };
        let joiner_vk = *inner.secret.device.verifying_key().as_bytes();
        let mut out = Vec::new();
        out.extend_from_slice(ACCEPT_MAT_MAGIC);
        out.push(MAT_VERSION);
        encode_membership(&mut out, &accept);
        out.extend_from_slice(&joiner_vk);
        hex_encode(&out)
    }

    /// Apply a joiner's Accept receipt (founder side). Returns true on success.
    pub fn apply_accept_receipt_hex(&self, receipt_hex: String) -> bool {
        let Ok(bytes) = hex_decode(&receipt_hex) else {
            return false;
        };
        if bytes.len() < 5 + 32 || &bytes[0..4] != ACCEPT_MAT_MAGIC || bytes[4] != MAT_VERSION {
            return false;
        }
        let Ok((accept, rest)) = decode_membership(&bytes[5..]) else {
            return false;
        };
        if rest.len() != 32 {
            return false;
        }
        let mut vk_bytes = [0u8; 32];
        vk_bytes.copy_from_slice(rest);
        let Ok(vk) = verifying_key_from_bytes(&vk_bytes) else {
            return false;
        };
        let Ok(mut g) = self.inner.lock() else {
            return false;
        };
        let Some(inner) = g.as_mut() else {
            return false;
        };
        if inner.room.append_membership(accept, &vk).is_err() {
            return false;
        }
        if !inner.known_device_vks.contains(&vk_bytes) {
            inner.known_device_vks.push(vk_bytes);
        }
        true
    }

    /// Sign a MessageEvent for this room; ciphertext is opaque (no MLS seal here).
    /// Empty `causal_parent_hexes` uses [`LocalRoomInner::last_tips`].
    pub fn sign_text_event(
        &self,
        ciphertext: Vec<u8>,
        causal_parent_hexes: Vec<String>,
    ) -> SignedMessageEventWire {
        let empty = SignedMessageEventWire {
            wire_envelope: Vec::new(),
            event_id_hex: String::new(),
        };
        let Ok(mut g) = self.inner.lock() else {
            return empty;
        };
        let Some(inner) = g.as_mut() else {
            return empty;
        };
        let mut parents = cids_from_hexes(causal_parent_hexes);
        if parents.is_empty() {
            parents = inner.last_tips.clone();
        }
        let event = create_signed_message_event(
            inner.room.room_id.0,
            inner.secret.device_id().0,
            inner.secret.identity_id().0,
            parents,
            0,
            ContentType::Text,
            ciphertext,
            &inner.secret.device,
        );
        let Ok(wire) = encode_message_event_wire_v1(&event) else {
            return empty;
        };
        inner.last_tips = vec![event.id];
        SignedMessageEventWire {
            wire_envelope: wire,
            event_id_hex: hex_encode(&event.id.0),
        }
    }

    /// Export trusted room membership state for process-restart restoration.
    ///
    /// The local identity secret is deliberately not included; Android supplies
    /// its Keystore-unwrapped secret again to [`local_room_session_from_state_blob`].
    pub fn export_state_blob(&self) -> Vec<u8> {
        let Ok(g) = self.inner.lock() else {
            return Vec::new();
        };
        let Some(inner) = g.as_ref() else {
            return Vec::new();
        };
        let Some(creator_vk) = inner.known_device_vks.iter().find(|vk_bytes| {
            verifying_key_from_bytes(vk_bytes)
                .map(|vk| inner.room.founding.verify(&vk).is_ok())
                .unwrap_or(false)
        }) else {
            return Vec::new();
        };

        let mut out = Vec::new();
        out.extend_from_slice(ROOM_STATE_MAGIC);
        out.push(MAT_VERSION);
        encode_founding(&mut out, &inner.room.founding, creator_vk);

        let mut events: Vec<_> = inner.room.membership.events().cloned().collect();
        events.sort_by_key(|event| event.id.0);
        out.extend_from_slice(&(events.len() as u32).to_le_bytes());
        for event in events {
            let mut encoded = Vec::new();
            encode_membership(&mut encoded, &event);
            out.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            out.extend_from_slice(&encoded);
        }

        out.extend_from_slice(&(inner.known_device_vks.len() as u32).to_le_bytes());
        for vk in &inner.known_device_vks {
            out.extend_from_slice(vk);
        }
        out.extend_from_slice(&(inner.last_tips.len() as u32).to_le_bytes());
        for tip in &inner.last_tips {
            out.extend_from_slice(&tip.0);
        }
        encode_optional_cid(&mut out, inner.welcome_cid);
        encode_optional_cid(&mut out, inner.commit_cid);
        out
    }
}

/// Join from invite material produced by [`LocalRoomSession::invite_material_hex`].
///
/// Applies Invite + Accept into a local membership CRDT. No OpenMLS Welcome.
/// Empty session (fail-closed) on malformed material.
pub fn join_room_from_invite(
    secret_blob: Vec<u8>,
    invite_material_hex: String,
) -> std::sync::Arc<LocalRoomSession> {
    std::sync::Arc::new(join_room_from_invite_inner(
        secret_blob,
        invite_material_hex,
    ))
}

/// Restore a founded/joined room after process death.
///
/// Fail-closed: verifies the founding signature and replays every membership
/// event with one of the previously trusted device verifying keys.
pub fn local_room_session_from_state_blob(
    secret_blob: Vec<u8>,
    state_blob: Vec<u8>,
) -> std::sync::Arc<LocalRoomSession> {
    std::sync::Arc::new(local_room_session_from_state_blob_inner(
        secret_blob,
        state_blob,
    ))
}

fn local_room_session_from_state_blob_inner(
    secret_blob: Vec<u8>,
    state_blob: Vec<u8>,
) -> LocalRoomSession {
    let empty = || LocalRoomSession {
        inner: Mutex::new(None),
    };
    let blob = IdentitySecretBlob::from_bytes(secret_blob);
    let Ok(secret) = import_identity_secret_blob(&blob) else {
        return empty();
    };
    if state_blob.len() < 5 || &state_blob[0..4] != ROOM_STATE_MAGIC || state_blob[4] != MAT_VERSION {
        return empty();
    }
    let Ok((founding, creator_vk_bytes, mut rest)) = decode_founding(&state_blob[5..]) else {
        return empty();
    };
    let Ok(creator_vk) = verifying_key_from_bytes(&creator_vk_bytes) else {
        return empty();
    };
    if founding.verify(&creator_vk).is_err() {
        return empty();
    }

    let Ok((event_count, after_count)) = take_u32(rest) else {
        return empty();
    };
    rest = after_count;
    if event_count > 256 {
        return empty();
    }
    let mut events = Vec::with_capacity(event_count as usize);
    for _ in 0..event_count {
        let Ok((len, after_len)) = take_u32(rest) else {
            return empty();
        };
        rest = after_len;
        let len = len as usize;
        if len == 0 || rest.len() < len {
            return empty();
        }
        let Ok((event, trailing)) = decode_membership(&rest[..len]) else {
            return empty();
        };
        if !trailing.is_empty() {
            return empty();
        }
        events.push(event);
        rest = &rest[len..];
    }

    let Ok((vk_count, after_vk_count)) = take_u32(rest) else {
        return empty();
    };
    rest = after_vk_count;
    if vk_count == 0 || vk_count > 64 || rest.len() < vk_count as usize * 32 {
        return empty();
    }
    let mut known_device_vks = Vec::with_capacity(vk_count as usize);
    for _ in 0..vk_count {
        let mut vk = [0u8; 32];
        vk.copy_from_slice(&rest[..32]);
        if verifying_key_from_bytes(&vk).is_err() {
            return empty();
        }
        known_device_vks.push(vk);
        rest = &rest[32..];
    }

    let Ok((tip_count, after_tip_count)) = take_u32(rest) else {
        return empty();
    };
    rest = after_tip_count;
    if tip_count > 64 || rest.len() < tip_count as usize * 32 {
        return empty();
    }
    let mut last_tips = Vec::with_capacity(tip_count as usize);
    for _ in 0..tip_count {
        let mut tip = [0u8; 32];
        tip.copy_from_slice(&rest[..32]);
        last_tips.push(Cid(tip));
        rest = &rest[32..];
    }
    let Ok((welcome_cid, after_welcome)) = decode_optional_cid(rest) else {
        return empty();
    };
    let Ok((commit_cid, trailing)) = decode_optional_cid(after_welcome) else {
        return empty();
    };
    if !trailing.is_empty() {
        return empty();
    }

    let mut room = RoomState::from_founding(founding);
    let mut pending = events;
    while !pending.is_empty() {
        let mut progressed = false;
        let mut next = Vec::new();
        for event in pending {
            let mut applied = false;
            for vk_bytes in &known_device_vks {
                let Ok(vk) = verifying_key_from_bytes(vk_bytes) else {
                    continue;
                };
                if room.append_membership(event.clone(), &vk).is_ok() {
                    applied = true;
                    progressed = true;
                    break;
                }
            }
            if !applied {
                next.push(event);
            }
        }
        if !progressed {
            return empty();
        }
        pending = next;
    }
    let me = secret.identity_id();
    if me != room.creator_id && !room.resolved_membership().is_active_member(&me) {
        return empty();
    }
    LocalRoomSession {
        inner: Mutex::new(Some(LocalRoomInner {
            secret,
            room,
            known_device_vks,
            last_tips,
            welcome_cid,
            commit_cid,
        })),
    }
}

fn join_room_from_invite_inner(
    secret_blob: Vec<u8>,
    invite_material_hex: String,
) -> LocalRoomSession {
    let empty = LocalRoomSession {
        inner: Mutex::new(None),
    };
    let blob = IdentitySecretBlob::from_bytes(secret_blob);
    let Ok(secret) = import_identity_secret_blob(&blob) else {
        return empty;
    };
    let Ok(bytes) = hex_decode(&invite_material_hex) else {
        return empty;
    };
    if bytes.len() < 5 || &bytes[0..4] != INVITE_MAT_MAGIC {
        return empty;
    }
    let mat_ver = bytes[4];
    if mat_ver != MAT_VERSION && mat_ver != MAT_VERSION_V2 {
        return empty;
    }
    let Ok((founding, creator_vk_bytes, rest)) = decode_founding(&bytes[5..]) else {
        return empty;
    };
    let Ok(creator_vk) = verifying_key_from_bytes(&creator_vk_bytes) else {
        return empty;
    };
    if founding.verify(&creator_vk).is_err() {
        return empty;
    }
    let Ok((invite, rest)) = decode_membership(rest) else {
        return empty;
    };
    let (inviter_slice, welcome_cid, commit_cid) = if mat_ver == MAT_VERSION_V2 {
        if rest.len() != 32 + 32 + 32 {
            return empty;
        }
        let mut welcome = [0u8; 32];
        let mut commit = [0u8; 32];
        welcome.copy_from_slice(&rest[32..64]);
        commit.copy_from_slice(&rest[64..96]);
        (
            &rest[0..32],
            if welcome == [0u8; 32] {
                None
            } else {
                Some(Cid(welcome))
            },
            if commit == [0u8; 32] {
                None
            } else {
                Some(Cid(commit))
            },
        )
    } else {
        if rest.len() != 32 {
            return empty;
        }
        (&rest[0..32], None, None)
    };
    let mut inviter_vk_bytes = [0u8; 32];
    inviter_vk_bytes.copy_from_slice(inviter_slice);
    let Ok(inviter_vk) = verifying_key_from_bytes(&inviter_vk_bytes) else {
        return empty;
    };
    if invite.target_id != secret.identity_id() {
        return empty;
    }
    let mut room = RoomState::from_founding(founding);
    if room.append_membership(invite.clone(), &inviter_vk).is_err() {
        return empty;
    }
    let parents = vec![invite.id];
    let accept = MembershipEvent::create_signed(
        room.room_id,
        secret.identity_id(),
        MembershipAction::Accept,
        secret.identity_id(),
        None,
        parents,
        &secret.device,
    );
    if room
        .append_membership(accept, &secret.device.verifying_key())
        .is_err()
    {
        return empty;
    }
    let joiner_vk = *secret.device.verifying_key().as_bytes();
    LocalRoomSession {
        inner: Mutex::new(Some(LocalRoomInner {
            secret,
            room,
            known_device_vks: vec![inviter_vk_bytes, joiner_vk],
            last_tips: Vec::new(),
            welcome_cid,
            commit_cid,
        })),
    }
}

/// One-shot founding helper (no session retain) for simple Kotlin call sites.
pub fn create_founding_room(secret_blob: Vec<u8>, created_unix_secs: u64) -> FoundedRoom {
    let session = LocalRoomSession::new(secret_blob, created_unix_secs);
    let active_member_id_hexes = session.active_member_id_hexes();
    let active_member_count = active_member_id_hexes.len() as u32;
    FoundedRoom {
        room_id_hex: session.room_id_hex(),
        creator_identity_id_hex: session.creator_identity_id_hex(),
        active_member_id_hexes,
        active_member_count,
    }
}

fn parse_identity_id(hex: &str) -> Result<IdentityId, ()> {
    let bytes = hex_decode_exact(hex, 32)?;
    Ok(IdentityId(bytes))
}

fn parse_optional_cid(hex: &str) -> Option<Cid> {
    if hex.is_empty() {
        return None;
    }
    let bytes = hex_decode_exact(hex, 32).ok()?;
    if bytes == [0u8; 32] {
        None
    } else {
        Some(Cid(bytes))
    }
}

fn encode_optional_cid(out: &mut Vec<u8>, cid: Option<Cid>) {
    match cid {
        Some(cid) => {
            out.push(1);
            out.extend_from_slice(&cid.0);
        }
        None => out.push(0),
    }
}

fn decode_optional_cid(bytes: &[u8]) -> Result<(Option<Cid>, &[u8]), ()> {
    let Some(flag) = bytes.first() else {
        return Err(());
    };
    match flag {
        0 => Ok((None, &bytes[1..])),
        1 if bytes.len() >= 33 => {
            let mut cid = [0u8; 32];
            cid.copy_from_slice(&bytes[1..33]);
            Ok((Some(Cid(cid)), &bytes[33..]))
        }
        _ => Err(()),
    }
}

fn take_u32(bytes: &[u8]) -> Result<(u32, &[u8]), ()> {
    if bytes.len() < 4 {
        return Err(());
    }
    let value = u32::from_le_bytes(bytes[..4].try_into().map_err(|_| ())?);
    Ok((value, &bytes[4..]))
}

fn encode_founding(out: &mut Vec<u8>, founding: &FoundingEvent, creator_device_vk: &[u8; 32]) {
    out.extend_from_slice(&founding.creator_id.0);
    out.extend_from_slice(&founding.created_unix_secs.to_le_bytes());
    out.extend_from_slice(&(founding.policy.max_members as u32).to_le_bytes());
    out.push(match founding.policy.history_backfill {
        HistoryBackfillPolicy::None => 0,
        _ => 0,
    });
    let sig = if founding.signature.len() == 64 {
        founding.signature.clone()
    } else {
        vec![0u8; 64]
    };
    out.extend_from_slice(&sig);
    out.extend_from_slice(creator_device_vk);
}

fn decode_founding(bytes: &[u8]) -> Result<(FoundingEvent, [u8; 32], &[u8]), ()> {
    // creator(32) + unix(8) + max(4) + hist(1) + sig(64) + vk(32) = 141
    if bytes.len() < 141 {
        return Err(());
    }
    let mut creator = [0u8; 32];
    creator.copy_from_slice(&bytes[0..32]);
    let created_unix_secs = u64::from_le_bytes(bytes[32..40].try_into().map_err(|_| ())?);
    let max_members = u32::from_le_bytes(bytes[40..44].try_into().map_err(|_| ())?) as usize;
    let hist = bytes[44];
    if hist != 0 {
        return Err(());
    }
    let signature = bytes[45..109].to_vec();
    let mut vk_bytes = [0u8; 32];
    vk_bytes.copy_from_slice(&bytes[109..141]);
    let founding = FoundingEvent {
        creator_id: IdentityId(creator),
        created_unix_secs,
        policy: RoomPolicy {
            max_members,
            history_backfill: HistoryBackfillPolicy::None,
        },
        signature,
    };
    Ok((founding, vk_bytes, &bytes[141..]))
}

fn encode_membership(out: &mut Vec<u8>, ev: &MembershipEvent) {
    out.extend_from_slice(&ev.id.0);
    out.extend_from_slice(&ev.room_id.0 .0);
    out.extend_from_slice(&ev.author_id.0);
    out.push(ev.action.as_u8());
    out.extend_from_slice(&ev.target_id.0);
    match ev.role {
        Some(r) => {
            out.push(1);
            out.push(r.as_u8());
        }
        None => {
            out.push(0);
            out.push(0);
        }
    }
    out.extend_from_slice(&(ev.parents.len() as u32).to_le_bytes());
    for p in &ev.parents {
        out.extend_from_slice(&p.0);
    }
    out.extend_from_slice(&(ev.signature.len() as u32).to_le_bytes());
    out.extend_from_slice(&ev.signature);
}

fn decode_membership(bytes: &[u8]) -> Result<(MembershipEvent, &[u8]), ()> {
    // id+room+author+action+target+role_flags = 32+32+32+1+32+2 = 131
    if bytes.len() < 131 + 4 {
        return Err(());
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes[0..32]);
    let mut room = [0u8; 32];
    room.copy_from_slice(&bytes[32..64]);
    let mut author = [0u8; 32];
    author.copy_from_slice(&bytes[64..96]);
    let action = MembershipAction::from_u8(bytes[96]).ok_or(())?;
    let mut target = [0u8; 32];
    target.copy_from_slice(&bytes[97..129]);
    let role = if bytes[129] == 1 {
        Some(MemberRole::from_u8(bytes[130]).ok_or(())?)
    } else {
        None
    };
    let mut off = 131;
    if bytes.len() < off + 4 {
        return Err(());
    }
    let parent_count = u32::from_le_bytes(bytes[off..off + 4].try_into().map_err(|_| ())?) as usize;
    off += 4;
    if parent_count > 64 || bytes.len() < off + parent_count * 32 + 4 {
        return Err(());
    }
    let mut parents = Vec::with_capacity(parent_count);
    for _ in 0..parent_count {
        let mut p = [0u8; 32];
        p.copy_from_slice(&bytes[off..off + 32]);
        parents.push(Cid(p));
        off += 32;
    }
    let sig_len = u32::from_le_bytes(bytes[off..off + 4].try_into().map_err(|_| ())?) as usize;
    off += 4;
    if sig_len > 128 || bytes.len() < off + sig_len {
        return Err(());
    }
    let signature = bytes[off..off + sig_len].to_vec();
    off += sig_len;
    let ev = MembershipEvent {
        id: Cid(id),
        room_id: RoomId(Cid(room)),
        author_id: IdentityId(author),
        action,
        target_id: IdentityId(target),
        role,
        parents,
        signature,
    };
    Ok((ev, &bytes[off..]))
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

fn hex_decode_exact(s: &str, len: usize) -> Result<[u8; 32], ()> {
    if len != 32 {
        return Err(());
    }
    let v = hex_decode(s)?;
    if v.len() != 32 {
        return Err(());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rooms_identity::export_identity_secret_blob;

    #[test]
    fn founding_room_via_session() {
        let generated = rooms_identity::create_identity_osrng();
        let blob = export_identity_secret_blob(&generated)
            .expect("export")
            .into_bytes();
        let session = LocalRoomSession::new(blob, 1_700_000_000);
        let rid = session.room_id_hex();
        assert_eq!(rid.len(), 64);
        assert_eq!(session.active_member_count(), 1);
        assert_eq!(
            session.active_member_id_hexes(),
            vec![generated.identity_id().to_hex()]
        );
        let invite = session.invite_token_hex("ab".repeat(32));
        assert!(!invite.is_empty());
        assert!(invite.starts_with("01")); // INVITE_TOKEN_VERSION_V1
        let signed = session.sign_text_event(b"opaque-ct".to_vec(), Vec::new());
        assert!(!signed.wire_envelope.is_empty());
        assert_eq!(signed.event_id_hex.len(), 64);
        let signed2 = session.sign_text_event(b"opaque-ct-2".to_vec(), Vec::new());
        let ev = rooms_proto::decode_message_event_wire_v1(&signed2.wire_envelope).unwrap();
        assert_eq!(ev.causal_parents.len(), 1);
        assert_eq!(hex_encode(&ev.causal_parents[0].0), signed.event_id_hex);
    }

    #[test]
    fn create_founding_room_helper() {
        let generated = rooms_identity::create_identity_osrng();
        let blob = export_identity_secret_blob(&generated)
            .expect("export")
            .into_bytes();
        let founded = create_founding_room(blob, 42);
        assert_eq!(founded.room_id_hex.len(), 64);
        assert_eq!(founded.active_member_count, 1);
        assert_eq!(
            founded.creator_identity_id_hex,
            generated.identity_id().to_hex()
        );
    }

    #[test]
    fn bad_blob_fail_closed() {
        let session = LocalRoomSession::new(vec![1, 2, 3], 0);
        assert!(session.room_id_hex().is_empty());
        assert!(session
            .sign_text_event(b"x".to_vec(), Vec::new())
            .wire_envelope
            .is_empty());
    }

    #[test]
    fn invite_join_accept_round_trip() {
        let founder = rooms_identity::create_identity_osrng();
        let joiner = rooms_identity::create_identity_osrng();
        let founder_blob = export_identity_secret_blob(&founder)
            .expect("export")
            .into_bytes();
        let joiner_blob = export_identity_secret_blob(&joiner)
            .expect("export")
            .into_bytes();

        let founder_session = LocalRoomSession::new(founder_blob, 1_700_000_100);
        assert_eq!(founder_session.active_member_count(), 1);

        let material = founder_session.invite_material_hex(joiner.identity_id().to_hex());
        assert!(!material.is_empty());
        assert!(material.starts_with("4452494d")); // "DRIM" hex
                                                   // Founder now has PendingInvite overlay; still 1 active.
        assert_eq!(founder_session.active_member_count(), 1);

        let joined = join_room_from_invite(joiner_blob, material);
        assert_eq!(joined.room_id_hex(), founder_session.room_id_hex());
        assert_eq!(joined.active_member_count(), 2);
        let members = joined.active_member_id_hexes();
        assert!(members.contains(&founder.identity_id().to_hex()));
        assert!(members.contains(&joiner.identity_id().to_hex()));

        let receipt = joined.accept_receipt_hex();
        assert!(!receipt.is_empty());
        assert!(founder_session.apply_accept_receipt_hex(receipt));
        assert_eq!(founder_session.active_member_count(), 2);
    }

    #[test]
    fn room_state_survives_process_restart() {
        let founder = rooms_identity::create_identity_osrng();
        let joiner = rooms_identity::create_identity_osrng();
        let founder_blob = export_identity_secret_blob(&founder)
            .expect("export")
            .into_bytes();
        let joiner_blob = export_identity_secret_blob(&joiner)
            .expect("export")
            .into_bytes();

        let founder_session = LocalRoomSession::new(founder_blob.clone(), 1_700_000_200);
        let material = founder_session.invite_material_hex(joiner.identity_id().to_hex());
        let joined = join_room_from_invite(joiner_blob.clone(), material);
        assert!(founder_session.apply_accept_receipt_hex(joined.accept_receipt_hex()));

        let founder_state = founder_session.export_state_blob();
        let joiner_state = joined.export_state_blob();
        assert!(!founder_state.is_empty());
        assert!(!joiner_state.is_empty());

        let founder_restored =
            local_room_session_from_state_blob(founder_blob, founder_state);
        let joiner_restored = local_room_session_from_state_blob(joiner_blob, joiner_state);
        assert_eq!(founder_restored.room_id_hex(), founder_session.room_id_hex());
        assert_eq!(joiner_restored.room_id_hex(), founder_session.room_id_hex());
        assert_eq!(founder_restored.active_member_count(), 2);
        assert_eq!(joiner_restored.active_member_count(), 2);
        assert!(!founder_restored
            .sign_text_event(b"after-restart".to_vec(), Vec::new())
            .wire_envelope
            .is_empty());
    }

    #[test]
    fn join_wrong_invitee_fail_closed() {
        let founder = rooms_identity::create_identity_osrng();
        let joiner = rooms_identity::create_identity_osrng();
        let other = rooms_identity::create_identity_osrng();
        let founder_blob = export_identity_secret_blob(&founder)
            .expect("export")
            .into_bytes();
        let other_blob = export_identity_secret_blob(&other)
            .expect("export")
            .into_bytes();
        let session = LocalRoomSession::new(founder_blob, 99);
        let material = session.invite_material_hex(joiner.identity_id().to_hex());
        let bad = join_room_from_invite(other_blob, material);
        assert!(bad.room_id_hex().is_empty());
    }
}
