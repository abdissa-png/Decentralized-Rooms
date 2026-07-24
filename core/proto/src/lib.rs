//! Canonical encodings for Decentralized Encrypted Rooms.
//!
//! Deterministic byte layouts used for hashing and signing (architecture §17).
//! Specs: `docs/protocol/{event-encoding,identity,invite-token,sync-frames}.md`.
//!
//! Wire rule: additive fields with a version byte; never silently change a hash domain.
//!
//! # Status
//! Phase 0 draft encoders — compile-checked and golden-tested; not a frozen RFC.

use blake3::Hash;

/// Protocol draft version string exposed to FFI / clients.
pub const PROTO_DRAFT_VERSION: &str = "0.1.0";

/// Invite token binary version (PROTO-INVITE-001).
pub const INVITE_TOKEN_VERSION_V1: u8 = 1;

/// MessageEvent encoding version (PROTO-EVENT-001).
pub const MESSAGE_EVENT_VERSION_V1: u8 = 1;

/// Sync frame version (PROTO-SYNC-001).
pub const SYNC_FRAME_VERSION_V1: u8 = 1;

/// Provisional URI scheme (brand TBD).
pub const INVITE_URI_SCHEME: &str = "derooms";

/// Content-addressed object identifier (BLAKE3 digest of canonical bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Cid(pub [u8; 32]);

impl Cid {
    /// Derive a CID from already-canonical bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Self {
        let hash = blake3_hash(bytes);
        Self(*hash.as_bytes())
    }
}

/// Hash raw bytes with BLAKE3 (content-addressing helper).
pub fn blake3_hash(bytes: &[u8]) -> Hash {
    blake3::hash(bytes)
}

/// Content type for a sealed message payload (event-encoding.md §3.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum ContentType {
    Text = 1,
    MediaRef = 2,
    Reaction = 3,
    Receipt = 4,
    System = 5,
}

impl ContentType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Text),
            2 => Some(Self::MediaRef),
            3 => Some(Self::Reaction),
            4 => Some(Self::Receipt),
            5 => Some(Self::System),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Encode / decode errors for draft codecs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecError {
    UnsupportedVersion,
    Truncated,
    InvalidLength,
    InvalidContentType,
    InvalidUtf8,
    EmptyRoomId,
    UnknownFrameKind,
}

/// Immutable message event fields (architecture §4.3).
///
/// `id` is derived: `BLAKE3(encode_message_event_hash_input(...))`.
/// `signature` is excluded from the hash domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageEvent {
    pub id: Cid,
    pub room_id: Cid,
    pub author_device_id: [u8; 32],
    pub author_identity_id: [u8; 32],
    /// Causal parents forming a DAG (not a linear previous-hash chain).
    pub causal_parents: Vec<Cid>,
    pub mls_epoch: u64,
    pub content_type: ContentType,
    /// AEAD ciphertext under the current MLS epoch (or Double Ratchet for 1:1).
    pub ciphertext: Vec<u8>,
    /// Author device signature over the signature domain (64 bytes when set).
    pub signature: Vec<u8>,
}

impl MessageEvent {
    /// Build a message event, deriving `id` from the v1 hash domain.
    #[allow(clippy::too_many_arguments)]
    pub fn from_fields_v1(
        room_id: Cid,
        author_device_id: [u8; 32],
        author_identity_id: [u8; 32],
        causal_parents: Vec<Cid>,
        mls_epoch: u64,
        content_type: ContentType,
        ciphertext: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        let id = message_event_id_v1(
            &room_id,
            &author_device_id,
            &author_identity_id,
            &causal_parents,
            mls_epoch,
            content_type,
            &ciphertext,
        );
        Self {
            id,
            room_id,
            author_device_id,
            author_identity_id,
            causal_parents,
            mls_epoch,
            content_type,
            ciphertext,
            signature,
        }
    }
}

/// Canonical hash-domain bytes for MessageEvent v1 (excludes `id` and `signature`).
///
/// Domain prefix: `rooms/MessageEvent/v1\0`
pub fn encode_message_event_hash_input(
    room_id: &Cid,
    author_device_id: &[u8; 32],
    author_identity_id: &[u8; 32],
    causal_parents: &[Cid],
    mls_epoch: u64,
    content_type: ContentType,
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut parents: Vec<[u8; 32]> = causal_parents.iter().map(|c| c.0).collect();
    parents.sort_unstable();

    let mut buf =
        Vec::with_capacity(24 + 32 * 3 + 4 + parents.len() * 32 + 8 + 1 + 4 + ciphertext.len());
    buf.extend_from_slice(b"rooms/MessageEvent/v1\0");
    buf.extend_from_slice(&room_id.0);
    buf.extend_from_slice(author_device_id);
    buf.extend_from_slice(author_identity_id);
    buf.extend_from_slice(&(parents.len() as u32).to_le_bytes());
    for p in &parents {
        buf.extend_from_slice(p);
    }
    buf.extend_from_slice(&mls_epoch.to_le_bytes());
    buf.push(content_type.as_u8());
    buf.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
    buf.extend_from_slice(ciphertext);
    buf
}

/// `id = BLAKE3(hash_domain_bytes)` for MessageEvent v1.
pub fn message_event_id_v1(
    room_id: &Cid,
    author_device_id: &[u8; 32],
    author_identity_id: &[u8; 32],
    causal_parents: &[Cid],
    mls_epoch: u64,
    content_type: ContentType,
    ciphertext: &[u8],
) -> Cid {
    Cid::from_canonical_bytes(&encode_message_event_hash_input(
        room_id,
        author_device_id,
        author_identity_id,
        causal_parents,
        mls_epoch,
        content_type,
        ciphertext,
    ))
}

/// Bytes covered by the author device signature (event-encoding.md §3.3).
pub fn encode_message_event_sign_input(id: &Cid) -> Vec<u8> {
    let mut buf = Vec::with_capacity(28 + 32);
    buf.extend_from_slice(b"rooms/MessageEvent/sig/v1\0");
    buf.extend_from_slice(&id.0);
    buf
}

/// Device entry inside an [`IdentityDocument`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceRecord {
    pub device_id: [u8; 32],
    pub signing_pubkey: [u8; 32],
    /// Cross-signature by the master identity key (64 bytes when set).
    pub cross_sig: Vec<u8>,
    pub revoked_at: Option<u64>,
}

/// Identity document (architecture §4.1) — identity ≠ device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityDocument {
    pub identity_id: [u8; 32],
    pub master_pubkey: [u8; 32],
    pub devices: Vec<DeviceRecord>,
    /// Material for out-of-band safety-number comparison.
    pub safety_number_material: Vec<u8>,
}

/// Canonical IdentityDocument bytes v1 (identity.md §3.1) — excludes `identity_id` / `doc_sig`.
pub fn encode_identity_document_v1(doc: &IdentityDocument) -> Result<Vec<u8>, CodecError> {
    let mut devices = doc.devices.clone();
    devices.sort_by_key(|a| a.device_id);

    let mut buf = Vec::new();
    buf.extend_from_slice(b"rooms/IdentityDocument/v1\0");
    buf.extend_from_slice(&doc.master_pubkey);
    buf.extend_from_slice(&(devices.len() as u32).to_le_bytes());
    for d in &devices {
        if d.cross_sig.len() != 64 {
            return Err(CodecError::InvalidLength);
        }
        buf.extend_from_slice(&d.device_id);
        buf.extend_from_slice(&d.signing_pubkey);
        buf.extend_from_slice(&d.cross_sig);
        match d.revoked_at {
            None => buf.push(0),
            Some(ts) => {
                buf.push(1);
                buf.extend_from_slice(&ts.to_le_bytes());
            }
        }
    }
    push_bytes(&mut buf, &doc.safety_number_material)?;
    Ok(buf)
}

/// Decode IdentityDocument v1; re-derives `identity_id = BLAKE3(master_pubkey)`.
pub fn decode_identity_document_v1(bytes: &[u8]) -> Result<IdentityDocument, CodecError> {
    let mut r = Reader::new(bytes);
    let prefix = b"rooms/IdentityDocument/v1\0";
    let got = r.take(prefix.len())?;
    if got != prefix {
        return Err(CodecError::UnsupportedVersion);
    }
    let master_pubkey = r.fixed32()?;
    let identity_id = *blake3_hash(&master_pubkey).as_bytes();
    let device_count = r.u32()? as usize;
    let mut devices = Vec::with_capacity(device_count);
    for _ in 0..device_count {
        let device_id = r.fixed32()?;
        let signing_pubkey = r.fixed32()?;
        let mut cross_sig = vec![0u8; 64];
        cross_sig.copy_from_slice(r.take(64)?);
        let revoked_flag = r.u8()?;
        let revoked_at = match revoked_flag {
            0 => None,
            1 => Some(r.u64()?),
            _ => return Err(CodecError::InvalidLength),
        };
        devices.push(DeviceRecord {
            device_id,
            signing_pubkey,
            cross_sig,
            revoked_at,
        });
    }
    let safety_number_material = r.bytes()?.to_vec();
    if !r.is_empty() {
        return Err(CodecError::InvalidLength);
    }
    Ok(IdentityDocument {
        identity_id,
        master_pubkey,
        devices,
        safety_number_material,
    })
}

/// Canonical bind bytes for device cross-sign (identity.md §3.2).
pub fn encode_device_cross_sign_bind(
    identity_id: &[u8; 32],
    device_id: &[u8; 32],
    signing_pubkey: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24 + 96);
    buf.extend_from_slice(b"rooms/DeviceCrossSign/v1\0");
    buf.extend_from_slice(identity_id);
    buf.extend_from_slice(device_id);
    buf.extend_from_slice(signing_pubkey);
    buf
}

/// Order-independent safety-number material sketch (identity.md §4).
pub fn encode_safety_number_material(id_a: &[u8; 32], id_b: &[u8; 32]) -> Vec<u8> {
    let (lo, hi) = if id_a <= id_b {
        (id_a, id_b)
    } else {
        (id_b, id_a)
    };
    let mut buf = Vec::with_capacity(22 + 64);
    buf.extend_from_slice(b"rooms/SafetyNumber/v1\0");
    buf.extend_from_slice(lo);
    buf.extend_from_slice(hi);
    buf
}

/// Invite token fields (invite-token.md).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InviteTokenV1 {
    pub room_id: Cid,
    pub inviter_identity_id: [u8; 32],
    pub authenticity: Vec<u8>,
    pub bootstrap_hints: Vec<String>,
}

/// Encode InviteToken binary v1.
pub fn encode_invite_token_v1(token: &InviteTokenV1) -> Result<Vec<u8>, CodecError> {
    if token.room_id.0 == [0u8; 32] {
        return Err(CodecError::EmptyRoomId);
    }
    let mut buf = Vec::new();
    buf.push(INVITE_TOKEN_VERSION_V1);
    buf.extend_from_slice(&token.room_id.0);
    buf.extend_from_slice(&token.inviter_identity_id);
    push_bytes(&mut buf, &token.authenticity)?;
    buf.extend_from_slice(&(token.bootstrap_hints.len() as u32).to_le_bytes());
    for hint in &token.bootstrap_hints {
        push_bytes(&mut buf, hint.as_bytes())?;
    }
    Ok(buf)
}

/// Decode InviteToken binary v1 (fail-closed on unknown version).
pub fn decode_invite_token_v1(bytes: &[u8]) -> Result<InviteTokenV1, CodecError> {
    let mut r = Reader::new(bytes);
    let version = r.u8()?;
    if version != INVITE_TOKEN_VERSION_V1 {
        return Err(CodecError::UnsupportedVersion);
    }
    let room_id = Cid(r.fixed32()?);
    if room_id.0 == [0u8; 32] {
        return Err(CodecError::EmptyRoomId);
    }
    let inviter_identity_id = r.fixed32()?;
    let authenticity = r.bytes()?.to_vec();
    let hints_count = r.checked_count(64, 4)?; // max 64 hints; each ≥ u32 len
    let mut bootstrap_hints = Vec::new();
    for _ in 0..hints_count {
        let raw = r.bytes()?;
        let s = std::str::from_utf8(raw).map_err(|_| CodecError::InvalidUtf8)?;
        bootstrap_hints.push(s.to_owned());
    }
    if !r.is_empty() {
        return Err(CodecError::InvalidLength);
    }
    Ok(InviteTokenV1 {
        room_id,
        inviter_identity_id,
        authenticity,
        bootstrap_hints,
    })
}

/// Sync frame kind codes (sync-frames.md §3.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SyncFrameKind {
    Offer = 1,
    Want = 2,
    Have = 3,
    Ack = 4,
}

impl SyncFrameKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Offer),
            2 => Some(Self::Want),
            3 => Some(Self::Have),
            4 => Some(Self::Ack),
            _ => None,
        }
    }
}

/// Version-vector entry (actor → counter).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionVectorEntry {
    pub actor_id: [u8; 32],
    pub counter: u64,
}

/// Sync Offer body (v1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncOfferV1 {
    pub room_id: Cid,
    pub version_vector: Vec<VersionVectorEntry>,
    pub tip_hashes: Vec<Cid>,
}

/// Encode a Sync Offer frame (header + body).
pub fn encode_sync_offer_v1(offer: &SyncOfferV1) -> Result<Vec<u8>, CodecError> {
    let mut buf = Vec::new();
    buf.push(SYNC_FRAME_VERSION_V1);
    buf.push(SyncFrameKind::Offer as u8);
    buf.extend_from_slice(&offer.room_id.0);

    let mut vv = offer.version_vector.clone();
    vv.sort_by_key(|a| a.actor_id);
    buf.extend_from_slice(&(vv.len() as u32).to_le_bytes());
    for e in &vv {
        buf.extend_from_slice(&e.actor_id);
        buf.extend_from_slice(&e.counter.to_le_bytes());
    }

    let mut tips: Vec<[u8; 32]> = offer.tip_hashes.iter().map(|c| c.0).collect();
    tips.sort_unstable();
    buf.extend_from_slice(&(tips.len() as u32).to_le_bytes());
    for t in &tips {
        buf.extend_from_slice(t);
    }
    Ok(buf)
}

/// Decode Sync Offer frame; fail-closed on bad version/kind.
pub fn decode_sync_offer_v1(bytes: &[u8]) -> Result<SyncOfferV1, CodecError> {
    let mut r = Reader::new(bytes);
    let version = r.u8()?;
    if version != SYNC_FRAME_VERSION_V1 {
        return Err(CodecError::UnsupportedVersion);
    }
    let kind = SyncFrameKind::from_u8(r.u8()?).ok_or(CodecError::UnknownFrameKind)?;
    if kind != SyncFrameKind::Offer {
        return Err(CodecError::UnknownFrameKind);
    }
    let room_id = Cid(r.fixed32()?);
    let entry_count = r.checked_count(1024, 40)?; // actor_id(32)+counter(8)
    let mut version_vector = Vec::new();
    for _ in 0..entry_count {
        version_vector.push(VersionVectorEntry {
            actor_id: r.fixed32()?,
            counter: r.u64()?,
        });
    }
    let tips_count = r.checked_count(4096, 32)?;
    let mut tip_hashes = Vec::new();
    for _ in 0..tips_count {
        tip_hashes.push(Cid(r.fixed32()?));
    }
    if !r.is_empty() {
        return Err(CodecError::InvalidLength);
    }
    Ok(SyncOfferV1 {
        room_id,
        version_vector,
        tip_hashes,
    })
}

/// Encode Want frame with an explicit CID list.
pub fn encode_sync_want_v1(room_id: &Cid, cids: &[Cid]) -> Result<Vec<u8>, CodecError> {
    let mut sorted: Vec<[u8; 32]> = cids.iter().map(|c| c.0).collect();
    sorted.sort_unstable();
    let mut buf = Vec::new();
    buf.push(SYNC_FRAME_VERSION_V1);
    buf.push(SyncFrameKind::Want as u8);
    buf.extend_from_slice(&room_id.0);
    buf.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
    for c in &sorted {
        buf.extend_from_slice(c);
    }
    Ok(buf)
}

/// Decode Want frame; fail-closed on bad version/kind.
pub fn decode_sync_want_v1(bytes: &[u8]) -> Result<(Cid, Vec<Cid>), CodecError> {
    let mut r = Reader::new(bytes);
    let version = r.u8()?;
    if version != SYNC_FRAME_VERSION_V1 {
        return Err(CodecError::UnsupportedVersion);
    }
    let kind = SyncFrameKind::from_u8(r.u8()?).ok_or(CodecError::UnknownFrameKind)?;
    if kind != SyncFrameKind::Want {
        return Err(CodecError::UnknownFrameKind);
    }
    let room_id = Cid(r.fixed32()?);
    let want_count = r.checked_count(4096, 32)?;
    let mut cids = Vec::new();
    for _ in 0..want_count {
        cids.push(Cid(r.fixed32()?));
    }
    if !r.is_empty() {
        return Err(CodecError::InvalidLength);
    }
    Ok((room_id, cids))
}

/// One object in a Sync Have frame (sync-frames.md §4.3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncHaveObject {
    pub cid: Cid,
    pub object_bytes: Vec<u8>,
}

/// Sync Have body (v1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncHaveV1 {
    pub room_id: Cid,
    pub objects: Vec<SyncHaveObject>,
}

/// Encode a Sync Have frame (header + body).
pub fn encode_sync_have_v1(have: &SyncHaveV1) -> Result<Vec<u8>, CodecError> {
    let mut buf = Vec::new();
    buf.push(SYNC_FRAME_VERSION_V1);
    buf.push(SyncFrameKind::Have as u8);
    buf.extend_from_slice(&have.room_id.0);
    buf.extend_from_slice(&(have.objects.len() as u32).to_le_bytes());
    for obj in &have.objects {
        buf.extend_from_slice(&obj.cid.0);
        push_bytes(&mut buf, &obj.object_bytes)?;
    }
    Ok(buf)
}

/// Decode Sync Have frame; fail-closed on bad version/kind.
pub fn decode_sync_have_v1(bytes: &[u8]) -> Result<SyncHaveV1, CodecError> {
    let mut r = Reader::new(bytes);
    let version = r.u8()?;
    if version != SYNC_FRAME_VERSION_V1 {
        return Err(CodecError::UnsupportedVersion);
    }
    let kind = SyncFrameKind::from_u8(r.u8()?).ok_or(CodecError::UnknownFrameKind)?;
    if kind != SyncFrameKind::Have {
        return Err(CodecError::UnknownFrameKind);
    }
    let room_id = Cid(r.fixed32()?);
    let object_count = r.checked_count(4096, 36)?; // cid(32)+len(4) min
    let mut objects = Vec::new();
    for _ in 0..object_count {
        let cid = Cid(r.fixed32()?);
        let object_bytes = r.bytes()?.to_vec();
        objects.push(SyncHaveObject { cid, object_bytes });
    }
    if !r.is_empty() {
        return Err(CodecError::InvalidLength);
    }
    Ok(SyncHaveV1 { room_id, objects })
}

/// Sync Ack body (v1) — tip CIDs the sender has applied (sync-frames.md §4.4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncAckV1 {
    pub room_id: Cid,
    pub applied_tips: Vec<Cid>,
}

/// Encode a Sync Ack frame (header + body).
pub fn encode_sync_ack_v1(ack: &SyncAckV1) -> Result<Vec<u8>, CodecError> {
    let mut tips: Vec<[u8; 32]> = ack.applied_tips.iter().map(|c| c.0).collect();
    tips.sort_unstable();
    let mut buf = Vec::new();
    buf.push(SYNC_FRAME_VERSION_V1);
    buf.push(SyncFrameKind::Ack as u8);
    buf.extend_from_slice(&ack.room_id.0);
    buf.extend_from_slice(&(tips.len() as u32).to_le_bytes());
    for t in &tips {
        buf.extend_from_slice(t);
    }
    Ok(buf)
}

/// Decode Sync Ack frame; fail-closed on bad version/kind.
pub fn decode_sync_ack_v1(bytes: &[u8]) -> Result<SyncAckV1, CodecError> {
    let mut r = Reader::new(bytes);
    let version = r.u8()?;
    if version != SYNC_FRAME_VERSION_V1 {
        return Err(CodecError::UnsupportedVersion);
    }
    let kind = SyncFrameKind::from_u8(r.u8()?).ok_or(CodecError::UnknownFrameKind)?;
    if kind != SyncFrameKind::Ack {
        return Err(CodecError::UnknownFrameKind);
    }
    let room_id = Cid(r.fixed32()?);
    let applied_count = r.checked_count(4096, 32)?;
    let mut applied_tips = Vec::new();
    for _ in 0..applied_count {
        applied_tips.push(Cid(r.fixed32()?));
    }
    if !r.is_empty() {
        return Err(CodecError::InvalidLength);
    }
    Ok(SyncAckV1 {
        room_id,
        applied_tips,
    })
}

/// Wire / storage envelope for MessageEvent (event-encoding.md §3.4).
///
/// ```text
/// version u8 = 1
/// hash_domain_bytes (rooms/MessageEvent/v1\0 || …)
/// signature 64
/// ```
pub fn encode_message_event_wire_v1(event: &MessageEvent) -> Result<Vec<u8>, CodecError> {
    if event.signature.len() != 64 {
        return Err(CodecError::InvalidLength);
    }
    let hash_domain = encode_message_event_hash_input(
        &event.room_id,
        &event.author_device_id,
        &event.author_identity_id,
        &event.causal_parents,
        event.mls_epoch,
        event.content_type,
        &event.ciphertext,
    );
    let mut buf = Vec::with_capacity(1 + hash_domain.len() + 64);
    buf.push(MESSAGE_EVENT_VERSION_V1);
    buf.extend_from_slice(&hash_domain);
    buf.extend_from_slice(&event.signature);
    Ok(buf)
}

/// Decode MessageEvent wire envelope; recomputes `id` from the hash domain.
pub fn decode_message_event_wire_v1(bytes: &[u8]) -> Result<MessageEvent, CodecError> {
    let mut r = Reader::new(bytes);
    let version = r.u8()?;
    if version != MESSAGE_EVENT_VERSION_V1 {
        return Err(CodecError::UnsupportedVersion);
    }
    let prefix = b"rooms/MessageEvent/v1\0";
    let got = r.take(prefix.len())?;
    if got != prefix {
        return Err(CodecError::UnsupportedVersion);
    }
    let room_id = Cid(r.fixed32()?);
    let author_device_id = r.fixed32()?;
    let author_identity_id = r.fixed32()?;
    let parents_len = r.u32()? as usize;
    let mut causal_parents = Vec::with_capacity(parents_len);
    for _ in 0..parents_len {
        causal_parents.push(Cid(r.fixed32()?));
    }
    let mls_epoch = r.u64()?;
    let content_type = ContentType::from_u8(r.u8()?).ok_or(CodecError::InvalidContentType)?;
    let ciphertext = r.bytes()?.to_vec();
    let mut signature = vec![0u8; 64];
    signature.copy_from_slice(r.take(64)?);
    if !r.is_empty() {
        return Err(CodecError::InvalidLength);
    }
    Ok(MessageEvent::from_fields_v1(
        room_id,
        author_device_id,
        author_identity_id,
        causal_parents,
        mls_epoch,
        content_type,
        ciphertext,
        signature,
    ))
}

/// Invite authenticity bind domain (invite-token.md §3.2).
///
/// ```text
/// rooms/InviteAuth/v1\0 || room_id || invitee_or_wildcard || expiry_u64_le
/// ```
///
/// `invitee_or_wildcard`: 32-byte invitee `IdentityId`, or all-zeros for open invites.
/// `expiry_unix_secs`: 0 means no expiry (Phase 1 sketch).
pub fn encode_invite_auth_bind_v1(
    room_id: &Cid,
    invitee_or_wildcard: &[u8; 32],
    expiry_unix_secs: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(22 + 32 + 32 + 8);
    buf.extend_from_slice(b"rooms/InviteAuth/v1\0");
    buf.extend_from_slice(&room_id.0);
    buf.extend_from_slice(invitee_or_wildcard);
    buf.extend_from_slice(&expiry_unix_secs.to_le_bytes());
    buf
}

/// All-zeros invitee = open (unnamed) invite.
pub const INVITE_WILDCARD_INVITEE: [u8; 32] = [0u8; 32];

/// Magic for typed sync objects carried in Have frames (Slice C).
pub const SYNC_OBJECT_MAGIC: &[u8; 4] = b"DRSO";

/// Object kinds for in-band MLS / control traffic (answers.md §49).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SyncObjectType {
    MessageEvent = 1,
    MlsWelcome = 2,
    MlsCommit = 3,
    KeyPackageBind = 4,
    MembershipEvent = 5,
}

impl SyncObjectType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::MessageEvent),
            2 => Some(Self::MlsWelcome),
            3 => Some(Self::MlsCommit),
            4 => Some(Self::KeyPackageBind),
            5 => Some(Self::MembershipEvent),
            _ => None,
        }
    }

    /// MLS Welcome/Commit should be Wanted before application ciphertext.
    pub fn is_control(self) -> bool {
        matches!(
            self,
            Self::MlsWelcome | Self::MlsCommit | Self::KeyPackageBind | Self::MembershipEvent
        )
    }
}

/// Encode typed sync object: `DRSO` || type || payload.
pub fn encode_sync_object_v1(obj_type: SyncObjectType, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(5 + payload.len());
    buf.extend_from_slice(SYNC_OBJECT_MAGIC);
    buf.push(obj_type as u8);
    buf.extend_from_slice(payload);
    buf
}

/// Decode typed sync object. Fail-closed on bad magic/type.
pub fn decode_sync_object_v1(bytes: &[u8]) -> Result<(SyncObjectType, &[u8]), CodecError> {
    if bytes.len() < 5 || &bytes[0..4] != SYNC_OBJECT_MAGIC {
        return Err(CodecError::UnsupportedVersion);
    }
    let obj_type = SyncObjectType::from_u8(bytes[4]).ok_or(CodecError::UnknownFrameKind)?;
    Ok((obj_type, &bytes[5..]))
}

/// Content id of a typed sync object wire (`BLAKE3(DRSO||type||payload)`).
pub fn sync_object_cid_v1(obj_type: SyncObjectType, payload: &[u8]) -> Cid {
    let wire = encode_sync_object_v1(obj_type, payload);
    Cid(*blake3_hash(&wire).as_bytes())
}

/// Canonical bind for KeyPackage authenticity (answers.md §58).
pub fn encode_key_package_bind_v1(
    identity_id: &[u8; 32],
    device_id: &[u8; 32],
    room_id: &Cid,
    key_package_tls_hash: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24 + 128);
    buf.extend_from_slice(b"rooms/KeyPackageBind/v1\0");
    buf.extend_from_slice(identity_id);
    buf.extend_from_slice(device_id);
    buf.extend_from_slice(&room_id.0);
    buf.extend_from_slice(key_package_tls_hash);
    buf
}

/// Signed KeyPackage bind blob for sync / FFI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyPackageBindV1 {
    pub identity_id: [u8; 32],
    pub device_id: [u8; 32],
    pub room_id: Cid,
    pub key_package_tls: Vec<u8>,
    pub device_signature: [u8; 64],
}

/// Encode KeyPackageBind wire (payload inside SyncObjectType::KeyPackageBind).
pub fn encode_key_package_bind_wire_v1(bind: &KeyPackageBindV1) -> Result<Vec<u8>, CodecError> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&bind.identity_id);
    buf.extend_from_slice(&bind.device_id);
    buf.extend_from_slice(&bind.room_id.0);
    push_bytes(&mut buf, &bind.key_package_tls)?;
    buf.extend_from_slice(&bind.device_signature);
    Ok(buf)
}

/// Decode KeyPackageBind wire.
pub fn decode_key_package_bind_wire_v1(bytes: &[u8]) -> Result<KeyPackageBindV1, CodecError> {
    let mut r = Reader::new(bytes);
    let identity_id = r.fixed32()?;
    let device_id = r.fixed32()?;
    let room_id = Cid(r.fixed32()?);
    let key_package_tls = r.bytes()?.to_vec();
    let mut device_signature = [0u8; 64];
    device_signature.copy_from_slice(r.take(64)?);
    if !r.is_empty() {
        return Err(CodecError::InvalidLength);
    }
    Ok(KeyPackageBindV1 {
        identity_id,
        device_id,
        room_id,
        key_package_tls,
        device_signature,
    })
}

/// Elect winning Commit CID when two concurrent Commits collide (answers.md §57).
/// Lowest CID wins (deterministic, no wall clock).
pub fn elect_commit_cid(a: &Cid, b: &Cid) -> Cid {
    if a.0 <= b.0 {
        *a
    } else {
        *b
    }
}

fn push_bytes(buf: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CodecError> {
    let len = u32::try_from(bytes.len()).map_err(|_| CodecError::InvalidLength)?;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
    Ok(())
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if self.pos + n > self.buf.len() {
            return Err(CodecError::Truncated);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, CodecError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, CodecError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn fixed32(&mut self) -> Result<[u8; 32], CodecError> {
        let b = self.take(32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(b);
        Ok(out)
    }

    fn bytes(&mut self) -> Result<&'a [u8], CodecError> {
        let len = self.u32()? as usize;
        // Cap to remaining input so corrupt lengths fail closed without OOM.
        if len > self.buf.len().saturating_sub(self.pos) {
            return Err(CodecError::Truncated);
        }
        self.take(len)
    }

    /// Read a count that cannot exceed `max` or the remaining buffer budget.
    fn checked_count(&mut self, max: usize, min_item_bytes: usize) -> Result<usize, CodecError> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(CodecError::InvalidLength);
        }
        let remaining = self.buf.len().saturating_sub(self.pos);
        if min_item_bytes > 0 && n > remaining / min_item_bytes {
            return Err(CodecError::Truncated);
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_hash_is_stable() {
        let a = blake3_hash(b"hello rooms");
        let b = blake3_hash(b"hello rooms");
        assert_eq!(a, b);
        assert_ne!(blake3_hash(b"hello rooms"), blake3_hash(b"hello roomz"));
    }

    /// Golden fixture: locks MessageEvent v1 hash-domain bytes + CID.
    #[test]
    fn message_event_v1_golden_hash_bytes() {
        let room = Cid([0x11; 32]);
        let device = [0x22; 32];
        let identity = [0x33; 32];
        let parents = vec![Cid([0x01; 32]), Cid([0x00; 32])]; // will sort
        let ciphertext = b"sealed".to_vec();

        let encoded = encode_message_event_hash_input(
            &room,
            &device,
            &identity,
            &parents,
            7,
            ContentType::Text,
            &ciphertext,
        );

        assert!(encoded.starts_with(b"rooms/MessageEvent/v1\0"));
        let prefix_len = b"rooms/MessageEvent/v1\0".len() + 32 * 3;
        let parents_len =
            u32::from_le_bytes(encoded[prefix_len..prefix_len + 4].try_into().unwrap());
        assert_eq!(parents_len, 2);
        assert_eq!(&encoded[prefix_len + 4..prefix_len + 36], &[0x00; 32]);
        assert_eq!(&encoded[prefix_len + 36..prefix_len + 68], &[0x01; 32]);

        let id = message_event_id_v1(
            &room,
            &device,
            &identity,
            &parents,
            7,
            ContentType::Text,
            &ciphertext,
        );
        assert_eq!(id.0, *blake3_hash(&encoded).as_bytes());

        // Pinned digest — changing the hash domain must fail this test.
        const GOLDEN_ID_HEX: &str =
            "e5a827508158c3fc8bd75771d7a7a2e3a7fb6930cd641cea96232b4afa265614";
        assert_eq!(hex_encode_32(&id.0), GOLDEN_ID_HEX);

        let ev = MessageEvent::from_fields_v1(
            room,
            device,
            identity,
            parents,
            7,
            ContentType::Text,
            ciphertext,
            vec![0u8; 64],
        );
        assert_eq!(ev.id, id);
        assert_eq!(hex_encode_32(&ev.id.0), GOLDEN_ID_HEX);
    }

    #[test]
    fn message_event_parents_order_does_not_change_id() {
        let room = Cid([9u8; 32]);
        let a = Cid([1u8; 32]);
        let b = Cid([2u8; 32]);
        let id1 = message_event_id_v1(
            &room,
            &[3u8; 32],
            &[4u8; 32],
            &[a, b],
            0,
            ContentType::Text,
            b"x",
        );
        let id2 = message_event_id_v1(
            &room,
            &[3u8; 32],
            &[4u8; 32],
            &[b, a],
            0,
            ContentType::Text,
            b"x",
        );
        assert_eq!(id1, id2);
    }

    #[test]
    fn invite_token_v1_round_trip_and_golden() {
        let token = InviteTokenV1 {
            room_id: Cid([0xAA; 32]),
            inviter_identity_id: [0xBB; 32],
            authenticity: b"auth".to_vec(),
            bootstrap_hints: vec!["/ip4/127.0.0.1/udp/4001/quic-v1".into()],
        };
        let bytes = encode_invite_token_v1(&token).unwrap();
        assert_eq!(bytes[0], INVITE_TOKEN_VERSION_V1);
        assert_eq!(&bytes[1..33], &[0xAA; 32]);
        let decoded = decode_invite_token_v1(&bytes).unwrap();
        assert_eq!(decoded, token);

        // Golden length-prefixed authenticity + hints layout canary
        assert_eq!(&bytes[65..69], &4u32.to_le_bytes()); // authenticity_len
        assert_eq!(&bytes[69..73], b"auth");
    }

    #[test]
    fn invite_token_unknown_version_fails_closed() {
        let mut bytes = encode_invite_token_v1(&InviteTokenV1 {
            room_id: Cid([1u8; 32]),
            inviter_identity_id: [2u8; 32],
            authenticity: vec![],
            bootstrap_hints: vec![],
        })
        .unwrap();
        bytes[0] = 99;
        assert_eq!(
            decode_invite_token_v1(&bytes),
            Err(CodecError::UnsupportedVersion)
        );
    }

    #[test]
    fn invite_empty_room_rejected() {
        let err = encode_invite_token_v1(&InviteTokenV1 {
            room_id: Cid([0u8; 32]),
            inviter_identity_id: [1u8; 32],
            authenticity: vec![],
            bootstrap_hints: vec![],
        });
        assert_eq!(err, Err(CodecError::EmptyRoomId));
    }

    #[test]
    fn sync_offer_round_trip() {
        let offer = SyncOfferV1 {
            room_id: Cid([7u8; 32]),
            version_vector: vec![
                VersionVectorEntry {
                    actor_id: [2u8; 32],
                    counter: 5,
                },
                VersionVectorEntry {
                    actor_id: [1u8; 32],
                    counter: 3,
                },
            ],
            tip_hashes: vec![Cid([9u8; 32]), Cid([8u8; 32])],
        };
        let bytes = encode_sync_offer_v1(&offer).unwrap();
        let decoded = decode_sync_offer_v1(&bytes).unwrap();
        assert_eq!(decoded.room_id, offer.room_id);
        // Sorted actors
        assert_eq!(decoded.version_vector[0].actor_id, [1u8; 32]);
        assert_eq!(decoded.version_vector[1].actor_id, [2u8; 32]);
        assert_eq!(decoded.tip_hashes[0].0, [8u8; 32]);
        assert_eq!(decoded.tip_hashes[1].0, [9u8; 32]);
    }

    #[test]
    fn sync_want_encodes_sorted_cids() {
        let room = Cid([1u8; 32]);
        let bytes = encode_sync_want_v1(&room, &[Cid([3u8; 32]), Cid([2u8; 32])]).unwrap();
        assert_eq!(bytes[0], SYNC_FRAME_VERSION_V1);
        assert_eq!(bytes[1], SyncFrameKind::Want as u8);
        assert_eq!(&bytes[2 + 32 + 4..2 + 32 + 4 + 32], &[2u8; 32]);
        let (decoded_room, cids) = decode_sync_want_v1(&bytes).unwrap();
        assert_eq!(decoded_room, room);
        assert_eq!(cids[0].0, [2u8; 32]);
        assert_eq!(cids[1].0, [3u8; 32]);
    }

    #[test]
    fn sync_have_round_trip() {
        let have = SyncHaveV1 {
            room_id: Cid([4u8; 32]),
            objects: vec![SyncHaveObject {
                cid: Cid([5u8; 32]),
                object_bytes: b"sealed-event".to_vec(),
            }],
        };
        let bytes = encode_sync_have_v1(&have).unwrap();
        assert_eq!(bytes[1], SyncFrameKind::Have as u8);
        assert_eq!(decode_sync_have_v1(&bytes).unwrap(), have);
    }

    #[test]
    fn sync_ack_round_trip_and_fail_closed() {
        let ack = SyncAckV1 {
            room_id: Cid([6u8; 32]),
            applied_tips: vec![Cid([8u8; 32]), Cid([7u8; 32])],
        };
        let bytes = encode_sync_ack_v1(&ack).unwrap();
        assert_eq!(bytes[0], SYNC_FRAME_VERSION_V1);
        assert_eq!(bytes[1], SyncFrameKind::Ack as u8);
        let decoded = decode_sync_ack_v1(&bytes).unwrap();
        assert_eq!(decoded.room_id, ack.room_id);
        // Tips are sorted ascending on encode.
        assert_eq!(decoded.applied_tips, vec![Cid([7u8; 32]), Cid([8u8; 32])]);

        let mut bad = bytes.clone();
        bad[0] = 9;
        assert_eq!(
            decode_sync_ack_v1(&bad),
            Err(CodecError::UnsupportedVersion)
        );
        bad = bytes;
        bad[1] = SyncFrameKind::Offer as u8;
        assert_eq!(decode_sync_ack_v1(&bad), Err(CodecError::UnknownFrameKind));
    }

    #[test]
    fn message_event_wire_round_trip() {
        let event = MessageEvent::from_fields_v1(
            Cid([1u8; 32]),
            [2u8; 32],
            [3u8; 32],
            vec![Cid([4u8; 32])],
            0,
            ContentType::Text,
            b"ct".to_vec(),
            vec![0xAB; 64],
        );
        let wire = encode_message_event_wire_v1(&event).unwrap();
        let decoded = decode_message_event_wire_v1(&wire).unwrap();
        assert_eq!(decoded.id, event.id);
        assert_eq!(decoded.ciphertext, event.ciphertext);
        assert_eq!(decoded.signature, event.signature);
    }

    #[test]
    fn invite_auth_bind_domain_stable() {
        let room = Cid([0x11; 32]);
        let invitee = [0x22; 32];
        let bind = encode_invite_auth_bind_v1(&room, &invitee, 0);
        assert!(bind.starts_with(b"rooms/InviteAuth/v1\0"));
        assert_eq!(&bind[20..52], &room.0);
        assert_eq!(&bind[52..84], &invitee);
        assert_eq!(&bind[84..92], &0u64.to_le_bytes());
    }

    #[test]
    fn sync_object_and_key_package_bind_round_trip() {
        let payload = b"welcome-tls";
        let wire = encode_sync_object_v1(SyncObjectType::MlsWelcome, payload);
        let (t, p) = decode_sync_object_v1(&wire).unwrap();
        assert_eq!(t, SyncObjectType::MlsWelcome);
        assert_eq!(p, payload);
        assert!(t.is_control());
        let cid = sync_object_cid_v1(SyncObjectType::MlsWelcome, payload);
        assert_eq!(cid.0, *blake3_hash(&wire).as_bytes());

        let room = Cid([0x33; 32]);
        let kp = b"key-package-tls".to_vec();
        let kp_hash = *blake3_hash(&kp).as_bytes();
        let bind_bytes = encode_key_package_bind_v1(&[1u8; 32], &[2u8; 32], &room, &kp_hash);
        assert!(bind_bytes.starts_with(b"rooms/KeyPackageBind/v1\0"));
        let bind = KeyPackageBindV1 {
            identity_id: [1u8; 32],
            device_id: [2u8; 32],
            room_id: room,
            key_package_tls: kp,
            device_signature: [0xAB; 64],
        };
        let wire = encode_key_package_bind_wire_v1(&bind).unwrap();
        assert_eq!(decode_key_package_bind_wire_v1(&wire).unwrap(), bind);
        let a = Cid([0x01; 32]);
        let b = Cid([0x02; 32]);
        assert_eq!(elect_commit_cid(&a, &b), a);
        assert_eq!(elect_commit_cid(&b, &a), a);
    }

    #[test]
    fn safety_number_order_independent() {
        let a = [1u8; 32];
        let mut b = [2u8; 32];
        b[0] = 0xFF;
        assert_eq!(
            encode_safety_number_material(&a, &b),
            encode_safety_number_material(&b, &a)
        );
    }

    #[test]
    fn identity_document_v1_round_trip() {
        let doc = IdentityDocument {
            identity_id: *blake3_hash(&[0xAA; 32]).as_bytes(),
            master_pubkey: [0xAA; 32],
            devices: vec![DeviceRecord {
                device_id: [0x01; 32],
                signing_pubkey: [0x02; 32],
                cross_sig: vec![0x03; 64],
                revoked_at: None,
            }],
            safety_number_material: b"sn".to_vec(),
        };
        let bytes = encode_identity_document_v1(&doc).unwrap();
        let decoded = decode_identity_document_v1(&bytes).unwrap();
        assert_eq!(decoded.master_pubkey, doc.master_pubkey);
        assert_eq!(decoded.identity_id, doc.identity_id);
        assert_eq!(decoded.devices, doc.devices);
        assert_eq!(decoded.safety_number_material, doc.safety_number_material);
    }

    fn hex_encode_32(bytes: &[u8; 32]) -> String {
        let mut s = String::with_capacity(64);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}
