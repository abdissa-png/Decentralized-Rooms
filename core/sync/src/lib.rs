//! Sync protocol helpers for Decentralized Encrypted Rooms.
//!
//! Owns version vectors, want/have negotiation, and MessageEvent DAG verify
//! (sign / CID). Does **not** own crypto seal/open of ciphertext
//! (architecture §11.2). Spec: `docs/protocol/sync-frames.md`,
//! `docs/protocol/event-encoding.md`.
//!
//! # Status
//! Phase 1: VV helpers + Offer/Want/Have/Ack encode + MessageEvent create/sign/verify
//! + in-process two-node sync + outbox stub + libp2p stream sync via `rooms-transport`.
//!
//! Phase 2 start: per-room VV merge, room-scoped CID/Merkle diff helpers,
//! [`BandwidthClass`] policy stubs (QUIC vs BLE text-first), BLE mesh frames,
//! Wi‑Fi Direct bulk sealed frames (High bandwidth).

mod mesh;
mod wifi_direct;

pub use mesh::{
    rotate_ephemeral_id, BleAppHeader, BleAppObjectType, BleMeshError, BleSealedFrame,
    SealedCarrierStore, BLE_APP_HEADER_LEN, BLE_FRAME_MAGIC, BLE_FRAME_VERSION,
    BLE_FRAME_VERSION_V2, BLE_MAX_SEALED_PAYLOAD, EPHEMERAL_ID_LEN,
};
pub use wifi_direct::{
    policy_allows_wifi_direct_bulk, simulate_bulk_transfer, WifiDirectError, WifiDirectSealedFrame,
    WD_FRAME_MAGIC, WD_FRAME_VERSION, WD_MAX_SEALED_PAYLOAD, WD_TIP_MAX_LEN,
};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rooms_proto::{
    decode_message_event_wire_v1, decode_sync_ack_v1, decode_sync_have_v1, decode_sync_object_v1,
    decode_sync_offer_v1, decode_sync_want_v1, encode_message_event_sign_input,
    encode_message_event_wire_v1, encode_sync_ack_v1, encode_sync_have_v1, encode_sync_object_v1,
    encode_sync_offer_v1, encode_sync_want_v1, sync_object_cid_v1, Cid, ContentType, MessageEvent,
    SyncAckV1, SyncFrameKind, SyncHaveObject, SyncHaveV1, SyncObjectType, SyncOfferV1,
    VersionVectorEntry, SYNC_FRAME_VERSION_V1,
};
use rooms_storage::{KvStore, Namespace, StorageError};
use std::collections::{BTreeMap, BTreeSet};

/// Placeholder version-vector entry for a room replica.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VersionVector {
    /// actor_id (device) → counter. Kept sorted by actor_id for canonical encode.
    pub counters: Vec<([u8; 32], u64)>,
}

impl VersionVector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, actor_id: &[u8; 32]) -> u64 {
        self.counters
            .iter()
            .find(|(a, _)| a == actor_id)
            .map(|(_, c)| *c)
            .unwrap_or(0)
    }

    /// Increment actor counter by 1; returns new value.
    pub fn increment(&mut self, actor_id: [u8; 32]) -> u64 {
        if let Some((_, c)) = self.counters.iter_mut().find(|(a, _)| *a == actor_id) {
            *c = c.saturating_add(1);
            return *c;
        }
        self.counters.push((actor_id, 1));
        self.counters.sort_by_key(|a| a.0);
        1
    }

    /// Set counter to at least `value` for actor.
    pub fn observe(&mut self, actor_id: [u8; 32], value: u64) {
        if let Some((_, c)) = self.counters.iter_mut().find(|(a, _)| *a == actor_id) {
            *c = (*c).max(value);
            return;
        }
        self.counters.push((actor_id, value));
        self.counters.sort_by_key(|a| a.0);
    }

    /// Pointwise max merge (commutative, idempotent).
    pub fn merge(&mut self, other: &Self) {
        for (actor, count) in &other.counters {
            self.observe(*actor, *count);
        }
    }

    /// True if every actor in `other` is ≤ self (self dominates other).
    pub fn dominates(&self, other: &Self) -> bool {
        for (actor, count) in &other.counters {
            if self.get(actor) < *count {
                return false;
            }
        }
        true
    }

    /// Concurrent when neither dominates the other (and not equal).
    pub fn is_concurrent(&self, other: &Self) -> bool {
        self != other && !self.dominates(other) && !other.dominates(self)
    }

    pub fn to_entries(&self) -> Vec<VersionVectorEntry> {
        self.counters
            .iter()
            .map(|(actor_id, counter)| VersionVectorEntry {
                actor_id: *actor_id,
                counter: *counter,
            })
            .collect()
    }

    pub fn from_entries(entries: &[VersionVectorEntry]) -> Self {
        let mut vv = Self::new();
        for e in entries {
            vv.observe(e.actor_id, e.counter);
        }
        vv
    }
}

/// Transport bandwidth class for sync policy (FR-SYNC-005). BLE path stubbed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BandwidthClass {
    /// QUIC / Wi‑Fi Direct — full Merkle sync, media allowed.
    High,
    /// BLE — headers + small text first; media deferred.
    Low,
    /// LoRa / DTN later — control + tiny text only.
    UltraLow,
}

/// Policy knobs selected by [`BandwidthClass`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncPolicy {
    pub include_media: bool,
    pub text_first: bool,
    pub max_have_objects: usize,
}

impl SyncPolicy {
    pub fn for_class(class: BandwidthClass) -> Self {
        match class {
            BandwidthClass::High => Self {
                include_media: true,
                text_first: false,
                max_have_objects: 1024,
            },
            BandwidthClass::Low => Self {
                include_media: false,
                text_first: true,
                max_have_objects: 32,
            },
            BandwidthClass::UltraLow => Self {
                include_media: false,
                text_first: true,
                max_have_objects: 4,
            },
        }
    }
}

/// Per-room CID set for Merkle/CID diff (extends 1:1 `missing_cids`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoomCidIndex {
    pub room_id: Cid,
    pub cids: BTreeSet<Cid>,
}

impl RoomCidIndex {
    pub fn new(room_id: Cid) -> Self {
        Self {
            room_id,
            cids: BTreeSet::new(),
        }
    }

    pub fn insert(&mut self, cid: Cid) {
        self.cids.insert(cid);
    }

    pub fn contains(&self, cid: &Cid) -> bool {
        self.cids.contains(cid)
    }

    /// CIDs present in `theirs` but missing locally.
    pub fn missing_from(&self, theirs: &[Cid]) -> Vec<Cid> {
        theirs
            .iter()
            .filter(|c| !self.cids.contains(c))
            .copied()
            .collect()
    }

    /// Symmetric difference size (for diagnostics).
    pub fn diff_count(&self, other: &Self) -> usize {
        self.cids.symmetric_difference(&other.cids).count()
    }
}

/// Filter Have objects by bandwidth policy (media deferred on Low/UltraLow).
pub fn filter_have_objects_for_policy(
    objects: &[(Cid, Vec<u8>)],
    events: &[(Cid, ContentType)],
    policy: SyncPolicy,
) -> Vec<(Cid, Vec<u8>)> {
    let type_by_cid: BTreeMap<Cid, ContentType> = events.iter().copied().collect();
    objects
        .iter()
        .filter(|(cid, _)| {
            if policy.include_media {
                return true;
            }
            !matches!(type_by_cid.get(cid), Some(ContentType::MediaRef))
        })
        .take(policy.max_have_objects)
        .cloned()
        .collect()
}

/// Sync frame kinds (PROTO-SYNC-001).
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SyncFrame {
    Offer {
        room_id: Cid,
        vv: VersionVector,
        tip_hashes: Vec<Cid>,
    },
    Want {
        room_id: Cid,
        cids: Vec<Cid>,
    },
    Have {
        room_id: Cid,
        objects: Vec<(Cid, Vec<u8>)>,
    },
    Ack {
        room_id: Cid,
        cids: Vec<Cid>,
    },
}

impl SyncFrame {
    /// Encode Offer / Want / Have / Ack frames.
    pub fn encode_v1(&self) -> Result<Vec<u8>, rooms_proto::CodecError> {
        match self {
            SyncFrame::Offer {
                room_id,
                vv,
                tip_hashes,
            } => encode_sync_offer_v1(&SyncOfferV1 {
                room_id: *room_id,
                version_vector: vv.to_entries(),
                tip_hashes: tip_hashes.clone(),
            }),
            SyncFrame::Want { room_id, cids } => encode_sync_want_v1(room_id, cids),
            SyncFrame::Have { room_id, objects } => encode_sync_have_v1(&SyncHaveV1 {
                room_id: *room_id,
                objects: objects
                    .iter()
                    .map(|(cid, object_bytes)| SyncHaveObject {
                        cid: *cid,
                        object_bytes: object_bytes.clone(),
                    })
                    .collect(),
            }),
            SyncFrame::Ack { room_id, cids } => encode_sync_ack_v1(&SyncAckV1 {
                room_id: *room_id,
                applied_tips: cids.clone(),
            }),
        }
    }

    /// Decode a v1 sync frame by peeking the kind byte (fail-closed).
    pub fn decode_v1(bytes: &[u8]) -> Result<Self, rooms_proto::CodecError> {
        if bytes.len() < 2 {
            return Err(rooms_proto::CodecError::Truncated);
        }
        if bytes[0] != SYNC_FRAME_VERSION_V1 {
            return Err(rooms_proto::CodecError::UnsupportedVersion);
        }
        let kind =
            SyncFrameKind::from_u8(bytes[1]).ok_or(rooms_proto::CodecError::UnknownFrameKind)?;
        match kind {
            SyncFrameKind::Offer => {
                let o = decode_sync_offer_v1(bytes)?;
                Ok(SyncFrame::Offer {
                    room_id: o.room_id,
                    vv: VersionVector {
                        counters: o
                            .version_vector
                            .into_iter()
                            .map(|e| (e.actor_id, e.counter))
                            .collect(),
                    },
                    tip_hashes: o.tip_hashes,
                })
            }
            SyncFrameKind::Want => {
                let (room_id, cids) = decode_sync_want_v1(bytes)?;
                Ok(SyncFrame::Want { room_id, cids })
            }
            SyncFrameKind::Have => {
                let h = decode_sync_have_v1(bytes)?;
                Ok(SyncFrame::Have {
                    room_id: h.room_id,
                    objects: h
                        .objects
                        .into_iter()
                        .map(|o| (o.cid, o.object_bytes))
                        .collect(),
                })
            }
            SyncFrameKind::Ack => {
                let a = decode_sync_ack_v1(bytes)?;
                Ok(SyncFrame::Ack {
                    room_id: a.room_id,
                    cids: a.applied_tips,
                })
            }
        }
    }
}

/// Compute CIDs present in `theirs` but missing from `ours` (set-diff).
pub fn missing_cids(ours: &[Cid], theirs: &[Cid]) -> Vec<Cid> {
    theirs
        .iter()
        .filter(|c| !ours.iter().any(|o| o == *c))
        .copied()
        .collect()
}

/// Errors verifying MessageEvent signatures / ids.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventVerifyError {
    BadSignature,
    BadSignatureLength,
    IdMismatch,
    BadKey,
}

/// Build a MessageEvent and sign with the author's device key.
#[allow(clippy::too_many_arguments)]
pub fn create_signed_message_event(
    room_id: Cid,
    author_device_id: [u8; 32],
    author_identity_id: [u8; 32],
    causal_parents: Vec<Cid>,
    mls_epoch: u64,
    content_type: ContentType,
    ciphertext: Vec<u8>,
    device_signing_key: &SigningKey,
) -> MessageEvent {
    let mut event = MessageEvent::from_fields_v1(
        room_id,
        author_device_id,
        author_identity_id,
        causal_parents,
        mls_epoch,
        content_type,
        ciphertext,
        Vec::new(),
    );
    let sign_input = encode_message_event_sign_input(&event.id);
    event.signature = device_signing_key.sign(&sign_input).to_bytes().to_vec();
    event
}

/// Verify device signature and that `id` matches the hash domain.
pub fn verify_message_event(
    event: &MessageEvent,
    device_verifying_key: &VerifyingKey,
) -> Result<(), EventVerifyError> {
    let expected_id = rooms_proto::message_event_id_v1(
        &event.room_id,
        &event.author_device_id,
        &event.author_identity_id,
        &event.causal_parents,
        event.mls_epoch,
        event.content_type,
        &event.ciphertext,
    );
    if expected_id != event.id {
        return Err(EventVerifyError::IdMismatch);
    }
    if event.signature.len() != 64 {
        return Err(EventVerifyError::BadSignatureLength);
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&event.signature);
    let sig = Signature::from_bytes(&sig_bytes);
    let sign_input = encode_message_event_sign_input(&event.id);
    device_verifying_key
        .verify(&sign_input, &sig)
        .map_err(|_| EventVerifyError::BadSignature)?;
    Ok(())
}

/// Persist / load MessageEvent wire envelopes under [`Namespace::Events`].
pub struct EventStore<'a> {
    store: &'a mut dyn KvStore,
}

impl<'a> EventStore<'a> {
    pub fn new(store: &'a mut dyn KvStore) -> Self {
        Self { store }
    }

    /// Store a verified event (caller must verify first). Key = event id.
    pub fn put_event(&mut self, event: &MessageEvent) -> Result<(), SyncError> {
        let wire = encode_message_event_wire_v1(event).map_err(SyncError::Codec)?;
        self.store
            .put(Namespace::Events, &event.id.0, &wire)
            .map_err(SyncError::Storage)?;
        Ok(())
    }

    pub fn get_event(&self, id: &Cid) -> Result<Option<MessageEvent>, SyncError> {
        match self
            .store
            .get(Namespace::Events, &id.0)
            .map_err(SyncError::Storage)?
        {
            None => Ok(None),
            Some(wire) => {
                let event = decode_message_event_wire_v1(&wire).map_err(SyncError::Codec)?;
                Ok(Some(event))
            }
        }
    }

    pub fn has_event(&self, id: &Cid) -> Result<bool, SyncError> {
        Ok(self
            .store
            .get(Namespace::Events, &id.0)
            .map_err(SyncError::Storage)?
            .is_some())
    }

    /// Load raw wire bytes for a CID if present.
    pub fn load_wire(&self, id: &Cid) -> Result<Option<Vec<u8>>, SyncError> {
        self.store
            .get(Namespace::Events, &id.0)
            .map_err(SyncError::Storage)
    }
}

/// Crash-safe outbound queue: persist wire envelopes until peer Ack (FR-DM-003).
///
/// Keys under [`Namespace::Outbox`] are event CIDs. Removal happens when an Ack
/// lists the CID (or after local apply confirmation on the provider side).
pub struct Outbox<'a> {
    store: &'a mut dyn KvStore,
}

impl<'a> Outbox<'a> {
    pub fn new(store: &'a mut dyn KvStore) -> Self {
        Self { store }
    }

    /// Enqueue a signed event wire blob pending sync Ack.
    pub fn enqueue(&mut self, event: &MessageEvent) -> Result<(), SyncError> {
        let wire = encode_message_event_wire_v1(event).map_err(SyncError::Codec)?;
        self.store
            .put(Namespace::Outbox, &event.id.0, &wire)
            .map_err(SyncError::Storage)?;
        Ok(())
    }

    pub fn get(&self, id: &Cid) -> Result<Option<Vec<u8>>, SyncError> {
        self.store
            .get(Namespace::Outbox, &id.0)
            .map_err(SyncError::Storage)
    }

    pub fn contains(&self, id: &Cid) -> Result<bool, SyncError> {
        Ok(self.get(id)?.is_some())
    }

    /// Remove outbound entries acknowledged by the peer.
    pub fn apply_ack(&mut self, ack: &SyncAckV1) -> Result<usize, SyncError> {
        let mut removed = 0usize;
        for cid in &ack.applied_tips {
            if self
                .store
                .get(Namespace::Outbox, &cid.0)
                .map_err(SyncError::Storage)?
                .is_some()
            {
                self.store
                    .delete(Namespace::Outbox, &cid.0)
                    .map_err(SyncError::Storage)?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

/// Sync / event-store errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncError {
    Storage(StorageError),
    Codec(rooms_proto::CodecError),
    Verify(EventVerifyError),
    RoomMismatch,
    UnexpectedFrame,
}

/// Local replica view used by the Offer/Want/Have engine.
#[derive(Debug)]
pub struct SyncReplica {
    pub room_id: Cid,
    /// Tip / known event CIDs for this room.
    pub tips: Vec<Cid>,
    pub vv: VersionVector,
    /// Full known CID set for room-scoped Merkle diff (Phase 2).
    pub cid_index: RoomCidIndex,
    /// Control-plane CIDs (MLS Welcome/Commit, KP bind, membership) for Want priority.
    pub control_cids: BTreeSet<Cid>,
}

impl SyncReplica {
    pub fn new(room_id: Cid) -> Self {
        Self {
            room_id,
            tips: Vec::new(),
            vv: VersionVector::default(),
            cid_index: RoomCidIndex::new(room_id),
            control_cids: BTreeSet::new(),
        }
    }

    /// Record a locally authored or applied event in VV + tip + CID index.
    pub fn note_event(&mut self, author_device_id: [u8; 32], event_id: Cid) {
        self.vv.increment(author_device_id);
        if !self.tips.contains(&event_id) {
            self.tips.push(event_id);
        }
        self.cid_index.insert(event_id);
    }

    /// Record a typed sync object (MLS Welcome/Commit/etc.) locally for Offer.
    pub fn note_typed_object(&mut self, cid: Cid, obj_type: SyncObjectType) {
        if !self.tips.contains(&cid) {
            self.tips.push(cid);
        }
        self.cid_index.insert(cid);
        if obj_type.is_control() {
            self.control_cids.insert(cid);
        }
    }

    pub fn build_offer(&self) -> SyncFrame {
        SyncFrame::Offer {
            room_id: self.room_id,
            vv: self.vv.clone(),
            tip_hashes: self.offer_tips_control_first(),
        }
    }

    pub fn build_want(&self, offered_tips: &[Cid]) -> SyncFrame {
        // Prefer full index when populated; fall back to tip set (Gate 1 path).
        let mut missing = if self.cid_index.cids.is_empty() {
            missing_cids(&self.tips, offered_tips)
        } else {
            self.cid_index.missing_from(offered_tips)
        };
        // Control-before-app (§47): Want known control CIDs before MessageEvents.
        missing.sort_by(|a, b| {
            let ac = self.control_cids.contains(a);
            let bc = self.control_cids.contains(b);
            match (ac, bc) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.0.cmp(&b.0),
            }
        });
        SyncFrame::Want {
            room_id: self.room_id,
            cids: missing,
        }
    }

    /// Offer tips with control CIDs listed first (provider side).
    pub fn offer_tips_control_first(&self) -> Vec<Cid> {
        let mut tips = self.tips.clone();
        tips.sort_by(|a, b| {
            let ac = self.control_cids.contains(a);
            let bc = self.control_cids.contains(b);
            match (ac, bc) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.0.cmp(&b.0),
            }
        });
        tips
    }

    pub fn build_ack(&self, applied: &[Cid]) -> SyncFrame {
        SyncFrame::Ack {
            room_id: self.room_id,
            cids: applied.to_vec(),
        }
    }
}

/// Persist a typed sync object under Events keyed by its CID.
pub fn put_typed_sync_object(
    store: &mut dyn KvStore,
    obj_type: SyncObjectType,
    payload: &[u8],
) -> Result<(Cid, Vec<u8>), SyncError> {
    let wire = encode_sync_object_v1(obj_type, payload);
    let cid = sync_object_cid_v1(obj_type, payload);
    store
        .put(Namespace::Events, &cid.0, &wire)
        .map_err(SyncError::Storage)?;
    Ok((cid, wire))
}

/// Build a Have frame for requested CIDs from the local event store.
pub fn build_have_frame(
    store: &dyn KvStore,
    room_id: Cid,
    want_cids: &[Cid],
) -> Result<SyncFrame, SyncError> {
    let mut objects = Vec::new();
    for cid in want_cids {
        if let Some(wire) = store
            .get(Namespace::Events, &cid.0)
            .map_err(SyncError::Storage)?
        {
            objects.push((*cid, wire));
        }
    }
    Ok(SyncFrame::Have { room_id, objects })
}

/// Apply a Have frame: decode each object, verify signature, persist.
///
/// Supports legacy MessageEvent wires and typed `DRSO` objects (MLS Welcome/Commit,
/// KeyPackage bind, membership). Corrupt / unverifiable objects are **skipped**
/// (ADV-CORRUPT). Returns the CIDs successfully applied.
pub fn apply_have_frame(
    store: &mut dyn KvStore,
    replica: &mut SyncReplica,
    have: &SyncHaveV1,
    device_verifying_key: &VerifyingKey,
) -> Result<Vec<Cid>, SyncError> {
    if have.room_id != replica.room_id {
        return Err(SyncError::RoomMismatch);
    }
    let mut applied = Vec::new();
    for obj in &have.objects {
        // Slice C: typed sync objects (MLS Welcome/Commit, KP bind, membership).
        if let Ok((obj_type, payload)) = decode_sync_object_v1(&obj.object_bytes) {
            let expect = sync_object_cid_v1(obj_type, payload);
            if expect != obj.cid {
                continue;
            }
            store
                .put(Namespace::Events, &obj.cid.0, &obj.object_bytes)
                .map_err(SyncError::Storage)?;
            replica.note_typed_object(obj.cid, obj_type);
            applied.push(obj.cid);
            continue;
        }
        let Ok(event) = decode_message_event_wire_v1(&obj.object_bytes) else {
            continue;
        };
        if event.id != obj.cid {
            continue;
        }
        if event.room_id != replica.room_id {
            continue;
        }
        if verify_message_event(&event, device_verifying_key).is_err() {
            continue;
        }
        store
            .put(Namespace::Events, &event.id.0, &obj.object_bytes)
            .map_err(SyncError::Storage)?;
        if !replica.tips.contains(&event.id) {
            replica.tips.push(event.id);
        }
        replica.cid_index.insert(event.id);
        applied.push(event.id);
    }
    Ok(applied)
}

/// Consumer-side: given an Offer payload, return encoded Want.
pub fn want_bytes_from_offer(
    consumer: &SyncReplica,
    offer_bytes: &[u8],
) -> Result<Vec<u8>, SyncError> {
    let offer = decode_sync_offer_v1(offer_bytes).map_err(SyncError::Codec)?;
    if offer.room_id != consumer.room_id {
        return Err(SyncError::RoomMismatch);
    }
    consumer
        .build_want(&offer.tip_hashes)
        .encode_v1()
        .map_err(SyncError::Codec)
}

/// Provider-side: given Want payload, return encoded Have from local store.
pub fn have_bytes_from_want(store: &dyn KvStore, want_bytes: &[u8]) -> Result<Vec<u8>, SyncError> {
    let (room_id, cids) = decode_sync_want_v1(want_bytes).map_err(SyncError::Codec)?;
    build_have_frame(store, room_id, &cids)?
        .encode_v1()
        .map_err(SyncError::Codec)
}

/// Consumer-side: apply Have bytes, return encoded Ack of applied tips.
pub fn ack_bytes_from_have(
    store: &mut dyn KvStore,
    replica: &mut SyncReplica,
    have_bytes: &[u8],
    device_verifying_key: &VerifyingKey,
) -> Result<(usize, Vec<u8>), SyncError> {
    let have = decode_sync_have_v1(have_bytes).map_err(SyncError::Codec)?;
    let applied_ids = apply_have_frame(store, replica, &have, device_verifying_key)?;
    let applied = applied_ids.len();
    let ack = replica
        .build_ack(&applied_ids)
        .encode_v1()
        .map_err(SyncError::Codec)?;
    Ok((applied, ack))
}

/// Run one Offer → Want → Have round between two in-process replicas.
///
/// Deterministic CI path: no network. `provider` holds events; `consumer` receives.
pub fn sync_round_in_process(
    provider_store: &dyn KvStore,
    consumer_store: &mut dyn KvStore,
    provider: &SyncReplica,
    consumer: &mut SyncReplica,
    author_device_vk: &VerifyingKey,
) -> Result<usize, SyncError> {
    let offer = provider.build_offer();
    let SyncFrame::Offer { tip_hashes, .. } = offer else {
        unreachable!("build_offer always returns Offer");
    };
    let want = consumer.build_want(&tip_hashes);
    let SyncFrame::Want { cids, room_id } = want else {
        unreachable!("build_want always returns Want");
    };
    if cids.is_empty() {
        return Ok(0);
    }
    let have_frame = build_have_frame(provider_store, room_id, &cids)?;
    let SyncFrame::Have { objects, .. } = have_frame else {
        unreachable!("build_have_frame always returns Have");
    };
    let have = SyncHaveV1 {
        room_id,
        objects: objects
            .into_iter()
            .map(|(cid, object_bytes)| SyncHaveObject { cid, object_bytes })
            .collect(),
    };
    Ok(apply_have_frame(consumer_store, consumer, &have, author_device_vk)?.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use rooms_storage::MemoryKvStore;

    #[test]
    fn missing_cids_filters_held() {
        let a = Cid([1u8; 32]);
        let b = Cid([2u8; 32]);
        let c = Cid([3u8; 32]);
        let missing = missing_cids(&[a, b], &[a, b, c]);
        assert_eq!(missing, vec![c]);
    }

    #[test]
    fn version_vector_merge_dominates_concurrent() {
        let actor_a = [0xAAu8; 32];
        let actor_b = [0xBBu8; 32];
        let mut left = VersionVector::new();
        left.increment(actor_a);
        left.increment(actor_a);
        let mut right = VersionVector::new();
        right.increment(actor_b);

        assert!(left.is_concurrent(&right));
        let mut merged = left.clone();
        merged.merge(&right);
        assert!(merged.dominates(&left));
        assert!(merged.dominates(&right));
        assert_eq!(merged.get(&actor_a), 2);
        assert_eq!(merged.get(&actor_b), 1);

        let mut again = merged.clone();
        again.merge(&merged);
        assert_eq!(again, merged);
    }

    #[test]
    fn room_cid_index_missing_and_policy_filter() {
        let room = Cid([0x11; 32]);
        let mut index = RoomCidIndex::new(room);
        let a = Cid([1u8; 32]);
        let b = Cid([2u8; 32]);
        let c = Cid([3u8; 32]);
        index.insert(a);
        assert_eq!(index.missing_from(&[a, b, c]), vec![b, c]);

        let high = SyncPolicy::for_class(BandwidthClass::High);
        let low = SyncPolicy::for_class(BandwidthClass::Low);
        assert!(high.include_media);
        assert!(low.text_first);
        assert!(!low.include_media);

        let objects = vec![(a, b"text".to_vec()), (b, b"media".to_vec())];
        let types = vec![(a, ContentType::Text), (b, ContentType::MediaRef)];
        let filtered = filter_have_objects_for_policy(&objects, &types, low);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].0, a);
    }

    #[test]
    fn adv_part_room_tip_merge_via_cid_index() {
        // ADV-PART style: two partitions author different tips; heal via CID union.
        let room = Cid([0x42; 32]);
        let tip_l = Cid([0x10; 32]);
        let tip_r = Cid([0x20; 32]);

        let mut left = SyncReplica::new(room);
        left.note_event([1u8; 32], tip_l);
        let mut right = SyncReplica::new(room);
        right.note_event([2u8; 32], tip_r);

        assert!(left.vv.is_concurrent(&right.vv));

        let mut vv = left.vv.clone();
        vv.merge(&right.vv);
        let mut index = left.cid_index.clone();
        for c in &right.cid_index.cids {
            index.insert(*c);
        }
        assert!(index.contains(&tip_l));
        assert!(index.contains(&tip_r));
        assert_eq!(index.diff_count(&left.cid_index), 1);
        assert!(vv.dominates(&left.vv) && vv.dominates(&right.vv));
    }

    #[test]
    fn offer_encodes() {
        let frame = SyncFrame::Offer {
            room_id: Cid([1u8; 32]),
            vv: VersionVector {
                counters: vec![([2u8; 32], 9)],
            },
            tip_hashes: vec![Cid([3u8; 32])],
        };
        let bytes = frame.encode_v1().unwrap();
        assert_eq!(bytes[0], rooms_proto::SYNC_FRAME_VERSION_V1);
        assert_eq!(bytes[1], rooms_proto::SyncFrameKind::Offer as u8);
        let decoded = SyncFrame::decode_v1(&bytes).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn have_and_ack_encode_roundtrip() {
        let have = SyncFrame::Have {
            room_id: Cid([1u8; 32]),
            objects: vec![(Cid([2u8; 32]), b"blob".to_vec())],
        };
        let bytes = have.encode_v1().unwrap();
        let decoded = decode_sync_have_v1(&bytes).unwrap();
        assert_eq!(decoded.objects[0].object_bytes, b"blob");

        let ack = SyncFrame::Ack {
            room_id: Cid([1u8; 32]),
            cids: vec![Cid([2u8; 32])],
        };
        let ack_bytes = ack.encode_v1().unwrap();
        assert_eq!(SyncFrame::decode_v1(&ack_bytes).unwrap(), ack);
    }

    #[test]
    fn signed_message_event_verifies_and_rejects_tamper() {
        let mut rng = StdRng::seed_from_u64(123);
        let sk = SigningKey::generate(&mut rng);
        let vk = sk.verifying_key();

        let room = Cid([0x11; 32]);
        let device = [0x22; 32];
        let identity = [0x33; 32];
        let parents = vec![Cid([0x01; 32]), Cid([0x00; 32])];
        let ciphertext = b"sealed".to_vec();

        let event = create_signed_message_event(
            room,
            device,
            identity,
            parents.clone(),
            7,
            ContentType::Text,
            ciphertext.clone(),
            &sk,
        );

        // Continuity with rooms-proto golden hash domain.
        const GOLDEN_ID_HEX: &str =
            "e5a827508158c3fc8bd75771d7a7a2e3a7fb6930cd641cea96232b4afa265614";
        assert_eq!(hex_encode_32(&event.id.0), GOLDEN_ID_HEX);
        verify_message_event(&event, &vk).expect("valid sig");

        let mut bad_sig = event.clone();
        bad_sig.signature[0] ^= 0xff;
        assert_eq!(
            verify_message_event(&bad_sig, &vk),
            Err(EventVerifyError::BadSignature)
        );

        let mut bad_ct = event.clone();
        bad_ct.ciphertext[0] ^= 0xff;
        // id field stale vs ciphertext → IdMismatch
        assert_eq!(
            verify_message_event(&bad_ct, &vk),
            Err(EventVerifyError::IdMismatch)
        );
    }

    #[test]
    fn two_node_sync_offer_want_have() {
        let mut rng = StdRng::seed_from_u64(20260805);
        let sk = SigningKey::generate(&mut rng);
        let vk = sk.verifying_key();

        let room = Cid([0xAA; 32]);
        let device_id = [0xBB; 32];
        let identity_id = [0xCC; 32];

        let event = create_signed_message_event(
            room,
            device_id,
            identity_id,
            vec![],
            0,
            ContentType::Text,
            b"opaque-signal-ct".to_vec(),
            &sk,
        );
        verify_message_event(&event, &vk).unwrap();

        let mut store_a = MemoryKvStore::new();
        let mut store_b = MemoryKvStore::new();

        {
            let mut events_a = EventStore::new(&mut store_a);
            events_a.put_event(&event).unwrap();
        }
        {
            let mut outbox = Outbox::new(&mut store_a);
            outbox.enqueue(&event).unwrap();
            assert!(outbox.contains(&event.id).unwrap());
        }

        let mut replica_a = SyncReplica::new(room);
        replica_a.tips.push(event.id);
        replica_a.vv.counters.push((device_id, 1));

        let mut replica_b = SyncReplica::new(room);

        let applied =
            sync_round_in_process(&store_a, &mut store_b, &replica_a, &mut replica_b, &vk)
                .expect("sync");
        assert_eq!(applied, 1);
        assert!(replica_b.tips.contains(&event.id));

        let loaded = EventStore::new(&mut store_b)
            .get_event(&event.id)
            .unwrap()
            .expect("stored on B");
        verify_message_event(&loaded, &vk).unwrap();
        assert_eq!(loaded.ciphertext, b"opaque-signal-ct");

        // Ack clears outbox on provider.
        let ack = SyncAckV1 {
            room_id: room,
            applied_tips: vec![event.id],
        };
        let removed = Outbox::new(&mut store_a).apply_ack(&ack).unwrap();
        assert_eq!(removed, 1);
        assert!(!Outbox::new(&mut store_a).contains(&event.id).unwrap());

        // Second round is a no-op
        let again =
            sync_round_in_process(&store_a, &mut store_b, &replica_a, &mut replica_b, &vk).unwrap();
        assert_eq!(again, 0);
    }

    /// ADV-DROP: random Offer/Want/Have drops (seeded 10–50%); converge when loss stops.
    #[test]
    fn adv_drop_sync_eventually_converges() {
        use rand::Rng;

        let mut rng = StdRng::seed_from_u64(0xAD_D0_0D_u64);
        let sk = SigningKey::generate(&mut rng);
        let vk = sk.verifying_key();
        let room = Cid([0xD0; 32]);
        let device_id = [0xD1; 32];
        let identity_id = [0xD2; 32];

        let mut store_a = MemoryKvStore::new();
        let mut replica_a = SyncReplica::new(room);
        let mut events = Vec::new();
        for i in 0..8u8 {
            let event = create_signed_message_event(
                room,
                device_id,
                identity_id,
                vec![],
                u64::from(i),
                ContentType::Text,
                vec![i, 0xAD],
                &sk,
            );
            EventStore::new(&mut store_a).put_event(&event).unwrap();
            replica_a.note_event(device_id, event.id);
            events.push(event.id);
        }

        let mut store_b = MemoryKvStore::new();
        let mut replica_b = SyncReplica::new(room);

        // Lossy phase: drop each frame independently with p ∈ [0.10, 0.50].
        let drop_pct = 10 + (rng.gen_range(0u32..41)); // 10..=50
        for _ in 0..40 {
            let offer = replica_a.build_offer().encode_v1().unwrap();
            if rng.gen_range(0u32..100) < drop_pct {
                continue;
            }
            let Ok(want_bytes) = want_bytes_from_offer(&replica_b, &offer) else {
                continue;
            };
            if rng.gen_range(0u32..100) < drop_pct {
                continue;
            }
            let Ok(have_bytes) = have_bytes_from_want(&store_a, &want_bytes) else {
                continue;
            };
            if rng.gen_range(0u32..100) < drop_pct {
                continue;
            }
            let _ = ack_bytes_from_have(&mut store_b, &mut replica_b, &have_bytes, &vk);
        }

        // Clean heal: no drops until consumer holds every provider tip.
        for _ in 0..16 {
            let applied =
                sync_round_in_process(&store_a, &mut store_b, &replica_a, &mut replica_b, &vk)
                    .unwrap();
            if applied == 0 {
                break;
            }
        }

        for cid in &events {
            assert!(
                EventStore::new(&mut store_b).has_event(cid).unwrap(),
                "ADV-DROP must converge after drops stop; missing {cid:?}"
            );
            assert!(replica_b.cid_index.contains(cid));
        }
        assert_eq!(replica_b.cid_index.cids.len(), events.len());
    }

    /// ADV-CORRUPT: bit-flipped Have / event bytes rejected; no panic; store clean.
    #[test]
    fn adv_corrupt_have_and_event_rejected() {
        let mut rng = StdRng::seed_from_u64(0xC0_FF_EE_u64);
        let sk = SigningKey::generate(&mut rng);
        let vk = sk.verifying_key();
        let room = Cid([0xC0; 32]);
        let device_id = [0xC1; 32];
        let identity_id = [0xC2; 32];

        let good = create_signed_message_event(
            room,
            device_id,
            identity_id,
            vec![],
            0,
            ContentType::Text,
            b"good-payload".to_vec(),
            &sk,
        );
        let mut bad = good.clone();
        bad.ciphertext[0] ^= 0xff; // id no longer matches ciphertext → reject

        let mut store = MemoryKvStore::new();
        let mut replica = SyncReplica::new(room);

        // Mixed Have: one valid wire + one bit-flipped event body.
        let good_wire = encode_message_event_wire_v1(&good).unwrap();
        let mut bad_wire = encode_message_event_wire_v1(&good).unwrap();
        let flip_at = bad_wire.len() / 2;
        bad_wire[flip_at] ^= 0xff;

        let have = SyncHaveV1 {
            room_id: room,
            objects: vec![
                SyncHaveObject {
                    cid: good.id,
                    object_bytes: good_wire,
                },
                SyncHaveObject {
                    cid: good.id, // claim good cid with corrupt bytes
                    object_bytes: bad_wire,
                },
                SyncHaveObject {
                    cid: bad.id,
                    object_bytes: encode_message_event_wire_v1(&bad).unwrap(),
                },
            ],
        };

        let applied = apply_have_frame(&mut store, &mut replica, &have, &vk).expect("no panic");
        assert_eq!(applied, vec![good.id]);
        assert!(EventStore::new(&mut store).has_event(&good.id).unwrap());
        // Corrupt claim must not poison store under a wrong/stale id.
        let loaded = EventStore::new(&mut store)
            .get_event(&good.id)
            .unwrap()
            .expect("good event");
        assert_eq!(loaded.ciphertext, b"good-payload");
        verify_message_event(&loaded, &vk).unwrap();

        // Whole-frame bit-flip on kind byte: decode fails closed (no panic).
        let mut have_bytes = SyncFrame::Have {
            room_id: room,
            objects: vec![(good.id, encode_message_event_wire_v1(&good).unwrap())],
        }
        .encode_v1()
        .unwrap();
        assert!(have_bytes.len() >= 2);
        have_bytes[1] ^= 0xff; // unknown SyncFrameKind
        assert!(SyncFrame::decode_v1(&have_bytes).is_err());
        assert!(ack_bytes_from_have(&mut store, &mut replica, &have_bytes, &vk).is_err());

        // Truncated payload rejected.
        assert!(SyncFrame::decode_v1(&have_bytes[..3.min(have_bytes.len())]).is_err());

        // Store still holds only the verified good event.
        assert_eq!(replica.cid_index.cids.len(), 1);
        let _ = bad; // silence: demonstrates id/ciphertext mismatch path above
    }

    #[test]
    fn typed_mls_welcome_syncs_in_band() {
        let room = Cid([0x42; 32]);
        let mut provider = MemoryKvStore::new();
        let mut consumer = MemoryKvStore::new();
        let mut provider_rep = SyncReplica::new(room);
        let mut consumer_rep = SyncReplica::new(room);
        let welcome = b"fake-welcome-tls-bytes";
        let (cid, _) =
            put_typed_sync_object(&mut provider, SyncObjectType::MlsWelcome, welcome).unwrap();
        provider_rep.note_typed_object(cid, SyncObjectType::MlsWelcome);
        assert!(provider_rep.control_cids.contains(&cid));
        let tips = provider_rep.offer_tips_control_first();
        assert_eq!(tips[0], cid);
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let n = sync_round_in_process(
            &provider,
            &mut consumer,
            &provider_rep,
            &mut consumer_rep,
            &vk,
        )
        .unwrap();
        assert_eq!(n, 1);
        assert!(consumer_rep.control_cids.contains(&cid));
        let wire = consumer.get(Namespace::Events, &cid.0).unwrap().unwrap();
        let (t, p) = decode_sync_object_v1(&wire).unwrap();
        assert_eq!(t, SyncObjectType::MlsWelcome);
        assert_eq!(p, welcome);
    }

    fn hex_encode_32(bytes: &[u8; 32]) -> String {
        let mut s = String::with_capacity(64);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}
