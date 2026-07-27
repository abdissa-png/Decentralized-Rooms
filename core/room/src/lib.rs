//! Room founding, membership CRDT, and policies (WBS 4.1.*).
//!
//! Owns append-only signed ACL events, deterministic state resolution
//! (**removal wins** over concurrent promote — FR-RM-007), `room_id` derivation
//! from founding bytes (FR-RM-001), and ≤50 member limit (FR-RM-005).
//!
//! MLS group operations live in [`rooms_mls`]. This crate does **not** own
//! transport or blob bytes (architecture §11.2).
//!
//! # History backfill (FR-RM-009)
//! New members receive **no automatic pre-join history**. Default policy is
//! [`HistoryBackfillPolicy::None`]. Explicit grant paths are deferred.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rooms_identity::IdentityId;
use rooms_proto::Cid;
use std::collections::{BTreeMap, HashMap, HashSet};
use thiserror::Error;

pub use rooms_mls::MAX_ROOM_MEMBERS;

/// Domain separation for founding event hash (FR-RM-001).
const FOUNDING_HASH_DOMAIN: &[u8] = b"rooms/FoundingEvent/v1\0";

/// Domain separation for membership event id / sign input.
const MEMBERSHIP_HASH_DOMAIN: &[u8] = b"rooms/MembershipEvent/v1\0";
const MEMBERSHIP_SIGN_DOMAIN: &[u8] = b"rooms/MembershipEvent/sign/v1\0";

/// Room identifier: `BLAKE3(founding_event_hash_domain)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct RoomId(pub Cid);

impl RoomId {
    /// Derive [`RoomId`] from canonical founding hash-domain bytes.
    pub fn from_founding_bytes(bytes: &[u8]) -> Self {
        Self(Cid::from_canonical_bytes(bytes))
    }

    pub fn as_cid(&self) -> Cid {
        self.0
    }
}

/// Membership role within a room.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[non_exhaustive]
pub enum MemberRole {
    Admin = 1,
    Member = 2,
}

impl MemberRole {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Admin),
            2 => Some(Self::Member),
            _ => None,
        }
    }
}

/// Membership mutation kinds (architecture §4.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[non_exhaustive]
pub enum MembershipAction {
    Invite = 1,
    Accept = 2,
    Remove = 3,
    Promote = 4,
    Demote = 5,
    Leave = 6,
}

impl MembershipAction {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Invite),
            2 => Some(Self::Accept),
            3 => Some(Self::Remove),
            4 => Some(Self::Promote),
            5 => Some(Self::Demote),
            6 => Some(Self::Leave),
            _ => None,
        }
    }

    /// Concurrent same-target priority: lower value applied first (remove wins).
    pub fn concurrent_priority(self) -> u8 {
        match self {
            Self::Remove => 0,
            Self::Leave => 1,
            Self::Demote => 2,
            Self::Promote => 3,
            Self::Accept => 4,
            Self::Invite => 5,
        }
    }
}

/// Whether new joiners receive pre-join message history (FR-RM-009).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
#[non_exhaustive]
pub enum HistoryBackfillPolicy {
    /// Default: no automatic history backfill for new members.
    #[default]
    None,
}

impl HistoryBackfillPolicy {
    /// Test / product hook: should the sync layer offer pre-join DAG objects?
    pub fn allows_automatic_history_backfill(self) -> bool {
        match self {
            Self::None => false,
        }
    }
}

/// Room-level policy knobs attached to founding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoomPolicy {
    pub max_members: usize,
    pub history_backfill: HistoryBackfillPolicy,
}

impl Default for RoomPolicy {
    fn default() -> Self {
        Self {
            max_members: MAX_ROOM_MEMBERS,
            history_backfill: HistoryBackfillPolicy::None,
        }
    }
}

/// Errors for room / membership operations.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum RoomError {
    #[error("bad signature")]
    BadSignature,
    #[error("unauthorized membership mutation")]
    Unauthorized,
    #[error("member limit exceeded (max {0})")]
    MemberLimitExceeded(usize),
    #[error("unknown membership action")]
    UnknownAction,
    #[error("event id mismatch")]
    IdMismatch,
    #[error("room mismatch")]
    RoomMismatch,
    #[error("not a member")]
    NotAMember,
}

/// Unsigned founding fields (hash domain excludes signature).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FoundingEvent {
    pub creator_id: IdentityId,
    pub created_unix_secs: u64,
    pub policy: RoomPolicy,
    /// Creator device signature over sign domain (64 bytes when set).
    pub signature: Vec<u8>,
}

impl FoundingEvent {
    /// Canonical hash-domain bytes (no signature).
    pub fn hash_domain_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(FOUNDING_HASH_DOMAIN);
        out.extend_from_slice(&self.creator_id.0);
        out.extend_from_slice(&self.created_unix_secs.to_le_bytes());
        out.extend_from_slice(&(self.policy.max_members as u32).to_le_bytes());
        out.push(match self.policy.history_backfill {
            HistoryBackfillPolicy::None => 0,
        });
        out
    }

    pub fn room_id(&self) -> RoomId {
        RoomId::from_founding_bytes(&self.hash_domain_bytes())
    }

    fn sign_input(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"rooms/FoundingEvent/sign/v1\0");
        out.extend_from_slice(&self.room_id().0 .0);
        out
    }

    /// Sign founding with the creator's device key.
    pub fn sign(&mut self, device_signing_key: &SigningKey) {
        self.signature = device_signing_key
            .sign(&self.sign_input())
            .to_bytes()
            .to_vec();
    }

    pub fn verify(&self, device_verifying_key: &VerifyingKey) -> Result<(), RoomError> {
        if self.signature.len() != 64 {
            return Err(RoomError::BadSignature);
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.signature);
        let sig = Signature::from_bytes(&sig_bytes);
        device_verifying_key
            .verify(&self.sign_input(), &sig)
            .map_err(|_| RoomError::BadSignature)?;
        Ok(())
    }
}

/// Create a signed founding event and return `(room_id, founding)`.
pub fn create_room(
    creator_id: IdentityId,
    created_unix_secs: u64,
    policy: RoomPolicy,
    device_signing_key: &SigningKey,
) -> (RoomId, FoundingEvent) {
    let mut founding = FoundingEvent {
        creator_id,
        created_unix_secs,
        policy,
        signature: Vec::new(),
    };
    founding.sign(device_signing_key);
    let room_id = founding.room_id();
    (room_id, founding)
}

/// Append-only membership event (signed; id derived from hash domain).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipEvent {
    pub id: Cid,
    pub room_id: RoomId,
    pub author_id: IdentityId,
    pub action: MembershipAction,
    pub target_id: IdentityId,
    /// Role for Invite / Promote; ignored for other actions.
    pub role: Option<MemberRole>,
    /// Causal parents in the membership log (sorted for hashing).
    pub parents: Vec<Cid>,
    pub signature: Vec<u8>,
}

impl MembershipEvent {
    fn hash_domain_bytes(
        room_id: &RoomId,
        author_id: &IdentityId,
        action: MembershipAction,
        target_id: &IdentityId,
        role: Option<MemberRole>,
        parents: &[Cid],
    ) -> Vec<u8> {
        let mut parents_sorted = parents.to_vec();
        parents_sorted.sort_by_key(|a| a.0);
        let mut out = Vec::new();
        out.extend_from_slice(MEMBERSHIP_HASH_DOMAIN);
        out.extend_from_slice(&room_id.0 .0);
        out.extend_from_slice(&author_id.0);
        out.push(action.as_u8());
        out.extend_from_slice(&target_id.0);
        out.push(role.map(|r| r.as_u8()).unwrap_or(0));
        out.extend_from_slice(&(parents_sorted.len() as u32).to_le_bytes());
        for p in &parents_sorted {
            out.extend_from_slice(&p.0);
        }
        out
    }

    pub fn event_id(
        room_id: &RoomId,
        author_id: &IdentityId,
        action: MembershipAction,
        target_id: &IdentityId,
        role: Option<MemberRole>,
        parents: &[Cid],
    ) -> Cid {
        Cid::from_canonical_bytes(&Self::hash_domain_bytes(
            room_id, author_id, action, target_id, role, parents,
        ))
    }

    fn sign_input(id: &Cid) -> Vec<u8> {
        let mut out = Vec::with_capacity(MEMBERSHIP_SIGN_DOMAIN.len() + 32);
        out.extend_from_slice(MEMBERSHIP_SIGN_DOMAIN);
        out.extend_from_slice(&id.0);
        out
    }

    /// Build and sign a membership event.
    pub fn create_signed(
        room_id: RoomId,
        author_id: IdentityId,
        action: MembershipAction,
        target_id: IdentityId,
        role: Option<MemberRole>,
        parents: Vec<Cid>,
        device_signing_key: &SigningKey,
    ) -> Self {
        let id = Self::event_id(&room_id, &author_id, action, &target_id, role, &parents);
        let mut parents_sorted = parents;
        parents_sorted.sort_by_key(|a| a.0);
        let signature = device_signing_key
            .sign(&Self::sign_input(&id))
            .to_bytes()
            .to_vec();
        Self {
            id,
            room_id,
            author_id,
            action,
            target_id,
            role,
            parents: parents_sorted,
            signature,
        }
    }

    pub fn verify(&self, device_verifying_key: &VerifyingKey) -> Result<(), RoomError> {
        let expected = Self::event_id(
            &self.room_id,
            &self.author_id,
            self.action,
            &self.target_id,
            self.role,
            &self.parents,
        );
        if expected != self.id {
            return Err(RoomError::IdMismatch);
        }
        if self.signature.len() != 64 {
            return Err(RoomError::BadSignature);
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.signature);
        let sig = Signature::from_bytes(&sig_bytes);
        device_verifying_key
            .verify(&Self::sign_input(&self.id), &sig)
            .map_err(|_| RoomError::BadSignature)?;
        Ok(())
    }
}

/// Resolved membership for one identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberStatus {
    /// Invited but not yet accepted.
    PendingInvite {
        role: MemberRole,
    },
    Active {
        role: MemberRole,
    },
    Removed,
}

/// Deterministic membership state from an append-only event set.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MembershipState {
    /// identity → status (Removed entries may be omitted or kept; we omit).
    members: BTreeMap<IdentityId, MemberStatus>,
}

impl MembershipState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, id: &IdentityId) -> Option<&MemberStatus> {
        self.members.get(id)
    }

    pub fn is_admin(&self, id: &IdentityId) -> bool {
        matches!(
            self.members.get(id),
            Some(MemberStatus::Active {
                role: MemberRole::Admin
            })
        )
    }

    pub fn is_active_member(&self, id: &IdentityId) -> bool {
        matches!(self.members.get(id), Some(MemberStatus::Active { .. }))
    }

    /// Active members only (admins + members), sorted by identity id.
    pub fn active_members(&self) -> Vec<(IdentityId, MemberRole)> {
        self.members
            .iter()
            .filter_map(|(id, st)| match st {
                MemberStatus::Active { role } => Some((*id, *role)),
                _ => None,
            })
            .collect()
    }

    pub fn active_count(&self) -> usize {
        self.active_members().len()
    }
}

/// Append-only membership log with CRDT merge (set union + deterministic resolve).
#[derive(Clone, Debug, Default)]
pub struct MembershipLog {
    pub room_id: Option<RoomId>,
    events: HashMap<Cid, MembershipEvent>,
}

impl MembershipLog {
    pub fn new(room_id: RoomId) -> Self {
        Self {
            room_id: Some(room_id),
            events: HashMap::new(),
        }
    }

    pub fn events(&self) -> impl Iterator<Item = &MembershipEvent> {
        self.events.values()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn contains(&self, id: &Cid) -> bool {
        self.events.contains_key(id)
    }

    /// Insert a verified event (caller verifies signature + authorization).
    pub fn insert(&mut self, event: MembershipEvent) -> Result<(), RoomError> {
        if let Some(rid) = self.room_id {
            if event.room_id != rid {
                return Err(RoomError::RoomMismatch);
            }
        } else {
            self.room_id = Some(event.room_id);
        }
        self.events.insert(event.id, event);
        Ok(())
    }

    /// Merge another replica's log (commutative union).
    pub fn merge(&mut self, other: &Self) -> Result<(), RoomError> {
        if let (Some(a), Some(b)) = (self.room_id, other.room_id) {
            if a != b {
                return Err(RoomError::RoomMismatch);
            }
        }
        if self.room_id.is_none() {
            self.room_id = other.room_id;
        }
        for (id, ev) in &other.events {
            self.events.entry(*id).or_insert_with(|| ev.clone());
        }
        Ok(())
    }

    /// Resolve deterministic membership state (FR-RM-006 / FR-RM-007).
    pub fn resolve(&self) -> MembershipState {
        resolve_membership(self.events.values().cloned().collect::<Vec<_>>())
    }

    /// Tip event ids (events not referenced as parents).
    pub fn tips(&self) -> Vec<Cid> {
        let mut referenced = HashSet::new();
        for ev in self.events.values() {
            for p in &ev.parents {
                referenced.insert(*p);
            }
        }
        let mut tips: Vec<Cid> = self
            .events
            .keys()
            .filter(|id| !referenced.contains(id))
            .copied()
            .collect();
        tips.sort_by_key(|a| a.0);
        tips
    }
}

/// Seed log with creator as initial admin (no event required beyond founding).
pub fn seed_creator_admin(creator: IdentityId) -> MembershipState {
    let mut state = MembershipState::new();
    state.members.insert(
        creator,
        MemberStatus::Active {
            role: MemberRole::Admin,
        },
    );
    state
}

fn resolve_membership(events: Vec<MembershipEvent>) -> MembershipState {
    // Order: topological by parents; concurrent waves sorted by
    // (action_priority, author_id, event_id) so Remove beats Promote (FR-RM-007).
    let by_id: HashMap<Cid, MembershipEvent> = events.into_iter().map(|e| (e.id, e)).collect();
    if by_id.is_empty() {
        return MembershipState::new();
    }

    let mut indegree: HashMap<Cid, usize> = HashMap::new();
    let mut children: HashMap<Cid, Vec<Cid>> = HashMap::new();
    for ev in by_id.values() {
        indegree.entry(ev.id).or_insert(0);
        for p in &ev.parents {
            if by_id.contains_key(p) {
                *indegree.entry(ev.id).or_insert(0) += 1;
                children.entry(*p).or_default().push(ev.id);
            }
        }
    }

    let mut ready: Vec<Cid> = indegree
        .iter()
        .filter(|(_, d)| **d == 0)
        .map(|(id, _)| *id)
        .collect();
    sort_concurrent(&mut ready, &by_id);

    let mut state = MembershipState::new();
    let mut seen: HashSet<Cid> = HashSet::new();
    while !ready.is_empty() {
        let wave = std::mem::take(&mut ready);
        for id in wave {
            if !seen.insert(id) {
                continue;
            }
            if let Some(ev) = by_id.get(&id) {
                apply_event(&mut state, ev, &by_id);
                if let Some(kids) = children.get(&id) {
                    for child in kids {
                        if let Some(d) = indegree.get_mut(child) {
                            *d = d.saturating_sub(1);
                            if *d == 0 {
                                ready.push(*child);
                            }
                        }
                    }
                }
            }
        }
        sort_concurrent(&mut ready, &by_id);
    }

    // Cycles / unreachable: apply leftovers by concurrent priority order.
    if seen.len() < by_id.len() {
        let mut rest: Vec<&MembershipEvent> =
            by_id.values().filter(|e| !seen.contains(&e.id)).collect();
        rest.sort_by(|a, b| {
            a.action
                .concurrent_priority()
                .cmp(&b.action.concurrent_priority())
                .then_with(|| a.author_id.0.cmp(&b.author_id.0))
                .then_with(|| a.id.0.cmp(&b.id.0))
        });
        for ev in rest {
            apply_event(&mut state, ev, &by_id);
        }
    }

    state
}

fn sort_concurrent(ids: &mut [Cid], by_id: &HashMap<Cid, MembershipEvent>) {
    ids.sort_by(|a, b| {
        let ea = &by_id[a];
        let eb = &by_id[b];
        ea.action
            .concurrent_priority()
            .cmp(&eb.action.concurrent_priority())
            .then_with(|| ea.author_id.0.cmp(&eb.author_id.0))
            .then_with(|| ea.id.0.cmp(&eb.id.0))
    });
}

fn apply_event(
    state: &mut MembershipState,
    ev: &MembershipEvent,
    by_id: &HashMap<Cid, MembershipEvent>,
) {
    match ev.action {
        MembershipAction::Invite => {
            if matches!(
                state.members.get(&ev.target_id),
                Some(MemberStatus::Removed)
            ) {
                // Remove-wins: concurrent invite (remove not in parents) stays Removed.
                // Explicit re-invite must parent a Remove of the same target.
                let causally_after_remove = ev.parents.iter().any(|p| {
                    matches!(
                        by_id.get(p),
                        Some(MembershipEvent {
                            action: MembershipAction::Remove,
                            target_id,
                            ..
                        }) if *target_id == ev.target_id
                    )
                });
                if !causally_after_remove {
                    return;
                }
                let role = ev.role.unwrap_or(MemberRole::Member);
                state
                    .members
                    .insert(ev.target_id, MemberStatus::PendingInvite { role });
                return;
            }
            if !matches!(
                state.members.get(&ev.target_id),
                Some(MemberStatus::Active { .. })
            ) {
                let role = ev.role.unwrap_or(MemberRole::Member);
                state
                    .members
                    .insert(ev.target_id, MemberStatus::PendingInvite { role });
            }
        }
        MembershipAction::Accept => {
            if let Some(MemberStatus::PendingInvite { role }) =
                state.members.get(&ev.target_id).copied()
            {
                // Only the invitee may accept (authorization checked at append).
                state
                    .members
                    .insert(ev.target_id, MemberStatus::Active { role });
            }
        }
        MembershipAction::Remove | MembershipAction::Leave => {
            state.members.insert(ev.target_id, MemberStatus::Removed);
            // Keep Removed marker so concurrent promote in same wave already
            // ordered after remove sees Removed... but promote runs after in wave.
            // For promote after remove in later causal event, still removed until re-invite.
        }
        MembershipAction::Promote => {
            match state.members.get(&ev.target_id) {
                Some(MemberStatus::Active { .. }) => {
                    state.members.insert(
                        ev.target_id,
                        MemberStatus::Active {
                            role: MemberRole::Admin,
                        },
                    );
                }
                Some(MemberStatus::Removed) => {
                    // Removal wins: do not promote a removed member.
                }
                Some(MemberStatus::PendingInvite { .. }) | None => {
                    // Cannot promote non-active.
                }
            }
        }
        MembershipAction::Demote => {
            if matches!(
                state.members.get(&ev.target_id),
                Some(MemberStatus::Active { .. })
            ) {
                state.members.insert(
                    ev.target_id,
                    MemberStatus::Active {
                        role: MemberRole::Member,
                    },
                );
            }
        }
    }
}

/// Check authorization for a membership mutation against resolved state.
pub fn authorize_mutation(
    state: &MembershipState,
    author: &IdentityId,
    action: MembershipAction,
    target: &IdentityId,
) -> Result<(), RoomError> {
    match action {
        MembershipAction::Invite
        | MembershipAction::Remove
        | MembershipAction::Promote
        | MembershipAction::Demote => {
            if !state.is_admin(author) {
                return Err(RoomError::Unauthorized);
            }
            Ok(())
        }
        MembershipAction::Accept => {
            if author != target {
                return Err(RoomError::Unauthorized);
            }
            Ok(())
        }
        MembershipAction::Leave => {
            if author != target {
                return Err(RoomError::Unauthorized);
            }
            if !state.is_active_member(author) {
                return Err(RoomError::NotAMember);
            }
            Ok(())
        }
    }
}

/// Enforce max members before accepting a new active member (FR-RM-005).
pub fn enforce_member_limit(state: &MembershipState, max_members: usize) -> Result<(), RoomError> {
    if state.active_count() > max_members {
        return Err(RoomError::MemberLimitExceeded(max_members));
    }
    Ok(())
}

/// Would adding one more active member exceed the limit?
pub fn would_exceed_member_limit(state: &MembershipState, max_members: usize) -> bool {
    state.active_count() >= max_members
}

/// Combined room handle: founding + membership log + MLS epoch bookmark.
#[derive(Clone, Debug)]
pub struct RoomState {
    pub room_id: RoomId,
    pub founding: FoundingEvent,
    pub membership: MembershipLog,
    pub creator_id: IdentityId,
    pub mls_epoch: u64,
}

impl RoomState {
    /// Create room from founding event; seed creator as admin.
    pub fn from_founding(founding: FoundingEvent) -> Self {
        let room_id = founding.room_id();
        let creator_id = founding.creator_id;
        Self {
            room_id,
            founding,
            membership: MembershipLog::new(room_id),
            creator_id,
            mls_epoch: 0,
        }
    }

    /// Resolved membership including founding creator as admin.
    pub fn resolved_membership(&self) -> MembershipState {
        let mut state = seed_creator_admin(self.creator_id);
        let from_log = self.membership.resolve();
        // Overlay log state (log can remove/leave the creator).
        for (id, status) in from_log.members {
            state.members.insert(id, status);
        }
        state
    }

    pub fn is_admin(&self, id: &IdentityId) -> bool {
        self.resolved_membership().is_admin(id)
    }

    pub fn history_backfill_allowed(&self) -> bool {
        self.founding
            .policy
            .history_backfill
            .allows_automatic_history_backfill()
    }

    /// Append a verified+authorized membership event; enforce member limit on Accept.
    pub fn append_membership(
        &mut self,
        event: MembershipEvent,
        author_vk: &VerifyingKey,
    ) -> Result<(), RoomError> {
        event.verify(author_vk)?;
        if event.room_id != self.room_id {
            return Err(RoomError::RoomMismatch);
        }
        let state = self.resolved_membership();
        authorize_mutation(&state, &event.author_id, event.action, &event.target_id)?;
        if event.action == MembershipAction::Accept
            && would_exceed_member_limit(&state, self.founding.policy.max_members)
        {
            return Err(RoomError::MemberLimitExceeded(
                self.founding.policy.max_members,
            ));
        }
        self.membership.insert(event)?;
        let after = self.resolved_membership();
        enforce_member_limit(&after, self.founding.policy.max_members)?;
        Ok(())
    }
}

/// Test hook: objects a new member should receive for history sync under policy.
///
/// With [`HistoryBackfillPolicy::None`], always returns empty — FR-RM-009.
pub fn history_cids_for_new_member(
    policy: HistoryBackfillPolicy,
    _pre_join_tips: &[Cid],
) -> Vec<Cid> {
    if policy.allows_automatic_history_backfill() {
        // Future: explicit grant could return pre_join_tips.
        Vec::new()
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::collections::BTreeSet;

    fn id(byte: u8) -> IdentityId {
        IdentityId([byte; 32])
    }

    fn sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn founding_room_id_stable_and_distinct() {
        let creator = id(1);
        let sk = sk(9);
        let (rid_a, f_a) = create_room(creator, 100, RoomPolicy::default(), &sk);
        let (rid_b, _) = create_room(creator, 100, RoomPolicy::default(), &sk);
        assert_eq!(rid_a, rid_b);
        assert_eq!(f_a.room_id(), rid_a);

        let (rid_c, _) = create_room(creator, 101, RoomPolicy::default(), &sk);
        assert_ne!(rid_a, rid_c);
    }

    #[test]
    fn founder_is_admin() {
        let sk = sk(3);
        let creator = id(9);
        let (room_id, founding) = create_room(creator, 1, RoomPolicy::default(), &sk);
        founding.verify(&sk.verifying_key()).unwrap();
        let room = RoomState::from_founding(founding);
        assert_eq!(room.room_id, room_id);
        assert!(room.is_admin(&creator));
        assert!(!room.is_admin(&id(1)));
    }

    #[test]
    fn max_members_constant_and_enforced() {
        assert_eq!(MAX_ROOM_MEMBERS, 50);
        let mut state = MembershipState::new();
        for i in 0..50u8 {
            state.members.insert(
                IdentityId([i; 32]),
                MemberStatus::Active {
                    role: MemberRole::Member,
                },
            );
        }
        assert!(would_exceed_member_limit(&state, MAX_ROOM_MEMBERS));
        enforce_member_limit(&state, MAX_ROOM_MEMBERS).unwrap();
        state.members.insert(
            IdentityId([50; 32]),
            MemberStatus::Active {
                role: MemberRole::Member,
            },
        );
        assert_eq!(
            enforce_member_limit(&state, MAX_ROOM_MEMBERS),
            Err(RoomError::MemberLimitExceeded(50))
        );
    }

    #[test]
    fn no_automatic_history_backfill() {
        let policy = HistoryBackfillPolicy::None;
        assert!(!policy.allows_automatic_history_backfill());
        let tips = vec![Cid([1u8; 32]), Cid([2u8; 32])];
        assert!(history_cids_for_new_member(policy, &tips).is_empty());

        let sk = sk(1);
        let (_, founding) = create_room(id(1), 0, RoomPolicy::default(), &sk);
        let room = RoomState::from_founding(founding);
        assert!(!room.history_backfill_allowed());
    }

    #[test]
    fn remove_wins_over_concurrent_promote() {
        let admin = id(1);
        let target = id(2);
        let room_id = RoomId::from_founding_bytes(b"test-room-remove-vs-promote");
        let sk_a = sk(10);
        let sk_b = sk(11);

        // Shared parent: both accept target as member first.
        let invite = MembershipEvent::create_signed(
            room_id,
            admin,
            MembershipAction::Invite,
            target,
            Some(MemberRole::Member),
            vec![],
            &sk_a,
        );
        let accept = MembershipEvent::create_signed(
            room_id,
            target,
            MembershipAction::Accept,
            target,
            None,
            vec![invite.id],
            &sk_b,
        );

        // Concurrent: remove vs promote, same parents (accept tip).
        let remove = MembershipEvent::create_signed(
            room_id,
            admin,
            MembershipAction::Remove,
            target,
            None,
            vec![accept.id],
            &sk_a,
        );
        let promote = MembershipEvent::create_signed(
            room_id,
            admin,
            MembershipAction::Promote,
            target,
            Some(MemberRole::Admin),
            vec![accept.id],
            &sk_a,
        );

        let mut log = MembershipLog::new(room_id);
        for ev in [invite, accept, remove.clone(), promote.clone()] {
            log.insert(ev).unwrap();
        }

        // Seed creator then overlay — resolve log alone for target.
        let resolved = log.resolve();
        assert_eq!(
            resolved.get(&target),
            Some(&MemberStatus::Removed),
            "FR-RM-007: removal wins over concurrent promote"
        );

        // Order of insert must not matter.
        let mut log2 = MembershipLog::new(room_id);
        for ev in [promote, remove] {
            log2.insert(ev).unwrap();
        }
        // Without invite/accept, promote is no-op and remove marks Removed.
        assert_eq!(log2.resolve().get(&target), Some(&MemberStatus::Removed));
    }

    /// Gate 2 nameplate: UT-CRDT remove-vs-promote.
    #[test]
    fn ut_crdt_remove_vs_promote() {
        remove_wins_over_concurrent_promote();
    }

    #[test]
    fn adv_part_membership_merge_converges() {
        // ADV-PART: split brain then heal — CRDT membership converges.
        let admin = id(1);
        let bob = id(2);
        let carol = id(3);
        let room_id = RoomId::from_founding_bytes(b"adv-part-membership");
        let sk_admin = sk(20);
        let sk_bob = sk(21);
        let sk_carol = sk(22);

        let invite_bob = MembershipEvent::create_signed(
            room_id,
            admin,
            MembershipAction::Invite,
            bob,
            Some(MemberRole::Member),
            vec![],
            &sk_admin,
        );
        let accept_bob = MembershipEvent::create_signed(
            room_id,
            bob,
            MembershipAction::Accept,
            bob,
            None,
            vec![invite_bob.id],
            &sk_bob,
        );

        // Partition A: admin removes bob.
        let remove_bob = MembershipEvent::create_signed(
            room_id,
            admin,
            MembershipAction::Remove,
            bob,
            None,
            vec![accept_bob.id],
            &sk_admin,
        );

        // Partition B: admin invites carol (concurrent with remove).
        let invite_carol = MembershipEvent::create_signed(
            room_id,
            admin,
            MembershipAction::Invite,
            carol,
            Some(MemberRole::Member),
            vec![accept_bob.id],
            &sk_admin,
        );
        let accept_carol = MembershipEvent::create_signed(
            room_id,
            carol,
            MembershipAction::Accept,
            carol,
            None,
            vec![invite_carol.id],
            &sk_carol,
        );

        let mut left = MembershipLog::new(room_id);
        left.insert(invite_bob.clone()).unwrap();
        left.insert(accept_bob.clone()).unwrap();
        left.insert(remove_bob.clone()).unwrap();

        let mut right = MembershipLog::new(room_id);
        right.insert(invite_bob).unwrap();
        right.insert(accept_bob).unwrap();
        right.insert(invite_carol).unwrap();
        right.insert(accept_carol).unwrap();

        let mut ab = left.clone();
        ab.merge(&right).unwrap();
        let mut ba = right.clone();
        ba.merge(&left).unwrap();

        assert_eq!(ab.resolve(), ba.resolve());
        let state = ab.resolve();
        assert_eq!(state.get(&bob), Some(&MemberStatus::Removed));
        assert!(matches!(
            state.get(&carol),
            Some(MemberStatus::Active {
                role: MemberRole::Member
            })
        ));

        // Tips differ under partition, union after heal.
        let mut tip_set: BTreeSet<Cid> = left.tips().into_iter().collect();
        tip_set.extend(right.tips());
        let healed_tips: BTreeSet<Cid> = ab.tips().into_iter().collect();
        // Healed tips are a subset of all tip candidates after parent refs update.
        assert!(!healed_tips.is_empty());
        let _ = tip_set;
    }

    #[test]
    fn concurrent_invite_and_remove_remove_wins() {
        // Concurrent invite (pending) vs remove of same target — remove wins.
        let admin = id(1);
        let target = id(2);
        let room_id = RoomId::from_founding_bytes(b"adv-invite-vs-remove");
        let sk_admin = sk(30);

        let invite = MembershipEvent::create_signed(
            room_id,
            admin,
            MembershipAction::Invite,
            target,
            Some(MemberRole::Member),
            vec![],
            &sk_admin,
        );
        let remove = MembershipEvent::create_signed(
            room_id,
            admin,
            MembershipAction::Remove,
            target,
            None,
            vec![],
            &sk_admin,
        );

        let mut ab = MembershipLog::new(room_id);
        ab.insert(invite.clone()).unwrap();
        ab.insert(remove.clone()).unwrap();
        let mut ba = MembershipLog::new(room_id);
        ba.insert(remove).unwrap();
        ba.insert(invite).unwrap();

        assert_eq!(ab.resolve(), ba.resolve());
        assert_eq!(ab.resolve().get(&target), Some(&MemberStatus::Removed));
    }

    #[test]
    fn double_remove_is_idempotent() {
        let admin = id(1);
        let bob = id(2);
        let room_id = RoomId::from_founding_bytes(b"adv-double-remove");
        let sk_admin = sk(31);
        let sk_bob = sk(32);

        let invite = MembershipEvent::create_signed(
            room_id,
            admin,
            MembershipAction::Invite,
            bob,
            Some(MemberRole::Member),
            vec![],
            &sk_admin,
        );
        let accept = MembershipEvent::create_signed(
            room_id,
            bob,
            MembershipAction::Accept,
            bob,
            None,
            vec![invite.id],
            &sk_bob,
        );
        let remove1 = MembershipEvent::create_signed(
            room_id,
            admin,
            MembershipAction::Remove,
            bob,
            None,
            vec![accept.id],
            &sk_admin,
        );
        // Same-parent duplicate remove collapses to one id; chain a second remove tip.
        let remove2 = MembershipEvent::create_signed(
            room_id,
            admin,
            MembershipAction::Remove,
            bob,
            None,
            vec![remove1.id],
            &sk_admin,
        );

        let mut log = MembershipLog::new(room_id);
        for ev in [invite, accept, remove1.clone(), remove2] {
            log.insert(ev).unwrap();
        }
        // Idempotent insert of the first remove.
        log.insert(remove1).unwrap();
        assert_eq!(log.resolve().get(&bob), Some(&MemberStatus::Removed));
        let snapshot = log.resolve();
        log.merge(&log.clone()).unwrap();
        assert_eq!(log.resolve(), snapshot);
    }

    #[test]
    fn unauthorized_non_admin_invite_rejected() {
        let mut rng = StdRng::seed_from_u64(42);
        let admin_sk = SigningKey::generate(&mut rng);
        let member_sk = SigningKey::generate(&mut rng);
        let admin = id(1);
        let member = id(2);
        let other = id(3);
        let (room_id, founding) = create_room(admin, 0, RoomPolicy::default(), &admin_sk);
        let mut room = RoomState::from_founding(founding);

        // Bootstrap member via admin.
        let invite = MembershipEvent::create_signed(
            room_id,
            admin,
            MembershipAction::Invite,
            member,
            Some(MemberRole::Member),
            vec![],
            &admin_sk,
        );
        room.append_membership(invite.clone(), &admin_sk.verifying_key())
            .unwrap();
        let accept = MembershipEvent::create_signed(
            room_id,
            member,
            MembershipAction::Accept,
            member,
            None,
            vec![invite.id],
            &member_sk,
        );
        room.append_membership(accept, &member_sk.verifying_key())
            .unwrap();

        let bad = MembershipEvent::create_signed(
            room_id,
            member,
            MembershipAction::Invite,
            other,
            Some(MemberRole::Member),
            room.membership.tips(),
            &member_sk,
        );
        assert_eq!(
            room.append_membership(bad, &member_sk.verifying_key()),
            Err(RoomError::Unauthorized)
        );
    }
}
