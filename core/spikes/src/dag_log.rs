//! Spike 2.3 — Toy hash-chained / DAG log + ed25519 signatures.
//!
//! Append-only events with BLAKE3 content hashes, causal parent links (true DAG,
//! not a linear chain), and ed25519 signatures. Tampering fails verification.
//! Feeds the Phase 0 canonical event-encoding spec (WBS 2.8).

use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use thiserror::Error;

pub const SPIKE_NAME: &str = "dag-log";
pub const WBS: &str = "2.3";

/// Domain-separated content id for a DAG event body (parents + payload).
pub type EventId = [u8; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DagEvent {
    pub id: EventId,
    pub parents: Vec<EventId>,
    pub payload: Vec<u8>,
    pub author: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Debug, Error)]
pub enum DagError {
    #[error("unknown parent {0:?}")]
    UnknownParent(EventId),
    #[error("duplicate event id")]
    Duplicate,
    #[error("content hash mismatch")]
    HashMismatch,
    #[error("invalid signature")]
    BadSignature,
    #[error("invalid verifying key")]
    BadKey,
}

/// In-memory append-only DAG store.
#[derive(Default)]
pub struct DagLog {
    events: HashMap<EventId, DagEvent>,
    /// Events with no known children (current tips).
    tips: HashSet<EventId>,
}

impl DagLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn tips(&self) -> Vec<EventId> {
        let mut t: Vec<_> = self.tips.iter().copied().collect();
        t.sort();
        t
    }

    pub fn get(&self) -> impl Iterator<Item = &DagEvent> {
        self.events.values()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Canonical bytes hashed into [`EventId`] (parents sorted for determinism).
    pub fn content_bytes(parents: &[EventId], payload: &[u8]) -> Vec<u8> {
        let mut sorted = parents.to_vec();
        sorted.sort();
        let mut buf = Vec::with_capacity(32 + sorted.len() * 32 + payload.len());
        buf.extend_from_slice(b"rooms-spike/dag-event/v0\0");
        buf.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
        for p in &sorted {
            buf.extend_from_slice(p);
        }
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    pub fn content_id(parents: &[EventId], payload: &[u8]) -> EventId {
        *blake3::hash(&Self::content_bytes(parents, payload)).as_bytes()
    }

    /// Bytes covered by the author's ed25519 signature.
    fn sign_bytes(id: &EventId, author: &[u8; 32]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(b"rooms-spike/dag-sig/v0\0");
        buf.extend_from_slice(id);
        buf.extend_from_slice(author);
        buf
    }

    pub fn sign_event(
        signing_key: &SigningKey,
        parents: Vec<EventId>,
        payload: Vec<u8>,
    ) -> DagEvent {
        let id = Self::content_id(&parents, &payload);
        let author = signing_key.verifying_key().to_bytes();
        let sig = signing_key.sign(&Self::sign_bytes(&id, &author));
        DagEvent {
            id,
            parents,
            payload,
            author,
            signature: sig.to_bytes(),
        }
    }

    pub fn verify_event(event: &DagEvent) -> Result<(), DagError> {
        let expected = Self::content_id(&event.parents, &event.payload);
        if expected != event.id {
            return Err(DagError::HashMismatch);
        }
        let vk = VerifyingKey::from_bytes(&event.author).map_err(|_| DagError::BadKey)?;
        let sig = Signature::from_bytes(&event.signature);
        vk.verify(&Self::sign_bytes(&event.id, &event.author), &sig)
            .map_err(|_| DagError::BadSignature)?;
        Ok(())
    }

    /// Verify and append. Parents must already be present (or empty for genesis).
    pub fn append(&mut self, event: DagEvent) -> Result<(), DagError> {
        Self::verify_event(&event)?;
        if self.events.contains_key(&event.id) {
            return Err(DagError::Duplicate);
        }
        for p in &event.parents {
            if !self.events.contains_key(p) {
                return Err(DagError::UnknownParent(*p));
            }
        }
        for p in &event.parents {
            self.tips.remove(p);
        }
        self.tips.insert(event.id);
        self.events.insert(event.id, event);
        Ok(())
    }
}

/// Generate a fresh ed25519 signing key for spike tests.
pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_chain_appends() {
        let sk = generate_signing_key();
        let mut log = DagLog::new();
        let e0 = DagLog::sign_event(&sk, vec![], b"genesis".to_vec());
        log.append(e0.clone()).unwrap();
        let e1 = DagLog::sign_event(&sk, vec![e0.id], b"child".to_vec());
        log.append(e1.clone()).unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log.tips(), vec![e1.id]);
    }

    #[test]
    fn concurrent_two_parent_tip() {
        let alice = generate_signing_key();
        let bob = generate_signing_key();
        let mut log = DagLog::new();

        let genesis = DagLog::sign_event(&alice, vec![], b"root".to_vec());
        log.append(genesis.clone()).unwrap();

        // Concurrent branches from the same parent.
        let a = DagLog::sign_event(&alice, vec![genesis.id], b"alice-branch".to_vec());
        let b = DagLog::sign_event(&bob, vec![genesis.id], b"bob-branch".to_vec());
        log.append(a.clone()).unwrap();
        log.append(b.clone()).unwrap();

        let tips = log.tips();
        assert_eq!(tips.len(), 2);
        assert!(tips.contains(&a.id) && tips.contains(&b.id));

        // Merge with two causal parents.
        let merge = DagLog::sign_event(&alice, vec![a.id, b.id], b"merge".to_vec());
        log.append(merge.clone()).unwrap();
        assert_eq!(log.tips(), vec![merge.id]);
        assert_eq!(merge.parents.len(), 2);
    }

    #[test]
    fn rejects_tampered_payload() {
        let sk = generate_signing_key();
        let mut event = DagLog::sign_event(&sk, vec![], b"honest".to_vec());
        event.payload = b"evil".to_vec();
        assert!(matches!(
            DagLog::verify_event(&event),
            Err(DagError::HashMismatch)
        ));
    }

    #[test]
    fn rejects_bad_signature() {
        let sk = generate_signing_key();
        let mut event = DagLog::sign_event(&sk, vec![], b"honest".to_vec());
        event.signature[0] ^= 0xff;
        assert!(matches!(
            DagLog::verify_event(&event),
            Err(DagError::BadSignature)
        ));
    }

    #[test]
    fn rejects_unknown_parent() {
        let sk = generate_signing_key();
        let mut log = DagLog::new();
        let fake_parent = [9u8; 32];
        let event = DagLog::sign_event(&sk, vec![fake_parent], b"orphan".to_vec());
        assert!(matches!(log.append(event), Err(DagError::UnknownParent(_))));
    }
}
