//! Local content-addressed storage for Decentralized Encrypted Rooms.
//!
//! Owns persistence and CID indexing (architecture: RocksDB target, encrypted at
//! rest later). Does **not** own peer dialing or crypto seal/open.
//!
//! # Status
//! Phase 1 kickoff: [`KvStore`] trait + in-memory and **sled** backends.
//! RocksDB remains the production swap (see `docs/phase-1-status.md`) — sled was
//! chosen for clean builds without native RocksDB deps in CI-like environments.

use rooms_proto::Cid;
use std::collections::HashMap;
use std::path::Path;

/// Logical key namespaces (WBS 3.1.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum Namespace {
    Meta = 1,
    Identity = 2,
    Events = 3,
    Outbox = 4,
    Sessions = 5,
    /// Sync resume bookmarks per peer (answers.md §35).
    Cursors = 6,
}

impl Namespace {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Storage errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageError {
    Backend(String),
    InvalidKey,
}

/// Thin key-value store used by identity / DAG persistence.
pub trait KvStore {
    fn put(&mut self, ns: Namespace, key: &[u8], value: &[u8]) -> Result<(), StorageError>;
    fn get(&self, ns: Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;
    fn delete(&mut self, ns: Namespace, key: &[u8]) -> Result<(), StorageError>;
}

fn namespaced_key(ns: Namespace, key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + key.len());
    out.push(ns.as_u8());
    out.extend_from_slice(key);
    out
}

/// In-memory KvStore (tests / ephemeral).
#[derive(Default, Debug)]
pub struct MemoryKvStore {
    map: HashMap<Vec<u8>, Vec<u8>>,
}

impl MemoryKvStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KvStore for MemoryKvStore {
    fn put(&mut self, ns: Namespace, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.map.insert(namespaced_key(ns, key), value.to_vec());
        Ok(())
    }

    fn get(&self, ns: Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.map.get(&namespaced_key(ns, key)).cloned())
    }

    fn delete(&mut self, ns: Namespace, key: &[u8]) -> Result<(), StorageError> {
        self.map.remove(&namespaced_key(ns, key));
        Ok(())
    }
}

/// sled-backed KvStore (Phase 1 MVP; swap for RocksDB later).
pub struct SledKvStore {
    db: sled::Db,
}

impl SledKvStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let db = sled::open(path.as_ref()).map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(Self { db })
    }
}

impl KvStore for SledKvStore {
    fn put(&mut self, ns: Namespace, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.db
            .insert(namespaced_key(ns, key), value)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        self.db
            .flush()
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    fn get(&self, ns: Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        match self
            .db
            .get(namespaced_key(ns, key))
            .map_err(|e| StorageError::Backend(e.to_string()))?
        {
            Some(v) => Ok(Some(v.to_vec())),
            None => Ok(None),
        }
    }

    fn delete(&mut self, ns: Namespace, key: &[u8]) -> Result<(), StorageError> {
        self.db
            .remove(namespaced_key(ns, key))
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }
}

/// Convenience: store identity document bytes under [`Namespace::Identity`].
pub fn put_identity_document(
    store: &mut dyn KvStore,
    identity_id: &[u8; 32],
    document_bytes: &[u8],
) -> Result<(), StorageError> {
    store.put(Namespace::Identity, identity_id, document_bytes)
}

pub fn get_identity_document(
    store: &dyn KvStore,
    identity_id: &[u8; 32],
) -> Result<Option<Vec<u8>>, StorageError> {
    store.get(Namespace::Identity, identity_id)
}

/// Sync resume cursor for a peer (answers.md §35). Key = peer device id (32 bytes).
pub fn put_sync_cursor(
    store: &mut dyn KvStore,
    peer_device_id: &[u8; 32],
    cursor_bytes: &[u8],
) -> Result<(), StorageError> {
    store.put(Namespace::Cursors, peer_device_id, cursor_bytes)
}

/// Load sync resume cursor for a peer.
pub fn get_sync_cursor(
    store: &dyn KvStore,
    peer_device_id: &[u8; 32],
) -> Result<Option<Vec<u8>>, StorageError> {
    store.get(Namespace::Cursors, peer_device_id)
}

/// Minimal blob store keyed by content id (legacy helper).
#[derive(Default, Debug)]
pub struct MemoryBlobStore {
    blobs: HashMap<[u8; 32], Vec<u8>>,
}

impl MemoryBlobStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&mut self, cid: Cid, bytes: Vec<u8>) {
        self.blobs.insert(cid.0, bytes);
    }

    pub fn get(&self, cid: &Cid) -> Option<&[u8]> {
        self.blobs.get(&cid.0).map(|v| v.as_slice())
    }

    pub fn contains(&self, cid: &Cid) -> bool {
        self.blobs.contains_key(&cid.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rooms_proto::{encode_identity_document_v1, DeviceRecord, IdentityDocument};

    #[test]
    fn round_trip_blob() {
        let mut store = MemoryBlobStore::new();
        let data = b"sealed-blob".to_vec();
        let cid = Cid::from_canonical_bytes(&data);
        store.put(cid, data.clone());
        assert_eq!(store.get(&cid), Some(data.as_slice()));
        assert!(store.contains(&cid));
    }

    #[test]
    fn memory_kv_identity_roundtrip() {
        let doc = IdentityDocument {
            identity_id: [0x11; 32],
            master_pubkey: [0x22; 32],
            devices: vec![DeviceRecord {
                device_id: [0x33; 32],
                signing_pubkey: [0x44; 32],
                cross_sig: vec![0x55; 64],
                revoked_at: None,
            }],
            safety_number_material: vec![],
        };
        let bytes = encode_identity_document_v1(&doc).unwrap();
        let mut store = MemoryKvStore::new();
        put_identity_document(&mut store, &doc.identity_id, &bytes).unwrap();
        let got = get_identity_document(&store, &doc.identity_id)
            .unwrap()
            .expect("blob");
        assert_eq!(got, bytes);
    }

    #[test]
    fn sled_kv_identity_roundtrip() {
        let dir = std::env::temp_dir().join(format!("rooms-storage-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut store = SledKvStore::open(&dir).expect("open sled");
        let id = [0xAB; 32];
        let blob = b"identity-doc-bytes".to_vec();
        put_identity_document(&mut store, &id, &blob).unwrap();
        let got = get_identity_document(&store, &id).unwrap().unwrap();
        assert_eq!(got, blob);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
