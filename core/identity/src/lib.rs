//! Identity and device key types for Decentralized Encrypted Rooms.
//!
//! **Invariant:** identity ≠ device. A master identity key cross-signs per-device
//! signing keys. Compromised devices are revoked; forward secrecy limits future
//! damage only (architecture §4.1, SRS `FR-ID-*`, `docs/protocol/identity.md`).
//!
//! Phase 1: generate master + device ed25519 keypairs, derive ids, build and
//! verify an [`IdentityDocument`]. Secret export is an **opaque blob** for
//! Android Keystore wrapping (see `docs/android-keystore-plan.md`). **Never log
//! secret material.** No custom crypto protocols.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use rooms_proto::{
    decode_identity_document_v1, encode_device_cross_sign_bind, encode_identity_document_v1,
    encode_safety_number_material, DeviceRecord, IdentityDocument,
};
use std::collections::HashMap;
use std::fmt;

/// Stable user id: `BLAKE3(master_identity_public_key)` (identity.md §2.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct IdentityId(pub [u8; 32]);

impl IdentityId {
    /// Derive [`IdentityId`] from a master ed25519 verifying key.
    pub fn from_master_verifying_key(master: &VerifyingKey) -> Self {
        let hash = blake3::hash(master.as_bytes());
        Self(*hash.as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }
}

/// Per-installation device identifier: `BLAKE3(device_signing_public_key)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DeviceId(pub [u8; 32]);

impl DeviceId {
    pub fn from_device_verifying_key(device: &VerifyingKey) -> Self {
        let hash = blake3::hash(device.as_bytes());
        Self(*hash.as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }
}

/// Master identity verifying key (rarely used for day-to-day signing).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MasterIdentityPublicKey(pub VerifyingKey);

impl MasterIdentityPublicKey {
    pub fn identity_id(&self) -> IdentityId {
        IdentityId::from_master_verifying_key(&self.0)
    }
}

/// Per-device signing verifying key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceSigningPublicKey(pub VerifyingKey);

impl DeviceSigningPublicKey {
    pub fn device_id(&self) -> DeviceId {
        DeviceId::from_device_verifying_key(&self.0)
    }
}

/// Public halves of an identity (no secrets).
#[derive(Clone, Debug)]
pub struct IdentityKeyMaterial {
    pub master_public: MasterIdentityPublicKey,
    pub device_public: DeviceSigningPublicKey,
}

impl IdentityKeyMaterial {
    pub fn identity_id(&self) -> IdentityId {
        self.master_public.identity_id()
    }

    pub fn device_id(&self) -> DeviceId {
        self.device_public.device_id()
    }

    /// Canonical bytes the master key should sign to bind this device.
    pub fn cross_sign_bind_bytes(&self) -> Vec<u8> {
        encode_device_cross_sign_bind(
            self.identity_id().as_bytes(),
            self.device_id().as_bytes(),
            self.device_public.0.as_bytes(),
        )
    }
}

/// Freshly generated identity: master + first device + cross-signed document.
///
/// Secret key material is held in memory only until Keystore integration lands.
pub struct GeneratedIdentity {
    pub master: SigningKey,
    pub device: SigningKey,
    pub document: IdentityDocument,
}

impl GeneratedIdentity {
    pub fn identity_id(&self) -> IdentityId {
        IdentityId(self.document.identity_id)
    }

    pub fn device_id(&self) -> DeviceId {
        DeviceId::from_device_verifying_key(&self.device.verifying_key())
    }

    pub fn public_material(&self) -> IdentityKeyMaterial {
        IdentityKeyMaterial {
            master_public: MasterIdentityPublicKey(self.master.verifying_key()),
            device_public: DeviceSigningPublicKey(self.device.verifying_key()),
        }
    }

    /// Canonical document bytes for persistence (`rooms/IdentityDocument/v1`).
    pub fn document_bytes(&self) -> Result<Vec<u8>, rooms_proto::CodecError> {
        encode_identity_document_v1(&self.document)
    }
}

impl fmt::Debug for GeneratedIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedIdentity")
            .field("identity_id", &self.identity_id().to_hex())
            .field("device_id", &self.device_id().to_hex())
            .field("document_devices", &self.document.devices.len())
            .finish_non_exhaustive()
    }
}

/// Errors verifying identity documents / cross-signs / secret blobs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    BadMasterKey,
    BadDeviceKey,
    BadSignature,
    IdentityMismatch,
    DeviceMismatch,
    MissingDevice,
    BadSecretBlob,
    Codec(rooms_proto::CodecError),
}

/// Generate master + device keypairs, derive ids, cross-sign, build document.
pub fn create_identity<R: RngCore + CryptoRng>(rng: &mut R) -> GeneratedIdentity {
    let master = SigningKey::generate(rng);
    let device = SigningKey::generate(rng);
    build_identity(master, device)
}

/// Generate using the OS CSPRNG.
pub fn create_identity_osrng() -> GeneratedIdentity {
    create_identity(&mut OsRng)
}

fn build_identity(master: SigningKey, device: SigningKey) -> GeneratedIdentity {
    let master_vk = master.verifying_key();
    let device_vk = device.verifying_key();
    let identity_id = IdentityId::from_master_verifying_key(&master_vk);
    let device_id = DeviceId::from_device_verifying_key(&device_vk);

    let bind = encode_device_cross_sign_bind(
        identity_id.as_bytes(),
        device_id.as_bytes(),
        device_vk.as_bytes(),
    );
    let cross_sig = master.sign(&bind).to_bytes().to_vec();

    let document = IdentityDocument {
        identity_id: identity_id.0,
        master_pubkey: *master_vk.as_bytes(),
        devices: vec![DeviceRecord {
            device_id: device_id.0,
            signing_pubkey: *device_vk.as_bytes(),
            cross_sig,
            revoked_at: None,
        }],
        safety_number_material: Vec::new(),
    };

    GeneratedIdentity {
        master,
        device,
        document,
    }
}

/// Verify every device cross-sign in a document against the master pubkey.
pub fn verify_identity_document(doc: &IdentityDocument) -> Result<(), IdentityError> {
    let master =
        VerifyingKey::from_bytes(&doc.master_pubkey).map_err(|_| IdentityError::BadMasterKey)?;
    let expected_id = IdentityId::from_master_verifying_key(&master);
    if expected_id.0 != doc.identity_id {
        return Err(IdentityError::IdentityMismatch);
    }
    if doc.devices.is_empty() {
        return Err(IdentityError::MissingDevice);
    }
    for device in &doc.devices {
        verify_device_cross_sign(doc, device, &master)?;
    }
    Ok(())
}

fn verify_device_cross_sign(
    doc: &IdentityDocument,
    device: &DeviceRecord,
    master: &VerifyingKey,
) -> Result<(), IdentityError> {
    let device_vk = VerifyingKey::from_bytes(&device.signing_pubkey)
        .map_err(|_| IdentityError::BadDeviceKey)?;
    let expected_device_id = DeviceId::from_device_verifying_key(&device_vk);
    if expected_device_id.0 != device.device_id {
        return Err(IdentityError::DeviceMismatch);
    }
    if device.cross_sig.len() != 64 {
        return Err(IdentityError::BadSignature);
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&device.cross_sig);
    let sig = Signature::from_bytes(&sig_bytes);
    let bind =
        encode_device_cross_sign_bind(&doc.identity_id, &device.device_id, &device.signing_pubkey);
    master
        .verify(&bind, &sig)
        .map_err(|_| IdentityError::BadSignature)?;
    Ok(())
}

/// Reload a document from canonical bytes and verify cross-signs.
pub fn load_verified_document(bytes: &[u8]) -> Result<IdentityDocument, IdentityError> {
    let doc = decode_identity_document_v1(bytes).map_err(IdentityError::Codec)?;
    verify_identity_document(&doc)?;
    Ok(doc)
}

/// Derive `identity_id` hex from a 32-byte master verifying key.
pub fn identity_id_hex_from_master_pubkey(
    master_pubkey: &[u8; 32],
) -> Result<String, IdentityError> {
    let vk = VerifyingKey::from_bytes(master_pubkey).map_err(|_| IdentityError::BadMasterKey)?;
    Ok(IdentityId::from_master_verifying_key(&vk).to_hex())
}

/// Safety-number material for a pair of identities (order-independent).
pub fn safety_number_material(a: &IdentityId, b: &IdentityId) -> Vec<u8> {
    encode_safety_number_material(a.as_bytes(), b.as_bytes())
}

/// Try to parse a 32-byte ed25519 verifying key.
pub fn verifying_key_from_bytes(
    bytes: &[u8; 32],
) -> Result<VerifyingKey, ed25519_dalek::SignatureError> {
    VerifyingKey::from_bytes(bytes)
}

/// In-memory identity document store (persist-ready API; swap for KvStore later).
#[derive(Default, Debug)]
pub struct MemoryIdentityStore {
    docs: HashMap<[u8; 32], Vec<u8>>,
}

impl MemoryIdentityStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put_document(&mut self, generated: &GeneratedIdentity) -> Result<(), IdentityError> {
        let bytes = generated.document_bytes().map_err(IdentityError::Codec)?;
        self.docs.insert(generated.document.identity_id, bytes);
        Ok(())
    }

    pub fn get_document(
        &self,
        identity_id: &IdentityId,
    ) -> Result<Option<IdentityDocument>, IdentityError> {
        match self.docs.get(&identity_id.0) {
            None => Ok(None),
            Some(bytes) => Ok(Some(load_verified_document(bytes)?)),
        }
    }
}

/// Opaque identity secret package for Keystore wrap / unwrap (API 26+).
///
/// Layout (versioned; **not** encrypted here — Android AES/GCM wrap is external):
/// ```text
/// version                u8 = 1
/// master_signing_seed    32
/// device_signing_seed    32
/// document_len           u32 LE
/// document_bytes         document_len  // IdentityDocument v1 canonical
/// ```
///
/// Debug / Display intentionally omit bytes. Do not log this type.
#[derive(Clone)]
pub struct IdentitySecretBlob {
    bytes: Vec<u8>,
}

impl IdentitySecretBlob {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl fmt::Debug for IdentitySecretBlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentitySecretBlob")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

const IDENTITY_SECRET_BLOB_V1: u8 = 1;

/// Export master + device seeds and document for Keystore wrapping.
///
/// The returned blob is still **plaintext secrets** until Android wraps it.
pub fn export_identity_secret_blob(
    generated: &GeneratedIdentity,
) -> Result<IdentitySecretBlob, IdentityError> {
    let doc_bytes = generated.document_bytes().map_err(IdentityError::Codec)?;
    let mut buf = Vec::with_capacity(1 + 64 + 4 + doc_bytes.len());
    buf.push(IDENTITY_SECRET_BLOB_V1);
    buf.extend_from_slice(generated.master.to_bytes().as_slice());
    buf.extend_from_slice(generated.device.to_bytes().as_slice());
    let len = u32::try_from(doc_bytes.len()).map_err(|_| IdentityError::BadSecretBlob)?;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&doc_bytes);
    Ok(IdentitySecretBlob { bytes: buf })
}

/// Import a previously exported secret blob and re-verify the document.
pub fn import_identity_secret_blob(
    blob: &IdentitySecretBlob,
) -> Result<GeneratedIdentity, IdentityError> {
    let bytes = blob.as_bytes();
    if bytes.len() < 1 + 32 + 32 + 4 {
        return Err(IdentityError::BadSecretBlob);
    }
    if bytes[0] != IDENTITY_SECRET_BLOB_V1 {
        return Err(IdentityError::BadSecretBlob);
    }
    let mut master_seed = [0u8; 32];
    master_seed.copy_from_slice(&bytes[1..33]);
    let mut device_seed = [0u8; 32];
    device_seed.copy_from_slice(&bytes[33..65]);
    let doc_len = u32::from_le_bytes([bytes[65], bytes[66], bytes[67], bytes[68]]) as usize;
    if bytes.len() != 69 + doc_len {
        return Err(IdentityError::BadSecretBlob);
    }
    let document = load_verified_document(&bytes[69..])?;
    let master = SigningKey::from_bytes(&master_seed);
    let device = SigningKey::from_bytes(&device_seed);
    if master.verifying_key().as_bytes() != &document.master_pubkey {
        return Err(IdentityError::IdentityMismatch);
    }
    let expected_device = DeviceId::from_device_verifying_key(&device.verifying_key());
    if document.devices.is_empty() || document.devices[0].device_id != expected_device.0 {
        return Err(IdentityError::DeviceMismatch);
    }
    Ok(GeneratedIdentity {
        master,
        device,
        document,
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn identity_id_differs_from_device_id() {
        let master = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        let device = SigningKey::from_bytes(&[2u8; 32]).verifying_key();

        let material = IdentityKeyMaterial {
            master_public: MasterIdentityPublicKey(master),
            device_public: DeviceSigningPublicKey(device),
        };

        assert_ne!(material.identity_id().0, material.device_id().0);
        assert_eq!(
            material.identity_id(),
            IdentityId::from_master_verifying_key(&master)
        );
        let bind = material.cross_sign_bind_bytes();
        assert!(bind.starts_with(b"rooms/DeviceCrossSign/v1\0"));
    }

    #[test]
    fn safety_number_stable() {
        let a = IdentityId([1u8; 32]);
        let b = IdentityId([9u8; 32]);
        assert_eq!(
            safety_number_material(&a, &b),
            safety_number_material(&b, &a)
        );
    }

    #[test]
    fn generate_document_verify_cross_sign() {
        let mut rng = StdRng::seed_from_u64(42);
        let generated = create_identity(&mut rng);
        verify_identity_document(&generated.document).expect("cross-sign ok");

        let bytes = generated.document_bytes().unwrap();
        let reloaded = load_verified_document(&bytes).unwrap();
        assert_eq!(reloaded.identity_id, generated.document.identity_id);
        assert_eq!(reloaded.devices.len(), 1);

        let hex = identity_id_hex_from_master_pubkey(&generated.document.master_pubkey).unwrap();
        assert_eq!(hex, generated.identity_id().to_hex());
        assert_eq!(hex.len(), 64);
    }

    #[test]
    fn tampered_cross_sign_fails() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut generated = create_identity(&mut rng);
        generated.document.devices[0].cross_sig[0] ^= 0xff;
        assert_eq!(
            verify_identity_document(&generated.document),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn memory_store_round_trip() {
        let mut rng = StdRng::seed_from_u64(99);
        let generated = create_identity(&mut rng);
        let mut store = MemoryIdentityStore::new();
        store.put_document(&generated).unwrap();
        let got = store
            .get_document(&generated.identity_id())
            .unwrap()
            .expect("present");
        assert_eq!(got, generated.document);
    }

    #[test]
    fn secret_blob_round_trip_and_debug_hides_secrets() {
        let mut rng = StdRng::seed_from_u64(55);
        let generated = create_identity(&mut rng);
        let blob = export_identity_secret_blob(&generated).unwrap();
        let debug = format!("{blob:?}");
        assert!(debug.contains("IdentitySecretBlob"));
        assert!(!debug.contains(&generated.identity_id().to_hex()));
        // Seeds must not appear in Debug
        assert!(!debug.contains("master"));
        let restored = import_identity_secret_blob(&blob).unwrap();
        assert_eq!(restored.identity_id(), generated.identity_id());
        assert_eq!(restored.device_id(), generated.device_id());
        assert_eq!(restored.document, generated.document);
        verify_identity_document(&restored.document).unwrap();
    }
}
