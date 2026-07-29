//! BLE mesh text-first sync frames (WBS 4.3.* MVP).
//!
//! Carries **already-sealed** payloads only — no novel crypto over BLE.
//! Enforces [`BandwidthClass::Low`] size limits (headers/text first; no media).

use crate::{BandwidthClass, SyncPolicy};

/// Magic for BLE mesh frames (`DRBM` = Decentralized Rooms BLE Mesh).
pub const BLE_FRAME_MAGIC: &[u8; 4] = b"DRBM";
/// Frame format version (v1 = sealed only; v2 = optional app routing header).
pub const BLE_FRAME_VERSION: u8 = 1;
/// BLE mesh frame with app routing header (answers.md §59 multiplexing).
pub const BLE_FRAME_VERSION_V2: u8 = 2;

/// Max sealed payload on Low bandwidth (BLE ATT MTU budget after headers).
/// Text-first sealed blob budget. Raised to fit typical libsignal sealed text
/// (~1–2 KiB) while staying well under Wi‑Fi Direct High.
pub const BLE_MAX_SEALED_PAYLOAD: usize = 4096;

/// Rotating ephemeral proximity id length (16 random bytes).
pub const EPHEMERAL_ID_LEN: usize = 16;

/// App routing header length for v2 frames (dest_id || room_id || type || cid).
pub const BLE_APP_HEADER_LEN: usize = 32 + 32 + 1 + 32;

/// Object type byte in BLE app header (mirrors SyncObjectType where possible).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BleAppObjectType {
    OpaqueSealed = 0,
    MessageEvent = 1,
    MlsWelcome = 2,
    MlsCommit = 3,
    KeyPackageBind = 4,
}

impl BleAppObjectType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::OpaqueSealed),
            1 => Some(Self::MessageEvent),
            2 => Some(Self::MlsWelcome),
            3 => Some(Self::MlsCommit),
            4 => Some(Self::KeyPackageBind),
            _ => None,
        }
    }
}

/// Cleartext routing header so multiple chats share one BLE path (§59).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BleAppHeader {
    pub dest_identity_id: [u8; 32],
    pub room_id: [u8; 32],
    pub object_type: BleAppObjectType,
    pub cid: [u8; 32],
}

impl BleAppHeader {
    pub fn encode(&self) -> [u8; BLE_APP_HEADER_LEN] {
        let mut out = [0u8; BLE_APP_HEADER_LEN];
        out[0..32].copy_from_slice(&self.dest_identity_id);
        out[32..64].copy_from_slice(&self.room_id);
        out[64] = self.object_type as u8;
        out[65..97].copy_from_slice(&self.cid);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, BleMeshError> {
        if bytes.len() < BLE_APP_HEADER_LEN {
            return Err(BleMeshError::Truncated);
        }
        let mut dest_identity_id = [0u8; 32];
        let mut room_id = [0u8; 32];
        let mut cid = [0u8; 32];
        dest_identity_id.copy_from_slice(&bytes[0..32]);
        room_id.copy_from_slice(&bytes[32..64]);
        let object_type = BleAppObjectType::from_u8(bytes[64]).ok_or(BleMeshError::BadVersion)?;
        cid.copy_from_slice(&bytes[65..97]);
        Ok(Self {
            dest_identity_id,
            room_id,
            object_type,
            cid,
        })
    }
}

/// Errors for BLE mesh framing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BleMeshError {
    BadMagic,
    BadVersion,
    PayloadTooLarge,
    Truncated,
    MediaForbidden,
}

/// Small sealed sync / text frame for proximity exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BleSealedFrame {
    /// Rotating ephemeral advertiser id (not a long-term identity).
    pub ephemeral_id: [u8; EPHEMERAL_ID_LEN],
    /// Already-sealed ciphertext (MLS / libsignal / opaque MessageEvent ct).
    pub sealed_payload: Vec<u8>,
    /// Optional v2 app routing header (multiplex chats/rooms on one radio).
    pub app_header: Option<BleAppHeader>,
}

impl BleSealedFrame {
    /// Encode under Low bandwidth policy; rejects oversized / media-class abuse.
    /// Uses v2 when `app_header` is set; otherwise v1 (backward compatible).
    pub fn encode(&self) -> Result<Vec<u8>, BleMeshError> {
        let policy = SyncPolicy::for_class(BandwidthClass::Low);
        if !policy.text_first {
            return Err(BleMeshError::MediaForbidden);
        }
        if self.sealed_payload.len() > BLE_MAX_SEALED_PAYLOAD {
            return Err(BleMeshError::PayloadTooLarge);
        }
        if self.sealed_payload.len() > policy.max_have_objects.saturating_mul(64) {
            return Err(BleMeshError::PayloadTooLarge);
        }
        let version = if self.app_header.is_some() {
            BLE_FRAME_VERSION_V2
        } else {
            BLE_FRAME_VERSION
        };
        let header_extra = if self.app_header.is_some() {
            BLE_APP_HEADER_LEN
        } else {
            0
        };
        let mut out = Vec::with_capacity(
            4 + 1 + EPHEMERAL_ID_LEN + header_extra + 2 + self.sealed_payload.len(),
        );
        out.extend_from_slice(BLE_FRAME_MAGIC);
        out.push(version);
        out.extend_from_slice(&self.ephemeral_id);
        if let Some(h) = &self.app_header {
            out.extend_from_slice(&h.encode());
        }
        out.extend_from_slice(&(self.sealed_payload.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.sealed_payload);
        Ok(out)
    }

    /// Decode a BLE mesh frame (fail-closed). Accepts v1 and v2.
    pub fn decode(bytes: &[u8]) -> Result<Self, BleMeshError> {
        if bytes.len() < 4 + 1 + EPHEMERAL_ID_LEN + 2 {
            return Err(BleMeshError::Truncated);
        }
        if &bytes[0..4] != BLE_FRAME_MAGIC {
            return Err(BleMeshError::BadMagic);
        }
        let version = bytes[4];
        if version != BLE_FRAME_VERSION && version != BLE_FRAME_VERSION_V2 {
            return Err(BleMeshError::BadVersion);
        }
        let mut ephemeral_id = [0u8; EPHEMERAL_ID_LEN];
        ephemeral_id.copy_from_slice(&bytes[5..5 + EPHEMERAL_ID_LEN]);
        let mut off = 5 + EPHEMERAL_ID_LEN;
        let app_header = if version == BLE_FRAME_VERSION_V2 {
            let h = BleAppHeader::decode(&bytes[off..])?;
            off += BLE_APP_HEADER_LEN;
            Some(h)
        } else {
            None
        };
        if bytes.len() < off + 2 {
            return Err(BleMeshError::Truncated);
        }
        let len = u16::from_le_bytes([bytes[off], bytes[off + 1]]) as usize;
        let start = off + 2;
        if len > BLE_MAX_SEALED_PAYLOAD || start + len > bytes.len() {
            return Err(BleMeshError::Truncated);
        }
        Ok(Self {
            ephemeral_id,
            sealed_payload: bytes[start..start + len].to_vec(),
            app_header,
        })
    }
}

/// Store-and-forward carrier: hold sealed objects keyed by CID-like tip.
///
/// Does not decrypt. A third device can ferry sealed blobs under
/// [`BandwidthClass::Low`] / [`SyncPolicy`] budgets (FIFO when full).
#[derive(Clone, Debug, Default)]
pub struct SealedCarrierStore {
    /// tip_hex → sealed payload
    items: Vec<(String, Vec<u8>)>,
}

impl SealedCarrierStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Max items allowed under Low bandwidth sync policy.
    pub fn low_budget_capacity() -> usize {
        SyncPolicy::for_class(BandwidthClass::Low).max_have_objects
    }

    /// Accept a sealed object if within Low bandwidth size.
    pub fn put_sealed(&mut self, tip_hex: String, sealed: Vec<u8>) -> Result<(), BleMeshError> {
        if sealed.len() > BLE_MAX_SEALED_PAYLOAD {
            return Err(BleMeshError::PayloadTooLarge);
        }
        // Dedup by tip — keep newest sealed bytes.
        if let Some(pos) = self.items.iter().position(|(t, _)| t == &tip_hex) {
            self.items.remove(pos);
        }
        if self.items.len() >= Self::low_budget_capacity() {
            // Drop oldest (FIFO) to stay within Low policy budget.
            self.items.remove(0);
        }
        self.items.push((tip_hex, sealed));
        Ok(())
    }

    /// Pop the oldest sealed object for proximity forward.
    pub fn take_one(&mut self) -> Option<(String, Vec<u8>)> {
        if self.items.is_empty() {
            None
        } else {
            Some(self.items.remove(0))
        }
    }

    pub fn take_all(&mut self) -> Vec<(String, Vec<u8>)> {
        std::mem::take(&mut self.items)
    }

    pub fn peek(&self) -> &[(String, Vec<u8>)] {
        &self.items
    }

    /// True when Low policy forbids media and prefers text (BLE path).
    pub fn policy_allows_ble_text() -> bool {
        let p = SyncPolicy::for_class(BandwidthClass::Low);
        p.text_first && !p.include_media
    }
}

/// Rotate ephemeral id: returns a new 16-byte id (caller supplies CSPRNG bytes).
pub fn rotate_ephemeral_id(random_16: [u8; EPHEMERAL_ID_LEN]) -> [u8; EPHEMERAL_ID_LEN] {
    random_16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip() {
        let frame = BleSealedFrame {
            ephemeral_id: [0xAB; 16],
            sealed_payload: b"already-sealed-libsignal-or-mls".to_vec(),
            app_header: None,
        };
        let enc = frame.encode().unwrap();
        let dec = BleSealedFrame::decode(&enc).unwrap();
        assert_eq!(dec, frame);
    }

    #[test]
    fn frame_v2_app_header_round_trip() {
        let header = BleAppHeader {
            dest_identity_id: [0x11; 32],
            room_id: [0x22; 32],
            object_type: BleAppObjectType::MessageEvent,
            cid: [0x33; 32],
        };
        let frame = BleSealedFrame {
            ephemeral_id: [0xCD; 16],
            sealed_payload: b"sealed".to_vec(),
            app_header: Some(header.clone()),
        };
        let enc = frame.encode().unwrap();
        assert_eq!(enc[4], BLE_FRAME_VERSION_V2);
        let dec = BleSealedFrame::decode(&enc).unwrap();
        assert_eq!(dec.app_header, Some(header));
        assert_eq!(dec.sealed_payload, b"sealed");
    }

    #[test]
    fn rejects_oversized_payload() {
        let frame = BleSealedFrame {
            ephemeral_id: [1; 16],
            sealed_payload: vec![0u8; BLE_MAX_SEALED_PAYLOAD + 1],
            app_header: None,
        };
        assert_eq!(frame.encode(), Err(BleMeshError::PayloadTooLarge));
    }

    #[test]
    fn carrier_fifo_under_low_budget() {
        let mut store = SealedCarrierStore::new();
        let max = SyncPolicy::for_class(BandwidthClass::Low).max_have_objects;
        for i in 0..(max + 3) {
            store
                .put_sealed(format!("{i:02x}"), vec![i as u8; 8])
                .unwrap();
        }
        assert_eq!(store.len(), max);
        assert_eq!(store.peek()[0].0, format!("{:02x}", 3));
    }

    #[test]
    fn low_policy_is_text_first_no_media() {
        let p = SyncPolicy::for_class(BandwidthClass::Low);
        assert!(p.text_first);
        assert!(!p.include_media);
        assert!(SealedCarrierStore::policy_allows_ble_text());
    }

    #[test]
    fn carrier_take_one_fifo_and_dedup() {
        let mut store = SealedCarrierStore::new();
        store.put_sealed("aa".into(), vec![1]).unwrap();
        store.put_sealed("bb".into(), vec![2]).unwrap();
        store.put_sealed("aa".into(), vec![9]).unwrap();
        let (tip, sealed) = store.take_one().unwrap();
        assert_eq!(tip, "bb");
        assert_eq!(sealed, vec![2]);
        let (tip2, sealed2) = store.take_one().unwrap();
        assert_eq!(tip2, "aa");
        assert_eq!(sealed2, vec![9]);
        assert!(store.take_one().is_none());
    }
}
