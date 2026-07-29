//! Wi‑Fi Direct bulk sealed transfer frames (WBS 4.3.4 MVP).
//!
//! Carries **already-sealed** payloads only — no novel crypto on the radio.
//! Uses [`BandwidthClass::High`] budgets (media-sized sealed blobs allowed).
//! Host / CI simulation lives here; Android `WifiDirectBulkController` speaks
//! the same wire format over a P2P socket.

use crate::{BandwidthClass, SyncPolicy};

/// Magic for Wi‑Fi Direct bulk frames (`DRWD`).
pub const WD_FRAME_MAGIC: &[u8; 4] = b"DRWD";
/// Frame format version.
pub const WD_FRAME_VERSION: u8 = 1;

/// Max sealed payload on High bandwidth (media-class sealed blobs).
pub const WD_MAX_SEALED_PAYLOAD: usize = 256 * 1024;

/// Session / group tip label length (hex tip or opaque id, UTF-8 capped).
pub const WD_TIP_MAX_LEN: usize = 64;

/// Errors for Wi‑Fi Direct bulk framing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WifiDirectError {
    BadMagic,
    BadVersion,
    PayloadTooLarge,
    Truncated,
    MediaForbidden,
    BadTip,
}

/// Bulk sealed frame for proximity Wi‑Fi Direct (or host socket simulation).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WifiDirectSealedFrame {
    /// Opaque tip / object id (not decrypted; carrier-friendly).
    pub tip_hex: String,
    /// Already-sealed ciphertext (MLS / libsignal / opaque MessageEvent ct).
    pub sealed_payload: Vec<u8>,
}

impl WifiDirectSealedFrame {
    /// Encode under High bandwidth policy (media allowed; large sealed OK).
    pub fn encode(&self) -> Result<Vec<u8>, WifiDirectError> {
        let policy = SyncPolicy::for_class(BandwidthClass::High);
        if !policy.include_media && self.sealed_payload.len() > 4_096 {
            return Err(WifiDirectError::MediaForbidden);
        }
        if self.sealed_payload.len() > WD_MAX_SEALED_PAYLOAD {
            return Err(WifiDirectError::PayloadTooLarge);
        }
        if self.tip_hex.is_empty() || self.tip_hex.len() > WD_TIP_MAX_LEN {
            return Err(WifiDirectError::BadTip);
        }
        if !self.tip_hex.is_ascii() {
            return Err(WifiDirectError::BadTip);
        }
        let tip = self.tip_hex.as_bytes();
        let mut out = Vec::with_capacity(4 + 1 + 1 + tip.len() + 4 + self.sealed_payload.len());
        out.extend_from_slice(WD_FRAME_MAGIC);
        out.push(WD_FRAME_VERSION);
        out.push(tip.len() as u8);
        out.extend_from_slice(tip);
        out.extend_from_slice(&(self.sealed_payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.sealed_payload);
        Ok(out)
    }

    /// Decode a Wi‑Fi Direct bulk frame (fail-closed).
    pub fn decode(bytes: &[u8]) -> Result<Self, WifiDirectError> {
        if bytes.len() < 4 + 1 + 1 + 4 {
            return Err(WifiDirectError::Truncated);
        }
        if &bytes[0..4] != WD_FRAME_MAGIC {
            return Err(WifiDirectError::BadMagic);
        }
        if bytes[4] != WD_FRAME_VERSION {
            return Err(WifiDirectError::BadVersion);
        }
        let tip_len = bytes[5] as usize;
        if tip_len == 0 || tip_len > WD_TIP_MAX_LEN || 6 + tip_len + 4 > bytes.len() {
            return Err(WifiDirectError::Truncated);
        }
        let tip_hex = std::str::from_utf8(&bytes[6..6 + tip_len])
            .map_err(|_| WifiDirectError::BadTip)?
            .to_string();
        let len_off = 6 + tip_len;
        let sealed_len =
            u32::from_le_bytes(bytes[len_off..len_off + 4].try_into().unwrap()) as usize;
        let start = len_off + 4;
        if sealed_len > WD_MAX_SEALED_PAYLOAD || start + sealed_len > bytes.len() {
            return Err(WifiDirectError::Truncated);
        }
        Ok(Self {
            tip_hex,
            sealed_payload: bytes[start..start + sealed_len].to_vec(),
        })
    }
}

/// Host / CI simulation: splice two in-memory buffers as if over Wi‑Fi Direct.
///
/// Returns the decoded sealed payload the receiver would obtain.
pub fn simulate_bulk_transfer(
    sender_frame: &WifiDirectSealedFrame,
) -> Result<Vec<u8>, WifiDirectError> {
    let wire = sender_frame.encode()?;
    let decoded = WifiDirectSealedFrame::decode(&wire)?;
    Ok(decoded.sealed_payload)
}

/// True when High policy allows media-class sealed blobs on Wi‑Fi Direct.
pub fn policy_allows_wifi_direct_bulk() -> bool {
    let p = SyncPolicy::for_class(BandwidthClass::High);
    p.include_media && !p.text_first
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip_media_sized() {
        let sealed = vec![0xA5u8; 8_192];
        let frame = WifiDirectSealedFrame {
            tip_hex: "aabbccddeeff00112233445566778899".into(),
            sealed_payload: sealed.clone(),
        };
        let enc = frame.encode().unwrap();
        let dec = WifiDirectSealedFrame::decode(&enc).unwrap();
        assert_eq!(dec, frame);
        assert_eq!(simulate_bulk_transfer(&frame).unwrap(), sealed);
    }

    #[test]
    fn rejects_oversized_payload() {
        let frame = WifiDirectSealedFrame {
            tip_hex: "aa".into(),
            sealed_payload: vec![0u8; WD_MAX_SEALED_PAYLOAD + 1],
        };
        assert_eq!(frame.encode(), Err(WifiDirectError::PayloadTooLarge));
    }

    #[test]
    fn rejects_bad_tip() {
        let frame = WifiDirectSealedFrame {
            tip_hex: String::new(),
            sealed_payload: vec![1, 2, 3],
        };
        assert_eq!(frame.encode(), Err(WifiDirectError::BadTip));
    }

    #[test]
    fn high_policy_allows_media() {
        assert!(policy_allows_wifi_direct_bulk());
        let p = SyncPolicy::for_class(BandwidthClass::High);
        assert!(p.include_media);
        assert!(!p.text_first);
    }

    #[test]
    fn host_sim_rejects_truncated() {
        assert_eq!(
            WifiDirectSealedFrame::decode(b"DR"),
            Err(WifiDirectError::Truncated)
        );
    }
}
