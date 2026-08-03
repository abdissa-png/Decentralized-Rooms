//! Phase 0 learning spikes for Decentralized Encrypted Rooms.
//!
//! Spikes are educational prototypes that feed later specs. Compose Noise /
//! OpenMLS / libsignal libraries — do not invent custom crypto protocols.

pub mod crdt;
pub mod dag_log;
pub mod kademlia;
pub mod libsignal;
pub mod noise;
pub mod openmls;

#[cfg(test)]
mod tests {
    #[test]
    fn spike_modules_link() {
        assert_eq!(crate::noise::SPIKE_NAME, "noise-xx");
        assert_eq!(crate::dag_log::SPIKE_NAME, "dag-log");
        assert_eq!(crate::crdt::SPIKE_NAME, "crdt");
        assert_eq!(crate::kademlia::SPIKE_NAME, "kademlia");
        assert_eq!(crate::openmls::SPIKE_NAME, "openmls");
        assert_eq!(crate::libsignal::SPIKE_NAME, "libsignal");
    }
}
