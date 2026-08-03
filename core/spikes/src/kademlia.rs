//! Spike 2.5 — Minimal Kademlia-style lookup (deterministic, in-process).
//!
//! XOR distance + k-bucket routing table + iterative FIND_NODE among a small
//! set of simulated nodes. **No real UDP in CI** — localhost UDP is flaky under
//! parallel test runners; production discovery will use libp2p Kademlia.
//!
//! # Limits
//! - Fixed `k` (bucket size), no refresh/republish timers
//! - No FIND_VALUE / store, no NAT traversal
//! - Synchronous simulated network (HashMap of nodes), not wire protocol

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};

pub const SPIKE_NAME: &str = "kademlia";
pub const WBS: &str = "2.5";

/// 160-bit node id (SHA1-sized, classic Kademlia); we use 20 bytes of BLAKE3.
pub type NodeId = [u8; 20];

pub const K: usize = 3;
pub const ALPHA: usize = 2;

pub fn node_id_from_bytes(seed: &[u8]) -> NodeId {
    let hash = blake3::hash(seed);
    let mut id = [0u8; 20];
    id.copy_from_slice(&hash.as_bytes()[..20]);
    id
}

pub fn xor_distance(a: &NodeId, b: &NodeId) -> [u8; 20] {
    let mut d = [0u8; 20];
    for i in 0..20 {
        d[i] = a[i] ^ b[i];
    }
    d
}

/// Bucket index: highest bit position of XOR distance (0 = identical, 159 = far).
pub fn bucket_index(local: &NodeId, remote: &NodeId) -> Option<usize> {
    let d = xor_distance(local, remote);
    for (byte_i, byte) in d.iter().enumerate() {
        if *byte != 0 {
            let leading = byte.leading_zeros() as usize;
            return Some(159 - (byte_i * 8 + leading));
        }
    }
    None
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerInfo {
    pub id: NodeId,
}

#[derive(Clone, Debug)]
pub struct RoutingTable {
    local_id: NodeId,
    /// buckets[i] holds up to K peers with bucket_index == i
    buckets: Vec<Vec<PeerInfo>>,
}

impl RoutingTable {
    pub fn new(local_id: NodeId) -> Self {
        Self {
            local_id,
            buckets: vec![Vec::new(); 160],
        }
    }

    pub fn local_id(&self) -> NodeId {
        self.local_id
    }

    pub fn insert(&mut self, peer: PeerInfo) {
        if peer.id == self.local_id {
            return;
        }
        let Some(idx) = bucket_index(&self.local_id, &peer.id) else {
            return;
        };
        let bucket = &mut self.buckets[idx];
        if let Some(pos) = bucket.iter().position(|p| p.id == peer.id) {
            let existing = bucket.remove(pos);
            bucket.push(existing);
            return;
        }
        if bucket.len() < K {
            bucket.push(peer);
        }
        // Spike: drop if full (no ping replacement).
    }

    /// Return up to `count` known peers closest to `target`.
    pub fn closest(&self, target: &NodeId, count: usize) -> Vec<PeerInfo> {
        let mut all: Vec<_> = self.buckets.iter().flatten().cloned().collect();
        all.sort_by_key(|a| xor_distance(&a.id, target));
        all.truncate(count);
        all
    }
}

/// Simulated node answering FIND_NODE from its routing table.
#[derive(Clone, Debug)]
pub struct SimNode {
    pub table: RoutingTable,
}

impl SimNode {
    pub fn new(id: NodeId) -> Self {
        Self {
            table: RoutingTable::new(id),
        }
    }

    pub fn find_node(&self, target: &NodeId) -> Vec<PeerInfo> {
        self.table.closest(target, K)
    }
}

#[derive(Eq, PartialEq)]
struct Candidate {
    dist: [u8; 20],
    id: NodeId,
}

impl Ord for Candidate {
    fn cmp(&self, other: &Self) -> Ordering {
        // Min-heap via reverse distance order.
        other.dist.cmp(&self.dist)
    }
}

impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Iterative FIND_NODE over an in-process network map.
pub fn iterative_find_node(
    network: &HashMap<NodeId, SimNode>,
    start: NodeId,
    target: NodeId,
) -> Vec<NodeId> {
    let Some(starter) = network.get(&start) else {
        return vec![];
    };

    let mut shortlist: BinaryHeap<Candidate> = BinaryHeap::new();
    let mut seen: HashSet<NodeId> = HashSet::new();
    let mut queried: HashSet<NodeId> = HashSet::new();

    for peer in starter.find_node(&target) {
        if seen.insert(peer.id) {
            shortlist.push(Candidate {
                dist: xor_distance(&peer.id, &target),
                id: peer.id,
            });
        }
    }
    // Always consider contacting ourselves if we are the target.
    if start == target {
        return vec![start];
    }

    loop {
        let mut to_query: Vec<NodeId> = Vec::new();
        let snapshot: Vec<_> = shortlist.iter().map(|c| c.id).collect();
        for id in snapshot {
            if queried.contains(&id) {
                continue;
            }
            to_query.push(id);
            if to_query.len() >= ALPHA {
                break;
            }
        }
        if to_query.is_empty() {
            break;
        }

        let mut progressed = false;
        for id in to_query {
            queried.insert(id);
            let Some(node) = network.get(&id) else {
                continue;
            };
            for peer in node.find_node(&target) {
                if seen.insert(peer.id) {
                    shortlist.push(Candidate {
                        dist: xor_distance(&peer.id, &target),
                        id: peer.id,
                    });
                    progressed = true;
                }
            }
            // If the contacted node *is* the target, we're done discovering it.
            if id == target {
                progressed = true;
            }
        }
        if !progressed {
            // Still may have unqueried closer nodes; continue until none left.
            let remaining = shortlist.iter().any(|c| !queried.contains(&c.id));
            if !remaining {
                break;
            }
        }
    }

    let mut result: Vec<(NodeId, [u8; 20])> = seen
        .into_iter()
        .map(|id| (id, xor_distance(&id, &target)))
        .collect();
    result.sort_by_key(|a| a.1);
    result.into_iter().take(K).map(|(id, _)| id).collect()
}

/// Build a small fully-connected (via routing inserts) simulated swarm.
pub fn build_swarm(seeds: &[&[u8]]) -> HashMap<NodeId, SimNode> {
    let ids: Vec<NodeId> = seeds.iter().map(|s| node_id_from_bytes(s)).collect();
    let mut network: HashMap<NodeId, SimNode> =
        ids.iter().map(|&id| (id, SimNode::new(id))).collect();

    // Each node learns about every other (toy bootstrap).
    let all_peers: Vec<PeerInfo> = ids.iter().map(|&id| PeerInfo { id }).collect();
    for node in network.values_mut() {
        for peer in &all_peers {
            node.table.insert(peer.clone());
        }
    }
    network
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_distance_identity() {
        let a = node_id_from_bytes(b"a");
        assert_eq!(xor_distance(&a, &a), [0u8; 20]);
    }

    #[test]
    fn bucket_index_far_vs_near() {
        let local = [0u8; 20];
        let mut near = [0u8; 20];
        near[19] = 1;
        let mut far = [0u8; 20];
        far[0] = 0x80;
        assert!(bucket_index(&local, &near).unwrap() < bucket_index(&local, &far).unwrap());
    }

    #[test]
    fn find_node_among_five_local_nodes() {
        let network = build_swarm(&[b"n0", b"n1", b"n2", b"n3", b"n4"]);
        let ids: Vec<_> = network.keys().copied().collect();
        let start = ids[0];
        let target = ids[3];

        let closest = iterative_find_node(&network, start, target);
        assert!(
            closest.contains(&target),
            "lookup from {start:?} should discover target {target:?}; got {closest:?}"
        );
        assert!(closest.len() <= K);
    }

    #[test]
    fn routing_table_closest_ordering() {
        let local = node_id_from_bytes(b"local");
        let mut table = RoutingTable::new(local);
        for seed in [b"p0".as_slice(), b"p1", b"p2", b"p3", b"p4"] {
            table.insert(PeerInfo {
                id: node_id_from_bytes(seed),
            });
        }
        let target = node_id_from_bytes(b"p2");
        let closest = table.closest(&target, 3);
        assert_eq!(closest[0].id, target);
    }
}
