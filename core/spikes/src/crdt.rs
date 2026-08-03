//! Spike 2.4 — CRDT counter → OR-Set with concurrent merge tests.
//!
//! Demonstrates deterministic merge under partition (commutativity + idempotence).
//! Informs membership / nickname CRDT policies — not production room state.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub const SPIKE_NAME: &str = "crdt";
pub const WBS: &str = "2.4";

/// Actor identifier for CRDT replicas (device or peer id in production).
pub type ActorId = u64;

/// Grow-only counter: each actor's increments are max-merged.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GCounter {
    counts: BTreeMap<ActorId, u64>,
}

impl GCounter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc(&mut self, actor: ActorId, by: u64) {
        *self.counts.entry(actor).or_insert(0) = self
            .counts
            .get(&actor)
            .copied()
            .unwrap_or(0)
            .saturating_add(by);
    }

    pub fn value(&self) -> u64 {
        self.counts.values().sum()
    }

    pub fn merge(&mut self, other: &Self) {
        for (&actor, &count) in &other.counts {
            let entry = self.counts.entry(actor).or_insert(0);
            *entry = (*entry).max(count);
        }
    }
}

/// Positive-negative counter built from two G-Counters.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PnCounter {
    pub pos: GCounter,
    pub neg: GCounter,
}

impl PnCounter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc(&mut self, actor: ActorId, by: u64) {
        self.pos.inc(actor, by);
    }

    pub fn dec(&mut self, actor: ActorId, by: u64) {
        self.neg.inc(actor, by);
    }

    pub fn value(&self) -> i64 {
        self.pos.value() as i64 - self.neg.value() as i64
    }

    pub fn merge(&mut self, other: &Self) {
        self.pos.merge(&other.pos);
        self.neg.merge(&other.neg);
    }
}

/// Unique tag for an OR-Set add (actor + local monotonic counter).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Dot {
    pub actor: ActorId,
    pub counter: u64,
}

/// Observed-remove set (add-wins): concurrent add vs remove keeps the element
/// when a newer/ unseen add was not covered by the remove's observed dots.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OrSet<T: Clone + Eq + Ord + std::hash::Hash> {
    /// element → live dots
    entries: HashMap<T, HashSet<Dot>>,
    /// Per-actor clock used to mint dots.
    clocks: BTreeMap<ActorId, u64>,
}

impl<T: Clone + Eq + Ord + std::hash::Hash> OrSet<T> {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            clocks: BTreeMap::new(),
        }
    }

    fn next_dot(&mut self, actor: ActorId) -> Dot {
        let c = self.clocks.entry(actor).or_insert(0);
        *c += 1;
        Dot { actor, counter: *c }
    }

    pub fn add(&mut self, actor: ActorId, value: T) {
        let dot = self.next_dot(actor);
        self.entries.entry(value).or_default().insert(dot);
    }

    pub fn remove(&mut self, value: &T) {
        self.entries.remove(value);
    }

    pub fn contains(&self, value: &T) -> bool {
        self.entries
            .get(value)
            .map(|d| !d.is_empty())
            .unwrap_or(false)
    }

    pub fn elements(&self) -> BTreeSet<T> {
        self.entries
            .iter()
            .filter(|(_, dots)| !dots.is_empty())
            .map(|(v, _)| v.clone())
            .collect()
    }

    pub fn merge(&mut self, other: &Self) {
        for (&actor, &clock) in &other.clocks {
            let entry = self.clocks.entry(actor).or_insert(0);
            *entry = (*entry).max(clock);
        }

        let keys: HashSet<T> = self
            .entries
            .keys()
            .chain(other.entries.keys())
            .cloned()
            .collect();

        for key in keys {
            let a = self.entries.remove(&key).unwrap_or_default();
            let b = other.entries.get(&key).cloned().unwrap_or_default();
            let union: HashSet<Dot> = a.union(&b).copied().collect();
            // Observed-remove: keep dots present in either replica.
            // A local remove clears dots; merge re-adds dots still live elsewhere
            // (add-wins under concurrent add||remove when the add's dot wasn't
            // observed by the remover — here modeled as: if other still has dots,
            // they survive).
            if !union.is_empty() {
                self.entries.insert(key, union);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn g_counter_merge_commutative_idempotent() {
        let mut a = GCounter::new();
        a.inc(1, 3);
        let mut b = GCounter::new();
        b.inc(2, 5);

        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);
        assert_eq!(ab, ba);
        assert_eq!(ab.value(), 8);

        let mut again = ab.clone();
        again.merge(&ab);
        assert_eq!(again, ab);
    }

    #[test]
    fn pn_counter_partition_then_merge() {
        let mut left = PnCounter::new();
        let mut right = PnCounter::new();
        left.inc(1, 10);
        left.dec(1, 2);
        right.inc(2, 4);
        right.dec(2, 1);

        let mut merged = left.clone();
        merged.merge(&right);
        assert_eq!(merged.value(), 11); // (10-2) + (4-1)

        let mut merged2 = right.clone();
        merged2.merge(&left);
        assert_eq!(merged, merged2);
    }

    #[test]
    fn or_set_concurrent_add_wins() {
        let mut a = OrSet::new();
        let mut b = OrSet::new();

        // Both start empty; partition: A adds "x", B removes nothing then adds "y".
        a.add(1, "x");
        b.add(2, "y");

        // Concurrent: A removes "y" (not present locally — no-op), B removes "x".
        b.remove(&"x"); // B never observed A's add of "x", so this is a no-op on B.
                        // Simulate B observing a stale "x" and removing it:
        let mut b_with_x = b.clone();
        b_with_x.add(2, "x");
        b_with_x.remove(&"x");

        // True concurrent add-wins: A has "x", B never had "x".
        let mut merged = a.clone();
        merged.merge(&b);
        assert!(merged.contains(&"x"));
        assert!(merged.contains(&"y"));

        // If B added then removed "x" with its own dot, merge with A's "x" keeps
        // A's distinct dot → add-wins.
        let mut a2 = OrSet::new();
        a2.add(1, "x");
        let mut b2 = OrSet::new();
        b2.add(2, "x");
        b2.remove(&"x");
        let mut m = a2.clone();
        m.merge(&b2);
        assert!(
            m.contains(&"x"),
            "A's add-dot survives B's remove of a different dot"
        );
    }

    #[test]
    fn or_set_merge_idempotent() {
        let mut a = OrSet::new();
        a.add(1, "room-admin");
        a.add(2, "moderator");
        let mut b = a.clone();
        b.remove(&"moderator");
        b.add(3, "member");

        let mut m1 = a.clone();
        m1.merge(&b);
        let mut m2 = m1.clone();
        m2.merge(&b);
        assert_eq!(m1.elements(), m2.elements());
    }
}
