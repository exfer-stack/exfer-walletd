//! Per-key cache entry with **CAS-on-generation** writes.
//!
//! The single non-negotiable invariant of the cache: a refresher fetch
//! that started *before* a `transfer` commit must never overwrite the
//! invalidation that commit performed. Without this, a freshly-spent
//! address's balance silently reverts to the pre-spend value for the
//! next 30 seconds.
//!
//! Mechanism: every entry carries a monotonic `generation`. Reads
//! sample the generation. Writes pass the sampled generation; if it
//! no longer matches (because someone called [`EntryStore::invalidate`]
//! between read and write), the write is dropped on the floor and the
//! caller logs a debug line. Only [`EntryStore::invalidate`] bumps
//! generation; refresher writes do not. That keeps the rule simple:
//! "an invalidation strictly happens-after every write that lost the
//! CAS".
//!
//! Storage is `std::sync::RwLock<HashMap<K, Slot<T>>>`. Coarse on
//! purpose: the only writers are the refresher (one task) and the
//! transfer commit path (one per request). Sharding can come if the
//! profile gets a knob for it; current measurements don't justify it.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::RwLock;
use std::time::Instant;

/// Monotonic per-entry version. Bumped only by
/// [`EntryStore::invalidate`]; writes do not advance it.
pub type Generation = u64;

/// Snapshot returned by [`EntryStore::get`]. `value` is present iff a
/// non-invalidated entry exists; `generation` is always meaningful and
/// is the token the caller must replay to [`EntryStore::try_write`].
#[derive(Debug, Clone)]
pub struct EntrySnapshot<T: Clone> {
    pub value: Option<T>,
    pub generation: Generation,
    pub fetched_at: Option<Instant>,
    pub tip_at_fetch: u64,
    pub last_error: Option<String>,
}

impl<T: Clone> EntrySnapshot<T> {
    /// Synthetic snapshot for a key that has never been written.
    pub fn empty() -> Self {
        Self {
            value: None,
            generation: 0,
            fetched_at: None,
            tip_at_fetch: 0,
            last_error: None,
        }
    }
}

/// Internal slot stored in the map. Identical fields as the snapshot,
/// but never exposed by reference (`get` clones).
#[derive(Debug, Clone)]
struct Slot<T: Clone> {
    value: Option<T>,
    generation: Generation,
    fetched_at: Option<Instant>,
    tip_at_fetch: u64,
    last_error: Option<String>,
}

impl<T: Clone> Slot<T> {
    fn fresh() -> Self {
        Self {
            value: None,
            generation: 0,
            fetched_at: None,
            tip_at_fetch: 0,
            last_error: None,
        }
    }

    fn to_snapshot(&self) -> EntrySnapshot<T> {
        EntrySnapshot {
            value: self.value.clone(),
            generation: self.generation,
            fetched_at: self.fetched_at,
            tip_at_fetch: self.tip_at_fetch,
            last_error: self.last_error.clone(),
        }
    }
}

/// Generic per-key cache with generation-CAS writes.
pub struct EntryStore<K, T>
where
    K: Eq + Hash,
    T: Clone,
{
    map: RwLock<HashMap<K, Slot<T>>>,
}

impl<K, T> Default for EntryStore<K, T>
where
    K: Eq + Hash,
    T: Clone,
{
    fn default() -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
        }
    }
}

impl<K, T> EntryStore<K, T>
where
    K: Eq + Hash + Clone,
    T: Clone,
{
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of keys currently tracked.
    pub fn len(&self) -> usize {
        self.map.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.read().unwrap().is_empty()
    }

    /// Get a snapshot for the given key. If the key has never been
    /// written, returns [`EntrySnapshot::empty`] — callers always have
    /// a generation to replay (the empty snapshot's generation is `0`).
    pub fn get(&self, key: &K) -> EntrySnapshot<T> {
        let g = self.map.read().unwrap();
        match g.get(key) {
            Some(slot) => slot.to_snapshot(),
            None => EntrySnapshot::empty(),
        }
    }

    /// Conditional write. Succeeds iff the key's generation has not
    /// changed since `expected_generation` was sampled. On success,
    /// the entry's value is replaced and `last_error` is cleared.
    ///
    /// The generation is **not** advanced — only [`Self::invalidate`]
    /// advances generation. This keeps the CAS rule simple: invalidations
    /// strictly happen-after every successful write whose generation was
    /// stale relative to the invalidation.
    ///
    /// Returns `true` on success, `false` if CAS failed (caller's data
    /// is stale and should be discarded).
    pub fn try_write(
        &self,
        key: &K,
        expected_generation: Generation,
        value: T,
        tip_at_fetch: u64,
    ) -> bool {
        let mut g = self.map.write().unwrap();
        let slot = g.entry(key.clone()).or_insert_with(Slot::fresh);
        if slot.generation != expected_generation {
            return false;
        }
        slot.value = Some(value);
        slot.fetched_at = Some(Instant::now());
        slot.tip_at_fetch = tip_at_fetch;
        slot.last_error = None;
        true
    }

    /// Record an error against the key without disturbing the cached
    /// value or generation. Used by the refresher to leave a forensic
    /// trail when a per-address upstream call fails — the previous
    /// value (possibly stale) stays available; the `last_error` field
    /// communicates "the last refresh attempt failed, here's why."
    pub fn note_error(&self, key: &K, err: String) {
        let mut g = self.map.write().unwrap();
        let slot = g.entry(key.clone()).or_insert_with(Slot::fresh);
        slot.last_error = Some(err);
    }

    /// Bump generation, clear value, return the new generation.
    /// Called from the `transfer` commit hook and from the refresher
    /// on reorg detection.
    pub fn invalidate(&self, key: &K) -> Generation {
        let mut g = self.map.write().unwrap();
        let slot = g.entry(key.clone()).or_insert_with(Slot::fresh);
        slot.generation = slot.generation.wrapping_add(1);
        slot.value = None;
        slot.fetched_at = None;
        slot.tip_at_fetch = 0;
        slot.last_error = None;
        slot.generation
    }

    /// Invalidate every key. Used on reorg detection — wholesale forget
    /// everything below the reorg point. Generations are still bumped
    /// per-key, so a refresher mid-fetch loses its CAS the same way as
    /// targeted invalidation.
    pub fn invalidate_all(&self) {
        let mut g = self.map.write().unwrap();
        for slot in g.values_mut() {
            slot.generation = slot.generation.wrapping_add(1);
            slot.value = None;
            slot.fetched_at = None;
            slot.tip_at_fetch = 0;
            slot.last_error = None;
        }
    }

    /// Insert a starter entry **without CAS**. Used by `generate_address`
    /// to pre-seed a freshly-created key. The seed's `tip_at_fetch` is
    /// the caller's choice: pass `0` to force the next refresher tick to
    /// treat the entry as maximally stale (i.e. "I asserted the value
    /// but I'm not the source of truth; please refresh").
    ///
    /// Generation is preserved if the key already exists (so a racing
    /// invalidation that bumped to `G+1` is not silently rolled back).
    pub fn seed(&self, key: K, value: T, tip_at_fetch: u64) {
        let mut g = self.map.write().unwrap();
        let slot = g.entry(key).or_insert_with(Slot::fresh);
        slot.value = Some(value);
        slot.fetched_at = Some(Instant::now());
        slot.tip_at_fetch = tip_at_fetch;
        slot.last_error = None;
    }

    /// Visit every entry. The visitor receives `(key, snapshot)`
    /// pairs while a read lock is held — visitor must be quick (no
    /// blocking I/O, no awaits). Used by the refresher to enumerate
    /// stale entries.
    pub fn for_each<F>(&self, mut visitor: F)
    where
        F: FnMut(&K, EntrySnapshot<T>),
    {
        let g = self.map.read().unwrap();
        for (k, slot) in g.iter() {
            visitor(k, slot.to_snapshot());
        }
    }

    /// Number of keys whose `fetched_at` is older than `min_age` (or
    /// have never been written, which counts as maximally stale).
    /// Used by stratified-refresh budget calculations.
    pub fn stale_count(&self, now: Instant, min_age: std::time::Duration) -> usize {
        let g = self.map.read().unwrap();
        g.values()
            .filter(|s| match s.fetched_at {
                None => true,
                Some(t) => now.duration_since(t) >= min_age,
            })
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_get_returns_empty_snapshot() {
        let s: EntryStore<String, u64> = EntryStore::new();
        let snap = s.get(&"a".to_string());
        assert!(snap.value.is_none());
        assert_eq!(snap.generation, 0);
        assert_eq!(snap.tip_at_fetch, 0);
    }

    #[test]
    fn try_write_with_correct_generation_succeeds() {
        let s: EntryStore<String, u64> = EntryStore::new();
        let key = "a".to_string();
        let snap = s.get(&key);
        assert!(s.try_write(&key, snap.generation, 100, 50));

        let after = s.get(&key);
        assert_eq!(after.value, Some(100));
        assert_eq!(after.tip_at_fetch, 50);
        assert!(after.fetched_at.is_some());
    }

    #[test]
    fn try_write_with_stale_generation_drops_the_write() {
        let s: EntryStore<String, u64> = EntryStore::new();
        let key = "a".to_string();
        let snap_before = s.get(&key);

        // Invalidation between sample and write.
        let new_gen = s.invalidate(&key);
        assert_eq!(new_gen, 1);

        // Refresher's stale write — must be dropped.
        let accepted = s.try_write(&key, snap_before.generation, 100, 50);
        assert!(!accepted);

        let after = s.get(&key);
        assert!(after.value.is_none(), "stale write must not have landed");
        assert_eq!(after.generation, 1);
    }

    #[test]
    fn invalidate_clears_value_and_bumps_generation() {
        let s: EntryStore<String, u64> = EntryStore::new();
        let key = "a".to_string();
        s.try_write(&key, 0, 42, 10);

        let snap = s.get(&key);
        assert_eq!(snap.value, Some(42));
        assert_eq!(snap.generation, 0);

        let new_gen = s.invalidate(&key);
        assert_eq!(new_gen, 1);

        let after = s.get(&key);
        assert!(after.value.is_none());
        assert_eq!(after.generation, 1);
    }

    #[test]
    fn invalidate_all_bumps_every_entry() {
        let s: EntryStore<String, u64> = EntryStore::new();
        s.try_write(&"a".into(), 0, 1, 10);
        s.try_write(&"b".into(), 0, 2, 10);
        s.invalidate_all();
        assert!(s.get(&"a".to_string()).value.is_none());
        assert!(s.get(&"b".to_string()).value.is_none());
        assert_eq!(s.get(&"a".to_string()).generation, 1);
        assert_eq!(s.get(&"b".to_string()).generation, 1);
    }

    #[test]
    fn write_does_not_advance_generation() {
        // The CAS-on-invalidate-only rule: refresher writes leave gen
        // alone, so a *later* invalidation still wins over an *earlier*
        // refresh.
        let s: EntryStore<String, u64> = EntryStore::new();
        let key = "a".to_string();
        s.try_write(&key, 0, 1, 10);
        s.try_write(&key, 0, 2, 11);
        s.try_write(&key, 0, 3, 12);
        assert_eq!(s.get(&key).generation, 0);
        assert_eq!(s.get(&key).value, Some(3));
    }

    #[test]
    fn note_error_does_not_disturb_value_or_generation() {
        let s: EntryStore<String, u64> = EntryStore::new();
        let key = "a".to_string();
        s.try_write(&key, 0, 5, 100);
        s.note_error(&key, "boom".into());
        let after = s.get(&key);
        assert_eq!(after.value, Some(5), "value must persist through error");
        assert_eq!(after.generation, 0);
        assert_eq!(after.last_error.as_deref(), Some("boom"));
    }

    #[test]
    fn seed_overrides_value_and_clears_last_error() {
        let s: EntryStore<String, u64> = EntryStore::new();
        let key = "a".to_string();
        s.note_error(&key, "boom".into());
        s.seed(key.clone(), 7, 0);
        let after = s.get(&key);
        assert_eq!(after.value, Some(7));
        assert_eq!(after.tip_at_fetch, 0, "seed force-stale tip");
        assert!(after.last_error.is_none());
    }

    #[test]
    fn seed_preserves_generation_after_invalidation() {
        // If a `transfer` commit bumped generation between
        // `generate_address` and the seed (impossible today, but the
        // contract must hold), the seed must not roll generation back.
        let s: EntryStore<String, u64> = EntryStore::new();
        let key = "a".to_string();
        s.try_write(&key, 0, 5, 10);
        s.invalidate(&key);
        assert_eq!(s.get(&key).generation, 1);
        s.seed(key.clone(), 9, 0);
        assert_eq!(s.get(&key).generation, 1);
        assert_eq!(s.get(&key).value, Some(9));
    }

    #[test]
    fn for_each_visits_every_entry() {
        let s: EntryStore<String, u64> = EntryStore::new();
        s.try_write(&"a".into(), 0, 1, 10);
        s.try_write(&"b".into(), 0, 2, 10);
        s.try_write(&"c".into(), 0, 3, 10);

        let mut collected = Vec::new();
        s.for_each(|k, snap| {
            collected.push((k.clone(), snap.value));
        });
        collected.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            collected,
            vec![
                ("a".to_string(), Some(1)),
                ("b".to_string(), Some(2)),
                ("c".to_string(), Some(3)),
            ]
        );
    }

    #[test]
    fn stale_count_treats_never_written_as_stale() {
        let s: EntryStore<String, u64> = EntryStore::new();
        s.seed("a".into(), 1, 0);
        // 'a' was just seeded, fetched_at = now, not stale.
        assert_eq!(
            s.stale_count(Instant::now(), std::time::Duration::from_secs(60)),
            0
        );
    }

    #[test]
    fn stale_count_after_invalidate_counts_invalidated() {
        let s: EntryStore<String, u64> = EntryStore::new();
        let key = "a".to_string();
        s.try_write(&key, 0, 1, 10);
        s.invalidate(&key);
        // After invalidate, fetched_at is None → counts as stale at any
        // min_age.
        assert_eq!(
            s.stale_count(Instant::now(), std::time::Duration::from_secs(60)),
            1
        );
    }
}
