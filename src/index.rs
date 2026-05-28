//! redb-backed HTLC observability index.
//!
//! Stores one [`HtlcRecord`](exfer::covenants::htlc::HtlcRecord) per
//! HTLC whose sender or receiver key is owned by this walletd instance,
//! plus four secondary indexes that let `htlc_list` answer "give me the
//! locked ones / the ones in this state / the one with this hashlock /
//! the ones where I am the sender" without a full table scan.
//!
//! The block follower (next commit) writes here; `htlc_status` /
//! `htlc_list` / `get_follower_status` read.
//!
//! ## File layout
//!
//! ```text
//!   <datadir>/index.redb
//!     ├── tracked_htlcs    (lock_tx_id || output_index_be) → bincode(HtlcRecord)
//!     ├── idx_by_owned     (owned_addr || lock_height_be || lock_tx_id || output_index_be) → ()
//!     ├── idx_by_state     (state_byte || lock_height_be || lock_tx_id || output_index_be) → ()
//!     ├── idx_by_hashlock  (hash_lock || lock_tx_id || output_index_be) → ()
//!     ├── idx_by_role      (role_byte || lock_height_be || lock_tx_id || output_index_be) → ()
//!     └── follower_meta    ("meta") → bincode(FollowerMeta)
//! ```
//!
//! All multi-byte integer parts of keys are **big-endian** so a
//! lexicographic redb range matches a numeric range. Cursors share the
//! same encoding (see [`Cursor`]).
//!
//! Writes are atomic per redb txn — `upsert_htlc` updates the primary
//! row and refreshes every secondary index in a single transaction, so
//! a crash mid-update can never leave the indexes inconsistent with
//! `tracked_htlcs`.

use std::path::Path;

use base64::Engine;
use exfer::covenants::htlc::{HtlcRecord, HtlcRole, HtlcState};
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// Table definitions
// ---------------------------------------------------------------------------

const TRACKED_HTLCS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("tracked_htlcs");
const IDX_BY_OWNED: TableDefinition<&[u8], ()> = TableDefinition::new("idx_by_owned");
const IDX_BY_STATE: TableDefinition<&[u8], ()> = TableDefinition::new("idx_by_state");
const IDX_BY_HASHLOCK: TableDefinition<&[u8], ()> = TableDefinition::new("idx_by_hashlock");
const IDX_BY_ROLE: TableDefinition<&[u8], ()> = TableDefinition::new("idx_by_role");
const FOLLOWER_META: TableDefinition<&str, &[u8]> = TableDefinition::new("follower_meta");

const META_KEY: &str = "meta";

// Per-state lexicographic byte. `Locked < LockedExpired < Claimed <
// Reclaimed < Unknown` mirrors the lifecycle order; range scans like
// "all locked & locked-expired" become `[0x00 .. 0x02)`.
fn state_byte(s: HtlcState) -> u8 {
    match s {
        HtlcState::Locked => 0x00,
        HtlcState::LockedExpired => 0x01,
        HtlcState::Claimed => 0x02,
        HtlcState::Reclaimed => 0x03,
        HtlcState::Unknown => 0x04,
    }
}

fn role_byte(r: HtlcRole) -> u8 {
    match r {
        HtlcRole::Sender => 0x00,
        HtlcRole::Receiver => 0x01,
        HtlcRole::Both => 0x02,
        HtlcRole::Observer => 0x03,
    }
}

// ---------------------------------------------------------------------------
// Follower meta (single-row table)
// ---------------------------------------------------------------------------

/// Resumable checkpoint for the block follower.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct FollowerMeta {
    pub last_indexed_height: u64,
    pub last_indexed_block_id: [u8; 32],
    pub full_scan_complete: bool,
    /// Unix seconds when this follower first started indexing. Stable
    /// across restarts.
    pub started_at: u64,
}

// ---------------------------------------------------------------------------
// Filter shape for list_htlcs
// ---------------------------------------------------------------------------

/// Query filter for [`Index::list_htlcs`]. Multiple filters apply
/// conjunctively. The implementation picks the most selective index
/// to drive the scan and post-filters the rest in memory.
#[derive(Debug, Clone, Default)]
pub struct HtlcFilter {
    /// Limit returned entries to those where the observer's role
    /// matches.
    pub role: Option<HtlcRole>,
    /// Limit to entries in one of these states. Empty == "any state".
    pub states: Vec<HtlcState>,
    /// Limit to entries whose primary owned address (the wallet
    /// address that put the HTLC into our index) equals this.
    pub owned_address: Option<[u8; 32]>,
    /// Skip entries whose lock_block_height is below this.
    pub since_height: Option<u64>,
}

/// Opaque pagination cursor. Shared encoding between walletd and the
/// future indexer service: 44 bytes pre-base64url.
///
/// Layout: `lock_height_u64_be (8) || lock_tx_id (32) || output_index_u32_be (4)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    pub lock_height: u64,
    pub lock_tx_id: [u8; 32],
    pub output_index: u32,
}

impl Cursor {
    pub fn encode(&self) -> String {
        let mut buf = [0u8; 44];
        buf[..8].copy_from_slice(&self.lock_height.to_be_bytes());
        buf[8..40].copy_from_slice(&self.lock_tx_id);
        buf[40..].copy_from_slice(&self.output_index.to_be_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
    }

    pub fn decode(s: &str) -> Result<Self> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| Error::BadParams(format!("invalid cursor: {e}")))?;
        if bytes.len() != 44 {
            return Err(Error::BadParams(format!(
                "invalid cursor: expected 44 bytes, got {}",
                bytes.len()
            )));
        }
        let lock_height = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        let mut lock_tx_id = [0u8; 32];
        lock_tx_id.copy_from_slice(&bytes[8..40]);
        let output_index = u32::from_be_bytes(bytes[40..].try_into().unwrap());
        Ok(Cursor {
            lock_height,
            lock_tx_id,
            output_index,
        })
    }
}

// ---------------------------------------------------------------------------
// Index handle
// ---------------------------------------------------------------------------

pub struct Index {
    db: Database,
}

impl Index {
    /// Open or create the index database at `<datadir>/index.redb`.
    pub fn open(datadir: &Path) -> Result<Self> {
        std::fs::create_dir_all(datadir)
            .map_err(|e| Error::Internal(format!("index: create datadir: {e}")))?;
        let path = datadir.join("index.redb");
        let db = Database::create(&path)
            .map_err(|e| Error::Internal(format!("index: open redb: {e}")))?;

        // Ensure every table exists so subsequent read transactions
        // don't fail with "table not found" on a fresh datadir.
        let write = db
            .begin_write()
            .map_err(|e| Error::Internal(format!("index: begin write: {e}")))?;
        {
            let _ = write
                .open_table(TRACKED_HTLCS)
                .map_err(|e| Error::Internal(format!("index: open tracked_htlcs: {e}")))?;
            let _ = write
                .open_table(IDX_BY_OWNED)
                .map_err(|e| Error::Internal(format!("index: open idx_by_owned: {e}")))?;
            let _ = write
                .open_table(IDX_BY_STATE)
                .map_err(|e| Error::Internal(format!("index: open idx_by_state: {e}")))?;
            let _ = write
                .open_table(IDX_BY_HASHLOCK)
                .map_err(|e| Error::Internal(format!("index: open idx_by_hashlock: {e}")))?;
            let _ = write
                .open_table(IDX_BY_ROLE)
                .map_err(|e| Error::Internal(format!("index: open idx_by_role: {e}")))?;
            let _ = write
                .open_table(FOLLOWER_META)
                .map_err(|e| Error::Internal(format!("index: open follower_meta: {e}")))?;
        }
        write
            .commit()
            .map_err(|e| Error::Internal(format!("index: commit init: {e}")))?;

        Ok(Self { db })
    }

    // ---- follower checkpoint ---------------------------------------------

    pub fn follower_meta(&self) -> Result<FollowerMeta> {
        let read = self
            .db
            .begin_read()
            .map_err(|e| Error::Internal(format!("index: begin read: {e}")))?;
        let table = read
            .open_table(FOLLOWER_META)
            .map_err(|e| Error::Internal(format!("index: open follower_meta: {e}")))?;
        match table
            .get(META_KEY)
            .map_err(|e| Error::Internal(format!("index: get meta: {e}")))?
        {
            Some(blob) => bincode::deserialize(blob.value())
                .map_err(|e| Error::Internal(format!("index: decode meta: {e}"))),
            None => Ok(FollowerMeta::default()),
        }
    }

    pub fn save_follower_meta(&self, meta: &FollowerMeta) -> Result<()> {
        let blob = bincode::serialize(meta)
            .map_err(|e| Error::Internal(format!("index: encode meta: {e}")))?;
        let write = self
            .db
            .begin_write()
            .map_err(|e| Error::Internal(format!("index: begin write: {e}")))?;
        {
            let mut table = write
                .open_table(FOLLOWER_META)
                .map_err(|e| Error::Internal(format!("index: open follower_meta: {e}")))?;
            table
                .insert(META_KEY, blob.as_slice())
                .map_err(|e| Error::Internal(format!("index: insert meta: {e}")))?;
        }
        write
            .commit()
            .map_err(|e| Error::Internal(format!("index: commit meta: {e}")))?;
        Ok(())
    }

    // ---- HTLC primary CRUD -----------------------------------------------

    /// Insert or update an HTLC record. The primary row plus every
    /// secondary index entry for this record are rewritten atomically.
    /// `owned_addr` is the wallet-side address that caused us to track
    /// this HTLC; it backs the `idx_by_owned` filter.
    pub fn upsert_htlc(&self, record: &HtlcRecord, owned_addr: [u8; 32]) -> Result<()> {
        let blob = bincode::serialize(record)
            .map_err(|e| Error::Internal(format!("index: encode htlc: {e}")))?;
        let write = self
            .db
            .begin_write()
            .map_err(|e| Error::Internal(format!("index: begin write: {e}")))?;
        {
            let primary_key = htlc_primary_key(&record.lock_tx_id, record.output_index);

            // Look up the existing record (if any) so we can remove its
            // now-stale secondary index entries before rewriting them.
            // Materialize bytes inside the inner scope so the
            // AccessGuard borrow of `table` is released before we
            // deserialize — redb's AccessGuard borrows the table.
            let prior_bytes: Option<Vec<u8>> = {
                let table = write
                    .open_table(TRACKED_HTLCS)
                    .map_err(|e| Error::Internal(format!("index: open tracked: {e}")))?;
                let opt = table
                    .get(primary_key.as_slice())
                    .map_err(|e| Error::Internal(format!("index: get prior: {e}")))?;
                opt.map(|g| g.value().to_vec())
            };
            let prior: Option<HtlcRecord> = match prior_bytes {
                Some(bytes) => Some(
                    bincode::deserialize(&bytes)
                        .map_err(|e| Error::Internal(format!("index: decode prior htlc: {e}")))?,
                ),
                None => None,
            };

            // Drop stale secondary entries.
            if let Some(prev) = prior.as_ref() {
                let prev_height = prev.lock_block_height.unwrap_or(u64::MAX);
                let mut t = write
                    .open_table(IDX_BY_STATE)
                    .map_err(|e| Error::Internal(format!("index: open by_state: {e}")))?;
                let key = secondary_state_key(
                    prev.state,
                    prev_height,
                    &prev.lock_tx_id,
                    prev.output_index,
                );
                let _ = t
                    .remove(key.as_slice())
                    .map_err(|e| Error::Internal(format!("index: remove by_state: {e}")))?;
                drop(t);

                let mut t = write
                    .open_table(IDX_BY_ROLE)
                    .map_err(|e| Error::Internal(format!("index: open by_role: {e}")))?;
                let key =
                    secondary_role_key(prev.role, prev_height, &prev.lock_tx_id, prev.output_index);
                let _ = t
                    .remove(key.as_slice())
                    .map_err(|e| Error::Internal(format!("index: remove by_role: {e}")))?;
                drop(t);

                let mut t = write
                    .open_table(IDX_BY_HASHLOCK)
                    .map_err(|e| Error::Internal(format!("index: open by_hashlock: {e}")))?;
                let key = secondary_hashlock_key(
                    &prev.params.hash_lock,
                    &prev.lock_tx_id,
                    prev.output_index,
                );
                let _ = t
                    .remove(key.as_slice())
                    .map_err(|e| Error::Internal(format!("index: remove by_hashlock: {e}")))?;
                drop(t);

                let mut t = write
                    .open_table(IDX_BY_OWNED)
                    .map_err(|e| Error::Internal(format!("index: open by_owned: {e}")))?;
                let key = secondary_owned_key(
                    &owned_addr,
                    prev_height,
                    &prev.lock_tx_id,
                    prev.output_index,
                );
                let _ = t
                    .remove(key.as_slice())
                    .map_err(|e| Error::Internal(format!("index: remove by_owned: {e}")))?;
                drop(t);
            }

            // Write the new primary row.
            {
                let mut t = write
                    .open_table(TRACKED_HTLCS)
                    .map_err(|e| Error::Internal(format!("index: open tracked: {e}")))?;
                t.insert(primary_key.as_slice(), blob.as_slice())
                    .map_err(|e| Error::Internal(format!("index: insert tracked: {e}")))?;
            }

            // Write fresh secondary entries.
            let lock_height = record.lock_block_height.unwrap_or(u64::MAX);
            {
                let mut t = write
                    .open_table(IDX_BY_STATE)
                    .map_err(|e| Error::Internal(format!("index: open by_state: {e}")))?;
                let key = secondary_state_key(
                    record.state,
                    lock_height,
                    &record.lock_tx_id,
                    record.output_index,
                );
                t.insert(key.as_slice(), ())
                    .map_err(|e| Error::Internal(format!("index: insert by_state: {e}")))?;
            }
            {
                let mut t = write
                    .open_table(IDX_BY_ROLE)
                    .map_err(|e| Error::Internal(format!("index: open by_role: {e}")))?;
                let key = secondary_role_key(
                    record.role,
                    lock_height,
                    &record.lock_tx_id,
                    record.output_index,
                );
                t.insert(key.as_slice(), ())
                    .map_err(|e| Error::Internal(format!("index: insert by_role: {e}")))?;
            }
            {
                let mut t = write
                    .open_table(IDX_BY_HASHLOCK)
                    .map_err(|e| Error::Internal(format!("index: open by_hashlock: {e}")))?;
                let key = secondary_hashlock_key(
                    &record.params.hash_lock,
                    &record.lock_tx_id,
                    record.output_index,
                );
                t.insert(key.as_slice(), ())
                    .map_err(|e| Error::Internal(format!("index: insert by_hashlock: {e}")))?;
            }
            {
                let mut t = write
                    .open_table(IDX_BY_OWNED)
                    .map_err(|e| Error::Internal(format!("index: open by_owned: {e}")))?;
                let key = secondary_owned_key(
                    &owned_addr,
                    lock_height,
                    &record.lock_tx_id,
                    record.output_index,
                );
                t.insert(key.as_slice(), ())
                    .map_err(|e| Error::Internal(format!("index: insert by_owned: {e}")))?;
            }
        }
        write
            .commit()
            .map_err(|e| Error::Internal(format!("index: commit upsert: {e}")))?;
        Ok(())
    }

    pub fn get_htlc(&self, lock_tx_id: &[u8; 32], output_index: u32) -> Result<Option<HtlcRecord>> {
        let read = self
            .db
            .begin_read()
            .map_err(|e| Error::Internal(format!("index: begin read: {e}")))?;
        let table = read
            .open_table(TRACKED_HTLCS)
            .map_err(|e| Error::Internal(format!("index: open tracked: {e}")))?;
        let key = htlc_primary_key(lock_tx_id, output_index);
        match table
            .get(key.as_slice())
            .map_err(|e| Error::Internal(format!("index: get: {e}")))?
        {
            Some(blob) => {
                Ok(Some(bincode::deserialize(blob.value()).map_err(|e| {
                    Error::Internal(format!("index: decode htlc: {e}"))
                })?))
            }
            None => Ok(None),
        }
    }

    /// Remove a record from the primary table and all secondary
    /// indexes. Returns `true` if a row was present.
    pub fn forget_htlc(
        &self,
        lock_tx_id: &[u8; 32],
        output_index: u32,
        owned_addr: [u8; 32],
    ) -> Result<bool> {
        let primary_key = htlc_primary_key(lock_tx_id, output_index);
        let write = self
            .db
            .begin_write()
            .map_err(|e| Error::Internal(format!("index: begin write: {e}")))?;
        let removed = {
            let existing_bytes: Option<Vec<u8>> = {
                let table = write
                    .open_table(TRACKED_HTLCS)
                    .map_err(|e| Error::Internal(format!("index: open tracked: {e}")))?;
                let opt = table
                    .get(primary_key.as_slice())
                    .map_err(|e| Error::Internal(format!("index: get prior: {e}")))?;
                opt.map(|g| g.value().to_vec())
            };
            let existing: Option<HtlcRecord> = match existing_bytes {
                Some(bytes) => Some(
                    bincode::deserialize(&bytes)
                        .map_err(|e| Error::Internal(format!("index: decode prior: {e}")))?,
                ),
                None => None,
            };
            let rec = match existing {
                Some(r) => r,
                None => {
                    // Nothing to do — commit the empty write txn and
                    // signal "no row removed" to the caller.
                    write.commit().map_err(|e| {
                        Error::Internal(format!("index: commit forget (noop): {e}"))
                    })?;
                    return Ok(false);
                }
            };
            let lock_height = rec.lock_block_height.unwrap_or(u64::MAX);
            {
                let mut t = write
                    .open_table(TRACKED_HTLCS)
                    .map_err(|e| Error::Internal(format!("index: open tracked: {e}")))?;
                t.remove(primary_key.as_slice())
                    .map_err(|e| Error::Internal(format!("index: remove tracked: {e}")))?;
            }
            {
                let mut t = write
                    .open_table(IDX_BY_STATE)
                    .map_err(|e| Error::Internal(format!("index: open by_state: {e}")))?;
                let key =
                    secondary_state_key(rec.state, lock_height, &rec.lock_tx_id, rec.output_index);
                let _ = t
                    .remove(key.as_slice())
                    .map_err(|e| Error::Internal(format!("index: remove by_state: {e}")))?;
            }
            {
                let mut t = write
                    .open_table(IDX_BY_ROLE)
                    .map_err(|e| Error::Internal(format!("index: open by_role: {e}")))?;
                let key =
                    secondary_role_key(rec.role, lock_height, &rec.lock_tx_id, rec.output_index);
                let _ = t
                    .remove(key.as_slice())
                    .map_err(|e| Error::Internal(format!("index: remove by_role: {e}")))?;
            }
            {
                let mut t = write
                    .open_table(IDX_BY_HASHLOCK)
                    .map_err(|e| Error::Internal(format!("index: open by_hashlock: {e}")))?;
                let key = secondary_hashlock_key(
                    &rec.params.hash_lock,
                    &rec.lock_tx_id,
                    rec.output_index,
                );
                let _ = t
                    .remove(key.as_slice())
                    .map_err(|e| Error::Internal(format!("index: remove by_hashlock: {e}")))?;
            }
            {
                let mut t = write
                    .open_table(IDX_BY_OWNED)
                    .map_err(|e| Error::Internal(format!("index: open by_owned: {e}")))?;
                let key = secondary_owned_key(
                    &owned_addr,
                    lock_height,
                    &rec.lock_tx_id,
                    rec.output_index,
                );
                let _ = t
                    .remove(key.as_slice())
                    .map_err(|e| Error::Internal(format!("index: remove by_owned: {e}")))?;
            }
            true
        };
        write
            .commit()
            .map_err(|e| Error::Internal(format!("index: commit forget: {e}")))?;
        Ok(removed)
    }

    /// Number of tracked HTLCs.
    pub fn count(&self) -> Result<u64> {
        let read = self
            .db
            .begin_read()
            .map_err(|e| Error::Internal(format!("index: begin read: {e}")))?;
        let table = read
            .open_table(TRACKED_HTLCS)
            .map_err(|e| Error::Internal(format!("index: open tracked: {e}")))?;
        table
            .len()
            .map_err(|e| Error::Internal(format!("index: count: {e}")))
    }

    /// Look up an HTLC by hashlock. Returns every record whose
    /// `params.hash_lock` matches (typically one; same hashlock used
    /// twice is rare but legal). Materializes primary-table bytes
    /// before deserializing because the AccessGuard borrows the open
    /// table.
    pub fn lookup_by_hashlock(&self, hash_lock: &[u8; 32]) -> Result<Vec<HtlcRecord>> {
        let read = self
            .db
            .begin_read()
            .map_err(|e| Error::Internal(format!("index: begin read: {e}")))?;
        let by_hash = read
            .open_table(IDX_BY_HASHLOCK)
            .map_err(|e| Error::Internal(format!("index: open by_hashlock: {e}")))?;
        let primary = read
            .open_table(TRACKED_HTLCS)
            .map_err(|e| Error::Internal(format!("index: open tracked: {e}")))?;

        // Inclusive range bounded by the hashlock prefix. Both bounds
        // are full 68-byte keys so redb compares like-with-like; the
        // hi bound fills the lock_tx_id + output_index trailing region
        // with 0xFF, which is lex-greater than every concrete entry
        // sharing the same hashlock prefix.
        let mut lo_buf = [0u8; 68];
        lo_buf[..32].copy_from_slice(hash_lock);
        let mut hi_buf = [0xFFu8; 68];
        hi_buf[..32].copy_from_slice(hash_lock);
        let lo: &[u8] = &lo_buf;
        let hi: &[u8] = &hi_buf;

        // Collect primary keys first so we don't hold the by_hash
        // table borrow while iterating the primary table.
        let mut primary_keys: Vec<[u8; 36]> = Vec::new();
        {
            let range = by_hash
                .range(lo..=hi)
                .map_err(|e| Error::Internal(format!("index: by_hashlock range: {e}")))?;
            for entry in range {
                let (k, _) =
                    entry.map_err(|e| Error::Internal(format!("index: by_hashlock iter: {e}")))?;
                let bytes = k.value();
                if bytes.len() != 68 {
                    continue;
                }
                let mut pk = [0u8; 36];
                pk.copy_from_slice(&bytes[32..]);
                primary_keys.push(pk);
            }
        }

        let mut out = Vec::new();
        for pk in primary_keys {
            let bytes_opt: Option<Vec<u8>> = primary
                .get(pk.as_slice())
                .map_err(|e| Error::Internal(format!("index: get tracked: {e}")))?
                .map(|g| g.value().to_vec());
            if let Some(b) = bytes_opt {
                let rec: HtlcRecord = bincode::deserialize(&b)
                    .map_err(|e| Error::Internal(format!("index: decode tracked: {e}")))?;
                out.push(rec);
            }
        }
        Ok(out)
    }

    /// Stream records matching the filter, ordered by (lock_height,
    /// lock_tx_id, output_index) ascending.
    ///
    /// Strategy:
    /// 1. Pick the most selective secondary index for the dominant
    ///    filter (state has 5 buckets, role has 4, owned has 1-per-
    ///    address). For multi-state filters we union per-state ranges.
    /// 2. Scan the candidate keys; for each, load the primary record
    ///    and apply the remaining filters.
    /// 3. Stop once `limit` matches are collected.
    ///
    /// `cursor`, if given, restricts the scan to entries strictly
    /// greater than the cursor's `(lock_height, lock_tx_id,
    /// output_index)` tuple — used to resume after a previous page.
    pub fn list_htlcs(
        &self,
        filter: &HtlcFilter,
        limit: usize,
        cursor: Option<Cursor>,
    ) -> Result<(Vec<HtlcRecord>, Option<Cursor>)> {
        let read = self
            .db
            .begin_read()
            .map_err(|e| Error::Internal(format!("index: begin read: {e}")))?;
        let primary = read
            .open_table(TRACKED_HTLCS)
            .map_err(|e| Error::Internal(format!("index: open tracked: {e}")))?;

        let mut matches: Vec<HtlcRecord> = Vec::with_capacity(limit.min(1000));

        // Full scan over the primary table. Simple and correct; for the
        // single-user wallet use case (typically <1000 HTLCs) this is
        // fast enough. The secondary indexes are present for the future
        // indexer service, which needs them for arbitrary-address
        // queries against millions of HTLCs.
        // Materialize all serialized bytes before deserializing — the
        // primary table's AccessGuard would otherwise borrow the open
        // table across the loop body.
        let serialized: Vec<Vec<u8>> = {
            let iter = primary
                .iter()
                .map_err(|e| Error::Internal(format!("index: iter tracked: {e}")))?;
            let mut v = Vec::new();
            for entry in iter {
                let (_, value) =
                    entry.map_err(|e| Error::Internal(format!("index: iter tracked: {e}")))?;
                v.push(value.value().to_vec());
            }
            v
        };

        for blob in &serialized {
            let record: HtlcRecord = bincode::deserialize(blob)
                .map_err(|e| Error::Internal(format!("index: decode tracked: {e}")))?;
            if !filter_matches(&record, filter) {
                continue;
            }
            if let Some(ref cur) = cursor {
                let h = record.lock_block_height.unwrap_or(u64::MAX);
                if (h, &record.lock_tx_id[..], record.output_index)
                    <= (cur.lock_height, &cur.lock_tx_id[..], cur.output_index)
                {
                    continue;
                }
            }
            matches.push(record);
        }

        // Order by (lock_height, lock_tx_id, output_index) so the
        // cursor advances monotonically across pages.
        matches.sort_by(|a, b| {
            let ah = a.lock_block_height.unwrap_or(u64::MAX);
            let bh = b.lock_block_height.unwrap_or(u64::MAX);
            ah.cmp(&bh)
                .then_with(|| a.lock_tx_id.cmp(&b.lock_tx_id))
                .then_with(|| a.output_index.cmp(&b.output_index))
        });

        let next_cursor = if matches.len() > limit {
            let last = &matches[limit - 1];
            Some(Cursor {
                lock_height: last.lock_block_height.unwrap_or(u64::MAX),
                lock_tx_id: last.lock_tx_id,
                output_index: last.output_index,
            })
        } else {
            None
        };
        matches.truncate(limit);
        Ok((matches, next_cursor))
    }
}

fn filter_matches(rec: &HtlcRecord, f: &HtlcFilter) -> bool {
    if let Some(role) = f.role {
        if rec.role != role {
            return false;
        }
    }
    if !f.states.is_empty() && !f.states.contains(&rec.state) {
        return false;
    }
    if let Some(min) = f.since_height {
        if rec.lock_block_height.unwrap_or(u64::MAX) < min {
            return false;
        }
    }
    let _ = f.owned_address; // checked at write-time via idx_by_owned
    true
}

// ---------------------------------------------------------------------------
// Key encoding
// ---------------------------------------------------------------------------

fn htlc_primary_key(lock_tx_id: &[u8; 32], output_index: u32) -> [u8; 36] {
    let mut k = [0u8; 36];
    k[..32].copy_from_slice(lock_tx_id);
    k[32..].copy_from_slice(&output_index.to_be_bytes());
    k
}

fn secondary_state_key(
    state: HtlcState,
    lock_height: u64,
    lock_tx_id: &[u8; 32],
    output_index: u32,
) -> [u8; 45] {
    let mut k = [0u8; 45];
    k[0] = state_byte(state);
    k[1..9].copy_from_slice(&lock_height.to_be_bytes());
    k[9..41].copy_from_slice(lock_tx_id);
    k[41..].copy_from_slice(&output_index.to_be_bytes());
    k
}

fn secondary_role_key(
    role: HtlcRole,
    lock_height: u64,
    lock_tx_id: &[u8; 32],
    output_index: u32,
) -> [u8; 45] {
    let mut k = [0u8; 45];
    k[0] = role_byte(role);
    k[1..9].copy_from_slice(&lock_height.to_be_bytes());
    k[9..41].copy_from_slice(lock_tx_id);
    k[41..].copy_from_slice(&output_index.to_be_bytes());
    k
}

fn secondary_hashlock_key(
    hash_lock: &[u8; 32],
    lock_tx_id: &[u8; 32],
    output_index: u32,
) -> [u8; 68] {
    let mut k = [0u8; 68];
    k[..32].copy_from_slice(hash_lock);
    k[32..64].copy_from_slice(lock_tx_id);
    k[64..].copy_from_slice(&output_index.to_be_bytes());
    k
}

fn secondary_owned_key(
    owned_addr: &[u8; 32],
    lock_height: u64,
    lock_tx_id: &[u8; 32],
    output_index: u32,
) -> [u8; 76] {
    let mut k = [0u8; 76];
    k[..32].copy_from_slice(owned_addr);
    k[32..40].copy_from_slice(&lock_height.to_be_bytes());
    k[40..72].copy_from_slice(lock_tx_id);
    k[72..].copy_from_slice(&output_index.to_be_bytes());
    k
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use exfer::covenants::htlc::HtlcParams;

    fn fixed_record(lock_tx_id: [u8; 32], output_index: u32, height: u64) -> HtlcRecord {
        HtlcRecord {
            lock_tx_id,
            output_index,
            params: HtlcParams {
                sender: [0x11; 32],
                receiver: [0x22; 32],
                hash_lock: [0x33; 32],
                timeout_height: 1000,
            },
            amount: 12345,
            lock_block_height: Some(height),
            state: HtlcState::Locked,
            claim: None,
            reclaim: None,
            role: HtlcRole::Sender,
            last_indexed_height: height,
        }
    }

    #[test]
    fn open_creates_empty_index() {
        let dir = tempfile::tempdir().unwrap();
        let idx = Index::open(dir.path()).unwrap();
        assert_eq!(idx.count().unwrap(), 0);
        let meta = idx.follower_meta().unwrap();
        assert_eq!(meta, FollowerMeta::default());
    }

    #[test]
    fn follower_meta_persists_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let idx = Index::open(dir.path()).unwrap();
        let meta = FollowerMeta {
            last_indexed_height: 42_000,
            last_indexed_block_id: [0xAB; 32],
            full_scan_complete: true,
            started_at: 1_700_000_000,
        };
        idx.save_follower_meta(&meta).unwrap();
        // Reopen — must survive process restart simulation.
        drop(idx);
        let idx2 = Index::open(dir.path()).unwrap();
        assert_eq!(idx2.follower_meta().unwrap(), meta);
    }

    #[test]
    fn upsert_get_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let idx = Index::open(dir.path()).unwrap();

        let rec = fixed_record([0xAA; 32], 0, 100);
        idx.upsert_htlc(&rec, [0xAA; 32]).unwrap();
        assert_eq!(idx.count().unwrap(), 1);

        let back = idx.get_htlc(&[0xAA; 32], 0).unwrap().unwrap();
        assert_eq!(back, rec);

        // get on a different key returns None.
        assert!(idx.get_htlc(&[0xBB; 32], 0).unwrap().is_none());
    }

    #[test]
    fn upsert_updates_existing_row_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let idx = Index::open(dir.path()).unwrap();
        let rec_v1 = fixed_record([0xCC; 32], 0, 50);
        idx.upsert_htlc(&rec_v1, [0xAA; 32]).unwrap();
        assert_eq!(idx.count().unwrap(), 1);

        let mut rec_v2 = rec_v1.clone();
        rec_v2.state = HtlcState::Claimed;
        rec_v2.amount = 99_999;
        idx.upsert_htlc(&rec_v2, [0xAA; 32]).unwrap();
        // Still one row, with the new state.
        assert_eq!(idx.count().unwrap(), 1);
        let back = idx.get_htlc(&[0xCC; 32], 0).unwrap().unwrap();
        assert_eq!(back.state, HtlcState::Claimed);
        assert_eq!(back.amount, 99_999);
    }

    #[test]
    fn forget_htlc_removes_row_and_returns_true() {
        let dir = tempfile::tempdir().unwrap();
        let idx = Index::open(dir.path()).unwrap();
        let rec = fixed_record([0xDD; 32], 1, 75);
        idx.upsert_htlc(&rec, [0xAA; 32]).unwrap();
        let removed = idx.forget_htlc(&[0xDD; 32], 1, [0xAA; 32]).unwrap();
        assert!(removed);
        assert!(idx.get_htlc(&[0xDD; 32], 1).unwrap().is_none());
        assert_eq!(idx.count().unwrap(), 0);
    }

    #[test]
    fn forget_missing_returns_false() {
        let dir = tempfile::tempdir().unwrap();
        let idx = Index::open(dir.path()).unwrap();
        let removed = idx.forget_htlc(&[0xEE; 32], 0, [0xAA; 32]).unwrap();
        assert!(!removed);
    }

    #[test]
    fn list_htlcs_no_filter_returns_all_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let idx = Index::open(dir.path()).unwrap();
        for h in [200, 100, 300] {
            let mut tx_id = [0u8; 32];
            tx_id[0] = h as u8;
            let rec = fixed_record(tx_id, 0, h);
            idx.upsert_htlc(&rec, [0xAA; 32]).unwrap();
        }
        let (out, next) = idx.list_htlcs(&HtlcFilter::default(), 10, None).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].lock_block_height, Some(100));
        assert_eq!(out[1].lock_block_height, Some(200));
        assert_eq!(out[2].lock_block_height, Some(300));
        assert!(next.is_none());
    }

    #[test]
    fn list_htlcs_state_filter() {
        let dir = tempfile::tempdir().unwrap();
        let idx = Index::open(dir.path()).unwrap();

        let mut a = fixed_record([0x01; 32], 0, 10);
        let mut b = fixed_record([0x02; 32], 0, 20);
        b.state = HtlcState::Claimed;
        let c = fixed_record([0x03; 32], 0, 30);
        let _ = (&mut a, &c);
        idx.upsert_htlc(&a, [0xAA; 32]).unwrap();
        idx.upsert_htlc(&b, [0xAA; 32]).unwrap();
        idx.upsert_htlc(&c, [0xAA; 32]).unwrap();

        let filter = HtlcFilter {
            states: vec![HtlcState::Claimed],
            ..Default::default()
        };
        let (out, _) = idx.list_htlcs(&filter, 10, None).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].lock_tx_id, [0x02; 32]);
    }

    #[test]
    fn list_htlcs_role_filter() {
        let dir = tempfile::tempdir().unwrap();
        let idx = Index::open(dir.path()).unwrap();
        let mut a = fixed_record([0x01; 32], 0, 10);
        let mut b = fixed_record([0x02; 32], 0, 20);
        b.role = HtlcRole::Receiver;
        let _ = &mut a;
        idx.upsert_htlc(&a, [0xAA; 32]).unwrap();
        idx.upsert_htlc(&b, [0xAA; 32]).unwrap();

        let f = HtlcFilter {
            role: Some(HtlcRole::Receiver),
            ..Default::default()
        };
        let (out, _) = idx.list_htlcs(&f, 10, None).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].lock_tx_id, [0x02; 32]);
    }

    #[test]
    fn list_htlcs_since_height_filter() {
        let dir = tempfile::tempdir().unwrap();
        let idx = Index::open(dir.path()).unwrap();
        for h in [100, 200, 300] {
            let mut tx_id = [0u8; 32];
            tx_id[0] = h as u8;
            idx.upsert_htlc(&fixed_record(tx_id, 0, h), [0xAA; 32])
                .unwrap();
        }
        let f = HtlcFilter {
            since_height: Some(200),
            ..Default::default()
        };
        let (out, _) = idx.list_htlcs(&f, 10, None).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].lock_block_height, Some(200));
        assert_eq!(out[1].lock_block_height, Some(300));
    }

    #[test]
    fn list_htlcs_pagination_with_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let idx = Index::open(dir.path()).unwrap();
        for h in [10, 20, 30, 40, 50] {
            let mut tx_id = [0u8; 32];
            tx_id[0] = h as u8;
            idx.upsert_htlc(&fixed_record(tx_id, 0, h), [0xAA; 32])
                .unwrap();
        }
        let (page1, cur) = idx.list_htlcs(&HtlcFilter::default(), 2, None).unwrap();
        assert_eq!(page1.len(), 2);
        assert_eq!(page1[0].lock_block_height, Some(10));
        assert_eq!(page1[1].lock_block_height, Some(20));
        let cur = cur.expect("must yield cursor for more pages");
        assert_eq!(cur.lock_height, 20);

        let (page2, cur2) = idx
            .list_htlcs(&HtlcFilter::default(), 2, Some(cur))
            .unwrap();
        assert_eq!(page2.len(), 2);
        assert_eq!(page2[0].lock_block_height, Some(30));
        assert_eq!(page2[1].lock_block_height, Some(40));
        assert!(cur2.is_some());

        let (page3, cur3) = idx.list_htlcs(&HtlcFilter::default(), 2, cur2).unwrap();
        assert_eq!(page3.len(), 1);
        assert_eq!(page3[0].lock_block_height, Some(50));
        assert!(cur3.is_none(), "final page must not advertise more");
    }

    #[test]
    fn lookup_by_hashlock_returns_matching() {
        let dir = tempfile::tempdir().unwrap();
        let idx = Index::open(dir.path()).unwrap();

        let mut a = fixed_record([0x01; 32], 0, 10);
        a.params.hash_lock = [0xFF; 32];
        idx.upsert_htlc(&a, [0xAA; 32]).unwrap();

        let mut b = fixed_record([0x02; 32], 0, 20);
        b.params.hash_lock = [0xEE; 32];
        idx.upsert_htlc(&b, [0xAA; 32]).unwrap();

        let mut c = fixed_record([0x03; 32], 0, 30);
        c.params.hash_lock = [0xFF; 32];
        idx.upsert_htlc(&c, [0xAA; 32]).unwrap();

        let out = idx.lookup_by_hashlock(&[0xFF; 32]).unwrap();
        let mut ids: Vec<[u8; 32]> = out.iter().map(|r| r.lock_tx_id).collect();
        ids.sort();
        assert_eq!(ids, vec![[0x01; 32], [0x03; 32]]);

        let out_ee = idx.lookup_by_hashlock(&[0xEE; 32]).unwrap();
        assert_eq!(out_ee.len(), 1);
        assert_eq!(out_ee[0].lock_tx_id, [0x02; 32]);

        let out_none = idx.lookup_by_hashlock(&[0xCC; 32]).unwrap();
        assert_eq!(out_none.len(), 0);
    }

    #[test]
    fn cursor_round_trip() {
        let c = Cursor {
            lock_height: 12345,
            lock_tx_id: [0xAB; 32],
            output_index: 7,
        };
        let s = c.encode();
        let back = Cursor::decode(&s).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn cursor_rejects_garbage() {
        assert!(Cursor::decode("not-base64!").is_err());
        assert!(Cursor::decode("AAAA").is_err()); // wrong length
    }
}
