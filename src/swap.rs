//! Cross-chain swap engine: EXFER ↔ USDT-BSC via HTLC ↔ HTLC atomic swaps,
//! with exfer-pool as the market-maker bot.
//!
//! walletd owns the whole lifecycle so secrets never leave the daemon: it
//! generates the preimage, locks the EXFER leg internally (via `tx::htlc`),
//! signs the BSC leg ([`crate::evm`]), persists every pending swap to an
//! encrypted journal ([`Journal`]), and a background monitor advances each swap
//! to settlement or timeout-refund.
//!
//! Two directions (see plan §"两腿 HTLC 编排"):
//!   - exfer_to_usdt (sell): user locks EXFER first (long timeout); pool mirrors
//!     USDT on BSC; user claims USDT (gasless relay); pool claims EXFER.
//!   - usdt_to_exfer (buy):  user locks USDT first (needs BNB); pool mirrors
//!     EXFER; user claims EXFER internally; pool claims USDT.
//!
//! This file: shared types + the encrypted [`Journal`]. The engine + monitor +
//! RPC handlers build on top (see `engine` submodule).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::store::WalletStore;

/// AAD binding the sealed journal to its purpose (domain separation from the
/// seed/vault blobs).
const JOURNAL_AAD: &[u8] = b"exfer-walletd/v1/swap-journal";
const JOURNAL_FILE: &str = "swaps.enc";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Sell EXFER for USDT. User locks EXFER first.
    ExferToUsdt,
    /// Buy EXFER with USDT. User locks USDT (on BSC) first.
    UsdtToExfer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapStatus {
    /// Quote obtained, preimage generated, nothing locked yet.
    Quoted,
    /// User's first leg locked on-chain.
    UserLocked,
    /// Pool mirrored the lock on the other chain.
    PoolLocked,
    /// We are claiming the counter-asset (revealing the preimage).
    Claiming,
    /// Both legs settled.
    Completed,
    /// A leg timed out; we are reclaiming the user's first lock.
    Refunding,
    /// First lock reclaimed after timeout.
    Refunded,
    /// Unrecoverable error (see `error`).
    Failed,
}

/// One pending/completed swap. The `preimage` is the secret; the whole record
/// is sealed at rest at the same security bar as private keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapRecord {
    /// Pool-assigned swap id.
    pub swap_id: String,
    pub direction: Direction,
    pub status: SwapStatus,

    /// 0x-prefixed hashlock (SHA-256 of the preimage).
    pub hashlock: String,
    /// 0x-prefixed 32-byte preimage (secret).
    pub preimage: String,

    /// Human-readable amounts (for UI).
    pub amount_in: String,
    pub amount_out: String,
    /// Smallest-unit amounts (EXFER=8dp, USDT=18dp on BSC).
    pub amount_in_units: String,
    pub amount_out_units: String,

    // ---- quote-derived params needed to drive both legs ----
    /// Pool's EXFER pubkey (receiver of the user's EXFER lock; sell direction).
    pub pool_exfer_pubkey: Option<String>,
    /// Pool's BSC address (recipient of the user's USDT lock; buy direction).
    pub pool_bsc_address: Option<String>,
    /// HTLC contract address on BSC (from the quote, never hardcoded).
    pub htlc_contract: Option<String>,
    /// USDT token address on BSC.
    pub usdt_token: Option<String>,
    /// Our own BSC address (recipient of pool's USDT lock; sell direction).
    pub our_bsc_address: Option<String>,
    /// Our own EXFER address/pubkey (recipient of pool's EXFER lock; buy direction).
    pub our_exfer_address: Option<String>,

    // ---- on-chain references ----
    pub user_lock_tx: Option<String>,
    pub pool_lock_ref: Option<String>,
    pub claim_tx: Option<String>,
    pub refund_tx: Option<String>,

    // ---- timeouts ----
    /// Block height the user's EXFER lock refunds at (sell direction).
    pub exfer_timeout_height: Option<u64>,
    /// Unix seconds the user's USDT lock refunds at (buy direction).
    pub bsc_timeout_sec: Option<u64>,
    /// Quote expiry (unix seconds); after this an unexecuted quote is dead.
    pub expires_at: u64,

    pub error: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

impl SwapRecord {
    /// Terminal states are never advanced by the monitor.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            SwapStatus::Completed | SwapStatus::Refunded | SwapStatus::Failed
        )
    }
}

/// Encrypted, crash-safe store of pending swaps.
///
/// In-memory map is authoritative for reads; the sealed file is rewritten on
/// every state transition (a handful of writes per swap — Argon2id cost is fine
/// at that cadence, and we never re-seal on a mere poll). Recovered on startup.
pub struct Journal {
    file: PathBuf,
    store: std::sync::Arc<dyn WalletStore>,
    records: Mutex<BTreeMap<String, SwapRecord>>,
}

impl Journal {
    /// Open (and decrypt) the journal in `dir`, or start empty if absent.
    pub fn open(dir: impl AsRef<Path>, store: std::sync::Arc<dyn WalletStore>) -> Result<Self> {
        let file = dir.as_ref().join(JOURNAL_FILE);
        let records = if file.exists() {
            let blob = std::fs::read(&file)
                .map_err(|e| Error::Internal(format!("read swap journal: {e}")))?;
            let plain = store.unseal_aux(JOURNAL_AAD, &blob)?;
            let list: Vec<SwapRecord> = serde_json::from_slice(&plain)
                .map_err(|e| Error::Internal(format!("parse swap journal: {e}")))?;
            list.into_iter().map(|r| (r.swap_id.clone(), r)).collect()
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            file,
            store,
            records: Mutex::new(records),
        })
    }

    fn persist_locked(&self, map: &BTreeMap<String, SwapRecord>) -> Result<()> {
        let list: Vec<&SwapRecord> = map.values().collect();
        let plain =
            serde_json::to_vec(&list).map_err(|e| Error::Internal(format!("ser journal: {e}")))?;
        let blob = self.store.seal_aux(JOURNAL_AAD, &plain)?;
        // Atomic write: tmp + rename so a crash mid-write can't corrupt it.
        let tmp = self.file.with_extension("enc.tmp");
        std::fs::write(&tmp, &blob).map_err(|e| Error::Internal(format!("write journal: {e}")))?;
        std::fs::rename(&tmp, &self.file)
            .map_err(|e| Error::Internal(format!("rename journal: {e}")))?;
        Ok(())
    }

    /// Insert or replace a record, then persist.
    pub fn put(&self, rec: SwapRecord) -> Result<()> {
        let mut map = self.records.lock().unwrap_or_else(|e| e.into_inner());
        map.insert(rec.swap_id.clone(), rec);
        self.persist_locked(&map)
    }

    /// Mutate a record in place via `f`, bump `updated_at`, then persist.
    /// `now` is supplied by the caller (no wall-clock reads buried in here).
    pub fn update<F>(&self, swap_id: &str, now: u64, f: F) -> Result<()>
    where
        F: FnOnce(&mut SwapRecord),
    {
        let mut map = self.records.lock().unwrap_or_else(|e| e.into_inner());
        let rec = map
            .get_mut(swap_id)
            .ok_or_else(|| Error::BadParams(format!("unknown swap_id {swap_id}")))?;
        f(rec);
        rec.updated_at = now;
        self.persist_locked(&map)
    }

    pub fn get(&self, swap_id: &str) -> Option<SwapRecord> {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(swap_id)
            .cloned()
    }

    /// All records, newest first.
    pub fn list(&self) -> Vec<SwapRecord> {
        let mut v: Vec<SwapRecord> = self
            .records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect();
        v.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        v
    }

    /// Non-terminal records the monitor still needs to advance.
    pub fn pending(&self) -> Vec<SwapRecord> {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|r| !r.is_terminal())
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::keyring::KeyringStore;
    use std::sync::Arc;

    fn test_store(dir: &Path) -> Arc<dyn WalletStore> {
        // Seeded keyring so seal_aux/unseal_aux have a passphrase.
        Arc::new(KeyringStore::open_or_init_fresh(dir, b"test-pass-123").unwrap())
    }

    fn sample(id: &str, now: u64) -> SwapRecord {
        SwapRecord {
            swap_id: id.into(),
            direction: Direction::ExferToUsdt,
            status: SwapStatus::Quoted,
            hashlock: "0x".to_string() + &"ab".repeat(32),
            preimage: "0x".to_string() + &"cd".repeat(32),
            amount_in: "1.0".into(),
            amount_out: "0.99".into(),
            amount_in_units: "100000000".into(),
            amount_out_units: "990000000000000000".into(),
            pool_exfer_pubkey: None,
            pool_bsc_address: None,
            htlc_contract: None,
            usdt_token: None,
            our_bsc_address: None,
            our_exfer_address: None,
            user_lock_tx: None,
            pool_lock_ref: None,
            claim_tx: None,
            refund_tx: None,
            exfer_timeout_height: None,
            bsc_timeout_sec: None,
            expires_at: now + 600,
            error: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn journal_roundtrip_and_recover() {
        let dir = tempfile::tempdir().unwrap();
        let store = test_store(dir.path());

        let j = Journal::open(dir.path(), store.clone()).unwrap();
        j.put(sample("swap-1", 1000)).unwrap();
        j.update("swap-1", 1001, |r| {
            r.status = SwapStatus::UserLocked;
            r.user_lock_tx = Some("0xdead".into());
        })
        .unwrap();

        // Reopen with the same store/passphrase: state must survive (crash-safe).
        let j2 = Journal::open(dir.path(), store).unwrap();
        let rec = j2.get("swap-1").expect("recovered");
        assert_eq!(rec.status, SwapStatus::UserLocked);
        assert_eq!(rec.user_lock_tx.as_deref(), Some("0xdead"));
        assert_eq!(rec.preimage, "0x".to_string() + &"cd".repeat(32));
        assert_eq!(j2.pending().len(), 1);
    }

    #[test]
    fn wrong_passphrase_cannot_read() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = test_store(dir.path());
            let j = Journal::open(dir.path(), store).unwrap();
            j.put(sample("s", 1)).unwrap();
        }
        // A different keystore/passphrase must fail to unseal.
        let other = tempfile::tempdir().unwrap();
        let wrong: Arc<dyn WalletStore> =
            Arc::new(KeyringStore::open_or_init_fresh(other.path(), b"different").unwrap());
        // Point the wrong store at the original journal file dir.
        let res = Journal::open(dir.path(), wrong);
        assert!(res.is_err(), "wrong passphrase must not decrypt the journal");
    }
}
