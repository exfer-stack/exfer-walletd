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
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::evm::{evm_address, EvmClient};
use crate::indexer::IndexerClient;
use crate::inflight::InFlightUtxos;
use crate::store::WalletStore;
use crate::upstream::ExferNode;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parse a human USDT amount (≤18 dp) into 18-decimal smallest units.
fn parse_units_18(s: &str) -> Result<alloy::primitives::U256> {
    let s = s.trim();
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if (whole.is_empty() && frac.is_empty())
        || !whole.chars().all(|c| c.is_ascii_digit())
        || !frac.chars().all(|c| c.is_ascii_digit())
    {
        return Err(Error::BadParams("amount must be a decimal number".into()));
    }
    if frac.len() > 18 {
        return Err(Error::BadParams("USDT has at most 18 decimals".into()));
    }
    let mut combined = String::from(whole);
    combined.push_str(frac);
    for _ in frac.len()..18 {
        combined.push('0');
    }
    alloy::primitives::U256::from_str_radix(&combined, 10)
        .map_err(|e| Error::BadParams(format!("bad amount: {e}")))
}

/// The funds-safety reveal-gate, as a pure predicate so it can be unit-tested
/// without any network. Returns true ONLY when the pool's on-chain BNB lock is
/// safe to claim against — i.e. safe to reveal our preimage. ALL must hold:
///   - state == Locked (not None/Claimed/Refunded),
///   - recipient == our derived BSC address (it pays US),
///   - amount >= the quoted output (we get at least what we were promised),
///   - enough time left before the lock's timeout to land our claim.
///
/// If any is false we must NOT reveal the preimage (we'd give away the EXFER
/// leg with nothing guaranteed in return).
fn pool_lock_safe_to_claim(
    oc: &crate::evm::OnChainSwap,
    our: alloy::primitives::Address,
    want_out: alloy::primitives::U256,
    now: u64,
) -> bool {
    oc.state == crate::evm::HtlcState::Locked
        && oc.recipient == our
        && oc.amount >= want_out
        && now + CLAIM_MARGIN_SECS < oc.timeout_sec
}

/// AAD binding the sealed journal to its purpose (domain separation from the
/// seed/vault blobs).
const JOURNAL_AAD: &[u8] = b"exfer-walletd/v1/swap-journal";
const JOURNAL_FILE: &str = "swaps.enc";

/// AAD + filename for the native-BNB transfer log (a separate domain from the
/// swap journal so a blob from one can never be decrypted as the other).
const BNBLOG_AAD: &[u8] = b"exfer-walletd/v1/bnb-txlog";
const BNBLOG_FILE: &str = "bnb-txs.enc";

/// Margin before the pool's BSC lock expiry within which we still consider it
/// safe to reveal the preimage (the claim needs time to mine). Sized well above
/// this deployment's observed worst case: the 2026-06-06 incident saw a 65s
/// block-propagation stall, and BSC RPC reads (`latest`) can themselves lag the
/// chain by tens of seconds — so the wall-clock check here can believe more time
/// remains than really does. 600s left only ~6-10 blocks of cushion for a
/// value-bearing reveal; 1800s (30 min) keeps a deep margin while still being
/// far under the pool leg's lifetime (poolHtlcHours, 12h) and the minimum lock we
/// accept (MIN_BSC_LOCK_SECS, 2h), so it never rejects an otherwise-good claim.
const CLAIM_MARGIN_SECS: u64 = 1800;
/// Minimum user-leg lock duration we'll accept from the pool, so the user keeps
/// a generous reclaim window even if the pool stalls/vanishes.
const MIN_EXFER_LOCK_BLOCKS: u64 = 360; // ~1h at 10s blocks
const MIN_BSC_LOCK_SECS: u64 = 2 * 3600;
/// While a claim is broadcast but not yet confirmed on-chain, re-broadcast it at
/// most this often if it hasn't landed (covers a reorg/mempool eviction without
/// spamming the network every monitor tick).
const CLAIM_REBROADCAST_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Sell EXFER for BNB. User locks EXFER first.
    ExferToBnb,
    /// Buy EXFER with BNB. User locks BNB (on BSC) first.
    BnbToExfer,
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
    /// A quote the user never executed — its validity window lapsed. NOT a
    /// failure (no funds ever moved); it's a price quote that was never acted
    /// on. Surfaced separately so it isn't shown as a failed swap.
    Expired,
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
    /// Smallest-unit amounts (EXFER=8dp, BNB=18dp on BSC).
    pub amount_in_units: String,
    pub amount_out_units: String,

    // ---- quote-derived params needed to drive both legs ----
    /// Pool's EXFER pubkey (receiver of the user's EXFER lock; sell direction).
    pub pool_exfer_pubkey: Option<String>,
    /// Pool's BSC address (recipient of the user's BNB lock; buy direction).
    pub pool_bsc_address: Option<String>,
    /// HTLC contract address on BSC (from the quote, never hardcoded).
    pub htlc_contract: Option<String>,
    /// Our own BSC address (recipient of pool's BNB lock; sell direction).
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
    /// AMM fee in basis points (e.g. 30 = 0.30%), reflected in amount_out.
    #[serde(default)]
    pub fee_bps: u32,
    /// Network fee (human BNB) the pool kept to cover its settlement gas —
    /// already deducted from amount_out. Surfaced so the client can disclose it.
    #[serde(default)]
    pub network_fee_bnb: Option<String>,

    pub error: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

impl SwapRecord {
    /// Terminal states are never advanced by the monitor.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            SwapStatus::Completed | SwapStatus::Refunded | SwapStatus::Expired | SwapStatus::Failed
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

    /// Remove a record entirely (and persist). Used to prune un-executed quotes
    /// that expired — they hold no funds and need no recovery, so keeping them
    /// only clutters the user's history. Idempotent.
    pub fn remove(&self, swap_id: &str) -> Result<()> {
        let mut map = self.records.lock().unwrap_or_else(|e| e.into_inner());
        if map.remove(swap_id).is_some() {
            self.persist_locked(&map)?;
        }
        Ok(())
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
        v.sort_by_key(|r| std::cmp::Reverse(r.created_at));
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

// ───────────────────────── BNB tx log ─────────────────────────

/// One native-BNB transfer we initiated. `status` starts "pending" and the
/// monitor flips it to "confirmed"/"failed" from the on-chain receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnbTx {
    /// 0x-prefixed 32-byte tx hash (routes to BscScan in the UI).
    pub hash: String,
    /// "out" for a withdrawal we sent. (Deposits, when added, will be "in".)
    pub direction: String,
    /// Our derived BSC address (the sender).
    pub from: String,
    /// The counterparty address.
    pub to: String,
    /// Value moved, in wei (18 dp).
    pub amount_wei: String,
    /// "pending" | "confirmed" | "failed".
    pub status: String,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Encrypted, crash-safe log of native-BNB transfers we initiated. No indexer
/// watches the BSC address, so without this a withdrawal's txhash would be lost
/// the moment its toast faded; the Activity feed reads this to show a sent-BNB
/// row with an explorer link. Sealed at the same bar as the swap journal.
pub struct BnbTxLog {
    file: PathBuf,
    store: Arc<dyn WalletStore>,
    records: Mutex<Vec<BnbTx>>,
}

impl BnbTxLog {
    pub fn open(dir: impl AsRef<Path>, store: Arc<dyn WalletStore>) -> Result<Self> {
        let file = dir.as_ref().join(BNBLOG_FILE);
        let records: Vec<BnbTx> = if file.exists() {
            let blob = std::fs::read(&file)
                .map_err(|e| Error::Internal(format!("read bnb txlog: {e}")))?;
            let plain = store.unseal_aux(BNBLOG_AAD, &blob)?;
            serde_json::from_slice(&plain)
                .map_err(|e| Error::Internal(format!("parse bnb txlog: {e}")))?
        } else {
            Vec::new()
        };
        Ok(Self {
            file,
            store,
            records: Mutex::new(records),
        })
    }

    fn persist_locked(&self, list: &[BnbTx]) -> Result<()> {
        let plain =
            serde_json::to_vec(list).map_err(|e| Error::Internal(format!("ser bnb txlog: {e}")))?;
        let blob = self.store.seal_aux(BNBLOG_AAD, &plain)?;
        let tmp = self.file.with_extension("enc.tmp");
        std::fs::write(&tmp, &blob)
            .map_err(|e| Error::Internal(format!("write bnb txlog: {e}")))?;
        std::fs::rename(&tmp, &self.file)
            .map_err(|e| Error::Internal(format!("rename bnb txlog: {e}")))?;
        Ok(())
    }

    /// Append a transfer (idempotent on hash), then persist.
    pub fn record(&self, tx: BnbTx) -> Result<()> {
        let mut list = self.records.lock().unwrap_or_else(|e| e.into_inner());
        if list.iter().any(|t| t.hash.eq_ignore_ascii_case(&tx.hash)) {
            return Ok(());
        }
        list.push(tx);
        self.persist_locked(&list)
    }

    /// Flip a tx's status (e.g. pending → confirmed); persists only on change.
    pub fn set_status(&self, hash: &str, status: &str, now: u64) -> Result<()> {
        let mut list = self.records.lock().unwrap_or_else(|e| e.into_inner());
        let mut changed = false;
        for t in list.iter_mut() {
            if t.hash.eq_ignore_ascii_case(hash) && t.status != status {
                t.status = status.to_string();
                t.updated_at = now;
                changed = true;
            }
        }
        if changed {
            self.persist_locked(&list)
        } else {
            Ok(())
        }
    }

    /// All transfers, newest first.
    pub fn list(&self) -> Vec<BnbTx> {
        let mut v = self
            .records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        v.sort_by_key(|t| std::cmp::Reverse(t.created_at));
        v
    }

    /// Hashes still awaiting a receipt — the set the history call re-checks.
    pub fn pending_hashes(&self) -> Vec<String> {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|t| t.status == "pending")
            .map(|t| t.hash.clone())
            .collect()
    }
}

// ───────────────────────── pool client ─────────────────────────

/// HTTP client for the exfer-pool market-maker bot.
#[derive(Clone)]
pub struct PoolClient {
    http: reqwest::Client,
    base_url: String,
}

#[derive(Deserialize)]
struct BscInstr {
    #[serde(rename = "htlcContract")]
    htlc_contract: String,
    recipient: String,
    #[serde(rename = "timeoutSec")]
    timeout_sec: u64,
}

#[derive(Deserialize)]
struct ExferInstr {
    #[serde(rename = "receiverPubkey")]
    receiver_pubkey: String,
    #[serde(rename = "timeoutHeight")]
    timeout_height: u64,
}

#[derive(Deserialize)]
struct Instructions {
    #[serde(default)]
    bsc: Option<BscInstr>,
    #[serde(default)]
    exfer: Option<ExferInstr>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct QuoteResp {
    swap_id: String,
    amount_in: String,
    amount_out: String,
    amount_in_units: String,
    amount_out_units: String,
    expires_at: u64,
    #[serde(default)]
    fee_bps: u32,
    #[serde(default)]
    network_fee_bnb: Option<String>,
    // Present for both directions (sell only carries an EXFER lock in
    // `instructions`, but we still need the BSC contract ref to verify/relay).
    #[serde(default)]
    htlc_contract: Option<String>,
    instructions: Instructions,
}

impl PoolClient {
    pub fn new(base_url: impl Into<String>, ca_pem: Option<String>) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        // When a pool CA is pinned, trust ONLY it (disable the public CA bundle)
        // so a self-signed pool cert is verified, but a MITM holding any
        // CA-signed cert cannot impersonate the pool and tamper with quotes /
        // deposit addresses. Absent → default client (public roots / plain HTTP).
        let http = match ca_pem {
            Some(pem) if !pem.trim().is_empty() => reqwest::Certificate::from_pem(pem.as_bytes())
                .and_then(|cert| {
                    reqwest::Client::builder()
                        .add_root_certificate(cert)
                        .tls_built_in_root_certs(false)
                        .build()
                })
                .unwrap_or_else(|e| {
                    tracing::error!("pinned pool CA invalid ({e}); using default TLS client");
                    reqwest::Client::new()
                }),
            _ => reqwest::Client::new(),
        };
        Self { http, base_url }
    }

    async fn quote(
        &self,
        direction: Direction,
        amount_in_human: &str,
        hashlock: &str,
        user_bsc_address: Option<&str>,
        user_exfer_address: Option<&str>,
    ) -> Result<QuoteResp> {
        let dir = match direction {
            Direction::ExferToBnb => "exfer_to_bnb",
            Direction::BnbToExfer => "bnb_to_exfer",
        };
        let body = serde_json::json!({
            "direction": dir,
            "amount_in": amount_in_human,
            "hashlock": hashlock,
            "user_bsc_address": user_bsc_address,
            "user_exfer_address": user_exfer_address,
        });
        let resp = self
            .http
            .post(format!("{}/api/quote", self.base_url))
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::UpstreamUnreachable(format!("pool /api/quote: {e}")))?;
        if !resp.status().is_success() {
            let txt = resp.text().await.unwrap_or_default();
            return Err(Error::UpstreamUnexpected(format!(
                "pool quote rejected: {txt}"
            )));
        }
        resp.json::<QuoteResp>()
            .await
            .map_err(|e| Error::UpstreamUnexpected(format!("pool quote decode: {e}")))
    }

    /// GET /api/pool → indicative pool stats (mid price + fee) for the UI's
    /// pre-quote rate preview. Best-effort: a flaky pool just hides the preview.
    async fn pool_info(&self) -> Result<serde_json::Value> {
        self.http
            .get(format!("{}/api/pool", self.base_url))
            .send()
            .await
            .map_err(|e| Error::UpstreamUnreachable(format!("pool /api/pool: {e}")))?
            .json()
            .await
            .map_err(|e| Error::UpstreamUnexpected(format!("pool info decode: {e}")))
    }

    async fn get_swap(&self, id: &str) -> Result<serde_json::Value> {
        self.http
            .get(format!("{}/api/swap/{id}", self.base_url))
            .send()
            .await
            .map_err(|e| Error::UpstreamUnreachable(format!("pool /api/swap: {e}")))?
            .json()
            .await
            .map_err(|e| Error::UpstreamUnexpected(format!("pool swap decode: {e}")))
    }

    // ── liquidity-provider proxies (thin pass-throughs to the pool's /api/lp) ──
    async fn lp_get(&self, path: &str) -> Result<serde_json::Value> {
        self.http
            .get(format!("{}{}", self.base_url, path))
            .send()
            .await
            .map_err(|e| Error::UpstreamUnreachable(format!("pool {path}: {e}")))?
            .json()
            .await
            .map_err(|e| Error::UpstreamUnexpected(format!("pool {path} decode: {e}")))
    }

    async fn lp_post(&self, path: &str, body: serde_json::Value) -> Result<serde_json::Value> {
        self.http
            .post(format!("{}{}", self.base_url, path))
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::UpstreamUnreachable(format!("pool {path}: {e}")))?
            .json()
            .await
            .map_err(|e| Error::UpstreamUnexpected(format!("pool {path} decode: {e}")))
    }

    async fn notify_exfer_lock(&self, id: &str, tx_id: &str) -> Result<()> {
        self.http
            .post(format!("{}/api/swap/{id}/notify-exfer-lock", self.base_url))
            .json(&serde_json::json!({ "exfer_lock_tx_id": tx_id }))
            .send()
            .await
            .map_err(|e| Error::UpstreamUnreachable(format!("pool notify-exfer-lock: {e}")))?;
        Ok(())
    }

    async fn relay_claim(&self, id: &str, preimage: &str) -> Result<serde_json::Value> {
        let resp = self
            .http
            .post(format!("{}/api/swap/{id}/relay-claim", self.base_url))
            .json(&serde_json::json!({ "preimage": preimage }))
            .send()
            .await
            .map_err(|e| Error::UpstreamUnreachable(format!("pool relay-claim: {e}")))?;
        if !resp.status().is_success() {
            let txt = resp.text().await.unwrap_or_default();
            return Err(Error::UpstreamUnexpected(format!(
                "relay-claim rejected: {txt}"
            )));
        }
        resp.json()
            .await
            .map_err(|e| Error::UpstreamUnexpected(format!("relay-claim decode: {e}")))
    }
}

// ───────────────────────── engine ─────────────────────────

#[derive(Clone)]
pub struct EngineConfig {
    pub pool_url: String,
    /// PEM of the pool's TLS cert to pin (self-signed HTTPS). None → default TLS.
    pub pool_ca_pem: Option<String>,
    pub bsc_rpc_url: String,
    pub bsc_chain_id: u64,
}

/// Owns the full swap lifecycle. Secrets stay in the daemon; the engine signs
/// both legs (EXFER via `tx::htlc`, BSC via [`EvmClient`]) and persists every
/// transition to the encrypted [`Journal`].
pub struct SwapEngine {
    store: Arc<dyn WalletStore>,
    node: Arc<ExferNode>,
    inflight: Arc<InFlightUtxos>,
    indexer: Option<IndexerClient>,
    evm: EvmClient,
    pool: PoolClient,
    journal: Arc<Journal>,
    /// Local log of native-BNB transfers we initiated, for the Activity feed.
    bnb_log: Arc<BnbTxLog>,
    /// BSC chain id (56 mainnet / 97 testnet) — surfaced so the UI picks the
    /// right explorer base.
    bsc_chain_id: u64,
    /// Serializes BSC sends from our single derived account (nonce safety).
    bsc_lock: tokio::sync::Mutex<()>,
    /// Lock outpoints (`lock_tx_id ++ output_index`) the chain-driven sweep has
    /// already broadcast a reclaim for this session. Stops [`sweep_stranded_locks`]
    /// from re-broadcasting the same reclaim every tick (and on every app reopen)
    /// during the block or two before the indexer flips the HTLC to `reclaimed`.
    swept_locks: std::sync::Mutex<std::collections::HashSet<[u8; 36]>>,
    /// Hashlocks (`0x`, lowercased) the BNB sweep has already broadcast a refund
    /// for this session — the BSC analog of `swept_locks`. Stops re-sending a
    /// refund every tick before the chain flips the HTLC to `Refunded`.
    swept_bnb: std::sync::Mutex<std::collections::HashSet<String>>,
    /// In-memory high-water block for the stranded-BNB `eth_getLogs` scan. `0` =
    /// not yet scanned: the first sweep of a session scans from the contract's
    /// deploy block (recovering anything stranded while the app was closed), then
    /// later ticks scan only new blocks. Reset to `0` on restart (fresh engine) so
    /// every app launch re-does the full recovery scan — exactly when we want it.
    bsc_sweep_cursor: std::sync::Mutex<u64>,
    /// Per-swap_id async locks. execute()/refund() are check-then-act across long
    /// awaits (broadcast a lock, then flip status); without this a double-tapped
    /// or retried call would pass the status guard twice and lock the first leg
    /// twice (extra BNB / orphaned EXFER lock / wasted gas). Holding a per-swap
    /// lock serializes them so the loser re-reads a now non-Quoted status and
    /// returns the existing record (idempotent).
    swap_locks: std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

fn strip0x(s: &str) -> &str {
    s.trim_start_matches("0x")
}

/// The fixed ExferHtlc deployment `(contract, scan_floor_block)` for a BSC chain
/// id, or `None` for an unknown/dev chain (the stranded-BNB sweep then no-ops).
/// The floor bounds the `eth_getLogs` history scan: no lock can predate the
/// contract's first `Locked` event, so scanning below it only wastes calls.
///
/// The pool uses ONE long-lived HTLC per chain (it custodies in-flight funds, so
/// the address is effectively permanent — `GET /api/pool` → `bsc.htlc_contract`).
/// Mainnet (56) `0x4Fdf…` is the live deployment; the floor is set just below its
/// first observed lock (block 104_450_944). A pool HTLC redeploy is a coordinated
/// release that must update this table. Testnet (97) mirrors
/// `deployment-htlc-97.json`.
fn bsc_htlc_for_chain(chain_id: u64) -> Option<(&'static str, u64)> {
    match chain_id {
        56 => Some(("0x4FdfB5f599cB84b87693aCCA1B9D57f5236e2E3d", 104_440_000)),
        97 => Some(("0xBAd7f057c8196fF1b724fa1D8cb9D2397780E54d", 0)),
        _ => None,
    }
}

/// Blocks to rewind the in-memory sweep cursor each pass, so a shallow BSC reorg
/// just below the last scanned tip can't hide a lock. Re-scanning a few blocks is
/// free — the per-hashlock on-chain check + dedup set make it idempotent.
const BSC_SWEEP_REORG_MARGIN: u64 = 50;

fn hash256_from_hex(s: &str) -> Result<exfer::types::Hash256> {
    Ok(exfer::types::Hash256(crate::tx::decode_hash(strip0x(s))?))
}

/// A stranded HTLC lock the chain sweep can reclaim: decoded, ready to spend.
struct ReclaimableLock {
    lock_tx: exfer::types::Hash256,
    output_index: u32,
    receiver: [u8; 32],
    hashlock: exfer::types::Hash256,
    timeout: u64,
    /// `0x`-prefixed hashlock, for matching back to a journal record.
    hashlock_0x: String,
    /// Raw lock-tx hex, for logging.
    lock_tx_hex: String,
}

/// Decide whether one `htlc_list` row is a stranded lock WE can reclaim now, and
/// if so decode its reclaim params. Pure (no I/O) so the field-name / sender-vs-
/// receiver / timeout-boundary logic — where the bugs hide — is unit-testable
/// against the real indexer JSON shape. Returns `None` to skip the row.
///
/// Reclaimable ⇔ all hold: funds are still in the HTLC (neither arm fired), WE
/// are the sender (the address filter also returns locks we *received*, which
/// are claimed not reclaimed), the tip is strictly past the timeout (the refund
/// arm needs `height > timeout`), and every param decodes.
fn decode_reclaimable_lock(
    my_pubkey: &str,
    tip: u64,
    h: &serde_json::Value,
) -> Option<ReclaimableLock> {
    let params = h.get("params")?;
    let sender = params.get("sender").and_then(|v| v.as_str()).unwrap_or("");
    if !sender.eq_ignore_ascii_case(my_pubkey) {
        return None;
    }
    // Funds remain in the HTLC only while neither arm has fired. Do NOT key on
    // the `state` string: a past-timeout lock is reported as `locked` OR
    // `locked_expired` depending on whether it was mined before or after its
    // own timeout height, and BOTH are reclaimable. A present `claim`/`reclaim`
    // is the on-chain proof it's already settled — then there's nothing to do.
    let claimed = h.get("claim").is_some_and(|v| !v.is_null());
    let reclaimed = h.get("reclaim").is_some_and(|v| !v.is_null());
    if claimed || reclaimed {
        return None;
    }
    let timeout = params.get("timeout_height").and_then(|v| v.as_u64())?;
    if tip <= timeout {
        return None;
    }
    let lock_tx_hex = h.get("lock_tx_id").and_then(|v| v.as_str())?.to_string();
    let output_index = u32::try_from(h.get("output_index").and_then(|v| v.as_u64())?).ok()?;
    let receiver_hex = params.get("receiver").and_then(|v| v.as_str())?;
    let hashlock_hex = params.get("hash_lock").and_then(|v| v.as_str())?;

    Some(ReclaimableLock {
        lock_tx: hash256_from_hex(&lock_tx_hex).ok()?,
        output_index,
        receiver: crate::tx::decode_hash(strip0x(receiver_hex)).ok()?,
        hashlock: hash256_from_hex(hashlock_hex).ok()?,
        timeout,
        hashlock_0x: format!("0x{}", strip0x(hashlock_hex)),
        lock_tx_hex,
    })
}

impl SwapEngine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Arc<dyn WalletStore>,
        node: Arc<ExferNode>,
        inflight: Arc<InFlightUtxos>,
        indexer: Option<IndexerClient>,
        journal: Arc<Journal>,
        bnb_log: Arc<BnbTxLog>,
        cfg: EngineConfig,
    ) -> Self {
        let evm = EvmClient::new(cfg.bsc_rpc_url.clone(), cfg.bsc_chain_id);
        let pool = PoolClient::new(cfg.pool_url.clone(), cfg.pool_ca_pem.clone());
        Self {
            store,
            node,
            inflight,
            indexer,
            evm,
            pool,
            journal,
            bnb_log,
            bsc_chain_id: cfg.bsc_chain_id,
            bsc_lock: tokio::sync::Mutex::new(()),
            swap_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
            swept_locks: std::sync::Mutex::new(std::collections::HashSet::new()),
            swept_bnb: std::sync::Mutex::new(std::collections::HashSet::new()),
            bsc_sweep_cursor: std::sync::Mutex::new(0),
        }
    }

    pub fn journal(&self) -> &Arc<Journal> {
        &self.journal
    }

    /// A lock unique to `swap_id`, so concurrent execute()/refund() calls for the
    /// same swap run one-at-a-time. Entries are cheap and few (a wallet makes few
    /// swaps), so they're left in the map rather than reaped.
    fn swap_lock(&self, swap_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self.swap_locks.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(swap_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Indicative pool stats for the UI's pre-quote rate preview:
    /// `{ mid_price_bnb_per_exfer, fee_bps }`. Best-effort.
    pub async fn pool_info(&self) -> Result<serde_json::Value> {
        let v = self.pool.pool_info().await?;
        let reserves = v.get("reserves");
        Ok(serde_json::json!({
            "mid_price_bnb_per_exfer": v.get("mid_price_bnb_per_exfer").cloned().unwrap_or(serde_json::Value::Null),
            "fee_bps": v.get("fee_bps").cloned().unwrap_or(serde_json::Value::Null),
            "max_swap_bps": v.get("max_swap_bps").cloned().unwrap_or(serde_json::Value::Null),
            // Human reserves so the UI can pre-warn when an amount exceeds what
            // the pool can fill (rather than only erroring on Review).
            "exfer_reserve": reserves.and_then(|r| r.get("exfer")).cloned().unwrap_or(serde_json::Value::Null),
            "bnb_reserve": reserves.and_then(|r| r.get("bnb")).cloned().unwrap_or(serde_json::Value::Null),
        }))
    }

    // ── liquidity-provider proxies (pass the pool's /api/lp through to the app) ──
    pub async fn lp_pool_info(&self) -> Result<serde_json::Value> {
        self.pool.lp_get("/api/lp").await
    }
    pub async fn price_klines(&self, interval: &str, limit: u32) -> Result<serde_json::Value> {
        self.pool
            .lp_get(&format!(
                "/api/price/klines?interval={interval}&limit={limit}"
            ))
            .await
    }
    pub async fn lp_position(&self, exfer_address: &str) -> Result<serde_json::Value> {
        self.pool
            .lp_get(&format!("/api/lp/position/{exfer_address}"))
            .await
    }
    pub async fn lp_deposit_start(
        &self,
        exfer_address: &str,
        bsc_address: &str,
    ) -> Result<serde_json::Value> {
        self.pool
            .lp_post(
                "/api/lp/deposit/start",
                serde_json::json!({ "exfer_address": exfer_address, "bsc_address": bsc_address }),
            )
            .await
    }
    pub async fn lp_deposit_status(&self, id: &str) -> Result<serde_json::Value> {
        self.pool.lp_get(&format!("/api/lp/deposit/{id}")).await
    }
    pub async fn lp_withdraw_self(
        &self,
        exfer_address: &str,
        shares: &str,
    ) -> Result<serde_json::Value> {
        self.pool
            .lp_post(
                "/api/lp/withdraw/self",
                serde_json::json!({ "exfer_address": exfer_address, "shares": shares }),
            )
            .await
    }

    /// Derived BSC address (EIP-55) for receiving / depositing BNB.
    pub fn bsc_address(&self) -> Result<String> {
        let secret = self.store.evm_secret()?;
        evm_address(&secret)
    }

    async fn load_signer(&self, address_hex: &str) -> Result<crate::store::Signer> {
        let store = self.store.clone();
        let a = address_hex.to_string();
        tokio::task::spawn_blocking(move || store.load_by_address(&a))
            .await
            .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))?
    }

    /// Native BNB balance (wei) for the derived BSC address, as a decimal
    /// string. Lets the UI pre-flight a buy (BNB is both principal and gas).
    /// Returns `(bnb_wei, sweep_reserve_wei)` — the live balance and the wei the
    /// UI should hold back when offering a "send everything" amount, so it can
    /// show a real number (balance − reserve) instead of a placeholder.
    pub async fn bsc_balances(&self) -> Result<(String, String)> {
        let secret = self.store.evm_secret()?;
        let addr = secret_address(&secret)?;
        let bnb = self.evm.bnb_balance(addr).await?;
        let reserve = self.evm.sweep_gas_reserve().await;
        Ok((bnb.to_string(), reserve.to_string()))
    }

    /// Withdraw native BNB from the derived BSC address to an external wallet
    /// (exchange / another wallet). `amount_human` is in BNB (18 dp); empty or
    /// "max" sends the whole balance minus a gas reserve. Returns the tx hash.
    pub async fn send_bnb(&self, to: &str, amount_human: &str) -> Result<String> {
        let secret = self.store.evm_secret()?;
        let addr = secret_address(&secret)?;
        let amount = if amount_human.trim().is_empty() || amount_human.eq_ignore_ascii_case("max") {
            // Leave a (live-priced) reserve for the transfer's own gas.
            let bal = self.evm.bnb_balance(addr).await?;
            bal.saturating_sub(self.evm.sweep_gas_reserve().await)
        } else {
            parse_units_18(amount_human)?
        };
        if amount.is_zero() {
            return Err(Error::BadParams(
                "nothing to send (zero BNB after gas reserve)".into(),
            ));
        }
        let hash = {
            let _guard = self.bsc_lock.lock().await;
            self.evm.send_bnb(&secret, to, amount).await?
        };
        // Record it so the Activity feed can show this withdrawal (txhash +
        // explorer link). Best-effort: a log failure must not lose the txhash
        // the user needs, so we return it regardless.
        let now = now_secs();
        if let Err(e) = self.bnb_log.record(BnbTx {
            hash: hash.clone(),
            direction: "out".into(),
            from: addr.to_checksum(None),
            to: to.to_string(),
            amount_wei: amount.to_string(),
            status: "pending".into(),
            created_at: now,
            updated_at: now,
        }) {
            tracing::warn!(err = %e, "failed to record BNB withdrawal in txlog");
        }
        Ok(hash)
    }

    /// Native-BNB transfer history (currently withdrawals we initiated). Before
    /// returning, it refreshes any still-pending tx from its on-chain receipt so
    /// the UI sees confirmations without a separate monitor. `chain_id` lets the
    /// client route the explorer (56 → bscscan.com, 97 → testnet.bscscan.com).
    pub async fn bnb_tx_history(&self) -> Result<serde_json::Value> {
        for hash in self.bnb_log.pending_hashes() {
            match self.evm.receipt_status(&hash).await {
                Ok(Some(true)) => {
                    let _ = self.bnb_log.set_status(&hash, "confirmed", now_secs());
                }
                Ok(Some(false)) => {
                    let _ = self.bnb_log.set_status(&hash, "failed", now_secs());
                }
                // Not yet mined, or a transient RPC error — leave it pending.
                _ => {}
            }
        }
        Ok(serde_json::json!({
            "chain_id": self.bsc_chain_id,
            "txs": self.bnb_log.list(),
        }))
    }

    /// Quote + reserve a swap. Generates the preimage (kept secret), persists a
    /// `Quoted` record. `from_exfer` is the EXFER address that funds (sell) or
    /// receives (buy) the EXFER leg.
    pub async fn get_quote(
        &self,
        direction: Direction,
        amount_in_human: String,
        from_exfer: String,
    ) -> Result<SwapRecord> {
        use rand::RngCore;
        use sha2::{Digest, Sha256};

        let secret = self.store.evm_secret()?;
        let our_bsc = evm_address(&secret)?;
        let signer = self.load_signer(&from_exfer).await?;
        let our_pubkey = hex::encode(signer.pubkey());

        let mut pre = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut pre);
        let hashlock = format!("0x{}", hex::encode(Sha256::digest(pre)));
        let preimage = format!("0x{}", hex::encode(pre));

        let (user_bsc, user_exfer) = match direction {
            Direction::ExferToBnb => (Some(our_bsc.as_str()), None),
            Direction::BnbToExfer => (None, Some(our_pubkey.as_str())),
        };
        let q = self
            .pool
            .quote(direction, &amount_in_human, &hashlock, user_bsc, user_exfer)
            .await?;

        let now = now_secs();
        let rec = SwapRecord {
            swap_id: q.swap_id,
            direction,
            status: SwapStatus::Quoted,
            hashlock,
            preimage,
            amount_in: q.amount_in,
            amount_out: q.amount_out,
            amount_in_units: q.amount_in_units,
            amount_out_units: q.amount_out_units,
            pool_exfer_pubkey: q
                .instructions
                .exfer
                .as_ref()
                .map(|e| e.receiver_pubkey.clone()),
            pool_bsc_address: q.instructions.bsc.as_ref().map(|b| b.recipient.clone()),
            htlc_contract: q
                .htlc_contract
                .clone()
                .or_else(|| q.instructions.bsc.as_ref().map(|b| b.htlc_contract.clone())),
            our_bsc_address: Some(our_bsc),
            our_exfer_address: Some(from_exfer),
            user_lock_tx: None,
            pool_lock_ref: None,
            claim_tx: None,
            refund_tx: None,
            exfer_timeout_height: q.instructions.exfer.as_ref().map(|e| e.timeout_height),
            bsc_timeout_sec: q.instructions.bsc.as_ref().map(|b| b.timeout_sec),
            expires_at: q.expires_at,
            fee_bps: q.fee_bps,
            network_fee_bnb: q.network_fee_bnb,
            error: None,
            created_at: now,
            updated_at: now,
        };
        self.journal.put(rec.clone())?;
        Ok(rec)
    }

    /// Execute the user's first leg (sell: lock EXFER; buy: lock native BNB).
    pub async fn execute(&self, swap_id: &str) -> Result<SwapRecord> {
        // Hold the per-swap lock across the whole execute so a concurrent
        // double-tap/retry can't also pass the Quoted guard and lock a second
        // first-leg. The loser blocks here, then re-reads a non-Quoted status
        // below and returns the existing record.
        let swap_lock = self.swap_lock(swap_id);
        let _guard = swap_lock.lock().await;
        let rec = self
            .journal
            .get(swap_id)
            .ok_or_else(|| Error::BadParams(format!("unknown swap_id {swap_id}")))?;
        if rec.status != SwapStatus::Quoted {
            return Ok(rec); // already executing/done
        }
        let now = now_secs();
        if now >= rec.expires_at {
            self.journal.update(swap_id, now, |r| {
                r.status = SwapStatus::Failed;
                r.error = Some("quote expired before execution".into());
            })?;
            return Err(Error::BadParams(
                "quote expired; request a fresh quote".into(),
            ));
        }

        match rec.direction {
            Direction::ExferToBnb => {
                let from = rec
                    .our_exfer_address
                    .clone()
                    .ok_or_else(|| Error::Internal("missing EXFER from-address".into()))?;
                let signer = self.load_signer(&from).await?;
                let receiver = crate::tx::decode_hash(strip0x(
                    rec.pool_exfer_pubkey
                        .as_deref()
                        .ok_or_else(|| Error::Internal("missing pool EXFER pubkey".into()))?,
                ))?;
                let hash_lock = hash256_from_hex(&rec.hashlock)?;
                let timeout = rec
                    .exfer_timeout_height
                    .ok_or_else(|| Error::Internal("missing EXFER timeout height".into()))?;
                // Funds-safety: refuse a too-short user-leg timeout (the pool
                // supplies it). We must keep a long window to reclaim if the swap
                // stalls; otherwise a malicious pool could starve our reclaim.
                let tip = self.node.get_block_height().await?.height;
                if timeout < tip + MIN_EXFER_LOCK_BLOCKS {
                    return Err(Error::BadParams(
                        "pool returned an unsafe (too-short) EXFER lock timeout".into(),
                    ));
                }
                let amount: u64 = rec
                    .amount_in_units
                    .parse()
                    .map_err(|e| Error::Internal(format!("bad EXFER amount: {e}")))?;
                let receipt = crate::tx::htlc::htlc_lock(
                    &signer,
                    receiver,
                    hash_lock,
                    timeout,
                    amount,
                    crate::tx::FeeChoice::Rate(1),
                    crate::api::DEFAULT_MAX_FEE,
                    &self.node,
                    &self.inflight,
                )
                .await?;
                self.pool
                    .notify_exfer_lock(swap_id, &receipt.tx_id)
                    .await
                    .ok();
                self.journal.update(swap_id, now_secs(), |r| {
                    r.status = SwapStatus::UserLocked;
                    r.user_lock_tx = Some(receipt.tx_id);
                })?;
            }
            Direction::BnbToExfer => {
                let secret = self.store.evm_secret()?;
                let htlc = rec
                    .htlc_contract
                    .clone()
                    .ok_or_else(|| Error::Internal("missing HTLC contract".into()))?;
                let recipient = rec
                    .pool_bsc_address
                    .clone()
                    .ok_or_else(|| Error::Internal("missing pool BSC address".into()))?;
                let timeout = rec
                    .bsc_timeout_sec
                    .ok_or_else(|| Error::Internal("missing BSC timeout".into()))?;
                if timeout < now_secs() + MIN_BSC_LOCK_SECS {
                    return Err(Error::BadParams(
                        "pool returned an unsafe (too-short) BNB lock timeout".into(),
                    ));
                }
                // Amount of native BNB to lock (msg.value), 18-dp wei.
                let amount = alloy::primitives::U256::from_str_radix(&rec.amount_in_units, 10)
                    .map_err(|e| Error::Internal(format!("bad BNB amount: {e}")))?;

                let our_addr = secret_address(&secret)?;
                // Pre-flight: BNB is both the principal and the gas — need at
                // least the lock amount plus a little headroom for gas.
                let bnb = self.evm.bnb_balance(our_addr).await?;
                if bnb <= amount {
                    return Err(Error::BadParams(
                        "not enough BNB: need the swap amount plus a little for gas".into(),
                    ));
                }

                let _guard = self.bsc_lock.lock().await;
                // Native lock — value is sent inline, no token / no approve.
                let tx = self
                    .evm
                    .htlc_lock(&secret, &htlc, &rec.hashlock, &recipient, amount, timeout)
                    .await?;
                self.journal.update(swap_id, now_secs(), |r| {
                    r.status = SwapStatus::UserLocked;
                    r.user_lock_tx = Some(tx);
                })?;
            }
        }
        Ok(self.journal.get(swap_id).unwrap_or(rec))
    }

    /// Funds-safety gate (sell direction): verify the pool's BNB lock exists
    /// on BSC and is safe to claim against BEFORE we reveal the preimage. Must
    /// be Locked, paid to OUR address, cover the quoted output, and have enough
    /// time left to claim. Never trust the pool's self-reported status for this.
    /// The decision itself is the pure [`pool_lock_safe_to_claim`] (unit-tested);
    /// this method only does the I/O (read the on-chain swap) around it.
    async fn verify_pool_bsc_lock(&self, rec: &SwapRecord) -> Result<bool> {
        let htlc = match rec.htlc_contract.as_deref() {
            Some(h) => h,
            None => return Ok(false),
        };
        let our = match rec.our_bsc_address.as_deref() {
            Some(a) => a
                .parse::<alloy::primitives::Address>()
                .map_err(|e| Error::Internal(format!("bad our BSC address: {e}")))?,
            None => return Ok(false),
        };
        let want_out = alloy::primitives::U256::from_str_radix(&rec.amount_out_units, 10)
            .map_err(|e| Error::Internal(format!("bad amount_out_units: {e}")))?;
        let oc = self.evm.get_htlc_swap(htlc, &rec.hashlock).await?;
        let safe = pool_lock_safe_to_claim(&oc, our, want_out, now_secs());
        tracing::debug!(swap = %rec.swap_id, state = ?oc.state, safe, "verify_pool_bsc_lock");
        Ok(safe)
    }

    /// One monitor tick for a single swap: advance toward settlement, or refund
    /// after timeout. Errors are logged by the caller and retried next tick.
    pub async fn advance(&self, rec: &SwapRecord) -> Result<()> {
        match (rec.status, rec.direction) {
            // Sell: the pool must mirror with a USDT lock on BSC. We DO NOT trust
            // the pool's self-reported status to decide it's safe to reveal the
            // preimage — we verify the lock on-chain (state Locked, recipient is
            // us, amount covers the quote, and enough time left to claim). Only
            // then do we advance to PoolLocked (which triggers the preimage
            // reveal). This is the funds-safety gate for the sell direction.
            (SwapStatus::UserLocked, Direction::ExferToBnb) => {
                if !self.verify_pool_bsc_lock(rec).await? {
                    return Ok(()); // pool's USDT lock not yet verified on-chain; retry
                }
                let plr = self.pool.get_swap(&rec.swap_id).await.ok().and_then(|pj| {
                    pj.get("poolLockTxhash")
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                });
                self.journal.update(&rec.swap_id, now_secs(), |r| {
                    r.status = SwapStatus::PoolLocked;
                    r.pool_lock_ref = plr;
                })?;
            }
            // Buy: the pool mirrors with an EXFER lock. Safe to gate on the pool's
            // status hint here — we never reveal the preimage on a pool say-so;
            // the actual claim (PoolLocked branch) reconstructs the pool's EXFER
            // lock from authoritative indexer data and only reveals if it exists.
            (SwapStatus::UserLocked, Direction::BnbToExfer) => {
                let pj = self.pool.get_swap(&rec.swap_id).await?;
                let pstatus = pj.get("status").and_then(|v| v.as_str()).unwrap_or("");
                if matches!(pstatus, "pool_locked" | "preimage_seen" | "completed") {
                    let plr = pj
                        .get("poolLockTxhash")
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                    self.journal.update(&rec.swap_id, now_secs(), |r| {
                        r.status = SwapStatus::PoolLocked;
                        r.pool_lock_ref = plr;
                    })?;
                }
            }
            // Sell: claim the pool's BNB (gasless relay, with self-claim fallback).
            // Completion is driven off the BSC HTLC state, not the claim broadcast,
            // so a dropped/unmined claim is retried until the chain shows it claimed.
            (SwapStatus::PoolLocked | SwapStatus::Claiming, Direction::ExferToBnb) => {
                let htlc = rec.htlc_contract.clone().unwrap_or_default();
                // Authoritative completion: read the on-chain HTLC state.
                if !htlc.is_empty() {
                    if let Ok(sw) = self.evm.get_htlc_swap(&htlc, &rec.hashlock).await {
                        match sw.state {
                            crate::evm::HtlcState::Claimed => {
                                // Backfill the counterparty (pool's BNB) lock ref if
                                // a flaky get_swap at the PoolLocked transition missed
                                // it, so the detail view shows all legs (not just 2).
                                let pool_lock = match rec.pool_lock_ref.clone() {
                                    Some(p) => Some(p),
                                    None => {
                                        self.pool.get_swap(&rec.swap_id).await.ok().and_then(|pj| {
                                            pj.get("poolLockTxhash")
                                                .and_then(|v| v.as_str())
                                                .map(str::to_string)
                                        })
                                    }
                                };
                                self.journal.update(&rec.swap_id, now_secs(), |r| {
                                    r.status = SwapStatus::Completed;
                                    r.pool_lock_ref = pool_lock;
                                    r.error = None;
                                })?;
                                return Ok(());
                            }
                            crate::evm::HtlcState::Refunded => {
                                // Pool reclaimed its BNB (we never claimed in time) →
                                // the swap failed; reclaim the user's EXFER lock.
                                self.journal.update(&rec.swap_id, now_secs(), |r| {
                                    r.status = SwapStatus::Refunding;
                                    r.error = Some(
                                        "BNB claim never confirmed; pool refunded its lock — reclaiming your EXFER"
                                            .into(),
                                    );
                                })?;
                                return Ok(());
                            }
                            _ => {} // Locked / None → (re)claim below
                        }
                    }
                }
                // Throttle re-sends: send on first entry, then at most every
                // CLAIM_REBROADCAST_SECS while awaiting confirmation (relay_claim is
                // idempotent; a double on-chain claim just reverts — harmless).
                let first = rec.status == SwapStatus::PoolLocked;
                let due = now_secs().saturating_sub(rec.updated_at) >= CLAIM_REBROADCAST_SECS;
                if !(first || due) {
                    return Ok(());
                }
                match self.pool.relay_claim(&rec.swap_id, &rec.preimage).await {
                    Ok(v) => {
                        let tx = v.get("txhash").and_then(|x| x.as_str()).map(str::to_string);
                        self.journal.update(&rec.swap_id, now_secs(), |r| {
                            r.status = SwapStatus::Claiming;
                            if tx.is_some() {
                                r.claim_tx = tx;
                            }
                        })?;
                    }
                    Err(e) => {
                        // Fallback: self-submit if we hold BNB for gas.
                        let secret = self.store.evm_secret()?;
                        let our = secret_address(&secret)?;
                        if !htlc.is_empty() && !self.evm.bnb_balance(our).await?.is_zero() {
                            let _guard = self.bsc_lock.lock().await;
                            let tx = self.evm.htlc_claim(&secret, &htlc, &rec.preimage).await?;
                            self.journal.update(&rec.swap_id, now_secs(), |r| {
                                r.status = SwapStatus::Claiming;
                                r.claim_tx = Some(tx);
                            })?;
                        } else {
                            return Err(e);
                        }
                    }
                }
            }
            // Buy: claim the pool's EXFER lock, revealing the preimage. Completion
            // is driven off the AUTHORITATIVE indexed HTLC state, never off the
            // mere broadcast: a claim orphaned by a reorg/mempool eviction is
            // re-sent until the chain shows it claimed. (The old code marked
            // Completed right after broadcasting, leaving swaps falsely "completed"
            // when the claim never confirmed — funds safe, but stuck + a dead
            // explorer link.) Handles both first-claim (PoolLocked) and awaiting/
            // re-sending (Claiming).
            (SwapStatus::PoolLocked | SwapStatus::Claiming, Direction::BnbToExfer) => {
                let indexer = self.indexer.as_ref().ok_or_else(|| {
                    Error::Internal("indexer required for buy-direction claim".into())
                })?;
                let from = rec.our_exfer_address.clone().unwrap_or_default();
                let signer = self.load_signer(&from).await?;
                let our_pubkey = hex::encode(signer.pubkey());
                let our_addr = strip0x(&from).to_lowercase();
                let resp = indexer
                    .htlc_lookup_by_hashlock(
                        serde_json::json!({ "hash_lock": strip0x(&rec.hashlock) }),
                    )
                    .await?;
                let htlcs = resp
                    .get("htlcs")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                // The pool's lock pays US — match the indexed receiver against our
                // pubkey OR our address (indexers differ on which they store).
                let pool_lock = htlcs.iter().find(|h| {
                    h.get("params")
                        .and_then(|p| p.get("receiver"))
                        .and_then(|v| v.as_str())
                        .map(|r| {
                            let r = r.to_lowercase();
                            r == our_pubkey.to_lowercase() || r == our_addr
                        })
                        .unwrap_or(false)
                });
                let Some(pl) = pool_lock else {
                    // Not yet indexed (lag) — or never matched. Surface it so a
                    // persistently-stuck buy is diagnosable, not silent.
                    tracing::warn!(
                        swap = %rec.swap_id,
                        htlcs = htlcs.len(),
                        "buy claim: pool EXFER lock not found by hashlock yet; will retry"
                    );
                    return Ok(()); // retry next tick
                };
                let state = pl.get("state").and_then(|v| v.as_str()).unwrap_or("");
                // CLAIMED on-chain → settled. Record the AUTHORITATIVE claim tx_id
                // (the indexed mined tx) so the explorer link always resolves — the
                // self-broadcast hash we held may have been a dropped attempt.
                if state == "claimed" {
                    let claim_tx = pl
                        .get("claim")
                        .and_then(|c| c.get("tx_id"))
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                        .or_else(|| rec.claim_tx.clone());
                    // Backfill the counterparty (pool's EXFER) lock ref if a flaky
                    // get_swap at the PoolLocked transition missed it — the indexed
                    // lock_tx_id is authoritative — so the detail view shows all legs.
                    let pool_lock = rec.pool_lock_ref.clone().or_else(|| {
                        pl.get("lock_tx_id")
                            .and_then(|v| v.as_str())
                            .map(str::to_string)
                    });
                    self.journal.update(&rec.swap_id, now_secs(), |r| {
                        r.status = SwapStatus::Completed;
                        r.claim_tx = claim_tx;
                        r.pool_lock_ref = pool_lock;
                        r.error = None;
                    })?;
                    return Ok(());
                }
                // RECLAIMED → the pool took its EXFER back because we never finalised
                // the claim before the lock timed out. The swap failed; drop to
                // Refunding so the user's BNB lock is reclaimed.
                if state == "reclaimed" {
                    self.journal.update(&rec.swap_id, now_secs(), |r| {
                        r.status = SwapStatus::Refunding;
                        r.error = Some(
                            "EXFER claim never confirmed; pool reclaimed its lock — refunding your BNB"
                                .into(),
                        );
                    })?;
                    return Ok(());
                }
                // Still LOCKED. Re-broadcast the claim ONLY if our previous attempt
                // is no longer on-chain/in mempool (dropped) — otherwise wait for it
                // to mine and the indexer to flip to "claimed". First entry
                // (PoolLocked, no claim_tx yet) always sends.
                let prior_live = match rec.claim_tx.as_deref() {
                    Some(tx) => self.node.get_transaction(tx).await.is_ok(),
                    None => false,
                };
                if prior_live {
                    return Ok(()); // claim in flight; awaiting confirmation
                }

                let params = pl.get("params").cloned().unwrap_or_default();
                let lock_tx_id =
                    pl.get("lock_tx_id")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            Error::UpstreamUnexpected("indexed htlc missing lock_tx_id".into())
                        })?;
                let sender = params
                    .get("sender")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        Error::UpstreamUnexpected("indexed htlc missing sender".into())
                    })?;
                let timeout = params
                    .get("timeout_height")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                // Funds-safety reveal-gate (buy direction, #8) — re-checked before
                // EVERY (re)send: the pool's EXFER lock must cover the quote and
                // leave a safe reclaim margin, else we ABORT without revealing.
                let lock_amount = pl.get("amount").and_then(|v| v.as_u64()).ok_or_else(|| {
                    Error::UpstreamUnexpected("indexed htlc missing amount".into())
                })?;
                let want_out: u64 = rec
                    .amount_out_units
                    .parse()
                    .map_err(|e| Error::Internal(format!("bad amount_out_units: {e}")))?;
                if lock_amount < want_out {
                    return Err(Error::UpstreamUnexpected(format!(
                        "pool EXFER lock underfunded: locked {lock_amount} < quoted {want_out}; \
                         refusing to reveal preimage"
                    )));
                }
                let tip = self.node.get_block_height().await?.height;
                if timeout < tip + MIN_EXFER_LOCK_BLOCKS {
                    return Err(Error::UpstreamUnexpected(format!(
                        "pool EXFER lock timeout too short: {timeout} < tip {tip} + \
                         {MIN_EXFER_LOCK_BLOCKS}; refusing to reveal preimage"
                    )));
                }
                let preimage = hex::decode(strip0x(&rec.preimage))
                    .map_err(|e| Error::Internal(format!("bad preimage: {e}")))?;
                let receipt = crate::tx::htlc::htlc_claim(
                    &signer,
                    hash256_from_hex(lock_tx_id)?,
                    0,
                    preimage,
                    crate::tx::decode_hash(strip0x(sender))?,
                    timeout,
                    None,
                    &self.node,
                )
                .await?;
                // Claiming (not Completed): the indexer "claimed" state above is
                // what finally completes it, after this confirms.
                self.journal.update(&rec.swap_id, now_secs(), |r| {
                    r.status = SwapStatus::Claiming;
                    r.claim_tx = Some(receipt.tx_id);
                })?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Whether the user's first leg is past its refund deadline (so a reclaim
    /// can succeed). Sell: EXFER block height ≥ timeout. Buy: unix time ≥ timeout.
    /// One-time startup reconcile (see [`run_monitor`]): an older build marked a
    /// swap Completed right after BROADCASTING the claim, so a claim later orphaned
    /// by a reorg left it falsely "completed" — funds safe, but the asset never
    /// arrived. Re-verify recently-completed swaps against authoritative on-chain
    /// state; if the claim isn't actually there, drop back to PoolLocked so the
    /// monitor re-settles (re-claims, or refunds at timeout). Best-effort: any
    /// lookup error leaves the record untouched.
    pub async fn reconcile_completed(&self) {
        let now = now_secs();
        const WINDOW_SECS: u64 = 48 * 3600; // beyond the timeout window it's final
        for rec in self.journal.list() {
            if rec.status != SwapStatus::Completed
                || now.saturating_sub(rec.updated_at) > WINDOW_SECS
            {
                continue;
            }
            if self.claim_is_confirmed(&rec).await == Some(false) {
                let _ = self.journal.update(&rec.swap_id, now, |r| {
                    r.status = SwapStatus::PoolLocked;
                    r.error =
                        Some("recovered: claim was not confirmed on-chain — re-settling".into());
                });
                tracing::warn!(
                    swap = %rec.swap_id, direction = ?rec.direction,
                    "reconcile: completed swap had no confirmed on-chain claim; re-settling"
                );
            }
        }
    }

    /// Authoritative "did the claim actually land on-chain?" — Some(true)=claimed,
    /// Some(false)=the lock exists but isn't claimed (re-claimable / refundable),
    /// None=unknown (lookup failed; don't touch the record).
    async fn claim_is_confirmed(&self, rec: &SwapRecord) -> Option<bool> {
        match rec.direction {
            Direction::BnbToExfer => {
                let indexer = self.indexer.as_ref()?;
                let from = rec.our_exfer_address.clone()?;
                let signer = self.load_signer(&from).await.ok()?;
                let our_pubkey = hex::encode(signer.pubkey()).to_lowercase();
                let our_addr = strip0x(&from).to_lowercase();
                let resp = indexer
                    .htlc_lookup_by_hashlock(
                        serde_json::json!({ "hash_lock": strip0x(&rec.hashlock) }),
                    )
                    .await
                    .ok()?;
                let htlcs = resp.get("htlcs")?.as_array()?;
                let pl = htlcs.iter().find(|h| {
                    h.get("params")
                        .and_then(|p| p.get("receiver"))
                        .and_then(|v| v.as_str())
                        .map(|r| {
                            let r = r.to_lowercase();
                            r == our_pubkey || r == our_addr
                        })
                        .unwrap_or(false)
                })?;
                match pl.get("state").and_then(|v| v.as_str()).unwrap_or("") {
                    "claimed" => Some(true),
                    "locked" | "reclaimed" => Some(false),
                    _ => None,
                }
            }
            Direction::ExferToBnb => {
                let htlc = rec.htlc_contract.as_deref()?;
                let sw = self.evm.get_htlc_swap(htlc, &rec.hashlock).await.ok()?;
                match sw.state {
                    crate::evm::HtlcState::Claimed => Some(true),
                    crate::evm::HtlcState::Locked | crate::evm::HtlcState::Refunded => Some(false),
                    crate::evm::HtlcState::None => None,
                }
            }
        }
    }

    async fn refundable(&self, rec: &SwapRecord) -> bool {
        match rec.direction {
            Direction::ExferToBnb => {
                match (rec.exfer_timeout_height, self.node.get_block_height().await) {
                    (Some(t), Ok(tip)) => tip.height >= t,
                    _ => false,
                }
            }
            Direction::BnbToExfer => rec
                .bsc_timeout_sec
                .map(|t| now_secs() >= t)
                .unwrap_or(false),
        }
    }

    /// Reclaim the user's first leg after its timeout. No funds are ever lost:
    /// the user always controls the refund arm of their own lock.
    pub async fn refund(&self, swap_id: &str) -> Result<SwapRecord> {
        // Same per-swap lock as execute(): a double-tapped refund (or a UI refund
        // racing the monitor's refund) must not broadcast two reclaims.
        let swap_lock = self.swap_lock(swap_id);
        let _guard = swap_lock.lock().await;
        let rec = self
            .journal
            .get(swap_id)
            .ok_or_else(|| Error::BadParams(format!("unknown swap_id {swap_id}")))?;
        if rec.is_terminal() {
            return Ok(rec);
        }
        let lock_tx = rec
            .user_lock_tx
            .clone()
            .ok_or_else(|| Error::BadParams("nothing locked yet for this swap".into()))?;

        match rec.direction {
            Direction::ExferToBnb => {
                let from = rec.our_exfer_address.clone().unwrap_or_default();
                let signer = self.load_signer(&from).await?;
                let receiver = crate::tx::decode_hash(strip0x(
                    rec.pool_exfer_pubkey.as_deref().unwrap_or(""),
                ))?;
                let receipt = crate::tx::htlc::htlc_reclaim(
                    &signer,
                    hash256_from_hex(&lock_tx)?,
                    0,
                    receiver,
                    hash256_from_hex(&rec.hashlock)?,
                    rec.exfer_timeout_height.unwrap_or(0),
                    None,
                    &self.node,
                )
                .await?;
                self.journal.update(swap_id, now_secs(), |r| {
                    r.status = SwapStatus::Refunded;
                    r.refund_tx = Some(receipt.tx_id);
                })?;
            }
            Direction::BnbToExfer => {
                let secret = self.store.evm_secret()?;
                let htlc = rec.htlc_contract.clone().unwrap_or_default();
                let _guard = self.bsc_lock.lock().await;
                let tx = self.evm.htlc_refund(&secret, &htlc, &rec.hashlock).await?;
                self.journal.update(swap_id, now_secs(), |r| {
                    r.status = SwapStatus::Refunded;
                    r.refund_tx = Some(tx);
                })?;
            }
        }
        Ok(self.journal.get(swap_id).unwrap_or(rec))
    }

    /// Chain-driven recovery of stranded EXFER HTLC locks — independent of the
    /// swap journal. A swap whose claim step is interrupted (network drop, app
    /// kill) strands the user's EXFER lock; the monitor's journal-driven refund
    /// recovers it *only if the swap record still lives on the device*. But the
    /// very failures that strand funds — reinstall, cleared data, a new phone,
    /// restoring without the vault — are exactly the ones that lose that local
    /// record, so the journal-driven path can't help there.
    ///
    /// This path depends on nothing local but the user's keys: for every EXFER
    /// address in the keyring, ask the indexer for HTLCs touching that pubkey,
    /// keep the ones WE locked (`sender == us`) that are still `locked` and past
    /// their timeout height, and broadcast the reclaim. The reclaim pays back to
    /// the sender — i.e. the user's own address. Best-effort: every lookup, parse
    /// or broadcast error is logged and skipped so one bad entry never blocks the
    /// rest, and an in-memory guard stops us re-broadcasting a reclaim that's
    /// already in flight (before the indexer flips the HTLC to `reclaimed`).
    ///
    /// No funds are ever at risk: a reclaim spends the refund arm of the user's
    /// own lock, which only the user's key can sign.
    pub async fn sweep_stranded_locks(&self) {
        let Some(indexer) = self.indexer.as_ref() else {
            return;
        };
        let tip = match self.node.get_block_height().await {
            Ok(t) => t.height,
            Err(e) => {
                tracing::debug!(error = %e, "sweep: get_block_height failed; skipping this pass");
                return;
            }
        };
        let store = self.store.clone();
        let entries = match tokio::task::spawn_blocking(move || store.list()).await {
            Ok(Ok(e)) => e,
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "sweep: keyring list failed; skipping");
                return;
            }
            Err(e) => {
                tracing::debug!(error = %e, "sweep: keyring list task panicked; skipping");
                return;
            }
        };

        for entry in entries {
            // Resolve the signer so we have the raw pubkey to query by and the
            // key to sign the reclaim. Non-EXFER entries (e.g. the BSC key) either
            // fail to load here or simply match no EXFER HTLCs — harmless.
            let signer = match self.load_signer(&entry.address).await {
                Ok(s) => s,
                Err(_) => continue,
            };
            let my_pubkey = hex::encode(signer.pubkey());

            // Query by address only — NOT by `state: "locked"`: the indexer
            // reports a past-timeout lock as `locked_expired`, so a state filter
            // would hide exactly the locks we need to reclaim. We filter for
            // "funds still locked" client-side in `decode_reclaimable_lock`.
            let resp = match indexer
                .htlc_list(serde_json::json!({
                    "address": my_pubkey,
                    "limit": 1000,
                }))
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(address = %entry.address, error = %e, "sweep: htlc_list failed");
                    continue;
                }
            };
            let Some(htlcs) = resp.get("htlcs").and_then(|v| v.as_array()) else {
                continue;
            };

            for h in htlcs {
                let Some(lock) = decode_reclaimable_lock(&my_pubkey, tip, h) else {
                    continue;
                };

                // Dedup: skip if we already broadcast a reclaim for this outpoint
                // this session (the indexer may still report `locked` until the
                // reclaim mines).
                let mut outpoint = [0u8; 36];
                outpoint[..32].copy_from_slice(&lock.lock_tx.0);
                outpoint[32..].copy_from_slice(&lock.output_index.to_be_bytes());
                {
                    let mut swept = self.swept_locks.lock().unwrap_or_else(|e| e.into_inner());
                    if !swept.insert(outpoint) {
                        continue;
                    }
                }

                match crate::tx::htlc::htlc_reclaim(
                    &signer,
                    lock.lock_tx,
                    lock.output_index,
                    lock.receiver,
                    lock.hashlock,
                    lock.timeout,
                    None,
                    &self.node,
                )
                .await
                {
                    Ok(receipt) => {
                        tracing::info!(
                            address = %entry.address,
                            lock_tx = %lock.lock_tx_hex,
                            reclaim_tx = %receipt.tx_id,
                            "sweep: reclaimed stranded EXFER HTLC lock back to the user"
                        );
                        // If this swap is still in the journal, reflect the
                        // recovery so the UI shows it as Refunded rather than
                        // stuck. Match by hashlock; ignore if absent (the whole
                        // point of the sweep is recovery without a record).
                        if let Some(rec) = self.journal.list().into_iter().find(|r| {
                            r.hashlock.eq_ignore_ascii_case(&lock.hashlock_0x) && !r.is_terminal()
                        }) {
                            let _ = self.journal.update(&rec.swap_id, now_secs(), |r| {
                                r.status = SwapStatus::Refunded;
                                r.refund_tx = Some(receipt.tx_id.clone());
                            });
                        }
                    }
                    Err(e) => {
                        // Drop the dedup guard so a transient failure retries next
                        // pass; a permanent one (already spent) just re-logs once.
                        self.swept_locks
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .remove(&outpoint);
                        tracing::debug!(lock_tx = %lock.lock_tx_hex, error = %e, "sweep: reclaim broadcast failed");
                    }
                }
            }
        }
    }

    /// Chain-driven recovery of stranded BNB HTLC locks (buy direction) — the BSC
    /// twin of [`sweep_stranded_locks`]. A buy locks the user's BNB on BSC first;
    /// if the claim step is interrupted (network drop, app kill) AND the local
    /// swap record is later lost (reinstall, new device, cleared data), the
    /// journal-driven refund can't help — the very failures that strand the BNB
    /// are the ones that lose the record.
    ///
    /// This path needs nothing local but the user's BSC key: enumerate every lock
    /// that key SENT to the chain's fixed ExferHtlc (via the indexed `Locked`
    /// event), and for each one still `Locked` past its `timeoutSec`, broadcast
    /// `refund(hashlock)` — which the contract only honours for the original
    /// sender, so no funds are ever at risk. Best-effort; an in-memory dedup guard
    /// (`swept_bnb`) stops re-broadcasting before the chain flips to `Refunded`.
    pub async fn sweep_stranded_bnb_locks(&self) {
        // Fixed deployment for this chain; unknown/dev chains have no enumerable
        // contract → nothing to sweep.
        let Some((contract, deploy_block)) = bsc_htlc_for_chain(self.bsc_chain_id) else {
            return;
        };
        // Our BSC key + address. Seed-only wallets created before the BSC key
        // existed have none → nothing to sweep.
        let secret = match self.store.evm_secret() {
            Ok(s) => s,
            Err(_) => return,
        };
        let our = match crate::evm::EvmClient::address_of(&secret) {
            Ok(a) => a,
            Err(e) => {
                tracing::debug!(error = %e, "bnb sweep: bad BSC address; skipping");
                return;
            }
        };

        let tip = match self.evm.block_number().await {
            Ok(t) => t,
            Err(e) => {
                tracing::debug!(error = %e, "bnb sweep: block_number failed; skipping pass");
                return;
            }
        };
        // Scan from the deploy block on the first pass of a session (full
        // recovery), then only new blocks, rewound a little for reorg safety.
        let from = {
            let cursor = *self
                .bsc_sweep_cursor
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if cursor == 0 {
                deploy_block
            } else {
                cursor
                    .saturating_sub(BSC_SWEEP_REORG_MARGIN)
                    .max(deploy_block)
            }
        };
        if from > tip {
            return;
        }

        let hashlocks = match self
            .evm
            .locked_hashlocks_by_sender(contract, our, from, tip)
            .await
        {
            Ok(h) => h,
            Err(e) => {
                tracing::debug!(error = %e, "bnb sweep: getLogs enumeration failed; skipping pass");
                return;
            }
        };
        // Chain clock the refund gate is measured against (NOT wall time).
        let now_ts = match self.evm.latest_block_timestamp().await {
            Ok(t) => t,
            Err(e) => {
                tracing::debug!(error = %e, "bnb sweep: block timestamp failed; skipping pass");
                return;
            }
        };

        for hashlock in hashlocks {
            let sw = match self.evm.get_htlc_swap(contract, &hashlock).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(%hashlock, error = %e, "bnb sweep: getSwap failed; skipping");
                    continue;
                }
            };
            // Funds still in the HTLC and past the refund deadline?
            if sw.state != crate::evm::HtlcState::Locked || now_ts < sw.timeout_sec {
                continue;
            }

            let key = hashlock.to_lowercase();
            {
                let mut swept = self.swept_bnb.lock().unwrap_or_else(|e| e.into_inner());
                if !swept.insert(key.clone()) {
                    continue; // refund already in flight this session
                }
            }

            let tx = {
                let _guard = self.bsc_lock.lock().await;
                self.evm.htlc_refund(&secret, contract, &hashlock).await
            };
            match tx {
                Ok(txhash) => {
                    tracing::info!(
                        %hashlock,
                        refund_tx = %txhash,
                        "bnb sweep: refunded stranded BNB HTLC lock back to the user"
                    );
                    // Mirror the recovery into the journal if a live record exists
                    // (so the UI shows Refunded, not stuck). Match by hashlock; the
                    // sweep's whole point is to work WITHOUT a record, so absence is
                    // fine.
                    if let Some(rec) =
                        self.journal.list().into_iter().find(|r| {
                            r.hashlock.eq_ignore_ascii_case(&hashlock) && !r.is_terminal()
                        })
                    {
                        let _ = self.journal.update(&rec.swap_id, now_secs(), |r| {
                            r.status = SwapStatus::Refunded;
                            r.refund_tx = Some(txhash.clone());
                        });
                    }
                }
                Err(e) => {
                    // Drop the dedup guard so a transient failure retries next pass.
                    self.swept_bnb
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&key);
                    tracing::debug!(%hashlock, error = %e, "bnb sweep: refund broadcast failed");
                }
            }
        }

        // Advance the cursor past this fully-scanned tip so subsequent ticks in
        // this session only scan new blocks.
        *self
            .bsc_sweep_cursor
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = tip + 1;
    }
}

/// Background monitor: each tick, advance every pending swap toward settlement,
/// expire stale quotes, and reclaim past-deadline locks. Runs until shutdown.
pub async fn run_monitor(engine: Arc<SwapEngine>, shutdown: tokio_util::sync::CancellationToken) {
    const TICK: std::time::Duration = std::time::Duration::from_secs(3);
    // Periodic safety net: re-verify "completed" swaps against authoritative
    // on-chain state. A claim is marked Completed once it's IN a block — final
    // enough almost always, but a deep reorg could orphan it after the fact. So
    // rather than make every swap wait N confirmations (slower for everyone, for
    // a rare event), we just re-check completed swaps on a timer: if a claim is
    // no longer on-chain, reconcile_completed drops it back to re-settle (re-claim,
    // or refund at timeout). Also recovers swaps an older build mismarked.
    const RECONCILE_EVERY: std::time::Duration = std::time::Duration::from_secs(5 * 60);
    tracing::info!("swap monitor started");
    engine.reconcile_completed().await;
    // Chain-driven recovery at startup: reclaim any stranded EXFER HTLC lock the
    // user holds the key for, even if its swap record was lost (reinstall, new
    // device). This is what makes "just reopen the app" recover funds.
    engine.sweep_stranded_locks().await;
    // The BSC twin: recover stranded BNB locks from a buy whose claim was
    // interrupted, even with no local record (reinstall / new device).
    engine.sweep_stranded_bnb_locks().await;
    let mut last_reconcile = std::time::Instant::now();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(TICK) => {}
        }
        if last_reconcile.elapsed() >= RECONCILE_EVERY {
            engine.reconcile_completed().await;
            engine.sweep_stranded_locks().await;
            engine.sweep_stranded_bnb_locks().await;
            last_reconcile = std::time::Instant::now();
        }
        for rec in engine.journal().pending() {
            // A quote the user never executed: once its validity lapses, just
            // PRUNE it. No funds ever moved and there's nothing to recover, so a
            // harmless price check shouldn't linger (as Expired) or — worse, as
            // older builds did — show up as a failed swap. Deleting keeps the
            // journal (and the user's history) to swaps they actually made.
            if rec.status == SwapStatus::Quoted {
                if now_secs() >= rec.expires_at {
                    let _ = engine.journal().remove(&rec.swap_id);
                }
                continue;
            }
            // Past the refund deadline → reclaim the user's lock. Includes
            // Claiming (a claim that never confirmed in the whole timeout window)
            // and Refunding (we already detected the counterparty reclaimed and are
            // waiting for our own lock's timeout to recover it).
            if matches!(
                rec.status,
                SwapStatus::UserLocked
                    | SwapStatus::PoolLocked
                    | SwapStatus::Claiming
                    | SwapStatus::Refunding
            ) && engine.refundable(&rec).await
            {
                if let Err(e) = engine.refund(&rec.swap_id).await {
                    tracing::debug!(swap = %rec.swap_id, error = %e, "swap refund retry");
                }
                continue;
            }
            // Otherwise drive it forward. Logged at warn (not debug) so a swap
            // that's silently stuck mid-settlement is actually visible in logs.
            if let Err(e) = engine.advance(&rec).await {
                tracing::warn!(swap = %rec.swap_id, status = ?rec.status, error = %e, "swap advance retry");
            }
        }
    }
    tracing::info!("swap monitor stopped");
}

/// Address for a raw secret (helper to avoid re-parsing in two places).
fn secret_address(secret: &[u8; 32]) -> Result<alloy::primitives::Address> {
    evm_address(secret)?
        .parse::<alloy::primitives::Address>()
        .map_err(|e| Error::Internal(format!("bad derived BSC address: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::keyring::KeyringStore;
    use std::sync::Arc;

    // The exact `htlc_list` row the live indexer returns for the stranded sell
    // (tx d737274…, the customer's 20k-EXFER lock) — used as a fixture so the
    // sweep's parse/filter logic is pinned to the real wire shape.
    const LIVE_LOCKED_ROW: &str = r#"{
        "amount": 2000000000000,
        "claim": null,
        "last_indexed_height": 812636,
        "lock_block_height": 812636,
        "lock_tx_id": "d737274792fae5c531c96656d167a98223ac8ea3bed078e0e8a9ce96e99ce6c8",
        "output_index": 0,
        "params": {
            "hash_lock": "ad2ee1c42cf1da686eaaf843ad29b902abbdb8f4fc7c5258a6ebc43f9e86b46f",
            "receiver": "3587f4c43dac81d593863c53ff8f0bebe702aba781781785b7f1c6712586599c",
            "sender": "04f7e2704bf82eba1c3180aa995bdc627374f0be236cedd0003847e388705778",
            "timeout_height": 814071
        },
        "reclaim": null,
        "role": "observer",
        "state": "locked"
    }"#;
    const SENDER: &str = "04f7e2704bf82eba1c3180aa995bdc627374f0be236cedd0003847e388705778";

    #[test]
    fn sweep_decodes_real_stranded_lock_when_past_timeout() {
        let h: serde_json::Value = serde_json::from_str(LIVE_LOCKED_ROW).unwrap();
        // tip 815693 > timeout 814071 → reclaimable, params decode to the live values.
        let lock = decode_reclaimable_lock(SENDER, 815693, &h).expect("should be reclaimable");
        assert_eq!(lock.output_index, 0);
        assert_eq!(lock.timeout, 814071);
        assert_eq!(
            lock.lock_tx_hex,
            "d737274792fae5c531c96656d167a98223ac8ea3bed078e0e8a9ce96e99ce6c8"
        );
        assert_eq!(
            hex::encode(lock.receiver),
            "3587f4c43dac81d593863c53ff8f0bebe702aba781781785b7f1c6712586599c"
        );
        assert_eq!(
            lock.hashlock_0x,
            "0xad2ee1c42cf1da686eaaf843ad29b902abbdb8f4fc7c5258a6ebc43f9e86b46f"
        );
        // Case-insensitive sender match too.
        assert!(decode_reclaimable_lock(&SENDER.to_uppercase(), 815693, &h).is_some());
    }

    #[test]
    fn sweep_skips_lock_not_yet_past_timeout() {
        let h: serde_json::Value = serde_json::from_str(LIVE_LOCKED_ROW).unwrap();
        // tip == timeout and tip < timeout are both NOT reclaimable (refund arm
        // needs height strictly greater than timeout).
        assert!(decode_reclaimable_lock(SENDER, 814071, &h).is_none());
        assert!(decode_reclaimable_lock(SENDER, 814070, &h).is_none());
    }

    #[test]
    fn sweep_skips_locks_we_did_not_send() {
        let h: serde_json::Value = serde_json::from_str(LIVE_LOCKED_ROW).unwrap();
        // We are the RECEIVER of this lock, not the sender → never our reclaim.
        let receiver = "3587f4c43dac81d593863c53ff8f0bebe702aba781781785b7f1c6712586599c";
        assert!(decode_reclaimable_lock(receiver, 815693, &h).is_none());
        // An unrelated pubkey → skip.
        assert!(decode_reclaimable_lock(&"11".repeat(32), 815693, &h).is_none());
    }

    #[test]
    fn sweep_skips_already_settled_locks() {
        // Settled = the on-chain `claim` or `reclaim` arm has fired. Either
        // present → never re-reclaim, regardless of the `state` string.
        let mut claimed: serde_json::Value = serde_json::from_str(LIVE_LOCKED_ROW).unwrap();
        claimed["state"] = "claimed".into();
        claimed["claim"] =
            serde_json::json!({"block_height": 815000, "preimage": "ab", "tx_id": "cd"});
        assert!(decode_reclaimable_lock(SENDER, 815693, &claimed).is_none());

        let mut reclaimed: serde_json::Value = serde_json::from_str(LIVE_LOCKED_ROW).unwrap();
        reclaimed["state"] = "reclaimed".into();
        reclaimed["reclaim"] = serde_json::json!({"block_height": 815000, "tx_id": "cd"});
        assert!(decode_reclaimable_lock(SENDER, 815693, &reclaimed).is_none());
    }

    #[test]
    fn sweep_reclaims_locked_expired_state() {
        // Regression (caught by a live mainnet test): a lock mined AFTER its
        // timeout is reported as `locked_expired`, not `locked`. Funds are still
        // in the HTLC (claim/reclaim both null) → it MUST be reclaimable. Keying
        // on `state == "locked"` skipped exactly these.
        let mut v: serde_json::Value = serde_json::from_str(LIVE_LOCKED_ROW).unwrap();
        v["state"] = "locked_expired".into();
        assert!(decode_reclaimable_lock(SENDER, 815693, &v).is_some());
    }

    fn test_store(dir: &Path) -> Arc<dyn WalletStore> {
        // Seeded keyring so seal_aux/unseal_aux have a passphrase.
        Arc::new(KeyringStore::open_or_init_fresh(dir, b"test-pass-123").unwrap())
    }

    fn sample(id: &str, now: u64) -> SwapRecord {
        SwapRecord {
            swap_id: id.into(),
            direction: Direction::ExferToBnb,
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
            our_bsc_address: None,
            our_exfer_address: None,
            user_lock_tx: None,
            pool_lock_ref: None,
            claim_tx: None,
            refund_tx: None,
            exfer_timeout_height: None,
            bsc_timeout_sec: None,
            expires_at: now + 600,
            fee_bps: 30,
            network_fee_bnb: Some("0.0002".into()),
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
        assert!(
            res.is_err(),
            "wrong passphrase must not decrypt the journal"
        );
    }

    // ---- funds-safety reveal-gate (the most important check in the engine) ----

    use crate::evm::{HtlcState, OnChainSwap};
    use alloy::primitives::{Address, U256};

    fn locked_swap(recipient: Address, amount: U256, timeout_sec: u64) -> OnChainSwap {
        OnChainSwap {
            recipient,
            amount,
            timeout_sec,
            state: HtlcState::Locked,
        }
    }

    #[test]
    fn reveal_gate_passes_only_when_all_conditions_hold() {
        let us = Address::repeat_byte(0x11);
        let want = U256::from(1000u64);
        let now = 10_000u64;
        // Healthy lock: Locked, pays us, covers the quote, plenty of time.
        let oc = locked_swap(us, want, now + CLAIM_MARGIN_SECS + 60);
        assert!(pool_lock_safe_to_claim(&oc, us, want, now));
        // Over-collateralized (amount > want) is fine.
        let oc = locked_swap(us, want + U256::from(1u64), now + CLAIM_MARGIN_SECS + 60);
        assert!(pool_lock_safe_to_claim(&oc, us, want, now));
    }

    #[test]
    fn reveal_gate_blocks_unsafe_locks() {
        let us = Address::repeat_byte(0x11);
        let attacker = Address::repeat_byte(0x22);
        let want = U256::from(1000u64);
        let now = 10_000u64;
        let far = now + CLAIM_MARGIN_SECS + 60;

        // Wrong recipient (lock pays someone else) → never reveal.
        assert!(!pool_lock_safe_to_claim(
            &locked_swap(attacker, want, far),
            us,
            want,
            now
        ));
        // Underfunded (amount < quoted out) → never reveal.
        assert!(!pool_lock_safe_to_claim(
            &locked_swap(us, want - U256::from(1u64), far),
            us,
            want,
            now
        ));
        // Not enough time left before timeout to land our claim → never reveal.
        assert!(!pool_lock_safe_to_claim(
            &locked_swap(us, want, now + CLAIM_MARGIN_SECS - 1),
            us,
            want,
            now
        ));
        // Not in Locked state → never reveal.
        for st in [HtlcState::None, HtlcState::Claimed, HtlcState::Refunded] {
            let oc = OnChainSwap {
                recipient: us,
                amount: want,
                timeout_sec: far,
                state: st,
            };
            assert!(
                !pool_lock_safe_to_claim(&oc, us, want, now),
                "state {st:?} must block"
            );
        }
    }

    // ---- amount parsing (a wrong parse = wrong amount locked) ----

    #[test]
    fn parse_units_18_basics() {
        use alloy::primitives::U256;
        assert_eq!(
            parse_units_18("1").unwrap(),
            U256::from(10u64).pow(U256::from(18u64))
        );
        assert_eq!(parse_units_18("0").unwrap(), U256::ZERO);
        // 0.5 BNB = 5e17 wei
        assert_eq!(
            parse_units_18("0.5").unwrap(),
            U256::from(5u64) * U256::from(10u64).pow(U256::from(17u64))
        );
        // full 18-dp precision
        assert_eq!(
            parse_units_18("0.000000000000000001").unwrap(),
            U256::from(1u64)
        );
    }

    #[test]
    fn parse_units_18_rejects_bad_input() {
        assert!(parse_units_18("abc").is_err());
        assert!(parse_units_18("1.2.3").is_err());
        // more than 18 fractional digits must be rejected, not silently truncated
        assert!(parse_units_18("0.0000000000000000001").is_err());
    }

    #[test]
    fn direction_serde_matches_wire_strings() {
        // The pool + mobile speak these exact snake_case strings; a drift here
        // would route the wrong leg.
        assert_eq!(
            serde_json::to_string(&Direction::ExferToBnb).unwrap(),
            "\"exfer_to_bnb\""
        );
        assert_eq!(
            serde_json::to_string(&Direction::BnbToExfer).unwrap(),
            "\"bnb_to_exfer\""
        );
        assert_eq!(
            serde_json::from_str::<Direction>("\"exfer_to_bnb\"").unwrap(),
            Direction::ExferToBnb
        );
    }

    #[test]
    fn bsc_htlc_for_chain_knows_mainnet_and_testnet() {
        // Mainnet (56) must resolve to the live deployment the sweep refunds
        // against; a wrong address/deploy-block would miss every stranded lock.
        assert_eq!(
            bsc_htlc_for_chain(56),
            Some(("0x4FdfB5f599cB84b87693aCCA1B9D57f5236e2E3d", 104_440_000))
        );
        assert_eq!(
            bsc_htlc_for_chain(97),
            Some(("0xBAd7f057c8196fF1b724fa1D8cb9D2397780E54d", 0))
        );
        // Unknown/dev chains opt out of the sweep entirely (no enumerable HTLC).
        assert_eq!(bsc_htlc_for_chain(1), None);
        assert_eq!(bsc_htlc_for_chain(31337), None);
    }
}
