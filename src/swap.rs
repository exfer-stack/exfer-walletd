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

/// AAD binding the sealed journal to its purpose (domain separation from the
/// seed/vault blobs).
const JOURNAL_AAD: &[u8] = b"exfer-walletd/v1/swap-journal";
const JOURNAL_FILE: &str = "swaps.enc";

/// Margin before the pool's BSC lock expiry within which we still consider it
/// safe to reveal the preimage (the claim needs time to mine).
const CLAIM_MARGIN_SECS: u64 = 600;
/// Minimum user-leg lock duration we'll accept from the pool, so the user keeps
/// a generous reclaim window even if the pool stalls/vanishes.
const MIN_EXFER_LOCK_BLOCKS: u64 = 360; // ~1h at 10s blocks
const MIN_BSC_LOCK_SECS: u64 = 2 * 3600;

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
    // Present for both directions (sell only carries an EXFER lock in
    // `instructions`, but we still need the BSC contract ref to verify/relay).
    #[serde(default)]
    htlc_contract: Option<String>,
    instructions: Instructions,
}

impl PoolClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
        }
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
    /// Serializes BSC sends from our single derived account (nonce safety).
    bsc_lock: tokio::sync::Mutex<()>,
}

fn strip0x(s: &str) -> &str {
    s.trim_start_matches("0x")
}

fn hash256_from_hex(s: &str) -> Result<exfer::types::Hash256> {
    Ok(exfer::types::Hash256(crate::tx::decode_hash(strip0x(s))?))
}

impl SwapEngine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Arc<dyn WalletStore>,
        node: Arc<ExferNode>,
        inflight: Arc<InFlightUtxos>,
        indexer: Option<IndexerClient>,
        journal: Arc<Journal>,
        cfg: EngineConfig,
    ) -> Self {
        let evm = EvmClient::new(cfg.bsc_rpc_url.clone(), cfg.bsc_chain_id);
        let pool = PoolClient::new(cfg.pool_url.clone());
        Self {
            store,
            node,
            inflight,
            indexer,
            evm,
            pool,
            journal,
            bsc_lock: tokio::sync::Mutex::new(()),
        }
    }

    pub fn journal(&self) -> &Arc<Journal> {
        &self.journal
    }

    /// Indicative pool stats for the UI's pre-quote rate preview:
    /// `{ mid_price_bnb_per_exfer, fee_bps }`. Best-effort.
    pub async fn pool_info(&self) -> Result<serde_json::Value> {
        let v = self.pool.pool_info().await?;
        Ok(serde_json::json!({
            "mid_price_bnb_per_exfer": v.get("mid_price_bnb_per_exfer").cloned().unwrap_or(serde_json::Value::Null),
            "fee_bps": v.get("fee_bps").cloned().unwrap_or(serde_json::Value::Null),
        }))
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
    pub async fn bsc_balances(&self) -> Result<String> {
        let secret = self.store.evm_secret()?;
        let addr = secret_address(&secret)?;
        let bnb = self.evm.bnb_balance(addr).await?;
        Ok(bnb.to_string())
    }

    /// Withdraw native BNB from the derived BSC address to an external wallet
    /// (exchange / another wallet). `amount_human` is in BNB (18 dp); empty or
    /// "max" sends the whole balance minus a gas reserve. Returns the tx hash.
    pub async fn send_bnb(&self, to: &str, amount_human: &str) -> Result<String> {
        let secret = self.store.evm_secret()?;
        let addr = secret_address(&secret)?;
        let amount = if amount_human.trim().is_empty() || amount_human.eq_ignore_ascii_case("max") {
            // Leave a small reserve for the transfer's own gas.
            let bal = self.evm.bnb_balance(addr).await?;
            let reserve = alloy::primitives::U256::from(300_000u64)
                .saturating_mul(alloy::primitives::U256::from(5_000_000_000u64)); // ~gas*price
            bal.saturating_sub(reserve)
        } else {
            parse_units_18(amount_human)?
        };
        if amount.is_zero() {
            return Err(Error::BadParams("nothing to send (zero BNB after gas reserve)".into()));
        }
        let _guard = self.bsc_lock.lock().await;
        self.evm.send_bnb(&secret, to, amount).await
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
            error: None,
            created_at: now,
            updated_at: now,
        };
        self.journal.put(rec.clone())?;
        Ok(rec)
    }

    /// Execute the user's first leg (sell: lock EXFER; buy: lock native BNB).
    pub async fn execute(&self, swap_id: &str) -> Result<SwapRecord> {
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

    /// Funds-safety gate (sell direction): verify the pool's USDT lock exists
    /// on BSC and is safe to claim against BEFORE we reveal the preimage. Must
    /// be Locked, paid to OUR address, cover the quoted output, and have enough
    /// time left to claim. Never trust the pool's self-reported status for this.
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
        let cond_state = oc.state == crate::evm::HtlcState::Locked;
        let cond_recip = oc.recipient == our;
        let cond_amt = oc.amount >= want_out;
        let cond_time = now_secs() + CLAIM_MARGIN_SECS < oc.timeout_sec;
        tracing::debug!(
            swap = %rec.swap_id,
            state = ?oc.state, cond_state, cond_recip, cond_amt, cond_time,
            "verify_pool_bsc_lock"
        );
        Ok(cond_state && cond_recip && cond_amt && cond_time)
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
            // Sell: claim the pool's USDT (gasless relay, with self-claim fallback).
            (SwapStatus::PoolLocked, Direction::ExferToBnb) => {
                match self.pool.relay_claim(&rec.swap_id, &rec.preimage).await {
                    Ok(v) => {
                        let tx = v.get("txhash").and_then(|x| x.as_str()).map(str::to_string);
                        self.journal.update(&rec.swap_id, now_secs(), |r| {
                            r.status = SwapStatus::Completed;
                            r.claim_tx = tx;
                        })?;
                    }
                    Err(e) => {
                        // Fallback: self-submit if we hold BNB for gas.
                        let secret = self.store.evm_secret()?;
                        let htlc = rec.htlc_contract.clone().unwrap_or_default();
                        let our = secret_address(&secret)?;
                        if !htlc.is_empty() && !self.evm.bnb_balance(our).await?.is_zero() {
                            let _guard = self.bsc_lock.lock().await;
                            let tx = self.evm.htlc_claim(&secret, &htlc, &rec.preimage).await?;
                            self.journal.update(&rec.swap_id, now_secs(), |r| {
                                r.status = SwapStatus::Completed;
                                r.claim_tx = Some(tx);
                            })?;
                        } else {
                            return Err(e);
                        }
                    }
                }
            }
            // Buy: claim the pool's EXFER lock, revealing the preimage on-chain.
            (SwapStatus::PoolLocked, Direction::BnbToExfer) => {
                let indexer = self.indexer.as_ref().ok_or_else(|| {
                    Error::Internal("indexer required for buy-direction claim".into())
                })?;
                let from = rec.our_exfer_address.clone().unwrap_or_default();
                let signer = self.load_signer(&from).await?;
                let our_pubkey = hex::encode(signer.pubkey());
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
                let pool_lock = htlcs.iter().find(|h| {
                    h.get("params")
                        .and_then(|p| p.get("receiver"))
                        .and_then(|v| v.as_str())
                        .map(|r| r.eq_ignore_ascii_case(&our_pubkey))
                        .unwrap_or(false)
                });
                let Some(pl) = pool_lock else {
                    return Ok(()); // pool's EXFER lock not indexed yet; retry next tick
                };
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
                self.journal.update(&rec.swap_id, now_secs(), |r| {
                    r.status = SwapStatus::Completed;
                    r.claim_tx = Some(receipt.tx_id);
                })?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Whether the user's first leg is past its refund deadline (so a reclaim
    /// can succeed). Sell: EXFER block height ≥ timeout. Buy: unix time ≥ timeout.
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
}

/// Background monitor: each tick, advance every pending swap toward settlement,
/// expire stale quotes, and reclaim past-deadline locks. Runs until shutdown.
pub async fn run_monitor(engine: Arc<SwapEngine>, shutdown: tokio_util::sync::CancellationToken) {
    const TICK: std::time::Duration = std::time::Duration::from_secs(3);
    tracing::info!("swap monitor started");
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(TICK) => {}
        }
        for rec in engine.journal().pending() {
            // Expire quotes the user never executed.
            if rec.status == SwapStatus::Quoted {
                if now_secs() >= rec.expires_at {
                    let _ = engine.journal().update(&rec.swap_id, now_secs(), |r| {
                        r.status = SwapStatus::Failed;
                        r.error = Some("quote expired (never executed)".into());
                    });
                }
                continue;
            }
            // Past the refund deadline → reclaim the user's lock.
            if matches!(rec.status, SwapStatus::UserLocked | SwapStatus::PoolLocked)
                && engine.refundable(&rec).await
            {
                if let Err(e) = engine.refund(&rec.swap_id).await {
                    tracing::debug!(swap = %rec.swap_id, error = %e, "swap refund retry");
                }
                continue;
            }
            // Otherwise drive it forward.
            if let Err(e) = engine.advance(&rec).await {
                tracing::debug!(swap = %rec.swap_id, error = %e, "swap advance retry");
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
}
