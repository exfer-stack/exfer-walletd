//! `htlc_status` / `htlc_list` / `htlc_forget` / `get_follower_status` —
//! JSON-RPC handlers over the v1.9 HTLC observability index.
//!
//! All four methods consult [`crate::index::Index`] (populated by the
//! block follower) and never touch upstream RPC. The first three
//! follow the standard `noun_verb` Read / Manage scope split; the
//! fourth is a Read-scope status snapshot.

use exfer::covenants::htlc::{HtlcRole, HtlcState};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{ensure_64_hex, ApiState};
use crate::error::{Error, Result};
use crate::index::{Cursor, HtlcFilter};

// ---------------------------------------------------------------------------
// htlc_status
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct HtlcStatusParams {
    pub lock_tx_id: String,
    #[serde(default)]
    pub output_index: u32,
}

pub async fn htlc_status_method(state: &ApiState, params: Value) -> Result<Value> {
    let p: HtlcStatusParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("htlc_status params: {e}")))?;
    ensure_64_hex(&p.lock_tx_id)?;
    let tx_id = decode_hex32(&p.lock_tx_id)?;
    let index = state.index.clone();
    let output_index = p.output_index;
    let rec = tokio::task::spawn_blocking(move || index.get_htlc(&tx_id, output_index))
        .await
        .map_err(|e| Error::Internal(format!("htlc_status: blocking task panicked: {e}")))??;
    match rec {
        Some(r) => serde_json::to_value(&r).map_err(|e| Error::Internal(e.to_string())),
        None => Err(Error::Wallet(format!(
            "no tracked HTLC at ({}, {})",
            p.lock_tx_id, p.output_index
        ))),
    }
}

// ---------------------------------------------------------------------------
// htlc_list
// ---------------------------------------------------------------------------

/// Default page size (`limit` if the caller doesn't pass one).
pub const HTLC_LIST_DEFAULT_LIMIT: u32 = 100;
/// Maximum permitted page size.
pub const HTLC_LIST_MAX_LIMIT: u32 = 1000;

#[derive(Debug, Deserialize)]
pub struct HtlcListParams {
    /// Restrict to entries where the observer plays this role.
    #[serde(default)]
    pub role: Option<HtlcRole>,
    /// Restrict to entries in any of these states. Empty == every
    /// state.
    #[serde(default)]
    pub state: Option<HtlcStateFilter>,
    /// Restrict to entries on or after this block height.
    #[serde(default)]
    pub since_height: Option<u64>,
    /// Page size. Default `HTLC_LIST_DEFAULT_LIMIT`, capped at
    /// `HTLC_LIST_MAX_LIMIT`.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Opaque pagination cursor returned by a previous call.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Address filter — currently advisory; the walletd index only
    /// stores HTLCs already linked to an owned key, so this just
    /// shapes future API parity with the indexer service.
    #[serde(default)]
    pub address: Option<String>,
}

/// `state` accepts either a single `HtlcState` or an array. We model
/// it as a tagged enum so serde does the right thing automatically.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum HtlcStateFilter {
    One(HtlcState),
    Many(Vec<HtlcState>),
}

#[derive(Debug, Serialize)]
pub struct HtlcListResponse {
    pub htlcs: Vec<exfer::covenants::htlc::HtlcRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

pub async fn htlc_list_method(state: &ApiState, params: Value) -> Result<Value> {
    let p: HtlcListParams = if params.is_null() {
        HtlcListParams {
            role: None,
            state: None,
            since_height: None,
            limit: None,
            cursor: None,
            address: None,
        }
    } else {
        serde_json::from_value(params)
            .map_err(|e| Error::BadParams(format!("htlc_list params: {e}")))?
    };

    let limit_u32 = p
        .limit
        .unwrap_or(HTLC_LIST_DEFAULT_LIMIT)
        .min(HTLC_LIST_MAX_LIMIT);
    let limit = limit_u32 as usize;

    let states = match p.state {
        Some(HtlcStateFilter::One(s)) => vec![s],
        Some(HtlcStateFilter::Many(v)) => v,
        None => vec![],
    };

    let cursor = match p.cursor.as_deref() {
        Some(s) => Some(Cursor::decode(s)?),
        None => None,
    };

    if let Some(ref addr) = p.address {
        ensure_64_hex(addr)?;
    }

    let filter = HtlcFilter {
        role: p.role,
        states,
        since_height: p.since_height,
        owned_address: None, // walletd-side index is already scoped to owned
    };

    let index = state.index.clone();
    let (records, next_cur) =
        tokio::task::spawn_blocking(move || index.list_htlcs(&filter, limit, cursor))
            .await
            .map_err(|e| Error::Internal(format!("htlc_list: blocking task panicked: {e}")))??;

    let resp = HtlcListResponse {
        htlcs: records,
        next_cursor: next_cur.map(|c| c.encode()),
    };
    serde_json::to_value(&resp).map_err(|e| Error::Internal(e.to_string()))
}

// ---------------------------------------------------------------------------
// htlc_forget
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct HtlcForgetParams {
    pub lock_tx_id: String,
    #[serde(default)]
    pub output_index: u32,
}

#[derive(Debug, Serialize)]
pub struct HtlcForgetResponse {
    pub removed: bool,
}

pub async fn htlc_forget_method(state: &ApiState, params: Value) -> Result<Value> {
    let p: HtlcForgetParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("htlc_forget params: {e}")))?;
    ensure_64_hex(&p.lock_tx_id)?;
    let tx_id = decode_hex32(&p.lock_tx_id)?;
    let output_index = p.output_index;

    let index = state.index.clone();
    // Only allow forgetting settled HTLCs. Look it up first so we can
    // reject pending ones with a useful error.
    let index_for_get = index.clone();
    let existing =
        tokio::task::spawn_blocking(move || index_for_get.get_htlc(&tx_id, output_index))
            .await
            .map_err(|e| Error::Internal(format!("htlc_forget: blocking task panicked: {e}")))??;
    let Some(rec) = existing else {
        return Ok(serde_json::to_value(HtlcForgetResponse { removed: false }).unwrap());
    };
    if !matches!(rec.state, HtlcState::Claimed | HtlcState::Reclaimed) {
        return Err(Error::BadParams(format!(
            "htlc_forget: refusing to forget a non-settled HTLC (state = {:?}); \
             only Claimed / Reclaimed entries may be removed",
            rec.state
        )));
    }
    // Best-effort: pass [0u8;32] as owned_addr — the index removes
    // primary-table row + every secondary entry derivable from the
    // record itself; only the by_owned secondary would need the addr,
    // and re-scanning by_owned with a sentinel address is just a noop.
    let removed =
        tokio::task::spawn_blocking(move || index.forget_htlc(&tx_id, output_index, [0u8; 32]))
            .await
            .map_err(|e| Error::Internal(format!("htlc_forget: blocking task panicked: {e}")))??;
    serde_json::to_value(HtlcForgetResponse { removed }).map_err(|e| Error::Internal(e.to_string()))
}

// ---------------------------------------------------------------------------
// get_follower_status
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct FollowerStatusResponse {
    pub last_indexed_height: u64,
    pub last_indexed_block_id: String,
    pub tip_height: u64,
    /// `tip_height - last_indexed_height`. May be negative briefly if
    /// the tip RPC and the follower race; clients should treat <0 as 0.
    pub lag: i64,
    pub indexed_htlc_count: u64,
    pub follower_started_at: u64,
    pub full_scan_complete: bool,
}

pub async fn get_follower_status_method(state: &ApiState, _params: Value) -> Result<Value> {
    let tip = state.node.get_block_height().await?;
    let index = state.index.clone();
    let (meta, count) = tokio::task::spawn_blocking(move || {
        let meta = index.follower_meta()?;
        let count = index.count()?;
        Ok::<_, Error>((meta, count))
    })
    .await
    .map_err(|e| Error::Internal(format!("get_follower_status: blocking task panicked: {e}")))??;
    let resp = FollowerStatusResponse {
        last_indexed_height: meta.last_indexed_height,
        last_indexed_block_id: hex::encode(meta.last_indexed_block_id),
        tip_height: tip.height,
        lag: (tip.height as i64) - (meta.last_indexed_height as i64),
        indexed_htlc_count: count,
        follower_started_at: meta.started_at,
        full_scan_complete: meta.full_scan_complete,
    };
    serde_json::to_value(&resp).map_err(|e| Error::Internal(e.to_string()))
}

// ---------------------------------------------------------------------------
// wait_for_tx
// ---------------------------------------------------------------------------

/// Maximum permitted `timeout_secs`. Above this the API clamps the
/// request rather than rejecting it.
pub const WAIT_FOR_TX_MAX_TIMEOUT_SECS: u64 = 600;

#[derive(Debug, Deserialize)]
pub struct WaitForTxParams {
    pub tx_id: String,
    #[serde(default = "default_min_confirmations")]
    pub min_confirmations: u32,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_min_confirmations() -> u32 {
    1
}

fn default_timeout_secs() -> u64 {
    60
}

#[derive(Debug, Serialize)]
pub struct WaitForTxResponse {
    pub tx_id: String,
    pub block_id: String,
    pub block_height: u64,
    pub confirmations: u64,
}

pub async fn wait_for_tx_method(state: &ApiState, params: Value) -> Result<Value> {
    let p: WaitForTxParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("wait_for_tx params: {e}")))?;
    ensure_64_hex(&p.tx_id)?;
    let timeout_secs = p.timeout_secs.min(WAIT_FOR_TX_MAX_TIMEOUT_SECS);
    let min_confs = p.min_confirmations.max(1);

    let work = wait_for_tx_inner(state, p.tx_id.clone(), min_confs);
    match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), work).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(Error::WaitTimeout {
            tx_id: p.tx_id,
            min_confirmations: min_confs,
            elapsed_secs: timeout_secs,
        }),
    }
}

/// Polls `get_transaction` on each tip-channel tick until the tx is in
/// a block with `min_confs` confirmations behind it. Upstream
/// "not-found" responses are silently treated as "not yet visible"
/// (the tx may still be propagating) and the loop continues.
async fn wait_for_tx_inner(state: &ApiState, tx_id: String, min_confs: u32) -> Result<Value> {
    let mut tip_rx = state.tip_rx.clone();
    loop {
        // Snapshot current observed state.
        let lookup = state.node.get_transaction(&tx_id).await;
        let block_height = match lookup {
            Ok(s) => s.block_height,
            Err(Error::UpstreamRpc { .. }) => None, // not visible yet
            Err(e) => return Err(e),
        };
        if let Some(bh) = block_height {
            let follower_height = *tip_rx.borrow();
            let confirmations = follower_height.saturating_sub(bh).saturating_add(1);
            if confirmations >= min_confs as u64 {
                // Final fetch so we can return the canonical block_id.
                let s = state.node.get_transaction(&tx_id).await?;
                let resp = WaitForTxResponse {
                    tx_id: s.tx_id,
                    block_id: s.block_id.unwrap_or_default(),
                    block_height: s.block_height.unwrap_or(bh),
                    confirmations,
                };
                return serde_json::to_value(&resp).map_err(|e| Error::Internal(e.to_string()));
            }
        }
        // Wait for tip to advance (or shutdown).
        if tip_rx.changed().await.is_err() {
            // Sender dropped — daemon is shutting down.
            return Err(Error::Internal(
                "wait_for_tx: follower channel closed".into(),
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// wait_for_payment
// ---------------------------------------------------------------------------

/// Maximum permitted `timeout_secs` for `wait_for_payment`. Above this the
/// API clamps the request rather than rejecting it.
pub const WAIT_FOR_PAYMENT_MAX_TIMEOUT_SECS: u64 = 600;

#[derive(Debug, Deserialize)]
pub struct WaitForPaymentParams {
    /// 64-hex address (script) to watch for incoming credit.
    pub address: String,
    /// Only report a credit whose value is at least this many exfers.
    /// Defaults to 1 (any non-zero credit).
    #[serde(default = "default_min_amount")]
    pub min_amount: u64,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_min_amount() -> u64 {
    1
}

/// Block until a *new* credit to `address` is observed, or `timeout_secs`
/// elapses. The fast path wakes on the in-process `WalletEvents` bus (a
/// `Script` nudge arrives within a network RTT of the paying tx hitting the
/// node's mempool when the node's `/sse` push is connected); the fallback
/// wakes on each follower tip advance. Returns as soon as the payment is
/// *seen* in the mempool (0 confirmations) — pair with `wait_for_tx` for
/// settlement finality.
///
/// A quiet window is a normal outcome for a watcher, not an error: on
/// timeout this returns `{received: false, timed_out: true}` so an agent
/// can simply call again.
pub async fn wait_for_payment_method(state: &ApiState, params: Value) -> Result<Value> {
    let p: WaitForPaymentParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("wait_for_payment params: {e}")))?;
    ensure_64_hex(&p.address)?;
    let timeout_secs = p.timeout_secs.min(WAIT_FOR_PAYMENT_MAX_TIMEOUT_SECS);

    let work = wait_for_payment_inner(state, p.address.clone(), p.min_amount);
    match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), work).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(e),
        Err(_) => Ok(serde_json::json!({
            "address": p.address,
            "received": false,
            "timed_out": true,
            "waited_secs": timeout_secs,
        })),
    }
}

/// A credit observed for the watched address.
struct PaymentSeen {
    tx_id: Option<String>,
    amount: u64,
    confirmed: bool,
    tip_height: u64,
}

/// Snapshot the address's current incoming state so only *new* credit is
/// reported. Returns (mempool received tx_ids, confirmed balance).
async fn payment_baseline(
    state: &ApiState,
    address: &str,
) -> Result<(std::collections::HashSet<String>, u64)> {
    let mut seen = std::collections::HashSet::new();
    if let Some(m) = state.node.get_address_mempool_opt(address).await? {
        for tx in &m.mempool {
            if !tx.received.is_empty() {
                seen.insert(tx.tx_id.clone());
            }
        }
    }
    let balance = state.node.get_balance(address).await?.balance;
    Ok((seen, balance))
}

/// Detect a credit absent at baseline. A new mempool tx paying this address
/// is the sub-second path; a confirmed-balance increase is the fallback for
/// nodes without `get_address_mempool` or payments that land straight in a
/// block.
async fn detect_payment(
    state: &ApiState,
    address: &str,
    baseline_txids: &std::collections::HashSet<String>,
    baseline_balance: u64,
    min_amount: u64,
) -> Result<Option<PaymentSeen>> {
    let mempool = state.node.get_address_mempool_opt(address).await?;
    if let Some(m) = &mempool {
        for tx in &m.mempool {
            if tx.received.is_empty() || baseline_txids.contains(&tx.tx_id) {
                continue;
            }
            let amount: u64 = tx.received.iter().map(|r| r.value).sum();
            if amount >= min_amount {
                return Ok(Some(PaymentSeen {
                    tx_id: Some(tx.tx_id.clone()),
                    amount,
                    confirmed: false,
                    tip_height: m.tip_height,
                }));
            }
        }
    }
    let balance = state.node.get_balance(address).await?.balance;
    if balance > baseline_balance {
        let delta = balance - baseline_balance;
        if delta >= min_amount {
            let tip_height = mempool
                .as_ref()
                .map(|m| m.tip_height)
                .unwrap_or_else(|| *state.tip_rx.borrow());
            return Ok(Some(PaymentSeen {
                tx_id: None,
                amount: delta,
                confirmed: true,
                tip_height,
            }));
        }
    }
    Ok(None)
}

async fn wait_for_payment_inner(
    state: &ApiState,
    address: String,
    min_amount: u64,
) -> Result<Value> {
    use crate::sse_client::WalletNudge;
    use tokio::sync::broadcast::error::RecvError;

    // The 32-byte script we match `Script` nudges against. `ensure_64_hex`
    // already guaranteed this decodes to 32 bytes.
    let target = hex::decode(&address).ok();

    // Subscribe before snapshotting so a payment landing in the gap still
    // wakes us.
    let mut rx = state.events.subscribe();
    let mut tip_rx = state.tip_rx.clone();
    let (baseline_txids, baseline_balance) = payment_baseline(state, &address).await?;

    let mut bus_alive = true;
    loop {
        if let Some(seen) =
            detect_payment(state, &address, &baseline_txids, baseline_balance, min_amount).await?
        {
            return Ok(serde_json::json!({
                "address": address,
                "received": true,
                "timed_out": false,
                "tx_id": seen.tx_id,
                "amount": seen.amount,
                "confirmations": if seen.confirmed { 1 } else { 0 },
                "tip_height": seen.tip_height,
            }));
        }

        // Wait for the next *relevant* wake-up: a matching script nudge, a
        // tip advance, or a resync. Other addresses' nudges are ignored
        // without re-querying.
        loop {
            tokio::select! {
                r = rx.recv(), if bus_alive => match r {
                    Ok(WalletNudge::Script(s)) => {
                        if target.as_deref() == Some(s.as_slice()) {
                            break;
                        }
                    }
                    Ok(WalletNudge::Tip(_)) | Ok(WalletNudge::Resync) => break,
                    Err(RecvError::Lagged(_)) => break,
                    Err(RecvError::Closed) => bus_alive = false,
                },
                c = tip_rx.changed() => {
                    if c.is_err() {
                        return Err(Error::Internal(
                            "wait_for_payment: follower channel closed".into(),
                        ));
                    }
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn decode_hex32(s: &str) -> Result<[u8; 32]> {
    let b = hex::decode(s).map_err(|e| Error::BadHex(e.to_string()))?;
    if b.len() != 32 {
        return Err(Error::BadAddressLen(b.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Ok(out)
}
