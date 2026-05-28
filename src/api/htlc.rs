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
    let (records, next_cur) = tokio::task::spawn_blocking(move || {
        index.list_htlcs(&filter, limit, cursor)
    })
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
    let existing = tokio::task::spawn_blocking(move || index_for_get.get_htlc(&tx_id, output_index))
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
    let removed = tokio::task::spawn_blocking(move || {
        index.forget_htlc(&tx_id, output_index, [0u8; 32])
    })
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
