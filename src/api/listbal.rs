//! `list_balances` JSON-RPC handler.
//!
//! Returns every managed address with its cached balance and a
//! freshness envelope:
//!
//! ```json
//! {
//!   "tip": { "height": 12345, "block_id": "ab..." },
//!   "as_of_ms_ago": 1834,
//!   "addresses": [
//!     { "address": "8d89...", "balance": 1500000, "utxo_count": 3,
//!       "fetched_at_ms_ago": 1834, "tip_at_fetch": 12344,
//!       "stale": false, "last_error": null }
//!   ]
//! }
//! ```
//!
//! `stale=true` means "this is a lower bound: the address had at
//! least this much last we heard." It's a hint, not an error. Callers
//! that need strict freshness should call `get_balance(addr)` to
//! trigger a synchronous cache-aside fetch.
//!
//! Never touches upstream synchronously. The refresher fills the L2
//! cache continuously in the background.

use std::time::Instant;

use serde_json::{json, Value};

use crate::api::ApiState;
use crate::error::{Error, Result};

pub async fn list_balances(state: &ApiState) -> Result<Value> {
    // Snapshot the address list — cheap with L6 in place (BTreeSet
    // clone) so we don't need spawn_blocking.
    let addrs = state
        .store
        .list()
        .map_err(|e| Error::Internal(format!("store.list: {e}")))?;

    // Tip — peek only; never block list_balances on upstream. If the
    // cache has never been primed we still return rows (everything
    // marked stale).
    let (tip_height, tip_block_id, tip_fetched_at) = match state.cache.tip.peek() {
        Some(snap) => (
            Some(snap.tip.height),
            Some(snap.tip.block_id),
            Some(snap.fetched_at),
        ),
        None => (None, None, None),
    };

    let now = Instant::now();
    let as_of_ms_ago = tip_fetched_at
        .map(|t| now.saturating_duration_since(t).as_millis() as u64)
        .unwrap_or(0);

    let rows: Vec<Value> = addrs
        .into_iter()
        .map(|addr| build_row(state, &addr, now))
        .collect();

    Ok(json!({
        "tip": {
            "height": tip_height,
            "block_id": tip_block_id,
        },
        "as_of_ms_ago": as_of_ms_ago,
        "addresses": rows,
    }))
}

pub(crate) fn build_row(state: &ApiState, addr: &str, now: Instant) -> Value {
    let bal = state.cache.balance.peek(addr);
    let utxo = state.cache.utxo.peek_address(addr, &state.inflight);

    // Either layer's last_error suffices for the row. Prefer L2's
    // (balance is what the typical dashboard caller cares about); fall
    // back to L3's.
    let last_error = bal.last_error.clone().or(utxo.last_error.clone());

    // Stale iff either layer is stale (the row is only "fresh" when
    // both L2 and L3 are fresh).
    let stale = bal.stale || utxo.stale;

    let fetched_at_ms_ago = match (bal.fetched_at, utxo.fetched_at) {
        (Some(a), Some(b)) => Some(now.saturating_duration_since(a.max(b)).as_millis() as u64),
        (Some(a), None) | (None, Some(a)) => {
            Some(now.saturating_duration_since(a).as_millis() as u64)
        }
        (None, None) => None,
    };

    // tip_at_fetch is the *older* of the two layers' tips — that's
    // the tip the row's data is jointly anchored to.
    let tip_at_fetch = match (bal.tip_at_fetch, utxo.tip_at_fetch) {
        (0, 0) => None,
        (0, t) | (t, 0) => Some(t),
        (a, b) => Some(a.min(b)),
    };

    let utxo_count = utxo.utxos.as_ref().map(|u| u.utxos.len());

    json!({
        "address": addr,
        "balance": bal.balance,
        "utxo_count": utxo_count,
        "fetched_at_ms_ago": fetched_at_ms_ago,
        "tip_at_fetch": tip_at_fetch,
        "stale": stale,
        "last_error": last_error,
    })
}
