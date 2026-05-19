//! Manual cache-refresh RPC handlers — `refresh_address` (single)
//! and `refresh_addresses` (batch).
//!
//! These exist because the v0.14.0 `balanced` profile defaults to
//! `refresh_interval = 0` (no background polling). On rate-limited
//! public RPCs like `rpc.exfer.dev`, automatic polling requires
//! `refresh_interval >= 4N` seconds where N is the managed address
//! count — at 100 addresses that's 6.7 minutes per round, at 1000
//! it's 67 minutes. Auto-polling doesn't scale; applications drive
//! the cadence themselves.
//!
//! Both methods bypass TTL: a refresh ALWAYS hits upstream, then
//! CAS-writes the L2 + L3 cache. Per-call failures are recorded in
//! the row's `last_error` field; the cached value (if any) is
//! preserved — same contract as the background refresher.

use std::time::Instant;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::listbal::build_row;
use crate::api::ApiState;
use crate::error::{Error, Result};

#[derive(Debug, Deserialize)]
pub struct RefreshAddressParams {
    pub address: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshAddressesParams {
    pub addresses: Vec<String>,
}

/// `refresh_address` — single-address forced refresh.
///
/// Returns the same row shape that `list_balances` emits for one
/// address, post-refresh. On upstream failure the row still appears
/// but with `last_error` populated and the value carrying the prior
/// cached state (or `null` if cache was cold).
pub async fn refresh_address(state: &ApiState, params: Value) -> Result<Value> {
    let p: RefreshAddressParams = serde_json::from_value(params)
        .map_err(|e| Error::BadEnvelope(format!("refresh_address params: {e}")))?;
    crate::api::ensure_64_hex(&p.address)?;

    state.cache.refresh_address(&p.address, &state.node).await;

    let now = Instant::now();
    let row = build_row(state, &p.address, now);
    Ok(json!({ "address": row }))
}

/// `refresh_addresses` — batch forced refresh. Concurrency-bounded
/// (uses `cache.params.concurrency`, default 8) so a 100-address
/// batch doesn't burst all at once. Returns the same envelope as
/// `list_balances` — caller can substitute this call wherever they'd
/// otherwise call `list_balances` after a known-changed event.
pub async fn refresh_addresses(state: &ApiState, params: Value) -> Result<Value> {
    let p: RefreshAddressesParams = serde_json::from_value(params)
        .map_err(|e| Error::BadEnvelope(format!("refresh_addresses params: {e}")))?;

    // Validate up front — if any address is malformed, reject the
    // whole batch (consistent with how get_balance behaves).
    for a in &p.addresses {
        crate::api::ensure_64_hex(a)?;
    }

    let concurrency = state.cache.params.concurrency.max(1);
    let cache = state.cache.clone();
    let node = state.node.clone();

    use futures::stream::{self, StreamExt};
    let owned_addrs = p.addresses.clone();
    stream::iter(owned_addrs)
        .for_each_concurrent(concurrency, |addr| {
            let cache = cache.clone();
            let node = node.clone();
            async move {
                cache.refresh_address(&addr, &node).await;
            }
        })
        .await;

    // Build the envelope from the post-refresh cache state.
    let tip_view = state.cache.tip.peek().map(|s| {
        json!({
            "height": s.tip.height,
            "block_id": s.tip.block_id,
        })
    });
    let now = Instant::now();
    let rows: Vec<Value> = p
        .addresses
        .iter()
        .map(|a| build_row(state, a, now))
        .collect();
    let as_of_ms_ago = state
        .cache
        .tip
        .peek()
        .map(|s| now.saturating_duration_since(s.fetched_at).as_millis() as u64)
        .unwrap_or(0);

    Ok(json!({
        "tip": tip_view,
        "as_of_ms_ago": as_of_ms_ago,
        "addresses": rows,
    }))
}
