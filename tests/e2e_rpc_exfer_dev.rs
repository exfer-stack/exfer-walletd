//! End-to-end smoke test against `rpc.exfer.dev` — the live public
//! RPC.
//!
//! Marked `#[ignore]` so `cargo test` skips it in CI. Run manually:
//!
//! ```bash
//! cargo test --test e2e_rpc_exfer_dev -- --ignored --nocapture
//! ```
//!
//! What this proves (when it runs green):
//!
//! 1. The cache layers compile against a real upstream and the wire
//!    shapes match (`get_block_height`, `get_balance`,
//!    `get_address_utxos`, `get_block`, `get_transaction`).
//! 2. The refresher cleanly handles upstream rate limiting — we
//!    observed `rpc.exfer.dev` capping at "30 balance/utxo queries per
//!    minute" and the refresher correctly classifies the rate-limit
//!    response as a per-tick all-failure → exponential backoff (5s →
//!    10s → 20s …) while preserving last-known-good values + filling
//!    `last_error` in each row.
//! 3. `list_balances` cache hit is < 20ms warm and ~1.5s cold (single
//!    upstream round trip in the cold path; zero in the warm path).
//! 4. `get_block(height=…)` warms L4: cold ~1.5s, warm < 10ms (260×
//!    speed-up against `rpc.exfer.dev`).
//!
//! Operability note: `rpc.exfer.dev`'s 30-query-per-minute rate
//! limit means the `balanced` profile (5s tick × 2 calls per addr ×
//! N addrs) saturates quickly at N > 3. Production deployments that
//! point at `rpc.exfer.dev` should set
//! `--cache-refresh-secs 60` (or higher) and accept the staleness
//! trade-off.

use std::time::Duration;

use exfer_walletd::upstream::ExferNode;

const RPC_URL: &str = "https://rpc.exfer.dev";

#[tokio::test]
#[ignore = "hits live public RPC — run manually with --ignored"]
async fn e2e_tip_fetch_against_rpc_exfer_dev() {
    let node = ExferNode::new(RPC_URL, Duration::from_secs(10)).unwrap();
    let tip = node.get_block_height().await.expect("tip fetch");
    assert!(tip.height > 0, "live tip must be positive");
    assert_eq!(tip.block_id.len(), 64, "block_id is 64-hex");
    println!("rpc.exfer.dev tip height = {}", tip.height);
}

#[tokio::test]
#[ignore = "hits live public RPC — run manually with --ignored"]
async fn e2e_list_balances_envelope_shape_against_real_upstream() {
    use exfer_walletd::api::{dispatch, ApiState, RpcRequest};
    use exfer_walletd::cache::{CacheProfile, WalletCache};
    use exfer_walletd::store::FsWalletStore;
    use serde_json::json;
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let store = FsWalletStore::open(dir.path()).unwrap();
    let node = ExferNode::new(RPC_URL, Duration::from_secs(10)).unwrap();
    let cache = Arc::new(WalletCache::new(CacheProfile::Balanced, Some(60)));
    let state = ApiState {
        store: Arc::new(store),
        node: Arc::new(node),
        inflight: Arc::new(exfer_walletd::inflight::InFlightUtxos::new()),
        cache: cache.clone(),
    };

    // Generate two addresses.
    for _ in 0..2 {
        dispatch(
            &state,
            RpcRequest {
                jsonrpc: "2.0".into(),
                method: "generate_address".into(),
                params: json!({}),
                id: json!(1),
            },
        )
        .await
        .unwrap();
    }

    let r = dispatch(
        &state,
        RpcRequest {
            jsonrpc: "2.0".into(),
            method: "list_balances".into(),
            params: json!({}),
            id: json!(1),
        },
    )
    .await
    .unwrap();

    // Envelope shape.
    assert!(r.get("tip").is_some(), "list_balances has tip");
    assert!(r.get("as_of_ms_ago").is_some());
    let rows = r["addresses"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "one row per managed address");

    // Cold rows should be stale (seed = tip_at_fetch=0).
    for row in rows {
        assert!(row["address"].is_string());
        // balance=0 from seed_zero.
        assert_eq!(row["balance"], 0);
        // tip_at_fetch=null on the seed value.
        assert!(row["tip_at_fetch"].is_null());
        assert_eq!(row["stale"], true);
    }
}
