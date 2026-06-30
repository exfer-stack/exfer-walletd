//! Integration test: the spend allowance ceilings are enforced on the
//! JSON-RPC dispatch path, and the check is a true **pre-broadcast,
//! pre-keystore** short-circuit.
//!
//! The node URL points at a closed port. If the allowance gate ever let a
//! capped spend through, the handler would go on to load the signer and
//! contact the node — surfacing a `WalletNotFound` or transport error
//! instead of `AllowanceExceeded`. So reaching `-32038` proves the gate
//! fires first, before any funds could move.

use std::sync::Arc;
use std::time::Duration;

use exfer_walletd::allowance::{AllowanceCaps, AllowanceLedger};
use exfer_walletd::api::{dispatch, ApiState, RpcRequest};
use exfer_walletd::error::Error;
use exfer_walletd::store::HdSeedStore;
use exfer_walletd::upstream::{ExferNode, RetryPolicy};
use serde_json::json;

fn capped_state(caps: AllowanceCaps) -> (ApiState, tempfile::TempDir) {
    let wallet_dir = tempfile::TempDir::new().unwrap();
    let store = HdSeedStore::open_or_init_fresh(wallet_dir.path(), b"test-passphrase").unwrap();
    let node = ExferNode::with_retry_policy(
        "http://127.0.0.1:1", // closed port — must never be reached for capped spends
        Duration::from_secs(1),
        RetryPolicy::none(),
    )
    .unwrap();
    let index = Arc::new(exfer_walletd::index::Index::open(wallet_dir.path()).unwrap());
    let (_tip_tx, tip_rx) = tokio::sync::watch::channel(0u64);
    let state = ApiState {
        store: Arc::new(store),
        node: Arc::new(node),
        inflight: Arc::new(exfer_walletd::inflight::InFlightUtxos::new()),
        idempotency: Arc::new(exfer_walletd::idempotency::IdempotencyCache::new()),
        index,
        tip_rx,
        indexer: None,
        events: exfer_walletd::sse_client::WalletEvents::new(),
        engine: None,
        allowance: Arc::new(AllowanceLedger::in_memory(caps).unwrap()),
        lock_watch: None,
    };
    (state, wallet_dir)
}

fn rpc(method: &str, params: serde_json::Value) -> RpcRequest {
    RpcRequest {
        jsonrpc: "2.0".into(),
        method: method.into(),
        params,
        id: Some(json!(1)),
    }
}

fn addr(byte: &str) -> String {
    byte.repeat(32) // 64 hex chars
}

#[tokio::test]
async fn transfer_over_per_tx_cap_rejected_before_broadcast() {
    let (state, _wd) = capped_state(AllowanceCaps {
        per_tx: Some(1_000),
        ..Default::default()
    });
    let err = dispatch(
        &state,
        rpc(
            "transfer",
            json!({
                "from": addr("11"),
                "outputs": [{ "to": addr("22"), "amount": 5_000u64 }],
            }),
        ),
    )
    .await
    .unwrap_err();
    match err {
        Error::AllowanceExceeded {
            scope,
            limit,
            requested,
            ..
        } => {
            assert_eq!(scope, "per_tx");
            assert_eq!(limit, 1_000);
            assert_eq!(requested, 5_000);
        }
        other => panic!("expected AllowanceExceeded, got {other:?}"),
    }
}

#[tokio::test]
async fn transfer_sums_multiple_outputs_against_per_tx_cap() {
    let (state, _wd) = capped_state(AllowanceCaps {
        per_tx: Some(1_000),
        ..Default::default()
    });
    // Two outputs of 600 each = 1_200 total > 1_000 cap.
    let err = dispatch(
        &state,
        rpc(
            "transfer",
            json!({
                "from": addr("11"),
                "outputs": [
                    { "to": addr("22"), "amount": 600u64 },
                    { "to": addr("33"), "amount": 600u64 },
                ],
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            err,
            Error::AllowanceExceeded {
                requested: 1_200,
                ..
            }
        ),
        "expected summed-output AllowanceExceeded, got {err:?}"
    );
}

#[tokio::test]
async fn htlc_lock_over_per_tx_cap_rejected_before_broadcast() {
    let (state, _wd) = capped_state(AllowanceCaps {
        per_tx: Some(1_000),
        ..Default::default()
    });
    let err = dispatch(
        &state,
        rpc(
            "htlc_lock",
            json!({
                "from": addr("11"),
                "receiver": addr("22"),
                "hash_lock": addr("33"),
                "timeout": 100u64,
                "amount": 9_000u64,
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            err,
            Error::AllowanceExceeded {
                scope: "per_tx",
                requested: 9_000,
                ..
            }
        ),
        "expected AllowanceExceeded, got {err:?}"
    );
}

#[tokio::test]
async fn under_cap_spend_passes_the_gate() {
    // A spend within the cap must NOT be rejected by the allowance layer.
    // With a non-managed `from`, it then fails downstream (signer load /
    // node) — any error EXCEPT AllowanceExceeded proves the gate let it
    // through.
    let (state, _wd) = capped_state(AllowanceCaps {
        per_tx: Some(1_000),
        ..Default::default()
    });
    let err = dispatch(
        &state,
        rpc(
            "transfer",
            json!({
                "from": addr("11"),
                "outputs": [{ "to": addr("22"), "amount": 500u64 }],
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(
        !matches!(err, Error::AllowanceExceeded { .. }),
        "under-cap spend was wrongly blocked by the allowance gate: {err:?}"
    );
}

#[tokio::test]
async fn allowance_status_reports_configured_caps() {
    let (state, _wd) = capped_state(AllowanceCaps {
        per_tx: Some(1_000),
        per_period: Some(50_000),
        period_secs: 3_600,
    });
    let v = dispatch(&state, rpc("allowance_status", json!({})))
        .await
        .unwrap();
    assert_eq!(v["per_tx"], json!(1_000));
    assert_eq!(v["per_period"], json!(50_000));
    assert_eq!(v["period_secs"], json!(3_600));
    assert_eq!(v["spent_this_period"], json!(0));
    assert_eq!(v["remaining_this_period"], json!(50_000));
}

#[tokio::test]
async fn unlimited_default_never_rejects() {
    // The zero-break contract: with no caps, even an enormous spend is not
    // touched by the allowance layer.
    let (state, _wd) = capped_state(AllowanceCaps::default());
    let err = dispatch(
        &state,
        rpc(
            "transfer",
            json!({
                "from": addr("11"),
                "outputs": [{ "to": addr("22"), "amount": u64::MAX }],
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(
        !matches!(err, Error::AllowanceExceeded { .. }),
        "unlimited ledger must never raise AllowanceExceeded, got {err:?}"
    );
    // And status reflects "no caps".
    let v = dispatch(&state, rpc("allowance_status", json!({})))
        .await
        .unwrap();
    assert_eq!(v["per_tx"], json!(null));
    assert_eq!(v["per_period"], json!(null));
}

#[tokio::test]
async fn exfer_to_bnb_swap_refused_when_caps_active() {
    // The EXFER→BNB swap leg isn't metered yet, so with caps active it must
    // be refused (fail-closed) rather than silently bypass the cap. The gate
    // fires before the engine check, so it triggers even with no engine.
    let (state, _wd) = capped_state(AllowanceCaps {
        per_tx: Some(1_000),
        ..Default::default()
    });
    let err = dispatch(
        &state,
        rpc(
            "swap_get_quote",
            json!({ "direction": "exfer_to_bnb", "amount_in": "1.0", "from": addr("11") }),
        ),
    )
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("spend caps") || msg.contains("exfer_to_bnb"),
        "expected the allowance gate to refuse the swap, got: {msg}"
    );
}

#[tokio::test]
async fn exfer_to_bnb_swap_not_gated_when_caps_inactive() {
    // With no caps, the allowance gate is inert — the swap falls through to
    // the normal engine path (which here errors as 'not configured', NOT as
    // a caps refusal).
    let (state, _wd) = capped_state(AllowanceCaps::default());
    let err = dispatch(
        &state,
        rpc(
            "swap_get_quote",
            json!({ "direction": "exfer_to_bnb", "amount_in": "1.0", "from": addr("11") }),
        ),
    )
    .await
    .unwrap_err();
    assert!(
        !err.to_string().contains("spend caps"),
        "allowance gate must not fire when no caps are configured: {err}"
    );
}
