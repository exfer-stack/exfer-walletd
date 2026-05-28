//! End-to-end test for the v1.9 block follower.
//!
//! Builds a synthetic 3-block chain in memory:
//!   block 0:  empty (genesis)
//!   block 1:  contains lock_tx — an HTLC output paying our wallet
//!   block 2:  contains claim_tx — spends lock_tx[0] via the hash arm
//!
//! Mounts wiremock to serve get_block_height / get_block / get_transaction
//! over the synthetic chain, runs the real Follower's `tick()` once
//! synchronously, and verifies the redb index ends up in the
//! expected state: the HTLC is tracked, classified as Receiver-owned,
//! and transitioned from Locked → Claimed with the right preimage.

use std::sync::Arc;
use std::time::Duration;

use exfer::covenants::htlc::{htlc, HtlcRole, HtlcState};
use exfer::script::serialize::serialize_program;
use exfer::script::value::Value;
use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};
use exfer::types::Hash256;
use exfer_walletd::follower::{Follower, FollowerConfig};
use exfer_walletd::index::Index;
use exfer_walletd::store::{HdSeedStore, WalletStore};
use exfer_walletd::upstream::{ExferNode, RetryPolicy};
use serde_json::json;
use sha2::Digest;
use wiremock::matchers::{body_partial_json, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Synthetic tx + block fabrication
// ---------------------------------------------------------------------------

/// A trivial 1-in/1-out tx with a fully-zero "coinbase-like" input.
/// The follower never validates signatures or coin-balance, so this is
/// enough to exercise the parse path.
fn fabricate_lock_tx(htlc_script: Vec<u8>, amount: u64) -> Transaction {
    Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0xFFFF_FFFF,
        }],
        outputs: vec![TxOutput {
            value: amount,
            script: htlc_script,
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![0u8; 0],
            redeemer: None,
        }],
    }
}

/// Build the claim arm witness:
///   Value::Left(Unit)         (Left arm selector)
///   || Value::Bytes(preimage)
///   || Value::Bytes(sig)
fn claim_witness(preimage: &[u8; 32]) -> Vec<u8> {
    let mut w = Value::Left(Box::new(Value::Unit)).serialize();
    w.extend_from_slice(&Value::Bytes(preimage.to_vec()).serialize());
    // Signature: 64 zero bytes are fine — the follower doesn't check
    // signatures, only the witness selector byte and preimage bytes.
    w.extend_from_slice(&Value::Bytes(vec![0u8; 64]).serialize());
    w
}

/// Build a claim_tx that spends `(lock_tx_id, 0)` via the hash arm.
fn fabricate_claim_tx(
    lock_tx_id: Hash256,
    preimage: &[u8; 32],
    pay_to_script: Vec<u8>,
    amount: u64,
) -> Transaction {
    Transaction {
        inputs: vec![TxInput {
            prev_tx_id: lock_tx_id,
            output_index: 0,
        }],
        outputs: vec![TxOutput {
            value: amount,
            script: pay_to_script,
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: claim_witness(preimage),
            redeemer: None,
        }],
    }
}

async fn mount_tip(mock: &MockServer, height: u64, block_id_hex: &str) {
    Mock::given(method("POST"))
        .and(body_partial_json(json!({ "method": "get_block_height" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result":  { "height": height, "block_id": block_id_hex },
            "id": 1
        })))
        .mount(mock)
        .await;
}

async fn mount_block(mock: &MockServer, height: u64, block_id_hex: &str, tx_ids: Vec<&str>) {
    let tx_ids: Vec<serde_json::Value> = tx_ids
        .iter()
        .map(|s| serde_json::Value::String((*s).to_string()))
        .collect();
    Mock::given(method("POST"))
        .and(body_partial_json(
            json!({ "method": "get_block", "params": { "height": height } }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result": {
                "hash": block_id_hex,
                "height": height,
                "timestamp": 1_700_000_000u64 + height,
                "tx_count": tx_ids.len(),
                "transactions": tx_ids,
                "prev_block_id": "00".repeat(32),
                "difficulty_target": "ff".repeat(32),
                "nonce": 0u64,
                "state_root": "00".repeat(32),
                "tx_root": "00".repeat(32),
            },
            "id": 1
        })))
        .mount(mock)
        .await;
}

async fn mount_tx(mock: &MockServer, tx_id_hex: &str, tx_hex: &str, block_height: u64, block_id_hex: &str) {
    Mock::given(method("POST"))
        .and(body_partial_json(json!({
            "method": "get_transaction",
            "params": { "hash": tx_id_hex }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result": {
                "tx_id": tx_id_hex,
                "tx_hex": tx_hex,
                "in_mempool": false,
                "block_hash": block_id_hex,
                "block_height": block_height,
            },
            "id": 1
        })))
        .mount(mock)
        .await;
}

// ---------------------------------------------------------------------------
// End-to-end follower test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn follower_indexes_lock_then_classifies_claim() {
    let mock = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();

    // ---- 1. Build a wallet + extract sender/receiver pubkeys --------
    let store = HdSeedStore::open_or_init_fresh(dir.path(), b"test-passphrase").unwrap();
    let derived_sender = store.create(None).unwrap();
    let derived_receiver = store.create(None).unwrap();
    let signer_sender = store.load_by_address(&derived_sender.address).unwrap();
    let signer_receiver = store.load_by_address(&derived_receiver.address).unwrap();
    let sender_pubkey = signer_sender.pubkey();
    let receiver_pubkey = signer_receiver.pubkey();

    // ---- 2. Build HTLC params + script ------------------------------
    let preimage = [0x42u8; 32];
    // hash_lock = sha256(preimage) — the follower itself doesn't
    // re-verify this (no script eval at index time), but let's keep
    // the values self-consistent so the integration story makes sense.
    let hash_lock = {
        let mut h = sha2::Sha256::new();
        h.update(preimage);
        Hash256(h.finalize().into())
    };
    let timeout = 1_000_000u64;
    let program = htlc(&sender_pubkey, &receiver_pubkey, &hash_lock, timeout);
    let htlc_script = serialize_program(&program);

    // ---- 3. Fabricate lock_tx and claim_tx --------------------------
    let lock_tx = fabricate_lock_tx(htlc_script, 100_000);
    let lock_tx_id = lock_tx.tx_id().unwrap();
    let lock_tx_id_hex = hex::encode(lock_tx_id.as_bytes());
    let lock_tx_hex = hex::encode(lock_tx.serialize().unwrap());

    let claim_tx = fabricate_claim_tx(lock_tx_id, &preimage, vec![0u8; 32], 99_000);
    let claim_tx_id = claim_tx.tx_id().unwrap();
    let claim_tx_id_hex = hex::encode(claim_tx_id.as_bytes());
    let claim_tx_hex = hex::encode(claim_tx.serialize().unwrap());

    // ---- 4. Mount the synthetic chain on wiremock -------------------
    let b1_id_hex = "01".repeat(32);
    let b2_id_hex = "02".repeat(32);

    // Phase A: only block 1 (lock) is on chain.
    mount_tip(&mock, 1, &b1_id_hex).await;
    mount_block(&mock, 0, &"00".repeat(32), vec![]).await;
    mount_block(&mock, 1, &b1_id_hex, vec![&lock_tx_id_hex]).await;
    mount_tx(&mock, &lock_tx_id_hex, &lock_tx_hex, 1, &b1_id_hex).await;

    // ---- 5. Construct follower and drive one tick -------------------
    let store: Arc<dyn WalletStore> = Arc::new(store);
    let node = Arc::new(
        ExferNode::with_retry_policy(mock.uri(), Duration::from_secs(5), RetryPolicy::none())
            .unwrap(),
    );
    let index = Arc::new(Index::open(dir.path()).unwrap());
    let (follower, _tip_rx) = Follower::new(
        store.clone(),
        node.clone(),
        index.clone(),
        FollowerConfig {
            poll_interval: Duration::from_millis(1),
            disabled: false,
        },
    );

    // Refresh ownership cache and run the tick manually (no spawn —
    // we want sync control over advancement).
    follower.refresh_owned().await.unwrap();
    follower.tick().await.unwrap();

    // ---- 6. Assert index contains a Locked record ------------------
    let rec = index
        .get_htlc(lock_tx_id.as_bytes().try_into().unwrap(), 0)
        .unwrap()
        .expect("htlc must be indexed after lock");
    assert_eq!(rec.state, HtlcState::Locked, "fresh lock should be Locked");
    assert_eq!(rec.role, HtlcRole::Both); // both keys belong to us
    assert_eq!(rec.amount, 100_000);
    assert_eq!(rec.lock_block_height, Some(1));
    assert_eq!(rec.params.sender, sender_pubkey);
    assert_eq!(rec.params.receiver, receiver_pubkey);
    assert_eq!(rec.params.hash_lock, hash_lock.0);
    assert_eq!(rec.params.timeout_height, timeout);
    assert!(rec.claim.is_none());
    assert!(rec.reclaim.is_none());

    // ---- 7. Phase B: append block 2 (claim) and re-tick -------------
    let mock2 = MockServer::start().await;
    mount_tip(&mock2, 2, &b2_id_hex).await;
    mount_block(&mock2, 0, &"00".repeat(32), vec![]).await;
    mount_block(&mock2, 1, &b1_id_hex, vec![&lock_tx_id_hex]).await;
    mount_block(&mock2, 2, &b2_id_hex, vec![&claim_tx_id_hex]).await;
    mount_tx(&mock2, &lock_tx_id_hex, &lock_tx_hex, 1, &b1_id_hex).await;
    mount_tx(&mock2, &claim_tx_id_hex, &claim_tx_hex, 2, &b2_id_hex).await;

    let node2 = Arc::new(
        ExferNode::with_retry_policy(mock2.uri(), Duration::from_secs(5), RetryPolicy::none())
            .unwrap(),
    );
    let (follower2, _) = Follower::new(
        store.clone(),
        node2.clone(),
        index.clone(),
        FollowerConfig {
            poll_interval: Duration::from_millis(1),
            disabled: false,
        },
    );
    follower2.refresh_owned().await.unwrap();
    follower2.tick().await.unwrap();

    // ---- 8. Assert record transitioned to Claimed -------------------
    let rec2 = index
        .get_htlc(lock_tx_id.as_bytes().try_into().unwrap(), 0)
        .unwrap()
        .expect("htlc record must still exist after claim");
    assert_eq!(
        rec2.state,
        HtlcState::Claimed,
        "after the claim tx is indexed the state must advance"
    );
    let claim = rec2.claim.expect("claim detail must be populated");
    assert_eq!(claim.preimage, preimage, "extracted preimage must match");
    assert_eq!(claim.block_height, 2);
    assert_eq!(claim.tx_id, *claim_tx_id.as_bytes());
    assert_eq!(claim.input_index, 0);
}

#[tokio::test]
async fn follower_ignores_htlcs_paying_someone_else() {
    let mock = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();

    // Our wallet owns nothing relevant — generate addresses but build
    // the HTLC with foreign pubkeys.
    let store = HdSeedStore::open_or_init_fresh(dir.path(), b"test-passphrase").unwrap();
    let _ = store.create(None).unwrap();

    let foreign_sender = [0x77u8; 32];
    let foreign_receiver = [0x88u8; 32];
    let hash_lock = Hash256([0x99u8; 32]);
    let program = htlc(&foreign_sender, &foreign_receiver, &hash_lock, 500);
    let script = serialize_program(&program);
    let tx = fabricate_lock_tx(script, 1_000);
    let tx_id_hex = hex::encode(tx.tx_id().unwrap().as_bytes());
    let tx_hex = hex::encode(tx.serialize().unwrap());

    let b1_id_hex = "ab".repeat(32);
    mount_tip(&mock, 1, &b1_id_hex).await;
    mount_block(&mock, 0, &"00".repeat(32), vec![]).await;
    mount_block(&mock, 1, &b1_id_hex, vec![&tx_id_hex]).await;
    mount_tx(&mock, &tx_id_hex, &tx_hex, 1, &b1_id_hex).await;

    let store: Arc<dyn WalletStore> = Arc::new(store);
    let node = Arc::new(
        ExferNode::with_retry_policy(mock.uri(), Duration::from_secs(5), RetryPolicy::none())
            .unwrap(),
    );
    let index = Arc::new(Index::open(dir.path()).unwrap());
    let (follower, _) = Follower::new(
        store.clone(),
        node.clone(),
        index.clone(),
        FollowerConfig::default(),
    );
    follower.refresh_owned().await.unwrap();
    follower.tick().await.unwrap();

    // No record was inserted — the HTLC doesn't touch any owned key.
    assert_eq!(index.count().unwrap(), 0);
}

#[tokio::test]
async fn follower_skips_non_htlc_outputs() {
    // A vanilla P2PKH output must not trigger any insert.
    let mock = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let store = HdSeedStore::open_or_init_fresh(dir.path(), b"test-passphrase").unwrap();
    let _ = store.create(None).unwrap();

    // Plain 32-byte script (the Phase-1 P2PKH locking script).
    let tx = fabricate_lock_tx(vec![0xAAu8; 32], 5_000);
    let tx_id_hex = hex::encode(tx.tx_id().unwrap().as_bytes());
    let tx_hex = hex::encode(tx.serialize().unwrap());

    let b1_id_hex = "cd".repeat(32);
    mount_tip(&mock, 1, &b1_id_hex).await;
    mount_block(&mock, 0, &"00".repeat(32), vec![]).await;
    mount_block(&mock, 1, &b1_id_hex, vec![&tx_id_hex]).await;
    mount_tx(&mock, &tx_id_hex, &tx_hex, 1, &b1_id_hex).await;

    let store: Arc<dyn WalletStore> = Arc::new(store);
    let node = Arc::new(
        ExferNode::with_retry_policy(mock.uri(), Duration::from_secs(5), RetryPolicy::none())
            .unwrap(),
    );
    let index = Arc::new(Index::open(dir.path()).unwrap());
    let (follower, _) = Follower::new(
        store.clone(),
        node.clone(),
        index.clone(),
        FollowerConfig::default(),
    );
    follower.refresh_owned().await.unwrap();
    follower.tick().await.unwrap();

    assert_eq!(index.count().unwrap(), 0);
}

#[tokio::test]
async fn follower_advances_meta_to_tip() {
    let mock = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let store = HdSeedStore::open_or_init_fresh(dir.path(), b"test-passphrase").unwrap();
    let _ = store.create(None).unwrap();

    // Five empty blocks.
    let block_ids: Vec<String> = (0..=4).map(|i| format!("{:02x}", i).repeat(32)).collect();
    mount_tip(&mock, 4, &block_ids[4]).await;
    for h in 0..=4 {
        mount_block(&mock, h, &block_ids[h as usize], vec![]).await;
    }

    let store: Arc<dyn WalletStore> = Arc::new(store);
    let node = Arc::new(
        ExferNode::with_retry_policy(mock.uri(), Duration::from_secs(5), RetryPolicy::none())
            .unwrap(),
    );
    let index = Arc::new(Index::open(dir.path()).unwrap());
    let (follower, mut tip_rx) = Follower::new(
        store.clone(),
        node.clone(),
        index.clone(),
        FollowerConfig::default(),
    );
    follower.refresh_owned().await.unwrap();
    follower.tick().await.unwrap();

    let meta = index.follower_meta().unwrap();
    assert_eq!(meta.last_indexed_height, 4);
    assert_eq!(
        hex::encode(meta.last_indexed_block_id),
        block_ids[4]
    );
    assert!(meta.full_scan_complete, "after reaching tip the flag must be set");

    // The watch channel must have published the new tip.
    tip_rx.changed().await.ok();
    assert!(*tip_rx.borrow() >= 4);
}
