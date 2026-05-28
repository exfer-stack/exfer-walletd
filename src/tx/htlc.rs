//! HTLC lifecycle: `lock` / `claim` / `reclaim`.
//!
//! Mirrors the `exfer script htlc-*` CLI commands, but constructs and
//! signs in-process and exposes the lifecycle over walletd's JSON-RPC so
//! a remote / non-Rust agent can drive HTLCs without re-implementing
//! Exfer Script + sighash. The node stays a pure query+broadcast layer:
//! this module only calls `get_address_utxos`, `get_transaction`,
//! `get_block_height`, and `send_raw_transaction`.
//!
//! - **lock**: fund from the wallet and create an output locked by the
//!   HTLC covenant (`exfer::covenants::htlc`). Reuses the shared
//!   [`crate::tx::build_sign_broadcast`] coin-selection/fee/signing path.
//! - **claim**: spend the HTLC output via the hashlock arm — witness is
//!   `Left(Unit) ‖ preimage ‖ sig`. The on-chain output is authenticated
//!   against a locally reconstructed script so a malicious node can't
//!   feed us a phantom output to "claim".
//! - **reclaim**: spend via the timeout arm — witness is `Right(Unit) ‖
//!   sig`; only valid once `block_height > timeout`.

use ed25519_dalek::Signer as _;
use exfer::consensus::cost::min_fee_with_script_cost;
use exfer::covenants::htlc::htlc as build_htlc_program;
use exfer::script::serialize::serialize_program;
use exfer::script::value::Value;
use exfer::script::{compute_cost, ListSizes, Program};
use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};
use exfer::types::{Hash256, DUST_THRESHOLD};
use exfer::wallet::auth::authenticate_tx_hex;
use serde::Serialize;

use crate::error::{Error, Result};
use crate::inflight::InFlightUtxos;
use crate::store::Signer;
use crate::tx::{build_only, build_sign_broadcast, CoreOutput, FeeChoice};
use crate::upstream::ExferNode;

#[derive(Debug, Clone, Serialize)]
pub struct HtlcLockReceipt {
    pub tx_id: String,
    /// The HTLC-locked output is always at index 0 (change, if any, is 1).
    pub htlc_output_index: u32,
    pub amount: u64,
    pub hash_lock: String,
    pub timeout: u64,
    pub receiver: String,
    pub size: u64,
    pub fee: u64,
    pub fee_rate: u64,
    pub built_at_height: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change: Option<u64>,
}

/// Result of [`simulate_htlc_lock`] — exactly what [`htlc_lock`] would
/// build, minus broadcast. `total_in` is included so an agent can
/// double-check its cost ceiling without re-summing the inputs.
#[derive(Debug, Clone, Serialize)]
pub struct SimulateHtlcLockReceipt {
    pub size: u64,
    pub fee: u64,
    pub fee_rate: u64,
    pub htlc_output_index: u32,
    pub amount: u64,
    pub hash_lock: String,
    pub timeout: u64,
    pub receiver: String,
    pub total_in: u64,
    pub change: u64,
    pub built_at_height: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct HtlcSpendReceipt {
    pub tx_id: String,
    /// `"claim"` or `"reclaim"`.
    pub kind: &'static str,
    /// Amount paid to the signer's own address (`htlc_value − fee`).
    pub value: u64,
    pub fee: u64,
    pub lock_tx_id: String,
    pub output_index: u32,
    pub size: u64,
}

/// Lock `amount` behind an HTLC payable to `receiver_pubkey` against
/// `hash_lock`, refundable to the signer after `timeout`.
#[allow(clippy::too_many_arguments)]
pub async fn htlc_lock(
    signer: &Signer,
    receiver_pubkey: [u8; 32],
    hash_lock: Hash256,
    timeout: u64,
    amount: u64,
    fee_choice: FeeChoice,
    max_fee: u64,
    node: &ExferNode,
    inflight: &InFlightUtxos,
) -> Result<HtlcLockReceipt> {
    let program = build_htlc_program(&signer.pubkey(), &receiver_pubkey, &hash_lock, timeout);
    let script = serialize_program(&program);
    let outputs = vec![CoreOutput {
        script,
        value: amount,
    }];
    let core = build_sign_broadcast(signer, outputs, fee_choice, max_fee, node, inflight).await?;

    Ok(HtlcLockReceipt {
        tx_id: core.tx_id_hex,
        htlc_output_index: 0,
        amount,
        hash_lock: hex::encode(hash_lock.as_bytes()),
        timeout,
        receiver: hex::encode(receiver_pubkey),
        size: core.size,
        fee: core.effective_fee,
        fee_rate: core.fee_rate,
        built_at_height: core.built_at_height,
        change: if core.has_change {
            Some(core.change_value)
        } else {
            None
        },
    })
}

/// Dry-run sibling of [`htlc_lock`]. Builds and signs the lock
/// transaction the same way [`htlc_lock`] does, then discards the tx
/// and the inflight reservation. Returns a
/// [`SimulateHtlcLockReceipt`] suitable for cost-ceiling commitments.
#[allow(clippy::too_many_arguments)]
pub async fn simulate_htlc_lock(
    signer: &Signer,
    receiver_pubkey: [u8; 32],
    hash_lock: Hash256,
    timeout: u64,
    amount: u64,
    fee_choice: FeeChoice,
    max_fee: u64,
    node: &ExferNode,
    inflight: &InFlightUtxos,
) -> Result<SimulateHtlcLockReceipt> {
    let program = build_htlc_program(&signer.pubkey(), &receiver_pubkey, &hash_lock, timeout);
    let script = serialize_program(&program);
    let outputs = vec![CoreOutput {
        script,
        value: amount,
    }];
    let (built, _guard) = build_only(signer, outputs, fee_choice, max_fee, node, inflight).await?;
    let total_in: u64 = built.selected.iter().map(|(_, v)| v).sum();
    Ok(SimulateHtlcLockReceipt {
        size: built.size,
        fee: built.effective_fee,
        fee_rate: built.fee_rate,
        htlc_output_index: 0,
        amount,
        hash_lock: hex::encode(hash_lock.as_bytes()),
        timeout,
        receiver: hex::encode(receiver_pubkey),
        total_in,
        change: if built.has_change {
            built.change_value
        } else {
            0
        },
        built_at_height: built.built_at_height,
    })
}

/// Claim an HTLC output by revealing `preimage` (hashlock arm). The
/// signer is the receiver. `sender_pubkey` + `timeout` are needed to
/// reconstruct (and authenticate) the locked script.
#[allow(clippy::too_many_arguments)]
pub async fn htlc_claim(
    signer: &Signer,
    lock_tx_id: Hash256,
    output_index: u32,
    preimage: Vec<u8>,
    sender_pubkey: [u8; 32],
    timeout: u64,
    fee: Option<u64>,
    node: &ExferNode,
) -> Result<HtlcSpendReceipt> {
    let hash_lock = Hash256::sha256(&preimage);
    // The claimer is the receiver in the covenant.
    let program = build_htlc_program(&sender_pubkey, &signer.pubkey(), &hash_lock, timeout);

    let preimage_for_witness = preimage;
    spend_htlc(
        signer,
        &program,
        lock_tx_id,
        output_index,
        fee,
        node,
        "claim",
        move |sig| {
            let mut w = Value::Left(Box::new(Value::Unit)).serialize();
            w.extend_from_slice(&Value::Bytes(preimage_for_witness.clone()).serialize());
            w.extend_from_slice(&Value::Bytes(sig.to_vec()).serialize());
            w
        },
    )
    .await
}

/// Reclaim an HTLC output after `timeout` (refund arm). The signer is the
/// original sender. `receiver_pubkey` + `hash_lock` + `timeout`
/// reconstruct (and authenticate) the locked script.
#[allow(clippy::too_many_arguments)]
pub async fn htlc_reclaim(
    signer: &Signer,
    lock_tx_id: Hash256,
    output_index: u32,
    receiver_pubkey: [u8; 32],
    hash_lock: Hash256,
    timeout: u64,
    fee: Option<u64>,
    node: &ExferNode,
) -> Result<HtlcSpendReceipt> {
    // The reclaimer is the sender in the covenant.
    let program = build_htlc_program(&signer.pubkey(), &receiver_pubkey, &hash_lock, timeout);

    // The refund arm checks `block_height > timeout`. Reject early with a
    // clear error rather than broadcasting a tx the node will reject.
    let tip = node.get_block_height().await?;
    if tip.height <= timeout {
        return Err(Error::TimeoutNotReached {
            current_height: tip.height,
            timeout,
        });
    }

    spend_htlc(
        signer,
        &program,
        lock_tx_id,
        output_index,
        fee,
        node,
        "reclaim",
        move |sig| {
            let mut w = Value::Right(Box::new(Value::Unit)).serialize();
            w.extend_from_slice(&Value::Bytes(sig.to_vec()).serialize());
            w
        },
    )
    .await
}

/// Shared single-input spend of an HTLC output. Fetches + authenticates
/// the locked output against `expected_script`, sizes the fee from the
/// consensus minimum, signs, builds the witness via `build_witness(sig)`,
/// and broadcasts. `build_witness` is called twice (a zero-sig probe to
/// size the witness, then the real signature) — the witness is excluded
/// from `sig_message`, so its content never affects the signature.
#[allow(clippy::too_many_arguments)]
async fn spend_htlc(
    signer: &Signer,
    program: &Program,
    lock_tx_id: Hash256,
    output_index: u32,
    fee: Option<u64>,
    node: &ExferNode,
    kind: &'static str,
    build_witness: impl Fn(&[u8]) -> Vec<u8>,
) -> Result<HtlcSpendReceipt> {
    let expected_script = serialize_program(program);

    // ---- 1. fetch + authenticate the locked output ------------------
    let lock_tx_id_hex = hex::encode(lock_tx_id.as_bytes());
    let tx_status = node.get_transaction(&lock_tx_id_hex).await?;
    let raw = hex::decode(&tx_status.tx_hex).map_err(|e| Error::BadHex(e.to_string()))?;
    let (htlc_value, _script) =
        authenticate_tx_hex(&raw, lock_tx_id, output_index, Some(&expected_script))
            .map_err(|e| Error::HtlcOutputAuth(format!("{e:?}")))?;

    // ---- 2. size the witness (zero-sig probe) -----------------------
    let witness_len = build_witness(&[0u8; 64]).len();
    let to_script = signer.address().as_bytes().to_vec();
    let mk_tx = |value: u64| Transaction {
        inputs: vec![TxInput {
            prev_tx_id: lock_tx_id,
            output_index,
        }],
        outputs: vec![TxOutput {
            value,
            script: to_script.clone(),
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![0u8; witness_len],
            redeemer: None,
        }],
    };

    // ---- 3. settle the fee against the consensus minimum ------------
    // A claim/reclaim spends a *script* (phase-2) input, so the node prices
    // it with `min_fee_with_script_cost` — the spent HTLC script's eval cost
    // plus a per-script validation cost — NOT the phase-1 placeholder that
    // bare `min_fee(tx)` assumes. Replicate that from the reconstructed
    // program, or the node rejects with FeeBelowMinimum. `cells + steps`
    // over-approximates the eval cost the node actually charges, and the
    // +25% margin absorbs any fee-model drift between walletd's pinned
    // exfer crate and the live node's release.
    let sc = compute_cost(
        program,
        &ListSizes {
            input_count: 1,
            output_count: 1,
        },
    )
    .map_err(|e| Error::TxBuild(format!("script cost: {e:?}")))?;
    let script_eval_cost = sc.cells as u128 + sc.steps as u128;
    let script_validation_cost = ((expected_script.len() as u64).div_ceil(64) * 10) as u128;
    let template = mk_tx(htlc_value);
    let base_min = min_fee_with_script_cost(&template, script_eval_cost, script_validation_cost)
        .ok_or_else(|| Error::TxBuild("min_fee computation overflowed".into()))?;
    let min = base_min + base_min / 4 + 1;
    let fee = match fee {
        Some(f) if f < min => {
            return Err(Error::TxBuild(format!(
                "fee {f} below required minimum {min}"
            )));
        }
        Some(f) => f,
        None => min,
    };
    let value = htlc_value
        .checked_sub(fee)
        .ok_or_else(|| Error::TxBuild(format!("fee {fee} exceeds htlc value {htlc_value}")))?;
    if value < DUST_THRESHOLD {
        return Err(Error::DustOutput {
            amount: value,
            dust_threshold: DUST_THRESHOLD,
        });
    }

    // ---- 4. build + sign --------------------------------------------
    let mut tx = mk_tx(value);
    let sig_msg = tx
        .sig_message()
        .map_err(|e| Error::TxSerialize(format!("sig_message: {e:?}")))?;
    let sig = signer.signing_key().sign(&sig_msg);
    tx.witnesses[0].witness = build_witness(&sig.to_bytes());

    let tx_id = tx
        .tx_id()
        .map_err(|e| Error::TxSerialize(format!("tx_id: {e:?}")))?;
    let serialized = tx
        .serialize()
        .map_err(|e| Error::TxSerialize(format!("{e:?}")))?;

    // ---- 5. broadcast -----------------------------------------------
    let tx_hex = hex::encode(&serialized);
    let sent = node.send_raw_transaction(&tx_hex).await?;
    let our_tx_id_hex = hex::encode(tx_id.as_bytes());
    if sent.tx_id != our_tx_id_hex {
        return Err(Error::UpstreamUnexpected(format!(
            "node returned tx_id {} but we computed {our_tx_id_hex}",
            sent.tx_id
        )));
    }

    Ok(HtlcSpendReceipt {
        tx_id: our_tx_id_hex,
        kind,
        value,
        fee,
        lock_tx_id: lock_tx_id_hex,
        output_index,
        size: serialized.len() as u64,
    })
}
