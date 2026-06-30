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
use crate::tx::{broadcast_built, build_only, CoreOutput, FeeChoice};
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
///
/// When `lock_watch` is `Some`, the just-broadcast lock is registered for
/// the confirmation watchdog (rebroadcast on mempool eviction). The
/// registration is best-effort and happens after a successful broadcast
/// but before `guard.commit()` — it never alters the lock result.
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
    lock_watch: Option<&crate::lock_watch::LockWatch>,
) -> Result<HtlcLockReceipt> {
    let program = build_htlc_program(&signer.pubkey(), &receiver_pubkey, &hash_lock, timeout);
    let script = serialize_program(&program);
    let outputs = vec![CoreOutput {
        script,
        value: amount,
    }];

    // build_only + broadcast_built (instead of build_sign_broadcast) so we
    // retain the BuiltTx and can register it with the watchdog after the
    // broadcast succeeds and before committing the inflight reservation.
    let (built, guard) =
        build_only(signer, outputs, None, fee_choice, max_fee, node, inflight).await?;
    broadcast_built(node, &built).await?;

    // Best-effort watchdog registration. Must never fail the lock (it has
    // already broadcast): serialization is infallible in practice here, but
    // we degrade to "not watched" rather than propagate.
    if let Some(w) = lock_watch {
        if let Ok(bytes) = built.tx.serialize() {
            w.register(
                hex::encode(built.tx_id.as_bytes()),
                hex::encode(bytes),
                built.selected.iter().map(|(op, _)| *op).collect(),
            );
        }
    }

    guard.commit();

    Ok(HtlcLockReceipt {
        tx_id: hex::encode(built.tx_id.as_bytes()),
        htlc_output_index: 0,
        amount,
        hash_lock: hex::encode(hash_lock.as_bytes()),
        timeout,
        receiver: hex::encode(receiver_pubkey),
        size: built.size,
        fee: built.effective_fee,
        fee_rate: built.fee_rate,
        built_at_height: built.built_at_height,
        change: if built.has_change {
            Some(built.change_value)
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
    let (built, _guard) =
        build_only(signer, outputs, None, fee_choice, max_fee, node, inflight).await?;
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

/// Result of [`build_presigned_claim`]: a fully receiver-signed, NOT-broadcast
/// HTLC claim whose preimage is a 32-byte placeholder.
pub struct PresignedClaim {
    /// Hex of the serialized tx, with 32 placeholder bytes where the preimage
    /// belongs. Whoever holds the real secret overwrites those bytes and broadcasts.
    pub tx_hex: String,
    /// Byte offset in the serialized tx where the 32-byte preimage starts.
    pub preimage_offset: usize,
    /// EXFER the claimer receives (HTLC value minus fee).
    pub value: u64,
}

/// Build — but do NOT broadcast — a receiver-signed claim of an HTLC output,
/// leaving the preimage as a 32-byte zero placeholder.
///
/// The signature covers only the tx body (header + inputs + outputs; witnesses
/// are excluded from `sig_message`) and the `tx_id` likewise excludes the
/// witness, so a third party who knows the real preimage can overwrite the 32
/// placeholder bytes at `preimage_offset` and broadcast — the signature and the
/// tx_id stay valid.
///
/// This is the v2 BUY primitive: the user (receiver of the pool's EXFER lock)
/// pre-signs while online and hands this to the pool; the pool — which generated
/// the secret — splices it in and relays the EXFER, so the user never has to
/// come back online to claim.
///
/// Deliberately mirrors [`spend_htlc`]'s fetch/fee/build/sign steps (kept
/// SEPARATE so the live claim/reclaim path is untouched); only the broadcast is
/// replaced by returning the serialized bytes + the offset.
#[allow(clippy::too_many_arguments)]
pub async fn build_presigned_claim(
    signer: &Signer,
    lock_tx_id: Hash256,
    output_index: u32,
    sender_pubkey: [u8; 32],
    hash_lock: Hash256,
    timeout: u64,
    fee: Option<u64>,
    node: &ExferNode,
) -> Result<PresignedClaim> {
    // The claimer (signer) is the receiver in the covenant; sender = the pool.
    let program = build_htlc_program(&sender_pubkey, &signer.pubkey(), &hash_lock, timeout);
    let expected_script = serialize_program(&program);

    // 1. fetch + authenticate the pool's locked output.
    let lock_tx_id_hex = hex::encode(lock_tx_id.as_bytes());
    let tx_status = node.get_transaction(&lock_tx_id_hex).await?;
    let raw = hex::decode(&tx_status.tx_hex).map_err(|e| Error::BadHex(e.to_string()))?;
    let (htlc_value, _script) =
        authenticate_tx_hex(&raw, lock_tx_id, output_index, Some(&expected_script))
            .map_err(|e| Error::HtlcOutputAuth(format!("{e:?}")))?;

    // Witness = Left(Unit) ‖ Bytes(placeholder32) ‖ Bytes(sig). The placeholder
    // MUST be exactly 32 bytes so the tx size, fee, and byte layout match the
    // final (real-preimage) tx — only the 32 bytes' VALUE changes at splice time.
    const PLACEHOLDER: [u8; 32] = [0u8; 32];
    let build_witness = |sig: &[u8]| {
        let mut w = Value::Left(Box::new(Value::Unit)).serialize();
        w.extend_from_slice(&Value::Bytes(PLACEHOLDER.to_vec()).serialize());
        w.extend_from_slice(&Value::Bytes(sig.to_vec()).serialize());
        w
    };

    // 2. size the witness (zero-sig probe).
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

    // 3. settle the fee against the consensus minimum (script-input cost).
    let sc = compute_cost(
        &program,
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

    // 4. build + sign (sig over the body; witness excluded).
    let mut tx = mk_tx(value);
    let sig_msg = tx
        .sig_message()
        .map_err(|e| Error::TxSerialize(format!("sig_message: {e:?}")))?;
    let sig = signer.signing_key().sign(&sig_msg);
    tx.witnesses[0].witness = build_witness(&sig.to_bytes());

    // 5. serialize + locate the placeholder. The witness blob is the tail of the
    //    tx; the preimage is its 2nd item, at offset 7 within the blob
    //    (Left(Unit)=2B, Bytes-tag=1B, len-u32-LE=4B). Find the blob's absolute
    //    start (it contains the unique sig, so it appears exactly once), then +7.
    let serialized = tx
        .serialize()
        .map_err(|e| Error::TxSerialize(format!("{e:?}")))?;
    let witness_blob = &tx.witnesses[0].witness;
    let blob_start = serialized
        .windows(witness_blob.len())
        .position(|w| w == witness_blob.as_slice())
        .ok_or_else(|| Error::TxSerialize("witness blob not found in serialized tx".into()))?;
    let preimage_offset = blob_start + 7;
    if serialized.get(preimage_offset..preimage_offset + 32) != Some(&PLACEHOLDER[..]) {
        return Err(Error::TxSerialize(
            "preimage placeholder not at the computed offset".into(),
        ));
    }

    Ok(PresignedClaim {
        tx_hex: hex::encode(&serialized),
        preimage_offset,
        value,
    })
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
