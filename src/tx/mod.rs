//! Transaction build/sign/broadcast engine.
//!
//! Builds, signs, and broadcasts Exfer transactions. We bypass
//! `exfer::wallet::wallet::Wallet::build_transaction` (which is hardcoded
//! to single-recipient + single-change) and construct the [`Transaction`]
//! ourselves so we can:
//!
//! - Pack up to [`crate::api::MAX_OUTPUTS`] recipients in one tx
//! - Lock outputs behind arbitrary scripts (p2pkh transfer, or an HTLC
//!   covenant — see [`htlc`])
//! - Compute the fee from a `fee_rate` (exfers per cost-unit) using
//!   the same `consensus::cost` model the chain enforces
//! - Enforce a `max_fee` cap before broadcast (defensive against
//!   off-by-zero mistakes in the request)
//! - Return a receipt that names every input consumed and every output
//!   created (including the auto-change), so callers reconcile without
//!   a follow-up `get_transaction(tx_id)`
//!
//! Flow ([`build_sign_broadcast`]):
//!
//! ```text
//!   list UTXOs ──► estimate fee for (1 input, N outputs + 1 change)
//!              ──► greedy-pick covering total_amount + estimate (skip in-flight)
//!              ──► build tx; compute actual fee; re-select if estimate was low
//!              ──► sign locally (ed25519 over sig_message)
//!              ──► send_raw_transaction
//!              ──► self-check: node tx_id == computed tx_id
//! ```
//!
//! Input values are taken directly from `get_address_utxos`. A dishonest
//! upstream that lies about UTXO values can only cause the resulting tx
//! to fail consensus on broadcast — funds aren't at risk because the
//! signature is over what we built.

pub mod decode;
pub mod htlc;

use ed25519_dalek::Signer as _;
use exfer::consensus::cost::{min_fee, tx_cost};
use exfer::types::transaction::{OutPoint, Transaction, TxInput, TxOutput, TxWitness};
use exfer::types::{Hash256, DUST_THRESHOLD, MIN_FEE_DIVISOR};
use serde::Serialize;

use crate::error::{Error, Result};
use crate::inflight::{ClaimGuard, InFlightUtxos};
use crate::store::Signer;
use crate::upstream::ExferNode;

/// Upper bound on fee-estimation iterations. Each iteration may add a
/// few inputs, increasing tx_cost and thus min_fee. Two iterations
/// terminate every realistic case; three is a safety net.
const FEE_ESTIMATE_MAX_ITERS: usize = 3;

/// How the caller wants the fee computed. Exactly one is in effect per
/// transfer; see `api::TransferParams` for the user-facing surface.
#[derive(Debug, Clone, Copy)]
pub enum FeeChoice {
    /// Pay exactly this many exfers (subject to consensus min and
    /// `max_fee` cap).
    Absolute(u64),
    /// Pay `ceil(tx_cost × rate / MIN_FEE_DIVISOR)` exfers (subject to
    /// consensus min and `max_fee` cap). `rate = 1` reproduces the
    /// consensus floor.
    Rate(u64),
}

/// A single non-change output: an arbitrary locking script + value.
/// p2pkh transfers pass the 32-byte recipient address as the script;
/// `htlc_lock` passes a serialized HTLC program.
#[derive(Debug, Clone)]
pub(crate) struct CoreOutput {
    pub script: Vec<u8>,
    pub value: u64,
}

/// Outcome of [`build_sign_broadcast`] — enough for any caller to build
/// its own receipt shape without re-deriving anything.
pub(crate) struct CoreReceipt {
    pub tx_id_hex: String,
    pub size: u64,
    pub effective_fee: u64,
    pub fee_rate: u64,
    pub built_at_height: u64,
    /// (outpoint, value) for every input consumed.
    pub selected: Vec<(OutPoint, u64)>,
    pub change_value: u64,
    pub has_change: bool,
}

/// Outcome of [`build_only`] — a fully assembled, signed, but
/// **un-broadcast** transaction together with the inflight reservation
/// guard that holds its inputs.
///
/// Callers chain into [`broadcast_built`] (then `guard.commit()`) to send
/// the tx, or drop both fields to discard the build (releasing the
/// inflight claim) — the latter is what `simulate_*` methods do.
///
/// `tx_id`, `size`, and `effective_fee` are already correct at this
/// point: tx_id is witness-independent and the signed witness blob is
/// byte-for-byte the same length (96 bytes = 32-byte pubkey + 64-byte
/// signature) as the placeholder used during fee estimation.
pub(crate) struct BuiltTx {
    /// The fully signed transaction, ready to serialize and broadcast.
    pub tx: Transaction,
    /// Witness-independent tx_id computed from `tx_header || tx_body`.
    pub tx_id: Hash256,
    /// Wire size in bytes (= serialized length).
    pub size: u64,
    pub effective_fee: u64,
    pub fee_rate: u64,
    pub built_at_height: u64,
    pub selected: Vec<(OutPoint, u64)>,
    pub change_value: u64,
    pub has_change: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransferReceipt {
    pub tx_id: String,
    pub size: u64,
    pub fee: u64,
    /// Effective fee rate: `fee × MIN_FEE_DIVISOR / tx_cost`. Useful
    /// for clients to verify what they actually paid relative to the
    /// floor.
    pub fee_rate: u64,
    pub inputs: Vec<ReceiptInput>,
    pub outputs: Vec<ReceiptOutput>,
    /// Chain tip at the moment we fetched the sender's UTXO set. NOT
    /// the inclusion height — this transfer is freshly broadcast at
    /// this point; check `get_transaction(tx_id)` later for confirmation.
    pub built_at_height: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReceiptInput {
    pub tx_id: String,
    pub output_index: u32,
    pub value: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReceiptOutput {
    pub to: String,
    pub amount: u64,
    pub is_change: bool,
}

/// Result of [`simulate_transfer`] — the same shape as [`TransferReceipt`]
/// minus `tx_id` (nothing was broadcast), plus the helpful aggregates
/// `total_in` / `total_out` so agents can verify their cost ceiling
/// against the simulation result without re-summing.
#[derive(Debug, Clone, Serialize)]
pub struct SimulateTransferReceipt {
    pub size: u64,
    pub fee: u64,
    pub fee_rate: u64,
    pub inputs: Vec<ReceiptInput>,
    pub outputs: Vec<ReceiptOutput>,
    pub total_in: u64,
    pub total_out: u64,
    pub change: u64,
    pub built_at_height: u64,
}

/// Multi-output p2pkh transfer. Thin wrapper over [`build_sign_broadcast`]
/// that maps each recipient address to a 32-byte locking script and
/// assembles a [`TransferReceipt`].
pub async fn transfer(
    signer: &Signer,
    recipients: Vec<(Hash256, u64)>,
    fee_choice: FeeChoice,
    max_fee: u64,
    node: &ExferNode,
    inflight: &InFlightUtxos,
) -> Result<TransferReceipt> {
    if recipients.is_empty() {
        return Err(Error::TxBuild(
            "transfer: recipients must not be empty".into(),
        ));
    }
    let outputs: Vec<CoreOutput> = recipients
        .iter()
        .map(|(addr, value)| CoreOutput {
            script: addr.as_bytes().to_vec(),
            value: *value,
        })
        .collect();

    let core = build_sign_broadcast(signer, outputs, fee_choice, max_fee, node, inflight).await?;

    let mut outputs_receipt: Vec<ReceiptOutput> = recipients
        .iter()
        .map(|(addr, value)| ReceiptOutput {
            to: hex::encode(addr.as_bytes()),
            amount: *value,
            is_change: false,
        })
        .collect();
    if core.has_change {
        outputs_receipt.push(ReceiptOutput {
            to: signer.address_hex(),
            amount: core.change_value,
            is_change: true,
        });
    }

    Ok(TransferReceipt {
        tx_id: core.tx_id_hex,
        size: core.size,
        fee: core.effective_fee,
        fee_rate: core.fee_rate,
        inputs: core
            .selected
            .iter()
            .map(|(op, value)| ReceiptInput {
                tx_id: hex::encode(op.tx_id.as_bytes()),
                output_index: op.output_index,
                value: *value,
            })
            .collect(),
        outputs: outputs_receipt,
        built_at_height: core.built_at_height,
    })
}

/// Dry-run sibling of [`transfer`]. Builds and signs exactly what
/// [`transfer`] would broadcast, then **discards** both the transaction
/// and the inflight reservation. Returns a [`SimulateTransferReceipt`]
/// the caller can use to pre-commit cost ceilings against a real
/// transfer.
///
/// Read scope: this loads the keystore (so it knows the change
/// address) but never sends anything on the wire and never moves
/// funds.
pub async fn simulate_transfer(
    signer: &Signer,
    recipients: Vec<(Hash256, u64)>,
    fee_choice: FeeChoice,
    max_fee: u64,
    node: &ExferNode,
    inflight: &InFlightUtxos,
) -> Result<SimulateTransferReceipt> {
    if recipients.is_empty() {
        return Err(Error::TxBuild(
            "simulate_transfer: recipients must not be empty".into(),
        ));
    }
    let outputs: Vec<CoreOutput> = recipients
        .iter()
        .map(|(addr, value)| CoreOutput {
            script: addr.as_bytes().to_vec(),
            value: *value,
        })
        .collect();

    let (built, _guard) = build_only(signer, outputs, fee_choice, max_fee, node, inflight).await?;
    // Dropping `_guard` releases the inflight UTXO reservation — the
    // simulated build was a snapshot, not a commitment.

    let total_in: u64 = built.selected.iter().map(|(_, v)| v).sum();
    let mut outputs_receipt: Vec<ReceiptOutput> = recipients
        .iter()
        .map(|(addr, value)| ReceiptOutput {
            to: hex::encode(addr.as_bytes()),
            amount: *value,
            is_change: false,
        })
        .collect();
    if built.has_change {
        outputs_receipt.push(ReceiptOutput {
            to: signer.address_hex(),
            amount: built.change_value,
            is_change: true,
        });
    }
    let total_out: u64 = outputs_receipt.iter().map(|o| o.amount).sum();

    Ok(SimulateTransferReceipt {
        size: built.size,
        fee: built.effective_fee,
        fee_rate: built.fee_rate,
        inputs: built
            .selected
            .iter()
            .map(|(op, value)| ReceiptInput {
                tx_id: hex::encode(op.tx_id.as_bytes()),
                output_index: op.output_index,
                value: *value,
            })
            .collect(),
        outputs: outputs_receipt,
        total_in,
        total_out,
        change: if built.has_change {
            built.change_value
        } else {
            0
        },
        built_at_height: built.built_at_height,
    })
}

/// Fund, build, sign, and broadcast a transaction that creates the given
/// `outputs` (arbitrary locking scripts), with auto-change back to the
/// signer. Shared by [`transfer`] and [`htlc::htlc_lock`].
///
/// Composed from [`build_only`] + [`broadcast_built`]; the inflight claim
/// is committed on successful broadcast.
pub(crate) async fn build_sign_broadcast(
    signer: &Signer,
    outputs: Vec<CoreOutput>,
    fee_choice: FeeChoice,
    max_fee: u64,
    node: &ExferNode,
    inflight: &InFlightUtxos,
) -> Result<CoreReceipt> {
    let (built, guard) =
        build_only(signer, outputs, fee_choice, max_fee, node, inflight).await?;
    broadcast_built(node, &built).await?;
    guard.commit();
    Ok(CoreReceipt {
        tx_id_hex: hex::encode(built.tx_id.as_bytes()),
        size: built.size,
        effective_fee: built.effective_fee,
        fee_rate: built.fee_rate,
        built_at_height: built.built_at_height,
        selected: built.selected,
        change_value: built.change_value,
        has_change: built.has_change,
    })
}

/// Build and sign a transaction without broadcasting.
///
/// Returns the assembled [`BuiltTx`] together with the [`ClaimGuard`]
/// holding its inputs in the inflight set. Callers that proceed to
/// broadcast should chain into [`broadcast_built`] and then call
/// `guard.commit()`. Callers that just wanted a dry-run (i.e.
/// `simulate_*`) drop the guard to release the inflight reservation.
///
/// The transaction is signed before this returns so the produced
/// `tx_id`, `size`, and serialised form are exactly what would land
/// on-chain if [`broadcast_built`] were called. (Signing is required to
/// match the existing wire format; the placeholder-witness path is only
/// used internally for fee estimation.)
pub(crate) async fn build_only<'a>(
    signer: &Signer,
    outputs: Vec<CoreOutput>,
    fee_choice: FeeChoice,
    max_fee: u64,
    node: &ExferNode,
    inflight: &'a InFlightUtxos,
) -> Result<(BuiltTx, ClaimGuard<'a>)> {
    // ---- input validation -------------------------------------------
    if outputs.is_empty() {
        return Err(Error::TxBuild("outputs must not be empty".into()));
    }
    for o in &outputs {
        if o.value < DUST_THRESHOLD {
            return Err(Error::DustOutput {
                amount: o.value,
                dust_threshold: DUST_THRESHOLD,
            });
        }
    }

    let total_amount: u64 = outputs.iter().try_fold(0u64, |acc, o| {
        acc.checked_add(o.value)
            .ok_or_else(|| Error::TxBuild("sum(outputs.value) overflows u64".into()))
    })?;

    let wallet_script: Vec<u8> = signer.address().as_bytes().to_vec();

    // ---- 1. fetch sender UTXOs once ---------------------------------
    let utxos = node.get_address_utxos(&signer.address_hex()).await?;
    let tip_height = utxos.tip_height;

    let mut candidates: Vec<(OutPoint, crate::upstream::UtxoEntry)> =
        Vec::with_capacity(utxos.utxos.len());
    for entry in &utxos.utxos {
        let tx_id_bytes = decode_hash(&entry.tx_id)?;
        let op = OutPoint {
            tx_id: Hash256(tx_id_bytes),
            output_index: entry.output_index,
        };
        candidates.push((op, entry.clone()));
    }
    candidates.sort_by_key(|c| std::cmp::Reverse(c.1.value));

    // ---- 2. iterative fee-aware UTXO selection ----------------------
    let mut estimated_fee = match fee_choice {
        FeeChoice::Absolute(f) => f,
        FeeChoice::Rate(r) => estimate_fee_for_template(&outputs, 1, r, &wallet_script)?,
    };

    let (guard, selected) = {
        let mut iters = 0;
        loop {
            iters += 1;
            let needed = total_amount
                .checked_add(estimated_fee)
                .ok_or_else(|| Error::TxBuild("amount + fee overflows u64".into()))?;

            let result = inflight.select_and_claim(|pending| {
                let mut chosen: Vec<(OutPoint, crate::upstream::UtxoEntry)> = Vec::new();
                let mut chosen_outpoints: Vec<OutPoint> = Vec::new();
                let mut accumulated: u64 = 0;
                let mut spendable_total: u64 = 0;
                let mut spendable_count: usize = 0;
                let mut in_flight_value: u64 = 0;
                let mut in_flight_count: usize = 0;
                for (op, entry) in &candidates {
                    if pending.contains(op) {
                        in_flight_value = in_flight_value.saturating_add(entry.value);
                        in_flight_count += 1;
                        continue;
                    }
                    spendable_total = spendable_total.saturating_add(entry.value);
                    spendable_count += 1;
                    if accumulated >= needed {
                        continue;
                    }
                    chosen.push((*op, entry.clone()));
                    chosen_outpoints.push(*op);
                    accumulated = accumulated.saturating_add(entry.value);
                }

                if accumulated < needed {
                    return Err(Error::InsufficientBalance {
                        needed,
                        available: spendable_total,
                        utxo_count: spendable_count,
                        in_flight_value,
                        in_flight_count,
                    });
                }
                Ok((chosen_outpoints, chosen))
            });

            let (guard, selected) = result?;

            let new_estimate = match fee_choice {
                FeeChoice::Absolute(f) => f,
                FeeChoice::Rate(r) => {
                    estimate_fee_for_template(&outputs, selected.len(), r, &wallet_script)?
                }
            };

            if new_estimate <= estimated_fee || iters >= FEE_ESTIMATE_MAX_ITERS {
                break (guard, selected);
            }
            drop(guard);
            estimated_fee = new_estimate;
        }
    };

    // ---- 3. assemble outputs, then settle on the fee ----------------
    let total_in: u64 = selected.iter().map(|(_, e)| e.value).sum();
    let inputs: Vec<TxInput> = selected
        .iter()
        .map(|(op, _)| TxInput {
            prev_tx_id: op.tx_id,
            output_index: op.output_index,
        })
        .collect();

    let mut tx_outputs: Vec<TxOutput> = outputs
        .iter()
        .map(|o| TxOutput {
            value: o.value,
            script: o.script.clone(),
            datum: None,
            datum_hash: None,
        })
        .collect();

    // Placeholder change so the cost model includes it.
    tx_outputs.push(TxOutput {
        value: 0,
        script: wallet_script.clone(),
        datum: None,
        datum_hash: None,
    });
    let witnesses_template: Vec<TxWitness> = inputs
        .iter()
        .map(|_| TxWitness {
            witness: vec![0u8; 96],
            redeemer: None,
        })
        .collect();
    let tx_template = Transaction {
        inputs: inputs.clone(),
        outputs: tx_outputs.clone(),
        witnesses: witnesses_template.clone(),
    };
    let consensus_min = min_fee(&tx_template).ok_or_else(|| {
        Error::TxBuild("min_fee computation overflowed — transaction too large".into())
    })?;
    let tx_cost_actual = tx_cost(&tx_template).ok_or_else(|| {
        Error::TxBuild("tx_cost computation overflowed — transaction too large".into())
    })?;

    let mut chosen_fee = match fee_choice {
        FeeChoice::Absolute(f) => f,
        FeeChoice::Rate(r) => {
            let num = (tx_cost_actual as u128).saturating_mul(r as u128);
            let div = MIN_FEE_DIVISOR as u128;
            (num.div_ceil(div)) as u64
        }
    };
    if chosen_fee < consensus_min {
        chosen_fee = consensus_min;
    }
    if chosen_fee > max_fee {
        return Err(Error::FeeTooHigh {
            fee: chosen_fee,
            max_fee,
        });
    }

    let needed_total = total_amount
        .checked_add(chosen_fee)
        .ok_or_else(|| Error::TxBuild("amount + chosen_fee overflows u64".into()))?;
    if total_in < needed_total {
        drop(guard);
        return Err(Error::InsufficientBalance {
            needed: needed_total,
            available: total_in,
            utxo_count: selected.len(),
            in_flight_value: 0,
            in_flight_count: 0,
        });
    }

    let change_value = total_in - total_amount - chosen_fee;
    let pop_placeholder = tx_outputs.pop();
    debug_assert!(pop_placeholder.is_some());
    let mut has_change = false;
    if change_value >= DUST_THRESHOLD {
        tx_outputs.push(TxOutput {
            value: change_value,
            script: wallet_script.clone(),
            datum: None,
            datum_hash: None,
        });
        has_change = true;
    }
    let effective_fee = total_in - tx_outputs.iter().map(|o| o.value).sum::<u64>();
    if effective_fee > max_fee {
        return Err(Error::FeeTooHigh {
            fee: effective_fee,
            max_fee,
        });
    }

    // ---- 4. sign locally --------------------------------------------
    let mut tx = Transaction {
        inputs,
        outputs: tx_outputs,
        witnesses: witnesses_template,
    };
    let sig_msg = tx
        .sig_message()
        .map_err(|e| Error::TxSerialize(format!("sig_message: {e:?}")))?;
    let signature = signer.signing_key().sign(&sig_msg);
    let pubkey = signer.pubkey();
    for w in &mut tx.witnesses {
        let mut blob = Vec::with_capacity(96);
        blob.extend_from_slice(&pubkey);
        blob.extend_from_slice(&signature.to_bytes());
        w.witness = blob;
    }

    let final_min =
        min_fee(&tx).ok_or_else(|| Error::TxBuild("min_fee on final tx overflowed".into()))?;
    if effective_fee < final_min {
        return Err(Error::TxBuild(format!(
            "effective fee {effective_fee} below consensus minimum {final_min} after change folding"
        )));
    }

    let tx_id = tx
        .tx_id()
        .map_err(|e| Error::TxSerialize(format!("tx_id: {e:?}")))?;
    let serialized = tx
        .serialize()
        .map_err(|e| Error::TxSerialize(format!("{e:?}")))?;

    // ---- 5. (broadcast happens in broadcast_built) ------------------
    let final_cost =
        tx_cost(&tx).ok_or_else(|| Error::TxBuild("tx_cost on final tx overflowed".into()))?;
    let reported_rate = if final_cost == 0 {
        0
    } else {
        ((effective_fee as u128).saturating_mul(MIN_FEE_DIVISOR as u128) / (final_cost as u128))
            as u64
    };

    // `node` is intentionally part of the signature so the caller
    // doesn't have to thread the upstream client through; only the
    // UTXO query at the top of this function consumes it.
    let _ = node;

    let size = serialized.len() as u64;
    Ok((
        BuiltTx {
            tx,
            tx_id,
            size,
            effective_fee,
            fee_rate: reported_rate,
            built_at_height: tip_height,
            selected: selected.iter().map(|(op, e)| (*op, e.value)).collect(),
            change_value,
            has_change,
        },
        guard,
    ))
}

/// Broadcast a previously built transaction and verify the node's
/// returned tx_id matches what we computed locally. Caller is
/// responsible for `guard.commit()` on success.
pub(crate) async fn broadcast_built(node: &ExferNode, built: &BuiltTx) -> Result<()> {
    let serialized = built
        .tx
        .serialize()
        .map_err(|e| Error::TxSerialize(format!("{e:?}")))?;
    let tx_hex = hex::encode(&serialized);
    let sent = node.send_raw_transaction(&tx_hex).await?;
    let our_tx_id_hex = hex::encode(built.tx_id.as_bytes());
    if sent.tx_id != our_tx_id_hex {
        return Err(Error::UpstreamUnexpected(format!(
            "node returned tx_id {} but we computed {our_tx_id_hex}",
            sent.tx_id
        )));
    }
    Ok(())
}

/// Estimate the consensus minimum fee for a template with `input_count`
/// placeholder inputs + the requested `outputs` + 1 placeholder change.
/// Used to size UTXO selection before we know the real input count.
fn estimate_fee_for_template(
    outputs: &[CoreOutput],
    input_count: usize,
    fee_rate: u64,
    change_script: &[u8],
) -> Result<u64> {
    let inputs: Vec<TxInput> = (0..input_count)
        .map(|i| TxInput {
            prev_tx_id: Hash256([0u8; 32]),
            output_index: i as u32,
        })
        .collect();
    let mut tx_outputs: Vec<TxOutput> = outputs
        .iter()
        .map(|o| TxOutput {
            value: o.value,
            script: o.script.clone(),
            datum: None,
            datum_hash: None,
        })
        .collect();
    tx_outputs.push(TxOutput {
        value: DUST_THRESHOLD, // placeholder change
        script: change_script.to_vec(),
        datum: None,
        datum_hash: None,
    });
    let witnesses: Vec<TxWitness> = inputs
        .iter()
        .map(|_| TxWitness {
            witness: vec![0u8; 96],
            redeemer: None,
        })
        .collect();
    let tx = Transaction {
        inputs,
        outputs: tx_outputs,
        witnesses,
    };
    let cost = tx_cost(&tx)
        .ok_or_else(|| Error::TxBuild("tx_cost overflowed during fee estimate".into()))?;
    let num = (cost as u128).saturating_mul(fee_rate as u128);
    let div = MIN_FEE_DIVISOR as u128;
    Ok(num.div_ceil(div) as u64)
}

pub(crate) fn decode_hash(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).map_err(|e| Error::BadHex(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(Error::BadAddressLen(bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
