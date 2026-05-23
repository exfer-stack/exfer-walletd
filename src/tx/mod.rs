//! Multi-output transfer engine.
//!
//! Builds, signs, and broadcasts a single Exfer transaction with one or
//! more recipients. We bypass `exfer::wallet::wallet::Wallet::build_transaction`
//! (which is hardcoded to single-recipient + single-change) and construct
//! the [`Transaction`] ourselves so we can:
//!
//! - Pack up to [`crate::api::MAX_OUTPUTS`] recipients in one tx
//! - Compute the fee from a `fee_rate` (exfers per cost-unit) using
//!   the same `consensus::cost` model the chain enforces
//! - Enforce a `max_fee` cap before broadcast (defensive against
//!   off-by-zero mistakes in the request)
//! - Return a receipt that names every input consumed and every output
//!   created (including the auto-change), so callers reconcile without
//!   a follow-up `get_transaction(tx_id)`
//!
//! Flow:
//!
//! ```text
//!   list UTXOs ──► estimate fee for (1 input, N outputs + 1 change)
//!              ──► greedy-pick covering total_amount + estimate (skip in-flight)
//!              ──► authenticate selected (concurrently, cap 8)
//!              ──► build tx; compute actual fee; re-select if estimate was low
//!              ──► sign locally (ed25519 over sig_message)
//!              ──► send_raw_transaction
//!              ──► self-check: node tx_id == computed tx_id
//! ```

pub mod decode;

use ed25519_dalek::Signer as _;
use exfer::consensus::cost::{min_fee, tx_cost};
use exfer::types::transaction::{OutPoint, Transaction, TxInput, TxOutput, TxWitness};
use exfer::types::{Hash256, DUST_THRESHOLD, MIN_FEE_DIVISOR};
use exfer::wallet::auth::authenticate_tx_hex;
use futures::stream::{self, StreamExt, TryStreamExt};
use serde::Serialize;

use crate::error::{Error, Result};
use crate::inflight::InFlightUtxos;
use crate::store::Signer;
use crate::upstream::ExferNode;

/// How many `get_transaction` calls we fan out at once during UTXO
/// authentication. Sub-linear scaling vs input count, gentle on shared
/// public RPCs.
const AUTH_CONCURRENCY: usize = 8;

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

pub async fn transfer(
    signer: &Signer,
    recipients: Vec<(Hash256, u64)>,
    fee_choice: FeeChoice,
    max_fee: u64,
    node: &ExferNode,
    inflight: &InFlightUtxos,
) -> Result<TransferReceipt> {
    // ---- input validation (envelope-level checks live in api/mod.rs,
    //      but engine guards too so misuse from non-RPC callers is safe).
    if recipients.is_empty() {
        return Err(Error::TxBuild(
            "transfer: recipients must not be empty".into(),
        ));
    }
    for (_, amt) in &recipients {
        if *amt < DUST_THRESHOLD {
            return Err(Error::DustOutput {
                amount: *amt,
                dust_threshold: DUST_THRESHOLD,
            });
        }
    }

    let total_amount: u64 = recipients.iter().try_fold(0u64, |acc, (_, a)| {
        acc.checked_add(*a)
            .ok_or_else(|| Error::TxBuild("sum(outputs.amount) overflows u64".into()))
    })?;

    let sender_addr_hex = signer.address_hex();
    let wallet_script = std::sync::Arc::new(signer.address().as_bytes().to_vec());

    // ---- 1. fetch sender UTXOs once ---------------------------------
    let utxos = node.get_address_utxos(&sender_addr_hex).await?;
    let tip_height = utxos.tip_height;

    // Materialise candidate list in largest-value-first order — used
    // by every selection pass below.
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
    // Start with a fee estimate for a representative tx (1 input,
    // N outputs + 1 change). Re-select if adding inputs bumps min_fee
    // above what we covered. Bounded by FEE_ESTIMATE_MAX_ITERS.
    let mut estimated_fee = match fee_choice {
        FeeChoice::Absolute(f) => f,
        FeeChoice::Rate(r) => estimate_fee_for_template(&recipients, 1, r, &wallet_script)?,
    };

    let (guard, selected) = {
        let mut iters = 0;
        loop {
            iters += 1;
            let needed = total_amount
                .checked_add(estimated_fee)
                .ok_or_else(|| Error::TxBuild("amount + fee overflows u64".into()))?;

            let result: std::result::Result<
                (
                    crate::inflight::ClaimGuard<'_>,
                    Vec<(OutPoint, crate::upstream::UtxoEntry)>,
                ),
                Error,
            > = inflight.select_and_claim(|pending| {
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

            // Re-estimate fee for the actual input count and check if
            // the estimate is still sufficient.
            let new_estimate = match fee_choice {
                FeeChoice::Absolute(f) => f,
                FeeChoice::Rate(r) => {
                    estimate_fee_for_template(&recipients, selected.len(), r, &wallet_script)?
                }
            };

            if new_estimate <= estimated_fee || iters >= FEE_ESTIMATE_MAX_ITERS {
                break (guard, selected);
            }
            // Fee grew; release the claim and re-select with the
            // higher estimate.
            drop(guard);
            estimated_fee = new_estimate;
        }
    };

    // ---- 3. authenticate selected UTXOs in parallel -----------------
    let owned: Vec<crate::upstream::UtxoEntry> = selected.into_iter().map(|(_, e)| e).collect();
    let authed: Vec<(OutPoint, u64)> = stream::iter(owned)
        .map(|entry| {
            let wallet_script = wallet_script.clone();
            async move {
                let tx_id_bytes = decode_hash(&entry.tx_id)?;
                let tx_id = Hash256(tx_id_bytes);

                let funding = node.get_transaction(&entry.tx_id).await?;
                let raw = hex::decode(&funding.tx_hex)
                    .map_err(|e| Error::UtxoAuth(format!("funding tx_hex not hex: {e}")))?;

                let (auth_value, _auth_script) = authenticate_tx_hex(
                    &raw,
                    tx_id,
                    entry.output_index,
                    Some(wallet_script.as_ref()),
                )
                .map_err(|e| Error::UtxoAuth(e.to_string()))?;

                Ok::<_, Error>((
                    OutPoint {
                        tx_id,
                        output_index: entry.output_index,
                    },
                    auth_value,
                ))
            }
        })
        .buffer_unordered(AUTH_CONCURRENCY)
        .try_collect()
        .await?;

    let total_in: u64 = authed.iter().map(|(_, v)| *v).sum();

    // ---- 4. assemble outputs, then iteratively settle on the fee.
    //         We may need to redo the assembly if min_fee on the actual
    //         tx exceeds the estimated_fee we covered.
    let inputs: Vec<TxInput> = authed
        .iter()
        .map(|(op, _)| TxInput {
            prev_tx_id: op.tx_id,
            output_index: op.output_index,
        })
        .collect();

    let mut outputs: Vec<TxOutput> = recipients
        .iter()
        .map(|(addr, value)| TxOutput {
            value: *value,
            script: addr.as_bytes().to_vec(),
            datum: None,
            datum_hash: None,
        })
        .collect();

    // Compute consensus min_fee on the actual tx shape (with placeholder
    // change so the cost includes it).
    let placeholder_change = TxOutput {
        value: 0,
        script: (*wallet_script).clone(),
        datum: None,
        datum_hash: None,
    };
    outputs.push(placeholder_change);
    let witnesses_template: Vec<TxWitness> = inputs
        .iter()
        .map(|_| TxWitness {
            witness: vec![0u8; 96],
            redeemer: None,
        })
        .collect();
    let tx_template = Transaction {
        inputs: inputs.clone(),
        outputs: outputs.clone(),
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
            // fee = ceil(tx_cost * r / MIN_FEE_DIVISOR), then floor at consensus min.
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

    // Verify the inputs cover (total_amount + chosen_fee). If not, the
    // earlier selection was too small (rare: chosen_fee > estimated_fee
    // and the residual didn't absorb it).
    let needed_total = total_amount
        .checked_add(chosen_fee)
        .ok_or_else(|| Error::TxBuild("amount + chosen_fee overflows u64".into()))?;
    if total_in < needed_total {
        // Release inflight claim and surface insufficient-balance.
        drop(guard);
        return Err(Error::InsufficientBalance {
            needed: needed_total,
            available: total_in,
            utxo_count: authed.len(),
            in_flight_value: 0,
            in_flight_count: 0,
        });
    }

    // Replace placeholder change with actual change, or drop it if
    // sub-dust (folded into fee).
    let change_value = total_in - total_amount - chosen_fee;
    let pop_placeholder = outputs.pop();
    debug_assert!(pop_placeholder.is_some());
    let mut has_change = false;
    if change_value >= DUST_THRESHOLD {
        outputs.push(TxOutput {
            value: change_value,
            script: (*wallet_script).clone(),
            datum: None,
            datum_hash: None,
        });
        has_change = true;
    }
    // Effective fee after dust folding (may exceed chosen_fee by up to
    // DUST_THRESHOLD-1).
    let effective_fee = total_in - outputs.iter().map(|o| o.value).sum::<u64>();
    if effective_fee > max_fee {
        return Err(Error::FeeTooHigh {
            fee: effective_fee,
            max_fee,
        });
    }

    // ---- 5. sign locally ----
    let mut tx = Transaction {
        inputs,
        outputs,
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

    // Re-verify min_fee on the final tx (change may have changed cost).
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

    // ---- 6. broadcast ----
    let tx_hex = hex::encode(&serialized);
    let sent = node.send_raw_transaction(&tx_hex).await?;
    let our_tx_id_hex = hex::encode(tx_id.as_bytes());
    if sent.tx_id != our_tx_id_hex {
        return Err(Error::UpstreamUnexpected(format!(
            "node returned tx_id {} but we computed {our_tx_id_hex}",
            sent.tx_id
        )));
    }
    guard.commit();

    // ---- 7. assemble receipt ----
    let receipt_inputs: Vec<ReceiptInput> = authed
        .iter()
        .map(|(op, v)| ReceiptInput {
            tx_id: hex::encode(op.tx_id.as_bytes()),
            output_index: op.output_index,
            value: *v,
        })
        .collect();
    let mut receipt_outputs: Vec<ReceiptOutput> = recipients
        .iter()
        .map(|(addr, value)| ReceiptOutput {
            to: hex::encode(addr.as_bytes()),
            amount: *value,
            is_change: false,
        })
        .collect();
    if has_change {
        receipt_outputs.push(ReceiptOutput {
            to: sender_addr_hex.clone(),
            amount: change_value,
            is_change: true,
        });
    }

    // fee_rate reported back: effective_fee / tx_cost × MIN_FEE_DIVISOR
    // (re-derived from the final tx).
    let final_cost =
        tx_cost(&tx).ok_or_else(|| Error::TxBuild("tx_cost on final tx overflowed".into()))?;
    let reported_rate = if final_cost == 0 {
        0
    } else {
        ((effective_fee as u128).saturating_mul(MIN_FEE_DIVISOR as u128) / (final_cost as u128))
            as u64
    };

    Ok(TransferReceipt {
        tx_id: our_tx_id_hex,
        size: serialized.len() as u64,
        fee: effective_fee,
        fee_rate: reported_rate,
        inputs: receipt_inputs,
        outputs: receipt_outputs,
        built_at_height: tip_height,
    })
}

/// Estimate the consensus minimum fee for a transfer template with
/// `input_count` placeholder inputs + the requested recipients + 1
/// placeholder change output. Used to size UTXO selection before we
/// know the real input count.
fn estimate_fee_for_template(
    recipients: &[(Hash256, u64)],
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
    let mut outputs: Vec<TxOutput> = recipients
        .iter()
        .map(|(addr, v)| TxOutput {
            value: *v,
            script: addr.as_bytes().to_vec(),
            datum: None,
            datum_hash: None,
        })
        .collect();
    outputs.push(TxOutput {
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
        outputs,
        witnesses,
    };
    let cost = tx_cost(&tx)
        .ok_or_else(|| Error::TxBuild("tx_cost overflowed during fee estimate".into()))?;
    // fee = ceil(cost × rate / MIN_FEE_DIVISOR)
    let num = (cost as u128).saturating_mul(fee_rate as u128);
    let div = MIN_FEE_DIVISOR as u128;
    Ok(num.div_ceil(div) as u64)
}

fn decode_hash(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).map_err(|e| Error::BadHex(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(Error::BadAddressLen(bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
