//! Transfer engine.
//!
//! Reproduces the spend path used by `exfer wallet send --rpc`, with two
//! refinements over the most-literal port:
//!
//! 1. **Lazy UTXO selection.** The upstream returns every UTXO the
//!    sender owns. Authenticating all of them is `O(N)` round-trips —
//!    catastrophic on a hot wallet with thousands of deposits. We sort
//!    largest-value-first, walk until we have enough to cover
//!    `amount + fee`, and authenticate only that subset.
//!
//! 2. **Parallel authentication.** The selected UTXOs' parent-tx
//!    fetches are independent; we fan them out with bounded
//!    concurrency so wall-clock time is `~RTT` instead of `k × RTT`.
//!
//! Flow:
//!
//! ```text
//!   list UTXOs ──► sort by value desc
//!              ──► greedy-pick until value ≥ amount + fee
//!              ──► authenticate selected (concurrently, cap 8)
//!              ──► build & sign tx (local)
//!              ──► send_raw_transaction
//!              ──► self-check: node's tx_id == computed tx_id
//! ```

pub mod decode;

use exfer::chain::state::{UtxoEntry, UtxoSet};
use exfer::types::transaction::OutPoint;
use exfer::types::Hash256;
use exfer::wallet::auth::authenticate_tx_hex;
use exfer::wallet::wallet::Wallet;
use futures::stream::{self, StreamExt, TryStreamExt};

use crate::cache::WalletCache;
use crate::error::{Error, Result};
use crate::inflight::InFlightUtxos;
use crate::store::WalletStore;
use crate::upstream::ExferNode;

/// How many `get_transaction` calls we'll have in flight at once during
/// UTXO authentication. Picked to be large enough that wall-clock
/// scales sub-linearly with input count, small enough to be friendly
/// to a shared / community upstream.
const AUTH_CONCURRENCY: usize = 8;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TransferReceipt {
    pub tx_id: String,
    pub size: usize,
    pub tip_height: u64,
    pub submitted: bool,
}

// All eight parameters are essential dependencies (wallet keys, tx
// shape, network access, mutual-exclusion state, cache + store for the
// commit hook). Bundling them into a struct would just hide the same
// arity behind a constructor.
#[allow(clippy::too_many_arguments)]
pub async fn transfer(
    wallet: &Wallet,
    recipient: Hash256,
    amount_exfers: u64,
    fee_exfers: u64,
    node: &ExferNode,
    inflight: &InFlightUtxos,
    cache: &WalletCache,
    store: &dyn WalletStore,
) -> Result<TransferReceipt> {
    let sender_addr_hex = hex::encode(wallet.address().as_bytes());

    // 1. List candidate UTXOs — spend path always hits upstream and
    //    writes back to the L3 cache as a side effect (priming future
    //    display reads for free). The in-flight subtraction below
    //    happens under the existing select_and_claim atomic lock; we
    //    don't double-filter inside read_for_spend.
    let utxos = cache
        .get_address_utxos_for_spend(&sender_addr_hex, node)
        .await?;
    let tip_height = utxos.tip_height;
    let current_height = tip_height.saturating_add(1);

    let needed = amount_exfers
        .checked_add(fee_exfers)
        .ok_or_else(|| Error::TxBuild("amount + fee overflows u64".into()))?;

    // 2. Greedy selection, largest-first, skipping outpoints already
    //    claimed by another in-flight transfer. The whole snapshot →
    //    select → claim sequence runs under a single Mutex acquisition
    //    inside InFlightUtxos::select_and_claim, so two concurrent
    //    transfers from the same wallet can never both pick the same
    //    outpoint.
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

    let (guard, selected): (
        crate::inflight::ClaimGuard<'_>,
        Vec<(OutPoint, crate::upstream::UtxoEntry)>,
    ) = inflight.select_and_claim(|pending| {
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
    })?;

    let wallet_script = std::sync::Arc::new(wallet.address().as_bytes().to_vec());

    // 3. Authenticate selected UTXOs in parallel. Each future owns its
    //    inputs ('static) so buffer_unordered is Send-bound on tokio's
    //    multi-thread executor.
    let owned: Vec<crate::upstream::UtxoEntry> = selected.into_iter().map(|(_, e)| e).collect();
    let authed: Vec<(OutPoint, UtxoEntry)> = stream::iter(owned)
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
                    UtxoEntry {
                        output: exfer::types::transaction::TxOutput {
                            value: auth_value,
                            script: (*wallet_script).clone(),
                            datum: None,
                            datum_hash: None,
                        },
                        height: entry.height,
                        is_coinbase: entry.is_coinbase,
                    },
                ))
            }
        })
        .buffer_unordered(AUTH_CONCURRENCY)
        .try_collect()
        .await?;

    let mut utxo_set = UtxoSet::new();
    for (outpoint, entry) in authed {
        utxo_set
            .insert(outpoint, entry)
            .map_err(|e| Error::Internal(format!("utxo insert: {e:?}")))?;
    }

    // 4. Build + sign locally.
    let tx = wallet
        .build_transaction(
            recipient,
            amount_exfers,
            fee_exfers,
            &utxo_set,
            current_height,
        )
        .map_err(|e| Error::TxBuild(format!("{e:?}")))?;

    let tx_id = tx
        .tx_id()
        .map_err(|e| Error::TxSerialize(format!("tx_id: {e:?}")))?;
    let serialized = tx
        .serialize()
        .map_err(|e| Error::TxSerialize(format!("{e:?}")))?;

    // 5. Broadcast.
    let tx_hex = hex::encode(&serialized);
    let sent = node.send_raw_transaction(&tx_hex).await?;

    let our_tx_id_hex = hex::encode(tx_id.as_bytes());
    if sent.tx_id != our_tx_id_hex {
        return Err(Error::UpstreamUnexpected(format!(
            "node returned tx_id {} but we computed {our_tx_id_hex}",
            sent.tx_id
        )));
    }

    // Broadcast succeeded — keep the in-flight claim so a follow-up
    // transfer can't pick the same UTXOs before the upstream's
    // confirmed listing catches up. TTL evicts the entry eventually.
    guard.commit();

    // Eager cache invalidation after commit. Bumps L2/L3 generation
    // for `from` (and `to` if locally managed and different from from)
    // so any in-flight refresher write loses its CAS and the next
    // dashboard read sees post-spend state from upstream.
    let to_hex = hex::encode(recipient.as_bytes());
    cache.on_transfer_commit(&sender_addr_hex, &to_hex, store);

    Ok(TransferReceipt {
        tx_id: our_tx_id_hex,
        size: serialized.len(),
        tip_height,
        submitted: true,
    })
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
