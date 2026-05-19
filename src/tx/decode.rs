//! Decoded `get_transaction` view.
//!
//! Pure-passthrough `get_transaction` (just `tx_hex` + chain coords) makes
//! integrators decode the wire format themselves to answer "who sent
//! what?" — every exchange / explorer / accounting backend has reinvented
//! this. We do it once here.
//!
//! Outputs are decoded inline (no upstream calls — script bytes in a
//! P2PKH output are the recipient address). Inputs need parent-tx
//! fetches to recover the spending address and value; we run those in
//! parallel with the same bounded concurrency as the `transfer` engine.
//! Per-parent failures degrade gracefully: that input's `address`/`value`
//! come back `null` and `fee` becomes `null`, but the rest of the
//! response is still returned.

use exfer::types::transaction::Transaction;
use futures::stream::{self, StreamExt};
use serde::Serialize;

use crate::error::{Error, Result};
use crate::upstream::ExferNode;

/// Match the `transfer` engine's cap so an aggressive `get_transaction`
/// can't out-fan-out a healthy spend path on the upstream.
const INPUT_RESOLVE_CONCURRENCY: usize = 8;

/// Per-input resolution result: `(address, script_hex, value)`. `address`
/// is `Some` for standard P2PKH; `script_hex` is `Some` for non-P2PKH;
/// exactly one of the two is populated (see [`address_or_script`]).
type ResolvedInput = (Option<String>, Option<String>, u64);

#[derive(Debug, Clone, Serialize)]
pub struct DecodedInput {
    pub prev_tx_id: String,
    pub output_index: u32,
    /// Spending address (hex, 64-char) when the parent tx was reachable
    /// and the referenced output was a standard 32-byte P2PKH script.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Hex-encoded script when the parent was reachable but the
    /// referenced output's script wasn't 32 bytes (non-P2PKH).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_hex: Option<String>,
    /// Value (exfers) of the consumed output. `None` if parent fetch
    /// failed or the output index was out of bounds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecodedOutput {
    /// 64-hex P2PKH address when the script is a standard 32-byte
    /// pubkey hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Hex-encoded raw script for non-P2PKH outputs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_hex: Option<String>,
    pub value: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecodedTx {
    pub inputs: Vec<DecodedInput>,
    pub outputs: Vec<DecodedOutput>,
    /// `total_in - total_out`. `None` if any input failed to resolve.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee: Option<u64>,
    /// Sum of all input values. `None` if any input failed to resolve.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_in: Option<u64>,
    pub total_out: u64,
}

/// Decode `tx_hex` and (best-effort) resolve each input's spending
/// address + value by fetching parent transactions from `node`.
pub async fn decode_with_inputs(node: &ExferNode, tx_hex: &str) -> Result<DecodedTx> {
    let raw = hex::decode(tx_hex).map_err(|e| Error::Internal(format!("tx_hex not hex: {e}")))?;
    let (tx, _consumed) = Transaction::deserialize(&raw)
        .map_err(|e| Error::Internal(format!("tx_hex deserialize: {e:?}")))?;

    let outputs: Vec<DecodedOutput> = tx
        .outputs
        .iter()
        .map(|o| decoded_output(&o.script, o.value))
        .collect();
    let total_out: u64 = outputs.iter().map(|o| o.value).sum();

    // Outpoints in declared order — we need to preserve order in the
    // response, and `buffer_unordered` doesn't.
    let outpoints: Vec<(usize, String, u32)> = tx
        .inputs
        .iter()
        .enumerate()
        .map(|(i, inp)| (i, hex::encode(inp.prev_tx_id.as_bytes()), inp.output_index))
        .collect();

    let mut resolved: Vec<Option<ResolvedInput>> = vec![None; outpoints.len()];

    let fetches = stream::iter(outpoints.clone())
        .map(|(i, prev_id, out_idx)| async move {
            let result = resolve_input(node, &prev_id, out_idx).await;
            (i, result)
        })
        .buffer_unordered(INPUT_RESOLVE_CONCURRENCY);

    let collected: Vec<(usize, Option<ResolvedInput>)> = fetches.collect().await;
    for (i, r) in collected {
        resolved[i] = r;
    }

    let mut inputs: Vec<DecodedInput> = Vec::with_capacity(outpoints.len());
    let mut total_in: u64 = 0;
    let mut any_unresolved = false;
    for ((_, prev_id, out_idx), r) in outpoints.into_iter().zip(resolved.into_iter()) {
        match r {
            Some((address, script_hex, value)) => {
                total_in = total_in.saturating_add(value);
                inputs.push(DecodedInput {
                    prev_tx_id: prev_id,
                    output_index: out_idx,
                    address,
                    script_hex,
                    value: Some(value),
                });
            }
            None => {
                any_unresolved = true;
                inputs.push(DecodedInput {
                    prev_tx_id: prev_id,
                    output_index: out_idx,
                    address: None,
                    script_hex: None,
                    value: None,
                });
            }
        }
    }

    let (total_in, fee) = if any_unresolved {
        (None, None)
    } else {
        // Saturating sub keeps us safe in the theoretical case where a
        // corrupt upstream reports outputs > inputs.
        let fee = total_in.saturating_sub(total_out);
        (Some(total_in), Some(fee))
    };

    Ok(DecodedTx {
        inputs,
        outputs,
        fee,
        total_in,
        total_out,
    })
}

async fn resolve_input(
    node: &ExferNode,
    prev_tx_id: &str,
    output_index: u32,
) -> Option<ResolvedInput> {
    let parent = node.get_transaction(prev_tx_id).await.ok()?;
    let raw = hex::decode(&parent.tx_hex).ok()?;
    let (parent_tx, _consumed) = Transaction::deserialize(&raw).ok()?;
    let out = parent_tx.outputs.get(output_index as usize)?;
    let (address, script_hex) = address_or_script(&out.script);
    Some((address, script_hex, out.value))
}

fn decoded_output(script: &[u8], value: u64) -> DecodedOutput {
    let (address, script_hex) = address_or_script(script);
    DecodedOutput {
        address,
        script_hex,
        value,
    }
}

/// Phase 1 P2PKH outputs lock to a 32-byte pubkey hash that IS the
/// address. Anything else gets surfaced as raw `script_hex` so clients
/// can still see it without us guessing wrong.
fn address_or_script(script: &[u8]) -> (Option<String>, Option<String>) {
    if script.len() == 32 {
        (Some(hex::encode(script)), None)
    } else {
        (None, Some(hex::encode(script)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exfer::types::transaction::{TxInput, TxOutput, TxWitness};
    use exfer::types::Hash256;

    fn h(byte: u8) -> Hash256 {
        Hash256([byte; 32])
    }

    fn p2pkh(value: u64, addr_byte: u8) -> TxOutput {
        TxOutput {
            value,
            script: vec![addr_byte; 32],
            datum: None,
            datum_hash: None,
        }
    }

    /// Build a transaction with arbitrary inputs/outputs, serialize it,
    /// return the hex. The decoder only reads inputs and outputs but
    /// the wire format requires one witness per input.
    fn build_tx_hex(inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> String {
        let witnesses: Vec<TxWitness> = inputs
            .iter()
            .map(|_| TxWitness {
                witness: Vec::new(),
                redeemer: None,
            })
            .collect();
        let tx = Transaction {
            inputs,
            outputs,
            witnesses,
        };
        hex::encode(tx.serialize().unwrap())
    }

    #[test]
    fn outputs_decode_with_addresses_for_p2pkh() {
        let hexed = build_tx_hex(
            vec![TxInput {
                prev_tx_id: h(0xaa),
                output_index: 0,
            }],
            vec![p2pkh(1_000, 0xbb), p2pkh(2_000, 0xcc)],
        );
        let raw = hex::decode(&hexed).unwrap();
        let (tx, _) = Transaction::deserialize(&raw).unwrap();
        let outs: Vec<DecodedOutput> = tx
            .outputs
            .iter()
            .map(|o| decoded_output(&o.script, o.value))
            .collect();

        assert_eq!(outs.len(), 2);
        assert_eq!(outs[0].address.as_deref(), Some(&*"bb".repeat(32)));
        assert!(outs[0].script_hex.is_none());
        assert_eq!(outs[0].value, 1_000);
        assert_eq!(outs[1].address.as_deref(), Some(&*"cc".repeat(32)));
        assert_eq!(outs[1].value, 2_000);
    }

    #[test]
    fn non_p2pkh_output_falls_back_to_script_hex() {
        let weird = vec![0x11; 17];
        let out = decoded_output(&weird, 5);
        assert!(out.address.is_none());
        assert_eq!(
            out.script_hex.as_deref(),
            Some("1111111111111111111111111111111111")
        );
        assert_eq!(out.value, 5);
    }
}
