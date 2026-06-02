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

use exfer::types::transaction::{Transaction, TxOutput, TxWitness};
use futures::stream::{self, StreamExt};
use serde::Serialize;

use crate::error::{Error, Result};
use crate::upstream::ExferNode;

/// Phase 1 P2PKH witness layout. The witness blob is exactly
/// `pubkey(32) || signature(64) = 96` bytes. Anything else (coinbase,
/// future script types) is surfaced as raw `witness_hex` for the
/// client to interpret.
const PHASE1_WITNESS_LEN: usize = 96;

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
    /// Spending address (hex, 64-char). For Phase-1 P2PKH this is
    /// derived from the witness pubkey (no upstream calls); falls back
    /// to the parent-fetch derived value when the witness layout is
    /// non-standard.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Hex-encoded script when the referenced output's script wasn't
    /// 32 bytes (non-P2PKH) and the parent was reachable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_hex: Option<String>,
    /// Value (exfers) of the consumed output. `None` if parent fetch
    /// failed or the output index was out of bounds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<u64>,
    /// Decoded witness from `tx_hex` (zero upstream calls). `None` if
    /// no witness slot was present (rare — chain always carries one
    /// per input).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<DecodedWitness>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecodedWitness {
    /// Phase 1 P2PKH spender pubkey (first 32 bytes of witness).
    /// Hashing this yields the input's `address`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,
    /// Phase 1 P2PKH Ed25519 signature (last 64 bytes of witness).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Raw witness bytes when the layout isn't 96-byte Phase-1
    /// (coinbase, future script types). Present alongside `pubkey` /
    /// `signature` is never set — exactly one form is populated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_hex: Option<String>,
    /// Optional redeemer bytes (Phase 1: always absent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redeemer_hex: Option<String>,
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
    /// Hex-encoded datum carried by this output (a generic, app-defined
    /// on-chain blob), if any. Surfaced verbatim — meaning is the app's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datum: Option<String>,
    /// Hex-encoded datum hash commitment, if the output carries one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datum_hash: Option<String>,
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
    /// Serialized transaction size in bytes (== `tx_hex.len() / 2`).
    pub size: usize,
}

/// Decode `tx_hex` and (best-effort) resolve each input's spending
/// address + value. Phase-1 P2PKH addresses come from the witness
/// pubkey (zero upstream calls); values still need a parent fetch.
pub async fn decode_with_inputs(node: &ExferNode, tx_hex: &str) -> Result<DecodedTx> {
    let raw = hex::decode(tx_hex).map_err(|e| Error::Internal(format!("tx_hex not hex: {e}")))?;
    let size = raw.len();
    let (tx, _consumed) = Transaction::deserialize(&raw)
        .map_err(|e| Error::Internal(format!("tx_hex deserialize: {e:?}")))?;

    let outputs: Vec<DecodedOutput> = tx
        .outputs
        .iter()
        .map(|o| decoded_output(&o.script, o.value, &o.datum, &o.datum_hash))
        .collect();
    let total_out: u64 = outputs.iter().map(|o| o.value).sum();

    // Decode witnesses inline (free — already in tx_hex). For Phase-1
    // P2PKH, the pubkey is the first 32 bytes of the witness blob;
    // hashing it gives the spender's address. We prefer this over the
    // parent-fetch path because: (a) zero upstream cost, (b) survives
    // parent-fetch failures, (c) is what the chain itself verifies.
    let witnesses: Vec<Option<DecodedWitness>> = tx.witnesses.iter().map(decode_witness).collect();
    let witness_addresses: Vec<Option<String>> = witnesses
        .iter()
        .map(|w| w.as_ref().and_then(address_from_witness))
        .collect();

    // Outpoints in declared order — preserve for the response since
    // `buffer_unordered` doesn't.
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
    let mut any_value_missing = false;
    let count = outpoints.len();
    for i in 0..count {
        let (_, ref prev_id, out_idx) = outpoints[i];
        let witness = witnesses[i].clone();
        let witness_address = witness_addresses[i].clone();
        match resolved[i].clone() {
            Some((parent_addr, parent_script, value)) => {
                total_in = total_in.saturating_add(value);
                inputs.push(DecodedInput {
                    prev_tx_id: prev_id.clone(),
                    output_index: out_idx,
                    // Witness-derived first; parent-derived fills in
                    // for non-Phase-1 inputs that don't carry a pubkey.
                    address: witness_address.or(parent_addr),
                    script_hex: parent_script,
                    value: Some(value),
                    witness,
                });
            }
            None => {
                any_value_missing = true;
                inputs.push(DecodedInput {
                    prev_tx_id: prev_id.clone(),
                    output_index: out_idx,
                    // Address can still come from the witness even
                    // when the parent was unreachable — that's the
                    // whole point of decoding witnesses locally.
                    address: witness_address,
                    script_hex: None,
                    value: None,
                    witness,
                });
            }
        }
    }

    let (total_in, fee) = if any_value_missing {
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
        size,
    })
}

fn decode_witness(w: &TxWitness) -> Option<DecodedWitness> {
    if w.witness.is_empty() && w.redeemer.is_none() {
        return None;
    }
    let redeemer_hex = w.redeemer.as_deref().map(hex::encode);
    if w.witness.len() == PHASE1_WITNESS_LEN {
        Some(DecodedWitness {
            pubkey: Some(hex::encode(&w.witness[..32])),
            signature: Some(hex::encode(&w.witness[32..])),
            witness_hex: None,
            redeemer_hex,
        })
    } else {
        Some(DecodedWitness {
            pubkey: None,
            signature: None,
            witness_hex: Some(hex::encode(&w.witness)),
            redeemer_hex,
        })
    }
}

fn address_from_witness(w: &DecodedWitness) -> Option<String> {
    let pk_hex = w.pubkey.as_deref()?;
    let pk_bytes: [u8; 32] = hex::decode(pk_hex).ok()?.try_into().ok()?;
    Some(hex::encode(
        TxOutput::pubkey_hash_from_key(&pk_bytes).as_bytes(),
    ))
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

fn decoded_output(
    script: &[u8],
    value: u64,
    datum: &Option<Vec<u8>>,
    datum_hash: &Option<exfer::types::Hash256>,
) -> DecodedOutput {
    let (address, script_hex) = address_or_script(script);
    DecodedOutput {
        address,
        script_hex,
        value,
        datum: datum.as_ref().map(hex::encode),
        datum_hash: datum_hash.as_ref().map(|h| hex::encode(h.as_bytes())),
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
            .map(|o| decoded_output(&o.script, o.value, &o.datum, &o.datum_hash))
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
        let out = decoded_output(&weird, 5, &None, &None);
        assert!(out.address.is_none());
        assert_eq!(
            out.script_hex.as_deref(),
            Some("1111111111111111111111111111111111")
        );
        assert_eq!(out.value, 5);
    }

    #[test]
    fn datum_is_surfaced_verbatim() {
        let with = decoded_output(
            &[0xbb; 32],
            1_000,
            &Some(vec![0xde, 0xad, 0xbe, 0xef]),
            &None,
        );
        assert_eq!(with.datum.as_deref(), Some("deadbeef"));
        assert!(with.datum_hash.is_none());

        let without = decoded_output(&[0xbb; 32], 1_000, &None, &None);
        assert!(without.datum.is_none());
    }
}
