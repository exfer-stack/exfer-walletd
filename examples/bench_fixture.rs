//! One-off helper: build a parent+child tx pair and print their hex
//!     + tx_ids. Used by the bench mock upstream so walletd's get_transaction
//!     decode path runs against real serialized data.

use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};
use exfer::types::Hash256;

fn p2pkh(value: u64, addr_byte: u8) -> TxOutput {
    TxOutput {
        value,
        script: vec![addr_byte; 32],
        datum: None,
        datum_hash: None,
    }
}

fn main() {
    // Parent: synthetic origin, two P2PKH outputs.
    let parent = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256([0; 32]),
            output_index: 0,
        }],
        outputs: vec![p2pkh(100_000_000, 0xaa), p2pkh(50_000_000, 0xbb)],
        witnesses: vec![TxWitness {
            witness: vec![0u8; 96],
            redeemer: None,
        }],
    };
    let parent_id = parent.tx_id().unwrap();

    // Child: spends parent[0] with a 96-byte Phase-1 witness whose
    // pubkey deterministically derives the spender's address.
    let mut pubkey = [0u8; 32];
    for (i, b) in pubkey.iter_mut().enumerate() {
        *b = i as u8;
    }
    let mut sig = [0u8; 64];
    for (i, b) in sig.iter_mut().enumerate() {
        *b = ((i + 13) & 0xff) as u8;
    }
    let mut witness = pubkey.to_vec();
    witness.extend_from_slice(&sig);

    let child = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: parent_id,
            output_index: 0,
        }],
        outputs: vec![p2pkh(30_000_000, 0xcc), p2pkh(69_900_000, 0xdd)],
        witnesses: vec![TxWitness {
            witness,
            redeemer: None,
        }],
    };
    let child_id = child.tx_id().unwrap();

    println!("PARENT_ID={}", hex::encode(parent_id.as_bytes()));
    println!("PARENT_HEX={}", hex::encode(parent.serialize().unwrap()));
    println!("CHILD_ID={}", hex::encode(child_id.as_bytes()));
    println!("CHILD_HEX={}", hex::encode(child.serialize().unwrap()));
}
