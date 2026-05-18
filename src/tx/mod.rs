//! Transfer engine.
//!
//! Reproduces the spend path used by `exfer wallet send --rpc`:
//!
//! 1. List the sender's UTXOs via `get_address_utxos` on the upstream node.
//! 2. For each UTXO, fetch the funding transaction with `get_transaction`
//!    and authenticate the output (v1.4.2 Fix 1) — verify the strict
//!    deserialization, the txid match, and the locking-script byte
//!    equality. This makes us robust against a malicious RPC understating
//!    `value` or forging scripts.
//! 3. Build the spending transaction locally with `Wallet::build_transaction`,
//!    which signs each input with the wallet's Ed25519 private key.
//! 4. Serialize and broadcast the bytes via `send_raw_transaction`.

use exfer::chain::state::{UtxoEntry, UtxoSet};
use exfer::types::transaction::OutPoint;
use exfer::types::Hash256;
use exfer::wallet::auth::authenticate_tx_hex;
use exfer::wallet::wallet::Wallet;

use crate::error::{Error, Result};
use crate::upstream::ExferNode;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TransferReceipt {
    pub tx_id:      String,
    pub size:       usize,
    pub tip_height: u64,
    pub submitted:  bool,
}

/// Build, sign, broadcast a transfer of `amount_exfers` from `wallet` to
/// `recipient`, paying `fee_exfers` to the miner. Returns the broadcast
/// receipt.
pub async fn transfer(
    wallet:        &Wallet,
    recipient:     Hash256,
    amount_exfers: u64,
    fee_exfers:    u64,
    node:          &ExferNode,
) -> Result<TransferReceipt> {
    let sender_addr_hex = hex::encode(wallet.address().as_bytes());

    // ---- Step 1: list candidate UTXOs from the node ----
    let utxos = node.get_address_utxos(&sender_addr_hex).await?;
    let tip_height = utxos.tip_height;
    let current_height = tip_height.saturating_add(1);

    // ---- Step 2: authenticate each UTXO ----
    let wallet_script = wallet.address().as_bytes().to_vec();
    let mut utxo_set = UtxoSet::new();

    for entry in &utxos.utxos {
        let tx_id_bytes = decode_hash(&entry.tx_id)?;
        let tx_id = Hash256(tx_id_bytes);

        // Fetch the funding transaction.
        let funding = node.get_transaction(&entry.tx_id).await?;
        let raw = hex::decode(&funding.tx_hex)
            .map_err(|e| Error::UtxoAuth(format!("funding tx_hex not hex: {e}")))?;

        // Authenticate: strict deserialize, txid match, script equality.
        let (auth_value, _auth_script) =
            authenticate_tx_hex(&raw, tx_id, entry.output_index, Some(&wallet_script))
                .map_err(|e| Error::UtxoAuth(e.to_string()))?;

        let outpoint = OutPoint {
            tx_id,
            output_index: entry.output_index,
        };
        let utxo_entry = UtxoEntry {
            output: exfer::types::transaction::TxOutput {
                value:      auth_value,
                script:     wallet_script.clone(),
                datum:      None,
                datum_hash: None,
            },
            height:      entry.height,
            is_coinbase: entry.is_coinbase,
        };
        utxo_set
            .insert(outpoint, utxo_entry)
            .map_err(|e| Error::Internal(format!("utxo insert: {e:?}")))?;
    }

    // ---- Step 3: build + sign locally ----
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

    // ---- Step 4: broadcast ----
    let tx_hex = hex::encode(&serialized);
    let sent = node.send_raw_transaction(&tx_hex).await?;

    // Self-check: the node's reported tx_id should match what we computed.
    let our_tx_id_hex = hex::encode(tx_id.as_bytes());
    if sent.tx_id != our_tx_id_hex {
        return Err(Error::UpstreamUnexpected(format!(
            "node returned tx_id {} but we computed {our_tx_id_hex}",
            sent.tx_id
        )));
    }

    Ok(TransferReceipt {
        tx_id:      our_tx_id_hex,
        size:       serialized.len(),
        tip_height,
        submitted:  true,
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
