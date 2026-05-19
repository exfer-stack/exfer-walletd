//! `sign_message` / `verify_message` — proof-of-ownership signatures.
//!
//! Lets a wallet holder produce an Ed25519 signature over an arbitrary
//! UTF-8 message, and lets anyone verify such a signature given the
//! signer's pubkey. Pure in-process crypto — zero upstream calls.
//!
//! ## Domain separation
//!
//! Signed bytes are `b"EXFER-MSG" || message.as_bytes()`. The fixed
//! prefix prevents a message signature from ever being mistaken for a
//! transaction signature: transactions sign
//! `b"EXFER-SIG" || genesis_block_id || tx_signing_bytes` (see
//! `exfer::types::transaction::Transaction::sig_message`). Different
//! 9-byte prefix → no collision possible at byte 0.
//!
//! ## Scope
//!
//! `sign_message` is `Scope::Spend`: it doesn't move funds, but it
//! produces a verifiable claim of ownership, which is value-bearing in
//! exchange / KYC contexts. A leaked read-only token must not be able
//! to mint proofs of ownership.
//!
//! `verify_message` is `Scope::Read`: pure verification, no key access.

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey, SIGNATURE_LENGTH};
use exfer::types::Hash256;
use serde::{Deserialize, Serialize};

use crate::api::{ensure_64_hex, ApiState};
use crate::error::{Error, Result};

/// Domain separator for message signatures. Distinct from `EXFER-SIG`
/// (transactions) and any other domain used by the chain.
pub const MSG_DOMAIN: &[u8] = b"EXFER-MSG";

/// Address derivation in Exfer Phase 1: `address = H(DS_ADDR || pubkey)`.
/// Mirrors `TxOutput::pubkey_hash_from_key` so the value we return here
/// is byte-identical to what an output script would lock to.
fn address_for_pubkey(pubkey: &[u8; 32]) -> Hash256 {
    use exfer::types::transaction::TxOutput;
    TxOutput::pubkey_hash_from_key(pubkey)
}

fn domain_message(message: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(MSG_DOMAIN.len() + message.len());
    buf.extend_from_slice(MSG_DOMAIN);
    buf.extend_from_slice(message.as_bytes());
    buf
}

#[derive(Debug, Deserialize)]
pub struct SignMessageParams {
    pub address: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
struct SignMessageResult {
    signature: String,
    pubkey: String,
    address: String,
}

pub async fn sign_message(state: &ApiState, params: serde_json::Value) -> Result<serde_json::Value> {
    let p: SignMessageParams = serde_json::from_value(params)
        .map_err(|e| Error::BadEnvelope(format!("sign_message params: {e}")))?;
    ensure_64_hex(&p.address)?;

    // Wallet load is sync FS I/O — match the transfer path's blocking
    // pattern so we don't tie up a tokio runtime thread.
    let store = state.store.clone();
    let addr = p.address.clone();
    let wallet = tokio::task::spawn_blocking(move || store.load(&addr))
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;

    let signing_key = wallet.signing_key_for_cli();
    let signature: Signature = signing_key.sign(&domain_message(&p.message));
    let pubkey = wallet.pubkey();

    let result = SignMessageResult {
        signature: hex::encode(signature.to_bytes()),
        pubkey: hex::encode(pubkey),
        address: hex::encode(wallet.address().as_bytes()),
    };
    serde_json::to_value(&result).map_err(|e| Error::Internal(e.to_string()))
}

#[derive(Debug, Deserialize)]
pub struct VerifyMessageParams {
    pub pubkey: String,
    pub signature: String,
    pub message: String,
    /// Optional — if set, walletd also checks that `H(DS_ADDR || pubkey)`
    /// equals this address. Lets the caller verify "the holder of the
    /// key behind this address signed `message`" in one call.
    #[serde(default)]
    pub address: Option<String>,
}

#[derive(Debug, Serialize)]
struct VerifyMessageResult {
    valid: bool,
    /// The address computed from `pubkey` — always returned so a caller
    /// learning what the pubkey actually hashes to gets it even when
    /// `valid` is `false`.
    address: String,
}

pub async fn verify_message(
    _state: &ApiState,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    let p: VerifyMessageParams = serde_json::from_value(params)
        .map_err(|e| Error::BadEnvelope(format!("verify_message params: {e}")))?;
    ensure_64_hex(&p.pubkey)?;
    if let Some(a) = p.address.as_deref() {
        ensure_64_hex(a)?;
    }

    let pubkey_bytes: [u8; 32] = hex::decode(&p.pubkey)
        .map_err(|e| Error::BadHex(format!("pubkey: {e}")))?
        .try_into()
        .map_err(|v: Vec<u8>| Error::BadAddressLen(v.len()))?;
    let sig_bytes = hex::decode(&p.signature)
        .map_err(|e| Error::BadHex(format!("signature: {e}")))?;
    if sig_bytes.len() != SIGNATURE_LENGTH {
        return Err(Error::BadEnvelope(format!(
            "signature: expected {} bytes, got {}",
            SIGNATURE_LENGTH,
            sig_bytes.len()
        )));
    }
    let mut sig_arr = [0u8; SIGNATURE_LENGTH];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    let computed_address = hex::encode(address_for_pubkey(&pubkey_bytes).as_bytes());

    let sig_ok = VerifyingKey::from_bytes(&pubkey_bytes)
        .ok()
        .map(|vk| vk.verify(&domain_message(&p.message), &signature).is_ok())
        .unwrap_or(false);

    let addr_ok = match p.address.as_deref() {
        Some(claimed) => claimed.eq_ignore_ascii_case(&computed_address),
        None => true,
    };

    let result = VerifyMessageResult {
        valid: sig_ok && addr_ok,
        address: computed_address,
    };
    serde_json::to_value(&result).map_err(|e| Error::Internal(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn fresh_keypair() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let (sk, pk) = fresh_keypair();
        let msg = "challenge:nonce-1234abcd";
        let sig = sk.sign(&domain_message(msg));

        let vk = VerifyingKey::from_bytes(&pk).unwrap();
        assert!(vk.verify(&domain_message(msg), &sig).is_ok());
    }

    #[test]
    fn tampered_message_fails_verify() {
        let (sk, pk) = fresh_keypair();
        let sig = sk.sign(&domain_message("original"));
        let vk = VerifyingKey::from_bytes(&pk).unwrap();
        assert!(vk.verify(&domain_message("tampered"), &sig).is_err());
    }

    #[test]
    fn tx_signature_cannot_be_replayed_as_message_signature() {
        // A signature over `EXFER-SIG || ...` MUST NOT verify under the
        // message-signing domain (`EXFER-MSG || ...`). This is the
        // whole point of domain separation.
        let (sk, pk) = fresh_keypair();
        let mut tx_like = b"EXFER-SIG".to_vec();
        tx_like.extend_from_slice(&[0u8; 32]); // fake genesis_id
        tx_like.extend_from_slice(b"some-tx-bytes");
        let tx_sig = sk.sign(&tx_like);

        // Same trailing bytes, but under the message domain.
        let vk = VerifyingKey::from_bytes(&pk).unwrap();
        let msg = std::str::from_utf8(&tx_like[b"EXFER-SIG".len()..]).unwrap_or("");
        assert!(
            vk.verify(&domain_message(msg), &tx_sig).is_err(),
            "domain separation broken — tx sig must NOT verify as msg sig"
        );
    }

    #[test]
    fn address_derivation_matches_chain() {
        let (_sk, pk) = fresh_keypair();
        let our = address_for_pubkey(&pk);
        let chain = exfer::types::transaction::TxOutput::pubkey_hash_from_key(&pk);
        assert_eq!(our.as_bytes(), chain.as_bytes());
    }
}
