//! BSC / EVM leg of the cross-chain swap.
//!
//! Keeps secret material inside the daemon: the swap engine derives the BSC
//! secp256k1 key via [`crate::store::WalletStore::evm_secret`] and hands the raw
//! 32 bytes here only to sign. We use `alloy` for EIP-1559 encoding + signing
//! and ABI encoding, but deliberately NOT alloy's provider/transport stack —
//! all chain I/O goes over a plain `reqwest` JSON-RPC client so the mobile
//! cross-compile stays lean.
//!
//! ```text
//!  swap engine ──evm_secret()──▶ EvmClient
//!                                  │ eth_sendRawTransaction (signed EIP-1559)
//!                                  │ eth_call / eth_getTransactionCount / ...
//!                                  ▼
//!                              BSC node ──▶ ExferHtlc.sol + USDT (BEP-20)
//! ```

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy::eips::eip2718::Encodable2718;
use alloy::primitives::{Address, Bytes, TxKind, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy::sol;
use alloy::sol_types::SolCall;
use serde_json::{json, Value};

use crate::error::{Error, Result};

// ───────────────────────── ABI ─────────────────────────

sol! {
    function approve(address spender, uint256 value) external returns (bool);
    function balanceOf(address owner) external view returns (uint256);
    function lock(bytes32 hashlock, address recipient, address token, uint256 amount, uint64 timeoutSec) external;
    function claim(bytes32 preimage) external;
    function refund(bytes32 hashlock) external;
    function getSwap(bytes32 hashlock) external view returns (address sender, address recipient, address token, uint256 amount, uint64 timeoutSec, uint8 state);
}

/// On-chain HTLC state mirror (ExferHtlc.sol `enum State`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HtlcState {
    None,
    Locked,
    Claimed,
    Refunded,
}

impl HtlcState {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => HtlcState::Locked,
            2 => HtlcState::Claimed,
            3 => HtlcState::Refunded,
            _ => HtlcState::None,
        }
    }
}

/// Result of reading a swap from the HTLC contract.
#[derive(Debug, Clone)]
pub struct OnChainSwap {
    pub recipient: Address,
    pub amount: U256,
    pub timeout_sec: u64,
    pub state: HtlcState,
}

// ───────────────────────── key / address ─────────────────────────

fn signer_from_secret(secret: &[u8; 32]) -> Result<PrivateKeySigner> {
    PrivateKeySigner::from_slice(secret)
        .map_err(|e| Error::Internal(format!("invalid BSC secp256k1 secret: {e}")))
}

/// EIP-55 checksummed BSC address for the wallet's derived secp256k1 key.
pub fn evm_address(secret: &[u8; 32]) -> Result<String> {
    Ok(signer_from_secret(secret)?.address().to_checksum(None))
}

fn parse_address(s: &str) -> Result<Address> {
    s.parse::<Address>()
        .map_err(|e| Error::BadParams(format!("bad EVM address {s}: {e}")))
}

fn parse_b256(s: &str) -> Result<B256> {
    let h = s.trim_start_matches("0x");
    let bytes = hex::decode(h).map_err(|e| Error::BadParams(format!("bad 32-byte hex {s}: {e}")))?;
    if bytes.len() != 32 {
        return Err(Error::BadParams(format!("expected 32 bytes, got {}", bytes.len())));
    }
    Ok(B256::from_slice(&bytes))
}

// ───────────────────────── client ─────────────────────────

#[derive(Clone)]
pub struct EvmClient {
    http: reqwest::Client,
    rpc_url: String,
    chain_id: u64,
}

/// Minimum priority fee on BSC (1 gwei).
const MIN_PRIORITY_FEE_WEI: u128 = 1_000_000_000;
/// Hard cap on gas limit so a bad estimate can't drain BNB.
const GAS_LIMIT_CAP: u64 = 800_000;

impl EvmClient {
    pub fn new(rpc_url: impl Into<String>, chain_id: u64) -> Self {
        Self {
            http: reqwest::Client::new(),
            rpc_url: rpc_url.into(),
            chain_id,
        }
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp: Value = self
            .http
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::UpstreamUnreachable(format!("BSC {method}: {e}")))?
            .json()
            .await
            .map_err(|e| Error::UpstreamUnexpected(format!("BSC {method} decode: {e}")))?;
        if let Some(err) = resp.get("error") {
            let code = err.get("code").and_then(Value::as_i64).unwrap_or(0) as i32;
            let message = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("(no message)")
                .to_string();
            return Err(Error::UpstreamRpc { code, message });
        }
        resp.get("result")
            .cloned()
            .ok_or_else(|| Error::UpstreamUnexpected(format!("BSC {method}: no result")))
    }

    fn result_hex(v: &Value) -> Result<&str> {
        v.as_str()
            .ok_or_else(|| Error::UpstreamUnexpected("expected hex string result".into()))
    }

    fn hex_to_u64(s: &str) -> Result<u64> {
        u64::from_str_radix(s.trim_start_matches("0x"), 16)
            .map_err(|e| Error::UpstreamUnexpected(format!("bad u64 hex {s}: {e}")))
    }

    fn hex_to_u128(s: &str) -> Result<u128> {
        u128::from_str_radix(s.trim_start_matches("0x"), 16)
            .map_err(|e| Error::UpstreamUnexpected(format!("bad u128 hex {s}: {e}")))
    }

    fn hex_to_u256(s: &str) -> Result<U256> {
        U256::from_str_radix(s.trim_start_matches("0x"), 16)
            .map_err(|e| Error::UpstreamUnexpected(format!("bad u256 hex {s}: {e}")))
    }

    // ---- reads ----

    /// Pending nonce for `addr` (accounts for in-flight txs).
    pub async fn pending_nonce(&self, addr: Address) -> Result<u64> {
        let r = self
            .rpc("eth_getTransactionCount", json!([addr.to_checksum(None), "pending"]))
            .await?;
        Self::hex_to_u64(Self::result_hex(&r)?)
    }

    /// Native BNB balance (wei).
    pub async fn bnb_balance(&self, addr: Address) -> Result<U256> {
        let r = self
            .rpc("eth_getBalance", json!([addr.to_checksum(None), "latest"]))
            .await?;
        Self::hex_to_u256(Self::result_hex(&r)?)
    }

    /// BEP-20 token balance (smallest units).
    pub async fn erc20_balance(&self, token: Address, owner: Address) -> Result<U256> {
        let data = balanceOfCall { owner }.abi_encode();
        let out = self.eth_call(token, &data).await?;
        Ok(U256::from_be_slice(&out))
    }

    /// Read a swap entry from the HTLC contract.
    pub async fn get_swap(&self, htlc: Address, hashlock: B256) -> Result<OnChainSwap> {
        let data = getSwapCall { hashlock }.abi_encode();
        let out = self.eth_call(htlc, &data).await?;
        let dec = getSwapCall::abi_decode_returns(&out)
            .map_err(|e| Error::UpstreamUnexpected(format!("getSwap decode: {e}")))?;
        Ok(OnChainSwap {
            recipient: dec.recipient,
            amount: dec.amount,
            timeout_sec: dec.timeoutSec,
            state: HtlcState::from_u8(dec.state),
        })
    }

    async fn eth_call(&self, to: Address, data: &[u8]) -> Result<Vec<u8>> {
        let r = self
            .rpc(
                "eth_call",
                json!([{ "to": to.to_checksum(None), "data": format!("0x{}", hex::encode(data)) }, "latest"]),
            )
            .await?;
        let hexstr = Self::result_hex(&r)?;
        hex::decode(hexstr.trim_start_matches("0x"))
            .map_err(|e| Error::UpstreamUnexpected(format!("eth_call result decode: {e}")))
    }

    async fn gas_price(&self) -> Result<u128> {
        let r = self.rpc("eth_gasPrice", json!([])).await?;
        Self::hex_to_u128(Self::result_hex(&r)?)
    }

    async fn estimate_gas(&self, from: Address, to: Address, data: &[u8]) -> Result<u64> {
        let r = self
            .rpc(
                "eth_estimateGas",
                json!([{
                    "from": from.to_checksum(None),
                    "to": to.to_checksum(None),
                    "data": format!("0x{}", hex::encode(data)),
                }]),
            )
            .await?;
        let est = Self::hex_to_u64(Self::result_hex(&r)?)?;
        // +25% headroom, capped.
        Ok((est.saturating_mul(125) / 100).min(GAS_LIMIT_CAP))
    }

    // ---- writes (build + sign + send) ----

    /// Build, sign and broadcast an EIP-1559 call. Returns the tx hash.
    /// Caller is responsible for serializing concurrent sends from the same
    /// account (nonce safety) — the swap engine holds a per-account lock.
    async fn send_call(&self, secret: &[u8; 32], to: Address, data: Vec<u8>) -> Result<String> {
        let signer = signer_from_secret(secret)?;
        let from = signer.address();

        let nonce = self.pending_nonce(from).await?;
        let gas_price = self.gas_price().await?;
        let max_priority_fee_per_gas = MIN_PRIORITY_FEE_WEI;
        let max_fee_per_gas = gas_price.saturating_add(max_priority_fee_per_gas);
        let gas_limit = self.estimate_gas(from, to, &data).await?;

        let tx = TxEip1559 {
            chain_id: self.chain_id,
            nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            to: TxKind::Call(to),
            value: U256::ZERO,
            access_list: Default::default(),
            input: Bytes::from(data),
        };

        let sighash = tx.signature_hash();
        let sig = signer
            .sign_hash_sync(&sighash)
            .map_err(|e| Error::Internal(format!("BSC sign failed: {e}")))?;
        let signed = tx.into_signed(sig);
        let envelope: TxEnvelope = signed.into();
        let mut raw = Vec::new();
        envelope.encode_2718(&mut raw);

        let r = self
            .rpc("eth_sendRawTransaction", json!([format!("0x{}", hex::encode(raw))]))
            .await?;
        Ok(Self::result_hex(&r)?.to_string())
    }

    /// `approve(spender, MAX)` on a BEP-20 token.
    pub async fn approve_max(&self, secret: &[u8; 32], token: &str, spender: &str) -> Result<String> {
        let data = approveCall {
            spender: parse_address(spender)?,
            value: U256::MAX,
        }
        .abi_encode();
        self.send_call(secret, parse_address(token)?, data).await
    }

    /// Current token allowance owner→spender (smallest units). Lets the engine
    /// skip a redundant approve.
    pub async fn allowance(&self, token: &str, owner: Address, spender: &str) -> Result<U256> {
        // allowance(address,address) selector + args, hand-encoded (not in the
        // sol! block above to keep it minimal).
        let mut data = Vec::with_capacity(4 + 64);
        data.extend_from_slice(&alloy::primitives::keccak256("allowance(address,address)")[..4]);
        data.extend_from_slice(B256::left_padding_from(owner.as_slice()).as_slice());
        data.extend_from_slice(B256::left_padding_from(parse_address(spender)?.as_slice()).as_slice());
        let out = self.eth_call(parse_address(token)?, &data).await?;
        Ok(U256::from_be_slice(&out))
    }

    /// `lock(hashlock, recipient, token, amount, timeoutSec)` on the HTLC.
    pub async fn htlc_lock(
        &self,
        secret: &[u8; 32],
        htlc: &str,
        hashlock: &str,
        recipient: &str,
        token: &str,
        amount: U256,
        timeout_sec: u64,
    ) -> Result<String> {
        let data = lockCall {
            hashlock: parse_b256(hashlock)?,
            recipient: parse_address(recipient)?,
            token: parse_address(token)?,
            amount,
            timeoutSec: timeout_sec,
        }
        .abi_encode();
        self.send_call(secret, parse_address(htlc)?, data).await
    }

    /// `claim(preimage)` — reveal the preimage to receive the locked USDT.
    pub async fn htlc_claim(&self, secret: &[u8; 32], htlc: &str, preimage: &str) -> Result<String> {
        let data = claimCall { preimage: parse_b256(preimage)? }.abi_encode();
        self.send_call(secret, parse_address(htlc)?, data).await
    }

    /// `refund(hashlock)` — reclaim our own expired lock (sender arm).
    pub async fn htlc_refund(&self, secret: &[u8; 32], htlc: &str, hashlock: &str) -> Result<String> {
        let data = refundCall { hashlock: parse_b256(hashlock)? }.abi_encode();
        self.send_call(secret, parse_address(htlc)?, data).await
    }

    /// Receipt status: `Some(true)` = success, `Some(false)` = reverted,
    /// `None` = not yet mined.
    pub async fn receipt_status(&self, txhash: &str) -> Result<Option<bool>> {
        let r = self
            .rpc("eth_getTransactionReceipt", json!([txhash]))
            .await?;
        if r.is_null() {
            return Ok(None);
        }
        let status = r.get("status").and_then(Value::as_str).unwrap_or("0x0");
        Ok(Some(Self::hex_to_u64(status)? == 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known BIP-39 test vector → standard Ethereum address at m/44'/60'/0'/0/0.
    // Mnemonic: "test test test test test test test test test test test junk"
    // (the canonical Foundry/anvil default). Account 0 address:
    //   0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
    // We assert our secp256k1 + EIP-55 path reproduces it, proving the BSC
    // address matches what MetaMask shows for the same mnemonic.
    #[test]
    fn evm_address_matches_known_vector() {
        let seed = bip39::Mnemonic::parse_normalized(
            "test test test test test test test test test test test junk",
        )
        .unwrap()
        .to_seed("");
        let path: bip32::DerivationPath = "m/44'/60'/0'/0/0".parse().unwrap();
        let xprv = bip32::XPrv::derive_from_path(&seed[..], &path).unwrap();
        let mut secret = [0u8; 32];
        secret.copy_from_slice(xprv.private_key().to_bytes().as_slice());
        let addr = evm_address(&secret).unwrap();
        assert_eq!(addr, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    }

    #[test]
    fn htlc_state_decode() {
        assert_eq!(HtlcState::from_u8(0), HtlcState::None);
        assert_eq!(HtlcState::from_u8(1), HtlcState::Locked);
        assert_eq!(HtlcState::from_u8(2), HtlcState::Claimed);
        assert_eq!(HtlcState::from_u8(3), HtlcState::Refunded);
    }

    #[test]
    fn abi_encode_claim_has_selector() {
        let data = claimCall {
            preimage: B256::repeat_byte(0xAB),
        }
        .abi_encode();
        // selector(claim(bytes32)) = keccak("claim(bytes32)")[..4]
        let sel = &alloy::primitives::keccak256("claim(bytes32)")[..4];
        assert_eq!(&data[..4], sel);
        assert_eq!(data.len(), 4 + 32);
    }
}
