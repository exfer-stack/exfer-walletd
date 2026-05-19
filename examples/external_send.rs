//! Standalone "external user" send helper. Reads an encrypted wallet,
//! builds + signs + broadcasts a transfer through an HTTPS-capable
//! upstream — the exfer v1.9 CLI can only do raw TCP (no TLS), and the
//! HTTP backup nodes have been intermittently failing on broadcast.
//!
//! Used by the exchange-scenario test fixture to play the "external
//! depositor" role: from outside walletd's wallet store, fund a
//! walletd-managed deposit address.
//!
//! Usage:
//!   cargo run --release --example external_send -- \
//!       <encrypted_key>  <passphrase_file>  <to_hex>  <amount_exfers>  <fee_exfers>  <rpc_url>
//!
//! NOT a production tool. Test fixture only.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use exfer::types::Hash256;
use exfer::wallet::wallet::Wallet;

use exfer_walletd::cache::WalletCache;
use exfer_walletd::inflight::InFlightUtxos;
use exfer_walletd::store::{FsWalletStore, WalletStore};
use exfer_walletd::tx::transfer;
use exfer_walletd::upstream::ExferNode;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let key_path: PathBuf = args.next().expect("encrypted key path").into();
    let pass_path: PathBuf = args.next().expect("passphrase file").into();
    let to_hex: String = args.next().expect("recipient hex");
    let amount: u64 = args.next().expect("amount in exfers").parse()?;
    let fee: u64 = args.next().expect("fee in exfers").parse()?;
    let rpc: String = args.next().expect("rpc url");

    let pass = std::fs::read_to_string(&pass_path)?.trim().to_string();
    let wallet = Wallet::load(&key_path, Some(pass.as_bytes()))?;
    let from = hex::encode(wallet.address().as_bytes());
    eprintln!("external sender = {from}");

    let to_bytes = hex::decode(&to_hex)?;
    if to_bytes.len() != 32 {
        return Err(format!("recipient must be 32 bytes hex, got {}", to_bytes.len()).into());
    }
    let mut to_arr = [0u8; 32];
    to_arr.copy_from_slice(&to_bytes);
    let recipient = Hash256(to_arr);

    let node = Arc::new(ExferNode::new(&rpc, Duration::from_secs(30))?);
    let inflight = InFlightUtxos::new();

    // Throwaway in-memory store + disabled cache — `transfer()`
    // demands them but on the external path the cache hook is a no-op
    // and the store is only used to detect "to ∈ store" for bilateral
    // invalidation (which we don't want anyway: this `to` is in
    // walletd, but THIS process isn't walletd, so we treat it as
    // external from our standpoint).
    let tmp = tempfile::tempdir()?;
    let store: Arc<dyn WalletStore> = Arc::new(FsWalletStore::open(tmp.path())?);
    let cache = WalletCache::disabled();

    let receipt = transfer(
        &wallet, recipient, amount, fee, &node, &inflight, &cache, &*store,
    )
    .await?;

    println!(
        "{{\"tx_id\":\"{}\",\"size\":{},\"tip_height\":{},\"submitted\":{}}}",
        receipt.tx_id, receipt.size, receipt.tip_height, receipt.submitted
    );
    eprintln!("OK broadcast tx {}", receipt.tx_id);
    Ok(())
}
