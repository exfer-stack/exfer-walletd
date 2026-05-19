//! One-shot helper: decrypt an existing encrypted wallet file and
//! re-save it unencrypted into a walletd wallets/ directory (named
//! `<address>.key`).
//!
//! Usage:
//!     cargo run --example import_encrypted -- \
//!         <encrypted-key-path> <passphrase-path> <walletd-wallets-dir>
//!
//! NOT for production. Test fixture only — walletd's normal contract
//! is that keys are managed by `generate_address`, not imported.

use std::path::PathBuf;

use exfer::wallet::wallet::Wallet;

fn main() {
    let mut args = std::env::args().skip(1);
    let key_path: PathBuf = args.next().expect("encrypted key path").into();
    let passphrase_path: PathBuf = args.next().expect("passphrase file").into();
    let dest_dir: PathBuf = args.next().expect("destination wallets dir").into();

    let pass = std::fs::read_to_string(&passphrase_path)
        .expect("read passphrase")
        .trim()
        .to_string();

    let w = Wallet::load(&key_path, Some(pass.as_bytes())).expect("decrypt wallet");
    let addr = hex::encode(w.address().as_bytes());
    std::fs::create_dir_all(&dest_dir).expect("mkdir dest");
    let out = dest_dir.join(format!("{addr}.key"));
    w.save_unencrypted(&out).expect("save unencrypted");
    eprintln!("imported {addr} → {}", out.display());
}
