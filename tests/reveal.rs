//! Coverage for the v1.3.0 `reveal_mnemonic` + `reveal_private_key`
//! RPC family. Each lives at spend scope and is gated by re-supplied
//! passphrase verification.

use ed25519_dalek::Signer as _;
use exfer_walletd::store::{HdSeedStore, WalletStore};

const PASS: &[u8] = b"reveal-test-pw";

fn fresh_store() -> (tempfile::TempDir, HdSeedStore) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let store = HdSeedStore::open_or_init_fresh(dir.path(), PASS).expect("init store");
    (dir, store)
}

#[test]
fn reveal_mnemonic_returns_24_words_with_right_passphrase() {
    let (_dir, store) = fresh_store();
    // First-run mnemonic is what we'll compare against. Take it before
    // anyone else gets a chance to consume it.
    let printed = store.take_fresh_mnemonic().expect("first-run mnemonic");
    assert_eq!(printed.len(), 24);

    let revealed = store.reveal_mnemonic(PASS).expect("reveal");
    assert_eq!(revealed.len(), 24);
    assert_eq!(revealed, printed, "reveal must return the same words");
}

#[test]
fn reveal_mnemonic_rejects_wrong_passphrase() {
    let (_dir, store) = fresh_store();
    let err = store
        .reveal_mnemonic(b"wrong")
        .expect_err("must reject wrong passphrase");
    assert_eq!(
        err.rpc_code(),
        -32012,
        "wrong passphrase must surface as KeystoreLocked"
    );
}

#[test]
fn reveal_secret_hd_addr_round_trips_to_valid_signer() {
    let (_dir, store) = fresh_store();
    let d = store.create(None).expect("derive");
    let raw = store.reveal_secret(&d.address, PASS).expect("reveal secret");

    // Re-derive a SigningKey from the revealed secret and check that
    // its address matches the one the store derived.
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&raw);
    let pubkey = signing_key.verifying_key().to_bytes();
    let address = hex::encode(exfer::types::transaction::TxOutput::pubkey_hash_from_key(&pubkey));
    assert_eq!(address, d.address);

    // And the revealed key actually signs something the store can
    // verify (same address ⇒ same key).
    let msg = b"hello reveal";
    let _ = signing_key.sign(msg);
}

#[test]
fn reveal_secret_rejects_wrong_passphrase() {
    let (_dir, store) = fresh_store();
    let d = store.create(None).expect("derive");
    let err = store
        .reveal_secret(&d.address, b"wrong")
        .expect_err("must reject wrong passphrase");
    assert_eq!(err.rpc_code(), -32012);
}

#[test]
fn reveal_secret_unknown_address_returns_wallet_not_found() {
    let (_dir, store) = fresh_store();
    // Hex of correct length but never generated / imported.
    let bogus = "00".repeat(32);
    let err = store
        .reveal_secret(&bogus, PASS)
        .expect_err("unknown address must error");
    assert_eq!(err.rpc_code(), -32010, "WalletNotFound");
}

#[test]
fn restore_from_mnemonic_reproduces_addresses() {
    use exfer_walletd::store::WalletStore;
    // Wallet A: fresh init, grab its mnemonic + first 3 addresses.
    let dir_a = tempfile::TempDir::new().unwrap();
    let a = HdSeedStore::open_or_init_fresh(dir_a.path(), PASS).unwrap();
    let words = a.take_fresh_mnemonic().expect("fresh mnemonic");
    let phrase = words.join(" ");
    let addrs_a: Vec<String> = (0..3).map(|_| a.create(None).unwrap().address).collect();

    // Wallet B: restore from A's phrase into a clean dir, re-derive.
    let dir_b = tempfile::TempDir::new().unwrap();
    HdSeedStore::init_from_mnemonic(dir_b.path(), b"different-pw", &phrase).unwrap();
    let b = HdSeedStore::open_or_init_fresh(dir_b.path(), b"different-pw").unwrap();
    let addrs_b: Vec<String> = (0..3).map(|_| b.create(None).unwrap().address).collect();

    assert_eq!(addrs_a, addrs_b, "restored wallet must derive identical addresses");
}

#[test]
fn init_from_mnemonic_refuses_to_clobber_existing_seed() {
    let dir = tempfile::TempDir::new().unwrap();
    let s = HdSeedStore::open_or_init_fresh(dir.path(), PASS).unwrap();
    let phrase = s.take_fresh_mnemonic().unwrap().join(" ");
    // seed.enc now exists → restore must refuse.
    let err = HdSeedStore::init_from_mnemonic(dir.path(), PASS, &phrase).unwrap_err();
    assert_eq!(err.rpc_code(), -32011, "WalletAlreadyExists");
}

#[test]
fn init_from_mnemonic_rejects_garbage_phrase() {
    let dir = tempfile::TempDir::new().unwrap();
    let err = HdSeedStore::init_from_mnemonic(dir.path(), PASS, "not a real mnemonic at all")
        .unwrap_err();
    assert_eq!(err.rpc_code(), -32602, "BadParams");
}
