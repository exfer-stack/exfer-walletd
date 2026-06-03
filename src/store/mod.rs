//! Wallet keystore.
//!
//! Keyring model: the wallet is a flat collection of independent keys,
//! each individually exportable, importable, and deletable. A key can
//! originate three ways — generated independent (1:1, its own sealed
//! file), imported (a raw secret or a 24-word phrase), or HD-derived from
//! an optional legacy seed. No single secret governs the others: every
//! address has its OWN 24-word recovery phrase (its 256-bit ed25519
//! secret encoded as BIP-39), and the vault backs up the whole keyring in
//! one passphrase-sealed file.
//!
//! The HD seed is a backward-compatible *origin*, not the spine: existing
//! seed wallets keep deriving and their seed mnemonic still works, but new
//! addresses default to independent keys and backup no longer hinges on a
//! single mnemonic. See `keyring::KeyringStore` for the on-disk layout.
//!
//! Everything in this module is filesystem-backed; the trait stays
//! abstract so future backends (cloud KMS, HSM) can drop in.

pub mod keyring;
pub mod sealed;

use ed25519_dalek::SigningKey;
use exfer::types::transaction::TxOutput;
use exfer::types::Hash256;
use serde::Serialize;

use crate::error::Result;

pub use keyring::KeyringStore;
/// Backward-compatible alias. The keystore was renamed `HdSeedStore`
/// → `KeyringStore` when the model flipped from "one seed derives all" to
/// a flat keyring; downstream crates (the desktop) still import the old
/// name.
pub use keyring::KeyringStore as HdSeedStore;

// ----------------------------------------------------------------------------
// Signer — the only thing the rest of walletd needs from a loaded key
// ----------------------------------------------------------------------------

/// A loaded keypair in memory. Returned by every `WalletStore::load_*`
/// method. Holds the Ed25519 signing key plus the cached pubkey /
/// address so callers don't recompute the hash on every use.
#[derive(Clone)]
pub struct Signer {
    signing_key: SigningKey,
    pubkey: [u8; 32],
    address: Hash256,
}

impl Signer {
    /// Build a signer from a raw 32-byte ed25519 secret. The pubkey and
    /// address are derived once and cached.
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(secret);
        let pubkey = signing_key.verifying_key().to_bytes();
        let address = TxOutput::pubkey_hash_from_key(&pubkey);
        Self {
            signing_key,
            pubkey,
            address,
        }
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
    pub fn pubkey(&self) -> [u8; 32] {
        self.pubkey
    }
    pub fn address(&self) -> Hash256 {
        self.address
    }
    pub fn address_hex(&self) -> String {
        hex::encode(self.address.as_bytes())
    }
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // NEVER print the private key.
        f.debug_struct("Signer")
            .field("address", &self.address_hex())
            .finish()
    }
}

// ----------------------------------------------------------------------------
// Public DTOs
// ----------------------------------------------------------------------------

/// Result of `WalletStore::create`. Carries enough for callers (the
/// `generate_address` RPC) to assemble the JSON response.
#[derive(Debug, Clone, Serialize)]
pub struct DerivedAddress {
    pub address: String,
    pub pubkey: String,
    pub index: u32,
}

/// One row of `WalletStore::list`.
#[derive(Debug, Clone, Serialize)]
pub struct AddressEntry {
    pub address: String,
    /// HD derivation index; `None` for imported (non-derived) addresses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
    /// Operator-supplied label (e.g. "user-123"); `None` if unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// True iff this address came from a legacy `.key` import rather
    /// than HD derivation.
    pub imported: bool,
}

// ----------------------------------------------------------------------------
// Trait
// ----------------------------------------------------------------------------

pub trait WalletStore: Send + Sync + 'static {
    /// Derive the next HD address and persist `next_index`. Optional
    /// label is attached to the new address.
    fn create(&self, label: Option<String>) -> Result<DerivedAddress>;

    /// Load a signer for the given 64-hex address. Works for both
    /// derived and imported addresses.
    fn load_by_address(&self, address_hex: &str) -> Result<Signer>;

    /// Derive the wallet's canonical BSC/EVM secp256k1 secret key (BIP-32
    /// path `m/44'/60'/0'/0/0`) from the HD seed — the same 64-byte BIP-39
    /// seed the EXFER ed25519 keys come from, so the resulting BSC address is
    /// reproducible from the user's mnemonic (and importable into MetaMask).
    /// Errors on a seedless keyring. Used only by the cross-chain swap engine;
    /// the secret never leaves the daemon.
    fn evm_secret(&self) -> Result<zeroize::Zeroizing<[u8; 32]>>;

    /// Seal arbitrary auxiliary data (the pending-swap journal) with the
    /// keystore passphrase + caller-chosen AAD. Same Argon2id + ChaCha20-Poly1305
    /// scheme as the seed, so swap secrets (preimages) live at the same security
    /// bar as private keys.
    fn seal_aux(&self, aad: &[u8], payload: &[u8]) -> Result<Vec<u8>>;

    /// Inverse of [`seal_aux`]. Wrong passphrase / tampered blob → error.
    fn unseal_aux(&self, aad: &[u8], blob: &[u8]) -> Result<Vec<u8>>;

    /// Enumerate every known address (derived + imported), sorted by
    /// derivation index ascending (imported addresses appended).
    fn list(&self) -> Result<Vec<AddressEntry>>;

    /// Import a raw 32-byte ed25519 secret as a non-derived address.
    /// Returns the derived address (hex).
    fn import(&self, secret: &[u8; 32], label: Option<String>) -> Result<String>;

    /// Generate a fresh, independent ed25519 key and store it like an
    /// import (its own sealed file, NOT derived from the shared HD seed).
    /// This is the 1:1 model: every address has its own key, individually
    /// exportable, with no single secret controlling the whole wallet.
    /// Returns `(address_hex, pubkey_hex)`.
    fn create_independent(&self, label: Option<String>) -> Result<(String, String)>;

    /// Generate a fresh address using the STANDARD BIP-39 scheme: a random
    /// 24-word phrase whose key is `SHA-256("EXFER-MNEMONIC-ED25519-V1" ||
    /// BIP39_seed(phrase))`, with the phrase's entropy sealed alongside so it
    /// can be revealed later. The same phrase reproduces this exact address in
    /// any Exfer wallet. This is the default for new addresses; the legacy
    /// `create_independent` (raw random key) stays for backward compatibility.
    /// Default impl falls back to `create_independent` for stores that don't
    /// implement the standard scheme. Returns `(address_hex, pubkey_hex)`.
    fn create_standard(&self, label: Option<String>) -> Result<(String, String)> {
        self.create_independent(label)
    }

    /// Seal every managed key (HD-derived re-derived + imported) into one
    /// passphrase-encrypted vault blob — a single-file backup of the whole
    /// wallet that doesn't hinge on a single mnemonic. `passphrase` is
    /// verified against the keystore (wrong → `KeystoreLocked`) and also
    /// encrypts the blob. Sensitive — gate behind explicit user opt-in.
    fn export_vault(&self, passphrase: &[u8]) -> Result<Vec<u8>>;

    /// Restore keys from a vault blob, importing each as an independent
    /// key. Wrong passphrase → `KeystoreLocked`. Returns the addresses
    /// newly imported (already-present ones are skipped).
    fn import_vault(&self, blob: &[u8], passphrase: &[u8]) -> Result<Vec<String>>;

    /// Seal a chosen subset of addresses into one vault blob (identical
    /// format to [`export_vault`], so the result imports via
    /// [`import_vault`]). Empty `addresses` ⇒ every key. This is the
    /// single-address encrypted-export primitive. `passphrase` is verified
    /// against the keystore and also encrypts the blob. Any requested
    /// address not in the keystore → `WalletNotFound`.
    fn export_selected(&self, addresses: &[String], passphrase: &[u8]) -> Result<Vec<u8>>;

    /// Verify `passphrase` and return THIS address's own 24-word BIP-39
    /// phrase — its 256-bit ed25519 secret encoded as words. Distinct from
    /// [`reveal_mnemonic`] (the whole-wallet seed phrase): importing these
    /// words elsewhere reproduces exactly this one address as an
    /// independent key. Works for HD-derived and imported addresses.
    /// Wrong passphrase → `KeystoreLocked`; unknown → `WalletNotFound`.
    fn reveal_address_mnemonic(&self, address_hex: &str, passphrase: &[u8]) -> Result<Vec<String>>;

    /// Import a 24-word BIP-39 phrase as an independent key (its 256-bit
    /// entropy IS the ed25519 secret). Returns the address. Already-present
    /// → `WalletAlreadyExists`; not 24 words → `BadParams`.
    fn import_mnemonic(&self, phrase: &str, label: Option<String>) -> Result<String>;

    /// Import a 24-word STANDARD BIP-39 phrase (key = SHA-256(domain ||
    /// BIP39_seed)), reproducing the same address as exfer.dev / the apps, and
    /// seal the phrase so reveal returns it. Distinct from `import_mnemonic`,
    /// which treats the words as a raw-key (legacy) encoding. Default impl
    /// rejects; keyring stores override it.
    fn import_standard_mnemonic(&self, _phrase: &str, _label: Option<String>) -> Result<String> {
        Err(crate::error::Error::BadParams(
            "standard mnemonic import is not supported by this store".into(),
        ))
    }

    /// Permanently remove an address from the keystore. `passphrase` is
    /// verified first. For an independent/imported key this deletes the
    /// sealed key file (the secret is gone unless separately backed up);
    /// for an HD-derived address it drops it from the managed set (still
    /// re-derivable from the seed at its index). Wrong passphrase →
    /// `KeystoreLocked`; unknown address → `WalletNotFound`.
    fn delete(&self, address_hex: &str, passphrase: &[u8]) -> Result<()>;

    /// Whether an address is known to this store.
    fn exists(&self, address_hex: &str) -> bool;

    /// Verify `passphrase` matches the at-rest KEK and return the
    /// 24-word BIP-39 mnemonic that produced the keystore. Wrong
    /// passphrase MUST surface as `Error::KeystoreLocked`. Sensitive
    /// — only call when the user has explicitly opted in.
    fn reveal_mnemonic(&self, passphrase: &[u8]) -> Result<Vec<String>>;

    /// Verify `passphrase` and return the raw 32-byte ed25519 secret
    /// for a managed address (HD-derived or imported). Wrong
    /// passphrase → `KeystoreLocked`. Unknown address →
    /// `WalletNotFound`. Sensitive — only call when the user has
    /// explicitly opted in.
    fn reveal_secret(
        &self,
        address_hex: &str,
        passphrase: &[u8],
    ) -> Result<zeroize::Zeroizing<[u8; 32]>>;
}
