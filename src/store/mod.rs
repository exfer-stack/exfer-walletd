//! Wallet keystore.
//!
//! v1.0 model: a single HD seed encrypted at rest. Addresses are derived
//! on demand via SLIP-0010 (Ed25519). Backup the BIP-39 mnemonic and you
//! have backed up every present and future address. See `hd::HdSeedStore`
//! for the on-disk layout.
//!
//! Imported (non-derived) addresses live alongside derived ones — used
//! by the `migrate` subcommand to absorb legacy walletd `.key` files.
//!
//! Everything in this module is filesystem-backed; the trait stays
//! abstract so future backends (cloud KMS, HSM) can drop in.

pub mod hd;
pub mod sealed;

use ed25519_dalek::SigningKey;
use exfer::types::transaction::TxOutput;
use exfer::types::Hash256;
use serde::Serialize;

use crate::error::Result;

pub use hd::HdSeedStore;

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

    /// Enumerate every known address (derived + imported), sorted by
    /// derivation index ascending (imported addresses appended).
    fn list(&self) -> Result<Vec<AddressEntry>>;

    /// Import a raw 32-byte ed25519 secret as a non-derived address.
    /// Returns the derived address (hex).
    fn import(&self, secret: &[u8; 32], label: Option<String>) -> Result<String>;

    /// Whether an address is known to this store.
    fn exists(&self, address_hex: &str) -> bool;
}
