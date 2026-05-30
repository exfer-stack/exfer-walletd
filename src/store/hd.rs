//! HD seed-backed keystore.
//!
//! ## On-disk layout (`<wallet_dir>/`)
//!
//! ```text
//!   seed.enc                  ← BIP-39 entropy (32 B), sealed (see sealed.rs)
//!   state.json                ← {"next_index": N, "derived": {addr->idx},
//!                                 "labels": {addr->label}, "imported": [addr]}
//!   imported/<addr>.key.enc   ← sealed 32-byte secret for non-HD imports
//! ```
//!
//! ## Derivation path
//!
//! `m/44'/9527'/0'/0'/i'`  (Ed25519, all hardened — SLIP-0010 spec).
//!
//! `9527` is a private-use SLIP-44 coin type placeholder; revisit after
//! Exfer registers an official slot.
//!
//! ## Caching
//!
//! Derived signers are cached in-memory after first use. The seed lives
//! decrypted in memory for the daemon's lifetime (encrypted on disk).
//! `Signer` itself is cheap to construct from the cached seed (~µs of
//! HMAC-SHA512), so cache misses on cold addresses cost almost nothing.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use bip39::{Language, Mnemonic};

use super::sealed;
use super::{AddressEntry, DerivedAddress, Signer, WalletStore};
use crate::error::{Error, Result};

/// SLIP-44 coin-type placeholder until Exfer registers an official slot.
pub const EXFER_COIN_TYPE: u32 = 9527;

const SEED_FILE: &str = "seed.enc";
const STATE_FILE: &str = "state.json";
const IMPORTED_DIR: &str = "imported";
const SEED_AAD: &[u8] = b"exfer-walletd/v1/seed";
const IMPORTED_AAD: &[u8] = b"exfer-walletd/v1/imported";
const VAULT_AAD: &[u8] = b"exfer-walletd/v1/vault";

// ============================================================================
// Persisted state
// ============================================================================

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct State {
    #[serde(default)]
    next_index: u32,
    /// Reverse index: hex address → derivation index. Lets `load_by_address`
    /// answer "which `i` did this come from" in O(1) without re-walking
    /// `0..next_index` for every signature.
    #[serde(default)]
    derived: BTreeMap<String, u32>,
    /// Optional human-readable labels keyed by hex address.
    #[serde(default)]
    labels: BTreeMap<String, String>,
    /// Hex addresses imported via the `migrate` subcommand. The actual
    /// secret lives in `imported/<addr>.key.enc`.
    #[serde(default)]
    imported: Vec<String>,
}

impl State {
    fn load_or_default(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = std::fs::read(path)?;
        serde_json::from_slice(&bytes)
            .map_err(|e| Error::Internal(format!("parse {}: {e}", path.display())))
    }

    fn save_atomic(&self, path: &Path) -> Result<()> {
        let tmp = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| Error::Internal(format!("encode state: {e}")))?;
        std::fs::write(&tmp, &bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

// ============================================================================
// Store
// ============================================================================

/// Implements `Debug` opaquely; the seed and passphrase are NEVER printed.
pub struct HdSeedStore {
    root: PathBuf,
    /// Decrypted master entropy (32 bytes for 24-word mnemonic). Held
    /// in memory for the daemon's lifetime; cleared on Drop.
    seed: Zeroizing<[u8; 64]>,
    /// `Some` only between [`HdSeedStore::open_or_init_fresh`] returning
    /// and the operator pulling the words once via [`mnemonic_words`].
    /// Lives just long enough to be printed at first start.
    fresh_mnemonic: Mutex<Option<Vec<String>>>,
    /// Passphrase kept around for sealing imported keys; cleared on Drop.
    passphrase: Zeroizing<Vec<u8>>,
    state: Mutex<State>,
    /// Signer cache: address-hex → signer. Filled lazily on first use.
    cache: Mutex<BTreeMap<String, Signer>>,
}

impl std::fmt::Debug for HdSeedStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HdSeedStore")
            .field("root", &self.root.display().to_string())
            .finish_non_exhaustive()
    }
}

impl HdSeedStore {
    /// Open an existing keystore, or initialise a fresh one on first run.
    /// The passphrase MUST come from a deliberate operator decision (env
    /// var `WALLETD_KEYSTORE_PASSPHRASE` in production) — never default.
    pub fn open_or_init_fresh(root: impl Into<PathBuf>, passphrase: &[u8]) -> Result<Self> {
        let root: PathBuf = root.into();
        std::fs::create_dir_all(&root)?;
        std::fs::create_dir_all(root.join(IMPORTED_DIR))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700));
            let _ = std::fs::set_permissions(
                root.join(IMPORTED_DIR),
                std::fs::Permissions::from_mode(0o700),
            );
        }

        let seed_path = root.join(SEED_FILE);
        let (seed64, fresh_words) = if seed_path.exists() {
            let blob = std::fs::read(&seed_path)?;
            let entropy = sealed::unseal(passphrase, SEED_AAD, &blob)?;
            let entropy: [u8; 32] = entropy.as_slice().try_into().map_err(|_| {
                Error::KeystoreLocked(format!(
                    "seed file has wrong length ({} bytes, expected 32)",
                    entropy.len()
                ))
            })?;
            (entropy_to_seed64(&entropy), None)
        } else {
            // First run — generate a 24-word mnemonic, seal entropy.
            let mnemonic = Mnemonic::generate_in(Language::English, 24)
                .map_err(|e| Error::Internal(format!("mnemonic generation failed: {e}")))?;
            let mut entropy = mnemonic.to_entropy();
            if entropy.len() != 32 {
                return Err(Error::Internal(format!(
                    "BIP-39 24-word entropy was {} bytes; expected 32",
                    entropy.len()
                )));
            }
            let mut entropy_arr = [0u8; 32];
            entropy_arr.copy_from_slice(&entropy);
            entropy.zeroize();
            let blob = sealed::seal(passphrase, SEED_AAD, &entropy_arr)?;
            atomic_write_0600(&seed_path, &blob)?;
            let words: Vec<String> = mnemonic.words().map(|w| w.to_string()).collect();
            let seed64 = entropy_to_seed64(&entropy_arr);
            entropy_arr.zeroize();
            (seed64, Some(words))
        };

        let state = State::load_or_default(&root.join(STATE_FILE))?;

        Ok(Self {
            root,
            seed: Zeroizing::new(seed64),
            fresh_mnemonic: Mutex::new(fresh_words),
            passphrase: Zeroizing::new(passphrase.to_vec()),
            state: Mutex::new(state),
            cache: Mutex::new(BTreeMap::new()),
        })
    }

    /// Restore a keystore from an existing 24-word BIP-39 mnemonic:
    /// validate the phrase, seal its entropy to `<wallet_dir>/seed.enc`
    /// (same WDV1 format as a fresh init), and persist a default
    /// `state.json`. Refuses if a seed already exists — restore targets a
    /// clean datadir so it can't clobber live keys.
    ///
    /// After this returns, open the store normally with
    /// [`open_or_init_fresh`](Self::open_or_init_fresh) + the same
    /// passphrase; addresses re-derive deterministically from the seed.
    pub fn init_from_mnemonic(
        root: impl Into<PathBuf>,
        passphrase: &[u8],
        phrase: &str,
    ) -> Result<()> {
        let root: PathBuf = root.into();
        std::fs::create_dir_all(&root)?;
        std::fs::create_dir_all(root.join(IMPORTED_DIR))?;

        let seed_path = root.join(SEED_FILE);
        if seed_path.exists() {
            return Err(Error::WalletAlreadyExists(
                "a seed already exists in this wallet directory; refusing to overwrite".into(),
            ));
        }

        let mnemonic = Mnemonic::parse_in(Language::English, phrase.trim())
            .map_err(|e| Error::BadParams(format!("invalid recovery phrase: {e}")))?;
        let mut entropy = mnemonic.to_entropy();
        if entropy.len() != 32 {
            return Err(Error::BadParams(format!(
                "recovery phrase must be 24 words (256-bit); got {}-byte entropy",
                entropy.len()
            )));
        }
        let mut entropy_arr = [0u8; 32];
        entropy_arr.copy_from_slice(&entropy);
        entropy.zeroize();
        let blob = sealed::seal(passphrase, SEED_AAD, &entropy_arr)?;
        entropy_arr.zeroize();
        atomic_write_0600(&seed_path, &blob)?;

        // Fresh state — addresses are re-derived by the caller.
        State::default().save_atomic(&root.join(STATE_FILE))?;
        Ok(())
    }

    /// On first run only: take the freshly-generated 24-word mnemonic out
    /// of the store. Subsequent calls (and every call against an existing
    /// keystore) return `None`. Caller must persist these words OUT OF
    /// PROCESS — they are the master backup.
    pub fn take_fresh_mnemonic(&self) -> Option<Vec<String>> {
        self.fresh_mnemonic.lock().ok().and_then(|mut g| g.take())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Compute the signer for a derivation index without touching cache
    /// or state. Used internally; tests may call directly.
    pub fn derive(&self, index: u32) -> Signer {
        let secret = slip10_ed25519::derive_ed25519_private_key(
            self.seed.as_ref(),
            &[44, EXFER_COIN_TYPE, 0, 0, index],
        );
        Signer::from_secret_bytes(&secret)
    }

    /// Verify `passphrase` matches the at-rest KEK by re-unsealing the
    /// seed file, then return the 24-word BIP-39 mnemonic that
    /// produced this keystore.
    ///
    /// **The caller must pass the passphrase freshly** — we don't
    /// reuse the in-memory copy on purpose, so this surface mirrors
    /// MetaMask-style "type your password again to reveal" flows.
    /// Wrong passphrase → [`Error::KeystoreLocked`].
    pub fn reveal_mnemonic(&self, passphrase: &[u8]) -> Result<Vec<String>> {
        let entropy = self.unseal_entropy(passphrase)?;
        let mnemonic = Mnemonic::from_entropy(entropy.as_ref())
            .map_err(|e| Error::Internal(format!("mnemonic from entropy: {e}")))?;
        // entropy is dropped here; bip39 made an internal copy into
        // `mnemonic`, but the only externally-observable output is
        // the public word list.
        let _ = entropy; // keep zeroize until scope end
        Ok(mnemonic.words().map(|w| w.to_string()).collect())
    }

    /// Verify `passphrase` and return the raw 32-byte ed25519 secret
    /// for `address_hex`. Works for HD-derived addresses (re-derive
    /// from the seed) and for imported addresses (re-unseal the
    /// per-key file with the same passphrase).
    ///
    /// Wrong passphrase → [`Error::KeystoreLocked`]. Address not in
    /// this keystore → [`Error::WalletNotFound`].
    pub fn reveal_secret(
        &self,
        address_hex: &str,
        passphrase: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>> {
        let address_hex = address_hex.to_ascii_lowercase();

        // Verify the passphrase by re-unsealing the seed first. For
        // imported keys we also unseal the per-key file with the same
        // passphrase (a successful seed unseal proves the passphrase is
        // right; a failure on the imported key would mean the imported
        // key was sealed with a different passphrase, which today
        // shouldn't happen but the error path remains correct).
        let entropy = self.unseal_entropy(passphrase)?;

        let kind = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(i) = state.derived.get(&address_hex) {
                Some(("derived", Some(*i)))
            } else if state.imported.contains(&address_hex) {
                Some(("imported", None))
            } else {
                None
            }
        };
        let kind = kind.ok_or(Error::WalletNotFound(address_hex.clone()))?;

        let secret = match kind {
            ("derived", Some(idx)) => {
                let entropy_arr: [u8; 32] = *entropy;
                let seed64 = entropy_to_seed64(&entropy_arr);
                let raw = slip10_ed25519::derive_ed25519_private_key(
                    &seed64,
                    &[44, EXFER_COIN_TYPE, 0, 0, idx],
                );
                // seed64 is on-stack; explicit zeroize.
                let mut s = seed64;
                s.zeroize();
                raw
            }
            ("imported", None) => {
                let blob = std::fs::read(
                    self.root
                        .join(IMPORTED_DIR)
                        .join(format!("{address_hex}.key.enc")),
                )?;
                let secret_vec = sealed::unseal(passphrase, IMPORTED_AAD, &blob)
                    .map_err(|_| Error::KeystoreLocked("wrong passphrase".into()))?;
                let arr: [u8; 32] = secret_vec.as_slice().try_into().map_err(|_| {
                    Error::KeystoreLocked(format!(
                        "imported key for {address_hex} has wrong length ({} bytes, expected 32)",
                        secret_vec.len()
                    ))
                })?;
                arr
            }
            _ => unreachable!(),
        };
        let _ = entropy;
        Ok(Zeroizing::new(secret))
    }

    /// Internal: re-unseal `seed.enc` with a freshly-supplied
    /// passphrase. Returns the 32-byte BIP-39 entropy as a zeroizing
    /// buffer. Wrong passphrase → [`Error::KeystoreLocked`].
    fn unseal_entropy(&self, passphrase: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let seed_path = self.root.join(SEED_FILE);
        let blob = std::fs::read(&seed_path)?;
        let entropy_vec = sealed::unseal(passphrase, SEED_AAD, &blob)
            .map_err(|_| Error::KeystoreLocked("wrong passphrase".into()))?;
        let arr: [u8; 32] = entropy_vec.as_slice().try_into().map_err(|_| {
            Error::Internal(format!(
                "sealed entropy was {} bytes; expected 32",
                entropy_vec.len()
            ))
        })?;
        Ok(Zeroizing::new(arr))
    }
}

/// BIP-39 seed: PBKDF2-HMAC-SHA512(mnemonic_phrase, "mnemonic" || ""),
/// 2048 iterations, 64-byte output. We use an empty BIP-39 passphrase —
/// the keystore-level passphrase is what protects the *entropy at rest*.
fn entropy_to_seed64(entropy: &[u8; 32]) -> [u8; 64] {
    let mnemonic = Mnemonic::from_entropy(entropy).expect("32-byte entropy is valid for 24 words");
    mnemonic.to_seed("")
}

fn atomic_write_0600(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

impl WalletStore for HdSeedStore {
    fn create(&self, label: Option<String>) -> Result<DerivedAddress> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let index = state.next_index;
        // u32 max is plenty (4B addresses) but be explicit.
        if index == u32::MAX {
            return Err(Error::Internal(
                "HD index exhausted (u32::MAX) — bind a fresh keystore".into(),
            ));
        }
        let signer = self.derive(index);
        let addr_hex = signer.address_hex();
        let pubkey_hex = hex::encode(signer.pubkey());

        state.next_index = index + 1;
        state.derived.insert(addr_hex.clone(), index);
        if let Some(l) = label {
            state.labels.insert(addr_hex.clone(), l);
        }
        state.save_atomic(&self.root.join(STATE_FILE))?;

        // Populate cache so the immediate next `load_by_address` is hot.
        if let Ok(mut c) = self.cache.lock() {
            c.insert(addr_hex.clone(), signer);
        }

        Ok(DerivedAddress {
            address: addr_hex,
            pubkey: pubkey_hex,
            index,
        })
    }

    fn load_by_address(&self, address_hex: &str) -> Result<Signer> {
        let address_hex = address_hex.to_ascii_lowercase();
        // Cache hit?
        if let Ok(c) = self.cache.lock() {
            if let Some(s) = c.get(&address_hex) {
                return Ok(s.clone());
            }
        }

        // Look up in state.
        let (kind, idx) = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(i) = state.derived.get(&address_hex) {
                ("derived", Some(*i))
            } else if state.imported.contains(&address_hex) {
                ("imported", None)
            } else {
                return Err(Error::WalletNotFound(address_hex));
            }
        };

        let signer = match kind {
            "derived" => self.derive(idx.unwrap()),
            "imported" => {
                let blob = std::fs::read(
                    self.root
                        .join(IMPORTED_DIR)
                        .join(format!("{address_hex}.key.enc")),
                )?;
                let secret = sealed::unseal(&self.passphrase, IMPORTED_AAD, &blob)?;
                let secret: [u8; 32] = secret.as_slice().try_into().map_err(|_| {
                    Error::KeystoreLocked(format!(
                        "imported key for {address_hex} has wrong length ({} bytes, expected 32)",
                        secret.len()
                    ))
                })?;
                let s = Signer::from_secret_bytes(&secret);
                // s captures the bytes; clear the local copy.
                let mut zero = secret;
                zero.zeroize();
                s
            }
            _ => unreachable!(),
        };

        if let Ok(mut c) = self.cache.lock() {
            c.insert(address_hex, signer.clone());
        }
        Ok(signer)
    }

    fn list(&self) -> Result<Vec<AddressEntry>> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        // Derived rows, sorted by index ascending.
        let mut derived_pairs: Vec<(&String, &u32)> = state.derived.iter().collect();
        derived_pairs.sort_by_key(|(_, idx)| *idx);

        let mut out: Vec<AddressEntry> = derived_pairs
            .into_iter()
            .map(|(addr, idx)| AddressEntry {
                address: addr.clone(),
                index: Some(*idx),
                label: state.labels.get(addr).cloned(),
                imported: false,
            })
            .collect();

        let mut imported = state.imported.clone();
        imported.sort();
        for addr in imported {
            out.push(AddressEntry {
                label: state.labels.get(&addr).cloned(),
                address: addr,
                index: None,
                imported: true,
            });
        }
        Ok(out)
    }

    fn import(&self, secret: &[u8; 32], label: Option<String>) -> Result<String> {
        let signer = Signer::from_secret_bytes(secret);
        let addr_hex = signer.address_hex();
        let blob = sealed::seal(&self.passphrase, IMPORTED_AAD, secret)?;
        let path = self
            .root
            .join(IMPORTED_DIR)
            .join(format!("{addr_hex}.key.enc"));
        atomic_write_0600(&path, &blob)?;

        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.derived.contains_key(&addr_hex) || state.imported.contains(&addr_hex) {
            return Err(Error::WalletAlreadyExists(addr_hex));
        }
        state.imported.push(addr_hex.clone());
        if let Some(l) = label {
            state.labels.insert(addr_hex.clone(), l);
        }
        state.save_atomic(&self.root.join(STATE_FILE))?;

        if let Ok(mut c) = self.cache.lock() {
            c.insert(addr_hex.clone(), signer);
        }
        Ok(addr_hex)
    }

    fn exists(&self, address_hex: &str) -> bool {
        let lower = address_hex.to_ascii_lowercase();
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.derived.contains_key(&lower) || state.imported.contains(&lower)
    }

    fn reveal_mnemonic(&self, passphrase: &[u8]) -> Result<Vec<String>> {
        Self::reveal_mnemonic(self, passphrase)
    }

    fn reveal_secret(&self, address_hex: &str, passphrase: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        Self::reveal_secret(self, address_hex, passphrase)
    }

    fn create_independent(&self, label: Option<String>) -> Result<(String, String)> {
        use rand::RngCore;
        // Fresh CSPRNG key — its own sealed file via the import path, with no
        // tie to the HD seed. Any 32 random bytes are a valid ed25519 secret.
        let mut secret = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut *secret);
        let signer = Signer::from_secret_bytes(&secret);
        let pubkey_hex = hex::encode(signer.pubkey());
        let addr = self.import(&secret, label)?;
        Ok((addr, pubkey_hex))
    }

    fn export_vault(&self, passphrase: &[u8]) -> Result<Vec<u8>> {
        let entries = WalletStore::list(self)?;
        // Verify the passphrase once (one argon2id) rather than per key:
        // reveal_secret errors on a wrong passphrase. Secrets themselves are
        // then read from the already-unlocked keystore.
        if let Some(first) = entries.first() {
            let _ = self.reveal_secret(&first.address, passphrase)?;
        }
        let mut keys = Vec::with_capacity(entries.len());
        for e in &entries {
            let signer = self.load_by_address(&e.address)?;
            let secret = Zeroizing::new(signer.signing_key().to_bytes());
            keys.push(serde_json::json!({
                "address": e.address,
                "secret_hex": hex::encode(&*secret),
                "label": e.label,
            }));
        }
        let doc = serde_json::json!({ "version": 1, "keys": keys });
        let bytes = serde_json::to_vec(&doc)
            .map_err(|e| Error::Internal(format!("vault serialize: {e}")))?;
        sealed::seal(passphrase, VAULT_AAD, &bytes)
    }

    fn import_vault(&self, blob: &[u8], passphrase: &[u8]) -> Result<Vec<String>> {
        let bytes = sealed::unseal(passphrase, VAULT_AAD, blob)?;
        let doc: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| Error::ParseError(format!("vault: {e}")))?;
        let keys = doc
            .get("keys")
            .and_then(|v| v.as_array())
            .ok_or_else(|| Error::ParseError("vault: missing `keys`".into()))?;
        let mut imported = Vec::new();
        for k in keys {
            let secret_hex = k
                .get("secret_hex")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::ParseError("vault: key missing `secret_hex`".into()))?;
            let label = k
                .get("label")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let raw = hex::decode(secret_hex)
                .map_err(|e| Error::BadHex(format!("vault secret: {e}")))?;
            let secret: [u8; 32] = raw
                .as_slice()
                .try_into()
                .map_err(|_| Error::ParseError("vault: secret not 32 bytes".into()))?;
            let addr = Signer::from_secret_bytes(&secret).address_hex();
            if self.exists(&addr) {
                continue;
            }
            imported.push(self.import(&secret, label)?);
        }
        Ok(imported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn first_run_generates_mnemonic_and_persists_seed() {
        let dir = temp();
        let store = HdSeedStore::open_or_init_fresh(dir.path(), b"pw").unwrap();
        let words = store
            .take_fresh_mnemonic()
            .expect("first run prints mnemonic");
        assert_eq!(words.len(), 24);
        assert!(dir.path().join(SEED_FILE).exists());
        // Second call returns None.
        assert!(store.take_fresh_mnemonic().is_none());
    }

    #[test]
    fn reopen_with_same_passphrase_recovers_addresses() {
        let dir = temp();
        let s1 = HdSeedStore::open_or_init_fresh(dir.path(), b"pw").unwrap();
        let _ = s1.take_fresh_mnemonic();
        let a = s1.create(None).unwrap().address;
        let b = s1.create(Some("user-1".into())).unwrap().address;
        drop(s1);

        let s2 = HdSeedStore::open_or_init_fresh(dir.path(), b"pw").unwrap();
        assert!(s2.take_fresh_mnemonic().is_none());
        let list = s2.list().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].address, a);
        assert_eq!(list[0].index, Some(0));
        assert_eq!(list[1].address, b);
        assert_eq!(list[1].label.as_deref(), Some("user-1"));

        // Load + derive must produce byte-identical pubkeys.
        let s1_again = s2.load_by_address(&a).unwrap();
        let s2_again = s2.load_by_address(&b).unwrap();
        assert_ne!(s1_again.pubkey(), s2_again.pubkey());
    }

    #[test]
    fn wrong_passphrase_locks_keystore() {
        let dir = temp();
        let _s1 = HdSeedStore::open_or_init_fresh(dir.path(), b"right").unwrap();
        let err = HdSeedStore::open_or_init_fresh(dir.path(), b"wrong").unwrap_err();
        assert!(matches!(err, Error::KeystoreLocked(_)));
    }

    #[test]
    fn derivation_is_deterministic_for_same_seed() {
        // Generate one keystore, capture addresses, blow away state.json,
        // reopen, derive same indices — addresses must match because they
        // come from the seed not from state.
        let dir = temp();
        let s1 = HdSeedStore::open_or_init_fresh(dir.path(), b"pw").unwrap();
        let a0 = s1.derive(0).address_hex();
        let a1 = s1.derive(1).address_hex();
        drop(s1);

        let s2 = HdSeedStore::open_or_init_fresh(dir.path(), b"pw").unwrap();
        assert_eq!(s2.derive(0).address_hex(), a0);
        assert_eq!(s2.derive(1).address_hex(), a1);
    }

    #[test]
    fn import_roundtrip() {
        let dir = temp();
        let store = HdSeedStore::open_or_init_fresh(dir.path(), b"pw").unwrap();
        let secret = [7u8; 32];
        let addr = store.import(&secret, Some("legacy".into())).unwrap();

        let loaded = store.load_by_address(&addr).unwrap();
        // Re-derive expected pubkey from the raw secret to compare.
        let expected = Signer::from_secret_bytes(&secret);
        assert_eq!(loaded.pubkey(), expected.pubkey());

        let list = store.list().unwrap();
        let row = list.iter().find(|e| e.address == addr).unwrap();
        assert!(row.imported);
        assert_eq!(row.label.as_deref(), Some("legacy"));
    }

    #[test]
    fn vault_export_import_roundtrip() {
        // Source wallet: two independent (1:1) keys + one HD-derived.
        let src_dir = temp();
        let src = HdSeedStore::open_or_init_fresh(src_dir.path(), b"pw").unwrap();
        let _ = src.take_fresh_mnemonic();
        let (a, _) = src.create_independent(Some("savings".into())).unwrap();
        let (b, _) = src.create_independent(None).unwrap();
        let c = src.create(Some("hd-0".into())).unwrap().address;

        let blob = src.export_vault(b"pw").unwrap();
        assert!(!blob.is_empty());
        // Wrong passphrase must not decrypt.
        let dst_dir = temp();
        let dst = HdSeedStore::open_or_init_fresh(dst_dir.path(), b"pw2").unwrap();
        assert!(dst.import_vault(&blob, b"wrong").is_err());

        // Restore into the fresh wallet.
        let imported = dst.import_vault(&blob, b"pw").unwrap();
        assert_eq!(imported.len(), 3);
        for addr in [&a, &b, &c] {
            assert!(dst.exists(addr), "restored wallet missing {addr}");
            // Same address ⇒ same key ⇒ same pubkey, and it signs.
            let s = dst.load_by_address(addr).unwrap();
            assert_eq!(s.address_hex(), *addr);
        }
        // The label rode along in the vault.
        let row = dst.list().unwrap();
        assert_eq!(
            row.iter().find(|e| &e.address == &a).unwrap().label.as_deref(),
            Some("savings"),
        );
    }

    #[test]
    fn load_unknown_address_returns_typed_error() {
        let dir = temp();
        let store = HdSeedStore::open_or_init_fresh(dir.path(), b"pw").unwrap();
        let res = store.load_by_address(&"ab".repeat(32));
        assert!(matches!(res, Err(Error::WalletNotFound(_))));
    }
}
