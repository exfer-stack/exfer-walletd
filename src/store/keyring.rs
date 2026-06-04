//! Keyring keystore — a flat set of independent keys, with an OPTIONAL
//! HD seed as one backward-compatible origin.
//!
//! ## On-disk layout (`<wallet_dir>/`)
//!
//! ```text
//!   seed.enc                  ← OPTIONAL: sealed BIP-39 entropy (32 B).
//!                                Absent in a seedless keyring (see below).
//!   state.json                ← {"next_index": N, "derived": {addr->idx},
//!                                 "labels": {addr->label}, "imported": [addr]}
//!   imported/<addr>.key.enc   ← sealed 32-byte secret per independent /
//!                                imported key (the 1:1 keys live here)
//! ```
//!
//! ## Seeded vs seedless
//!
//! [`KeyringStore::open_or_init_fresh`] generates a `seed.enc` on first run
//! (legacy/operator path; the seed mnemonic backs up every derived
//! address). [`KeyringStore::open_keyring`] creates a *seedless* keyring —
//! no `seed.enc`, every address is its own independent key, backup is the
//! vault or per-address recovery phrases. Existing seeded wallets open
//! unchanged through either constructor.
//!
//! ## Derivation path (seeded only)
//!
//! `m/44'/9527'/0'/0'/i'`  (Ed25519, all hardened — SLIP-0010 spec).
//!
//! `9527` is a private-use SLIP-44 coin type placeholder; revisit after
//! Exfer registers an official slot.
//!
//! ## Caching
//!
//! Signers are cached in-memory after first use. When present, the seed
//! lives decrypted in memory for the daemon's lifetime (encrypted on
//! disk); re-deriving a signer is ~µs of HMAC-SHA512, so cache misses on
//! cold derived addresses cost almost nothing.

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
/// AAD for the sealed BIP-39 entropy stored next to a STANDARD address's key,
/// so its standard recovery phrase can be revealed later.
const MNEMONIC_AAD: &[u8] = b"exfer-walletd/v1/mnemonic";
/// Sealed-mnemonic filename suffix: `imported/<addr>.mnemonic.enc`. Present
/// only for standard addresses; absent for legacy/imported keys.
const MNEMONIC_SUFFIX: &str = ".mnemonic.enc";
/// Domain tag mixed with the BIP-39 seed to derive a STANDARD address's
/// ed25519 secret. MUST stay byte-for-byte identical across every Exfer
/// wallet (exfer.dev web, the apps) or the same phrase yields a different
/// address. Verified against an exfer.dev test vector in the tests below.
const STD_MNEMONIC_DOMAIN: &[u8] = b"EXFER-MNEMONIC-ED25519-V1";

// ---- independent BSC/EVM key (secp256k1) ----------------------------------
//
// The wallet's BSC/EVM identity can be a *first-class independent* secp256k1
// key with its OWN BIP-39 mnemonic, stored under `imported/`. This makes the
// BNB wallet work on a seedless keyring (the common in-app case) and lets a
// seeded wallet later create an independent BNB key without disturbing its
// existing seed-derived BSC address. See [`KeyringStore::evm_secret`].

/// Sealed 32-byte secp256k1 secret for the independent EVM key.
const EVM_KEY_FILE: &str = "evm.key.enc";
/// Sealed BIP-39 entropy of the independent EVM key's own mnemonic (absent
/// when the key was imported as a raw private key — no phrase to reveal).
const EVM_MNEMONIC_FILE: &str = "evm.mnemonic.enc";
/// AAD domain-separating the sealed EVM secret from every other sealed blob.
const EVM_KEY_AAD: &[u8] = b"exfer-walletd/v1/evm-key";
/// AAD for the EVM key's sealed mnemonic entropy.
const EVM_MNEMONIC_AAD: &[u8] = b"exfer-walletd/v1/evm-mnemonic";
/// Standard Ethereum derivation path — byte-identical to the seed-derived
/// path in [`KeyringStore::evm_secret`], so a fresh mnemonic is MetaMask
/// importable (yields the same address at this path).
const EVM_PATH: &str = "m/44'/60'/0'/0/0";

/// secp256k1 secret from a BIP-39 mnemonic at the standard Ethereum path
/// (`m/44'/60'/0'/0/0`, empty BIP-39 passphrase = MetaMask default). This is
/// byte-for-byte the same derivation the seed path uses, so the resulting BSC
/// address matches what MetaMask shows for the same mnemonic.
fn evm_secret_from_mnemonic(m: &Mnemonic) -> Result<Zeroizing<[u8; 32]>> {
    let seed = m.to_seed(""); // empty BIP-39 passphrase — MetaMask default
    let path: bip32::DerivationPath = EVM_PATH
        .parse()
        .map_err(|e| Error::Internal(format!("bad EVM path: {e}")))?;
    let xprv = bip32::XPrv::derive_from_path(&seed[..], &path)
        .map_err(|e| Error::Internal(format!("EVM derive failed: {e}")))?;
    let mut b = [0u8; 32];
    b.copy_from_slice(xprv.private_key().to_bytes().as_slice());
    Ok(Zeroizing::new(b))
}

/// Standard scheme: `secret = SHA-256(STD_MNEMONIC_DOMAIN || BIP39_seed(phrase))`.
/// The BIP-39 seed uses an empty passphrase (the keystore passphrase protects
/// the entropy at rest, not the seed). One-way, so the entropy is sealed
/// separately to make the phrase revealable.
fn standard_secret_from_mnemonic(mnemonic: &Mnemonic) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let seed = mnemonic.to_seed("");
    let mut h = Sha256::new();
    h.update(STD_MNEMONIC_DOMAIN);
    h.update(seed);
    h.finalize().into()
}

/// Seal a standard address's phrase entropy at `imported/<addr>.mnemonic.enc`,
/// so reveal can return the standard phrase. Best-effort: the address works
/// regardless; without this, reveal falls back to the legacy raw-key encoding.
fn seal_standard_mnemonic(
    root: &std::path::Path,
    passphrase: &[u8],
    addr: &str,
    mnemonic: &Mnemonic,
) {
    let mut entropy = mnemonic.to_entropy();
    let sealed = sealed::seal(passphrase, MNEMONIC_AAD, &entropy);
    entropy.zeroize();
    match sealed {
        Ok(blob) => {
            let mpath = root
                .join(IMPORTED_DIR)
                .join(format!("{addr}{MNEMONIC_SUFFIX}"));
            if let Err(e) = atomic_write_0600(&mpath, &blob) {
                tracing::warn!(error = %e, address = %addr, "could not store standard mnemonic");
            }
        }
        Err(e) => tracing::warn!(error = %e, address = %addr, "could not seal standard mnemonic"),
    }
}

// ============================================================================
// Persisted state
// ============================================================================

/// How the independent EVM key entered the keystore. Decides whether a
/// recovery phrase can be revealed: a raw-key import (MetaMask "Private Key")
/// has NO mnemonic, so reveal must refuse rather than fabricate one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
enum EvmKeySource {
    /// Freshly generated here (24-word mnemonic → secp256k1).
    Generated,
    /// Imported from a BIP-39 mnemonic (its entropy is sealed alongside).
    ImportedMnemonic,
    /// Imported from a raw 0x private key (no mnemonic exists).
    ImportedKey,
}

/// Metadata for the wallet's independent BSC/EVM key. Persisted in
/// `state.json`; absent (`None`) on legacy wallets and any wallet that
/// still uses its seed-derived BSC address.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EvmKeyMeta {
    /// EIP-55 checksummed address this key controls.
    address: String,
    /// Unix seconds when the key was created/imported.
    created_at: u64,
    /// Provenance — gates mnemonic reveal.
    source: EvmKeySource,
}

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
    /// The wallet's independent BSC/EVM key, if one was created/imported.
    /// `#[serde(default)]` keeps legacy `state.json` (no such field) parsing
    /// to `None` — those wallets fall back to seed-derived BSC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    evm_key: Option<EvmKeyMeta>,
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
pub struct KeyringStore {
    root: PathBuf,
    /// Decrypted master HD seed (PBKDF2 of the 24-word entropy). `None`
    /// for a *seedless* keyring — one made of only independent/imported
    /// keys, with no HD origin at all (`seed.enc` absent on disk). Held in
    /// memory for the daemon's lifetime; cleared on Drop.
    seed: Option<Zeroizing<[u8; 64]>>,
    /// `Some` only between a fresh seeded init returning and the operator
    /// pulling the words once via [`take_fresh_mnemonic`]. Lives just long
    /// enough to be printed at first start. Always `None` for a seedless
    /// keyring (nothing is generated).
    fresh_mnemonic: Mutex<Option<Vec<String>>>,
    /// Passphrase kept around for sealing imported keys; cleared on Drop.
    passphrase: Zeroizing<Vec<u8>>,
    state: Mutex<State>,
    /// Signer cache: address-hex → signer. Filled lazily on first use.
    cache: Mutex<BTreeMap<String, Signer>>,
}

impl std::fmt::Debug for KeyringStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyringStore")
            .field("root", &self.root.display().to_string())
            .finish_non_exhaustive()
    }
}

impl KeyringStore {
    /// Open an existing keystore, or initialise a fresh **seeded** one on
    /// first run (generates a 24-word HD seed). Legacy/operator path — the
    /// daemon still backs up via the seed mnemonic. New keyring-model
    /// callers prefer [`open_keyring`](Self::open_keyring).
    ///
    /// The passphrase MUST come from a deliberate operator decision (env
    /// var `WALLETD_KEYSTORE_PASSPHRASE` in production) — never default.
    pub fn open_or_init_fresh(root: impl Into<PathBuf>, passphrase: &[u8]) -> Result<Self> {
        Self::open_inner(root, passphrase, true)
    }

    /// Open an existing keystore, or initialise a fresh **seedless** one —
    /// a pure keyring with no HD seed (`seed.enc` is never created). New
    /// addresses are independent 1:1 keys; backup is the vault or
    /// per-address recovery phrases, not a single seed mnemonic.
    ///
    /// Opening an existing *seeded* wallet through this path loads its seed
    /// normally (full backward compatibility) — the seedless behaviour only
    /// applies when there is no `seed.enc` to begin with. When the wallet
    /// already holds keys, the passphrase is verified against one of them.
    pub fn open_keyring(root: impl Into<PathBuf>, passphrase: &[u8]) -> Result<Self> {
        let store = Self::open_inner(root, passphrase, false)?;
        // A seeded open verifies the passphrase by unsealing `seed.enc`. A
        // seedless open has no seed to check, so verify against an existing
        // key (if any) — otherwise a wrong passphrase would silently become
        // the sealing key for future imports and corrupt the keystore.
        if store.seed.is_none() {
            store.verify_passphrase(passphrase)?;
        }
        Ok(store)
    }

    fn open_inner(
        root: impl Into<PathBuf>,
        passphrase: &[u8],
        generate_seed_if_missing: bool,
    ) -> Result<Self> {
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
            (Some(entropy_to_seed64(&entropy)), None)
        } else if generate_seed_if_missing {
            // First run (seeded) — generate a 24-word mnemonic, seal entropy.
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
            (Some(seed64), Some(words))
        } else {
            // Seedless keyring — no HD origin.
            (None, None)
        };

        let state = State::load_or_default(&root.join(STATE_FILE))?;

        Ok(Self {
            root,
            seed: seed64.map(Zeroizing::new),
            fresh_mnemonic: Mutex::new(fresh_words),
            passphrase: Zeroizing::new(passphrase.to_vec()),
            state: Mutex::new(state),
            cache: Mutex::new(BTreeMap::new()),
        })
    }

    /// Verify `passphrase` without revealing anything. Seeded → unseal
    /// `seed.enc`. Seedless → unseal one managed key, if any exist (an
    /// empty seedless keyring has nothing to check against, so any
    /// passphrase is accepted and becomes the sealing key). Wrong
    /// passphrase → [`Error::KeystoreLocked`].
    fn verify_passphrase(&self, passphrase: &[u8]) -> Result<()> {
        if self.seed.is_some() {
            let _ = self.unseal_entropy(passphrase)?;
            return Ok(());
        }
        let probe = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.imported.first().cloned()
        };
        if let Some(addr) = probe {
            let blob = std::fs::read(self.root.join(IMPORTED_DIR).join(format!("{addr}.key.enc")))?;
            sealed::unseal(passphrase, IMPORTED_AAD, &blob)
                .map_err(|_| Error::KeystoreLocked("wrong passphrase".into()))?;
        }
        Ok(())
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
    /// or state. Used internally; tests may call directly. Panics on a
    /// seedless keyring — callers (`create`) guard on seed presence first.
    pub fn derive(&self, index: u32) -> Signer {
        let seed = self
            .seed
            .as_ref()
            .expect("derive() on a seedless keyring — guard on seed presence in the caller");
        let secret = slip10_ed25519::derive_ed25519_private_key(
            seed.as_ref(),
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
        if self.seed.is_none() {
            return Err(Error::BadParams(
                "this wallet has no seed phrase (seedless keyring); back it up via the \
                 vault export or per-address recovery phrases instead"
                    .into(),
            ));
        }
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
                // HD origin: unsealing `seed.enc` both verifies the
                // passphrase and re-derives the key.
                let entropy = self.unseal_entropy(passphrase)?;
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
                // Independent/imported key: unsealing the per-key file IS
                // the passphrase check (no seed needed → works seedless).
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

    /// Refuse to replace an existing independent EVM key unless `overwrite`.
    fn guard_evm_overwrite(&self, overwrite: bool) -> Result<()> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.evm_key.is_some() && !overwrite {
            return Err(Error::WalletAlreadyExists(
                "an independent BSC/EVM key already exists; pass overwrite to replace it".into(),
            ));
        }
        Ok(())
    }

    /// Seal the EVM secret (and, when present, its mnemonic entropy) to disk
    /// and record `state.evm_key`. Atomic-ish: the key file is written first,
    /// then state; on a state-write failure the orphan key file is removed.
    fn persist_evm_key(
        &self,
        secret: &[u8; 32],
        mnemonic: Option<&Mnemonic>,
        address: &str,
        source: EvmKeySource,
    ) -> Result<()> {
        let kpath = self.root.join(IMPORTED_DIR).join(EVM_KEY_FILE);
        let mpath = self.root.join(IMPORTED_DIR).join(EVM_MNEMONIC_FILE);

        let key_blob = sealed::seal(&self.passphrase, EVM_KEY_AAD, secret)?;
        atomic_write_0600(&kpath, &key_blob)?;

        // Seal the mnemonic entropy (so reveal can return the phrase); zeroize
        // entropy immediately after. Raw-key imports have no mnemonic.
        if let Some(m) = mnemonic {
            let mut entropy = m.to_entropy();
            let sealed = sealed::seal(&self.passphrase, EVM_MNEMONIC_AAD, &entropy);
            entropy.zeroize();
            match sealed {
                Ok(blob) => {
                    if let Err(e) = atomic_write_0600(&mpath, &blob) {
                        let _ = std::fs::remove_file(&kpath);
                        return Err(e);
                    }
                }
                Err(e) => {
                    let _ = std::fs::remove_file(&kpath);
                    return Err(e);
                }
            }
        } else if mpath.exists() {
            // Overwriting a mnemonic-backed key with a raw key: drop the stale
            // phrase so reveal can't return a mismatched one.
            let _ = std::fs::remove_file(&mpath);
        }

        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.evm_key = Some(EvmKeyMeta {
            address: address.to_string(),
            created_at: now_unix(),
            source,
        });
        if let Err(e) = state.save_atomic(&self.root.join(STATE_FILE)) {
            // Roll back the on-disk files so a half-write doesn't leave an
            // unreferenced key sealed on disk.
            let _ = std::fs::remove_file(&kpath);
            let _ = std::fs::remove_file(&mpath);
            return Err(e);
        }
        Ok(())
    }
}

/// BIP-39 seed: PBKDF2-HMAC-SHA512(mnemonic_phrase, "mnemonic" || ""),
/// 2048 iterations, 64-byte output. We use an empty BIP-39 passphrase —
/// the keystore-level passphrase is what protects the *entropy at rest*.
fn entropy_to_seed64(entropy: &[u8; 32]) -> [u8; 64] {
    let mnemonic = Mnemonic::from_entropy(entropy).expect("32-byte entropy is valid for 24 words");
    mnemonic.to_seed("")
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

impl WalletStore for KeyringStore {
    fn create(&self, label: Option<String>) -> Result<DerivedAddress> {
        if self.seed.is_none() {
            return Err(Error::BadParams(
                "this wallet has no HD seed (seedless keyring); use \
                 generate_independent_address for a 1:1 key"
                    .into(),
            ));
        }
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

    fn reveal_evm_secret(&self, passphrase: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        // Same gate as reveal_mnemonic: wrong passphrase → KeystoreLocked.
        self.verify_passphrase(passphrase)?;
        self.evm_secret()
    }

    fn evm_secret(&self) -> Result<Zeroizing<[u8; 32]>> {
        // Resolution order is LOAD-BEARING and must not be reordered:
        //
        //   1. independent EVM key (works seedless) — ALWAYS first, so a
        //      seeded wallet that later creates an independent key never
        //      splits funds across two BSC addresses.
        //   2. seed-derivation (UNCHANGED — existing operator wallets).
        //   3. neither → typed `EvmKeyNotCreated` (UI shows "create BNB
        //      wallet"). NEVER auto-create here.
        let p = self.root.join(IMPORTED_DIR).join(EVM_KEY_FILE);
        if p.exists() {
            let blob = std::fs::read(&p)?;
            let v = sealed::unseal(&self.passphrase, EVM_KEY_AAD, &blob)?;
            let arr: [u8; 32] = v
                .as_slice()
                .try_into()
                .map_err(|_| Error::Internal("evm.key.enc wrong length".into()))?;
            return Ok(Zeroizing::new(arr));
        }

        if let Some(seed) = self.seed.as_ref() {
            // BIP-32 secp256k1 derivation at the standard Ethereum path. Uses
            // the same 64-byte BIP-39 seed the ed25519 keys derive from, so
            // this BSC address matches what MetaMask shows for the user's
            // mnemonic. UNCHANGED from the original seed path — backward compat.
            let path: bip32::DerivationPath = EVM_PATH
                .parse()
                .map_err(|e| Error::Internal(format!("bad EVM derivation path: {e}")))?;
            let xprv = bip32::XPrv::derive_from_path(&seed[..], &path)
                .map_err(|e| Error::Internal(format!("EVM key derivation failed: {e}")))?;
            let fb = xprv.private_key().to_bytes();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(fb.as_slice());
            return Ok(Zeroizing::new(bytes));
        }

        Err(Error::EvmKeyNotCreated)
    }

    fn evm_address_opt(&self) -> Result<Option<String>> {
        // Independent key → its recorded EIP-55 address.
        {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(meta) = state.evm_key.as_ref() {
                return Ok(Some(meta.address.clone()));
            }
        }
        // Seed-derived BSC address (legacy/operator wallets). Never errors
        // for the seedless-no-key case — that just means "no BNB wallet yet".
        if self.seed.is_some() {
            let secret = self.evm_secret()?;
            return Ok(Some(crate::evm::evm_address(&secret)?));
        }
        Ok(None)
    }

    fn create_evm_key(&self, force: bool) -> Result<(String, Vec<String>)> {
        // Refuse to clobber an existing key (would strand BNB on the old one).
        {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.evm_key.is_some() {
                return Err(Error::WalletAlreadyExists(
                    "an independent BSC/EVM key already exists".into(),
                ));
            }
        }
        // On a seeded wallet the seed-derived address is canonical; creating
        // an independent key shadows it (evm_secret prefers the independent
        // key). Only do that on an explicit force.
        if self.seed.is_some() && !force {
            return Err(Error::BadParams(
                "this wallet already has a seed-derived BSC address; pass force \
                 to create a separate independent BNB key (the seed address \
                 would no longer be used)"
                    .into(),
            ));
        }

        let mnemonic = Mnemonic::generate_in(Language::English, 24)
            .map_err(|e| Error::Internal(format!("mnemonic generation failed: {e}")))?;
        let secret = evm_secret_from_mnemonic(&mnemonic)?;
        let address = crate::evm::evm_address(&secret)?;
        let words: Vec<String> = mnemonic.words().map(|w| w.to_string()).collect();

        self.persist_evm_key(&secret, Some(&mnemonic), &address, EvmKeySource::Generated)?;
        Ok((address, words))
    }

    fn reveal_evm_mnemonic(&self, passphrase: &[u8]) -> Result<Vec<String>> {
        self.verify_passphrase(passphrase)?;

        let source = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.evm_key.as_ref().map(|m| m.source.clone())
        };

        match source {
            Some(EvmKeySource::Generated) | Some(EvmKeySource::ImportedMnemonic) => {
                let mpath = self.root.join(IMPORTED_DIR).join(EVM_MNEMONIC_FILE);
                let blob = std::fs::read(&mpath)?;
                let entropy = sealed::unseal(passphrase, EVM_MNEMONIC_AAD, &blob)?;
                let mnemonic = Mnemonic::from_entropy(&entropy)
                    .map_err(|e| Error::Internal(format!("mnemonic from entropy: {e}")))?;
                Ok(mnemonic.words().map(|w| w.to_string()).collect())
            }
            Some(EvmKeySource::ImportedKey) => Err(Error::BadParams(
                "this BNB wallet was imported by raw private key; export the \
                 private key instead"
                    .into(),
            )),
            // No independent key: a seeded wallet's BSC address comes from the
            // SEED phrase, which is what reproduces it (and is MetaMask-derivable
            // at m/44'/60'/0'/0/0).
            None => Self::reveal_mnemonic(self, passphrase),
        }
    }

    fn import_evm_mnemonic(&self, phrase: &str, overwrite: bool) -> Result<String> {
        self.guard_evm_overwrite(overwrite)?;
        let mnemonic = Mnemonic::parse_in(Language::English, phrase.trim())
            .map_err(|e| Error::BadParams(format!("invalid recovery phrase: {e}")))?;
        // Accept 12- or 24-word BIP-39 (16- or 32-byte entropy).
        let elen = mnemonic.to_entropy().len();
        if elen != 16 && elen != 32 {
            return Err(Error::BadParams(
                "recovery phrase must be 12 or 24 words (BIP-39)".into(),
            ));
        }
        let secret = evm_secret_from_mnemonic(&mnemonic)?;
        let address = crate::evm::evm_address(&secret)?;
        self.persist_evm_key(
            &secret,
            Some(&mnemonic),
            &address,
            EvmKeySource::ImportedMnemonic,
        )?;
        Ok(address)
    }

    fn import_evm_key(&self, secret: &[u8; 32], overwrite: bool) -> Result<String> {
        self.guard_evm_overwrite(overwrite)?;
        // Validate as a real secp256k1 scalar (rejects zero / >= curve order)
        // before sealing a key that could never sign.
        let address = crate::evm::evm_address(secret)
            .map_err(|_| Error::BadParams("invalid secp256k1 private key".into()))?;
        let s = Zeroizing::new(*secret);
        self.persist_evm_key(&s, None, &address, EvmKeySource::ImportedKey)?;
        Ok(address)
    }

    fn delete_evm_key(&self, passphrase: &[u8]) -> Result<()> {
        self.verify_passphrase(passphrase)?;
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.evm_key.is_none() {
                return Err(Error::WalletNotFound("no independent BSC/EVM key".into()));
            }
            // Cryptographically gate the delete on the supplied passphrase by
            // unsealing the EVM key with it. verify_passphrase() above is a no-op
            // on a pure-EVM seedless keyring (no ed25519 key to check against);
            // unsealing evm.key.enc fails on a wrong passphrase, so a bad one
            // can't drop the key.
            let kp = self.root.join(IMPORTED_DIR).join(EVM_KEY_FILE);
            if kp.exists() {
                let blob = std::fs::read(&kp)?;
                sealed::unseal(passphrase, EVM_KEY_AAD, &blob)?;
            }
            state.evm_key = None;
            state.save_atomic(&self.root.join(STATE_FILE))?;
        }
        // Remove both sealed files (mnemonic absent for raw-key imports).
        let kpath = self.root.join(IMPORTED_DIR).join(EVM_KEY_FILE);
        if kpath.exists() {
            std::fs::remove_file(&kpath)?;
        }
        let mpath = self.root.join(IMPORTED_DIR).join(EVM_MNEMONIC_FILE);
        if mpath.exists() {
            let _ = std::fs::remove_file(&mpath);
        }
        Ok(())
    }

    fn seal_aux(&self, aad: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
        sealed::seal(&self.passphrase[..], aad, payload)
    }

    fn unseal_aux(&self, aad: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
        sealed::unseal(&self.passphrase[..], aad, blob)
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

    fn create_standard(&self, label: Option<String>) -> Result<(String, String)> {
        // Generate a real BIP-39 phrase and derive the key with the STANDARD
        // scheme, so the same phrase reproduces this address in any Exfer
        // wallet (exfer.dev, the apps). The key is stored like any imported
        // key; the phrase's entropy is sealed alongside so it can be revealed.
        let mnemonic = Mnemonic::generate_in(Language::English, 24)
            .map_err(|e| Error::Internal(format!("mnemonic generation failed: {e}")))?;
        let mut secret = Zeroizing::new(standard_secret_from_mnemonic(&mnemonic));
        let signer = Signer::from_secret_bytes(&secret);
        let pubkey_hex = hex::encode(signer.pubkey());
        let addr = self.import(&secret, label)?;
        secret.zeroize();
        seal_standard_mnemonic(&self.root, &self.passphrase, &addr, &mnemonic);
        Ok((addr, pubkey_hex))
    }

    fn export_vault(&self, passphrase: &[u8]) -> Result<Vec<u8>> {
        // Whole keyring = the empty-selection case.
        self.export_selected(&[], passphrase)
    }

    fn export_selected(&self, addresses: &[String], passphrase: &[u8]) -> Result<Vec<u8>> {
        let all = WalletStore::list(self)?;
        let selected: Vec<AddressEntry> = if addresses.is_empty() {
            all
        } else {
            let want: std::collections::BTreeSet<String> =
                addresses.iter().map(|a| a.to_ascii_lowercase()).collect();
            let picked: Vec<AddressEntry> = all
                .into_iter()
                .filter(|e| want.contains(&e.address.to_ascii_lowercase()))
                .collect();
            if picked.len() != want.len() {
                let have: std::collections::BTreeSet<String> = picked
                    .iter()
                    .map(|e| e.address.to_ascii_lowercase())
                    .collect();
                let missing: Vec<String> = want.into_iter().filter(|a| !have.contains(a)).collect();
                return Err(Error::WalletNotFound(missing.join(", ")));
            }
            picked
        };
        // Verify the passphrase once (one argon2id) rather than per key:
        // reveal_secret errors on a wrong passphrase. Secrets themselves are
        // then read from the already-unlocked keystore.
        if let Some(first) = selected.first() {
            let _ = self.reveal_secret(&first.address, passphrase)?;
        }
        let mut keys = Vec::with_capacity(selected.len());
        for e in &selected {
            let signer = self.load_by_address(&e.address)?;
            let secret = Zeroizing::new(signer.signing_key().to_bytes());
            keys.push(serde_json::json!({
                "address": e.address,
                "secret_hex": hex::encode(*secret),
                "label": e.label,
            }));
        }
        let doc = serde_json::json!({ "version": 1, "keys": keys });
        let bytes = serde_json::to_vec(&doc)
            .map_err(|e| Error::Internal(format!("vault serialize: {e}")))?;
        sealed::seal(passphrase, VAULT_AAD, &bytes)
    }

    fn reveal_address_mnemonic(&self, address_hex: &str, passphrase: &[u8]) -> Result<Vec<String>> {
        let addr = address_hex.to_ascii_lowercase();
        // STANDARD address: return the sealed standard phrase, which re-derives
        // this exact address in any Exfer wallet. A wrong passphrase fails the
        // AES-GCM auth in `unseal`.
        let mpath = self
            .root
            .join(IMPORTED_DIR)
            .join(format!("{addr}{MNEMONIC_SUFFIX}"));
        if mpath.exists() {
            let blob = std::fs::read(&mpath)?;
            let entropy = sealed::unseal(passphrase, MNEMONIC_AAD, &blob)?;
            let mnemonic = Mnemonic::from_entropy(&entropy)
                .map_err(|e| Error::Internal(format!("mnemonic from entropy: {e}")))?;
            return Ok(mnemonic.words().map(|w| w.to_string()).collect());
        }
        // LEGACY / imported address (no stored phrase): the words encode the raw
        // 32-byte key directly. `reveal_secret` verifies the passphrase and that
        // the address is managed. Unchanged behaviour for pre-existing wallets.
        let secret = self.reveal_secret(&addr, passphrase)?;
        let mnemonic = Mnemonic::from_entropy(secret.as_ref())
            .map_err(|e| Error::Internal(format!("mnemonic from key: {e}")))?;
        Ok(mnemonic.words().map(|w| w.to_string()).collect())
    }

    fn import_mnemonic(&self, phrase: &str, label: Option<String>) -> Result<String> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase.trim())
            .map_err(|e| Error::BadParams(format!("invalid recovery phrase: {e}")))?;
        let mut entropy = mnemonic.to_entropy();
        if entropy.len() != 32 {
            entropy.zeroize();
            return Err(Error::BadParams(format!(
                "recovery phrase must be 24 words (256-bit); got {}-byte entropy",
                entropy.len()
            )));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&entropy);
        entropy.zeroize();
        let r = self.import(&secret, label);
        secret.zeroize();
        r
    }

    fn import_standard_mnemonic(&self, phrase: &str, label: Option<String>) -> Result<String> {
        // Re-import a STANDARD phrase to the SAME address it has in any Exfer
        // wallet, and seal the phrase so reveal returns it (symmetric with
        // create_standard / a standard reveal). Use this for phrases produced
        // by the standard scheme; `import_mnemonic` stays for legacy raw-key
        // phrases.
        let mnemonic = Mnemonic::parse_in(Language::English, phrase.trim())
            .map_err(|e| Error::BadParams(format!("invalid recovery phrase: {e}")))?;
        if mnemonic.to_entropy().len() != 32 {
            return Err(Error::BadParams(
                "recovery phrase must be 24 words (256-bit)".into(),
            ));
        }
        let mut secret = Zeroizing::new(standard_secret_from_mnemonic(&mnemonic));
        let addr = self.import(&secret, label)?;
        secret.zeroize();
        seal_standard_mnemonic(&self.root, &self.passphrase, &addr, &mnemonic);
        Ok(addr)
    }

    fn delete(&self, address_hex: &str, passphrase: &[u8]) -> Result<()> {
        let address_hex = address_hex.to_ascii_lowercase();
        // Gate on the passphrase (works seeded or seedless).
        self.verify_passphrase(passphrase)?;

        let was_imported = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let was_derived = state.derived.remove(&address_hex).is_some();
            let was_imported =
                if let Some(pos) = state.imported.iter().position(|a| a == &address_hex) {
                    state.imported.remove(pos);
                    true
                } else {
                    false
                };
            if !was_derived && !was_imported {
                return Err(Error::WalletNotFound(address_hex));
            }
            state.labels.remove(&address_hex);
            state.save_atomic(&self.root.join(STATE_FILE))?;
            was_imported
        };

        if let Ok(mut c) = self.cache.lock() {
            c.remove(&address_hex);
        }
        // The secret only exists on disk for imported/independent keys;
        // HD-derived addresses have no per-key file (re-derivable from seed).
        if was_imported {
            let path = self
                .root
                .join(IMPORTED_DIR)
                .join(format!("{address_hex}.key.enc"));
            if path.exists() {
                std::fs::remove_file(&path)?;
            }
            // Drop the sealed standard mnemonic too (present only for standard
            // addresses), so deleting an address leaves nothing behind.
            let mpath = self
                .root
                .join(IMPORTED_DIR)
                .join(format!("{address_hex}{MNEMONIC_SUFFIX}"));
            if mpath.exists() {
                let _ = std::fs::remove_file(&mpath);
            }
        }
        Ok(())
    }

    fn import_vault(&self, blob: &[u8], passphrase: &[u8]) -> Result<Vec<String>> {
        let bytes = sealed::unseal(passphrase, VAULT_AAD, blob)?;
        let doc: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| Error::ParseError(format!("vault: {e}")))?;
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
            let raw =
                hex::decode(secret_hex).map_err(|e| Error::BadHex(format!("vault secret: {e}")))?;
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
        let store = KeyringStore::open_or_init_fresh(dir.path(), b"pw").unwrap();
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
        let s1 = KeyringStore::open_or_init_fresh(dir.path(), b"pw").unwrap();
        let _ = s1.take_fresh_mnemonic();
        let a = s1.create(None).unwrap().address;
        let b = s1.create(Some("user-1".into())).unwrap().address;
        drop(s1);

        let s2 = KeyringStore::open_or_init_fresh(dir.path(), b"pw").unwrap();
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
        let _s1 = KeyringStore::open_or_init_fresh(dir.path(), b"right").unwrap();
        let err = KeyringStore::open_or_init_fresh(dir.path(), b"wrong").unwrap_err();
        assert!(matches!(err, Error::KeystoreLocked(_)));
    }

    #[test]
    fn derivation_is_deterministic_for_same_seed() {
        // Generate one keystore, capture addresses, blow away state.json,
        // reopen, derive same indices — addresses must match because they
        // come from the seed not from state.
        let dir = temp();
        let s1 = KeyringStore::open_or_init_fresh(dir.path(), b"pw").unwrap();
        let a0 = s1.derive(0).address_hex();
        let a1 = s1.derive(1).address_hex();
        drop(s1);

        let s2 = KeyringStore::open_or_init_fresh(dir.path(), b"pw").unwrap();
        assert_eq!(s2.derive(0).address_hex(), a0);
        assert_eq!(s2.derive(1).address_hex(), a1);
    }

    #[test]
    fn import_roundtrip() {
        let dir = temp();
        let store = KeyringStore::open_or_init_fresh(dir.path(), b"pw").unwrap();
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
        let src = KeyringStore::open_or_init_fresh(src_dir.path(), b"pw").unwrap();
        let _ = src.take_fresh_mnemonic();
        let (a, _) = src.create_independent(Some("savings".into())).unwrap();
        let (b, _) = src.create_independent(None).unwrap();
        let c = src.create(Some("hd-0".into())).unwrap().address;

        let blob = src.export_vault(b"pw").unwrap();
        assert!(!blob.is_empty());
        // Wrong passphrase must not decrypt.
        let dst_dir = temp();
        let dst = KeyringStore::open_or_init_fresh(dst_dir.path(), b"pw2").unwrap();
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
            row.iter()
                .find(|e| e.address == a)
                .unwrap()
                .label
                .as_deref(),
            Some("savings"),
        );
    }

    #[test]
    fn address_mnemonic_roundtrip() {
        // Each address has its OWN 24-word phrase; importing it elsewhere
        // reproduces exactly that one address as an independent key.
        let src_dir = temp();
        let src = KeyringStore::open_or_init_fresh(src_dir.path(), b"pw").unwrap();
        let _ = src.take_fresh_mnemonic();
        let (a, _) = src.create_independent(Some("vault-a".into())).unwrap();

        let words = src.reveal_address_mnemonic(&a, b"pw").unwrap();
        assert_eq!(words.len(), 24);
        // Wrong passphrase must not reveal.
        assert!(matches!(
            src.reveal_address_mnemonic(&a, b"nope"),
            Err(Error::KeystoreLocked(_))
        ));

        // Import the phrase into a fresh, unrelated wallet → same address.
        let dst_dir = temp();
        let dst = KeyringStore::open_or_init_fresh(dst_dir.path(), b"other").unwrap();
        let _ = dst.take_fresh_mnemonic();
        let phrase = words.join(" ");
        let restored = dst
            .import_mnemonic(&phrase, Some("restored".into()))
            .unwrap();
        assert_eq!(
            restored, a,
            "address-mnemonic must reproduce the same address"
        );
        assert!(dst.load_by_address(&a).unwrap().address_hex() == a);

        // A derived address also yields a working per-address phrase.
        let hd = src.create(None).unwrap().address;
        let hd_words = src.reveal_address_mnemonic(&hd, b"pw").unwrap();
        let hd_restored = dst.import_mnemonic(&hd_words.join(" "), None).unwrap();
        assert_eq!(hd_restored, hd);
    }

    // Ground truth from exfer.dev (the web wallet): the standard scheme on this
    // public BIP-39 test phrase yields this exact address. If our standard
    // derivation ever drifts from the rest of the ecosystem, this fails.
    #[test]
    fn standard_scheme_matches_exfer_dev_vector() {
        let phrase = format!("{}art", "abandon ".repeat(23));
        let m = Mnemonic::parse_in(Language::English, phrase.trim()).unwrap();
        let secret = standard_secret_from_mnemonic(&m);
        let addr = Signer::from_secret_bytes(&secret).address_hex();
        assert_eq!(
            addr,
            "f74919726a8c38fff716258f85e0a569abaf9add9717d5ac8106eaca51ff3073"
        );
    }

    #[test]
    fn standard_address_reveals_standard_phrase() {
        let dir = temp();
        let store = KeyringStore::open_or_init_fresh(dir.path(), b"pw").unwrap();
        let _ = store.take_fresh_mnemonic();

        let (addr, _pubkey) = store.create_standard(Some("std".into())).unwrap();

        // Reveal returns the STANDARD phrase (not the legacy raw-key encoding),
        // and that phrase re-derives the same address under the standard scheme.
        let words = store.reveal_address_mnemonic(&addr, b"pw").unwrap();
        assert_eq!(words.len(), 24);
        let m = Mnemonic::parse_in(Language::English, &words.join(" ")).unwrap();
        let redrived = Signer::from_secret_bytes(&standard_secret_from_mnemonic(&m)).address_hex();
        assert_eq!(redrived, addr, "standard phrase must reproduce the address");

        // Wrong passphrase must not reveal.
        assert!(store.reveal_address_mnemonic(&addr, b"nope").is_err());

        // Importing that standard phrase as a RAW key (legacy) would land on a
        // DIFFERENT address — proving reveal returned the standard form.
        let dst_dir = temp();
        let dst = KeyringStore::open_or_init_fresh(dst_dir.path(), b"x").unwrap();
        let _ = dst.take_fresh_mnemonic();
        let legacy_addr = dst.import_mnemonic(&words.join(" "), None).unwrap();
        assert_ne!(legacy_addr, addr);
    }

    #[test]
    fn mixed_wallet_old_and_new_addresses_all_behave() {
        // A long-time user's wallet: legacy independent + HD addresses, an OLD
        // phrase imported from another wallet, a raw key imported from a
        // wallet.key, and NEW standard addresses — all mixed in one keystore.
        // Every kind must reveal + round-trip to the RIGHT address, survive a
        // reopen, and not disturb the others.
        let std_addr_of = |phrase: &str| {
            let m = Mnemonic::parse_in(Language::English, phrase).unwrap();
            Signer::from_secret_bytes(&standard_secret_from_mnemonic(&m)).address_hex()
        };
        let legacy_addr_of = |phrase: &str| {
            let m = Mnemonic::parse_in(Language::English, phrase).unwrap();
            let mut e = [0u8; 32];
            e.copy_from_slice(&m.to_entropy());
            Signer::from_secret_bytes(&e).address_hex()
        };

        let dir = temp();
        let store = KeyringStore::open_or_init_fresh(dir.path(), b"pw").unwrap();
        let _ = store.take_fresh_mnemonic();

        // (1) legacy independent (old "new address")
        let (legacy_ind, _) = store.create_independent(Some("ind".into())).unwrap();
        // (2) HD-derived (old generate_address)
        let hd = store.create(Some("hd".into())).unwrap().address;
        // (3) an OLD phrase exported from a DIFFERENT wallet, imported here
        let other_dir = temp();
        let other = KeyringStore::open_or_init_fresh(other_dir.path(), b"o").unwrap();
        let _ = other.take_fresh_mnemonic();
        let (other_addr, _) = other.create_independent(None).unwrap();
        let old_phrase = other
            .reveal_address_mnemonic(&other_addr, b"o")
            .unwrap()
            .join(" ");
        let imported_phrase = store
            .import_mnemonic(&old_phrase, Some("imp-phrase".into()))
            .unwrap();
        assert_eq!(
            imported_phrase, other_addr,
            "old phrase reproduces its address"
        );
        // (4) a raw private key imported (e.g. a wallet.key)
        let raw = [0x11u8; 32];
        let imported_key = store.import(&raw, Some("imp-key".into())).unwrap();
        assert_eq!(imported_key, Signer::from_secret_bytes(&raw).address_hex());
        // (5) two NEW standard addresses
        let (std_a, _) = store.create_standard(Some("std-a".into())).unwrap();
        let (std_b, _) = store.create_standard(Some("std-b".into())).unwrap();
        assert_ne!(std_a, std_b);

        // --- standard addresses reveal the STANDARD phrase (re-derives the
        //     same address under the standard scheme; legacy interp differs) ---
        for std in [&std_a, &std_b] {
            let p = store.reveal_address_mnemonic(std, b"pw").unwrap().join(" ");
            assert_eq!(std_addr_of(&p), *std, "standard phrase → standard address");
            assert_ne!(legacy_addr_of(&p), *std, "legacy interp must differ");
        }

        // --- legacy/imported addresses reveal the legacy (raw-key) phrase
        //     (round-trips as legacy; standard interp differs) ---
        for leg in [&legacy_ind, &hd, &imported_phrase, &imported_key] {
            let p = store.reveal_address_mnemonic(leg, b"pw").unwrap().join(" ");
            assert_eq!(legacy_addr_of(&p), *leg, "legacy phrase → same address");
            assert_ne!(std_addr_of(&p), *leg, "standard interp must differ");
        }
        // the imported old phrase reveals EXACTLY what was imported
        assert_eq!(
            store
                .reveal_address_mnemonic(&imported_phrase, b"pw")
                .unwrap()
                .join(" "),
            old_phrase
        );

        // --- persistence: reopen the keystore, behaviour is identical ---
        let std_a_phrase = store.reveal_address_mnemonic(&std_a, b"pw").unwrap();
        drop(store);
        let store = KeyringStore::open_keyring(dir.path(), b"pw").unwrap();
        assert_eq!(
            store.reveal_address_mnemonic(&std_a, b"pw").unwrap(),
            std_a_phrase
        );
        assert_eq!(std_addr_of(&std_a_phrase.join(" ")), std_a);
        // legacy still legacy after reopen
        let li = store
            .reveal_address_mnemonic(&legacy_ind, b"pw")
            .unwrap()
            .join(" ");
        assert_eq!(legacy_addr_of(&li), legacy_ind);

        // --- wrong passphrase fails for both kinds ---
        assert!(store.reveal_address_mnemonic(&std_a, b"nope").is_err());
        assert!(store.reveal_address_mnemonic(&legacy_ind, b"nope").is_err());

        // --- vault backup/restore preserves every address (the key), so funds
        //     are safe; a restored standard address reverts to the legacy
        //     reveal because the vault carries raw keys, not sealed phrases ---
        let vault = store.export_vault(b"pw").unwrap();
        let v_dir = temp();
        let vstore = KeyringStore::open_or_init_fresh(v_dir.path(), b"v2").unwrap();
        let _ = vstore.take_fresh_mnemonic();
        vstore.import_vault(&vault, b"pw").unwrap();
        let restored: std::collections::BTreeSet<String> = vstore
            .list()
            .unwrap()
            .into_iter()
            .map(|e| e.address)
            .collect();
        for a in [
            &legacy_ind,
            &hd,
            &imported_phrase,
            &imported_key,
            &std_a,
            &std_b,
        ] {
            assert!(restored.contains(a), "vault must restore {a}");
        }
        // restored standard address → same address, legacy reveal now
        let rp = vstore
            .reveal_address_mnemonic(&std_a, b"v2")
            .unwrap()
            .join(" ");
        assert_eq!(legacy_addr_of(&rp), std_a);

        // --- delete a standard address removes its sealed mnemonic file ---
        store.delete(&std_b, b"pw").unwrap();
        let mpath = dir
            .path()
            .join("imported")
            .join(format!("{std_b}.mnemonic.enc"));
        assert!(!mpath.exists(), "deleting must drop the sealed mnemonic");
        let live: std::collections::BTreeSet<String> = store
            .list()
            .unwrap()
            .into_iter()
            .map(|e| e.address)
            .collect();
        assert!(!live.contains(&std_b) && live.contains(&std_a));
    }

    #[test]
    fn standard_phrase_round_trips_via_import_standard_mnemonic() {
        // Symmetry: a standard phrase revealed here re-imports to the SAME
        // address (and seals so it reveals back), while importing it as legacy
        // lands elsewhere.
        let dir = temp();
        let store = KeyringStore::open_or_init_fresh(dir.path(), b"pw").unwrap();
        let _ = store.take_fresh_mnemonic();
        let (addr, _) = store.create_standard(Some("s".into())).unwrap();
        let phrase = store
            .reveal_address_mnemonic(&addr, b"pw")
            .unwrap()
            .join(" ");

        let dst_dir = temp();
        let dst = KeyringStore::open_or_init_fresh(dst_dir.path(), b"x").unwrap();
        let _ = dst.take_fresh_mnemonic();
        let restored = dst.import_standard_mnemonic(&phrase, None).unwrap();
        assert_eq!(restored, addr, "standard import reproduces the address");
        assert_eq!(
            dst.reveal_address_mnemonic(&restored, b"x")
                .unwrap()
                .join(" "),
            phrase,
            "imported standard phrase reveals back the same phrase"
        );

        let dst2_dir = temp();
        let dst2 = KeyringStore::open_or_init_fresh(dst2_dir.path(), b"y").unwrap();
        let _ = dst2.take_fresh_mnemonic();
        let as_legacy = dst2.import_mnemonic(&phrase, None).unwrap();
        assert_ne!(as_legacy, addr, "same phrase as legacy lands elsewhere");
    }

    #[test]
    fn legacy_address_still_reveals_raw_key_phrase() {
        // Backward compatibility: an independent (legacy) address has no sealed
        // standard mnemonic, so reveal falls back to the raw-key encoding and
        // re-imports to the SAME address — exactly as before this change.
        let dir = temp();
        let store = KeyringStore::open_or_init_fresh(dir.path(), b"pw").unwrap();
        let _ = store.take_fresh_mnemonic();
        let (addr, _) = store.create_independent(None).unwrap();
        let words = store.reveal_address_mnemonic(&addr, b"pw").unwrap();

        let dst_dir = temp();
        let dst = KeyringStore::open_or_init_fresh(dst_dir.path(), b"x").unwrap();
        let _ = dst.take_fresh_mnemonic();
        let restored = dst.import_mnemonic(&words.join(" "), None).unwrap();
        assert_eq!(restored, addr);
    }

    #[test]
    fn delete_removes_address() {
        let dir = temp();
        let store = KeyringStore::open_or_init_fresh(dir.path(), b"pw").unwrap();
        let _ = store.take_fresh_mnemonic();
        let (a, _) = store.create_independent(None).unwrap();
        let (b, _) = store.create_independent(None).unwrap();
        let key_file = dir.path().join(IMPORTED_DIR).join(format!("{a}.key.enc"));
        assert!(key_file.exists());

        // Wrong passphrase can't delete.
        assert!(matches!(
            store.delete(&a, b"nope"),
            Err(Error::KeystoreLocked(_))
        ));
        assert!(store.exists(&a));

        store.delete(&a, b"pw").unwrap();
        assert!(!store.exists(&a));
        assert!(!key_file.exists(), "sealed key file must be erased");
        assert!(matches!(
            store.load_by_address(&a),
            Err(Error::WalletNotFound(_))
        ));
        // The other key is untouched.
        assert!(store.exists(&b));
        assert_eq!(store.list().unwrap().len(), 1);

        // Deleting an unknown address is a typed error.
        assert!(matches!(
            store.delete(&a, b"pw"),
            Err(Error::WalletNotFound(_))
        ));
    }

    #[test]
    fn export_single_address_imports_only_that_key() {
        let src_dir = temp();
        let src = KeyringStore::open_or_init_fresh(src_dir.path(), b"pw").unwrap();
        let _ = src.take_fresh_mnemonic();
        let (a, _) = src.create_independent(Some("one".into())).unwrap();
        let (b, _) = src.create_independent(None).unwrap();

        // Export just `a`; the blob is a one-key vault.
        let blob = src
            .export_selected(std::slice::from_ref(&a), b"pw")
            .unwrap();
        // Requesting an unknown address errors.
        assert!(matches!(
            src.export_selected(&["ab".repeat(32)], b"pw"),
            Err(Error::WalletNotFound(_))
        ));

        let dst_dir = temp();
        let dst = KeyringStore::open_or_init_fresh(dst_dir.path(), b"pw2").unwrap();
        let _ = dst.take_fresh_mnemonic();
        let imported = dst.import_vault(&blob, b"pw").unwrap();
        assert_eq!(imported, vec![a.clone()]);
        assert!(dst.exists(&a));
        assert!(
            !dst.exists(&b),
            "single-key export must not carry other keys"
        );
    }

    #[test]
    fn seedless_keyring_has_no_seed_but_full_keyring_lifecycle() {
        let dir = temp();
        let store = KeyringStore::open_keyring(dir.path(), b"pw").unwrap();
        // No HD seed was generated.
        assert!(
            !dir.path().join(SEED_FILE).exists(),
            "seedless: no seed.enc"
        );
        assert!(store.take_fresh_mnemonic().is_none());

        // HD-only operations are refused; independent keys work.
        assert!(matches!(store.create(None), Err(Error::BadParams(_))));
        assert!(matches!(
            store.reveal_mnemonic(b"pw"),
            Err(Error::BadParams(_))
        ));
        let (a, _) = store.create_independent(Some("ind".into())).unwrap();
        assert!(store.exists(&a));

        // Per-address mnemonic, export, delete all work without a seed.
        let words = store.reveal_address_mnemonic(&a, b"pw").unwrap();
        assert_eq!(words.len(), 24);
        let blob = store.export_vault(b"pw").unwrap();
        assert!(!blob.is_empty());
        store.delete(&a, b"pw").unwrap();
        assert!(!store.exists(&a));
    }

    #[test]
    fn seedless_reopen_verifies_passphrase_against_a_key() {
        // Once a seedless keyring holds a key, reopening with the wrong
        // passphrase must fail rather than silently mis-seal future keys.
        let dir = temp();
        let s1 = KeyringStore::open_keyring(dir.path(), b"right").unwrap();
        let (_a, _) = s1.create_independent(None).unwrap();
        drop(s1);

        assert!(matches!(
            KeyringStore::open_keyring(dir.path(), b"wrong"),
            Err(Error::KeystoreLocked(_))
        ));
        // Correct passphrase reopens fine.
        assert!(KeyringStore::open_keyring(dir.path(), b"right").is_ok());
    }

    #[test]
    fn open_keyring_loads_an_existing_seeded_wallet() {
        // Backward compat: a wallet created seeded still opens (with its
        // seed) through the seedless constructor.
        let dir = temp();
        let seeded = KeyringStore::open_or_init_fresh(dir.path(), b"pw").unwrap();
        let _ = seeded.take_fresh_mnemonic();
        let hd = seeded.create(None).unwrap().address;
        drop(seeded);

        let reopened = KeyringStore::open_keyring(dir.path(), b"pw").unwrap();
        assert!(reopened.exists(&hd));
        // Seed is present → seed mnemonic still works, HD derive still works.
        assert_eq!(reopened.reveal_mnemonic(b"pw").unwrap().len(), 24);
        assert!(reopened.create(None).is_ok());
    }

    #[test]
    fn load_unknown_address_returns_typed_error() {
        let dir = temp();
        let store = KeyringStore::open_or_init_fresh(dir.path(), b"pw").unwrap();
        let res = store.load_by_address(&"ab".repeat(32));
        assert!(matches!(res, Err(Error::WalletNotFound(_))));
    }

    // ---- independent BSC/EVM key -------------------------------------------

    /// MetaMask-importable: a fresh mnemonic derives the SAME secp256k1 key at
    /// m/44'/60'/0'/0/0 as the canonical anvil test vector.
    #[test]
    fn evm_mnemonic_derivation_matches_metamask_vector() {
        let m = Mnemonic::parse_in(
            Language::English,
            "test test test test test test test test test test test junk",
        )
        .unwrap();
        let secret = evm_secret_from_mnemonic(&m).unwrap();
        assert_eq!(
            crate::evm::evm_address(&secret).unwrap(),
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        );
    }

    /// REGRESSION GUARD: a seeded wallet's seed-derived BSC address must stay
    /// byte-identical and keep working — the independent-key change is purely
    /// additive for seeded wallets that never create an independent key.
    #[test]
    fn seeded_bsc_address_unchanged_and_first_in_resolution() {
        let dir = temp();
        let store = KeyringStore::open_or_init_fresh(dir.path(), b"pw").unwrap();
        let _ = store.take_fresh_mnemonic();

        let seed_secret = store.evm_secret().unwrap();
        let seed_addr = crate::evm::evm_address(&seed_secret).unwrap();
        // evm_address_opt agrees and never errors.
        assert_eq!(store.evm_address_opt().unwrap().as_deref(), Some(seed_addr.as_str()));
        // reveal_evm_mnemonic on a seeded-without-independent wallet returns the
        // SEED phrase (24 words), and that phrase reproduces the same address.
        let words = store.reveal_evm_mnemonic(b"pw").unwrap();
        let from_seed_phrase =
            evm_secret_from_mnemonic(&Mnemonic::parse_in(Language::English, &words.join(" ")).unwrap())
                .unwrap();
        assert_eq!(crate::evm::evm_address(&from_seed_phrase).unwrap(), seed_addr);
    }

    /// VERIFIER REGRESSION: restore a wallet from a FIXED known seed phrase and
    /// assert its seed-derived BSC address equals an EXTERNAL fixed vector
    /// (the canonical anvil mnemonic → 0xf39Fd6…92266 at m/44'/60'/0'/0/0).
    /// This pins the seed→BSC derivation byte-for-byte against an address that
    /// existing operator wallets already hold funds on, independent of any
    /// other code path. If this address ever changes, seeded wallets' BNB is
    /// stranded — the exact funds-loss this change must NOT cause.
    #[test]
    fn verifier_seeded_restore_bsc_address_matches_external_vector() {
        // A FIXED, public 24-word BIP-39 vector (the canonical "abandon…art"
        // zero-entropy mnemonic). Its m/44'/60'/0'/0/0 secp256k1 address is a
        // well-known external value (e.g. Trezor/MetaMask derive the same).
        const PHRASE: &str = "abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon abandon abandon abandon \
            abandon art";
        // m/44'/60'/0'/0/0 (Ethereum path) address for this phrase — the
        // canonical "abandon…art" account #0 ETH address (publicly known).
        const EXPECTED: &str = "0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb";

        // Cross-check the EXTERNAL vector against the pure derivation helper,
        // independent of the keystore — pins the path/derivation itself.
        let direct = evm_secret_from_mnemonic(
            &Mnemonic::parse_in(Language::English, PHRASE).unwrap(),
        )
        .unwrap();
        assert_eq!(crate::evm::evm_address(&direct).unwrap(), EXPECTED);

        let dir = temp();
        KeyringStore::init_from_mnemonic(dir.path(), b"pw", PHRASE).unwrap();
        let store = KeyringStore::open_or_init_fresh(dir.path(), b"pw").unwrap();

        // The seeded wallet resolves its BSC key via the SEED branch (no
        // independent key present), and it must equal the external vector.
        let secret = store.evm_secret().unwrap();
        assert_eq!(crate::evm::evm_address(&secret).unwrap(), EXPECTED);
        assert_eq!(store.evm_address_opt().unwrap().as_deref(), Some(EXPECTED));

        // Creating an independent key (force) must NOT silently move the
        // canonical address: it shadows it, and evm_secret now resolves the
        // NEW key — but the seed address is still recoverable from the phrase,
        // proving no destructive in-place mutation of the seed material.
        let (ind_addr, _w) = store.create_evm_key(true).unwrap();
        assert_ne!(ind_addr, EXPECTED);
        let reseed = evm_secret_from_mnemonic(
            &Mnemonic::parse_in(Language::English, PHRASE).unwrap(),
        )
        .unwrap();
        assert_eq!(crate::evm::evm_address(&reseed).unwrap(), EXPECTED);
    }

    /// On a seedless wallet evm_secret is a typed EvmKeyNotCreated until a key
    /// is created; create→reveal→delete round-trips and reveal reproduces it.
    #[test]
    fn seedless_create_reveal_roundtrip() {
        let dir = temp();
        let store = KeyringStore::open_keyring(dir.path(), b"pw").unwrap();
        assert!(matches!(store.evm_secret(), Err(Error::EvmKeyNotCreated)));
        assert_eq!(store.evm_address_opt().unwrap(), None);

        let (addr, words) = store.create_evm_key(false).unwrap();
        assert_eq!(words.len(), 24);
        // The independent key is now THE BSC key.
        assert_eq!(store.evm_address_opt().unwrap().as_deref(), Some(addr.as_str()));
        let secret = store.evm_secret().unwrap();
        assert_eq!(crate::evm::evm_address(&secret).unwrap(), addr);

        // Reveal returns its own phrase, which reproduces the address.
        let revealed = store.reveal_evm_mnemonic(b"pw").unwrap();
        assert_eq!(revealed, words);
        let m = Mnemonic::parse_in(Language::English, &revealed.join(" ")).unwrap();
        assert_eq!(
            crate::evm::evm_address(&evm_secret_from_mnemonic(&m).unwrap()).unwrap(),
            addr
        );
        // Wrong passphrase can't reveal.
        assert!(store.reveal_evm_mnemonic(b"nope").is_err());

        // Survives a reopen.
        drop(store);
        let store = KeyringStore::open_keyring(dir.path(), b"pw").unwrap();
        assert_eq!(store.evm_address_opt().unwrap().as_deref(), Some(addr.as_str()));

        // Delete clears state + both files.
        store.delete_evm_key(b"pw").unwrap();
        assert_eq!(store.evm_address_opt().unwrap(), None);
        assert!(!dir.path().join("imported").join(EVM_KEY_FILE).exists());
        assert!(!dir.path().join("imported").join(EVM_MNEMONIC_FILE).exists());
    }

    /// create twice without overwrite is refused; create on a seeded wallet is
    /// refused unless force.
    #[test]
    fn evm_key_overwrite_and_seeded_force_guards() {
        // Seedless: second create rejected.
        let dir = temp();
        let store = KeyringStore::open_keyring(dir.path(), b"pw").unwrap();
        let _ = store.create_evm_key(false).unwrap();
        assert!(matches!(
            store.create_evm_key(false),
            Err(Error::WalletAlreadyExists(_))
        ));

        // Seeded: create refused without force, accepted with force, and the
        // independent key then shadows the seed-derived one.
        let sdir = temp();
        let seeded = KeyringStore::open_or_init_fresh(sdir.path(), b"pw").unwrap();
        let _ = seeded.take_fresh_mnemonic();
        let seed_addr = seeded.evm_address_opt().unwrap().unwrap();
        assert!(matches!(seeded.create_evm_key(false), Err(Error::BadParams(_))));
        let (ind_addr, _) = seeded.create_evm_key(true).unwrap();
        assert_ne!(ind_addr, seed_addr);
        assert_eq!(seeded.evm_address_opt().unwrap().as_deref(), Some(ind_addr.as_str()));
    }

    /// Import a MetaMask mnemonic and a raw key; raw-key reveal is refused.
    #[test]
    fn evm_import_mnemonic_and_raw_key() {
        let dir = temp();
        let store = KeyringStore::open_keyring(dir.path(), b"pw").unwrap();

        // 12-word import works; address matches direct derivation.
        let phrase = "test test test test test test test test test test test junk";
        let addr = store.import_evm_mnemonic(phrase, false).unwrap();
        let expected = crate::evm::evm_address(
            &evm_secret_from_mnemonic(&Mnemonic::parse_in(Language::English, phrase).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(addr, expected);
        // Re-import without overwrite rejected.
        assert!(matches!(
            store.import_evm_mnemonic(phrase, false),
            Err(Error::WalletAlreadyExists(_))
        ));

        // Overwrite with a raw key: no mnemonic, reveal refused with BadParams.
        let raw = [0x11u8; 32];
        let raw_addr = store.import_evm_key(&raw, true).unwrap();
        assert_eq!(raw_addr, crate::evm::evm_address(&raw).unwrap());
        assert!(!dir.path().join("imported").join(EVM_MNEMONIC_FILE).exists());
        assert!(matches!(
            store.reveal_evm_mnemonic(b"pw"),
            Err(Error::BadParams(_))
        ));
        // But the raw secret is usable for signing.
        assert_eq!(crate::evm::evm_address(&store.evm_secret().unwrap()).unwrap(), raw_addr);
    }

    /// A zero / invalid scalar is rejected before sealing a dead key.
    #[test]
    fn evm_import_rejects_invalid_scalar() {
        let dir = temp();
        let store = KeyringStore::open_keyring(dir.path(), b"pw").unwrap();
        assert!(matches!(
            store.import_evm_key(&[0u8; 32], false),
            Err(Error::BadParams(_))
        ));
        // Nothing was persisted.
        assert_eq!(store.evm_address_opt().unwrap(), None);
    }
}
