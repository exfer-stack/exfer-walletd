//! Wallet storage.
//!
//! The store is abstracted behind a trait so the rest of the codebase
//! can be written against `dyn WalletStore`. The single shipped backend
//! is filesystem-based (`FsWalletStore`); future backends — `redb`,
//! cloud KMS, HSMs — implement the same trait and drop in.
//!
//! ## Filesystem layout (the bundled `FsWalletStore`)
//!
//! ```text
//!   <wallet_dir>/
//!   ├── 8d896d64...d750.key     ← one file per managed address
//!   ├── fcbd5a81...c69d.key
//!   └── ...
//! ```
//!
//! The filename is the 64-hex address. Files are unencrypted (server-side,
//! no passphrase prompt possible) but written with mode 0600. Protect the
//! disk at rest with LUKS / fly volume encryption / equivalent.

use std::path::{Path, PathBuf};

use exfer::wallet::wallet::Wallet;

use crate::error::{Error, Result};

// ============================================================================
// Trait
// ============================================================================

/// Persistence-backend abstraction.
///
/// The shipped implementation is [`FsWalletStore`]. Replace it with a
/// `redb`, cloud-KMS, or HSM-backed implementation by writing another
/// type that implements this trait; the API and HTTP layers are agnostic.
pub trait WalletStore: Send + Sync + 'static {
    /// Generate a fresh keypair and persist it. Returns the loaded
    /// `Wallet` and the hex-encoded address used as its identifier.
    fn create(&self) -> Result<(Wallet, String)>;

    /// Load an existing wallet by its 64-hex address.
    fn load(&self, address_hex: &str) -> Result<Wallet>;

    /// Enumerate every managed address. Sorted ascending.
    fn list(&self) -> Result<Vec<String>>;

    /// Whether a wallet exists for the given address.
    fn exists(&self, address_hex: &str) -> bool;
}

// ============================================================================
// Filesystem implementation
// ============================================================================

#[derive(Debug, Clone)]
pub struct FsWalletStore {
    root: PathBuf,
}

impl FsWalletStore {
    /// Open the wallet directory, creating it (mode 0700) if missing.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700));
        }
        Ok(Self { root })
    }

    /// Directory holding the .key files. Useful for tests and logging.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Path for the given 64-hex address.
    fn path_for(&self, address_hex: &str) -> PathBuf {
        self.root.join(format!("{address_hex}.key"))
    }
}

impl WalletStore for FsWalletStore {
    fn create(&self) -> Result<(Wallet, String)> {
        let wallet = Wallet::generate();
        let addr = hex::encode(wallet.address().as_bytes());
        let path = self.path_for(&addr);
        if path.exists() {
            // SHA-256 collision on Ed25519 → effectively impossible.
            // We still guard against accidental overwrite.
            return Err(Error::WalletAlreadyExists(addr));
        }
        wallet
            .save_unencrypted(&path)
            .map_err(|e| Error::Wallet(format!("save {}: {e}", path.display())))?;
        Ok((wallet, addr))
    }

    fn load(&self, address_hex: &str) -> Result<Wallet> {
        let path = self.path_for(address_hex);
        if !path.exists() {
            return Err(Error::WalletNotFound(address_hex.to_string()));
        }
        // We always save with `save_unencrypted`, so passphrase is None.
        Wallet::load(&path, None).map_err(|e| Error::Wallet(format!("load {}: {e}", path.display())))
    }

    fn list(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            let path = entry.path();
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let ext = path.extension().and_then(|s| s.to_str());
            if ext != Some("key") {
                continue;
            }
            if stem.len() == 64 && stem.chars().all(|c| c.is_ascii_hexdigit()) {
                out.push(stem.to_string());
            }
        }
        out.sort();
        Ok(out)
    }

    fn exists(&self, address_hex: &str) -> bool {
        self.path_for(address_hex).exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> (tempfile::TempDir, FsWalletStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = FsWalletStore::open(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn create_then_load_roundtrip() {
        let (_dir, store) = temp();
        let (w1, addr) = store.create().unwrap();
        assert_eq!(addr.len(), 64);
        let w2 = store.load(&addr).unwrap();
        assert_eq!(w1.pubkey(), w2.pubkey());
        assert_eq!(w1.address().as_bytes(), w2.address().as_bytes());
    }

    #[test]
    fn list_returns_all_created_addresses() {
        let (_dir, store) = temp();
        let mut expected = Vec::new();
        for _ in 0..3 {
            let (_w, addr) = store.create().unwrap();
            expected.push(addr);
        }
        expected.sort();
        let listed = store.list().unwrap();
        assert_eq!(listed, expected);
    }

    #[test]
    fn load_missing_returns_typed_error() {
        let (_dir, store) = temp();
        let result = store.load(&"00".repeat(32));
        assert!(matches!(result, Err(Error::WalletNotFound(_))));
    }

    #[test]
    fn exists_works() {
        let (_dir, store) = temp();
        let (_w, addr) = store.create().unwrap();
        assert!(store.exists(&addr));
        assert!(!store.exists(&"00".repeat(32)));
    }
}
