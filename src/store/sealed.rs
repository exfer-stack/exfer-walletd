//! Argon2id + ChaCha20-Poly1305 sealing helpers.
//!
//! On-disk format (`.sealed` files):
//!
//! ```text
//!   magic: "WDV1" (4)
//!   version: u8 (1)
//!   argon2id salt (16)
//!   nonce (12)
//!   ciphertext (variable: payload bytes + 16-byte Poly1305 tag)
//! ```
//!
//! Argon2id parameters: m=64 MiB / t=3 / p=1. Picked to sit at ~0.5–1s on
//! a modern x86 core — slow enough to defeat offline brute force against
//! medium-strength passphrases, fast enough that startup (one unseal per
//! seed) and rare imported-key access don't feel sluggish.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

use crate::error::{Error, Result};

pub const MAGIC: &[u8; 4] = b"WDV1";
pub const VERSION: u8 = 1;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const HEADER_LEN: usize = MAGIC.len() + 1 + SALT_LEN + NONCE_LEN;

/// Argon2id parameters. Documented above; keep them in code so the value
/// is committed alongside the format and a future bump (`V2`) is easy.
fn argon2_params() -> Argon2<'static> {
    let p = Params::new(65_536, 3, 1, Some(32)).expect("static argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
}

fn derive_kek(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let argon = argon2_params();
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| Error::KeystoreLocked(format!("argon2id derive failed: {e}")))?;
    Ok(out)
}

/// Seal `payload` under `passphrase` and return the on-disk bytes.
pub fn seal(passphrase: &[u8], aad: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    let mut kek = derive_kek(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&kek));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(nonce, Payload { msg: payload, aad })
        .map_err(|e| Error::Internal(format!("chacha20poly1305 encrypt: {e}")))?;
    kek.zeroize();

    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt the inverse of [`seal`]. The `aad` argument must match what
/// was supplied at seal time; mismatch → `KeystoreLocked`.
pub fn unseal(passphrase: &[u8], aad: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < HEADER_LEN + TAG_LEN {
        return Err(Error::KeystoreLocked(format!(
            "sealed blob too short: {} bytes (min {})",
            blob.len(),
            HEADER_LEN + TAG_LEN
        )));
    }
    if &blob[0..4] != MAGIC {
        return Err(Error::KeystoreLocked(
            "sealed blob magic mismatch (not a walletd keystore file)".into(),
        ));
    }
    if blob[4] != VERSION {
        return Err(Error::KeystoreLocked(format!(
            "unsupported keystore version {} (expected {VERSION})",
            blob[4]
        )));
    }
    let salt = &blob[5..5 + SALT_LEN];
    let nonce_bytes = &blob[5 + SALT_LEN..5 + SALT_LEN + NONCE_LEN];
    let ct = &blob[HEADER_LEN..];

    let mut kek = derive_kek(passphrase, salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&kek));
    let nonce = Nonce::from_slice(nonce_bytes);

    let pt = cipher
        .decrypt(nonce, Payload { msg: ct, aad })
        .map_err(|_| Error::KeystoreLocked("decryption failed (wrong passphrase?)".into()))?;
    kek.zeroize();
    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_seal_unseal() {
        let pt = b"hello world";
        let blob = seal(b"correct horse battery staple", b"aad", pt).unwrap();
        let recovered = unseal(b"correct horse battery staple", b"aad", &blob).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let blob = seal(b"right", b"", b"secret").unwrap();
        let err = unseal(b"wrong", b"", &blob).unwrap_err();
        assert!(matches!(err, Error::KeystoreLocked(_)));
    }

    #[test]
    fn wrong_aad_fails() {
        let blob = seal(b"pw", b"context-A", b"secret").unwrap();
        let err = unseal(b"pw", b"context-B", &blob).unwrap_err();
        assert!(matches!(err, Error::KeystoreLocked(_)));
    }

    #[test]
    fn truncated_blob_fails() {
        let blob = seal(b"pw", b"", b"secret").unwrap();
        let err = unseal(b"pw", b"", &blob[..HEADER_LEN]).unwrap_err();
        assert!(matches!(err, Error::KeystoreLocked(_)));
    }

    #[test]
    fn bad_magic_fails() {
        let mut blob = seal(b"pw", b"", b"secret").unwrap();
        blob[0] = b'X';
        let err = unseal(b"pw", b"", &blob).unwrap_err();
        assert!(matches!(err, Error::KeystoreLocked(_)));
    }
}
