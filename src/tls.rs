//! Self-signed TLS for the JSON-RPC listener.
//!
//! When `--tls` is set, walletd serves HTTPS using a self-signed leaf
//! certificate that it generates on first run alongside the bearer
//! token. The SDK side (`exfer-walletd-py`) pins the cert by SHA-256
//! fingerprint instead of validating against a CA chain — so there is
//! no PKI, no rotation ceremony, and no need for a reverse proxy or a
//! TLS terminator like Caddy / nginx.
//!
//! First-run side effects (mirrors `ensure_token_file`):
//!
//! - `<datadir>/cert.pem` — PEM-encoded leaf cert (mode 0600)
//! - `<datadir>/cert.key` — PEM-encoded private key (mode 0600)
//! - `<datadir>/cert.fingerprint` — `sha256:<lowercase-hex-64>\n` (mode 0600)
//!
//! On subsequent runs, the existing files are loaded as-is. To force a
//! new cert, delete all three.

use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use rcgen::{CertificateParams, DnType, KeyPair, SanType};
use rustls::ServerConfig;
use rustls_pemfile::Item;
use sha2::{Digest, Sha256};

/// Loaded TLS material. The `fingerprint` is in the canonical wire
/// form (`sha256:<hex>`) and is what the SDK side compares against the
/// peer cert it sees during the handshake.
pub struct TlsMaterial {
    pub server_config: Arc<ServerConfig>,
    pub fingerprint: String,
    pub generated: bool,
}

/// Ensure cert + key + fingerprint files exist at the configured paths.
///
/// If all three exist, load and return them. If any are missing, generate
/// a fresh self-signed cert, write the trio with mode 0600, and print
/// the same first-run box used for the token (so operators see the
/// fingerprint exactly once on first start). `extra_san` lets the caller
/// add the configured bind IP when it's not loopback, so `openssl
/// s_client` and friends don't complain about SAN mismatch even though
/// the SDK doesn't care.
pub fn ensure_cert_files(
    cert_path: &Path,
    key_path: &Path,
    fingerprint_path: &Path,
    extra_san: Option<IpAddr>,
) -> anyhow::Result<TlsMaterial> {
    let all_exist = cert_path.exists() && key_path.exists() && fingerprint_path.exists();

    if all_exist {
        let server_config = load_server_config(cert_path, key_path)?;
        let fingerprint = fs::read_to_string(fingerprint_path)
            .with_context(|| format!("reading {}", fingerprint_path.display()))?
            .trim()
            .to_string();
        return Ok(TlsMaterial {
            server_config,
            fingerprint,
            generated: false,
        });
    }

    let (cert_pem, key_pem, fingerprint) = generate_self_signed(extra_san)?;
    write_file(cert_path, cert_pem.as_bytes())?;
    write_file(key_path, key_pem.as_bytes())?;
    write_file(fingerprint_path, format!("{fingerprint}\n").as_bytes())?;

    print_first_run_box(cert_path, fingerprint_path, &fingerprint);

    let server_config = load_server_config(cert_path, key_path)?;
    Ok(TlsMaterial {
        server_config,
        fingerprint,
        generated: true,
    })
}

fn generate_self_signed(extra_san: Option<IpAddr>) -> anyhow::Result<(String, String, String)> {
    let mut sans = vec![
        SanType::DnsName("localhost".try_into()?),
        SanType::IpAddress(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        SanType::IpAddress(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
    ];
    if let Some(extra) = extra_san {
        if !extra.is_loopback() {
            sans.push(SanType::IpAddress(extra));
        }
    }

    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "exfer-walletd");
    params.subject_alt_names = sans;
    // rcgen's default is 4096 days; bump to ~10 years so operators
    // don't have to think about rotation in any realistic timeframe.
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(3650);

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let fingerprint = sha256_fingerprint(cert.der());

    Ok((cert_pem, key_pem, fingerprint))
}

fn sha256_fingerprint(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    format!("sha256:{}", hex::encode(digest))
}

fn load_server_config(cert_path: &Path, key_path: &Path) -> anyhow::Result<Arc<ServerConfig>> {
    // rustls 0.23 needs a crypto provider installed once per process.
    // ring is the default; the install_default call is idempotent
    // (returns Err if a provider is already installed, which we ignore).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut cert_reader = std::io::BufReader::new(fs::File::open(cert_path)?);
    let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader).collect::<Result<_, _>>()?;
    anyhow::ensure!(
        !cert_chain.is_empty(),
        "no certificates found in {}",
        cert_path.display()
    );

    let mut key_reader = std::io::BufReader::new(fs::File::open(key_path)?);
    let key = rustls_pemfile::read_one(&mut key_reader)?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", key_path.display()))?;
    let private_key: rustls::pki_types::PrivateKeyDer<'static> = match key {
        Item::Pkcs8Key(k) => rustls::pki_types::PrivateKeyDer::Pkcs8(k),
        Item::Pkcs1Key(k) => rustls::pki_types::PrivateKeyDer::Pkcs1(k),
        Item::Sec1Key(k) => rustls::pki_types::PrivateKeyDer::Sec1(k),
        other => anyhow::bail!(
            "unsupported key format in {}: {:?}",
            key_path.display(),
            other
        ),
    };

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("building rustls ServerConfig")?;
    Ok(Arc::new(server_config))
}

fn write_file(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(contents)?;
    Ok(())
}

fn print_first_run_box(cert_path: &Path, fingerprint_path: &Path, fingerprint: &str) {
    eprintln!();
    eprintln!("  ┌─ first run ───────────────────────────────────────────────────────────");
    eprintln!("  │ generated self-signed TLS cert");
    eprintln!("  │   cert:        {}", cert_path.display());
    eprintln!("  │   fingerprint: {}", fingerprint_path.display());
    eprintln!("  │");
    eprintln!("  │     {fingerprint}");
    eprintln!("  │");
    eprintln!("  │ pin this value on the client side (SDK: fingerprint=…).");
    eprintln!("  └───────────────────────────────────────────────────────────────────────");
    eprintln!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn paths(dir: &TempDir) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        (
            dir.path().join("cert.pem"),
            dir.path().join("cert.key"),
            dir.path().join("cert.fingerprint"),
        )
    }

    #[test]
    fn generates_and_persists_trio_on_first_run() {
        let dir = TempDir::new().unwrap();
        let (cert, key, fp) = paths(&dir);

        let m = ensure_cert_files(&cert, &key, &fp, None).unwrap();
        assert!(m.generated);
        assert!(m.fingerprint.starts_with("sha256:"));
        assert_eq!(m.fingerprint.len(), "sha256:".len() + 64);
        assert!(cert.exists() && key.exists() && fp.exists());

        let on_disk = fs::read_to_string(&fp).unwrap();
        assert_eq!(on_disk.trim(), m.fingerprint);
    }

    #[test]
    fn reuses_existing_trio_on_second_run() {
        let dir = TempDir::new().unwrap();
        let (cert, key, fp) = paths(&dir);

        let first = ensure_cert_files(&cert, &key, &fp, None).unwrap();
        let second = ensure_cert_files(&cert, &key, &fp, None).unwrap();

        assert!(first.generated);
        assert!(!second.generated);
        assert_eq!(first.fingerprint, second.fingerprint);
    }

    #[test]
    fn fingerprint_matches_cert_der_sha256() {
        let dir = TempDir::new().unwrap();
        let (cert, key, fp) = paths(&dir);
        ensure_cert_files(&cert, &key, &fp, None).unwrap();

        let pem = fs::read_to_string(&cert).unwrap();
        let mut reader = std::io::BufReader::new(pem.as_bytes());
        let der_chain: Vec<_> = rustls_pemfile::certs(&mut reader)
            .collect::<Result<_, _>>()
            .unwrap();
        let recomputed = sha256_fingerprint(&der_chain[0]);

        let on_disk = fs::read_to_string(&fp).unwrap();
        assert_eq!(on_disk.trim(), recomputed);
    }

    #[cfg(unix)]
    #[test]
    fn files_are_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let (cert, key, fp) = paths(&dir);
        ensure_cert_files(&cert, &key, &fp, None).unwrap();
        for p in [&cert, &key, &fp] {
            let mode = fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{}: mode={:o}", p.display(), mode);
        }
    }
}
