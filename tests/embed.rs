//! End-to-end smoke for the library entry point used by the Tauri
//! desktop wrapper.
//!
//! Verifies that `run_embedded`:
//!
//! 1. Boots with TLS + bind port 0 and reports the OS-assigned port
//!    back through `ServerHandle.local_addr`.
//! 2. Surfaces the self-signed cert's SHA-256 fingerprint in
//!    `ServerHandle.fingerprint`, and that fingerprint matches the leaf
//!    the TLS handshake actually presents (sanity check against the
//!    same pin model the desktop shell will use).
//! 3. Answers `GET /healthz` over HTTPS.
//! 4. Shuts down cleanly when the cancellation token is cancelled.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use exfer_walletd::config::Config;
use exfer_walletd::run_embedded;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

/// Reqwest cert verifier that accepts exactly one leaf — the one whose
/// SHA-256(DER) matches `expected`. Mirrors the verifier the desktop
/// shell uses; defined inline here so the test stays self-contained.
#[derive(Debug)]
struct FingerprintVerifier {
    expected: [u8; 32],
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got = Sha256::digest(end_entity.as_ref());
        if got.as_slice() == self.expected.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "leaf cert SHA-256 does not match pinned fingerprint".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

fn build_config(datadir: std::path::PathBuf) -> Config {
    Config {
        datadir: Some(datadir),
        bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        allow_public_bind: false,
        tls: true,
        tls_cert: None,
        tls_key: None,
        tls_san: vec![],
        node_rpc: "http://127.0.0.1:1".to_string(), // intentionally unreachable; not exercised
        wallet_dir: None,
        auth_token_read: Some("read-token-test-only".to_string()),
        auth_token_manage: Some("manage-token-test-only".to_string()),
        auth_token_spend: Some("spend-token-test-only".to_string()),
        upstream_timeout_secs: 1,
        upstream_attempts: 1,
        upstream_retry_backoff_ms: 0,
        indexer_rpc: None,
        indexer_token: None,
        indexer_timeout_secs: None,
        swap_pool_url: None,
        swap_pool_ca: None,
        bsc_rpc_url: "https://bsc-dataseed1.binance.org".into(),
        bsc_chain_id: 56,
        spend_cap_per_tx: None,
        spend_cap_per_period: None,
        spend_cap_period_secs: 86_400,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boots_with_tls_serves_healthz_and_shuts_down_cleanly() {
    let dir = TempDir::new().unwrap();
    let datadir = dir.path().to_path_buf();

    let shutdown = CancellationToken::new();
    let handle = run_embedded(
        build_config(datadir.clone()),
        "test-passphrase",
        shutdown.clone(),
    )
    .await
    .expect("run_embedded should succeed");

    // (1) OS assigned a real port, not 0.
    assert_ne!(
        handle.local_addr.port(),
        0,
        "bind port 0 should be resolved to a real port"
    );
    // (2) TLS is on, so the fingerprint must be present.
    let fingerprint = handle
        .fingerprint
        .clone()
        .expect("TLS=true should surface a fingerprint");
    assert!(fingerprint.starts_with("sha256:"));
    let hex_part = fingerprint.strip_prefix("sha256:").unwrap();
    assert_eq!(hex_part.len(), 64);
    let mut expected = [0u8; 32];
    hex::decode_to_slice(hex_part, &mut expected).expect("fingerprint hex");

    // (3) /healthz answers over HTTPS, and the cert presented by the
    // handshake matches the fingerprint walletd just reported.
    let tls_cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(FingerprintVerifier { expected }))
        .with_no_client_auth();

    let client = reqwest::ClientBuilder::new()
        .use_preconfigured_tls(tls_cfg)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let url = format!("https://{}/healthz", handle.local_addr);
    let body = client
        .get(&url)
        .send()
        .await
        .expect("healthz GET should succeed")
        .text()
        .await
        .expect("healthz body");
    assert_eq!(body.trim(), "ok");

    // (4) Cancelling the shutdown token stops the server cleanly.
    handle
        .shutdown()
        .await
        .expect("shutdown should join without error");

    // After shutdown, the port is no longer reachable. We don't poll
    // this aggressively (the OS may keep the listener in TIME_WAIT
    // briefly); the join completing above is the actual signal.
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_empty_passphrase() {
    let dir = TempDir::new().unwrap();
    let shutdown = CancellationToken::new();
    let err = run_embedded(build_config(dir.path().to_path_buf()), "", shutdown)
        .await
        .expect_err("empty passphrase must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("passphrase must not be empty"),
        "unexpected error message: {msg}"
    );
}

/// Regression: a shutdown must fully release the datadir so an immediate
/// re-boot on the SAME datadir succeeds. The block follower (and SSE
/// client) used to outlive `shutdown()` — they held a clone of the wallet
/// store, so the second `run_embedded` blocked on the redb datadir lock.
/// The embedded node-switch path (stop -> start, e.g. set_node_rpc) depends
/// on this working; before the fix it left walletd offline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_reopens_same_datadir_after_shutdown() {
    let dir = TempDir::new().unwrap();
    let datadir = dir.path().to_path_buf();

    // First boot, then shut down.
    let h1 = run_embedded(
        build_config(datadir.clone()),
        "test-passphrase",
        CancellationToken::new(),
    )
    .await
    .expect("first boot should succeed");
    h1.shutdown().await.expect("first shutdown should join");

    // Second boot on the SAME datadir must succeed promptly. Bound it so a
    // regression (the follower keeping the store open) surfaces as a clean
    // timeout failure instead of hanging the whole suite.
    let h2 = tokio::time::timeout(
        Duration::from_secs(15),
        run_embedded(
            build_config(datadir.clone()),
            "test-passphrase",
            CancellationToken::new(),
        ),
    )
    .await
    .expect("second boot must not hang on the datadir lock")
    .expect("second boot should succeed");

    assert_ne!(h2.local_addr.port(), 0);
    h2.shutdown().await.expect("second shutdown should join");
}
