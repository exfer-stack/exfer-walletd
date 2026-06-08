//! `quote_issue` / `quote_verify` — the EXFER-QUOTE signed price credential.
//!
//! An EXFER-QUOTE is a canonical, signed statement of *what one party
//! will be owed, in what unit, on what chain, until when, and who said
//! so* (see `docs/src/quote-spec.md`). It adds nothing to consensus: no
//! tx field, no jet, no tag in the chain. Settlement happens through
//! ordinary EXFER transactions linked by `quote_id`.
//!
//! `quote_issue` constructs and signs the Section 3 image (`Scope::Spend`,
//! same posture as `sign_message` — it mints a value-bearing credential).
//! `quote_verify` implements *accept* (Section 5 rules 1–8): a PURE,
//! key-free check (`Scope::Read`) that MUST NOT touch the key store.
//! *Honor* (Section 6) and rule 9 (acceptor-controls-payee) are the
//! integrating application's job and are deliberately NOT implemented here.
//!
//! ## Domain separation
//!
//! The image begins with the literal ASCII tag `b"EXFER-QUOTE"`
//! (NOT length-prefixed), distinct from `EXFER-SIG` (transactions) and
//! `EXFER-MSG` (message signing). The three are mutually non-prefix, so
//! no image of one domain can be reinterpreted as another (asserted by
//! the `tag_non_prefix` test below).
//!
//! ## Endianness
//!
//! ALL integers in the image are BIG-ENDIAN. This diverges from the
//! little-endian tx body (node `src/types/transaction.rs`); the spec
//! states the divergence explicitly — do NOT "fix" it.

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey, SIGNATURE_LENGTH};
use exfer::types::{is_weak_ed25519_key, Hash256};
use serde::{Deserialize, Serialize};

use crate::api::ApiState;
use crate::error::{Error, Result};

/// Literal domain tag prefixed to every signing image (11 bytes, ASCII,
/// NOT length-prefixed). See `docs/src/quote-spec.md` Section 3.
pub const QUOTE_DOMAIN: &[u8] = b"EXFER-QUOTE";

/// Wire version this implementation produces and accepts. An unknown
/// version is rejected with no best-effort decode (Section 9).
pub const QUOTE_VERSION: u8 = 1;

/// Maximum quote lifetime (`expires_at - issued_at`). Section 7.
pub const MAX_TTL: u64 = 3600;

/// Maximum tolerated forward skew on `issued_at` (`issued_at <= now + MAX_SKEW`).
/// Section 7.
pub const MAX_SKEW: u64 = 60;

/// `memo` upper bound in bytes (Section 7).
pub const MAX_MEMO_BYTES: usize = 256;

/// `currency` bounds: 3–12 chars `[A-Z0-9]` (Section 7).
pub const MIN_CURRENCY_LEN: usize = 3;
pub const MAX_CURRENCY_LEN: usize = 12;

// ----------------------------------------------------------------------------
// Address derivation (mirrors the chain + `signmsg.rs`)
// ----------------------------------------------------------------------------

/// `address = domain_hash(EXFER-ADDR, pubkey)` — byte-identical to
/// `TxOutput::pubkey_hash_from_key` and `signmsg.rs::address_for_pubkey`.
fn address_for_pubkey(pubkey: &[u8; 32]) -> Hash256 {
    use exfer::types::transaction::TxOutput;
    TxOutput::pubkey_hash_from_key(pubkey)
}

// ----------------------------------------------------------------------------
// The quote object + image
// ----------------------------------------------------------------------------

/// A fully decoded EXFER-QUOTE. The signing image (Section 3) is a pure
/// function of these fields plus `genesis_block_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quote {
    pub version: u8,
    pub quote_id: [u8; 16],
    pub currency: String,
    pub amount_minor: u64,
    pub rate_exfers_per_unit: u64,
    pub exfer_amount: u64,
    pub payee_pubkey: [u8; 32],
    /// Presence determines `payer_flag` (1 iff `Some`). Section 3.
    pub payer_pubkey: Option<[u8; 32]>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub memo: String,
}

impl Quote {
    /// Build the Section 3 binary signing image. `genesis_block_id` is
    /// the 32-byte node-derived genesis (NEVER a compiled constant).
    ///
    /// ```text
    /// "EXFER-QUOTE"            (11 bytes literal ASCII, NOT length-prefixed)
    /// genesis_block_id         (32 bytes)
    /// version                  (u8)
    /// quote_id                 (16 bytes)
    /// currency_len             (u8)
    /// currency                 (currency_len bytes, ASCII)
    /// amount_minor             (u64 BE)
    /// rate_exfers_per_unit     (u64 BE)
    /// exfer_amount             (u64 BE)
    /// payee_pubkey             (32 bytes)
    /// payer_flag               (u8; 0 or 1)
    /// [payer_pubkey            (32 bytes) iff payer_flag == 1]
    /// issued_at                (u64 BE)
    /// expires_at               (u64 BE)
    /// memo_len                 (u16 BE)
    /// memo                     (memo_len bytes, UTF-8)
    /// ```
    pub fn signing_image(&self, genesis_block_id: &[u8; 32]) -> Vec<u8> {
        let currency_bytes = self.currency.as_bytes();
        let memo_bytes = self.memo.as_bytes();
        let mut out = Vec::with_capacity(
            QUOTE_DOMAIN.len()
                + 32
                + 1
                + 16
                + 1
                + currency_bytes.len()
                + 8 * 3
                + 32
                + 1
                + if self.payer_pubkey.is_some() { 32 } else { 0 }
                + 8 * 2
                + 2
                + memo_bytes.len(),
        );
        out.extend_from_slice(QUOTE_DOMAIN);
        out.extend_from_slice(genesis_block_id);
        out.push(self.version);
        out.extend_from_slice(&self.quote_id);
        out.push(currency_bytes.len() as u8);
        out.extend_from_slice(currency_bytes);
        out.extend_from_slice(&self.amount_minor.to_be_bytes());
        out.extend_from_slice(&self.rate_exfers_per_unit.to_be_bytes());
        out.extend_from_slice(&self.exfer_amount.to_be_bytes());
        out.extend_from_slice(&self.payee_pubkey);
        match &self.payer_pubkey {
            Some(pk) => {
                out.push(1);
                out.extend_from_slice(pk);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&(memo_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(memo_bytes);
        out
    }
}

/// Validate field bounds shared by issue and verify (Section 7). This is
/// the value-level check; structural strict-decode lives in the JSON
/// decode helpers and is enforced by typed lengths.
fn check_bounds(q: &Quote) -> std::result::Result<(), String> {
    if q.version != QUOTE_VERSION {
        return Err(format!("unsupported version {}", q.version));
    }
    let clen = q.currency.len();
    if !(MIN_CURRENCY_LEN..=MAX_CURRENCY_LEN).contains(&clen) {
        return Err(format!(
            "currency length {clen} out of [{MIN_CURRENCY_LEN},{MAX_CURRENCY_LEN}]"
        ));
    }
    if !q
        .currency
        .bytes()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return Err("currency must be [A-Z0-9]".to_string());
    }
    if q.memo.len() > MAX_MEMO_BYTES {
        return Err(format!(
            "memo {} bytes exceeds {MAX_MEMO_BYTES}",
            q.memo.len()
        ));
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// hex helpers
// ----------------------------------------------------------------------------

fn decode_fixed<const N: usize>(field: &str, hex_str: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(hex_str).map_err(|e| Error::BadHex(format!("{field}: {e}")))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        Error::BadParams(format!("{field}: expected {N} bytes, got {}", v.len()))
    })
}

// ----------------------------------------------------------------------------
// JSON shapes
// ----------------------------------------------------------------------------

/// The canonical quote JSON object (snake_case, lowercase hex). Used as
/// both the `quote_issue` result body and the `quote_verify` input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteJson {
    pub version: u8,
    pub quote_id: String,
    pub currency: String,
    pub amount_minor: u64,
    pub rate_exfers_per_unit: u64,
    pub exfer_amount: u64,
    pub payee_pubkey: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer_pubkey: Option<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub memo: String,
    pub signer_pubkey: String,
    pub signature: String,
}

/// Decode the quote fields (everything that goes into the image) from a
/// JSON object. `payer_flag` is derived PURELY from `payer_pubkey`
/// presence — a `payer_pubkey` is never silently ignored (Section 3).
fn quote_from_json(j: &QuoteJson) -> Result<Quote> {
    let quote_id: [u8; 16] = decode_fixed("quote_id", &j.quote_id)?;
    let payee_pubkey: [u8; 32] = decode_fixed("payee_pubkey", &j.payee_pubkey)?;
    let payer_pubkey: Option<[u8; 32]> = match &j.payer_pubkey {
        Some(s) => Some(decode_fixed("payer_pubkey", s)?),
        None => None,
    };
    Ok(Quote {
        version: j.version,
        quote_id,
        currency: j.currency.clone(),
        amount_minor: j.amount_minor,
        rate_exfers_per_unit: j.rate_exfers_per_unit,
        exfer_amount: j.exfer_amount,
        payee_pubkey,
        payer_pubkey,
        issued_at: j.issued_at,
        expires_at: j.expires_at,
        memo: j.memo.clone(),
    })
}

// ----------------------------------------------------------------------------
// quote_issue
// ----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct QuoteIssueParams {
    /// The issuer/signer wallet address (64 hex) whose key signs the image.
    pub address: String,
    /// The party to be paid, by pubkey (64 hex).
    pub payee_pubkey: String,
    /// Pricing-unit code, 3–12 chars `[A-Z0-9]`.
    pub currency: String,
    pub amount_minor: u64,
    pub rate_exfers_per_unit: u64,
    /// The only binding amount, u64 base units.
    pub exfer_amount: u64,
    /// Lifetime in seconds; `issued_at = now`, `expires_at = now + ttl_secs`.
    /// Must satisfy `0 < ttl_secs <= MAX_TTL`.
    pub ttl_secs: u64,
    /// Optional payer binding (64 hex). When present the quote is
    /// non-transferable (Section 6).
    #[serde(default)]
    pub payer_pubkey: Option<String>,
    /// Optional signed UTF-8 note, ≤ 256 bytes.
    #[serde(default)]
    pub memo: Option<String>,
    /// Optional explicit `quote_id` (32 hex). When omitted, 16 random
    /// bytes are generated.
    #[serde(default)]
    pub quote_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct QuoteIssueResult {
    /// The full signed quote object (the credential to hand out).
    quote: QuoteJson,
    /// Raw Ed25519 signature over the image (128 hex). Also echoed in
    /// `quote.signature`.
    signature: String,
    /// Issuer address = `domain_hash(EXFER-ADDR, signer_pubkey)`.
    signer_address: String,
    /// Payee plain-output address = `domain_hash(EXFER-ADDR, payee_pubkey)`.
    payee_address: String,
    /// The genesis bound into the image (live node value, 64 hex).
    genesis_block_id: String,
    /// The exact bytes that were signed (hex), for audit / re-verification.
    image: String,
    /// HTLC preimage secret, generated payee-side (Section 6 requires the
    /// payee to originate the secret). 32 random bytes, 64 hex. KEEP SECRET.
    htlc_preimage: String,
    /// `hash_lock = SHA-256(htlc_preimage)` (64 hex) for the covenant.
    htlc_hash_lock: String,
}

pub async fn quote_issue(state: &ApiState, params: serde_json::Value) -> Result<serde_json::Value> {
    use rand::rngs::OsRng;
    use rand::RngCore;

    let p: QuoteIssueParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("quote_issue params: {e}")))?;

    // --- live, node-derived genesis (NEVER a compiled constant) ---
    let tip = state.node.get_block_height().await?;
    if tip.genesis_block_id.is_empty() {
        return Err(Error::UpstreamUnexpected(
            "node get_block_height returned no genesis_block_id (requires node PR #33)".to_string(),
        ));
    }
    let genesis: [u8; 32] = decode_fixed("genesis_block_id", &tip.genesis_block_id)
        .map_err(|e| Error::UpstreamUnexpected(format!("node genesis_block_id: {e}")))?;

    // --- assemble the quote object ---
    let quote_id: [u8; 16] = match &p.quote_id {
        Some(s) => decode_fixed("quote_id", s)?,
        None => {
            let mut q = [0u8; 16];
            OsRng.fill_bytes(&mut q);
            q
        }
    };
    let payee_pubkey: [u8; 32] = decode_fixed("payee_pubkey", &p.payee_pubkey)?;
    let payer_pubkey: Option<[u8; 32]> = match &p.payer_pubkey {
        Some(s) => Some(decode_fixed("payer_pubkey", s)?),
        None => None,
    };

    if p.ttl_secs == 0 || p.ttl_secs > MAX_TTL {
        return Err(Error::BadParams(format!(
            "ttl_secs must be in (0, {MAX_TTL}], got {}",
            p.ttl_secs
        )));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Error::Internal(format!("clock before epoch: {e}")))?
        .as_secs();

    let quote = Quote {
        version: QUOTE_VERSION,
        quote_id,
        currency: p.currency,
        amount_minor: p.amount_minor,
        rate_exfers_per_unit: p.rate_exfers_per_unit,
        exfer_amount: p.exfer_amount,
        payee_pubkey,
        payer_pubkey,
        issued_at: now,
        expires_at: now + p.ttl_secs,
        memo: p.memo.unwrap_or_default(),
    };

    check_bounds(&quote).map_err(Error::BadParams)?;

    // Reject weak/small-order keys for payee/payer up front (the signer
    // key comes from our own keystore and is checked once derived).
    if is_weak_ed25519_key(&quote.payee_pubkey) {
        return Err(Error::BadParams(
            "payee_pubkey is a weak/small-order key".to_string(),
        ));
    }
    if let Some(pk) = &quote.payer_pubkey {
        if is_weak_ed25519_key(pk) {
            return Err(Error::BadParams(
                "payer_pubkey is a weak/small-order key".to_string(),
            ));
        }
    }

    // --- HTLC secret, generated payee-side (Section 6) ---
    let mut preimage = [0u8; 32];
    OsRng.fill_bytes(&mut preimage);
    let hash_lock = Hash256::sha256(&preimage);

    // --- build the image, then sign raw Ed25519 via the keystore signer ---
    let image = quote.signing_image(&genesis);

    // Wallet load is sync FS I/O — match `sign_message`'s blocking pattern.
    let store = state.store.clone();
    let addr = p.address.clone();
    let image_for_sign = image.clone();
    let (signature, signer_pubkey, signer_address) =
        tokio::task::spawn_blocking(move || -> Result<([u8; 64], [u8; 32], String)> {
            let signer = store.load_by_address(&addr)?;
            let sig: Signature = signer.signing_key().sign(&image_for_sign);
            Ok((sig.to_bytes(), signer.pubkey(), signer.address_hex()))
        })
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;

    if is_weak_ed25519_key(&signer_pubkey) {
        return Err(Error::Internal(
            "signer key is a weak/small-order key".to_string(),
        ));
    }

    let quote_json = QuoteJson {
        version: quote.version,
        quote_id: hex::encode(quote.quote_id),
        currency: quote.currency.clone(),
        amount_minor: quote.amount_minor,
        rate_exfers_per_unit: quote.rate_exfers_per_unit,
        exfer_amount: quote.exfer_amount,
        payee_pubkey: hex::encode(quote.payee_pubkey),
        payer_pubkey: quote.payer_pubkey.map(hex::encode),
        issued_at: quote.issued_at,
        expires_at: quote.expires_at,
        memo: quote.memo.clone(),
        signer_pubkey: hex::encode(signer_pubkey),
        signature: hex::encode(signature),
    };

    let result = QuoteIssueResult {
        quote: quote_json,
        signature: hex::encode(signature),
        signer_address,
        payee_address: hex::encode(address_for_pubkey(&quote.payee_pubkey).as_bytes()),
        genesis_block_id: tip.genesis_block_id.clone(),
        image: hex::encode(&image),
        htlc_preimage: hex::encode(preimage),
        htlc_hash_lock: hex::encode(hash_lock.as_bytes()),
    };
    serde_json::to_value(&result).map_err(|e| Error::Internal(e.to_string()))
}

// ----------------------------------------------------------------------------
// quote_verify — accept (Section 5 rules 1–8). PURE, key-free.
// ----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct QuoteVerifyParams {
    /// The quote object to verify (snake_case, lowercase hex).
    pub quote: QuoteJson,
}

#[derive(Debug, Serialize)]
struct QuoteVerifyResult {
    valid: bool,
    /// Reason `valid` is false; `None` when valid.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    /// Issuer address derived from `signer_pubkey` — always returned,
    /// even on failure, so a caller learns what the key hashes to.
    signer_address: String,
    /// Payee plain-output address derived from `payee_pubkey`.
    payee_address: String,
    /// The genesis the quote is being checked against (live node value).
    genesis_block_id: String,
}

/// Accept-check a quote against the live genesis and clock. Returns
/// `Ok(())` on accept, `Err(reason)` on a verification failure (NOT a
/// malformed-input error — those surface earlier as `-32602`).
fn accept_check(
    quote: &Quote,
    signer_pubkey: &[u8; 32],
    signature_bytes: &[u8; SIGNATURE_LENGTH],
    genesis: &[u8; 32],
    now: u64,
) -> std::result::Result<(), String> {
    // Rule 2: version is one we implement (also covered by check_bounds).
    // Rule 1 (strict decode) is enforced structurally during JSON decode
    // + field-width checks here.
    check_bounds(quote)?;

    // Rule 3: signer/payee/payer must not be weak/small-order keys.
    if is_weak_ed25519_key(signer_pubkey) {
        return Err("signer_pubkey is a weak/small-order key".to_string());
    }
    if is_weak_ed25519_key(&quote.payee_pubkey) {
        return Err("payee_pubkey is a weak/small-order key".to_string());
    }
    if let Some(pk) = &quote.payer_pubkey {
        if is_weak_ed25519_key(pk) {
            return Err("payer_pubkey is a weak/small-order key".to_string());
        }
    }

    // Rule 4: signature verifies under signer_pubkey over the image.
    let image = quote.signing_image(genesis);
    let signature = Signature::from_bytes(signature_bytes);
    let vk = VerifyingKey::from_bytes(signer_pubkey)
        .map_err(|_| "signer_pubkey is not a valid Ed25519 point".to_string())?;
    if vk.verify(&image, &signature).is_err() {
        return Err("signature does not verify over the image".to_string());
    }

    // Rule 5 (genesis match) is implicit: the image is reconstructed with
    // the live genesis, so a cross-genesis quote fails rule 4 above. No
    // genesis is carried in the JSON, so there is nothing further to compare.

    // Rule 7: issued_at < expires_at, TTL <= MAX_TTL, issued_at skew.
    if quote.issued_at >= quote.expires_at {
        return Err("issued_at must be strictly before expires_at".to_string());
    }
    if quote.expires_at - quote.issued_at > MAX_TTL {
        return Err(format!(
            "ttl {} exceeds MAX_TTL {MAX_TTL}",
            quote.expires_at - quote.issued_at
        ));
    }
    if quote.issued_at > now.saturating_add(MAX_SKEW) {
        return Err("issued_at is too far in the future (skew)".to_string());
    }

    // Rule 6: local time < expires_at (no grace inside the quote).
    if now >= quote.expires_at {
        return Err("quote has expired".to_string());
    }

    // Rule 8 (signer is one the acceptor accepts out of band) and rule 9
    // (acceptor controls payee) are NOT checked here — quote_verify is
    // pure and proves authorship, not authority. That is the integrating
    // app's job (Section 5, Section 11).
    Ok(())
}

pub async fn quote_verify(
    state: &ApiState,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    let p: QuoteVerifyParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("quote_verify params: {e}")))?;

    // Strict decode of the JSON into typed fields. A malformed object
    // (bad hex, wrong-length key, etc.) is a -32602 BadParams, NOT a
    // `valid:false` — these are decode errors, before any sig check.
    let quote = quote_from_json(&p.quote)?;
    let signer_pubkey: [u8; 32] = decode_fixed("signer_pubkey", &p.quote.signer_pubkey)?;
    let sig_bytes =
        hex::decode(&p.quote.signature).map_err(|e| Error::BadHex(format!("signature: {e}")))?;
    if sig_bytes.len() != SIGNATURE_LENGTH {
        return Err(Error::BadParams(format!(
            "signature: expected {SIGNATURE_LENGTH} bytes, got {}",
            sig_bytes.len()
        )));
    }
    let mut sig_arr = [0u8; SIGNATURE_LENGTH];
    sig_arr.copy_from_slice(&sig_bytes);

    // Live, node-derived genesis (rule 5). PURE: no key store touched.
    let tip = state.node.get_block_height().await?;
    if tip.genesis_block_id.is_empty() {
        return Err(Error::UpstreamUnexpected(
            "node get_block_height returned no genesis_block_id (requires node PR #33)".to_string(),
        ));
    }
    let genesis: [u8; 32] = decode_fixed("genesis_block_id", &tip.genesis_block_id)
        .map_err(|e| Error::UpstreamUnexpected(format!("node genesis_block_id: {e}")))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Error::Internal(format!("clock before epoch: {e}")))?
        .as_secs();

    let outcome = accept_check(&quote, &signer_pubkey, &sig_arr, &genesis, now);

    let result = QuoteVerifyResult {
        valid: outcome.is_ok(),
        reason: outcome.err(),
        signer_address: hex::encode(address_for_pubkey(&signer_pubkey).as_bytes()),
        payee_address: hex::encode(address_for_pubkey(&quote.payee_pubkey).as_bytes()),
        genesis_block_id: tip.genesis_block_id.clone(),
    };
    serde_json::to_value(&result).map_err(|e| Error::Internal(e.to_string()))
}

// ----------------------------------------------------------------------------
// Strict JSON decode used by tests + the verify path.
// ----------------------------------------------------------------------------

/// Strict-decode a complete image (Section 3) into a `Quote`. Rejects:
/// trailing bytes after `memo`; `payer_flag` not in {0,1}; truncated /
/// out-of-bounds fields. Returns the decoded quote on success. This is
/// the binary counterpart to `quote_from_json`, used to validate the
/// byte-exact test vectors.
pub fn decode_image_strict(image: &[u8]) -> std::result::Result<(Quote, [u8; 32]), String> {
    let mut o = 0usize;
    fn take<'a>(
        b: &'a [u8],
        o: &mut usize,
        n: usize,
        what: &str,
    ) -> std::result::Result<&'a [u8], String> {
        if *o + n > b.len() {
            return Err(format!("truncated reading {what}"));
        }
        let s = &b[*o..*o + n];
        *o += n;
        Ok(s)
    }

    let tag = take(image, &mut o, QUOTE_DOMAIN.len(), "domain tag")?;
    if tag != QUOTE_DOMAIN {
        return Err("bad domain tag".to_string());
    }
    let genesis: [u8; 32] = take(image, &mut o, 32, "genesis")?.try_into().unwrap();
    let version = take(image, &mut o, 1, "version")?[0];
    let quote_id: [u8; 16] = take(image, &mut o, 16, "quote_id")?.try_into().unwrap();
    let currency_len = take(image, &mut o, 1, "currency_len")?[0] as usize;
    let currency_bytes = take(image, &mut o, currency_len, "currency")?.to_vec();
    let currency =
        String::from_utf8(currency_bytes).map_err(|_| "currency not UTF-8".to_string())?;
    let amount_minor =
        u64::from_be_bytes(take(image, &mut o, 8, "amount_minor")?.try_into().unwrap());
    let rate = u64::from_be_bytes(take(image, &mut o, 8, "rate")?.try_into().unwrap());
    let exfer_amount =
        u64::from_be_bytes(take(image, &mut o, 8, "exfer_amount")?.try_into().unwrap());
    let payee_pubkey: [u8; 32] = take(image, &mut o, 32, "payee_pubkey")?.try_into().unwrap();
    let payer_flag = take(image, &mut o, 1, "payer_flag")?[0];
    let payer_pubkey = match payer_flag {
        0 => None,
        1 => Some(<[u8; 32]>::try_from(take(image, &mut o, 32, "payer_pubkey")?).unwrap()),
        other => return Err(format!("payer_flag not in {{0,1}} (value={other})")),
    };
    let issued_at = u64::from_be_bytes(take(image, &mut o, 8, "issued_at")?.try_into().unwrap());
    let expires_at = u64::from_be_bytes(take(image, &mut o, 8, "expires_at")?.try_into().unwrap());
    let memo_len =
        u16::from_be_bytes(take(image, &mut o, 2, "memo_len")?.try_into().unwrap()) as usize;
    let memo_bytes = take(image, &mut o, memo_len, "memo")?.to_vec();
    let memo = String::from_utf8(memo_bytes).map_err(|_| "memo not UTF-8".to_string())?;

    if o != image.len() {
        return Err(format!(
            "trailing bytes after memo ({} extra)",
            image.len() - o
        ));
    }

    let quote = Quote {
        version,
        quote_id,
        currency,
        amount_minor,
        rate_exfers_per_unit: rate,
        exfer_amount,
        payee_pubkey,
        payer_pubkey,
        issued_at,
        expires_at,
        memo,
    };
    Ok((quote, genesis))
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    /// All signable `EXFER-*` domain tags. Per Section 3 they MUST be
    /// mutually non-prefix so no image of one domain can be reinterpreted
    /// as another.
    const SIGNABLE_TAGS: &[&[u8]] = &[
        b"EXFER-QUOTE",
        b"EXFER-SIG", // node tx signing
        b"EXFER-MSG", // walletd message signing
    ];

    #[test]
    fn tag_non_prefix() {
        for (i, a) in SIGNABLE_TAGS.iter().enumerate() {
            for (j, b) in SIGNABLE_TAGS.iter().enumerate() {
                if i == j {
                    continue;
                }
                assert!(
                    !a.starts_with(b) && !b.starts_with(a),
                    "domain tags {:?} and {:?} must be mutually non-prefix",
                    std::str::from_utf8(a).unwrap(),
                    std::str::from_utf8(b).unwrap(),
                );
            }
        }
    }

    fn parse_vectors() -> Vec<serde_json::Value> {
        // The machine-readable JSON array lives between the last
        // "MACHINE-READABLE (JSON)" banner and EOF in vectors.txt.
        let raw = include_str!("../../docs/quote-test-vectors/vectors.txt");
        let banner = raw
            .find("MACHINE-READABLE (JSON)")
            .expect("vectors.txt has the machine-readable banner");
        let after = &raw[banner..];
        let start = after.find('[').expect("vectors.txt has a JSON array");
        let json = &after[start..];
        serde_json::from_str(json).expect("vectors.txt JSON array parses")
    }

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn vectors_positive_image_and_signature_byte_exact() {
        let vecs = parse_vectors();
        let mut seen = 0;
        for v in &vecs {
            if v["kind"] != "positive" {
                continue;
            }
            seen += 1;
            let name = v["name"].as_str().unwrap();
            let expected_image = h(v["image_hex"].as_str().unwrap());
            let genesis = h(v["genesis_block_id"].as_str().unwrap());
            let genesis: [u8; 32] = genesis.try_into().unwrap();

            // Decode the JSON object into a Quote and rebuild the image;
            // it must equal the vector image byte-for-byte.
            let qj: QuoteJson = serde_json::from_value(v["json"].clone()).unwrap();
            let quote = quote_from_json(&qj).unwrap();
            let image = quote.signing_image(&genesis);
            assert_eq!(
                hex::encode(&image),
                v["image_hex"].as_str().unwrap(),
                "{name}: rebuilt image must match vector"
            );

            // Strict-decoding the vector image must reproduce the same Quote.
            let (decoded, dg) = decode_image_strict(&expected_image)
                .unwrap_or_else(|e| panic!("{name}: strict decode failed: {e}"));
            assert_eq!(decoded, quote, "{name}: decoded quote mismatch");
            assert_eq!(dg, genesis, "{name}: decoded genesis mismatch");

            // The signature must verify under signer_pubkey over the image.
            let signer_pubkey: [u8; 32] =
                h(v["signer_pubkey"].as_str().unwrap()).try_into().unwrap();
            let sig_bytes: [u8; 64] = h(v["signature"].as_str().unwrap()).try_into().unwrap();
            let now = quote.issued_at + 1; // inside the window
            accept_check(&quote, &signer_pubkey, &sig_bytes, &genesis, now)
                .unwrap_or_else(|e| panic!("{name}: accept_check should pass: {e}"));
        }
        assert_eq!(seen, 3, "expected 3 positive vectors");
    }

    #[test]
    fn vectors_negative_rejected_at_strict_decode() {
        let vecs = parse_vectors();
        let mut seen = 0;
        for v in &vecs {
            if v["kind"] != "negative" {
                continue;
            }
            seen += 1;
            let name = v["name"].as_str().unwrap();
            let image = h(v["image_hex"].as_str().unwrap());
            let res = decode_image_strict(&image);
            assert!(
                res.is_err(),
                "{name}: strict decode MUST reject the negative vector"
            );
        }
        assert_eq!(seen, 2, "expected 2 negative vectors");
    }

    #[test]
    fn strict_decode_trailing_byte_rejected() {
        let vecs = parse_vectors();
        let vec_a = vecs
            .iter()
            .find(|v| v["name"] == "vec_a_minimal_no_payer_empty_memo")
            .unwrap();
        let mut image = h(vec_a["image_hex"].as_str().unwrap());
        // valid as-is
        assert!(decode_image_strict(&image).is_ok());
        // one trailing byte => reject
        image.push(0x00);
        let err = decode_image_strict(&image).unwrap_err();
        assert!(
            err.contains("trailing"),
            "expected trailing-bytes error, got: {err}"
        );
    }

    #[test]
    fn strict_decode_payer_flag_out_of_range_rejected() {
        let vecs = parse_vectors();
        let vec_e = vecs
            .iter()
            .find(|v| v["name"] == "vec_e_payer_flag_2_reject")
            .unwrap();
        let image = h(vec_e["image_hex"].as_str().unwrap());
        let err = decode_image_strict(&image).unwrap_err();
        assert!(
            err.contains("payer_flag"),
            "expected payer_flag error, got: {err}"
        );
    }

    #[test]
    fn roundtrip_issue_then_verify_and_tamper() {
        // Fixed test genesis (NOT the zero test-domain genesis used by the
        // vectors, to prove genesis-binding is live).
        let genesis: [u8; 32] = [0x11; 32];

        let signer_sk = SigningKey::from_bytes(&[7u8; 32]);
        let signer_pubkey = signer_sk.verifying_key().to_bytes();
        assert!(!is_weak_ed25519_key(&signer_pubkey));

        let payee_sk = SigningKey::from_bytes(&[9u8; 32]);
        let payee_pubkey = payee_sk.verifying_key().to_bytes();

        let now = 1_781_000_000u64;
        let quote = Quote {
            version: QUOTE_VERSION,
            quote_id: [0xAB; 16],
            currency: "USD".to_string(),
            amount_minor: 1250,
            rate_exfers_per_unit: 4_000_000_000,
            exfer_amount: 50_000_000_000,
            payee_pubkey,
            payer_pubkey: None,
            issued_at: now,
            expires_at: now + 300,
            memo: "roundtrip".to_string(),
        };

        let image = quote.signing_image(&genesis);
        let sig = signer_sk.sign(&image).to_bytes();

        // valid inside the window
        accept_check(&quote, &signer_pubkey, &sig, &genesis, now + 10)
            .expect("freshly issued quote must verify");

        // tamper: a different genesis must fail (genesis-binding)
        let other_genesis = [0x22; 32];
        assert!(
            accept_check(&quote, &signer_pubkey, &sig, &other_genesis, now + 10).is_err(),
            "cross-genesis quote must be rejected"
        );

        // tamper: mutate a field => signature no longer matches
        let mut tampered = quote.clone();
        tampered.exfer_amount += 1;
        assert!(
            accept_check(&tampered, &signer_pubkey, &sig, &genesis, now + 10).is_err(),
            "tampered amount must fail signature check"
        );

        // expired
        assert!(
            accept_check(&quote, &signer_pubkey, &sig, &genesis, now + 1000).is_err(),
            "expired quote must be rejected"
        );
    }

    #[test]
    fn ttl_exceeding_max_rejected() {
        let genesis = [0x33; 32];
        let signer_sk = SigningKey::from_bytes(&[3u8; 32]);
        let signer_pubkey = signer_sk.verifying_key().to_bytes();
        let payee_pubkey = SigningKey::from_bytes(&[5u8; 32])
            .verifying_key()
            .to_bytes();
        let now = 1_781_000_000u64;
        let quote = Quote {
            version: QUOTE_VERSION,
            quote_id: [1u8; 16],
            currency: "USD".to_string(),
            amount_minor: 1,
            rate_exfers_per_unit: 1,
            exfer_amount: 1,
            payee_pubkey,
            payer_pubkey: None,
            issued_at: now,
            expires_at: now + MAX_TTL + 1, // over the cap
            memo: String::new(),
        };
        let image = quote.signing_image(&genesis);
        let sig = signer_sk.sign(&image).to_bytes();
        let err = accept_check(&quote, &signer_pubkey, &sig, &genesis, now + 1).unwrap_err();
        assert!(err.contains("MAX_TTL"), "expected TTL error, got: {err}");
    }
}
