# EXFER-QUOTE: A Signed Price-Credential Standard

**Status:** Draft &nbsp;·&nbsp; **Wire version byte:** 1 &nbsp;·&nbsp; **Layer:** application / wallet.

A signed EXFER-QUOTE is a price credential: a canonical, signed statement of *what one party will be owed, in what unit, on what chain, until when, and who said so*. It adds nothing to EXFER consensus — no transaction field, no jet, no consensus tag, no covenant change. Settlement happens only through ordinary EXFER transactions, linked to a quote by `quote_id` in a settlement datum (Section 6). The chain is reached only through JSON-RPC.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, MAY, and OPTIONAL are to be interpreted as in RFC 2119 / RFC 8174 when in all capitals.

This standard derives from and resolves [ahuman-exfer/exfer#28](https://github.com/ahuman-exfer/exfer/issues/28). The walletd methods (Section 11) are gated on [#33](https://github.com/ahuman-exfer/exfer/pull/33) (node-derived genesis).

A quote is a **price credential, not a money credential**: holding one moves no value. A leaked or replayed quote can at worst be presented for one settlement at that price before it expires; every rule below exists to bound that blast radius to one settlement, and every check is acceptor-side.

---

## 1. Terminology

- **Image** — the byte-exact serialization that is signed (Section 3). The signature is not part of the image.
- **Signer / Issuer** — holder of the key that signs; `signer_pubkey` is its public key.
- **Payee** — the party to be paid (`payee_pubkey`).
- **Payer** — the party funding settlement; optionally bound by `payer_pubkey`.
- **Acceptor** — the party that delivers priced goods against an observed settlement. It verifies (Section 5) and enforces honor (Section 6). Usually the payee.
- **Accept** — pure, stateless check that a quote is a valid credential (Section 5).
- **Honor** — stateful delivery of goods after a settlement is observed and gated (Section 6).
- **Settlement** — the on-chain EXFER transaction paying the payee, linked to the quote by `quote_id` in its output datum.
- **Gate** — a durable store consulted before honoring: SEEN-SET (one `quote_id` once) and CONSUMED-OUTPOINT (one outpoint once).

Conventions: JSON is snake_case, binary is lowercase hex. Image integers are big-endian. EXFER amounts are u64 base units (1 EXFER = 100,000,000 exfers); they MUST NOT be encoded as floats or decimal strings.

---

## 2. The Object

```json
{
  "version": 1,
  "quote_id": "9f2c4a1e0b7d3c5a8e6f1029384b5c6d",
  "currency": "USD",
  "amount_minor": 1250,
  "rate_exfers_per_unit": 4000000000,
  "exfer_amount": 50000000000,
  "payee_pubkey": "<64 hex>",
  "payer_pubkey": "<64 hex, optional>",
  "issued_at": 1781234567,
  "expires_at": 1781234867,
  "memo": "api-credits/2026-06",
  "signer_pubkey": "<64 hex>",
  "signature": "<128 hex>"
}
```

- `quote_id` — 16 random bytes (hex32). Also the settlement-to-quote link: a honored settlement MUST carry it in its output datum (Section 6).
- `currency` — pricing-unit code, 3–12 chars `[A-Z0-9]`. The pricing unit is never the settlement unit; settlement is always EXFER.
- `amount_minor`, `rate_exfers_per_unit` — signed-but-informative display/audit data. No verifier recomputes the conversion.
- `exfer_amount` (u64 base units) — the only binding amount.
- `payee_pubkey` — by pubkey, not address: covers both the HTLC hash-arm receiver and the plain-output address `domain_hash(EXFER-ADDR, payee_pubkey)`.
- `payer_pubkey` (optional) — when present, makes the quote non-transferable (Section 6).
- `issued_at`, `expires_at` — absolute Unix seconds (wall-clock), deliberately not block height.
- `memo` — signed UTF-8 note, ≤ 256 bytes.
- `signer_pubkey`, `signature` — the issuer key and its raw Ed25519 signature over the image.

---

## 3. The Signing Image

The signature is raw Ed25519 over a fixed binary image, not over the JSON — byte-identical across implementations, no canonicalization. All integers big-endian (this diverges from the little-endian tx body; state it, do not "fix" it).

```
"EXFER-QUOTE"                 (11 bytes, literal ASCII; NOT length-prefixed)
genesis_block_id             (32 bytes)
version                      (u8)
quote_id                     (16 bytes)
currency_len                 (u8)
currency                     (currency_len bytes, ASCII)
amount_minor                 (u64 BE)
rate_exfers_per_unit         (u64 BE)
exfer_amount                 (u64 BE)
payee_pubkey                 (32 bytes)
payer_flag                   (u8; MUST be exactly 0 or 1)
[payer_pubkey                (32 bytes) iff payer_flag == 1]
issued_at                    (u64 BE)
expires_at                   (u64 BE)
memo_len                     (u16 BE)
memo                         (memo_len bytes, UTF-8)
```

The v1 image has no reserved region; it strict-ends at `memo`.

**Strict decode.** A verifier MUST, before any signature check: reject trailing bytes after `memo` (length is fully determined by `currency_len`, `payer_flag`, `memo_len`); reject `payer_flag` not in {0,1}; derive `payer_flag` from JSON-field presence alone and never honor a quote whose `payer_pubkey` it silently ignores; enforce field widths and the `currency`/`memo` bounds (Section 7). With a fixed prefix, fixed-width keys/amounts, length-prefixed `currency`/`memo`, and a presence-determined `payer_pubkey`, the field-tuple-to-bytes map is injective.

**Domain separation.** The literal tag `EXFER-QUOTE` and its raw-Ed25519 siblings `EXFER-SIG` (node `src/types/mod.rs:364`, transaction signing) and `EXFER-MSG` (walletd `src/api/signmsg.rs:34`, message signing) MUST be mutually non-prefix, so no image of one domain can be reinterpreted as another. A conforming implementation MUST ship a test asserting pairwise mutual-non-prefix across all signable `EXFER-*` tags. Format evolution extends through the version byte, never a new tag (Section 9).

---

## 4. Signing and Address Derivation

The signature is raw Ed25519 (RFC 8032) over the image. The issuer MUST bind the live, node-derived `genesis_block_id`, read at `get_block_height` (node `src/rpc.rs:456`, `node.genesis_id`, never tip-derived), NOT a compiled-in constant — a compiled constant separates builds, not networks (the PR #30 mismatch), and is forbidden. Unlike `EXFER-MSG`, EXFER-QUOTE IS genesis-bound, like `EXFER-SIG`.

The issuer address is `domain_hash(EXFER-ADDR, signer_pubkey)`, where `domain_hash(sep, data) = SHA-256(len(sep) || sep || data)` — byte-identical to `TxOutput::pubkey_hash_from_key` (node `src/types/transaction.rs:95`, `DS_ADDR` at `src/types/mod.rs:368`; walletd `src/api/signmsg.rs:39`). The payee's plain-output address derives identically. Hex fields are bare lowercase hex; an issuer MUST NOT emit the swap path's `0x`-prefixed hex or decimal-string amounts.

---

## 5. Verification: Accept

*Accept* is the pure, stateless check that a quote is a valid credential. A verifier MUST NOT touch a key store or release value. An acceptor accepts iff all hold:

1. The image strict-decodes (Section 3).
2. The `version` is one the verifier implements; an unknown version is rejected with no best-effort decode.
3. `signer_pubkey`, `payee_pubkey`, and (if present) `payer_pubkey` are not weak/small-order keys — `is_weak_ed25519_key`, mandatory in all verify paths (node `src/types/mod.rs:353`, enforced in consensus at `src/consensus/validation.rs:598`). NOTE: walletd's `verify_message` omits this check, so it is not a complete pattern to copy.
4. The signature verifies under `signer_pubkey` over the image (Section 4).
5. The image's `genesis_block_id` equals the live value at `get_block_height` (node `src/rpc.rs:456`); reject cross-genesis quotes.
6. Local time < `expires_at` (no grace inside the quote).
7. `issued_at < expires_at`, `expires_at - issued_at <= MAX_TTL`, `issued_at <= now + MAX_SKEW`; `currency` resolves to a known code (Section 7).
8. `signer_pubkey` is one the acceptor accepts (out of band) — the quote proves authorship, not authority.
9. `payee_pubkey` is a key the acceptor itself controls — a quote naming a third-party payee MUST be rejected.

A verifier SHOULD return the derived issuer address and parsed fields even when `valid:false`, and map malformed input to JSON-RPC `-32602` while returning a verification failure as `valid:false`.

---

## 6. Settlement Binding and Honor

Accept checks the credential; honor delivers goods against an observed settlement. Honor itself (the business logic of release) is the integrating application's job; this standard fixes the binding, the gates, and the timing.

**One settlement, one quote.** Output-existence alone is insufficient: every payment to a payee lands at the same reused address, so two quotes for the same payee at the same price would both be satisfied by one payment. The binding is 1:1:

- The honored settlement output MUST carry `quote_id` in its datum, and the acceptor MUST match it. Datum is covered by the payer's funding signature (node `src/types/transaction.rs:115`, into the EXFER-SIG image at `:340`), so the link is signature-bound with no consensus change. `quote_id`-in-datum is therefore REQUIRED.
- The acceptor maintains a durable CONSUMED-OUTPOINT gate; the settlement outpoint MUST be unconsumed; on honor it records both `(signer_pubkey, quote_id)` and the outpoint. One outpoint honors at most one quote.

**Plain-output honor.** Honor when a settlement output, confirmed to the acceptor's depth policy, pays exactly `exfer_amount` to `domain_hash(EXFER-ADDR, payee_pubkey)`, carries the matching `quote_id` in datum, and has an unconsumed outpoint. An output below `exfer_amount` MUST NOT be honored.

**HTLC honor.** An HTLC output is not receipt: the timeout path is `height_gt(timeout_height) AND sig_check(sender)` (node `src/covenants/htlc.rs:32-34`), strictly greater and reading the confirming block height, so a sender reclaim is first confirmable at `timeout_height + 1`. Therefore honor only AFTER the acceptor's OWN claim transaction confirms to depth — at which point it reduces to plain-output honor (same datum/outpoint binding, keyed on the HTLC outpoint). To attempt the claim: the HTLC output is confirmed with `receiver_key = payee_pubkey`, value exactly `exfer_amount`, `quote_id` in datum, outpoint unconsumed; the payee holds the preimage locally; and `tip_height + CLAIM_MARGIN <= timeout_height`, with `CLAIM_MARGIN` exceeding max-tolerated reorg depth plus confirmation depth. Because preimage-in-hand is a precondition, the payee is the `hash_lock` originator in practice, so issuer tooling MUST generate the secret payee-side. HTLC scripts are parsed client-side via `try_parse_htlc` (node `src/covenants/htlc.rs:187`); an acceptor MUST confirm the actual on-chain script, not the quote's claimed parameters.

**Payer binding.** When `payer_pubkey` is present: for the HTLC form, the covenant's `sender_key` MUST equal `payer_pubkey`; for the plain-output form, at least one settlement input MUST spend an output locked to `domain_hash(EXFER-ADDR, payer_pubkey)` (consensus already enforced a signature under that key — `validate_phase1_input`, node `src/consensus/validation.rs:566`, check at `:598`). The plain-output rule proves the payer **authorized the transaction**, not that the payer funded `exfer_amount`; if "payer-funded" is intended, additionally require the payer-keyed inputs to sum to `>= exfer_amount`. Funding purely from covenant/script inputs cannot satisfy payer binding — the acceptor MUST NOT honor, and issuers MUST omit `payer_pubkey` for such payers. There is no acceptance-signature side channel.

**Gates.** Both gates (SEEN-SET keyed `(signer_pubkey, quote_id)`, CONSUMED-OUTPOINT keyed by outpoint) MUST be durably committed before honor (write-ahead), retained until `expires_at + MAX_RECHECK_WINDOW`, and shared per accepting identity (multiple instances / co-payees MUST share or partition). Late honor in the retention window applies ONLY to a quote accepted-and-observed strictly before `expires_at`; a quote first presented at or after `expires_at` MUST be declined.

**Two clocks.** `expires_at` is wall-clock and bounds price risk; HTLC `timeout_height`, confirmation depth, and `CLAIM_MARGIN` are on the block-height clock. A reorg moves the block-height clock backward while `expires_at` does not move. An acceptor MUST drive honor off the block-height clock plus `CLAIM_MARGIN` and use the wall-clock only for observation and gate retention; treating a once-seen confirmation as permanent across a reorg is the error this forbids.

---

## 7. Parameters and Bounds

| Bound | Value | Kind |
|---|---|---|
| `MAX_TTL` | 3600 s cap; 300 s RECOMMENDED | protocol cap / policy |
| `issued_at < expires_at` | strict | protocol |
| `MAX_SKEW` | 60 s on `issued_at` only (expiry-side skew folded into `MAX_RECHECK_WINDOW`) | policy |
| `MAX_RECHECK_WINDOW` | 120 s RECOMMENDED | acceptor policy |
| `memo` | ≤ 256 bytes UTF-8 | protocol |
| `currency` | 3–12 chars `[A-Z0-9]` | protocol |
| `CLAIM_MARGIN` | > max-tolerated reorg depth + confirmation depth | acceptor policy |

This standard fixes the relationships among `CLAIM_MARGIN`, reorg depth, and confirmation depth, not their concrete values; mis-sizing them defeats the reorg mitigation despite conformance to the ordering.

---

## 8. Security Notes

A signed quote is a bearer credential: verification is a pure, key-free function of the quote plus the live `genesis_block_id`. The design does not prevent copying; it bounds what a copy can do:

| Bound | Mechanism | Removes |
|---|---|---|
| Single instance | `genesis_block_id` binding (Sections 3–4) | cross-instance replay (devnet quote on mainnet) |
| Single domain | `EXFER-QUOTE` tag + mutual-non-prefix (Section 3) | reinterpretation as a tx or message |
| Single version | version-byte reject-if-unknown (Sections 5, 9) | re-decode under another layout |
| Bounded lifetime | `expires_at` + strict late-honor (Sections 5, 6) | post-expiry honor and first-presentation |
| Single settlement | `quote_id`-in-datum + two gates (Section 6) | multi-quote/one-settlement and double-honor |
| Honest key only | weak-key rejection (Section 5) | one signature validating across quotes |

An acceptor MUST treat the conjunction as the perimeter and MUST NOT relax any bound for convenience. **Residual risks** (accept or mitigate at the app layer; not fixable without a consensus change): independent acceptors that do not share gate state can each honor one settlement (no global registry); prev-output script lookup is gated by `TX_INDEX_TABLE` (node `src/chain/storage.rs:79`), `SPENT_BY_TABLE` carries no script (`:105`), and there is no outpoint-to-output RPC — the caveat bites only historical funding, since a just-submitted settlement's inputs are recent and indexed; parameter mis-sizing and a non-payee-originated preimage both break the reasoning above and must be re-derived for such deployments.

---

## 9. Versioning and Conformance

**Versioning.** The `version` byte selects a complete image layout; a signature under one version MUST NOT verify under another, and a verifier MUST reject an unknown version with no best-effort decode. Any change to field layout/width/encoding, endianness, the domain tag, the hash construction, the signature scheme, or the set of required fields REQUIRES a new version byte. A new pricing unit is added by registering a `currency` code (additive, no version bump). A new `EXFER-*` domain tag is reserved for a genuinely new signing use-case — a format change MUST NOT mint a new tag.

**Conformance.** Three roles: a VERIFIER implements Section 5 (pure, key-free; maps to `quote_verify`); an ISSUER additionally constructs valid images and generates the HTLC secret payee-side (maps to `quote_issue`); an ACCEPTOR additionally enforces the honor rules and gates of Section 6. A conformance claim MUST be backed by the Section 10 vectors plus the two required tests (tag-non-prefix, strict-decode).

---

## 10. Test Vectors

Byte-exact and reproducible. An issuer MUST reproduce `image_hex`; a verifier re-signing with the stated seed MUST reproduce the signature; a strict decoder MUST reject the two negatives at decode, before any signature check. (Generated and independently signature-verified with an RFC 8032 Ed25519 implementation; the generator is under `docs/quote-test-vectors/`.)

**Parameters.** Signature: raw Ed25519 over the image. `genesis_block_id` = 32 zero bytes (TEST DOMAIN only; a real quote binds the node-derived genesis). Seeds: signer `00010203…1f`, payee `2021…3f`, payer `4041…5f`. Derived `signer_pubkey = 03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8`, `payee_pubkey = 29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7`, `payer_pubkey = 2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d`. `payee_address = domain_hash(EXFER-ADDR, payee_pubkey) = 7f90e5febf8366d1240e1a2bdec7d1a2f5361a486ef34afa96a73b3990651fd9`.

**vec_a** — minimal, no payer, empty memo (`quote_id=000102030405060708090a0b0c0d0e0f`, `currency=USD`, `amount_minor=1250`, `rate=4000000000`, `exfer_amount=50000000000`, `issued_at=1781234567`, `expires_at=1781234867`). 139 bytes.

```
image:     45584645522d51554f5445000000000000000000000000000000000000000000000000000000000000000001000102030405060708090a0b0c0d0e0f0355534400000000000004e200000000ee6b28000000000ba43b740029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd700000000006a2b7b87000000006a2b7cb30000
signature: bcfc1e3b8e9f4a42ebd1daf1e3f093b8f164028094e75d6bb1ea750c6fe40e4c8d9401c7a350520024498a134888ec7ccff16c9297457817c3a1fd3a46928e05
```

**vec_b** — with payer (`payer_flag=1`, non-transferable; `quote_id=9f2c4a1e0b7d3c5a8e6f1029384b5c6d`, `memo="api-credits/2026-06"`). 190 bytes.

```
image:     45584645522d51554f54450000000000000000000000000000000000000000000000000000000000000000019f2c4a1e0b7d3c5a8e6f1029384b5c6d0355534400000000000004e200000000ee6b28000000000ba43b740029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7012543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d000000006a2b7b87000000006a2b7cb300136170692d637265646974732f323032362d3036
signature: 11ec5160924ec6d91efd3900fbeec6798a08ca02aef8db2e2a07afba1b24a0968927fcb20a7c81601bf6a2640ab6e223f46d1f8ee131add0e17b37dd959fe906
```

**vec_c** — multi-byte UTF-8 memo, non-ISO ticker (`quote_id=ffeeddccbbaa99887766554433221100`, `currency=SATS`, `amount_minor=123456`, `rate=1`, `exfer_amount=123456`, `memo="货到付款 — café 🚀"`). 167 bytes.

```
image:     45584645522d51554f5445000000000000000000000000000000000000000000000000000000000000000001ffeeddccbbaa998877665544332211000453415453000000000001e2400000000000000001000000000001e24029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd700000000006a2b7b87000000006a2b7cb3001be8b4a7e588b0e4bb98e6acbe20e2809420636166c3a920f09f9a80
signature: 07f427d44873b88f6313c7d11ba394216f12728c7abd18c546add914c66f2eb8e7a683c5fb0adfe056d4ade389b8d01ecbd904fdd51864759e7dbbdedbc5390d
```

**vec_d (negative)** — vec_a plus one trailing `0x00` after `memo` (140 bytes). Strict-decode MUST reject (trailing bytes).

```
image:     45584645522d51554f5445000000000000000000000000000000000000000000000000000000000000000001000102030405060708090a0b0c0d0e0f0355534400000000000004e200000000ee6b28000000000ba43b740029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd700000000006a2b7b87000000006a2b7cb3000000
```

**vec_e (negative)** — vec_a with the `payer_flag` byte (offset 120) = `0x02` (139 bytes). Strict-decode MUST reject (`payer_flag` not in {0,1}).

```
image:     45584645522d51554f5445000000000000000000000000000000000000000000000000000000000000000001000102030405060708090a0b0c0d0e0f0355534400000000000004e200000000ee6b28000000000ba43b740029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd702000000006a2b7b87000000006a2b7cb30000
```

---

## 11. walletd Integration

The reference implementation is walletd `quote_issue` (`Scope::Spend`, same posture as `sign_message`) and `quote_verify` (`Scope::Read`, pure), following the `signmsg.rs` register. Both ship gated on #33: they bind `genesis_block_id` from the node's `get_block_height` (node `src/rpc.rs:456`) or do not ship at all. `quote_verify` implements *accept* (Section 5); *honor* (Section 6) is the integrating application's job. exfer-py and the MCP server then expose both, carrying the scope through (a `Read` token cannot mint quotes). Nothing in the consensus crate, no jet, no tag.

Two RPC-surface facts an acceptor must budget for: there is no outpoint-to-output RPC, so plain-output payer-binding verification is a two-call derivation off `get_transaction` (contingent on `TX_INDEX_TABLE` coverage); and HTLC script parsing is client-side via `try_parse_htlc`. A signed quote MAY also be carried as a `quote=` parameter on an `exfer:` URI (walletd `src/payment_uri.rs`) with no format break. The existing unsigned swap quote (`swap_get_quote`, channel-authenticated only) MAY later additionally carry an EXFER-QUOTE image for object-side verification; until then the two coexist and this standard changes no swap behavior.

---

## 12. Changelog

- **v1 (Draft), 2026-06-07.** Initial standard, derived from and resolving [issue #28](https://github.com/ahuman-exfer/exfer/issues/28); wire image frozen per the approval. Implementation gated on [#33](https://github.com/ahuman-exfer/exfer/pull/33). Wire version byte = 1.
