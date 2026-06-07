#!/usr/bin/env python3
"""
EXFER-QUOTE test-vector generator (BIP-340 style).

REPRODUCIBILITY CONTRACT
========================
- Signing scheme : raw Ed25519 (RFC 8032), signature over the byte-exact image.
- Image prefix   : the ASCII bytes b"EXFER-QUOTE" (NOT length-prefixed; the
                   schema fixes a literal prefix, distinct from the consensus
                   domain_hash construction). The image is what is signed; the
                   signature is NOT part of the image.
- Endianness     : ALL integers in the image are BIG-ENDIAN (diverges from the
                   tx body, which is little-endian; node src/types/transaction.rs:290).
- genesis_block_id : 32 zero bytes (0x00 * 32). This is the TEST DOMAIN ONLY.
                   A real quote binds the node-derived genesis (src/rpc.rs).
- Keys           : deterministic Ed25519 from a fixed 32-byte seed.
                   issuer/signer seed = bytes(range(32))         = 00 01 .. 1f
                   payee seed         = bytes(range(32,64))       = 20 21 .. 3f
                   payer seed         = bytes(range(64,96))       = 40 41 .. 5f
- Address deriv   : address = SHA256( len(b"EXFER-ADDR") || b"EXFER-ADDR" || pubkey )
                   i.e. node Hash256::domain_hash(DS_ADDR, pubkey)
                   (src/types/mod.rs:368, src/types/hash.rs:15,
                    src/types/transaction.rs:95). Shown so an implementer can
                    confirm address-derivation-matches-chain.

IMAGE LAYOUT (issue-28-quote-schema-final.md lines 36-45)
=========================================================
  b"EXFER-QUOTE"                      (11 bytes, literal ASCII)
  genesis_block_id                    (32 bytes)
  version                             (u8)
  quote_id                            (16 bytes)
  currency_len                        (u8)
  currency                            (currency_len bytes, ASCII)
  amount_minor                        (u64 BE)
  rate_exfers_per_unit                (u64 BE)
  exfer_amount                        (u64 BE)
  payee_pubkey                        (32 bytes)
  payer_flag                          (u8; MUST be 0 or 1)
  [payer_pubkey                       (32 bytes) iff payer_flag == 1]
  issued_at                           (u64 BE)
  expires_at                          (u64 BE)
  memo_len                            (u16 BE)
  memo                                (memo_len bytes, UTF-8)

Lib used: pynacl (probed importable). Falls back to cryptography if needed.
"""

import json
import struct
import hashlib

# ---- Ed25519 backend (pynacl preferred, cryptography fallback) ----
_BACKEND = None
try:
    from nacl.signing import SigningKey  # type: ignore

    _BACKEND = "pynacl"

    def ed25519_keypair(seed: bytes):
        sk = SigningKey(seed)
        return sk, bytes(sk.verify_key)

    def ed25519_sign(sk, msg: bytes) -> bytes:
        return sk.sign(msg).signature
except Exception:  # pragma: no cover
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from cryptography.hazmat.primitives import serialization

    _BACKEND = "cryptography"

    def ed25519_keypair(seed: bytes):
        sk = Ed25519PrivateKey.from_private_bytes(seed)
        pub = sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return sk, pub

    def ed25519_sign(sk, msg: bytes) -> bytes:
        return sk.sign(msg)


PREFIX = b"EXFER-QUOTE"
DS_ADDR = b"EXFER-ADDR"
GENESIS = bytes(32)  # 32 zero bytes = TEST DOMAIN


def address_for_pubkey(pubkey: bytes) -> bytes:
    """node Hash256::domain_hash(DS_ADDR, pubkey)."""
    h = hashlib.sha256()
    h.update(bytes([len(DS_ADDR)]))
    h.update(DS_ADDR)
    h.update(pubkey)
    return h.digest()


def build_image(
    version: int,
    quote_id: bytes,
    currency: bytes,
    amount_minor: int,
    rate_exfers_per_unit: int,
    exfer_amount: int,
    payee_pubkey: bytes,
    payer_flag: int,
    payer_pubkey,
    issued_at: int,
    expires_at: int,
    memo: bytes,
) -> bytes:
    assert len(quote_id) == 16, "quote_id must be 16 bytes"
    assert len(payee_pubkey) == 32
    assert len(currency) <= 255
    assert len(memo) <= 0xFFFF
    out = bytearray()
    out += PREFIX
    out += GENESIS
    out += struct.pack(">B", version)
    out += quote_id
    out += struct.pack(">B", len(currency))
    out += currency
    out += struct.pack(">Q", amount_minor)
    out += struct.pack(">Q", rate_exfers_per_unit)
    out += struct.pack(">Q", exfer_amount)
    out += payee_pubkey
    out += struct.pack(">B", payer_flag)
    if payer_flag == 1:
        assert payer_pubkey is not None and len(payer_pubkey) == 32
        out += payer_pubkey
    out += struct.pack(">Q", issued_at)
    out += struct.pack(">Q", expires_at)
    out += struct.pack(">H", len(memo))
    out += memo
    return bytes(out)


# ---- deterministic test keys ----
issuer_sk, issuer_pub = ed25519_keypair(bytes(range(0, 32)))
payee_sk, payee_pub = ed25519_keypair(bytes(range(32, 64)))
payer_sk, payer_pub = ed25519_keypair(bytes(range(64, 96)))

QID_A = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
QID_B = bytes.fromhex("9f2c4a1e0b7d3c5a8e6f1029384b5c6d")
QID_C = bytes.fromhex("ffeeddccbbaa99887766554433221100")


def emit_positive(name, descr, fields):
    img = build_image(**fields)
    sig = ed25519_sign(issuer_sk, img)
    rec = {
        "name": name,
        "kind": "positive",
        "description": descr,
        "expected_verify": True,
        "json": {
            "version": fields["version"],
            "quote_id": fields["quote_id"].hex(),
            "currency": fields["currency"].decode("ascii"),
            "amount_minor": fields["amount_minor"],
            "rate_exfers_per_unit": fields["rate_exfers_per_unit"],
            "exfer_amount": fields["exfer_amount"],
            "payee_pubkey": fields["payee_pubkey"].hex(),
            "payer_pubkey": (
                fields["payer_pubkey"].hex()
                if fields["payer_flag"] == 1
                else None
            ),
            "payer_flag": fields["payer_flag"],
            "issued_at": fields["issued_at"],
            "expires_at": fields["expires_at"],
            "memo": fields["memo"].decode("utf-8"),
            "signer_pubkey": issuer_pub.hex(),
            "signature": sig.hex(),
        },
        "genesis_block_id": GENESIS.hex(),
        "image_hex": img.hex(),
        "image_len": len(img),
        "signer_pubkey": issuer_pub.hex(),
        "signature": sig.hex(),
        "payee_address": address_for_pubkey(payee_pub).hex(),
    }
    return rec


vectors = []

# (a) minimal: no payer, empty memo
vectors.append(
    emit_positive(
        "vec_a_minimal_no_payer_empty_memo",
        "Minimal quote: payer_flag=0 (no payer key), empty memo, ISO currency.",
        dict(
            version=1,
            quote_id=QID_A,
            currency=b"USD",
            amount_minor=1250,
            rate_exfers_per_unit=4000000000,
            exfer_amount=50000000000,
            payee_pubkey=payee_pub,
            payer_flag=0,
            payer_pubkey=None,
            issued_at=1781234567,
            expires_at=1781234867,
            memo=b"",
        ),
    )
)

# (b) with payer_pubkey (payer_flag=1)
vectors.append(
    emit_positive(
        "vec_b_with_payer",
        "Quote bound to a payer: payer_flag=1, payer_pubkey present (non-transferable).",
        dict(
            version=1,
            quote_id=QID_B,
            currency=b"USD",
            amount_minor=1250,
            rate_exfers_per_unit=4000000000,
            exfer_amount=50000000000,
            payee_pubkey=payee_pub,
            payer_flag=1,
            payer_pubkey=payer_pub,
            issued_at=1781234567,
            expires_at=1781234867,
            memo=b"api-credits/2026-06",
        ),
    )
)

# (c) multi-byte UTF-8 memo + non-ISO ticker
vectors.append(
    emit_positive(
        "vec_c_utf8_memo_noniso_currency",
        "Multi-byte UTF-8 memo (CJK + emoji) and a non-ISO ticker (SATS).",
        dict(
            version=1,
            quote_id=QID_C,
            currency=b"SATS",
            amount_minor=123456,
            rate_exfers_per_unit=1,
            exfer_amount=123456,
            payee_pubkey=payee_pub,
            payer_flag=0,
            payer_pubkey=None,
            issued_at=1781234567,
            expires_at=1781234867,
            memo="货到付款 — café \U0001f680".encode("utf-8"),
        ),
    )
)

# ---- Negative vectors (decode MUST reject; no valid signature is meaningful) ----

# (d) trailing-byte image: a valid (a)-shaped image with one extra 0x00 appended.
base_img = bytes.fromhex(vectors[0]["image_hex"])
trailing_img = base_img + b"\x00"
trailing_sig = ed25519_sign(issuer_sk, trailing_img)  # signs the WRONG length on purpose
vectors.append(
    {
        "name": "vec_d_trailing_byte_reject",
        "kind": "negative",
        "description": (
            "Strict-decode MUST reject: image identical to vec_a plus one trailing "
            "0x00 byte after memo. Image length is fully determined by currency_len, "
            "payer_flag and memo_len, so any trailing byte is a decode error "
            "BEFORE signature check."
        ),
        "expected_verify": False,
        "reject_reason": "trailing bytes after memo (strict-decode failure)",
        "genesis_block_id": GENESIS.hex(),
        "image_hex": trailing_img.hex(),
        "image_len": len(trailing_img),
        "valid_image_len": len(base_img),
        "signer_pubkey": issuer_pub.hex(),
        "signature_over_trailing_image": trailing_sig.hex(),
    }
)

# (e) payer_flag == 2: decode error. Build the bytes by hand so payer_flag is 2.
def build_bad_payer_flag(flag: int) -> bytes:
    out = bytearray()
    out += PREFIX
    out += GENESIS
    out += struct.pack(">B", 1)            # version
    out += QID_A                           # quote_id
    out += struct.pack(">B", 3)            # currency_len
    out += b"USD"                          # currency
    out += struct.pack(">Q", 1250)         # amount_minor
    out += struct.pack(">Q", 4000000000)   # rate_exfers_per_unit
    out += struct.pack(">Q", 50000000000)  # exfer_amount
    out += payee_pub                       # payee_pubkey
    out += struct.pack(">B", flag)         # payer_flag = 2 (ILLEGAL)
    # NB: with flag=2 the decoder cannot know whether a payer key follows.
    out += struct.pack(">Q", 1781234567)   # issued_at
    out += struct.pack(">Q", 1781234867)   # expires_at
    out += struct.pack(">H", 0)            # memo_len
    return bytes(out)


bad_flag_img = build_bad_payer_flag(2)
bad_flag_sig = ed25519_sign(issuer_sk, bad_flag_img)
vectors.append(
    {
        "name": "vec_e_payer_flag_2_reject",
        "kind": "negative",
        "description": (
            "Strict-decode MUST reject: payer_flag = 2. The flag MUST be exactly "
            "0 or 1; any other value is a decode error (the decoder cannot even "
            "determine whether a payer_pubkey follows). Reject BEFORE signature check."
        ),
        "expected_verify": False,
        "reject_reason": "payer_flag not in {0,1} (value=2) (strict-decode failure)",
        "genesis_block_id": GENESIS.hex(),
        "image_hex": bad_flag_img.hex(),
        "image_len": len(bad_flag_img),
        "payer_flag_value": 2,
        "signer_pubkey": issuer_pub.hex(),
        "signature_over_image": bad_flag_sig.hex(),
    }
)


def main():
    print("=" * 78)
    print("EXFER-QUOTE TEST VECTORS")
    print("=" * 78)
    print(f"ed25519 backend     : {_BACKEND}")
    print(f"issuer/signer seed  : {bytes(range(0,32)).hex()}")
    print(f"payee seed          : {bytes(range(32,64)).hex()}")
    print(f"payer seed          : {bytes(range(64,96)).hex()}")
    print(f"signer_pubkey       : {issuer_pub.hex()}")
    print(f"payee_pubkey        : {payee_pub.hex()}")
    print(f"payer_pubkey        : {payer_pub.hex()}")
    print(f"genesis_block_id    : {GENESIS.hex()}  (TEST DOMAIN: 32 zero bytes)")
    print(f"image prefix (hex)  : {PREFIX.hex()}  (= ASCII {PREFIX!r})")
    print(f"payee_address       : {address_for_pubkey(payee_pub).hex()}")
    print(f"                      = domain_hash(EXFER-ADDR, payee_pubkey)")
    print("=" * 78)
    for v in vectors:
        print()
        print(f"### {v['name']}  [{v['kind']}, expected_verify={v['expected_verify']}]")
        print(f"    {v['description']}")
        if v["kind"] == "positive":
            j = v["json"]
            print("    JSON fields:")
            for k in (
                "version", "quote_id", "currency", "amount_minor",
                "rate_exfers_per_unit", "exfer_amount", "payee_pubkey",
                "payer_pubkey", "payer_flag", "issued_at", "expires_at",
                "memo", "signer_pubkey", "signature",
            ):
                print(f"      {k:22s}: {j[k]}")
            print(f"    image_len           : {v['image_len']}")
            print(f"    image_hex           : {v['image_hex']}")
            print(f"    signature           : {v['signature']}")
            print(f"    payee_address       : {v['payee_address']}")
        else:
            print(f"    reject_reason       : {v['reject_reason']}")
            print(f"    image_len           : {v['image_len']}")
            print(f"    image_hex           : {v['image_hex']}")
            sigkey = next((k for k in v if k.startswith("signature")), None)
            if sigkey:
                print(f"    {sigkey:22s}: {v[sigkey]}")
    print()
    print("=" * 78)
    print("MACHINE-READABLE (JSON)")
    print("=" * 78)
    print(json.dumps(vectors, indent=2))


if __name__ == "__main__":
    main()