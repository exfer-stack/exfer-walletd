# Keystore (HD seed)

v1.0 keeps **one** BIP-39 seed per daemon. Every address you ever
generate is derived from that seed by index — back up the seed once,
back up every present and future address.

## On-disk layout (`<wallet_dir>/`)

```
seed.enc                  ← BIP-39 entropy (32 B) sealed with argon2id + ChaCha20-Poly1305
state.json                ← {"next_index": N, "derived": {addr→idx},
                              "labels": {addr→label}, "imported": [addr,…]}
imported/<addr>.key.enc   ← sealed 32-byte secret for non-HD imports
```

`<wallet_dir>` defaults to `<datadir>/wallets` (mode `0700`).

## At-rest encryption

The seed (and any imported secrets) is wrapped in a small format:

```
magic   "WDV1" (4)
version 1 (1)
salt    16 bytes  (random per-seal; fed to argon2id)
nonce   12 bytes  (random per-seal; fed to ChaCha20-Poly1305)
ct      payload + 16-byte Poly1305 tag
```

Argon2id parameters: **m=64 MiB / t=3 / p=1** (≈0.5–1s on a modern
x86 core). Enough to defeat offline brute force against medium-strength
passphrases; cheap enough that startup (one unseal per seed) and
imported-key access stay snappy.

## The passphrase

The encryption KEK comes from `WALLETD_KEYSTORE_PASSPHRASE`. walletd
**refuses to start without it**. Set it via:

- env var directly (development):
  ```bash
  WALLETD_KEYSTORE_PASSPHRASE='correct horse battery staple' exfer-walletd
  ```
- secret manager → env at process spawn (production):
  - systemd: `Environment="WALLETD_KEYSTORE_PASSPHRASE=…"` in a
    `0600` drop-in
  - Docker / k8s: pull from Secrets Manager / Vault / AWS-SM /
    GCP-SM into the container env at start
- never check in: `.env` files in git are an immediate red flag

If the passphrase is wrong on a subsequent start, walletd surfaces
`KeystoreLocked` (`-32012`) and exits before binding any socket.

## Derivation path

```
m / 44' / 9527' / 0' / 0' / index'
```

- SLIP-0010 Ed25519 (forces hardened derivation at every level).
- Coin type `9527'` is a placeholder until Exfer registers an
  official SLIP-44 slot. Pinned in code; switching it would invalidate
  every derived address — only changes inside a major version bump.
- BIP-39 passphrase is empty: the *keystore* passphrase encrypts
  entropy at rest; the wallet itself has no second factor.

`derive_ed25519_private_key(seed, [44, 9527, 0, 0, index])` (from the
`slip10_ed25519` crate) produces a 32-byte secret; we wrap that as an
`ed25519_dalek::SigningKey` and compute the address as
`TxOutput::pubkey_hash_from_key(pubkey)` — byte-identical to the
on-chain address scheme.

## First-run mnemonic

The first time walletd starts with an empty `<wallet_dir>`, it
generates a 24-word BIP-39 mnemonic, seals the entropy to disk, and
prints the words to **stderr** inside a boxed section:

```
┌─ first run: HD seed ──────────────────────────────────────────────────
│ A new BIP-39 mnemonic has been generated and the seed has been
│ encrypted at rest with your WALLETD_KEYSTORE_PASSPHRASE.
│
│ ⚠  WRITE THESE 24 WORDS DOWN. They are the ONLY way to recover
│    every address this daemon will ever derive. They will NEVER be
│    shown again.
│
│     1. abandon    2. ability   3. able      4. about     5. above     6. absent
│     7. absorb     8. abstract  9. absurd   10. abuse    11. access   12. accident
│    13. account   14. accuse   15. achieve  16. acid     17. acoustic 18. acquire
│    19. across    20. act      21. action   22. actor    23. actress  24. actual
└───────────────────────────────────────────────────────────────────────
```

The mnemonic is **never re-printed** on later starts. Capture it
out-of-band on first run (paper, password manager, hardware backup).

## Recovery

Today: the only recovery is "restart with the same `seed.enc` + same
`WALLETD_KEYSTORE_PASSPHRASE`". A first-class "restore from mnemonic"
CLI shipping `--from-mnemonic <words>` is on the v1.1 roadmap.

For now, if you lose `seed.enc` but kept the mnemonic, re-importing
is a manual procedure: write a 32-byte entropy file derived from
your mnemonic, then arrange for it to be at `<wallet_dir>/seed.enc`
in walletd's sealed format. (Open an issue if you need this and we'll
prioritise the proper CLI.)

## Imported (non-derived) addresses

`exfer-walletd migrate --from <legacy-walletdir>` imports legacy v0.x
`.key` files (raw 32-byte ed25519 secrets, or upstream-encrypted
`EXFK`) as **non-derived** addresses. Each imported secret is sealed
with the same KEK as the seed and stored at
`<wallet_dir>/imported/<addr>.key.enc`.

Imported addresses appear in `list_addresses` with `imported: true`
and `index: null`. They sign normally; the only loss is that they're
not recoverable from the mnemonic — back up imported secrets separately
or accept that they're abandoned-by-design after a re-keying.

## Index pacing

Each `generate_address` bumps `next_index` and persists it atomically
(`state.json.tmp` → rename). With `u32` indices you have ~4 billion
addresses before the keystore refuses to mint more — well beyond any
practical exchange / payment processor.

`state.json` is *not* required for derivation correctness — the
address at any index is purely a function of the seed. If you ever
lose `state.json` but kept the seed, re-creating an empty one is
safe; `list_addresses` will just be empty until you `generate_address`
or learn the indices through other means.
