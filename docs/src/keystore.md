# Keystore (keyring)

Walletd's keystore is a **flat keyring**: a collection of independent
keys, each individually exportable, importable, and deletable. No single
secret governs the others — every address has its OWN 24-word recovery
phrase, and a single **vault** file backs up the whole keyring under one
passphrase.

This replaced the older "one HD seed derives every address" model. A
legacy HD seed still works as a backward-compatible *origin* (see
[Seeded vs seedless](#seeded-vs-seedless)), but it is no longer the
spine of the wallet.

## Key origins

A key enters the keyring one of three ways:

| Origin | Created by | Recovery |
| ------ | ---------- | -------- |
| **Standard** (default) | `generate_standard_address`, `import_standard_mnemonic` | its own 24-word BIP-39 phrase, cross-wallet compatible |
| **Independent** | `generate_independent_address` | its own 24-word phrase (the raw ed25519 secret encoded as BIP-39) |
| **Imported** | `import_private_key`, `import_mnemonic` | the supplied secret / phrase; back it up yourself |
| **HD-derived** (legacy) | `generate_address` on a seeded keyring | the keyring's single seed mnemonic |

`generate_standard_address` is the **default for new addresses**. It
mints a fresh 1:1 address from a random standard BIP-39 phrase whose
derivation matches `exfer.dev` and the apps — the same phrase re-imported
into any Exfer wallet yields the same address. Each method returns
`{address, pubkey, imported: true}`.

## Standard vs independent

Both are 1:1 keys with their own recovery phrase; they differ only in
how the phrase maps to the secret:

- **Standard** mixes the BIP-39 seed with the domain tag
  `EXFER-MNEMONIC-ED25519-V1` (pinned, byte-identical across `exfer.dev`
  web and the apps). Its phrase is sealed alongside the key so
  `reveal_address_mnemonic` can return it, and the phrase restores the
  same address in any Exfer wallet.
- **Independent** encodes the raw 32-byte ed25519 secret directly as a
  BIP-39 phrase. Self-contained, but not derived through the standard
  domain — restore it into walletd, not into a different wallet's
  "import mnemonic".

## On-disk layout (`<wallet_dir>/`)

```
seed.enc                       ← OPTIONAL legacy HD entropy (32 B), sealed.
                                 Absent in a seedless keyring.
state.json                     ← {"next_index": N, "derived": {addr→idx},
                                  "labels": {addr→label}, "imported": [addr,…]}
imported/<addr>.key.enc        ← sealed 32-byte secret per 1:1 key
imported/<addr>.mnemonic.enc   ← sealed BIP-39 phrase for STANDARD keys only
                                 (lets reveal_address_mnemonic return it)
```

`<wallet_dir>` defaults to `<datadir>/wallets` (mode `0700`).

## At-rest encryption

Every sealed file (keys, mnemonics, the optional seed, the vault) uses
one format:

```
magic   "WDV1" (4)
version 1 (1)
salt    16 bytes  (random per-seal; fed to argon2id)
nonce   12 bytes  (random per-seal; fed to ChaCha20-Poly1305)
ct      payload + 16-byte Poly1305 tag
```

Argon2id parameters: **m=64 MiB / t=3 / p=1** (≈0.5–1s on a modern x86
core) — enough to defeat offline brute force against medium-strength
passphrases, cheap enough that unseal stays snappy. Each sealed class is
bound to its own AAD (`exfer-walletd/v1/{seed,imported,vault,mnemonic}`)
so a blob can't be replayed across roles.

## The keystore passphrase

The at-rest KEK comes from `WALLETD_KEYSTORE_PASSPHRASE`; walletd
**refuses to start without it**. Set it via:

- env var directly (development):
  ```bash
  WALLETD_KEYSTORE_PASSPHRASE='correct horse battery staple' exfer-walletd
  ```
- secret manager → env at process spawn (production): systemd
  `Environment=` in a `0600` drop-in; Docker/k8s from a Secrets Manager.
- never check `.env` files into git.

A wrong passphrase on a later start surfaces `KeystoreLocked`
(`-32012`) and walletd exits before binding any socket.

## Backup and recovery

Two complementary backups:

1. **The vault** (recommended). `export_vault` seals the entire keyring
   — every key, with standard mnemonics — into one passphrase-protected
   blob; `import_vault` restores it into another walletd. This is the
   single-file backup that survives adding new addresses without
   re-backing-up. `export_address` exports just one key as a vault blob.
2. **Per-address recovery phrase.** `reveal_address_mnemonic` returns one
   address's 24 words. A standard phrase restores that address into any
   Exfer wallet; an independent phrase restores into walletd.

Deleting a key (`delete_address`) is destructive: it refuses while the
address holds a balance unless you pass `force: true`, and once erased
the key is gone unless it was backed up (vault or phrase). Sweep first.

## Seeded vs seedless

- **Seedless** (default for fresh keyrings): no `seed.enc`. Every
  address is its own 1:1 key; backup is the vault or per-address phrases.
- **Seeded** (legacy / operator): a `seed.enc` is present and
  `generate_address` derives addresses by index along
  `m/44'/9527'/0'/0'/i'` (SLIP-0010 Ed25519, all-hardened). The single
  seed mnemonic backs up every *derived* address. Coin type `9527'` is a
  private-use SLIP-44 placeholder until Exfer registers an official slot;
  changing it would invalidate every derived address.

Existing seeded wallets keep working unchanged — they derive as before,
and new addresses default to standard 1:1 keys. `state.json` is not
required for derivation correctness on a seeded keyring (the address at
any index is a pure function of the seed), but it is the only record of
imported/independent keys, so it is included in the vault.
