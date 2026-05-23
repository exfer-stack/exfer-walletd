# Migrating from v0.x → v1.0

v1.0 is a deliberately breaking release. The wire schema, scope model,
and on-disk keystore all change. Treat the upgrade as: stand up a fresh
v1.0 keystore alongside your v0.x deployment, migrate the old `.key`
files in, repoint clients to the new schema, then turn off v0.x.

## What changed

### Field naming

| v0.x | v1.0 |
|---|---|
| `get_transaction` param `{hash}` | `{tx_id}` |
| `get_block` (untagged `hash` xor `height`) | `get_block_by_id {block_id}` + `get_block_by_height {height}` |
| `get_block_hash {height}` | `get_block_id_at_height {height}` |
| `BlockSummary.hash` | `BlockSummary.block_id` |
| `TxStatus.block_hash` | `TxStatus.block_id` |
| UTXO entry `script_len` (always null) | removed |
| transfer `{from, to, amount, fee}` | `{from, outputs: [{to, amount}], fee_rate? / fee?, max_fee?, client_token?}` |
| transfer receipt `{tx_id, size, tip_height, submitted}` | `{tx_id, size, fee, fee_rate, inputs, outputs, built_at_height}` |

### Error codes

`BadEnvelope` split into:

- `-32700` JSON parse error (body not parseable)
- `-32600` envelope-shape error (`jsonrpc != "2.0"`, missing method, …)
- `-32602` per-method param shape error (most call sites; matches
  spec's "Invalid params")

New error codes for v1.0 transfer semantics:

| Code | Variant |
|---|---|
| `-32012` | `KeystoreLocked` (wrong passphrase, corrupted seed) |
| `-32032` | `FeeTooHigh` (computed fee exceeds `max_fee`) |
| `-32033` | `DustOutput` |
| `-32034` | `TooManyOutputs` (cap = 16) |
| `-32035` | `IdempotencyConflict` (token reused with different params) |

### Auth scopes

Two scopes (`read`, `spend`) → three scopes (`read`, `manage`, `spend`).
`generate_address` moves to `manage` (previously was `read` — a bug,
since it writes state).

Config flags:

| v0.x | v1.0 |
|---|---|
| `--auth-token` (legacy single token) | **removed** |
| `--auth-token-read` | same |
| (none) | `--auth-token-manage` |
| `--auth-token-spend` | same |

On first run, walletd auto-generates three files in `<datadir>/`:
`token-read`, `token-manage`, `token-spend` (each mode `0600`).

### Keystore

- v0.x: one plaintext `<addr>.key` file per address (32 raw bytes).
- v1.0: one encrypted `seed.enc` for the entire HD chain, plus
  `state.json` indexing derived addresses.

The encryption KEK is derived from `WALLETD_KEYSTORE_PASSPHRASE` via
Argon2id; walletd refuses to start without that env var set.

### JSON-RPC compliance

- `jsonrpc` field is now strictly checked; anything other than `"2.0"`
  returns `-32600`.
- Batch requests (JSON array of envelopes) are supported per § 6.
- Notifications (envelopes with no `id` field) get no response per § 4.1.

## Migration procedure

1. **Stop v0.x** (or leave it running on a separate port; nothing
   prevents the two from coexisting).

2. **Set the keystore passphrase**:
   ```bash
   export WALLETD_KEYSTORE_PASSPHRASE='whatever-your-secret-manager-provides'
   ```

3. **Start v1.0 once** to initialise the HD seed and three scoped
   tokens:
   ```bash
   exfer-walletd --datadir /var/lib/walletd-v1
   ```
   Capture the 24-word mnemonic printed to stderr (paper / password
   manager / hardware backup). The mnemonic will never be shown again.

4. **Stop v1.0**, then **import the legacy `.key` files**:
   ```bash
   exfer-walletd migrate \
       --datadir /var/lib/walletd-v1 \
       --from    /var/lib/walletd-v0/wallets
   ```
   For each legacy `<addr>.key`, walletd imports the secret under
   `<datadir>/wallets/imported/<addr>.key.enc` and records the
   address in `state.json.imported[]`.

5. **Restart v1.0** in serving mode and switch clients over.

6. **Repoint clients**:
   - Use the new field names (`tx_id`, `block_id`, multi-output
     transfer, etc.). The dry-run table at the top of this doc maps
     every renamed surface.
   - Use the new scoped tokens (`token-spend` for withdrawal workers,
     `token-read` for deposit watchers, etc.).
   - Use the `client_token` field on `transfer` for retry safety.

7. **Decommission v0.x** once you've verified all dependent clients
   speak v1.

## Notes

- Imported addresses are NOT recoverable from the mnemonic. They
  remain spendable as long as `<datadir>/wallets/imported/*.key.enc`
  exists. Back them up alongside the seed.
- `migrate` refuses to run against a brand-new keystore (no captured
  mnemonic) — the assumption is you want all imports plus future
  derivations to be backed by a recorded seed.
- If a legacy `.key` is in the upstream encrypted (`EXFK`) format,
  pass `--legacy-passphrase` (or `WALLETD_LEGACY_PASSPHRASE`).
