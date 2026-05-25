# RPC reference (v1.0)

JSON-RPC 2.0 over `POST /`. `GET /healthz` is unauthenticated and
returns `ok` for liveness probes.

Single requests and batches (per JSON-RPC 2.0 § 6) are both accepted.
Notifications (requests with no `id` field) get no response per spec.

Every method below follows the same envelope:

**Request**

```json
{
  "jsonrpc": "2.0",
  "method":  "<method-name>",
  "params":  { ... },
  "id":      1
}
```

`jsonrpc` must be exactly `"2.0"`. `id`, when present, must be a
JSON string, number, or `null`; object, array, and boolean ids are
rejected with `-32600` and response `id: null`. Omitting `id` makes
the request a JSON-RPC notification and walletd returns no response.

**Response (success)**

```json
{ "jsonrpc": "2.0", "result": { ... }, "id": 1 }
```

**Response (error)**

```json
{ "jsonrpc": "2.0",
  "error":   { "code": -32xxx, "message": "...", "data": { ... } },
  "id":      1 }
```

`data` is omitted for most errors; populated for the structured ones
listed in [Error codes](./errors.md).

Amounts and fees are integers in **exfers**, where
`1 EXFER = 100_000_000 exfers`. Consensus dust threshold is `200`
exfers.

Examples below assume:

```bash
URL='http://127.0.0.1:7448'
SPEND=$(cat ~/.exfer-walletd/token-spend)
READ=$(cat ~/.exfer-walletd/token-read)
```

## Scope mapping

| Scope | Methods |
|---|---|
| `read` | `ping`, `validate_address`, `get_balance`, `get_wallet_balance`, `get_block_height`, `get_block_by_id`, `get_block_by_height`, `get_block_id_at_height`, `get_transaction`, `get_address_utxos`, `get_script_utxos`, `get_status`, `list_addresses`, `verify_message` |
| `manage` | `generate_address`, `abandon_transfer` |
| `spend` | `transfer`, `send_raw_transaction`, `sign_message`, `reveal_mnemonic`, `reveal_private_key` |

`spend` ⊇ `manage` ⊇ `read`. A token at a higher scope satisfies every
lower scope.

---

## `ping`

| | |
|---|---|
| **Scope** | read |
| **Params** | `{}` |
| **Returns** | `{ ok: true }` |

---

## `validate_address`

Pure-function check that `address` is a syntactically well-formed
64-character hex string (32 bytes). No upstream call.

| | |
|---|---|
| **Scope** | read |
| **Params** | `{ address: string }` |
| **Returns** | `{ valid: bool, normalized: hex64 \| null }` |

`normalized` is lowercased on success, `null` on failure.

---

## `generate_address`

Derive the next HD address from the keystore seed and persist its
index. Optionally tag it with a `label`.

| | |
|---|---|
| **Scope** | manage |
| **Params** | `{ label?: string }` |
| **Returns** | `{ address: hex64, pubkey: hex64, index: u32 }` |

Sequential calls return `index: 0, 1, 2, …`. The address is fully
determined by `(seed, index)` — back up the 24-word mnemonic (shown
once at first start) and every present and future address is
recoverable.

---

## `list_addresses`

Enumerate every known address (derived + imported).

| | |
|---|---|
| **Scope** | read |
| **Params** | `{}` |
| **Returns** | `{ addresses: AddressEntry[] }` |

```ts
type AddressEntry = {
  address: hex64,
  index?: u32,      // present for derived; absent for imported
  label?: string,
  imported: bool,
};
```

---

## `get_wallet_balance`

Aggregate confirmed balance across every managed address.

For each known address, walletd calls upstream `get_balance` and
`get_address_utxos` so it can return both `balance` and `utxo_count`.
That is **2 upstream scan RPCs per address**, executed concurrently
with cap 8. On public/community nodes with per-IP scan quotas, large
wallets can hit upstream rate limits; use `list_addresses` plus paced
per-address reads if you need quota-safe polling until upstream batch
balance lookup exists.

| | |
|---|---|
| **Scope** | read |
| **Params** | `{}` |
| **Returns** | `{ entries: WalletEntry[], total: u64 }` |

```ts
type WalletEntry = {
  address: hex64,
  index?: u32,
  label?: string,
  imported: bool,
  balance: u64,
  utxo_count: u32,
  truncated: bool,  // upstream UTXO list was clipped at 1000
};
```

---

## `get_status`

Operator dashboard in one call: daemon version, chain tip, wallet
count, upstream URLs, in-flight counters.

| | |
|---|---|
| **Scope** | read |
| **Params** | `{}` |
| **Returns** | see below |

```ts
{
  version:             string,
  tip: { block_id: hex64 | null, height: u64 | null },
  upstream_ok:         bool,
  upstream_nodes:      string[],
  wallet_count:        u32,
  in_flight_utxos:     u32,
  in_flight_transfers: u32,
}
```

`tip.*` is `null` if the upstream RPC fails — the status call still
succeeds so a dashboard can show partial state.

---

## `get_balance`

Confirmed balance for one address.

| | |
|---|---|
| **Scope** | read |
| **Params** | `{ address: hex64 }` |
| **Returns** | `{ address: hex64, balance: u64 }` |

Mempool entries are NOT counted (upstream design). For pending
balance, walk `get_address_utxos` and inspect mempool transactions
manually.

---

## `get_address_utxos`

List confirmed UTXOs locked to an address.

| | |
|---|---|
| **Scope** | read |
| **Params** | `{ address: hex64 }` |
| **Returns** | see below |

```ts
{
  address:    hex64 | null,
  script_hex: hex   | null,
  tip_height: u64,
  truncated:  bool,
  utxos: [
    { tx_id: hex64, output_index: u32, value: u64,
      height: u64, is_coinbase: bool },
    ...
  ]
}
```

If `truncated` is `true`, the upstream node hit its 1000-entry result
limit and there is no pagination cursor (upstream limitation — see
README for the open RFC).

---

## `get_script_utxos`

Same shape as `get_address_utxos`, keyed by raw script bytes (hex).

| | |
|---|---|
| **Scope** | read |
| **Params** | `{ script_hex: hex }` |

---

## `get_block_height`

Chain tip.

| | |
|---|---|
| **Scope** | read |
| **Params** | `{}` |
| **Returns** | `{ height: u64, block_id: hex64 }` |

---

## `get_block_by_id`

| | |
|---|---|
| **Scope** | read |
| **Params** | `{ block_id: hex64 }` |
| **Returns** | `BlockSummary` (see below) |

---

## `get_block_by_height`

| | |
|---|---|
| **Scope** | read |
| **Params** | `{ height: u64 }` |
| **Returns** | `BlockSummary` |

```ts
type BlockSummary = {
  block_id:          hex64,
  height:            u64,
  prev_block_id:     hex64,
  state_root:        hex64,
  tx_root:           hex64,
  timestamp:         u64,
  nonce:             u64,
  difficulty_target: hex64,
  tx_count:          u64,
  transactions:      hex64[],   // tx_ids
};
```

---

## `get_block_id_at_height`

Explicit `height → block_id` lookup. Same shape as `get_block_height`.

| | |
|---|---|
| **Scope** | read |
| **Params** | `{ height: u64 }` |
| **Returns** | `{ height: u64, block_id: hex64 }` |

**Performance**: the upstream node has no native height→id index, so
walletd fetches the full block and discards everything else. Same
network cost as `get_block_by_height`. If your next step is to read
the block body, call `get_block_by_height` directly — one round trip
instead of two.

---

## `get_transaction`

Fetch a single transaction by id. Returns confirmed-chain or mempool
entries; `in_mempool` distinguishes.

| | |
|---|---|
| **Scope** | read |
| **Params** | `{ tx_id: hex64 }` |
| **Returns** | see below |

```ts
{
  tx_id:        hex64,
  tx_hex:       hex,
  in_mempool:   bool,
  block_id:     hex64 | null,
  block_height: u64   | null,

  // Decoded view (added for accounting / explorers — no upstream
  // calls beyond parent-tx fetches for value resolution).
  inputs: [
    {
      prev_tx_id:    hex64,
      output_index:  u32,
      address?:      hex64,
      script_hex?:   hex,
      value?:        u64,
      witness?: {
        pubkey?:       hex64,
        signature?:    hex128,
        witness_hex?:  hex,
        redeemer_hex?: hex,
      },
    }, ...
  ],
  outputs: [
    { address?: hex64, script_hex?: hex, value: u64 },
    ...
  ],
  total_out:  u64,
  total_in?:  u64,    // omitted if any input failed to resolve
  fee?:       u64,    // omitted with total_in
  size:       u64,
}
```

---

## `transfer`

Build, sign, and broadcast a multi-output payment.

| | |
|---|---|
| **Scope** | spend |

**Params**

| Field         | Type                                          | Required | Description |
| ------------- | --------------------------------------------- | -------- | ----------- |
| `from`        | hex64                                         | yes      | Sender address (HD-derived or imported). |
| `outputs`     | `[{ to: hex64, amount: u64 }]` (1..=16)       | yes      | Recipient list. Each `amount` ≥ DUST_THRESHOLD (200). |
| `fee_rate`    | u64                                           | no       | exfers per cost-unit. Mutually exclusive with `fee`. |
| `fee`         | u64                                           | no       | Absolute fee in exfers. Mutually exclusive with `fee_rate`. |
| `max_fee`     | u64                                           | no       | Cap; default **2_000_000** (0.02 EXFER). |
| `client_token`| string (8..=128 ASCII)                        | no       | Idempotency key. |

Defaults: if neither `fee` nor `fee_rate` is set, `fee_rate=1`
(consensus minimum). Fee is always floored at `consensus::cost::min_fee`
and refused if it would exceed `max_fee`.

**Returns**

```ts
{
  tx_id:           hex64,
  size:            u64,
  fee:             u64,      // effective fee (incl. folded sub-dust change)
  fee_rate:        u64,      // effective fee × MIN_FEE_DIVISOR / tx_cost
  inputs:          [{ tx_id: hex64, output_index: u32, value: u64 }],
  outputs:         [{ to: hex64, amount: u64, is_change: bool }],
  built_at_height: u64,      // tip at UTXO-listing time (not inclusion)
}
```

**Idempotency**: when `client_token` is supplied, the receipt is
cached for 1 hour. A repeat call with the same token + same params
returns the cached receipt without re-running. Same token + different
params → `-32035 IdempotencyConflict`.

**Common errors**

| Code     | When |
|----------|------|
| `-32001` | Wrong scope token. |
| `-32602` | Param shape error (`from` not 64-hex, `outputs[]` missing, `fee`+`fee_rate` both set, …). |
| `-32010` | Wallet not found — `from` is not a known address. |
| `-32020` | Upstream node unreachable / RPC error. |
| `-32030` | UTXO authentication failed. |
| `-32031` | Insufficient balance (with `in_flight_reserved` hint). |
| `-32032` | Fee exceeds `max_fee`. |
| `-32033` | An `outputs[].amount` is below dust. |
| `-32034` | `outputs[]` longer than 16. |
| `-32035` | Same `client_token` used with different params. |

---

## `send_raw_transaction`

Broadcast a pre-signed transaction. Passes through to the upstream.

| | |
|---|---|
| **Scope** | spend |
| **Params** | `{ tx_hex: hex }` |
| **Returns** | `{ tx_id: hex64 }` |

---

## `abandon_transfer`

Release outpoints from walletd's in-flight set (the local "soft
reserve" that prevents two concurrent transfers from picking the
same UTXO). Use after a transfer's broadcast appears to have failed
*and* you've confirmed via `get_transaction(tx_id)` that the network
never accepted it.

| | |
|---|---|
| **Scope** | manage |
| **Params** | `{ outpoints: [{ tx_id: hex64, output_index: u32 }] }` |
| **Returns** | `{ released_count: u32, remaining_in_flight: u32 }` |

In-flight outpoints also auto-expire on TTL (10 minutes); this call
is for explicit / faster release.

---

## `sign_message`

Sign an arbitrary UTF-8 message with the Ed25519 key of a managed
wallet. Domain-separated under `EXFER-MSG`, so a message signature
can never be mistaken for a transaction signature (transactions sign
under `EXFER-SIG`).

| | |
|---|---|
| **Scope** | spend |
| **Params** | `{ address: hex64, message: string }` |
| **Returns** | `{ signature: hex128, pubkey: hex64, address: hex64 }` |

`sign_message` is gated behind `spend` even though it doesn't move
funds, because the artifact is a verifiable proof of key ownership —
value-bearing in exchange / KYC contexts.

---

## `verify_message`

Verify an Ed25519 message signature. Pure crypto, no wallet access.

| | |
|---|---|
| **Scope** | read |
| **Params** | `{ pubkey: hex64, signature: hex128, message: string, address?: hex64 }` |
| **Returns** | `{ valid: bool, address: hex64 }` |

`address` (in the response) is always the address derived from
`pubkey`, so a verifier sees what the key actually hashes to even on
`valid: false`. If the optional request `address` is supplied, `valid`
is true iff signature verifies AND `H(DS_ADDR || pubkey) == address`.

---

## `reveal_mnemonic`

Re-supply the keystore passphrase and receive the 24-word BIP-39
mnemonic that produced this keystore. **Sensitive — only call after a
deliberate user action.**

| | |
|---|---|
| **Scope** | spend |
| **Params** | `{ passphrase: string }` |
| **Returns** | `{ mnemonic: string[] }` (24 lowercase BIP-39 words) |

The passphrase is verified by re-unsealing `seed.enc` with it. Wrong
passphrase surfaces as [`-32012` Keystore locked](./errors.md). The
in-memory passphrase from daemon start is **not** reused — clients
must pass it freshly, which mirrors standard wallet
"type your password to reveal" gating.

Walletd's HD path is `m/44'/9527'/0'/0'/i'`, so the returned mnemonic
is **not** directly portable to most third-party wallets (their default
coin-type-44 derivation uses a different `coin_type` slot). It is the
canonical recovery secret for re-running walletd against the same
keystore.

---

## `reveal_private_key`

Re-supply the keystore passphrase and receive the raw 32-byte ed25519
secret for a single managed address. **Sensitive — only call after a
deliberate user action.**

| | |
|---|---|
| **Scope** | spend |
| **Params** | `{ address: hex64, passphrase: string }` |
| **Returns** | `{ address: hex64, secret_hex: hex64 }` |

Works for HD-derived addresses (re-derives from the just-unsealed
seed) and for imported addresses (re-unseals the per-key file with the
same passphrase). Wrong passphrase → `-32012 Keystore locked`. Address
not in this keystore → `-32010 Wallet not found`.

The returned `secret_hex` is a 32-byte ed25519 private key in
lowercase hex, the same secret format consumed by
[`exfer-walletd migrate --from <dir>`](./keystore.md#imported-non-derived-addresses).

---

## Batch requests

Send a JSON array of envelopes; receive a JSON array of responses,
with notifications (no `id`) omitted. JSON-RPC 2.0 permits batch
responses in any order, so clients should correlate by `id`. Walletd
currently preserves request order in the response array, but callers
should not rely on order when using generic JSON-RPC tooling.

```bash
curl -s $URL \
  -H "Authorization: Bearer $READ" \
  -H 'content-type: application/json' \
  -d '[
        {"jsonrpc":"2.0","method":"ping","id":1},
        {"jsonrpc":"2.0","method":"get_block_height","id":2}
      ]'
```

Empty batches return a single top-level `-32600` response. Batches
consisting entirely of notifications return `204 No Content`. Mixed
batches return HTTP 200 with per-item `result` / `error` objects in
the array.
