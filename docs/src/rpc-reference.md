# RPC reference

JSON-RPC 2.0 over `POST /`. `GET /healthz` is unauthenticated and
returns `ok` for liveness probes.

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

**Response (success)**

```json
{
  "jsonrpc": "2.0",
  "result":  { ... },
  "id":      1
}
```

**Response (error)**

```json
{
  "jsonrpc": "2.0",
  "error":   { "code": -32xxx, "message": "..." },
  "id":      1
}
```

See [Error codes](./errors.md) for the full code table.

Amounts and fees are integers in **exfers**, where
`1 EXFER = 100_000_000 exfers`.

Examples below assume:

```bash
URL='http://127.0.0.1:7448'
TOKEN=$(cat ~/.exfer-walletd/token)   # or your secret-manager fetch
```

---

## `ping`

Liveness check. Goes nowhere near the upstream node.

| | |
|---|---|
| **Scope** | read |
| **Params** | `{}` |
| **Returns** | `{ ok: true }` |

**Example**

```bash
curl -s $URL -H "Authorization: Bearer $TOKEN" \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","method":"ping","id":1}'
```

```json
{"jsonrpc":"2.0","result":{"ok":true},"id":1}
```

---

## `generate_address`

Create a new Ed25519 keypair, persist the key file in
`WALLETD_WALLET_DIR/<address>.key`, return the public details.

| | |
|---|---|
| **Scope** | read |
| **Params** | `{}` |
| **Returns** | `{ address: hex64, pubkey: hex64 }` |

**Example**

```bash
curl -s $URL -H "Authorization: Bearer $TOKEN" \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","method":"generate_address","id":1}'
```

```json
{
  "jsonrpc": "2.0",
  "result": {
    "address": "27e1c883f3f1bdb124e5430dacc92e1e8ca25a73e50052cadba78e065ce09eaf",
    "pubkey":  "658f0a295fefbaa4f94a020e45aa82938ec34946a05733906ef2fc5300b2ba5f"
  },
  "id": 1
}
```

**Errors**

| Code | When |
|---|---|
| `-32011` | Address already exists (cosmic collision; effectively impossible). |

---

## `list_addresses`

Enumerate every managed address. Sorted ascending.

| | |
|---|---|
| **Scope** | read |
| **Params** | `{}` *or* `{ with_balance: true }` |
| **Returns** | `{ addresses: hex64[] }` (default) *or* the same shape as [`list_balances`](#list_balances) (when `with_balance: true`) |

**Example**

```bash
curl -s $URL -H "Authorization: Bearer $TOKEN" \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","method":"list_addresses","id":1}'
```

```json
{
  "jsonrpc": "2.0",
  "result": {
    "addresses": [
      "1ecce7b8e4c6ac566332cd53a0c02387bb3e5273c5bcf2d77353f7a05615c2bd",
      "27e1c883f3f1bdb124e5430dacc92e1e8ca25a73e50052cadba78e065ce09eaf"
    ]
  },
  "id": 1
}
```

With `{ with_balance: true }` the call forwards to `list_balances`
(below) and returns the richer envelope. The legacy default array
shape is preserved for backward compatibility.

---

## `refresh_address`

Force a synchronous cache refresh for one address. Bypasses TTL —
always hits upstream, then CAS-writes L2 + L3. The right primitive
for "user just clicked check deposit" / "we know address X just had
activity, update now."

As of v0.14.0 the `balanced` profile defaults to **manual refresh
mode** (`refresh_interval = 0`); the background refresher does not
auto-poll. Applications drive the cadence via this method (and its
batch sibling [`refresh_addresses`](#refresh_addresses)).

| | |
|---|---|
| **Scope** | read |
| **Params** | `{ address: hex64 }` |
| **Returns** | `{ address: Row }` — same row shape as `list_balances` |

On per-call upstream failure (rate limit, transport error, etc.) the
call still returns `200` — the failure is surfaced in the row's
`last_error` field; any prior cached value is preserved. Same
contract as the background refresher.

**Example**

```bash
curl -s $URL -H "Authorization: Bearer $TOKEN" \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","method":"refresh_address","params":{"address":"<addr>"},"id":1}'
```

---

## `refresh_addresses`

Batch forced refresh. Concurrency-bounded server-side
(`params.concurrency`, default 8). Returns the same envelope as
`list_balances`.

| | |
|---|---|
| **Scope** | read |
| **Params** | `{ addresses: hex64[] }` |
| **Returns** | Same as [`list_balances`](#list_balances) |

Use when the application knows an event affected a specific *set* of
addresses (sweep batch, deposit-watcher pass over an active subset).
Don't use this to poll-everything every N seconds — that's what
`--cache-refresh-secs N` is for, and the [operations docs](./operations.md)
explain when auto-polling is actually safe (only on dedicated nodes
or with very small N — the 4N math is unavoidable on shared
rate-limited RPCs).

Per-address failures are isolated — one rate-limited row doesn't
poison the whole batch; each row carries its own `last_error`.

---

## `list_balances`

Per-address balance + UTXO-count snapshot for every managed address,
sourced from the in-memory cache (no upstream RPC traffic per call).
The background refresher keeps the cache warm; on a 30s `balanced`
TTL, the typical row is < 30 seconds old.

| | |
|---|---|
| **Scope** | read |
| **Params** | `{}` |
| **Returns** | `{ tip, as_of_ms_ago, addresses: Row[] }` |

Row shape:

```ts
{
  address:            string,      // 64-hex
  balance:            number|null, // null iff the L2 cache has never
                                   // resolved this address (cold +
                                   // refresher hasn't run yet)
  utxo_count:         number|null, // null iff L3 cache cold
  fetched_at_ms_ago:  number|null, // age of the newer of L2/L3 entries
  tip_at_fetch:       number|null, // older of L2/L3 tip anchors
  stale:              boolean,     // true if either layer is past TTL
                                   // (or upstream is degraded)
  last_error:         string|null  // most recent per-address error
}
```

`stale: true` is **a hint, not an error**. The value should be treated
as a lower bound — the address had at least this balance the last
time we successfully heard from upstream. Callers that need strict
freshness should call `get_balance` per-address instead (synchronous
cache-aside fetch).

**Example**

```bash
curl -s $URL -H "Authorization: Bearer $TOKEN" \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","method":"list_balances","id":1}'
```

```json
{
  "jsonrpc": "2.0",
  "result": {
    "tip": { "height": 589354, "block_id": "f9c8a440..." },
    "as_of_ms_ago": 1834,
    "addresses": [
      {
        "address": "1ecce7b8e4c6ac566332cd53a0c02387bb3e5273c5bcf2d77353f7a05615c2bd",
        "balance": 1500000,
        "utxo_count": 3,
        "fetched_at_ms_ago": 1834,
        "tip_at_fetch": 589353,
        "stale": false,
        "last_error": null
      },
      {
        "address": "27e1c883f3f1bdb124e5430dacc92e1e8ca25a73e50052cadba78e065ce09eaf",
        "balance": null,
        "utxo_count": null,
        "fetched_at_ms_ago": null,
        "tip_at_fetch": null,
        "stale": true,
        "last_error": null
      }
    ]
  },
  "id": 1
}
```

The dashboard pattern that motivated this method — "give me all my
deposit addresses with their current balance" — used to cost
`N+1` RPCs (1 × `list_addresses` + N × `get_balance`). With
`list_balances` and the `balanced` cache profile, it costs **one** RPC
per call regardless of N.

`list_balances` requires `--cache-profile ≠ off`. With caching
disabled, the call still works but every row reports `stale: true`
with `balance: null` (the cache layer is still in-place, just never
populated).

---

## `get_balance`

Confirmed balance for an address. Passes through to the upstream node.

| | |
|---|---|
| **Scope** | read |

**Params**

| Field     | Type   | Required | Description                          |
| --------- | ------ | -------- | ------------------------------------ |
| `address` | hex64  | yes      | 64-character hex address (32 bytes). |

**Returns** `{ address: hex64, balance: u64 }`

**Example**

```bash
curl -s $URL -H "Authorization: Bearer $TOKEN" \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","method":"get_balance","params":{"address":"<addr>"},"id":1}'
```

```json
{
  "jsonrpc": "2.0",
  "result": {"address":"...","balance": 99900000},
  "id": 1
}
```

`balance` is the sum of confirmed UTXOs. Mempool UTXOs are not
counted — see [`get_address_utxos`](#get_address_utxos) for the
mempool-aware view.

---

## `get_address_utxos`

List confirmed UTXOs locked to an address.

| | |
|---|---|
| **Scope** | read |

**Params**

| Field     | Type   | Required | Description                  |
| --------- | ------ | -------- | ---------------------------- |
| `address` | hex64  | yes      | 64-character hex address.    |

**Returns**

```ts
{
  address:     hex64 | null,
  script_hex:  hex   | null,
  tip_height:  u64,
  truncated:   bool,
  utxos: [
    {
      tx_id:        hex64,
      output_index: u32,
      value:        u64,
      height:       u64,
      is_coinbase:  bool,
      script_len:   u32 | null,
    },
    ...
  ]
}
```

If `truncated` is `true`, the upstream node hit a result limit. Use
filters on your side to paginate.

**Example**

```bash
curl -s $URL -H "Authorization: Bearer $TOKEN" \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","method":"get_address_utxos","params":{"address":"<addr>"},"id":1}'
```

```json
{
  "jsonrpc": "2.0",
  "result": {
    "address":    "27e1c8...",
    "script_hex": null,
    "tip_height": 577429,
    "truncated":  false,
    "utxos": [
      {
        "tx_id":        "a02ab025d75a295540d681f89da3f8bfed894e02cea721085facbf9ad4525c68",
        "output_index": 1,
        "value":        69900000,
        "height":       577429,
        "is_coinbase":  false,
        "script_len":   null
      }
    ]
  },
  "id": 1
}
```

---

## `get_script_utxos`

Like `get_address_utxos`, but matches by raw script bytes rather than
an address. Useful for non-trivial locking scripts.

| | |
|---|---|
| **Scope** | read |

**Params**

| Field        | Type | Required | Description                                 |
| ------------ | ---- | -------- | ------------------------------------------- |
| `script_hex` | hex  | yes      | Hex-encoded locking script (any length).    |

**Returns** Same shape as [`get_address_utxos`](#get_address_utxos).

---

## `get_block_height`

Current chain tip.

| | |
|---|---|
| **Scope** | read |
| **Params** | `{}` |
| **Returns** | `{ height: u64, block_id: hex64 }` |

**Example**

```bash
curl -s $URL -H "Authorization: Bearer $TOKEN" \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","method":"get_block_height","id":1}'
```

```json
{
  "jsonrpc": "2.0",
  "result": {"height": 577429, "block_id": "17b95f159c3e51440207cc6648f655201bac84fd0e1e5a9ad8461e2d7a2932d5"},
  "id": 1
}
```

---

## `get_block`

Fetch a block by height **or** by hash. Exactly one of the two must
be set.

| | |
|---|---|
| **Scope** | read |

**Params (one of)**

| Field    | Type   | Description                  |
| -------- | ------ | ---------------------------- |
| `height` | u64    | Block height (genesis = 0).  |
| `hash`   | hex64  | 64-character hex block hash. |

Prefer the `hash` form when you already have it; the `height` form is
identical in cost — one upstream RPC either way. Don't chain
`get_block_hash` → `get_block(hash)` when you only have a height; that
costs two round trips for no benefit (see
[`get_block_hash`](#get_block_hash) below).

**Returns**

```ts
{
  hash:              hex64,
  height:            u64,
  prev_block_id:     hex64,
  state_root:        hex64,
  tx_root:           hex64,
  timestamp:         u64,
  nonce:             u64,
  difficulty_target: hex64,
  tx_count:          u32,
  transactions:      hex64[],
}
```

**Example (by height)**

```bash
curl -s $URL -H "Authorization: Bearer $TOKEN" \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","method":"get_block","params":{"height":577000},"id":1}'
```

**Example (by hash)**

```bash
curl -s $URL -H "Authorization: Bearer $TOKEN" \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","method":"get_block","params":{"hash":"17b95f..."},"id":1}'
```

---

## `get_block_hash`

Resolve a block `height` to its `block_id`. Bitcoin-style explicit
lookup — returns the same `{height, block_id}` shape as
[`get_block_height`](#get_block_height) so clients can treat both
uniformly.

| | |
|---|---|
| **Scope** | read |

**Params**

| Field    | Type | Required | Description                  |
| -------- | ---- | -------- | ---------------------------- |
| `height` | u64  | yes      | Block height (genesis = 0).  |

**Returns** `{ height: u64, block_id: hex64 }`

**Example**

```bash
curl -s $URL -H "Authorization: Bearer $TOKEN" \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","method":"get_block_hash","params":{"height":577000},"id":1}'
```

```json
{
  "jsonrpc": "2.0",
  "result": {"height": 577000, "block_id": "17b95f159c3e51440207cc6648f655201bac84fd0e1e5a9ad8461e2d7a2932d5"},
  "id": 1
}
```

**Performance** — the upstream Exfer node has no height→hash index;
this call fetches the full block and discards everything but the
hash. Cost is identical to `get_block(height=…)`. If your next step
is to read the block body, use `get_block(height=…)` directly — one
round trip instead of two.

---

## `get_transaction`

Fetch a single transaction by its `tx_id`. Returns confirmed-chain
or mempool entries; `in_mempool` distinguishes.

| | |
|---|---|
| **Scope** | read |

**Params**

| Field  | Type   | Required | Description                       |
| ------ | ------ | -------- | --------------------------------- |
| `hash` | hex64  | yes      | The transaction's `tx_id`.        |

**Returns**

```ts
{
  tx_id:        hex64,
  tx_hex:       hex,          // serialised transaction bytes
  in_mempool:   bool,         // true = unconfirmed, false = on chain
  block_hash:   hex64 | null, // null if in_mempool
  block_height: u64   | null, // null if in_mempool

  // Decoded view — added so callers don't have to parse tx_hex.
  //
  // Outputs and witnesses decode inline from tx_hex (zero upstream
  // calls). Phase-1 P2PKH `inputs[].address` is derived from
  // `witness.pubkey` for the same reason — no parent fetch required.
  // Values are still pulled from parent transactions in parallel
  // (cap 8); per-parent failures degrade gracefully — `value` and
  // `fee` / `total_in` go missing for that input, but `address` and
  // `witness` survive because they come from tx_hex alone.
  inputs: [
    {
      prev_tx_id:    hex64,
      output_index:  u32,
      address?:      hex64,   // present for standard P2PKH inputs
      script_hex?:   hex,     // present for non-P2PKH inputs (parent script)
      value?:        u64,     // exfers
      witness?: {
        pubkey?:       hex64, // Phase-1: first 32 bytes of witness blob
        signature?:    hex128,// Phase-1: last 64 bytes
        witness_hex?:  hex,   // non-Phase-1 fallback (coinbase, future types)
        redeemer_hex?: hex,   // Phase-1: always absent
      },
    },
    ...
  ],
  outputs: [
    {
      address?:    hex64,     // present for standard P2PKH outputs
      script_hex?: hex,       // present for non-P2PKH outputs
      value:       u64,       // exfers
    },
    ...
  ],
  total_out:  u64,            // sum of outputs[].value — always present
  total_in?:  u64,            // omitted if any input failed to resolve
  fee?:       u64,            // total_in - total_out; omitted with total_in
  size:       u64,            // serialized byte length == tx_hex.len() / 2
}
```

**Example**

```bash
curl -s $URL -H "Authorization: Bearer $TOKEN" \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","method":"get_transaction","params":{"hash":"a02ab0..."},"id":1}'
```

```json
{
  "jsonrpc": "2.0",
  "result": {
    "tx_id":        "a02ab025d75a295540d681f89da3f8bfed894e02cea721085facbf9ad4525c68",
    "tx_hex":       "01000200fcbe0c52689b...",
    "in_mempool":   false,
    "block_hash":   "1bac70390bb6d4039e82d9b881a73a69a7c569c51961163e2d0fc09a36e9b67c",
    "block_height": 577429,
    "inputs": [
      {
        "prev_tx_id":   "fcbe0c52689b9d4b8e7c0411e2b1cf76d0bf2bbf25ad8cb2c3b62905ee2c1f00",
        "output_index": 1,
        "address":      "658f0a295fefbaa4f94a020e45aa82938ec34946a05733906ef2fc5300b2ba5f",
        "value":        100000000,
        "witness": {
          "pubkey":    "e1020a2d703030dd093dcb0fba90dd0b67460b2170ff0e29e69c9fcc541adc45",
          "signature": "8f4ad5…64-byte-sig-as-128-hex…"
        }
      }
    ],
    "outputs": [
      { "address": "27e1c883f3f1bdb124e5430dacc92e1e8ca25a73e50052cadba78e065ce09eaf", "value": 30000000 },
      { "address": "658f0a295fefbaa4f94a020e45aa82938ec34946a05733906ef2fc5300b2ba5f", "value": 69900000 }
    ],
    "total_in":  100000000,
    "total_out":  99900000,
    "fee":           100000,
    "size":             362
  },
  "id": 1
}
```

For typical 1-input deposit/withdraw transactions this adds a single
parallel upstream `get_transaction` call; latency is ≈ `2 × RTT` to the
upstream node (see [Picking a node](./picking-a-node.md) for the latency
math).

---

## `transfer`

**The headline method.** Build, sign, and broadcast a payment from
one of walletd's managed wallets to any address.

| | |
|---|---|
| **Scope** | spend |

**Params**

| Field    | Type   | Required | Description                                                          |
| -------- | ------ | -------- | -------------------------------------------------------------------- |
| `from`   | hex64  | yes      | Sender address. Must be a wallet walletd holds the key for.          |
| `to`     | hex64  | yes      | Recipient address.                                                   |
| `amount` | u64    | yes      | Amount in **exfers** (`1 EXFER = 100_000_000 exfers`).               |
| `fee`    | u64    | no       | Fee in exfers. Default `100_000` (= 0.001 EXFER).                    |

**Returns**

```ts
{
  tx_id:      hex64,   // the computed + broadcast tx_id
  size:       usize,   // byte size of the signed tx
  tip_height: u64,     // chain tip at the moment of submission
  submitted:  bool,    // always true on success; the error path returns an error envelope
}
```

**How it works internally**

1. `get_address_utxos(from)` on the upstream node.
2. Sort UTXOs largest-first, pick greedily until value ≥ amount+fee.
3. For each *selected* UTXO, fetch the parent tx (`get_transaction`)
   in parallel and authenticate the output (strict deserialise + tx_id
   match + script equality). Cap is 8 concurrent fetches.
4. `Wallet::build_transaction` produces the signed tx locally.
5. `send_raw_transaction` broadcasts.
6. Verify the upstream's reported `tx_id` matches our computed one.

The greedy selector means a wallet with thousands of UTXOs but only
one large enough to cover the transfer uses **one** input. UTXOs
already reserved by other in-flight transfers from this daemon are
skipped (see [Errors → `-32031`](./errors.md#-32031-insufficient-balance)).

**Example**

```bash
curl -s $URL -H "Authorization: Bearer $TOKEN" \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","method":"transfer","params":{
            "from":   "<your-managed-address>",
            "to":     "<recipient-address>",
            "amount": 30000000,
            "fee":    100000
         },"id":1}'
```

```json
{
  "jsonrpc": "2.0",
  "result": {
    "tx_id":      "a02ab025d75a295540d681f89da3f8bfed894e02cea721085facbf9ad4525c68",
    "size":       227,
    "tip_height": 577427,
    "submitted":  true
  },
  "id": 1
}
```

**Common errors**

| Code     | When |
|----------|------|
| `-32001` | Token missing / wrong / read-scope hitting spend method. |
| `-32602` | `from` / `to` not 64-hex, or `amount` missing. |
| `-32010` | Wallet not found — walletd doesn't hold the key for `from`. |
| `-32020` | Upstream node unreachable or returned an RPC error (e.g. mempool rejected the tx). |
| `-32030` | UTXO authentication failed — the upstream returned tx data that didn't match the outpoint. |
| `-32031` | Insufficient balance (with hint about in-flight UTXOs if any). |
| `-32603` | Internal error. |

---

## `send_raw_transaction`

Broadcast a pre-signed transaction. Passes through to the upstream.
Used by `transfer` internally; expose it for callers that build txes
externally.

| | |
|---|---|
| **Scope** | spend |

**Params**

| Field    | Type | Required | Description                                |
| -------- | ---- | -------- | ------------------------------------------ |
| `tx_hex` | hex  | yes      | Serialised signed transaction bytes (hex). |

**Returns** `{ tx_id: hex64 }`

**Example**

```bash
curl -s $URL -H "Authorization: Bearer $TOKEN" \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","method":"send_raw_transaction","params":{"tx_hex":"01000200..."},"id":1}'
```

```json
{"jsonrpc":"2.0","result":{"tx_id":"a02ab0..."},"id":1}
```

If the upstream rejects (already-confirmed, malformed, double-spend),
the error is surfaced as `-32020` with the upstream's message intact.

---

## `sign_message`

Sign an arbitrary UTF-8 message with the Ed25519 key of a managed
wallet. Proof-of-ownership for exchange KYC, cold-wallet
challenge-response, off-chain auth — same role as Bitcoin's
`signmessage`. Pure in-process crypto — no upstream calls.

| | |
|---|---|
| **Scope** | spend |

Although signing doesn't move funds, the artifact is a verifiable
proof of ownership of a wallet key. A leaked read-only token must not
be able to mint such proofs, so this is gated behind the spend scope.

**Params**

| Field     | Type   | Required | Description                                              |
| --------- | ------ | -------- | -------------------------------------------------------- |
| `address` | hex64  | yes      | Address of a wallet walletd holds the key for.           |
| `message` | string | yes      | UTF-8 message to sign. Bytes signed = `"EXFER-MSG" ‖ message.as_bytes()`. |

The fixed `EXFER-MSG` domain separator prevents a message signature
from ever being mistaken for a transaction signature (transactions
sign under `EXFER-SIG`).

**Returns** `{ signature: hex128, pubkey: hex64, address: hex64 }`

**Example**

```bash
curl -s $URL -H "Authorization: Bearer $TOKEN" \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","method":"sign_message","params":{
            "address": "<your-managed-address>",
            "message": "kyc-nonce-1234abcd"
         },"id":1}'
```

```json
{
  "jsonrpc": "2.0",
  "result": {
    "signature": "8f4ad5…64-byte-sig-as-128-hex…",
    "pubkey":    "658f0a295fefbaa4f94a020e45aa82938ec34946a05733906ef2fc5300b2ba5f",
    "address":   "27e1c883f3f1bdb124e5430dacc92e1e8ca25a73e50052cadba78e065ce09eaf"
  },
  "id": 1
}
```

**Errors**

| Code     | When |
|----------|------|
| `-32001` | Read-scope token hitting a spend method. |
| `-32010` | Wallet not found — walletd doesn't hold the key for `address`. |
| `-32602` | `address` not 64-hex. |

---

## `verify_message`

Verify an Ed25519 message signature. Pure crypto, no wallet access
required — anyone with a `read` token (or no scope split at all) can
call it. The signer doesn't have to be a wallet walletd manages.

| | |
|---|---|
| **Scope** | read |

**Params**

| Field       | Type   | Required | Description                                                                |
| ----------- | ------ | -------- | -------------------------------------------------------------------------- |
| `pubkey`    | hex64  | yes      | Signer's 32-byte Ed25519 public key (as returned by `sign_message`).       |
| `signature` | hex128 | yes      | 64-byte signature.                                                         |
| `message`   | string | yes      | Same UTF-8 message that was signed.                                        |
| `address`   | hex64  | no       | If present, walletd also checks that `H(DS_ADDR ‖ pubkey) == address`. |

**Returns**

```ts
{
  valid:   bool,    // signature verifies AND (if address provided) hash matches
  address: hex64,   // computed `H(DS_ADDR ‖ pubkey)` — always returned
}
```

`address` is always returned (even when `valid` is `false`) so a
caller can see what the pubkey actually hashes to without recomputing
locally.

**Example**

```bash
curl -s $URL -H "Authorization: Bearer $TOKEN" \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","method":"verify_message","params":{
            "pubkey":    "658f0a…",
            "signature": "8f4ad5…",
            "message":   "kyc-nonce-1234abcd",
            "address":   "27e1c8…"
         },"id":1}'
```

```json
{
  "jsonrpc": "2.0",
  "result": { "valid": true, "address": "27e1c8…" },
  "id": 1
}
```

**Errors**

| Code     | When |
|----------|------|
| `-32602` | `pubkey` or `address` not 64-hex; `signature` not 128-hex / 64 bytes. |

A bad signature is **not** an error — it's `{ "valid": false }`.

---

## `GET /healthz`

Liveness probe. Returns `200 OK` with body `ok\n`. **Not** behind
auth — meant for container orchestrators.

```bash
curl -s $URL/healthz
# ok
```

---

## Python client

A minimal helper:

```python
import requests

URL   = "http://127.0.0.1:7448"
TOKEN = "..."  # WALLETD_AUTH_TOKEN

def rpc(method, params=None, id=1):
    r = requests.post(
        URL,
        json={"jsonrpc":"2.0","method":method,"params":params or {}, "id":id},
        headers={"Authorization": f"Bearer {TOKEN}"},
        timeout=30,
    )
    r.raise_for_status()
    body = r.json()
    if body.get("error"):
        raise RuntimeError(body["error"])
    return body["result"]

# Per-user deposit address
addr = rpc("generate_address")["address"]

# Watch for funds
bal = rpc("get_balance", {"address": addr})

# Sweep to a hot wallet
if bal["balance"] > 200_000:
    r = rpc("transfer", {
        "from":   addr,
        "to":     "<hot-wallet>",
        "amount": bal["balance"] - 100_000,
        "fee":    100_000,
    })
    print("tx submitted:", r["tx_id"])
```

## Node.js client

```javascript
const URL   = "http://127.0.0.1:7448";
const TOKEN = process.env.WALLETD_AUTH_TOKEN;

async function rpc(method, params = {}) {
  const r = await fetch(URL, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${TOKEN}`,
    },
    body: JSON.stringify({ jsonrpc: "2.0", method, params, id: 1 }),
  });
  const body = await r.json();
  if (body.error) throw new Error(JSON.stringify(body.error));
  return body.result;
}

const { address } = await rpc("generate_address");
console.log("address:", address);
```

## Next

- [Error codes →](./errors.md)
- [Operations →](./operations.md)
