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

The shell variable conventions in the examples:

```bash
URL='http://127.0.0.1:8080'
TOKEN='your-token-here'
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
| **Params** | `{}` |
| **Returns** | `{ addresses: hex64[] }` |

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
  tx_hex:       hex,         // serialised transaction bytes
  in_mempool:   bool,        // true = unconfirmed, false = on chain
  block_hash:   hex64 | null, // null if in_mempool
  block_height: u64   | null, // null if in_mempool
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
    "block_height": 577429
  },
  "id": 1
}
```

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

URL   = "http://127.0.0.1:8080"
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
const URL   = "http://127.0.0.1:8080";
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
- [Production deploy →](./production-deploy.md)
