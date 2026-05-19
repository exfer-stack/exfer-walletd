# Error codes

JSON-RPC convention: errors usually return HTTP 200 with the error in
the body. Walletd emits non-200 only for transport-layer problems
(401, 400 for malformed JSON).

| Code     | HTTP | Name                | Meaning                                                                  |
| -------- | ---- | ------------------- | ------------------------------------------------------------------------ |
| `-32700` | 400  | Parse error         | Malformed JSON / missing fields.                                         |
| `-32600` | 200  | Invalid Request     | (Reserved; walletd doesn't currently emit this.)                         |
| `-32601` | 200  | Method not found    | Unknown method name.                                                     |
| `-32602` | 200  | Invalid params      | Bad hex, wrong address length, missing required field, …                 |
| `-32603` | 200  | Internal error      | Unexpected; the message has details.                                     |
| `-32001` | 401  | Unauthorized        | Missing token, wrong token, or insufficient scope.                       |
| `-32010` | 200  | Wallet not found    | `from` address is not one walletd holds the key for.                     |
| `-32011` | 200  | Wallet exists       | Address collision on `generate_address` (cosmically rare).               |
| `-32020` | 200  | Upstream            | Upstream node unreachable, or returned an RPC error; message intact.     |
| `-32030` | 200  | Tx build / auth     | UTXO authentication failed, or transaction construction failed.          |
| `-32031` | 200  | Insufficient balance| Walletd can't cover `amount + fee` from spendable UTXOs.                 |

## `-32031` insufficient balance

The most common spend-path error. Walletd's error body looks like:

```json
{
  "code": -32031,
  "message": "insufficient balance: need 5100000 exfers (amount + fee), wallet has 4000000 spendable across 1 UTXO(s)"
}
```

If some UTXOs were filtered out by the
[in-flight tracker](./security-model.md#in-flight-utxo-tracker)
(another transfer from this wallet hasn't confirmed yet), the message
will say so:

```text
insufficient balance: need 1100000 exfers (amount + fee), wallet has
0 spendable across 0 UTXO(s) (1 more UTXO(s) worth 64800000 exfers
reserved by pending transfers from this daemon; retry once they
confirm or use a different sending wallet)
```

For an integrator: branch on `code == -32031`, retry after a few
seconds if the message mentions "reserved by pending transfers." If
not, the wallet is genuinely under-funded.

## `-32020` upstream errors

Walletd preserves the upstream node's error code and message in the
text of `-32020`. Examples seen in practice:

- `upstream node returned error code -32602: Mempool pre-check failed: double-spend of OutPoint {...}` — another transfer of yours is already spending the same UTXO. The [in-flight tracker](./security-model.md#in-flight-utxo-tracker) protects against this in normal use, but it can still surface across walletd restarts.
- `upstream node returned error code -32004: tx not found` — querying a tx_id that's neither on chain nor in mempool.
- `upstream node unreachable: ...: error sending request` — transient transport failure. Walletd already retried up to `--upstream-attempts` times (default `4`) with linear backoff (`--upstream-retry-backoff-ms`, default `500ms` → waits of 500/1000/1500ms between sweeps); each attempt rotates through every configured `--node-rpc` URL before counting as failed. The message reports the last URL it tried.

## `-32001` unauthorized

Four cases produce this:

1. No `Authorization: Bearer` header.
2. The header is set but the token doesn't match.
3. Two-token mode, the request used the read token, but the method
   needs spend scope.
4. The token compares against `subtle::ConstantTimeEq` — even a
   single-character difference returns 401 in identical time.

The body message is the same across all four (`authentication required`)
to avoid leaking which case it was.

## Mapping table for clients

| If you see…             | Action                                       |
| ----------------------- | -------------------------------------------- |
| `-32001`                | Check token + scope. Don't retry blindly.    |
| `-32020` "unreachable"  | Wait a moment, retry. Consider multi-URL.    |
| `-32020` "double-spend" | Retry after confirmation or use new wallet.  |
| `-32031` (with in-flight hint) | Wait for the pending tx to confirm. |
| `-32031` (no hint)      | Fund the wallet.                             |
| `-32602`                | Programming error — check param formatting.  |

## Next

- [Operations →](./operations.md)
- [Security model →](./security-model.md)
