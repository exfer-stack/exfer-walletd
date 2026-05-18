# exfer-walletd

**Exfer Wallet Daemon** — an independent HTTP service that manages
wallet keypairs and exposes higher-level RPC methods (`generate_address`,
`transfer`, `balance`, …) on top of one or more Exfer nodes.

The Exfer node's own JSON-RPC interface is intentionally read-only +
broadcast: it cannot sign on your behalf because nodes never hold keys.
`exfer-walletd` closes that gap by holding a pool of wallet keypairs,
building and signing transactions locally using the same crypto
primitives as the upstream `exfer` binary (via the `exfer` crate), and
broadcasting through the node(s).

```
   ┌─ exchange / app backend ─┐
   │                          │
   │  JSON-RPC over HTTP      │     ─────► generate_address / transfer
   │  (Bearer auth)           │     ─────► get_balance / list_addresses
   │                          │            (plus every node passthrough)
   └─────────────────────────▶│
                              │
                       exfer-walletd
                              │
                              │  one or more node URLs
                              │  (loopback, LAN, internet, fly internal)
                              ▼
                     ┌─── exfer node(s) ───┐
```

**Keys never leave the host running the daemon. The upstream node(s)
never see a private key.**

## Why this exists

The Exfer node was deliberately built without a wallet RPC: it doesn't
know what addresses are yours, doesn't hold keys, and won't sign for
you. That's a good security default, but it shifts wallet logic to the
client. Every exchange / wallet / payment processor ended up
reimplementing the same flow (list UTXOs → build tx → Ed25519-sign →
broadcast). `exfer-walletd` is the canonical implementation of that
flow, exposed as an RPC service that's drop-in usable from any backend
language.

## Decoupled from the node

The daemon makes **no assumptions about where the node lives**:

| Deployment | `--node-rpc` value |
|---|---|
| Daemon and node on the same host (most common) | `http://127.0.0.1:9334` |
| Daemon on app server, node on a separate host  | `http://node.your-vpc.internal:9334` |
| Daemon talking to a managed / community RPC    | `http://82.221.100.201:9334` |
| HA with multiple nodes (round-robin + failover)| `http://a:9334,http://b:9334,http://c:9334` |

A comma-separated list rotates per call and fails over to the next node
on transport errors. Application-level errors (`Block not found`, etc.)
are surfaced immediately — only transport / 5xx triggers the next node.

## API

JSON-RPC 2.0 over `POST /`. Optional Bearer token in `Authorization`
(set `WALLETD_AUTH_TOKEN` to require it).

| Method | Params | Returns | Notes |
|---|---|---|---|
| `generate_address` | `{}` | `{address, pubkey}` | **Daemon-only.** Creates and persists a new wallet. |
| `list_addresses` | `{}` | `{addresses: [...]}` | **Daemon-only.** Enumerates managed addresses. |
| `transfer` | `{from, to, amount, fee?}` | `{tx_id, size, tip_height, submitted}` | **Daemon-only.** Loads `<from>`'s wallet, fetches and authenticates UTXOs from upstream (v1.4.2 anti-malicious-RPC flow), builds + Ed25519-signs locally, broadcasts. |
| `get_block_height` | `{}` | `{height, block_id}` | Passthrough to node. |
| `get_block` | `{height}` or `{hash}` | block | Passthrough. |
| `get_transaction` | `{hash}` | tx | Passthrough. |
| `get_balance` | `{address}` | `{address, balance}` | Passthrough. |
| `get_address_utxos` | `{address}` | UTXO list | Passthrough. |
| `get_script_utxos` | `{script_hex}` | UTXO list | Passthrough. |
| `send_raw_transaction` | `{tx_hex}` | `{tx_id}` | Passthrough. |
| `ping` | `{}` | `{ok: true}` | Liveness. |

`GET /healthz` returns `200 OK` for container probes.

### Amounts and fees

`amount` and `fee` are integers in **exfers** (base units).
`1 EXFER = 100_000_000 exfers`. Default fee is `100_000`
(`0.001 EXFER`) if omitted. The daemon does not interpret human
"EXFER" notation; convert on the client.

### Error codes

Standard JSON-RPC plus daemon-specific:

| Code | Meaning |
|---|---|
| `-32601` | Unknown method |
| `-32602` | Invalid params (bad hex, wrong address length, etc.) |
| `-32700` | Malformed request envelope |
| `-32001` | Unauthorized (auth token mismatch) |
| `-32010` | Wallet not found for `from` address |
| `-32011` | Wallet already exists at that address |
| `-32020` | Upstream node unreachable or returned RPC error |
| `-32030` | Transaction build / UTXO authentication failure |
| `-32603` | Internal error |

## Configuration

| Flag | Env var | Default | Purpose |
|---|---|---|---|
| `--bind` | `WALLETD_BIND` | `0.0.0.0:8080` | HTTP listen address |
| `--node-rpc` | `EXFER_NODE_RPC` | `http://127.0.0.1:9334` | One or more node JSON-RPC URLs (comma-separated for HA) |
| `--wallet-dir` | `WALLETD_WALLET_DIR` | `/var/lib/exfer-wallets` | Directory holding `<address>.key` files |
| `--auth-token` | `WALLETD_AUTH_TOKEN` | unset | Bearer token. If unset, API is open — only on trusted networks. |
| `--upstream-timeout-secs` | `WALLETD_UPSTREAM_TIMEOUT_SECS` | `30` | Per-request timeout when talking to a node |

## Build

```bash
git clone https://github.com/ahuman-exfer/exfer.git
git clone https://github.com/exfer-stack/exfer-walletd.git
cd exfer-walletd
cargo build --release
```

Output: `target/release/exfer-walletd` (~3.6 MB static binary).

## Run

### Single-server, colocated with a node

```bash
exfer node --datadir /var/lib/exfer --rpc-bind 127.0.0.1:9334 --repair-perms &

WALLETD_AUTH_TOKEN="$(openssl rand -hex 32)" \
exfer-walletd \
    --bind        0.0.0.0:8080 \
    --node-rpc    http://127.0.0.1:9334 \
    --wallet-dir  /var/lib/exfer-wallets
```

### Daemon on app box, node elsewhere

```bash
exfer-walletd \
    --bind        0.0.0.0:8080 \
    --node-rpc    http://exfer-node.internal:9334 \
    --wallet-dir  /var/lib/exfer-wallets \
    --auth-token  $(cat /etc/exfer-walletd/token)
```

### High availability: multi-node round-robin

```bash
exfer-walletd \
    --node-rpc 'http://node-a:9334,http://node-b:9334,http://node-c:9334'
```

Calls rotate across nodes and fail over on transport errors. The daemon
itself stays single-instance per wallet directory (wallet files are not
yet replicated across instances — keep them on a single source-of-truth
filesystem).

## Example client (Python)

```python
import requests

WALLETD = "https://walletd.your-host:8080"
TOKEN   = "the bearer token you set"

def rpc(method, params=None, id=1):
    r = requests.post(
        WALLETD,
        json={"jsonrpc": "2.0", "method": method, "params": params or {}, "id": id},
        headers={"Authorization": f"Bearer {TOKEN}"},
        timeout=30,
    )
    r.raise_for_status()
    body = r.json()
    if body.get("error"):
        raise RuntimeError(body["error"])
    return body["result"]

# 1. Generate a deposit address for a new user
deposit = rpc("generate_address")
print("deposit address:", deposit["address"])

# 2. Watch for incoming funds
bal = rpc("get_balance", {"address": deposit["address"]})
print("balance:", bal["balance"], "exfers")

# 3. Sweep deposit to your hot wallet
hot = rpc("generate_address")["address"]   # do this once, persist it
receipt = rpc("transfer", {
    "from":   deposit["address"],
    "to":     hot,
    "amount": bal["balance"] - 100_000,
    "fee":    100_000,
})
print("submitted tx", receipt["tx_id"])
```

## Security

- **Run as a dedicated unprivileged user.** The wallet directory is
  created with mode `0700` and each `.key` file with `0600`.
- **Encrypt the wallet disk at rest.** The daemon stores keys
  unencrypted (a server has no human to type a passphrase). LUKS /
  dm-crypt / fly volume encryption are the right primitives; filesystem
  permissions are the *first* line of defense, not the only one.
- **Set `WALLETD_AUTH_TOKEN`** unless the daemon is bound to a strictly
  private interface (`127.0.0.1`, a VPN, a fly-internal port). Without
  a token, anyone who can reach the HTTP port can generate addresses
  and spend any managed wallet.
- **Keep the daemon's HTTP behind TLS** when exposed beyond loopback.
  The fly.io reference deployment terminates TLS at the edge.

## Extending the storage layer

The wallet store is abstracted behind the `WalletStore` trait. The
shipped backend is `FsWalletStore` (one file per address). To plug in
something else (`redb`, cloud KMS, hardware HSM, MPC backend),
implement `WalletStore` for the new type and wire it into `server::run`.
The HTTP / API layers are agnostic.

## Tests

```bash
cargo test            # 18 unit + integration tests
./tests/e2e_live.sh   # end-to-end against a running daemon
```

Unit tests cover the wallet store. Integration tests use `wiremock` to
simulate upstream Exfer nodes and exercise every dispatch path. HTTP
tests boot the actual axum server on an ephemeral port.

## License

MIT, same as the [upstream Exfer project](https://github.com/ahuman-exfer/exfer).
