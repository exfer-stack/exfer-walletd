[Source](https://github.com/exfer-stack/exfer-walletd) · [Releases](https://github.com/exfer-stack/exfer-walletd/releases)

---

# exfer-walletd

A JSON-RPC HTTP daemon that holds wallet keys and signs Exfer
transactions on behalf of a backend. Same pattern as `cardano-wallet`
for Cardano: a separate signing service, decoupled from the chain
node.

```
your backend ──► exfer-walletd ──► exfer node(s)
                 (holds keys,        (chain data, p2p,
                  signs locally)      broadcast — no keys)
```

The Exfer node's own JSON-RPC is intentionally read-only + broadcast.
It can't sign for you because nodes never hold keys. `exfer-walletd`
closes that gap: it manages a pool of Ed25519 keypairs, builds and
signs transactions locally, and broadcasts the signed bytes through
whatever node(s) you point it at.

---

## Contents

1. [Install](#install)
2. [Quick start (local dev)](#quick-start-local-dev)
3. [Tokens and scopes](#tokens-and-scopes)
4. [RPC reference](#rpc-reference)
5. [Errors](#errors)
6. [Production deploy](#production-deploy) — systemd + Caddy, docker-compose, fly.io
7. [Security model](#security-model) — what's protected, what isn't
8. [Backup, upgrade, key rotation](#operations)

---

## Install

Pre-built binaries for Linux, macOS, Windows are on the [Releases
page](https://github.com/exfer-stack/exfer-walletd/releases).

```bash
curl -L -o exfer-walletd \
    https://github.com/exfer-stack/exfer-walletd/releases/latest/download/exfer-walletd-linux-x86_64
chmod +x exfer-walletd
sudo install -m 0755 exfer-walletd /usr/local/bin/
exfer-walletd --version
```

Or build from source (Rust 1.75+):

```bash
git clone https://github.com/exfer-stack/exfer-walletd
cd exfer-walletd
cargo build --release
# Binary at target/release/exfer-walletd
```

---

## Quick start (local dev)

Run on loopback with no auth — useful for trying it out from your
laptop. The daemon refuses to bind a non-loopback address without a
token, so this mode is safe by construction.

```bash
# Terminal 1 — an Exfer node with RPC enabled
exfer node --datadir ./chain --rpc-bind 127.0.0.1:9334

# Terminal 2 — walletd
mkdir -p ./wallets
exfer-walletd \
    --bind        127.0.0.1:8080 \
    --node-rpc    http://127.0.0.1:9334 \
    --wallet-dir  ./wallets

# Terminal 3 — try it
curl -s http://127.0.0.1:8080/ -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","method":"ping","id":1}'
# → {"jsonrpc":"2.0","result":{"ok":true},"id":1}
```

For anything beyond local dev, set tokens (next section) and put a TLS
terminator in front (see [Production deploy](#production-deploy)).

---

## Tokens and scopes

`exfer-walletd` uses two independent bearer tokens, each gating a
scope:

| Env var                       | Scope  | Methods                                                    |
| ----------------------------- | ------ | ---------------------------------------------------------- |
| `WALLETD_AUTH_TOKEN_READ`     | read   | every method **except** `transfer` / `send_raw_transaction` |
| `WALLETD_AUTH_TOKEN_SPEND`    | spend  | all methods (spend implies read)                            |
| `WALLETD_AUTH_TOKEN`          | all    | single-token mode — grants every method (read + spend)      |

Why two: a deposit-watcher service that polls balances only needs the
read token. A withdrawal worker that moves funds needs spend. Splitting
them limits blast radius if one set of credentials leaks.

Generate them with anything CSPRNG. 32 random bytes hex-encoded is
plenty:

```bash
openssl rand -hex 32   # → 64-char hex string
```

Send them in `Authorization: Bearer <token>`. Comparison is constant-
time (`subtle::ConstantTimeEq`) so a timing oracle can't peel the
token byte by byte.

**Bind safety**: at startup, walletd refuses to bind a non-loopback
address (`0.0.0.0`, a LAN IP, the public IP) unless at least one token
is configured. You can't accidentally publish an open wallet by
forgetting `--auth-token`.

---

## RPC reference

JSON-RPC 2.0 over `POST /`. `GET /healthz` returns plain `ok` and is
unauthenticated, for container probes.

Amounts and fees are integers in **exfers** (`1 EXFER = 100_000_000
exfers`). Default fee if you omit `fee` from a `transfer` call:
`100_000` (`0.001 EXFER`).

### Methods

| Method                 | Scope | Params                       | Returns                                       |
| ---------------------- | ----- | ---------------------------- | --------------------------------------------- |
| `generate_address`     | read  | `{}`                         | `{address, pubkey}`                           |
| `list_addresses`       | read  | `{}`                         | `{addresses: [...]}`                          |
| `get_balance`          | read  | `{address}`                  | `{address, balance}`                          |
| `get_address_utxos`    | read  | `{address}`                  | UTXO list                                     |
| `get_script_utxos`     | read  | `{script_hex}`               | UTXO list                                     |
| `get_block_height`     | read  | `{}`                         | `{height, block_id}`                          |
| `get_block`            | read  | `{height}` or `{hash}`       | block object                                  |
| `get_transaction`      | read  | `{hash}`                     | transaction object                            |
| `ping`                 | read  | `{}`                         | `{ok: true}`                                  |
| `transfer`             | spend | `{from, to, amount, fee?}`   | `{tx_id, size, tip_height, submitted}`        |
| `send_raw_transaction` | spend | `{tx_hex}`                   | `{tx_id}`                                     |

### Examples (curl)

Set these once in your shell:

```bash
URL='https://walletd.example.com'
READ='paste-your-read-token'
SPEND='paste-your-spend-token'
```

**Create a fresh deposit address** (read scope is fine — `generate_address`
doesn't move funds):

```bash
curl -s $URL -H 'content-type: application/json' \
     -H "Authorization: Bearer $READ" \
     -d '{"jsonrpc":"2.0","method":"generate_address","id":1}'
# → {"jsonrpc":"2.0","result":{
#     "address":"35d9cbe8e7ee1200cfc019178b4590ac2a6a78f3d81278a09c21d546afb708bc",
#     "pubkey":"c919106ad80f3fd7c5fe2faa43ed731e2ad6931f03cc2e28e78ba2c4168ce0cb"
#   },"id":1}
```

**Check balance**:

```bash
curl -s $URL -H 'content-type: application/json' \
     -H "Authorization: Bearer $READ" \
     -d '{"jsonrpc":"2.0","method":"get_balance",
          "params":{"address":"35d9...08bc"},"id":2}'
# → {"jsonrpc":"2.0","result":{"address":"35d9...","balance":100000000},"id":2}
```

**Send funds** (spend scope required):

```bash
curl -s $URL -H 'content-type: application/json' \
     -H "Authorization: Bearer $SPEND" \
     -d '{"jsonrpc":"2.0","method":"transfer","params":{
            "from":"35d9...08bc",
            "to":  "8a1f...c042",
            "amount": 99900000,
            "fee":    100000
         },"id":3}'
# → {"jsonrpc":"2.0","result":{
#     "tx_id":"f3...","size":234,"tip_height":1820145,"submitted":true
#   },"id":3}
```

**List every managed address**:

```bash
curl -s $URL -H 'content-type: application/json' \
     -H "Authorization: Bearer $READ" \
     -d '{"jsonrpc":"2.0","method":"list_addresses","id":4}'
```

### Examples (Python)

```python
import requests

URL   = "https://walletd.example.com"
READ  = "..."   # read token
SPEND = "..."   # spend token

def rpc(method, params=None, *, scope="read", id=1):
    token = READ if scope == "read" else SPEND
    r = requests.post(
        URL,
        json={"jsonrpc":"2.0","method":method,"params":params or {}, "id":id},
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    )
    r.raise_for_status()
    body = r.json()
    if body.get("error"):
        raise RuntimeError(body["error"])
    return body["result"]

# Issue per-user deposit addresses
deposit = rpc("generate_address")
print("address:", deposit["address"])

# Sweep once funds land
bal = rpc("get_balance", {"address": deposit["address"]})
if bal["balance"] > 200_000:
    receipt = rpc("transfer", {
        "from":   deposit["address"],
        "to":     "your-hot-wallet",
        "amount": bal["balance"] - 100_000,
        "fee":    100_000,
    }, scope="spend")
    print("tx submitted:", receipt["tx_id"])
```

### Examples (Node.js)

```javascript
const URL = "https://walletd.example.com";

async function rpc(method, params = {}, { scope = "read" } = {}) {
  const token = scope === "spend" ? process.env.SPEND : process.env.READ;
  const r = await fetch(URL, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token}`,
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

---

## Errors

| Code     | HTTP | Meaning                                                        |
| -------- | ---- | -------------------------------------------------------------- |
| `-32700` | 400  | Malformed request envelope (not JSON, missing fields)          |
| `-32601` | 200  | Unknown method                                                 |
| `-32602` | 200  | Invalid params (bad hex, wrong address length, …)              |
| `-32001` | 401  | Unauthorized (missing token, wrong token, insufficient scope)  |
| `-32010` | 200  | Wallet not found for `from` address                            |
| `-32011` | 200  | Wallet already exists at that address                          |
| `-32020` | 200  | Upstream node unreachable or returned RPC error                |
| `-32030` | 200  | Transaction build / UTXO authentication failure                |
| `-32603` | 200  | Internal error                                                 |

Per JSON-RPC convention, errors usually return HTTP 200 with the error
in the body. Transport-level problems (401, malformed JSON → 400)
escape to the HTTP layer so clients can branch on the status code
without reading the body.

---

## Production deploy

Three recipes. Pick the one that matches your environment.

### Recipe A — systemd + Caddy on a single VM (most common)

A single host running both the Exfer node and walletd, with Caddy
terminating TLS and reverse-proxying to walletd on loopback.

Files in [`deploy/systemd/`](https://github.com/exfer-stack/exfer-walletd/tree/main/deploy/systemd)
and [`deploy/caddy/`](https://github.com/exfer-stack/exfer-walletd/tree/main/deploy/caddy)
of the repo.

```bash
# 1. Install the binary
curl -L -o /tmp/exfer-walletd \
     https://github.com/exfer-stack/exfer-walletd/releases/latest/download/exfer-walletd-linux-x86_64
sudo install -m 0755 /tmp/exfer-walletd /usr/local/bin/

# 2. Dedicated user + data dir
sudo useradd --system --home /var/lib/exfer-walletd --shell /usr/sbin/nologin exfer-walletd
sudo install -d -o exfer-walletd -g exfer-walletd -m 0700 /var/lib/exfer-walletd

# 3. Env file (mode 0600; tokens never appear in command line)
sudo install -d -m 0750 /etc/exfer-walletd
sudo tee /etc/exfer-walletd/env >/dev/null <<EOF
WALLETD_BIND=127.0.0.1:8080
WALLETD_WALLET_DIR=/var/lib/exfer-walletd
EXFER_NODE_RPC=http://127.0.0.1:9334
WALLETD_AUTH_TOKEN_READ=$(openssl rand -hex 32)
WALLETD_AUTH_TOKEN_SPEND=$(openssl rand -hex 32)
RUST_LOG=info,exfer_walletd=info
EOF
sudo chown root:exfer-walletd /etc/exfer-walletd/env
sudo chmod 0640 /etc/exfer-walletd/env

# 4. Install the systemd unit
sudo curl -L -o /etc/systemd/system/exfer-walletd.service \
     https://raw.githubusercontent.com/exfer-stack/exfer-walletd/main/deploy/systemd/exfer-walletd.service
sudo systemctl daemon-reload
sudo systemctl enable --now exfer-walletd
sudo systemctl status exfer-walletd
```

Now in front of it put Caddy (or nginx) for TLS. With Caddy you get
automatic LetsEncrypt for free:

```Caddyfile
walletd.example.com {
    reverse_proxy 127.0.0.1:8080
    request_body { max_size 1MB }
}
```

That's it. Caddy fetches a cert on first request, walletd is reachable
at `https://walletd.example.com/`, and the bearer token never crosses
plaintext wire.

> **Read the tokens out of the env file** to give to your client
> application: `sudo cat /etc/exfer-walletd/env`. Do not paste them
> into shell history; copy them into your application's secret store
> (Vault, AWS Secrets Manager, 1Password, fly secrets, …).

### Recipe B — docker-compose (walletd in a container, node elsewhere)

Useful when the Exfer node already runs separately (a bare-metal node,
a managed RPC provider, or a different container).

`docker-compose.yml`:

```yaml
services:
  exfer-walletd:
    image: ghcr.io/exfer-stack/exfer-walletd:latest  # or build: .
    restart: unless-stopped
    ports:
      - "127.0.0.1:8080:8080"     # bind loopback; put Caddy/nginx in front
    environment:
      WALLETD_BIND: "0.0.0.0:8080"
      WALLETD_WALLET_DIR: "/wallets"
      EXFER_NODE_RPC: "http://exfer-node-host:9334"
      WALLETD_AUTH_TOKEN_READ:  "${WALLETD_AUTH_TOKEN_READ}"
      WALLETD_AUTH_TOKEN_SPEND: "${WALLETD_AUTH_TOKEN_SPEND}"
    volumes:
      - walletd_data:/wallets
    entrypoint: ["/usr/local/bin/exfer-walletd"]

volumes:
  walletd_data:
```

Generate tokens into a sibling `.env` (mode 0600, **not committed**):

```bash
cat >.env <<EOF
WALLETD_AUTH_TOKEN_READ=$(openssl rand -hex 32)
WALLETD_AUTH_TOKEN_SPEND=$(openssl rand -hex 32)
EOF
chmod 600 .env

docker compose up -d
```

The image entrypoint defaults to the combined node+walletd supervisor
(used for the fly deploy); we override it to run walletd only.

### Recipe C — fly.io single-machine (node + walletd in one VM)

The repo includes a turnkey `fly.toml` + `Dockerfile` that runs both
the Exfer node and walletd inside one fly machine on a single
persistent volume. Cheapest topology if you don't already have a node.

```bash
fly launch --no-deploy --copy-config --name your-app
fly volume create exfer_data --region nrt --size 50

# Tokens stored as fly secrets — encrypted in transit and at rest
fly secrets set \
    WALLETD_AUTH_TOKEN_READ=$(openssl rand -hex 32) \
    WALLETD_AUTH_TOKEN_SPEND=$(openssl rand -hex 32)

fly deploy
```

Walletd is exposed at `https://your-app.fly.dev/`. Port 80 is
deliberately not bound (see [Security model](#security-model)).

The first deploy will block on initial block download — the node has
to replay the chain. Expect several hours; subsequent restarts are
fast because the volume preserves chain state.

---

## Security model

### What's protected

| Layer            | Mechanism                                                                                                  |
| ---------------- | ---------------------------------------------------------------------------------------------------------- |
| Token at rest    | Env file `0640 root:exfer-walletd` on systemd; fly secrets store encrypted; docker `.env` mode `0600`      |
| Token in transit | Caddy/nginx/fly proxy terminates TLS; walletd bound on loopback so the plaintext hop is in-process         |
| Token compare    | `subtle::ConstantTimeEq` — no timing oracle                                                                |
| Bind safety      | Startup refuses non-loopback bind without a token — can't publish an open wallet by accident               |
| Path traversal   | Wallet filename = 64-hex address, validated before any FS op                                               |
| Audit trail      | Every spend-scope request emits a structured log line: method, client IP, request id, outcome              |
| Wallet keys      | Files `0600`, dir `0700`, owned by the daemon user. Backing volume should be encrypted (LUKS, fly volume)  |
| Private keys     | Never transmitted. Signing happens in-process; only the signed transaction bytes go to the upstream node   |

### What's *not* protected (by design)

These are deliberate trade-offs, not bugs. Know what model you're
running.

- **Wallet keys are plaintext on disk.** A server has no human to type
  a passphrase, so the daemon stores keys unencrypted and relies on
  filesystem permissions plus volume-level encryption. Anyone who can
  read the daemon's wallet directory can spend every wallet.
- **One spend token = total spend authority.** Any holder of the
  spend token can spend any managed wallet. No per-key authorization,
  no quorum, no MPC. If you need finer-grained authority, implement
  the [`WalletStore`](https://github.com/exfer-stack/exfer-walletd/blob/main/src/store/mod.rs)
  trait against an HSM or KMS backend and slot it in.
- **TLS terminates at the proxy.** Between Caddy/nginx/fly-proxy and
  walletd, traffic is plaintext HTTP on loopback (recipe A & C) or on
  a docker bridge (recipe B). If you don't trust the host or the
  bridge network, run walletd in its own isolated VM.
- **No rate limit, no IP allowlist.** A 32-random-byte token is
  computationally infeasible to brute-force online, but if the
  deployment is reachable from the public internet you still want
  Cloudflare / a WAF / firewall rules in front of it for DoS
  protection.
- **Upstream node RPC is unauthenticated.** Walletd → node uses plain
  HTTP and assumes the node's RPC port is reachable only over a
  trusted hop (loopback, VPC). Don't expose the node's RPC port to
  the public internet.

### Common misconfigurations to avoid

- **Don't pass `--auth-token=…` on the command line.** It shows up in
  `ps aux` for anyone on the host. Use the env file or env vars.
- **Don't run walletd as root** unless you genuinely need to bind a
  privileged port (and you should be reverse-proxying anyway).
- **Don't put the wallet directory on shared storage** (NFS, S3-FUSE).
  Mode bits don't translate; concurrent writers will corrupt keys.
- **Don't expose port 80 plaintext to the public internet.** fly's
  `force_https` only redirects GET/HEAD; a stray POST would leak the
  token before the redirect happens. Either close port 80 entirely or
  have your reverse proxy refuse non-TLS connections.

---

## Operations

### Backup

Back up the wallet directory. Losing it = losing every key = losing
every penny those addresses hold.

```bash
# Stop walletd briefly so we get a consistent snapshot
sudo systemctl stop exfer-walletd
sudo tar -C /var/lib -czf wallets-$(date +%F).tar.gz exfer-walletd
sudo systemctl start exfer-walletd

# Encrypt before storing off-box
gpg --symmetric --cipher-algo AES256 wallets-$(date +%F).tar.gz
# → wallets-YYYY-MM-DD.tar.gz.gpg — safe to ship offsite
```

If you can't stop the daemon, snapshot the underlying volume (LVM,
ZFS, fly volume snapshot). Atomic copies of `.key` files are fine —
walletd writes them with `O_CREAT | O_EXCL` and never modifies
in-place.

### Upgrade

Walletd uses semver. Patches and minors are drop-in; majors will
be called out in the release notes.

```bash
sudo systemctl stop exfer-walletd
curl -L -o /tmp/exfer-walletd \
     https://github.com/exfer-stack/exfer-walletd/releases/latest/download/exfer-walletd-linux-x86_64
sudo install -m 0755 /tmp/exfer-walletd /usr/local/bin/
sudo systemctl start exfer-walletd
sudo journalctl -u exfer-walletd -n 20
```

The wallet directory format is stable: any version of walletd can
load any wallet file written by any other version.

### Rotate tokens

Tokens are stateless — just change them.

```bash
sudo sed -i "s|WALLETD_AUTH_TOKEN_SPEND=.*|WALLETD_AUTH_TOKEN_SPEND=$(openssl rand -hex 32)|" \
    /etc/exfer-walletd/env
sudo systemctl restart exfer-walletd
```

Then update your client application to use the new token. Plan the
window: any in-flight request authenticated with the old token will
fail after the restart and need to retry with the new one.

---

## License

MIT, same as the [upstream Exfer project](https://github.com/ahuman-exfer/exfer).
