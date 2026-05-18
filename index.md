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
whatever node(s) you point it at — your own node on loopback, a node
on your LAN/VPC, or a third-party public RPC endpoint.

---

## Contents

1. [Install](#install)
2. [Quick start](#quick-start) — `init` to a running daemon in two commands
3. [Picking a node](#picking-a-node) — local vs. remote vs. multiple
4. [Tokens and scopes](#tokens-and-scopes)
5. [RPC reference](#rpc-reference)
6. [Errors](#errors)
7. [Production deploy](#production-deploy) — systemd + Caddy, docker-compose
8. [Security model](#security-model) — what's protected, what isn't
9. [Backup, upgrade, key rotation, uninstall](#operations)

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

## Quick start

`exfer-walletd init` scaffolds an env file (read + spend tokens, bind,
wallet dir, upstream node) and creates the wallet directory. The
daemon then starts with zero CLI flags — all config comes from the env
file. This is the recommended path for both first-time tries and
production.

### Local dev (no sudo)

Useful for trying it from your laptop without touching `/etc` or
`/var/lib`. The daemon refuses to bind a non-loopback interface
without an explicit opt-in, so loopback dev is safe by construction.

```bash
exfer-walletd init \
    --env-file   ./walletd.env \
    --wallet-dir ./wallets \
    --node-rpc   http://127.0.0.1:9334   # see "Picking a node" below

# Load the generated tokens + config into the current shell
set -a; . ./walletd.env; set +a

exfer-walletd
# starting walletd on 127.0.0.1:8080, upstream http://127.0.0.1:9334

# In another terminal — ping is read-scope
curl -s http://127.0.0.1:8080/ -H 'content-type: application/json' \
     -H "Authorization: Bearer $WALLETD_AUTH_TOKEN_READ" \
     -d '{"jsonrpc":"2.0","method":"ping","id":1}'
# → {"jsonrpc":"2.0","result":{"ok":true},"id":1}
```

The env file is mode `0600` and contains your tokens — don't commit it.

### System-wide (systemd)

See [Production deploy → Recipe A](#recipe-a--systemd--caddy-on-a-single-vm-most-common)
for the full systemd walkthrough. The first step there is the same
`init`, but writing to `/etc/exfer-walletd/env` and `/var/lib/exfer-walletd`.

### `init` flag reference

| Flag             | Default                      | What it sets in the env file                              |
| ---------------- | ---------------------------- | --------------------------------------------------------- |
| `--env-file`     | `/etc/exfer-walletd/env`     | Path of the generated env file (`0600`)                   |
| `--wallet-dir`   | `/var/lib/exfer-walletd`     | `WALLETD_WALLET_DIR` (also `mkdir -p ... -m 0700`)        |
| `--bind`         | `127.0.0.1:8080`             | `WALLETD_BIND`                                            |
| `--node-rpc`     | `http://127.0.0.1:9334`      | `EXFER_NODE_RPC` (single URL or comma-separated list)     |
| `--print`        | off                          | Print env body to stdout instead of writing a file        |
| `--force`        | off                          | Overwrite an existing env file (otherwise refuses)        |

`init` is idempotent: a pre-existing env file is left alone so a
re-run can't silently rotate tokens that are in use. Pass `--force` to
deliberately regenerate.

---

## Picking a node

`exfer-walletd` is decoupled from any specific node. Anything that
speaks the Exfer JSON-RPC will do. Choose based on what you already
run:

### You run your own node on the same host

Default. `init` records `EXFER_NODE_RPC=http://127.0.0.1:9334`.
Nothing more to do — start the node first, then walletd.

```bash
# Terminal 1 — an Exfer node with RPC enabled
exfer node --datadir ./chain --rpc-bind 127.0.0.1:9334

# Terminal 2 — walletd (after `init`)
exfer-walletd
```

### You're pointing at someone else's node (LAN, VPC, public RPC)

Pass `--node-rpc` to `init`, or edit `EXFER_NODE_RPC` in the env file
afterwards. Walletd treats the upstream like any other HTTP service —
no auth, just a URL.

```bash
exfer-walletd init --node-rpc https://exfer-rpc.example.com
```

Caveats when the upstream isn't yours:

- The upstream sees every broadcast you submit (signed bytes only — no
  keys, no plaintext). Treat the choice of RPC provider like any other
  trust decision.
- If the upstream is on the public internet, prefer HTTPS for the
  upstream URL too. Walletd uses `rustls` for outbound HTTPS, no extra
  config needed.

### You want fail-over across several nodes

Comma-separate the URLs. Walletd round-robins and fails over to the
next on transport / 5xx error.

```bash
exfer-walletd init --node-rpc 'http://node-a:9334,http://node-b:9334,https://public-rpc.example.com'
```

### You don't have a node yet

Run one with the upstream Exfer CLI (`exfer node …`), or skip ahead
and use a public RPC provider for now — you can switch by editing one
line in the env file later.

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
read token. A withdrawal worker that moves funds needs spend.
Splitting them limits blast radius if one set of credentials leaks.

`exfer-walletd init` generates fresh 32-byte tokens for both scopes
and records them in the env file. If you ever need to mint one by
hand:

```bash
openssl rand -hex 32   # → 64-char hex string
```

Send them in `Authorization: Bearer <token>`. Comparison is constant-
time (`subtle::ConstantTimeEq`) so a timing oracle can't peel the
token byte by byte.

**Bind safety**: walletd enforces a three-tier policy at startup:

| Bind address | Policy |
|---|---|
| Loopback (`127.0.0.1`, `::1`) | Always allowed. No wire to encrypt. |
| Private (RFC1918 `10.x / 172.16-31 / 192.168.x`, IPv6 ULA `fc00::/7`, link-local) | Allowed. Warns if no token is set — LAN clients could call walletd anonymously. |
| Public (`0.0.0.0`, `::`, any globally-routable IP) | **Refused** unless `--allow-public-bind` (or `WALLETD_ALLOW_PUBLIC_BIND=1`) is set. Token is required regardless. |

The reason public binds require an explicit opt-in: walletd doesn't
terminate TLS itself. Without a TLS terminator in front (Caddy,
nginx, Cloudflare, k8s ingress, a cloud load balancer), the bearer
token rides the public-internet wire as plaintext. The opt-in flag is
your assertion that "a TLS terminator is in front of me." If you
forget to set it, walletd refuses to start — fail-closed.

The default `--bind` is `127.0.0.1:8080`. Put Caddy in front and you
never need the flag.

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
| `-32031` | 200  | Insufficient balance for `amount + fee` (body shows totals)    |
| `-32603` | 200  | Internal error                                                 |

Per JSON-RPC convention, errors usually return HTTP 200 with the error
in the body. Transport-level problems (401, malformed JSON → 400)
escape to the HTTP layer so clients can branch on the status code
without reading the body.

---

## Production deploy

Two recipes. Pick the one that matches your environment.

### Recipe A — systemd + Caddy on a single VM (most common)

A single host running walletd (with the Exfer node either on the same
host or somewhere reachable), Caddy terminating TLS and reverse-
proxying to walletd on loopback.

Files in [`deploy/systemd/`](https://github.com/exfer-stack/exfer-walletd/tree/main/deploy/systemd)
and [`deploy/caddy/`](https://github.com/exfer-stack/exfer-walletd/tree/main/deploy/caddy)
of the repo.

```bash
# 1. Install the binary
curl -L -o /tmp/exfer-walletd \
     https://github.com/exfer-stack/exfer-walletd/releases/latest/download/exfer-walletd-linux-x86_64
sudo install -m 0755 /tmp/exfer-walletd /usr/local/bin/

# 2. Scaffold env file + wallet dir + fresh tokens in one shot.
#    --node-rpc accepts loopback, a host on your VPC, or a public RPC URL.
#    Omit it to default to http://127.0.0.1:9334.
sudo exfer-walletd init --node-rpc http://your-node-host:9334

# 3. Create the runtime user and tighten ownership. (`init` prints
#    these same four commands on success, in case you forget.)
sudo useradd --system --home /var/lib/exfer-walletd --shell /usr/sbin/nologin exfer-walletd
sudo chown -R exfer-walletd:exfer-walletd /var/lib/exfer-walletd
sudo chown root:exfer-walletd /etc/exfer-walletd/env
sudo chmod 0640 /etc/exfer-walletd/env

# 4. Install the systemd unit and start
sudo curl -L -o /etc/systemd/system/exfer-walletd.service \
     https://raw.githubusercontent.com/exfer-stack/exfer-walletd/main/deploy/systemd/exfer-walletd.service
sudo systemctl daemon-reload
sudo systemctl enable --now exfer-walletd
sudo systemctl status exfer-walletd
```

`init` is idempotent — re-running it on a host that already has an env
file errors out, so you can't accidentally rotate tokens that are in
use. Pass `--force` to deliberately regenerate. `--print` writes the
env contents to stdout instead of a file (useful when secrets live in
a vault and you don't want a host file at all).

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
> (Vault, AWS Secrets Manager, 1Password, your platform's secret
> store, …).

### Recipe B — docker-compose (walletd in a container, node elsewhere)

Useful when the Exfer node already runs separately (a bare-metal node,
a managed RPC provider, or a different container).

Generate tokens into a sibling `.env` (mode 0600, **not committed**):

```bash
cat >.env <<EOF
WALLETD_AUTH_TOKEN_READ=$(openssl rand -hex 32)
WALLETD_AUTH_TOKEN_SPEND=$(openssl rand -hex 32)
EXFER_NODE_RPC=http://your-node-host:9334
EOF
chmod 600 .env
```

`docker-compose.yml`:

```yaml
services:
  exfer-walletd:
    image: ghcr.io/exfer-stack/exfer-walletd:latest  # or build: .
    restart: unless-stopped
    ports:
      - "127.0.0.1:8080:8080"     # bind loopback; put Caddy/nginx in front
    environment:
      # Inside the container we bind 0.0.0.0 so the published port works,
      # but the published port is on 127.0.0.1 on the host. The
      # ALLOW_PUBLIC_BIND flag acknowledges that arrangement — without
      # it, walletd refuses to bind 0.0.0.0 at startup.
      WALLETD_BIND: "0.0.0.0:8080"
      WALLETD_ALLOW_PUBLIC_BIND: "1"
      WALLETD_WALLET_DIR: "/wallets"
      EXFER_NODE_RPC: "${EXFER_NODE_RPC}"
      WALLETD_AUTH_TOKEN_READ:  "${WALLETD_AUTH_TOKEN_READ}"
      WALLETD_AUTH_TOKEN_SPEND: "${WALLETD_AUTH_TOKEN_SPEND}"
    volumes:
      - walletd_data:/wallets
    entrypoint: ["/usr/local/bin/exfer-walletd"]
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://127.0.0.1:8080/healthz"]
      interval: 30s
      timeout: 5s
      retries: 3

volumes:
  walletd_data:
```

```bash
docker compose up -d
```

The image entrypoint defaults to a combined node + walletd supervisor;
we override it to run walletd only and talk to a node elsewhere
(loopback on the host via `host.docker.internal`, a sibling container,
or a public RPC URL — whatever `EXFER_NODE_RPC` points at).

---

## Security model

### What's protected

| Layer            | Mechanism                                                                                                  |
| ---------------- | ---------------------------------------------------------------------------------------------------------- |
| Token at rest    | Env file `0640 root:exfer-walletd` on systemd; docker `.env` mode `0600`; otherwise your secrets store     |
| Token in transit | Caddy / nginx / your TLS terminator handles the wire; walletd is bound on loopback so the plaintext hop is in-process |
| Token compare    | `subtle::ConstantTimeEq` — no timing oracle                                                                |
| Bind safety      | Three-tier policy: loopback always OK, private warns, public refused without explicit `--allow-public-bind` |
| Path traversal   | Wallet filename = 64-hex address, validated before any FS op                                               |
| Audit trail      | Every spend-scope request emits a structured log line: method, client IP, request id, outcome              |
| Wallet keys      | Files `0600`, dir `0700`, owned by the daemon user. Encrypt the backing volume (LUKS, dm-crypt, cloud volume encryption) |
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
- **TLS terminates at the proxy.** Between your TLS terminator
  (Caddy/nginx/cloud LB/ingress) and walletd, traffic is plaintext
  HTTP — either on loopback (recipe A) or on a docker bridge (recipe
  B). If you don't trust the host or the bridge network, run walletd
  in its own isolated VM.
- **No rate limit, no IP allowlist.** A 32-random-byte token is
  computationally infeasible to brute-force online, but if the
  deployment is reachable from the public internet you still want
  Cloudflare / a WAF / firewall rules in front of it for DoS
  protection.
- **Upstream node RPC is unauthenticated.** Walletd → node uses plain
  HTTP and assumes the node's RPC port is reachable only over a
  trusted hop (loopback, VPC, or HTTPS to a public provider). Don't
  expose your own node's RPC port to the public internet without a
  proxy in front.

### Common misconfigurations to avoid

- **Don't pass `--auth-token=…` on the command line.** It shows up in
  `ps aux` for anyone on the host. Use the env file (what `init`
  generates) or env vars.
- **Don't run walletd as root** unless you genuinely need to bind a
  privileged port (and you should be reverse-proxying anyway).
- **Don't put the wallet directory on shared storage** (NFS, S3-FUSE).
  Mode bits don't translate; concurrent writers will corrupt keys.
- **Don't expose port 80 plaintext to the public internet.** Some
  cloud proxies' "force HTTPS" toggles only redirect GET/HEAD; a stray
  POST will leak the token before the redirect happens. Close port 80
  at the proxy or have your reverse proxy refuse non-TLS connections.

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
ZFS, your cloud volume snapshot). Atomic copies of `.key` files are
fine — walletd writes them with `O_CREAT | O_EXCL` and never modifies
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

### Uninstall

`exfer-walletd uninstall` reverses `init`. Dry-run by default — it
prints the plan and exits without touching anything until you pass
`--yes`. The wallet directory is preserved by default; losing
`.key` files loses every penny those addresses hold.

```bash
# 1. See what would happen — no changes made.
sudo exfer-walletd uninstall --systemd
#   uninstall plan:
#     1. systemctl stop exfer-walletd  (ignore failure if inactive)
#     2. systemctl disable exfer-walletd
#     3. rm /etc/systemd/system/exfer-walletd.service
#     4. systemctl daemon-reload
#     5. rm /etc/exfer-walletd/env  (env file with tokens)
#   Dry run. Re-run with --yes to execute.

# 2. Execute. Wallet directory still untouched.
sudo exfer-walletd uninstall --systemd --yes

# 3. ONLY when you really want the keys gone (and have backups elsewhere):
sudo exfer-walletd uninstall \
    --systemd --wallets --i-understand-this-deletes-keys --yes
```

If the wallet directory contains key files, walletd refuses
`--wallets` unless you also pass `--i-understand-this-deletes-keys`
— the long flag exists precisely so that habit + `--yes` can't
accidentally destroy a treasury. The runtime user, the binary in
`/usr/local/bin`, and any reverse-proxy block in your Caddyfile /
nginx config are *not* touched; uninstall prints the exact commands
to clean them up by hand at the end.

### Point at a different node

The upstream node URL lives in `EXFER_NODE_RPC`. Edit, restart, done
— wallets and tokens are unaffected.

```bash
sudo sed -i "s|^EXFER_NODE_RPC=.*|EXFER_NODE_RPC=http://new-node-host:9334|" \
    /etc/exfer-walletd/env
sudo systemctl restart exfer-walletd
```

Comma-separate URLs for round-robin + failover across several nodes.

---

## License

MIT, same as the [upstream Exfer project](https://github.com/ahuman-exfer/exfer).
