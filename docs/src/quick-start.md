# Quick start

## Dev (laptop / single VM)

Node, walletd, and your code all on one host? Zero flags:

```bash
exfer-walletd
```

Defaults: `--bind 127.0.0.1:8080`, `--node-rpc http://127.0.0.1:9334`,
`--datadir ~/.exfer-walletd`. Assumes a node is already running on
`127.0.0.1:9334`.

On first run, walletd creates `~/.exfer-walletd/` (mode `0700`),
generates a 32-byte bearer token, prints it once in an ASCII box on
stderr, and starts serving.

## Your datadir at a glance

Everything walletd manages lives in one directory. After first run:

```bash
$ ls -la ~/.exfer-walletd/
drwx------  rufus  4096   .
-rw-------  rufus    65   token              ← bearer token (hex)
drwx------  rufus  4096   wallets/           ← one .key file per generate_address

$ cat ~/.exfer-walletd/token
a85da0752815bbf652a1b147649cde77c17f784f3e608d362c629c798a555e7b
```

If you also passed `--tls` (see below), three more files appear:
`cert.pem`, `cert.key`, `cert.fingerprint`.

Backup = `tar czf ... ~/.exfer-walletd`. Uninstall = `rm -rf` it.
There's nothing else walletd touches.

## Call it

```bash
TOKEN=$(cat ~/.exfer-walletd/token)
curl -s http://127.0.0.1:8080/ \
     -H 'content-type: application/json' \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"jsonrpc":"2.0","method":"ping","id":1}'
# → {"jsonrpc":"2.0","result":{"ok":true},"id":1}
```

Full method list: [RPC reference](./rpc-reference.md).

## Cross-host: bind a non-loopback interface

Default bind is loopback-only, so a backend on a different server
can't reach it. Bind your host's private/internal IP:

```bash
exfer-walletd --bind 10.0.1.5:8080
```

Private/RFC1918 addresses are allowed with no extra flag. **Public
IPs** (`0.0.0.0`, any globally routable IP) need either `--tls` (next
section) or `--allow-public-bind` (acknowledging that an external TLS
terminator sits in front).

## Production: enable `--tls`

Pass `--tls` and walletd terminates TLS itself with a self-signed
cert it generates on first run. No CA, no rotation ceremony, no
reverse proxy.

```bash
exfer-walletd --tls --bind 0.0.0.0:8443
```

On first start with `--tls`, walletd creates `cert.pem`, `cert.key`,
and `cert.fingerprint` in the datadir (all `0600`) and prints the
SHA-256 fingerprint once in an ASCII box on stderr:

```
  ┌─ first run ───────────────────────────────────────────────────────────
  │ generated self-signed TLS cert
  │   cert:        /var/lib/walletd/cert.pem
  │   fingerprint: /var/lib/walletd/cert.fingerprint
  │
  │     sha256:b66953c47263ac0da8192676e4770f0f799563322985c57246a6fab1bf24aa86
  │
  │ pin this value on the client side (SDK: fingerprint=…).
  └───────────────────────────────────────────────────────────────────────
```

Lost the line? `cat ~/.exfer-walletd/cert.fingerprint`.

Pin it on the client. The Python SDK reads it automatically:

```python
from exfer_walletd import Client
with Client.from_datadir(url="https://walletd.internal:8443") as c:
    print(c.healthz())
```

`--tls` relaxes `--allow-public-bind` — TLS already protects the
token on the wire.

### Bootstrap from the backend host (no SSH to walletd)

Walletd with `--tls` exposes two unauthenticated GET endpoints on the
HTTPS port so you can grab the cert / fingerprint from the backend
side without shelling into the walletd host:

```bash
# from your backend host (or anywhere):
curl --insecure -o /etc/walletd/cert.pem \
     https://walletd.internal:8443/exfer-walletd/cert.pem

curl --insecure https://walletd.internal:8443/exfer-walletd/cert.fingerprint
# → sha256:b66953c47263ac0da8192676e4770f0f799563322985c57246a6fab1bf24aa86
```

The `--insecure` flag is the bootstrap step — it skips cert
verification on this **one** request. After you've saved the cert
(or the fingerprint) and configured your client to pin it, every
subsequent connection is strict.

**Security caveat** — this is
[TOFU](https://en.wikipedia.org/wiki/Trust_on_first_use): if an
attacker is on the network path the moment you run the bootstrap
`curl`, they can hand you a cert they control. For deployments
inside one VPC / private network this is essentially never an issue.
For deployments crossing untrusted networks (public internet, cafe
wifi, etc.), prefer copying `cert.pem` or `cert.fingerprint` over a
channel you already trust (scp, your secret manager, the same env
vars you push the token through).

The bootstrap endpoints are only mounted when `--tls` is on. Plain
HTTP walletd never serves these — handing out cert material over
plaintext would defeat the whole pinning model.

## Other flags

```bash
exfer-walletd --node-rpc 'http://a:9334,http://b:9334'  # round-robin + failover
exfer-walletd --datadir  /var/lib/walletd               # different storage location
exfer-walletd --auth-token-read  ...                    # split read/spend tokens
exfer-walletd --auth-token-spend ...
```

Every flag also reads from a matching env var (`WALLETD_BIND`,
`WALLETD_TLS`, `EXFER_NODE_RPC`, …). Full list: `exfer-walletd --help`.

## Next

- [Picking a node →](./picking-a-node.md)
- [Tokens and scopes →](./tokens-and-scopes.md)
- [RPC reference →](./rpc-reference.md)
