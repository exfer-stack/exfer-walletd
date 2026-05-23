# Quick start

## Pick your shape

| Scenario                                       | Command                                                            | Wire |
| ---------------------------------------------- | ------------------------------------------------------------------ | ---- |
| Dev — node, walletd, caller on one host        | `exfer-walletd`                                                    | plain HTTP on `127.0.0.1` |
| **Prod — cross-host, recommended**             | `exfer-walletd --tls --bind <private-ip>:7448`                     | HTTPS, self-signed cert, SDK pins by fingerprint |
| Prod — TLS terminator (nginx/Caddy/cloud LB) already in front | `exfer-walletd --allow-public-bind --bind 0.0.0.0:7448` | plain HTTP behind your proxy |

**If your walletd talks to a backend on a different host, you want
`--tls`.** A bearer token over plaintext HTTP is fatal — walletd
fails-closed on public binds to make that hard to do by accident.
Full details: [Production: enable `--tls`](#production-enable-tls)
below.

## Dev (laptop / single VM)

Node, walletd, and your code all on one host:

```bash
export WALLETD_KEYSTORE_PASSPHRASE='correct horse battery staple'
exfer-walletd
```

Defaults: `--bind 127.0.0.1:7448`, `--node-rpc http://127.0.0.1:9334`,
`--datadir ~/.exfer-walletd`. `WALLETD_KEYSTORE_PASSPHRASE` is
**required** — walletd encrypts the HD seed at rest with argon2id +
ChaCha20-Poly1305 and refuses to start without an explicit passphrase.

On first run, walletd:

1. Creates `~/.exfer-walletd/` (mode `0700`).
2. Generates a 24-word BIP-39 mnemonic + a fresh HD seed; seals the
   seed and prints the mnemonic once on stderr inside an ASCII box.
   **Write the words down — they are the only seed backup.**
3. Generates three bearer tokens (one per scope) at
   `<datadir>/token-{read,manage,spend}` and prints each once in an
   ASCII box.
4. Starts serving.

## Your datadir at a glance

Everything walletd manages lives in one directory. After first run:

```bash
$ ls -la ~/.exfer-walletd/
drwx------  walletd  4096   .
-rw-------  walletd    65   token-read
-rw-------  walletd    65   token-manage
-rw-------  walletd    65   token-spend
drwx------  walletd  4096   wallets/
    ├── seed.enc        ← sealed BIP-39 entropy
    ├── state.json      ← next_index, labels, imported list
    └── imported/       ← legacy .key migrations (sealed)

$ cat ~/.exfer-walletd/token-spend
a85da0752815bbf652a1b147649cde77c17f784f3e608d362c629c798a555e7b
```

If you also passed `--tls` (see below), three more files appear:
`cert.pem`, `cert.key`, `cert.fingerprint`.

**Backup** = the 24-word mnemonic (offline) plus
`tar czf ... ~/.exfer-walletd/wallets/imported`. The mnemonic
recovers every HD-derived address; the `imported/` files cover
addresses that came in via `migrate`. Uninstall = `rm -rf` the
datadir.

## Call it

```bash
TOKEN=$(cat ~/.exfer-walletd/token-spend)
curl -s http://127.0.0.1:7448/ \
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
exfer-walletd --bind 10.0.1.5:7448
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
exfer-walletd --tls --bind 10.0.1.5:7448
```

The bound IP is auto-added to the cert's `subjectAltName`. If your
clients connect via a hostname (or you bind `0.0.0.0` and proxy in),
also pass `--tls-san`:

```bash
exfer-walletd --tls --bind 0.0.0.0:7448 --tls-san walletd.internal,10.0.1.5
```

On first start, walletd creates `cert.pem`, `cert.key`, and
`cert.fingerprint` in the datadir (all `0600`) and prints the
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

`--tls` relaxes `--allow-public-bind` — TLS already protects the
token on the wire.

Changed your bind, hostname, or `--tls-san` later? The cert is only
generated on first run. Delete the trio (`rm cert.{pem,key,fingerprint}`)
and restart to regenerate.

### Two ways to verify the cert on the client

**SDK — fingerprint pinning (recommended).** No CA, no SAN dance.

```python
from exfer_walletd import Client
with Client.from_datadir(url="https://<walletd-host>:7448") as c:
    print(c.healthz())
```

**Strict CA-style validation** — `curl --cacert`, Java, anything that
checks the SAN. Drop `cert.pem` on the client and verify by the same
hostname/IP you put in the SAN:

```bash
curl --cacert /etc/walletd/cert.pem https://walletd.internal:7448/healthz
```

If the hostname/IP isn't in the SAN, you get
`SSL: no alternative certificate subject name matches target host name`.
Fix by regenerating the cert with `--tls-san` covering it.

### Bootstrap from the backend host (no SSH to walletd)

Walletd with `--tls` exposes two unauthenticated GET endpoints on the
HTTPS port so you can grab the cert / fingerprint from the backend
side without shelling into the walletd host:

```bash
# from your backend host (or anywhere):
curl --insecure -o /etc/walletd/cert.pem \
     https://<walletd-host>:7448/exfer-walletd/cert.pem

curl --insecure https://<walletd-host>:7448/exfer-walletd/cert.fingerprint
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
exfer-walletd --node-rpc 'http://a:9334,http://b:9334'        # round-robin + failover
exfer-walletd --datadir  /var/lib/walletd                     # different storage location
exfer-walletd --auth-token-read   "$(openssl rand -hex 32)" \ # supply any subset of the
              --auth-token-manage "$(openssl rand -hex 32)" \ # three scoped tokens from
              --auth-token-spend  "$(openssl rand -hex 32)"   # a secret manager
```

Every flag also reads from a matching env var (`WALLETD_BIND`,
`WALLETD_TLS`, `EXFER_NODE_RPC`, …). Full list: `exfer-walletd --help`.

## Next

- [Picking a node →](./picking-a-node.md)
- [Tokens and scopes →](./tokens-and-scopes.md)
- [RPC reference →](./rpc-reference.md)
