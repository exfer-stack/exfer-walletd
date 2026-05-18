# Tokens and scopes

`exfer-walletd` uses bearer-token authentication on every request
except `GET /healthz`. Comparison is **constant-time**
([`subtle::ConstantTimeEq`](https://docs.rs/subtle)) so a timing
oracle can't peel the token byte by byte.

## Default: one auto-generated token

First run creates `<datadir>/token` (default `~/.exfer-walletd/token`,
mode `0600`) with a 32-byte CSPRNG hex string. That single token
grants every method.

```bash
TOKEN=$(cat ~/.exfer-walletd/token)
curl -H "Authorization: Bearer $TOKEN" ...
```

Subsequent runs read the file silently. To override (e.g. take the
token from a secret manager instead):

```bash
exfer-walletd --auth-token "$(vault read -field=token secret/walletd)"
# or via env
WALLETD_AUTH_TOKEN=... exfer-walletd
```

## Optional: split read / spend

If a deposit-watcher and a withdrawal-worker are separate services,
issue them separate tokens so a leaked read token can't move funds:

```bash
exfer-walletd \
    --auth-token-read  "$(openssl rand -hex 32)" \
    --auth-token-spend "$(openssl rand -hex 32)"
```

(Or set `WALLETD_AUTH_TOKEN_READ` / `WALLETD_AUTH_TOKEN_SPEND`.)

When either scoped token is set, walletd ignores the on-disk
`<datadir>/token` and enforces the two-scope model:

| Env var                       | Scope  | Methods                                                      |
| ----------------------------- | ------ | ------------------------------------------------------------ |
| `WALLETD_AUTH_TOKEN_READ`     | read   | Every method **except** `transfer` / `send_raw_transaction`. |
| `WALLETD_AUTH_TOKEN_SPEND`    | spend  | All methods. Spend implies read.                              |
| `WALLETD_AUTH_TOKEN`          | all    | Single-token mode (also the auto-generated file's behaviour). |

## Sending the token

Every request:

```http
POST / HTTP/1.1
Host: localhost:8080
Content-Type: application/json
Authorization: Bearer <your token>

{"jsonrpc":"2.0","method":"ping","id":1}
```

## What each scope can do

Method scope is hardcoded — clients can't override it.

| Method                  | Read | Spend | All  |
| ----------------------- | :--: | :---: | :--: |
| `ping`                  |  ✓   |   ✓   |  ✓   |
| `generate_address`      |  ✓   |   ✓   |  ✓   |
| `list_addresses`        |  ✓   |   ✓   |  ✓   |
| `get_balance`           |  ✓   |   ✓   |  ✓   |
| `get_address_utxos`     |  ✓   |   ✓   |  ✓   |
| `get_script_utxos`      |  ✓   |   ✓   |  ✓   |
| `get_block_height`      |  ✓   |   ✓   |  ✓   |
| `get_block`             |  ✓   |   ✓   |  ✓   |
| `get_transaction`       |  ✓   |   ✓   |  ✓   |
| `transfer`              |      |   ✓   |  ✓   |
| `send_raw_transaction`  |      |   ✓   |  ✓   |

Read scope hitting a spend method → `401 Unauthorized` / `-32001`.

## Bind safety

Walletd enforces a three-tier bind policy at startup:

| Bind address                              | Policy                                             |
| ----------------------------------------- | -------------------------------------------------- |
| Loopback (`127.0.0.1`, `::1`)             | Always allowed. No wire to encrypt.                |
| Private (RFC1918, ULA, link-local)        | Allowed. Warns if no token — LAN clients unauthenticated. |
| Public (any global IP, `0.0.0.0`, `::`)   | **Refused** unless `--allow-public-bind` is set.   |

The reason public binds require an explicit opt-in: walletd does not
terminate TLS itself. Without a TLS terminator in front (Caddy, nginx,
Cloudflare, k8s ingress, a cloud LB), the bearer token rides the wire
as plaintext.

The opt-in flag is your assertion that "a TLS terminator is in front
of me." If you forget to set it, walletd refuses to start — fail-closed.

The default `--bind` is `127.0.0.1:8080`. For cross-host calls, bind a
private/internal IP — no opt-in needed.

## Rotating tokens

Single-token (auto-generated) mode — just delete the file and restart:

```bash
rm ~/.exfer-walletd/token
exfer-walletd      # generates + prints a fresh one
```

Two-token mode — change the env values / CLI flags and restart.

Either way: any in-flight request authenticated with the old token
will fail after the restart and need to retry with the new one. Plan
the window.

## Next

- [RPC reference →](./rpc-reference.md)
- [Error codes →](./errors.md)
