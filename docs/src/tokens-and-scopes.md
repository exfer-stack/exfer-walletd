# Tokens and scopes

`exfer-walletd` uses bearer-token authentication on every request
except `GET /healthz`. Comparison is **constant-time**
([`subtle::ConstantTimeEq`](https://docs.rs/subtle)) so a timing
oracle can't peel the token byte by byte.

## Modes

| Env var                       | Scope  | Methods                                                    |
| ----------------------------- | ------ | ---------------------------------------------------------- |
| `WALLETD_AUTH_TOKEN`          | all    | Everything (read + spend). Single-token mode.              |
| `WALLETD_AUTH_TOKEN_READ`     | read   | Every method **except** `transfer` / `send_raw_transaction`. |
| `WALLETD_AUTH_TOKEN_SPEND`    | spend  | All methods. Spend implies read.                            |

Use whichever fits:

- **Single-token (default)**: one backend service uses walletd.
  Simplest, one secret to manage. This is what `init` generates.
- **Two-token (`--scoped`)**: deposit-watcher and withdrawal-worker
  are separate services. A leaked read token can't move funds.

You can also generate tokens by hand:

```bash
openssl rand -hex 32
# → 64-char hex CSPRNG string
```

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

The default `--bind` is `127.0.0.1:8080`. Put Caddy in front and you
never need the flag.

## Rotating tokens

Tokens are stateless — just change them.

```bash
sudo sed -i "s|WALLETD_AUTH_TOKEN=.*|WALLETD_AUTH_TOKEN=$(openssl rand -hex 32)|" \
    /etc/exfer-walletd/env
sudo systemctl restart exfer-walletd
```

Then update your client application. Any in-flight request
authenticated with the old token will fail after the restart and
need to retry with the new one.

## Next

- [RPC reference →](./rpc-reference.md)
- [Error codes →](./errors.md)
