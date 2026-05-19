# Tokens and scopes

Walletd uses bearer-token authentication on every request except
`GET /healthz`. Comparison is constant-time
([`subtle::ConstantTimeEq`](https://docs.rs/subtle)).

## Default: one auto-generated token

First run creates `<datadir>/token` (default `~/.exfer-walletd/token`,
mode `0600`) with a 32-byte CSPRNG hex string. That single token
grants every method.

```bash
TOKEN=$(cat ~/.exfer-walletd/token)
curl -H "Authorization: Bearer $TOKEN" ...
```

To take the token from a secret manager instead:

```bash
exfer-walletd --auth-token "$(vault read -field=token secret/walletd)"
# or
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

When either scoped token is set, walletd ignores `<datadir>/token`
and enforces the two-scope model:

| Env var                       | Scope  | Methods                                                      |
| ----------------------------- | ------ | ------------------------------------------------------------ |
| `WALLETD_AUTH_TOKEN_READ`     | read   | Every method **except** `transfer` / `send_raw_transaction` / `sign_message`. |
| `WALLETD_AUTH_TOKEN_SPEND`    | spend  | All methods. Spend implies read.                              |
| `WALLETD_AUTH_TOKEN`          | all    | Single-token mode (also the auto-generated file's behaviour). |

A read-scope token hitting a spend method → `401 Unauthorized` /
`-32001`. Method scope is hardcoded — clients can't override it.

## Bind safety

Walletd enforces at startup:

| Bind address                              | Policy                                             |
| ----------------------------------------- | -------------------------------------------------- |
| Loopback (`127.0.0.1`, `::1`)             | Always allowed.                                    |
| Private (RFC1918, ULA, link-local)        | Allowed; warns if no token is set.                 |
| Public (any global IP, `0.0.0.0`, `::`)   | Refused unless `--tls` OR `--allow-public-bind`.   |

The reason public binds need an opt-in: by default walletd doesn't
terminate TLS, and a plaintext bearer token on the public wire is
fatal. `--tls` (walletd terminates TLS itself, see
[Quick start → Production](./quick-start.md#production-enable-tls))
solves it directly; `--allow-public-bind` is your assertion that an
external TLS terminator sits in front. Without one, walletd
fail-closes.

## Next

- [RPC reference →](./rpc-reference.md)
- [Operations →](./operations.md)
