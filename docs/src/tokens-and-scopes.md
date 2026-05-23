# Tokens and scopes

Walletd uses bearer-token authentication on every request except
`GET /healthz`. Comparison is constant-time
([`subtle::ConstantTimeEq`](https://docs.rs/subtle)).

## Three scoped tokens

v1.0 issues **three** tokens, one per scope. On first start walletd
auto-generates them at `<datadir>/token-{read,manage,spend}` (mode
`0600`).

| Scope    | Methods                                                                                            |
| -------- | -------------------------------------------------------------------------------------------------- |
| `read`   | `ping`, `validate_address`, `get_*` family, `list_addresses`, `verify_message`, `get_status`, `get_wallet_balance` |
| `manage` | `generate_address`, `abandon_transfer`                                                              |
| `spend`  | `transfer`, `send_raw_transaction`, `sign_message`                                                  |

**Containment**: `spend ⊇ manage ⊇ read`. A token at a higher scope
satisfies every lower scope, so an exchange's withdrawal worker only
needs the spend token — it gets `manage` and `read` for free.

## Configuring

The default behaviour (auto-generate on first run) suits most setups.
Override any subset from a secret manager:

```bash
exfer-walletd \
    --auth-token-read   "$(vault read -field=token secret/walletd-read)" \
    --auth-token-manage "$(vault read -field=token secret/walletd-manage)" \
    --auth-token-spend  "$(vault read -field=token secret/walletd-spend)"
```

Env equivalents: `WALLETD_AUTH_TOKEN_READ`, `WALLETD_AUTH_TOKEN_MANAGE`,
`WALLETD_AUTH_TOKEN_SPEND`. Setting any of them suppresses auto-file
creation for that scope.

## Typical splits

| Component                 | Token to issue  |
| ------------------------- | --------------- |
| Deposit watcher           | `token-read`    |
| Address provisioning      | `token-manage`  |
| Withdrawal worker         | `token-spend`   |
| Operator dashboard / SRE  | `token-read`    |

A leaked read token can survey balances and pubkeys but cannot mint
addresses or spend. A leaked manage token can mint addresses but
cannot spend or sign messages. A leaked spend token is "every wallet,
all funds" — guard accordingly.

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
