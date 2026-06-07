# Tokens and scopes

Walletd uses bearer-token authentication on every request except
`GET /healthz`. Comparison is constant-time
([`subtle::ConstantTimeEq`](https://docs.rs/subtle)).

## Three scoped tokens

Walletd issues **three** tokens, one per scope. On first start it
auto-generates them at `<datadir>/token-{read,manage,spend}` (mode
`0600`).

The authoritative scope of every method is `Scope::for_method` in
`src/auth.rs`; anything not listed below as `manage` or `spend` is
`read`. The [RPC reference](./rpc-reference.md) tags each method with
its scope.

| Scope    | Methods                                                                                            |
| -------- | -------------------------------------------------------------------------------------------------- |
| `read`   | `ping`, `validate_address`, the `get_*` family, `list_addresses`, `list_settlements`, `verify_message`, `get_status`, `get_wallet_balance`, `htlc_status`/`htlc_list`/`htlc_lookup_by_hashlock`, `simulate_*`, `wait_for_tx`/`wait_for_payment`, `payment_uri_*`, `swap_status`/`swap_list`/`swap_pool_info`/`swap_price_klines`, `lp_pool_info`/`lp_position`/`lp_deposit_status`, `bsc_get_address`/`bsc_get_balances`/`bsc_tx_history`, `contract_stats`, `get_attestation_edges` |
| `manage` | `generate_address`, `generate_independent_address`, `generate_standard_address`, `import_private_key`, `import_mnemonic`, `import_standard_mnemonic`, `bsc_create_address`, `bsc_import_mnemonic`, `bsc_import_key`, `abandon_transfer`, `htlc_forget` |
| `spend`  | `transfer`, `send_raw_transaction`, `sign_message`, `htlc_lock`/`htlc_claim`/`htlc_reclaim`, `reveal_mnemonic`/`reveal_private_key`/`reveal_address_mnemonic`/`reveal_evm_private_key`, `export_vault`/`export_address`/`import_vault`, `delete_address`, `swap_get_quote`/`swap_execute`/`swap_refund`, `bsc_send_bnb`/`bsc_reveal_mnemonic`/`bsc_delete_key`, `lp_withdraw_self` |

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
