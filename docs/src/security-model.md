# Security model

## What you get out of the box

- Three scoped bearer tokens at rest: `<datadir>/token-{read,manage,spend}`,
  mode `0600`; datadir itself is `0700`. Constant-time comparison on
  every request. See [Tokens and scopes](./tokens-and-scopes.md).
- Public binds fail-close unless TLS is on (`--tls`) or you opt in
  with `--allow-public-bind`. See
  [Tokens and scopes → Bind safety](./tokens-and-scopes.md#bind-safety).
- HD seed sealed at `<wallet_dir>/seed.enc` with argon2id +
  ChaCha20-Poly1305 (KEK from `WALLETD_KEYSTORE_PASSPHRASE`).
  Imported (non-derived) secrets sealed under the same KEK at
  `<wallet_dir>/imported/<addr>.key.enc`. Filenames are validated
  64-hex addresses — no path traversal.
- Signing happens in-process. Only the signed transaction bytes go
  to the upstream node; private keys never leave the daemon.
- In-flight UTXO tracker prevents back-to-back transfers from the
  same wallet racing onto the same outpoint
  (see [internals below](#in-flight-utxo-tracker)).
- Every spend-scope request emits a structured audit log line
  (`spend audit`) with `method`, `client_ip`, `request_id`, `outcome`
  — at `INFO` on success, `WARN` on error (the warn line also carries
  the error message). Honors `X-Forwarded-For` for `client_ip` when
  present.

## What's *not* protected (by design)

These are deliberate trade-offs, not bugs. Know what model you're
running.

- **One passphrase unlocks every key.** The HD seed and any imported
  secrets share the same KEK (derived from
  `WALLETD_KEYSTORE_PASSPHRASE` via argon2id). Anyone who has the
  passphrase plus read access to `<wallet_dir>/` can spend every
  wallet. At-rest encryption defeats offline attackers against the
  disk; live attackers with both inputs get full authority.
- **One spend token = total spend authority.** No per-key
  authorization, no quorum, no MPC. If you need finer-grained
  authority, implement the
  [`WalletStore`](https://github.com/exfer-stack/exfer-walletd/blob/main/src/store/mod.rs)
  trait against an HSM or KMS and slot it in.
- **TLS is opt-in.** Walletd defaults to plaintext HTTP on loopback.
  For cross-host traffic, either pass `--tls` (in-process,
  fingerprint-pinned by the SDK) or terminate TLS externally and
  pair with `--allow-public-bind`.
- **No rate limit, no IP allowlist.** A 32-byte token is infeasible
  to brute-force online, but for public exposure you still want a
  WAF / firewall / Cloudflare in front for DoS protection.
- **Upstream node RPC is unauthenticated.** Walletd → node assumes
  a trusted hop (loopback, VPC, or HTTPS to a public provider).

## In-flight UTXO tracker

When `transfer` picks an outpoint as an input, walletd records it in
an in-memory set with a 10-minute TTL. Subsequent transfers from the
same wallet skip outpoints in this set, so two back-to-back transfers
can't race onto the same UTXO and trigger the upstream's mempool
double-spend rejection.

- **Pre-broadcast errors release the claim** (RAII guard). Build /
  sign / authentication failures leave the outpoints re-selectable.
- **Successful broadcast holds the claim until TTL.** Even if the
  consuming tx confirms in 30s, the slot stays held for 10 minutes —
  small wasted availability, always safe.
- **Transport-error broadcast also releases.** Walletd can't be sure
  the broadcast landed; releasing is the safe call (a retry will get
  the upstream's own double-spend rejection if it did).
- **In-memory only — no persistence across restarts.** A pending tx
  from a pre-restart process is invisible to a fresh one. Run a
  single daemon instance per datadir.

## Common misconfigurations to avoid

- **Don't pass `--auth-token-{read,manage,spend}=…` on the command
  line.** They show up in `ps aux`. Use the auto-generated
  `<datadir>/token-{read,manage,spend}` files, or env vars from a
  secret manager.
- **Don't put the wallet directory on shared storage** (NFS,
  S3-FUSE). Mode bits don't translate; concurrent writers will
  corrupt keys.
- **Don't deploy two walletd processes against the same datadir.**
  They don't coordinate on the in-flight tracker.
- **Don't expose port 80 plaintext to the public internet.** Some
  cloud proxies' "force HTTPS" toggle only redirects GET/HEAD; a
  stray POST will leak the token before redirect happens.

## Next

- [Operations →](./operations.md)
- [FAQ & troubleshooting →](./faq.md)
