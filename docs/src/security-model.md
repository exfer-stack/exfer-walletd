# Security model

## What's protected

| Layer            | Mechanism                                                                                                  |
| ---------------- | ---------------------------------------------------------------------------------------------------------- |
| Token at rest    | Env file `0640 root:exfer-walletd` on systemd; docker `.env` mode `0600`; otherwise your secret store.     |
| Token in transit | Caddy / nginx / your TLS terminator handles the wire; walletd is bound on loopback so the plaintext hop is in-process. |
| Token compare    | `subtle::ConstantTimeEq` — no timing oracle.                                                               |
| Bind safety      | Three-tier policy: loopback always OK, private warns, public refused without explicit `--allow-public-bind`. |
| Path traversal   | Wallet filename = 64-hex address, validated before any FS op.                                              |
| Audit trail      | Every spend-scope request emits a structured log line: method, client IP, request id, outcome.             |
| Wallet keys      | Files `0600`, dir `0700`, owned by the daemon user. Encrypt the backing volume (LUKS, dm-crypt, cloud volume encryption). |
| Private keys     | Never transmitted. Signing happens in-process; only the signed transaction bytes go to the upstream node.  |
| Mempool races    | In-flight UTXO tracker prevents back-to-back transfers from the same wallet from racing onto the same outpoint. |

## What's *not* protected (by design)

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

## In-flight UTXO tracker

When `transfer` selects an outpoint as an input, walletd records that
outpoint in an in-memory set with a 10-minute TTL. Subsequent
transfers from the same wallet skip outpoints that are still in this
set, so two back-to-back transfers can't race onto the same UTXO
and trigger the upstream's mempool double-spend rejection.

Behaviours worth knowing:

- **Pre-broadcast errors release the claim.** If UTXO authentication
  fails or the build/sign step errors, the RAII guard releases the
  outpoints on its way out of the function. They're immediately
  re-selectable.
- **Broadcast success keeps the claim until TTL.** Even if the
  consuming tx confirms in 30s, the claim stays in the in-flight set
  for the full 10 minutes. Small wasted-availability window but
  always safe.
- **Transport-error broadcast also releases.** If `send_raw_transaction`
  to the upstream failed with a transport error, walletd can't be
  sure the broadcast went through — but on the safe side it releases
  the claim. If the broadcast *did* land in mempool, a retry will get
  the upstream's own double-spend rejection (surfaced as `-32020`
  with the upstream message). This is the same behaviour as the pre-
  tracker version.
- **No persistence across restarts.** The set is in-memory. A pending
  tx from a pre-restart process will not be skipped by a fresh
  process. Acceptable for most deployments; if you need stronger
  guarantees, run a single daemon instance.

## Common misconfigurations to avoid

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
- **Don't deploy two walletd processes pointing at the same wallet
  directory.** They won't coordinate on the in-flight tracker.

## Next

- [Operations →](./operations.md)
- [FAQ & troubleshooting →](./faq.md)
