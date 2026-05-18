# Picking a node

`exfer-walletd` is decoupled from any specific Exfer node. Anything
that speaks the Exfer JSON-RPC will do. Choose based on what you
already run.

## Same host (most common)

Default. `init` records `EXFER_NODE_RPC=http://127.0.0.1:9334`.
Nothing more to do — start the node first, then walletd.

```bash
# Terminal 1 — an Exfer node with RPC enabled
exfer node --datadir ./chain --rpc-bind 127.0.0.1:9334

# Terminal 2 — walletd (after `init`)
exfer-walletd
```

The walletd → node hop is loopback HTTP, plaintext. That's fine —
loopback never leaves the kernel, no NIC, no wire.

## Different host (LAN, VPC, public RPC)

Pass `--node-rpc` to `init`, or edit `EXFER_NODE_RPC` in the env file.
Walletd treats the upstream like any other HTTP service — no auth,
just a URL.

```bash
exfer-walletd init --node-rpc https://exfer-rpc.example.com
```

Caveats when the upstream isn't yours:

- The upstream sees every broadcast you submit (**signed bytes only**
  — no keys, no plaintext sensitive data). Treat the choice of RPC
  provider like any other trust decision.
- If the upstream is on the public internet, prefer HTTPS for the
  upstream URL too. Walletd uses `rustls` for outbound HTTPS, no
  extra config needed.
- The community node at `http://82.221.100.201:9334` is unauthenticated
  and convenient for testing, but it has the usual public-RPC issues
  (occasional unavailability, rate-limit, no SLA). Don't depend on it
  in production.

## Multiple nodes (round-robin + failover)

Comma-separate the URLs. Walletd rotates the starting node per call
and falls over to the next on transport / 5xx error. Application-level
errors (`Block not found`) are surfaced immediately without trying
the next node.

```bash
exfer-walletd init --node-rpc \
  'http://node-a:9334,http://node-b:9334,https://public-rpc.example.com'
```

Failover only triggers on:

- Connection refused / timeout
- HTTP 5xx
- Response that doesn't decode as JSON-RPC

Failover does **not** trigger on:

- HTTP 4xx (treated as application error)
- JSON-RPC body with `error.code` set (the node knows the answer, it's
  just an error answer — retrying on a different node is unlikely to
  produce a better one and could even be wrong if nodes are out of sync)

## You don't have a node yet

Either:

- Run one with the upstream Exfer CLI (`exfer node --datadir ... --rpc-bind 127.0.0.1:9334`).
  This is the right choice for production — you control the trust path.
- Or use a public RPC provider as a stop-gap. You can switch by
  editing one line in the env file later.

## Latency matters

Walletd's `transfer` makes 3 sequential round-trips to the upstream
plus N parallel parent-tx fetches (where N = number of input UTXOs):

```
list_utxos  ──► upstream                          1 RTT
get_transaction × N (parallel, cap 8)             ⌈N/8⌉ RTTs
send_raw_transaction ──► upstream                 1 RTT
```

Total submit time ≈ `(2 + ⌈N/8⌉) × RTT`.

- Local node (RTT ~5ms): single-UTXO transfer ~15ms
- LAN node (RTT ~50ms): ~150ms
- Public RPC (RTT ~750ms): ~2.3s

For an exchange hot wallet with many small UTXOs, run a local or VPC-
internal node — public RPC will be visibly slow.

## Next

- [Tokens and scopes →](./tokens-and-scopes.md)
- [RPC reference →](./rpc-reference.md)
