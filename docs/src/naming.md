# Names (highest-burn registry)

Human-readable names (`alice`) that resolve to an address, with **no
consensus change** — built entirely on ordinary transfers plus an indexer
convention.

## How it works

1. **A name derives a burn-script.** `name_script(name)` =
   `SHA256("EXFER-NAME-v1:" + lowercase(trim(name)))` — a 32-byte target
   that no key hashes to, so value sent there is **burned**. walletd and
   the indexer derive this identically (a shared test vector guards it).

2. **Claiming = burning to that script.** `name_claim` sends `amount` to
   the name's burn-script via a normal transfer. The `amount` is your **bid**.

3. **Ownership = highest cumulative burn.** The party that has burned the
   most to a name owns it. This is an **open auction**: a name can be
   taken at any time by out-burning the current owner (no permanence).
   Ties break by earliest first claim, then lowest address.

4. **The owner declares where the name points.** Pass `target` to
   `name_claim` to point the name at any address; this is encoded as an
   extra output in the claim tx. Omit it to point the name at yourself.

5. **Resolution** (`resolve_name`, indexer-backed) sums each bidder's
   burns to the name's script, picks the highest, reads that winner's
   latest claim tx for the current pointer, and returns
   `{name, script, address, owner, total_burned, claim_tx_id, claim_height}`.
   `address` is where the name points now; `owner` is the top burner.

## Methods

| Method | Scope | Purpose |
|---|---|---|
| `name_script` | read | Pure: derive a name's burn-script. |
| `name_claim` | spend | Burn `amount` to claim/out-bid; optional `target`. Policy-gated. |
| `resolve_name` | read | Resolve a name → current pointer (needs `--indexer-rpc`). |

```jsonc
// claim "alice" for yourself with a 1 EXFER burn-bid
name_claim { "name": "alice", "from": "<your addr>", "amount": 100000000 }

// out-bid and point "alice" at a different address
name_claim { "name": "alice", "from": "<your addr>", "amount": 200000000,
             "target": "<some other addr>" }

// resolve
resolve_name { "name": "alice" }
//  → { "address": "<pointer>", "owner": "<top burner>", "total_burned": 200000000, ... }
```

## Scope & limits (v1)

- **Forward only.** name → address. There is no address → name reverse
  enumeration.
- **Auction, not ownership.** A name is held by burn dominance, not
  permanently. Budget accordingly for names you care about.
- **Pointer needs the claim tx.** `resolve_name` fetches the winner's
  latest claim tx to read the declared `target`; if that tx can't be
  fetched/parsed it falls back to pointing at the owner.
- **Rich records wait for Phase 2.** When the chain's `datum` field is
  enabled, a name could carry an arbitrary record instead of a single
  address. The derivation domain (`EXFER-NAME-v1`) is versioned for that.
