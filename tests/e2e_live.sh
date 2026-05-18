#!/usr/bin/env bash
# End-to-end smoke test against a live exfer-walletd instance.
#
# Usage:
#   ./tests/e2e_live.sh [base_url]
#
# Defaults to https://exfer-node-stack.fly.dev. Supply an alternate URL
# (e.g. http://127.0.0.1:8080) to test a local wrapper instead.
#
# The script:
#   1. Verifies healthz returns "ok"
#   2. Verifies ping returns {ok: true}
#   3. Generates a fresh address (wrapper-only API)
#   4. Confirms the new address appears in list_addresses
#   5. Calls passthrough get_balance for the new address (expected 0)
#   6. Calls passthrough get_block_height (validates node-RPC plumbing)
#   7. Exercises the error path with an unknown method
#
# Exits 0 on success, non-zero on the first failure.

set -euo pipefail

URL="${1:-https://exfer-node-stack.fly.dev}"
AUTH="${WALLETD_AUTH_TOKEN:-}"
CURL_OPTS=(-sS --max-time 20)
if [ -n "$AUTH" ]; then
    CURL_OPTS+=(-H "Authorization: Bearer $AUTH")
fi
# Allow self-signed certs / DNS-override scenarios.
if [ -n "${E2E_RESOLVE:-}" ]; then
    CURL_OPTS+=(--resolve "$E2E_RESOLVE" -k)
fi

cyan()  { printf "\033[36m%s\033[0m\n" "$1"; }
green() { printf "\033[32m%s\033[0m\n" "$1"; }
red()   { printf "\033[31m%s\033[0m\n" "$1"; }

rpc() {
    local method="$1"; shift
    local params
    if [ $# -gt 0 ]; then
        params="$1"
    else
        params='{}'
    fi
    curl "${CURL_OPTS[@]}" -X POST "$URL/" \
        -H 'content-type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}"
}

assert_eq() {
    if [ "$1" != "$2" ]; then
        red "FAIL: expected '$2', got '$1'"
        exit 1
    fi
}
assert_has() {
    if ! echo "$1" | grep -q "$2"; then
        red "FAIL: response does not contain '$2'"
        echo "  response: $1"
        exit 1
    fi
}

cyan "[1/7] GET $URL/healthz"
HEALTH=$(curl "${CURL_OPTS[@]}" "$URL/healthz")
assert_eq "$(echo "$HEALTH" | tr -d '[:space:]')" "ok"
green "    ok"

cyan "[2/7] ping"
R=$(rpc ping); assert_has "$R" '"ok":true'
green "    ok"

cyan "[3/7] generate_address"
R=$(rpc generate_address)
ADDR=$(echo "$R" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['address'])")
PUBKEY=$(echo "$R" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['pubkey'])")
if [ "${#ADDR}" != 64 ] || [ "${#PUBKEY}" != 64 ]; then
    red "FAIL: address or pubkey not 64 hex chars"; exit 1
fi
green "    address=$ADDR"
green "    pubkey =$PUBKEY"

cyan "[4/7] list_addresses contains the new address"
R=$(rpc list_addresses)
assert_has "$R" "$ADDR"
green "    ok"

cyan "[5/7] get_balance for new address (passthrough)"
R=$(rpc get_balance "{\"address\":\"$ADDR\"}")
if echo "$R" | grep -q '"balance":0'; then
    green "    ok (balance=0 as expected)"
elif echo "$R" | grep -q 'upstream node unreachable'; then
    cyan "    SKIP (node still replaying / IBD in progress)"
else
    red "FAIL: unexpected get_balance response"
    echo "  $R"; exit 1
fi

cyan "[6/7] get_block_height (passthrough)"
R=$(rpc get_block_height)
if echo "$R" | grep -q '"height":'; then
    HEIGHT=$(echo "$R" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['height'])")
    green "    ok (tip height=$HEIGHT)"
elif echo "$R" | grep -q 'upstream node unreachable'; then
    cyan "    SKIP (node still replaying / IBD in progress)"
else
    red "FAIL: unexpected get_block_height response"
    echo "  $R"; exit 1
fi

cyan "[7/7] unknown method returns -32601"
R=$(rpc no_such_method)
assert_has "$R" '"code":-32601'
green "    ok"

green ""
green "All checks passed against $URL"
