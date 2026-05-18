#!/bin/bash
# Supervise the Exfer node and the wrapper in a single container.
#
# Two processes inside one VM keeps localhost communication trivial and
# matches what an exchange's single-server deployment looks like. If
# either process exits, we exit too so fly's machine supervisor can
# restart the whole thing cleanly.
#
# bash (not /bin/sh) because we rely on `wait -n` to react to whichever
# child exits first — Ubuntu's /bin/sh is dash and lacks that flag.

set -e

NODE_DATADIR="${NODE_DATADIR:-/data}"
NODE_RPC_BIND="${NODE_RPC_BIND:-127.0.0.1:9334}"
NODE_P2P_BIND="${NODE_P2P_BIND:-0.0.0.0:9333}"

WALLETD_BIND="${WALLETD_BIND:-0.0.0.0:8080}"
WALLETD_WALLET_DIR="${WALLETD_WALLET_DIR:-/wallets}"
EXFER_NODE_RPC="${EXFER_NODE_RPC:-http://${NODE_RPC_BIND}}"

echo "[entrypoint] starting exfer node on ${NODE_P2P_BIND} (RPC ${NODE_RPC_BIND})"
exfer node \
    --datadir   "${NODE_DATADIR}" \
    --bind      "${NODE_P2P_BIND}" \
    --rpc-bind  "${NODE_RPC_BIND}" \
    --repair-perms &
NODE_PID=$!

# Forward signals to children so SIGTERM from fly stops both cleanly.
trap 'echo "[entrypoint] forwarding TERM"; kill -TERM "${NODE_PID}" "${WALLETD_PID}" 2>/dev/null || true' TERM INT

# Give the node a moment to bind its RPC port. If it exits early we'll
# fall out of the wait below and the container restarts.
sleep 3

echo "[entrypoint] starting exfer-walletd on ${WALLETD_BIND} (talking to ${EXFER_NODE_RPC})"
export WALLETD_BIND
export WALLETD_WALLET_DIR
export EXFER_NODE_RPC
exfer-walletd &
WALLETD_PID=$!

# Wait on either child; exit as soon as one of them dies so the supervisor
# can replace the whole machine.
wait -n "${NODE_PID}" "${WALLETD_PID}"
EXIT_CODE=$?
echo "[entrypoint] a child exited with ${EXIT_CODE}; tearing down"
kill -TERM "${NODE_PID}" "${WALLETD_PID}" 2>/dev/null || true
wait || true
exit "${EXIT_CODE}"
