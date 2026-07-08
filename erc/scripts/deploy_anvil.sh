#!/usr/bin/env bash
# Spins up a fresh anvil, deploys the full reference stack deterministically,
# and asserts the pinned runtime code hashes. With --keep, leaves anvil running.
#
# Usage: erc/scripts/deploy_anvil.sh [--keep] [--port 8545]
set -euo pipefail

ERC="$(cd "$(dirname "$0")/.." && pwd)"
PORT=8545
KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --keep) KEEP=1 ;;
    --port) PORT="$2"; shift ;;
  esac
  shift
done

ANVIL="${ANVIL:-$HOME/.foundry/bin/anvil}"
RPC="http://127.0.0.1:$PORT"

"$ANVIL" --port "$PORT" --silent &
ANVIL_PID=$!
cleanup() { if [ "$KEEP" = "0" ]; then kill "$ANVIL_PID" 2>/dev/null || true; fi }
trap cleanup EXIT

# wait for RPC
for i in $(seq 1 50); do
  if curl -s -o /dev/null "$RPC" -X POST -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'; then
    break
  fi
  sleep 0.2
done

node "$ERC/scripts/deploy_all.mjs" --rpc "$RPC"

if [ "$KEEP" = "1" ]; then
  echo "anvil left running on $RPC (pid $ANVIL_PID)"
  trap - EXIT
fi
