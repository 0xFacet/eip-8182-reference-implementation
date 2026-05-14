#!/usr/bin/env bash
# One-command benchmark harness for EIP-8182. Builds the three transact
# sessions (transfer + withdraw_eth + withdraw_erc20), runs the gas benches
# in forge, then renders the combined report.
#
# Outputs:
#   build/bench/raw/<name>.json    (per-bench gas, written by Bench.t.sol)
#   build/bench/report.json        (combined report)
#   stdout: human-readable table
set -euo pipefail

cd "$(dirname "$0")/../.."

mkdir -p build/bench/raw

for mode in transfer withdraw_eth withdraw_erc20; do
  echo "==> Building $mode session (pool + Honk auth)"
  node scripts/integration/build_honk_session.js --mode="$mode"
done

# Build the Groth16-demo session too. The bench's gas measurements pull the
# Groth16 auth proof from this file, and the render script reads its timings
# (which use rapidsnark when RAPIDSNARK_PROVER is set) as the "fastest
# realistic" prove time for the table.
echo "==> Building Groth16 demo session (transfer mode)"
node scripts/integration/build_session.js

echo "==> Running gas benches via forge"
forge test --match-contract BenchTest --match-test "test_bench_" >/dev/null

echo "==> Rendering report"
node scripts/bench/render.js
