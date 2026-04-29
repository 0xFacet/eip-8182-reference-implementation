#!/usr/bin/env bash
# Compile the demo auth circuit, run a Groth16 setup using the cached
# 2^12 ptau (the demo circuit fits comfortably; pool needs 2^19 — see
# build_pool.sh), and emit the verification key and Solidity verifier.
#
# Usage:
#   scripts/circuit/build_auth_demo.sh                 # compile + setup
#   FORCE=1 scripts/circuit/build_auth_demo.sh         # rebuild even if artifacts present
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

CIRCOM="${CIRCOM:-$ROOT/vendor/circom}"
SNARKJS="$ROOT/node_modules/.bin/snarkjs"
OUT="$ROOT/build/auth_demo"
PTAU_FILE="$ROOT/build/pot12_final.ptau"
VERIFIER_OUT="$ROOT/contracts/src/AuthDemoGroth16Verifier.sol"

mkdir -p "$OUT"

if [ ! -f "$PTAU_FILE" ]; then
  echo "ERR: $PTAU_FILE not found; the demo circuit reuses the cached pot12 ptau" >&2
  exit 1
fi

# 1. Compile auth_demo.circom.
if [ "${FORCE:-0}" = "1" ] || [ ! -f "$OUT/auth_demo.r1cs" ]; then
  echo "==> compiling auth_demo.circom (--O2)"
  "$CIRCOM" circuits/auth-demo/auth_demo.circom \
    -l circuits/common -l circuits/auth-demo \
    --r1cs --wasm --sym --O2 \
    -o "$OUT"
fi

# 2. Groth16 setup. Single contribution; for production this would be an MPC.
if [ "${FORCE:-0}" = "1" ] || [ ! -f "$OUT/auth_demo_final.zkey" ]; then
  echo "==> groth16 setup"
  "$SNARKJS" groth16 setup "$OUT/auth_demo.r1cs" "$PTAU_FILE" "$OUT/auth_demo_0.zkey"
  echo "==> single contribution"
  "$SNARKJS" zkey contribute "$OUT/auth_demo_0.zkey" "$OUT/auth_demo_final.zkey" \
    --name="dev-build" -e="$(date +%s) reference-implementation"
fi

# 3. Export verification key.
echo "==> export verification key"
"$SNARKJS" zkey export verificationkey "$OUT/auth_demo_final.zkey" "$OUT/auth_demo_vkey.json"

# 4. Export Solidity verifier and rename the contract symbol so the import in
# DemoAuthVerifier.sol resolves (snarkjs emits `Groth16Verifier` by default).
echo "==> export Solidity verifier"
"$SNARKJS" zkey export solidityverifier "$OUT/auth_demo_final.zkey" "$VERIFIER_OUT"
sed -i.bak 's/^contract Groth16Verifier {/contract AuthDemoGroth16Verifier {/' "$VERIFIER_OUT"
rm -f "$VERIFIER_OUT.bak"

echo
echo "build done: $OUT"
ls -la "$OUT"
