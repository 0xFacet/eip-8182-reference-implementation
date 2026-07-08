#!/usr/bin/env bash
# Compile the demo auth circuit (non-normative, dev/test), Groth16 setup with
# the cached 2^12 ptau, and emit the vkey + Solidity verifier core.
#
# Usage:
#   erc/scripts/build_auth_demo.sh                 # compile + setup
#   FORCE=1 erc/scripts/build_auth_demo.sh         # rebuild even if artifacts present
set -euo pipefail

ERC="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$ERC/.." && pwd)"
cd "$ERC"

CIRCOM="${CIRCOM:-$REPO/vendor/circom}"
SNARKJS="$ERC/node_modules/.bin/snarkjs"
OUT="$ERC/build/auth_demo"
PTAU_FILE="$REPO/build/pot12_final.ptau"
VERIFIER_OUT="$ERC/contracts/src/generated/AuthDemoGroth16VerifierCore.sol"

mkdir -p "$OUT"

if [ ! -f "$PTAU_FILE" ]; then
  echo "ERR: $PTAU_FILE not found; the demo circuit reuses the repo's cached pot12 ptau" >&2
  exit 1
fi

if [ "${FORCE:-0}" = "1" ] || [ ! -f "$OUT/auth_demo.r1cs" ]; then
  echo "==> compiling auth_demo.circom (--O2)"
  "$CIRCOM" circuits/auth-demo/auth_demo.circom \
    -l circuits/common -l circuits/auth-demo \
    --r1cs --wasm --sym --O2 \
    -o "$OUT"
fi

if [ "${FORCE:-0}" = "1" ] || [ ! -f "$OUT/auth_demo_final.zkey" ]; then
  echo "==> groth16 setup"
  "$SNARKJS" groth16 setup "$OUT/auth_demo.r1cs" "$PTAU_FILE" "$OUT/auth_demo_0.zkey"
  echo "==> single contribution (dev)"
  "$SNARKJS" zkey contribute "$OUT/auth_demo_0.zkey" "$OUT/auth_demo_final.zkey" \
    --name="erc-dev-build" -e="erc-app-layer-private-transfers auth demo dev v1"
fi

echo "==> export verification key"
"$SNARKJS" zkey export verificationkey "$OUT/auth_demo_final.zkey" "$OUT/auth_demo_vkey.json"

echo "==> export Solidity verifier core"
"$SNARKJS" zkey export solidityverifier "$OUT/auth_demo_final.zkey" "$VERIFIER_OUT"
sed -i.bak 's/^contract Groth16Verifier {/contract AuthDemoGroth16VerifierCore {/' "$VERIFIER_OUT"
rm -f "$VERIFIER_OUT.bak"

echo "build done: $OUT"
