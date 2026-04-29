#!/usr/bin/env bash
# Compile the pool circuit, run a Groth16 trusted setup using a downloaded
# Powers-of-Tau, and emit verification key + zkey for proving.
#
# Usage:
#   scripts/circuit/build_pool.sh                 # compile + setup, fast path
#   FORCE=1 scripts/circuit/build_pool.sh         # rebuild even if artifacts present
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

CIRCOM="${CIRCOM:-$ROOT/vendor/circom}"
SNARKJS="$ROOT/node_modules/.bin/snarkjs"
OUT="$ROOT/build/pool"
PTAU_BUCKET="https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_19.ptau"
PTAU_FILE="$ROOT/build/pot19.ptau"
VERIFIER_OUT="$ROOT/contracts/src/PoolGroth16Verifier.sol"

mkdir -p "$OUT"

# 1. Compile pool.circom (use --O2 to fold linear constraints; the resulting
# 223K-non-linear-constraint R1CS fits in 2^19 ptau).
if [ "${FORCE:-0}" = "1" ] || [ ! -f "$OUT/pool.r1cs" ]; then
  echo "==> compiling pool.circom (--O2)"
  "$CIRCOM" circuits/pool/pool.circom \
    -l circuits/common -l circuits/pool \
    --r1cs --wasm --sym --O2 \
    -o "$OUT"
fi

# 2. Fetch Powers-of-Tau (one-time, 350 MB).
if [ ! -f "$PTAU_FILE" ]; then
  echo "==> downloading 2^19 ptau (~350 MB)"
  curl -L -o "$PTAU_FILE.tmp" "$PTAU_BUCKET"
  mv "$PTAU_FILE.tmp" "$PTAU_FILE"
fi

# 3. Groth16 trusted setup (per-circuit). Single contribution; for a real
# launch this would be replaced by an MPC ceremony with N participants.
if [ "${FORCE:-0}" = "1" ] || [ ! -f "$OUT/pool_final.zkey" ]; then
  echo "==> groth16 setup"
  "$SNARKJS" groth16 setup "$OUT/pool.r1cs" "$PTAU_FILE" "$OUT/pool_0.zkey"
  echo "==> single contribution (replace with MPC ceremony for production)"
  "$SNARKJS" zkey contribute "$OUT/pool_0.zkey" "$OUT/pool_final.zkey" \
    --name="dev-build" -e="$(date +%s) reference-implementation"
fi

# 4. Export verification key.
echo "==> export verification key"
"$SNARKJS" zkey export verificationkey "$OUT/pool_final.zkey" "$OUT/pool_vkey.json"

# 5. Convert to canonical bin layout consumed by the precompile.
echo "==> writing canonical pool_vk.bin"
node "$ROOT/scripts/assets/vk_to_bin.js" "$OUT/pool_vkey.json" "$OUT/pool_vk.bin"
shasum -a 256 "$OUT/pool_vk.bin" | awk '{print $1}' > "$OUT/pool_vk.sha256"

# 6. Export Solidity verifier and rename the snarkjs default symbol so
# MockPoolPrecompile's import resolves.
echo "==> export Solidity verifier"
"$SNARKJS" zkey export solidityverifier "$OUT/pool_final.zkey" "$VERIFIER_OUT"
sed -i.bak 's/^contract Groth16Verifier {/contract PoolGroth16Verifier {/' "$VERIFIER_OUT"
rm -f "$VERIFIER_OUT.bak"

echo
echo "build done: $OUT"
ls -la "$OUT"
