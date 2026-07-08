#!/usr/bin/env bash
# Compile the ERC pool circuit, run a Groth16 trusted setup using the cached
# Powers-of-Tau, and emit verification key + zkey + standalone verifier core.
#
# Usage:
#   erc/scripts/build_pool.sh                 # compile + setup, fast path
#   FORCE=1 erc/scripts/build_pool.sh         # rebuild even if artifacts present
#
# NOTE: single dev contribution with fixed entropy — NOT a production ceremony.
set -euo pipefail

ERC="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$ERC/.." && pwd)"
cd "$ERC"

CIRCOM="${CIRCOM:-$REPO/vendor/circom}"
SNARKJS="$ERC/node_modules/.bin/snarkjs"
OUT="$ERC/build/pool"
PTAU_BUCKET="https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_19.ptau"
PTAU_FILE="$REPO/build/pot19.ptau"
VERIFIER_OUT="$ERC/contracts/src/generated/PoolGroth16VerifierCore.sol"

mkdir -p "$OUT"

# 0. Regenerate constants so the circuit sees current domain tags.
node "$ERC/scripts/gen_constants.js" > /dev/null

# 1. Compile pool.circom (--O2 folds linear constraints).
if [ "${FORCE:-0}" = "1" ] || [ ! -f "$OUT/pool.r1cs" ]; then
  echo "==> compiling pool.circom (--O2)"
  "$CIRCOM" circuits/pool/pool.circom \
    -l circuits/common -l circuits/pool \
    --r1cs --wasm --sym --O2 \
    -o "$OUT"
fi

# 2. Powers-of-Tau: reuse the repo's cached pot19.
if [ ! -f "$PTAU_FILE" ]; then
  echo "==> downloading 2^19 ptau (~600 MB)"
  curl -L -o "$PTAU_FILE.tmp" "$PTAU_BUCKET"
  mv "$PTAU_FILE.tmp" "$PTAU_FILE"
fi

# 3. Groth16 trusted setup (per-circuit). Single deterministic dev
# contribution; a real deployment replaces this with an MPC ceremony.
if [ "${FORCE:-0}" = "1" ] || [ ! -f "$OUT/pool_final.zkey" ]; then
  echo "==> groth16 setup"
  "$SNARKJS" groth16 setup "$OUT/pool.r1cs" "$PTAU_FILE" "$OUT/pool_0.zkey"
  echo "==> single contribution (dev ceremony — replace with MPC for production)"
  "$SNARKJS" zkey contribute "$OUT/pool_0.zkey" "$OUT/pool_final.zkey" \
    --name="erc-dev-build" -e="erc-app-layer-private-transfers dev ceremony v1"
fi

# 4. Export verification key.
echo "==> export verification key"
"$SNARKJS" zkey export verificationkey "$OUT/pool_final.zkey" "$OUT/pool_vkey.json"

# 5. Canonical bin layout (spec §7.2 canonical verifier embeds this VK).
echo "==> writing canonical pool_vk.bin"
node "$ERC/scripts/vk_to_bin.cjs" "$OUT/pool_vkey.json" "$ERC/assets/pool_vk.bin"
shasum -a 256 "$ERC/assets/pool_vk.bin" | awk '{print $1}' > "$ERC/assets/pool_vk.sha256"

# 6. Export Solidity verifier core; the CanonicalPoolVerifier wrapper feeds it
# the decoded PublicInputs struct.
echo "==> export Solidity verifier core"
"$SNARKJS" zkey export solidityverifier "$OUT/pool_final.zkey" "$VERIFIER_OUT"
sed -i.bak 's/^contract Groth16Verifier {/contract PoolGroth16VerifierCore {/' "$VERIFIER_OUT"
rm -f "$VERIFIER_OUT.bak"

echo
echo "build done: $OUT"
ls -la "$OUT" | head
