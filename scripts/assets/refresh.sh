#!/usr/bin/env bash
# Rebuild every asset linked from EIPS/eip-8182.md and copy into the EIP repo.
#
# Inputs:  build/pool/pool_vkey.json       (snarkjs vk for the pool circuit)
#          build/pool/pool_final.zkey      (snarkjs zkey)
#          build/pool/pool_js/pool.wasm    (witness gen wasm)
#          build/auth_demo/*               (analogous for the demo auth circuit)
#
# Outputs: assets/eip-8182/pool_vk.bin
#          assets/eip-8182/pool_vk.sha256
#          assets/eip-8182/pool_verify_happy_path.json
#          assets/eip-8182/pool_verify_invalid_proof.json
#          assets/eip-8182/pool_verify_noncanonical_field.json
#          assets/eip-8182/shielded-pool-state.json
#          (the unchanged poseidon2_* files are left in place)
#
# Optional: EIP_ASSETS_DIR=/path/to/EIPs/assets/eip-8182 to also copy the
# refreshed bundle into the spec repo.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

POOL_DIR="build/pool"
ASSETS_LOCAL="assets/eip-8182"
mkdir -p "$ASSETS_LOCAL"

if [ ! -f "$POOL_DIR/pool_vkey.json" ]; then
  echo "ERR: $POOL_DIR/pool_vkey.json not found; run scripts/circuit/build_pool.sh first" >&2
  exit 1
fi

# 1. pool_vk.bin + sha256.
echo "==> pool_vk.bin"
node scripts/assets/vk_to_bin.js "$POOL_DIR/pool_vkey.json" "$ASSETS_LOCAL/pool_vk.bin"
shasum -a 256 "$ASSETS_LOCAL/pool_vk.bin" | awk '{print $1}' > "$ASSETS_LOCAL/pool_vk.sha256"

# 2. Three pool-verify vectors (typed inputs to ShieldedPool.verifyProof).
echo "==> pool-verify vectors"
# build_session.js writes build/integration/session.json — a fresh worst-case
# pool proof against the current zkey, plus its 21 public signals.
node scripts/integration/build_session.js >/dev/null
node scripts/assets/gen_pool_verify_vectors.js \
  "$POOL_DIR/pool_vkey.json" \
  "build/integration/session.json" \
  "$ASSETS_LOCAL"

# 3. Shielded-pool genesis state dump (depends on the deployed contract).
echo "==> shielded-pool-state.json"
forge script contracts/script/InstallSystemContracts.s.sol:InstallSystemContracts \
  --ffi --silent
cp build/shielded-pool-state.json "$ASSETS_LOCAL/shielded-pool-state.json"

# 4. Optionally mirror EIP-referenced files into the spec repo. The pool-verify
# vectors are NOT referenced from the spec — they exist only as integration
# fixtures for this reference implementation.
if [ -n "${EIP_ASSETS_DIR:-}" ]; then
  echo "==> mirroring to $EIP_ASSETS_DIR"
  cp "$ASSETS_LOCAL/pool_vk.bin" \
     "$ASSETS_LOCAL/pool_vk.sha256" \
     "$ASSETS_LOCAL/shielded-pool-state.json" \
     "$EIP_ASSETS_DIR/"
fi

echo
echo "done. asset bundle in $ASSETS_LOCAL"
ls -la "$ASSETS_LOCAL"
