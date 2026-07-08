#!/usr/bin/env bash
# Compile the Noir ECDSA auth circuit and generate the UltraHonk Solidity
# verifier used by EcdsaEip712AuthVerifier.
#
# Usage: erc/scripts/build_auth_honk.sh
set -euo pipefail

ERC="$(cd "$(dirname "$0")/.." && pwd)"
AUTH="$ERC/circuits-noir/auth"
NARGO="${NARGO:-$HOME/.nargo/bin/nargo}"
BB="${BB:-$HOME/.bb/bb}"

cd "$AUTH"

echo "==> nargo compile"
"$NARGO" compile

echo "==> bb write_vk (ultra_honk, evm)"
"$BB" write_vk --scheme ultra_honk -b target/auth.json -t evm -o target

echo "==> bb write_solidity_verifier"
"$BB" write_solidity_verifier --scheme ultra_honk -k target/vk -o target/HonkVerifier.sol

cp target/HonkVerifier.sol "$ERC/contracts/src/generated/HonkVerifier.sol"
echo "wrote contracts/src/generated/HonkVerifier.sol"
