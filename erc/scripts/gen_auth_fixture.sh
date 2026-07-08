#!/usr/bin/env bash
# Generates the real UltraHonk auth-proof fixture for AuthVerifiers.t.sol:
#   contracts/test/fixtures/auth_honk_proof_transfer.json
#
# It pins the EIP-712 / ECDSA transfer-scenario witness (the same values the
# nargo `vector_test` pins from assets/derivation_vectors.json), runs
#   nargo execute  ->  bb prove --scheme ultra_honk -t evm
# and marshals bb's outputs into { proof: 0x..., publicSignals: [blinded,digest] }.
#
# The 16 pairing-point-object field elements are carried INSIDE target/proof;
# target/public_inputs holds exactly the circuit's 2 Noir outputs (2 x 32 bytes,
# big-endian) in order [blindedAuthCommitment, transactionIntentDigest].
#
# Usage: erc/scripts/gen_auth_fixture.sh
set -euo pipefail

ERC="$(cd "$(dirname "$0")/.." && pwd)"
export AUTH="$ERC/circuits-noir/auth"
export OUT="$ERC/contracts/test/fixtures/auth_honk_proof_transfer.json"
NARGO="${NARGO:-$HOME/.nargo/bin/nargo}"
BB="${BB:-$HOME/.bb/bb}"

cd "$AUTH"

# --- Prover.toml: transfer-scenario witness (mirrors src/vector_test.nr). ---
cat > Prover.toml <<'TOML'
execution_chain_id = "31337"
pool_address = "639406966332270026714112114313373821099470528513"
auth_verifier = "639406966332270026714112114313373821099470531073"
authorizing_address = "1390849295786071768276380950238675083608645509734"
operation_kind = "0"
token_address = "0"
recipient_owner_nullifier_key_hash = "7201541566185150869083227853997804359737874983565337061418212586637888715007"
amount = "700"
fee_note_recipient_owner_nullifier_key_hash = "0"
fee_amount = "0"
public_recipient_address = "0"
execution_constraints_flags = "0"
locked_output_binding0 = "0"
locked_output_binding1 = "0"
locked_output_binding2 = "0"
policy_data_hash = "1924180730567573949438414972962865885128629851683618892617351438379423999084"
valid_until_seconds = "4000000000"
blinding_factor = "177"
nonce = ["0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x99"]
pubkey_x = ["0x83","0x18","0x53","0x5b","0x54","0x10","0x5d","0x4a","0x7a","0xae","0x60","0xc0","0x8f","0xc4","0x5f","0x96","0x87","0x18","0x1b","0x4f","0xdf","0xc6","0x25","0xbd","0x1a","0x75","0x3f","0xa7","0x39","0x7f","0xed","0x75"]
pubkey_y = ["0x35","0x47","0xf1","0x1c","0xa8","0x69","0x66","0x46","0xf2","0xf3","0xac","0xb0","0x8e","0x31","0x01","0x6a","0xfa","0xc2","0x3e","0x63","0x0c","0x5d","0x11","0xf5","0x9f","0x61","0xfe","0xf5","0x7b","0x0d","0x2a","0xa5"]
signature = ["0xda","0xba","0xd5","0x91","0x6e","0x39","0x9f","0x37","0x64","0x1a","0x3f","0xcd","0xe1","0xce","0x66","0x8b","0x83","0x83","0xb9","0x9d","0x20","0x30","0x42","0xa9","0x5c","0x42","0xee","0xd3","0x86","0x4d","0x2b","0xf4","0x4e","0x17","0xaa","0x5d","0xf7","0x1a","0x40","0x4c","0xf5","0xf6","0x99","0x1e","0xca","0xac","0xb4","0xad","0xda","0xb8","0x26","0xd5","0xcb","0x9d","0x1e","0x97","0x0a","0x7d","0x3f","0x67","0x20","0xac","0x6c","0xe2"]
TOML

echo "==> nargo execute"
"$NARGO" execute witness

echo "==> bb prove (ultra_honk, evm)"
"$BB" prove --scheme ultra_honk -b target/auth.json -w target/witness.gz -o target -t evm

echo "==> bb verify (local sanity)"
"$BB" verify --scheme ultra_honk -k target/vk -p target/proof -i target/public_inputs -t evm

echo "==> marshal fixture"
node --input-type=module -e '
import fs from "node:fs";
const AUTH = process.env.AUTH;
const OUT = process.env.OUT;
const proof = fs.readFileSync(AUTH + "/target/proof");
const pub = fs.readFileSync(AUTH + "/target/public_inputs");
if (pub.length !== 64) throw new Error("expected 64-byte public_inputs, got " + pub.length);
const blinded = "0x" + pub.subarray(0, 32).toString("hex");
const digest  = "0x" + pub.subarray(32, 64).toString("hex");
const fixture = {
  scenario: "transfer",
  note: "Real UltraHonk auth proof. publicSignals=[blindedAuthCommitment, transactionIntentDigest]; pairing points are inside proof.",
  proof: "0x" + proof.toString("hex"),
  publicSignals: [blinded, digest],
};
fs.writeFileSync(OUT, JSON.stringify(fixture, null, 2) + "\n");
console.log("wrote " + OUT);
console.log("  proofLen =", proof.length, "bytes");
console.log("  blinded  =", blinded);
console.log("  digest   =", digest);
'

echo "done"
