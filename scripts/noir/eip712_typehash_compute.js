#!/usr/bin/env node
// Compute EIP-712 type hashes for the realistic auth circuit and print them
// as Noir `global [u8; 32]` literals ready to paste into circuits-noir/auth/src/main.nr.
//
// Usage:
//   node scripts/noir/eip712_typehash_compute.js

const { ethers } = require("ethers");

const NAME = "EIP-8182 Auth";
const VERSION = "1";

const DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

// Per EIP-8182 Section 6.4 (normative MUST): companion ERCs MUST authenticate
// blindingFactor via signature over the full signed intent struct, even though
// blindingFactor is excluded from the poseidon transactionIntentDigest. Hence
// the 15-field struct below.
const INTENT_TYPE =
  "TransactionIntent(" +
    "address authVerifier," +
    "address authorizingAddress," +
    "uint256 operationKind," +
    "address tokenAddress," +
    "address recipientAddress," +
    "uint256 amount," +
    "address feeRecipientAddress," +
    "uint256 feeAmount," +
    "uint256 executionConstraintsFlags," +
    "bytes32 lockedOutputBinding0," +
    "bytes32 lockedOutputBinding1," +
    "bytes32 lockedOutputBinding2," +
    "bytes32 nonce," +
    "uint256 validUntilSeconds," +
    "uint256 blindingFactor" +
  ")";

function k(s) {
  return ethers.keccak256(ethers.toUtf8Bytes(s));
}

const DOMAIN_TYPE_HASH = k(DOMAIN_TYPE);
const NAME_HASH = k(NAME);
const VERSION_HASH = k(VERSION);
const INTENT_TYPE_HASH = k(INTENT_TYPE);

function hexToNoirArray(hex) {
  const bytes = hex.replace(/^0x/, "").match(/.{2}/g);
  const lines = [];
  for (let i = 0; i < bytes.length; i += 8) {
    lines.push("    " + bytes.slice(i, i + 8).map(b => `0x${b}`).join(", ") + ",");
  }
  return lines.join("\n");
}

console.log("// String inputs (preserved alongside the hashes for reference):");
console.log(`//   NAME_TEXT     = ${JSON.stringify(NAME)}`);
console.log(`//   VERSION_TEXT  = ${JSON.stringify(VERSION)}`);
console.log(`//   DOMAIN_TYPE   = ${JSON.stringify(DOMAIN_TYPE)}`);
console.log(`//   INTENT_TYPE   = ${JSON.stringify(INTENT_TYPE)}`);
console.log();
console.log(`// keccak256("${DOMAIN_TYPE}")`);
console.log(`pub global DOMAIN_TYPE_HASH: [u8; 32] = [`);
console.log(hexToNoirArray(DOMAIN_TYPE_HASH));
console.log(`];`);
console.log();
console.log(`// keccak256(NAME_TEXT)`);
console.log(`pub global NAME_HASH: [u8; 32] = [`);
console.log(hexToNoirArray(NAME_HASH));
console.log(`];`);
console.log();
console.log(`// keccak256(VERSION_TEXT)`);
console.log(`pub global VERSION_HASH: [u8; 32] = [`);
console.log(hexToNoirArray(VERSION_HASH));
console.log(`];`);
console.log();
console.log(`// keccak256("${INTENT_TYPE}")`);
console.log(`pub global INTENT_TYPE_HASH: [u8; 32] = [`);
console.log(hexToNoirArray(INTENT_TYPE_HASH));
console.log(`];`);
console.log();

// Also write to a JSON sidecar that the prover-toml generator and the test
// can read, so the off-circuit signing matches by construction.
const fs = require("fs");
const path = require("path");
const out = {
  NAME, VERSION,
  DOMAIN_TYPE, INTENT_TYPE,
  DOMAIN_TYPE_HASH, NAME_HASH, VERSION_HASH, INTENT_TYPE_HASH,
};
const outDir = path.resolve(__dirname, "..", "..", "build", "noir_auth");
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, "eip712_typehashes.json"), JSON.stringify(out, null, 2));
console.error(`(also wrote ${path.join(outDir, "eip712_typehashes.json")})`);
