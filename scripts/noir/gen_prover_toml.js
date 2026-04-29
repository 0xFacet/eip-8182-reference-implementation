#!/usr/bin/env node
// Build circuits-noir/auth/Prover.toml from a coordinated set of intent +
// signing values. Produces a sidecar JSON that build_real_session.js (and
// the integration test) consume so the auth circuit's public outputs match
// the pool circuit's intent commitments.
//
// Usage:
//   node scripts/noir/gen_prover_toml.js [shared.json]
//
// Without `shared.json`, generates a deterministic test session with a fixed
// secp256k1 private key, the same intent fields the pool worst-case witness
// uses, and the realistic auth verifier address (0x000000...8182aaaa).

const fs = require("fs");
const path = require("path");
const { ethers } = require("ethers");

const ROOT = path.resolve(__dirname, "..", "..");
const PROVER_TOML = path.join(ROOT, "circuits-noir", "auth", "Prover.toml");
const TYPEHASHES = path.join(ROOT, "build", "noir_auth", "eip712_typehashes.json");
const SIDECAR = path.join(ROOT, "build", "noir_auth", "session_sidecar.json");

const { poseidon } = require(path.join(ROOT, "scripts", "witness", "poseidon2.js"));
const TAGS = JSON.parse(fs.readFileSync(path.join(ROOT, "build", "domain_tags.json"), "utf8"));
const T = Object.fromEntries(Object.entries(TAGS).map(([k, v]) => [k, BigInt(v)]));
// Local-only tag for the auth circuit's pubkey-derived authDataCommitment.
// keccak256("eip-8182.auth_data_commitment") mod p_bn254. Must match
// circuits-noir/common/src/constants.nr::AUTH_DATA_COMMITMENT_DOMAIN.
T.AUTH_DATA_COMMITMENT_DOMAIN =
  21705131131828257353191222797690334758731062146742465638606838220894884700291n;

const PRIVACY_POOL_ADDRESS = 0x81820n;
const REAL_AUTH_VERIFIER_ADDRESS = 0x8182AAAA8182AAAA8182AAAA8182AAAA8182AAAAn;

function bytesToBigInt(b) {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

function bigIntToBytes(v, len) {
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(v & 0xFFn);
    v >>= 8n;
  }
  return out;
}

function ethAddressFromPubkey(pkx, pky) {
  const concat = new Uint8Array(64);
  concat.set(pkx, 0);
  concat.set(pky, 32);
  const h = ethers.keccak256(concat);
  return BigInt("0x" + h.slice(2 + 24));
}

function splitBytes32(bytes32) {
  const hi = bytes32.slice(0, 16);
  const lo = bytes32.slice(16, 32);
  return [bytesToBigInt(hi), bytesToBigInt(lo)];
}

function defaultIntent(authVerifierAddr, authorizingAddress) {
  // Mirror gen_pool_witness_input.js's worst-case intent so the pool side
  // can be coordinated without surgery on its hardcoded values.
  return {
    auth_verifier:               authVerifierAddr,
    authorizing_address:         authorizingAddress,
    operation_kind:              0n,                              // TRANSFER_OP per pool gen
    token_address:               0x2222222222222222222222222222222222222222n,
    recipient_address:           0x3333333333333333333333333333333333333333n,
    amount:                      8n,                              // outAmount[0]
    fee_recipient_address:       0x4444444444444444444444444444444444444444n,
    fee_amount:                  2n,                              // outAmount[2]
    execution_constraints_flags: 7n,                              // worst-case (all 3 slots locked)
    locked_output_binding0:      0n,                              // overwritten with poseidon binding below
    locked_output_binding1:      0n,
    locked_output_binding2:      0n,
    nonce_bytes:                 (() => {
      // 32-byte nonce; pool gen used 0x9F3A1C7E5B2D4F86 as a Field, but here
      // we need a [u8; 32] nonce that decodes to that field via hi*2^128+lo.
      // The deterministic choice: zero-pad the field on the left to 32 bytes.
      const v = 0x9F3A1C7E5B2D4F86n;
      return bigIntToBytes(v, 32);
    })(),
    valid_until_seconds:         1735689600n,
    execution_chain_id:          1n,
  };
}

function lockedOutputBindings(intent) {
  // Computed by pool circuit per Section 9.11. For our purposes we just need
  // values that match what the pool side computes. We'll re-derive in
  // build_real_session.js once we have the output note bodies; here, allow
  // the caller to provide them via shared.json. If not provided, use 0 (the
  // bench-only mode). build_real_session.js overwrites with the real values.
  return [intent.locked_output_binding0, intent.locked_output_binding1, intent.locked_output_binding2];
}

function eip712Domain(chainId) {
  return {
    name: "EIP-8182 Auth",
    version: "1",
    chainId: Number(chainId),
    verifyingContract: ethers.getAddress("0x" + PRIVACY_POOL_ADDRESS.toString(16).padStart(40, "0")),
  };
}

// Per EIP-8182 Section 6.4 normative MUST: companion ERCs MUST authenticate
// blindingFactor via signature, even though it is excluded from
// transactionIntentDigest. Hence the trailing `blindingFactor` field.
const TYPES = {
  TransactionIntent: [
    { name: "authVerifier",                 type: "address" },
    { name: "authorizingAddress",           type: "address" },
    { name: "operationKind",                type: "uint256" },
    { name: "tokenAddress",                 type: "address" },
    { name: "recipientAddress",             type: "address" },
    { name: "amount",                       type: "uint256" },
    { name: "feeRecipientAddress",          type: "address" },
    { name: "feeAmount",                    type: "uint256" },
    { name: "executionConstraintsFlags",    type: "uint256" },
    { name: "lockedOutputBinding0",         type: "bytes32" },
    { name: "lockedOutputBinding1",         type: "bytes32" },
    { name: "lockedOutputBinding2",         type: "bytes32" },
    { name: "nonce",                        type: "bytes32" },
    { name: "validUntilSeconds",            type: "uint256" },
    { name: "blindingFactor",               type: "uint256" },
  ],
};

function makeIntentMessage(intent, lockedBindings, blindingFactor) {
  const addr = (v) => ethers.getAddress("0x" + v.toString(16).padStart(40, "0"));
  const b32  = (v) => "0x" + v.toString(16).padStart(64, "0");
  const b32FromBytes = (b) => "0x" + Buffer.from(b).toString("hex");
  return {
    authVerifier:                addr(intent.auth_verifier),
    authorizingAddress:          addr(intent.authorizing_address),
    operationKind:               intent.operation_kind,
    tokenAddress:                addr(intent.token_address),
    recipientAddress:            addr(intent.recipient_address),
    amount:                      intent.amount,
    feeRecipientAddress:         addr(intent.fee_recipient_address),
    feeAmount:                   intent.fee_amount,
    executionConstraintsFlags:   intent.execution_constraints_flags,
    lockedOutputBinding0:        b32(lockedBindings[0]),
    lockedOutputBinding1:        b32(lockedBindings[1]),
    lockedOutputBinding2:        b32(lockedBindings[2]),
    nonce:                       b32FromBytes(intent.nonce_bytes),
    validUntilSeconds:           intent.valid_until_seconds,
    blindingFactor:              blindingFactor,
  };
}

function tomlField(name, valueDecimal) {
  return `${name} = "${valueDecimal}"`;
}

function tomlBytes(name, bytes) {
  const items = Array.from(bytes).map(b => `"${b}"`).join(", ");
  return `${name} = [${items}]`;
}

function writeProverToml(toml) {
  fs.mkdirSync(path.dirname(PROVER_TOML), { recursive: true });
  fs.writeFileSync(PROVER_TOML, toml);
}

async function main() {
  const argPath = process.argv[2];
  let shared;
  if (argPath) {
    shared = JSON.parse(fs.readFileSync(argPath, "utf8"));
  } else {
    shared = {};
  }

  // Deterministic test private key.
  const privKeyHex = shared.private_key_hex
    || "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
  const wallet = new ethers.Wallet(privKeyHex);
  // Uncompressed public key (0x04 || X || Y), strip leading byte.
  const uncompressed = ethers.SigningKey.computePublicKey(privKeyHex, false); // 0x04 prefix
  const pubBytes = ethers.getBytes(uncompressed).slice(1);
  const pkx = pubBytes.slice(0, 32);
  const pky = pubBytes.slice(32, 64);

  const authorizingAddress = ethAddressFromPubkey(pkx, pky);
  // Sanity: the wallet's address must equal the keccak-derived value we use.
  const walletAddr = BigInt(wallet.address);
  if (walletAddr !== authorizingAddress) {
    throw new Error(`mismatch: wallet=${walletAddr.toString(16)} derived=${authorizingAddress.toString(16)}`);
  }

  const authVerifierAddr = shared.auth_verifier_addr
    ? BigInt(shared.auth_verifier_addr)
    : REAL_AUTH_VERIFIER_ADDRESS;

  let intent;
  if (shared.intent) {
    // Coerce all fields to BigInt; nonce_bytes stays an array of small ints.
    const i = shared.intent;
    intent = {
      auth_verifier:               BigInt(i.auth_verifier),
      authorizing_address:         BigInt(i.authorizing_address),
      operation_kind:              BigInt(i.operation_kind),
      token_address:               BigInt(i.token_address),
      recipient_address:           BigInt(i.recipient_address),
      amount:                      BigInt(i.amount),
      fee_recipient_address:       BigInt(i.fee_recipient_address),
      fee_amount:                  BigInt(i.fee_amount),
      execution_constraints_flags: BigInt(i.execution_constraints_flags),
      locked_output_binding0:      BigInt(i.locked_output_binding0 ?? 0),
      locked_output_binding1:      BigInt(i.locked_output_binding1 ?? 0),
      locked_output_binding2:      BigInt(i.locked_output_binding2 ?? 0),
      nonce_bytes:                 Uint8Array.from(i.nonce_bytes),
      valid_until_seconds:         BigInt(i.valid_until_seconds),
      execution_chain_id:          BigInt(i.execution_chain_id),
    };
  } else {
    intent = defaultIntent(authVerifierAddr, authorizingAddress);
  }
  const lockedBindings = shared.locked_output_bindings
    ? shared.locked_output_bindings.map(BigInt)
    : lockedOutputBindings(intent);

  // The signature must authenticate `blindingFactor` per Section 6.4. Compute
  // it here so the EIP-712 message can include it.
  const blinding_factor = shared.blinding_factor
    ? BigInt(shared.blinding_factor)
    : 0xB17ED15ABCDEF0123456789ABCDEF01n;

  const message = makeIntentMessage(intent, lockedBindings, blinding_factor);
  const domain = eip712Domain(intent.execution_chain_id);

  // EIP-712 typed-data signing hash, per ethers.
  const digestHex = ethers.TypedDataEncoder.hash(domain, TYPES, message);
  const digest = ethers.getBytes(digestHex);

  // Sign the digest. ethers's signMessage prefixes; signDigest does not.
  const sigObj = wallet.signingKey.sign(digestHex);
  // sigObj is a Signature with r, s, v. Concatenate r||s, 64 bytes.
  const rBytes = ethers.getBytes(sigObj.r);
  const sBytes = ethers.getBytes(sigObj.s);
  const signature = new Uint8Array(64);
  signature.set(rBytes, 0);
  signature.set(sBytes, 32);

  // Cross-check: verifyingKey.recoverPublicKey should give back our pubkey.
  const recovered = ethers.SigningKey.recoverPublicKey(digestHex, sigObj);
  const recoveredBytes = ethers.getBytes(recovered).slice(1);
  for (let i = 0; i < 64; i++) {
    if (recoveredBytes[i] !== pubBytes[i]) {
      throw new Error("ECDSA recovery sanity check failed");
    }
  }

  // Compute expected public outputs (matching circuit).
  // auth_data_commitment now includes AUTH_DATA_COMMITMENT_DOMAIN as the first
  // input -- defense-in-depth, matches privacy_pool_common::crypto.
  const [pkx_hi, pkx_lo] = splitBytes32(pkx);
  const [pky_hi, pky_lo] = splitBytes32(pky);
  const auth_data_commitment = poseidon(
    T.AUTH_DATA_COMMITMENT_DOMAIN,
    pkx_hi, pkx_lo, pky_hi, pky_lo,
  );

  const blinded_auth_commitment = poseidon(
    T.BLINDED_AUTH_COMMITMENT_DOMAIN,
    auth_data_commitment,
    blinding_factor,
  );

  // Decode the 32-byte nonce as the field element the circuit will compute.
  const nonceField = bytesToBigInt(intent.nonce_bytes);

  const transaction_intent_digest = poseidon(
    T.TRANSACTION_INTENT_DIGEST_DOMAIN,
    intent.auth_verifier,
    intent.authorizing_address,
    intent.operation_kind,
    intent.token_address,
    intent.recipient_address,
    intent.amount,
    intent.fee_recipient_address,
    intent.fee_amount,
    intent.execution_constraints_flags,
    lockedBindings[0],
    lockedBindings[1],
    lockedBindings[2],
    nonceField,
    intent.valid_until_seconds,
    intent.execution_chain_id,
  );

  // -- Prover.toml --
  const lines = [
    tomlField("auth_verifier",                intent.auth_verifier.toString()),
    tomlField("authorizing_address",          intent.authorizing_address.toString()),
    tomlField("operation_kind",               intent.operation_kind.toString()),
    tomlField("token_address",                intent.token_address.toString()),
    tomlField("recipient_address",            intent.recipient_address.toString()),
    tomlField("amount",                       intent.amount.toString()),
    tomlField("fee_recipient_address",        intent.fee_recipient_address.toString()),
    tomlField("fee_amount",                   intent.fee_amount.toString()),
    tomlField("execution_constraints_flags",  intent.execution_constraints_flags.toString()),
    tomlField("locked_output_binding0",       lockedBindings[0].toString()),
    tomlField("locked_output_binding1",       lockedBindings[1].toString()),
    tomlField("locked_output_binding2",       lockedBindings[2].toString()),
    tomlBytes("nonce",                        intent.nonce_bytes),
    tomlField("valid_until_seconds",          intent.valid_until_seconds.toString()),
    tomlField("execution_chain_id",           intent.execution_chain_id.toString()),
    tomlBytes("pubkey_x",                     pkx),
    tomlBytes("pubkey_y",                     pky),
    tomlBytes("signature",                    signature),
    tomlField("blinding_factor",              blinding_factor.toString()),
  ];
  writeProverToml(lines.join("\n") + "\n");

  // -- Sidecar JSON for build_real_session.js + integration test --
  const sidecar = {
    private_key_hex: privKeyHex,
    pubkey_x_hex: ethers.hexlify(pkx),
    pubkey_y_hex: ethers.hexlify(pky),
    pubkey_eth_address: "0x" + authorizingAddress.toString(16).padStart(40, "0"),
    auth_verifier_address: "0x" + intent.auth_verifier.toString(16).padStart(40, "0"),
    eip712_digest_hex: digestHex,
    signature_hex: ethers.hexlify(signature),
    blinding_factor_hex: "0x" + blinding_factor.toString(16),
    auth_data_commitment_dec: auth_data_commitment.toString(),
    blinded_auth_commitment_dec: blinded_auth_commitment.toString(),
    transaction_intent_digest_dec: transaction_intent_digest.toString(),
    nonce_bytes_hex: ethers.hexlify(intent.nonce_bytes),
    locked_output_bindings_dec: lockedBindings.map(b => b.toString()),
    intent_decimal: {
      auth_verifier:               intent.auth_verifier.toString(),
      authorizing_address:         intent.authorizing_address.toString(),
      operation_kind:              intent.operation_kind.toString(),
      token_address:               intent.token_address.toString(),
      recipient_address:           intent.recipient_address.toString(),
      amount:                      intent.amount.toString(),
      fee_recipient_address:       intent.fee_recipient_address.toString(),
      fee_amount:                  intent.fee_amount.toString(),
      execution_constraints_flags: intent.execution_constraints_flags.toString(),
      valid_until_seconds:         intent.valid_until_seconds.toString(),
      execution_chain_id:          intent.execution_chain_id.toString(),
    },
  };
  fs.mkdirSync(path.dirname(SIDECAR), { recursive: true });
  fs.writeFileSync(SIDECAR, JSON.stringify(sidecar, null, 2));

  console.log("wrote", PROVER_TOML);
  console.log("wrote", SIDECAR);
  console.log("  authorizing_address       =", "0x" + authorizingAddress.toString(16).padStart(40, "0"));
  console.log("  auth_data_commitment      =", auth_data_commitment.toString());
  console.log("  blinded_auth_commitment   =", blinded_auth_commitment.toString());
  console.log("  transaction_intent_digest =", transaction_intent_digest.toString());
}

main().catch(e => { console.error(e); process.exit(1); });
