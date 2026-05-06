#!/usr/bin/env node
// Build the three EIP-8182 PROOF_VERIFY_PRECOMPILE test vectors.
//
//   pool_precompile_happy_path.json       — valid proof, MUST return uint256(1)
//   pool_precompile_invalid_proof.json    — single-byte-flipped proof, MUST return uint256(0)
//   pool_precompile_noncanonical_field.json — first publicInput set to p (>= p), MUST return uint256(0)
//
// Each vector contains the raw 992-byte abi.encode(bytes proof, PublicInputs publicInputs)
// the precompile would receive on chain, the expected 32-byte output, and a
// human-readable breakdown.

const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const { AbiCoder } = require("ethers");

const usage =
  "usage: gen_precompile_vectors.js <vk.json> <proof.json> <public.json> <out_dir>";
if (process.argv.length < 6) {
  console.error(usage);
  process.exit(1);
}
const [, , vkPath, proofPath, publicsPath, outDir] = process.argv;

const BN254_FR =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const vk = JSON.parse(fs.readFileSync(vkPath, "utf8"));
const proof = JSON.parse(fs.readFileSync(proofPath, "utf8"));
const publics = JSON.parse(fs.readFileSync(publicsPath, "utf8"));

if (!Array.isArray(publics) || publics.length !== 21) {
  throw new Error(`expected 21 public signals, got ${publics.length}`);
}

function fpBytes(s) {
  const b = Buffer.alloc(32);
  let x = BigInt(s);
  if (x < 0n) throw new Error("negative");
  for (let i = 31; i >= 0; i--) {
    b[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) throw new Error("scalar > 256 bits");
  return b;
}
function g1Bytes(p) {
  if (BigInt(p[2]) !== 1n) throw new Error("g1 z != 1");
  return Buffer.concat([fpBytes(p[0]), fpBytes(p[1])]);
}
function g2BytesEvm(p) {
  // EIP-197 order: x.c1 || x.c0 || y.c1 || y.c0
  if (BigInt(p[2][0]) !== 1n || BigInt(p[2][1]) !== 0n) {
    throw new Error("g2 z != (1,0)");
  }
  return Buffer.concat([
    fpBytes(p[0][1]),
    fpBytes(p[0][0]),
    fpBytes(p[1][1]),
    fpBytes(p[1][0]),
  ]);
}

// 256-byte canonical proof: A (G1, 64) || B (G2, 128) || C (G1, 64)
const proofBytes = Buffer.concat([
  g1Bytes(proof.pi_a),
  g2BytesEvm(proof.pi_b),
  g1Bytes(proof.pi_c),
]);
if (proofBytes.length !== 256) throw new Error("proof bytes != 256");

const publicsBig = publics.map((s) => BigInt(s));
for (const x of publicsBig) {
  if (x >= BN254_FR) {
    throw new Error("source proof has non-canonical public input");
  }
}

const coder = AbiCoder.defaultAbiCoder();
// The PublicInputs struct is 21 static uint256, encoded inline.
function encodeInput(proofBuf, publicsArr) {
  return coder.encode(
    ["bytes", "tuple(" + Array(21).fill("uint256").join(",") + ")"],
    ["0x" + proofBuf.toString("hex"), publicsArr.map((b) => b.toString())],
  );
}

const happyInput = encodeInput(proofBytes, publicsBig);

// Sanity-verify the source proof against the VK with snarkjs before publishing.
async function verifyOK(p, pubs) {
  return await snarkjs.groth16.verify(
    vk,
    pubs.map((b) => b.toString()),
    p,
  );
}

(async () => {
  const okSource = await verifyOK(proof, publics);
  if (!okSource)
    throw new Error("source proof failed snarkjs verify — refusing to publish");

  // ----- Vector 1: happy path -----
  fs.mkdirSync(outDir, { recursive: true });
  const happyVec = {
    description:
      "Valid Groth16/BN254 proof for the EIP-8182 pool circuit. The PROOF_VERIFY_PRECOMPILE MUST return uint256(1).",
    input: happyInput,
    expectedOutput:
      "0x0000000000000000000000000000000000000000000000000000000000000001",
    components: {
      proof: "0x" + proofBytes.toString("hex"),
      publicInputs: publicsBig.map((b) => "0x" + b.toString(16).padStart(64, "0")),
      publicInputsLabels: [
        "historicalNoteRootAccumulatorRoot",
        "nullifier0",
        "nullifier1",
        "noteBodyCommitment0",
        "noteBodyCommitment1",
        "noteBodyCommitment2",
        "publicAmountOut",
        "publicRecipientAddress",
        "publicTokenAddress",
        "intentReplayId",
        "registryRoot",
        "validUntilSeconds",
        "executionChainId",
        "authPolicyRegistrationRoot",
        "authPolicyRevocationRoot",
        "outputNoteDataHash0",
        "outputNoteDataHash1",
        "outputNoteDataHash2",
        "authVerifier",
        "blindedAuthCommitment",
        "transactionIntentDigest",
      ],
    },
  };
  fs.writeFileSync(
    path.join(outDir, "pool_precompile_happy_path.json"),
    JSON.stringify(happyVec, null, 2) + "\n",
  );

  // ----- Vector 2: invalid proof (one bit flipped in pi_c.x) -----
  // Flip a bit deep inside C.x so the resulting field element stays < q (the
  // base-field modulus); the precompile MUST then fail subgroup/pairing check
  // and return zero.
  const badProofBytes = Buffer.from(proofBytes);
  badProofBytes[200] ^= 0x01; // sits inside C.x (offset 192..223)
  const badInput = encodeInput(badProofBytes, publicsBig);
  const badProofObj = JSON.parse(JSON.stringify(proof));
  // Reflect the bit flip in the JSON for transparency.
  // Recompute pi_c.x from badProofBytes.
  const cxHex = badProofBytes.subarray(192, 224).toString("hex");
  badProofObj.pi_c[0] = BigInt("0x" + cxHex).toString();
  const okBad = await verifyOK(badProofObj, publics);
  if (okBad)
    throw new Error("flipped-bit proof unexpectedly verified — choose another bit");
  const invalidVec = {
    description:
      "A valid proof with a single bit flipped inside pi_c.x. The pairing check MUST fail and the precompile MUST return uint256(0).",
    mutation:
      "byte index 200 of the 256-byte proof XORed with 0x01 (flips one bit of pi_c.x)",
    input: badInput,
    expectedOutput:
      "0x0000000000000000000000000000000000000000000000000000000000000000",
    components: {
      proof: "0x" + badProofBytes.toString("hex"),
      publicInputs: publicsBig.map((b) => "0x" + b.toString(16).padStart(64, "0")),
    },
  };
  fs.writeFileSync(
    path.join(outDir, "pool_precompile_invalid_proof.json"),
    JSON.stringify(invalidVec, null, 2) + "\n",
  );

  // ----- Vector 3: non-canonical public input -----
  // Set publicInputs[0] (historicalNoteRootAccumulatorRoot) to exactly p
  // (BN254 scalar field order). Section 3.5 forbids public inputs >= p; the
  // precompile MUST reject.
  const ncPublics = [...publicsBig];
  ncPublics[0] = BN254_FR;
  const ncInput = encodeInput(proofBytes, ncPublics);
  const ncVec = {
    description:
      "publicInputs[0] (historicalNoteRootAccumulatorRoot) set to p (BN254 scalar field order). The precompile MUST reject any public input >= p (Section 3.5) and return uint256(0).",
    mutation: "publicInputs[0] := p_bn254_fr",
    input: ncInput,
    expectedOutput:
      "0x0000000000000000000000000000000000000000000000000000000000000000",
    components: {
      proof: "0x" + proofBytes.toString("hex"),
      publicInputs: ncPublics.map((b) => "0x" + b.toString(16).padStart(64, "0")),
    },
  };
  fs.writeFileSync(
    path.join(outDir, "pool_precompile_noncanonical_field.json"),
    JSON.stringify(ncVec, null, 2) + "\n",
  );

  console.log("wrote 3 precompile vectors to", outDir);
  process.exit(0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
