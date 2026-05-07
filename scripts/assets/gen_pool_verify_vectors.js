#!/usr/bin/env node
// Build the three EIP-8182 inline pool-proof verification test vectors.
//
//   pool_verify_happy_path.json       — valid proof, MUST verify (verifyProof returns true)
//   pool_verify_invalid_proof.json    — single-byte-flipped proof, MUST NOT verify
//   pool_verify_noncanonical_field.json — first publicInput set to p (>= p), MUST NOT verify
//
// Each vector contains the typed (pA, pB, pC, pubSignals) form consumed by
// ShieldedPool.verifyProof(uint[2], uint[2][2], uint[2], uint[21]) and the
// expected boolean result. Section 5.5 specifies inline verification using the
// VK embedded in the system contract bytecode.

const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

const usage =
  "usage: gen_pool_verify_vectors.js <vk.json> <session.json> <out_dir>\n" +
  "  vk.json:      build/pool/pool_vkey.json\n" +
  "  session.json: build/integration/session.json (written by build_session.js)";
if (process.argv.length < 5) {
  console.error(usage);
  process.exit(1);
}
const [, , vkPath, sessionPath, outDir] = process.argv;

const BN254_FR =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const vk = JSON.parse(fs.readFileSync(vkPath, "utf8"));
const session = JSON.parse(fs.readFileSync(sessionPath, "utf8"));
// session.json stores the canonical 256-byte proof under .pool.proofHex (the
// EIP-197 layout consumed by verifyProof). Reconstruct snarkjs's nested proof
// shape from the bytes so we can re-verify with snarkjs.groth16.verify.
const { proof: codec } = require("../../src/lib");
const proof = codec.bytesToSnarkjsProof(
  Buffer.from(session.pool.proofHex.replace(/^0x/, ""), "hex"),
);
const publics = session.pool.publicSignals;

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

// 256-byte canonical proof: A (G1, 64) || B (G2, 128) || C (G1, 64).
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

// Split the 256-byte proof into the typed Groth16 (pA, pB, pC) form.
function readWord(buf, offset) {
  const slice = buf.subarray(offset, offset + 32);
  return BigInt("0x" + slice.toString("hex"));
}
function splitProof(buf) {
  return {
    pA: [
      readWord(buf, 0).toString(),
      readWord(buf, 32).toString(),
    ],
    pB: [
      [readWord(buf, 64).toString(),  readWord(buf, 96).toString()],
      [readWord(buf, 128).toString(), readWord(buf, 160).toString()],
    ],
    pC: [
      readWord(buf, 192).toString(),
      readWord(buf, 224).toString(),
    ],
  };
}

const PUBLIC_INPUT_LABELS = [
  "noteCommitmentRoot",
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
];

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

  fs.mkdirSync(outDir, { recursive: true });

  // ----- Vector 1: happy path -----
  const happySplit = splitProof(proofBytes);
  const happyVec = {
    description:
      "Valid Groth16/BN254 proof for the EIP-8182 pool circuit. ShieldedPool.verifyProof MUST return true.",
    inputs: {
      ...happySplit,
      pubSignals: publicsBig.map((b) => b.toString()),
    },
    expectedResult: true,
    components: {
      proof: "0x" + proofBytes.toString("hex"),
      publicInputs: publicsBig.map((b) => "0x" + b.toString(16).padStart(64, "0")),
      publicInputsLabels: PUBLIC_INPUT_LABELS,
    },
  };
  fs.writeFileSync(
    path.join(outDir, "pool_verify_happy_path.json"),
    JSON.stringify(happyVec, null, 2) + "\n",
  );

  // ----- Vector 2: invalid proof (one bit flipped in pi_c.x) -----
  // Flip a bit deep inside C.x so the resulting field element stays < q (the
  // base-field modulus); the verifier MUST then fail subgroup/pairing check
  // and return false.
  const badProofBytes = Buffer.from(proofBytes);
  badProofBytes[200] ^= 0x01; // sits inside C.x (offset 192..223)
  const badProofObj = JSON.parse(JSON.stringify(proof));
  const cxHex = badProofBytes.subarray(192, 224).toString("hex");
  badProofObj.pi_c[0] = BigInt("0x" + cxHex).toString();
  const okBad = await verifyOK(badProofObj, publics);
  if (okBad)
    throw new Error("flipped-bit proof unexpectedly verified — choose another bit");
  const badSplit = splitProof(badProofBytes);
  const invalidVec = {
    description:
      "A valid proof with a single bit flipped inside pi_c.x. ShieldedPool.verifyProof MUST return false.",
    mutation:
      "byte index 200 of the 256-byte proof XORed with 0x01 (flips one bit of pi_c.x)",
    inputs: {
      ...badSplit,
      pubSignals: publicsBig.map((b) => b.toString()),
    },
    expectedResult: false,
    components: {
      proof: "0x" + badProofBytes.toString("hex"),
      publicInputs: publicsBig.map((b) => "0x" + b.toString(16).padStart(64, "0")),
    },
  };
  fs.writeFileSync(
    path.join(outDir, "pool_verify_invalid_proof.json"),
    JSON.stringify(invalidVec, null, 2) + "\n",
  );

  // ----- Vector 3: non-canonical public input -----
  // Set publicInputs[0] (noteCommitmentRoot) to exactly p (BN254 scalar field
  // order). Section 3.5 forbids public inputs >= p; the verifier MUST reject.
  const ncPublics = [...publicsBig];
  ncPublics[0] = BN254_FR;
  const ncVec = {
    description:
      "publicInputs[0] (noteCommitmentRoot) set to p (BN254 scalar field order). The verifier MUST reject any public input >= p (Section 3.5) and return false.",
    mutation: "publicInputs[0] := p_bn254_fr",
    inputs: {
      ...happySplit,
      pubSignals: ncPublics.map((b) => b.toString()),
    },
    expectedResult: false,
    components: {
      proof: "0x" + proofBytes.toString("hex"),
      publicInputs: ncPublics.map((b) => "0x" + b.toString(16).padStart(64, "0")),
    },
  };
  fs.writeFileSync(
    path.join(outDir, "pool_verify_noncanonical_field.json"),
    JSON.stringify(ncVec, null, 2) + "\n",
  );

  console.log("wrote 3 pool-verify vectors to", outDir);
  process.exit(0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
