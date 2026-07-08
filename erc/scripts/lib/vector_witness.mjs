// Builds pool-circuit witness input JSON for the scenarios in
// assets/derivation_vectors.json. Shared by circom_vector_check.js and
// gen_pool_fixtures.js.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ERC = path.resolve(HERE, "../..");

export const VECTORS = JSON.parse(
  fs.readFileSync(path.join(ERC, "assets/derivation_vectors.json"), "utf8"),
);

export const dec = (h) => BigInt(h).toString();
const ZERO32 = Array(32).fill("0");

export function witnessFor(scenario, overrides = {}) {
  const s = VECTORS.scenarios[scenario];
  const sender = VECTORS.identities.sender;
  const pi = s.publicInputs.map(dec);
  const inputs = s.inputs;
  const twoInputs = inputs.length === 2;

  return {
    // public
    noteCommitmentRoot: pi[0],
    nullifier0: pi[1],
    nullifier1: pi[2],
    noteBodyCommitment0: pi[3],
    noteBodyCommitment1: pi[4],
    noteBodyCommitment2: pi[5],
    publicAmountOut: pi[6],
    publicRecipientAddress: pi[7],
    publicTokenAddress: pi[8],
    intentReplayId: pi[9],
    validUntilSeconds: pi[10],
    executionChainId: pi[11],
    poolAddress: pi[12],
    identityRoot: pi[13],
    outputNoteDataHash0: pi[14],
    outputNoteDataHash1: pi[15],
    outputNoteDataHash2: pi[16],
    authVerifier: pi[17],
    blindedAuthCommitment: pi[18],
    transactionIntentDigest: pi[19],
    policyOperationDataHash: pi[20],
    policyDataHash: pi[21],
    authorizedSubmitter: pi[22],
    downstreamActionCommitment: pi[23],
    // witnesses
    senderOwnerNullifierKey: dec(sender.ownerNullifierKey),
    senderNoteSecretSeed: dec(sender.noteSecretSeed),
    authorizingAddress: dec(sender.address),
    noteSecretSeedHash: dec(sender.noteSecretSeedHash),
    policySetCommitment: dec(sender.policySetCommitment),
    leafPosition: sender.leafPosition,
    identitySiblings: sender.identitySiblings.map(dec),
    inIsReal: twoInputs ? ["1", "1"] : ["1", "0"],
    inAmount: twoInputs ? [inputs[0].amount, inputs[1].amount] : [inputs[0].amount, "0"],
    inNoteSecret: twoInputs
      ? [dec(inputs[0].noteSecret), dec(inputs[1].noteSecret)]
      : [dec(inputs[0].noteSecret), "0"],
    inLeafIndex: twoInputs ? [inputs[0].leafIndex, inputs[1].leafIndex] : [inputs[0].leafIndex, "0"],
    inSiblings: twoInputs
      ? [inputs[0].merkleSiblings.map(dec), inputs[1].merkleSiblings.map(dec)]
      : [inputs[0].merkleSiblings.map(dec), ZERO32],
    outIsReal: s.outputs.map((o) => (o.isDummy ? "0" : "1")),
    outAmount: s.outputs.map((o) => o.amount),
    outOwnerNullifierKeyHash: s.outputs.map((o) => dec(o.ownerNullifierKeyHash)),
    outLockedOutputBinding: ["0", "0", "0"],
    tokenAddress: "0",
    recipientOwnerNullifierKeyHash: dec(s.intentFields.recipientOwnerNullifierKeyHash),
    feeNoteRecipientOwnerNullifierKeyHash: dec(s.intentFields.feeNoteRecipientOwnerNullifierKeyHash),
    feeAmount: dec(s.intentFields.feeAmount),
    nonce: dec(s.nonce),
    executionConstraintsFlags: dec(s.intentFields.executionConstraintsFlags),
    authDataCommitment: dec(s.authDataCommitment),
    blindingFactor: dec(s.blindingFactor),
    registrationBlinder: dec(sender.registrationBlinder),
    policySetLeafPosition: sender.policySlot,
    policySetSiblings: sender.policySetSiblings.map(dec),
    ...overrides,
  };
}

// snarkjs proof JSON -> canonical 256-byte layout (spec section 7.2):
//   A.x || A.y || B.x.c1 || B.x.c0 || B.y.c1 || B.y.c0 || C.x || C.y
export function proofToBytes(proof) {
  const fp = (v) => BigInt(v).toString(16).padStart(64, "0");
  if (BigInt(proof.pi_a[2]) !== 1n) throw new Error("g1 z != 1");
  if (BigInt(proof.pi_c[2]) !== 1n) throw new Error("g1 z != 1");
  if (BigInt(proof.pi_b[2][0]) !== 1n || BigInt(proof.pi_b[2][1]) !== 0n) throw new Error("g2 z != (1,0)");
  return (
    "0x" +
    fp(proof.pi_a[0]) +
    fp(proof.pi_a[1]) +
    fp(proof.pi_b[0][1]) +
    fp(proof.pi_b[0][0]) +
    fp(proof.pi_b[1][1]) +
    fp(proof.pi_b[1][0]) +
    fp(proof.pi_c[0]) +
    fp(proof.pi_c[1])
  );
}
