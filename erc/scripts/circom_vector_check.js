// Cross-surface gate for the Circom pool circuit: builds witness inputs for
// the transfer and withdrawal scenarios in assets/derivation_vectors.json,
// runs snarkjs groth16 fullProve + verify, and asserts the produced public
// signals equal the vector publicInputs exactly (all 24, in order).
//
// Run after build_pool.sh:  node scripts/circom_vector_check.js

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ERC = path.resolve(HERE, "..");
const V = JSON.parse(fs.readFileSync(path.join(ERC, "assets/derivation_vectors.json"), "utf8"));
const WASM = path.join(ERC, "build/pool/pool_js/pool.wasm");
const ZKEY = path.join(ERC, "build/pool/pool_final.zkey");
const VKEY = JSON.parse(fs.readFileSync(path.join(ERC, "build/pool/pool_vkey.json"), "utf8"));

const dec = (h) => BigInt(h).toString();
const ZERO32 = Array(32).fill("0");

function witnessFor(scenario) {
  const s = V.scenarios[scenario];
  const sender = V.identities.sender;
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
    inNoteSecret: twoInputs ? [dec(inputs[0].noteSecret), dec(inputs[1].noteSecret)] : [dec(inputs[0].noteSecret), "0"],
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
  };
}

let failed = false;
for (const scenario of ["transfer", "withdrawal"]) {
  process.stdout.write(`==> ${scenario}: proving... `);
  const input = witnessFor(scenario);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  const ok = await snarkjs.groth16.verify(VKEY, publicSignals, proof);
  const expected = V.scenarios[scenario].publicInputs.map(dec);
  const match = JSON.stringify(publicSignals) === JSON.stringify(expected);
  console.log(`verify=${ok} publicInputs(24)Match=${match}`);
  if (!ok || !match) {
    failed = true;
    if (!match) {
      for (let i = 0; i < 24; i++) {
        if (publicSignals[i] !== expected[i]) {
          console.error(`  PI[${i}]: got ${publicSignals[i]} want ${expected[i]}`);
        }
      }
    }
  }
}

// Gated variant: same withdrawal witness but policyOperationDataHash set to
// transactOperationDataHash must ALSO prove (circuit permits 0 or opdata).
{
  process.stdout.write("==> withdrawal (policy-gated opdata): proving... ");
  const input = witnessFor("withdrawal");
  input.policyOperationDataHash = dec(V.scenarios.withdrawal.transactOperationDataHash);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  const ok = await snarkjs.groth16.verify(VKEY, publicSignals, proof);
  console.log(`verify=${ok}`);
  if (!ok) failed = true;
}

// Negative control: a wrong policyOperationDataHash must fail witness generation.
{
  process.stdout.write("==> negative control (bad policyOperationDataHash): ");
  const input = witnessFor("transfer");
  input.policyOperationDataHash = "12345";
  try {
    await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    console.log("PROVED — THIS IS A BUG");
    failed = true;
  } catch {
    console.log("rejected as expected");
  }
}

process.exit(failed ? 1 : 0);
