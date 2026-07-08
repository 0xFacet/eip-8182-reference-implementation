// Pool-circuit witness assembly (spec §8). Produces the exact input-signal JSON
// snarkjs.groth16.fullProve expects for build/pool — the same shape as
// scripts/lib/vector_witness.mjs witnessFor(), but built from live values.

import { type PublicInputs, publicInputsToArray } from "./derivations.ts";

const IDENTITY_TREE_DEPTH = 32;
const NOTE_TREE_DEPTH = 32;
const POLICY_SET_DEPTH = 8;

const d = (x: bigint): string => x.toString();
const zeros = (n: number): string[] => Array.from({ length: n }, () => "0");

export interface SpenderWitness {
  ownerNullifierKey: bigint;
  noteSecretSeed: bigint;
  /** uint160 of the authorizing Ethereum address. */
  authorizingAddress: bigint;
  noteSecretSeedHash: bigint;
  policySetCommitment: bigint;
  registrationBlinder: bigint;
  authDataCommitment: bigint;
  /** identity-tree leaf position (registry leafPosition). */
  identityLeafPosition: bigint;
  identitySiblings: bigint[]; // length 32
  /** policy-set slot holding the policyCommitment. */
  policySlot: bigint;
  policySetSiblings: bigint[]; // length 8
}

export interface InputNoteWitness {
  isReal: boolean;
  amount: bigint;
  noteSecret: bigint;
  leafIndex: bigint;
  siblings: bigint[]; // length 32 (ignored/zeros for phantom)
}

export interface OutputNoteWitness {
  isReal: boolean; // !isDummy
  amount: bigint;
  ownerNullifierKeyHash: bigint;
}

export interface PoolWitnessParams {
  publicInputs: PublicInputs;
  spender: SpenderWitness;
  /** 1 or 2 real inputs; a single input pads slot 1 with a phantom. */
  inputs: InputNoteWitness[];
  outputs: OutputNoteWitness[]; // exactly 3
  intent: {
    recipientOwnerNullifierKeyHash: bigint;
    feeNoteRecipientOwnerNullifierKeyHash: bigint;
    feeAmount: bigint;
    nonce: bigint;
    executionConstraintsFlags: bigint;
    lockedOutputBinding: [bigint, bigint, bigint];
    tokenAddress: bigint;
  };
  blindingFactor: bigint;
}

export interface PoolWitness {
  input: Record<string, unknown>;
  /** the 24 public inputs, ordered, as bigints. */
  publicInputs: bigint[];
}

/** Assemble the pool-circuit witness input JSON and the ordered public inputs. */
export function buildPoolWitnessInput(p: PoolWitnessParams): PoolWitness {
  const pi = p.publicInputs;
  if (p.outputs.length !== 3) throw new Error("pool witness requires exactly 3 output slots");
  if (p.inputs.length !== 1 && p.inputs.length !== 2) {
    throw new Error("pool witness requires 1 or 2 real inputs");
  }
  if (p.spender.identitySiblings.length !== IDENTITY_TREE_DEPTH) {
    throw new Error(`identitySiblings must be length ${IDENTITY_TREE_DEPTH}`);
  }
  if (p.spender.policySetSiblings.length !== POLICY_SET_DEPTH) {
    throw new Error(`policySetSiblings must be length ${POLICY_SET_DEPTH}`);
  }

  const twoInputs = p.inputs.length === 2;
  const in0 = p.inputs[0]!;
  const in1 = p.inputs[1];
  for (const inp of p.inputs) {
    if (inp.siblings.length !== NOTE_TREE_DEPTH) throw new Error(`input siblings must be length ${NOTE_TREE_DEPTH}`);
  }

  const input: Record<string, unknown> = {
    // ---- public inputs (spec §4 order) ----
    noteCommitmentRoot: d(pi.noteCommitmentRoot),
    nullifier0: d(pi.nullifier0),
    nullifier1: d(pi.nullifier1),
    noteBodyCommitment0: d(pi.noteBodyCommitment0),
    noteBodyCommitment1: d(pi.noteBodyCommitment1),
    noteBodyCommitment2: d(pi.noteBodyCommitment2),
    publicAmountOut: d(pi.publicAmountOut),
    publicRecipientAddress: d(pi.publicRecipientAddress),
    publicTokenAddress: d(pi.publicTokenAddress),
    intentReplayId: d(pi.intentReplayId),
    validUntilSeconds: d(pi.validUntilSeconds),
    executionChainId: d(pi.executionChainId),
    poolAddress: d(pi.poolAddress),
    identityRoot: d(pi.identityRoot),
    outputNoteDataHash0: d(pi.outputNoteDataHash0),
    outputNoteDataHash1: d(pi.outputNoteDataHash1),
    outputNoteDataHash2: d(pi.outputNoteDataHash2),
    authVerifier: d(pi.authVerifier),
    blindedAuthCommitment: d(pi.blindedAuthCommitment),
    transactionIntentDigest: d(pi.transactionIntentDigest),
    policyOperationDataHash: d(pi.policyOperationDataHash),
    policyDataHash: d(pi.policyDataHash),
    authorizedSubmitter: d(pi.authorizedSubmitter),
    downstreamActionCommitment: d(pi.downstreamActionCommitment),
    // ---- identity witnesses ----
    senderOwnerNullifierKey: d(p.spender.ownerNullifierKey),
    senderNoteSecretSeed: d(p.spender.noteSecretSeed),
    authorizingAddress: d(p.spender.authorizingAddress),
    noteSecretSeedHash: d(p.spender.noteSecretSeedHash),
    policySetCommitment: d(p.spender.policySetCommitment),
    leafPosition: d(p.spender.identityLeafPosition),
    identitySiblings: p.spender.identitySiblings.map(d),
    // ---- input notes ----
    inIsReal: twoInputs ? ["1", "1"] : ["1", "0"],
    inAmount: twoInputs ? [d(in0.amount), d(in1!.amount)] : [d(in0.amount), "0"],
    inNoteSecret: twoInputs ? [d(in0.noteSecret), d(in1!.noteSecret)] : [d(in0.noteSecret), "0"],
    inLeafIndex: twoInputs ? [d(in0.leafIndex), d(in1!.leafIndex)] : [d(in0.leafIndex), "0"],
    inSiblings: twoInputs ? [in0.siblings.map(d), in1!.siblings.map(d)] : [in0.siblings.map(d), zeros(NOTE_TREE_DEPTH)],
    // ---- output notes ----
    outIsReal: p.outputs.map((o) => (o.isReal ? "1" : "0")),
    outAmount: p.outputs.map((o) => d(o.amount)),
    outOwnerNullifierKeyHash: p.outputs.map((o) => d(o.ownerNullifierKeyHash)),
    outLockedOutputBinding: p.intent.lockedOutputBinding.map(d),
    // ---- intent + policy witnesses ----
    tokenAddress: d(p.intent.tokenAddress),
    recipientOwnerNullifierKeyHash: d(p.intent.recipientOwnerNullifierKeyHash),
    feeNoteRecipientOwnerNullifierKeyHash: d(p.intent.feeNoteRecipientOwnerNullifierKeyHash),
    feeAmount: d(p.intent.feeAmount),
    nonce: d(p.intent.nonce),
    executionConstraintsFlags: d(p.intent.executionConstraintsFlags),
    authDataCommitment: d(p.spender.authDataCommitment),
    blindingFactor: d(p.blindingFactor),
    registrationBlinder: d(p.spender.registrationBlinder),
    policySetLeafPosition: d(p.spender.policySlot),
    policySetSiblings: p.spender.policySetSiblings.map(d),
  };

  return { input, publicInputs: publicInputsToArray(pi) };
}
