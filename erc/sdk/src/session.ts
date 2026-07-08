// buildTransactSession: assemble a fully-proven transact call from live values.
// Builds the intent, derives all notes, encrypts outputs, applies the §16.1
// policy, produces REAL Groth16 pool + UltraHonk auth proofs, and hard-checks
// that the two proofs agree on blindedAuthCommitment and transactionIntentDigest.

import {
  type IntentFields,
  type PublicInputs,
  blindedAuthCommitment as blindedAuthCommitmentOf,
  intentReplayId as intentReplayIdOf,
  noteBodyCommitment,
  nullifier as nullifierOf,
  noteCommitment as noteCommitmentOf,
  ownerCommitment as ownerCommitmentOf,
  ownerNullifierKeyHash as onkHashOf,
  phantomNullifier,
  policyOperationDigest as policyOperationDigestOf,
  publicInputsToArray,
  transactIntentFieldsHash,
  transactNoteSecret,
  transactOperationDataHash as transactOperationDataHashOf,
  transactPublicTransitionHash,
  transactionIntentDigest as transactionIntentDigestOf,
} from "./derivations.ts";
import { type SignedIntent, type TypedDataSigner, signPrivateTransferIntent } from "./eip712.ts";
import { encryptOutputNoteData } from "./envelope.ts";
import { keccakField, fieldToAddress } from "./field.ts";
import { encodeNotePayload, NOTE_PAYLOAD_KIND_TRANSACT } from "./payload.ts";
import { type HonkAuthProof, proveHonkAuth, provePoolGroth16 } from "./prover.ts";
import { buildPoolWitnessInput, type InputNoteWitness } from "./witness.ts";
import {
  DUMMY_OWNER_NULLIFIER_KEY_HASH,
  POLICY_APPLIES_TRANSFER,
  POLICY_APPLIES_WITHDRAWAL,
  POLICY_OPERATION_TRANSACT,
  TRANSFER_OP,
  WITHDRAWAL_OP,
} from "./generated/constants.ts";

export interface SessionSpender {
  account: TypedDataSigner;
  ownerNullifierKey: bigint;
  noteSecretSeed: bigint;
  noteSecretSeedHash: bigint;
  policySetCommitment: bigint;
  registrationBlinder: bigint;
  authDataCommitment: bigint;
  policySlot: bigint;
  policySetSiblings: bigint[]; // len 8
  identityLeafPosition: bigint;
  identitySiblings: bigint[]; // len 32
}

export interface SessionInput {
  amount: bigint;
  noteSecret: bigint;
  leafIndex: bigint;
  siblings: bigint[]; // len 32
}

export interface SessionOutput {
  ownerNullifierKeyHash: bigint; // DUMMY_OWNER_NULLIFIER_KEY_HASH for a dummy slot
  amount: bigint;
  tokenAddress: bigint;
  /** ML-KEM-768 receive key; required for real slots. */
  receiveKey?: Uint8Array;
  memo?: Uint8Array;
}

export interface SessionPolicy {
  applies: bigint;
  policyVerifier: bigint;
  signAttestation?: (policyOperationDigest: bigint) => Promise<`0x${string}`>;
  buildPolicyData?: (p: {
    policyOperationDigest: bigint;
    policyOperationDataHash: bigint;
    fields: IntentFields;
    publicInputs: PublicInputs;
  }) => Promise<`0x${string}`> | `0x${string}`;
}

export interface BuildTransactSessionParams {
  chainId: bigint;
  poolAddress: bigint;
  authVerifier: bigint;
  spender: SessionSpender;
  noteCommitmentRoot: bigint;
  identityRoot: bigint;
  inputs: SessionInput[]; // 1 or 2 real inputs
  outputs: SessionOutput[]; // exactly 3
  operation: "transfer" | "withdrawal";
  /** authorization-bound amount (slot0 amount for transfer, = publicAmountOut for withdrawal). */
  amount: bigint;
  /** note/intent token (0 = ETH). */
  tokenAddress: bigint;
  recipientOwnerNullifierKeyHash: bigint;
  feeNoteRecipientOwnerNullifierKeyHash: bigint;
  feeAmount: bigint;
  publicAmountOut: bigint;
  publicRecipientAddress: bigint;
  publicTokenAddress: bigint;
  nonce: bigint;
  validUntilSeconds: bigint;
  blindingFactor: bigint;
  executionConstraintsFlags?: bigint;
  lockedOutputBinding?: [bigint, bigint, bigint];
  /** Caller binding (spec §7.1): if nonzero, only this address may submit transact. Default 0. */
  authorizedSubmitter?: bigint;
  /** Opaque router-action commitment; requires authorizedSubmitter != 0 when nonzero. Default 0. */
  downstreamActionCommitment?: bigint;
  policy: SessionPolicy;
}

export interface SessionOutputNote {
  slot: 0 | 1 | 2;
  isReal: boolean;
  ownerNullifierKeyHash: bigint;
  amount: bigint;
  tokenAddress: bigint;
  noteSecret: bigint;
  ownerCommitment: bigint;
  noteBodyCommitment: bigint;
  outputNoteData: Uint8Array;
  outputNoteDataHash: bigint;
}

export interface TransactSession {
  publicInputs: PublicInputs;
  publicInputsArray: bigint[];
  poolProof: `0x${string}`;
  authProof: `0x${string}`;
  outputNoteData: [Uint8Array, Uint8Array, Uint8Array];
  policyData: `0x${string}`;
  intentReplayId: bigint;
  fields: IntentFields;
  signed: SignedIntent;
  auth: HonkAuthProof;
  outputs: SessionOutputNote[];
}

const EMPTY_BYTES = new Uint8Array(0);

export async function buildTransactSession(p: BuildTransactSessionParams): Promise<TransactSession> {
  if (p.outputs.length !== 3) throw new Error("session requires exactly 3 output slots");
  if (p.inputs.length !== 1 && p.inputs.length !== 2) throw new Error("session requires 1 or 2 inputs");

  const spenderOnkHash = onkHashOf(p.spender.ownerNullifierKey);
  const authorizingAddress = BigInt(p.spender.account.address);
  const lockedOutputBinding = p.lockedOutputBinding ?? [0n, 0n, 0n];
  const executionConstraintsFlags = p.executionConstraintsFlags ?? 0n;
  const authorizedSubmitter = p.authorizedSubmitter ?? 0n;
  const downstreamActionCommitment = p.downstreamActionCommitment ?? 0n;
  if (downstreamActionCommitment !== 0n && authorizedSubmitter === 0n) {
    throw new Error("downstreamActionCommitment != 0 requires authorizedSubmitter != 0 (spec §7.1)");
  }
  const operationKind = p.operation === "withdrawal" ? WITHDRAWAL_OP : TRANSFER_OP;

  const fields: IntentFields = {
    poolAddress: p.poolAddress,
    authVerifier: p.authVerifier,
    authorizingAddress,
    operationKind,
    tokenAddress: p.tokenAddress,
    recipientOwnerNullifierKeyHash: p.recipientOwnerNullifierKeyHash,
    amount: p.amount,
    feeNoteRecipientOwnerNullifierKeyHash: p.feeNoteRecipientOwnerNullifierKeyHash,
    feeAmount: p.feeAmount,
    publicRecipientAddress: p.publicRecipientAddress,
    authorizedSubmitter,
    downstreamActionCommitment,
    executionConstraintsFlags,
    lockedOutputBinding0: lockedOutputBinding[0],
    lockedOutputBinding1: lockedOutputBinding[1],
    lockedOutputBinding2: lockedOutputBinding[2],
    nonce: p.nonce,
    validUntilSeconds: p.validUntilSeconds,
    executionChainId: p.chainId,
  };
  const fieldsHash = transactIntentFieldsHash(fields);
  const replayId = intentReplayIdOf(p.spender.ownerNullifierKey, authorizingAddress, p.chainId, p.poolAddress, p.nonce);

  // ---- output notes + encryption ----
  const outputs: SessionOutputNote[] = [];
  for (let i = 0; i < 3; i++) {
    const spec = p.outputs[i]!;
    const isReal = spec.ownerNullifierKeyHash !== DUMMY_OWNER_NULLIFIER_KEY_HASH;
    const noteSecret = transactNoteSecret(p.spender.noteSecretSeed, p.chainId, p.poolAddress, replayId, i as 0 | 1 | 2);
    const oc = ownerCommitmentOf(p.chainId, p.poolAddress, spec.ownerNullifierKeyHash, noteSecret);
    const nbc = noteBodyCommitment(oc, spec.amount, spec.tokenAddress);
    let outputNoteData: Uint8Array = EMPTY_BYTES;
    if (isReal) {
      if (!spec.receiveKey) throw new Error(`output slot ${i} is real but has no receiveKey`);
      const payload = encodeNotePayload({
        kind: NOTE_PAYLOAD_KIND_TRANSACT,
        chainId: p.chainId,
        poolAddress: fieldToAddress(p.poolAddress, "poolAddress"),
        tokenAddress: fieldToAddress(spec.tokenAddress, "tokenAddress"),
        amount: spec.amount,
        ownerNullifierKeyHash: spec.ownerNullifierKeyHash,
        noteSecret,
        noteBodyCommitment: nbc,
        outputIndex: i,
        memo: spec.memo,
      });
      outputNoteData = await encryptOutputNoteData(spec.receiveKey, payload);
    }
    outputs.push({
      slot: i as 0 | 1 | 2,
      isReal,
      ownerNullifierKeyHash: spec.ownerNullifierKeyHash,
      amount: spec.amount,
      tokenAddress: spec.tokenAddress,
      noteSecret,
      ownerCommitment: oc,
      noteBodyCommitment: nbc,
      outputNoteData,
      outputNoteDataHash: keccakField(outputNoteData),
    });
  }

  // ---- input nullifiers ----
  const inputWitnesses: InputNoteWitness[] = [];
  const nullifiers: bigint[] = [];
  for (const inp of p.inputs) {
    const oc = ownerCommitmentOf(p.chainId, p.poolAddress, spenderOnkHash, inp.noteSecret);
    const nbc = noteBodyCommitment(oc, inp.amount, p.tokenAddress);
    const nc = noteCommitmentOf(p.chainId, p.poolAddress, nbc, inp.leafIndex);
    nullifiers.push(nullifierOf(p.chainId, p.poolAddress, nc, p.spender.ownerNullifierKey));
    inputWitnesses.push({ isReal: true, amount: inp.amount, noteSecret: inp.noteSecret, leafIndex: inp.leafIndex, siblings: inp.siblings });
  }
  const nullifier0 = nullifiers[0]!;
  const nullifier1 =
    p.inputs.length === 2
      ? nullifiers[1]!
      : phantomNullifier(p.chainId, p.poolAddress, p.spender.ownerNullifierKey, replayId, 1);

  const blinded = blindedAuthCommitmentOf(p.spender.authDataCommitment, p.blindingFactor);

  // ---- policy application (§16.1) ----
  const appliesBit = p.publicAmountOut === 0n ? POLICY_APPLIES_TRANSFER : POLICY_APPLIES_WITHDRAWAL;
  const gated = (p.policy.applies & appliesBit) !== 0n;

  // transitionHash needs the first 19 public inputs (through blindedAuthCommitment)
  // plus authorizedSubmitter + downstreamActionCommitment (indices 22/23);
  // fields 19..21 do not participate, so a placeholder-tail struct is exact here.
  const piForTransition: PublicInputs = {
    noteCommitmentRoot: p.noteCommitmentRoot,
    nullifier0,
    nullifier1,
    noteBodyCommitment0: outputs[0]!.noteBodyCommitment,
    noteBodyCommitment1: outputs[1]!.noteBodyCommitment,
    noteBodyCommitment2: outputs[2]!.noteBodyCommitment,
    publicAmountOut: p.publicAmountOut,
    publicRecipientAddress: p.publicRecipientAddress,
    publicTokenAddress: p.publicTokenAddress,
    intentReplayId: replayId,
    validUntilSeconds: p.validUntilSeconds,
    executionChainId: p.chainId,
    poolAddress: p.poolAddress,
    identityRoot: p.identityRoot,
    outputNoteDataHash0: outputs[0]!.outputNoteDataHash,
    outputNoteDataHash1: outputs[1]!.outputNoteDataHash,
    outputNoteDataHash2: outputs[2]!.outputNoteDataHash,
    authVerifier: p.authVerifier,
    blindedAuthCommitment: blinded,
    transactionIntentDigest: 0n,
    policyOperationDataHash: 0n,
    policyDataHash: 0n,
    authorizedSubmitter,
    downstreamActionCommitment,
  };
  const transitionHash = transactPublicTransitionHash(piForTransition);
  const transactOpDataHash = transactOperationDataHashOf(fieldsHash, transitionHash);

  let policyOperationDataHash = 0n;
  let policyData: `0x${string}` = "0x";
  if (gated) {
    policyOperationDataHash = transactOpDataHash;
    const digest = policyOperationDigestOf(
      p.chainId,
      p.poolAddress,
      p.policy.policyVerifier,
      POLICY_OPERATION_TRANSACT,
      policyOperationDataHash,
    );
    if (p.policy.buildPolicyData) {
      policyData = await p.policy.buildPolicyData({
        policyOperationDigest: digest,
        policyOperationDataHash,
        fields,
        publicInputs: piForTransition,
      });
    } else if (p.policy.signAttestation) {
      policyData = await p.policy.signAttestation(digest);
    } else {
      throw new Error("gated operation requires policy data");
    }
  }
  const policyDataHash = keccakField(policyData === "0x" ? EMPTY_BYTES : policyData);
  const transactionIntentDigest = transactionIntentDigestOf(fieldsHash, policyDataHash);

  const publicInputs: PublicInputs = {
    ...piForTransition,
    transactionIntentDigest,
    policyOperationDataHash,
    policyDataHash,
  };
  const publicInputsArray = publicInputsToArray(publicInputs);

  // ---- sign the intent (spender) ----
  const signed = await signPrivateTransferIntent(p.spender.account, fields, policyDataHash);

  // ---- witness + pool proof ----
  const { input } = buildPoolWitnessInput({
    publicInputs,
    spender: {
      ownerNullifierKey: p.spender.ownerNullifierKey,
      noteSecretSeed: p.spender.noteSecretSeed,
      authorizingAddress,
      noteSecretSeedHash: p.spender.noteSecretSeedHash,
      policySetCommitment: p.spender.policySetCommitment,
      registrationBlinder: p.spender.registrationBlinder,
      authDataCommitment: p.spender.authDataCommitment,
      identityLeafPosition: p.spender.identityLeafPosition,
      identitySiblings: p.spender.identitySiblings,
      policySlot: p.spender.policySlot,
      policySetSiblings: p.spender.policySetSiblings,
    },
    inputs: inputWitnesses,
    outputs: outputs.map((o) => ({ isReal: o.isReal, amount: o.amount, ownerNullifierKeyHash: o.ownerNullifierKeyHash })),
    intent: {
      recipientOwnerNullifierKeyHash: p.recipientOwnerNullifierKeyHash,
      feeNoteRecipientOwnerNullifierKeyHash: p.feeNoteRecipientOwnerNullifierKeyHash,
      feeAmount: p.feeAmount,
      nonce: p.nonce,
      executionConstraintsFlags,
      lockedOutputBinding,
      tokenAddress: p.tokenAddress,
    },
    blindingFactor: p.blindingFactor,
  });

  const pool = await provePoolGroth16(input);
  // Cross-check the prover's public signals match our derived public inputs.
  if (pool.publicSignals.length !== publicInputsArray.length) {
    throw new Error("pool public signal count mismatch");
  }
  for (let i = 0; i < publicInputsArray.length; i++) {
    if (BigInt(pool.publicSignals[i]!) !== publicInputsArray[i]!) {
      throw new Error(`pool public signal ${i} mismatch: ${pool.publicSignals[i]} != ${publicInputsArray[i]}`);
    }
  }

  // ---- auth proof (UltraHonk) ----
  const auth = proveHonkAuth({ fields, policyDataHash, blindingFactor: p.blindingFactor, signed });
  if (auth.publicSignals[0] !== publicInputs.blindedAuthCommitment) {
    throw new Error(`auth blindedAuthCommitment (${auth.publicSignals[0]}) != pool public[18] (${publicInputs.blindedAuthCommitment})`);
  }
  if (auth.publicSignals[1] !== publicInputs.transactionIntentDigest) {
    throw new Error(`auth transactionIntentDigest (${auth.publicSignals[1]}) != pool public[19] (${publicInputs.transactionIntentDigest})`);
  }

  return {
    publicInputs,
    publicInputsArray,
    poolProof: pool.proof,
    authProof: auth.proof,
    outputNoteData: [outputs[0]!.outputNoteData, outputs[1]!.outputNoteData, outputs[2]!.outputNoteData],
    policyData,
    intentReplayId: replayId,
    fields,
    signed,
    auth,
    outputs,
  };
}
