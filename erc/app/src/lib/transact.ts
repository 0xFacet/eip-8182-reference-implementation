// Browser transact builder. Reproduces the pre-proving half of the SDK's
// buildTransactSession: derive output notes, encrypt to recipients, compute the
// 24 public inputs, apply the §16.1 policy, sign the EIP-712 intent, and assemble
// BOTH witness inputs (pool Groth16 signals + Noir auth circuit map). Proving
// itself runs in the Web Worker — this stays on the main thread because it needs
// the wallet signature.

import type { Hex } from "viem";
import {
  type IntentFields,
  type PublicInputs,
  blindedAuthCommitment as blindedAuthCommitmentOf,
  identityLeaf as identityLeafOf,
  intentReplayId as intentReplayIdOf,
  noteBodyCommitment,
  noteCommitment as noteCommitmentOf,
  nullifier as nullifierOf,
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
} from "../../../sdk/src/derivations.ts";
import { keccakField, fieldToAddress } from "../../../sdk/src/field.ts";
import { bytesToHex } from "../../../sdk/src/bytes.ts";
import { encryptOutputNoteData } from "../../../sdk/src/envelope.ts";
import { encodeNotePayload, NOTE_PAYLOAD_KIND_TRANSACT } from "../../../sdk/src/payload.ts";
import { AppendOnlyTree, SparseTree } from "../../../sdk/src/trees.ts";
import {
  DUMMY_OWNER_NULLIFIER_KEY_HASH,
  POLICY_APPLIES_TRANSFER,
  POLICY_APPLIES_WITHDRAWAL,
  POLICY_OPERATION_TRANSACT,
  TRANSFER_OP,
  WITHDRAWAL_OP,
} from "../../../sdk/src/generated/constants.ts";
import type { SignedIntent } from "../../../sdk/src/eip712.ts";

const EMPTY = new Uint8Array(0);

export interface BuilderSpender {
  authVerifier: bigint;
  ownerNullifierKey: bigint;
  noteSecretSeed: bigint;
  noteSecretSeedHash: bigint;
  identityRoot: bigint;
  authorizingAddress: bigint;
  authDataCommitment: bigint;
  policySetCommitment: bigint;
  registrationBlinder: bigint;
  policySlot: bigint;
  policySetSiblings: bigint[];
  identityLeafPosition: bigint;
  identitySiblings: bigint[];
}

export interface BuilderInput {
  amount: bigint;
  noteSecret: bigint;
  leafIndex: bigint;
  siblings: bigint[];
}

export interface BuilderOutput {
  ownerNullifierKeyHash: bigint;
  amount: bigint;
  tokenAddress: bigint;
  receiveKey?: Uint8Array;
  memo?: Uint8Array;
}

export interface BuilderPolicy {
  applies: bigint;
  policyVerifier: bigint;
  signAttestation?: (policyOperationDigest: bigint) => Promise<Hex>;
  buildPolicyData?: (p: {
    policyOperationDigest: bigint;
    policyOperationDataHash: bigint;
    fields: IntentFields;
    publicInputs: PublicInputs;
  }) => Promise<Hex> | Hex;
}

export interface BuildTransactParams {
  chainId: bigint;
  poolAddress: bigint;
  authVerifier: bigint;
  spender: BuilderSpender;
  noteCommitmentRoot: bigint;
  identityRoot: bigint;
  inputs: BuilderInput[];
  outputs: BuilderOutput[];
  operation: "transfer" | "withdrawal";
  amount: bigint;
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
  /** §7.1 named-submitter binding; 0 = bearer (anyone may submit). Default 0. */
  authorizedSubmitter?: bigint;
  /** Opaque router-action commitment; requires authorizedSubmitter != 0 when nonzero. Default 0. */
  downstreamActionCommitment?: bigint;
  policy: BuilderPolicy;
  signIntent: (fields: IntentFields, policyDataHash: bigint) => Promise<SignedIntent>;
}

export interface TransactBundle {
  poolWitnessInput: Record<string, unknown>;
  authCircuitInput: Record<string, unknown>;
  publicInputs: PublicInputs;
  publicInputsArray: bigint[];
  outputNoteData: [Hex, Hex, Hex];
  policyData: Hex;
  intentReplayId: bigint;
  blindedAuthCommitment: bigint;
  transactionIntentDigest: bigint;
  /** derived per-slot output metadata, for UI display. */
  outputs: Array<{ slot: number; isReal: boolean; amount: bigint; ownerNullifierKeyHash: bigint; noteSecret: bigint; noteBodyCommitment: bigint }>;
}

const d = (x: bigint): string => x.toString();
const zeros = (n: number): string[] => Array.from({ length: n }, () => "0");

function beBytes(v: bigint, len: number): number[] {
  const out = new Array<number>(len).fill(0);
  let x = v;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) throw new Error("value exceeds byte length");
  return out;
}

export async function buildTransactBundle(p: BuildTransactParams): Promise<TransactBundle> {
  if (p.outputs.length !== 3) throw new Error("transact requires exactly 3 output slots");
  if (p.inputs.length !== 1 && p.inputs.length !== 2) throw new Error("transact requires 1 or 2 inputs");
  if (p.authVerifier !== p.spender.authVerifier) throw new Error("auth verifier does not match the active policy method");

  const spenderOnkHash = onkHashOf(p.spender.ownerNullifierKey);
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
    authorizingAddress: p.spender.authorizingAddress,
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
  const replayId = intentReplayIdOf(p.spender.ownerNullifierKey, p.spender.authorizingAddress, p.chainId, p.poolAddress, p.nonce);

  const idLeaf = identityLeafOf(p.spender.authorizingAddress, spenderOnkHash, p.spender.noteSecretSeedHash, p.spender.policySetCommitment);
  if (!SparseTree.verify(32, p.identityRoot, p.spender.identityLeafPosition, idLeaf, p.spender.identitySiblings)) {
    throw new Error("sender identity does not match the selected identity root; rescan identity and retry");
  }

  // input nullifiers + local Merkle preflight
  const nullifiers: bigint[] = [];
  for (let i = 0; i < p.inputs.length; i++) {
    const inp = p.inputs[i]!;
    const oc = ownerCommitmentOf(p.chainId, p.poolAddress, spenderOnkHash, inp.noteSecret);
    const nbc = noteBodyCommitment(oc, inp.amount, p.tokenAddress);
    const nc = noteCommitmentOf(p.chainId, p.poolAddress, nbc, inp.leafIndex);
    if (!AppendOnlyTree.verify(32, p.noteCommitmentRoot, inp.leafIndex, nc, inp.siblings)) {
      throw new Error(`input note ${i} does not match the selected note root; rescan notes and retry`);
    }
    nullifiers.push(nullifierOf(p.chainId, p.poolAddress, nc, p.spender.ownerNullifierKey));
  }
  const nullifier0 = nullifiers[0]!;
  const nullifier1 = p.inputs.length === 2 ? nullifiers[1]! : phantomNullifier(p.chainId, p.poolAddress, p.spender.ownerNullifierKey, replayId, 1);

  // output notes + encryption
  const outputs = [];
  for (let i = 0; i < 3; i++) {
    const spec = p.outputs[i]!;
    const isReal = spec.ownerNullifierKeyHash !== DUMMY_OWNER_NULLIFIER_KEY_HASH;
    const noteSecret = transactNoteSecret(p.spender.noteSecretSeed, p.chainId, p.poolAddress, replayId, i as 0 | 1 | 2);
    const oc = ownerCommitmentOf(p.chainId, p.poolAddress, spec.ownerNullifierKeyHash, noteSecret);
    const nbc = noteBodyCommitment(oc, spec.amount, spec.tokenAddress);
    let ond: Uint8Array = EMPTY;
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
      ond = await encryptOutputNoteData(spec.receiveKey, payload);
    }
    outputs.push({ slot: i, isReal, amount: spec.amount, ownerNullifierKeyHash: spec.ownerNullifierKeyHash, noteSecret, noteBodyCommitment: nbc, ond, ondHash: keccakField(ond) });
  }

  const blinded = blindedAuthCommitmentOf(p.spender.authDataCommitment, p.blindingFactor);

  // policy application (§16.1)
  const appliesBit = p.publicAmountOut === 0n ? POLICY_APPLIES_TRANSFER : POLICY_APPLIES_WITHDRAWAL;
  const gated = (p.policy.applies & appliesBit) !== 0n;

  const piBase: PublicInputs = {
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
    outputNoteDataHash0: outputs[0]!.ondHash,
    outputNoteDataHash1: outputs[1]!.ondHash,
    outputNoteDataHash2: outputs[2]!.ondHash,
    authVerifier: p.authVerifier,
    blindedAuthCommitment: blinded,
    transactionIntentDigest: 0n,
    policyOperationDataHash: 0n,
    policyDataHash: 0n,
    authorizedSubmitter,
    downstreamActionCommitment,
  };
  const transitionHash = transactPublicTransitionHash(piBase);
  const transactOpDataHash = transactOperationDataHashOf(fieldsHash, transitionHash);

  let policyOperationDataHash = 0n;
  let policyData: Hex = "0x";
  if (gated) {
    policyOperationDataHash = transactOpDataHash;
    const digest = policyOperationDigestOf(p.chainId, p.poolAddress, p.policy.policyVerifier, POLICY_OPERATION_TRANSACT, policyOperationDataHash);
    if (p.policy.buildPolicyData) {
      policyData = await p.policy.buildPolicyData({
        policyOperationDigest: digest,
        policyOperationDataHash,
        fields,
        publicInputs: piBase,
      });
    } else if (p.policy.signAttestation) {
      policyData = await p.policy.signAttestation(digest);
    } else {
      throw new Error("gated operation requires policy data");
    }
  }
  const policyDataHash = keccakField(policyData === "0x" ? EMPTY : policyData);
  const transactionIntentDigest = transactionIntentDigestOf(fieldsHash, policyDataHash);

  const publicInputs: PublicInputs = { ...piBase, transactionIntentDigest, policyOperationDataHash, policyDataHash };
  const publicInputsArray = publicInputsToArray(publicInputs);

  // sign the intent (wallet)
  const signed = await p.signIntent(fields, policyDataHash);

  // pool witness input
  const twoInputs = p.inputs.length === 2;
  const in0 = p.inputs[0]!;
  const in1 = p.inputs[1];
  const poolWitnessInput: Record<string, unknown> = {
    noteCommitmentRoot: d(publicInputs.noteCommitmentRoot),
    nullifier0: d(publicInputs.nullifier0),
    nullifier1: d(publicInputs.nullifier1),
    noteBodyCommitment0: d(publicInputs.noteBodyCommitment0),
    noteBodyCommitment1: d(publicInputs.noteBodyCommitment1),
    noteBodyCommitment2: d(publicInputs.noteBodyCommitment2),
    publicAmountOut: d(publicInputs.publicAmountOut),
    publicRecipientAddress: d(publicInputs.publicRecipientAddress),
    publicTokenAddress: d(publicInputs.publicTokenAddress),
    intentReplayId: d(publicInputs.intentReplayId),
    validUntilSeconds: d(publicInputs.validUntilSeconds),
    executionChainId: d(publicInputs.executionChainId),
    poolAddress: d(publicInputs.poolAddress),
    identityRoot: d(publicInputs.identityRoot),
    outputNoteDataHash0: d(publicInputs.outputNoteDataHash0),
    outputNoteDataHash1: d(publicInputs.outputNoteDataHash1),
    outputNoteDataHash2: d(publicInputs.outputNoteDataHash2),
    authVerifier: d(publicInputs.authVerifier),
    blindedAuthCommitment: d(publicInputs.blindedAuthCommitment),
    transactionIntentDigest: d(publicInputs.transactionIntentDigest),
    policyOperationDataHash: d(publicInputs.policyOperationDataHash),
    policyDataHash: d(publicInputs.policyDataHash),
    authorizedSubmitter: d(publicInputs.authorizedSubmitter),
    downstreamActionCommitment: d(publicInputs.downstreamActionCommitment),
    senderOwnerNullifierKey: d(p.spender.ownerNullifierKey),
    senderNoteSecretSeed: d(p.spender.noteSecretSeed),
    authorizingAddress: d(p.spender.authorizingAddress),
    noteSecretSeedHash: d(p.spender.noteSecretSeedHash),
    policySetCommitment: d(p.spender.policySetCommitment),
    leafPosition: d(p.spender.identityLeafPosition),
    identitySiblings: p.spender.identitySiblings.map(d),
    inIsReal: twoInputs ? ["1", "1"] : ["1", "0"],
    inAmount: twoInputs ? [d(in0.amount), d(in1!.amount)] : [d(in0.amount), "0"],
    inNoteSecret: twoInputs ? [d(in0.noteSecret), d(in1!.noteSecret)] : [d(in0.noteSecret), "0"],
    inLeafIndex: twoInputs ? [d(in0.leafIndex), d(in1!.leafIndex)] : [d(in0.leafIndex), "0"],
    inSiblings: twoInputs ? [in0.siblings.map(d), in1!.siblings.map(d)] : [in0.siblings.map(d), zeros(32)],
    outIsReal: outputs.map((o) => (o.isReal ? "1" : "0")),
    outAmount: outputs.map((o) => d(o.amount)),
    outOwnerNullifierKeyHash: outputs.map((o) => d(o.ownerNullifierKeyHash)),
    outLockedOutputBinding: lockedOutputBinding.map(d),
    tokenAddress: d(p.tokenAddress),
    recipientOwnerNullifierKeyHash: d(p.recipientOwnerNullifierKeyHash),
    feeNoteRecipientOwnerNullifierKeyHash: d(p.feeNoteRecipientOwnerNullifierKeyHash),
    feeAmount: d(p.feeAmount),
    nonce: d(p.nonce),
    executionConstraintsFlags: d(executionConstraintsFlags),
    authDataCommitment: d(p.spender.authDataCommitment),
    blindingFactor: d(p.blindingFactor),
    registrationBlinder: d(p.spender.registrationBlinder),
    policySetLeafPosition: d(p.spender.policySlot),
    policySetSiblings: p.spender.policySetSiblings.map(d),
  };

  // auth circuit input (Noir)
  const authCircuitInput: Record<string, unknown> = {
    execution_chain_id: d(fields.executionChainId),
    pool_address: d(fields.poolAddress),
    auth_verifier: d(fields.authVerifier),
    authorizing_address: d(fields.authorizingAddress),
    operation_kind: d(fields.operationKind),
    token_address: d(fields.tokenAddress),
    recipient_owner_nullifier_key_hash: d(fields.recipientOwnerNullifierKeyHash),
    amount: d(fields.amount),
    fee_note_recipient_owner_nullifier_key_hash: d(fields.feeNoteRecipientOwnerNullifierKeyHash),
    fee_amount: d(fields.feeAmount),
    public_recipient_address: d(fields.publicRecipientAddress),
    authorized_submitter: d(fields.authorizedSubmitter),
    downstream_action_commitment: d(fields.downstreamActionCommitment),
    execution_constraints_flags: d(fields.executionConstraintsFlags),
    locked_output_binding0: d(fields.lockedOutputBinding0),
    locked_output_binding1: d(fields.lockedOutputBinding1),
    locked_output_binding2: d(fields.lockedOutputBinding2),
    policy_data_hash: d(policyDataHash),
    nonce: beBytes(fields.nonce, 32),
    valid_until_seconds: d(fields.validUntilSeconds),
    pubkey_x: beBytes(BigInt(signed.publicKeyX), 32),
    pubkey_y: beBytes(BigInt(signed.publicKeyY), 32),
    signature: [...beBytes(BigInt(signed.r), 32), ...beBytes(BigInt(signed.s), 32)],
    blinding_factor: d(p.blindingFactor),
  };

  return {
    poolWitnessInput,
    authCircuitInput,
    publicInputs,
    publicInputsArray,
    outputNoteData: [bytesToHex(outputs[0]!.ond), bytesToHex(outputs[1]!.ond), bytesToHex(outputs[2]!.ond)],
    policyData,
    intentReplayId: replayId,
    blindedAuthCommitment: blinded,
    transactionIntentDigest,
    outputs: outputs.map((o) => ({ slot: o.slot, isReal: o.isReal, amount: o.amount, ownerNullifierKeyHash: o.ownerNullifierKeyHash, noteSecret: o.noteSecret, noteBodyCommitment: o.noteBodyCommitment })),
  };
}
