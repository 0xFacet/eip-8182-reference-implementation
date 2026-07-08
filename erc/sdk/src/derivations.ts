// Spec §15.6 / §16.1 derived values. Every formula here is normative and
// cross-checked against the Circom, Noir, and Solidity surfaces through
// assets/derivation_vectors.json.

import { keccak_256 } from "@noble/hashes/sha3.js";
import { type BytesLike, bytesToHex, toBytes } from "./bytes.ts";
import { BN254_SCALAR_MODULUS, type FieldNumberish, toField } from "./field.ts";
import { poseidon } from "./poseidon2.ts";
import {
  BLINDED_AUTH_COMMITMENT_DOMAIN,
  EIP712_AUTH_DATA_DOMAIN,
  IDENTITY_LEAF_DOMAIN,
  INTENT_REPLAY_ID_DOMAIN,
  NOTE_BODY_COMMITMENT_DOMAIN,
  NOTE_COMMITMENT_DOMAIN,
  NOTE_SECRET_SEED_DOMAIN,
  NULLIFIER_DOMAIN,
  OUTPUT_BINDING_DOMAIN,
  OWNER_COMMITMENT_DOMAIN,
  OWNER_NULLIFIER_KEY_HASH_DOMAIN,
  PHANTOM_NULLIFIER_DOMAIN,
  POLICY_COMMITMENT_DOMAIN,
  POLICY_DEPOSIT_OPERATION_DATA_DOMAIN,
  POLICY_OPERATION_DOMAIN,
  POLICY_TRANSACT_OPERATION_DATA_DOMAIN,
  POLICY_TRANSACT_PUBLIC_TRANSITION_DOMAIN,
  TRANSACT_INTENT_FIELDS_DOMAIN,
  TRANSACT_NOTE_SECRET_DOMAIN,
  TRANSACTION_INTENT_DIGEST_DOMAIN,
} from "./generated/constants.ts";

export function ownerNullifierKeyHash(ownerNullifierKey: FieldNumberish): bigint {
  return poseidon(OWNER_NULLIFIER_KEY_HASH_DOMAIN, ownerNullifierKey);
}

export function noteSecretSeedHash(noteSecretSeed: FieldNumberish): bigint {
  return poseidon(NOTE_SECRET_SEED_DOMAIN, noteSecretSeed);
}

/** poseidon(OWNER_COMMITMENT_DOMAIN, executionChainId, poolAddress, ownerNullifierKeyHash, noteSecret) */
export function ownerCommitment(
  executionChainId: FieldNumberish,
  poolAddress: FieldNumberish,
  ownerNullifierKeyHashValue: FieldNumberish,
  noteSecret: FieldNumberish,
): bigint {
  return poseidon(OWNER_COMMITMENT_DOMAIN, executionChainId, poolAddress, ownerNullifierKeyHashValue, noteSecret);
}

/** poseidon(NOTE_BODY_COMMITMENT_DOMAIN, ownerCommitment, amount, tokenAddress) — NOT pool-scoped. */
export function noteBodyCommitment(
  ownerCommitmentValue: FieldNumberish,
  amount: FieldNumberish,
  tokenAddress: FieldNumberish,
): bigint {
  return poseidon(NOTE_BODY_COMMITMENT_DOMAIN, ownerCommitmentValue, amount, tokenAddress);
}

/** poseidon(NOTE_COMMITMENT_DOMAIN, executionChainId, poolAddress, noteBodyCommitment, leafIndex) */
export function noteCommitment(
  executionChainId: FieldNumberish,
  poolAddress: FieldNumberish,
  noteBodyCommitmentValue: FieldNumberish,
  leafIndex: FieldNumberish,
): bigint {
  return poseidon(NOTE_COMMITMENT_DOMAIN, executionChainId, poolAddress, noteBodyCommitmentValue, leafIndex);
}

/** poseidon(NULLIFIER_DOMAIN, executionChainId, poolAddress, noteCommitment, ownerNullifierKey) */
export function nullifier(
  executionChainId: FieldNumberish,
  poolAddress: FieldNumberish,
  noteCommitmentValue: FieldNumberish,
  ownerNullifierKey: FieldNumberish,
): bigint {
  return poseidon(NULLIFIER_DOMAIN, executionChainId, poolAddress, noteCommitmentValue, ownerNullifierKey);
}

/** poseidon(PHANTOM_NULLIFIER_DOMAIN, executionChainId, poolAddress, ownerNullifierKey, intentReplayId, inputIndex) */
export function phantomNullifier(
  executionChainId: FieldNumberish,
  poolAddress: FieldNumberish,
  ownerNullifierKey: FieldNumberish,
  intentReplayIdValue: FieldNumberish,
  inputIndex: 0 | 1,
): bigint {
  return poseidon(
    PHANTOM_NULLIFIER_DOMAIN,
    executionChainId,
    poolAddress,
    ownerNullifierKey,
    intentReplayIdValue,
    inputIndex,
  );
}

/** poseidon(TRANSACT_NOTE_SECRET_DOMAIN, noteSecretSeed, executionChainId, poolAddress, intentReplayId, outputIndex) */
export function transactNoteSecret(
  noteSecretSeed: FieldNumberish,
  executionChainId: FieldNumberish,
  poolAddress: FieldNumberish,
  intentReplayIdValue: FieldNumberish,
  outputIndex: 0 | 1 | 2,
): bigint {
  return poseidon(
    TRANSACT_NOTE_SECRET_DOMAIN,
    noteSecretSeed,
    executionChainId,
    poolAddress,
    intentReplayIdValue,
    outputIndex,
  );
}

/** poseidon(INTENT_REPLAY_ID_DOMAIN, ownerNullifierKey, authorizingAddress, executionChainId, poolAddress, nonce) */
export function intentReplayId(
  ownerNullifierKey: FieldNumberish,
  authorizingAddress: FieldNumberish,
  executionChainId: FieldNumberish,
  poolAddress: FieldNumberish,
  nonce: FieldNumberish,
): bigint {
  return poseidon(INTENT_REPLAY_ID_DOMAIN, ownerNullifierKey, authorizingAddress, executionChainId, poolAddress, nonce);
}

/** poseidon(IDENTITY_LEAF_DOMAIN, uint160(user), ownerNullifierKeyHash, noteSecretSeedHash, policySetCommitment) */
export function identityLeaf(
  user: FieldNumberish,
  ownerNullifierKeyHashValue: FieldNumberish,
  noteSecretSeedHashValue: FieldNumberish,
  policySetCommitment: FieldNumberish,
): bigint {
  return poseidon(IDENTITY_LEAF_DOMAIN, user, ownerNullifierKeyHashValue, noteSecretSeedHashValue, policySetCommitment);
}

/** poseidon(POLICY_COMMITMENT_DOMAIN, uint160(authVerifier), authDataCommitment, registrationBlinder) */
export function policyCommitment(
  authVerifier: FieldNumberish,
  authDataCommitment: FieldNumberish,
  registrationBlinder: FieldNumberish,
): bigint {
  return poseidon(POLICY_COMMITMENT_DOMAIN, authVerifier, authDataCommitment, registrationBlinder);
}

/** poseidon(BLINDED_AUTH_COMMITMENT_DOMAIN, authDataCommitment, blindingFactor) */
export function blindedAuthCommitment(
  authDataCommitment: FieldNumberish,
  blindingFactor: FieldNumberish,
): bigint {
  return poseidon(BLINDED_AUTH_COMMITMENT_DOMAIN, authDataCommitment, blindingFactor);
}

/** poseidon(OUTPUT_BINDING_DOMAIN, noteBodyCommitment, outputNoteDataHash) */
export function outputBinding(
  noteBodyCommitmentValue: FieldNumberish,
  outputNoteDataHashValue: FieldNumberish,
): bigint {
  return poseidon(OUTPUT_BINDING_DOMAIN, noteBodyCommitmentValue, outputNoteDataHashValue);
}

/** uint256(keccak256(outputNoteData)) mod p; empty bytes hash to keccak256("") mod p. */
export function outputNoteDataHash(data: BytesLike): bigint {
  return BigInt(bytesToHex(keccak_256(toBytes(data, "outputNoteData")))) % BN254_SCALAR_MODULUS;
}

/** Appendix A: poseidon(EIP712_AUTH_DATA_DOMAIN, uint160(authorizingAddress)) */
export function eip712AuthDataCommitment(authorizingAddress: FieldNumberish): bigint {
  return poseidon(EIP712_AUTH_DATA_DOMAIN, authorizingAddress);
}

export interface IntentFields {
  poolAddress: bigint;
  authVerifier: bigint;
  authorizingAddress: bigint;
  operationKind: bigint;
  tokenAddress: bigint;
  recipientOwnerNullifierKeyHash: bigint;
  amount: bigint;
  feeNoteRecipientOwnerNullifierKeyHash: bigint;
  feeAmount: bigint;
  publicRecipientAddress: bigint;
  /** Caller binding: if nonzero, only this address may submit the transact call (spec §7.1). */
  authorizedSubmitter: bigint;
  /** Opaque commitment to a downstream router action; 0 if none. Requires authorizedSubmitter != 0. */
  downstreamActionCommitment: bigint;
  executionConstraintsFlags: bigint;
  lockedOutputBinding0: bigint;
  lockedOutputBinding1: bigint;
  lockedOutputBinding2: bigint;
  nonce: bigint;
  validUntilSeconds: bigint;
  executionChainId: bigint;
}

/** poseidon(TRANSACT_INTENT_FIELDS_DOMAIN, ...19 fields in IntentFields declaration order) — spec §15.6. */
export function transactIntentFieldsHash(f: IntentFields): bigint {
  return poseidon(
    TRANSACT_INTENT_FIELDS_DOMAIN,
    f.poolAddress,
    f.authVerifier,
    f.authorizingAddress,
    f.operationKind,
    f.tokenAddress,
    f.recipientOwnerNullifierKeyHash,
    f.amount,
    f.feeNoteRecipientOwnerNullifierKeyHash,
    f.feeAmount,
    f.publicRecipientAddress,
    f.authorizedSubmitter,
    f.downstreamActionCommitment,
    f.executionConstraintsFlags,
    f.lockedOutputBinding0,
    f.lockedOutputBinding1,
    f.lockedOutputBinding2,
    f.nonce,
    f.validUntilSeconds,
    f.executionChainId,
  );
}

/** poseidon(TRANSACTION_INTENT_DIGEST_DOMAIN, transactIntentFieldsHash, policyDataHash) — spec §15.6. */
export function transactionIntentDigest(fieldsHash: FieldNumberish, policyDataHash: FieldNumberish): bigint {
  return poseidon(TRANSACTION_INTENT_DIGEST_DOMAIN, fieldsHash, policyDataHash);
}

/** The 24 public inputs of the pool relation, spec §4 declaration order. */
export interface PublicInputs {
  noteCommitmentRoot: bigint;
  nullifier0: bigint;
  nullifier1: bigint;
  noteBodyCommitment0: bigint;
  noteBodyCommitment1: bigint;
  noteBodyCommitment2: bigint;
  publicAmountOut: bigint;
  publicRecipientAddress: bigint;
  publicTokenAddress: bigint;
  intentReplayId: bigint;
  validUntilSeconds: bigint;
  executionChainId: bigint;
  poolAddress: bigint;
  identityRoot: bigint;
  outputNoteDataHash0: bigint;
  outputNoteDataHash1: bigint;
  outputNoteDataHash2: bigint;
  authVerifier: bigint;
  blindedAuthCommitment: bigint;
  transactionIntentDigest: bigint;
  policyOperationDataHash: bigint;
  policyDataHash: bigint;
  authorizedSubmitter: bigint;
  downstreamActionCommitment: bigint;
}

export const PUBLIC_INPUT_FIELDS = [
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
  "validUntilSeconds",
  "executionChainId",
  "poolAddress",
  "identityRoot",
  "outputNoteDataHash0",
  "outputNoteDataHash1",
  "outputNoteDataHash2",
  "authVerifier",
  "blindedAuthCommitment",
  "transactionIntentDigest",
  "policyOperationDataHash",
  "policyDataHash",
  "authorizedSubmitter",
  "downstreamActionCommitment",
] as const satisfies readonly (keyof PublicInputs)[];

export function publicInputsToArray(pi: PublicInputs): bigint[] {
  return PUBLIC_INPUT_FIELDS.map((k) => toField(pi[k], k));
}

/**
 * poseidon(POLICY_TRANSACT_PUBLIC_TRANSITION_DOMAIN, ...21 public transition fields
 * (through downstreamActionCommitment)) — spec §16.1.
 */
export function transactPublicTransitionHash(pi: PublicInputs): bigint {
  return poseidon(
    POLICY_TRANSACT_PUBLIC_TRANSITION_DOMAIN,
    pi.noteCommitmentRoot,
    pi.nullifier0,
    pi.nullifier1,
    pi.noteBodyCommitment0,
    pi.noteBodyCommitment1,
    pi.noteBodyCommitment2,
    pi.publicAmountOut,
    pi.publicRecipientAddress,
    pi.publicTokenAddress,
    pi.intentReplayId,
    pi.validUntilSeconds,
    pi.executionChainId,
    pi.poolAddress,
    pi.identityRoot,
    pi.outputNoteDataHash0,
    pi.outputNoteDataHash1,
    pi.outputNoteDataHash2,
    pi.authVerifier,
    pi.blindedAuthCommitment,
    pi.authorizedSubmitter,
    pi.downstreamActionCommitment,
  );
}

/** poseidon(POLICY_TRANSACT_OPERATION_DATA_DOMAIN, transactIntentFieldsHash, transactPublicTransitionHash) — spec §16.1. */
export function transactOperationDataHash(fieldsHash: FieldNumberish, transitionHash: FieldNumberish): bigint {
  return poseidon(POLICY_TRANSACT_OPERATION_DATA_DOMAIN, fieldsHash, transitionHash);
}

/** poseidon(POLICY_OPERATION_DOMAIN, chainId, poolAddress, uint160(policyVerifier), policyOperationKind, operationDataHash) — spec §16.1. */
export function policyOperationDigest(
  chainId: FieldNumberish,
  poolAddress: FieldNumberish,
  policyVerifier: FieldNumberish,
  policyOperationKind: FieldNumberish,
  operationDataHash: FieldNumberish,
): bigint {
  return poseidon(POLICY_OPERATION_DOMAIN, chainId, poolAddress, policyVerifier, policyOperationKind, operationDataHash);
}

/** poseidon(POLICY_DEPOSIT_OPERATION_DATA_DOMAIN, chainId, poolAddress, sender, token, amount, ownerCommitment, outputNoteDataHash) — spec §16.1. */
export function depositOperationDataHash(
  chainId: FieldNumberish,
  poolAddress: FieldNumberish,
  sender: FieldNumberish,
  token: FieldNumberish,
  amount: FieldNumberish,
  ownerCommitmentValue: FieldNumberish,
  outputNoteDataHashValue: FieldNumberish,
): bigint {
  return poseidon(
    POLICY_DEPOSIT_OPERATION_DATA_DOMAIN,
    chainId,
    poolAddress,
    sender,
    token,
    amount,
    ownerCommitmentValue,
    outputNoteDataHashValue,
  );
}
