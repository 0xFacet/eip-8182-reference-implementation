import { keccak_256 } from "@noble/hashes/sha3";

export const EIP8182_FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export function deriveEip8182Domain(contextName: string): bigint {
  let value = 0n;
  for (const byte of keccak_256(new TextEncoder().encode(`eip-8182.${contextName}`))) {
    value = (value << 8n) | BigInt(byte);
  }
  return value % EIP8182_FIELD_MODULUS;
}

export const OWNER_COMMITMENT_DOMAIN = deriveEip8182Domain("owner_commitment");
export const NOTE_BODY_COMMITMENT_DOMAIN = deriveEip8182Domain("note_body_commitment");
export const NOTE_COMMITMENT_DOMAIN = deriveEip8182Domain("note_commitment");
export const NULLIFIER_DOMAIN = deriveEip8182Domain("nullifier");
export const PHANTOM_NULLIFIER_DOMAIN = deriveEip8182Domain("phantom_nullifier");
export const INTENT_REPLAY_ID_DOMAIN = deriveEip8182Domain("intent_replay_id");
export const OWNER_NULLIFIER_KEY_HASH_DOMAIN = deriveEip8182Domain("owner_nullifier_key_hash");
export const TRANSACT_NOTE_SECRET_DOMAIN = deriveEip8182Domain("transact_note_secret");
export const TRANSACTION_INTENT_DIGEST_DOMAIN = deriveEip8182Domain("transaction_intent_digest");
export const OUTPUT_BINDING_DOMAIN = deriveEip8182Domain("output_binding");
export const AUTH_POLICY_DOMAIN = deriveEip8182Domain("auth_policy");
export const AUTH_POLICY_KEY_DOMAIN = deriveEip8182Domain("auth_policy_key");
export const AUTH_VK_DOMAIN = deriveEip8182Domain("auth_vk");
export const NOTE_SECRET_SEED_DOMAIN = deriveEip8182Domain("note_secret_seed");
export const USER_REGISTRY_LEAF_DOMAIN = deriveEip8182Domain("user_registry_leaf");

export function computeOwnerNullifierKeyHash(
  hash: (values: bigint[]) => bigint,
  ownerNullifierKey: bigint,
): bigint {
  return hash([OWNER_NULLIFIER_KEY_HASH_DOMAIN, ownerNullifierKey]);
}

export function computeNoteSecretSeedHash(
  hash: (values: bigint[]) => bigint,
  noteSecretSeed: bigint,
): bigint {
  return hash([NOTE_SECRET_SEED_DOMAIN, noteSecretSeed]);
}

export function computeIntentReplayId(
  hash: (values: bigint[]) => bigint,
  ownerNullifierKey: bigint,
  authorizingAddress: bigint,
  executionChainId: bigint,
  nonce: bigint,
): bigint {
  return hash([
    INTENT_REPLAY_ID_DOMAIN,
    ownerNullifierKey,
    authorizingAddress,
    executionChainId,
    nonce,
  ]);
}

export function computeTransactionIntentDigest(
  hash: (values: bigint[]) => bigint,
  params: {
    policyVersion: bigint;
    authorizingAddress: bigint;
    operationKind: bigint;
    tokenAddress: bigint;
    recipientAddress: bigint;
    amount: bigint;
    feeRecipientAddress?: bigint;
    feeAmount?: bigint;
    executionConstraintsFlags?: bigint;
    lockedOutputBinding0?: bigint;
    lockedOutputBinding1?: bigint;
    lockedOutputBinding2?: bigint;
    nonce: bigint;
    validUntilSeconds: bigint;
    executionChainId: bigint;
  },
): bigint {
  return hash([
    TRANSACTION_INTENT_DIGEST_DOMAIN,
    params.policyVersion,
    params.authorizingAddress,
    params.operationKind,
    params.tokenAddress,
    params.recipientAddress,
    params.amount,
    params.feeRecipientAddress ?? 0n,
    params.feeAmount ?? 0n,
    params.executionConstraintsFlags ?? 0n,
    params.lockedOutputBinding0 ?? 0n,
    params.lockedOutputBinding1 ?? 0n,
    params.lockedOutputBinding2 ?? 0n,
    params.nonce,
    params.validUntilSeconds,
    params.executionChainId,
  ]);
}

export function computeNoteSecret(
  hash: (values: bigint[]) => bigint,
  noteSecretSeed: bigint,
  intentReplayId: bigint,
  outputIndex: bigint,
): bigint {
  return hash([TRANSACT_NOTE_SECRET_DOMAIN, noteSecretSeed, intentReplayId, outputIndex]);
}

/// Real-note nullifier per EIP Section 7.6. Binds to the final (leaf-sealed) note
/// commitment, so the prover must know the input note's leaf index.
export function computeNoteNullifier(
  hash: (values: bigint[]) => bigint,
  noteCommitment: bigint,
  ownerNullifierKey: bigint,
): bigint {
  return hash([NULLIFIER_DOMAIN, noteCommitment, ownerNullifierKey]);
}

export function computePhantomNullifier(
  hash: (values: bigint[]) => bigint,
  ownerNullifierKey: bigint,
  intentReplayId: bigint,
  inputIndex: bigint,
): bigint {
  return hash([PHANTOM_NULLIFIER_DOMAIN, ownerNullifierKey, intentReplayId, inputIndex]);
}

/// Owner-side note commitment per EIP Section 7.3.
export function computeOwnerCommitment(
  hash: (values: bigint[]) => bigint,
  ownerNullifierKeyHash: bigint,
  noteSecret: bigint,
): bigint {
  return hash([OWNER_COMMITMENT_DOMAIN, ownerNullifierKeyHash, noteSecret]);
}

/// Semantic note body commitment per EIP Section 7.4. Input order is normative.
export function computeNoteBodyCommitment(
  hash: (values: bigint[]) => bigint,
  params: {
    ownerCommitment: bigint;
    amount: bigint;
    tokenAddress: bigint;
  },
): bigint {
  return hash([
    NOTE_BODY_COMMITMENT_DOMAIN,
    params.ownerCommitment,
    params.amount,
    params.tokenAddress,
  ]);
}

/// Final leaf-sealed note commitment per EIP Section 7.5.
export function computeFinalNoteCommitment(
  hash: (values: bigint[]) => bigint,
  noteBodyCommitment: bigint,
  leafIndex: bigint,
): bigint {
  return hash([NOTE_COMMITMENT_DOMAIN, noteBodyCommitment, leafIndex]);
}

/// Convenience: compute the full 3-layer commitment for a note given its
/// owner-identifying fragments, public fragments, and leaf index.
export function computeFullNoteCommitment(
  hash: (values: bigint[]) => bigint,
  params: {
    ownerNullifierKeyHash: bigint;
    noteSecret: bigint;
    amount: bigint;
    tokenAddress: bigint;
    leafIndex: bigint;
  },
): bigint {
  const oc = computeOwnerCommitment(hash, params.ownerNullifierKeyHash, params.noteSecret);
  const body = computeNoteBodyCommitment(hash, {
    ownerCommitment: oc,
    amount: params.amount,
    tokenAddress: params.tokenAddress,
  });
  return computeFinalNoteCommitment(hash, body, params.leafIndex);
}

export function computeOutputBinding(
  hash: (values: bigint[]) => bigint,
  noteBodyCommitment: bigint,
  outputNoteDataHash: bigint,
): bigint {
  return hash([OUTPUT_BINDING_DOMAIN, noteBodyCommitment, outputNoteDataHash]);
}
