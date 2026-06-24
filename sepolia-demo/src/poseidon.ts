import { keccak_256 } from "@noble/hashes/sha3.js";
import { randomBytes, toBytes, type BytesLike, utf8ToBytes } from "./bytes.js";
import { BN254_SCALAR_MODULUS, normalizeAddress, toNonnegativeBigInt, type FieldNumberish, type HexAddress } from "./payload.js";
import {
  POSEIDON_EXTERNAL_MATRIX,
  POSEIDON_FIELD_MODULUS,
  POSEIDON_INTERNAL_DIAGONAL,
  POSEIDON_ROUND_CONSTANTS
} from "./poseidon-params.js";

const WIDTH = 4;
const RATE = 3;
const FULL_ROUNDS = 8;
const HALF_FULL_ROUNDS = FULL_ROUNDS / 2;
const PARTIAL_ROUNDS = 56;

const FIELD_MODULUS = BigInt(POSEIDON_FIELD_MODULUS);
if (FIELD_MODULUS !== BN254_SCALAR_MODULUS) {
  throw new Error("Poseidon params field modulus does not match BN254 scalar modulus");
}

const EXTERNAL_MATRIX = POSEIDON_EXTERNAL_MATRIX.map((row) => row.map(BigInt));
const INTERNAL_DIAGONAL = POSEIDON_INTERNAL_DIAGONAL.map(BigInt);
const ROUND_CONSTANTS = POSEIDON_ROUND_CONSTANTS.map(BigInt);

export const OWNER_NULLIFIER_KEY_HASH_DOMAIN = domainTag("owner_nullifier_key_hash");
export const OWNER_COMMITMENT_DOMAIN = domainTag("owner_commitment");
export const NOTE_BODY_COMMITMENT_DOMAIN = domainTag("note_body_commitment");
export const NOTE_COMMITMENT_DOMAIN = domainTag("note_commitment");
export const NULLIFIER_DOMAIN = domainTag("nullifier");
export const PHANTOM_NULLIFIER_DOMAIN = domainTag("phantom_nullifier");
export const NOTE_SECRET_SEED_DOMAIN = domainTag("note_secret_seed");
export const TRANSACT_NOTE_SECRET_DOMAIN = domainTag("transact_note_secret");
export const INTENT_REPLAY_ID_DOMAIN = domainTag("intent_replay_id");
export const OUTPUT_BINDING_DOMAIN = domainTag("output_binding");
export const AUTH_POLICY_DOMAIN = domainTag("auth_policy");
export const POLICY_COMMITMENT_DOMAIN = domainTag("policy_commitment");
export const TRANSACTION_INTENT_DIGEST_DOMAIN = domainTag("transaction_intent_digest");
export const AUTH_DATA_COMMITMENT_DOMAIN = domainTag("auth_data_commitment");
export const BLINDED_AUTH_COMMITMENT_DOMAIN = domainTag("blinded_auth_commitment");

export function poseidon(...inputs: readonly FieldNumberish[]): bigint {
  const lenTag = BigInt(inputs.length) << 64n;
  let state = [0n, 0n, 0n, lenTag];

  if (inputs.length === 0) {
    return permutation(state)[0] ?? fail("empty permutation output");
  }

  for (let chunk = 0; chunk * RATE < inputs.length; chunk += 1) {
    for (let slot = 0; slot < RATE; slot += 1) {
      const input = inputs[chunk * RATE + slot];
      if (input !== undefined) state[slot] = mod((state[slot] ?? 0n) + toField(input, "poseidon input"));
    }
    state = permutation(state);
  }

  return state[0] ?? fail("permutation output missing");
}

export function domainTag(name: string): bigint {
  return bytesToBigInt(keccak_256(utf8ToBytes(`eip-8182.${name}`))) % FIELD_MODULUS;
}

export function toField(value: FieldNumberish, name = "field"): bigint {
  const field = toNonnegativeBigInt(value, name);
  if (field >= FIELD_MODULUS) throw new Error(`${name} must be a BN254 scalar field element`);
  return field;
}

export function randomField(): bigint {
  let value = bytesToBigInt(randomBytes(32)) % FIELD_MODULUS;
  if (value === 0n) value = 1n;
  return value;
}

export function keccakField(value: BytesLike): bigint {
  return bytesToBigInt(keccak_256(toBytes(value, "keccak input"))) % FIELD_MODULUS;
}

export function fieldToHex(value: FieldNumberish): `0x${string}` {
  return `0x${toField(value).toString(16).padStart(64, "0")}`;
}

export function addressToField(address: string): bigint {
  return BigInt(normalizeAddress(address));
}

export function ownerNullifierKeyHash(ownerNullifierKey: FieldNumberish): bigint {
  return poseidon(OWNER_NULLIFIER_KEY_HASH_DOMAIN, ownerNullifierKey);
}

export function dummyOwnerNullifierKeyHash(): bigint {
  return ownerNullifierKeyHash(0xdeadn);
}

export function ownerCommitment(ownerNullifierKeyHashValue: FieldNumberish, noteSecret: FieldNumberish): bigint {
  return poseidon(OWNER_COMMITMENT_DOMAIN, ownerNullifierKeyHashValue, noteSecret);
}

export function noteBodyCommitment(
  ownerCommitmentValue: FieldNumberish,
  amount: FieldNumberish,
  tokenAddress: FieldNumberish | HexAddress
): bigint {
  return poseidon(NOTE_BODY_COMMITMENT_DOMAIN, ownerCommitmentValue, amount, addressOrField(tokenAddress, "tokenAddress"));
}

export function noteCommitment(noteBodyCommitmentValue: FieldNumberish, leafIndex: FieldNumberish): bigint {
  return poseidon(NOTE_COMMITMENT_DOMAIN, noteBodyCommitmentValue, leafIndex);
}

export function nullifier(noteCommitmentValue: FieldNumberish, ownerNullifierKey: FieldNumberish): bigint {
  return poseidon(NULLIFIER_DOMAIN, noteCommitmentValue, ownerNullifierKey);
}

export function phantomNullifier(
  ownerNullifierKey: FieldNumberish,
  intentReplayIdValue: FieldNumberish,
  inputIndex: 0 | 1
): bigint {
  return poseidon(PHANTOM_NULLIFIER_DOMAIN, ownerNullifierKey, intentReplayIdValue, inputIndex);
}

export function noteSecretSeedHash(noteSecretSeed: FieldNumberish): bigint {
  return poseidon(NOTE_SECRET_SEED_DOMAIN, noteSecretSeed);
}

export function transactNoteSecret(
  noteSecretSeed: FieldNumberish,
  intentReplayIdValue: FieldNumberish,
  outputIndex: 0 | 1 | 2
): bigint {
  return poseidon(TRANSACT_NOTE_SECRET_DOMAIN, noteSecretSeed, intentReplayIdValue, outputIndex);
}

export function intentReplayId(
  ownerNullifierKey: FieldNumberish,
  authorizingAddress: HexAddress,
  executionChainId: FieldNumberish,
  nonce: FieldNumberish
): bigint {
  return poseidon(INTENT_REPLAY_ID_DOMAIN, ownerNullifierKey, addressToField(authorizingAddress), executionChainId, nonce);
}

export function outputBinding(noteBodyCommitmentValue: FieldNumberish, outputNoteDataHash: FieldNumberish): bigint {
  return poseidon(OUTPUT_BINDING_DOMAIN, noteBodyCommitmentValue, outputNoteDataHash);
}

export function policyCommitment(
  authVerifier: HexAddress,
  authDataCommitment: FieldNumberish,
  registrationBlinder: FieldNumberish
): bigint {
  return poseidon(POLICY_COMMITMENT_DOMAIN, addressToField(authVerifier), authDataCommitment, registrationBlinder);
}

export function authDataCommitmentFromPublicKey(publicKey: BytesLike): bigint {
  const bytes = toBytes(publicKey, "secp256k1 public key");
  const uncompressed = bytes.length === 65 && bytes[0] === 4 ? bytes.slice(1) : bytes;
  if (uncompressed.length !== 64) throw new Error("secp256k1 public key must be 64-byte raw or 65-byte uncompressed");
  return poseidon(
    AUTH_DATA_COMMITMENT_DOMAIN,
    bytesToBigInt(uncompressed.slice(0, 16)),
    bytesToBigInt(uncompressed.slice(16, 32)),
    bytesToBigInt(uncompressed.slice(32, 48)),
    bytesToBigInt(uncompressed.slice(48, 64))
  );
}

export function blindedAuthCommitment(
  authDataCommitmentValue: FieldNumberish,
  blindingFactor: FieldNumberish
): bigint {
  return poseidon(BLINDED_AUTH_COMMITMENT_DOMAIN, authDataCommitmentValue, blindingFactor);
}

export function authPolicyLeaf(
  user: HexAddress,
  ownerNullifierKeyHashValue: FieldNumberish,
  noteSecretSeedHashValue: FieldNumberish,
  policySetCommitmentValue: FieldNumberish
): bigint {
  return poseidon(
    AUTH_POLICY_DOMAIN,
    addressToField(user),
    ownerNullifierKeyHashValue,
    noteSecretSeedHashValue,
    policySetCommitmentValue
  );
}

export interface TransactionIntentDigestInput {
  authVerifier: HexAddress;
  authorizingAddress: HexAddress;
  operationKind: FieldNumberish;
  tokenAddress: FieldNumberish | HexAddress;
  recipientOwnerNullifierKeyHash: FieldNumberish;
  amount: FieldNumberish;
  feeNoteRecipientOwnerNullifierKeyHash: FieldNumberish;
  feeAmount: FieldNumberish;
  publicRecipientAddress: FieldNumberish | HexAddress;
  executionConstraintsFlags: FieldNumberish;
  lockedOutputBinding0: FieldNumberish;
  lockedOutputBinding1: FieldNumberish;
  lockedOutputBinding2: FieldNumberish;
  nonce: FieldNumberish;
  validUntilSeconds: FieldNumberish;
  executionChainId: FieldNumberish;
}

export function transactionIntentDigest(input: TransactionIntentDigestInput): bigint {
  return poseidon(
    TRANSACTION_INTENT_DIGEST_DOMAIN,
    addressToField(input.authVerifier),
    addressToField(input.authorizingAddress),
    input.operationKind,
    addressOrField(input.tokenAddress, "tokenAddress"),
    input.recipientOwnerNullifierKeyHash,
    input.amount,
    input.feeNoteRecipientOwnerNullifierKeyHash,
    input.feeAmount,
    addressOrField(input.publicRecipientAddress, "publicRecipientAddress"),
    input.executionConstraintsFlags,
    input.lockedOutputBinding0,
    input.lockedOutputBinding1,
    input.lockedOutputBinding2,
    input.nonce,
    input.validUntilSeconds,
    input.executionChainId
  );
}

export function sparseMerkleRootAndSiblings(
  leaves: readonly (readonly [FieldNumberish, FieldNumberish])[],
  depth: number,
  queryKey: FieldNumberish
): { root: bigint; siblings: bigint[] } {
  if (!Number.isSafeInteger(depth) || depth < 0 || depth > 64) throw new Error("depth must be a safe nonnegative integer");

  const empty = emptyMerkleHashes(depth);
  const nodes = new Map<string, bigint>();
  const key = (height: number, index: bigint) => `${height}:${index.toString(10)}`;

  for (const [leafKey, leaf] of leaves) {
    nodes.set(key(0, toNonnegativeBigInt(leafKey, "leaf key")), toField(leaf, "leaf"));
  }

  for (let height = 0; height < depth; height += 1) {
    const prefixes = new Set<bigint>();
    for (const nodeKey of nodes.keys()) {
      const [heightText, indexText] = nodeKey.split(":");
      if (Number(heightText) !== height || indexText === undefined) continue;
      prefixes.add(BigInt(indexText) >> 1n);
    }

    for (const prefix of prefixes) {
      const left = nodes.get(key(height, prefix << 1n)) ?? must(empty[height], "empty left");
      const right = nodes.get(key(height, (prefix << 1n) | 1n)) ?? must(empty[height], "empty right");
      nodes.set(key(height + 1, prefix), poseidon(left, right));
    }
  }

  const siblings: bigint[] = [];
  const query = toNonnegativeBigInt(queryKey, "queryKey");
  for (let height = 0; height < depth; height += 1) {
    const siblingIndex = (query >> BigInt(height)) ^ 1n;
    siblings.push(nodes.get(key(height, siblingIndex)) ?? must(empty[height], "empty sibling"));
  }

  return { root: nodes.get(key(depth, 0n)) ?? must(empty[depth], "empty root"), siblings };
}

export function singleLeafPolicySetCommitment(policyCommitmentValue: FieldNumberish): bigint {
  return sparseMerkleRootAndSiblings([[0n, policyCommitmentValue]], 8, 0n).root;
}

export function emptyMerkleHashes(depth: number): bigint[] {
  const hashes = [0n];
  for (let height = 0; height < depth; height += 1) {
    hashes.push(poseidon(must(hashes[height], "empty hash"), must(hashes[height], "empty hash")));
  }
  return hashes;
}

function addressOrField(value: FieldNumberish | HexAddress, name: string): bigint {
  return typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value)
    ? addressToField(value)
    : toField(value, name);
}

function permutation(stateIn: readonly bigint[]): bigint[] {
  let state = applyExternalMatrix([...stateIn]);

  for (let round = 0; round < HALF_FULL_ROUNDS; round += 1) {
    addRoundConstants(state, round * WIDTH);
    for (let slot = 0; slot < WIDTH; slot += 1) state[slot] = pow5(state[slot] ?? 0n);
    state = applyExternalMatrix(state);
  }

  for (let round = 0; round < PARTIAL_ROUNDS; round += 1) {
    state[0] = mod((state[0] ?? 0n) + must(ROUND_CONSTANTS[HALF_FULL_ROUNDS * WIDTH + round], "partial round constant"));
    state[0] = pow5(state[0] ?? 0n);
    state = applyInternalMatrix(state);
  }

  for (let round = 0; round < HALF_FULL_ROUNDS; round += 1) {
    addRoundConstants(state, HALF_FULL_ROUNDS * WIDTH + PARTIAL_ROUNDS + round * WIDTH);
    for (let slot = 0; slot < WIDTH; slot += 1) state[slot] = pow5(state[slot] ?? 0n);
    state = applyExternalMatrix(state);
  }

  return state;
}

function addRoundConstants(state: bigint[], base: number): void {
  for (let slot = 0; slot < WIDTH; slot += 1) {
    state[slot] = mod((state[slot] ?? 0n) + must(ROUND_CONSTANTS[base + slot], "round constant"));
  }
}

function applyExternalMatrix(state: readonly bigint[]): bigint[] {
  const out = new Array<bigint>(WIDTH).fill(0n);
  for (let row = 0; row < WIDTH; row += 1) {
    let sum = 0n;
    for (let col = 0; col < WIDTH; col += 1) {
      sum = mod(sum + must(must(EXTERNAL_MATRIX[row], "external row")[col], "external matrix cell") * (state[col] ?? 0n));
    }
    out[row] = sum;
  }
  return out;
}

function applyInternalMatrix(state: readonly bigint[]): bigint[] {
  let sum = 0n;
  for (let slot = 0; slot < WIDTH; slot += 1) sum = mod(sum + (state[slot] ?? 0n));
  return state.map((value, slot) => mod(sum + must(INTERNAL_DIAGONAL[slot], "internal diagonal") * value));
}

function pow5(value: bigint): bigint {
  const squared = mod(value * value);
  return mod(mod(squared * squared) * value);
}

function mod(value: bigint): bigint {
  const reduced = value % FIELD_MODULUS;
  return reduced < 0n ? reduced + FIELD_MODULUS : reduced;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function must<T>(value: T | undefined, name: string): T {
  if (value === undefined) throw new Error(`${name} missing`);
  return value;
}

function fail(message: string): never {
  throw new Error(message);
}
