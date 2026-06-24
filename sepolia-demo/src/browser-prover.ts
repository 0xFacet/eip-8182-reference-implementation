import { keccak_256 } from "@noble/hashes/sha3.js";
import {
  authIntentDigest,
  recoverPublicKey
} from "./auth.js";
import { bytesToHex, concatBytes, hexToBytes, toBytes, type BytesLike } from "./bytes.js";
import type { ChainRoots } from "./contracts.js";
import type {
  ShieldedPoolAuthPolicySetEvent,
  ShieldedPoolDepositEvent,
  ShieldedPoolTransactEvent,
  IndexedNote
} from "./indexer.js";
import {
  normalizeAddress,
  outputNoteDataHash,
  toNonnegativeBigInt,
  type FieldNumberish,
  type HexAddress
} from "./payload.js";
import {
  addressToField,
  authDataCommitmentFromPublicKey,
  authPolicyLeaf,
  blindedAuthCommitment,
  dummyOwnerNullifierKeyHash,
  emptyMerkleHashes,
  intentReplayId,
  noteBodyCommitment,
  noteCommitment,
  nullifier,
  outputBinding,
  ownerCommitment,
  phantomNullifier,
  policyCommitment,
  poseidon,
  sparseMerkleRootAndSiblings,
  transactNoteSecret,
  transactionIntentDigest
} from "./poseidon.js";
import type { DemoProfile } from "./profile.js";
import type { DemoPoolPublicInputs } from "./prover.js";
import type { PreparedDemoPrivateTransfer, PreparedTransferSlot } from "./transfer.js";

export const POOL_PUBLIC_INPUT_FIELDS = [
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
  "authPolicyRoot",
  "outputNoteDataHash0",
  "outputNoteDataHash1",
  "outputNoteDataHash2",
  "authVerifier",
  "blindedAuthCommitment",
  "transactionIntentDigest"
] as const satisfies readonly (keyof DemoPoolPublicInputs)[];

export const NOTE_TREE_DEPTH = 32;
export const AUTH_POLICY_TREE_DEPTH = 32;
export const POLICY_SET_DEPTH = 8;

export interface BrowserProverRequest {
  chainId: FieldNumberish;
  poolAddress: HexAddress;
  authVerifier: HexAddress;
  account: HexAddress;
  roots: ChainRoots;
  profile: DemoProfile;
  inputNote: IndexedNote;
  preparedTransfer: PreparedDemoPrivateTransfer;
  authSignature: AuthSignatureInput;
  deposits: readonly ShieldedPoolDepositEvent[];
  transacts: readonly ShieldedPoolTransactEvent[];
  authEvents: readonly ShieldedPoolAuthPolicySetEvent[];
  policySetLeafPosition?: FieldNumberish;
}

export type AuthSignatureInput = `0x${string}` | {
  signature: `0x${string}`;
  blindingFactor?: FieldNumberish;
  pubkeyX?: BytesLike;
  pubkeyY?: BytesLike;
};

export interface DemoProverState {
  noteLeaves: Map<number, bigint>;
  authLeaves: Map<number, bigint>;
  userEntries: Map<HexAddress, AuthTreeEntry>;
  noteRoot: bigint;
  authRoot: bigint;
}

export interface AuthTreeEntry {
  user: HexAddress;
  ownerNullifierKeyHash: bigint;
  noteSecretSeedHash: bigint;
  policySetCommitment: bigint;
  leafPosition: bigint;
  leafValue: bigint;
  postUpdateAuthPolicyRoot: bigint;
}

export interface DemoAuthWitness {
  authDataCommitment: bigint;
  blindedAuthCommitment: bigint;
  transactionIntentDigest: bigint;
  senderOwnerNullifierKey: bigint;
  senderOwnerNullifierKeyHash: bigint;
  senderNoteSecretSeed: bigint;
  noteSecretSeedHash: bigint;
  policySetCommitment: bigint;
  policySetLeafPosition: bigint;
  policySetSiblings: bigint[];
  leafPosition: bigint;
  authPolicySiblings: bigint[];
  registrationBlinder: bigint;
  authCircuitInput: Record<string, string | number[]>;
}

export interface DemoPoolWitness {
  publicInputs: DemoPoolPublicInputs;
  witnessInput: unknown;
  outputNoteDataHexes: readonly [`0x${string}`, `0x${string}`, `0x${string}`];
}

export interface BrowserWitnessBundle {
  state: DemoProverState;
  auth: DemoAuthWitness;
  pool: DemoPoolWitness;
}

export interface NormalizedBrowserProverRequest extends BrowserProverRequest {
  chainId: bigint;
  poolAddress: HexAddress;
  authVerifier: HexAddress;
  account: HexAddress;
  roots: {
    noteCommitmentRoot: bigint;
    authPolicyRoot: bigint;
  };
  authSignature: NormalizedAuthSignature;
  policySetLeafPosition: bigint;
}

export interface NormalizedAuthSignature {
  signature: `0x${string}`;
  signatureBytes: Uint8Array;
  blindingFactor: bigint;
  pubkeyX?: Uint8Array;
  pubkeyY?: Uint8Array;
}

interface TransferSlotWitness {
  outputIndex: 0 | 1 | 2;
  isReal: boolean;
  amount: bigint;
  ownerNullifierKeyHash: bigint;
  noteSecret: bigint;
  noteBodyCommitment: bigint;
  outputNoteDataHash: bigint;
  outputNoteDataHex: `0x${string}`;
  outputBinding: bigint;
}

export function buildBrowserWitnessBundle(request: BrowserProverRequest): BrowserWitnessBundle {
  const normalized = normalizeBrowserProverRequest(request);
  const state = reconstructStateFromEvents(normalized);
  const auth = buildAuthWitnessInputs(normalized, state);
  const pool = buildPoolWitness(normalized, state, auth);
  assertPreparedPreviewMatches(normalized.preparedTransfer, pool.publicInputs);
  return { state, auth, pool };
}

export function reconstructStateFromEvents(request: NormalizedBrowserProverRequest): DemoProverState {
  const noteLeaves = new Map<number, bigint>();
  let lastNoteRoot: bigint | undefined;

  for (const event of sortEvents([...request.deposits, ...request.transacts])) {
    if (isDepositEvent(event)) {
      noteLeaves.set(toLeafIndex(event.leafIndex), toNonnegativeBigInt(event.noteCommitment, "deposit.noteCommitment"));
      if (event.postInsertionCommitmentRoot !== undefined) {
        lastNoteRoot = toNonnegativeBigInt(event.postInsertionCommitmentRoot, "deposit.postInsertionCommitmentRoot");
      }
      continue;
    }

    const leaf0 = toLeafIndex(event.leafIndex0);
    noteLeaves.set(leaf0, toNonnegativeBigInt(event.noteCommitment0, "transact.noteCommitment0"));
    noteLeaves.set(leaf0 + 1, toNonnegativeBigInt(event.noteCommitment1, "transact.noteCommitment1"));
    noteLeaves.set(leaf0 + 2, toNonnegativeBigInt(event.noteCommitment2, "transact.noteCommitment2"));
    if (event.postInsertionCommitmentRoot !== undefined) {
      lastNoteRoot = toNonnegativeBigInt(event.postInsertionCommitmentRoot, "transact.postInsertionCommitmentRoot");
    }
  }

  const authLeaves = new Map<number, bigint>();
  const userEntries = new Map<HexAddress, AuthTreeEntry>();
  let lastAuthRoot: bigint | undefined;
  for (const event of sortEvents(request.authEvents)) {
    const user = normalizeAddress(event.user, "AuthPolicySet.user");
    const leafPosition = toNonnegativeBigInt(event.leafPosition, "AuthPolicySet.leafPosition");
    const entry: AuthTreeEntry = {
      user,
      ownerNullifierKeyHash: toNonnegativeBigInt(event.ownerNullifierKeyHash, "AuthPolicySet.ownerNullifierKeyHash"),
      noteSecretSeedHash: toNonnegativeBigInt(event.noteSecretSeedHash, "AuthPolicySet.noteSecretSeedHash"),
      policySetCommitment: toNonnegativeBigInt(event.policySetCommitment, "AuthPolicySet.policySetCommitment"),
      leafPosition,
      leafValue: toNonnegativeBigInt(event.leafValue, "AuthPolicySet.leafValue"),
      postUpdateAuthPolicyRoot: toNonnegativeBigInt(event.postUpdateAuthPolicyRoot, "AuthPolicySet.postUpdateAuthPolicyRoot")
    };
    authLeaves.set(toLeafIndex(entry.leafPosition), entry.leafValue);
    userEntries.set(user, entry);
    lastAuthRoot = entry.postUpdateAuthPolicyRoot;
  }

  const noteRoot = noteCommitmentTree(noteLeaves, NOTE_TREE_DEPTH).root;
  const authRoot = sparseMerkleRootAndSiblings([...authLeaves.entries()], AUTH_POLICY_TREE_DEPTH, 0n).root;
  if (lastNoteRoot !== undefined && noteRoot !== lastNoteRoot) {
    throw new Error(`reconstructed note root ${noteRoot} does not match last event root ${lastNoteRoot}`);
  }
  if (lastAuthRoot !== undefined && authRoot !== lastAuthRoot) {
    throw new Error(`reconstructed auth root ${authRoot} does not match last event root ${lastAuthRoot}`);
  }
  if (noteRoot !== request.roots.noteCommitmentRoot) {
    throw new Error(`reconstructed note root ${noteRoot} does not match on-chain root ${request.roots.noteCommitmentRoot}`);
  }
  if (authRoot !== request.roots.authPolicyRoot) {
    throw new Error(`reconstructed auth root ${authRoot} does not match on-chain root ${request.roots.authPolicyRoot}`);
  }

  return { noteLeaves, authLeaves, userEntries, noteRoot, authRoot };
}

export function buildAuthWitnessInputs(
  request: NormalizedBrowserProverRequest,
  state: DemoProverState
): DemoAuthWitness {
  const profile = request.profile;
  const transfer = request.preparedTransfer;
  const slots = transferSlots(transfer);
  const senderOwnerNullifierKey = toNonnegativeBigInt(profile.ownerNullifierKey, "profile.ownerNullifierKey");
  const senderOwnerNullifierKeyHash = toNonnegativeBigInt(profile.ownerNullifierKeyHash, "profile.ownerNullifierKeyHash");
  const senderNoteSecretSeed = toNonnegativeBigInt(profile.noteSecretSeed, "profile.noteSecretSeed");
  const noteSecretSeedHash = toNonnegativeBigInt(profile.noteSecretSeedHash, "profile.noteSecretSeedHash");
  const registrationBlinder = toNonnegativeBigInt(profile.registrationBlinder, "profile.registrationBlinder");
  const blindingFactor = request.authSignature.blindingFactor;

  const digestHex = authIntentDigest(transfer, request.account);
  const pubkey = recoverOrReadPubkey(request.authSignature, digestHex);
  const recoveredAddress = publicKeyToAddress(concatBytes(pubkey.x, pubkey.y));
  if (recoveredAddress !== request.account) {
    throw new Error(`auth signature pubkey derives ${recoveredAddress}, expected profile account ${request.account}`);
  }
  if (profile.authPublicKey !== undefined) {
    const profilePubkey = hexToBytes(profile.authPublicKey, "profile.authPublicKey");
    const recoveredPubkey = concatBytes(new Uint8Array([4]), pubkey.x, pubkey.y);
    if (!bytesEqual(profilePubkey, recoveredPubkey)) {
      throw new Error("auth signature public key does not match signed browser profile");
    }
  }

  const authPublicKey = concatBytes(new Uint8Array([4]), pubkey.x, pubkey.y);
  const authDataCommitment = authDataCommitmentFromPublicKey(authPublicKey);
  const blinded = blindedAuthCommitment(authDataCommitment, blindingFactor);
  const policy = policyCommitment(request.authVerifier, authDataCommitment, registrationBlinder);
  const policySet = sparseMerkleRootAndSiblings(
    [[request.policySetLeafPosition, policy]],
    POLICY_SET_DEPTH,
    request.policySetLeafPosition
  );
  const entry = state.userEntries.get(request.account);
  if (entry === undefined) throw new Error(`no AuthPolicySet event found for ${request.account}`);
  if (entry.ownerNullifierKeyHash !== senderOwnerNullifierKeyHash) throw new Error("AuthPolicySet ownerNullifierKeyHash does not match profile");
  if (entry.noteSecretSeedHash !== noteSecretSeedHash) throw new Error("AuthPolicySet noteSecretSeedHash does not match profile");
  if (entry.policySetCommitment !== policySet.root) {
    throw new Error(`computed policySetCommitment ${policySet.root} does not match AuthPolicySet ${entry.policySetCommitment}`);
  }
  const expectedLeaf = authPolicyLeaf(request.account, senderOwnerNullifierKeyHash, noteSecretSeedHash, policySet.root);
  if (entry.leafValue !== expectedLeaf) throw new Error("AuthPolicySet leafValue does not match computed auth-policy leaf");
  const authMembership = sparseMerkleRootAndSiblings([...state.authLeaves.entries()], AUTH_POLICY_TREE_DEPTH, entry.leafPosition);

  const intentDigest = transactionIntentDigest({
    authVerifier: request.authVerifier,
    authorizingAddress: request.account,
    operationKind: 0n,
    tokenAddress: transfer.tokenAddress,
    recipientOwnerNullifierKeyHash: slots[0].ownerNullifierKeyHash,
    amount: slots[0].amount,
    feeNoteRecipientOwnerNullifierKeyHash: 0n,
    feeAmount: 0n,
    publicRecipientAddress: 0n,
    executionConstraintsFlags: 0n,
    lockedOutputBinding0: 0n,
    lockedOutputBinding1: 0n,
    lockedOutputBinding2: 0n,
    nonce: transfer.nonce,
    validUntilSeconds: transfer.validUntilSeconds,
    executionChainId: request.chainId
  });

  return {
    authDataCommitment,
    blindedAuthCommitment: blinded,
    transactionIntentDigest: intentDigest,
    senderOwnerNullifierKey,
    senderOwnerNullifierKeyHash,
    senderNoteSecretSeed,
    noteSecretSeedHash,
    policySetCommitment: policySet.root,
    policySetLeafPosition: request.policySetLeafPosition,
    policySetSiblings: policySet.siblings,
    leafPosition: entry.leafPosition,
    authPolicySiblings: authMembership.siblings,
    registrationBlinder,
    authCircuitInput: {
      auth_verifier: decimal(addressToField(request.authVerifier)),
      authorizing_address: decimal(addressToField(request.account)),
      token_address: decimal(addressToField(transfer.tokenAddress)),
      recipient_owner_nullifier_key_hash: decimal(slots[0].ownerNullifierKeyHash),
      amount: decimal(slots[0].amount),
      nonce: bigintToBytes(transfer.nonce, 32),
      valid_until_seconds: decimal(transfer.validUntilSeconds),
      execution_chain_id: decimal(request.chainId),
      pubkey_x: Array.from(pubkey.x),
      pubkey_y: Array.from(pubkey.y),
      signature: Array.from(signatureRS(request.authSignature.signatureBytes)),
      blinding_factor: decimal(blindingFactor)
    }
  };
}

export function buildPoolWitness(
  request: NormalizedBrowserProverRequest,
  state: DemoProverState,
  auth: DemoAuthWitness
): DemoPoolWitness {
  const transfer = request.preparedTransfer;
  const input = normalizeInputNote(request.inputNote);
  const payload = input.payload;
  const slots = transferSlots(transfer);
  const inputOwnerCommitment = ownerCommitment(auth.senderOwnerNullifierKeyHash, payload.noteSecret);
  const inputBody = noteBodyCommitment(inputOwnerCommitment, payload.amount, payload.tokenAddress);
  const inputCommitment = noteCommitment(inputBody, input.leafIndex);
  if (inputCommitment !== input.noteCommitment) throw new Error("inputNote commitment does not match payload/profile fields");
  if (state.noteLeaves.get(Number(input.leafIndex)) !== inputCommitment) {
    throw new Error(`input note commitment not found at leaf ${input.leafIndex}`);
  }

  const noteMembership = noteCommitmentTree(state.noteLeaves, NOTE_TREE_DEPTH, input.leafIndex);
  const replayId = intentReplayId(auth.senderOwnerNullifierKey, request.account, request.chainId, transfer.nonce);
  if (replayId !== toNonnegativeBigInt(transfer.intentReplayId, "preparedTransfer.intentReplayId")) {
    throw new Error("preparedTransfer.intentReplayId does not match profile/account/nonce");
  }

  const dummyOwnerHash = dummyOwnerNullifierKeyHash();
  const computedSlots = slots.map((slot, i) => {
    const expectedSecret = transactNoteSecret(auth.senderNoteSecretSeed, replayId, i as 0 | 1 | 2);
    if (slot.noteSecret !== expectedSecret) throw new Error(`output slot ${i} noteSecret does not match sender seed/replay id`);
    const owner = ownerCommitment(slot.ownerNullifierKeyHash, slot.noteSecret);
    const bodyToken = slot.isReal ? transfer.tokenAddress : "0x0000000000000000000000000000000000000000";
    const body = noteBodyCommitment(owner, slot.amount, bodyToken);
    if (body !== slot.noteBodyCommitment) throw new Error(`output slot ${i} noteBodyCommitment mismatch`);
    const binding = outputBinding(body, slot.outputNoteDataHash);
    if (binding !== slot.outputBinding) throw new Error(`output slot ${i} outputBinding mismatch`);
    return { ...slot, noteBodyCommitment: body, outputBinding: binding };
  }) as unknown as readonly [TransferSlotWitness, TransferSlotWitness, TransferSlotWitness];

  if (!computedSlots[0].isReal) throw new Error("transfer output slot 0 must be real");
  if (computedSlots[2].isReal) throw new Error("fee output slot 2 is not supported by the current demo transfer payload");
  if (!computedSlots[1].isReal && computedSlots[1].ownerNullifierKeyHash !== dummyOwnerHash) {
    throw new Error("dummy change output must use the reserved dummy owner hash");
  }
  if (computedSlots[2].ownerNullifierKeyHash !== dummyOwnerHash) {
    throw new Error("dummy fee output must use the reserved dummy owner hash");
  }

  const publicInputs: DemoPoolPublicInputs = {
    noteCommitmentRoot: state.noteRoot,
    nullifier0: nullifier(inputCommitment, auth.senderOwnerNullifierKey),
    nullifier1: phantomNullifier(auth.senderOwnerNullifierKey, replayId, 1),
    noteBodyCommitment0: computedSlots[0].noteBodyCommitment,
    noteBodyCommitment1: computedSlots[1].noteBodyCommitment,
    noteBodyCommitment2: computedSlots[2].noteBodyCommitment,
    publicAmountOut: 0n,
    publicRecipientAddress: 0n,
    publicTokenAddress: 0n,
    intentReplayId: replayId,
    validUntilSeconds: toNonnegativeBigInt(transfer.validUntilSeconds, "preparedTransfer.validUntilSeconds"),
    executionChainId: request.chainId,
    authPolicyRoot: state.authRoot,
    outputNoteDataHash0: computedSlots[0].outputNoteDataHash,
    outputNoteDataHash1: computedSlots[1].outputNoteDataHash,
    outputNoteDataHash2: computedSlots[2].outputNoteDataHash,
    authVerifier: addressToField(request.authVerifier),
    blindedAuthCommitment: auth.blindedAuthCommitment,
    transactionIntentDigest: auth.transactionIntentDigest
  };

  return {
    publicInputs,
    witnessInput: decimalize({
      ...publicInputs,
      senderOwnerNullifierKey: auth.senderOwnerNullifierKey,
      senderNoteSecretSeed: auth.senderNoteSecretSeed,
      authorizingAddress: addressToField(request.account),
      noteSecretSeedHash: auth.noteSecretSeedHash,
      policySetCommitment: auth.policySetCommitment,
      leafPosition: auth.leafPosition,
      authPolicySiblings: auth.authPolicySiblings,
      inIsReal: [1n, 0n],
      inAmount: [payload.amount, 0n],
      inNoteSecret: [payload.noteSecret, 0n],
      inLeafIndex: [input.leafIndex, 0n],
      inSiblings: [noteMembership.siblings, Array(NOTE_TREE_DEPTH).fill(0n)],
      outIsReal: computedSlots.map((slot) => slot.isReal ? 1n : 0n),
      outAmount: computedSlots.map((slot) => slot.amount),
      outOwnerNullifierKeyHash: computedSlots.map((slot) => slot.ownerNullifierKeyHash),
      outLockedOutputBinding: [0n, 0n, 0n],
      tokenAddress: addressToField(transfer.tokenAddress),
      recipientOwnerNullifierKeyHash: computedSlots[0].ownerNullifierKeyHash,
      feeNoteRecipientOwnerNullifierKeyHash: 0n,
      feeAmount: 0n,
      nonce: transfer.nonce,
      executionConstraintsFlags: 0n,
      authDataCommitment: auth.authDataCommitment,
      blindingFactor: request.authSignature.blindingFactor,
      registrationBlinder: auth.registrationBlinder,
      policySetLeafPosition: auth.policySetLeafPosition,
      policySetSiblings: auth.policySetSiblings
    }),
    outputNoteDataHexes: computedSlots.map((slot) => slot.outputNoteDataHex) as [`0x${string}`, `0x${string}`, `0x${string}`]
  };
}

export function publicInputObjectFromSignals(signals: readonly FieldNumberish[]): DemoPoolPublicInputs {
  if (signals.length < POOL_PUBLIC_INPUT_FIELDS.length) {
    throw new Error(`pool public signals length ${signals.length} is less than ${POOL_PUBLIC_INPUT_FIELDS.length}`);
  }
  return Object.fromEntries(
    POOL_PUBLIC_INPUT_FIELDS.map((field, i) => [field, toNonnegativeBigInt(must(signals[i], field), field)])
  ) as unknown as DemoPoolPublicInputs;
}

export function publicInputStrings(publicInputs: DemoPoolPublicInputs): Record<keyof DemoPoolPublicInputs, string> {
  return Object.fromEntries(
    POOL_PUBLIC_INPUT_FIELDS.map((field) => [field, publicInputs[field].toString(10)])
  ) as Record<keyof DemoPoolPublicInputs, string>;
}

export function verifyPoolAuthAgreement(poolPublicInputs: DemoPoolPublicInputs, authPublicInputs: readonly FieldNumberish[]): void {
  if (authPublicInputs.length !== 2) throw new Error(`auth proof returned ${authPublicInputs.length} public inputs; expected 2`);
  const authBlinded = toNonnegativeBigInt(authPublicInputs[0] ?? 0n, "authPublicInputs[0]");
  const authDigest = toNonnegativeBigInt(authPublicInputs[1] ?? 0n, "authPublicInputs[1]");
  if (poolPublicInputs.blindedAuthCommitment !== authBlinded) {
    throw new Error(`blinded auth commitment mismatch: pool=${poolPublicInputs.blindedAuthCommitment} auth=${authBlinded}`);
  }
  if (poolPublicInputs.transactionIntentDigest !== authDigest) {
    throw new Error(`transaction intent digest mismatch: pool=${poolPublicInputs.transactionIntentDigest} auth=${authDigest}`);
  }
}

export function snarkjsProofToBytes(proof: SnarkjsGroth16Proof): Uint8Array {
  return concatBytes(g1Bytes(proof.pi_a), g2BytesEvm(proof.pi_b), g1Bytes(proof.pi_c));
}

export function normalizeBrowserProverRequest(request: BrowserProverRequest): NormalizedBrowserProverRequest {
  const chainId = toNonnegativeBigInt(request.chainId, "chainId");
  const poolAddress = normalizeAddress(request.poolAddress, "poolAddress");
  const authVerifier = normalizeAddress(request.authVerifier, "authVerifier");
  const account = normalizeAddress(request.account ?? request.profile.account, "account");
  return {
    ...request,
    chainId,
    poolAddress,
    authVerifier,
    account,
    roots: {
      noteCommitmentRoot: toNonnegativeBigInt(request.roots.noteCommitmentRoot, "roots.noteCommitmentRoot"),
      authPolicyRoot: toNonnegativeBigInt(request.roots.authPolicyRoot, "roots.authPolicyRoot")
    },
    authSignature: normalizeAuthSignature(request.authSignature, request.preparedTransfer.blindingFactor),
    policySetLeafPosition: request.policySetLeafPosition === undefined
      ? 0n
      : toNonnegativeBigInt(request.policySetLeafPosition, "policySetLeafPosition")
  };
}

function noteCommitmentTree(
  leaves: ReadonlyMap<number, bigint>,
  depth: number,
  queryIndex: FieldNumberish = 0n
): { root: bigint; siblings: bigint[] } {
  const empty = emptyMerkleHashes(depth);
  let level = new Map(leaves);
  let pos = toLeafIndex(queryIndex);
  const siblings: bigint[] = [];
  for (let height = 0; height < depth; height += 1) {
    const sibling = pos ^ 1;
    siblings.push(level.get(sibling) ?? must(empty[height], "empty hash"));
    const next = new Map<number, bigint>();
    for (const [p] of level) {
      const paired = p ^ 1;
      const left = (p & 1) ? (level.get(paired) ?? must(empty[height], "empty left")) : must(level.get(p), "left");
      const right = (p & 1) ? must(level.get(p), "right") : (level.get(paired) ?? must(empty[height], "empty right"));
      next.set(p >> 1, poseidon(left, right));
    }
    level = next;
    pos >>= 1;
  }
  return { root: level.get(0) ?? must(empty[depth], "empty root"), siblings };
}

function transferSlots(transfer: PreparedDemoPrivateTransfer): readonly [TransferSlotWitness, TransferSlotWitness, TransferSlotWitness] {
  if (!Array.isArray(transfer.outputSlots) || transfer.outputSlots.length !== 3) {
    throw new Error("preparedTransfer.outputSlots must have exactly three slots");
  }
  return transfer.outputSlots.map((slot, i) => transferSlot(slot, i)) as [
    TransferSlotWitness,
    TransferSlotWitness,
    TransferSlotWitness
  ];
}

function transferSlot(slot: PreparedTransferSlot, i: number): TransferSlotWitness {
  const outputNoteDataHex = hexString(slot.outputNoteDataHex, `preparedTransfer.outputSlots[${i}].outputNoteDataHex`);
  const computedHash = outputNoteDataHash(hexToBytes(outputNoteDataHex, `preparedTransfer.outputSlots[${i}].outputNoteDataHex`));
  const suppliedHash = toNonnegativeBigInt(slot.outputNoteDataHash, `preparedTransfer.outputSlots[${i}].outputNoteDataHash`);
  if (suppliedHash !== computedHash) throw new Error(`output slot ${i} outputNoteDataHash mismatch`);
  return {
    outputIndex: slot.outputIndex,
    isReal: Boolean(slot.isReal),
    amount: toNonnegativeBigInt(slot.amount, `preparedTransfer.outputSlots[${i}].amount`),
    ownerNullifierKeyHash: toNonnegativeBigInt(slot.ownerNullifierKeyHash, `preparedTransfer.outputSlots[${i}].ownerNullifierKeyHash`),
    noteSecret: toNonnegativeBigInt(slot.noteSecret, `preparedTransfer.outputSlots[${i}].noteSecret`),
    noteBodyCommitment: toNonnegativeBigInt(slot.noteBodyCommitment, `preparedTransfer.outputSlots[${i}].noteBodyCommitment`),
    outputNoteDataHash: computedHash,
    outputNoteDataHex,
    outputBinding: toNonnegativeBigInt(slot.outputBinding, `preparedTransfer.outputSlots[${i}].outputBinding`)
  };
}

function normalizeInputNote(note: IndexedNote): {
  leafIndex: bigint;
  noteCommitment: bigint;
  payload: {
    tokenAddress: HexAddress;
    amount: bigint;
    noteSecret: bigint;
  };
} {
  const payload = note.payload;
  if (payload === undefined) throw new Error("inputNote.payload is required");
  return {
    leafIndex: toNonnegativeBigInt(note.leafIndex ?? payload.leafIndex ?? 0n, "inputNote.leafIndex"),
    noteCommitment: toNonnegativeBigInt(note.noteCommitment ?? payload.noteCommitment ?? 0n, "inputNote.noteCommitment"),
    payload: {
      tokenAddress: normalizeAddress(payload.tokenAddress, "inputNote.payload.tokenAddress"),
      amount: toNonnegativeBigInt(payload.amount, "inputNote.payload.amount"),
      noteSecret: toNonnegativeBigInt(payload.noteSecret, "inputNote.payload.noteSecret")
    }
  };
}

function normalizeAuthSignature(value: AuthSignatureInput, fallbackBlindingFactor: FieldNumberish): NormalizedAuthSignature {
  const auth = typeof value === "string" ? { signature: value } : value;
  const signature = hexString(auth.signature, "authSignature.signature");
  const signatureBytes = hexToBytes(signature, "authSignature.signature");
  if (signatureBytes.length !== 64 && signatureBytes.length !== 65) {
    throw new Error("authSignature.signature must be a 64-byte r||s or 65-byte EIP-712 signature");
  }
  const out: NormalizedAuthSignature = {
    signature,
    signatureBytes,
    blindingFactor: toNonnegativeBigInt(auth.blindingFactor ?? fallbackBlindingFactor, "blindingFactor")
  };
  if (auth.pubkeyX !== undefined) out.pubkeyX = expectByteLength(auth.pubkeyX, 32, "authSignature.pubkeyX");
  if (auth.pubkeyY !== undefined) out.pubkeyY = expectByteLength(auth.pubkeyY, 32, "authSignature.pubkeyY");
  return out;
}

function recoverOrReadPubkey(authSignature: NormalizedAuthSignature, digestHex: `0x${string}`): { x: Uint8Array; y: Uint8Array } {
  if (authSignature.signatureBytes.length === 65) {
    const recovered = recoverPublicKey(digestHex, authSignature.signature);
    return {
      x: recovered.publicKey.slice(1, 33),
      y: recovered.publicKey.slice(33, 65)
    };
  }
  if (authSignature.pubkeyX && authSignature.pubkeyY) return { x: authSignature.pubkeyX, y: authSignature.pubkeyY };
  throw new Error("64-byte auth signatures must include authSignature.pubkeyX and authSignature.pubkeyY");
}

function assertPreparedPreviewMatches(transfer: PreparedDemoPrivateTransfer, publicInputs: DemoPoolPublicInputs): void {
  const preview = transfer.publicInputPreview;
  for (const field of POOL_PUBLIC_INPUT_FIELDS) {
    const previewValue = preview[field as keyof typeof preview];
    if (previewValue === undefined) continue;
    const expected = toNonnegativeBigInt(previewValue, `preparedTransfer.publicInputPreview.${field}`);
    if (expected !== publicInputs[field]) {
      throw new Error(`preparedTransfer publicInputPreview.${field}=${expected} but witness uses ${publicInputs[field]}`);
    }
  }
}

function isDepositEvent(
  event: ShieldedPoolDepositEvent | ShieldedPoolTransactEvent
): event is ShieldedPoolDepositEvent {
  return "leafIndex" in event;
}

function sortEvents<T extends { blockNumber?: number; logIndex?: number }>(events: readonly T[]): T[] {
  return [...events].sort((a, b) => {
    const blockDiff = (a.blockNumber ?? 0) - (b.blockNumber ?? 0);
    if (blockDiff !== 0) return blockDiff;
    return (a.logIndex ?? 0) - (b.logIndex ?? 0);
  });
}

function toLeafIndex(value: FieldNumberish): number {
  const leaf = toNonnegativeBigInt(value, "leaf index");
  if (leaf > 0xffffffffn) throw new Error(`leaf index out of range: ${leaf}`);
  return Number(leaf);
}

function decimal(value: FieldNumberish): string {
  return toNonnegativeBigInt(value, "decimal").toString(10);
}

function decimalize(value: unknown): unknown {
  if (typeof value === "bigint") return value.toString(10);
  if (Array.isArray(value)) return value.map(decimalize);
  if (isRecord(value)) return Object.fromEntries(Object.entries(value).map(([key, field]) => [key, decimalize(field)]));
  return value;
}

function signatureRS(bytes: Uint8Array): Uint8Array {
  return bytes.length === 64 ? bytes : bytes.slice(0, 64);
}

function publicKeyToAddress(publicKey: BytesLike): HexAddress {
  const raw = toBytes(publicKey, "publicKey");
  if (raw.length !== 64) throw new Error("public key must be 64 bytes");
  const hash = keccak_256(raw);
  return normalizeAddress(bytesToHex(hash.slice(-20)), "publicKey address");
}

function bigintToBytes(value: FieldNumberish, length: number): number[] {
  let n = toNonnegativeBigInt(value, "bytes");
  const out = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i -= 1) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  if (n !== 0n) throw new Error(`value does not fit in ${length} bytes`);
  return Array.from(out);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function expectByteLength(value: BytesLike, length: number, name: string): Uint8Array {
  const bytes = toBytes(value, name);
  if (bytes.length !== length) throw new Error(`${name} must be ${length} bytes`);
  return bytes;
}

function hexString(value: unknown, name: string): `0x${string}` {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]*$/.test(value) || value.length % 2 !== 0) {
    throw new Error(`${name} must be hex bytes`);
  }
  return value as `0x${string}`;
}

function fpBytes(value: FieldNumberish): Uint8Array {
  let x = toNonnegativeBigInt(value, "proof scalar");
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i -= 1) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) throw new Error("scalar > 256 bits");
  return out;
}

function g1Bytes(point: SnarkjsG1Point): Uint8Array {
  if (toNonnegativeBigInt(point[2], "g1 z") !== 1n) throw new Error("g1 z != 1");
  return concatBytes(fpBytes(point[0]), fpBytes(point[1]));
}

function g2BytesEvm(point: SnarkjsG2Point): Uint8Array {
  if (toNonnegativeBigInt(point[2][0], "g2 z c0") !== 1n || toNonnegativeBigInt(point[2][1], "g2 z c1") !== 0n) {
    throw new Error("g2 z != (1,0)");
  }
  return concatBytes(
    fpBytes(point[0][1]),
    fpBytes(point[0][0]),
    fpBytes(point[1][1]),
    fpBytes(point[1][0])
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function must<T>(value: T | undefined, name: string): T {
  if (value === undefined) throw new Error(`${name} missing`);
  return value;
}

type SnarkjsG1Point = [FieldNumberish, FieldNumberish, FieldNumberish];
type SnarkjsG2Point = [
  [FieldNumberish, FieldNumberish],
  [FieldNumberish, FieldNumberish],
  [FieldNumberish, FieldNumberish]
];

export interface SnarkjsGroth16Proof {
  pi_a: SnarkjsG1Point;
  pi_b: SnarkjsG2Point;
  pi_c: SnarkjsG1Point;
}
