// Build a worst-case witness input for the pool circuit:
//   transfer (operationKind=0, derived from publicAmountOut == 0)
//   2 real inputs, 3 real outputs (no phantoms, no dummies)
//   fee slot used (slot 2 active)
//   all 3 output slots locked (lockedOutputBinding != 0 paired with flag bits 0/1/2)
//
// Computes all derived values (commitments, nullifiers, Merkle roots)
// off-circuit using scripts/poseidon2.js so the circuit's checks all pass.
//
// Output: build/pool/input.json — directly consumable by the wasm witness gen.
//
// Witness shape MUST track circuits/pool/pool.circom — fields the circuit
// derives (path bits, leaf-index bits, operationKind, output token slots) are
// NOT included; canonical tokenAddress and feeNoteRecipientAddress are.

const fs = require('fs');
const path = require('path');
const { poseidon, P } = require('./poseidon2');
const { keccak256 } = require('ethereum-cryptography/keccak');
const { utf8ToBytes } = require('ethereum-cryptography/utils');

const ROOT = path.resolve(__dirname, '../..');
const TAGS = JSON.parse(fs.readFileSync(path.join(ROOT, 'build/domain_tags.json'), 'utf8'));
const T = Object.fromEntries(Object.entries(TAGS).map(([k,v]) => [k, BigInt(v)]));

// ---- Helpers ----
const bitsLSB = (val, n) => Array.from({length: n}, (_, i) => Number((BigInt(val) >> BigInt(i)) & 1n));

function buildEmptyHashes(depth) {
  const e = [0n];
  for (let h = 0; h < depth; h++) e.push(poseidon(e[h], e[h]));
  return e;
}

function noteCommitmentTreeRoot(leaves, depth) {
  const empty = buildEmptyHashes(depth);
  let level = new Map(leaves);
  for (let h = 0; h < depth; h++) {
    const next = new Map();
    for (const [pos] of level) {
      const sib = pos ^ 1;
      const left  = (pos & 1) ? (level.get(sib) ?? empty[h]) : level.get(pos);
      const right = (pos & 1) ? level.get(pos)               : (level.get(sib) ?? empty[h]);
      next.set(pos >> 1, poseidon(left, right));
    }
    level = next;
  }
  return level.get(0) ?? empty[depth];
}
function noteCommitmentSiblings(leafIdx, leaves, depth) {
  const empty = buildEmptyHashes(depth);
  const sibs = [];
  let pos = leafIdx;
  let level = new Map(leaves);
  for (let h = 0; h < depth; h++) {
    const sibPos = pos ^ 1;
    sibs.push(level.get(sibPos) ?? empty[h]);
    const next = new Map();
    for (const [p] of level) {
      const sib = p ^ 1;
      const left  = (p & 1) ? (level.get(sib) ?? empty[h]) : level.get(p);
      const right = (p & 1) ? level.get(p)                  : (level.get(sib) ?? empty[h]);
      next.set(p >> 1, poseidon(left, right));
    }
    level = next;
    pos = pos >> 1;
  }
  return sibs;
}

// Sparse depth-160 user registry: build root + per-key siblings. Bottom-up
// walk uses bit h of the (uint160) key at level h (matches the circuit's
// MSB-first top-down convention; bottom-up indexing is identical for any
// fixed-depth binary key).
function buildSparseRegistryRoot(entries, depth) {
  const emptyAtLevel = [0n];
  for (let h = 0; h < depth; h++) {
    emptyAtLevel.push(poseidon(emptyAtLevel[h], emptyAtLevel[h]));
  }

  const nodes = new Map();
  const keyOf = (h, pfx) => `${h}:${pfx.toString(16)}`;
  for (const e of entries) {
    nodes.set(keyOf(0, BigInt(e.key)), e.leaf);
  }
  for (let h = 0; h < depth; h++) {
    const nextPrefixes = new Set();
    for (const k of nodes.keys()) {
      const [hStr, hex] = k.split(':');
      if (Number(hStr) !== h) continue;
      const pfx = BigInt('0x' + hex);
      nextPrefixes.add(pfx >> 1n);
    }
    for (const pfx of nextPrefixes) {
      const leftChild  = pfx << 1n;
      const rightChild = (pfx << 1n) | 1n;
      const leftVal  = nodes.get(keyOf(h, leftChild))  ?? emptyAtLevel[h];
      const rightVal = nodes.get(keyOf(h, rightChild)) ?? emptyAtLevel[h];
      nodes.set(keyOf(h+1, pfx), poseidon(leftVal, rightVal));
    }
  }
  const root = nodes.get(keyOf(depth, 0n)) ?? emptyAtLevel[depth];

  function siblingsForKey(key) {
    const sibs = [];
    let pos = BigInt(key);
    for (let h = 0; h < depth; h++) {
      const cur = pos >> BigInt(h);
      const sibPfx = cur ^ 1n;
      sibs.push(nodes.get(keyOf(h, sibPfx)) ?? emptyAtLevel[h]);
    }
    return sibs;
  }

  return { root, siblingsForKey };
}

// ---- Sender identity ----
const senderOwnerNullifierKey = 0xCAFE0001n;
const senderNoteSecretSeed    = 0xCAFE0002n;
const authorizingAddress      = 0x1111111111111111111111111111111111111111n;

const senderOwnerNullifierKeyHash = poseidon(T.OWNER_NULLIFIER_KEY_HASH_DOMAIN, senderOwnerNullifierKey);
const senderNoteSecretSeedHash    = poseidon(T.NOTE_SECRET_SEED_DOMAIN,         senderNoteSecretSeed);
const senderRegLeaf = poseidon(
  T.USER_REGISTRY_LEAF_DOMAIN,
  authorizingAddress,
  senderOwnerNullifierKeyHash,
  senderNoteSecretSeedHash,
);

// ---- Canonical token (single witness shared across real inputs/outputs) ----
const tokenAddress = 0x2222222222222222222222222222222222222222n;

// ---- Inputs (2 real notes, both spent, owned by sender) ----
const inIsReal      = [1n, 1n];
const inAmount      = [10n, 5n];
const inNoteSecret  = [0xDEADBEEF01n, 0xDEADBEEF02n];
const inLeafIndex   = [0n, 1n];

const inOwnerCommitment = inAmount.map((_, i) =>
  poseidon(T.OWNER_COMMITMENT_DOMAIN, senderOwnerNullifierKeyHash, inNoteSecret[i]));
const inNoteBodyCommitment = inAmount.map((_, i) =>
  poseidon(T.NOTE_BODY_COMMITMENT_DOMAIN, inOwnerCommitment[i], inAmount[i], tokenAddress));
const inNoteCommitment = inAmount.map((_, i) =>
  poseidon(T.NOTE_COMMITMENT_DOMAIN, inNoteBodyCommitment[i], inLeafIndex[i]));
const inRealNullifier = inAmount.map((_, i) =>
  poseidon(T.NULLIFIER_DOMAIN, inNoteCommitment[i], senderOwnerNullifierKey));

// Mirror the on-chain two-deposit setup: input 0 was deposited first
// (post-deposit-1 root R1, accumulator leaf 0); input 1 was deposited next
// (post-deposit-2 root R2, accumulator leaf 1). Each input gets its own
// per-slot noteRoot + rootLogIndex, exercising the spec's per-slot
// independence.
const noteLeavesAfterDeposit1 = new Map([
  [Number(inLeafIndex[0]), inNoteCommitment[0]],
]);
const noteLeavesAfterDeposit2 = new Map([
  [Number(inLeafIndex[0]), inNoteCommitment[0]],
  [Number(inLeafIndex[1]), inNoteCommitment[1]],
]);
const noteRootAfterDeposit1 = noteCommitmentTreeRoot(noteLeavesAfterDeposit1, 32);
const noteRootAfterDeposit2 = noteCommitmentTreeRoot(noteLeavesAfterDeposit2, 32);

const inNoteRoot = [noteRootAfterDeposit1, noteRootAfterDeposit2];
const inRootLogIndex = [0n, 1n];
// Each input's note-tree path is taken at the era it was first witnessed.
// Input 0: leaf 0 in a tree that has only itself.
// Input 1: leaf 1 in a tree that has both inputs.
const inSiblings = [
  noteCommitmentSiblings(Number(inLeafIndex[0]), noteLeavesAfterDeposit1, 32),
  noteCommitmentSiblings(Number(inLeafIndex[1]), noteLeavesAfterDeposit2, 32),
];

// Build the depth-32 historical note-root accumulator: leaf at index i is
// poseidon(HISTORICAL_NOTE_ROOT_LEAF_DOMAIN, inNoteRoot[i], i).
const histLeaves = new Map(inNoteRoot.map((nr, i) => [
  Number(inRootLogIndex[i]),
  poseidon(T.HISTORICAL_NOTE_ROOT_LEAF_DOMAIN, nr, inRootLogIndex[i]),
]));
const historicalNoteRootAccumulatorRoot = noteCommitmentTreeRoot(histLeaves, 32);
const inHistRootSiblings = inRootLogIndex.map(idx =>
  noteCommitmentSiblings(Number(idx), histLeaves, 32));

// ---- Outputs (all 3 real) ----
const outIsReal = [1n, 1n, 1n];
const outAmount = [8n, 5n, 2n]; // 8+5+2 = 15 = 10+5 input total, publicAmountOut = 0

const outRecipient = [
  0x3333333333333333333333333333333333333333n, // payment recipient (transfer slot 0)
  authorizingAddress,                          // change to sender (slot 1)
  0x4444444444444444444444444444444444444444n, // fee recipient (slot 2)
];
const outOwnerNullifierKey = [
  0xBABE0001n,                  // recipient's key
  senderOwnerNullifierKey,      // sender's own key for change
  0xBABE0003n,                  // fee recipient's key
];
const outOwnerNullifierKeyHash = outOwnerNullifierKey.map(k =>
  poseidon(T.OWNER_NULLIFIER_KEY_HASH_DOMAIN, k));
const outRecipientNoteSecretSeed = [0xC0DE01n, senderNoteSecretSeed, 0xC0DE03n];
const outRecipientNoteSecretSeedHash = outRecipientNoteSecretSeed.map(s =>
  poseidon(T.NOTE_SECRET_SEED_DOMAIN, s));

// ---- User registry (sender + 3 recipients, deduplicated) ----
const outRecipientLeaf = outRecipient.map((u, i) =>
  poseidon(T.USER_REGISTRY_LEAF_DOMAIN, u, outOwnerNullifierKeyHash[i],
           outRecipientNoteSecretSeedHash[i]));

const registryEntries = [
  { key: authorizingAddress, leaf: senderRegLeaf },
  { key: outRecipient[0],    leaf: outRecipientLeaf[0] },
  { key: outRecipient[1],    leaf: outRecipientLeaf[1] }, // sender's own — same key as sender
  { key: outRecipient[2],    leaf: outRecipientLeaf[2] },
];
const dedupedEntries = [];
const seen = new Set();
for (const e of registryEntries) {
  const k = e.key.toString();
  if (!seen.has(k)) { dedupedEntries.push(e); seen.add(k); }
}
const userRegBuilt = buildSparseRegistryRoot(dedupedEntries, 160);
const registryRoot = userRegBuilt.root;
const senderUserSiblings = userRegBuilt.siblingsForKey(authorizingAddress);
const outRecipientSiblings = outRecipient.map(u => userRegBuilt.siblingsForKey(u));

// ---- Operation mode + intent fields ----
//   operationKind is derived from publicAmountOut by the circuit; transfer
//   here means publicAmountOut == 0.
const recipientAddress      = outRecipient[0];
const feeRecipientAddress   = outRecipient[2];
const feeNoteRecipientAddress = outRecipient[2];   // matches feeRecipientAddress when feeRecipientAddress != 0
const feeAmount             = outAmount[2];
const nonce                 = 0x9F3A1C7E5B2D4F86n;
const executionConstraintsFlags = 0n;
const validUntilSeconds     = 1735689600n;
const executionChainId      = 1n;

// ---- Auth-policy registration + revocation ----
const authVerifier        = 0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1n;
const authSecret          = 0xA0701337n;
const authDataCommitment  = poseidon(T.POLICY_COMMITMENT_DOMAIN, authSecret);
const blindingFactor      = 0xB17ED15ABCDEF0123456789ABCDEF01n;
const registrationBlinder = 0xCC00CC00CC00CC00n;
const leafPosition        = 0n;

const policyCommitment = poseidon(T.POLICY_COMMITMENT_DOMAIN, authVerifier, authDataCommitment, registrationBlinder);
const authPolicyLeaf   = poseidon(T.AUTH_POLICY_DOMAIN, authorizingAddress, policyCommitment);

const authRegEmpty = [0n];
for (let h = 0; h < 32; h++) authRegEmpty.push(poseidon(authRegEmpty[h], authRegEmpty[h]));

function appendOnlyRoot(leafVal, leafIdx, depth) {
  const leaves = new Map([[Number(leafIdx), leafVal]]);
  return noteCommitmentTreeRoot(leaves, depth);
}
function appendOnlySiblings(leafIdx, leafVal, depth) {
  const leaves = new Map([[Number(leafIdx), leafVal]]);
  return noteCommitmentSiblings(Number(leafIdx), leaves, depth);
}

const authPolicyRegistrationRoot = appendOnlyRoot(authPolicyLeaf, leafPosition, 32);
const authRegSiblings            = appendOnlySiblings(leafPosition, authPolicyLeaf, 32);
const authPolicyRevocationRoot   = authRegEmpty[32];
const authRevSiblings            = Array.from({length: 32}, (_, h) => authRegEmpty[h]);

// ---- Output noteSecrets, body commitments, intent replay ID ----
const intentReplayId = poseidon(T.INTENT_REPLAY_ID_DOMAIN, senderOwnerNullifierKey,
                                 authorizingAddress, executionChainId, nonce);

const outNoteSecret = [0,1,2].map(i =>
  poseidon(T.TRANSACT_NOTE_SECRET_DOMAIN, senderNoteSecretSeed, intentReplayId, BigInt(i)));
const outOwnerCommitment = [0,1,2].map(i =>
  poseidon(T.OWNER_COMMITMENT_DOMAIN, outOwnerNullifierKeyHash[i], outNoteSecret[i]));
// All 3 outputs are real, so the body's tokenAddress field == canonical token.
// Dummy outputs would use 0 here (circuit: outBodyToken = outIsReal * tokenAddress).
const outNoteBodyCommitment = [0,1,2].map(i =>
  poseidon(T.NOTE_BODY_COMMITMENT_DOMAIN, outOwnerCommitment[i], outAmount[i], tokenAddress));

// ---- outputNoteData hashes + locked output bindings ----
const OUTPUT_NOTE_DATA = ['eip-8182-output-0', 'eip-8182-output-1', 'eip-8182-output-2'];
const outputNoteDataHash = OUTPUT_NOTE_DATA.map(s => {
  const h = keccak256(utf8ToBytes(s));
  let v = 0n;
  for (const b of h) v = (v << 8n) | BigInt(b);
  return v % P;
});
const outLockedOutputBinding = [0,1,2].map(i =>
  poseidon(T.OUTPUT_BINDING_DOMAIN, outNoteBodyCommitment[i], outputNoteDataHash[i]));

// All 3 slots locked => executionConstraintsFlags has bits 0/1/2 set (= 7).
// (Spec Section 9.11: flag bit i pairs with lockedOutputBinding_i.)
// We override executionConstraintsFlags = 7 for the worst-case witness.
const execFlagsWorstCase = 7n;

// ---- Blinded auth commitment + intent digest ----
//   Transfer mode: digest's amount == outAmount[0] (recipient amount),
//                  tokenAddress == canonical token, operationKind == 0.
const blindedAuthCommitment = poseidon(T.BLINDED_AUTH_COMMITMENT_DOMAIN, authDataCommitment, blindingFactor);
const transactionIntentDigest = poseidon(
  T.TRANSACTION_INTENT_DIGEST_DOMAIN,
  authVerifier,
  authorizingAddress,
  0n,                               // operationKind = TRANSFER_OP
  tokenAddress,
  recipientAddress,
  outAmount[0],                     // recipient amount
  feeRecipientAddress,
  feeAmount,
  execFlagsWorstCase,
  outLockedOutputBinding[0],
  outLockedOutputBinding[1],
  outLockedOutputBinding[2],
  nonce,
  validUntilSeconds,
  executionChainId,
);

// ---- Public values ----
const publicAmountOut         = 0n;     // transfer
const publicRecipientAddress  = 0n;
const publicTokenAddress      = 0n;

// ---- Assemble input.json ----
const toStr = v => (typeof v === 'bigint' ? v.toString() : String(v));
const arr   = a => a.map(toStr);
const arr2  = a => a.map(arr);

const out = {
  // public (21)
  historicalNoteRootAccumulatorRoot: toStr(historicalNoteRootAccumulatorRoot),
  nullifier0:                  toStr(inRealNullifier[0]),
  nullifier1:                  toStr(inRealNullifier[1]),
  noteBodyCommitment0:         toStr(outNoteBodyCommitment[0]),
  noteBodyCommitment1:         toStr(outNoteBodyCommitment[1]),
  noteBodyCommitment2:         toStr(outNoteBodyCommitment[2]),
  publicAmountOut:             toStr(publicAmountOut),
  publicRecipientAddress:      toStr(publicRecipientAddress),
  publicTokenAddress:          toStr(publicTokenAddress),
  intentReplayId:              toStr(intentReplayId),
  registryRoot:                toStr(registryRoot),
  validUntilSeconds:           toStr(validUntilSeconds),
  executionChainId:            toStr(executionChainId),
  authPolicyRegistrationRoot:  toStr(authPolicyRegistrationRoot),
  authPolicyRevocationRoot:    toStr(authPolicyRevocationRoot),
  outputNoteDataHash0:         toStr(outputNoteDataHash[0]),
  outputNoteDataHash1:         toStr(outputNoteDataHash[1]),
  outputNoteDataHash2:         toStr(outputNoteDataHash[2]),
  authVerifier:                toStr(authVerifier),
  blindedAuthCommitment:       toStr(blindedAuthCommitment),
  transactionIntentDigest:     toStr(transactionIntentDigest),

  // private — sender
  senderOwnerNullifierKey:     toStr(senderOwnerNullifierKey),
  senderNoteSecretSeed:        toStr(senderNoteSecretSeed),
  authorizingAddress:          toStr(authorizingAddress),
  senderUserSiblings:          arr(senderUserSiblings),

  // private — inputs
  inIsReal:                    arr(inIsReal),
  inAmount:                    arr(inAmount),
  inNoteSecret:                arr(inNoteSecret),
  inLeafIndex:                 arr(inLeafIndex),
  inSiblings:                  arr2(inSiblings),

  // private — historical note-root accumulator membership (per real input)
  inNoteRoot:                  arr(inNoteRoot),
  inRootLogIndex:              arr(inRootLogIndex),
  inHistRootSiblings:          arr2(inHistRootSiblings),

  // private — outputs
  outIsReal:                   arr(outIsReal),
  outAmount:                   arr(outAmount),
  outOwnerNullifierKeyHash:    arr(outOwnerNullifierKeyHash),
  outRecipient:                arr(outRecipient),
  outRecipientNoteSecretSeedHash: arr(outRecipientNoteSecretSeedHash),
  outRecipientSiblings:        arr2(outRecipientSiblings),
  outLockedOutputBinding:      arr(outLockedOutputBinding),

  // private — canonical token
  tokenAddress:                toStr(tokenAddress),

  // private — intent fields
  recipientAddress:            toStr(recipientAddress),
  feeRecipientAddress:         toStr(feeRecipientAddress),
  feeNoteRecipientAddress:     toStr(feeNoteRecipientAddress),
  feeAmount:                   toStr(feeAmount),
  nonce:                       toStr(nonce),
  executionConstraintsFlags:   toStr(execFlagsWorstCase),

  // private — auth-policy
  authDataCommitment:          toStr(authDataCommitment),
  blindingFactor:              toStr(blindingFactor),
  registrationBlinder:         toStr(registrationBlinder),
  leafPosition:                toStr(leafPosition),
  authRegSiblings:             arr(authRegSiblings),
  authRevSiblings:             arr(authRevSiblings),
};

const outPath = path.join(ROOT, 'build/pool/input.json');
fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.writeFileSync(outPath, JSON.stringify(out, null, 2));
console.log(`wrote ${outPath}`);
