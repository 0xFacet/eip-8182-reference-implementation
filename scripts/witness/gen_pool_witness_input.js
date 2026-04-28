// Build a worst-case witness input for the pool circuit:
//   transfer (operationKind=1)
//   2 real inputs, 3 real outputs (no phantoms, no dummies)
//   fee slot used (slot 2 active)
//   all 3 output slots locked (lockedOutputBinding != 0)
//
// Computes all derived values (commitments, nullifiers, Merkle roots)
// off-circuit using scripts/poseidon2.js so the circuit's checks all pass.
//
// Output: build/pool/input.json — directly consumable by the wasm witness gen.

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
const bitsMSB = (val, n) => Array.from({length: n}, (_, i) => Number((BigInt(val) >> BigInt(n - 1 - i)) & 1n));

// Merkle root from leaf, pathBits, siblings (poseidon(left,right) arity-2)
function merkleRoot(leaf, pathBits, siblings) {
  let cur = BigInt(leaf);
  for (let i = 0; i < pathBits.length; i++) {
    const sib = BigInt(siblings[i]);
    const [l, r] = pathBits[i] === 0 ? [cur, sib] : [sib, cur];
    cur = poseidon(l, r);
  }
  return cur;
}

// ---- Build the witness ----
const input = {};

// === Sender identity ===
const senderOwnerNullifierKey = 0xCAFE0001n;
const senderNoteSecretSeed    = 0xCAFE0002n;
const authorizingAddress      = 0x1111111111111111111111111111111111111111n; // <2^160

const senderOwnerNullifierKeyHash = poseidon(T.OWNER_NULLIFIER_KEY_HASH_DOMAIN, senderOwnerNullifierKey);
const senderNoteSecretSeedHash    = poseidon(T.NOTE_SECRET_SEED_DOMAIN,         senderNoteSecretSeed);
const senderRegLeaf = poseidon(
  T.USER_REGISTRY_LEAF_DOMAIN,
  authorizingAddress,
  senderOwnerNullifierKeyHash,
  senderNoteSecretSeedHash,
);

// User registry: depth-160, MSB-first on uint160(user).
// All-zero siblings for simplicity. registryRoot computed.
const senderUserPathBits = bitsLSB(authorizingAddress, 160);
const senderUserSiblings = Array(160).fill(0n);
const registryRoot       = merkleRoot(senderRegLeaf, senderUserPathBits, senderUserSiblings);

// === Inputs (2 real notes, both spent, owned by sender) ===
const inIsReal      = [1n, 1n];
const inAmount      = [10n, 5n];
const inTokenAddress = [0x2222222222222222222222222222222222222222n,
                        0x2222222222222222222222222222222222222222n];
const inNoteSecret  = [0xDEADBEEF01n, 0xDEADBEEF02n];
const inLeafIndex   = [0n, 1n]; // distinct leaves to avoid same-tree assumption issues

// Per-input commitments / nullifiers
const inOwnerCommitment = inAmount.map((_, i) =>
  poseidon(T.OWNER_COMMITMENT_DOMAIN, senderOwnerNullifierKeyHash, inNoteSecret[i]));
const inNoteBodyCommitment = inAmount.map((_, i) =>
  poseidon(T.NOTE_BODY_COMMITMENT_DOMAIN, inOwnerCommitment[i], inAmount[i], inTokenAddress[i]));
const inNoteCommitment = inAmount.map((_, i) =>
  poseidon(T.NOTE_COMMITMENT_DOMAIN, inNoteBodyCommitment[i], inLeafIndex[i]));
const inRealNullifier = inAmount.map((_, i) =>
  poseidon(T.NULLIFIER_DOMAIN, inNoteCommitment[i], senderOwnerNullifierKey));

// Merkle paths for the 2 input notes — both must hit noteCommitmentRoot.
// Build a single tree where slot 0 holds inNoteCommitment[0], slot 1 holds [1],
// rest empty (0). Compute pathBits from inLeafIndex (LSB-first).
// Empty subtree hash at every level: emptyAtLevel[0] = 0 (empty leaf),
// emptyAtLevel[h+1] = poseidon(emptyAtLevel[h], emptyAtLevel[h]). The contract
// uses these exact values when inserting into an append-only or sparse Merkle
// tree, so the witness MUST use them as siblings for any unset slot.
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
const noteLeaves = new Map([
  [Number(inLeafIndex[0]), inNoteCommitment[0]],
  [Number(inLeafIndex[1]), inNoteCommitment[1]],
]);
const noteCommitmentRoot = noteCommitmentTreeRoot(noteLeaves, 32);
const inSiblings = inLeafIndex.map(idx => noteCommitmentSiblings(Number(idx), noteLeaves, 32));
const inLeafIndexBits = inLeafIndex.map(idx => bitsLSB(idx, 32));

// === Outputs (all 3 real) ===
const outIsReal = [1n, 1n, 1n];
const outAmount = [8n, 5n, 2n]; // 8+5+2 = 15 = 10+5 input total, publicAmountOut = 0
const outTokenAddress = [inTokenAddress[0], inTokenAddress[0], inTokenAddress[0]];

const outRecipient = [
  0x3333333333333333333333333333333333333333n, // payment recipient
  authorizingAddress,                          // change to sender
  0x4444444444444444444444444444444444444444n, // fee recipient
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

// User-registry membership for each output recipient
const outRecipientLeaf = outRecipient.map((u, i) =>
  poseidon(T.USER_REGISTRY_LEAF_DOMAIN, u, outOwnerNullifierKeyHash[i],
           outRecipientNoteSecretSeedHash[i]));
const outRecipientPathBits = outRecipient.map(u => bitsLSB(u, 160));
// All-zero siblings for the recipient paths — but they must each give the SAME
// registryRoot to satisfy the constraint. So construct a registry that contains
// sender + all 3 recipients and use real siblings.
//
// Sparse: store the four leaves at their MSB-keyed positions.
function registryRootAndSiblings(leavesMap, depth, queryKey) {
  // leavesMap: Map<bigint key, leaf value>
  // Compute root + siblings for queryKey via depth-160 sparse Merkle.
  // We hash per-level by collecting non-empty positions and pairing.
  let level = new Map();
  for (const [key, leaf] of leavesMap) {
    level.set(BigInt(key), leaf);
  }
  let cur = BigInt(queryKey);
  const sibs = [];
  for (let h = 0; h < depth; h++) {
    const bit = Number(cur & 1n); // LSB of MSB-traversal: we walk top-down, so bit at depth d=h corresponds to bit (depth-1-h) of key. Easier: path is MSB-first, so at first iteration we use the highest bit.
    // To keep things simple and consistent with circuit, build root from bottom up
    // by walking key MSB-first through 160 levels.
    sibs.push(0n); // placeholder
    cur >>= 1n;
  }
  // Bail: this is non-trivial; use simpler approach below.
  return null;
}

// Simpler: compute registryRoot from a sparse depth-160 tree containing all
// four leaves (sender + 3 recipients). Walk top-down accumulating each level
// of the tree using the keys.
function buildSparseRegistryRoot(entries, depth) {
  // entries: array of {key: bigint (uint160), leaf: bigint}.
  // Returns: { root, siblingsForKey: Map<keyBigint, bigint[]> }
  // Approach: maintain a Map from "node ID" (depth, prefix_bits) to value.
  // node ID = (depth, prefix as bigint with depth bits, MSB-first).
  // Empty subtree value at level d (0 = leaf) = 0 (per spec, empty leaf = 0,
  // and parent of two zeros = poseidon(0, 0) which is... not 0 per length-tagged
  // sponge. Let's actually compute it.
  const emptyAtLevel = [0n];
  for (let h = 0; h < depth; h++) {
    emptyAtLevel.push(poseidon(emptyAtLevel[h], emptyAtLevel[h]));
  }

  // node values: keyed by (height, prefix MSB-first as bigint)
  // height 0 = leaf level
  const nodes = new Map();
  const keyOf = (h, pfx) => `${h}:${pfx.toString(16)}`;
  for (const e of entries) {
    nodes.set(keyOf(0, BigInt(e.key)), e.leaf);
  }
  // Walk up. For each height, determine which prefixes need recomputation.
  for (let h = 0; h < depth; h++) {
    const nextPrefixes = new Set();
    for (const k of nodes.keys()) {
      const [hStr, hex] = k.split(':');
      if (Number(hStr) !== h) continue;
      const pfx = BigInt('0x' + hex);
      nextPrefixes.add(pfx >> 1n);
    }
    for (const pfx of nextPrefixes) {
      // children: pfx*2 and pfx*2+1. left = pfx*2 -> bit 0 ? Actually MSB-first
      // means at height h we have (depth-h)-bit prefix; left child has next bit 0.
      const leftChild  = pfx << 1n;
      const rightChild = (pfx << 1n) | 1n;
      const leftVal  = nodes.get(keyOf(h, leftChild))  ?? emptyAtLevel[h];
      const rightVal = nodes.get(keyOf(h, rightChild)) ?? emptyAtLevel[h];
      nodes.set(keyOf(h+1, pfx), poseidon(leftVal, rightVal));
    }
  }
  const root = nodes.get(keyOf(depth, 0n)) ?? emptyAtLevel[depth];

  // Compute siblings for one key.
  function siblingsForKey(key) {
    // pathBits MSB-first (depth elements).
    // At each height h (going from leaf up), the current prefix is key >> h
    // (in MSB-traversal we'd want different shifting; sticking with h = bottom-up).
    // Actually for MSB-first paths in the circuit, pathBits[h] (h = 0 is at root, h = depth-1 is at leaf)
    // selects left/right at level h from root.
    // But our circuit (MerklePath) walks bottom-up: pathBits[0] is at leaf level.
    // For MSB-first: pathBits_circuit[h] = bit (depth-1-h) of key (so bit d-1 first), which
    // matches the bitsMSB() helper where bitsMSB[h] = (key >> (depth-1-h)) & 1.
    const sibs = [];
    let pos = BigInt(key);
    for (let h = 0; h < depth; h++) {
      // At height h (bottom-up), the prefix at this height has (depth-h) bits.
      // The current node is at prefix (key >> h). Its sibling has the LSB flipped.
      const cur = pos >> BigInt(h);
      const sibPfx = cur ^ 1n;
      sibs.push(nodes.get(keyOf(h, sibPfx)) ?? emptyAtLevel[h]);
    }
    return sibs;
  }

  return { root, siblingsForKey };
}

const registryEntries = [
  { key: authorizingAddress, leaf: senderRegLeaf },
  { key: outRecipient[0],    leaf: outRecipientLeaf[0] },
  { key: outRecipient[1],    leaf: outRecipientLeaf[1] }, // sender's own — same key as sender
  { key: outRecipient[2],    leaf: outRecipientLeaf[2] },
];
// dedupe: sender's key might collide with outRecipient[1]; keep the sender entry
// (they're identical anyway since output 1 is change to self)
const dedupedEntries = [];
const seen = new Set();
for (const e of registryEntries) {
  const k = e.key.toString();
  if (!seen.has(k)) { dedupedEntries.push(e); seen.add(k); }
}
const userRegBuilt = buildSparseRegistryRoot(dedupedEntries, 160);
const registryRootReal = userRegBuilt.root;
const senderUserSiblingsReal = userRegBuilt.siblingsForKey(authorizingAddress);
// For circuit pathBits convention: MSB-first walked top-down. Our MerklePath is
// bottom-up with pathBits[0] = leaf-level decision. bitsMSB(key, depth) gives
// pathBits[h] = bit (depth-1-h) which matches bottom-up walk for MSB-first key.

const outRecipientSiblings = outRecipient.map(u => userRegBuilt.siblingsForKey(u));

// === Operation mode + intent fields ===
const operationKind     = 1n; // transfer
const recipientAddress  = outRecipient[0];
const feeRecipientAddress = outRecipient[2];
const feeAmount         = outAmount[2];
const nonce             = 0x9F3A1C7E5B2D4F86n; // uniformly-random per spec (Section 9.8)
const executionConstraintsFlags = 0n; // bits 4..31 must be zero; we use 0 for simplicity
const validUntilSeconds = 1735689600n; // some uint32 time
const executionChainId  = 1n;

// === Auth-policy registration + revocation ===
// authSecret + authDataCommitment must agree with the demo auth-circuit
// witness (scripts/witness/gen_auth_demo_witness_input.js) so the two proofs
// share identical blindedAuthCommitment + transactionIntentDigest values.
const authVerifier        = 0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1n;
const authSecret          = 0xA0701337n;
const authDataCommitment  = poseidon(T.POLICY_COMMITMENT_DOMAIN, authSecret);
const blindingFactor      = 0xB17ED15ABCDEF0123456789ABCDEF01n;
const registrationBlinder = 0xCC00CC00CC00CC00n;
// First slot in the registration tree, so the integration test only needs a
// single registerAuthPolicy call to reproduce the witness's tree state.
const leafPosition        = 0n;
const leafPositionBits    = bitsLSB(leafPosition, 32);

const policyCommitment = poseidon(T.POLICY_COMMITMENT_DOMAIN, authVerifier, authDataCommitment, registrationBlinder);
const authPolicyLeaf   = poseidon(T.AUTH_POLICY_DOMAIN, authorizingAddress, policyCommitment);

// Auth-policy registration tree: depth-32 append-only. Place our leaf at leafPosition,
// rest empty. Empty leaf = 0; empty subtree at level h = poseidon^h(0,0).
const authRegEmpty = [0n];
for (let h = 0; h < 32; h++) authRegEmpty.push(poseidon(authRegEmpty[h], authRegEmpty[h]));

function appendOnlyRoot(leafVal, leafIdx, depth) {
  // Same as note tree: only one leaf set, others zero.
  const leaves = new Map([[Number(leafIdx), leafVal]]);
  return noteCommitmentTreeRoot(leaves, depth);
}
function appendOnlySiblings(leafIdx, leafVal, depth) {
  const leaves = new Map([[Number(leafIdx), leafVal]]);
  return noteCommitmentSiblings(Number(leafIdx), leaves, depth);
}

const authPolicyRegistrationRoot = appendOnlyRoot(authPolicyLeaf, leafPosition, 32);
const authRegSiblings            = appendOnlySiblings(leafPosition, authPolicyLeaf, 32);

// Auth-policy revocation tree: leaf at leafPosition is 0 (non-revoked).
// Empty everywhere => root = empty subtree at depth 32.
const authPolicyRevocationRoot = authRegEmpty[32];
const authRevSiblings          = Array.from({length: 32}, (_, h) => authRegEmpty[h]);

// === Output noteSecrets, output owner/body commitments, intent replay ID ===
const intentReplayId = poseidon(T.INTENT_REPLAY_ID_DOMAIN, senderOwnerNullifierKey,
                                 authorizingAddress, executionChainId, nonce);

const outNoteSecret = [0n, 0n, 0n].map((_, i) =>
  poseidon(T.TRANSACT_NOTE_SECRET_DOMAIN, senderNoteSecretSeed, intentReplayId, BigInt(i)));
const outOwnerCommitment = [0,1,2].map(i =>
  poseidon(T.OWNER_COMMITMENT_DOMAIN, outOwnerNullifierKeyHash[i], outNoteSecret[i]));
const outNoteBodyCommitment = [0,1,2].map(i =>
  poseidon(T.NOTE_BODY_COMMITMENT_DOMAIN, outOwnerCommitment[i], outAmount[i], outTokenAddress[i]));

// outputNoteDataHash values are public inputs. For the worst case we lock all 3
// slots: lockedOutputBinding_i = poseidon(OUTPUT_BINDING_DOMAIN, body_i, dataHash_i).
// outputNoteDataHash = uint256(keccak256(outputNoteData_i)) mod p (Section 9.7).
// We commit to fixed payload strings here so the integration test can pass the
// same bytes to transact() and have the contract recompute matching hashes.
const OUTPUT_NOTE_DATA = ['eip-8182-output-0', 'eip-8182-output-1', 'eip-8182-output-2'];
const outputNoteDataHash = OUTPUT_NOTE_DATA.map(s => {
  const h = keccak256(utf8ToBytes(s));
  let v = 0n;
  for (const b of h) v = (v << 8n) | BigInt(b);
  return v % P;
});
const outLockedOutputBinding = [0,1,2].map(i =>
  poseidon(T.OUTPUT_BINDING_DOMAIN, outNoteBodyCommitment[i], outputNoteDataHash[i]));

// === Blinded auth commitment + intent digest ===
const blindedAuthCommitment = poseidon(T.BLINDED_AUTH_COMMITMENT_DOMAIN, authDataCommitment, blindingFactor);
const transactionIntentDigest = poseidon(
  T.TRANSACTION_INTENT_DIGEST_DOMAIN,
  authVerifier,
  authorizingAddress,
  operationKind,
  inTokenAddress[0],
  recipientAddress,
  inAmount[0],
  feeRecipientAddress,
  feeAmount,
  executionConstraintsFlags,
  outLockedOutputBinding[0],
  outLockedOutputBinding[1],
  outLockedOutputBinding[2],
  nonce,
  validUntilSeconds,
  executionChainId,
);

// === Public values ===
const publicAmountOut         = 0n;     // transfer
const publicRecipientAddress  = 0n;
const publicTokenAddress      = 0n;

// === Assemble input.json ===
const toStr = v => (typeof v === 'bigint' ? v.toString() : String(v));
const arr   = a => a.map(toStr);
const arr2  = a => a.map(arr);

const out = {
  // public
  noteCommitmentRoot:          toStr(noteCommitmentRoot),
  nullifier0:                  toStr(inRealNullifier[0]),
  nullifier1:                  toStr(inRealNullifier[1]),
  noteBodyCommitment0:         toStr(outNoteBodyCommitment[0]),
  noteBodyCommitment1:         toStr(outNoteBodyCommitment[1]),
  noteBodyCommitment2:         toStr(outNoteBodyCommitment[2]),
  publicAmountOut:             toStr(publicAmountOut),
  publicRecipientAddress:      toStr(publicRecipientAddress),
  publicTokenAddress:          toStr(publicTokenAddress),
  intentReplayId:              toStr(intentReplayId),
  registryRoot:                toStr(registryRootReal),
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

  // private
  senderOwnerNullifierKey:     toStr(senderOwnerNullifierKey),
  senderNoteSecretSeed:        toStr(senderNoteSecretSeed),
  authorizingAddress:          toStr(authorizingAddress),
  senderUserPathBits:          arr(senderUserPathBits),
  senderUserSiblings:          arr(senderUserSiblingsReal),

  inIsReal:                    arr(inIsReal),
  inAmount:                    arr(inAmount),
  inTokenAddress:              arr(inTokenAddress),
  inNoteSecret:                arr(inNoteSecret),
  inLeafIndex:                 arr(inLeafIndex),
  inLeafIndexBits:             arr2(inLeafIndexBits),
  inSiblings:                  arr2(inSiblings),

  outIsReal:                   arr(outIsReal),
  outAmount:                   arr(outAmount),
  outTokenAddress:             arr(outTokenAddress),
  outOwnerNullifierKeyHash:    arr(outOwnerNullifierKeyHash),
  outRecipient:                arr(outRecipient),
  outRecipientNoteSecretSeedHash: arr(outRecipientNoteSecretSeedHash),
  outRecipientPathBits:        arr2(outRecipientPathBits),
  outRecipientSiblings:        arr2(outRecipientSiblings),
  outLockedOutputBinding:      arr(outLockedOutputBinding),

  operationKind:               toStr(operationKind),
  recipientAddress:            toStr(recipientAddress),
  feeRecipientAddress:         toStr(feeRecipientAddress),
  feeAmount:                   toStr(feeAmount),
  nonce:                       toStr(nonce),
  executionConstraintsFlags:   toStr(executionConstraintsFlags),

  authDataCommitment:          toStr(authDataCommitment),
  blindingFactor:              toStr(blindingFactor),
  registrationBlinder:         toStr(registrationBlinder),
  leafPosition:                toStr(leafPosition),
  leafPositionBits:            arr(leafPositionBits),
  authRegSiblings:             arr(authRegSiblings),
  authRevSiblings:             arr(authRevSiblings),
};

const outPath = path.join(ROOT, 'build/pool/input.json');
fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.writeFileSync(outPath, JSON.stringify(out, null, 2));
console.log(`wrote ${outPath}`);
