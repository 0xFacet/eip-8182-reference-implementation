#!/usr/bin/env node
// Negative-witness tests for the pool circuit.
//
// Each case applies a targeted mutation to the worst-case happy-path witness
// at build/pool/input.json, runs the wasm witness generator, and asserts it
// fails. Where a mutation changes a value the circuit re-derives downstream
// (output commitments, locked output bindings, intent digest), the test
// recomputes the dependent values via `recomputeDerived` so the failure
// isolates the intended constraint rather than firing on a stale binding.
//
// Usage:
//   node scripts/witness/gen_pool_witness_input.js   # produce baseline first
//   node scripts/witness/negative_test.js
//
// Exit code 0 = all negatives correctly rejected; 1 = at least one passed
// when it should have failed.

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { spawnSync } = require('child_process');
const { poseidon } = require('./poseidon2');

const ROOT      = path.resolve(__dirname, '../..');
const POOL_DIR  = path.join(ROOT, 'build/pool');
const BASE_JSON = path.join(POOL_DIR, 'input.json');
const WASM      = path.join(POOL_DIR, 'pool_js/pool.wasm');
const WGEN      = path.join(POOL_DIR, 'pool_js/generate_witness.js');

if (!fs.existsSync(BASE_JSON)) {
  console.error(`baseline witness ${BASE_JSON} missing — run gen_pool_witness_input.js first`);
  process.exit(2);
}

const TAGS = JSON.parse(fs.readFileSync(path.join(ROOT, 'build/domain_tags.json'), 'utf8'));
const T = Object.fromEntries(Object.entries(TAGS).map(([k, v]) => [k, BigInt(v)]));
const DUMMY_OWNER_HASH = poseidon(T.OWNER_NULLIFIER_KEY_HASH_DOMAIN, 0xdeadn).toString();

const BASE = JSON.parse(fs.readFileSync(BASE_JSON, 'utf8'));

function clone(o) {
  return JSON.parse(JSON.stringify(o));
}

function tryGenerateWitness(input) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'eip8182-neg-'));
  const inPath  = path.join(tmp, 'input.json');
  const outPath = path.join(tmp, 'witness.wtns');
  fs.writeFileSync(inPath, JSON.stringify(input));
  try {
    const r = spawnSync('node', [WGEN, WASM, inPath, outPath], { encoding: 'utf8' });
    return { ok: r.status === 0, stderr: r.stderr || r.stdout || '' };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

// Recompute every derived value the pool circuit checks via equality against a
// public input or against another witness. After this helper runs the witness
// is internally consistent except for whatever invariant the mutation broke.
function recomputeDerived(w) {
  const get = (k) => BigInt(w[k]);
  const senderOwnerNullifierKey = get('senderOwnerNullifierKey');
  const senderNoteSecretSeed    = get('senderNoteSecretSeed');
  const authorizingAddress      = get('authorizingAddress');
  const executionChainId        = get('executionChainId');
  const nonce                   = get('nonce');
  const tokenAddress            = get('tokenAddress');
  const publicAmountOut         = get('publicAmountOut');
  const operationKind           = publicAmountOut === 0n ? 0n : 1n;
  const flags                   = get('executionConstraintsFlags');

  const intentReplayId = poseidon(
    T.INTENT_REPLAY_ID_DOMAIN,
    senderOwnerNullifierKey, authorizingAddress, executionChainId, nonce,
  );

  const outOwnerNullifierKeyHash = w.outOwnerNullifierKeyHash.map(BigInt);
  const outAmount   = w.outAmount.map(BigInt);
  const outIsReal   = w.outIsReal.map(BigInt);
  const outputNoteDataHash = [
    BigInt(w.outputNoteDataHash0),
    BigInt(w.outputNoteDataHash1),
    BigInt(w.outputNoteDataHash2),
  ];

  const outNoteSecret = [0n, 1n, 2n].map((i) =>
    poseidon(T.TRANSACT_NOTE_SECRET_DOMAIN, senderNoteSecretSeed, intentReplayId, i));
  const outOwnerCommitment = [0, 1, 2].map((i) =>
    poseidon(T.OWNER_COMMITMENT_DOMAIN, outOwnerNullifierKeyHash[i], outNoteSecret[i]));
  const noteBodyCommitment = [0, 1, 2].map((i) => {
    const bodyToken = outIsReal[i] === 0n ? 0n : tokenAddress;
    return poseidon(T.NOTE_BODY_COMMITMENT_DOMAIN, outOwnerCommitment[i], outAmount[i], bodyToken);
  });

  const newOutLockedOutputBinding = [0n, 1n, 2n].map((i) => {
    const bit = (flags >> i) & 1n;
    return bit === 1n
      ? poseidon(T.OUTPUT_BINDING_DOMAIN, noteBodyCommitment[Number(i)], outputNoteDataHash[Number(i)])
      : 0n;
  });

  const intentAmount = operationKind === 0n ? outAmount[0] : publicAmountOut;
  const digest = poseidon(
    T.TRANSACTION_INTENT_DIGEST_DOMAIN,
    get('authVerifier'), authorizingAddress, operationKind, tokenAddress,
    get('recipientOwnerNullifierKeyHash'), intentAmount,
    get('feeNoteRecipientOwnerNullifierKeyHash'), get('feeAmount'),
    get('publicRecipientAddress'), flags,
    newOutLockedOutputBinding[0], newOutLockedOutputBinding[1], newOutLockedOutputBinding[2],
    nonce, get('validUntilSeconds'), executionChainId,
  );

  w.intentReplayId         = intentReplayId.toString();
  w.noteBodyCommitment0    = noteBodyCommitment[0].toString();
  w.noteBodyCommitment1    = noteBodyCommitment[1].toString();
  w.noteBodyCommitment2    = noteBodyCommitment[2].toString();
  w.outLockedOutputBinding = newOutLockedOutputBinding.map((v) => v.toString());
  w.transactionIntentDigest = digest.toString();
  return w;
}

// ---- Negative cases ----
const cases = [
  {
    name: 'dummy output with non-zero amount (slot 1)',
    mutate: (i) => {
      i.outIsReal[1] = '0';
      i.outAmount[1] = '7';
      return i;
    },
  },
  {
    name: 'dummy output with non-DUMMY ownerNullifierKeyHash (slot 1)',
    mutate: (i) => {
      i.outIsReal[1] = '0';
      i.outAmount[1] = '0';
      // outOwnerNullifierKeyHash[1] left as the sender's hash (not DUMMY).
      // Adjust value conservation: 10+5 = 13+0+2 = 15.
      i.outAmount[0] = '13';
      return i;
    },
  },
  {
    name: 'real output with amount = 0 (slot 0)',
    mutate: (i) => {
      i.outAmount[0] = '0';
      i.outAmount[1] = '13';
      return i;
    },
  },
  {
    name: 'both inputs phantom (no real input)',
    mutate: (i) => {
      i.inIsReal = ['0', '0'];
      i.inAmount = ['0', '0'];
      i.outAmount = ['0', '0', '0'];
      i.outIsReal = ['1', '0', '0'];
      return i;
    },
  },
  {
    name: 'phantom input with non-zero amount',
    mutate: (i) => {
      i.inIsReal[0] = '0';
      return i;
    },
  },
  {
    name: 'transfer slot 0 owner != recipientOwnerNullifierKeyHash',
    mutate: (i) => {
      // Mutate ONLY the intent's recipient owner-hash; recomputeDerived
      // updates the digest so the failure isolates the slot-0 owner-binding:
      //   (1 - operationKind) * (outOwnerNullifierKeyHash[0] - recipientOwnerNullifierKeyHash) === 0
      i.recipientOwnerNullifierKeyHash = '0x1234567890abcdef';
      return recomputeDerived(i);
    },
  },
  {
    name: 'reserved flag bit 3 set',
    mutate: (i) => {
      i.executionConstraintsFlags = '15';
      return i;
    },
  },
  {
    name: 'lockedOutputBinding[0] != 0 with flag bit 0 = 0',
    mutate: (i) => {
      i.executionConstraintsFlags = '6';
      return i;
    },
  },
  {
    name: 'real input/output token != canonical (membership fails)',
    mutate: (i) => {
      i.tokenAddress = '0x9999999999999999999999999999999999999999';
      return i;
    },
  },
  {
    name: 'real slot 2 with feeNoteRecipientOwnerNullifierKeyHash = 0',
    mutate: (i) => {
      // Both intent field and slot-2 owner-hash set to 0 so the slot-2
      // owner-binding (outOwnerNullifierKeyHash[2] == feeNoteRecipientOwnerNullifierKeyHash)
      // holds; recomputeDerived fixes body[2], binding[2], digest. The
      // failure then isolates `outIsReal[2] * feeRecipOwnerIsZero === 0`.
      i.feeNoteRecipientOwnerNullifierKeyHash = '0';
      i.outOwnerNullifierKeyHash[2] = '0';
      return recomputeDerived(i);
    },
  },
  {
    name: 'real slot 2 with feeNoteRecipientOwnerNullifierKeyHash = DUMMY',
    mutate: (i) => {
      // Same shape as the previous case but tests the DUMMY-rejection check
      // `outIsReal[2] * feeRecipOwnerIsDummy === 0`.
      i.feeNoteRecipientOwnerNullifierKeyHash = DUMMY_OWNER_HASH;
      i.outOwnerNullifierKeyHash[2] = DUMMY_OWNER_HASH;
      return recomputeDerived(i);
    },
  },
  {
    name: 'transfer with recipientOwnerNullifierKeyHash = DUMMY',
    mutate: (i) => {
      // Both the intent field and slot-0 owner-hash set to DUMMY so the
      // slot-0 owner-binding holds; the DUMMY-rejection check
      // `(1 - operationKind) * recipOwnerIsDummy === 0` then fires.
      i.recipientOwnerNullifierKeyHash = DUMMY_OWNER_HASH;
      i.outOwnerNullifierKeyHash[0] = DUMMY_OWNER_HASH;
      return recomputeDerived(i);
    },
  },
  {
    name: 'feeAmount = 0 with nonzero feeNoteRecipientOwnerNullifierKeyHash',
    mutate: (i) => {
      // Make slot 2 dummy (the spec requires feeAmount=0 <=> slot 2 dummy)
      // and leave feeNoteRecipientOwnerNullifierKeyHash nonzero. The check
      // `feeAmtIsZero.out * feeNoteRecipientOwnerNullifierKeyHash === 0`
      // fires.
      i.feeAmount = '0';
      i.outIsReal[2] = '0';
      i.outAmount[2] = '0';
      i.outOwnerNullifierKeyHash[2] = DUMMY_OWNER_HASH;
      // Value conservation: 10+5 = outAmount[0] + outAmount[1] + 0 = 15.
      i.outAmount[0] = '10';
      // outAmount[1] stays at 5.
      // Intent field stays at the baseline (sender's onkHash, non-zero).
      // recomputeDerived recomputes body[0/2], bindings, digest.
      return recomputeDerived(i);
    },
  },
  {
    name: 'withdrawal-mode witness with outIsReal[1] = 1 (forbidden)',
    mutate: (i) => {
      // Switch to withdrawal mode but leave slot 1 real. The check
      // `operationKind * outIsReal[1] === 0` fires.
      // Withdrawal mode requires:
      //   - publicAmountOut > 0
      //   - publicRecipientAddress != 0
      //   - publicTokenAddress == tokenAddress
      //   - recipientOwnerNullifierKeyHash == 0
      //   - slot 0 (if real) owned by sender
      i.publicAmountOut       = '5';
      i.publicRecipientAddress = '0x3333333333333333333333333333333333333333';
      i.publicTokenAddress    = i.tokenAddress;
      i.recipientOwnerNullifierKeyHash = '0';
      // Slot 0 (real) -> sender's owner-hash:
      // The baseline noteSecretSeed-derived owner-hash for the sender is the
      // value already in outOwnerNullifierKeyHash[1]; reuse it.
      i.outOwnerNullifierKeyHash[0] = i.outOwnerNullifierKeyHash[1];
      // Value conservation: 10+5 = outAmount[0] + outAmount[1] + 2 + 5 -> outAmount[0]=3, outAmount[1]=5.
      i.outAmount[0] = '3';
      // outAmount[1] stays at 5; slot 1 is the forbidden real output.
      return recomputeDerived(i);
    },
  },
  {
    name: 'authPolicyRoot mismatch (sibling tampered)',
    mutate: (i) => {
      i.authPolicySiblings[0] =
        (BigInt(i.authPolicySiblings[0]) ^ 1n).toString();
      return i;
    },
  },
  {
    name: 'policySetCommitment mismatch (sibling tampered)',
    mutate: (i) => {
      i.policySetSiblings[0] =
        (BigInt(i.policySetSiblings[0]) ^ 1n).toString();
      return i;
    },
  },
];

let pass = 0, fail = 0;
for (const c of cases) {
  const inp = c.mutate(clone(BASE));
  const r = tryGenerateWitness(inp);
  if (r.ok) {
    console.log(`FAIL — accepted bad witness: ${c.name}`);
    fail++;
  } else {
    console.log(`OK   — rejected: ${c.name}`);
    pass++;
  }
}

console.log(`\n${pass}/${cases.length} negative cases correctly rejected`);
process.exit(fail === 0 ? 0 : 1);
