// Emits assets/derivation_vectors.json — the cross-surface gate consumed by
// the Circom witness harness, Noir #[test]s, forge Vectors.t.sol, and vitest.
// Everything below is deterministic; regenerate with:
//   npm run gen:vectors

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { privateKeyToAccount } from "viem/accounts";
import { hashTypedData, parseSignature } from "viem";
import { poseidon } from "../sdk/src/poseidon2.ts";
import * as D from "../sdk/src/derivations.ts";
import { BN254_SCALAR_MODULUS as P_MOD } from "../sdk/src/field.ts";
import { AppendOnlyTree, SparseTree, emptyRoot } from "../sdk/src/trees.ts";
import {
  DUMMY_OWNER_NULLIFIER_KEY_HASH,
  POLICY_OPERATION_TRANSACT,
  TRANSFER_OP,
  WITHDRAWAL_OP,
} from "../sdk/src/generated/constants.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(HERE, "../assets/derivation_vectors.json");

const hex = (v: bigint) => "0x" + v.toString(16);
const CHAIN_ID = 31337n;
const POOL = BigInt("0x700000000000000000000000000000000000A001");
const AUTH_VERIFIER = BigInt("0x700000000000000000000000000000000000AA01");
const POLICY_VERIFIER = BigInt("0x700000000000000000000000000000000000CC01");
const ROUTER = BigInt("0x700000000000000000000000000000000000DD01");
// Sample opaque downstream-action commitment (a router-profile keccak, reduced mod p).
const SAMPLE_DOWNSTREAM_COMMITMENT =
  BigInt("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef") % P_MOD;

// anvil deterministic accounts
const SENDER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;
const sender = privateKeyToAccount(SENDER_KEY);
const SENDER = BigInt(sender.address);
const RECIPIENT_ADDR = BigInt("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
const WITHDRAW_TO = BigInt("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC");

const EMPTY_POLICY_DATA_HASH = D.outputNoteDataHash(new Uint8Array(0)); // keccak256("") mod p

// ---------- identities ----------
const senderOnk = 0xa11cen;
const senderOnkHash = D.ownerNullifierKeyHash(senderOnk);
const senderSeed = 0x5eedn;
const senderSeedHash = D.noteSecretSeedHash(senderSeed);
const senderAuthData = D.eip712AuthDataCommitment(SENDER);
const senderBlinder = 0xb11dn;
const senderPolicyCommitment = D.policyCommitment(AUTH_VERIFIER, senderAuthData, senderBlinder);
const SENDER_POLICY_SLOT = 3n;
const senderPolicySet = new SparseTree(8);
senderPolicySet.set(SENDER_POLICY_SLOT, senderPolicyCommitment);
const senderPolicySetCommitment = senderPolicySet.root();

const recipientOnk = 0xb0bn;
const recipientOnkHash = D.ownerNullifierKeyHash(recipientOnk);
const recipientSeed = 0x5eed2n;
const recipientSeedHash = D.noteSecretSeedHash(recipientSeed);
const recipientAuthData = D.eip712AuthDataCommitment(RECIPIENT_ADDR);
const recipientBlinder = 0xb11d2n;
const recipientPolicyCommitment = D.policyCommitment(AUTH_VERIFIER, recipientAuthData, recipientBlinder);
const recipientPolicySet = new SparseTree(8);
recipientPolicySet.set(0n, recipientPolicyCommitment);
const recipientPolicySetCommitment = recipientPolicySet.root();

const identityTree = new SparseTree(32);
const senderLeaf = D.identityLeaf(SENDER, senderOnkHash, senderSeedHash, senderPolicySetCommitment);
const recipientLeaf = D.identityLeaf(RECIPIENT_ADDR, recipientOnkHash, recipientSeedHash, recipientPolicySetCommitment);
identityTree.set(1n, senderLeaf);
identityTree.set(2n, recipientLeaf);
const identityRoot = identityTree.root();

// ---------- deposited notes ----------
const noteTree = new AppendOnlyTree(32);
interface NoteFix {
  amount: bigint;
  secret: bigint;
  leafIndex: bigint;
  ownerCommitment: bigint;
  noteBodyCommitment: bigint;
  noteCommitment: bigint;
  nullifier: bigint;
}
function makeDepositNote(amount: bigint, secret: bigint): NoteFix {
  const oc = D.ownerCommitment(CHAIN_ID, POOL, senderOnkHash, secret);
  const nbc = D.noteBodyCommitment(oc, amount, 0n);
  const leafIndex = noteTree.nextLeafIndex;
  const nc = D.noteCommitment(CHAIN_ID, POOL, nbc, leafIndex);
  noteTree.append(nc);
  return {
    amount,
    secret,
    leafIndex,
    ownerCommitment: oc,
    noteBodyCommitment: nbc,
    noteCommitment: nc,
    nullifier: D.nullifier(CHAIN_ID, POOL, nc, senderOnk),
  };
}
const note0 = makeDepositNote(600n, 0x111n);
const note1 = makeDepositNote(400n, 0x222n);
const noteCommitmentRoot = noteTree.root();

// ---------- output helpers ----------
// All three output slots derive noteSecret_i from the SENDER's seed (§8):
// recipients learn their note secret from the encrypted payload, not the seed.
function buildOutputs(
  replayId: bigint,
  slots: Array<{ ownerHash: bigint; amount: bigint; token: bigint }>,
  outputNoteData: string[],
) {
  return slots.map((slot, i) => {
    const noteSecret = D.transactNoteSecret(senderSeed, CHAIN_ID, POOL, replayId, i as 0 | 1 | 2);
    const oc = D.ownerCommitment(CHAIN_ID, POOL, slot.ownerHash, noteSecret);
    const nbc = D.noteBodyCommitment(oc, slot.amount, slot.token);
    const ondBytes = outputNoteData[i]!.startsWith("0x")
      ? Uint8Array.from(Buffer.from(outputNoteData[i]!.slice(2), "hex"))
      : new Uint8Array(0);
    const ondHash = D.outputNoteDataHash(ondBytes);
    return {
      isDummy: slot.ownerHash === DUMMY_OWNER_NULLIFIER_KEY_HASH,
      ownerNullifierKeyHash: hex(slot.ownerHash),
      amount: slot.amount.toString(),
      tokenAddress: hex(slot.token),
      noteSecret: hex(noteSecret),
      ownerCommitment: hex(oc),
      noteBodyCommitment: hex(nbc),
      outputNoteData: outputNoteData[i]!,
      outputNoteDataHash: hex(ondHash),
      outputBinding: hex(D.outputBinding(nbc, ondHash)),
    };
  });
}

// ---------- EIP-712 ----------
const EIP712_TYPES = {
  PrivateTransferIntent: [
    { name: "chainId", type: "uint256" },
    { name: "poolAddress", type: "address" },
    { name: "authVerifier", type: "address" },
    { name: "authorizingAddress", type: "address" },
    { name: "operationKind", type: "uint256" },
    { name: "tokenAddress", type: "address" },
    { name: "recipientOwnerNullifierKeyHash", type: "uint256" },
    { name: "amount", type: "uint256" },
    { name: "feeNoteRecipientOwnerNullifierKeyHash", type: "uint256" },
    { name: "feeAmount", type: "uint256" },
    { name: "publicRecipientAddress", type: "address" },
    { name: "authorizedSubmitter", type: "address" },
    { name: "downstreamActionCommitment", type: "uint256" },
    { name: "executionConstraintsFlags", type: "uint256" },
    { name: "lockedOutputBinding0", type: "uint256" },
    { name: "lockedOutputBinding1", type: "uint256" },
    { name: "lockedOutputBinding2", type: "uint256" },
    { name: "policyDataHash", type: "uint256" },
    { name: "nonce", type: "uint256" },
    { name: "validUntilSeconds", type: "uint256" },
  ],
} as const;

async function signIntent(fields: D.IntentFields, policyDataHash: bigint) {
  const toAddr = (v: bigint) => `0x${v.toString(16).padStart(40, "0")}` as `0x${string}`;
  const message = {
    chainId: fields.executionChainId,
    poolAddress: toAddr(fields.poolAddress),
    authVerifier: toAddr(fields.authVerifier),
    authorizingAddress: toAddr(fields.authorizingAddress),
    operationKind: fields.operationKind,
    tokenAddress: toAddr(fields.tokenAddress),
    recipientOwnerNullifierKeyHash: fields.recipientOwnerNullifierKeyHash,
    amount: fields.amount,
    feeNoteRecipientOwnerNullifierKeyHash: fields.feeNoteRecipientOwnerNullifierKeyHash,
    feeAmount: fields.feeAmount,
    publicRecipientAddress: toAddr(fields.publicRecipientAddress),
    authorizedSubmitter: toAddr(fields.authorizedSubmitter),
    downstreamActionCommitment: fields.downstreamActionCommitment,
    executionConstraintsFlags: fields.executionConstraintsFlags,
    lockedOutputBinding0: fields.lockedOutputBinding0,
    lockedOutputBinding1: fields.lockedOutputBinding1,
    lockedOutputBinding2: fields.lockedOutputBinding2,
    policyDataHash,
    nonce: fields.nonce,
    validUntilSeconds: fields.validUntilSeconds,
  };
  const domain = {
    name: "ERCXXXXPrivateTransfers",
    version: "1",
    chainId: Number(fields.executionChainId),
    verifyingContract: toAddr(fields.poolAddress),
  } as const;
  const digest = hashTypedData({ domain, types: EIP712_TYPES, primaryType: "PrivateTransferIntent", message });
  const signature = await sender.signTypedData({ domain, types: EIP712_TYPES, primaryType: "PrivateTransferIntent", message });
  const parsed = parseSignature(signature);
  const pub = sender.publicKey; // 0x04 || x || y
  return {
    domain,
    digest,
    signature,
    r: parsed.r,
    s: parsed.s,
    v: Number(parsed.v ?? (parsed.yParity === 0 ? 27n : 28n)),
    publicKeyX: "0x" + pub.slice(4, 68),
    publicKeyY: "0x" + pub.slice(68, 132),
  };
}

// ---------- scenario: transfer (2 real inputs, recipient + change, no fee) ----------
async function transferScenario() {
  const nonce = 0x99n;
  const blindingFactor = 0xb1n;
  const replayId = D.intentReplayId(senderOnk, SENDER, CHAIN_ID, POOL, nonce);
  const outputs = buildOutputs(
    replayId,
    [
      { ownerHash: recipientOnkHash, amount: 700n, token: 0n },
      { ownerHash: senderOnkHash, amount: 300n, token: 0n },
      { ownerHash: DUMMY_OWNER_NULLIFIER_KEY_HASH, amount: 0n, token: 0n },
    ],
    ["0xdead01", "0xdead02", "0x"],
  );
  const fields: D.IntentFields = {
    poolAddress: POOL,
    authVerifier: AUTH_VERIFIER,
    authorizingAddress: SENDER,
    operationKind: TRANSFER_OP,
    tokenAddress: 0n,
    recipientOwnerNullifierKeyHash: recipientOnkHash,
    amount: 700n,
    feeNoteRecipientOwnerNullifierKeyHash: 0n,
    feeAmount: 0n,
    publicRecipientAddress: 0n,
    authorizedSubmitter: 0n,
    downstreamActionCommitment: 0n,
    executionConstraintsFlags: 0n,
    lockedOutputBinding0: 0n,
    lockedOutputBinding1: 0n,
    lockedOutputBinding2: 0n,
    nonce,
    validUntilSeconds: 4000000000n,
    executionChainId: CHAIN_ID,
  };
  const fieldsHash = D.transactIntentFieldsHash(fields);
  const digest = D.transactionIntentDigest(fieldsHash, EMPTY_POLICY_DATA_HASH);
  const blinded = D.blindedAuthCommitment(senderAuthData, blindingFactor);
  const eip712 = await signIntent(fields, EMPTY_POLICY_DATA_HASH);

  const pi: D.PublicInputs = {
    noteCommitmentRoot,
    nullifier0: note0.nullifier,
    nullifier1: note1.nullifier,
    noteBodyCommitment0: BigInt(outputs[0]!.noteBodyCommitment),
    noteBodyCommitment1: BigInt(outputs[1]!.noteBodyCommitment),
    noteBodyCommitment2: BigInt(outputs[2]!.noteBodyCommitment),
    publicAmountOut: 0n,
    publicRecipientAddress: 0n,
    publicTokenAddress: 0n,
    intentReplayId: replayId,
    validUntilSeconds: fields.validUntilSeconds,
    executionChainId: CHAIN_ID,
    poolAddress: POOL,
    identityRoot,
    outputNoteDataHash0: BigInt(outputs[0]!.outputNoteDataHash),
    outputNoteDataHash1: BigInt(outputs[1]!.outputNoteDataHash),
    outputNoteDataHash2: BigInt(outputs[2]!.outputNoteDataHash),
    authVerifier: AUTH_VERIFIER,
    blindedAuthCommitment: blinded,
    transactionIntentDigest: digest,
    policyOperationDataHash: 0n,
    policyDataHash: EMPTY_POLICY_DATA_HASH,
    authorizedSubmitter: 0n,
    downstreamActionCommitment: 0n,
  };
  const transitionHash = D.transactPublicTransitionHash(pi);
  return {
    kind: "transfer",
    nonce: hex(nonce),
    blindingFactor: hex(blindingFactor),
    intentReplayId: hex(replayId),
    inputs: [serializeInput(note0), serializeInput(note1)],
    outputs,
    intentFields: serializeFields(fields),
    policyDataHash: hex(EMPTY_POLICY_DATA_HASH),
    transactIntentFieldsHash: hex(fieldsHash),
    transactionIntentDigest: hex(digest),
    blindedAuthCommitment: hex(blinded),
    authDataCommitment: hex(senderAuthData),
    eip712,
    publicInputs: D.publicInputsToArray(pi).map(hex),
    transactPublicTransitionHash: hex(transitionHash),
    transactOperationDataHash: hex(D.transactOperationDataHash(fieldsHash, transitionHash)),
  };
}

// ---------- scenario: withdrawal (1 real input + phantom, change, gated policy values) ----------
async function withdrawalScenario() {
  const nonce = 0x9an;
  const blindingFactor = 0xb2n;
  const replayId = D.intentReplayId(senderOnk, SENDER, CHAIN_ID, POOL, nonce);
  const phantom = D.phantomNullifier(CHAIN_ID, POOL, senderOnk, replayId, 1);
  const outputs = buildOutputs(
    replayId,
    [
      { ownerHash: senderOnkHash, amount: 350n, token: 0n },
      { ownerHash: DUMMY_OWNER_NULLIFIER_KEY_HASH, amount: 0n, token: 0n },
      { ownerHash: DUMMY_OWNER_NULLIFIER_KEY_HASH, amount: 0n, token: 0n },
    ],
    ["0xdead03", "0x", "0x"],
  );
  const fields: D.IntentFields = {
    poolAddress: POOL,
    authVerifier: AUTH_VERIFIER,
    authorizingAddress: SENDER,
    operationKind: WITHDRAWAL_OP,
    tokenAddress: 0n,
    recipientOwnerNullifierKeyHash: 0n,
    amount: 250n,
    feeNoteRecipientOwnerNullifierKeyHash: 0n,
    feeAmount: 0n,
    publicRecipientAddress: WITHDRAW_TO,
    // Router-bound withdrawal: only ROUTER may submit, bound to a downstream action.
    authorizedSubmitter: ROUTER,
    downstreamActionCommitment: SAMPLE_DOWNSTREAM_COMMITMENT,
    executionConstraintsFlags: 0n,
    lockedOutputBinding0: 0n,
    lockedOutputBinding1: 0n,
    lockedOutputBinding2: 0n,
    nonce,
    validUntilSeconds: 4000000000n,
    executionChainId: CHAIN_ID,
  };
  const fieldsHash = D.transactIntentFieldsHash(fields);
  const digest = D.transactionIntentDigest(fieldsHash, EMPTY_POLICY_DATA_HASH);
  const blinded = D.blindedAuthCommitment(senderAuthData, blindingFactor);
  const eip712 = await signIntent(fields, EMPTY_POLICY_DATA_HASH);

  const piBase: D.PublicInputs = {
    noteCommitmentRoot,
    nullifier0: note0.nullifier,
    nullifier1: phantom,
    noteBodyCommitment0: BigInt(outputs[0]!.noteBodyCommitment),
    noteBodyCommitment1: BigInt(outputs[1]!.noteBodyCommitment),
    noteBodyCommitment2: BigInt(outputs[2]!.noteBodyCommitment),
    publicAmountOut: 250n,
    publicRecipientAddress: WITHDRAW_TO,
    publicTokenAddress: 0n,
    intentReplayId: replayId,
    validUntilSeconds: fields.validUntilSeconds,
    executionChainId: CHAIN_ID,
    poolAddress: POOL,
    identityRoot,
    outputNoteDataHash0: BigInt(outputs[0]!.outputNoteDataHash),
    outputNoteDataHash1: BigInt(outputs[1]!.outputNoteDataHash),
    outputNoteDataHash2: BigInt(outputs[2]!.outputNoteDataHash),
    authVerifier: AUTH_VERIFIER,
    blindedAuthCommitment: blinded,
    transactionIntentDigest: digest,
    policyOperationDataHash: 0n,
    policyDataHash: EMPTY_POLICY_DATA_HASH,
    authorizedSubmitter: ROUTER,
    downstreamActionCommitment: SAMPLE_DOWNSTREAM_COMMITMENT,
  };
  const transitionHash = D.transactPublicTransitionHash(piBase);
  const opDataHash = D.transactOperationDataHash(fieldsHash, transitionHash);
  const policyDigest = D.policyOperationDigest(CHAIN_ID, POOL, POLICY_VERIFIER, POLICY_OPERATION_TRANSACT, opDataHash);
  return {
    kind: "withdrawal",
    nonce: hex(nonce),
    blindingFactor: hex(blindingFactor),
    intentReplayId: hex(replayId),
    phantomNullifier: hex(phantom),
    inputs: [serializeInput(note0)],
    outputs,
    intentFields: serializeFields(fields),
    policyDataHash: hex(EMPTY_POLICY_DATA_HASH),
    transactIntentFieldsHash: hex(fieldsHash),
    transactionIntentDigest: hex(digest),
    blindedAuthCommitment: hex(blinded),
    authDataCommitment: hex(senderAuthData),
    eip712,
    publicInputs: D.publicInputsToArray(piBase).map(hex),
    transactPublicTransitionHash: hex(transitionHash),
    transactOperationDataHash: hex(opDataHash),
    policyOperationDigest: hex(policyDigest),
  };
}

function serializeInput(n: NoteFix) {
  return {
    amount: n.amount.toString(),
    noteSecret: hex(n.secret),
    leafIndex: n.leafIndex.toString(),
    ownerCommitment: hex(n.ownerCommitment),
    noteBodyCommitment: hex(n.noteBodyCommitment),
    noteCommitment: hex(n.noteCommitment),
    nullifier: hex(n.nullifier),
    merkleSiblings: noteTree.proof(n.leafIndex).map(hex),
  };
}

function serializeFields(f: D.IntentFields) {
  return Object.fromEntries(Object.entries(f).map(([k, v]) => [k, hex(v as bigint)]));
}

// ---------- deposit sealing + policy deposit digest ----------
const depositExample = (() => {
  const oc = D.ownerCommitment(CHAIN_ID, POOL, recipientOnkHash, 0x333n);
  const nbc = D.noteBodyCommitment(oc, 12345n, 0n);
  const nc = D.noteCommitment(CHAIN_ID, POOL, nbc, 7n);
  const ondHash = D.outputNoteDataHash(Uint8Array.from([0xaa, 0xbb]));
  const opData = D.depositOperationDataHash(CHAIN_ID, POOL, SENDER, 0n, 12345n, oc, ondHash);
  return {
    ownerNullifierKeyHash: hex(recipientOnkHash),
    noteSecret: hex(0x333n),
    amount: "12345",
    tokenAddress: "0x0",
    leafIndex: "7",
    ownerCommitment: hex(oc),
    noteBodyCommitment: hex(nbc),
    noteCommitment: hex(nc),
    outputNoteData: "0xaabb",
    outputNoteDataHash: hex(ondHash),
    depositOperationDataHash: hex(opData),
    policyOperationDigestDeposit: hex(D.policyOperationDigest(CHAIN_ID, POOL, POLICY_VERIFIER, 0n, opData)),
  };
})();

// ---------- primitive vectors ----------
const primitives = {
  ownerNullifierKeyHash: [
    { in: [hex(senderOnk)], out: hex(senderOnkHash) },
    { in: [hex(recipientOnk)], out: hex(recipientOnkHash) },
  ],
  noteSecretSeedHash: [{ in: [hex(senderSeed)], out: hex(senderSeedHash) }],
  identityLeaf: [
    {
      in: [hex(SENDER), hex(senderOnkHash), hex(senderSeedHash), hex(senderPolicySetCommitment)],
      out: hex(senderLeaf),
    },
  ],
  policyCommitment: [
    { in: [hex(AUTH_VERIFIER), hex(senderAuthData), hex(senderBlinder)], out: hex(senderPolicyCommitment) },
  ],
  eip712AuthDataCommitment: [{ in: [hex(SENDER)], out: hex(senderAuthData) }],
  emptyRoots: { depth8: hex(emptyRoot(8)), depth32: hex(emptyRoot(32)) },
  merkleNode: { in: [hex(1n), hex(2n)], out: hex(poseidon(1n, 2n)) },
};

// ---------- assemble ----------
const out = {
  generator: "erc/scripts/gen_vectors.ts",
  chainId: hex(CHAIN_ID),
  poolAddress: hex(POOL),
  authVerifier: hex(AUTH_VERIFIER),
  policyVerifier: hex(POLICY_VERIFIER),
  router: hex(ROUTER),
  sampleDownstreamActionCommitment: hex(SAMPLE_DOWNSTREAM_COMMITMENT),
  emptyPolicyDataHash: hex(EMPTY_POLICY_DATA_HASH),
  dummyOwnerNullifierKeyHash: hex(DUMMY_OWNER_NULLIFIER_KEY_HASH),
  identities: {
    sender: {
      address: hex(SENDER),
      privateKey: SENDER_KEY,
      ownerNullifierKey: hex(senderOnk),
      ownerNullifierKeyHash: hex(senderOnkHash),
      noteSecretSeed: hex(senderSeed),
      noteSecretSeedHash: hex(senderSeedHash),
      registrationBlinder: hex(senderBlinder),
      policyCommitment: hex(senderPolicyCommitment),
      policySlot: SENDER_POLICY_SLOT.toString(),
      policySetCommitment: hex(senderPolicySetCommitment),
      policySetSiblings: senderPolicySet.proof(SENDER_POLICY_SLOT).map(hex),
      leafPosition: "1",
      identityLeaf: hex(senderLeaf),
      identitySiblings: identityTree.proof(1n).map(hex),
    },
    recipient: {
      address: hex(RECIPIENT_ADDR),
      ownerNullifierKey: hex(recipientOnk),
      ownerNullifierKeyHash: hex(recipientOnkHash),
      noteSecretSeed: hex(recipientSeed),
      noteSecretSeedHash: hex(recipientSeedHash),
      registrationBlinder: hex(recipientBlinder),
      policyCommitment: hex(recipientPolicyCommitment),
      policySlot: "0",
      policySetCommitment: hex(recipientPolicySetCommitment),
      leafPosition: "2",
      identityLeaf: hex(recipientLeaf),
    },
    identityRoot: hex(identityRoot),
  },
  noteTree: { root: hex(noteCommitmentRoot), leaves: [hex(note0.noteCommitment), hex(note1.noteCommitment)] },
  deposit: depositExample,
  primitives,
  scenarios: {} as Record<string, unknown>,
};

const transfer = await transferScenario();
const withdrawal = await withdrawalScenario();
out.scenarios["transfer"] = transfer;
out.scenarios["withdrawal"] = withdrawal;

fs.writeFileSync(OUT, JSON.stringify(out, null, 2) + "\n");
console.log("wrote", OUT);
console.log("transfer digest:", transfer.transactionIntentDigest);
console.log("withdrawal digest:", withdrawal.transactionIntentDigest);
