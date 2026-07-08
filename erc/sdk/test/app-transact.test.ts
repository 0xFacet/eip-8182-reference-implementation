import { describe, expect, it } from "vitest";
import {
  noteBodyCommitment,
  noteCommitment,
  identityLeaf,
  noteSecretSeedHash,
  ownerCommitment,
  ownerNullifierKeyHash,
} from "../src/derivations.ts";
import { DUMMY_OWNER_NULLIFIER_KEY_HASH } from "../src/generated/constants.ts";
import { AppendOnlyTree, SparseTree, emptyRoot } from "../src/trees.ts";
import { buildTransactBundle, type BuildTransactParams, type BuilderInput } from "../../app/src/lib/transact.ts";

const CHAIN_ID = 31337n;
const POOL = 0x1234n;
const AUTH_VERIFIER = 0x2000n;
const ACCOUNT = 0x3000n;
const OWNER_NULLIFIER_KEY = 111n;
const NOTE_SECRET_SEED = 222n;
const NOTE_SECRET = 333n;
const AMOUNT = 100n;
const TOKEN = 0n;
const POLICY_SET_COMMITMENT = 555n;

const hex32 = (v: bigint): `0x${string}` => `0x${v.toString(16).padStart(64, "0")}`;
const zeros = (n: number): bigint[] => Array.from({ length: n }, () => 0n);

function inputNote(): { input: BuilderInput; root: bigint } {
  const onkHash = ownerNullifierKeyHash(OWNER_NULLIFIER_KEY);
  const oc = ownerCommitment(CHAIN_ID, POOL, onkHash, NOTE_SECRET);
  const nbc = noteBodyCommitment(oc, AMOUNT, TOKEN);
  const nc = noteCommitment(CHAIN_ID, POOL, nbc, 0n);
  const tree = new AppendOnlyTree(32);
  tree.append(nc);
  return {
    input: { amount: AMOUNT, noteSecret: NOTE_SECRET, leafIndex: 0n, siblings: tree.proof(0n) },
    root: tree.root(),
  };
}

function identityProof(): { leafPosition: bigint; siblings: bigint[]; root: bigint } {
  const seedHash = noteSecretSeedHash(NOTE_SECRET_SEED);
  const leaf = identityLeaf(ACCOUNT, ownerNullifierKeyHash(OWNER_NULLIFIER_KEY), seedHash, POLICY_SET_COMMITMENT);
  const tree = new SparseTree(32);
  tree.set(1n, leaf);
  return { leafPosition: 1n, siblings: tree.proof(1n), root: tree.root() };
}

function baseParams(noteCommitmentRoot: bigint): BuildTransactParams {
  const { input } = inputNote();
  const id = identityProof();
  return {
    chainId: CHAIN_ID,
    poolAddress: POOL,
    authVerifier: AUTH_VERIFIER,
    spender: {
      authVerifier: AUTH_VERIFIER,
      ownerNullifierKey: OWNER_NULLIFIER_KEY,
      noteSecretSeed: NOTE_SECRET_SEED,
      noteSecretSeedHash: noteSecretSeedHash(NOTE_SECRET_SEED),
      identityRoot: id.root,
      authorizingAddress: ACCOUNT,
      authDataCommitment: 444n,
      policySetCommitment: POLICY_SET_COMMITMENT,
      registrationBlinder: 666n,
      policySlot: 0n,
      policySetSiblings: zeros(8),
      identityLeafPosition: id.leafPosition,
      identitySiblings: id.siblings,
    },
    noteCommitmentRoot,
    identityRoot: id.root,
    inputs: [input],
    outputs: [
      { ownerNullifierKeyHash: DUMMY_OWNER_NULLIFIER_KEY_HASH, amount: 0n, tokenAddress: TOKEN },
      { ownerNullifierKeyHash: DUMMY_OWNER_NULLIFIER_KEY_HASH, amount: 0n, tokenAddress: TOKEN },
      { ownerNullifierKeyHash: DUMMY_OWNER_NULLIFIER_KEY_HASH, amount: 0n, tokenAddress: TOKEN },
    ],
    operation: "transfer",
    amount: 0n,
    tokenAddress: TOKEN,
    recipientOwnerNullifierKeyHash: 0n,
    feeNoteRecipientOwnerNullifierKeyHash: 0n,
    feeAmount: 0n,
    publicAmountOut: 0n,
    publicRecipientAddress: 0n,
    publicTokenAddress: 0n,
    nonce: 888n,
    validUntilSeconds: 1_800_000_000n,
    blindingFactor: 999n,
    policy: { applies: 0n, policyVerifier: 0n },
    async signIntent() {
      return {
        digest: hex32(1n),
        signature: "0x",
        v: 27,
        r: hex32(2n),
        s: hex32(3n),
        publicKeyX: hex32(4n),
        publicKeyY: hex32(5n),
      };
    },
  };
}

describe("app transact builder", () => {
  it("accepts an input note whose sibling path matches the selected root", async () => {
    const { root } = inputNote();
    const bundle = await buildTransactBundle(baseParams(root));
    expect(bundle.publicInputs.noteCommitmentRoot).toBe(root);
  });

  it("rejects an input note whose sibling path does not match the selected root", async () => {
    await expect(buildTransactBundle(baseParams(emptyRoot(32)))).rejects.toThrow("rescan notes and retry");
  });

  it("rejects an identity proof whose sibling path does not match the selected root", async () => {
    const { root } = inputNote();
    await expect(buildTransactBundle({ ...baseParams(root), identityRoot: emptyRoot(32) })).rejects.toThrow("rescan identity and retry");
  });
});
