import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { poseidon } from "../src/poseidon2.ts";
import * as D from "../src/derivations.ts";
import { BN254_SCALAR_MODULUS } from "../src/field.ts";

const vectors = JSON.parse(
  readFileSync(new URL("../../assets/poseidon2_vectors.json", import.meta.url), "utf8"),
);

describe("poseidon2 sponge", () => {
  it("matches every published Poseidon2 vector", () => {
    for (const vec of vectors.poseidonVectors) {
      expect(poseidon(...vec.inputs.map(BigInt))).toBe(BigInt(vec.output));
    }
  });
});

describe("pool-scoped derivations", () => {
  const chainA = 1n;
  const chainB = 11155111n;
  const poolA = 0x1111n;
  const poolB = 0x2222n;

  it("noteCommitment changes with chainId and poolAddress", () => {
    const base = D.noteCommitment(chainA, poolA, 42n, 7n);
    expect(D.noteCommitment(chainB, poolA, 42n, 7n)).not.toBe(base);
    expect(D.noteCommitment(chainA, poolB, 42n, 7n)).not.toBe(base);
  });

  it("nullifier / phantomNullifier / replayId / transactNoteSecret / ownerCommitment are pool-scoped", () => {
    expect(D.nullifier(chainA, poolA, 1n, 2n)).not.toBe(D.nullifier(chainA, poolB, 1n, 2n));
    expect(D.phantomNullifier(chainA, poolA, 1n, 2n, 0)).not.toBe(D.phantomNullifier(chainA, poolB, 1n, 2n, 0));
    expect(D.intentReplayId(1n, 2n, chainA, poolA, 3n)).not.toBe(D.intentReplayId(1n, 2n, chainA, poolB, 3n));
    expect(D.transactNoteSecret(1n, chainA, poolA, 2n, 0)).not.toBe(D.transactNoteSecret(1n, chainA, poolB, 2n, 0));
    expect(D.ownerCommitment(chainA, poolA, 1n, 2n)).not.toBe(D.ownerCommitment(chainA, poolB, 1n, 2n));
  });

  it("noteBodyCommitment is NOT pool-scoped (arity 4)", () => {
    // Only ownerCommitment carries pool scope into the note body.
    const nbc = D.noteBodyCommitment(5n, 100n, 0n);
    expect(nbc).toBe(poseidon(D0("note_body_commitment"), 5n, 100n, 0n));
  });
});

function D0(ctx: string): bigint {
  // independent tag recomputation to pin arities against raw sponge calls
  const digest = keccak_256(new TextEncoder().encode(`erc-app-layer-private-transfers.${ctx}`));
  let v = 0n;
  for (const b of digest) v = (v << 8n) | BigInt(b);
  return v % BN254_SCALAR_MODULUS;
}

describe("intent digests", () => {
  const fields: D.IntentFields = {
    poolAddress: 0x1111n,
    authVerifier: 0x2222n,
    authorizingAddress: 0x3333n,
    operationKind: 0n,
    tokenAddress: 0n,
    recipientOwnerNullifierKeyHash: 77n,
    amount: 1000n,
    feeNoteRecipientOwnerNullifierKeyHash: 0n,
    feeAmount: 0n,
    publicRecipientAddress: 0n,
    authorizedSubmitter: 0xdd01n,
    downstreamActionCommitment: 0xbeefn,
    executionConstraintsFlags: 0n,
    lockedOutputBinding0: 0n,
    lockedOutputBinding1: 0n,
    lockedOutputBinding2: 0n,
    nonce: 999n,
    validUntilSeconds: 2000000000n,
    executionChainId: 1n,
  };

  it("two-level digest = poseidon(digest domain, fieldsHash, policyDataHash)", () => {
    const fh = D.transactIntentFieldsHash(fields);
    const digest = D.transactionIntentDigest(fh, 5n);
    expect(digest).toBe(poseidon(D0("transaction_intent_digest"), fh, 5n));
    expect(D.transactionIntentDigest(fh, 6n)).not.toBe(digest);
  });

  it("fieldsHash is arity 20 in declaration order (incl. authorizedSubmitter + downstreamActionCommitment)", () => {
    const expected = poseidon(
      D0("transact_intent_fields"),
      fields.poolAddress,
      fields.authVerifier,
      fields.authorizingAddress,
      fields.operationKind,
      fields.tokenAddress,
      fields.recipientOwnerNullifierKeyHash,
      fields.amount,
      fields.feeNoteRecipientOwnerNullifierKeyHash,
      fields.feeAmount,
      fields.publicRecipientAddress,
      fields.authorizedSubmitter,
      fields.downstreamActionCommitment,
      fields.executionConstraintsFlags,
      fields.lockedOutputBinding0,
      fields.lockedOutputBinding1,
      fields.lockedOutputBinding2,
      fields.nonce,
      fields.validUntilSeconds,
      fields.executionChainId,
    );
    expect(D.transactIntentFieldsHash(fields)).toBe(expected);
  });

  it("authorizedSubmitter and downstreamActionCommitment change the fields hash", () => {
    expect(D.transactIntentFieldsHash({ ...fields, authorizedSubmitter: 1n })).not.toBe(
      D.transactIntentFieldsHash(fields),
    );
    expect(D.transactIntentFieldsHash({ ...fields, downstreamActionCommitment: 1n })).not.toBe(
      D.transactIntentFieldsHash(fields),
    );
  });
});

describe("policy digests", () => {
  const pi: D.PublicInputs = {
    noteCommitmentRoot: 1n,
    nullifier0: 2n,
    nullifier1: 3n,
    noteBodyCommitment0: 4n,
    noteBodyCommitment1: 5n,
    noteBodyCommitment2: 6n,
    publicAmountOut: 7n,
    publicRecipientAddress: 8n,
    publicTokenAddress: 9n,
    intentReplayId: 10n,
    validUntilSeconds: 11n,
    executionChainId: 12n,
    poolAddress: 13n,
    identityRoot: 14n,
    outputNoteDataHash0: 15n,
    outputNoteDataHash1: 16n,
    outputNoteDataHash2: 17n,
    authVerifier: 18n,
    blindedAuthCommitment: 19n,
    transactionIntentDigest: 20n,
    policyOperationDataHash: 21n,
    policyDataHash: 22n,
    authorizedSubmitter: 23n,
    downstreamActionCommitment: 24n,
  };

  it("transition hash covers the 21 public transition fields (excludes digest + policy hashes)", () => {
    const base = D.transactPublicTransitionHash(pi);
    // Excluded from the transition hash:
    expect(D.transactPublicTransitionHash({ ...pi, transactionIntentDigest: 999n })).toBe(base);
    expect(D.transactPublicTransitionHash({ ...pi, policyOperationDataHash: 999n })).toBe(base);
    expect(D.transactPublicTransitionHash({ ...pi, policyDataHash: 999n })).toBe(base);
    // Included:
    expect(D.transactPublicTransitionHash({ ...pi, blindedAuthCommitment: 999n })).not.toBe(base);
    expect(D.transactPublicTransitionHash({ ...pi, noteCommitmentRoot: 999n })).not.toBe(base);
    expect(D.transactPublicTransitionHash({ ...pi, authorizedSubmitter: 999n })).not.toBe(base);
    expect(D.transactPublicTransitionHash({ ...pi, downstreamActionCommitment: 999n })).not.toBe(base);
  });

  it("publicInputsToArray preserves spec §4 declaration order", () => {
    const arr = D.publicInputsToArray(pi);
    expect(arr).toEqual([
      1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n, 11n, 12n, 13n, 14n, 15n, 16n, 17n, 18n, 19n, 20n, 21n, 22n, 23n, 24n,
    ]);
  });

  it("outputNoteDataHash of empty bytes = keccak256('') mod p", () => {
    // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    const expected = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470n % BN254_SCALAR_MODULUS;
    expect(D.outputNoteDataHash(new Uint8Array(0))).toBe(expected);
  });
});
