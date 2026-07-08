import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { keccak_256 } from "@noble/hashes/sha3.js";
import * as C from "../src/generated/constants.ts";
import { domainTag, poseidon } from "../src/poseidon2.ts";
import { BN254_SCALAR_MODULUS } from "../src/field.ts";

const tagsAsset = JSON.parse(readFileSync(new URL("../../assets/domain_tags.json", import.meta.url), "utf8"));

function independentTag(ctx: string): bigint {
  const bytes = new TextEncoder().encode(`erc-app-layer-private-transfers.${ctx}`);
  const digest = keccak_256(bytes);
  let v = 0n;
  for (const b of digest) v = (v << 8n) | BigInt(b);
  return v % BN254_SCALAR_MODULUS;
}

describe("generated constants", () => {
  it("domain tags match the spec formula, independently recomputed", () => {
    expect(C.OWNER_NULLIFIER_KEY_HASH_DOMAIN).toBe(independentTag("owner_nullifier_key_hash"));
    expect(C.IDENTITY_LEAF_DOMAIN).toBe(independentTag("identity_leaf"));
    expect(C.TRANSACT_INTENT_FIELDS_DOMAIN).toBe(independentTag("transact_intent_fields"));
    expect(C.POLICY_TRANSACT_PUBLIC_TRANSITION_DOMAIN).toBe(independentTag("policy_transact_public_transition"));
    expect(C.BLINDED_AUTH_COMMITMENT_DOMAIN).toBe(independentTag("blinded_auth_commitment"));
  });

  it("runtime domainTag() agrees with generated constants for every tag in the asset", () => {
    const contexts: Record<string, string> = {
      OWNER_NULLIFIER_KEY_HASH_DOMAIN: "owner_nullifier_key_hash",
      OWNER_COMMITMENT_DOMAIN: "owner_commitment",
      NOTE_BODY_COMMITMENT_DOMAIN: "note_body_commitment",
      NOTE_COMMITMENT_DOMAIN: "note_commitment",
      NULLIFIER_DOMAIN: "nullifier",
      PHANTOM_NULLIFIER_DOMAIN: "phantom_nullifier",
      INTENT_REPLAY_ID_DOMAIN: "intent_replay_id",
      TRANSACT_NOTE_SECRET_DOMAIN: "transact_note_secret",
      NOTE_SECRET_SEED_DOMAIN: "note_secret_seed",
      TRANSACT_INTENT_FIELDS_DOMAIN: "transact_intent_fields",
      TRANSACTION_INTENT_DIGEST_DOMAIN: "transaction_intent_digest",
      OUTPUT_BINDING_DOMAIN: "output_binding",
      IDENTITY_LEAF_DOMAIN: "identity_leaf",
      POLICY_COMMITMENT_DOMAIN: "policy_commitment",
      POLICY_OPERATION_DOMAIN: "policy_operation",
      POLICY_TRANSACT_PUBLIC_TRANSITION_DOMAIN: "policy_transact_public_transition",
      POLICY_TRANSACT_OPERATION_DATA_DOMAIN: "policy_transact_operation_data",
      POLICY_DEPOSIT_OPERATION_DATA_DOMAIN: "policy_deposit_operation_data",
      BLINDED_AUTH_COMMITMENT_DOMAIN: "blinded_auth_commitment",
      EIP712_AUTH_DATA_DOMAIN: "eip712_auth_data",
    };
    for (const [name, ctx] of Object.entries(contexts)) {
      const generated = (C as Record<string, unknown>)[name];
      expect(generated, name).toBe(domainTag(ctx));
      expect(generated, `${name} vs asset`).toBe(BigInt(tagsAsset.tags[name]));
    }
  });

  it("dummy owner hash = poseidon(ONKH_DOMAIN, 0xdead)", () => {
    expect(C.DUMMY_OWNER_NULLIFIER_KEY_HASH).toBe(poseidon(C.OWNER_NULLIFIER_KEY_HASH_DOMAIN, 0xdeadn));
  });

  it("tags differ from the 8182 namespace", () => {
    const old = (ctx: string): bigint => {
      const digest = keccak_256(new TextEncoder().encode(`eip-8182.${ctx}`));
      let v = 0n;
      for (const b of digest) v = (v << 8n) | BigInt(b);
      return v % BN254_SCALAR_MODULUS;
    };
    expect(C.NULLIFIER_DOMAIN).not.toBe(old("nullifier"));
    expect(C.NOTE_COMMITMENT_DOMAIN).not.toBe(old("note_commitment"));
  });

  it("suite and registry id hashes match their strings", () => {
    const hash = (s: string) => {
      const d = keccak_256(new TextEncoder().encode(s));
      return `0x${Array.from(d, (x) => x.toString(16).padStart(2, "0")).join("")}`;
    };
    expect(C.SUITE_ID).toBe(hash("ERCXXXX_MLKEM768_HKDFSHA256_AESGCM256_ABI_V1"));
    expect(C.REGISTRY_ID).toBe(hash("ERCXXXX_PRIVACY_IDENTITY_REGISTRY_V1"));
  });
});
