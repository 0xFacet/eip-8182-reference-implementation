// Proves the SDK's EIP-712 typed-data hashing agrees with the shared cross-surface
// vector (assets/derivation_vectors.json), which the Noir auth circuit also pins.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { IntentFields } from "../src/derivations.ts";
import { EIP712_TYPES, eip712Domain, hashPrivateTransferIntent, signPrivateTransferIntent } from "../src/eip712.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const VECTORS = JSON.parse(fs.readFileSync(path.join(HERE, "../../assets/derivation_vectors.json"), "utf8"));

function fieldsFromVector(scenario: string): { fields: IntentFields; policyDataHash: bigint } {
  const s = VECTORS.scenarios[scenario];
  const f = s.intentFields;
  const b = (k: string) => BigInt(f[k]);
  const fields: IntentFields = {
    poolAddress: b("poolAddress"),
    authVerifier: b("authVerifier"),
    authorizingAddress: b("authorizingAddress"),
    operationKind: b("operationKind"),
    tokenAddress: b("tokenAddress"),
    recipientOwnerNullifierKeyHash: b("recipientOwnerNullifierKeyHash"),
    amount: b("amount"),
    feeNoteRecipientOwnerNullifierKeyHash: b("feeNoteRecipientOwnerNullifierKeyHash"),
    feeAmount: b("feeAmount"),
    publicRecipientAddress: b("publicRecipientAddress"),
    authorizedSubmitter: b("authorizedSubmitter"),
    downstreamActionCommitment: b("downstreamActionCommitment"),
    executionConstraintsFlags: b("executionConstraintsFlags"),
    lockedOutputBinding0: b("lockedOutputBinding0"),
    lockedOutputBinding1: b("lockedOutputBinding1"),
    lockedOutputBinding2: b("lockedOutputBinding2"),
    nonce: b("nonce"),
    validUntilSeconds: b("validUntilSeconds"),
    executionChainId: b("executionChainId"),
  };
  return { fields, policyDataHash: BigInt(s.policyDataHash) };
}

describe("eip712 auth", () => {
  it("hashPrivateTransferIntent matches the transfer vector digest", () => {
    const { fields, policyDataHash } = fieldsFromVector("transfer");
    expect(hashPrivateTransferIntent(fields, policyDataHash)).toBe(VECTORS.scenarios.transfer.eip712.digest);
  });

  it("hashPrivateTransferIntent matches the withdrawal vector digest", () => {
    const { fields, policyDataHash } = fieldsFromVector("withdrawal");
    expect(hashPrivateTransferIntent(fields, policyDataHash)).toBe(VECTORS.scenarios.withdrawal.eip712.digest);
  });

  it("domain uses the pool as verifyingContract", () => {
    const { fields } = fieldsFromVector("transfer");
    const domain = eip712Domain(fields.executionChainId, fields.poolAddress);
    expect(domain.verifyingContract.toLowerCase()).toBe(VECTORS.scenarios.transfer.eip712.domain.verifyingContract.toLowerCase());
    expect(domain.name).toBe("ERCXXXXPrivateTransfers");
  });

  it("signPrivateTransferIntent reproduces the vector signature + pubkey", async () => {
    const { fields, policyDataHash } = fieldsFromVector("transfer");
    const account = privateKeyToAccount(VECTORS.identities.sender.privateKey);
    const signed = await signPrivateTransferIntent(account, fields, policyDataHash);
    const ev = VECTORS.scenarios.transfer.eip712;
    expect(signed.digest).toBe(ev.digest);
    expect(signed.r).toBe(ev.r);
    expect(signed.s).toBe(ev.s);
    expect(signed.v).toBe(ev.v);
    expect(signed.publicKeyX.toLowerCase()).toBe(ev.publicKeyX.toLowerCase());
    expect(signed.publicKeyY.toLowerCase()).toBe(ev.publicKeyY.toLowerCase());
  });

  it("exposes the 20-field type", () => {
    expect(EIP712_TYPES.PrivateTransferIntent).toHaveLength(20);
  });
});
