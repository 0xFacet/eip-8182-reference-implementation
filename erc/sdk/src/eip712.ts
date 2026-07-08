// Appendix A EIP-712 auth signing (20-field PrivateTransferIntent), bound to
// the deployed pool identity (chainId, verifyingContract = poolAddress).
// The type layout and domain here MUST match circuits-noir/auth/src/main.nr and
// scripts/gen_vectors.ts (proven equal via assets/derivation_vectors.json).

import { hashTypedData, parseSignature } from "viem";
import type { IntentFields } from "./derivations.ts";
import type { HexAddress } from "./field.ts";

/** Appendix A typed-data field order (20 fields; policyDataHash sits before nonce). */
export const EIP712_TYPES = {
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

export const EIP712_DOMAIN_NAME = "ERCXXXXPrivateTransfers";
export const EIP712_DOMAIN_VERSION = "1";

const toAddr = (v: bigint): HexAddress => `0x${v.toString(16).padStart(40, "0")}` as HexAddress;

export function eip712Domain(chainId: bigint, poolAddress: bigint) {
  return {
    name: EIP712_DOMAIN_NAME,
    version: EIP712_DOMAIN_VERSION,
    chainId: Number(chainId),
    verifyingContract: toAddr(poolAddress),
  } as const;
}

/** Build the 20-field typed-data message from IntentFields + policyDataHash. */
export function intentMessage(fields: IntentFields, policyDataHash: bigint) {
  return {
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
  } as const;
}

/** The EIP-712 signing digest (keccak of \x19\x01 || domainSeparator || hashStruct). */
export function hashPrivateTransferIntent(fields: IntentFields, policyDataHash: bigint): `0x${string}` {
  return hashTypedData({
    domain: eip712Domain(fields.executionChainId, fields.poolAddress),
    types: EIP712_TYPES,
    primaryType: "PrivateTransferIntent",
    message: intentMessage(fields, policyDataHash),
  });
}

export interface SignedIntent {
  digest: `0x${string}`;
  signature: `0x${string}`;
  v: number;
  r: `0x${string}`;
  s: `0x${string}`;
  /** 32-byte hex, no 0x-length surprises: the secp256k1 public key coordinates. */
  publicKeyX: `0x${string}`;
  publicKeyY: `0x${string}`;
}

/** A minimal structural type for a viem local account used here. */
export interface TypedDataSigner {
  address: `0x${string}`;
  publicKey: `0x${string}`; // 0x04 || X(32) || Y(32)
  signTypedData: (args: {
    domain: ReturnType<typeof eip712Domain>;
    types: typeof EIP712_TYPES;
    primaryType: "PrivateTransferIntent";
    message: ReturnType<typeof intentMessage>;
  }) => Promise<`0x${string}`>;
}

/** Sign the 20-field intent with a viem account; returns sig parts + pubkey coords. */
export async function signPrivateTransferIntent(
  account: TypedDataSigner,
  fields: IntentFields,
  policyDataHash: bigint,
): Promise<SignedIntent> {
  const domain = eip712Domain(fields.executionChainId, fields.poolAddress);
  const message = intentMessage(fields, policyDataHash);
  const digest = hashTypedData({ domain, types: EIP712_TYPES, primaryType: "PrivateTransferIntent", message });
  const signature = await account.signTypedData({
    domain,
    types: EIP712_TYPES,
    primaryType: "PrivateTransferIntent",
    message,
  });
  const parsed = parseSignature(signature);
  const pub = account.publicKey; // 0x04 || x || y
  return {
    digest,
    signature,
    r: parsed.r,
    s: parsed.s,
    v: Number(parsed.v ?? (parsed.yParity === 0 ? 27n : 28n)),
    publicKeyX: `0x${pub.slice(4, 68)}`,
    publicKeyY: `0x${pub.slice(68, 132)}`,
  };
}
