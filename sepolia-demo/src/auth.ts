import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { TypedDataEncoder } from "ethers";
import { bytesToHex, hexToBytes, toBytes, utf8ToBytes, type BytesLike } from "./bytes.js";
import { fieldToAddress, normalizeAddress, type FieldNumberish, type HexAddress } from "./payload.js";
import { fieldToHex } from "./poseidon.js";
import type { PreparedDemoPrivateTransfer } from "./transfer.js";

export const AUTH_EIP712_VERIFYING_CONTRACT = "0x0000000000000000000000000000000000081820" as const;

export interface RecoveredSecp256k1PublicKey {
  publicKey: Uint8Array;
  address: HexAddress;
}

export interface AuthIntentTypedData {
  domain: {
    name: "EIP-8182 Auth";
    version: "1";
    chainId: number;
    verifyingContract: HexAddress;
  };
  types: {
    EIP712Domain: readonly Eip712TypedDataField[];
    TransactionIntent: readonly Eip712TypedDataField[];
  };
  primaryType: "TransactionIntent";
  message: Record<string, string | bigint>;
}

export interface Eip712TypedDataField {
  name: string;
  type: string;
}

export const AUTH_EIP712_DOMAIN_TYPES: readonly Eip712TypedDataField[] = [
  { name: "name", type: "string" },
  { name: "version", type: "string" },
  { name: "chainId", type: "uint256" },
  { name: "verifyingContract", type: "address" }
] as const;

export const AUTH_INTENT_TYPES: readonly Eip712TypedDataField[] = [
  { name: "authVerifier", type: "address" },
  { name: "authorizingAddress", type: "address" },
  { name: "tokenAddress", type: "address" },
  { name: "recipientOwnerNullifierKeyHash", type: "uint256" },
  { name: "amount", type: "uint256" },
  { name: "nonce", type: "bytes32" },
  { name: "validUntilSeconds", type: "uint256" }
] as const;

export type AuthIntentEthersTypes = Record<string, Eip712TypedDataField[]>;

export function authIntentEthersTypes(typedData?: AuthIntentTypedData): AuthIntentEthersTypes {
  return {
    TransactionIntent: [...(typedData?.types.TransactionIntent ?? AUTH_INTENT_TYPES)]
  };
}

export function authIntentDigest(
  transfer: PreparedDemoPrivateTransfer,
  authorizingAddress: HexAddress
): `0x${string}` {
  const typedData = authIntentTypedData(transfer, authorizingAddress);
  return TypedDataEncoder.hash(
    typedData.domain,
    authIntentEthersTypes(typedData),
    typedData.message
  ) as `0x${string}`;
}

export function recoverPersonalSignPublicKey(message: string, signature: BytesLike): RecoveredSecp256k1PublicKey {
  return recoverPublicKey(eip191MessageDigest(message), signature);
}

export function recoverPublicKey(digest: BytesLike, signature: BytesLike): RecoveredSecp256k1PublicKey {
  const { compact, recovery } = splitSignature(signature);
  const recovered = secp256k1.Signature
    .fromBytes(compact)
    .addRecoveryBit(recovery)
    .recoverPublicKey(toBytes(digest, "digest"))
    .toBytes(false);
  const address = publicKeyToAddress(recovered);
  return { publicKey: recovered, address };
}

export function publicKeyToAddress(publicKey: BytesLike): HexAddress {
  const bytes = toBytes(publicKey, "publicKey");
  const raw = bytes.length === 65 && bytes[0] === 4 ? bytes.slice(1) : bytes;
  if (raw.length !== 64) throw new Error("publicKey must be 64-byte raw or 65-byte uncompressed secp256k1 key");
  const hash = keccak_256(raw);
  return normalizeAddress(bytesToHex(hash.slice(-20)), "publicKey address");
}

export function eip191MessageDigest(message: string): Uint8Array {
  const messageBytes = utf8ToBytes(message);
  const prefix = utf8ToBytes(`\x19Ethereum Signed Message:\n${messageBytes.length}`);
  const input = new Uint8Array(prefix.length + messageBytes.length);
  input.set(prefix, 0);
  input.set(messageBytes, prefix.length);
  return keccak_256(input);
}

export function authIntentTypedData(
  transfer: PreparedDemoPrivateTransfer,
  authorizingAddress: HexAddress
): AuthIntentTypedData {
  const chainId = Number(transfer.publicInputPreview.executionChainId);
  if (!Number.isSafeInteger(chainId)) throw new Error("execution chain id does not fit in a JS number");
  return {
    domain: {
      name: "EIP-8182 Auth",
      version: "1",
      chainId,
      verifyingContract: AUTH_EIP712_VERIFYING_CONTRACT
    },
    types: {
      EIP712Domain: AUTH_EIP712_DOMAIN_TYPES,
      TransactionIntent: AUTH_INTENT_TYPES
    },
    primaryType: "TransactionIntent",
    message: {
      authVerifier: fieldAddress(transfer.publicInputPreview.authVerifier),
      authorizingAddress: normalizeAddress(authorizingAddress, "authorizingAddress"),
      tokenAddress: transfer.tokenAddress,
      recipientOwnerNullifierKeyHash: transfer.outputSlots[0].ownerNullifierKeyHash,
      amount: transfer.transferAmount,
      nonce: fieldToHex(transfer.nonce),
      validUntilSeconds: transfer.validUntilSeconds
    }
  };
}

export function jsonStringifyTypedData(value: AuthIntentTypedData): string {
  return JSON.stringify(value, (_key, field) => typeof field === "bigint" ? field.toString(10) : field);
}

export function splitSignature(signature: BytesLike): { compact: Uint8Array; recovery: 0 | 1 } {
  const bytes = typeof signature === "string" ? hexToBytes(signature, "signature") : toBytes(signature, "signature");
  if (bytes.length !== 65) throw new Error("signature must be 65 bytes");
  const v = bytes[64] ?? 0;
  const recovery = v >= 35 ? (v - 35) % 2 : v >= 27 ? v - 27 : v;
  if (recovery !== 0 && recovery !== 1) throw new Error("unsupported signature recovery id");
  return { compact: bytes.slice(0, 64), recovery };
}

function fieldAddress(value: FieldNumberish): HexAddress {
  return fieldToAddress(value, "field address");
}
