import { keccak_256 } from "@noble/hashes/sha3.js";
import { type BytesLike, bytesToHex, randomBytes, toBytes } from "./bytes.ts";

export const BN254_SCALAR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export type HexAddress = `0x${string}`;
export type FieldNumberish = bigint | number | string;

export function toNonnegativeBigInt(value: FieldNumberish, name = "value"): bigint {
  let out: bigint;
  if (typeof value === "bigint") out = value;
  else if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error(`${name} must be a safe integer`);
    out = BigInt(value);
  } else out = BigInt(value);
  if (out < 0n) throw new Error(`${name} must be nonnegative`);
  return out;
}

export function toField(value: FieldNumberish, name = "field"): bigint {
  const field = toNonnegativeBigInt(value, name);
  if (field >= BN254_SCALAR_MODULUS) throw new Error(`${name} must be a BN254 scalar field element`);
  return field;
}

export function normalizeAddress(address: string, name = "address"): HexAddress {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) throw new Error(`${name} must be a 20-byte hex address`);
  return address.toLowerCase() as HexAddress;
}

export function addressToField(address: string, name = "address"): bigint {
  return BigInt(normalizeAddress(address, name));
}

export function fieldToAddress(value: FieldNumberish, name = "address field"): HexAddress {
  const field = toNonnegativeBigInt(value, name);
  if (field >= 1n << 160n) throw new Error(`${name} must be < 2^160`);
  return `0x${field.toString(16).padStart(40, "0")}` as HexAddress;
}

export function keccakField(value: BytesLike): bigint {
  const digest = keccak_256(toBytes(value, "keccak input"));
  return BigInt(bytesToHex(digest)) % BN254_SCALAR_MODULUS;
}

export function fieldToHex(value: FieldNumberish): `0x${string}` {
  return `0x${toField(value).toString(16).padStart(64, "0")}`;
}

export function randomField(): bigint {
  let value = BigInt(bytesToHex(randomBytes(32))) % BN254_SCALAR_MODULUS;
  if (value === 0n) value = 1n;
  return value;
}
