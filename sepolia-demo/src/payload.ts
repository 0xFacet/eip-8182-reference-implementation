import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToUtf8, type BytesLike, toBytes, utf8ToBytes } from "./bytes.js";

export const NOTE_PAYLOAD_VERSION = 1;
export const BN254_SCALAR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export type HexAddress = `0x${string}`;
export type FieldNumberish = bigint | number | string;
export type NotePayloadKind = "deposit" | "transact";

export interface NotePayload {
  version?: typeof NOTE_PAYLOAD_VERSION;
  kind: NotePayloadKind;
  chainId: FieldNumberish;
  poolAddress: HexAddress;
  tokenAddress: HexAddress;
  amount: FieldNumberish;
  ownerNullifierKeyHash: FieldNumberish;
  noteSecret: FieldNumberish;
  noteBodyCommitment?: FieldNumberish;
  noteCommitment?: FieldNumberish;
  leafIndex?: FieldNumberish;
  outputIndex?: 0 | 1 | 2;
  memo?: string;
}

export interface DecodedNotePayload {
  version: typeof NOTE_PAYLOAD_VERSION;
  kind: NotePayloadKind;
  chainId: bigint;
  poolAddress: HexAddress;
  tokenAddress: HexAddress;
  amount: bigint;
  ownerNullifierKeyHash: bigint;
  noteSecret: bigint;
  noteBodyCommitment?: bigint;
  noteCommitment?: bigint;
  leafIndex?: bigint;
  outputIndex?: 0 | 1 | 2;
  memo?: string;
}

type EncodedNotePayload = {
  v: typeof NOTE_PAYLOAD_VERSION;
  kind: NotePayloadKind;
  chainId: string;
  poolAddress: HexAddress;
  tokenAddress: HexAddress;
  amount: string;
  ownerNullifierKeyHash: string;
  noteSecret: string;
  noteBodyCommitment?: string;
  noteCommitment?: string;
  leafIndex?: string;
  outputIndex?: 0 | 1 | 2;
  memo?: string;
};

export function encodeNotePayload(payload: NotePayload): Uint8Array {
  const canonical: EncodedNotePayload = {
    v: NOTE_PAYLOAD_VERSION,
    kind: normalizeKind(payload.kind),
    chainId: toNonnegativeBigInt(payload.chainId, "chainId").toString(10),
    poolAddress: normalizeAddress(payload.poolAddress, "poolAddress"),
    tokenAddress: normalizeAddress(payload.tokenAddress, "tokenAddress"),
    amount: toNonnegativeBigInt(payload.amount, "amount").toString(10),
    ownerNullifierKeyHash: toFieldString(payload.ownerNullifierKeyHash, "ownerNullifierKeyHash"),
    noteSecret: toFieldString(payload.noteSecret, "noteSecret")
  };

  if (payload.noteBodyCommitment !== undefined) {
    canonical.noteBodyCommitment = toFieldString(payload.noteBodyCommitment, "noteBodyCommitment");
  }
  if (payload.noteCommitment !== undefined) {
    canonical.noteCommitment = toFieldString(payload.noteCommitment, "noteCommitment");
  }
  if (payload.leafIndex !== undefined) {
    canonical.leafIndex = toNonnegativeBigInt(payload.leafIndex, "leafIndex").toString(10);
  }
  if (payload.outputIndex !== undefined) canonical.outputIndex = normalizeOutputIndex(payload.outputIndex);
  if (payload.memo !== undefined) canonical.memo = String(payload.memo);

  return utf8ToBytes(JSON.stringify(canonical));
}

export function decodeNotePayload(encoded: BytesLike): DecodedNotePayload {
  let value: unknown;
  try {
    value = JSON.parse(bytesToUtf8(encoded));
  } catch (cause) {
    throw new Error("note payload is not valid JSON", { cause });
  }

  if (!isRecord(value)) throw new Error("note payload must be a JSON object");
  if (value.v !== NOTE_PAYLOAD_VERSION) throw new Error(`unsupported note payload version: ${String(value.v)}`);

  const decoded: DecodedNotePayload = {
    version: NOTE_PAYLOAD_VERSION,
    kind: normalizeKind(readString(value, "kind")),
    chainId: parseNonnegativeDecimal(readString(value, "chainId"), "chainId"),
    poolAddress: normalizeAddress(readString(value, "poolAddress"), "poolAddress"),
    tokenAddress: normalizeAddress(readString(value, "tokenAddress"), "tokenAddress"),
    amount: parseNonnegativeDecimal(readString(value, "amount"), "amount"),
    ownerNullifierKeyHash: parseField(readString(value, "ownerNullifierKeyHash"), "ownerNullifierKeyHash"),
    noteSecret: parseField(readString(value, "noteSecret"), "noteSecret")
  };

  if (value.noteBodyCommitment !== undefined) {
    decoded.noteBodyCommitment = parseField(readString(value, "noteBodyCommitment"), "noteBodyCommitment");
  }
  if (value.noteCommitment !== undefined) {
    decoded.noteCommitment = parseField(readString(value, "noteCommitment"), "noteCommitment");
  }
  if (value.leafIndex !== undefined) decoded.leafIndex = parseNonnegativeDecimal(readString(value, "leafIndex"), "leafIndex");
  if (value.outputIndex !== undefined) decoded.outputIndex = normalizeOutputIndex(value.outputIndex);
  if (value.memo !== undefined) decoded.memo = readString(value, "memo");

  return decoded;
}

export function outputNoteDataHash(outputNoteData: BytesLike): bigint {
  return bytesToBigInt(keccak_256(toBytes(outputNoteData))) % BN254_SCALAR_MODULUS;
}

export function normalizeAddress(address: string, name = "address"): HexAddress {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) throw new Error(`${name} must be a 20-byte hex address`);
  return address.toLowerCase() as HexAddress;
}

export function fieldToAddress(value: FieldNumberish, name = "addressField"): HexAddress {
  const field = toNonnegativeBigInt(value, name);
  if (field >= 1n << 160n) throw new Error(`${name} does not fit in an address`);
  return `0x${field.toString(16).padStart(40, "0")}` as HexAddress;
}

export function toNonnegativeBigInt(value: FieldNumberish, name: string): bigint {
  if (typeof value === "bigint") {
    if (value < 0n) throw new Error(`${name} must be nonnegative`);
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${name} must be a nonnegative safe integer`);
    return BigInt(value);
  }
  if (typeof value === "string") {
    const normalized = value.trim();
    const parsed = normalized.startsWith("0x") || normalized.startsWith("0X")
      ? BigInt(normalized)
      : parseNonnegativeDecimal(normalized, name);
    if (parsed < 0n) throw new Error(`${name} must be nonnegative`);
    return parsed;
  }
  throw new TypeError(`${name} must be bigint, number, or string`);
}

function toFieldString(value: FieldNumberish, name: string): string {
  return normalizeField(value, name).toString(10);
}

function normalizeField(value: FieldNumberish, name: string): bigint {
  const field = toNonnegativeBigInt(value, name);
  if (field >= BN254_SCALAR_MODULUS) throw new Error(`${name} must be a BN254 scalar field element`);
  return field;
}

function parseField(value: string, name: string): bigint {
  const field = parseNonnegativeDecimal(value, name);
  if (field >= BN254_SCALAR_MODULUS) throw new Error(`${name} must be a BN254 scalar field element`);
  return field;
}

function parseNonnegativeDecimal(value: string, name: string): bigint {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) throw new Error(`${name} must be a nonnegative decimal string`);
  return BigInt(value);
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) + BigInt(byte);
  return value;
}

function normalizeKind(kind: unknown): NotePayloadKind {
  if (kind === "deposit" || kind === "transact") return kind;
  throw new Error("kind must be deposit or transact");
}

function normalizeOutputIndex(value: unknown): 0 | 1 | 2 {
  if (value === 0 || value === 1 || value === 2) return value;
  throw new Error("outputIndex must be 0, 1, or 2");
}

function readString(value: Record<string, unknown>, key: string): string {
  const field = value[key];
  if (typeof field !== "string") throw new Error(`${key} must be a string`);
  return field;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
