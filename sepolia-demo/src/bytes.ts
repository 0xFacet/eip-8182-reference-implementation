export type BytesLike = Uint8Array | ArrayBuffer | ArrayBufferView | readonly number[] | string;

type BufferLikeConstructor = {
  from(value: Uint8Array): { toString(encoding: "base64"): string };
  from(value: string, encoding: "base64"): Uint8Array;
};

const HEX_RE = /^(0x)?[0-9a-fA-F]*$/;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function utf8ToBytes(value: string): Uint8Array {
  return textEncoder.encode(value);
}

export function bytesToUtf8(value: BytesLike): string {
  return textDecoder.decode(toBytes(value));
}

export function toBytes(value: BytesLike, name = "bytes"): Uint8Array {
  if (value instanceof Uint8Array) return new Uint8Array(value);
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  }
  if (Array.isArray(value)) return Uint8Array.from(value);
  if (typeof value === "string") return hexToBytes(value, name);
  throw new TypeError(`${name} must be bytes or a hex string`);
}

export function hexToBytes(hex: string, name = "hex"): Uint8Array {
  if (!HEX_RE.test(hex)) throw new Error(`${name} must be a hex string`);
  const normalized = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (normalized.length % 2 !== 0) throw new Error(`${name} must have an even number of hex digits`);
  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(value: BytesLike): `0x${string}` {
  const bytes = toBytes(value);
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return `0x${hex}`;
}

export function base64UrlEncode(value: BytesLike): string {
  const bytes = toBytes(value);
  const maybeBuffer = (globalThis as { Buffer?: BufferLikeConstructor }).Buffer;
  if (maybeBuffer) return base64ToBase64Url(maybeBuffer.from(bytes).toString("base64"));

  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return base64ToBase64Url(btoa(binary));
}

export function base64UrlDecode(value: string, name = "base64url"): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new Error(`${name} must be base64url`);
  const maybeBuffer = (globalThis as { Buffer?: BufferLikeConstructor }).Buffer;
  if (maybeBuffer) return new Uint8Array(maybeBuffer.from(base64UrlToBase64(value), "base64"));

  const padded = base64UrlToBase64(value);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

function base64ToBase64Url(value: string): string {
  return value.replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64UrlToBase64(value: string): string {
  return value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
}

export function concatBytes(...parts: readonly BytesLike[]): Uint8Array {
  const arrays = parts.map((part) => toBytes(part));
  const length = arrays.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of arrays) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function randomBytes(length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 0) throw new Error("random byte length must be a nonnegative integer");
  if (!globalThis.crypto?.getRandomValues) throw new Error("crypto.getRandomValues is required");

  const out = new Uint8Array(length);
  for (let offset = 0; offset < out.length; offset += 65536) {
    globalThis.crypto.getRandomValues(out.subarray(offset, Math.min(offset + 65536, out.length)));
  }
  return out;
}

export function expectLength(value: BytesLike, length: number, name: string): Uint8Array {
  const bytes = toBytes(value, name);
  if (bytes.length !== length) throw new Error(`${name} must be ${length} bytes`);
  return bytes;
}
