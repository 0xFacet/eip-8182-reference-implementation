import { x25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import {
  base64UrlDecode,
  base64UrlEncode,
  bytesToUtf8,
  concatBytes,
  expectLength,
  type BytesLike,
  randomBytes,
  toBytes,
  utf8ToBytes
} from "./bytes.js";
import { decodeNotePayload, encodeNotePayload, type DecodedNotePayload, type FieldNumberish, type NotePayload, toNonnegativeBigInt } from "./payload.js";

export const ENVELOPE_VERSION = 1;
export const ENVELOPE_SUITE_ID = "EIP8182_SEPOLIA_DEMO_MLKEM768_X25519_HKDFSHA256_AESGCM256";
export const ML_KEM_768_PUBLIC_KEY_BYTES = 1184;
export const ML_KEM_768_SECRET_KEY_BYTES = 2400;
export const ML_KEM_768_CIPHERTEXT_BYTES = 1088;
export const X25519_KEY_BYTES = 32;
export const AES_GCM_NONCE_BYTES = 12;

export interface RecipientEncryptionPublicKey {
  mlKem768PublicKey: BytesLike;
  x25519PublicKey: BytesLike;
  keyId?: string;
}

export interface RecipientEncryptionSecretKey {
  mlKem768SecretKey: BytesLike;
  x25519SecretKey: BytesLike;
  keyId?: string;
  ownerNullifierKeyHash?: FieldNumberish;
}

export interface RecipientEncryptionKeyPair {
  publicKey: RecipientEncryptionPublicKey;
  secretKey: RecipientEncryptionSecretKey;
}

export interface GenerateRecipientEncryptionKeyPairOptions {
  mlKemSeed?: BytesLike;
  x25519SecretKey?: BytesLike;
  ownerNullifierKeyHash?: FieldNumberish;
}

export interface EnvelopeOptions {
  aad?: BytesLike;
  nonce?: BytesLike;
  x25519EphemeralSecretKey?: BytesLike;
}

export interface EncryptionEnvelope {
  v: typeof ENVELOPE_VERSION;
  suite: typeof ENVELOPE_SUITE_ID;
  kid: string;
  kem: string;
  eph: string;
  nonce: string;
  ct: string;
}

type EnvelopeHeader = Omit<EncryptionEnvelope, "ct">;

export class MalformedEnvelopeError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "MalformedEnvelopeError";
  }
}

export class EnvelopeDecryptionError extends Error {
  constructor(message = "envelope decryption failed", options?: ErrorOptions) {
    super(message, options);
    this.name = "EnvelopeDecryptionError";
  }
}

export function generateRecipientEncryptionKeyPair(
  options: GenerateRecipientEncryptionKeyPairOptions = {}
): RecipientEncryptionKeyPair {
  const mlKemSeed = options.mlKemSeed === undefined ? undefined : expectLength(options.mlKemSeed, 64, "mlKemSeed");
  const mlKemKeys = mlKemSeed === undefined ? ml_kem768.keygen() : ml_kem768.keygen(mlKemSeed);
  const x25519SecretKey = options.x25519SecretKey === undefined
    ? randomBytes(X25519_KEY_BYTES)
    : expectLength(options.x25519SecretKey, X25519_KEY_BYTES, "x25519SecretKey");
  const x25519PublicKey = x25519.getPublicKey(x25519SecretKey);

  const publicKey: RecipientEncryptionPublicKey = {
    mlKem768PublicKey: mlKemKeys.publicKey,
    x25519PublicKey
  };
  publicKey.keyId = recipientKeyId(publicKey);

  const secretKey: RecipientEncryptionSecretKey = {
    mlKem768SecretKey: mlKemKeys.secretKey,
    x25519SecretKey,
    keyId: publicKey.keyId
  };
  if (options.ownerNullifierKeyHash !== undefined) {
    secretKey.ownerNullifierKeyHash = toNonnegativeBigInt(options.ownerNullifierKeyHash, "ownerNullifierKeyHash");
  }

  return { publicKey, secretKey };
}

export function recipientKeyId(recipient: RecipientEncryptionPublicKey): string {
  const mlKemPublicKey = expectLength(recipient.mlKem768PublicKey, ML_KEM_768_PUBLIC_KEY_BYTES, "mlKem768PublicKey");
  const x25519PublicKey = expectLength(recipient.x25519PublicKey, X25519_KEY_BYTES, "x25519PublicKey");
  const digest = sha256(concatBytes(utf8ToBytes(ENVELOPE_SUITE_ID), new Uint8Array([0]), mlKemPublicKey, x25519PublicKey));
  return `sha256:${base64UrlEncode(digest)}`;
}

export async function encryptNotePayload(
  payload: NotePayload,
  recipient: RecipientEncryptionPublicKey,
  options: EnvelopeOptions = {}
): Promise<Uint8Array> {
  return encryptEnvelope(encodeNotePayload(payload), recipient, options);
}

export async function decryptNotePayload(
  envelopeBytes: BytesLike,
  recipient: RecipientEncryptionSecretKey,
  options: Pick<EnvelopeOptions, "aad"> = {}
): Promise<DecodedNotePayload> {
  return decodeNotePayload(await decryptEnvelope(envelopeBytes, recipient, options));
}

export async function encryptEnvelope(
  plaintext: BytesLike,
  recipient: RecipientEncryptionPublicKey,
  options: EnvelopeOptions = {}
): Promise<Uint8Array> {
  const mlKemPublicKey = expectLength(recipient.mlKem768PublicKey, ML_KEM_768_PUBLIC_KEY_BYTES, "mlKem768PublicKey");
  const recipientX25519PublicKey = expectLength(recipient.x25519PublicKey, X25519_KEY_BYTES, "x25519PublicKey");
  const ephemeralSecretKey = options.x25519EphemeralSecretKey === undefined
    ? randomBytes(X25519_KEY_BYTES)
    : expectLength(options.x25519EphemeralSecretKey, X25519_KEY_BYTES, "x25519EphemeralSecretKey");
  const ephemeralPublicKey = x25519.getPublicKey(ephemeralSecretKey);
  const { cipherText: mlKemCiphertext, sharedSecret: mlKemSharedSecret } = ml_kem768.encapsulate(mlKemPublicKey);
  const x25519SharedSecret = x25519.getSharedSecret(ephemeralSecretKey, recipientX25519PublicKey);
  const nonce = options.nonce === undefined
    ? randomBytes(AES_GCM_NONCE_BYTES)
    : expectLength(options.nonce, AES_GCM_NONCE_BYTES, "nonce");

  const header: EnvelopeHeader = {
    v: ENVELOPE_VERSION,
    suite: ENVELOPE_SUITE_ID,
    kid: recipient.keyId ?? recipientKeyId(recipient),
    kem: base64UrlEncode(mlKemCiphertext),
    eph: base64UrlEncode(ephemeralPublicKey),
    nonce: base64UrlEncode(nonce)
  };

  const key = await deriveAesGcmKey(mlKemSharedSecret, x25519SharedSecret, header, options.aad);
  const ciphertext = new Uint8Array(await getSubtle().encrypt(
    {
      name: "AES-GCM",
      iv: asArrayBuffer(nonce),
      additionalData: asArrayBuffer(envelopeAad(header, options.aad)),
      tagLength: 128
    },
    key,
    asArrayBuffer(toBytes(plaintext, "plaintext"))
  ));

  return serializeEnvelope({ ...header, ct: base64UrlEncode(ciphertext) });
}

export async function decryptEnvelope(
  envelopeBytes: BytesLike,
  recipient: RecipientEncryptionSecretKey,
  options: Pick<EnvelopeOptions, "aad"> = {}
): Promise<Uint8Array> {
  const envelope = parseEnvelope(envelopeBytes);
  const header = envelopeHeader(envelope);
  const mlKemCiphertext = expectLength(base64UrlDecode(envelope.kem, "kem"), ML_KEM_768_CIPHERTEXT_BYTES, "kem");
  const ephemeralPublicKey = expectLength(base64UrlDecode(envelope.eph, "eph"), X25519_KEY_BYTES, "eph");
  const nonce = expectLength(base64UrlDecode(envelope.nonce, "nonce"), AES_GCM_NONCE_BYTES, "nonce");
  const ciphertext = base64UrlDecode(envelope.ct, "ct");
  const mlKemSecretKey = expectLength(recipient.mlKem768SecretKey, ML_KEM_768_SECRET_KEY_BYTES, "mlKem768SecretKey");
  const x25519SecretKey = expectLength(recipient.x25519SecretKey, X25519_KEY_BYTES, "x25519SecretKey");

  try {
    const mlKemSharedSecret = ml_kem768.decapsulate(mlKemCiphertext, mlKemSecretKey);
    const x25519SharedSecret = x25519.getSharedSecret(x25519SecretKey, ephemeralPublicKey);
    const key = await deriveAesGcmKey(mlKemSharedSecret, x25519SharedSecret, header, options.aad);
    return new Uint8Array(await getSubtle().decrypt(
      {
        name: "AES-GCM",
        iv: asArrayBuffer(nonce),
        additionalData: asArrayBuffer(envelopeAad(header, options.aad)),
        tagLength: 128
      },
      key,
      asArrayBuffer(ciphertext)
    ));
  } catch (cause) {
    throw new EnvelopeDecryptionError("envelope decryption failed", { cause });
  }
}

export function serializeEnvelope(envelope: EncryptionEnvelope): Uint8Array {
  return utf8ToBytes(JSON.stringify(normalizeEnvelope({ ...envelope })));
}

export function parseEnvelope(envelopeBytes: BytesLike): EncryptionEnvelope {
  let value: unknown;
  try {
    value = JSON.parse(bytesToUtf8(envelopeBytes));
  } catch (cause) {
    throw new MalformedEnvelopeError("envelope is not valid JSON", { cause });
  }
  if (!isRecord(value)) throw new MalformedEnvelopeError("envelope must be a JSON object");
  return normalizeEnvelope(value);
}

export function isEncryptionEnvelopeBytes(value: BytesLike): boolean {
  try {
    parseEnvelope(value);
    return true;
  } catch {
    return false;
  }
}

function normalizeEnvelope(value: Record<string, unknown>): EncryptionEnvelope {
  if (value.v !== ENVELOPE_VERSION) throw new MalformedEnvelopeError(`unsupported envelope version: ${String(value.v)}`);
  if (value.suite !== ENVELOPE_SUITE_ID) throw new MalformedEnvelopeError(`unsupported envelope suite: ${String(value.suite)}`);

  return {
    v: ENVELOPE_VERSION,
    suite: ENVELOPE_SUITE_ID,
    kid: readString(value, "kid"),
    kem: readString(value, "kem"),
    eph: readString(value, "eph"),
    nonce: readString(value, "nonce"),
    ct: readString(value, "ct")
  };
}

function envelopeHeader(envelope: EncryptionEnvelope): EnvelopeHeader {
  return {
    v: envelope.v,
    suite: envelope.suite,
    kid: envelope.kid,
    kem: envelope.kem,
    eph: envelope.eph,
    nonce: envelope.nonce
  };
}

async function deriveAesGcmKey(
  mlKemSharedSecret: BytesLike,
  x25519SharedSecret: BytesLike,
  header: EnvelopeHeader,
  aad?: BytesLike
): Promise<CryptoKey> {
  const headerBytes = serializeHeader(header);
  const aadHash = aad === undefined ? new Uint8Array() : sha256(toBytes(aad, "aad"));
  const salt = sha256(concatBytes(utf8ToBytes("eip-8182-sepolia-demo-envelope-salt-v1"), headerBytes));
  const info = concatBytes(utf8ToBytes("eip-8182-sepolia-demo-note-key-v1"), aadHash);
  const ikm = concatBytes(mlKemSharedSecret, x25519SharedSecret);
  const hkdfKey = await getSubtle().importKey("raw", asArrayBuffer(ikm), "HKDF", false, ["deriveKey"]);
  return getSubtle().deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: asArrayBuffer(salt), info: asArrayBuffer(info) },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function envelopeAad(header: EnvelopeHeader, aad?: BytesLike): Uint8Array {
  return aad === undefined
    ? serializeHeader(header)
    : concatBytes(serializeHeader(header), new Uint8Array([0]), toBytes(aad, "aad"));
}

function serializeHeader(header: EnvelopeHeader): Uint8Array {
  return utf8ToBytes(JSON.stringify(header));
}

function getSubtle(): SubtleCrypto {
  if (!globalThis.crypto?.subtle) throw new Error("WebCrypto SubtleCrypto is required");
  return globalThis.crypto.subtle;
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function readString(value: Record<string, unknown>, key: string): string {
  const field = value[key];
  if (typeof field !== "string" || field.length === 0) throw new MalformedEnvelopeError(`${key} must be a nonempty string`);
  return field;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
