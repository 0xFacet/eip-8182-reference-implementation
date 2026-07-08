// Default encrypted outputNoteData envelope (spec §11), suite
// ERCXXXX_MLKEM768_HKDFSHA256_AESGCM256_ABI_V1.
//
//   headerBytes = abi.encode(uint256 version=1, bytes32 suiteId, bytes kemCiphertext, bytes12 nonce)
//   salt        = sha256(utf8("ercXXXX.private-transfer-envelope-salt-v1") || headerBytes)
//   info        = utf8("ercXXXX.private-transfer-note-key-v1")   (default aadContext ABSENT)
//   key         = HKDF-SHA-256(ikm=mlKemSharedSecret, salt, info, 32)
//   ciphertext  = AES-256-GCM(key, nonce, plaintext, aad=headerBytes)  [128-bit tag]
//   outputNoteData = abi.encode(version, suiteId, kemCiphertext, nonce, ciphertext)
//
// ML-KEM-768 provides the KEM. AEAD uses WebCrypto so this runs in Node and the
// browser. tryDecryptOutputNoteData returns null on ANY failure.

import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { encodeAbiParameters } from "viem";
import { decodeEnvelopeTuple } from "./abiStrict.ts";
import { bytesToHex, concatBytes, hexToBytes, randomBytes, utf8ToBytes } from "./bytes.ts";
import { HKDF_INFO_LABEL, HKDF_SALT_LABEL, SUITE_ID } from "./generated/constants.ts";

export const ENVELOPE_VERSION = 1n;
export const ML_KEM_768_PUBLIC_KEY_LENGTH = 1184;
export const ML_KEM_768_SECRET_KEY_LENGTH = 2400;
export const ML_KEM_768_CIPHERTEXT_LENGTH = 1088;
export const ML_KEM_768_SEED_LENGTH = 64;
export const ML_KEM_768_ENCAPS_MESSAGE_LENGTH = 32;
export const ENVELOPE_NONCE_LENGTH = 12;
export const AES_GCM_TAG_LENGTH_BITS = 128;

const SUITE_ID_BYTES = hexToBytes(SUITE_ID, "suiteId");
const SALT_LABEL = utf8ToBytes(HKDF_SALT_LABEL);
const INFO_BYTES = utf8ToBytes(HKDF_INFO_LABEL); // default aadContext absent => info has no aadContextHash

const ENVELOPE_ABI = [
  { name: "version", type: "uint256" },
  { name: "suiteId", type: "bytes32" },
  { name: "kemCiphertext", type: "bytes" },
  { name: "nonce", type: "bytes12" },
  { name: "ciphertext", type: "bytes" },
] as const;

const HEADER_ABI = [
  { name: "version", type: "uint256" },
  { name: "suiteId", type: "bytes32" },
  { name: "kemCiphertext", type: "bytes" },
  { name: "nonce", type: "bytes12" },
] as const;

export interface EncryptOptions {
  /** 12-byte AES-GCM nonce. Random when omitted. */
  nonce?: Uint8Array;
  /** 32-byte ML-KEM encapsulation message for deterministic vectors. Random when omitted. */
  kemMessage?: Uint8Array;
}

export interface ReceiveKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** Generate an ML-KEM-768 receive key pair. Optional 64-byte seed for determinism. */
export function generateReceiveKeyPair(seed?: Uint8Array): ReceiveKeyPair {
  if (seed !== undefined && seed.length !== ML_KEM_768_SEED_LENGTH) {
    throw new Error(`ML-KEM-768 seed must be ${ML_KEM_768_SEED_LENGTH} bytes`);
  }
  const kp = seed === undefined ? ml_kem768.keygen() : ml_kem768.keygen(seed);
  return { publicKey: kp.publicKey, secretKey: kp.secretKey };
}

/** headerBytes = abi.encode(version, suiteId, kemCiphertext, nonce). */
function computeHeaderBytes(kemCiphertext: Uint8Array, nonce: Uint8Array): Uint8Array {
  const encoded = encodeAbiParameters(HEADER_ABI, [
    ENVELOPE_VERSION,
    SUITE_ID,
    bytesToHex(kemCiphertext),
    bytesToHex(nonce),
  ]);
  return hexToBytes(encoded, "headerBytes");
}

/** key = HKDF-SHA-256(ikm=sharedSecret, salt=sha256(saltLabel || headerBytes), info, 32). */
function deriveKey(sharedSecret: Uint8Array, headerBytes: Uint8Array): Uint8Array {
  const salt = sha256(concatBytes(SALT_LABEL, headerBytes));
  return hkdf(sha256, sharedSecret, salt, INFO_BYTES, 32);
}

// Copy bytes into a fresh ArrayBuffer. WebCrypto's BufferSource type wants an
// ArrayBuffer-backed view; noble/our Uint8Arrays are typed over ArrayBufferLike.
function toArrayBuffer(u: Uint8Array): ArrayBuffer {
  return u.slice().buffer as ArrayBuffer;
}

async function aesGcmEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await globalThis.crypto.subtle.importKey("raw", toArrayBuffer(key), { name: "AES-GCM" }, false, [
    "encrypt",
  ]);
  const result = await globalThis.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: toArrayBuffer(nonce), additionalData: toArrayBuffer(aad), tagLength: AES_GCM_TAG_LENGTH_BITS },
    cryptoKey,
    toArrayBuffer(plaintext),
  );
  return new Uint8Array(result);
}

async function aesGcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await globalThis.crypto.subtle.importKey("raw", toArrayBuffer(key), { name: "AES-GCM" }, false, [
    "decrypt",
  ]);
  const result = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: toArrayBuffer(nonce), additionalData: toArrayBuffer(aad), tagLength: AES_GCM_TAG_LENGTH_BITS },
    cryptoKey,
    toArrayBuffer(ciphertext),
  );
  return new Uint8Array(result);
}

/**
 * Encrypt a note payload for a recipient ML-KEM-768 public key, producing the
 * strict-ABI `outputNoteData` envelope bytes.
 */
export async function encryptOutputNoteData(
  recipientMlKem768PublicKey: Uint8Array,
  plaintext: Uint8Array,
  opts: EncryptOptions = {},
): Promise<Uint8Array> {
  if (recipientMlKem768PublicKey.length !== ML_KEM_768_PUBLIC_KEY_LENGTH) {
    throw new Error(`recipient ML-KEM-768 public key must be ${ML_KEM_768_PUBLIC_KEY_LENGTH} bytes`);
  }
  const nonce = opts.nonce ?? randomBytes(ENVELOPE_NONCE_LENGTH);
  if (nonce.length !== ENVELOPE_NONCE_LENGTH) {
    throw new Error(`nonce must be ${ENVELOPE_NONCE_LENGTH} bytes`);
  }
  if (opts.kemMessage !== undefined && opts.kemMessage.length !== ML_KEM_768_ENCAPS_MESSAGE_LENGTH) {
    throw new Error(`kemMessage must be ${ML_KEM_768_ENCAPS_MESSAGE_LENGTH} bytes`);
  }

  const { cipherText: kemCiphertext, sharedSecret } =
    opts.kemMessage === undefined
      ? ml_kem768.encapsulate(recipientMlKem768PublicKey)
      : ml_kem768.encapsulate(recipientMlKem768PublicKey, opts.kemMessage);

  const headerBytes = computeHeaderBytes(kemCiphertext, nonce);
  const key = deriveKey(sharedSecret, headerBytes);
  const ciphertext = await aesGcmEncrypt(key, nonce, plaintext, headerBytes);

  const encoded = encodeAbiParameters(ENVELOPE_ABI, [
    ENVELOPE_VERSION,
    SUITE_ID,
    bytesToHex(kemCiphertext),
    bytesToHex(nonce),
    bytesToHex(ciphertext),
  ]);
  return hexToBytes(encoded, "outputNoteData");
}

function suiteIdMatches(suiteId: Uint8Array): boolean {
  if (suiteId.length !== SUITE_ID_BYTES.length) return false;
  for (let i = 0; i < suiteId.length; i += 1) {
    if (suiteId[i] !== SUITE_ID_BYTES[i]) return false;
  }
  return true;
}

/**
 * Attempt to decrypt an `outputNoteData` envelope with an ML-KEM-768 secret key.
 * Returns the plaintext, or null on ANY failure (strict-decode, wrong
 * suite/version, lengths, decapsulation, or AEAD authentication).
 */
export async function tryDecryptOutputNoteData(
  secretKey: Uint8Array,
  outputNoteData: Uint8Array,
): Promise<Uint8Array | null> {
  try {
    const env = decodeEnvelopeTuple(outputNoteData);
    if (env.version !== ENVELOPE_VERSION) return null;
    if (!suiteIdMatches(env.suiteId)) return null;
    if (secretKey.length !== ML_KEM_768_SECRET_KEY_LENGTH) return null;

    const sharedSecret = ml_kem768.decapsulate(env.kemCiphertext, secretKey);
    const headerBytes = computeHeaderBytes(env.kemCiphertext, env.nonce);
    const key = deriveKey(sharedSecret, headerBytes);
    return await aesGcmDecrypt(key, env.nonce, env.ciphertext, headerBytes);
  } catch {
    return null;
  }
}
