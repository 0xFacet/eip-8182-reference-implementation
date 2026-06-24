import { bytesToHex, type BytesLike } from "./bytes.js";
import {
  decryptEnvelope,
  decryptNotePayload,
  type EnvelopeDecryptionError,
  type RecipientEncryptionSecretKey
} from "./envelope.js";
import { decodeNotePayload, type DecodedNotePayload, toNonnegativeBigInt } from "./payload.js";

export interface TrialDecryptionCandidate {
  id: string;
  secretKey: RecipientEncryptionSecretKey;
}

export interface TrialDecryptOptions {
  aad?: BytesLike;
  requireOwnerMatch?: boolean;
}

export interface TrialDecryptBytesResult {
  candidateId: string;
  plaintext: Uint8Array;
}

export interface TrialDecryptNotePayloadResult {
  candidateId: string;
  payload: DecodedNotePayload;
}

export async function trialDecryptEnvelope(
  envelopeBytes: BytesLike,
  candidates: readonly TrialDecryptionCandidate[],
  options: TrialDecryptOptions = {}
): Promise<TrialDecryptBytesResult | null> {
  const envelopeOptions = options.aad === undefined ? {} : { aad: options.aad };
  for (const candidate of candidates) {
    try {
      return {
        candidateId: candidate.id,
        plaintext: await decryptEnvelope(envelopeBytes, candidate.secretKey, envelopeOptions)
      };
    } catch (_cause) {
      continue;
    }
  }
  return null;
}

export async function trialDecryptNotePayload(
  envelopeBytes: BytesLike,
  candidates: readonly TrialDecryptionCandidate[],
  options: TrialDecryptOptions = {}
): Promise<TrialDecryptNotePayloadResult | null> {
  const envelopeOptions = options.aad === undefined ? {} : { aad: options.aad };
  for (const candidate of candidates) {
    try {
      const payload = await decryptNotePayload(envelopeBytes, candidate.secretKey, envelopeOptions);
      if (options.requireOwnerMatch !== false && candidate.secretKey.ownerNullifierKeyHash !== undefined) {
        const expected = toNonnegativeBigInt(candidate.secretKey.ownerNullifierKeyHash, "ownerNullifierKeyHash");
        if (payload.ownerNullifierKeyHash !== expected) continue;
      }
      return { candidateId: candidate.id, payload };
    } catch (_cause) {
      continue;
    }
  }
  return null;
}

export async function decodePlainOrEncryptedNotePayload(
  outputNoteData: BytesLike,
  candidates: readonly TrialDecryptionCandidate[],
  options: TrialDecryptOptions = {}
): Promise<TrialDecryptNotePayloadResult | null> {
  try {
    const payload = decodeNotePayload(outputNoteData);
    return { candidateId: "plaintext", payload };
  } catch {
    return trialDecryptNotePayload(outputNoteData, candidates, options);
  }
}

export function decryptionFailureLabel(error: unknown): string {
  if (error instanceof Error) return `${error.name}: ${error.message}`;
  return `unknown decryption failure: ${bytesToHex(new TextEncoder().encode(String(error)))}`;
}

export type { EnvelopeDecryptionError };
