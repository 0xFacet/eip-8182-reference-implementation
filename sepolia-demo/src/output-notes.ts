import {
  encryptNotePayload,
  type EnvelopeOptions,
  type RecipientEncryptionPublicKey
} from "./envelope.js";
import { type BytesLike } from "./bytes.js";
import { outputNoteDataHash, type NotePayload } from "./payload.js";

export interface PreparedOutputNoteData {
  outputNoteData: Uint8Array;
  outputNoteDataHash: bigint;
}

export interface EncryptedOutputRequest {
  payload: NotePayload;
  recipient: RecipientEncryptionPublicKey;
  envelope?: EnvelopeOptions;
}

export type TransactOutputRequest = EncryptedOutputRequest | { dummy: true; outputNoteData?: BytesLike };

export async function prepareEncryptedOutputNoteData(
  request: EncryptedOutputRequest
): Promise<PreparedOutputNoteData> {
  const outputNoteData = await encryptNotePayload(
    request.payload,
    request.recipient,
    request.envelope ?? {}
  );
  return {
    outputNoteData,
    outputNoteDataHash: outputNoteDataHash(outputNoteData)
  };
}

export async function prepareTransactOutputNoteData(
  outputs: readonly [TransactOutputRequest, TransactOutputRequest, TransactOutputRequest]
): Promise<readonly [PreparedOutputNoteData, PreparedOutputNoteData, PreparedOutputNoteData]> {
  return [
    await prepareOutput(outputs[0]),
    await prepareOutput(outputs[1]),
    await prepareOutput(outputs[2])
  ];
}

async function prepareOutput(output: TransactOutputRequest): Promise<PreparedOutputNoteData> {
  if ("dummy" in output) {
    const outputNoteData = output.outputNoteData === undefined
      ? new Uint8Array()
      : toUint8Array(output.outputNoteData);
    return {
      outputNoteData,
      outputNoteDataHash: outputNoteDataHash(outputNoteData)
    };
  }
  return prepareEncryptedOutputNoteData(output);
}

function toUint8Array(value: BytesLike): Uint8Array {
  if (value instanceof Uint8Array) return new Uint8Array(value);
  if (typeof value === "string") {
    const normalized = value.startsWith("0x") || value.startsWith("0X") ? value.slice(2) : value;
    if (normalized.length % 2 !== 0 || /[^0-9a-fA-F]/.test(normalized)) {
      throw new Error("dummy outputNoteData string must be hex bytes");
    }
    const out = new Uint8Array(normalized.length / 2);
    for (let i = 0; i < out.length; i += 1) {
      out[i] = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  }
  if (Array.isArray(value)) return Uint8Array.from(value);
  throw new TypeError("dummy outputNoteData must be bytes or a hex string");
}
