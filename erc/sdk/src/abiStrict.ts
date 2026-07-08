// Strict Solidity-ABI decoder for the two static tuple shapes this ERC needs:
// the encrypted-envelope tuple (spec §11) and the note-payload tuple (spec §12).
//
// Encoding may use viem's encodeAbiParameters (it emits canonical form). Decoding
// MUST be this hand-rolled strict walker, which rejects every non-canonical
// encoding: dynamic head offsets that are not at the exact sequential tail
// position, out-of-bounds lengths, nonzero tail padding, nonzero static-field
// padding (address high bytes, bytesN low bytes), and trailing bytes after the
// last tail. Any violation throws a descriptive Error.

// Each top-level ABI parameter is encoded as a "tuple" of top-level params here,
// matching abi.encode(a, b, c, ...) — NOT wrapped in an outer dynamic tuple.

const WORD = 32;

type StaticField =
  | { readonly name: string; readonly kind: "uint256" }
  | { readonly name: string; readonly kind: "bytes32" }
  | { readonly name: string; readonly kind: "bytesN"; readonly width: number }
  | { readonly name: string; readonly kind: "address" };

type DynamicField = { readonly name: string; readonly kind: "bytes" };

type Field = StaticField | DynamicField;

export type DecodedValue = bigint | Uint8Array;

function ceilWord(n: number): number {
  return Math.ceil(n / WORD) * WORD;
}

function readUint(bytes: Uint8Array, offset: number): bigint {
  let value = 0n;
  for (let i = 0; i < WORD; i += 1) {
    value = (value << 8n) | BigInt(bytes[offset + i]);
  }
  return value;
}

function assertZeroRange(bytes: Uint8Array, start: number, end: number, message: string): void {
  for (let i = start; i < end; i += 1) {
    if (bytes[i] !== 0) throw new Error(message);
  }
}

/**
 * Decode `bytes` against a static schema of top-level ABI params with FULL
 * strictness. Returns decoded values positionally: bigint for uint256/address,
 * Uint8Array for bytes32/bytesN/bytes. Throws on any non-canonical encoding.
 */
export function decodeStrictTuple(bytes: Uint8Array, schema: readonly Field[]): DecodedValue[] {
  const headSize = schema.length * WORD;
  if (bytes.length < headSize) {
    throw new Error(`strict-abi: buffer length ${bytes.length} shorter than head ${headSize}`);
  }

  const values = new Array<DecodedValue>(schema.length);
  // Expected position of the next dynamic tail. Tails are packed sequentially
  // starting immediately after the head, with no gaps or overlaps.
  let expectedTail = headSize;

  for (let i = 0; i < schema.length; i += 1) {
    const field = schema[i];
    const head = i * WORD;

    if (field.kind === "bytes") {
      const declaredOffset = readUint(bytes, head);
      if (declaredOffset !== BigInt(expectedTail)) {
        throw new Error(
          `strict-abi: field "${field.name}" non-canonical offset ${declaredOffset} (expected ${expectedTail})`,
        );
      }
      const tail = expectedTail;
      if (tail + WORD > bytes.length) {
        throw new Error(`strict-abi: field "${field.name}" length word out of bounds`);
      }
      const lengthBig = readUint(bytes, tail);
      if (lengthBig > BigInt(bytes.length)) {
        throw new Error(`strict-abi: field "${field.name}" length ${lengthBig} out of bounds`);
      }
      const length = Number(lengthBig);
      const dataStart = tail + WORD;
      const paddedLength = ceilWord(length);
      if (dataStart + paddedLength > bytes.length) {
        throw new Error(`strict-abi: field "${field.name}" data out of bounds`);
      }
      assertZeroRange(
        bytes,
        dataStart + length,
        dataStart + paddedLength,
        `strict-abi: field "${field.name}" nonzero tail padding`,
      );
      values[i] = bytes.slice(dataStart, dataStart + length);
      expectedTail = dataStart + paddedLength;
      continue;
    }

    // Static field: value lives entirely in this head word.
    if (field.kind === "uint256") {
      values[i] = readUint(bytes, head);
    } else if (field.kind === "bytes32") {
      values[i] = bytes.slice(head, head + WORD);
    } else if (field.kind === "bytesN") {
      // bytesN is left-aligned: value in the high `width` bytes, low bytes zero.
      assertZeroRange(
        bytes,
        head + field.width,
        head + WORD,
        `strict-abi: field "${field.name}" nonzero bytes${field.width} padding`,
      );
      values[i] = bytes.slice(head, head + field.width);
    } else {
      // address (uint160): right-aligned, high 12 bytes MUST be zero.
      assertZeroRange(bytes, head, head + (WORD - 20), `strict-abi: field "${field.name}" nonzero address padding`);
      values[i] = readUint(bytes, head);
    }
  }

  if (expectedTail !== bytes.length) {
    throw new Error(`strict-abi: ${bytes.length - expectedTail} trailing byte(s) after last tail`);
  }
  return values;
}

// ---- Envelope tuple (spec §11) ------------------------------------------------
// (uint256 version, bytes32 suiteId, bytes kemCiphertext, bytes12 nonce, bytes ciphertext)

const ENVELOPE_SCHEMA: readonly Field[] = [
  { name: "version", kind: "uint256" },
  { name: "suiteId", kind: "bytes32" },
  { name: "kemCiphertext", kind: "bytes" },
  { name: "nonce", kind: "bytesN", width: 12 },
  { name: "ciphertext", kind: "bytes" },
];

export const ENVELOPE_KEM_CIPHERTEXT_LENGTH = 1088;
export const ENVELOPE_MIN_CIPHERTEXT_LENGTH = 16; // 128-bit AES-GCM tag minimum

export interface EnvelopeTuple {
  version: bigint;
  suiteId: Uint8Array;
  kemCiphertext: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

/** Strict-decode the encrypted envelope tuple and enforce spec §11 field lengths. */
export function decodeEnvelopeTuple(bytes: Uint8Array): EnvelopeTuple {
  const [version, suiteId, kemCiphertext, nonce, ciphertext] = decodeStrictTuple(bytes, ENVELOPE_SCHEMA);
  const kem = kemCiphertext as Uint8Array;
  const ct = ciphertext as Uint8Array;
  if (kem.length !== ENVELOPE_KEM_CIPHERTEXT_LENGTH) {
    throw new Error(`envelope: kemCiphertext length ${kem.length} != ${ENVELOPE_KEM_CIPHERTEXT_LENGTH}`);
  }
  if (ct.length < ENVELOPE_MIN_CIPHERTEXT_LENGTH) {
    throw new Error(`envelope: ciphertext length ${ct.length} < ${ENVELOPE_MIN_CIPHERTEXT_LENGTH}`);
  }
  return {
    version: version as bigint,
    suiteId: suiteId as Uint8Array,
    kemCiphertext: kem,
    nonce: nonce as Uint8Array,
    ciphertext: ct,
  };
}

// ---- Note payload tuple (spec §12) -------------------------------------------
// (uint256 version, uint256 kind, uint256 flags, uint256 chainId,
//  address poolAddress, address tokenAddress, uint256 amount,
//  uint256 ownerNullifierKeyHash, uint256 noteSecret, uint256 noteBodyCommitment,
//  uint256 outputIndex, bytes memo)

const NOTE_PAYLOAD_SCHEMA: readonly Field[] = [
  { name: "version", kind: "uint256" },
  { name: "kind", kind: "uint256" },
  { name: "flags", kind: "uint256" },
  { name: "chainId", kind: "uint256" },
  { name: "poolAddress", kind: "address" },
  { name: "tokenAddress", kind: "address" },
  { name: "amount", kind: "uint256" },
  { name: "ownerNullifierKeyHash", kind: "uint256" },
  { name: "noteSecret", kind: "uint256" },
  { name: "noteBodyCommitment", kind: "uint256" },
  { name: "outputIndex", kind: "uint256" },
  { name: "memo", kind: "bytes" },
];

export interface NotePayloadTuple {
  version: bigint;
  kind: bigint;
  flags: bigint;
  chainId: bigint;
  poolAddress: bigint;
  tokenAddress: bigint;
  amount: bigint;
  ownerNullifierKeyHash: bigint;
  noteSecret: bigint;
  noteBodyCommitment: bigint;
  outputIndex: bigint;
  memo: Uint8Array;
}

/** Strict-decode the note-payload tuple with no field-value rules applied. */
export function decodeNotePayloadTuple(bytes: Uint8Array): NotePayloadTuple {
  const v = decodeStrictTuple(bytes, NOTE_PAYLOAD_SCHEMA);
  return {
    version: v[0] as bigint,
    kind: v[1] as bigint,
    flags: v[2] as bigint,
    chainId: v[3] as bigint,
    poolAddress: v[4] as bigint,
    tokenAddress: v[5] as bigint,
    amount: v[6] as bigint,
    ownerNullifierKeyHash: v[7] as bigint,
    noteSecret: v[8] as bigint,
    noteBodyCommitment: v[9] as bigint,
    outputIndex: v[10] as bigint,
    memo: v[11] as Uint8Array,
  };
}
