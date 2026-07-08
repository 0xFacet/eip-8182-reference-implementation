import { describe, expect, it } from "vitest";
import { encodeAbiParameters } from "viem";
import { hexToBytes } from "../src/bytes.ts";
import { decodeEnvelopeTuple, decodeNotePayloadTuple, decodeStrictTuple } from "../src/abiStrict.ts";
import { SUITE_ID } from "../src/generated/constants.ts";

// ---- helpers -----------------------------------------------------------------

const bytesN = (n: number, fill = 0xab) => new Uint8Array(n).fill(fill);
const toHex = (b: Uint8Array) => `0x${Buffer.from(b).toString("hex")}` as `0x${string}`;

function setWord(buf: Uint8Array, wordIndex: number, value: bigint): Uint8Array {
  const out = new Uint8Array(buf);
  const start = wordIndex * 32;
  for (let i = 31; i >= 0; i -= 1) {
    out[start + i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return out;
}

// A structurally valid envelope tuple encoding (viem canonical form).
function encodeEnvelope(kemLen = 1088, ctLen = 32): Uint8Array {
  return hexToBytes(
    encodeAbiParameters(
      [
        { type: "uint256" },
        { type: "bytes32" },
        { type: "bytes" },
        { type: "bytes12" },
        { type: "bytes" },
      ],
      [1n, SUITE_ID, toHex(bytesN(kemLen, 0x11)), toHex(bytesN(12, 0x22)), toHex(bytesN(ctLen, 0x33))],
    ),
    "env",
  );
}

const KEM_OFFSET_WORD = 2;
const NONCE_WORD = 3;
const CT_OFFSET_WORD = 4;
const CANONICAL_KEM_OFFSET = 160n;
const CANONICAL_CT_OFFSET = 160n + 32n + 1088n; // 1280

describe("decodeStrictTuple round-trips", () => {
  it("decodes the canonical envelope encoding", () => {
    const env = decodeEnvelopeTuple(encodeEnvelope());
    expect(env.version).toBe(1n);
    expect(env.kemCiphertext.length).toBe(1088);
    expect(env.nonce.length).toBe(12);
    expect(env.ciphertext.length).toBe(32);
  });

  it("decodes a static-only tuple with no dynamic tails", () => {
    const buf = hexToBytes(
      encodeAbiParameters([{ type: "uint256" }, { type: "address" }], [7n, "0x00000000000000000000000000000000000000ff"]),
      "static",
    );
    const [a, b] = decodeStrictTuple(buf, [
      { name: "n", kind: "uint256" },
      { name: "addr", kind: "address" },
    ]);
    expect(a).toBe(7n);
    expect(b).toBe(0xffn);
  });
});

describe("decodeEnvelopeTuple adversarial corpus (must throw)", () => {
  it("rejects a non-canonical first-tail offset", () => {
    const bad = setWord(encodeEnvelope(), KEM_OFFSET_WORD, CANONICAL_KEM_OFFSET + 32n);
    expect(() => decodeEnvelopeTuple(bad)).toThrow(/non-canonical offset/);
  });

  it("rejects overlapping dynamic tails", () => {
    // Point the ciphertext offset back into the kem tail region.
    const bad = setWord(encodeEnvelope(), CT_OFFSET_WORD, CANONICAL_KEM_OFFSET);
    expect(() => decodeEnvelopeTuple(bad)).toThrow(/non-canonical offset/);
  });

  it("rejects trailing bytes after the last tail", () => {
    const valid = encodeEnvelope();
    const bad = new Uint8Array(valid.length + 1);
    bad.set(valid, 0);
    expect(() => decodeEnvelopeTuple(bad)).toThrow(/trailing byte/);
  });

  it("rejects a truncated buffer", () => {
    const valid = encodeEnvelope();
    expect(() => decodeEnvelopeTuple(valid.slice(0, valid.length - 32))).toThrow();
  });

  it("rejects kemCiphertext length 1087 and 1089", () => {
    expect(() => decodeEnvelopeTuple(encodeEnvelope(1087))).toThrow(/kemCiphertext length/);
    expect(() => decodeEnvelopeTuple(encodeEnvelope(1089))).toThrow(/kemCiphertext length/);
  });

  it("rejects ciphertext length 15 (below AES-GCM tag)", () => {
    // ct offset shifts because kem stays 1088; recompute not needed, encodeEnvelope handles it.
    expect(() => decodeEnvelopeTuple(encodeEnvelope(1088, 15))).toThrow(/ciphertext length/);
  });

  it("rejects nonzero bytes12 nonce padding", () => {
    const valid = encodeEnvelope();
    const bad = new Uint8Array(valid);
    bad[NONCE_WORD * 32 + 20] = 0x99; // a byte inside the 20-byte zero pad region
    expect(() => decodeEnvelopeTuple(bad)).toThrow(/nonce.*padding/);
  });

  it("rejects an out-of-bounds tail length", () => {
    const bad = setWord(encodeEnvelope(), KEM_OFFSET_WORD, CANONICAL_KEM_OFFSET); // keep canonical
    // Corrupt the kem length word to a huge value.
    const kemLenWord = Number(CANONICAL_KEM_OFFSET) / 32;
    const worse = setWord(bad, kemLenWord, 1n << 200n);
    expect(() => decodeEnvelopeTuple(worse)).toThrow(/out of bounds/);
  });

  it("keeps canonical ciphertext offset validated", () => {
    // Sanity: the canonical ct offset really is 1280 for the valid encoding.
    const valid = encodeEnvelope();
    let read = 0n;
    for (let i = 0; i < 32; i += 1) read = (read << 8n) | BigInt(valid[CT_OFFSET_WORD * 32 + i]);
    expect(read).toBe(CANONICAL_CT_OFFSET);
  });
});

describe("decodeNotePayloadTuple adversarial corpus (must throw)", () => {
  const PAYLOAD_ABI = [
    { type: "uint256" }, // version
    { type: "uint256" }, // kind
    { type: "uint256" }, // flags
    { type: "uint256" }, // chainId
    { type: "address" }, // poolAddress
    { type: "address" }, // tokenAddress
    { type: "uint256" }, // amount
    { type: "uint256" }, // ownerNullifierKeyHash
    { type: "uint256" }, // noteSecret
    { type: "uint256" }, // noteBodyCommitment
    { type: "uint256" }, // outputIndex
    { type: "bytes" }, // memo
  ] as const;

  function encodePayload(memoLen = 4): Uint8Array {
    return hexToBytes(
      encodeAbiParameters(PAYLOAD_ABI, [
        1n,
        1n,
        0n,
        1n,
        "0x0000000000000000000000000000000000000001",
        "0x0000000000000000000000000000000000000002",
        5n,
        6n,
        7n,
        8n,
        2n,
        toHex(bytesN(memoLen, 0x44)),
      ]),
      "payload",
    );
  }

  it("decodes a canonical payload tuple", () => {
    const t = decodeNotePayloadTuple(encodePayload());
    expect(t.poolAddress).toBe(1n);
    expect(t.flags).toBe(0n);
    expect(t.memo.length).toBe(4);
  });

  it("rejects a non-canonical memo offset (overlap)", () => {
    // memo is the only dynamic field at head word index 11; expected offset = 12*32 = 384.
    const bad = setWord(encodePayload(), 11, 352n);
    expect(() => decodeNotePayloadTuple(bad)).toThrow(/non-canonical offset/);
  });

  it("rejects nonzero address high-byte padding", () => {
    const valid = encodePayload();
    const bad = new Uint8Array(valid);
    bad[4 * 32] = 0x01; // top byte of poolAddress word
    expect(() => decodeNotePayloadTuple(bad)).toThrow(/address padding/);
  });

  it("rejects trailing bytes", () => {
    const valid = encodePayload();
    const bad = new Uint8Array(valid.length + 1);
    bad.set(valid);
    expect(() => decodeNotePayloadTuple(bad)).toThrow(/trailing byte/);
  });
});
