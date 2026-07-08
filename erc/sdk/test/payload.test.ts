import { describe, expect, it } from "vitest";
import { encodeAbiParameters } from "viem";
import { hexToBytes } from "../src/bytes.ts";
import { BN254_SCALAR_MODULUS } from "../src/field.ts";
import {
  decodeNotePayload,
  encodeNotePayload,
  NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS,
} from "../src/payload.ts";

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

const P = "0x1111111111111111111111111111111111111111" as const;
const T = "0x0000000000000000000000000000000000000002" as const;

// Encode raw (bypassing encodeNotePayload validation) to build adversarial inputs.
function rawEncode(overrides: Partial<Record<string, bigint>>, memoLen = 0): Uint8Array {
  const f = {
    version: 1n,
    kind: 1n,
    flags: 0n,
    chainId: 1n,
    amount: 5n,
    onk: 6n,
    noteSecret: 7n,
    noteBodyCommitment: 8n,
    outputIndex: 2n,
    ...overrides,
  };
  const memo = `0x${"22".repeat(memoLen)}` as `0x${string}`;
  return hexToBytes(
    encodeAbiParameters(PAYLOAD_ABI, [
      f.version,
      f.kind,
      f.flags,
      f.chainId,
      P,
      T,
      f.amount,
      f.onk,
      f.noteSecret,
      f.noteBodyCommitment,
      f.outputIndex,
      memo,
    ]),
    "raw",
  );
}

describe("note payload round-trip", () => {
  it("encodes and decodes a transact payload with a memo", () => {
    const bytes = encodeNotePayload({
      kind: 1,
      chainId: 11155111,
      poolAddress: P,
      tokenAddress: T,
      amount: (1n << 248n) - 1n,
      ownerNullifierKeyHash: BN254_SCALAR_MODULUS - 1n,
      noteSecret: 123n,
      noteBodyCommitment: 456n,
      outputIndex: 2,
      memo: new TextEncoder().encode("hello"),
    });
    const p = decodeNotePayload(bytes);
    expect(p.kind).toBe(1n);
    expect(p.flags).toBe(0n);
    expect(p.amount).toBe((1n << 248n) - 1n);
    expect(p.ownerNullifierKeyHash).toBe(BN254_SCALAR_MODULUS - 1n);
    expect(p.poolAddress).toBe(P);
    expect(p.tokenAddress).toBe(T);
    expect(new TextDecoder().decode(p.memo)).toBe("hello");
  });

  it("encodes and decodes a deposit payload with empty memo", () => {
    const bytes = encodeNotePayload({
      kind: 0,
      chainId: 1,
      poolAddress: P,
      tokenAddress: T,
      amount: 1000n,
      ownerNullifierKeyHash: 1n,
      noteSecret: 2n,
      noteBodyCommitment: 3n,
      outputIndex: 0,
    });
    const p = decodeNotePayload(bytes);
    expect(p.kind).toBe(0n);
    expect(p.flags).toBe(0n);
    expect(p.outputIndex).toBe(0n);
    expect(p.memo.length).toBe(0);
  });

  it("encodes and decodes a variable-output deposit (DEPOSIT_USES_EVENT_PUBLICS)", () => {
    // Variable-output deposit: tokenAddress, amount, noteBodyCommitment are zero
    // sentinels (spec §12); the real values come from the emitted event.
    const bytes = encodeNotePayload({
      kind: 0,
      flags: NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS,
      chainId: 1,
      poolAddress: P,
      tokenAddress: "0x0000000000000000000000000000000000000000",
      amount: 0n,
      ownerNullifierKeyHash: 1n,
      noteSecret: 2n,
      noteBodyCommitment: 0n,
      outputIndex: 0,
    });
    const p = decodeNotePayload(bytes);
    expect(p.flags).toBe(NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS);
    expect(p.tokenAddress).toBe("0x0000000000000000000000000000000000000000");
    expect(p.amount).toBe(0n);
    expect(p.noteBodyCommitment).toBe(0n);
  });
});

describe("encodeNotePayload rejects invalid inputs", () => {
  const base = {
    chainId: 1,
    poolAddress: P,
    tokenAddress: T,
    amount: 5n,
    ownerNullifierKeyHash: 1n,
    noteSecret: 2n,
    noteBodyCommitment: 3n,
  };
  it("deposit with nonzero outputIndex", () => {
    expect(() => encodeNotePayload({ ...base, kind: 0, outputIndex: 1 })).toThrow(/deposit outputIndex/);
  });
  it("transact with outputIndex 3", () => {
    expect(() => encodeNotePayload({ ...base, kind: 1, outputIndex: 3 })).toThrow(/outputIndex/);
  });
  it("amount >= 2^248", () => {
    expect(() => encodeNotePayload({ ...base, kind: 1, outputIndex: 0, amount: 1n << 248n })).toThrow(/2\^248/);
  });
  it("DEPOSIT_USES_EVENT_PUBLICS on a transact payload", () => {
    expect(() =>
      encodeNotePayload({ ...base, kind: 1, outputIndex: 0, flags: NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS, amount: 0n, noteBodyCommitment: 0n }),
    ).toThrow(/only valid for deposit/);
  });
  it("DEPOSIT_USES_EVENT_PUBLICS with nonzero amount", () => {
    expect(() =>
      encodeNotePayload({ ...base, kind: 0, outputIndex: 0, flags: NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS, tokenAddress: "0x0000000000000000000000000000000000000000", amount: 5n, noteBodyCommitment: 0n }),
    ).toThrow(/sentinel/);
  });
  it("DEPOSIT_USES_EVENT_PUBLICS with nonzero tokenAddress", () => {
    expect(() =>
      encodeNotePayload({ ...base, kind: 0, outputIndex: 0, flags: NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS, tokenAddress: T, amount: 0n, noteBodyCommitment: 0n }),
    ).toThrow(/sentinel/);
  });
  it("DEPOSIT_USES_EVENT_PUBLICS with nonzero noteBodyCommitment", () => {
    expect(() =>
      encodeNotePayload({ ...base, kind: 0, outputIndex: 0, flags: NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS, tokenAddress: "0x0000000000000000000000000000000000000000", amount: 0n, noteBodyCommitment: 3n }),
    ).toThrow(/sentinel/);
  });
  it("unknown flag bit", () => {
    expect(() => encodeNotePayload({ ...base, kind: 0, outputIndex: 0, flags: 2n })).toThrow(/unknown flags/);
  });
});

describe("decodeNotePayload adversarial corpus (must throw)", () => {
  it("kind 3", () => {
    expect(() => decodeNotePayload(rawEncode({ kind: 3n }))).toThrow(/kind/);
  });

  it("version 2", () => {
    expect(() => decodeNotePayload(rawEncode({ version: 2n }))).toThrow(/version/);
  });

  it("deposit with outputIndex 5", () => {
    expect(() => decodeNotePayload(rawEncode({ kind: 0n, outputIndex: 5n }))).toThrow(/deposit outputIndex/);
  });

  it("transact with outputIndex 3", () => {
    expect(() => decodeNotePayload(rawEncode({ kind: 1n, outputIndex: 3n }))).toThrow(/outputIndex/);
  });

  it("amount >= 2^248", () => {
    expect(() => decodeNotePayload(rawEncode({ amount: 1n << 248n, outputIndex: 0n }))).toThrow(/2\^248/);
  });

  it("ownerNullifierKeyHash >= p", () => {
    expect(() => decodeNotePayload(rawEncode({ onk: BN254_SCALAR_MODULUS, outputIndex: 0n }))).toThrow(/field element/);
  });

  it("noteBodyCommitment >= p", () => {
    expect(() =>
      decodeNotePayload(rawEncode({ noteBodyCommitment: BN254_SCALAR_MODULUS + 5n, outputIndex: 0n })),
    ).toThrow(/field element/);
  });

  it("memo tail overlap (non-canonical offset)", () => {
    const valid = rawEncode({ outputIndex: 0n }, 4);
    const bad = new Uint8Array(valid);
    // memo offset lives in head word 11 (bytes 352..384); canonical value is 384.
    // Rewrite it to 352 to force an overlap with its own offset slot.
    for (let i = 0; i < 32; i += 1) bad[11 * 32 + i] = 0;
    bad[11 * 32 + 31] = 352 & 0xff;
    bad[11 * 32 + 30] = (352 >> 8) & 0xff;
    expect(() => decodeNotePayload(bad)).toThrow(/non-canonical offset/);
  });
});
