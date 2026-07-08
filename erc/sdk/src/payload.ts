// Note payload (spec §12). The encrypted plaintext for the default envelope is
// the strict-ABI encoding of the note-payload tuple. Encoding uses viem's
// canonical encoder; decoding uses the strict walker in abiStrict.ts and then
// enforces every §12 field rule.

import { encodeAbiParameters } from "viem";
import { decodeNotePayloadTuple } from "./abiStrict.ts";
import { type BytesLike, bytesToHex, hexToBytes, toBytes } from "./bytes.ts";
import { BN254_SCALAR_MODULUS, type HexAddress, fieldToAddress } from "./field.ts";
import { NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS } from "./generated/constants.ts";

export const NOTE_PAYLOAD_VERSION = 1n;
export const NOTE_PAYLOAD_KIND_DEPOSIT = 0n;
export const NOTE_PAYLOAD_KIND_TRANSACT = 1n;
export const NOTE_PAYLOAD_AMOUNT_BOUND = 1n << 248n;
export { NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS };
/** Only bit 0 (DEPOSIT_USES_EVENT_PUBLICS) is defined for the reference profile. */
const NOTE_PAYLOAD_KNOWN_FLAGS = NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS;

export interface NotePayload {
  version: bigint;
  kind: bigint;
  flags: bigint;
  chainId: bigint;
  poolAddress: HexAddress;
  tokenAddress: HexAddress;
  amount: bigint;
  ownerNullifierKeyHash: bigint;
  noteSecret: bigint;
  noteBodyCommitment: bigint;
  outputIndex: bigint;
  memo: Uint8Array;
}

export interface NotePayloadInput {
  version?: bigint | number;
  kind: bigint | number;
  /** Variable-output flags (spec §12); default 0. Bit 0 = DEPOSIT_USES_EVENT_PUBLICS. */
  flags?: bigint | number;
  chainId: bigint | number;
  poolAddress: HexAddress;
  tokenAddress: HexAddress;
  amount: bigint | number;
  ownerNullifierKeyHash: bigint;
  noteSecret: bigint;
  noteBodyCommitment: bigint;
  outputIndex: bigint | number;
  memo?: BytesLike;
}

const NOTE_PAYLOAD_ABI = [
  { name: "version", type: "uint256" },
  { name: "kind", type: "uint256" },
  { name: "flags", type: "uint256" },
  { name: "chainId", type: "uint256" },
  { name: "poolAddress", type: "address" },
  { name: "tokenAddress", type: "address" },
  { name: "amount", type: "uint256" },
  { name: "ownerNullifierKeyHash", type: "uint256" },
  { name: "noteSecret", type: "uint256" },
  { name: "noteBodyCommitment", type: "uint256" },
  { name: "outputIndex", type: "uint256" },
  { name: "memo", type: "bytes" },
] as const;

function validateFields(p: {
  version: bigint;
  kind: bigint;
  flags: bigint;
  tokenAddress: bigint;
  amount: bigint;
  ownerNullifierKeyHash: bigint;
  noteSecret: bigint;
  noteBodyCommitment: bigint;
  outputIndex: bigint;
}): void {
  if (p.version !== NOTE_PAYLOAD_VERSION) {
    throw new Error(`note payload: version ${p.version} != ${NOTE_PAYLOAD_VERSION}`);
  }
  if (p.kind !== NOTE_PAYLOAD_KIND_DEPOSIT && p.kind !== NOTE_PAYLOAD_KIND_TRANSACT) {
    throw new Error(`note payload: kind ${p.kind} must be 0 (deposit) or 1 (transact)`);
  }
  if ((p.flags & ~NOTE_PAYLOAD_KNOWN_FLAGS) !== 0n) {
    throw new Error(`note payload: unknown flags bits set (0x${p.flags.toString(16)})`);
  }
  const usesEventPublics = (p.flags & NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS) !== 0n;
  if (usesEventPublics) {
    // Variable-output deposit: the token/amount/noteBodyCommitment come from the
    // ShieldedPoolDeposit event, so the payload MUST zero them (spec §12).
    if (p.kind !== NOTE_PAYLOAD_KIND_DEPOSIT) {
      throw new Error(`note payload: DEPOSIT_USES_EVENT_PUBLICS is only valid for deposit (kind 0)`);
    }
    if (p.tokenAddress !== 0n || p.amount !== 0n || p.noteBodyCommitment !== 0n) {
      throw new Error(`note payload: DEPOSIT_USES_EVENT_PUBLICS requires zero tokenAddress + amount + noteBodyCommitment (sentinels)`);
    }
  }
  if (p.amount >= NOTE_PAYLOAD_AMOUNT_BOUND) {
    throw new Error(`note payload: amount must be < 2^248`);
  }
  for (const [name, value] of [
    ["ownerNullifierKeyHash", p.ownerNullifierKeyHash],
    ["noteSecret", p.noteSecret],
    ["noteBodyCommitment", p.noteBodyCommitment],
  ] as const) {
    if (value >= BN254_SCALAR_MODULUS) throw new Error(`note payload: ${name} must be a BN254 field element (< p)`);
  }
  if (p.kind === NOTE_PAYLOAD_KIND_DEPOSIT) {
    if (p.outputIndex !== 0n) throw new Error(`note payload: deposit outputIndex must be 0`);
  } else if (p.outputIndex > 2n) {
    throw new Error(`note payload: transact outputIndex must be 0, 1, or 2`);
  }
}

/** Strict-ABI encode a note payload, validating all §12 field rules first. */
export function encodeNotePayload(input: NotePayloadInput): Uint8Array {
  const version = BigInt(input.version ?? NOTE_PAYLOAD_VERSION);
  const kind = BigInt(input.kind);
  const flags = BigInt(input.flags ?? 0n);
  const amount = BigInt(input.amount);
  const outputIndex = BigInt(input.outputIndex);
  validateFields({
    version,
    kind,
    flags,
    tokenAddress: BigInt(input.tokenAddress),
    amount,
    ownerNullifierKeyHash: input.ownerNullifierKeyHash,
    noteSecret: input.noteSecret,
    noteBodyCommitment: input.noteBodyCommitment,
    outputIndex,
  });
  const memo = input.memo === undefined ? new Uint8Array(0) : toBytes(input.memo, "memo");
  const encoded = encodeAbiParameters(NOTE_PAYLOAD_ABI, [
    version,
    kind,
    flags,
    BigInt(input.chainId),
    input.poolAddress,
    input.tokenAddress,
    amount,
    input.ownerNullifierKeyHash,
    input.noteSecret,
    input.noteBodyCommitment,
    outputIndex,
    bytesToHex(memo),
  ]);
  return hexToBytes(encoded, "encoded note payload");
}

/** Strict-decode a note payload and enforce every §12 field rule. */
export function decodeNotePayload(bytes: Uint8Array): NotePayload {
  const t = decodeNotePayloadTuple(bytes);
  validateFields({
    version: t.version,
    kind: t.kind,
    flags: t.flags,
    tokenAddress: BigInt(t.tokenAddress),
    amount: t.amount,
    ownerNullifierKeyHash: t.ownerNullifierKeyHash,
    noteSecret: t.noteSecret,
    noteBodyCommitment: t.noteBodyCommitment,
    outputIndex: t.outputIndex,
  });
  return {
    version: t.version,
    kind: t.kind,
    flags: t.flags,
    chainId: t.chainId,
    poolAddress: fieldToAddress(t.poolAddress, "poolAddress"),
    tokenAddress: fieldToAddress(t.tokenAddress, "tokenAddress"),
    amount: t.amount,
    ownerNullifierKeyHash: t.ownerNullifierKeyHash,
    noteSecret: t.noteSecret,
    noteBodyCommitment: t.noteBodyCommitment,
    outputIndex: t.outputIndex,
    memo: t.memo,
  };
}
