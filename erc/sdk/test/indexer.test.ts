import { describe, expect, it } from "vitest";
import { recoverNotes } from "../src/indexer.ts";
import {
  encodeNotePayload,
  NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS,
  NOTE_PAYLOAD_KIND_DEPOSIT,
} from "../src/payload.ts";
import { encryptOutputNoteData, generateReceiveKeyPair } from "../src/envelope.ts";
import { bytesToHex } from "../src/bytes.ts";
import { addressToField } from "../src/field.ts";
import {
  noteBodyCommitment,
  noteCommitment,
  ownerCommitment,
  ownerNullifierKeyHash,
} from "../src/derivations.ts";

// §13 note recovery, including the variable-output (DEPOSIT_USES_EVENT_PUBLICS)
// deposit path where the payload carries zero sentinels and the real token/amount
// come from the emitted ShieldedPoolDeposit event.

const CHAIN_ID = 31337n;
const POOL = "0x8a791620dd6260079bf849dc5567adc3f2fdc318" as const;
const TOKEN = "0x0000000000000000000000000000000000000002" as const;
const ZERO_ADDR = "0x0000000000000000000000000000000000000000" as const;

const poolField = addressToField(POOL, "poolAddress");
const OWNER_NULLIFIER_KEY = 12345n;
const ownerHash = ownerNullifierKeyHash(OWNER_NULLIFIER_KEY);
const NOTE_SECRET = 0x1234abcdn;

// A viem PublicClient stub whose getContractEvents returns the injected deposit
// events for ShieldedPoolDeposit and nothing for ShieldedPoolTransact.
function stubClient(depositEvents: unknown[]) {
  return {
    async getContractEvents({ eventName }: { eventName: string }) {
      return eventName === "ShieldedPoolDeposit" ? depositEvents : [];
    },
  } as never;
}

function depositEvent(args: {
  leafIndex: bigint;
  noteCommitment: bigint;
  amount: bigint;
  tokenField: bigint;
  outputNoteData: `0x${string}`;
  logIndex: number;
}) {
  return {
    args: {
      leafIndex: args.leafIndex,
      noteCommitment: args.noteCommitment,
      amount: args.amount,
      tokenAddress: args.tokenField,
      outputNoteData: args.outputNoteData,
    },
    blockHash: "0xblock",
    transactionHash: `0xtx${args.logIndex}`,
    logIndex: args.logIndex,
  };
}

async function encryptedPayload(overrides: {
  flags?: bigint;
  tokenAddress: `0x${string}`;
  amount: bigint;
  noteBodyCommitment: bigint;
}): Promise<{ hex: `0x${string}`; secretKey: Uint8Array }> {
  const kp = generateReceiveKeyPair(new Uint8Array(64).fill(7));
  const payload = encodeNotePayload({
    kind: NOTE_PAYLOAD_KIND_DEPOSIT,
    flags: overrides.flags ?? 0n,
    chainId: CHAIN_ID,
    poolAddress: POOL,
    tokenAddress: overrides.tokenAddress,
    amount: overrides.amount,
    ownerNullifierKeyHash: ownerHash,
    noteSecret: NOTE_SECRET,
    noteBodyCommitment: overrides.noteBodyCommitment,
    outputIndex: 0,
  });
  const env = await encryptOutputNoteData(kp.publicKey, payload);
  return { hex: bytesToHex(env), secretKey: kp.secretKey };
}

describe("recoverNotes", () => {
  it("recovers a plain (flag-unset) deposit and reports payload amount/token", async () => {
    const leafIndex = 0n;
    const amount = 1000n;
    const tokenField = addressToField(TOKEN, "tokenAddress");
    const oc = ownerCommitment(CHAIN_ID, poolField, ownerHash, NOTE_SECRET);
    const nbc = noteBodyCommitment(oc, amount, tokenField);
    const nc = noteCommitment(CHAIN_ID, poolField, nbc, leafIndex);

    const { hex, secretKey } = await encryptedPayload({ tokenAddress: TOKEN, amount, noteBodyCommitment: nbc });
    const notes = await recoverNotes({
      publicClient: stubClient([depositEvent({ leafIndex, noteCommitment: nc, amount, tokenField, outputNoteData: hex, logIndex: 0 })]),
      pools: [{ address: POOL, chainId: CHAIN_ID }],
      secretKey,
      ownerNullifierKey: OWNER_NULLIFIER_KEY,
    });

    expect(notes).toHaveLength(1);
    expect(notes[0]!.amount).toBe(amount);
    expect(notes[0]!.tokenAddress).toBe(tokenField);
    expect(notes[0]!.noteCommitment).toBe(nc);
  });

  it("recovers a variable-output deposit using event-authoritative amount/token, not the zero sentinels", async () => {
    // Payload was encrypted before the swap: sentinels only. The real values are
    // whatever the router's reshield deposit emitted on-chain.
    const leafIndex = 8n;
    const eventAmount = 380n; // e.g. a swap output unknown at encryption time
    const eventTokenField = addressToField(TOKEN, "tokenAddress");
    const oc = ownerCommitment(CHAIN_ID, poolField, ownerHash, NOTE_SECRET);
    const nbc = noteBodyCommitment(oc, eventAmount, eventTokenField);
    const nc = noteCommitment(CHAIN_ID, poolField, nbc, leafIndex);

    const { hex, secretKey } = await encryptedPayload({
      flags: NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS,
      tokenAddress: ZERO_ADDR, // sentinel
      amount: 0n, // sentinel
      noteBodyCommitment: 0n, // sentinel
    });
    const notes = await recoverNotes({
      publicClient: stubClient([
        depositEvent({ leafIndex, noteCommitment: nc, amount: eventAmount, tokenField: eventTokenField, outputNoteData: hex, logIndex: 0 }),
      ]),
      pools: [{ address: POOL, chainId: CHAIN_ID }],
      secretKey,
      ownerNullifierKey: OWNER_NULLIFIER_KEY,
    });

    expect(notes).toHaveLength(1);
    expect(notes[0]!.amount).toBe(eventAmount); // NOT the 0 sentinel
    expect(notes[0]!.tokenAddress).toBe(eventTokenField);
    expect(notes[0]!.noteCommitment).toBe(nc);
  });

  it("rejects a variable-output deposit whose event commitment does not match", async () => {
    // Same sentinel payload, but the event commitment is for a different amount:
    // recovery must not accept it (final-commitment check still binds).
    const leafIndex = 9n;
    const oc = ownerCommitment(CHAIN_ID, poolField, ownerHash, NOTE_SECRET);
    const nbcForged = noteBodyCommitment(oc, 999n, addressToField(TOKEN, "tokenAddress"));
    const ncForged = noteCommitment(CHAIN_ID, poolField, nbcForged, leafIndex);

    const { hex, secretKey } = await encryptedPayload({
      flags: NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS,
      tokenAddress: ZERO_ADDR,
      amount: 0n,
      noteBodyCommitment: 0n,
    });
    // Event claims amount 380 but the emitted commitment is for amount 999.
    const notes = await recoverNotes({
      publicClient: stubClient([
        depositEvent({ leafIndex, noteCommitment: ncForged, amount: 380n, tokenField: addressToField(TOKEN, "tokenAddress"), outputNoteData: hex, logIndex: 0 }),
      ]),
      pools: [{ address: POOL, chainId: CHAIN_ID }],
      secretKey,
      ownerNullifierKey: OWNER_NULLIFIER_KEY,
    });

    expect(notes).toHaveLength(0);
  });
});
