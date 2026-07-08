import { describe, expect, it } from "vitest";
import { recoverNotes } from "../../app/src/lib/indexer.ts";
import { bytesToHex } from "../src/bytes.ts";
import {
  noteBodyCommitment,
  noteCommitment,
  ownerCommitment,
  ownerNullifierKeyHash,
} from "../src/derivations.ts";
import { encryptOutputNoteData, generateReceiveKeyPair } from "../src/envelope.ts";
import { addressToField } from "../src/field.ts";
import {
  encodeNotePayload,
  NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS,
  NOTE_PAYLOAD_KIND_DEPOSIT,
} from "../src/payload.ts";

const CHAIN_ID = 31337n;
const POOL = "0x8a791620dd6260079bf849dc5567adc3f2fdc318" as const;
const TOKEN = "0x0000000000000000000000000000000000000002" as const;
const ZERO_ADDR = "0x0000000000000000000000000000000000000000" as const;

const poolField = addressToField(POOL, "poolAddress");
const OWNER_NULLIFIER_KEY = 12345n;
const ownerHash = ownerNullifierKeyHash(OWNER_NULLIFIER_KEY);
const NOTE_SECRET = 0x1234abcdn;

function stubClient(depositEvents: unknown[], opts: { head?: bigint; throwLogs?: unknown } = {}) {
  return {
    async getBlockNumber() {
      return opts.head ?? 0n;
    },
    async getContractEvents({ eventName }: { eventName: string }) {
      if (opts.throwLogs) throw opts.throwLogs;
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
    transactionHash: "0xtx",
    logIndex: 0,
  };
}

async function encryptedVariableDeposit(): Promise<{ hex: `0x${string}`; secretKey: Uint8Array }> {
  const kp = generateReceiveKeyPair(new Uint8Array(64).fill(7));
  const payload = encodeNotePayload({
    kind: NOTE_PAYLOAD_KIND_DEPOSIT,
    flags: NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS,
    chainId: CHAIN_ID,
    poolAddress: POOL,
    tokenAddress: ZERO_ADDR,
    amount: 0n,
    ownerNullifierKeyHash: ownerHash,
    noteSecret: NOTE_SECRET,
    noteBodyCommitment: 0n,
    outputIndex: 0,
  });
  const env = await encryptOutputNoteData(kp.publicKey, payload);
  return { hex: bytesToHex(env), secretKey: kp.secretKey };
}

describe("app recoverNotes", () => {
  it("recovers variable-output deposits from event amount/token", async () => {
    const leafIndex = 8n;
    const eventAmount = 380n;
    const eventTokenField = addressToField(TOKEN, "tokenAddress");
    const oc = ownerCommitment(CHAIN_ID, poolField, ownerHash, NOTE_SECRET);
    const nbc = noteBodyCommitment(oc, eventAmount, eventTokenField);
    const nc = noteCommitment(CHAIN_ID, poolField, nbc, leafIndex);
    const { hex, secretKey } = await encryptedVariableDeposit();

    const notes = await recoverNotes({
      pub: stubClient([
        depositEvent({ leafIndex, noteCommitment: nc, amount: eventAmount, tokenField: eventTokenField, outputNoteData: hex }),
      ]),
      pools: [{ address: POOL, label: "Pool", chainId: CHAIN_ID }],
      secretKey,
      ownerNullifierKey: OWNER_NULLIFIER_KEY,
    });

    expect(notes).toHaveLength(1);
    expect(notes[0]!.amount).toBe(eventAmount);
    expect(notes[0]!.tokenAddress).toBe(eventTokenField);
    expect(notes[0]!.noteCommitment).toBe(nc);
  });

  it("rejects variable-output deposits whose event commitment does not match", async () => {
    const leafIndex = 9n;
    const eventTokenField = addressToField(TOKEN, "tokenAddress");
    const oc = ownerCommitment(CHAIN_ID, poolField, ownerHash, NOTE_SECRET);
    const forgedBody = noteBodyCommitment(oc, 999n, eventTokenField);
    const forgedCommitment = noteCommitment(CHAIN_ID, poolField, forgedBody, leafIndex);
    const { hex, secretKey } = await encryptedVariableDeposit();

    const notes = await recoverNotes({
      pub: stubClient([
        depositEvent({ leafIndex, noteCommitment: forgedCommitment, amount: 380n, tokenField: eventTokenField, outputNoteData: hex }),
      ]),
      pools: [{ address: POOL, label: "Pool", chainId: CHAIN_ID }],
      secretKey,
      ownerNullifierKey: OWNER_NULLIFIER_KEY,
    });

    expect(notes).toHaveLength(0);
  });

  it("treats a lagging RPC head-at-start-block getLogs error as no logs yet", async () => {
    const startBlock = 0xab4799n;
    const notes = await recoverNotes({
      pub: stubClient([], {
        head: startBlock,
        throwLogs: {
          shortMessage: "Invalid parameters were provided to the RPC method.",
          details: "block range extends beyond current head block",
        },
      }),
      pools: [{ address: POOL, label: "Pool", chainId: CHAIN_ID, startBlock }],
      secretKey: new Uint8Array(32),
      ownerNullifierKey: OWNER_NULLIFIER_KEY,
    });

    expect(notes).toHaveLength(0);
  });
});
