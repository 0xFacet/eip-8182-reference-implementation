// Note discovery + recovery (spec §13). Scans ShieldedPoolDeposit and
// ShieldedPoolTransact events for the given pools, trial-decrypts each output
// with a local ML-KEM-768 secret key, and ACCEPTS a note only after recomputing
// owner/body/final commitments against the emitted event commitment.

import type { Address, Hex, PublicClient } from "viem";
import { shieldedPoolAbi } from "./abis.ts";
import { hexToBytes } from "./bytes.ts";
import {
  noteBodyCommitment,
  noteCommitment as noteCommitmentOf,
  ownerCommitment as ownerCommitmentOf,
  ownerNullifierKeyHash as onkHashOf,
} from "./derivations.ts";
import { tryDecryptOutputNoteData } from "./envelope.ts";
import { addressToField } from "./field.ts";
import {
  decodeNotePayload,
  NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS,
  NOTE_PAYLOAD_KIND_DEPOSIT,
} from "./payload.ts";

export interface IndexerPool {
  address: Address;
  chainId: bigint;
}

export interface RecoveredNote {
  id: string; // chainId:poolAddress:leafIndex:outputIndex
  poolAddress: bigint;
  chainId: bigint;
  leafIndex: bigint;
  outputIndex: bigint;
  amount: bigint;
  tokenAddress: bigint;
  ownerNullifierKeyHash: bigint;
  noteSecret: bigint;
  noteBodyCommitment: bigint;
  noteCommitment: bigint;
  /** the source event's dedup key. */
  dedupKey: string;
}

export interface RecoverParams {
  publicClient: PublicClient;
  pools: IndexerPool[];
  /** the viewer's ML-KEM-768 secret key. */
  secretKey: Uint8Array;
  /** the viewer's ownerNullifierKey (its hash must match the note owner hash). */
  ownerNullifierKey: bigint;
}

interface Candidate {
  chainId: bigint;
  poolAddress: bigint;
  leafIndex: bigint;
  outputIndex: bigint;
  eventCommitment: bigint;
  data: Uint8Array;
  dedupKey: string;
  /** §13: expected payload kind — 0 for a ShieldedPoolDeposit output, 1 for transact. */
  kind: bigint;
  /** Event-authoritative asset/value, from ShieldedPoolDeposit (§13 variable-output
   *  recovery). Zero for transact outputs, which never use the variable-output flag. */
  eventAmount: bigint;
  eventTokenField: bigint;
}

/** Scan the pools and return every note the viewer can decrypt AND validate. */
export async function recoverNotes(p: RecoverParams): Promise<RecoveredNote[]> {
  const ownerHash = onkHashOf(p.ownerNullifierKey);
  const candidates: Candidate[] = [];

  for (const pool of p.pools) {
    const poolField = addressToField(pool.address, "poolAddress");
    const deposits = await p.publicClient.getContractEvents({
      address: pool.address,
      abi: shieldedPoolAbi,
      eventName: "ShieldedPoolDeposit",
      fromBlock: 0n,
    });
    for (const e of deposits) {
      const a = e.args as {
        leafIndex: bigint;
        noteCommitment: bigint;
        amount: bigint;
        tokenAddress: bigint;
        outputNoteData: Hex;
      };
      candidates.push({
        chainId: pool.chainId,
        poolAddress: poolField,
        leafIndex: BigInt(a.leafIndex),
        outputIndex: 0n,
        eventCommitment: a.noteCommitment,
        data: hexToBytes(a.outputNoteData),
        dedupKey: `${e.blockHash}:${e.transactionHash}:${e.logIndex}:0`,
        kind: 0n, // NOTE_PAYLOAD_KIND_DEPOSIT
        eventAmount: BigInt(a.amount),
        eventTokenField: BigInt(a.tokenAddress),
      });
    }
    const transacts = await p.publicClient.getContractEvents({
      address: pool.address,
      abi: shieldedPoolAbi,
      eventName: "ShieldedPoolTransact",
      fromBlock: 0n,
    });
    for (const e of transacts) {
      const a = e.args as {
        leafIndex0: bigint;
        noteCommitment0: bigint;
        noteCommitment1: bigint;
        noteCommitment2: bigint;
        outputNoteData0: Hex;
        outputNoteData1: Hex;
        outputNoteData2: Hex;
      };
      const i0 = BigInt(a.leafIndex0);
      const slots: Array<[bigint, bigint, Hex]> = [
        [i0, a.noteCommitment0, a.outputNoteData0],
        [i0 + 1n, a.noteCommitment1, a.outputNoteData1],
        [i0 + 2n, a.noteCommitment2, a.outputNoteData2],
      ];
      slots.forEach(([leafIndex, commitment, data], slot) => {
        candidates.push({
          chainId: pool.chainId,
          poolAddress: poolField,
          leafIndex,
          outputIndex: BigInt(slot),
          eventCommitment: commitment,
          data: hexToBytes(data),
          dedupKey: `${e.blockHash}:${e.transactionHash}:${e.logIndex}:${slot}`,
          kind: 1n, // NOTE_PAYLOAD_KIND_TRANSACT
          eventAmount: 0n, // transact outputs never use the variable-output flag
          eventTokenField: 0n,
        });
      });
    }
  }

  const seen = new Set<string>();
  const recovered: RecoveredNote[] = [];
  for (const c of candidates) {
    if (seen.has(c.dedupKey)) continue;
    seen.add(c.dedupKey);
    if (c.data.length === 0) continue; // dummy slot

    const plaintext = await tryDecryptOutputNoteData(p.secretKey, c.data);
    if (plaintext === null) continue;

    let payload;
    try {
      payload = decodeNotePayload(plaintext);
    } catch {
      continue;
    }

    // §13 acceptance checks.
    if (payload.kind !== c.kind) continue; // deposit output must be kind 0, transact output kind 1
    if (payload.chainId !== c.chainId) continue;
    if (addressToField(payload.poolAddress, "poolAddress") !== c.poolAddress) continue;
    if (payload.outputIndex !== c.outputIndex) continue;
    if (payload.ownerNullifierKeyHash !== ownerHash) continue;

    // §13: a variable-output deposit carries zero sentinels in the payload and
    // takes its real token/amount from the emitted event. decodeNotePayload has
    // already enforced tokenAddress/amount/noteBodyCommitment == 0 for this flag.
    const usesEventPublics =
      payload.kind === NOTE_PAYLOAD_KIND_DEPOSIT &&
      (payload.flags & NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS) !== 0n;

    const amount = usesEventPublics ? c.eventAmount : payload.amount;
    const tokenField = usesEventPublics ? c.eventTokenField : addressToField(payload.tokenAddress, "tokenAddress");
    const oc = ownerCommitmentOf(c.chainId, c.poolAddress, ownerHash, payload.noteSecret);
    const nbc = noteBodyCommitment(oc, amount, tokenField);
    // Non-variable-output notes bind the body commitment in the payload too; the
    // variable-output payload only carries a zero sentinel there, so skip that
    // equality and rely solely on the final-commitment check against the event.
    if (!usesEventPublics && nbc !== payload.noteBodyCommitment) continue;
    const nc = noteCommitmentOf(c.chainId, c.poolAddress, nbc, c.leafIndex);
    if (nc !== c.eventCommitment) continue;

    recovered.push({
      id: `${c.chainId}:${c.poolAddress}:${c.leafIndex}:${c.outputIndex}`,
      poolAddress: c.poolAddress,
      chainId: c.chainId,
      leafIndex: c.leafIndex,
      outputIndex: c.outputIndex,
      amount,
      tokenAddress: tokenField,
      ownerNullifierKeyHash: payload.ownerNullifierKeyHash,
      noteSecret: payload.noteSecret,
      noteBodyCommitment: nbc,
      noteCommitment: nc,
      dedupKey: c.dedupKey,
    });
  }
  return recovered;
}
