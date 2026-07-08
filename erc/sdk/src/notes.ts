// Note construction helpers (spec §8/§12/§15.6). A Note carries every value
// needed to spend it later: the pool-scoped commitments plus the owning
// identity's ownerNullifierKeyHash and the note secret.

import {
  noteBodyCommitment,
  noteCommitment,
  nullifier as nullifierOf,
  ownerCommitment,
  ownerNullifierKeyHash as onkHashOf,
  transactNoteSecret,
} from "./derivations.ts";
import { NOTE_PAYLOAD_KIND_DEPOSIT, NOTE_PAYLOAD_KIND_TRANSACT } from "./payload.ts";

export interface Note {
  chainId: bigint;
  poolAddress: bigint;
  tokenAddress: bigint;
  amount: bigint;
  /** kind: 0 deposit, 1 transact. */
  kind: bigint;
  outputIndex: bigint;
  /** owning identity's ownerNullifierKeyHash. */
  ownerNullifierKeyHash: bigint;
  noteSecret: bigint;
  leafIndex: bigint;
  ownerCommitment: bigint;
  noteBodyCommitment: bigint;
  noteCommitment: bigint;
}

export interface DepositNoteParams {
  chainId: bigint;
  poolAddress: bigint;
  tokenAddress: bigint;
  amount: bigint;
  ownerNullifierKeyHash: bigint;
  noteSecret: bigint;
  /** leaf index assigned by the pool (from the ShieldedPoolDeposit event). */
  leafIndex: bigint;
}

/** Recompute a deposit note's pool-scoped commitments at a known leaf index. */
export function buildDepositNote(p: DepositNoteParams): Note {
  const oc = ownerCommitment(p.chainId, p.poolAddress, p.ownerNullifierKeyHash, p.noteSecret);
  const nbc = noteBodyCommitment(oc, p.amount, p.tokenAddress);
  const nc = noteCommitment(p.chainId, p.poolAddress, nbc, p.leafIndex);
  return {
    chainId: p.chainId,
    poolAddress: p.poolAddress,
    tokenAddress: p.tokenAddress,
    amount: p.amount,
    kind: NOTE_PAYLOAD_KIND_DEPOSIT,
    outputIndex: 0n,
    ownerNullifierKeyHash: p.ownerNullifierKeyHash,
    noteSecret: p.noteSecret,
    leafIndex: p.leafIndex,
    ownerCommitment: oc,
    noteBodyCommitment: nbc,
    noteCommitment: nc,
  };
}

export interface TransactOutputParams {
  chainId: bigint;
  poolAddress: bigint;
  tokenAddress: bigint;
  amount: bigint;
  ownerNullifierKeyHash: bigint;
  /** the SENDER's noteSecretSeed (§8: all output secrets derive from it). */
  noteSecretSeed: bigint;
  intentReplayId: bigint;
  outputIndex: 0 | 1 | 2;
  /** the leaf index the pool assigns to this output slot (leafIndex0 + i). */
  leafIndex: bigint;
}

/** Build a transact output note; noteSecret is the deterministic §8 output secret. */
export function buildTransactOutputNote(p: TransactOutputParams): Note {
  const noteSecret = transactNoteSecret(
    p.noteSecretSeed,
    p.chainId,
    p.poolAddress,
    p.intentReplayId,
    p.outputIndex,
  );
  const oc = ownerCommitment(p.chainId, p.poolAddress, p.ownerNullifierKeyHash, noteSecret);
  const nbc = noteBodyCommitment(oc, p.amount, p.tokenAddress);
  const nc = noteCommitment(p.chainId, p.poolAddress, nbc, p.leafIndex);
  return {
    chainId: p.chainId,
    poolAddress: p.poolAddress,
    tokenAddress: p.tokenAddress,
    amount: p.amount,
    kind: NOTE_PAYLOAD_KIND_TRANSACT,
    outputIndex: BigInt(p.outputIndex),
    ownerNullifierKeyHash: p.ownerNullifierKeyHash,
    noteSecret,
    leafIndex: p.leafIndex,
    ownerCommitment: oc,
    noteBodyCommitment: nbc,
    noteCommitment: nc,
  };
}

/** The nullifier that spends a note, given the owner's ownerNullifierKey. */
export function noteNullifier(note: Note, ownerNullifierKey: bigint): bigint {
  return nullifierOf(note.chainId, note.poolAddress, note.noteCommitment, ownerNullifierKey);
}

/** Convenience: ownerNullifierKeyHash from an ownerNullifierKey. */
export function ownerHash(ownerNullifierKey: bigint): bigint {
  return onkHashOf(ownerNullifierKey);
}
