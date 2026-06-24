import { bytesToHex, type BytesLike, toBytes } from "./bytes.js";
import {
  decodePlainOrEncryptedNotePayload,
  type TrialDecryptionCandidate,
  type TrialDecryptNotePayloadResult
} from "./trial-decrypt.js";
import {
  fieldToAddress,
  type DecodedNotePayload,
  type FieldNumberish,
  type HexAddress,
  normalizeAddress,
  outputNoteDataHash,
  toNonnegativeBigInt
} from "./payload.js";
import {
  noteBodyCommitment as computeNoteBodyCommitment,
  noteCommitment as computeNoteCommitment,
  ownerCommitment
} from "./poseidon.js";

export const SHIELDED_POOL_EVENT_ABI = [
  "event ShieldedPoolDeposit(address indexed depositor,uint256 noteCommitment,uint256 leafIndex,uint256 amount,uint256 tokenAddress,uint256 postInsertionCommitmentRoot,bytes outputNoteData)",
  "event ShieldedPoolTransact(uint256 indexed nullifier0,uint256 indexed nullifier1,uint256 indexed intentReplayId,address authVerifier,uint256 noteCommitment0,uint256 noteCommitment1,uint256 noteCommitment2,uint256 leafIndex0,uint256 postInsertionCommitmentRoot,bytes outputNoteData0,bytes outputNoteData1,bytes outputNoteData2)",
  "event AuthPolicySet(address indexed user,uint256 ownerNullifierKeyHash,uint256 noteSecretSeedHash,uint256 policySetCommitment,uint256 leafPosition,uint256 leafValue,uint256 postUpdateAuthPolicyRoot)"
] as const;

export interface ChainEventMeta {
  blockNumber?: number;
  blockHash?: string;
  transactionHash?: string;
  logIndex?: number;
}

export interface ShieldedPoolDepositEvent extends ChainEventMeta {
  depositor?: HexAddress;
  noteCommitment: FieldNumberish;
  leafIndex: FieldNumberish;
  amount: FieldNumberish;
  tokenAddress: FieldNumberish | HexAddress;
  postInsertionCommitmentRoot?: FieldNumberish;
  outputNoteData: BytesLike;
}

export interface ShieldedPoolTransactEvent extends ChainEventMeta {
  nullifier0?: FieldNumberish;
  nullifier1?: FieldNumberish;
  intentReplayId?: FieldNumberish;
  authVerifier?: HexAddress;
  noteCommitment0: FieldNumberish;
  noteCommitment1: FieldNumberish;
  noteCommitment2: FieldNumberish;
  leafIndex0: FieldNumberish;
  postInsertionCommitmentRoot?: FieldNumberish;
  outputNoteData0: BytesLike;
  outputNoteData1: BytesLike;
  outputNoteData2: BytesLike;
}

export interface ShieldedPoolAuthPolicySetEvent extends ChainEventMeta {
  user: HexAddress;
  ownerNullifierKeyHash: FieldNumberish;
  noteSecretSeedHash: FieldNumberish;
  policySetCommitment: FieldNumberish;
  leafPosition: FieldNumberish;
  leafValue: FieldNumberish;
  postUpdateAuthPolicyRoot: FieldNumberish;
}

export type IndexedNoteStatus = "pending" | "decrypted" | "spent";
export type IndexedNoteSource = "deposit" | "transact";

export interface IndexedNote {
  id: string;
  source: IndexedNoteSource;
  chainId: bigint;
  poolAddress: HexAddress;
  leafIndex: bigint;
  outputIndex: 0 | 1 | 2;
  noteCommitment: bigint;
  outputNoteData: Uint8Array;
  outputNoteDataHash: bigint;
  status: IndexedNoteStatus;
  payload?: DecodedNotePayload;
  decryptedBy?: string;
  blockNumber?: number;
  blockHash?: string;
  transactionHash?: string;
  logIndex?: number;
}

export interface SepoliaDemoIndexerOptions {
  chainId: FieldNumberish;
  poolAddress: HexAddress;
  candidates?: readonly TrialDecryptionCandidate[];
  store?: InMemoryNoteStore;
}

export class InMemoryNoteStore {
  private readonly notes = new Map<string, IndexedNote>();

  upsert(note: IndexedNote): IndexedNote {
    this.notes.set(note.id, note);
    return note;
  }

  get(id: string): IndexedNote | undefined {
    return this.notes.get(id);
  }

  all(): IndexedNote[] {
    return [...this.notes.values()].sort((a, b) => Number(a.leafIndex - b.leafIndex) || a.outputIndex - b.outputIndex);
  }

  byStatus(status: IndexedNoteStatus): IndexedNote[] {
    return this.all().filter((note) => note.status === status);
  }
}

export class SepoliaDemoIndexer {
  readonly chainId: bigint;
  readonly poolAddress: HexAddress;
  readonly candidates: readonly TrialDecryptionCandidate[];
  readonly store: InMemoryNoteStore;

  constructor(options: SepoliaDemoIndexerOptions) {
    this.chainId = toNonnegativeBigInt(options.chainId, "chainId");
    this.poolAddress = normalizeAddress(options.poolAddress, "poolAddress");
    this.candidates = options.candidates ?? [];
    this.store = options.store ?? new InMemoryNoteStore();
  }

  async ingestDeposit(event: ShieldedPoolDepositEvent): Promise<IndexedNote> {
    const note = await this.makeNote({
      source: "deposit",
      outputIndex: 0,
      leafIndex: event.leafIndex,
      noteCommitment: event.noteCommitment,
      outputNoteData: event.outputNoteData,
      expectedAmount: event.amount,
      expectedTokenAddress: event.tokenAddress,
      meta: event
    });
    return this.store.upsert(note);
  }

  async ingestTransact(event: ShieldedPoolTransactEvent): Promise<IndexedNote[]> {
    const leafIndex0 = toNonnegativeBigInt(event.leafIndex0, "leafIndex0");
    const outputs = [
      { outputIndex: 0 as const, noteCommitment: event.noteCommitment0, leafIndex: leafIndex0, outputNoteData: event.outputNoteData0 },
      { outputIndex: 1 as const, noteCommitment: event.noteCommitment1, leafIndex: leafIndex0 + 1n, outputNoteData: event.outputNoteData1 },
      { outputIndex: 2 as const, noteCommitment: event.noteCommitment2, leafIndex: leafIndex0 + 2n, outputNoteData: event.outputNoteData2 }
    ];

    const notes: IndexedNote[] = [];
    for (const output of outputs) {
      notes.push(this.store.upsert(await this.makeNote({ source: "transact", ...output, meta: event })));
    }
    return notes;
  }

  private async makeNote(input: {
    source: IndexedNoteSource;
    outputIndex: 0 | 1 | 2;
    leafIndex: FieldNumberish;
    noteCommitment: FieldNumberish;
    outputNoteData: BytesLike;
    meta: ChainEventMeta;
    expectedAmount?: FieldNumberish;
    expectedTokenAddress?: FieldNumberish | HexAddress;
  }): Promise<IndexedNote> {
    const outputNoteData = toBytes(input.outputNoteData, "outputNoteData");
    const decrypted = await decodePlainOrEncryptedNotePayload(outputNoteData, this.candidates);
    const leafIndex = toNonnegativeBigInt(input.leafIndex, "leafIndex");
    const noteCommitment = toNonnegativeBigInt(input.noteCommitment, "noteCommitment");
    const note: IndexedNote = {
      id: noteId(this.chainId, this.poolAddress, leafIndex, input.outputIndex),
      source: input.source,
      chainId: this.chainId,
      poolAddress: this.poolAddress,
      leafIndex,
      outputIndex: input.outputIndex,
      noteCommitment,
      outputNoteData,
      outputNoteDataHash: outputNoteDataHash(outputNoteData),
      status: "pending",
      ...eventMeta(input.meta)
    };

    const checks: {
      expectedAmount?: FieldNumberish;
      expectedTokenAddress?: FieldNumberish | HexAddress;
    } = {};
    if (input.expectedAmount !== undefined) checks.expectedAmount = input.expectedAmount;
    if (input.expectedTokenAddress !== undefined) checks.expectedTokenAddress = input.expectedTokenAddress;

    applyDecryption(note, decrypted, checks);
    return note;
  }
}

export function noteId(chainId: FieldNumberish, poolAddress: HexAddress, leafIndex: FieldNumberish, outputIndex: 0 | 1 | 2): string {
  return [
    toNonnegativeBigInt(chainId, "chainId").toString(10),
    normalizeAddress(poolAddress, "poolAddress"),
    toNonnegativeBigInt(leafIndex, "leafIndex").toString(10),
    outputIndex.toString(10)
  ].join(":");
}

export function normalizeEventTokenAddress(value: FieldNumberish | HexAddress): HexAddress {
  return typeof value === "string" && value.startsWith("0x") && value.length === 42
    ? normalizeAddress(value, "tokenAddress")
    : fieldToAddress(value, "tokenAddress");
}

export function outputNoteDataHex(note: IndexedNote): `0x${string}` {
  return bytesToHex(note.outputNoteData);
}

function applyDecryption(
  note: IndexedNote,
  decrypted: TrialDecryptNotePayloadResult | null,
  checks: {
    expectedAmount?: FieldNumberish;
    expectedTokenAddress?: FieldNumberish | HexAddress;
  } = {}
): void {
  if (decrypted === null) return;
  if (!payloadMatchesIndexedNote(note, decrypted.payload, checks)) return;
  note.payload = decrypted.payload;
  note.decryptedBy = decrypted.candidateId;
  note.status = "decrypted";
}

export function payloadMatchesIndexedNote(
  note: IndexedNote,
  payload: DecodedNotePayload,
  checks: {
    expectedAmount?: FieldNumberish;
    expectedTokenAddress?: FieldNumberish | HexAddress;
  } = {}
): boolean {
  if (payload.chainId !== note.chainId) return false;
  if (payload.poolAddress !== note.poolAddress) return false;
  if (payload.kind !== note.source) return false;
  if (payload.leafIndex !== undefined && payload.leafIndex !== note.leafIndex) return false;
  if (payload.outputIndex !== undefined && payload.outputIndex !== note.outputIndex) return false;
  if (payload.noteCommitment !== undefined && payload.noteCommitment !== note.noteCommitment) return false;
  const computedOwnerCommitment = ownerCommitment(payload.ownerNullifierKeyHash, payload.noteSecret);
  const computedBody = computeNoteBodyCommitment(computedOwnerCommitment, payload.amount, payload.tokenAddress);
  if (payload.noteBodyCommitment !== undefined && payload.noteBodyCommitment !== computedBody) return false;
  if (computeNoteCommitment(computedBody, note.leafIndex) !== note.noteCommitment) return false;
  if (
    checks.expectedAmount !== undefined
      && payload.amount !== toNonnegativeBigInt(checks.expectedAmount, "expectedAmount")
  ) {
    return false;
  }
  if (checks.expectedTokenAddress !== undefined) {
    const expectedToken = normalizeEventTokenAddress(checks.expectedTokenAddress);
    if (payload.tokenAddress !== expectedToken) return false;
  }
  return true;
}

function eventMeta(meta: ChainEventMeta): ChainEventMeta {
  const out: ChainEventMeta = {};
  if (meta.blockNumber !== undefined) out.blockNumber = meta.blockNumber;
  if (meta.blockHash !== undefined) out.blockHash = meta.blockHash;
  if (meta.transactionHash !== undefined) out.transactionHash = meta.transactionHash;
  if (meta.logIndex !== undefined) out.logIndex = meta.logIndex;
  return out;
}
