// Browser note discovery + Merkle reconstruction. Event-sources both pools and
// the registry, rebuilds the append-only note tree and the sparse identity tree,
// and trial-decrypts every output against a local ML-KEM-768 secret key with the
// full spec §13 acceptance checks. Reuses the pure SDK crypto surface.

import type { Address, Hex, PublicClient } from "viem";
import { hexToBytes } from "../../../sdk/src/bytes.ts";
import {
  noteBodyCommitment,
  noteCommitment as noteCommitmentOf,
  nullifier as nullifierOf,
  ownerCommitment as ownerCommitmentOf,
  ownerNullifierKeyHash as onkHashOf,
} from "../../../sdk/src/derivations.ts";
import { tryDecryptOutputNoteData } from "../../../sdk/src/envelope.ts";
import { addressToField } from "../../../sdk/src/field.ts";
import {
  decodeNotePayload,
  NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS,
  NOTE_PAYLOAD_KIND_DEPOSIT,
  NOTE_PAYLOAD_KIND_TRANSACT,
} from "../../../sdk/src/payload.ts";
import { AppendOnlyTree, SparseTree } from "../../../sdk/src/trees.ts";

const shieldedPoolIndexerAbi = [
  {
    type: "event",
    name: "ShieldedPoolDeposit",
    inputs: [
      { name: "depositor", type: "address", indexed: true },
      { name: "noteCommitment", type: "uint256", indexed: false },
      { name: "leafIndex", type: "uint256", indexed: false },
      { name: "amount", type: "uint256", indexed: false },
      { name: "tokenAddress", type: "uint256", indexed: false },
      { name: "postInsertionCommitmentRoot", type: "uint256", indexed: false },
      { name: "outputNoteData", type: "bytes", indexed: false },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "ShieldedPoolTransact",
    inputs: [
      { name: "nullifier0", type: "uint256", indexed: true },
      { name: "nullifier1", type: "uint256", indexed: true },
      { name: "intentReplayId", type: "uint256", indexed: true },
      { name: "authVerifier", type: "address", indexed: false },
      { name: "noteCommitment0", type: "uint256", indexed: false },
      { name: "noteCommitment1", type: "uint256", indexed: false },
      { name: "noteCommitment2", type: "uint256", indexed: false },
      { name: "leafIndex0", type: "uint256", indexed: false },
      { name: "postInsertionCommitmentRoot", type: "uint256", indexed: false },
      { name: "outputNoteData0", type: "bytes", indexed: false },
      { name: "outputNoteData1", type: "bytes", indexed: false },
      { name: "outputNoteData2", type: "bytes", indexed: false },
    ],
    anonymous: false,
  },
] as const;

const registryIndexerAbi = [
  {
    type: "event",
    name: "IdentitySet",
    inputs: [
      { name: "user", type: "address", indexed: true },
      { name: "ownerNullifierKeyHash", type: "uint256", indexed: false },
      { name: "noteSecretSeedHash", type: "uint256", indexed: false },
      { name: "policySetCommitment", type: "uint256", indexed: false },
      { name: "leafPosition", type: "uint32", indexed: false },
      { name: "leafValue", type: "uint256", indexed: false },
      { name: "postUpdateIdentityRoot", type: "uint256", indexed: false },
    ],
    anonymous: false,
  },
] as const;

const DEFAULT_LOG_CHUNK_SIZE = 2_000n;
const HEAD_RETRY_BLOCK_LAG = 12n;

export interface LogScan {
  fromBlock?: bigint;
  toBlock?: bigint;
  chunkSize?: bigint;
}

type IndexedEvent<TArgs> = {
  args: TArgs;
  blockHash?: Hex | null;
  transactionHash?: Hex | null;
  logIndex?: number | null;
};

type DepositArgs = {
  leafIndex: bigint;
  noteCommitment: bigint;
  amount: bigint;
  tokenAddress: bigint;
  outputNoteData: Hex;
};

type TransactArgs = {
  leafIndex0: bigint;
  noteCommitment0: bigint;
  noteCommitment1: bigint;
  noteCommitment2: bigint;
  outputNoteData0: Hex;
  outputNoteData1: Hex;
  outputNoteData2: Hex;
};

type IdentitySetArgs = {
  user: string;
  leafPosition: number | bigint;
  leafValue: bigint;
};

async function logRanges(pub: PublicClient, scan: LogScan = {}): Promise<Array<{ fromBlock: bigint; toBlock: bigint }>> {
  const fromBlock = scan.fromBlock ?? 0n;
  const toBlock = scan.toBlock ?? (await pub.getBlockNumber());
  const chunkSize = scan.chunkSize ?? DEFAULT_LOG_CHUNK_SIZE;
  if (chunkSize <= 0n) throw new Error("log chunk size must be positive");
  if (fromBlock > toBlock) return [];

  const ranges: Array<{ fromBlock: bigint; toBlock: bigint }> = [];
  for (let chunkFrom = fromBlock; chunkFrom <= toBlock;) {
    const chunkTo = chunkFrom + chunkSize - 1n < toBlock ? chunkFrom + chunkSize - 1n : toBlock;
    ranges.push({ fromBlock: chunkFrom, toBlock: chunkTo });
    chunkFrom = chunkTo + 1n;
  }
  return ranges;
}

function isBeyondHeadError(e: unknown): boolean {
  return errorText(e).toLowerCase().includes("beyond current head");
}

function errorText(e: unknown, seen = new Set<unknown>()): string {
  if (e === null || e === undefined) return "";
  if (typeof e !== "object") return String(e);
  if (seen.has(e)) return "";
  seen.add(e);

  const parts = [String(e)];
  const record = e as Record<string, unknown>;
  for (const key of ["message", "shortMessage", "details", "reason", "data"]) {
    if (key in record) parts.push(errorText(record[key], seen));
  }
  if ("cause" in record) parts.push(errorText(record.cause, seen));
  return parts.filter(Boolean).join(" ");
}

async function withHeadRetry<T>(range: { fromBlock: bigint; toBlock: bigint }, fn: (toBlock: bigint) => Promise<T>): Promise<T | []> {
  try {
    return await fn(range.toBlock);
  } catch (e) {
    if (!isBeyondHeadError(e)) throw e;
    if (range.toBlock <= range.fromBlock) return [];
    const retryTo = range.toBlock > HEAD_RETRY_BLOCK_LAG ? range.toBlock - HEAD_RETRY_BLOCK_LAG : 0n;
    if (retryTo < range.fromBlock) return [];
    return fn(retryTo);
  }
}

async function getDepositEvents(pub: PublicClient, pool: Address, scan: LogScan = {}): Promise<Array<IndexedEvent<DepositArgs>>> {
  const events: Array<IndexedEvent<DepositArgs>> = [];
  for (const range of await logRanges(pub, scan)) {
    const chunk = await withHeadRetry(range, (toBlock) =>
      pub.getContractEvents({
        address: pool,
        abi: shieldedPoolIndexerAbi,
        eventName: "ShieldedPoolDeposit",
        fromBlock: range.fromBlock,
        toBlock,
      }),
    );
    events.push(...(chunk as unknown as Array<IndexedEvent<DepositArgs>>));
  }
  return events;
}

async function getTransactEvents(pub: PublicClient, pool: Address, scan: LogScan = {}): Promise<Array<IndexedEvent<TransactArgs>>> {
  const events: Array<IndexedEvent<TransactArgs>> = [];
  for (const range of await logRanges(pub, scan)) {
    const chunk = await withHeadRetry(range, (toBlock) =>
      pub.getContractEvents({
        address: pool,
        abi: shieldedPoolIndexerAbi,
        eventName: "ShieldedPoolTransact",
        fromBlock: range.fromBlock,
        toBlock,
      }),
    );
    events.push(...(chunk as unknown as Array<IndexedEvent<TransactArgs>>));
  }
  return events;
}

async function getIdentitySetEvents(pub: PublicClient, registry: Address, scan: LogScan = {}): Promise<Array<IndexedEvent<IdentitySetArgs>>> {
  const events: Array<IndexedEvent<IdentitySetArgs>> = [];
  for (const range of await logRanges(pub, scan)) {
    const chunk = await withHeadRetry(range, (toBlock) =>
      pub.getContractEvents({
        address: registry,
        abi: registryIndexerAbi,
        eventName: "IdentitySet",
        fromBlock: range.fromBlock,
        toBlock,
      }),
    );
    events.push(...(chunk as unknown as Array<IndexedEvent<IdentitySetArgs>>));
  }
  return events;
}

export interface NoteTree {
  tree: AppendOnlyTree;
  root: bigint;
  leaves: bigint[];
}

export async function rebuildNoteTree(pub: PublicClient, pool: Address, scan: LogScan = {}): Promise<NoteTree> {
  const deposits = await getDepositEvents(pub, pool, scan);
  const transacts = await getTransactEvents(pub, pool, scan);
  const entries: Array<{ leafIndex: bigint; commitment: bigint }> = [];
  for (const e of deposits) {
    const a = e.args;
    entries.push({ leafIndex: BigInt(a.leafIndex), commitment: a.noteCommitment });
  }
  for (const e of transacts) {
    const a = e.args;
    const i0 = BigInt(a.leafIndex0);
    entries.push({ leafIndex: i0, commitment: a.noteCommitment0 });
    entries.push({ leafIndex: i0 + 1n, commitment: a.noteCommitment1 });
    entries.push({ leafIndex: i0 + 2n, commitment: a.noteCommitment2 });
  }
  entries.sort((x, y) => (x.leafIndex < y.leafIndex ? -1 : x.leafIndex > y.leafIndex ? 1 : 0));
  const tree = new AppendOnlyTree(32);
  const leaves: bigint[] = [];
  for (const entry of entries) {
    if (entry.leafIndex !== tree.nextLeafIndex) throw new Error(`note tree gap at leaf ${entry.leafIndex}`);
    tree.append(entry.commitment);
    leaves.push(entry.commitment);
  }
  return { tree, root: tree.root(), leaves };
}

export async function getNoteProof(pub: PublicClient, pool: Address, leafIndex: bigint, scan: LogScan = {}): Promise<{ siblings: bigint[]; root: bigint }> {
  const { tree, root } = await rebuildNoteTree(pub, pool, scan);
  return { siblings: tree.proof(leafIndex), root };
}

export interface IdentityTree {
  tree: SparseTree;
  root: bigint;
  byUser: Map<string, { leafPosition: bigint; leafValue: bigint }>;
}

export async function rebuildIdentityTree(pub: PublicClient, registry: Address, scan: LogScan = {}): Promise<IdentityTree> {
  const events = await getIdentitySetEvents(pub, registry, scan);
  const tree = new SparseTree(32);
  const byUser = new Map<string, { leafPosition: bigint; leafValue: bigint }>();
  for (const e of events) {
    const a = e.args;
    const leafPosition = BigInt(a.leafPosition);
    tree.set(leafPosition, a.leafValue);
    byUser.set(a.user.toLowerCase(), { leafPosition, leafValue: a.leafValue });
  }
  return { tree, root: tree.root(), byUser };
}

export async function getIdentityProof(
  pub: PublicClient,
  registry: Address,
  user: Address,
  scan: LogScan = {},
): Promise<{ leafPosition: bigint; siblings: bigint[]; root: bigint }> {
  const { tree, root, byUser } = await rebuildIdentityTree(pub, registry, scan);
  const entry = byUser.get(user.toLowerCase());
  if (!entry) throw new Error(`no identity for ${user}`);
  return { leafPosition: entry.leafPosition, siblings: tree.proof(entry.leafPosition), root };
}

export interface RecoveredNote {
  id: string;
  poolAddress: bigint;
  poolLabel: string;
  chainId: bigint;
  leafIndex: bigint;
  outputIndex: bigint;
  amount: bigint;
  tokenAddress: bigint;
  ownerNullifierKeyHash: bigint;
  noteSecret: bigint;
  noteBodyCommitment: bigint;
  noteCommitment: bigint;
  nullifier: bigint;
  spent: boolean;
}

interface Candidate {
  chainId: bigint;
  poolAddress: bigint;
  poolLabel: string;
  leafIndex: bigint;
  outputIndex: bigint;
  eventCommitment: bigint;
  data: Uint8Array;
  dedupKey: string;
  kind: bigint;
  eventAmount: bigint;
  eventTokenField: bigint;
}

export interface IndexerPool {
  address: Address;
  label: string;
  chainId: bigint;
  startBlock?: bigint;
}

/** Scan the pools and return every note the viewer can decrypt AND validate. */
export async function recoverNotes(p: {
  pub: PublicClient;
  pools: IndexerPool[];
  secretKey: Uint8Array;
  ownerNullifierKey: bigint;
  logChunkSize?: bigint;
}): Promise<RecoveredNote[]> {
  const ownerHash = onkHashOf(p.ownerNullifierKey);
  const candidates: Candidate[] = [];

  for (const pool of p.pools) {
    const poolField = addressToField(pool.address, "poolAddress");
    const scan = { fromBlock: pool.startBlock, chunkSize: p.logChunkSize };
    const deposits = await getDepositEvents(p.pub, pool.address, scan);
    for (const e of deposits) {
      const a = e.args;
      candidates.push({
        chainId: pool.chainId,
        poolAddress: poolField,
        poolLabel: pool.label,
        leafIndex: BigInt(a.leafIndex),
        outputIndex: 0n,
        eventCommitment: a.noteCommitment,
        data: hexToBytes(a.outputNoteData),
        dedupKey: `${e.blockHash}:${e.transactionHash}:${e.logIndex}:0`,
        kind: NOTE_PAYLOAD_KIND_DEPOSIT,
        eventAmount: BigInt(a.amount),
        eventTokenField: BigInt(a.tokenAddress),
      });
    }
    const transacts = await getTransactEvents(p.pub, pool.address, scan);
    for (const e of transacts) {
      const a = e.args;
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
          poolLabel: pool.label,
          leafIndex,
          outputIndex: BigInt(slot),
          eventCommitment: commitment,
          data: hexToBytes(data),
          dedupKey: `${e.blockHash}:${e.transactionHash}:${e.logIndex}:${slot}`,
          kind: NOTE_PAYLOAD_KIND_TRANSACT,
          eventAmount: 0n,
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
    if (c.data.length === 0) continue;

    const plaintext = await tryDecryptOutputNoteData(p.secretKey, c.data);
    if (plaintext === null) continue;
    let payload;
    try {
      payload = decodeNotePayload(plaintext);
    } catch {
      continue;
    }
    if (payload.kind !== c.kind) continue;
    if (payload.chainId !== c.chainId) continue;
    if (addressToField(payload.poolAddress, "poolAddress") !== c.poolAddress) continue;
    if (payload.outputIndex !== c.outputIndex) continue;
    if (payload.ownerNullifierKeyHash !== ownerHash) continue;

    const usesEventPublics =
      payload.kind === NOTE_PAYLOAD_KIND_DEPOSIT &&
      (payload.flags & NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS) !== 0n;
    const amount = usesEventPublics ? c.eventAmount : payload.amount;
    const tokenField = usesEventPublics ? c.eventTokenField : addressToField(payload.tokenAddress, "tokenAddress");
    const oc = ownerCommitmentOf(c.chainId, c.poolAddress, ownerHash, payload.noteSecret);
    const nbc = noteBodyCommitment(oc, amount, tokenField);
    if (!usesEventPublics && nbc !== payload.noteBodyCommitment) continue;
    const nc = noteCommitmentOf(c.chainId, c.poolAddress, nbc, c.leafIndex);
    if (nc !== c.eventCommitment) continue;

    recovered.push({
      id: `${c.chainId}:${c.poolAddress}:${c.leafIndex}:${c.outputIndex}`,
      poolAddress: c.poolAddress,
      poolLabel: c.poolLabel,
      chainId: c.chainId,
      leafIndex: c.leafIndex,
      outputIndex: c.outputIndex,
      amount,
      tokenAddress: tokenField,
      ownerNullifierKeyHash: payload.ownerNullifierKeyHash,
      noteSecret: payload.noteSecret,
      noteBodyCommitment: nbc,
      noteCommitment: nc,
      nullifier: nullifierOf(c.chainId, c.poolAddress, nc, p.ownerNullifierKey),
      spent: false,
    });
  }
  return recovered;
}
