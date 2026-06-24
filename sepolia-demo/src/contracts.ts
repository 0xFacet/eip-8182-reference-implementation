import { keccak_256 } from "@noble/hashes/sha3.js";
import {
  bytesToHex,
  hexToBytes,
  toBytes,
  type BytesLike,
  utf8ToBytes
} from "./bytes.js";
import {
  fieldToAddress,
  normalizeAddress,
  toNonnegativeBigInt,
  type FieldNumberish,
  type HexAddress
} from "./payload.js";
import type {
  ShieldedPoolAuthPolicySetEvent,
  ShieldedPoolDepositEvent,
  ShieldedPoolTransactEvent
} from "./indexer.js";
import type { RecipientEncryptionPublicKey } from "./envelope.js";
import type { DemoPoolPublicInputs } from "./prover.js";

export type Hex = `0x${string}`;

export interface Eip1193Provider {
  request(args: { method: string; params?: unknown[] | Record<string, unknown> }): Promise<unknown>;
}

export interface TransactionReceipt {
  transactionHash: Hex;
  status?: Hex;
  blockNumber?: Hex;
}

export interface RegistryRecipient {
  registered: boolean;
  ownerNullifierKeyHash: bigint;
  publicKey: RecipientEncryptionPublicKey;
  metadataVersion: number;
}

export interface ChainRoots {
  noteCommitmentRoot: bigint;
  authPolicyRoot: bigint;
}

export interface AuthPolicyEntry {
  registered: boolean;
  leafPosition: bigint;
  ownerNullifierKeyHash: bigint;
  noteSecretSeedHash: bigint;
  policySetCommitment: bigint;
}

export const SHIELDED_POOL_DEPOSIT_TOPIC = eventTopic(
  "ShieldedPoolDeposit(address,uint256,uint256,uint256,uint256,uint256,bytes)"
);
export const SHIELDED_POOL_TRANSACT_TOPIC = eventTopic(
  "ShieldedPoolTransact(uint256,uint256,uint256,address,uint256,uint256,uint256,uint256,uint256,bytes,bytes,bytes)"
);
export const SHIELDED_POOL_AUTH_POLICY_SET_TOPIC = eventTopic(
  "AuthPolicySet(address,uint256,uint256,uint256,uint256,uint256,uint256)"
);
const DEFAULT_LOG_CHUNK_SIZE = 2_000n;

export async function requestWalletAccounts(provider: Eip1193Provider): Promise<HexAddress[]> {
  const accounts = await provider.request({ method: "eth_requestAccounts" });
  if (!Array.isArray(accounts)) throw new Error("wallet returned invalid accounts");
  return accounts.map((account) => normalizeAddress(String(account), "account"));
}

export async function getWalletChainId(provider: Eip1193Provider): Promise<bigint> {
  const chainId = await provider.request({ method: "eth_chainId" });
  if (typeof chainId !== "string") throw new Error("wallet returned invalid chain id");
  return BigInt(chainId);
}

export async function switchWalletChain(provider: Eip1193Provider, chainId: FieldNumberish): Promise<void> {
  await provider.request({
    method: "wallet_switchEthereumChain",
    params: [{ chainId: toQuantity(chainId) }]
  });
}

export async function signProfileMessage(
  provider: Eip1193Provider,
  account: HexAddress,
  message: string
): Promise<Hex> {
  const signature = await provider.request({
    method: "personal_sign",
    params: [bytesToHex(utf8ToBytes(message)), account]
  });
  if (typeof signature !== "string" || !isHex(signature)) throw new Error("wallet returned invalid signature");
  return signature as Hex;
}

export async function readRecipient(
  provider: Eip1193Provider,
  registry: HexAddress,
  recipient: HexAddress
): Promise<RegistryRecipient> {
  const data = encodeGetRecipient(recipient);
  const result = await ethCall(provider, registry, data);
  return decodeGetRecipient(result);
}

export async function readCurrentRoots(provider: Eip1193Provider, pool: HexAddress): Promise<ChainRoots> {
  const result = await ethCall(provider, pool, encodeGetCurrentRoots());
  return {
    noteCommitmentRoot: readWord(result, 0),
    authPolicyRoot: readWord(result, 32)
  };
}

export async function readNullifierSpent(
  provider: Eip1193Provider,
  pool: HexAddress,
  nullifierValue: FieldNumberish
): Promise<boolean> {
  const result = await ethCall(provider, pool, encodeIsNullifierSpent(nullifierValue));
  return readWord(result, 0) !== 0n;
}

export async function readAuthPolicyEntry(
  provider: Eip1193Provider,
  pool: HexAddress,
  user: HexAddress
): Promise<AuthPolicyEntry> {
  const result = await ethCall(provider, pool, encodeGetAuthPolicyEntry(user));
  return {
    registered: readWord(result, 0) !== 0n,
    leafPosition: readWord(result, 32),
    ownerNullifierKeyHash: readWord(result, 64),
    noteSecretSeedHash: readWord(result, 96),
    policySetCommitment: readWord(result, 128)
  };
}

export async function sendPublishRecipient(
  provider: Eip1193Provider,
  from: HexAddress,
  registry: HexAddress,
  ownerNullifierKeyHash: FieldNumberish,
  publicKey: RecipientEncryptionPublicKey,
  metadataVersion = 1
): Promise<Hex> {
  return sendTransaction(provider, {
    from,
    to: registry,
    data: encodePublishRecipient(ownerNullifierKeyHash, publicKey, metadataVersion)
  });
}

export async function sendClearRecipient(
  provider: Eip1193Provider,
  from: HexAddress,
  registry: HexAddress
): Promise<Hex> {
  return sendTransaction(provider, {
    from,
    to: registry,
    data: encodeClearRecipient()
  });
}

export async function sendSetAuthPolicy(
  provider: Eip1193Provider,
  from: HexAddress,
  pool: HexAddress,
  ownerNullifierKeyHash: FieldNumberish,
  noteSecretSeedHash: FieldNumberish,
  policySetCommitment: FieldNumberish
): Promise<Hex> {
  return sendTransaction(provider, {
    from,
    to: pool,
    data: encodeSetAuthPolicy(ownerNullifierKeyHash, noteSecretSeedHash, policySetCommitment)
  });
}

export async function sendDeposit(
  provider: Eip1193Provider,
  from: HexAddress,
  pool: HexAddress,
  token: HexAddress,
  amount: FieldNumberish,
  ownerCommitment: FieldNumberish,
  outputNoteData: BytesLike
): Promise<Hex> {
  const value = normalizeAddress(token, "token") === "0x0000000000000000000000000000000000000000"
    ? toQuantity(amount)
    : undefined;
  const request: SendTransactionRequest = {
    from,
    to: pool,
    data: encodeDeposit(token, amount, ownerCommitment, outputNoteData)
  };
  if (value !== undefined) request.value = value;
  return sendTransaction(provider, request);
}

export async function sendTransact(
  provider: Eip1193Provider,
  from: HexAddress,
  pool: HexAddress,
  bundle: {
    poolProof: BytesLike;
    authProof: BytesLike;
    publicInputs: DemoPoolPublicInputs;
    outputNoteData0: BytesLike;
    outputNoteData1: BytesLike;
    outputNoteData2: BytesLike;
  }
): Promise<Hex> {
  return sendTransaction(provider, {
    from,
    to: pool,
    data: encodeTransact(
      bundle.poolProof,
      bundle.authProof,
      bundle.publicInputs,
      bundle.outputNoteData0,
      bundle.outputNoteData1,
      bundle.outputNoteData2
    )
  });
}

export async function getPoolDepositLogs(
  provider: Eip1193Provider,
  pool: HexAddress,
  fromBlock: FieldNumberish,
  toBlock: FieldNumberish | "latest" = "latest"
): Promise<ShieldedPoolDepositEvent[]> {
  const logs = await ethGetLogsChunked(provider, {
    address: pool,
    fromBlock,
    toBlock,
    topics: [SHIELDED_POOL_DEPOSIT_TOPIC]
  });
  return logs.map(parseDepositLog);
}

export async function getPoolTransactLogs(
  provider: Eip1193Provider,
  pool: HexAddress,
  fromBlock: FieldNumberish,
  toBlock: FieldNumberish | "latest" = "latest"
): Promise<ShieldedPoolTransactEvent[]> {
  const logs = await ethGetLogsChunked(provider, {
    address: pool,
    fromBlock,
    toBlock,
    topics: [SHIELDED_POOL_TRANSACT_TOPIC]
  });
  return logs.map(parseTransactLog);
}

export async function getPoolAuthPolicySetLogs(
  provider: Eip1193Provider,
  pool: HexAddress,
  fromBlock: FieldNumberish,
  toBlock: FieldNumberish | "latest" = "latest"
): Promise<ShieldedPoolAuthPolicySetEvent[]> {
  const logs = await ethGetLogsChunked(provider, {
    address: pool,
    fromBlock,
    toBlock,
    topics: [SHIELDED_POOL_AUTH_POLICY_SET_TOPIC]
  });
  return logs.map(parseAuthPolicySetLog);
}

export async function waitForTransactionReceipt(
  provider: Eip1193Provider,
  transactionHash: Hex,
  options: { pollMs?: number; timeoutMs?: number } = {}
): Promise<TransactionReceipt> {
  const pollMs = options.pollMs ?? 1500;
  const timeoutMs = options.timeoutMs ?? 120_000;
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const receipt = await provider.request({
      method: "eth_getTransactionReceipt",
      params: [transactionHash]
    });
    if (receipt !== null) {
      const typedReceipt = receipt as TransactionReceipt;
      if (typedReceipt.status === undefined) throw new Error(`transaction ${transactionHash} receipt is missing status`);
      if (BigInt(typedReceipt.status) !== 1n) throw new Error(`transaction ${transactionHash} reverted`);
      return typedReceipt;
    }
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
  throw new Error(`timed out waiting for ${transactionHash}`);
}

export function encodePublishRecipient(
  ownerNullifierKeyHashValue: FieldNumberish,
  publicKey: RecipientEncryptionPublicKey,
  metadataVersion = 1
): Hex {
  return encodeCallWithDynamicBytes(
    "publishRecipient(uint256,bytes,bytes32,uint32)",
    [
      encodeUint(ownerNullifierKeyHashValue),
      null,
      encodeBytes32(publicKey.x25519PublicKey, "x25519PublicKey"),
      encodeUint(metadataVersion)
    ],
    [{ index: 1, bytes: publicKey.mlKem768PublicKey }]
  );
}

export function encodeSetAuthPolicy(
  ownerNullifierKeyHashValue: FieldNumberish,
  noteSecretSeedHashValue: FieldNumberish,
  policySetCommitmentValue: FieldNumberish
): Hex {
  return concatHex(
    selector("setAuthPolicy(uint256,uint256,uint256)"),
    encodeUint(ownerNullifierKeyHashValue),
    encodeUint(noteSecretSeedHashValue),
    encodeUint(policySetCommitmentValue)
  );
}

export function encodeDeposit(
  token: HexAddress,
  amount: FieldNumberish,
  ownerCommitmentValue: FieldNumberish,
  outputNoteData: BytesLike
): Hex {
  return encodeCallWithDynamicBytes(
    "deposit(address,uint256,uint256,bytes)",
    [
      encodeAddress(token),
      encodeUint(amount),
      encodeUint(ownerCommitmentValue),
      null
    ],
    [{ index: 3, bytes: outputNoteData }]
  );
}

export function encodeTransact(
  poolProof: BytesLike,
  authProof: BytesLike,
  publicInputs: DemoPoolPublicInputs,
  outputNoteData0: BytesLike,
  outputNoteData1: BytesLike,
  outputNoteData2: BytesLike
): Hex {
  const tuple = [
    publicInputs.noteCommitmentRoot,
    publicInputs.nullifier0,
    publicInputs.nullifier1,
    publicInputs.noteBodyCommitment0,
    publicInputs.noteBodyCommitment1,
    publicInputs.noteBodyCommitment2,
    publicInputs.publicAmountOut,
    publicInputs.publicRecipientAddress,
    publicInputs.publicTokenAddress,
    publicInputs.intentReplayId,
    publicInputs.validUntilSeconds,
    publicInputs.executionChainId,
    publicInputs.authPolicyRoot,
    publicInputs.outputNoteDataHash0,
    publicInputs.outputNoteDataHash1,
    publicInputs.outputNoteDataHash2,
    publicInputs.authVerifier,
    publicInputs.blindedAuthCommitment,
    publicInputs.transactionIntentDigest
  ].map(encodeUint);
  const tails = [
    encodeBytes(poolProof),
    encodeBytes(authProof),
    encodeBytes(outputNoteData0),
    encodeBytes(outputNoteData1),
    encodeBytes(outputNoteData2)
  ];
  const headWords = 1 + 1 + tuple.length + 1 + 1 + 1;
  let offset = BigInt(headWords * 32);
  const dynamicHeads: Hex[] = [];
  for (const tail of tails) {
    dynamicHeads.push(encodeUint(offset));
    offset += BigInt(hexDataLength(tail));
  }
  return concatHex(
    selector("transact(bytes,bytes,(uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256),bytes,bytes,bytes)"),
    dynamicHeads[0] ?? fail("pool proof offset missing"),
    dynamicHeads[1] ?? fail("auth proof offset missing"),
    ...tuple,
    dynamicHeads[2] ?? fail("output 0 offset missing"),
    dynamicHeads[3] ?? fail("output 1 offset missing"),
    dynamicHeads[4] ?? fail("output 2 offset missing"),
    ...tails
  );
}

export function encodeGetRecipient(recipient: HexAddress): Hex {
  return concatHex(selector("getRecipient(address)"), encodeAddress(recipient));
}

export function encodeClearRecipient(): Hex {
  return selector("clearRecipient()");
}

export function encodeGetCurrentRoots(): Hex {
  return selector("getCurrentRoots()");
}

export function encodeGetAuthPolicyEntry(user: HexAddress): Hex {
  return concatHex(selector("getAuthPolicyEntry(address)"), encodeAddress(user));
}

export function encodeIsNullifierSpent(nullifierValue: FieldNumberish): Hex {
  return concatHex(selector("isNullifierSpent(uint256)"), encodeUint(nullifierValue));
}

function decodeGetRecipient(data: Hex): RegistryRecipient {
  if (data === "0x" || hexToBytes(data).length < 64) {
    return {
      registered: false,
      ownerNullifierKeyHash: 0n,
      publicKey: { mlKem768PublicKey: new Uint8Array(), x25519PublicKey: new Uint8Array() },
      metadataVersion: 0
    };
  }
  const registered = readWord(data, 0) !== 0n;
  const tupleOffset = Number(readWord(data, 32));
  if (!registered) {
    return {
      registered: false,
      ownerNullifierKeyHash: 0n,
      publicKey: { mlKem768PublicKey: new Uint8Array(), x25519PublicKey: new Uint8Array() },
      metadataVersion: 0
    };
  }

  const ownerNullifierKeyHashValue = readWord(data, tupleOffset);
  const mlKemOffset = Number(readWord(data, tupleOffset + 32));
  const x25519PublicKey = hexToBytes(readWordHex(data, tupleOffset + 64), "x25519PublicKey");
  const metadataVersion = Number(readWord(data, tupleOffset + 96));
  const mlKem768PublicKey = decodeDynamicBytes(data, tupleOffset + mlKemOffset);
  return {
    registered,
    ownerNullifierKeyHash: ownerNullifierKeyHashValue,
    publicKey: { mlKem768PublicKey, x25519PublicKey },
    metadataVersion
  };
}

interface SendTransactionRequest {
  from: HexAddress;
  to: HexAddress;
  data: Hex;
  value?: Hex;
}

async function sendTransaction(provider: Eip1193Provider, tx: SendTransactionRequest): Promise<Hex> {
  const request: Record<string, string> = {
    from: tx.from,
    to: tx.to,
    data: tx.data
  };
  if (tx.value !== undefined) request.value = tx.value;
  const hash = await provider.request({ method: "eth_sendTransaction", params: [request] });
  if (typeof hash !== "string" || !isHex(hash)) throw new Error("wallet returned invalid transaction hash");
  return hash as Hex;
}

async function ethCall(provider: Eip1193Provider, to: HexAddress, data: Hex): Promise<Hex> {
  const result = await provider.request({
    method: "eth_call",
    params: [{ to, data }, "latest"]
  });
  if (typeof result !== "string" || !isHex(result)) throw new Error("eth_call returned invalid hex");
  return result as Hex;
}

interface GetLogsFilter {
  address: HexAddress;
  fromBlock: FieldNumberish;
  toBlock: FieldNumberish | "latest";
  topics: readonly Hex[];
}

interface RpcLog {
  address: HexAddress;
  topics: Hex[];
  data: Hex;
  blockNumber?: Hex;
  blockHash?: Hex;
  transactionHash?: Hex;
  logIndex?: Hex;
}

async function ethGetLogs(provider: Eip1193Provider, filter: GetLogsFilter): Promise<RpcLog[]> {
  const result = await provider.request({
    method: "eth_getLogs",
    params: [{
      address: normalizeAddress(filter.address, "address"),
      fromBlock: toBlockParam(filter.fromBlock),
      toBlock: filter.toBlock === "latest" ? "latest" : toBlockParam(filter.toBlock),
      topics: filter.topics
    }]
  });
  if (!Array.isArray(result)) throw new Error("eth_getLogs returned invalid logs");
  return result as RpcLog[];
}

async function ethGetLogsChunked(
  provider: Eip1193Provider,
  filter: GetLogsFilter,
  chunkSize = DEFAULT_LOG_CHUNK_SIZE
): Promise<RpcLog[]> {
  const fromBlock = toNonnegativeBigInt(filter.fromBlock, "fromBlock");
  const toBlock = filter.toBlock === "latest"
    ? await ethBlockNumber(provider)
    : toNonnegativeBigInt(filter.toBlock, "toBlock");
  if (fromBlock > toBlock) return [];

  const logs: RpcLog[] = [];
  for (let chunkFrom = fromBlock; chunkFrom <= toBlock;) {
    const chunkTo = minBigInt(chunkFrom + chunkSize - 1n, toBlock);
    logs.push(...await ethGetLogs(provider, {
      ...filter,
      fromBlock: chunkFrom,
      toBlock: chunkTo
    }));
    chunkFrom = chunkTo + 1n;
  }
  return logs;
}

async function ethBlockNumber(provider: Eip1193Provider): Promise<bigint> {
  const result = await provider.request({ method: "eth_blockNumber" });
  if (typeof result !== "string" || !isHex(result)) throw new Error("eth_blockNumber returned invalid block number");
  return BigInt(result);
}

function parseDepositLog(log: RpcLog): ShieldedPoolDepositEvent {
  const data = log.data;
  const parsed: ShieldedPoolDepositEvent = {
    noteCommitment: readWord(data, 0),
    leafIndex: readWord(data, 32),
    amount: readWord(data, 64),
    tokenAddress: fieldToAddress(readWord(data, 96), "tokenAddress"),
    postInsertionCommitmentRoot: readWord(data, 128),
    outputNoteData: decodeDynamicBytes(data, Number(readWord(data, 160))),
    ...logMeta(log)
  };
  const depositor = topicAddress(log.topics[1]);
  if (depositor !== undefined) parsed.depositor = depositor;
  return parsed;
}

function parseTransactLog(log: RpcLog): ShieldedPoolTransactEvent {
  const data = log.data;
  return {
    nullifier0: readWord(log.topics[1] ?? "0x0", 0),
    nullifier1: readWord(log.topics[2] ?? "0x0", 0),
    intentReplayId: readWord(log.topics[3] ?? "0x0", 0),
    authVerifier: readAddress(data, 0),
    noteCommitment0: readWord(data, 32),
    noteCommitment1: readWord(data, 64),
    noteCommitment2: readWord(data, 96),
    leafIndex0: readWord(data, 128),
    postInsertionCommitmentRoot: readWord(data, 160),
    outputNoteData0: decodeDynamicBytes(data, Number(readWord(data, 192))),
    outputNoteData1: decodeDynamicBytes(data, Number(readWord(data, 224))),
    outputNoteData2: decodeDynamicBytes(data, Number(readWord(data, 256))),
    ...logMeta(log)
  };
}

function parseAuthPolicySetLog(log: RpcLog): ShieldedPoolAuthPolicySetEvent {
  const user = topicAddress(log.topics[1]);
  if (user === undefined) throw new Error("AuthPolicySet log is missing indexed user topic");
  const data = log.data;
  return {
    user,
    ownerNullifierKeyHash: readWord(data, 0),
    noteSecretSeedHash: readWord(data, 32),
    policySetCommitment: readWord(data, 64),
    leafPosition: readWord(data, 96),
    leafValue: readWord(data, 128),
    postUpdateAuthPolicyRoot: readWord(data, 160),
    ...logMeta(log)
  };
}

function logMeta(log: RpcLog): {
  blockNumber?: number;
  blockHash?: string;
  transactionHash?: string;
  logIndex?: number;
} {
  const meta: {
    blockNumber?: number;
    blockHash?: string;
    transactionHash?: string;
    logIndex?: number;
  } = {};
  if (log.blockNumber !== undefined) meta.blockNumber = Number(BigInt(log.blockNumber));
  if (log.blockHash !== undefined) meta.blockHash = log.blockHash;
  if (log.transactionHash !== undefined) meta.transactionHash = log.transactionHash;
  if (log.logIndex !== undefined) meta.logIndex = Number(BigInt(log.logIndex));
  return meta;
}

function encodeCallWithDynamicBytes(
  signature: string,
  heads: readonly (Hex | null)[],
  dynamicValues: readonly { index: number; bytes: BytesLike }[]
): Hex {
  const dynamicByIndex = new Map(dynamicValues.map((value) => [value.index, value.bytes]));
  const encodedHeads: Hex[] = [];
  const encodedTails: Hex[] = [];
  let tailOffset = BigInt(heads.length * 32);
  for (let index = 0; index < heads.length; index += 1) {
    const staticHead = heads[index];
    const dynamic = dynamicByIndex.get(index);
    if (dynamic === undefined) {
      if (staticHead === null || staticHead === undefined) throw new Error(`missing ABI head at index ${index}`);
      encodedHeads.push(staticHead);
      continue;
    }
    const tail = encodeBytes(dynamic);
    encodedHeads.push(encodeUint(tailOffset));
    encodedTails.push(tail);
    tailOffset += BigInt(hexDataLength(tail));
  }
  return concatHex(selector(signature), ...encodedHeads, ...encodedTails);
}

function encodeBytes(value: BytesLike): Hex {
  const bytes = toBytes(value, "bytes");
  const padding = (32 - (bytes.length % 32)) % 32;
  return concatHex(encodeUint(bytes.length), bytesToHex(bytes), bytesToHex(new Uint8Array(padding)));
}

function encodeUint(value: FieldNumberish): Hex {
  const bigint = toNonnegativeBigInt(value, "uint");
  if (bigint >= 1n << 256n) throw new Error("uint does not fit in 256 bits");
  return `0x${bigint.toString(16).padStart(64, "0")}`;
}

function encodeAddress(address: HexAddress): Hex {
  const normalized = normalizeAddress(address, "address");
  return `0x${normalized.slice(2).padStart(64, "0")}`;
}

function encodeBytes32(value: BytesLike, name: string): Hex {
  const bytes = toBytes(value, name);
  if (bytes.length !== 32) throw new Error(`${name} must be 32 bytes`);
  return bytesToHex(bytes);
}

function selector(signature: string): Hex {
  return `0x${bytesToHex(keccak_256(utf8ToBytes(signature))).slice(2, 10)}`;
}

function eventTopic(signature: string): Hex {
  return bytesToHex(keccak_256(utf8ToBytes(signature)));
}

function concatHex(...parts: readonly Hex[]): Hex {
  return `0x${parts.map((part) => strip0x(part)).join("")}`;
}

function readWord(data: Hex, byteOffset: number): bigint {
  return BigInt(readWordHex(data, byteOffset));
}

function readWordHex(data: Hex, byteOffset: number): Hex {
  const start = byteOffset * 2;
  const hex = strip0x(data).slice(start, start + 64).padStart(64, "0");
  return `0x${hex}`;
}

function readAddress(data: Hex, byteOffset: number): HexAddress {
  return normalizeAddress(`0x${readWordHex(data, byteOffset).slice(-40)}`, "address");
}

function decodeDynamicBytes(data: Hex, byteOffset: number): Uint8Array {
  const length = Number(readWord(data, byteOffset));
  const bodyStart = byteOffset + 32;
  const hexStart = bodyStart * 2;
  return hexToBytes(`0x${strip0x(data).slice(hexStart, hexStart + length * 2)}`, "dynamic bytes");
}

function topicAddress(topic: Hex | undefined): HexAddress | undefined {
  if (topic === undefined) return undefined;
  return normalizeAddress(`0x${strip0x(topic).slice(-40)}`, "topic address");
}

function toQuantity(value: FieldNumberish): Hex {
  return `0x${toNonnegativeBigInt(value, "quantity").toString(16)}`;
}

function toBlockParam(value: FieldNumberish): Hex {
  return toQuantity(value);
}

function minBigInt(a: bigint, b: bigint): bigint {
  return a < b ? a : b;
}

function hexDataLength(hex: Hex): number {
  return strip0x(hex).length / 2;
}

function isHex(value: string): boolean {
  return /^0x[0-9a-fA-F]*$/.test(value);
}

function strip0x(value: Hex): string {
  return value.slice(2);
}

function fail(message: string): never {
  throw new Error(message);
}
