import { keccak_256 } from "@noble/hashes/sha3";
import { buildPoseidon } from "circomlibjs";
import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import os from "os";
import { XWing } from "@noble/post-quantum/hybrid.js";
import { extract, expand } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { createCipheriv, randomBytes } from "crypto";
import { execSync } from "child_process";
import {
  AUTH_POLICY_DOMAIN,
  AUTH_POLICY_KEY_DOMAIN,
  DELIVERY_SCHEME_X_WING,
  computeAuthVkHash,
  bytesToHex,
  computeIntentDigest,
  computeIntentNullifier,
  computeOutputBinding,
  computeRealNullifier,
  DEPOSIT_OPERATION_KIND,
  defaultExecutionConstraints,
  FIELD_MODULUS,
  hexToBytes,
  type ExecutionConstraints,
  ORIGIN_TAG_DOMAIN,
  LOCK_OUTPUT_BINDING_0,
  LOCK_OUTPUT_BINDING_1,
  LOCK_OUTPUT_BINDING_2,
  ORIGIN_MODE_DEFAULT,
  NK_DOMAIN,
  normalizeExecutionConstraints,
  OUTPUT_SECRET_DOMAIN,
  PHANTOM_DOMAIN,
  PROTOCOL_COMMITMENT_TREE_DEPTH,
  PROTOCOL_VERIFYING_CONTRACT_FIELD,
  RANDOMNESS_DOMAIN,
  TRANSFER_OPERATION_KIND,
  WITHDRAWAL_OPERATION_KIND,
  X_WING_PUBLIC_KEY_LENGTH,
} from "../../src/lib/protocol.ts";
import { execLogged, withLoggedCircuitLock } from "./ffi_debug.ts";
import type { FfiLogger } from "./ffi_debug.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export const CIRCUITS_DIR = resolve(__dirname, "../../circuits");
export const BB = process.env.BB_BINARY || `${os.homedir()}/.bb/bb`;
export const CIRCUIT_LOCK_DIR = resolve(os.tmpdir(), "eip8182-circuit-lock");
export const CIRCUIT_LOCK_STALE_MS = 10 * 60 * 1000;
export const CIRCUIT_SCRATCH_DIR = resolve(os.tmpdir(), "eip8182-circuit-scratch");
export const TOOL_ENV = buildToolEnv();

const REQUIRED_BB_VERSION = "4.0.0-nightly.20260120";

function assertBbVersion() {
  try {
    const raw = execSync(`${BB} --version`, {
      timeout: 5000,
      encoding: "utf8",
      env: TOOL_ENV,
    }).trim();
    if (raw !== REQUIRED_BB_VERSION) {
      throw new Error(
        `bb version mismatch: got "${raw}", expected "${REQUIRED_BB_VERSION}". ` +
        `Install the correct version or set BB_BINARY to the right path.`,
      );
    }
  } catch (e: any) {
    if (e.message?.includes("version mismatch")) throw e;
    throw new Error(`failed to run '${BB} --version': ${e.message}`);
  }
}

let bbVersionChecked = false;

export const DUMMY_NK_PREIMAGE = 0xdeadn;
export const FIELD_SIZE = FIELD_MODULUS;
export const TREE_DEPTH = PROTOCOL_COMMITMENT_TREE_DEPTH;

const DELIVERY_KEY_LABEL = "EIP-8182-delivery-scheme-1 key";
const DELIVERY_NONCE_LABEL = "EIP-8182-delivery-scheme-1 nonce";

type TomlScalar = string | number | boolean;
export type TomlValue = TomlScalar | TomlScalar[] | TomlTable | TomlTable[];
export interface TomlTable {
  [key: string]: TomlValue;
}

export interface PoseidonHelpers {
  h2: (a: bigint, b: bigint) => bigint;
  pHash: (values: bigint[]) => bigint;
}

export interface TransactionNote {
  amount: bigint;
  ownerAddress: bigint;
  randomness: bigint;
  nullifierKeyHash: bigint;
  tokenAddress: bigint;
  originTag: bigint;
}

export interface EncryptedNoteData {
  data: Uint8Array;
  hash: bigint;
}

export interface InnerProofArtifacts {
  innerProof: string[];
  innerVk: string[];
  innerVkHash: bigint;
  innerBbKeyHash: string;
}

export interface OuterWitnessOverrides {
  authorizingAddress?: bigint;
  policyVersion?: bigint;
}

export interface IntentWitness {
  authorizingAddress: bigint;
  policyVersion: bigint;
  operationKind: bigint;
  tokenAddress: bigint;
  recipientAddress: bigint;
  amount: bigint;
  feeRecipientAddress?: bigint;
  feeAmount?: bigint;
  originMode?: bigint;
  nonce: bigint;
  validUntilSeconds: bigint;
  executionChainId: bigint;
  executionConstraints: ExecutionConstraints;
  intentDigest: bigint;
}

export interface SingleSigAuthorizationWitness {
  policyVersion: bigint;
  operationKind: bigint;
  tokenAddress: bigint;
  recipientAddress: bigint;
  amount: bigint;
  feeRecipientAddress?: bigint;
  feeAmount?: bigint;
  originMode?: bigint;
  nonce: bigint;
  validUntilSeconds: bigint;
  executionChainId: bigint;
}

export interface TxProofParams {
  mode: "deposit" | "transfer" | "withdraw";
  depositorAddress?: string;
  senderAddress?: string;
  recipientAddress?: string;
  amount: string;
  tokenAddress?: string;
  feeRecipientAddress?: string;
  feeAmount?: string;
  feeNoteOwner?: string;
  nullifierKey: string;
  outputSecret: string;
  policyVersion?: string;
  originMode?: string;
  nonce: string;
  validUntilSeconds: string;
  executionChainId: string;
  commitmentRoot: string;
  userRegistryRoot: string;
  authPolicyRoot: string;
  inputLeafIndex?: string;
  inputAmount?: string;
  inputRandomness?: string;
  inputOriginTag?: string;
  inputSiblings?: unknown;
  userSiblings?: unknown;
  recipientSiblings?: unknown;
  authSiblings?: unknown;
  recipientNkHash?: string;
  recipientOsHash?: string;
  feeNkHash?: string;
  feeOsHash?: string;
  feeSiblings?: unknown;
  changeAmount?: string;
  deliverySchemeId?: string;
  deliveryPubKey?: string;
  recipientDeliverySchemeId?: string;
  recipientDeliveryPubKey?: string;
  changeDeliverySchemeId?: string;
  changeDeliveryPubKey?: string;
  feeDeliverySchemeId?: string;
  feeDeliveryPubKey?: string;
  executionConstraints?: {
    executionConstraintsFlags?: string;
    lockedOutputBinding0?: string;
    lockedOutputBinding1?: string;
    lockedOutputBinding2?: string;
  };
  outerAuthorizingAddress?: string;
  outerPolicyVersion?: string;
}

export interface CommonTxArtifacts {
  mode: TxProofParams["mode"];
  operationKind: bigint;
  authorizingAddress: bigint;
  recipientAddress: bigint;
  amount: bigint;
  tokenAddress: bigint;
  publicAmountIn: bigint;
  feeRecipientAddress: bigint;
  feeAmount: bigint;
  feeNoteOwner: bigint;
  nullifierKey: bigint;
  outputSecret: bigint;
  policyVersion: bigint;
  originMode: bigint;
  nonce: bigint;
  validUntilSeconds: bigint;
  executionChainId: bigint;
  commitmentRoot: bigint;
  userRegistryRoot: bigint;
  authPolicyRoot: bigint;
  nkHash: bigint;
  osHash: bigint;
  note0: TransactionNote;
  note1: TransactionNote;
  note2: TransactionNote;
  out0: bigint;
  out1: bigint;
  out2: bigint;
  enc0: EncryptedNoteData;
  enc1: EncryptedNoteData;
  enc2: EncryptedNoteData;
  executionConstraints: ExecutionConstraints;
  intentDigest: bigint;
  outputBinding0: bigint;
  outputBinding1: bigint;
  outputBinding2: bigint;
  intentNullifier: bigint;
  nullifier0: bigint;
  nullifier1: bigint;
  changeAmount: bigint;
  inputLeafIndex?: bigint;
  inputAmount?: bigint;
  inputRandomness?: bigint;
  inputOriginTag?: bigint;
  inputSiblings?: string[];
  userSiblings: string[];
  recipientSiblings: string[];
  recipientNkHash: bigint;
  recipientOsHash: bigint;
  feeSiblings: string[];
  feeNkHash: bigint;
  feeOsHash: bigint;
  authSiblings: string[];
  empty160: string[];
}

function buildToolEnv() {
  const toolHome =
    process.env.EIP8182_TOOL_HOME || resolve(os.tmpdir(), "eip8182-tool-home");
  mkdirSync(toolHome, { recursive: true });
  mkdirSync(CIRCUIT_SCRATCH_DIR, { recursive: true });

  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key.startsWith("npm_") || key.startsWith("BUN_")) delete env[key];
  }
  env.HOME = toolHome;
  env.NARGO_HOME = env.NARGO_HOME || resolve(toolHome, ".nargo");
  return env;
}

let scratchCounter = 0;

function nextScratchStem(prefix: string): string {
  mkdirSync(CIRCUIT_SCRATCH_DIR, { recursive: true });
  scratchCounter += 1;
  return resolve(
    CIRCUIT_SCRATCH_DIR,
    `${prefix}-${process.pid}-${Date.now()}-${scratchCounter}`,
  );
}

export async function withCircuitLock<T>(
  fn: () => Promise<T>,
  logger?: FfiLogger,
): Promise<T> {
  return withLoggedCircuitLock(CIRCUIT_LOCK_DIR, CIRCUIT_LOCK_STALE_MS, logger, fn);
}

export async function createPoseidonHelpers(): Promise<PoseidonHelpers> {
  const poseidon = await buildPoseidon();
  const h2 = (a: bigint, b: bigint): bigint =>
    BigInt(poseidon.F.toString(poseidon([a, b])));
  const rawHash = (values: bigint[]): bigint => {
    if (values.length === 1) return values[0];
    if (values.length === 2) return h2(values[0], values[1]);
    let leftSize = 1;
    while (leftSize * 2 < values.length) leftSize *= 2;
    return h2(rawHash(values.slice(0, leftSize)), rawHash(values.slice(leftSize)));
  };
  const pHash = (values: bigint[]): bigint => {
    if (values.length === 1) return values[0];
    return h2(BigInt(values.length), rawHash(values));
  };
  return { h2, pHash };
}

export function hex(value: bigint): string {
  return "0x" + value.toString(16);
}

export function toBigInt(value: string | bigint | undefined, fallback = 0n): bigint {
  if (value === undefined) return fallback;
  return typeof value === "bigint" ? value : BigInt(value);
}

function isLockSet(flags: bigint, lockBit: bigint): boolean {
  return (flags & lockBit) !== 0n
}

export function byteArrayStrings(bytes: Uint8Array): string[] {
  return Array.from(bytes).map((value) => value.toString());
}

export function fieldToBytes32(value: bigint): Uint8Array {
  return hexToBytes(`0x${value.toString(16).padStart(64, "0")}`);
}

export function foldFields(seed: bigint, values: bigint[], pHash: PoseidonHelpers["pHash"]): bigint {
  let acc = seed;
  for (const value of values) {
    acc = pHash([acc, value]);
  }
  return acc;
}

export function normalizeSiblingList(value: unknown): string[] | null {
  if (value === undefined || value === null) return null;
  if (Array.isArray(value)) return value.map((item) => String(item));
  return JSON.parse(String(value)) as string[];
}

export function emptyHashes(depth: number, h2: PoseidonHelpers["h2"]): string[] {
  const hashes: string[] = [];
  let current = 0n;
  for (let i = 0; i < depth; i++) {
    hashes.push(hex(current));
    current = h2(current, current);
  }
  return hashes;
}

export function resolveRegisteredDeliveryPubKey(
  schemeIdValue: string | bigint | undefined,
  keyValue: string | undefined,
): string | undefined {
  if (!keyValue) return undefined;
  const normalizedKey = bytesToHex(hexToBytes(keyValue));
  if (hexToBytes(normalizedKey).length !== X_WING_PUBLIC_KEY_LENGTH) return undefined;
  if (schemeIdValue === undefined) return normalizedKey;
  return toBigInt(schemeIdValue, 0n) === DELIVERY_SCHEME_X_WING
    ? normalizedKey
    : undefined;
}

function requiredRecipientField(
  field: string,
  mode: TxProofParams["mode"],
  recipient: bigint,
): never {
  throw new Error(
    `${field} required for ${mode} when recipientAddress ${hex(recipient)} differs from sender/depositor`,
  );
}

function requiredRecipientSiblings(
  mode: TxProofParams["mode"],
  recipient: bigint,
): never {
  throw new Error(
    `recipientSiblings required for ${mode} when recipientAddress ${hex(recipient)} differs from sender/depositor`,
  );
}

function requiredFeeField(field: string, feeNoteOwner: bigint): never {
  throw new Error(
    `${field} required when fee note owner ${hex(feeNoteOwner)} is not the sender or recipient`,
  );
}

function requiredFeeSiblings(feeNoteOwner: bigint): never {
  throw new Error(
    `feeSiblings required when fee note owner ${hex(feeNoteOwner)} is not the sender or recipient`,
  );
}

export function renderToml(document: TomlTable): string {
  const lines: string[] = [];

  const emitTable = (path: string[], table: TomlTable, isRoot: boolean) => {
    const scalarEntries: [string, TomlScalar | TomlScalar[]][] = [];
    const tableEntries: [string, TomlTable][] = [];
    const arrayTableEntries: [string, TomlTable[]][] = [];

    for (const [key, value] of Object.entries(table)) {
      if (Array.isArray(value)) {
        if (value.length > 0 && isPlainObject(value[0])) {
          arrayTableEntries.push([key, value as TomlTable[]]);
        } else {
          scalarEntries.push([key, value as TomlScalar[]]);
        }
      } else if (isPlainObject(value)) {
        tableEntries.push([key, value as TomlTable]);
      } else {
        scalarEntries.push([key, value as TomlScalar]);
      }
    }

    if (!isRoot && (scalarEntries.length > 0 || tableEntries.length > 0 || arrayTableEntries.length > 0)) {
      lines.push(`[${path.join(".")}]\n`);
    }

    for (const [key, value] of scalarEntries) {
      lines.push(`${key} = ${renderTomlScalarOrArray(value)}\n`);
    }

    for (const [key, value] of tableEntries) {
      if (!isRoot || scalarEntries.length > 0 || tableEntries.length > 0 || arrayTableEntries.length > 0) {
        lines.push("\n");
      }
      emitTable([...path, key], value, false);
    }

    for (const [key, tables] of arrayTableEntries) {
      for (const child of tables) {
        lines.push("\n");
        lines.push(`[[${[...path, key].join(".")}]]\n`);
        emitArrayTableBody(child);
      }
    }
  };

  const emitArrayTableBody = (table: TomlTable) => {
    const scalarEntries: [string, TomlScalar | TomlScalar[]][] = [];
    const tableEntries: [string, TomlTable][] = [];

    for (const [key, value] of Object.entries(table)) {
      if (Array.isArray(value)) {
        if (value.length > 0 && isPlainObject(value[0])) {
          throw new Error("nested array-of-table values are not supported");
        }
        scalarEntries.push([key, value as TomlScalar[]]);
      } else if (isPlainObject(value)) {
        tableEntries.push([key, value as TomlTable]);
      } else {
        scalarEntries.push([key, value as TomlScalar]);
      }
    }

    for (const [key, value] of scalarEntries) {
      lines.push(`${key} = ${renderTomlScalarOrArray(value)}\n`);
    }

    for (const [key, value] of tableEntries) {
      lines.push(`\n[${key}]\n`);
      emitNestedTableBody(value, key);
    }
  };

  const emitNestedTableBody = (table: TomlTable, prefix: string) => {
    const scalarEntries: [string, TomlScalar | TomlScalar[]][] = [];
    const tableEntries: [string, TomlTable][] = [];

    for (const [key, value] of Object.entries(table)) {
      if (Array.isArray(value)) {
        if (value.length > 0 && isPlainObject(value[0])) {
          throw new Error("nested array-of-table values are not supported");
        }
        scalarEntries.push([key, value as TomlScalar[]]);
      } else if (isPlainObject(value)) {
        tableEntries.push([key, value as TomlTable]);
      } else {
        scalarEntries.push([key, value as TomlScalar]);
      }
    }

    for (const [key, value] of scalarEntries) {
      lines.push(`${key} = ${renderTomlScalarOrArray(value)}\n`);
    }

    for (const [key, value] of tableEntries) {
      lines.push(`\n[${prefix}.${key}]\n`);
      emitNestedTableBody(value, `${prefix}.${key}`);
    }
  };

  emitTable([], document, true);
  return lines.join("").replace(/^\n+/, "");
}

function renderTomlScalarOrArray(value: TomlScalar | TomlScalar[]): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => renderTomlScalar(item)).join(", ")}]`;
  }
  return renderTomlScalar(value);
}

function renderTomlScalar(value: TomlScalar): string {
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return value.toString();
  return JSON.stringify(value);
}

function isPlainObject(value: unknown): value is TomlTable {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function execNoir(
  args: string,
  options?: { cwd?: string; timeout?: number; logger?: FfiLogger; stage?: string },
) {
  execLogged(args, {
    cwd: options?.cwd ?? CIRCUITS_DIR,
    timeout: options?.timeout ?? 120000,
    env: TOOL_ENV,
    logger: options?.logger,
    stage: options?.stage ?? args,
  });
}

export function runInnerCircuit(
  packageName: string,
  witness: TomlTable,
  outputDirName: string,
  pHash: PoseidonHelpers["pHash"],
  logger?: FfiLogger,
): InnerProofArtifacts {
  if (!bbVersionChecked) {
    assertBbVersion();
    bbVersionChecked = true;
  }
  const proverStem = nextScratchStem(`${packageName}-prover`);
  const witnessStem = nextScratchStem(`${packageName}-witness`);
  const outputDir = nextScratchStem(outputDirName);
  writeFileSync(`${proverStem}.toml`, renderToml(witness));
  logger?.log(`wrote prover inputs package=${packageName} path=${proverStem}.toml`);
  execNoir(`nargo execute --package ${packageName} --prover-name ${proverStem} ${witnessStem}`, {
    logger,
    stage: `nargo execute ${packageName}`,
  });
  execNoir(
    `${BB} prove -b ${CIRCUITS_DIR}/target/${packageName}.json -w ${witnessStem}.gz --write_vk -o ${outputDir}`,
    {
      logger,
      stage: `bb prove ${packageName}`,
    },
  );

  const innerProofBytes = readFileSync(resolve(outputDir, "proof"));
  const innerVkBytes = readFileSync(resolve(outputDir, "vk"));
  const innerVkHashBytes = readFileSync(resolve(outputDir, "vk_hash"));
  const innerProof = Array.from({ length: innerProofBytes.length / 32 }, (_, i) =>
    "0x" + innerProofBytes.slice(i * 32, (i + 1) * 32).toString("hex"),
  );
  const innerVk = Array.from({ length: innerVkBytes.length / 32 }, (_, i) =>
    "0x" + innerVkBytes.slice(i * 32, (i + 1) * 32).toString("hex"),
  );
  const innerVkHash = computeAuthVkHash(
    innerVk.map((value) => BigInt(value)),
    pHash,
  );

  return {
    innerProof,
    innerVk,
    innerVkHash,
    innerBbKeyHash: "0x" + innerVkHashBytes.toString("hex"),
  };
}

export function buildCommonTxArtifacts(
  params: TxProofParams,
  { h2, pHash }: PoseidonHelpers,
): CommonTxArtifacts {
  const authorizingAddress = toBigInt(params.senderAddress ?? params.depositorAddress);
  const recipientAddress = toBigInt(params.recipientAddress ?? params.depositorAddress);
  const amount = toBigInt(params.amount);
  const tokenAddress = toBigInt(params.tokenAddress, 0n);
  const feeRecipientAddress = toBigInt(params.feeRecipientAddress, 0n);
  const feeAmount = toBigInt(params.feeAmount, 0n);
  const nullifierKey = toBigInt(params.nullifierKey);
  const outputSecret = toBigInt(params.outputSecret);
  const policyVersion = toBigInt(params.policyVersion, 1n);
  const originMode = toBigInt(
    params.originMode,
    ORIGIN_MODE_DEFAULT,
  );
  const nonce = toBigInt(params.nonce);
  const validUntilSeconds = toBigInt(params.validUntilSeconds);
  const executionChainId = toBigInt(params.executionChainId);
  const commitmentRoot = toBigInt(params.commitmentRoot);
  const userRegistryRoot = toBigInt(params.userRegistryRoot);
  const authPolicyRoot = toBigInt(params.authPolicyRoot);
  const hasFee = feeAmount !== 0n;
  const requiresRecipientRegistry =
    params.mode === "deposit" || params.mode === "transfer";
  const operationKind =
    params.mode === "deposit"
      ? DEPOSIT_OPERATION_KIND
      : params.mode === "withdraw"
        ? WITHDRAWAL_OPERATION_KIND
        : TRANSFER_OPERATION_KIND;
  const publicAmountIn = params.mode === "deposit" ? amount + feeAmount : 0n;

  const nkHash = pHash([NK_DOMAIN, nullifierKey]);
  const osHash = pHash([OUTPUT_SECRET_DOMAIN, outputSecret]);
  const dummyNkHash = pHash([NK_DOMAIN, DUMMY_NK_PREIMAGE]);
  const recipientMatchesOwner = recipientAddress === authorizingAddress;
  const recipientNkHash =
    params.recipientNkHash !== undefined
      ? toBigInt(params.recipientNkHash)
      : !requiresRecipientRegistry
        ? 0n
      : recipientMatchesOwner
        ? nkHash
        : requiredRecipientField("recipientNkHash", params.mode, recipientAddress);
  const recipientOsHash =
    params.recipientOsHash !== undefined
      ? toBigInt(params.recipientOsHash)
      : !requiresRecipientRegistry
        ? 0n
      : recipientMatchesOwner
        ? osHash
        : requiredRecipientField("recipientOsHash", params.mode, recipientAddress);
  const empty160 = emptyHashes(160, h2);
  const userSiblings = normalizeSiblingList(params.userSiblings) ?? empty160;
  const recipientSiblings =
    normalizeSiblingList(params.recipientSiblings) ??
    (!requiresRecipientRegistry
      ? empty160
      : recipientMatchesOwner
        ? userSiblings
        : requiredRecipientSiblings(params.mode, recipientAddress));

  let feeNoteOwner = 0n;
  let feeNkHash = 0n;
  let feeOsHash = 0n;
  let feeSiblings = empty160;
  if (hasFee) {
    feeNoteOwner = toBigInt(
      params.feeNoteOwner,
      feeRecipientAddress !== 0n ? feeRecipientAddress : 0n,
    );
    if (feeNoteOwner === 0n) {
      throw new Error("feeNoteOwner required when feeAmount is nonzero and feeRecipientAddress is zero");
    }
    feeNkHash =
      params.feeNkHash !== undefined
        ? toBigInt(params.feeNkHash)
        : feeNoteOwner === authorizingAddress
          ? nkHash
          : feeNoteOwner === recipientAddress
            ? recipientNkHash
            : requiredFeeField("feeNkHash", feeNoteOwner);
    feeOsHash =
      params.feeOsHash !== undefined
        ? toBigInt(params.feeOsHash)
        : feeNoteOwner === authorizingAddress
          ? osHash
          : feeNoteOwner === recipientAddress
            ? recipientOsHash
            : requiredFeeField("feeOsHash", feeNoteOwner);
    feeSiblings =
      normalizeSiblingList(params.feeSiblings) ??
      (feeNoteOwner === authorizingAddress
        ? userSiblings
        : feeNoteOwner === recipientAddress
          ? recipientSiblings
          : requiredFeeSiblings(feeNoteOwner));
  }

  const intentNullifier = computeIntentNullifier(
    nullifierKey,
    authorizingAddress,
    executionChainId,
    nonce,
    pHash,
  );
  const outRand = [0n, 1n, 2n].map((salt) =>
    pHash([RANDOMNESS_DOMAIN, outputSecret, intentNullifier, salt]),
  );

  let nullifier0: bigint;
  let nullifier1: bigint;
  if (params.mode === "deposit") {
    nullifier0 = pHash([PHANTOM_DOMAIN, nullifierKey, intentNullifier, 0n]);
    nullifier1 = pHash([PHANTOM_DOMAIN, nullifierKey, intentNullifier, 1n]);
  } else {
    const inputRandomness = toBigInt(params.inputRandomness);
    nullifier0 = computeRealNullifier(nullifierKey, inputRandomness, pHash);
    nullifier1 = pHash([PHANTOM_DOMAIN, nullifierKey, intentNullifier, 1n]);
  }

  const derivedDepositOriginTag = pHash([
    ORIGIN_TAG_DOMAIN,
    executionChainId,
    authorizingAddress,
    tokenAddress,
    publicAmountIn,
    intentNullifier,
  ]);
  const propagatedOriginTag =
    params.mode === "deposit" ? 0n : toBigInt(params.inputOriginTag);
  const originTag =
    params.mode === "deposit"
      ? originMode === ORIGIN_MODE_DEFAULT
        ? 0n
        : derivedDepositOriginTag
      : propagatedOriginTag;
  const changeAmount =
    params.mode === "deposit"
      ? 0n
      : params.changeAmount !== undefined
        ? toBigInt(params.changeAmount)
        : params.inputAmount !== undefined
          ? toBigInt(params.inputAmount) - amount - feeAmount
          : 0n;
  if (changeAmount < 0n) {
    throw new Error("changeAmount cannot be negative");
  }

  let note0: TransactionNote;
  let note1: TransactionNote;
  let note2: TransactionNote;

  if (params.mode === "deposit") {
    note0 = {
      amount,
      ownerAddress: recipientAddress,
      randomness: outRand[0],
      nullifierKeyHash: recipientNkHash,
      tokenAddress,
      originTag,
    };
    note1 = {
      amount: 0n,
      ownerAddress: 0n,
      randomness: outRand[1],
      nullifierKeyHash: dummyNkHash,
      tokenAddress: 0n,
      originTag: 0n,
    };
    note2 = {
      amount: hasFee ? feeAmount : 0n,
      ownerAddress: hasFee ? feeNoteOwner : 0n,
      randomness: outRand[2],
      nullifierKeyHash: hasFee ? feeNkHash : dummyNkHash,
      tokenAddress: hasFee ? tokenAddress : 0n,
      originTag: hasFee ? originTag : 0n,
    };
  } else if (params.mode === "transfer") {
    note0 = {
      amount,
      ownerAddress: recipientAddress,
      randomness: outRand[0],
      nullifierKeyHash: recipientNkHash,
      tokenAddress,
      originTag,
    };
    note1 =
      changeAmount > 0n
        ? {
            amount: changeAmount,
            ownerAddress: authorizingAddress,
            randomness: outRand[1],
            nullifierKeyHash: nkHash,
            tokenAddress,
            originTag,
          }
        : {
            amount: 0n,
            ownerAddress: 0n,
            randomness: outRand[1],
            nullifierKeyHash: dummyNkHash,
            tokenAddress: 0n,
            originTag: 0n,
          };
    note2 = {
      amount: hasFee ? feeAmount : 0n,
      ownerAddress: hasFee ? feeNoteOwner : 0n,
      randomness: outRand[2],
      nullifierKeyHash: hasFee ? feeNkHash : dummyNkHash,
      tokenAddress: hasFee ? tokenAddress : 0n,
      originTag: hasFee ? originTag : 0n,
    };
  } else {
    note0 =
      changeAmount > 0n
        ? {
            amount: changeAmount,
            ownerAddress: authorizingAddress,
            randomness: outRand[0],
            nullifierKeyHash: nkHash,
            tokenAddress,
            originTag,
          }
        : {
            amount: 0n,
            ownerAddress: 0n,
            randomness: outRand[0],
            nullifierKeyHash: dummyNkHash,
            tokenAddress: 0n,
            originTag: 0n,
          };
    note1 = {
      amount: 0n,
      ownerAddress: 0n,
      randomness: outRand[1],
      nullifierKeyHash: dummyNkHash,
      tokenAddress: 0n,
      originTag: 0n,
    };
    note2 = {
      amount: hasFee ? feeAmount : 0n,
      ownerAddress: hasFee ? feeNoteOwner : 0n,
      randomness: outRand[2],
      nullifierKeyHash: hasFee ? feeNkHash : dummyNkHash,
      tokenAddress: hasFee ? tokenAddress : 0n,
      originTag: hasFee ? originTag : 0n,
    };
  }

  const out0 = pHash([
    note0.amount,
    note0.ownerAddress,
    note0.randomness,
    note0.nullifierKeyHash,
    note0.tokenAddress,
    note0.originTag,
  ]);
  const out1 = pHash([
    note1.amount,
    note1.ownerAddress,
    note1.randomness,
    note1.nullifierKeyHash,
    note1.tokenAddress,
    note1.originTag,
  ]);
  const out2 = pHash([
    note2.amount,
    note2.ownerAddress,
    note2.randomness,
    note2.nullifierKeyHash,
    note2.tokenAddress,
    note2.originTag,
  ]);

  const defaultDeliveryKey = resolveRegisteredDeliveryPubKey(
    params.deliverySchemeId,
    params.deliveryPubKey,
  );
  const recipientDeliveryKey =
    resolveRegisteredDeliveryPubKey(
      params.recipientDeliverySchemeId,
      params.recipientDeliveryPubKey,
    ) || (recipientMatchesOwner ? defaultDeliveryKey : undefined);
  const note0DeliveryKey =
    params.mode === "deposit" || params.mode === "transfer"
      ? recipientDeliveryKey
      : defaultDeliveryKey;
  const note1DeliveryKey =
    params.mode === "transfer"
      ? resolveRegisteredDeliveryPubKey(
          params.changeDeliverySchemeId,
          params.changeDeliveryPubKey,
        ) || defaultDeliveryKey
      : defaultDeliveryKey;
  const feeDeliveryKey =
    resolveRegisteredDeliveryPubKey(
      params.feeDeliverySchemeId,
      params.feeDeliveryPubKey,
    ) ||
    (hasFee
      ? feeNoteOwner === authorizingAddress
        ? defaultDeliveryKey
        : feeNoteOwner === recipientAddress
          ? recipientDeliveryKey
          : undefined
      : defaultDeliveryKey);
  const enc0 = encryptNoteData(note0, note0DeliveryKey);
  const enc1 = encryptNoteData(note1, note1DeliveryKey);
  const enc2 = encryptNoteData(note2, feeDeliveryKey);
  const outputBinding0 = computeOutputBinding(out0, enc0.hash, pHash);
  const outputBinding1 = computeOutputBinding(out1, enc1.hash, pHash);
  const outputBinding2 = computeOutputBinding(out2, enc2.hash, pHash);
  const requestedConstraints = normalizeExecutionConstraints({
    executionConstraintsFlags:
      params.executionConstraints?.executionConstraintsFlags === undefined
        ? defaultExecutionConstraints().executionConstraintsFlags
        : toBigInt(params.executionConstraints.executionConstraintsFlags),
    lockedOutputBinding0:
      params.executionConstraints?.lockedOutputBinding0 === undefined
        ? undefined
        : toBigInt(params.executionConstraints.lockedOutputBinding0),
    lockedOutputBinding1:
      params.executionConstraints?.lockedOutputBinding1 === undefined
        ? undefined
        : toBigInt(params.executionConstraints.lockedOutputBinding1),
    lockedOutputBinding2:
      params.executionConstraints?.lockedOutputBinding2 === undefined
        ? undefined
        : toBigInt(params.executionConstraints.lockedOutputBinding2),
  });
  const executionConstraints: ExecutionConstraints = {
    executionConstraintsFlags: requestedConstraints.executionConstraintsFlags,
    lockedOutputBinding0:
      requestedConstraints.lockedOutputBinding0 !== 0n
        ? requestedConstraints.lockedOutputBinding0
        : isLockSet(requestedConstraints.executionConstraintsFlags, LOCK_OUTPUT_BINDING_0)
          ? outputBinding0
          : 0n,
    lockedOutputBinding1:
      requestedConstraints.lockedOutputBinding1 !== 0n
        ? requestedConstraints.lockedOutputBinding1
        : isLockSet(requestedConstraints.executionConstraintsFlags, LOCK_OUTPUT_BINDING_1)
          ? outputBinding1
          : 0n,
    lockedOutputBinding2:
      requestedConstraints.lockedOutputBinding2 !== 0n
        ? requestedConstraints.lockedOutputBinding2
        : isLockSet(requestedConstraints.executionConstraintsFlags, LOCK_OUTPUT_BINDING_2)
          ? outputBinding2
          : 0n,
  };
  const intentDigest = computeIntentDigest(
    {
      authorizingAddress,
      policyVersion,
      operationKind,
      tokenAddress,
      recipientAddress,
      amount,
      feeRecipientAddress,
      feeAmount,
      originMode,
      nonce,
      validUntilSeconds,
      executionChainId,
      executionConstraints,
    },
    pHash,
  );

  return {
    mode: params.mode,
    operationKind,
    authorizingAddress,
    recipientAddress,
    amount,
    tokenAddress,
    publicAmountIn,
    feeRecipientAddress,
    feeAmount,
    feeNoteOwner,
    nullifierKey,
    outputSecret,
    policyVersion,
    originMode,
    nonce,
    validUntilSeconds,
    executionChainId,
    commitmentRoot,
    userRegistryRoot,
    authPolicyRoot,
    nkHash,
    osHash,
    note0,
    note1,
    note2,
    out0,
    out1,
    out2,
    enc0,
    enc1,
    enc2,
    executionConstraints,
    intentDigest,
    outputBinding0,
    outputBinding1,
    outputBinding2,
    intentNullifier,
    nullifier0,
    nullifier1,
    changeAmount,
    inputLeafIndex: params.inputLeafIndex === undefined ? undefined : toBigInt(params.inputLeafIndex),
    inputAmount: params.inputAmount === undefined ? undefined : toBigInt(params.inputAmount),
    inputRandomness:
      params.inputRandomness === undefined ? undefined : toBigInt(params.inputRandomness),
    inputOriginTag: params.inputOriginTag === undefined ? undefined : toBigInt(params.inputOriginTag),
    inputSiblings: normalizeSiblingList(params.inputSiblings) ?? undefined,
    userSiblings,
    recipientSiblings,
    recipientNkHash,
    recipientOsHash,
    feeSiblings,
    feeNkHash,
    feeOsHash,
    authSiblings: normalizeSiblingList(params.authSiblings) ?? empty160,
    empty160,
  };
}

function deriveKeyAndNonce(sharedSecret: Uint8Array): { key: Uint8Array; nonce: Uint8Array } {
  const prk = extract(sha256, sharedSecret, new Uint8Array(0));
  const key = expand(sha256, prk, DELIVERY_KEY_LABEL, 32);
  const nonce = expand(sha256, prk, DELIVERY_NONCE_LABEL, 12);
  return { key, nonce };
}

function encodeNote(note: TransactionNote): Uint8Array {
  const buf = new Uint8Array(192);
  writeUint256Bytes(buf, 0, note.amount);
  writeUint256Bytes(buf, 32, note.ownerAddress);
  writeUint256Bytes(buf, 64, note.randomness);
  writeUint256Bytes(buf, 96, note.nullifierKeyHash);
  writeUint256Bytes(buf, 128, note.tokenAddress);
  writeUint256Bytes(buf, 160, note.originTag);
  return buf;
}

function writeUint256Bytes(buf: Uint8Array, offset: number, value: bigint) {
  const hexValue = value.toString(16).padStart(64, "0");
  for (let i = 0; i < 32; i++) {
    buf[offset + i] = parseInt(hexValue.slice(i * 2, i * 2 + 2), 16);
  }
}

function noteDataHash(data: Uint8Array): bigint {
  const digest = keccak_256(data);
  let value = 0n;
  for (const byte of digest) value = (value << 8n) | BigInt(byte);
  return value % FIELD_SIZE;
}

function encryptNoteData(note: TransactionNote, deliveryKey?: string): EncryptedNoteData {
  if (note.amount === 0n) {
    const dummy = new Uint8Array(randomBytes(1328));
    return { data: dummy, hash: noteDataHash(dummy) };
  }
  if (!deliveryKey) {
    throw new Error("deliveryPubKey required for non-dummy notes");
  }
  const pubKey = hexToBytes(deliveryKey);
  const { sharedSecret, cipherText } = XWing.encapsulate(pubKey);
  const { key, nonce } = deriveKeyAndNonce(sharedSecret);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const ct = Buffer.concat([cipher.update(encodeNote(note)), cipher.final()]);
  const tag = cipher.getAuthTag();
  const result = new Uint8Array(1328);
  result.set(cipherText, 0);
  result.set(ct, 1120);
  result.set(tag, 1312);
  return { data: result, hash: noteDataHash(result) };
}

export function buildInnerBaseWitness(common: CommonTxArtifacts): TomlTable {
  return buildInnerBaseWitnessFromIntent(
    {
      authorizingAddress: common.authorizingAddress,
      policyVersion: common.policyVersion,
      operationKind: common.operationKind,
      tokenAddress: common.tokenAddress,
      recipientAddress: common.recipientAddress,
      amount: common.amount,
      feeRecipientAddress: common.feeRecipientAddress,
      feeAmount: common.feeAmount,
      originMode: common.originMode,
      nonce: common.nonce,
      validUntilSeconds: common.validUntilSeconds,
      executionChainId: common.executionChainId,
      executionConstraints: common.executionConstraints,
      intentDigest: common.intentDigest,
    },
  );
}

export function buildSingleSigAuthorizationWitness(
  common: CommonTxArtifacts,
): TomlTable {
  return buildSingleSigAuthorizationWitnessFromIntent({
    policyVersion: common.policyVersion,
    operationKind: common.operationKind,
    tokenAddress: common.tokenAddress,
    recipientAddress: common.recipientAddress,
    amount: common.amount,
    feeRecipientAddress: common.feeRecipientAddress,
    feeAmount: common.feeAmount,
    originMode: common.originMode,
    nonce: common.nonce,
    validUntilSeconds: common.validUntilSeconds,
    executionChainId: common.executionChainId,
  });
}

export function buildInnerBaseWitnessFromIntent(
  intent: IntentWitness,
): TomlTable {
  return {
    intent: {
      authorizing_address: hex(intent.authorizingAddress),
      policy_version: hex(intent.policyVersion),
      operation_kind: hex(intent.operationKind),
      token_address: hex(intent.tokenAddress),
      recipient_address: hex(intent.recipientAddress),
      amount: hex(intent.amount),
      fee_recipient_address: hex(intent.feeRecipientAddress ?? 0n),
      fee_amount: hex(intent.feeAmount ?? 0n),
      origin_mode: hex(
        intent.originMode ?? ORIGIN_MODE_DEFAULT,
      ),
      execution_constraints: {
        execution_constraints_flags: hex(
          intent.executionConstraints.executionConstraintsFlags,
        ),
        locked_output_binding0: hex(
          intent.executionConstraints.lockedOutputBinding0,
        ),
        locked_output_binding1: hex(
          intent.executionConstraints.lockedOutputBinding1,
        ),
        locked_output_binding2: hex(
          intent.executionConstraints.lockedOutputBinding2,
        ),
      },
      nonce: hex(intent.nonce),
      valid_until_seconds: hex(intent.validUntilSeconds),
      execution_chain_id: hex(intent.executionChainId),
    },
  };
}

export function buildSingleSigAuthorizationWitnessFromIntent(
  intent: SingleSigAuthorizationWitness,
): TomlTable {
  return {
    authorization: {
      policy_version: hex(intent.policyVersion),
      operation_kind: hex(intent.operationKind),
      token_address: hex(intent.tokenAddress),
      recipient_address: hex(intent.recipientAddress),
      amount: hex(intent.amount),
      fee_recipient_address: hex(intent.feeRecipientAddress ?? 0n),
      fee_amount: hex(intent.feeAmount ?? 0n),
      origin_mode: hex(
        intent.originMode ?? ORIGIN_MODE_DEFAULT,
      ),
      nonce: byteArrayStrings(fieldToBytes32(intent.nonce)),
      valid_until_seconds: hex(intent.validUntilSeconds),
    },
    execution_chain_id: hex(intent.executionChainId),
    pool_address: hex(PROTOCOL_VERIFYING_CONTRACT_FIELD),
  };
}

export function assertAuthPolicyRoot(
  common: CommonTxArtifacts,
  authDataCommitment: bigint,
  innerVkHash: bigint,
  { h2, pHash }: PoseidonHelpers,
) {
  let authRoot = pHash([AUTH_POLICY_DOMAIN, authDataCommitment, common.policyVersion]);
  const authKeyFull = pHash([
    AUTH_POLICY_KEY_DOMAIN,
    common.authorizingAddress,
    innerVkHash,
  ]);
  const authKey = authKeyFull & ((1n << 160n) - 1n);
  for (let i = 0; i < 160; i++) {
    const bit = Number((authKey >> BigInt(i)) & 1n);
    const sibling = BigInt(common.authSiblings[i]);
    authRoot = bit === 0 ? h2(authRoot, sibling) : h2(sibling, authRoot);
  }

  if (authRoot !== common.authPolicyRoot) {
    throw new Error(
      `authPolicyRoot mismatch: expected ${hex(authRoot)}, got ${hex(common.authPolicyRoot)}`,
    );
  }
}

export function proveOuterTransaction(
  common: CommonTxArtifacts,
  authDataCommitment: bigint,
  inner: InnerProofArtifacts,
  logger?: FfiLogger,
  overrides?: OuterWitnessOverrides,
): {
  proof: string;
  publicInputs: string[];
  outputNoteData: [string, string, string];
  note0: { amount: string; randomness: string; originTag: string };
  note1: { amount: string; randomness: string; originTag: string };
} {
  const outerAuthorizingAddress =
    overrides?.authorizingAddress ?? common.authorizingAddress;
  const outerPolicyVersion = overrides?.policyVersion ?? common.policyVersion;
  const outerWitness: TomlTable = {
    merkle_root: hex(common.commitmentRoot),
    nullifier0_out: hex(common.nullifier0),
    nullifier1_out: hex(common.nullifier1),
    commitment0_out: hex(common.out0),
    commitment1_out: hex(common.out1),
    commitment2_out: hex(common.out2),
    public_amount_in:
      common.mode === "deposit" ? hex(common.publicAmountIn) : "0",
    public_amount_out:
      common.mode === "withdraw" ? hex(common.amount) : "0",
    public_recipient:
      common.mode === "withdraw" ? hex(common.recipientAddress) : "0",
    public_token_address:
      common.mode === "deposit" || common.mode === "withdraw"
        ? hex(common.tokenAddress)
        : "0",
    depositor_address:
      common.mode === "deposit" ? hex(common.authorizingAddress) : "0",
    intent_nullifier_out: hex(common.intentNullifier),
    registry_root: hex(common.userRegistryRoot),
    valid_until_seconds: hex(common.validUntilSeconds),
    execution_chain_id: hex(common.executionChainId),
    auth_policy_registry_root: hex(common.authPolicyRoot),
    output_note_data_hash0: hex(common.enc0.hash),
    output_note_data_hash1: hex(common.enc1.hash),
    output_note_data_hash2: hex(common.enc2.hash),
    transfer_recipient_address: hex(common.recipientAddress),
    payment_amount: common.mode === "withdraw" ? "0" : hex(common.amount),
    private_token_address: hex(common.tokenAddress),
    change_amount: hex(common.changeAmount),
    fee_recipient_address: hex(common.feeRecipientAddress),
    fee_amount: hex(common.feeAmount),
    origin_mode: hex(common.originMode),
    fee_note_owner: hex(common.feeNoteOwner),
    inner_vk: inner.innerVk,
    inner_proof: inner.innerProof,
    inner_bb_key_hash: inner.innerBbKeyHash,
    authorizing_address: hex(outerAuthorizingAddress),
    auth_data_commitment: hex(authDataCommitment),
    intent_digest_out: hex(common.intentDigest),
    policy_version: hex(outerPolicyVersion),
    nonce: hex(common.nonce),
    nullifier_key: hex(common.nullifierKey),
    output_secret: hex(common.outputSecret),
    execution_constraints_flags: hex(
      common.executionConstraints.executionConstraintsFlags,
    ),
    locked_output_binding0: hex(common.executionConstraints.lockedOutputBinding0),
    locked_output_binding1: hex(common.executionConstraints.lockedOutputBinding1),
    locked_output_binding2: hex(common.executionConstraints.lockedOutputBinding2),
    sender_leaf: {
      nullifier_key_hash: hex(common.nkHash),
      output_secret_hash: hex(common.osHash),
    },
    sender_witness: {
      siblings: common.userSiblings,
    },
    recipient_leaf: {
      nullifier_key_hash: hex(common.recipientNkHash),
      output_secret_hash: hex(common.recipientOsHash),
    },
    recipient_witness: {
      siblings: common.recipientSiblings,
    },
    sponsor_leaf: {
      nullifier_key_hash: hex(common.feeNkHash),
      output_secret_hash: hex(common.feeOsHash),
    },
    sponsor_witness: {
      siblings: common.feeSiblings,
    },
    auth_witness: {
      siblings: common.authSiblings,
    },
  };

  if (common.mode === "deposit") {
    const phantomInput = {
      is_phantom: true,
      leaf_index: 0,
      siblings: Array(TREE_DEPTH).fill("0"),
      note: {
        amount: "0",
        owner_address: "0",
        randomness: "0",
        nullifier_key_hash: "0",
        token_address: "0",
        origin_tag: "0",
      },
    };
    outerWitness.input0 = phantomInput;
    outerWitness.input1 = phantomInput;
  } else {
    if (
      common.inputLeafIndex === undefined ||
      common.inputAmount === undefined ||
      common.inputRandomness === undefined ||
      common.inputOriginTag === undefined ||
      !common.inputSiblings
    ) {
      throw new Error("input witnesses required for transfer and withdraw proofs");
    }
    outerWitness.input0 = {
      is_phantom: false,
      leaf_index: Number(common.inputLeafIndex),
      siblings: common.inputSiblings,
      note: {
        amount: hex(common.inputAmount),
        owner_address: hex(common.authorizingAddress),
        randomness: hex(common.inputRandomness),
        nullifier_key_hash: hex(common.nkHash),
        token_address: hex(common.tokenAddress),
        origin_tag: hex(common.inputOriginTag),
      },
    };
    outerWitness.input1 = {
      is_phantom: true,
      leaf_index: 0,
      siblings: Array(TREE_DEPTH).fill("0"),
      note: {
        amount: "0",
        owner_address: "0",
        randomness: "0",
        nullifier_key_hash: "0",
        token_address: "0",
        origin_tag: "0",
      },
    };
  }

  const proverStem = nextScratchStem("outer-prover");
  const witnessStem = nextScratchStem("outer-witness");
  const outputDir = nextScratchStem("outer-prove");
  writeFileSync(`${proverStem}.toml`, renderToml(outerWitness));
  logger?.log(`wrote prover inputs package=outer path=${proverStem}.toml`);
  execNoir(`nargo execute --package outer --prover-name ${proverStem} ${witnessStem}`, {
    timeout: 600000,
    logger,
    stage: "nargo execute outer",
  });
  execNoir(
    `${BB} prove -b ${CIRCUITS_DIR}/target/outer.json -w ${witnessStem}.gz --write_vk -o ${outputDir} -t evm`,
    { timeout: 600000, logger, stage: "bb prove outer" },
  );

  const outerProof = readFileSync(resolve(outputDir, "proof"));
  const outerPi = readFileSync(resolve(outputDir, "public_inputs"));

  return {
    proof: "0x" + outerProof.toString("hex"),
    publicInputs: Array.from({ length: outerPi.length / 32 }, (_, i) =>
      "0x" + outerPi.slice(i * 32, (i + 1) * 32).toString("hex").padStart(64, "0"),
    ),
    outputNoteData: [
      bytesToHex(common.enc0.data),
      bytesToHex(common.enc1.data),
      bytesToHex(common.enc2.data),
    ],
    note0: {
      amount: hex(common.note0.amount),
      randomness: hex(common.note0.randomness),
      originTag: hex(common.note0.originTag),
    },
    note1: {
      amount: hex(common.note1.amount),
      randomness: hex(common.note1.randomness),
      originTag: hex(common.note1.originTag),
    },
  };
}

export const PROTOCOL_POOL_ADDRESS = PROTOCOL_VERIFYING_CONTRACT_FIELD;
