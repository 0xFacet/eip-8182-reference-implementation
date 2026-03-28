import { execFileSync } from "child_process";
import { mkdtempSync, readFileSync } from "fs";
import os from "os";
import { resolve } from "path";
import { performance } from "perf_hooks";
import * as secp from "@noble/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { XWing } from "@noble/post-quantum/hybrid.js";
import {
  AUTH_POLICY_DOMAIN,
  AUTH_POLICY_KEY_DOMAIN,
  NK_DOMAIN,
  OUTPUT_SECRET_DOMAIN,
  USER_REGISTRY_LEAF_DOMAIN,
  computeAuthVkHash,
  computeSingleSigAuthorizationSigningHash,
  hexToBytes,
  secp256k1PubkeyToAddress,
  singleSigAuthDataCommitment,
} from "../../src/lib/protocol.ts";
import {
  BB,
  CIRCUITS_DIR,
  TOOL_ENV,
  assertAuthPolicyRoot,
  buildCommonTxArtifacts,
  buildSingleSigAuthorizationWitness,
  byteArrayStrings,
  createPoseidonHelpers,
  hex,
  proveOuterTransaction,
  runInnerCircuit,
  type PoseidonHelpers,
  type TomlTable,
  type TxProofParams,
} from "./tx_proof_shared.ts";

type CaseName = "deposit" | "transfer" | "withdraw";

interface UserFixture {
  address: bigint;
  nk: bigint;
  os: bigint;
  ds: bigint;
  nkHash: bigint;
  osHash: bigint;
  authDataCommitment: bigint;
  deliveryPubKey: string;
  signingPrivateKey: string;
}

interface BenchCase {
  name: CaseName;
  params: TxProofParams & { signingPrivateKey: string };
}

interface BenchResult {
  case: CaseName;
  innerMs: number;
  outerMs: number;
  totalMs: number;
}

const ALICE_SIGNING_PRIVATE_KEY =
  "0x0000000000000000000000000000000000000000000000000000000000000001";
const BOB_SIGNING_PRIVATE_KEY =
  "0x0123456789012345678901234567890123456789012345678901234567890123";
const ALICE_NULLIFIER_KEY = 0x9999n;
const ALICE_OUTPUT_SECRET = 0xbeefn;
const ALICE_DELIVERY_SECRET = 0xcafen;
const BOB_NULLIFIER_KEY = 0x7777n;
const BOB_OUTPUT_SECRET = 0xd00dn;
const BOB_DELIVERY_SECRET = 0xf00dn;
const DEPOSIT_AMOUNT = 1_000_000_000_000_000_000n;
const TRANSFER_AMOUNT = 350_000_000_000_000_000n;
const WITHDRAW_AMOUNT = 400_000_000_000_000_000n;
const EXECUTION_CHAIN_ID = 31337n;
const VALID_UNTIL_SECONDS = 1_700_000_000n;
const PUBLIC_RECIPIENT = 0xA11CE00000000000000000000000000000000001n;

async function main() {
  const { json, requestedCase } = parseArgs(process.argv.slice(2));

  const helpers = await createPoseidonHelpers();
  const innerVkHash = computeInnerVkHash("eip712", helpers);
  const alice = buildUserFixture(
    ALICE_NULLIFIER_KEY,
    ALICE_OUTPUT_SECRET,
    ALICE_DELIVERY_SECRET,
    ALICE_SIGNING_PRIVATE_KEY,
    helpers,
  );
  const bob = buildUserFixture(
    BOB_NULLIFIER_KEY,
    BOB_OUTPUT_SECRET,
    BOB_DELIVERY_SECRET,
    BOB_SIGNING_PRIVATE_KEY,
    helpers,
  );
  const cases = buildCases(helpers, innerVkHash, alice, bob).filter((entry) =>
    requestedCase ? entry.name === requestedCase : true,
  );

  const results: BenchResult[] = [];
  for (const entry of cases) {
    console.error(`running ${entry.name}...`);
    results.push(await benchmarkCase(entry, helpers));
  }

  if (json) {
    process.stdout.write(`${JSON.stringify(results, null, 2)}\n`);
    return;
  }

  printTable(results);
}

function parseArgs(args: string[]): { json: boolean; requestedCase: CaseName | null } {
  let json = false;
  let requestedCase: CaseName | null = null;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--json") {
      json = true;
      continue;
    }
    if (arg === "--case") {
      const next = args[index + 1];
      if (next !== "deposit" && next !== "transfer" && next !== "withdraw") {
        throw new Error("usage: tsx integration/src/benchmark_eip712_proofs.ts [--json] [--case deposit|transfer|withdraw]");
      }
      requestedCase = next;
      index += 1;
      continue;
    }
    throw new Error("usage: tsx integration/src/benchmark_eip712_proofs.ts [--json] [--case deposit|transfer|withdraw]");
  }

  return { json, requestedCase };
}

function buildUserFixture(
  nk: bigint,
  osSecret: bigint,
  ds: bigint,
  signingPrivateKey: string,
  helpers: PoseidonHelpers,
): UserFixture {
  const privateKey = hexToBytes(signingPrivateKey);
  const publicKey = secp.getPublicKey(privateKey, false);
  const pubKeyX = publicKey.slice(1, 33);
  const pubKeyY = publicKey.slice(33, 65);
  const address = secp256k1PubkeyToAddress(pubKeyX, pubKeyY);
  const authDataCommitment = singleSigAuthDataCommitment(pubKeyX, pubKeyY, helpers.pHash);
  const seed = keccak_256(new TextEncoder().encode(`xwing-delivery-${ds.toString()}`));
  const { publicKey: deliveryPubKey } = XWing.keygen(seed);

  return {
    address,
    nk,
    os: osSecret,
    ds,
    nkHash: helpers.pHash([NK_DOMAIN, nk]),
    osHash: helpers.pHash([OUTPUT_SECRET_DOMAIN, osSecret]),
    authDataCommitment,
    deliveryPubKey:
      "0x" +
      Array.from(deliveryPubKey)
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join(""),
    signingPrivateKey,
  };
}

function buildCases(
  helpers: PoseidonHelpers,
  innerVkHash: bigint,
  alice: UserFixture,
  bob: UserFixture,
): BenchCase[] {
  const aliceUserLeaf = helpers.pHash([
    USER_REGISTRY_LEAF_DOMAIN,
    alice.address,
    alice.nkHash,
    alice.osHash,
  ]);
  const bobUserLeaf = helpers.pHash([
    USER_REGISTRY_LEAF_DOMAIN,
    bob.address,
    bob.nkHash,
    bob.osHash,
  ]);

  const aliceRegistry = merkleRootAndSiblings(
    [{ index: alice.address, value: aliceUserLeaf }],
    alice.address,
    160,
    helpers,
  );
  const aliceBobRegistryForAlice = merkleRootAndSiblings(
    [
      { index: alice.address, value: aliceUserLeaf },
      { index: bob.address, value: bobUserLeaf },
    ],
    alice.address,
    160,
    helpers,
  );
  const aliceBobRegistryForBob = merkleRootAndSiblings(
    [
      { index: alice.address, value: aliceUserLeaf },
      { index: bob.address, value: bobUserLeaf },
    ],
    bob.address,
    160,
    helpers,
  );

  const aliceAuthKey =
    helpers.pHash([AUTH_POLICY_KEY_DOMAIN, alice.address, innerVkHash]) &
    ((1n << 160n) - 1n);
  const aliceAuthLeaf = helpers.pHash([
    AUTH_POLICY_DOMAIN,
    alice.authDataCommitment,
    1n,
  ]);
  const aliceAuth = merkleRootAndSiblings(
    [{ index: aliceAuthKey, value: aliceAuthLeaf }],
    aliceAuthKey,
    160,
    helpers,
  );

  const depositParams: TxProofParams & { signingPrivateKey: string } = {
    mode: "deposit",
    depositorAddress: hex(alice.address),
    amount: DEPOSIT_AMOUNT.toString(),
    tokenAddress: "0",
    nullifierKey: hex(alice.nk),
    outputSecret: hex(alice.os),
    policyVersion: "1",
    nonce: "42",
    validUntilSeconds: VALID_UNTIL_SECONDS.toString(),
    executionChainId: EXECUTION_CHAIN_ID.toString(),
    commitmentRoot: hex(emptyRoot(32, helpers)),
    userRegistryRoot: hex(aliceRegistry.root),
    authPolicyRoot: hex(aliceAuth.root),
    userSiblings: aliceRegistry.siblings,
    recipientSiblings: aliceRegistry.siblings,
    authSiblings: aliceAuth.siblings,
    deliverySchemeId: "1",
    deliveryPubKey: alice.deliveryPubKey,
    signingPrivateKey: alice.signingPrivateKey,
  };

  const depositCommon = buildCommonTxArtifacts(depositParams, helpers);
  const postDepositCommitments = merkleRootAndSiblings(
    [
      { index: 0n, value: depositCommon.out0 },
      { index: 1n, value: depositCommon.out1 },
      { index: 2n, value: depositCommon.out2 },
    ],
    0n,
    32,
    helpers,
  );

  const transferParams: TxProofParams & { signingPrivateKey: string } = {
    mode: "transfer",
    senderAddress: hex(alice.address),
    recipientAddress: hex(bob.address),
    amount: TRANSFER_AMOUNT.toString(),
    tokenAddress: "0",
    nullifierKey: hex(alice.nk),
    outputSecret: hex(alice.os),
    policyVersion: "1",
    nonce: "44",
    validUntilSeconds: VALID_UNTIL_SECONDS.toString(),
    executionChainId: EXECUTION_CHAIN_ID.toString(),
    commitmentRoot: hex(postDepositCommitments.root),
    userRegistryRoot: hex(aliceBobRegistryForAlice.root),
    authPolicyRoot: hex(aliceAuth.root),
    inputLeafIndex: "0",
    inputAmount: depositCommon.note0.amount.toString(),
    inputRandomness: hex(depositCommon.note0.randomness),
    inputOriginTag: hex(depositCommon.note0.originTag),
    inputSiblings: postDepositCommitments.siblings,
    userSiblings: aliceBobRegistryForAlice.siblings,
    recipientSiblings: aliceBobRegistryForBob.siblings,
    authSiblings: aliceAuth.siblings,
    recipientNkHash: hex(bob.nkHash),
    recipientOsHash: hex(bob.osHash),
    changeAmount: (depositCommon.note0.amount - TRANSFER_AMOUNT).toString(),
    recipientDeliverySchemeId: "1",
    recipientDeliveryPubKey: bob.deliveryPubKey,
    changeDeliverySchemeId: "1",
    changeDeliveryPubKey: alice.deliveryPubKey,
    signingPrivateKey: alice.signingPrivateKey,
  };

  const withdrawParams: TxProofParams & { signingPrivateKey: string } = {
    mode: "withdraw",
    senderAddress: hex(alice.address),
    recipientAddress: hex(PUBLIC_RECIPIENT),
    amount: WITHDRAW_AMOUNT.toString(),
    tokenAddress: "0",
    nullifierKey: hex(alice.nk),
    outputSecret: hex(alice.os),
    policyVersion: "1",
    nonce: "43",
    validUntilSeconds: VALID_UNTIL_SECONDS.toString(),
    executionChainId: EXECUTION_CHAIN_ID.toString(),
    commitmentRoot: hex(postDepositCommitments.root),
    userRegistryRoot: hex(aliceRegistry.root),
    authPolicyRoot: hex(aliceAuth.root),
    inputLeafIndex: "0",
    inputAmount: depositCommon.note0.amount.toString(),
    inputRandomness: hex(depositCommon.note0.randomness),
    inputOriginTag: hex(depositCommon.note0.originTag),
    inputSiblings: postDepositCommitments.siblings,
    userSiblings: aliceRegistry.siblings,
    authSiblings: aliceAuth.siblings,
    deliverySchemeId: "1",
    deliveryPubKey: alice.deliveryPubKey,
    signingPrivateKey: alice.signingPrivateKey,
  };

  return [
    { name: "deposit", params: depositParams },
    { name: "transfer", params: transferParams },
    { name: "withdraw", params: withdrawParams },
  ];
}

async function benchmarkCase(
  testCase: BenchCase,
  helpers: PoseidonHelpers,
): Promise<BenchResult> {
  const result = await proveEip712(testCase.params, helpers);
  return {
    case: testCase.name,
    innerMs: roundMs(result.innerMs),
    outerMs: roundMs(result.outerMs),
    totalMs: roundMs(result.innerMs + result.outerMs),
  };
}

async function proveEip712(
  params: TxProofParams & { signingPrivateKey: string },
  helpers: PoseidonHelpers,
): Promise<{ innerMs: number; outerMs: number }> {
  const common = buildCommonTxArtifacts(params, helpers);
  const privateKey = hexToBytes(params.signingPrivateKey);
  const publicKey = secp.getPublicKey(privateKey, false);
  const pubKeyX = publicKey.slice(1, 33);
  const pubKeyY = publicKey.slice(33, 65);
  const authDataCommitment = singleSigAuthDataCommitment(pubKeyX, pubKeyY, helpers.pHash);

  const signingHash = computeSingleSigAuthorizationSigningHash({
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
  const signature = await secp.signAsync(signingHash, privateKey);

  const innerWitness: TomlTable = {
    ...buildSingleSigAuthorizationWitness(common),
    single_sig_policy: {
      signer: {
        x: byteArrayStrings(pubKeyX),
        y: byteArrayStrings(pubKeyY),
      },
    },
    approval: {
      signature: byteArrayStrings(signature.toCompactRawBytes()),
    },
  };

  const innerStartedAt = performance.now();
  const inner = runInnerCircuit(
    "eip712",
    innerWitness,
    `bench-${params.mode}-inner`,
    helpers.pHash,
  );
  const innerMs = performance.now() - innerStartedAt;

  assertAuthPolicyRoot(common, authDataCommitment, inner.innerVkHash, helpers);

  const outerStartedAt = performance.now();
  proveOuterTransaction(common, authDataCommitment, inner);
  const outerMs = performance.now() - outerStartedAt;

  return { innerMs, outerMs };
}

function computeInnerVkHash(packageName: string, helpers: PoseidonHelpers): bigint {
  const outputDir = mkdtempSync(resolve(os.tmpdir(), `eip8182-${packageName}-vk-`));
  execFileSync(
    BB,
    ["write_vk", "-b", resolve(CIRCUITS_DIR, "target", `${packageName}.json`), "-o", outputDir],
    { env: TOOL_ENV, stdio: "pipe" },
  );

  const vkBytes = readFileSync(resolve(outputDir, "vk"));
  const vkWords = Array.from({ length: vkBytes.length / 32 }, (_, index) =>
    BigInt(`0x${vkBytes.slice(index * 32, (index + 1) * 32).toString("hex")}`),
  );
  return computeAuthVkHash(vkWords, helpers.pHash);
}

function emptyRoot(depth: number, helpers: PoseidonHelpers): bigint {
  let current = 0n;
  for (let level = 0; level < depth; level += 1) {
    current = helpers.h2(current, current);
  }
  return current;
}

function merkleRootAndSiblings(
  leaves: Array<{ index: bigint; value: bigint }>,
  targetIndex: bigint,
  depth: number,
  helpers: PoseidonHelpers,
): { root: bigint; siblings: string[] } {
  let currentIndex = targetIndex;
  let empty = 0n;
  let nodes = new Map<bigint, bigint>(leaves.map((leaf) => [leaf.index, leaf.value]));
  const siblings: string[] = [];

  for (let level = 0; level < depth; level += 1) {
    const siblingIndex = currentIndex ^ 1n;
    siblings.push(hex(nodes.get(siblingIndex) ?? empty));

    const parents = new Set<bigint>([currentIndex >> 1n]);
    for (const index of nodes.keys()) {
      parents.add(index >> 1n);
    }

    const nextNodes = new Map<bigint, bigint>();
    for (const parentIndex of parents) {
      const leftIndex = parentIndex << 1n;
      const rightIndex = leftIndex | 1n;
      const left = nodes.get(leftIndex) ?? empty;
      const right = nodes.get(rightIndex) ?? empty;
      nextNodes.set(parentIndex, helpers.h2(left, right));
    }

    nodes = nextNodes;
    currentIndex >>= 1n;
    empty = helpers.h2(empty, empty);
  }

  return { root: nodes.get(0n) ?? empty, siblings };
}

function roundMs(value: number): number {
  return Math.round(value * 100) / 100;
}

function printTable(results: BenchResult[]) {
  const headers = ["case", "inner_ms", "outer_ms", "total_ms"];
  const rows = results.map((result) => [
    result.case,
    result.innerMs.toFixed(2),
    result.outerMs.toFixed(2),
    result.totalMs.toFixed(2),
  ]);
  const widths = headers.map((header, index) =>
    Math.max(header.length, ...rows.map((row) => row[index].length)),
  );
  const formatRow = (columns: string[]) =>
    columns.map((value, index) => value.padEnd(widths[index])).join("  ");

  console.log("inner_ms = runInnerCircuit(eip712)");
  console.log("outer_ms = proveOuterTransaction(outer)");
  console.log("total_ms = inner_ms + outer_ms");
  console.log("");
  console.log(formatRow(headers));
  console.log(formatRow(widths.map((width) => "-".repeat(width))));
  for (const row of rows) {
    console.log(formatRow(row));
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
});
