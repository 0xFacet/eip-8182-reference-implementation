#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import http from "node:http";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";

import * as demo from "../dist/index.js";

const require = createRequire(import.meta.url);
const snarkjs = require("snarkjs");
const { intent, proof: proofCodec, poseidon } = require("../../src/lib");
const T = require("../../src/lib/domain_tags");

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEMO_ROOT = path.resolve(__dirname, "..");
const ROOT = path.resolve(DEMO_ROOT, "..");
const POOL_BUILD = path.join(ROOT, "build", "pool");
const AUTH_DIR = path.join(ROOT, "circuits-noir", "auth");
const AUTH_TARGET = path.join(AUTH_DIR, "target");
const LOCAL_ENV_PATH = path.join(DEMO_ROOT, ".env.local");
const DEFAULT_WORK_ROOT = path.join("/tmp", "codex", "eip8182-prover-server");
const PORT = Number(process.env.PROVER_PORT || process.env.PORT || 8787);

const NOTE_TREE_DEPTH = 32;
const AUTH_POLICY_TREE_DEPTH = 32;
const POLICY_SET_DEPTH = 8;
const PRIVACY_POOL_ADDRESS = 0x81820n;
const AUTH_DATA_COMMITMENT_DOMAIN =
  21705131131828257353191222797690334758731062146742465638606838220894884700291n;

const SHIELDED_POOL_ABI = [
  "event ShieldedPoolDeposit(address indexed depositor,uint256 noteCommitment,uint256 leafIndex,uint256 amount,uint256 tokenAddress,uint256 postInsertionCommitmentRoot,bytes outputNoteData)",
  "event ShieldedPoolTransact(uint256 indexed nullifier0,uint256 indexed nullifier1,uint256 indexed intentReplayId,address authVerifier,uint256 noteCommitment0,uint256 noteCommitment1,uint256 noteCommitment2,uint256 leafIndex0,uint256 postInsertionCommitmentRoot,bytes outputNoteData0,bytes outputNoteData1,bytes outputNoteData2)",
  "event AuthPolicySet(address indexed user,uint256 ownerNullifierKeyHash,uint256 noteSecretSeedHash,uint256 policySetCommitment,uint256 leafPosition,uint256 leafValue,uint256 postUpdateAuthPolicyRoot)",
  "function getCurrentRoots() view returns (uint256 noteCommitmentRoot, uint256 authPolicyRoot)"
];
const POOL_IFACE = new ethers.Interface(SHIELDED_POOL_ABI);

const PUBLIC_INPUT_FIELDS = [
  "noteCommitmentRoot",
  "nullifier0",
  "nullifier1",
  "noteBodyCommitment0",
  "noteBodyCommitment1",
  "noteBodyCommitment2",
  "publicAmountOut",
  "publicRecipientAddress",
  "publicTokenAddress",
  "intentReplayId",
  "validUntilSeconds",
  "executionChainId",
  "authPolicyRoot",
  "outputNoteDataHash0",
  "outputNoteDataHash1",
  "outputNoteDataHash2",
  "authVerifier",
  "blindedAuthCommitment",
  "transactionIntentDigest"
];

const EIP712_TYPES = {
  TransactionIntent: [
    { name: "authVerifier", type: "address" },
    { name: "authorizingAddress", type: "address" },
    { name: "operationKind", type: "uint256" },
    { name: "tokenAddress", type: "address" },
    { name: "recipientOwnerNullifierKeyHash", type: "uint256" },
    { name: "amount", type: "uint256" },
    { name: "feeNoteRecipientOwnerNullifierKeyHash", type: "uint256" },
    { name: "feeAmount", type: "uint256" },
    { name: "publicRecipientAddress", type: "address" },
    { name: "executionConstraintsFlags", type: "uint256" },
    { name: "lockedOutputBinding0", type: "bytes32" },
    { name: "lockedOutputBinding1", type: "bytes32" },
    { name: "lockedOutputBinding2", type: "bytes32" },
    { name: "nonce", type: "bytes32" },
    { name: "validUntilSeconds", type: "uint256" },
    { name: "blindingFactor", type: "uint256" }
  ]
};

let proofQueue = Promise.resolve();
let localEnvPromise;

const server = http.createServer(async (req, res) => {
  try {
    setCors(res);
    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }
    if (req.method === "GET" && req.url === "/health") {
      sendJson(res, 200, { ok: true });
      return;
    }
    if (req.method !== "POST" || req.url !== "/prove-transfer") {
      sendJson(res, 404, { error: "not found" });
      return;
    }
    const body = await readJsonRequest(req);
    const result = await enqueueProof(() => proveTransfer(body));
    sendJson(res, 200, result);
  } catch (error) {
    sendJson(res, error.statusCode || 500, {
      error: error.message || String(error),
      cause: error.cause?.message
    });
  }
});

if (import.meta.url === `file://${process.argv[1]}`) {
  server.listen(PORT, "127.0.0.1", () => {
    console.log(`EIP-8182 prover server listening on http://127.0.0.1:${PORT}`);
  });
}

export { buildPoolWitness, buildProverToml, proveTransfer, reconstructStateFromLogs };

async function enqueueProof(fn) {
  const run = proofQueue.then(fn, fn);
  proofQueue = run.catch(() => {});
  return run;
}

async function proveTransfer(request) {
  const normalized = normalizeRequest(request, await loadLocalEnv());
  const provider = new ethers.JsonRpcProvider(normalized.rpcUrl);
  const chainId = (await provider.getNetwork()).chainId;
  if (chainId !== normalized.chainId) {
    throw new Error(`rpc chain id ${chainId} does not match profile/request chain id ${normalized.chainId}`);
  }

  const state = await reconstructStateFromLogs(provider, normalized);
  const auth = buildAuthWitnessInputs(normalized, state);
  const pool = buildPoolWitness(normalized, state, auth);
  assertPreparedPreviewMatches(normalized.preparedTransfer, pool.publicInputs);

  const id = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const workDir = path.join(normalized.workRoot, id);
  await mkdir(workDir, { recursive: true });
  const toolHome = path.join(normalized.workRoot, "home");
  const proverEnv = {
    ...process.env,
    HOME: toolHome,
    XDG_CACHE_HOME: path.join(toolHome, ".cache"),
    NARGO_HOME: path.join(toolHome, ".nargo")
  };
  await mkdir(proverEnv.XDG_CACHE_HOME, { recursive: true });
  await mkdir(proverEnv.NARGO_HOME, { recursive: true });

  const poolInputPath = path.join(workDir, "pool-input.json");
  const poolWitnessPath = path.join(workDir, "pool.wtns");
  await writeFile(poolInputPath, stringifyJson(pool.witnessInput));
  await writeFile(path.join(AUTH_DIR, "Prover.toml"), buildProverToml(auth.proverToml), "utf8");

  await run("node", [
    path.join(POOL_BUILD, "pool_js", "generate_witness.js"),
    path.join(POOL_BUILD, "pool_js", "pool.wasm"),
    poolInputPath,
    poolWitnessPath
  ], { cwd: ROOT });

  const poolStarted = Date.now();
  const { proof: poolProof, publicSignals } = await snarkjs.groth16.prove(
    path.join(POOL_BUILD, "pool_final.zkey"),
    poolWitnessPath
  );
  const poolProveMs = Date.now() - poolStarted;

  const poolVk = JSON.parse(await readFile(path.join(POOL_BUILD, "pool_vkey.json"), "utf8"));
  if (!await snarkjs.groth16.verify(poolVk, publicSignals, poolProof)) throw new Error("pool proof local verify failed");

  await run("nargo", ["execute", "auth"], { cwd: AUTH_DIR, env: proverEnv });
  const authStarted = Date.now();
  await run("bb", [
    "prove",
    "--scheme",
    "ultra_honk",
    "-b",
    "target/auth.json",
    "-w",
    "target/auth.gz",
    "-o",
    "target",
    "-t",
    "evm"
  ], { cwd: AUTH_DIR, env: proverEnv });
  const authProveMs = Date.now() - authStarted;

  const authPublicInputs = await readAuthPublicInputs(path.join(AUTH_TARGET, "public_inputs"));
  verifyPoolAuthAgreement(publicSignals, authPublicInputs);

  const publicInputs = publicInputObjectFromSignals(publicSignals);
  return {
    poolProofHex: hex(proofCodec.snarkjsProofToBytes(poolProof)),
    authProofHex: hex(await readFile(path.join(AUTH_TARGET, "proof"))),
    publicInputs,
    publicInputArray: PUBLIC_INPUT_FIELDS.map((field) => publicInputs[field]),
    outputNoteData0Hex: pool.outputNoteDataHexes[0],
    outputNoteData1Hex: pool.outputNoteDataHexes[1],
    outputNoteData2Hex: pool.outputNoteDataHexes[2],
    workDir,
    timings: { poolProveMs, authProveMs }
  };
}

async function loadLocalEnv() {
  if (localEnvPromise === undefined) {
    localEnvPromise = readFile(LOCAL_ENV_PATH, "utf8")
      .then(parseEnvFile)
      .catch((error) => {
        if (error?.code === "ENOENT") return {};
        throw error;
      });
  }
  return localEnvPromise;
}

function parseEnvFile(text) {
  const out = {};
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"'))
      || (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    out[key] = value;
  }
  return out;
}

function normalizeRequest(request, localEnv = {}) {
  if (!isRecord(request)) throw new Error("request body must be a JSON object");
  const profile = record(request.profile, "profile");
  const preparedTransfer = record(request.preparedTransfer, "preparedTransfer");
  const inputNote = record(request.inputNote, "inputNote");
  const authSignature = normalizeAuthSignature(
    request.authSignature,
    request.blindingFactor ?? preparedTransfer.blindingFactor
  );
  const poolAddress = normalizeAddress(request.poolAddress ?? request.pool ?? profile.poolAddress, "poolAddress");
  const rpcUrl = optionalString(request.rpcUrl, "rpcUrl")
    ?? process.env.SEPOLIA_RPC_URL
    ?? localEnv.SEPOLIA_RPC_URL;
  if (rpcUrl === undefined) throw new Error("rpcUrl is required unless SEPOLIA_RPC_URL is set");
  return {
    profile,
    preparedTransfer,
    inputNote,
    authSignature,
    rpcUrl,
    poolAddress,
    authVerifier: normalizeAddress(request.authVerifier ?? request.authAddress ?? request.auth, "authVerifier"),
    account: normalizeAddress(profile.account, "profile.account"),
    chainId: bigint(profile.chainId ?? request.chainId, "chainId"),
    fromBlock: request.fromBlock === undefined
      ? bigint(request.deploymentBlock ?? 0n, "deploymentBlock")
      : bigint(request.fromBlock, "fromBlock"),
    toBlock: request.toBlock ?? "latest",
    logChunkSize: Number(request.logChunkSize ?? 50_000),
    workRoot: path.resolve(String(request.workRoot ?? DEFAULT_WORK_ROOT)),
    policySetLeafPosition: request.policySetLeafPosition === undefined
      ? 0n
      : bigint(request.policySetLeafPosition, "policySetLeafPosition")
  };
}

function normalizeAuthSignature(value, fallbackBlindingFactor) {
  const auth = typeof value === "string" ? { signature: value } : record(value, "authSignature");
  const signature = hexString(auth.signature, "authSignature.signature");
  const bytes = ethers.getBytes(signature);
  if (bytes.length !== 64 && bytes.length !== 65) {
    throw new Error("authSignature.signature must be a 64-byte r||s or 65-byte EIP-712 signature");
  }
  return {
    signature,
    signatureBytes: bytes,
    blindingFactor: bigint(auth.blindingFactor ?? fallbackBlindingFactor, "blindingFactor"),
    pubkeyX: auth.pubkeyX === undefined ? undefined : hexBytes(auth.pubkeyX, "authSignature.pubkeyX", 32),
    pubkeyY: auth.pubkeyY === undefined ? undefined : hexBytes(auth.pubkeyY, "authSignature.pubkeyY", 32)
  };
}

async function reconstructStateFromLogs(provider, request) {
  const latest = request.toBlock === "latest" ? BigInt(await provider.getBlockNumber()) : bigint(request.toBlock, "toBlock");
  const deposits = await fetchEventLogs(provider, request.poolAddress, "ShieldedPoolDeposit", request.fromBlock, latest, request.logChunkSize);
  const transacts = await fetchEventLogs(provider, request.poolAddress, "ShieldedPoolTransact", request.fromBlock, latest, request.logChunkSize);
  const authEvents = await fetchEventLogs(provider, request.poolAddress, "AuthPolicySet", request.fromBlock, latest, request.logChunkSize);

  const noteLeaves = new Map();
  let lastNoteRoot;
  for (const event of sortEvents([...deposits, ...transacts])) {
    if (event.name === "ShieldedPoolDeposit") {
      noteLeaves.set(toLeafIndex(event.args.leafIndex), BigInt(event.args.noteCommitment));
      lastNoteRoot = BigInt(event.args.postInsertionCommitmentRoot);
    } else {
      const leaf0 = toLeafIndex(event.args.leafIndex0);
      noteLeaves.set(leaf0, BigInt(event.args.noteCommitment0));
      noteLeaves.set(leaf0 + 1, BigInt(event.args.noteCommitment1));
      noteLeaves.set(leaf0 + 2, BigInt(event.args.noteCommitment2));
      lastNoteRoot = BigInt(event.args.postInsertionCommitmentRoot);
    }
  }

  const authLeaves = new Map();
  const userEntries = new Map();
  let lastAuthRoot;
  for (const event of sortEvents(authEvents)) {
    const user = normalizeAddress(event.args.user, "AuthPolicySet.user");
    const leafPosition = toLeafIndex(event.args.leafPosition);
    const entry = {
      user,
      ownerNullifierKeyHash: BigInt(event.args.ownerNullifierKeyHash),
      noteSecretSeedHash: BigInt(event.args.noteSecretSeedHash),
      policySetCommitment: BigInt(event.args.policySetCommitment),
      leafPosition: BigInt(event.args.leafPosition),
      leafValue: BigInt(event.args.leafValue),
      postUpdateAuthPolicyRoot: BigInt(event.args.postUpdateAuthPolicyRoot)
    };
    authLeaves.set(leafPosition, entry.leafValue);
    userEntries.set(user, entry);
    lastAuthRoot = entry.postUpdateAuthPolicyRoot;
  }

  const noteRoot = noteCommitmentTree(noteLeaves, NOTE_TREE_DEPTH).root;
  const authRoot = sparseMerkleTree([...authLeaves.entries()], AUTH_POLICY_TREE_DEPTH, 0n).root;
  if (lastNoteRoot !== undefined && noteRoot !== lastNoteRoot) {
    throw new Error(`reconstructed note root ${noteRoot} does not match last event root ${lastNoteRoot}`);
  }
  if (lastAuthRoot !== undefined && authRoot !== lastAuthRoot) {
    throw new Error(`reconstructed auth root ${authRoot} does not match last event root ${lastAuthRoot}`);
  }

  const contract = new ethers.Contract(request.poolAddress, SHIELDED_POOL_ABI, provider);
  const [chainNoteRoot, chainAuthRoot] = await contract.getCurrentRoots();
  if (noteRoot !== BigInt(chainNoteRoot)) throw new Error(`reconstructed note root ${noteRoot} does not match on-chain root ${chainNoteRoot}`);
  if (authRoot !== BigInt(chainAuthRoot)) throw new Error(`reconstructed auth root ${authRoot} does not match on-chain root ${chainAuthRoot}`);

  return { noteLeaves, authLeaves, userEntries, noteRoot, authRoot };
}

function buildAuthWitnessInputs(request, state) {
  const profile = request.profile;
  const transfer = request.preparedTransfer;
  const slots = transferSlots(transfer);
  const senderOwnerNullifierKey = bigint(profile.ownerNullifierKey, "profile.ownerNullifierKey");
  const senderOwnerNullifierKeyHash = bigint(profile.ownerNullifierKeyHash, "profile.ownerNullifierKeyHash");
  const senderNoteSecretSeed = bigint(profile.noteSecretSeed, "profile.noteSecretSeed");
  const noteSecretSeedHash = bigint(profile.noteSecretSeedHash, "profile.noteSecretSeedHash");
  const registrationBlinder = bigint(profile.registrationBlinder, "profile.registrationBlinder");
  const blindingFactor = request.authSignature.blindingFactor;
  const intentFields = {
    authVerifier: addressField(request.authVerifier),
    authorizingAddress: addressField(request.account),
    operationKind: 0n,
    tokenAddress: addressField(transfer.tokenAddress),
    recipientOwnerNullifierKeyHash: slots[0].ownerNullifierKeyHash,
    amount: slots[0].amount,
    feeNoteRecipientOwnerNullifierKeyHash: 0n,
    feeAmount: 0n,
    publicRecipientAddress: 0n,
    executionConstraintsFlags: 7n,
    lockedOutputBinding0: slots[0].lockedOutputBinding,
    lockedOutputBinding1: slots[1].lockedOutputBinding,
    lockedOutputBinding2: slots[2].lockedOutputBinding,
    nonce: bigint(transfer.nonce, "preparedTransfer.nonce"),
    validUntilSeconds: bigint(transfer.validUntilSeconds, "preparedTransfer.validUntilSeconds"),
    executionChainId: request.chainId
  };

  const digestHex = eip712DigestHex(request.authVerifier, request.account, intentFields, blindingFactor);
  const pubkey = recoverOrReadPubkey(request.authSignature, digestHex);
  const derivedAddress = ethereumAddressFromPubkey(pubkey.x, pubkey.y);
  if (derivedAddress !== request.account) {
    throw new Error(`auth signature pubkey derives ${derivedAddress}, expected profile account ${request.account}`);
  }
  if (profile.authPublicKey !== undefined) {
    const profilePubkey = ethers.getBytes(hexString(profile.authPublicKey, "profile.authPublicKey"));
    const recoveredPubkey = ethers.concat(["0x04", pubkey.x, pubkey.y]);
    if (!ethers.getBytes(recoveredPubkey).every((byte, i) => byte === profilePubkey[i])) {
      throw new Error("auth signature public key does not match signed browser profile");
    }
  }

  const authDataCommitment = secp256k1AuthDataCommitment(pubkey.x, pubkey.y);
  const blindedAuthCommitment = intent.blindedAuthCommitment(authDataCommitment, blindingFactor);
  const policyCommitment = intent.policyCommitment(addressField(request.authVerifier), authDataCommitment, registrationBlinder);
  const policySet = sparseMerkleTree([[request.policySetLeafPosition, policyCommitment]], POLICY_SET_DEPTH, request.policySetLeafPosition);
  const entry = state.userEntries.get(request.account);
  if (entry === undefined) throw new Error(`no AuthPolicySet event found for ${request.account}`);
  if (entry.ownerNullifierKeyHash !== senderOwnerNullifierKeyHash) throw new Error("AuthPolicySet ownerNullifierKeyHash does not match profile");
  if (entry.noteSecretSeedHash !== noteSecretSeedHash) throw new Error("AuthPolicySet noteSecretSeedHash does not match profile");
  if (entry.policySetCommitment !== policySet.root) {
    throw new Error(`computed policySetCommitment ${policySet.root} does not match AuthPolicySet ${entry.policySetCommitment}`);
  }
  const expectedLeaf = intent.authPolicyLeaf(addressField(request.account), senderOwnerNullifierKeyHash, noteSecretSeedHash, policySet.root);
  if (entry.leafValue !== expectedLeaf) throw new Error("AuthPolicySet leafValue does not match computed auth-policy leaf");
  const authMembership = sparseMerkleTree([...state.authLeaves.entries()], AUTH_POLICY_TREE_DEPTH, entry.leafPosition);

  return {
    authDataCommitment,
    blindedAuthCommitment,
    transactionIntentDigest: intent.transactionIntentDigest(intentFields),
    senderOwnerNullifierKey,
    senderOwnerNullifierKeyHash,
    senderNoteSecretSeed,
    noteSecretSeedHash,
    policySetCommitment: policySet.root,
    policySetLeafPosition: request.policySetLeafPosition,
    policySetSiblings: policySet.siblings,
    leafPosition: entry.leafPosition,
    authPolicySiblings: authMembership.siblings,
    registrationBlinder,
    proverToml: {
      ...intentFields,
      pubkeyX: pubkey.x,
      pubkeyY: pubkey.y,
      signature: signatureRS(request.authSignature.signatureBytes),
      blindingFactor
    }
  };
}

function buildPoolWitness(request, state, auth) {
  const transfer = request.preparedTransfer;
  const input = normalizeInputNote(request.inputNote);
  const payload = input.payload;
  const slots = transferSlots(transfer);
  const inputOwnerCommitment = intent.ownerCommitment(auth.senderOwnerNullifierKeyHash, payload.noteSecret);
  const inputBody = intent.noteBodyCommitment(inputOwnerCommitment, payload.amount, addressField(payload.tokenAddress));
  const inputCommitment = intent.noteCommitment(inputBody, input.leafIndex);
  if (inputCommitment !== input.noteCommitment) throw new Error("inputNote commitment does not match payload/profile fields");
  if (state.noteLeaves.get(Number(input.leafIndex)) !== inputCommitment) throw new Error(`input note commitment not found at leaf ${input.leafIndex}`);

  const noteMembership = noteCommitmentTree(state.noteLeaves, NOTE_TREE_DEPTH, input.leafIndex);
  const replayId = intent.intentReplayId(auth.senderOwnerNullifierKey, addressField(request.account), request.chainId, bigint(transfer.nonce, "preparedTransfer.nonce"));
  if (replayId !== bigint(transfer.intentReplayId, "preparedTransfer.intentReplayId")) {
    throw new Error("preparedTransfer.intentReplayId does not match profile/account/nonce");
  }

  const dummyOwnerHash = poseidon(BigInt(T.OWNER_NULLIFIER_KEY_HASH_DOMAIN), 0xdeadn);
  const computedSlots = slots.map((slot, i) => {
    const expectedSecret = poseidon(BigInt(T.TRANSACT_NOTE_SECRET_DOMAIN), auth.senderNoteSecretSeed, replayId, BigInt(i));
    if (slot.noteSecret !== expectedSecret) throw new Error(`output slot ${i} noteSecret does not match sender seed/replay id`);
    const owner = intent.ownerCommitment(slot.ownerNullifierKeyHash, slot.noteSecret);
    const bodyToken = slot.isReal ? addressField(transfer.tokenAddress) : 0n;
    const body = intent.noteBodyCommitment(owner, slot.amount, bodyToken);
    if (body !== slot.noteBodyCommitment) throw new Error(`output slot ${i} noteBodyCommitment mismatch`);
    const binding = poseidon(BigInt(T.OUTPUT_BINDING_DOMAIN), body, slot.outputNoteDataHash);
    if (binding !== slot.lockedOutputBinding) throw new Error(`output slot ${i} lockedOutputBinding mismatch`);
    return { ...slot, noteBodyCommitment: body, lockedOutputBinding: binding };
  });

  if (!computedSlots[0].isReal) throw new Error("transfer output slot 0 must be real");
  if (computedSlots[2].isReal) throw new Error("fee output slot 2 is not supported by the current demo transfer payload");
  if (!computedSlots[1].isReal && computedSlots[1].ownerNullifierKeyHash !== dummyOwnerHash) throw new Error("dummy change output must use the reserved dummy owner hash");
  if (computedSlots[2].ownerNullifierKeyHash !== dummyOwnerHash) throw new Error("dummy fee output must use the reserved dummy owner hash");

  const publicInputs = {
    noteCommitmentRoot: state.noteRoot,
    nullifier0: intent.nullifier(inputCommitment, auth.senderOwnerNullifierKey),
    nullifier1: poseidon(BigInt(T.PHANTOM_NULLIFIER_DOMAIN), auth.senderOwnerNullifierKey, replayId, 1n),
    noteBodyCommitment0: computedSlots[0].noteBodyCommitment,
    noteBodyCommitment1: computedSlots[1].noteBodyCommitment,
    noteBodyCommitment2: computedSlots[2].noteBodyCommitment,
    publicAmountOut: 0n,
    publicRecipientAddress: 0n,
    publicTokenAddress: 0n,
    intentReplayId: replayId,
    validUntilSeconds: bigint(transfer.validUntilSeconds, "preparedTransfer.validUntilSeconds"),
    executionChainId: request.chainId,
    authPolicyRoot: state.authRoot,
    outputNoteDataHash0: computedSlots[0].outputNoteDataHash,
    outputNoteDataHash1: computedSlots[1].outputNoteDataHash,
    outputNoteDataHash2: computedSlots[2].outputNoteDataHash,
    authVerifier: addressField(request.authVerifier),
    blindedAuthCommitment: auth.blindedAuthCommitment,
    transactionIntentDigest: auth.transactionIntentDigest
  };

  return {
    publicInputs,
    witnessInput: decimalize({
      ...publicInputs,
      senderOwnerNullifierKey: auth.senderOwnerNullifierKey,
      senderNoteSecretSeed: auth.senderNoteSecretSeed,
      authorizingAddress: addressField(request.account),
      noteSecretSeedHash: auth.noteSecretSeedHash,
      policySetCommitment: auth.policySetCommitment,
      leafPosition: auth.leafPosition,
      authPolicySiblings: auth.authPolicySiblings,
      inIsReal: [1n, 0n],
      inAmount: [payload.amount, 0n],
      inNoteSecret: [payload.noteSecret, 0n],
      inLeafIndex: [input.leafIndex, 0n],
      inSiblings: [noteMembership.siblings, Array(NOTE_TREE_DEPTH).fill(0n)],
      outIsReal: computedSlots.map((slot) => slot.isReal ? 1n : 0n),
      outAmount: computedSlots.map((slot) => slot.amount),
      outOwnerNullifierKeyHash: computedSlots.map((slot) => slot.ownerNullifierKeyHash),
      outLockedOutputBinding: computedSlots.map((slot) => slot.lockedOutputBinding),
      tokenAddress: addressField(transfer.tokenAddress),
      recipientOwnerNullifierKeyHash: computedSlots[0].ownerNullifierKeyHash,
      feeNoteRecipientOwnerNullifierKeyHash: 0n,
      feeAmount: 0n,
      nonce: bigint(transfer.nonce, "preparedTransfer.nonce"),
      executionConstraintsFlags: 7n,
      authDataCommitment: auth.authDataCommitment,
      blindingFactor: auth.proverToml.blindingFactor,
      registrationBlinder: auth.registrationBlinder,
      policySetLeafPosition: auth.policySetLeafPosition,
      policySetSiblings: auth.policySetSiblings
    }),
    outputNoteDataHexes: computedSlots.map((slot) => slot.outputNoteDataHex)
  };
}

function buildProverToml(input) {
  const lines = [
    tomlField("auth_verifier", input.authVerifier),
    tomlField("authorizing_address", input.authorizingAddress),
    tomlField("operation_kind", input.operationKind),
    tomlField("token_address", input.tokenAddress),
    tomlField("recipient_owner_nullifier_key_hash", input.recipientOwnerNullifierKeyHash),
    tomlField("amount", input.amount),
    tomlField("fee_note_recipient_owner_nullifier_key_hash", input.feeNoteRecipientOwnerNullifierKeyHash),
    tomlField("fee_amount", input.feeAmount),
    tomlField("public_recipient_address", input.publicRecipientAddress),
    tomlField("execution_constraints_flags", input.executionConstraintsFlags),
    tomlField("locked_output_binding0", input.lockedOutputBinding0),
    tomlField("locked_output_binding1", input.lockedOutputBinding1),
    tomlField("locked_output_binding2", input.lockedOutputBinding2),
    tomlBytes("nonce", bigintToBytes(input.nonce, 32)),
    tomlField("valid_until_seconds", input.validUntilSeconds),
    tomlField("execution_chain_id", input.executionChainId),
    tomlBytes("pubkey_x", input.pubkeyX),
    tomlBytes("pubkey_y", input.pubkeyY),
    tomlBytes("signature", input.signature),
    tomlField("blinding_factor", input.blindingFactor)
  ];
  return `${lines.join("\n")}\n`;
}

function assertPreparedPreviewMatches(transfer, publicInputs) {
  const preview = transfer.publicInputPreview;
  if (!isRecord(preview)) throw new Error("preparedTransfer.publicInputPreview must be an object");
  for (const [key, value] of Object.entries(preview)) {
    if (value === undefined || publicInputs[key] === undefined) continue;
    const expected = bigint(value, `preparedTransfer.publicInputPreview.${key}`);
    if (expected !== publicInputs[key]) {
      throw new Error(`preparedTransfer publicInputPreview.${key}=${expected} but witness uses ${publicInputs[key]}`);
    }
  }
}

function eip712DigestHex(authVerifier, authorizingAddress, fields, blindingFactor) {
  const domain = {
    name: "EIP-8182 Auth",
    version: "1",
    chainId: Number(fields.executionChainId),
    verifyingContract: fieldToAddress(PRIVACY_POOL_ADDRESS)
  };
  const message = {
    authVerifier: normalizeAddress(authVerifier, "authVerifier"),
    authorizingAddress: normalizeAddress(authorizingAddress, "authorizingAddress"),
    operationKind: fields.operationKind,
    tokenAddress: fieldToAddress(fields.tokenAddress),
    recipientOwnerNullifierKeyHash: fields.recipientOwnerNullifierKeyHash,
    amount: fields.amount,
    feeNoteRecipientOwnerNullifierKeyHash: fields.feeNoteRecipientOwnerNullifierKeyHash,
    feeAmount: fields.feeAmount,
    publicRecipientAddress: fieldToAddress(fields.publicRecipientAddress),
    executionConstraintsFlags: fields.executionConstraintsFlags,
    lockedOutputBinding0: bytes32Hex(fields.lockedOutputBinding0),
    lockedOutputBinding1: bytes32Hex(fields.lockedOutputBinding1),
    lockedOutputBinding2: bytes32Hex(fields.lockedOutputBinding2),
    nonce: bytes32Hex(fields.nonce),
    validUntilSeconds: fields.validUntilSeconds,
    blindingFactor
  };
  return ethers.TypedDataEncoder.hash(domain, EIP712_TYPES, message);
}

function recoverOrReadPubkey(authSignature, digestHex) {
  if (authSignature.signatureBytes.length === 65) {
    const pub = ethers.getBytes(ethers.SigningKey.recoverPublicKey(digestHex, authSignature.signature));
    return { x: pub.slice(1, 33), y: pub.slice(33, 65) };
  }
  if (authSignature.pubkeyX && authSignature.pubkeyY) return { x: authSignature.pubkeyX, y: authSignature.pubkeyY };
  throw new Error("64-byte auth signatures must include authSignature.pubkeyX and authSignature.pubkeyY");
}

function secp256k1AuthDataCommitment(pubkeyX, pubkeyY) {
  const [xHi, xLo] = splitBytes32(pubkeyX);
  const [yHi, yLo] = splitBytes32(pubkeyY);
  return poseidon(AUTH_DATA_COMMITMENT_DOMAIN, xHi, xLo, yHi, yLo);
}

async function fetchEventLogs(provider, address, eventName, fromBlock, toBlock, chunkSize) {
  const event = POOL_IFACE.getEvent(eventName);
  const logs = [];
  for (let start = fromBlock; start <= toBlock; start += BigInt(chunkSize)) {
    const end = minBigint(start + BigInt(chunkSize) - 1n, toBlock);
    const chunk = await provider.getLogs({
      address,
      fromBlock: ethers.toQuantity(start),
      toBlock: ethers.toQuantity(end),
      topics: [event.topicHash]
    });
    for (const log of chunk) logs.push({ ...log, name: eventName, args: POOL_IFACE.parseLog(log).args });
  }
  return logs;
}

function noteCommitmentTree(leaves, depth, queryIndex = 0n) {
  const empty = emptyHashes(depth);
  let level = new Map(leaves);
  let pos = Number(queryIndex);
  const siblings = [];
  for (let height = 0; height < depth; height += 1) {
    const sibling = pos ^ 1;
    siblings.push(level.get(sibling) ?? empty[height]);
    const next = new Map();
    for (const [p] of level) {
      const paired = p ^ 1;
      const left = (p & 1) ? (level.get(paired) ?? empty[height]) : level.get(p);
      const right = (p & 1) ? level.get(p) : (level.get(paired) ?? empty[height]);
      next.set(p >> 1, poseidon(left, right));
    }
    level = next;
    pos >>= 1;
  }
  return { root: level.get(0) ?? empty[depth], siblings };
}

function sparseMerkleTree(leaves, depth, queryKey) {
  const empty = emptyHashes(depth);
  const nodes = new Map();
  const nodeKey = (height, index) => `${height}:${BigInt(index)}`;
  for (const [leafKey, leaf] of leaves) nodes.set(nodeKey(0, leafKey), BigInt(leaf));
  for (let height = 0; height < depth; height += 1) {
    const prefixes = new Set();
    for (const key of nodes.keys()) {
      const [heightText, indexText] = key.split(":");
      if (Number(heightText) === height) prefixes.add(BigInt(indexText) >> 1n);
    }
    for (const prefix of prefixes) {
      const left = nodes.get(nodeKey(height, prefix << 1n)) ?? empty[height];
      const right = nodes.get(nodeKey(height, (prefix << 1n) | 1n)) ?? empty[height];
      nodes.set(nodeKey(height + 1, prefix), poseidon(left, right));
    }
  }
  const siblings = [];
  const query = BigInt(queryKey);
  for (let height = 0; height < depth; height += 1) {
    siblings.push(nodes.get(nodeKey(height, (query >> BigInt(height)) ^ 1n)) ?? empty[height]);
  }
  return { root: nodes.get(nodeKey(depth, 0n)) ?? empty[depth], siblings };
}

function emptyHashes(depth) {
  const hashes = [0n];
  for (let i = 0; i < depth; i += 1) hashes.push(poseidon(hashes[i], hashes[i]));
  return hashes;
}

function transferSlots(transfer) {
  if (!Array.isArray(transfer.outputSlots) || transfer.outputSlots.length !== 3) {
    throw new Error("preparedTransfer.outputSlots must have exactly three slots");
  }
  return transfer.outputSlots.map((slot, i) => {
    const outputNoteDataHex = hexString(slot.outputNoteDataHex, `preparedTransfer.outputSlots[${i}].outputNoteDataHex`);
    const outputNoteDataHash = demo.outputNoteDataHash(ethers.getBytes(outputNoteDataHex));
    const suppliedHash = bigint(slot.outputNoteDataHash, `preparedTransfer.outputSlots[${i}].outputNoteDataHash`);
    if (suppliedHash !== outputNoteDataHash) throw new Error(`output slot ${i} outputNoteDataHash mismatch`);
    return {
      isReal: Boolean(slot.isReal),
      amount: bigint(slot.amount, `preparedTransfer.outputSlots[${i}].amount`),
      ownerNullifierKeyHash: bigint(slot.ownerNullifierKeyHash, `preparedTransfer.outputSlots[${i}].ownerNullifierKeyHash`),
      noteSecret: bigint(slot.noteSecret, `preparedTransfer.outputSlots[${i}].noteSecret`),
      noteBodyCommitment: bigint(slot.noteBodyCommitment, `preparedTransfer.outputSlots[${i}].noteBodyCommitment`),
      outputNoteDataHash,
      outputNoteDataHex,
      lockedOutputBinding: bigint(slot.lockedOutputBinding, `preparedTransfer.outputSlots[${i}].lockedOutputBinding`)
    };
  });
}

function normalizeInputNote(note) {
  const payload = record(note.payload, "inputNote.payload");
  return {
    leafIndex: bigint(note.leafIndex ?? payload.leafIndex, "inputNote.leafIndex"),
    noteCommitment: bigint(note.noteCommitment ?? payload.noteCommitment, "inputNote.noteCommitment"),
    payload: {
      tokenAddress: normalizeAddress(payload.tokenAddress, "inputNote.payload.tokenAddress"),
      amount: bigint(payload.amount, "inputNote.payload.amount"),
      noteSecret: bigint(payload.noteSecret, "inputNote.payload.noteSecret")
    }
  };
}

async function readAuthPublicInputs(file) {
  const data = await readFile(file);
  if (data.length !== 64) throw new Error(`unexpected auth public_inputs size ${data.length}; expected 64`);
  return [BigInt(`0x${data.subarray(0, 32).toString("hex")}`), BigInt(`0x${data.subarray(32, 64).toString("hex")}`)];
}

function verifyPoolAuthAgreement(poolPublicSignals, authPublicInputs) {
  const poolBlinded = BigInt(poolPublicSignals[17]);
  const poolDigest = BigInt(poolPublicSignals[18]);
  if (poolBlinded !== authPublicInputs[0]) {
    throw new Error(`blinded auth commitment mismatch: pool=${poolBlinded} auth=${authPublicInputs[0]}`);
  }
  if (poolDigest !== authPublicInputs[1]) {
    throw new Error(`transaction intent digest mismatch: pool=${poolDigest} auth=${authPublicInputs[1]}`);
  }
}

function publicInputObjectFromSignals(signals) {
  return Object.fromEntries(PUBLIC_INPUT_FIELDS.map((field, i) => [field, BigInt(signals[i]).toString(10)]));
}

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: "pipe", ...options });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (chunk) => { stdout += chunk; });
    child.stderr?.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolve({ stdout, stderr });
      else reject(new Error(`${command} ${args.join(" ")} exited ${code}\n${stdout}${stderr}`));
    });
  });
}

function readJsonRequest(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 10_000_000) {
        reject(Object.assign(new Error("request body too large"), { statusCode: 413 }));
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        resolve(JSON.parse(body));
      } catch (cause) {
        reject(Object.assign(new Error("invalid JSON request body"), { statusCode: 400, cause }));
      }
    });
    req.on("error", reject);
  });
}

function sendJson(res, statusCode, value) {
  res.writeHead(statusCode, { "content-type": "application/json" });
  res.end(stringifyJson(value));
}

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "content-type");
}

function stringifyJson(value) {
  return `${JSON.stringify(value, (_key, v) => typeof v === "bigint" ? v.toString(10) : v, 2)}\n`;
}

function decimalize(value) {
  if (typeof value === "bigint") return value.toString(10);
  if (Array.isArray(value)) return value.map(decimalize);
  if (isRecord(value)) return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, decimalize(v)]));
  return value;
}

function tomlField(name, value) {
  return `${name} = "${BigInt(value).toString(10)}"`;
}

function tomlBytes(name, bytes) {
  return `${name} = [${Array.from(bytes).map((byte) => `"${byte}"`).join(", ")}]`;
}

function signatureRS(bytes) {
  return bytes.length === 64 ? bytes : bytes.slice(0, 64);
}

function splitBytes32(bytes) {
  return [bytesToBigint(bytes.slice(0, 16)), bytesToBigint(bytes.slice(16, 32))];
}

function bytesToBigint(bytes) {
  let out = 0n;
  for (const byte of bytes) out = (out << 8n) | BigInt(byte);
  return out;
}

function bigintToBytes(value, length) {
  let n = BigInt(value);
  const out = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i -= 1) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  if (n !== 0n) throw new Error(`value does not fit in ${length} bytes`);
  return out;
}

function bytes32Hex(value) {
  return `0x${BigInt(value).toString(16).padStart(64, "0")}`;
}

function hex(bytes) {
  return ethers.hexlify(bytes);
}

function hexBytes(value, name, length) {
  const bytes = ethers.getBytes(hexString(value, name));
  if (bytes.length !== length) throw new Error(`${name} must be ${length} bytes`);
  return bytes;
}

function hexString(value, name) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]*$/.test(value) || value.length % 2 !== 0) {
    throw new Error(`${name} must be hex bytes`);
  }
  return value;
}

function normalizeAddress(value, name) {
  return ethers.getAddress(string(value, name)).toLowerCase();
}

function addressField(value) {
  return BigInt(normalizeAddress(value, "address"));
}

function fieldToAddress(value) {
  const field = BigInt(value);
  if (field < 0n || field >= (1n << 160n)) throw new Error("field does not fit in an address");
  return `0x${field.toString(16).padStart(40, "0")}`;
}

function ethereumAddressFromPubkey(x, y) {
  const h = ethers.keccak256(ethers.concat([x, y]));
  return ethers.getAddress(`0x${h.slice(-40)}`).toLowerCase();
}

function sortEvents(events) {
  return [...events].sort((a, b) => {
    if (a.blockNumber !== b.blockNumber) return a.blockNumber - b.blockNumber;
    return a.index - b.index;
  });
}

function toLeafIndex(value) {
  const leaf = BigInt(value);
  if (leaf < 0n || leaf > 0xffffffffn) throw new Error(`leaf index out of range: ${leaf}`);
  return Number(leaf);
}

function minBigint(a, b) {
  return a < b ? a : b;
}

function record(value, name) {
  if (!isRecord(value)) throw new Error(`${name} must be an object`);
  return value;
}

function string(value, name) {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${name} must be a nonempty string`);
  return value;
}

function optionalString(value, name) {
  if (value === undefined || value === null || value === "") return undefined;
  return string(value, name);
}

function bigint(value, name) {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${name} must be a nonnegative safe integer`);
    return BigInt(value);
  }
  if (typeof value === "string" && value.trim() !== "") return BigInt(value);
  throw new Error(`${name} must be a bigint-like value`);
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
