#!/usr/bin/env node
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";

import {
  SepoliaDemoIndexer,
  authIntentEthersTypes,
  authIntentTypedData,
  createDeterministicDemoProfile,
  finalizeDeterministicProfileAuth,
  getPoolDepositLogs,
  getPoolTransactLogs,
  hasProfileAuth,
  jsonStringifyTypedData,
  noteBodyCommitment,
  ownerCommitment,
  prepareDemoPrivateTransfer,
  prepareEncryptedOutputNoteData,
  profileField,
  profilePublicKey,
  profileSecretKey,
  profileDerivationMessage,
  randomField,
  readCurrentRoots,
  readRecipient,
  sendDeposit,
  sendPublishRecipient,
  sendSetAuthPolicy,
  sendTransact,
  waitForTransactionReceipt
} from "../dist/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEMO_ROOT = path.resolve(__dirname, "..");
const TMP_ROOT = path.join("/tmp", "codex", "eip8182-sepolia-demo");
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const DEFAULT_AMOUNT = 20_000_000_000_000n;
const DEFAULT_TRANSFER_AMOUNT = 10_000_000_000_000n;

async function main() {
  const env = parseEnv(await readFile(path.join(DEMO_ROOT, ".env.local"), "utf8"));
  const rpcUrl = env.SEPOLIA_RPC_URL;
  const privateKey = env.PRIVATE_KEY ?? env.SEPOLIA_PRIVATE_KEY;
  if (!rpcUrl) throw new Error("SEPOLIA_RPC_URL missing from sepolia-demo/.env.local");
  if (!privateKey) throw new Error("PRIVATE_KEY missing from sepolia-demo/.env.local");

  const config = parseDemoConfig(await readFile(path.join(DEMO_ROOT, "app", "src", "demoConfig.ts"), "utf8"));
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const wallet = new ethers.Wallet(privateKey, provider);
  const eip1193 = new WalletEip1193Provider(provider, wallet);
  const account = wallet.address.toLowerCase();
  const network = await provider.getNetwork();
  if (network.chainId !== BigInt(config.chainId)) {
    throw new Error(`RPC chain id ${network.chainId} does not match config ${config.chainId}`);
  }

  await mkdir(TMP_ROOT, { recursive: true });
  const profilePath = path.join(TMP_ROOT, `profile-${config.chainId}-${config.pool}-${config.authVerifier}-${account}.json`);
  const profile = await loadOrCreateProfile(profilePath, {
    chainId: config.chainId,
    poolAddress: config.pool,
    account,
    authVerifier: config.authVerifier,
    wallet
  });

  console.log(`account ${short(account)}`);
  await publishRecipient(eip1193, account, config, profile);
  await registerAuthPolicy(eip1193, account, config, profile);

  const depositTx = await deposit(eip1193, account, config, profile, DEFAULT_AMOUNT);
  const inputNote = await scanForTxNote(eip1193, config, profile, depositTx);
  const roots = await readCurrentRoots(eip1193, config.pool);
  const registryRecord = await readRecipient(eip1193, config.recipientRegistry, account);
  if (!registryRecord.registered) throw new Error("self recipient record missing after publish");

  const transfer = await prepareDemoPrivateTransfer({
    chainId: config.chainId,
    poolAddress: config.pool,
    authVerifier: config.authVerifier,
    sender: profile,
    inputNote,
    recipient: {
      ownerNullifierKeyHash: registryRecord.ownerNullifierKeyHash,
      publicKey: registryRecord.publicKey
    },
    amount: DEFAULT_TRANSFER_AMOUNT,
    noteCommitmentRoot: roots.noteCommitmentRoot,
    authPolicyRoot: roots.authPolicyRoot
  });

  const typedData = authIntentTypedData(transfer, account);
  const authSignature = await eip1193.request({
    method: "eth_signTypedData_v4",
    params: [account, jsonStringifyTypedData(typedData)]
  });

  console.log("proving transfer");
  const proofResponse = await fetch("http://127.0.0.1:8787/prove-transfer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: stringifyJson({
      chainId: config.chainId,
      deploymentBlock: config.deploymentBlock,
      poolAddress: config.pool,
      authVerifier: config.authVerifier,
      profile,
      inputNote,
      preparedTransfer: transfer,
      authSignature
    })
  });
  const proofJson = await proofResponse.json();
  if (!proofResponse.ok) throw new Error(`prover failed: ${proofJson.error ?? proofResponse.statusText}`);

  console.log("submitting transact");
  const tx = await sendTransact(eip1193, account, config.pool, {
    poolProof: proofJson.poolProofHex,
    authProof: proofJson.authProofHex,
    publicInputs: revivePublicInputs(proofJson.publicInputs),
    outputNoteData0: proofJson.outputNoteData0Hex,
    outputNoteData1: proofJson.outputNoteData1Hex,
    outputNoteData2: proofJson.outputNoteData2Hex
  });
  await waitForTransactionReceipt(eip1193, tx, { timeoutMs: 300_000 });

  const notes = await scanNotes(eip1193, config, profile);
  const received = notes.filter((note) => note.transactionHash === tx && note.status === "decrypted");
  console.log(`deposit ${short(depositTx)}`);
  console.log(`transact ${short(tx)}`);
  console.log(`decrypted outputs ${received.length}`);
}

async function loadOrCreateProfile(profilePath, options) {
  try {
    const existing = JSON.parse(await readFile(profilePath, "utf8"));
    if (hasProfileAuth(existing)) return existing;
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }

  const message = profileDerivationMessage({
    chainId: options.chainId,
    poolAddress: options.poolAddress,
    account: options.account,
    authVerifier: options.authVerifier
  });
  const signature = await options.wallet.signMessage(message);
  const draft = createDeterministicDemoProfile({
    chainId: options.chainId,
    poolAddress: options.poolAddress,
    account: options.account,
    authVerifier: options.authVerifier,
    derivationSignature: signature
  });
  const profile = finalizeDeterministicProfileAuth(draft, {
    authVerifier: options.authVerifier,
    profileSignature: signature
  });
  await writeFile(profilePath, JSON.stringify(profile, null, 2), { mode: 0o600 });
  return profile;
}

async function publishRecipient(provider, account, config, profile) {
  const tx = await sendPublishRecipient(
    provider,
    account,
    config.recipientRegistry,
    profile.ownerNullifierKeyHash,
    profilePublicKey(profile)
  );
  await waitForTransactionReceipt(provider, tx);
  console.log(`published recipient ${short(tx)}`);
}

async function registerAuthPolicy(provider, account, config, profile) {
  const tx = await sendSetAuthPolicy(
    provider,
    account,
    config.pool,
    profile.ownerNullifierKeyHash,
    profile.noteSecretSeedHash,
    profile.policySetCommitment
  );
  await waitForTransactionReceipt(provider, tx);
  console.log(`registered auth ${short(tx)}`);
}

async function deposit(provider, account, config, profile, amount) {
  const noteSecret = randomField();
  const ownerHash = profileField(profile, "ownerNullifierKeyHash");
  const noteOwnerCommitment = ownerCommitment(ownerHash, noteSecret);
  const body = noteBodyCommitment(noteOwnerCommitment, amount, ZERO_ADDRESS);
  const encrypted = await prepareEncryptedOutputNoteData({
    recipient: profilePublicKey(profile),
    payload: {
      kind: "deposit",
      chainId: BigInt(config.chainId),
      poolAddress: config.pool,
      tokenAddress: ZERO_ADDRESS,
      amount,
      ownerNullifierKeyHash: ownerHash,
      noteSecret,
      noteBodyCommitment: body,
      memo: "e2e smoke"
    }
  });
  const tx = await sendDeposit(
    provider,
    account,
    config.pool,
    ZERO_ADDRESS,
    amount,
    noteOwnerCommitment,
    encrypted.outputNoteData
  );
  await waitForTransactionReceipt(provider, tx);
  console.log(`deposited ${short(tx)}`);
  return tx;
}

async function scanForTxNote(provider, config, profile, tx) {
  const notes = await scanNotes(provider, config, profile);
  const note = [...notes]
    .reverse()
    .find((candidate) => candidate.transactionHash === tx && candidate.status === "decrypted");
  if (note === undefined) throw new Error(`deposited note not found for ${tx}`);
  return note;
}

async function scanNotes(provider, config, profile) {
  const indexer = new SepoliaDemoIndexer({
    chainId: config.chainId,
    poolAddress: config.pool,
    candidates: [{ id: "smoke profile", secretKey: profileSecretKey(profile) }]
  });
  const deposits = await getPoolDepositLogs(provider, config.pool, BigInt(config.deploymentBlock));
  for (const event of deposits) await indexer.ingestDeposit(event);
  const transacts = await getPoolTransactLogs(provider, config.pool, BigInt(config.deploymentBlock));
  for (const event of transacts) await indexer.ingestTransact(event);
  return indexer.store.all();
}

function parseDemoConfig(text) {
  const address = (name) => {
    const match = text.match(new RegExp(`${name}: '([^']+)'`));
    if (!match) throw new Error(`missing demo address ${name}`);
    return ethers.getAddress(match[1]).toLowerCase();
  };
  const chain = text.match(/SEPOLIA_CHAIN_ID = ([0-9]+)/);
  const block = text.match(/deploymentBlock = ([0-9]+)n/);
  if (!chain || !block) throw new Error("missing chain id or deployment block in demoConfig.ts");
  return {
    chainId: Number(chain[1]),
    deploymentBlock: BigInt(block[1]),
    pool: address("pool"),
    recipientRegistry: address("recipientRegistry"),
    authVerifier: address("authVerifier")
  };
}

function parseEnv(text) {
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

function revivePublicInputs(input) {
  return Object.fromEntries(
    Object.entries(input).map(([key, value]) => [key, BigInt(value)])
  );
}

function stringifyJson(value) {
  return JSON.stringify(value, (_key, field) => {
    if (typeof field === "bigint") return field.toString(10);
    if (field instanceof Uint8Array) return ethers.hexlify(field);
    return field;
  });
}

function short(value) {
  return `${value.slice(0, 10)}...${value.slice(-6)}`;
}

class WalletEip1193Provider {
  constructor(provider, wallet) {
    this.provider = provider;
    this.wallet = wallet;
  }

  async request({ method, params = [] }) {
    if (method === "eth_chainId") return ethers.toQuantity((await this.provider.getNetwork()).chainId);
    if (method === "eth_requestAccounts") return [this.wallet.address.toLowerCase()];
    if (method === "personal_sign") return this.wallet.signMessage(ethers.getBytes(params[0]));
    if (method === "eth_signTypedData_v4") {
      const typedData = JSON.parse(params[1]);
      return this.wallet.signTypedData(typedData.domain, authIntentEthersTypes(typedData), typedData.message);
    }
    if (method === "eth_sendTransaction") {
      const tx = params[0];
      const sent = await this.wallet.sendTransaction({
        to: tx.to,
        data: tx.data,
        value: tx.value ?? 0
      });
      return sent.hash;
    }
    return this.provider.send(method, params);
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
