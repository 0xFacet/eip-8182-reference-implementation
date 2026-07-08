// Shared e2e / negative-test harness: fresh anvil lifecycle, full-stack deploy,
// viem clients, and identity construction. Node-only (spawns anvil + deploy).

import { execFileSync, spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createPublicClient, createWalletClient, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import * as D from "../../sdk/src/derivations.ts";
import { SparseTree } from "../../sdk/src/trees.ts";
import { generateReceiveKeyPair } from "../../sdk/src/envelope.ts";
import { loadDeployment } from "../../sdk/src/abis.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ERC = path.resolve(HERE, "../..");
const ANVIL = process.env.ANVIL ?? path.join(process.env.HOME, ".foundry/bin/anvil");

export const CHAIN_ID = 31337n;
export const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

// anvil deterministic accounts.
export const ANVIL_KEYS = {
  deployer: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", // 0xf39F..2266
  sender: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d", // 0x7099..79C8
  recipient: "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a", // 0x3C44..93BC
  withdrawTo: "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6", // 0x90F7..b906
};

export function anvilChain(rpc) {
  return { id: 31337, name: "anvil", nativeCurrency: { name: "ETH", symbol: "ETH", decimals: 18 }, rpcUrls: { default: { http: [rpc] } } };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Spawn a fresh anvil on `port`, wait for RPC, and return a handle. */
export async function startAnvil(port = 8600) {
  const rpc = `http://127.0.0.1:${port}`;
  const proc = spawn(ANVIL, ["--port", String(port), "--silent"], { stdio: "ignore" });
  proc.on("error", (e) => {
    throw e;
  });
  proc.unref(); // never let the anvil child keep the node process alive
  const chain = anvilChain(rpc);
  const publicClient = createPublicClient({ chain, transport: http(rpc) });
  for (let i = 0; i < 100; i++) {
    try {
      await publicClient.getChainId();
      return { proc, rpc, port, chain, publicClient, stop: () => proc.kill("SIGKILL") };
    } catch {
      await sleep(150);
    }
  }
  proc.kill("SIGKILL");
  throw new Error(`anvil did not come up on ${rpc}`);
}

/** Deploy the full reference stack to `rpc` and return the deployment manifest. */
export function deployStack(rpc) {
  execFileSync("node", [path.join(ERC, "scripts/deploy_all.mjs"), "--rpc", rpc], {
    cwd: ERC,
    env: { ...process.env, FOUNDRY_OFFLINE: "true" },
    stdio: "pipe",
  });
  return loadDeployment(31337);
}

/**
 * Build a full identity: onk/seed hashes, an ECDSA policy-set commitment (depth 8,
 * policyCommitment at `slot`), an ML-KEM-768 receive key, and a viem wallet.
 */
export function createIdentity(rpc, authVerifier, spec) {
  const chain = anvilChain(rpc);
  const account = privateKeyToAccount(spec.privateKey);
  const onkHash = D.ownerNullifierKeyHash(spec.onk);
  const seedHash = D.noteSecretSeedHash(spec.seed);
  const authDataCommitment = D.eip712AuthDataCommitment(BigInt(account.address));
  const policyCommitment = D.policyCommitment(authVerifier, authDataCommitment, spec.blinder);
  const policySet = new SparseTree(8);
  policySet.set(spec.slot, policyCommitment);
  const kem = generateReceiveKeyPair(new Uint8Array(64).fill(spec.kemSeedByte));
  return {
    account,
    address: account.address,
    wallet: createWalletClient({ account, chain, transport: http(rpc) }),
    onk: spec.onk,
    seed: spec.seed,
    blinder: spec.blinder,
    slot: spec.slot,
    onkHash,
    seedHash,
    authDataCommitment,
    policyCommitment,
    policySetCommitment: policySet.root(),
    policySetSiblings: policySet.proof(spec.slot),
    kem,
  };
}

/** Assemble the `spender` object buildTransactSession expects, given an identity + identity proof. */
export function spenderFrom(identity, identityProof) {
  return {
    account: identity.account,
    ownerNullifierKey: identity.onk,
    noteSecretSeed: identity.seed,
    noteSecretSeedHash: identity.seedHash,
    policySetCommitment: identity.policySetCommitment,
    registrationBlinder: identity.blinder,
    authDataCommitment: identity.authDataCommitment,
    policySlot: identity.slot,
    policySetSiblings: identity.policySetSiblings,
    identityLeafPosition: identityProof.leafPosition,
    identitySiblings: identityProof.siblings,
  };
}
