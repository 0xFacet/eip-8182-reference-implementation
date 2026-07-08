// Deploys the full reference stack to the chain at --rpc (default local anvil):
//   1. Arachnid CREATE2 factory (installs via the canonical presigned tx if absent)
//   2. Canonical singletons via CREATE2: Poseidon2 permute lib, privacy identity
//      registry, canonical pool verifier — addresses/salts/codehashes must match
//      assets/deployment.json (hard assert).
//   3. Peripherals via CREATE: HonkVerifier + EcdsaEip712AuthVerifier,
//      AuthDemoGroth16VerifierCore + DemoAuthVerifier, SelfServeAllowlistPolicyVerifier,
//      two ShieldedPools (policy-free; allowlist DEPOSIT|WITHDRAWAL),
//      PublicActionRouter.
//   4. Writes assets/deployment.<chainId>.json with every address.
//
// Usage:
//   node scripts/deploy_all.mjs --rpc http://127.0.0.1:8545 --key 0x<privkey>
//   node scripts/deploy_all.mjs --rpc https://... --fresh-registry
//
// anvil default key0 is used when --key is omitted and the chain is 31337.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createPublicClient, createWalletClient, http, keccak256, concatHex, getCreate2Address, parseEther } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ERC = path.resolve(HERE, "..");
const OUT = path.join(ERC, "contracts/out");

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, cur, i, arr) => {
    if (cur.startsWith("--")) acc.push([cur.slice(2), arr[i + 1]]);
    return acc;
  }, []),
);
const RPC = args.rpc ?? "http://127.0.0.1:8545";
const FRESH_REGISTRY = "fresh-registry" in args;
const ANVIL_KEY0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

// Canonical keyless CREATE2 factory (Arachnid deterministic-deployment-proxy).
const FACTORY = "0x4e59b44847b379578588920ca78fbf26c0b4956c";
const FACTORY_DEPLOYER = "0x3fab184622dc19b6109349b94811493bf2a45362";
const FACTORY_RAW_TX =
  "0xf8a58085174876e800830186a08080b853604580600e600d39f3fe7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf31ba02222222222222222222222222222222222222222222222222222222222222222a02222222222222222222222222222222222222222222222222222222222222222";

const plan = JSON.parse(fs.readFileSync(path.join(ERC, "assets/deployment.json"), "utf8"));
const initcodes = JSON.parse(fs.readFileSync(path.join(ERC, "build/deploy/initcodes.json"), "utf8"));

const publicClient = createPublicClient({ transport: http(RPC) });
const chainId = await publicClient.getChainId();
const key = args.key ?? (chainId === 31337 ? ANVIL_KEY0 : process.env.SEPOLIA_PRIVATE_KEY);
if (!key) throw new Error("no deploy key: pass --key or set SEPOLIA_PRIVATE_KEY");
const account = privateKeyToAccount(key);
const wallet = createWalletClient({ account, transport: http(RPC) });
const chain = { id: chainId, name: `chain-${chainId}`, nativeCurrency: { name: "ETH", symbol: "ETH", decimals: 18 }, rpcUrls: { default: { http: [RPC] } } };
const outFile = path.join(ERC, `assets/deployment.${chainId}.json`);
const previousManifest = fs.existsSync(outFile) ? JSON.parse(fs.readFileSync(outFile, "utf8")) : {};
const deploymentBlocks = { ...(previousManifest.deploymentBlocks ?? {}) };

console.log(`deploying to chain ${chainId} as ${account.address}`);

async function waitFor(hash) {
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") throw new Error(`tx ${hash} failed`);
  return receipt;
}

async function ensureFactory() {
  const code = await publicClient.getCode({ address: FACTORY }).catch(() => undefined);
  if (code && code !== "0x") return console.log("factory: already installed");
  console.log("factory: installing via presigned tx");
  const fund = await wallet.sendTransaction({ chain, to: FACTORY_DEPLOYER, value: parseEther("0.03") });
  await waitFor(fund);
  const hash = await publicClient.sendRawTransaction({ serializedTransaction: FACTORY_RAW_TX });
  await waitFor(hash);
  const after = await publicClient.getCode({ address: FACTORY });
  if (!after || after === "0x") throw new Error("factory install failed");
}

async function deploySingleton(name, entry, initCode) {
  const existing = await publicClient.getCode({ address: entry.address }).catch(() => undefined);
  if (existing && existing !== "0x") {
    console.log(`${name}: already at ${entry.address}`);
  } else {
    const predicted = getCreate2Address({ from: FACTORY, salt: entry.salt, bytecode: initCode });
    if (predicted.toLowerCase() !== entry.address.toLowerCase()) {
      throw new Error(`${name}: plan address mismatch (plan ${entry.address}, predicted ${predicted}) — rerun compute_deployment.js`);
    }
    const hash = await wallet.sendTransaction({ chain, to: FACTORY, data: concatHex([entry.salt, initCode]), gas: 8_000_000n });
    const receipt = await waitFor(hash);
    deploymentBlocks[name] = Number(receipt.blockNumber);
    console.log(`${name}: deployed at ${entry.address}`);
  }
  const runtime = await publicClient.getCode({ address: entry.address });
  const hash = keccak256(runtime);
  if (hash !== entry.runtimeCodeHash) {
    throw new Error(`${name}: extcodehash mismatch (${hash} != plan ${entry.runtimeCodeHash})`);
  }
  console.log(`${name}: runtime code hash pinned OK`);
}

function artifact(rel) {
  return JSON.parse(fs.readFileSync(path.join(OUT, rel), "utf8"));
}

// Deployed-on-demand sub-libraries (e.g. HonkVerifier's ZKTranscriptLib),
// keyed by library name. The canonical Poseidon lib is pre-seeded.
const libAddressByName = { LibPoseidon2Permute: plan.poseidonLib.address };

async function resolveLibrary(libName) {
  if (libAddressByName[libName]) return libAddressByName[libName];
  // Sub-libraries live in the same artifact dir as their parent; find the file.
  const candidates = fs.readdirSync(OUT).flatMap((dir) => {
    const p = path.join(OUT, dir, `${libName}.json`);
    return fs.existsSync(p) ? [path.join(dir, `${libName}.json`)] : [];
  });
  if (candidates.length === 0) throw new Error(`no artifact for library ${libName}`);
  const addr = await deployRaw(libName, artifact(candidates[0]));
  libAddressByName[libName] = addr;
  return addr;
}

async function linkedBytecode(art) {
  let code = art.bytecode.object;
  for (const [, libs] of Object.entries(art.bytecode.linkReferences ?? {})) {
    for (const libName of Object.keys(libs)) {
      const addr = await resolveLibrary(libName);
      // forge placeholder is __$<34hex>$__ per library; replace all occurrences
      code = code.replaceAll(/__\$[0-9a-f]{34}\$__/g, addr.slice(2));
    }
  }
  return code;
}

async function deployRaw(name, art, constructorArgsHex = "0x") {
  const code = await linkedBytecode(art);
  const hash = await wallet.sendTransaction({ chain, data: concatHex([code, constructorArgsHex]), gas: 15_000_000n });
  const receipt = await waitFor(hash);
  deploymentBlocks[name] = Number(receipt.blockNumber);
  console.log(`${name}: ${receipt.contractAddress}`);
  return receipt.contractAddress;
}

async function deployContract(name, rel, constructorArgsHex = "0x") {
  return deployRaw(name, artifact(rel), constructorArgsHex);
}

import { encodeAbiParameters } from "viem";
const addr = (a) => ({ type: "address", value: a });

await ensureFactory();
await deploySingleton("poseidonLib", plan.poseidonLib, initcodes.poseidonLib);
await deploySingleton("poolVerifier", plan.poolVerifier, initcodes.poolVerifier);

// Peripherals (plain CREATE — only the singletons need determinism).
let registry = plan.registry.address;
if (FRESH_REGISTRY) {
  registry = await deployContract("registry", "PrivacyIdentityRegistry.sol/PrivacyIdentityRegistry.json");
  const runtime = await publicClient.getCode({ address: registry });
  const runtimeHash = keccak256(runtime);
  if (runtimeHash !== plan.registry.runtimeCodeHash) {
    throw new Error(`registry: runtime code hash mismatch (${runtimeHash} != plan ${plan.registry.runtimeCodeHash})`);
  }
  console.log("registry: fresh demo instance runtime code hash pinned OK");
} else {
  await deploySingleton("registry", plan.registry, initcodes.registry);
}
const honkVerifier = await deployContract("honkVerifier", "HonkVerifier.sol/HonkVerifier.json");
const ecdsaAuthVerifier = await deployContract(
  "ecdsaAuthVerifier",
  "EcdsaEip712AuthVerifier.sol/EcdsaEip712AuthVerifier.json",
  encodeAbiParameters([{ type: "address" }], [honkVerifier]),
);
const demoAuthCore = await deployContract("demoAuthCore", "AuthDemoGroth16VerifierCore.sol/AuthDemoGroth16VerifierCore.json");
const demoAuthVerifier = await deployContract(
  "demoAuthVerifier",
  "DemoAuthVerifier.sol/DemoAuthVerifier.json",
  encodeAbiParameters([{ type: "address" }], [demoAuthCore]),
);
const allowlistVerifier = await deployContract(
  "allowlistPolicyVerifier",
  "SelfServeAllowlistPolicyVerifier.sol/SelfServeAllowlistPolicyVerifier.json",
);
const poolArgs = (policyVerifier, applies) =>
  encodeAbiParameters(
    [{ type: "address" }, { type: "address" }, { type: "address" }, { type: "uint256" }],
    [registry, plan.poolVerifier.address, policyVerifier, applies],
  );
const poolFree = await deployContract("poolPolicyFree", "ShieldedPool.sol/ShieldedPool.json",
  poolArgs("0x0000000000000000000000000000000000000000", 0n));
const poolGated = await deployContract("poolAllowlistGated", "ShieldedPool.sol/ShieldedPool.json",
  poolArgs(allowlistVerifier, 5n)); // DEPOSIT(1) | WITHDRAWAL(4)
const publicActionRouter = await deployContract("publicActionRouter", "PublicActionRouter.sol/PublicActionRouter.json");

fs.writeFileSync(outFile, JSON.stringify({
  chainId,
  factory: FACTORY,
  poseidonLib: plan.poseidonLib.address,
  registry,
  poolVerifier: plan.poolVerifier.address,
  honkVerifier,
  ecdsaAuthVerifier,
  demoAuthCore,
  demoAuthVerifier,
  allowlistPolicyVerifier: allowlistVerifier,
  poolPolicyFree: poolFree,
  poolAllowlistGated: poolGated,
  publicActionRouter,
  deployer: account.address,
  deploymentBlocks,
}, null, 2) + "\n");
console.log(`wrote ${outFile}`);
