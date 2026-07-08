// Node-only ABI + deployment loader. Reads forge artifacts from contracts/out
// and the deploy manifest assets/deployment.<chainId>.json.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Abi } from "viem";

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const ERC_ROOT = path.resolve(HERE, "../..");
const OUT = path.join(ERC_ROOT, "contracts/out");

function loadAbi(rel: string): Abi {
  return JSON.parse(fs.readFileSync(path.join(OUT, rel), "utf8")).abi as Abi;
}

export const shieldedPoolAbi = loadAbi("ShieldedPool.sol/ShieldedPool.json");
export const registryAbi = loadAbi("PrivacyIdentityRegistry.sol/PrivacyIdentityRegistry.json");
export const publicActionRouterAbi = loadAbi("PublicActionRouter.sol/PublicActionRouter.json");
export const allowlistPolicyAbi = loadAbi("SelfServeAllowlistPolicyVerifier.sol/SelfServeAllowlistPolicyVerifier.json");

export interface Deployment {
  chainId: number;
  factory: string;
  poseidonLib: string;
  registry: `0x${string}`;
  poolVerifier: `0x${string}`;
  honkVerifier: `0x${string}`;
  ecdsaAuthVerifier: `0x${string}`;
  demoAuthCore: `0x${string}`;
  demoAuthVerifier: `0x${string}`;
  allowlistPolicyVerifier: `0x${string}`;
  poolPolicyFree: `0x${string}`;
  poolAllowlistGated: `0x${string}`;
  publicActionRouter: `0x${string}`;
  deployer: `0x${string}`;
}

export function loadDeployment(chainId = 31337): Deployment {
  const file = path.join(ERC_ROOT, `assets/deployment.${chainId}.json`);
  return JSON.parse(fs.readFileSync(file, "utf8")) as Deployment;
}
