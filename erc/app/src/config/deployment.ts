import type { Address } from "viem";
import deployment31337 from "../generated/deployment.31337.json";
import deployment11155111 from "../generated/deployment.11155111.json";

export interface Deployment {
  chainId: number;
  registry: Address;
  poolVerifier: Address;
  honkVerifier: Address;
  ecdsaAuthVerifier: Address;
  allowlistPolicyVerifier: Address;
  poolPolicyFree: Address;
  poolAllowlistGated: Address;
  publicActionRouter: Address;
  deployer: Address;
  deploymentBlocks?: Partial<Record<DeploymentBlockKey, number>>;
}

export const ANVIL_CHAIN_ID = 31337;
export const SEPOLIA_CHAIN_ID = 11155111;

type DeploymentBlockKey = "registry" | "poolPolicyFree" | "poolAllowlistGated" | "publicActionRouter";

export const deployments: Record<number, Deployment> = {
  [ANVIL_CHAIN_ID]: deployment31337 as Deployment,
  [SEPOLIA_CHAIN_ID]: deployment11155111 as Deployment,
};

export function getDeployment(chainId: number | undefined): Deployment | undefined {
  if (chainId === undefined) return deployments[ANVIL_CHAIN_ID];
  return deployments[chainId];
}

export interface PoolMeta {
  key: "free" | "gated";
  label: string;
  sub: string;
  address: Address;
  gated: boolean;
  startBlock: bigint;
}

export function deploymentStartBlock(d: Deployment, key: DeploymentBlockKey): bigint {
  return BigInt(d.deploymentBlocks?.[key] ?? 0);
}

export function poolsOf(d: Deployment): PoolMeta[] {
  return [
    {
      key: "free",
      label: "Policy-Free Pool",
      sub: "Open shielded pool — no attestation required",
      address: d.poolPolicyFree,
      gated: false,
      startBlock: deploymentStartBlock(d, "poolPolicyFree"),
    },
    {
      key: "gated",
      label: "Allowlist-Gated Pool",
      sub: "Deposits & withdrawals require joining the on-chain demo allowlist",
      address: d.poolAllowlistGated,
      gated: true,
      startBlock: deploymentStartBlock(d, "poolAllowlistGated"),
    },
  ];
}
