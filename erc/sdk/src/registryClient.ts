// Thin viem wrapper over the canonical privacy identity registry: registration,
// and event-sourced reconstruction of the depth-32 identity tree (spec §6/§15.4).

import type { Address, PublicClient, WalletClient } from "viem";
import { registryAbi } from "./abis.ts";
import { SparseTree } from "./trees.ts";

export interface RegisterProfileParams {
  ownerNullifierKeyHash: bigint;
  noteSecretSeedHash: bigint;
  policySetCommitment: bigint;
  mlKem768PublicKey: `0x${string}`;
  metadataVersion?: number;
}

export interface RegisterResult {
  leafPosition: bigint;
  leafValue: bigint;
  identityRoot: bigint;
  blockNumber: bigint;
}

/** setFullProfile from `account`, returning the assigned leaf position + root. */
export async function registerFullProfile(
  wallet: WalletClient,
  publicClient: PublicClient,
  registry: Address,
  account: Address,
  p: RegisterProfileParams,
): Promise<RegisterResult> {
  const hash = await wallet.writeContract({
    account,
    chain: null,
    address: registry,
    abi: registryAbi,
    functionName: "setFullProfile",
    args: [
      p.ownerNullifierKeyHash,
      p.noteSecretSeedHash,
      p.policySetCommitment,
      p.mlKem768PublicKey,
      p.metadataVersion ?? 1,
    ],
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") throw new Error("setFullProfile reverted");
  const events = await publicClient.getContractEvents({
    address: registry,
    abi: registryAbi,
    eventName: "IdentitySet",
    fromBlock: receipt.blockNumber,
    toBlock: receipt.blockNumber,
  });
  const mine = events.find((e) => (e.args as { user: string }).user.toLowerCase() === account.toLowerCase());
  if (!mine) throw new Error("IdentitySet event not found");
  const args = mine.args as { leafPosition: bigint; leafValue: bigint; postUpdateIdentityRoot: bigint };
  return {
    leafPosition: BigInt(args.leafPosition),
    leafValue: args.leafValue,
    identityRoot: args.postUpdateIdentityRoot,
    blockNumber: receipt.blockNumber,
  };
}

export interface IdentityTree {
  tree: SparseTree;
  root: bigint;
  /** address (lowercased) -> {leafPosition, leafValue}. */
  byUser: Map<string, { leafPosition: bigint; leafValue: bigint }>;
}

/** Rebuild the depth-32 identity SparseTree from IdentitySet events. */
export async function rebuildIdentityTree(publicClient: PublicClient, registry: Address): Promise<IdentityTree> {
  const events = await publicClient.getContractEvents({
    address: registry,
    abi: registryAbi,
    eventName: "IdentitySet",
    fromBlock: 0n,
  });
  const tree = new SparseTree(32);
  const byUser = new Map<string, { leafPosition: bigint; leafValue: bigint }>();
  for (const e of events) {
    const a = e.args as { user: string; leafPosition: bigint; leafValue: bigint };
    const leafPosition = BigInt(a.leafPosition);
    tree.set(leafPosition, a.leafValue);
    byUser.set(a.user.toLowerCase(), { leafPosition, leafValue: a.leafValue });
  }
  return { tree, root: tree.root(), byUser };
}

export interface IdentityProof {
  leafPosition: bigint;
  siblings: bigint[];
  root: bigint;
}

/** Identity membership proof (siblings + root) for a user, from live events. */
export async function getIdentityProof(
  publicClient: PublicClient,
  registry: Address,
  user: Address,
): Promise<IdentityProof> {
  const { tree, root, byUser } = await rebuildIdentityTree(publicClient, registry);
  const entry = byUser.get(user.toLowerCase());
  if (!entry) throw new Error(`no identity for ${user}`);
  return { leafPosition: entry.leafPosition, siblings: tree.proof(entry.leafPosition), root };
}

/** On-chain current identity root (for cross-checks). */
export async function getCurrentIdentityRoot(publicClient: PublicClient, registry: Address): Promise<bigint> {
  return (await publicClient.readContract({
    address: registry,
    abi: registryAbi,
    functionName: "getCurrentIdentityRoot",
  })) as bigint;
}
