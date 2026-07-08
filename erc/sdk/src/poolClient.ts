// Thin viem wrapper over a ShieldedPool: deposit, transact, and event-sourced
// reconstruction of the depth-32 append-only note-commitment tree (spec §15.4).

import type { Address, Hex, PublicClient, WalletClient } from "viem";
import { shieldedPoolAbi } from "./abis.ts";
import { depositOperationDataHash, policyOperationDigest } from "./derivations.ts";
import { POLICY_OPERATION_DEPOSIT } from "./generated/constants.ts";
import { keccakField } from "./field.ts";
import { AppendOnlyTree } from "./trees.ts";
import type { PublicInputs } from "./derivations.ts";

export interface DepositParams {
  token: Address;
  amount: bigint;
  ownerCommitment: bigint;
  outputNoteData: Hex;
  policyData: Hex;
}

export interface DepositResult {
  leafIndex: bigint;
  noteCommitment: bigint;
  postRoot: bigint;
  txHash: Hex;
}

export async function deposit(
  wallet: WalletClient,
  publicClient: PublicClient,
  pool: Address,
  account: Address,
  p: DepositParams,
): Promise<DepositResult> {
  const value = p.token === "0x0000000000000000000000000000000000000000" ? p.amount : 0n;
  const hash = await wallet.writeContract({
    account,
    chain: null,
    address: pool,
    abi: shieldedPoolAbi,
    functionName: "deposit",
    args: [p.token, p.amount, p.ownerCommitment, p.outputNoteData, p.policyData],
    value,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") throw new Error("deposit reverted");
  const events = await publicClient.getContractEvents({
    address: pool,
    abi: shieldedPoolAbi,
    eventName: "ShieldedPoolDeposit",
    fromBlock: receipt.blockNumber,
    toBlock: receipt.blockNumber,
  });
  const ev = events.find((e) => e.transactionHash?.toLowerCase() === hash.toLowerCase());
  if (!ev) throw new Error("ShieldedPoolDeposit event not found");
  const a = ev.args as { noteCommitment: bigint; leafIndex: bigint; postInsertionCommitmentRoot: bigint };
  return { leafIndex: BigInt(a.leafIndex), noteCommitment: a.noteCommitment, postRoot: a.postInsertionCommitmentRoot, txHash: hash };
}

export interface TransactCall {
  poolProof: Hex;
  authProof: Hex;
  publicInputs: PublicInputs;
  outputNoteData: [Uint8Array | Hex, Uint8Array | Hex, Uint8Array | Hex];
  policyData: Hex;
}

const asHex = (v: Uint8Array | Hex): Hex =>
  typeof v === "string" ? v : (("0x" + Buffer.from(v).toString("hex")) as Hex);

export interface TransactResult {
  leafIndex0: bigint;
  noteCommitments: [bigint, bigint, bigint];
  postRoot: bigint;
  txHash: Hex;
}

export async function transact(
  wallet: WalletClient,
  publicClient: PublicClient,
  pool: Address,
  account: Address,
  c: TransactCall,
): Promise<TransactResult> {
  const hash = await wallet.writeContract({
    account,
    chain: null,
    address: pool,
    abi: shieldedPoolAbi,
    functionName: "transact",
    args: [
      c.poolProof,
      c.authProof,
      c.publicInputs,
      asHex(c.outputNoteData[0]),
      asHex(c.outputNoteData[1]),
      asHex(c.outputNoteData[2]),
      c.policyData,
    ],
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") throw new Error("transact reverted");
  const events = await publicClient.getContractEvents({
    address: pool,
    abi: shieldedPoolAbi,
    eventName: "ShieldedPoolTransact",
    fromBlock: receipt.blockNumber,
    toBlock: receipt.blockNumber,
  });
  const ev = events.find((e) => e.transactionHash?.toLowerCase() === hash.toLowerCase());
  if (!ev) throw new Error("ShieldedPoolTransact event not found");
  const a = ev.args as {
    noteCommitment0: bigint;
    noteCommitment1: bigint;
    noteCommitment2: bigint;
    leafIndex0: bigint;
    postInsertionCommitmentRoot: bigint;
  };
  return {
    leafIndex0: BigInt(a.leafIndex0),
    noteCommitments: [a.noteCommitment0, a.noteCommitment1, a.noteCommitment2],
    postRoot: a.postInsertionCommitmentRoot,
    txHash: hash,
  };
}

/** Simulate a transact (no state change) — used by the negative harness to assert reverts. */
export async function simulateTransact(
  publicClient: PublicClient,
  pool: Address,
  account: Address,
  c: TransactCall,
): Promise<void> {
  await publicClient.simulateContract({
    account,
    address: pool,
    abi: shieldedPoolAbi,
    functionName: "transact",
    args: [
      c.poolProof,
      c.authProof,
      c.publicInputs,
      asHex(c.outputNoteData[0]),
      asHex(c.outputNoteData[1]),
      asHex(c.outputNoteData[2]),
      c.policyData,
    ],
  });
}

export interface NoteTree {
  tree: AppendOnlyTree;
  root: bigint;
  leaves: bigint[];
}

/** Rebuild the append-only note tree from Deposit + Transact events, in leaf order. */
export async function rebuildNoteTree(publicClient: PublicClient, pool: Address): Promise<NoteTree> {
  const deposits = await publicClient.getContractEvents({
    address: pool,
    abi: shieldedPoolAbi,
    eventName: "ShieldedPoolDeposit",
    fromBlock: 0n,
  });
  const transacts = await publicClient.getContractEvents({
    address: pool,
    abi: shieldedPoolAbi,
    eventName: "ShieldedPoolTransact",
    fromBlock: 0n,
  });
  const entries: Array<{ leafIndex: bigint; commitment: bigint }> = [];
  for (const e of deposits) {
    const a = e.args as { leafIndex: bigint; noteCommitment: bigint };
    entries.push({ leafIndex: BigInt(a.leafIndex), commitment: a.noteCommitment });
  }
  for (const e of transacts) {
    const a = e.args as { leafIndex0: bigint; noteCommitment0: bigint; noteCommitment1: bigint; noteCommitment2: bigint };
    const i0 = BigInt(a.leafIndex0);
    entries.push({ leafIndex: i0, commitment: a.noteCommitment0 });
    entries.push({ leafIndex: i0 + 1n, commitment: a.noteCommitment1 });
    entries.push({ leafIndex: i0 + 2n, commitment: a.noteCommitment2 });
  }
  entries.sort((x, y) => (x.leafIndex < y.leafIndex ? -1 : x.leafIndex > y.leafIndex ? 1 : 0));
  const tree = new AppendOnlyTree(32);
  const leaves: bigint[] = [];
  for (const entry of entries) {
    if (entry.leafIndex !== tree.nextLeafIndex) {
      throw new Error(`note tree gap: expected leaf ${tree.nextLeafIndex}, got ${entry.leafIndex}`);
    }
    tree.append(entry.commitment);
    leaves.push(entry.commitment);
  }
  return { tree, root: tree.root(), leaves };
}

export interface NoteProof {
  siblings: bigint[];
  root: bigint;
}

export async function getNoteProof(publicClient: PublicClient, pool: Address, leafIndex: bigint): Promise<NoteProof> {
  const { tree, root } = await rebuildNoteTree(publicClient, pool);
  return { siblings: tree.proof(leafIndex), root };
}

export async function getCurrentRoots(publicClient: PublicClient, pool: Address): Promise<{ noteCommitmentRoot: bigint; identityRoot: bigint }> {
  const [noteCommitmentRoot, identityRoot] = (await publicClient.readContract({
    address: pool,
    abi: shieldedPoolAbi,
    functionName: "getCurrentRoots",
  })) as [bigint, bigint];
  return { noteCommitmentRoot, identityRoot };
}

export async function isNullifierSpent(publicClient: PublicClient, pool: Address, nullifier: bigint): Promise<boolean> {
  return (await publicClient.readContract({ address: pool, abi: shieldedPoolAbi, functionName: "isNullifierSpent", args: [nullifier] })) as boolean;
}

export async function isIntentReplayIdUsed(publicClient: PublicClient, pool: Address, replayId: bigint): Promise<boolean> {
  return (await publicClient.readContract({ address: pool, abi: shieldedPoolAbi, functionName: "isIntentReplayIdUsed", args: [replayId] })) as boolean;
}

/**
 * Compute the policy operation digest for a gated deposit (spec §16.1). `sender`
 * is the address that calls deposit (for a router reshield, the router).
 */
export function depositPolicyOperationDigest(params: {
  chainId: bigint;
  poolAddress: bigint;
  policyVerifier: bigint;
  sender: bigint;
  token: bigint;
  amount: bigint;
  ownerCommitment: bigint;
  outputNoteData: Uint8Array;
}): bigint {
  const opData = depositOperationDataHash(
    params.chainId,
    params.poolAddress,
    params.sender,
    params.token,
    params.amount,
    params.ownerCommitment,
    keccakField(params.outputNoteData),
  );
  return policyOperationDigest(params.chainId, params.poolAddress, params.policyVerifier, POLICY_OPERATION_DEPOSIT, opData);
}
