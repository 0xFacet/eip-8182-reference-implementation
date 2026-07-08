// Thin viem wrapper over PublicActionRouter (spec §17 optional profile): one
// atomic unshield -> (optional action) -> reshield tx.
//
// The router binds the move through the two transact public inputs added in spec
// §7.1:
//   * authorizedSubmitter == address(router) — the source pool only lets THIS
//     router trigger the withdrawal, so a mempool observer cannot replay the
//     proof against the pool directly (front-run guard).
//   * downstreamActionCommitment == computeDownstreamActionCommitment(...) — the
//     exact reshield/action spec is bound into the pool proof; any substituted
//     spec yields a different commitment and reverts before nullifiers spend.
//
// computeDownstreamActionCommitment mirrors PublicActionRouter.sol byte-for-byte.

import {
  encodeAbiParameters,
  keccak256,
  type Address,
  type Hex,
  type PublicClient,
  type WalletClient,
} from "viem";
import { publicActionRouterAbi } from "./abis.ts";
import { BN254_SCALAR_MODULUS } from "./field.ts";
import type { PublicInputs } from "./derivations.ts";

const asHex = (v: Uint8Array | Hex): Hex =>
  typeof v === "string" ? v : (("0x" + Buffer.from(v).toString("hex")) as Hex);

/** The downstream action + reshield spec (mirror of PublicActionRouter.ActionSpec). */
export interface ActionSpec {
  sourcePool: Address;
  tokenIn: Address;
  amountIn: bigint;
  targetPool: Address;
  tokenOut: Address;
  ownerCommitment: bigint;
  depositNoteData: Hex;
  depositPolicyData: Hex;
  minOut: bigint;
  routerDeadline: bigint;
  /** 0 = same-asset move (no external call); otherwise a single swap/bridge call. */
  actionTarget: Address;
  actionCalldata: Hex;
}

export function sameAssetMoveSpec(params: {
  sourcePool: Address;
  token: Address;
  amount: bigint;
  targetPool: Address;
  ownerCommitment: bigint;
  depositNoteData: Hex;
  depositPolicyData?: Hex;
  routerDeadline: bigint;
}): ActionSpec {
  return {
    sourcePool: params.sourcePool,
    tokenIn: params.token,
    amountIn: params.amount,
    targetPool: params.targetPool,
    tokenOut: params.token,
    ownerCommitment: params.ownerCommitment,
    depositNoteData: params.depositNoteData,
    depositPolicyData: params.depositPolicyData ?? "0x",
    minOut: params.amount,
    routerDeadline: params.routerDeadline,
    actionTarget: "0x0000000000000000000000000000000000000000",
    actionCalldata: "0x",
  };
}

export interface RouterMoveInParams {
  from: Address;
  poolProof: Hex;
  authProof: Hex;
  publicInputs: PublicInputs;
  outputNoteData: [Uint8Array | Hex, Uint8Array | Hex, Uint8Array | Hex];
  policyData: Hex;
}

export interface MoveResult {
  txHash: Hex;
  blockNumber: bigint;
}

/**
 * The field-reduced commitment binding a withdrawal to an exact downstream
 * action + reshield spec. Mirrors PublicActionRouter.computeDownstreamActionCommitment
 * (spec §17). `router` is the deployed router address (Solidity `address(this)`).
 */
export function computeDownstreamActionCommitment(
  executionChainId: bigint,
  sourcePool: Address,
  intentReplayId: bigint,
  router: Address,
  spec: ActionSpec,
): bigint {
  const actionHash = keccak256(
    encodeAbiParameters([{ type: "address" }, { type: "bytes" }], [spec.actionTarget, spec.actionCalldata]),
  );
  const reshieldHash = keccak256(
    encodeAbiParameters(
      [
        { type: "address" },
        { type: "address" },
        { type: "uint256" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "uint256" },
        { type: "uint256" },
      ],
      [
        spec.targetPool,
        spec.tokenOut,
        spec.ownerCommitment,
        keccak256(spec.depositNoteData),
        keccak256(spec.depositPolicyData),
        spec.minOut,
        spec.routerDeadline,
      ],
    ),
  );
  const outer = keccak256(
    encodeAbiParameters(
      [
        { type: "string" },
        { type: "uint256" },
        { type: "address" },
        { type: "address" },
        { type: "uint256" },
        { type: "address" },
        { type: "uint256" },
        { type: "bytes32" },
        { type: "bytes32" },
      ],
      [
        "ERCXXXX_PUBLIC_ACTION_ROUTER_V1",
        executionChainId,
        router,
        sourcePool,
        intentReplayId,
        spec.tokenIn,
        spec.amountIn,
        actionHash,
        reshieldHash,
      ],
    ),
  );
  return BigInt(outer) % BN254_SCALAR_MODULUS;
}

/** Read the router's on-chain commitment (for cross-checking the TS mirror). */
export async function readDownstreamActionCommitment(
  publicClient: PublicClient,
  router: Address,
  executionChainId: bigint,
  sourcePool: Address,
  intentReplayId: bigint,
  spec: ActionSpec,
): Promise<bigint> {
  return (await publicClient.readContract({
    address: router,
    abi: publicActionRouterAbi,
    functionName: "computeDownstreamActionCommitment",
    args: [executionChainId, sourcePool, intentReplayId, spec],
  })) as bigint;
}

/** Atomically unshield `in.from` -> router -> (optional action) -> reshield into `spec.targetPool`. */
export async function executeMove(
  wallet: WalletClient,
  publicClient: PublicClient,
  router: Address,
  account: Address,
  in_: RouterMoveInParams,
  spec: ActionSpec,
): Promise<MoveResult> {
  const moveIn = {
    from: in_.from,
    poolProof: in_.poolProof,
    authProof: in_.authProof,
    publicInputs: in_.publicInputs,
    outputNoteData0: asHex(in_.outputNoteData[0]),
    outputNoteData1: asHex(in_.outputNoteData[1]),
    outputNoteData2: asHex(in_.outputNoteData[2]),
    policyData: in_.policyData,
  };
  const hash = await wallet.writeContract({
    account,
    chain: null,
    address: router,
    abi: publicActionRouterAbi,
    functionName: "executeMove",
    args: [moveIn, spec],
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") throw new Error("router executeMove reverted");
  return { txHash: hash, blockNumber: receipt.blockNumber };
}
