// Browser-safe viem read/write helpers over the registry, pools, and router.
// Mirrors the Node SDK clients but uses generated ABIs (no node fs imports).

import { encodeAbiParameters, keccak256, type Address, type Hex, type PublicClient, type WalletClient } from "viem";
import { allowlistPolicyAbi, registryAbi, shieldedPoolAbi, publicActionRouterAbi } from "../generated/abis.ts";
import type { PublicInputs } from "../../../sdk/src/derivations.ts";
import { BN254_SCALAR_MODULUS } from "../../../sdk/src/field.ts";
import { DUMMY_OWNER_NULLIFIER_KEY_HASH, OUTPUT_NOTE_DATA_SUITE, REGISTRY_ID } from "../../../sdk/src/generated/constants.ts";
import { CANONICAL_PRIVACY_REGISTRY_RUNTIME_CODE_HASH } from "../../../sdk/src/generated/addresses.ts";

const ZERO: Address = "0x0000000000000000000000000000000000000000";
export interface PrivacyProfile {
  identityRegistered: boolean;
  identity: {
    leafPosition: number;
    ownerNullifierKeyHash: bigint;
    noteSecretSeedHash: bigint;
    policySetCommitment: bigint;
  };
  receiveRegistered: boolean;
  receive: { mlKem768PublicKey: Hex; metadataVersion: number };
}

export async function getPrivacyProfile(
  pub: PublicClient,
  registry: Address,
  user: Address,
): Promise<PrivacyProfile> {
  const [identityRegistered, identity, receiveRegistered, receive] = (await pub.readContract({
    address: registry,
    abi: registryAbi,
    functionName: "getPrivacyProfile",
    args: [user],
  })) as [
    boolean,
    { leafPosition: number; ownerNullifierKeyHash: bigint; noteSecretSeedHash: bigint; policySetCommitment: bigint },
    boolean,
    { mlKem768PublicKey: Hex; metadataVersion: number },
  ];
  return { identityRegistered, identity, receiveRegistered, receive };
}

export async function getCurrentIdentityRoot(pub: PublicClient, registry: Address): Promise<bigint> {
  return (await pub.readContract({ address: registry, abi: registryAbi, functionName: "getCurrentIdentityRoot" })) as bigint;
}

export async function setFullProfile(
  wallet: WalletClient,
  pub: PublicClient,
  registry: Address,
  account: Address,
  p: {
    ownerNullifierKeyHash: bigint;
    noteSecretSeedHash: bigint;
    policySetCommitment: bigint;
    mlKem768PublicKey: Hex;
    metadataVersion?: number;
  },
): Promise<Hex> {
  const hash = await wallet.writeContract({
    account,
    chain: wallet.chain,
    address: registry,
    abi: registryAbi,
    functionName: "setFullProfile",
    args: [p.ownerNullifierKeyHash, p.noteSecretSeedHash, p.policySetCommitment, p.mlKem768PublicKey, p.metadataVersion ?? 1],
  });
  const receipt = await pub.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") throw new Error("setFullProfile reverted");
  return hash;
}

export interface ResolvedRecipient {
  ownerNullifierKeyHash: bigint;
  mlKem768PublicKey: Hex;
  leafPosition: bigint;
  metadataVersion: number;
}

export type RecipientResolution =
  | { ok: true; recipient: ResolvedRecipient }
  | { ok: false; reason: string };

export async function resolveRecipient(
  pub: PublicClient,
  addresses: { registry: Address; pool: Address },
  recipient: Address,
): Promise<RecipientResolution> {
  const { registry, pool } = addresses;
  const code = await pub.getCode({ address: registry });
  if (!code || code === "0x") return { ok: false, reason: "registry has no code" };
  if (keccak256(code).toLowerCase() !== CANONICAL_PRIVACY_REGISTRY_RUNTIME_CODE_HASH.toLowerCase()) {
    return { ok: false, reason: "registry runtime code hash is not canonical" };
  }

  const registryId = (await pub.readContract({
    address: registry,
    abi: registryAbi,
    functionName: "ercXXXXPrivacyRegistryId",
  })) as Hex;
  if (registryId.toLowerCase() !== REGISTRY_ID.toLowerCase()) return { ok: false, reason: "registry id mismatch" };

  const [registrySuite, poolSuite] = (await Promise.all([
    pub.readContract({ address: registry, abi: registryAbi, functionName: "outputNoteDataSuite" }),
    pub.readContract({ address: pool, abi: shieldedPoolAbi, functionName: "outputNoteDataSuite" }),
  ])) as [string, string];
  if (registrySuite !== OUTPUT_NOTE_DATA_SUITE) return { ok: false, reason: "registry suite mismatch" };
  if (poolSuite !== registrySuite) return { ok: false, reason: "pool/registry suite mismatch" };

  const profile = (await pub.readContract({
    address: registry,
    abi: registryAbi,
    functionName: "getPrivacyProfile",
    args: [recipient],
  })) as [
    boolean,
    { leafPosition: number | bigint; ownerNullifierKeyHash: bigint; noteSecretSeedHash: bigint; policySetCommitment: bigint },
    boolean,
    { mlKem768PublicKey: Hex; metadataVersion: number },
  ];
  const [identityRegistered, identity, receiveRegistered, receive] = profile;
  if (!identityRegistered) return { ok: false, reason: "recipient has no identity entry" };
  if (!receiveRegistered) return { ok: false, reason: "recipient has no receive entry" };

  const onk = BigInt(identity.ownerNullifierKeyHash);
  if (onk >= BN254_SCALAR_MODULUS) return { ok: false, reason: "ownerNullifierKeyHash >= p" };
  if (onk === 0n) return { ok: false, reason: "ownerNullifierKeyHash == 0" };
  if (onk === DUMMY_OWNER_NULLIFIER_KEY_HASH) return { ok: false, reason: "ownerNullifierKeyHash == DUMMY" };
  if ((receive.mlKem768PublicKey.length - 2) / 2 !== 1184) return { ok: false, reason: "ML-KEM public key length != 1184" };

  return {
    ok: true,
    recipient: {
      ownerNullifierKeyHash: onk,
      mlKem768PublicKey: receive.mlKem768PublicKey,
      leafPosition: BigInt(identity.leafPosition),
      metadataVersion: Number(receive.metadataVersion),
    },
  };
}

export async function getCurrentRoots(pub: PublicClient, pool: Address): Promise<{ noteCommitmentRoot: bigint; identityRoot: bigint }> {
  const [noteCommitmentRoot, identityRoot] = (await pub.readContract({
    address: pool,
    abi: shieldedPoolAbi,
    functionName: "getCurrentRoots",
  })) as [bigint, bigint];
  return { noteCommitmentRoot, identityRoot };
}

export async function policyAppliesToOperations(pub: PublicClient, pool: Address): Promise<bigint> {
  return (await pub.readContract({ address: pool, abi: shieldedPoolAbi, functionName: "policyAppliesToOperations" })) as bigint;
}

export async function policyVerifier(pub: PublicClient, pool: Address): Promise<Address> {
  return (await pub.readContract({ address: pool, abi: shieldedPoolAbi, functionName: "policyVerifier" })) as Address;
}

export async function isAllowlisted(pub: PublicClient, verifier: Address, account: Address): Promise<boolean> {
  return (await pub.readContract({
    address: verifier,
    abi: allowlistPolicyAbi,
    functionName: "isAllowed",
    args: [account],
  })) as boolean;
}

export async function joinAllowlist(
  wallet: WalletClient,
  pub: PublicClient,
  verifier: Address,
  account: Address,
): Promise<Hex> {
  const hash = await wallet.writeContract({
    account,
    chain: wallet.chain,
    address: verifier,
    abi: allowlistPolicyAbi,
    functionName: "joinAllowlist",
  });
  const receipt = await pub.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") throw new Error("joinAllowlist reverted");
  return hash;
}

export async function isNullifierSpent(pub: PublicClient, pool: Address, nullifier: bigint): Promise<boolean> {
  return (await pub.readContract({ address: pool, abi: shieldedPoolAbi, functionName: "isNullifierSpent", args: [nullifier] })) as boolean;
}

export async function poolBalance(pub: PublicClient, pool: Address): Promise<bigint> {
  return await pub.getBalance({ address: pool });
}

export interface DepositParams {
  token: Address;
  amount: bigint;
  ownerCommitment: bigint;
  outputNoteData: Hex;
  policyData: Hex;
}

export async function deposit(
  wallet: WalletClient,
  pub: PublicClient,
  pool: Address,
  account: Address,
  p: DepositParams,
): Promise<{ txHash: Hex; leafIndex: bigint; noteCommitment: bigint; postRoot: bigint }> {
  const value = p.token === ZERO ? p.amount : 0n;
  const hash = await wallet.writeContract({
    account,
    chain: wallet.chain,
    address: pool,
    abi: shieldedPoolAbi,
    functionName: "deposit",
    args: [p.token, p.amount, p.ownerCommitment, p.outputNoteData, p.policyData],
    value,
  });
  const receipt = await pub.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") throw new Error("deposit reverted");
  const events = await pub.getContractEvents({
    address: pool,
    abi: shieldedPoolAbi,
    eventName: "ShieldedPoolDeposit",
    fromBlock: receipt.blockNumber,
    toBlock: receipt.blockNumber,
  });
  const ev = events.find((e) => e.transactionHash?.toLowerCase() === hash.toLowerCase());
  if (!ev) throw new Error("ShieldedPoolDeposit event not found");
  const a = ev.args as { noteCommitment: bigint; leafIndex: bigint; postInsertionCommitmentRoot: bigint };
  return { txHash: hash, leafIndex: BigInt(a.leafIndex), noteCommitment: a.noteCommitment, postRoot: a.postInsertionCommitmentRoot };
}

export interface TransactArgs {
  poolProof: Hex;
  authProof: Hex;
  publicInputs: PublicInputs;
  outputNoteData: [Hex, Hex, Hex];
  policyData: Hex;
}

export async function transact(
  wallet: WalletClient,
  pub: PublicClient,
  pool: Address,
  account: Address,
  c: TransactArgs,
): Promise<{ txHash: Hex; leafIndex0: bigint; noteCommitments: [bigint, bigint, bigint] }> {
  const hash = await wallet.writeContract({
    account,
    chain: wallet.chain,
    address: pool,
    abi: shieldedPoolAbi,
    functionName: "transact",
    args: [c.poolProof, c.authProof, c.publicInputs, ...c.outputNoteData, c.policyData],
  });
  const receipt = await pub.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") throw new Error("transact reverted");
  const events = await pub.getContractEvents({
    address: pool,
    abi: shieldedPoolAbi,
    eventName: "ShieldedPoolTransact",
    fromBlock: receipt.blockNumber,
    toBlock: receipt.blockNumber,
  });
  const ev = events.find((e) => e.transactionHash?.toLowerCase() === hash.toLowerCase());
  if (!ev) throw new Error("ShieldedPoolTransact event not found");
  const a = ev.args as { leafIndex0: bigint; noteCommitment0: bigint; noteCommitment1: bigint; noteCommitment2: bigint };
  return { txHash: hash, leafIndex0: BigInt(a.leafIndex0), noteCommitments: [a.noteCommitment0, a.noteCommitment1, a.noteCommitment2] };
}

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
    actionTarget: ZERO,
    actionCalldata: "0x",
  };
}

export function computeDownstreamActionCommitment(
  executionChainId: bigint,
  sourcePool: Address,
  intentReplayId: bigint,
  router: Address,
  spec: ActionSpec,
): bigint {
  const actionHash = keccak256(encodeAbiParameters([{ type: "address" }, { type: "bytes" }], [spec.actionTarget, spec.actionCalldata]));
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

export async function readDownstreamActionCommitment(
  pub: PublicClient,
  router: Address,
  executionChainId: bigint,
  sourcePool: Address,
  intentReplayId: bigint,
  spec: ActionSpec,
): Promise<bigint> {
  return (await pub.readContract({
    address: router,
    abi: publicActionRouterAbi,
    functionName: "computeDownstreamActionCommitment",
    args: [executionChainId, sourcePool, intentReplayId, spec],
  })) as bigint;
}

export async function executeRouterMove(
  wallet: WalletClient,
  pub: PublicClient,
  router: Address,
  account: Address,
  in_: { from: Address; poolProof: Hex; authProof: Hex; publicInputs: PublicInputs; outputNoteData: [Hex, Hex, Hex]; policyData: Hex },
  spec: ActionSpec,
): Promise<Hex> {
  const moveIn = {
    from: in_.from,
    poolProof: in_.poolProof,
    authProof: in_.authProof,
    publicInputs: in_.publicInputs,
    outputNoteData0: in_.outputNoteData[0],
    outputNoteData1: in_.outputNoteData[1],
    outputNoteData2: in_.outputNoteData[2],
    policyData: in_.policyData,
  };
  const hash = await wallet.writeContract({
    account,
    chain: wallet.chain,
    address: router,
    abi: publicActionRouterAbi,
    functionName: "executeMove",
    args: [moveIn, spec],
  });
  const receipt = await pub.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") throw new Error("router executeMove reverted");
  return hash;
}
