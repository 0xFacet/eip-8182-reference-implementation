import { encodeAbiParameters, type Address, type Hex } from "viem";
import type { IntentFields, PublicInputs } from "./derivations.ts";
import { fieldToAddress } from "./field.ts";
import { POLICY_OPERATION_DEPOSIT, POLICY_OPERATION_TRANSACT } from "./generated/constants.ts";

const transactDetailsAbi = {
  type: "tuple",
  components: [
    { name: "authVerifier", type: "address" },
    { name: "authorizingAddress", type: "address" },
    { name: "operationKind", type: "uint256" },
    { name: "token", type: "address" },
    { name: "recipientOwnerNullifierKeyHash", type: "uint256" },
    { name: "amount", type: "uint256" },
    { name: "feeNoteRecipientOwnerNullifierKeyHash", type: "uint256" },
    { name: "feeAmount", type: "uint256" },
    { name: "publicRecipientAddress", type: "address" },
    { name: "authorizedSubmitter", type: "address" },
    { name: "downstreamActionCommitment", type: "uint256" },
    { name: "executionConstraintsFlags", type: "uint256" },
    { name: "lockedOutputBinding0", type: "uint256" },
    { name: "lockedOutputBinding1", type: "uint256" },
    { name: "lockedOutputBinding2", type: "uint256" },
    { name: "nonce", type: "uint256" },
    { name: "validUntilSeconds", type: "uint256" },
    { name: "noteCommitmentRoot", type: "uint256" },
    { name: "nullifier0", type: "uint256" },
    { name: "nullifier1", type: "uint256" },
    { name: "noteBodyCommitment0", type: "uint256" },
    { name: "noteBodyCommitment1", type: "uint256" },
    { name: "noteBodyCommitment2", type: "uint256" },
    { name: "publicAmountOut", type: "uint256" },
    { name: "publicTokenAddress", type: "address" },
    { name: "intentReplayId", type: "uint256" },
    { name: "identityRoot", type: "uint256" },
    { name: "outputNoteDataHash0", type: "uint256" },
    { name: "outputNoteDataHash1", type: "uint256" },
    { name: "outputNoteDataHash2", type: "uint256" },
    { name: "blindedAuthCommitment", type: "uint256" },
  ],
} as const;

export function encodeSelfServeDepositPolicyData(p: {
  sender: Address;
  token: Address;
  amount: bigint;
  ownerCommitment: bigint;
  outputNoteDataHash: bigint;
}): Hex {
  const details = encodeAbiParameters(
    [
      { type: "address" },
      { type: "address" },
      { type: "uint256" },
      { type: "uint256" },
      { type: "uint256" },
    ],
    [p.sender, p.token, p.amount, p.ownerCommitment, p.outputNoteDataHash],
  );
  return encodeAbiParameters([{ type: "uint8" }, { type: "bytes" }], [Number(POLICY_OPERATION_DEPOSIT), details]);
}

export function encodeSelfServeTransactPolicyData(fields: IntentFields, publicInputs: PublicInputs): Hex {
  const details = encodeAbiParameters([transactDetailsAbi], [{
    authVerifier: fieldToAddress(fields.authVerifier, "authVerifier"),
    authorizingAddress: fieldToAddress(fields.authorizingAddress, "authorizingAddress"),
    operationKind: fields.operationKind,
    token: fieldToAddress(fields.tokenAddress, "tokenAddress"),
    recipientOwnerNullifierKeyHash: fields.recipientOwnerNullifierKeyHash,
    amount: fields.amount,
    feeNoteRecipientOwnerNullifierKeyHash: fields.feeNoteRecipientOwnerNullifierKeyHash,
    feeAmount: fields.feeAmount,
    publicRecipientAddress: fieldToAddress(fields.publicRecipientAddress, "publicRecipientAddress"),
    authorizedSubmitter: fieldToAddress(fields.authorizedSubmitter, "authorizedSubmitter"),
    downstreamActionCommitment: fields.downstreamActionCommitment,
    executionConstraintsFlags: fields.executionConstraintsFlags,
    lockedOutputBinding0: fields.lockedOutputBinding0,
    lockedOutputBinding1: fields.lockedOutputBinding1,
    lockedOutputBinding2: fields.lockedOutputBinding2,
    nonce: fields.nonce,
    validUntilSeconds: fields.validUntilSeconds,
    noteCommitmentRoot: publicInputs.noteCommitmentRoot,
    nullifier0: publicInputs.nullifier0,
    nullifier1: publicInputs.nullifier1,
    noteBodyCommitment0: publicInputs.noteBodyCommitment0,
    noteBodyCommitment1: publicInputs.noteBodyCommitment1,
    noteBodyCommitment2: publicInputs.noteBodyCommitment2,
    publicAmountOut: publicInputs.publicAmountOut,
    publicTokenAddress: fieldToAddress(publicInputs.publicTokenAddress, "publicTokenAddress"),
    intentReplayId: publicInputs.intentReplayId,
    identityRoot: publicInputs.identityRoot,
    outputNoteDataHash0: publicInputs.outputNoteDataHash0,
    outputNoteDataHash1: publicInputs.outputNoteDataHash1,
    outputNoteDataHash2: publicInputs.outputNoteDataHash2,
    blindedAuthCommitment: publicInputs.blindedAuthCommitment,
  }]);
  return encodeAbiParameters([{ type: "uint8" }, { type: "bytes" }], [Number(POLICY_OPERATION_TRANSACT), details]);
}
