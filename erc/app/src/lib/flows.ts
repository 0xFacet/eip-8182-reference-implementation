// Assemble BuildTransactParams for the two note-spending flows: a private
// transfer (value hidden, routed to a recipient's ML-KEM key) and a withdrawal
// (value exposed to a public recipient). Both spend one input note and emit a
// change note back to the sender when there is a remainder.

import type { BuildTransactParams, BuilderInput, BuilderOutput, BuilderPolicy, BuilderSpender } from "./transact.ts";
import type { IntentFields } from "../../../sdk/src/derivations.ts";
import type { SignedIntent } from "../../../sdk/src/eip712.ts";
import { DUMMY_ONK_HASH } from "./identity.ts";
import type { Address, PublicClient } from "viem";
import { policyAppliesToOperations, policyVerifier as policyVerifierOf } from "./clients.ts";
import { encodeSelfServeTransactPolicyData } from "./selfServePolicy.ts";

/** Build the §16.1 policy for a spend on a given pool. Free pools are ungated. */
export async function resolvePolicy(pub: PublicClient, pool: Address, gated: boolean): Promise<BuilderPolicy> {
  if (!gated) return { applies: 0n, policyVerifier: 0n };
  const [applies, verifier] = await Promise.all([policyAppliesToOperations(pub, pool), policyVerifierOf(pub, pool)]);
  return {
    applies,
    policyVerifier: BigInt(verifier),
    buildPolicyData: ({ fields, publicInputs }) => encodeSelfServeTransactPolicyData(fields, publicInputs),
  };
}

const DUMMY_OUT: BuilderOutput = { ownerNullifierKeyHash: DUMMY_ONK_HASH, amount: 0n, tokenAddress: 0n };

export interface FlowCommon {
  chainId: bigint;
  poolAddress: bigint;
  spender: BuilderSpender;
  noteCommitmentRoot: bigint;
  input: BuilderInput;
  self: { onkHash: bigint; kemPublicKey: Uint8Array };
  nonce: bigint;
  validUntilSeconds: bigint;
  blindingFactor: bigint;
  policy: BuilderPolicy;
  signIntent: (fields: IntentFields, policyDataHash: bigint) => Promise<SignedIntent>;
}

function base(c: FlowCommon) {
  return {
    chainId: c.chainId,
    poolAddress: c.poolAddress,
    authVerifier: c.spender.authVerifier,
    spender: c.spender,
    noteCommitmentRoot: c.noteCommitmentRoot,
    identityRoot: c.spender.identityRoot,
    inputs: [c.input],
    tokenAddress: 0n,
    feeNoteRecipientOwnerNullifierKeyHash: 0n,
    feeAmount: 0n,
    publicTokenAddress: 0n,
    nonce: c.nonce,
    validUntilSeconds: c.validUntilSeconds,
    blindingFactor: c.blindingFactor,
    policy: c.policy,
    signIntent: c.signIntent,
  };
}

export function buildTransfer(c: FlowCommon, recipient: { onkHash: bigint; kemPublicKey: Uint8Array }, amount: bigint): BuildTransactParams {
  const change = c.input.amount - amount;
  const changeOut: BuilderOutput = change > 0n ? { ownerNullifierKeyHash: c.self.onkHash, amount: change, tokenAddress: 0n, receiveKey: c.self.kemPublicKey } : DUMMY_OUT;
  return {
    ...base(c),
    operation: "transfer",
    amount,
    recipientOwnerNullifierKeyHash: recipient.onkHash,
    publicAmountOut: 0n,
    publicRecipientAddress: 0n,
    outputs: [{ ownerNullifierKeyHash: recipient.onkHash, amount, tokenAddress: 0n, receiveKey: recipient.kemPublicKey }, changeOut, DUMMY_OUT],
  };
}

export function buildWithdraw(c: FlowCommon, publicRecipient: bigint, amount: bigint): BuildTransactParams {
  const change = c.input.amount - amount;
  const changeOut: BuilderOutput = change > 0n ? { ownerNullifierKeyHash: c.self.onkHash, amount: change, tokenAddress: 0n, receiveKey: c.self.kemPublicKey } : DUMMY_OUT;
  return {
    ...base(c),
    operation: "withdrawal",
    amount,
    recipientOwnerNullifierKeyHash: 0n,
    publicAmountOut: amount,
    publicRecipientAddress: publicRecipient,
    outputs: [changeOut, DUMMY_OUT, DUMMY_OUT],
  };
}
