import type { Address, PublicClient, WalletClient, Hex } from "viem";
import { noteBodyCommitment, ownerCommitment as ownerCommitmentOf } from "../../../sdk/src/derivations.ts";
import { keccakField, fieldToAddress } from "../../../sdk/src/field.ts";
import { bytesToHex } from "../../../sdk/src/bytes.ts";
import { encryptOutputNoteData } from "../../../sdk/src/envelope.ts";
import { encodeNotePayload, NOTE_PAYLOAD_KIND_DEPOSIT } from "../../../sdk/src/payload.ts";
import { deposit as depositTx } from "./clients.ts";
import { randomField } from "./proveTransact.ts";
import { encodeSelfServeDepositPolicyData } from "./selfServePolicy.ts";

const ZERO: Address = "0x0000000000000000000000000000000000000000";

export interface DepositResult {
  leafIndex: bigint;
  noteCommitment: bigint;
  amount: bigint;
  noteSecret: bigint;
  txHash: Hex;
}

/** Deposit ETH into a pool as a fresh note owned by, and encrypted to, the caller. */
export async function depositEth(params: {
  pub: PublicClient;
  wallet: WalletClient;
  chainId: bigint;
  account: Address;
  pool: Address;
  gated: boolean;
  onkHash: bigint;
  kemPublicKey: Uint8Array;
  amount: bigint;
}): Promise<DepositResult> {
  const poolF = BigInt(params.pool);
  const noteSecret = randomField();
  const oc = ownerCommitmentOf(params.chainId, poolF, params.onkHash, noteSecret);
  const nbc = noteBodyCommitment(oc, params.amount, 0n);
  const payload = encodeNotePayload({
    kind: NOTE_PAYLOAD_KIND_DEPOSIT,
    chainId: params.chainId,
    poolAddress: fieldToAddress(poolF, "poolAddress"),
    tokenAddress: fieldToAddress(0n),
    amount: params.amount,
    ownerNullifierKeyHash: params.onkHash,
    noteSecret,
    noteBodyCommitment: nbc,
    outputIndex: 0,
  });
  const ond = await encryptOutputNoteData(params.kemPublicKey, payload);

  let policyData: Hex = "0x";
  if (params.gated) {
    policyData = encodeSelfServeDepositPolicyData({
      sender: params.account,
      token: ZERO,
      amount: params.amount,
      ownerCommitment: oc,
      outputNoteDataHash: keccakField(ond),
    });
  }

  const res = await depositTx(params.wallet, params.pub, params.pool, params.account, {
    token: ZERO,
    amount: params.amount,
    ownerCommitment: oc,
    outputNoteData: bytesToHex(ond),
    policyData,
  });
  return { leafIndex: res.leafIndex, noteCommitment: res.noteCommitment, amount: params.amount, noteSecret, txHash: res.txHash };
}
