import { bytesToHex } from "./bytes.js";
import { profileField, profilePublicKey, type DemoProfile } from "./profile.js";
import {
  normalizeAddress,
  toNonnegativeBigInt,
  type FieldNumberish,
  type HexAddress,
  type NotePayload
} from "./payload.js";
import {
  prepareTransactOutputNoteData,
  type PreparedOutputNoteData,
  type TransactOutputRequest
} from "./output-notes.js";
import type { RecipientEncryptionPublicKey } from "./envelope.js";
import type { IndexedNote } from "./indexer.js";
import {
  addressToField,
  blindedAuthCommitment,
  dummyOwnerNullifierKeyHash,
  intentReplayId,
  noteBodyCommitment,
  nullifier,
  outputBinding,
  ownerCommitment,
  phantomNullifier,
  randomField,
  transactNoteSecret,
  transactionIntentDigest
} from "./poseidon.js";

export interface TransferRecipient {
  ownerNullifierKeyHash: FieldNumberish;
  publicKey: RecipientEncryptionPublicKey;
}

export interface PrepareDemoPrivateTransferOptions {
  chainId: FieldNumberish;
  poolAddress: HexAddress;
  authVerifier: HexAddress;
  sender: DemoProfile;
  inputNote: IndexedNote;
  recipient: TransferRecipient;
  amount: FieldNumberish;
  nonce?: FieldNumberish;
  blindingFactor?: FieldNumberish;
  validUntilSeconds?: FieldNumberish;
  noteCommitmentRoot?: FieldNumberish;
  authPolicyRoot?: FieldNumberish;
}

export interface PreparedTransferSlot {
  outputIndex: 0 | 1 | 2;
  isReal: boolean;
  amount: bigint;
  ownerNullifierKeyHash: bigint;
  noteSecret: bigint;
  ownerCommitment: bigint;
  noteBodyCommitment: bigint;
  outputNoteData: Uint8Array;
  outputNoteDataHex: `0x${string}`;
  outputNoteDataHash: bigint;
  outputBinding: bigint;
  payload?: NotePayload;
}

export interface PreparedDemoPrivateTransfer {
  inputNoteId: string;
  tokenAddress: HexAddress;
  transferAmount: bigint;
  changeAmount: bigint;
  nonce: bigint;
  blindingFactor: bigint;
  intentReplayId: bigint;
  transactionIntentDigest: bigint;
  validUntilSeconds: bigint;
  outputSlots: readonly [PreparedTransferSlot, PreparedTransferSlot, PreparedTransferSlot];
  publicInputPreview: {
    noteCommitmentRoot?: bigint;
    nullifier0: bigint;
    nullifier1: bigint;
    noteBodyCommitment0: bigint;
    noteBodyCommitment1: bigint;
    noteBodyCommitment2: bigint;
    publicAmountOut: 0n;
    publicRecipientAddress: 0n;
    publicTokenAddress: 0n;
    intentReplayId: bigint;
    validUntilSeconds: bigint;
    executionChainId: bigint;
    authPolicyRoot?: bigint;
    outputNoteDataHash0: bigint;
    outputNoteDataHash1: bigint;
    outputNoteDataHash2: bigint;
    authVerifier: bigint;
    blindedAuthCommitment: bigint;
    transactionIntentDigest: bigint;
  };
  proverStatus: {
    ready: boolean;
    reason: string;
  };
}

export async function prepareDemoPrivateTransfer(
  options: PrepareDemoPrivateTransferOptions
): Promise<PreparedDemoPrivateTransfer> {
  const payload = options.inputNote.payload;
  if (payload === undefined) throw new Error("input note must be decrypted before preparing a transfer");

  const chainId = toNonnegativeBigInt(options.chainId, "chainId");
  const poolAddress = normalizeAddress(options.poolAddress, "poolAddress");
  const authVerifier = normalizeAddress(options.authVerifier, "authVerifier");
  const senderAccount = normalizeAddress(options.sender.account, "sender.account");
  const tokenAddress = payload.tokenAddress;
  const inputAmount = payload.amount;
  const transferAmount = toNonnegativeBigInt(options.amount, "amount");
  if (transferAmount === 0n) throw new Error("amount must be greater than zero");
  if (transferAmount > inputAmount) throw new Error("amount exceeds selected note balance");
  if (payload.chainId !== chainId) throw new Error("selected note is from a different chain");
  if (payload.poolAddress !== poolAddress) throw new Error("selected note is from a different pool");

  const senderOwnerHash = profileField(options.sender, "ownerNullifierKeyHash");
  if (payload.ownerNullifierKeyHash !== senderOwnerHash) {
    throw new Error("selected note is not owned by the active profile");
  }

  const recipientOwnerHash = toNonnegativeBigInt(options.recipient.ownerNullifierKeyHash, "recipientOwnerNullifierKeyHash");
  const senderOwnerKey = profileField(options.sender, "ownerNullifierKey");
  const senderNoteSecretSeed = profileField(options.sender, "noteSecretSeed");
  const nonce = options.nonce === undefined ? randomField() : toNonnegativeBigInt(options.nonce, "nonce");
  const blindingFactor = options.blindingFactor === undefined
    ? randomField()
    : toNonnegativeBigInt(options.blindingFactor, "blindingFactor");
  if (options.sender.authDataCommitment === undefined) throw new Error("sender profile auth commitment is missing");
  const validUntilSeconds = options.validUntilSeconds === undefined
    ? BigInt(Math.floor(Date.now() / 1000) + 3600)
    : toNonnegativeBigInt(options.validUntilSeconds, "validUntilSeconds");
  const replayId = intentReplayId(senderOwnerKey, senderAccount, chainId, nonce);
  const changeAmount = inputAmount - transferAmount;
  const dummyOwnerHash = dummyOwnerNullifierKeyHash();

  const outputSecret0 = transactNoteSecret(senderNoteSecretSeed, replayId, 0);
  const outputSecret1 = transactNoteSecret(senderNoteSecretSeed, replayId, 1);
  const outputSecret2 = transactNoteSecret(senderNoteSecretSeed, replayId, 2);

  const body0 = buildOutputBody(recipientOwnerHash, outputSecret0, transferAmount, tokenAddress);
  const body1 = changeAmount === 0n
    ? buildOutputBody(dummyOwnerHash, outputSecret1, 0n, "0x0000000000000000000000000000000000000000")
    : buildOutputBody(senderOwnerHash, outputSecret1, changeAmount, tokenAddress);
  const body2 = buildOutputBody(dummyOwnerHash, outputSecret2, 0n, "0x0000000000000000000000000000000000000000");

  const payload0: NotePayload = {
    kind: "transact",
    chainId,
    poolAddress,
    tokenAddress,
    amount: transferAmount,
    ownerNullifierKeyHash: recipientOwnerHash,
    noteSecret: outputSecret0,
    noteBodyCommitment: body0.noteBodyCommitment,
    outputIndex: 0,
    memo: "recipient"
  };
  const outputRequests: [TransactOutputRequest, TransactOutputRequest, TransactOutputRequest] = [
    { payload: payload0, recipient: options.recipient.publicKey },
    changeAmount === 0n
      ? { dummy: true }
      : {
          payload: {
            kind: "transact",
            chainId,
            poolAddress,
            tokenAddress,
            amount: changeAmount,
            ownerNullifierKeyHash: senderOwnerHash,
            noteSecret: outputSecret1,
            noteBodyCommitment: body1.noteBodyCommitment,
            outputIndex: 1,
            memo: "change"
          },
          recipient: profilePublicKey(options.sender)
        },
    { dummy: true }
  ];

  const preparedOutputs = await prepareTransactOutputNoteData(outputRequests);
  const slot0 = buildPreparedSlot(0, true, transferAmount, recipientOwnerHash, outputSecret0, body0, preparedOutputs[0], payload0);
  const slot1Payload = "payload" in outputRequests[1] ? outputRequests[1].payload : undefined;
  const slot1 = buildPreparedSlot(1, changeAmount !== 0n, changeAmount, body1.ownerNullifierKeyHash, outputSecret1, body1, preparedOutputs[1], slot1Payload);
  const slot2 = buildPreparedSlot(2, false, 0n, dummyOwnerHash, outputSecret2, body2, preparedOutputs[2]);
  const outputSlots = [slot0, slot1, slot2] as const;

  const digest = transactionIntentDigest({
    authVerifier,
    authorizingAddress: senderAccount,
    operationKind: 0n,
    tokenAddress,
    recipientOwnerNullifierKeyHash: recipientOwnerHash,
    amount: transferAmount,
    feeNoteRecipientOwnerNullifierKeyHash: 0n,
    feeAmount: 0n,
    publicRecipientAddress: 0n,
    executionConstraintsFlags: 0n,
    lockedOutputBinding0: 0n,
    lockedOutputBinding1: 0n,
    lockedOutputBinding2: 0n,
    nonce,
    validUntilSeconds,
    executionChainId: chainId
  });

  const publicInputPreview: PreparedDemoPrivateTransfer["publicInputPreview"] = {
    nullifier0: nullifier(options.inputNote.noteCommitment, senderOwnerKey),
    nullifier1: phantomNullifier(senderOwnerKey, replayId, 1),
    noteBodyCommitment0: slot0.noteBodyCommitment,
    noteBodyCommitment1: slot1.noteBodyCommitment,
    noteBodyCommitment2: slot2.noteBodyCommitment,
    publicAmountOut: 0n,
    publicRecipientAddress: 0n,
    publicTokenAddress: 0n,
    intentReplayId: replayId,
    validUntilSeconds,
    executionChainId: chainId,
    outputNoteDataHash0: slot0.outputNoteDataHash,
    outputNoteDataHash1: slot1.outputNoteDataHash,
    outputNoteDataHash2: slot2.outputNoteDataHash,
    authVerifier: addressToField(authVerifier),
    blindedAuthCommitment: blindedAuthCommitment(options.sender.authDataCommitment, blindingFactor),
    transactionIntentDigest: digest
  };
  if (options.noteCommitmentRoot !== undefined) {
    publicInputPreview.noteCommitmentRoot = toNonnegativeBigInt(options.noteCommitmentRoot, "noteCommitmentRoot");
  }
  if (options.authPolicyRoot !== undefined) {
    publicInputPreview.authPolicyRoot = toNonnegativeBigInt(options.authPolicyRoot, "authPolicyRoot");
  }

  return {
    inputNoteId: options.inputNote.id,
    tokenAddress,
    transferAmount,
    changeAmount,
    nonce,
    blindingFactor,
    intentReplayId: replayId,
    transactionIntentDigest: digest,
    validUntilSeconds,
    outputSlots,
    publicInputPreview,
    proverStatus: {
      ready: true,
      reason: "Ready for browser proving. The wallet signs the transfer intent during submission."
    }
  };
}

function buildOutputBody(
  ownerNullifierKeyHashValue: bigint,
  noteSecret: bigint,
  amount: bigint,
  tokenAddress: HexAddress
): { ownerNullifierKeyHash: bigint; ownerCommitment: bigint; noteBodyCommitment: bigint } {
  const commitment = ownerCommitment(ownerNullifierKeyHashValue, noteSecret);
  return {
    ownerNullifierKeyHash: ownerNullifierKeyHashValue,
    ownerCommitment: commitment,
    noteBodyCommitment: noteBodyCommitment(commitment, amount, tokenAddress)
  };
}

function buildPreparedSlot(
  outputIndex: 0 | 1 | 2,
  isReal: boolean,
  amount: bigint,
  ownerNullifierKeyHashValue: bigint,
  noteSecret: bigint,
  body: { ownerCommitment: bigint; noteBodyCommitment: bigint },
  output: PreparedOutputNoteData,
  payload?: NotePayload
): PreparedTransferSlot {
  const slot: PreparedTransferSlot = {
    outputIndex,
    isReal,
    amount,
    ownerNullifierKeyHash: ownerNullifierKeyHashValue,
    noteSecret,
    ownerCommitment: body.ownerCommitment,
    noteBodyCommitment: body.noteBodyCommitment,
    outputNoteData: output.outputNoteData,
    outputNoteDataHex: bytesToHex(output.outputNoteData),
    outputNoteDataHash: output.outputNoteDataHash,
    outputBinding: outputBinding(body.noteBodyCommitment, output.outputNoteDataHash)
  };
  if (payload !== undefined) slot.payload = payload;
  return slot;
}
