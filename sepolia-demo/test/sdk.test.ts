import { describe, expect, it } from "vitest";
import { Wallet } from "ethers";
import {
  createDeterministicDemoProfile,
  decodeNotePayload,
  decryptNotePayload,
  encodeNotePayload,
  encryptNotePayload,
  authIntentTypedData,
  createDemoProfile,
  generateRecipientEncryptionKeyPair,
  noteBodyCommitment,
  noteCommitment,
  ownerCommitment,
  ownerNullifierKeyHash,
  outputNoteDataHash,
  parseEnvelope,
  profileDerivationMessage,
  prepareDemoPrivateTransfer,
  prepareTransactOutputNoteData,
  profileField,
  profilePublicKey,
  profileSecretKey,
  getPoolDepositLogs,
  readRecipient,
  SepoliaDemoIndexer,
  poseidon,
  trialDecryptNotePayload,
  waitForTransactionReceipt,
  type Eip1193Provider,
  type NotePayload
} from "../src/index.js";

const CHAIN_ID = 11155111n;
const POOL = "0x1111111111111111111111111111111111111111";
const AUTH_VERIFIER = "0x2222222222222222222222222222222222222222";
const TOKEN = "0x0000000000000000000000000000000000000000";
const OWNER = 123456789n;

function payload(overrides: Partial<NotePayload> = {}): NotePayload {
  const merged = {
    kind: "deposit",
    chainId: CHAIN_ID,
    poolAddress: POOL,
    tokenAddress: TOKEN,
    amount: 25n,
    ownerNullifierKeyHash: OWNER,
    noteSecret: 987654321n,
    leafIndex: 7n,
    outputIndex: 0,
    memo: "demo note",
    ...overrides
  };
  const body = merged.noteBodyCommitment
    ?? noteBodyCommitment(
      ownerCommitment(merged.ownerNullifierKeyHash, merged.noteSecret),
      merged.amount,
      merged.tokenAddress
    );
  return {
    ...merged,
    noteBodyCommitment: body,
    noteCommitment: merged.noteCommitment ?? noteCommitment(body, merged.leafIndex ?? 0n)
  };
}

describe("note payloads", () => {
  it("matches the Poseidon2 vector used by the reference witness builder", () => {
    expect(poseidon(1n, 2n)).toBe(
      BigInt("0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383")
    );
  });

  it("encodes and decodes canonical note payload bytes", () => {
    const expected = payload();
    const decoded = decodeNotePayload(encodeNotePayload(expected));
    expect(decoded.chainId).toBe(CHAIN_ID);
    expect(decoded.poolAddress).toBe(POOL);
    expect(decoded.amount).toBe(25n);
    expect(decoded.noteCommitment).toBe(expected.noteCommitment);
  });

  it("computes the EIP-8182 output note data hash as keccak256 mod BN254 scalar", () => {
    expect(outputNoteDataHash(new TextEncoder().encode("o0"))).toBe(
      18948458454720480307574014629951874841119005641073654350129459985731714748039n
    );
  });
});

describe("hybrid encryption envelopes", () => {
  it("encrypts and decrypts a note payload with ML-KEM-768 plus X25519", async () => {
    const keys = generateRecipientEncryptionKeyPair({ ownerNullifierKeyHash: OWNER });
    const envelopeBytes = await encryptNotePayload(payload(), keys.publicKey);
    const envelope = parseEnvelope(envelopeBytes);

    expect(envelope.suite).toContain("MLKEM768_X25519");
    expect(envelope.kid).toBe(keys.publicKey.keyId);

    const decoded = await decryptNotePayload(envelopeBytes, keys.secretKey);
    expect(decoded.ownerNullifierKeyHash).toBe(OWNER);
    expect(decoded.noteSecret).toBe(987654321n);
  });

  it("trial-decrypts against multiple candidate keys and rejects non-owners", async () => {
    const recipient = generateRecipientEncryptionKeyPair({ ownerNullifierKeyHash: OWNER });
    const wrong = generateRecipientEncryptionKeyPair({ ownerNullifierKeyHash: 999n });
    const envelopeBytes = await encryptNotePayload(payload(), recipient.publicKey);

    await expect(decryptNotePayload(envelopeBytes, wrong.secretKey)).rejects.toThrow("envelope decryption failed");

    const result = await trialDecryptNotePayload(envelopeBytes, [
      { id: "wrong", secretKey: wrong.secretKey },
      { id: "recipient", secretKey: recipient.secretKey }
    ]);

    expect(result?.candidateId).toBe("recipient");
    expect(result?.payload.amount).toBe(25n);
  });

  it("prepares transact outputNoteData for recipient, change, and dummy slots", async () => {
    const recipient = generateRecipientEncryptionKeyPair({ ownerNullifierKeyHash: OWNER });
    const sender = generateRecipientEncryptionKeyPair({ ownerNullifierKeyHash: 777n });
    const outputs = await prepareTransactOutputNoteData([
      { payload: payload({ kind: "transact", outputIndex: 0 }), recipient: recipient.publicKey },
      {
        payload: payload({
          kind: "transact",
          ownerNullifierKeyHash: 777n,
          noteSecret: 111n,
          outputIndex: 1
        }),
        recipient: sender.publicKey
      },
      { dummy: true }
    ]);

    expect(outputs[0].outputNoteData.length).toBeGreaterThan(ML_KEM_CT_MIN_BYTES);
    expect(outputs[0].outputNoteDataHash).toBe(outputNoteDataHash(outputs[0].outputNoteData));
    expect(outputs[2].outputNoteData).toHaveLength(0);
  });
});

describe("demo profiles", () => {
  it("derives stable local profile material from the wallet setup signature", async () => {
    const wallet = new Wallet("0x59c6995e998f97a5a0044976f5dae2c6bce185e9e5370ef2aeacb3c6fafd11c2");
    const message = profileDerivationMessage({
      chainId: CHAIN_ID,
      poolAddress: POOL,
      account: wallet.address,
      authVerifier: AUTH_VERIFIER
    });
    const signature = await wallet.signMessage(message);
    const first = createDeterministicDemoProfile({
      chainId: CHAIN_ID,
      poolAddress: POOL,
      account: wallet.address,
      authVerifier: AUTH_VERIFIER,
      derivationSignature: signature
    });
    const second = createDeterministicDemoProfile({
      chainId: CHAIN_ID,
      poolAddress: POOL,
      account: wallet.address,
      authVerifier: AUTH_VERIFIER,
      derivationSignature: signature
    });

    expect(second.ownerNullifierKey).toBe(first.ownerNullifierKey);
    expect(second.noteSecretSeed).toBe(first.noteSecretSeed);
    expect(second.registrationBlinder).toBe(first.registrationBlinder);
    expect(second.encryptionPublicKey.keyId).toBe(first.encryptionPublicKey.keyId);
    expect(second.encryptionSecretKey.mlKem768SecretKey).toBe(first.encryptionSecretKey.mlKem768SecretKey);
  });
});

const ML_KEM_CT_MIN_BYTES = 1088;

describe("Sepolia demo indexer skeleton", () => {
  it("stores deposit events and decrypts matching note payloads", async () => {
    const recipient = generateRecipientEncryptionKeyPair({ ownerNullifierKeyHash: OWNER });
    const expectedPayload = payload();
    const outputNoteData = await encryptNotePayload(expectedPayload, recipient.publicKey);
    const indexer = new SepoliaDemoIndexer({
      chainId: CHAIN_ID,
      poolAddress: POOL,
      candidates: [{ id: "recipient", secretKey: recipient.secretKey }]
    });

    const note = await indexer.ingestDeposit({
      noteCommitment: expectedPayload.noteCommitment!,
      leafIndex: 7n,
      amount: 25n,
      tokenAddress: TOKEN,
      outputNoteData,
      blockNumber: 123,
      transactionHash: "0xabc"
    });

    expect(note.status).toBe("decrypted");
    expect(note.payload?.noteSecret).toBe(987654321n);
    expect(indexer.store.all()).toHaveLength(1);
  });

  it("leaves decrypted payloads pending when event commitment does not match", async () => {
    const recipient = generateRecipientEncryptionKeyPair({ ownerNullifierKeyHash: OWNER });
    const outputNoteData = await encryptNotePayload(payload({ noteCommitment: 444n }), recipient.publicKey);
    const indexer = new SepoliaDemoIndexer({
      chainId: CHAIN_ID,
      poolAddress: POOL,
      candidates: [{ id: "recipient", secretKey: recipient.secretKey }]
    });

    const note = await indexer.ingestDeposit({
      noteCommitment: 333n,
      leafIndex: 7n,
      amount: 25n,
      tokenAddress: TOKEN,
      outputNoteData
    });

    expect(note.status).toBe("pending");
    expect(note.payload).toBeUndefined();
  });
});

describe("Sepolia RPC helpers", () => {
  it("fetches event logs in bounded block chunks", async () => {
    const calls: { method: string; params?: unknown[] | Record<string, unknown> }[] = [];
    const provider: Eip1193Provider = {
      async request(args) {
        calls.push(args);
        if (args.method === "eth_blockNumber") return "0x177a";
        if (args.method === "eth_getLogs") return [];
        throw new Error(`unexpected RPC method ${args.method}`);
      }
    };

    await expect(getPoolDepositLogs(provider, POOL, 10n, "latest")).resolves.toEqual([]);

    const ranges = calls
      .filter((call) => call.method === "eth_getLogs")
      .map((call) => {
        const params = call.params as [Record<string, string>];
        return [BigInt(params[0].fromBlock), BigInt(params[0].toBlock)];
      });
    expect(ranges).toEqual([
      [10n, 2009n],
      [2010n, 4009n],
      [4010n, 6009n],
      [6010n, 6010n]
    ]);
  });

  it("rejects mined transaction receipts that reverted", async () => {
    const provider: Eip1193Provider = {
      async request(args) {
        if (args.method !== "eth_getTransactionReceipt") throw new Error(`unexpected RPC method ${args.method}`);
        return {
          transactionHash: "0xabc",
          status: "0x0",
          blockNumber: "0x1"
        };
      }
    };

    await expect(waitForTransactionReceipt(provider, "0xabc")).rejects.toThrow("transaction 0xabc reverted");
  });
});

describe("private transfer preparation", () => {
  it("derives circuit-compatible output note secrets and encrypted output slots", async () => {
    const sender = createDemoProfile({
      chainId: CHAIN_ID,
      poolAddress: POOL,
      account: "0x3333333333333333333333333333333333333333"
    });
    sender.authDataCommitment = "123456789";
    const recipientOwnerHash = ownerNullifierKeyHash(0xabcden);
    const recipient = generateRecipientEncryptionKeyPair({ ownerNullifierKeyHash: recipientOwnerHash });
    const noteSecret = 0x12345n;
    const ownerHash = profileField(sender, "ownerNullifierKeyHash");
    const body = noteBodyCommitment(ownerCommitment(ownerHash, noteSecret), 25n, TOKEN);
    const commitment = noteCommitment(body, 7n);
    const outputNoteData = await encryptNotePayload(
      payload({
        ownerNullifierKeyHash: ownerHash,
        noteSecret,
        noteBodyCommitment: body,
        noteCommitment: commitment
      }),
      profilePublicKey(sender)
    );
    const indexer = new SepoliaDemoIndexer({
      chainId: CHAIN_ID,
      poolAddress: POOL,
      candidates: [{ id: "sender", secretKey: profileSecretKey(sender) }]
    });
    const inputNote = await indexer.ingestDeposit({
      noteCommitment: commitment,
      leafIndex: 7n,
      amount: 25n,
      tokenAddress: TOKEN,
      outputNoteData
    });

    const transfer = await prepareDemoPrivateTransfer({
      chainId: CHAIN_ID,
      poolAddress: POOL,
      authVerifier: "0x4444444444444444444444444444444444444444",
      sender,
      inputNote,
      recipient: {
        ownerNullifierKeyHash: recipientOwnerHash,
        publicKey: recipient.publicKey
      },
      amount: 10n,
      nonce: 42n,
      validUntilSeconds: 2_000_000_000n
    });

    expect(transfer.outputSlots[0].isReal).toBe(true);
    expect(transfer.outputSlots[0].amount).toBe(10n);
    expect(transfer.outputSlots[1].isReal).toBe(true);
    expect(transfer.outputSlots[1].amount).toBe(15n);
    expect(transfer.outputSlots[2].isReal).toBe(false);
    expect(transfer.outputSlots[0].outputNoteDataHash).toBe(outputNoteDataHash(transfer.outputSlots[0].outputNoteData));
    expect(transfer.publicInputPreview.outputNoteDataHash1).toBe(transfer.outputSlots[1].outputNoteDataHash);
    expect(transfer.proverStatus.ready).toBe(true);

    const typedData = authIntentTypedData(transfer, sender.account);
    expect(Object.keys(typedData.message)).toEqual([
      "authVerifier",
      "authorizingAddress",
      "tokenAddress",
      "recipientOwnerNullifierKeyHash",
      "amount",
      "nonce",
      "validUntilSeconds"
    ]);
    expect(typedData.message).not.toHaveProperty("publicRecipientAddress");
    expect(typedData.message).not.toHaveProperty("blindingFactor");
  });
});

describe("contract ABI helpers", () => {
  it("decodes getRecipient returns with dynamic ML-KEM public-key bytes", async () => {
    const encodedGetRecipientReturn =
      "0x0000000000000000000000000000000000000000000000000000000000000001" +
      "0000000000000000000000000000000000000000000000000000000000000040" +
      "000000000000000000000000000000000000000000000000000000000000007b" +
      "0000000000000000000000000000000000000000000000000000000000000080" +
      "1111111111111111111111111111111111111111111111111111111111111111" +
      "0000000000000000000000000000000000000000000000000000000000000001" +
      "0000000000000000000000000000000000000000000000000000000000000002" +
      "0102000000000000000000000000000000000000000000000000000000000000";
    const provider: Eip1193Provider = {
      async request() {
        return encodedGetRecipientReturn;
      }
    };

    const recipient = await readRecipient(
      provider,
      "0x5555555555555555555555555555555555555555",
      "0x6666666666666666666666666666666666666666"
    );

    expect(recipient.registered).toBe(true);
    expect(recipient.ownerNullifierKeyHash).toBe(123n);
    expect(recipient.publicKey.mlKem768PublicKey).toEqual(new Uint8Array([1, 2]));
    expect(recipient.publicKey.x25519PublicKey).toHaveLength(32);
    expect(recipient.metadataVersion).toBe(1);
  });
});
