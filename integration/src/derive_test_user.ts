import * as secp from "@noble/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { XWing } from "@noble/post-quantum/hybrid.js";
import {
  computeSingleSigAuthorizationSigningHash,
  TRANSFER_OPERATION_KIND,
  hexToBytes,
  secp256k1PubkeyToAddress,
  singleSigAuthDataCommitment,
} from "../../src/lib/protocol.ts";
import { createFfiLogger } from "./ffi_debug.ts";
import {
  buildSingleSigAuthorizationWitnessFromIntent,
  byteArrayStrings,
  createPoseidonHelpers,
  runInnerCircuit,
  withCircuitLock,
  type SingleSigAuthorizationWitness,
  type TomlTable,
} from "./tx_proof_shared.ts";
import {
  computeOwnerNullifierKeyHash,
  computeNoteSecretSeedHash,
} from "./eip8182.ts";

const logger = createFfiLogger("derive_test_user");

async function main() {
  const params = JSON.parse(process.argv[2]) as {
    ownerNullifierKey: string;
    noteSecretSeed: string;
    deliverySecret: string;
    signingPrivateKey: string;
  };

  const result = await withCircuitLock(async () => {
    const helpers = await createPoseidonHelpers();
    const ownerNullifierKey = BigInt(params.ownerNullifierKey);
    const noteSecretSeed = BigInt(params.noteSecretSeed);
    const deliverySecret = BigInt(params.deliverySecret);
    const signingPrivateKey = hexToBytes(params.signingPrivateKey);

    const ownerNullifierKeyHash = computeOwnerNullifierKeyHash(helpers.pHash, ownerNullifierKey);
    const noteSecretSeedHash = computeNoteSecretSeedHash(helpers.pHash, noteSecretSeed);

    const signingPubKey = secp.getPublicKey(signingPrivateKey, false);
    const pubKeyX = signingPubKey.slice(1, 33);
    const pubKeyY = signingPubKey.slice(33, 65);
    const authDataCommitment = singleSigAuthDataCommitment(
      pubKeyX,
      pubKeyY,
      helpers.pHash,
    );

    const xwingSeed = keccak_256(
      new TextEncoder().encode(`xwing-delivery-${deliverySecret.toString()}`),
    );
    const { publicKey: deliveryPubKey } = XWing.keygen(xwingSeed);

    const authorizingAddress = secp256k1PubkeyToAddress(pubKeyX, pubKeyY);
    const semanticIntent = {
      policyVersion: 1n,
      operationKind: TRANSFER_OPERATION_KIND,
      tokenAddress: 0n,
      recipientAddress: authorizingAddress,
      amount: 1n,
      feeRecipientAddress: 0n,
      feeAmount: 0n,
      originMode: 0n,
      nonce: 42n,
      validUntilSeconds: 3601n,
      executionChainId: 31337n,
    };
    const signingHash = computeSingleSigAuthorizationSigningHash({
      policyVersion: semanticIntent.policyVersion,
      operationKind: semanticIntent.operationKind,
      tokenAddress: semanticIntent.tokenAddress,
      recipientAddress: semanticIntent.recipientAddress,
      amount: semanticIntent.amount,
      feeRecipientAddress: semanticIntent.feeRecipientAddress,
      feeAmount: semanticIntent.feeAmount,
      originMode: semanticIntent.originMode,
      nonce: semanticIntent.nonce,
      validUntilSeconds: semanticIntent.validUntilSeconds,
      executionChainId: semanticIntent.executionChainId,
    });
    const signature = await secp.signAsync(signingHash, signingPrivateKey);

    const authorization: SingleSigAuthorizationWitness = {
      policyVersion: semanticIntent.policyVersion,
      operationKind: semanticIntent.operationKind,
      tokenAddress: semanticIntent.tokenAddress,
      recipientAddress: semanticIntent.recipientAddress,
      amount: semanticIntent.amount,
      feeRecipientAddress: semanticIntent.feeRecipientAddress,
      feeAmount: semanticIntent.feeAmount,
      originMode: semanticIntent.originMode,
      nonce: semanticIntent.nonce,
      validUntilSeconds: semanticIntent.validUntilSeconds,
      executionChainId: semanticIntent.executionChainId,
    };

    const witness: TomlTable = {
      ...buildSingleSigAuthorizationWitnessFromIntent(authorization),
      single_sig_policy: {
        signer: {
          x: byteArrayStrings(pubKeyX),
          y: byteArrayStrings(pubKeyY),
        },
      },
      approval: {
        signature: byteArrayStrings(signature.toCompactRawBytes()),
      },
    };

    const inner = runInnerCircuit(
      "eip712",
      witness,
      "eip712_prove",
      helpers.pHash,
      logger,
    );

    return {
      ownerNullifierKeyHash: ownerNullifierKeyHash.toString(),
      noteSecretSeedHash: noteSecretSeedHash.toString(),
      authDataCommitment: authDataCommitment.toString(),
      innerVkHash: inner.innerVkHash.toString(),
      deliveryPubKey:
        "0x" +
        Array.from(deliveryPubKey)
          .map((byte) => byte.toString(16).padStart(2, "0"))
          .join(""),
    };
  }, logger);

  process.stdout.write(JSON.stringify(result));
}

main().catch((error) => {
  process.stderr.write(error.message);
  process.exit(1);
});
