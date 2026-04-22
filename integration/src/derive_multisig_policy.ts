import * as secp from "@noble/secp256k1";
import {
  canonicalizeMultisigSigners,
  computeShieldedPoolIntentSigningHash,
  defaultExecutionConstraints,
  hexToBytes,
  MULTISIG_AUTH_DOMAIN,
  multisigAuthDataCommitment,
  TRANSFER_OPERATION_KIND,
} from "../../src/lib/protocol.ts";
import { createFfiLogger } from "./ffi_debug.ts";
import {
  buildInnerBaseWitnessFromIntent,
  byteArrayStrings,
  createPoseidonHelpers,
  runInnerCircuit,
  withCircuitLock,
  type TransactionIntentWitness,
  type TomlTable,
} from "./tx_proof_shared.ts";
import { computeTransactionIntentDigest } from "./eip8182.ts";

const logger = createFfiLogger("derive_multisig_policy");

async function main() {
  const params = JSON.parse(process.argv[2]) as {
    signingPrivateKey0: string;
    signingPrivateKey1: string;
    signingPrivateKey2: string;
  };

  const result = await withCircuitLock(async () => {
    const helpers = await createPoseidonHelpers();
    const rawSigners = [
      params.signingPrivateKey0,
      params.signingPrivateKey1,
      params.signingPrivateKey2,
    ].map((privateKey) => {
      const publicKey = secp.getPublicKey(hexToBytes(privateKey), false);
      return {
        privateKey,
        pubKeyX: publicKey.slice(1, 33),
        pubKeyY: publicKey.slice(33, 65),
      };
    });
    const canonicalSigners = canonicalizeMultisigSigners(rawSigners, helpers.pHash);
    const authDataCommitment = multisigAuthDataCommitment(
      canonicalSigners.map((signer) => signer.signerCommitment),
      helpers.pHash,
      helpers.pHash,
    );

    const executionConstraints = defaultExecutionConstraints();
    const semanticIntent = {
      authorizingAddress: 0x7e5f4552091a69125d5dfcb7b8c2659029395bdfn,
      policyVersion: 1n,
      operationKind: TRANSFER_OPERATION_KIND,
      tokenAddress: 0n,
      recipientAddress: 0x1000000000000000000000000000000000000001n,
      amount: 1n,
      feeRecipientAddress: 0n,
      feeAmount: 0n,
      nonce: 1n,
      validUntilSeconds: 3600n,
      executionChainId: 31337n,
    };
    const signingHash = computeShieldedPoolIntentSigningHash({
      ...semanticIntent,
      authDomainTag: MULTISIG_AUTH_DOMAIN,
      executionConstraints,
    });
    const sig0 = await secp.signAsync(
      signingHash,
      hexToBytes(canonicalSigners[0].value.privateKey),
    );
    const sig1 = await secp.signAsync(
      signingHash,
      hexToBytes(canonicalSigners[1].value.privateKey),
    );

    const transactionIntent: TransactionIntentWitness = {
      authorizingAddress: semanticIntent.authorizingAddress,
      policyVersion: semanticIntent.policyVersion,
      operationKind: semanticIntent.operationKind,
      tokenAddress: semanticIntent.tokenAddress,
      recipientAddress: semanticIntent.recipientAddress,
      amount: semanticIntent.amount,
      feeRecipientAddress: semanticIntent.feeRecipientAddress,
      feeAmount: semanticIntent.feeAmount,
      nonce: semanticIntent.nonce,
      validUntilSeconds: semanticIntent.validUntilSeconds,
      executionChainId: semanticIntent.executionChainId,
      executionConstraints,
      transactionIntentDigest: computeTransactionIntentDigest(helpers.pHash, {
        ...semanticIntent,
        executionConstraintsFlags: executionConstraints.executionConstraintsFlags,
        lockedOutputBinding0: executionConstraints.lockedOutputBinding0,
        lockedOutputBinding1: executionConstraints.lockedOutputBinding1,
        lockedOutputBinding2: executionConstraints.lockedOutputBinding2,
      }),
    };

    const witness: TomlTable = {
      ...buildInnerBaseWitnessFromIntent(transactionIntent),
      multisig_policy: {
        signers: canonicalSigners.map((signer) => ({
          x: byteArrayStrings(signer.pubKeyX),
          y: byteArrayStrings(signer.pubKeyY),
        })),
      },
      approvals: [
        {
          signer_index: "0x0",
          signature: byteArrayStrings(sig0.toCompactRawBytes()),
        },
        {
          signer_index: "0x1",
          signature: byteArrayStrings(sig1.toCompactRawBytes()),
        },
      ],
    };

    const inner = runInnerCircuit(
      "multisig_2of3",
      witness,
      "multisig_2of3_prove",
      helpers.pHash,
      logger,
    );

    return {
      authDataCommitment: authDataCommitment.toString(),
      innerVkHash: inner.innerVkHash.toString(),
    };
  }, logger);

  process.stdout.write(JSON.stringify(result));
}

main().catch((error) => {
  process.stderr.write(error.message);
  process.exit(1);
});
