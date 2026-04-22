import * as secp from "@noble/secp256k1";
import {
  canonicalizeMultisigSigners,
  computeShieldedPoolIntentSigningHash,
  hexToBytes,
  MULTISIG_AUTH_DOMAIN,
  multisigAuthDataCommitment,
} from "../../src/lib/protocol.ts";
import { createFfiLogger } from "./ffi_debug.ts";
import {
  assertAuthPolicyRoot,
  buildCommonTxArtifacts,
  buildInnerBaseWitness,
  byteArrayStrings,
  createPoseidonHelpers,
  runInnerCircuit,
  type TomlTable,
  type TxProofParams,
  proveOuterTransaction,
  withCircuitLock,
} from "./tx_proof_shared.ts";

const logger = createFfiLogger("generate_multisig_proof");

async function main() {
  const params = JSON.parse(process.argv[2]) as TxProofParams & {
    signingPrivateKey0: string;
    signingPrivateKey1: string;
    signingPrivateKey2: string;
    signerAIndex: string | number;
    signerBIndex: string | number;
  };

  const result = await withCircuitLock(async () => {
    const helpers = await createPoseidonHelpers();
    const common = buildCommonTxArtifacts(params, helpers);

    const signerKeys = [
      params.signingPrivateKey0,
      params.signingPrivateKey1,
      params.signingPrivateKey2,
    ];
    const canonicalSigners = canonicalizeMultisigSigners(
      signerKeys.map((privateKey) => {
        const publicKey = secp.getPublicKey(hexToBytes(privateKey), false);
        return {
          privateKey,
          pubKeyX: publicKey.slice(1, 33),
          pubKeyY: publicKey.slice(33, 65),
        };
      }),
      helpers.pHash,
    );
    const authDataCommitment = multisigAuthDataCommitment(
      canonicalSigners.map((signer) => signer.signerCommitment),
      helpers.pHash,
      helpers.pHash,
    );

    const signingHash = computeShieldedPoolIntentSigningHash({
      authorizingAddress: common.authorizingAddress,
      policyVersion: common.policyVersion,
      authDomainTag: MULTISIG_AUTH_DOMAIN,
      operationKind: common.operationKind,
      tokenAddress: common.tokenAddress,
      recipientAddress: common.recipientAddress,
      amount: common.amount,
      feeRecipientAddress: common.feeRecipientAddress,
      feeAmount: common.feeAmount,
      nonce: common.nonce,
      validUntilSeconds: common.validUntilSeconds,
      executionConstraints: common.executionConstraints,
      executionChainId: common.executionChainId,
    });

    const requestedSignerA = Number(params.signerAIndex);
    const requestedSignerB = Number(params.signerBIndex);
    if (
      requestedSignerA < 0 ||
      requestedSignerA > 2 ||
      requestedSignerB < 0 ||
      requestedSignerB > 2
    ) {
      throw new Error("signer indices must be 0, 1, or 2");
    }
    if (requestedSignerA === requestedSignerB) {
      throw new Error("multisig signer indices must differ");
    }

    const policySignerAIndex = canonicalSigners.findIndex(
      (signer) => signer.originalIndex === requestedSignerA,
    );
    const policySignerBIndex = canonicalSigners.findIndex(
      (signer) => signer.originalIndex === requestedSignerB,
    );
    if (policySignerAIndex === -1 || policySignerBIndex === -1) {
      throw new Error("multisig signer not found in canonical policy");
    }

    const signerASignature = await secp.signAsync(
      signingHash,
      hexToBytes(canonicalSigners[policySignerAIndex].value.privateKey),
    );
    const signerBSignature = await secp.signAsync(
      signingHash,
      hexToBytes(canonicalSigners[policySignerBIndex].value.privateKey),
    );

    const innerWitness: TomlTable = {
      ...buildInnerBaseWitness(common),
      multisig_policy: {
        signers: canonicalSigners.map((signer) => ({
          x: byteArrayStrings(signer.pubKeyX),
          y: byteArrayStrings(signer.pubKeyY),
        })),
      },
      approvals: [
        {
          signer_index: `0x${BigInt(policySignerAIndex).toString(16)}`,
          signature: byteArrayStrings(signerASignature.toCompactRawBytes()),
        },
        {
          signer_index: `0x${BigInt(policySignerBIndex).toString(16)}`,
          signature: byteArrayStrings(signerBSignature.toCompactRawBytes()),
        },
      ],
    };

    const inner = runInnerCircuit(
      "multisig_2of3",
      innerWitness,
      "multisig_2of3_prove",
      helpers.pHash,
      logger,
    );
    assertAuthPolicyRoot(common, authDataCommitment, inner.innerVkHash, helpers);

    return proveOuterTransaction(common, authDataCommitment, inner, logger, {
      authorizingAddress: params.outerAuthorizingAddress
        ? BigInt(params.outerAuthorizingAddress)
        : undefined,
      policyVersion: params.outerPolicyVersion
        ? BigInt(params.outerPolicyVersion)
        : undefined,
    });
  }, logger);

  process.stdout.write(JSON.stringify(result));
}

main().catch((error) => {
  process.stderr.write(error.message);
  process.exit(1);
});
