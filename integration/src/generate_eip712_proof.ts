import * as secp from "@noble/secp256k1";
import {
  computeSingleSigAuthorizationSigningHash,
  hexToBytes,
  secp256k1PubkeyToAddress,
  singleSigAuthDataCommitment,
} from "../../src/lib/protocol.ts";
import { createFfiLogger } from "./ffi_debug.ts";
import {
  assertAuthPolicyRoot,
  buildCommonTxArtifacts,
  buildSingleSigAuthorizationWitness,
  byteArrayStrings,
  createPoseidonHelpers,
  runInnerCircuit,
  type TomlTable,
  type TxProofParams,
  proveOuterTransaction,
  withCircuitLock,
} from "./tx_proof_shared.ts";

const logger = createFfiLogger("generate_eip712_proof");

async function main() {
  const params = JSON.parse(process.argv[2]) as TxProofParams & {
    signingPrivateKey?: string;
  };

  const result = await withCircuitLock(async () => {
    const helpers = await createPoseidonHelpers();
    const common = buildCommonTxArtifacts(params, helpers);
    if (
      common.executionConstraints.executionConstraintsFlags !== 0n ||
      common.executionConstraints.lockedOutputBinding0 !== 0n ||
      common.executionConstraints.lockedOutputBinding1 !== 0n ||
      common.executionConstraints.lockedOutputBinding2 !== 0n
    ) {
      throw new Error("eip712 only supports unconstrained execution constraints");
    }

    const privateKey = params.signingPrivateKey
      ? hexToBytes(params.signingPrivateKey)
      : secp.utils.randomPrivateKey();
    const publicKey = secp.getPublicKey(privateKey, false);
    const pubKeyX = publicKey.slice(1, 33);
    const pubKeyY = publicKey.slice(33, 65);
    const authDataCommitment = singleSigAuthDataCommitment(
      pubKeyX,
      pubKeyY,
      helpers.pHash,
    );

    const signingHash = computeSingleSigAuthorizationSigningHash({
      policyVersion: common.policyVersion,
      operationKind: common.operationKind,
      tokenAddress: common.tokenAddress,
      recipientAddress: common.recipientAddress,
      amount: common.amount,
      feeRecipientAddress: common.feeRecipientAddress,
      feeAmount: common.feeAmount,
      originMode: common.originMode,
      nonce: common.nonce,
      validUntilSeconds: common.validUntilSeconds,
      executionChainId: common.executionChainId,
    });
    const signature = await secp.signAsync(signingHash, privateKey);

    const derivedAuthorizingAddress = secp256k1PubkeyToAddress(pubKeyX, pubKeyY);
    if (derivedAuthorizingAddress !== common.authorizingAddress) {
      throw new Error("signature public key does not match authorizing address");
    }

    const innerWitness: TomlTable = {
      ...buildSingleSigAuthorizationWitness(common),
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
      innerWitness,
      "eip712_prove",
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
