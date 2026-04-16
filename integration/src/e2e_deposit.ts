import * as secp from "@noble/secp256k1";
import { XWing } from "@noble/post-quantum/hybrid.js";
import {
  AUTH_POLICY_DOMAIN,
  AUTH_POLICY_KEY_DOMAIN,
  computeSingleSigAuthorizationSigningHash,
  PROTOCOL_COMMITMENT_TREE_DEPTH,
  PROTOCOL_REGISTRY_TREE_DEPTH,
  secp256k1PubkeyToAddress,
  singleSigAuthDataCommitment,
  USER_REGISTRY_LEAF_DOMAIN,
} from "../../src/lib/protocol.ts";
import {
  buildCommonTxArtifacts,
  buildSingleSigAuthorizationWitness,
  byteArrayStrings,
  createPoseidonHelpers,
  runInnerCircuit,
  type TomlTable,
  proveOuterTransaction,
} from "./tx_proof_shared.ts";

const REGISTRY_DEPTH = PROTOCOL_REGISTRY_TREE_DEPTH;
const COMMITMENT_DEPTH = PROTOCOL_COMMITMENT_TREE_DEPTH;

async function main() {
  console.log("=== E2E Deposit Test ===\n");

  const helpers = await createPoseidonHelpers();
  const privateKey = secp.utils.randomPrivateKey();
  const publicKey = secp.getPublicKey(privateKey, false);
  const pubKeyX = publicKey.slice(1, 33);
  const pubKeyY = publicKey.slice(33, 65);
  const authDataCommitment = singleSigAuthDataCommitment(
    pubKeyX,
    pubKeyY,
    helpers.pHash,
  );
  const authorizingAddress = secp256k1PubkeyToAddress(pubKeyX, pubKeyY);
  const { publicKey: deliveryPubKey } = XWing.keygen(secp.utils.randomPrivateKey());

  const baseParams = {
    mode: "deposit" as const,
    depositorAddress: `0x${authorizingAddress.toString(16).padStart(40, "0")}`,
    amount: "1000",
    tokenAddress: "0",
    ownerNullifierKey: "0x9999",
    noteSecretSeed: "0xbeef",
    policyVersion: "1",
    nonce: "42",
    validUntilSeconds: "1700000000",
    executionChainId: "11155111",
    noteCommitmentRoot: "0",
    userRegistryRoot: "0",
    authPolicyRoot: "0",
    deliverySchemeId: "1",
    deliveryPubKey:
      "0x" +
      Array.from(deliveryPubKey)
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join(""),
  };
  const initialCommon = buildCommonTxArtifacts(baseParams, helpers);

  const commitmentRoot = emptyRoot(COMMITMENT_DEPTH, helpers.h2);
  const userLeaf = helpers.pHash([
    USER_REGISTRY_LEAF_DOMAIN,
    initialCommon.authorizingAddress,
    initialCommon.ownerNullifierKeyHash,
    initialCommon.noteSecretSeedHash,
  ]);
  const userRegistryRoot = merkleRootFromKey(
    userLeaf,
    initialCommon.authorizingAddress,
    REGISTRY_DEPTH,
    helpers,
  );

  const signingHash = computeSingleSigAuthorizationSigningHash({
    policyVersion: initialCommon.policyVersion,
    operationKind: initialCommon.operationKind,
    tokenAddress: initialCommon.tokenAddress,
    recipientAddress: initialCommon.recipientAddress,
    amount: initialCommon.amount,
    feeRecipientAddress: initialCommon.feeRecipientAddress,
    feeAmount: initialCommon.feeAmount,
    originMode: initialCommon.originMode,
    nonce: initialCommon.nonce,
    validUntilSeconds: initialCommon.validUntilSeconds,
    executionChainId: initialCommon.executionChainId,
  });
  const signature = await secp.signAsync(signingHash, privateKey);

  const innerWitness: TomlTable = {
    ...buildSingleSigAuthorizationWitness(initialCommon),
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
  );
  const authLeaf = helpers.pHash([
    AUTH_POLICY_DOMAIN,
    authDataCommitment,
    initialCommon.policyVersion,
  ]);
  const authKey = helpers.pHash([
    AUTH_POLICY_KEY_DOMAIN,
    initialCommon.authorizingAddress,
    inner.innerVkHash,
  ]) & ((1n << 160n) - 1n);
  const authPolicyRoot = merkleRootFromKey(
    authLeaf,
    authKey,
    REGISTRY_DEPTH,
    helpers,
  );
  const common = buildCommonTxArtifacts(
    {
      ...baseParams,
      noteCommitmentRoot: `0x${commitmentRoot.toString(16)}`,
      userRegistryRoot: `0x${userRegistryRoot.toString(16)}`,
      authPolicyRoot: `0x${authPolicyRoot.toString(16)}`,
    },
    helpers,
  );
  const proof = proveOuterTransaction(common, authDataCommitment, inner);

  console.log(`innerVkHash: 0x${inner.innerVkHash.toString(16)}`);
  console.log(`proof bytes: ${proof.proof.length}`);
  console.log("deposit end-to-end flow completed");
}

function emptyRoot(
  depth: number,
  h2: (left: bigint, right: bigint) => bigint,
): bigint {
  let current = 0n;
  for (let i = 0; i < depth; i++) {
    current = h2(current, current);
  }
  return current;
}

function merkleRootFromKey(
  leaf: bigint,
  key: bigint,
  depth: number,
  helpers: {
    h2: (left: bigint, right: bigint) => bigint
  },
): bigint {
  let current = leaf;
  let empty = 0n;
  for (let i = 0; i < depth; i++) {
    const bit = Number((key >> BigInt(i)) & 1n);
    current = bit === 0 ? helpers.h2(current, empty) : helpers.h2(empty, current);
    empty = helpers.h2(empty, empty);
  }
  return current;
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
