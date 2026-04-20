import * as secp from "@noble/secp256k1";
import { XWing } from "@noble/post-quantum/hybrid.js";
import { writeFileSync } from "fs";
import { resolve } from "path";
import os from "os";
import {
  AUTH_POLICY_DOMAIN,
  AUTH_POLICY_KEY_DOMAIN,
  computeSingleSigAuthorizationSigningHash,
  PROTOCOL_COMMITMENT_TREE_DEPTH,
  PROTOCOL_REGISTRY_TREE_DEPTH,
  secp256k1PubkeyToAddress,
  singleSigAuthDataCommitment,
  USER_REGISTRY_LEAF_DOMAIN,
  hexToBytes,
} from "../../src/lib/protocol.ts";
import {
  assertAuthPolicyRoot,
  buildCommonTxArtifacts,
  buildSingleSigAuthorizationWitness,
  byteArrayStrings,
  createPoseidonHelpers,
  runInnerCircuit,
  type TomlTable,
  proveOuterTransaction,
} from "./tx_proof_shared.ts";
import {
  computeFullNoteCommitment,
  computeOwnerNullifierKeyHash,
  computeNoteSecretSeedHash,
} from "./eip8182.ts";

const REGISTRY_DEPTH = PROTOCOL_REGISTRY_TREE_DEPTH;
const COMMITMENT_DEPTH = PROTOCOL_COMMITMENT_TREE_DEPTH;
const FIXTURE_PRIVATE_KEY_HEX =
  "1111111111111111111111111111111111111111111111111111111111111111";
const FIXTURE_DELIVERY_SEED_HEX =
  "2222222222222222222222222222222222222222222222222222222222222222";

const FIXTURE_NK = 0x9999n;
const FIXTURE_NSS = 0xbeefn;
const FIXTURE_DEPOSIT_AMOUNT = 1000n;
const FIXTURE_TRANSFER_AMOUNT = 400n;

async function main() {
  const outputPath = resolve(
    process.argv[2] ??
      `${os.tmpdir()}/eip8182-verifier-test-fixture-${process.pid}.json`,
  );
  const helpers = await createPoseidonHelpers();

  // Single identity used as both sender and recipient of the transfer (self-transfer).
  // Keeps the user-registry Merkle tree to a single non-zero leaf.
  const privateKey = hexToBytes(FIXTURE_PRIVATE_KEY_HEX);
  const publicKey = secp.getPublicKey(privateKey, false);
  const pubKeyX = publicKey.slice(1, 33);
  const pubKeyY = publicKey.slice(33, 65);
  const authorizingAddress = secp256k1PubkeyToAddress(pubKeyX, pubKeyY);
  const authDataCommitment = singleSigAuthDataCommitment(
    pubKeyX,
    pubKeyY,
    helpers.pHash,
  );
  const { publicKey: deliveryPubKey } = XWing.keygen(hexToBytes(FIXTURE_DELIVERY_SEED_HEX));
  const deliveryPubKeyHex =
    "0x" +
    Array.from(deliveryPubKey)
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");

  const ownerNullifierKeyHash = computeOwnerNullifierKeyHash(helpers.pHash, FIXTURE_NK);
  const noteSecretSeedHash = computeNoteSecretSeedHash(helpers.pHash, FIXTURE_NSS);

  // Simulate a deposit at leafIndex 0 that the transfer will spend.
  // The deposit's noteSecret is chosen off-chain; we invent one here.
  const depositLeafIndex = 0n;
  const depositNoteSecret = 0xc0ffeen;
  const depositCommitment = computeFullNoteCommitment(helpers.pHash, {
    ownerNullifierKeyHash,
    noteSecret: depositNoteSecret,
    amount: FIXTURE_DEPOSIT_AMOUNT,
    tokenAddress: 0n,
    originTag: 0n,
    leafIndex: depositLeafIndex,
  });

  const commitmentEmptyHashes = emptySparseHashes(COMMITMENT_DEPTH, helpers.h2);
  const commitmentRoot = appendOnlyLeafRoot(
    depositCommitment,
    depositLeafIndex,
    commitmentEmptyHashes,
    COMMITMENT_DEPTH,
    helpers.h2,
  );
  const commitmentSiblings = appendOnlyLeafSiblings(
    depositLeafIndex,
    commitmentEmptyHashes,
    COMMITMENT_DEPTH,
  );

  // Single user in the registry: our self-transferring identity.
  const userLeaf = helpers.pHash([
    USER_REGISTRY_LEAF_DOMAIN,
    authorizingAddress,
    ownerNullifierKeyHash,
    noteSecretSeedHash,
  ]);
  const userSiblings = sparseSiblingsForKey(authorizingAddress, REGISTRY_DEPTH, helpers.h2);
  const userRegistryRoot = sparseRootFromKey(
    userLeaf,
    authorizingAddress,
    REGISTRY_DEPTH,
    helpers.h2,
  );

  const scratchBaseParams = {
    mode: "transfer" as const,
    senderAddress: "0x" + authorizingAddress.toString(16).padStart(40, "0"),
    recipientAddress: "0x" + authorizingAddress.toString(16).padStart(40, "0"),
    amount: FIXTURE_TRANSFER_AMOUNT.toString(),
    tokenAddress: "0",
    ownerNullifierKey: FIXTURE_NK.toString(),
    noteSecretSeed: FIXTURE_NSS.toString(),
    policyVersion: "1",
    nonce: "42",
    validUntilSeconds: "1700000000",
    executionChainId: "11155111",
    noteCommitmentRoot: "0",
    userRegistryRoot: "0",
    authPolicyRoot: "0",
    inputLeafIndex: depositLeafIndex.toString(),
    inputAmount: FIXTURE_DEPOSIT_AMOUNT.toString(),
    inputNoteSecret: depositNoteSecret.toString(),
    inputOriginTag: "0",
    inputSiblings: commitmentSiblings.map((value) => "0x" + value.toString(16)),
    userSiblings: userSiblings.map((value) => "0x" + value.toString(16)),
    recipientSiblings: userSiblings.map((value) => "0x" + value.toString(16)),
    recipientOwnerNullifierKeyHash: "0x" + ownerNullifierKeyHash.toString(16),
    recipientNoteSecretSeedHash: "0x" + noteSecretSeedHash.toString(16),
    changeAmount: (FIXTURE_DEPOSIT_AMOUNT - FIXTURE_TRANSFER_AMOUNT).toString(),
    deliverySchemeId: "1",
    deliveryPubKey: deliveryPubKeyHex,
    recipientDeliverySchemeId: "1",
    recipientDeliveryPubKey: deliveryPubKeyHex,
    changeDeliverySchemeId: "1",
    changeDeliveryPubKey: deliveryPubKeyHex,
  };

  const initialCommon = buildCommonTxArtifacts(scratchBaseParams, helpers);
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

  const inner = runInnerCircuit("eip712", innerWitness, "eip712_prove", helpers.pHash);
  const authLeaf = helpers.pHash([
    AUTH_POLICY_DOMAIN,
    authDataCommitment,
    initialCommon.policyVersion,
  ]);
  const authKey =
    helpers.pHash([
      AUTH_POLICY_KEY_DOMAIN,
      authorizingAddress,
      inner.innerVkHash,
    ]) & ((1n << 160n) - 1n);
  const authPolicyRoot = sparseRootFromKey(authLeaf, authKey, REGISTRY_DEPTH, helpers.h2);

  const common = buildCommonTxArtifacts(
    {
      ...scratchBaseParams,
      noteCommitmentRoot: "0x" + commitmentRoot.toString(16),
      userRegistryRoot: "0x" + userRegistryRoot.toString(16),
      authPolicyRoot: "0x" + authPolicyRoot.toString(16),
    },
    helpers,
  );
  assertAuthPolicyRoot(common, authDataCommitment, inner.innerVkHash, helpers);

  const proof = proveOuterTransaction(common, authDataCommitment, inner);
  writeFileSync(
    outputPath,
    JSON.stringify(
      {
        proof: proof.proof,
        publicInputs: proof.publicInputs,
        outputNoteData: proof.outputNoteData,
      },
      null,
      2,
    ) + "\n",
  );

  console.log(`wrote verifier fixture: ${outputPath}`);
}

function emptySparseHashes(
  depth: number,
  h2: (left: bigint, right: bigint) => bigint,
): bigint[] {
  const result: bigint[] = [];
  let current = 0n;
  for (let i = 0; i < depth; i++) {
    result.push(current);
    current = h2(current, current);
  }
  return result;
}

function appendOnlyLeafRoot(
  leaf: bigint,
  leafIndex: bigint,
  emptyHashes: bigint[],
  depth: number,
  h2: (left: bigint, right: bigint) => bigint,
): bigint {
  let current = leaf;
  for (let level = 0; level < depth; level++) {
    const bit = (leafIndex >> BigInt(level)) & 1n;
    current = bit === 0n ? h2(current, emptyHashes[level]) : h2(emptyHashes[level], current);
  }
  return current;
}

function appendOnlyLeafSiblings(
  leafIndex: bigint,
  emptyHashes: bigint[],
  depth: number,
): bigint[] {
  // Only this leaf is non-empty, so every sibling is the empty hash at its level.
  void leafIndex;
  return emptyHashes.slice(0, depth);
}

function sparseRootFromKey(
  leaf: bigint,
  key: bigint,
  depth: number,
  h2: (left: bigint, right: bigint) => bigint,
): bigint {
  let current = leaf;
  let empty = 0n;
  for (let i = 0; i < depth; i++) {
    const bit = Number((key >> BigInt(i)) & 1n);
    current = bit === 0 ? h2(current, empty) : h2(empty, current);
    empty = h2(empty, empty);
  }
  return current;
}

function sparseSiblingsForKey(
  _key: bigint,
  depth: number,
  h2: (left: bigint, right: bigint) => bigint,
): bigint[] {
  const siblings: bigint[] = [];
  let empty = 0n;
  for (let i = 0; i < depth; i++) {
    siblings.push(empty);
    empty = h2(empty, empty);
  }
  return siblings;
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
