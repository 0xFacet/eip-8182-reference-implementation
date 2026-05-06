// EIP-8182 intent + commitment helpers — pure JS off-chain reference for the
// computations the contract and the circuit perform internally. Used by the
// integration test to construct matching pool + auth witnesses and to predict
// post-state values.

const { poseidon } = require("./poseidon2");
const T = require("./domain_tags");

const PUBLIC_INPUT_FIELDS = [
  "historicalNoteRootAccumulatorRoot",
  "nullifier0",
  "nullifier1",
  "noteBodyCommitment0",
  "noteBodyCommitment1",
  "noteBodyCommitment2",
  "publicAmountOut",
  "publicRecipientAddress",
  "publicTokenAddress",
  "intentReplayId",
  "registryRoot",
  "validUntilSeconds",
  "executionChainId",
  "authPolicyRegistrationRoot",
  "authPolicyRevocationRoot",
  "outputNoteDataHash0",
  "outputNoteDataHash1",
  "outputNoteDataHash2",
  "authVerifier",
  "blindedAuthCommitment",
  "transactionIntentDigest",
];

function transactionIntentDigest(intent) {
  return poseidon(
    T.TRANSACTION_INTENT_DIGEST_DOMAIN,
    BigInt(intent.authVerifier),
    BigInt(intent.authorizingAddress),
    BigInt(intent.operationKind),
    BigInt(intent.tokenAddress),
    BigInt(intent.recipientAddress),
    BigInt(intent.amount),
    BigInt(intent.feeRecipientAddress),
    BigInt(intent.feeAmount),
    BigInt(intent.executionConstraintsFlags),
    BigInt(intent.lockedOutputBinding0),
    BigInt(intent.lockedOutputBinding1),
    BigInt(intent.lockedOutputBinding2),
    BigInt(intent.nonce),
    BigInt(intent.validUntilSeconds),
    BigInt(intent.executionChainId),
  );
}

function intentReplayId(ownerNullifierKey, authorizingAddress, executionChainId, nonce) {
  return poseidon(
    T.INTENT_REPLAY_ID_DOMAIN,
    BigInt(ownerNullifierKey),
    BigInt(authorizingAddress),
    BigInt(executionChainId),
    BigInt(nonce),
  );
}

function ownerCommitment(ownerNullifierKeyHash, noteSecret) {
  return poseidon(T.OWNER_COMMITMENT_DOMAIN, BigInt(ownerNullifierKeyHash), BigInt(noteSecret));
}

function noteBodyCommitment(ownerCommitmentValue, amount, tokenAddress) {
  return poseidon(
    T.NOTE_BODY_COMMITMENT_DOMAIN,
    BigInt(ownerCommitmentValue),
    BigInt(amount),
    BigInt(tokenAddress),
  );
}

function noteCommitment(noteBodyCommitmentValue, leafIndex) {
  return poseidon(T.NOTE_COMMITMENT_DOMAIN, BigInt(noteBodyCommitmentValue), BigInt(leafIndex));
}

function nullifier(noteCommitmentValue, ownerNullifierKey) {
  return poseidon(T.NULLIFIER_DOMAIN, BigInt(noteCommitmentValue), BigInt(ownerNullifierKey));
}

function userRegistryLeaf(user, ownerNullifierKeyHash, noteSecretSeedHash) {
  return poseidon(
    T.USER_REGISTRY_LEAF_DOMAIN,
    BigInt(user),
    BigInt(ownerNullifierKeyHash),
    BigInt(noteSecretSeedHash),
  );
}

function authPolicyLeaf(user, policyCommitment) {
  return poseidon(T.AUTH_POLICY_DOMAIN, BigInt(user), BigInt(policyCommitment));
}

function policyCommitment(authVerifier, authDataCommitment, registrationBlinder) {
  return poseidon(
    T.POLICY_COMMITMENT_DOMAIN,
    BigInt(authVerifier),
    BigInt(authDataCommitment),
    BigInt(registrationBlinder),
  );
}

function blindedAuthCommitment(authDataCommitment, blindingFactor) {
  return poseidon(
    T.BLINDED_AUTH_COMMITMENT_DOMAIN,
    BigInt(authDataCommitment),
    BigInt(blindingFactor),
  );
}

module.exports = {
  PUBLIC_INPUT_FIELDS,
  transactionIntentDigest,
  intentReplayId,
  ownerCommitment,
  noteBodyCommitment,
  noteCommitment,
  nullifier,
  userRegistryLeaf,
  authPolicyLeaf,
  policyCommitment,
  blindedAuthCommitment,
};
