// Section 11 hash-context wrappers. Each is a thin sponge instantiation
// with the ordered inputs from the spec table.

pragma circom 2.0.0;

include "poseidon2_sponge.circom";
include "domain_tags.circom";

// poseidon(OWNER_NULLIFIER_KEY_HASH_DOMAIN, ownerNullifierKey)
template OwnerNullifierKeyHash() {
    signal input  ownerNullifierKey;
    signal output out;
    component s = Poseidon2Sponge(2);
    s.in[0] <== OWNER_NULLIFIER_KEY_HASH_DOMAIN();
    s.in[1] <== ownerNullifierKey;
    out <== s.out;
}

// poseidon(OWNER_COMMITMENT_DOMAIN, ownerNullifierKeyHash, noteSecret)
template OwnerCommitment() {
    signal input  ownerNullifierKeyHash;
    signal input  noteSecret;
    signal output out;
    component s = Poseidon2Sponge(3);
    s.in[0] <== OWNER_COMMITMENT_DOMAIN();
    s.in[1] <== ownerNullifierKeyHash;
    s.in[2] <== noteSecret;
    out <== s.out;
}

// poseidon(NOTE_BODY_COMMITMENT_DOMAIN, ownerCommitment, amount, tokenAddress)
template NoteBodyCommitment() {
    signal input  ownerCommitment;
    signal input  amount;
    signal input  tokenAddress;
    signal output out;
    component s = Poseidon2Sponge(4);
    s.in[0] <== NOTE_BODY_COMMITMENT_DOMAIN();
    s.in[1] <== ownerCommitment;
    s.in[2] <== amount;
    s.in[3] <== tokenAddress;
    out <== s.out;
}

// poseidon(NOTE_COMMITMENT_DOMAIN, noteBodyCommitment, leafIndex)
template NoteCommitment() {
    signal input  noteBodyCommitment;
    signal input  leafIndex;
    signal output out;
    component s = Poseidon2Sponge(3);
    s.in[0] <== NOTE_COMMITMENT_DOMAIN();
    s.in[1] <== noteBodyCommitment;
    s.in[2] <== leafIndex;
    out <== s.out;
}

// poseidon(NULLIFIER_DOMAIN, noteCommitment, ownerNullifierKey)
template Nullifier() {
    signal input  noteCommitment;
    signal input  ownerNullifierKey;
    signal output out;
    component s = Poseidon2Sponge(3);
    s.in[0] <== NULLIFIER_DOMAIN();
    s.in[1] <== noteCommitment;
    s.in[2] <== ownerNullifierKey;
    out <== s.out;
}

// poseidon(PHANTOM_NULLIFIER_DOMAIN, ownerNullifierKey, intentReplayId, inputIndex)
template PhantomNullifier() {
    signal input  ownerNullifierKey;
    signal input  intentReplayId;
    signal input  inputIndex;
    signal output out;
    component s = Poseidon2Sponge(4);
    s.in[0] <== PHANTOM_NULLIFIER_DOMAIN();
    s.in[1] <== ownerNullifierKey;
    s.in[2] <== intentReplayId;
    s.in[3] <== inputIndex;
    out <== s.out;
}

// poseidon(NOTE_SECRET_SEED_DOMAIN, noteSecretSeed)
template NoteSecretSeedHash() {
    signal input  noteSecretSeed;
    signal output out;
    component s = Poseidon2Sponge(2);
    s.in[0] <== NOTE_SECRET_SEED_DOMAIN();
    s.in[1] <== noteSecretSeed;
    out <== s.out;
}

// poseidon(TRANSACT_NOTE_SECRET_DOMAIN, noteSecretSeed, intentReplayId, outputIndex)
template TransactNoteSecret() {
    signal input  noteSecretSeed;
    signal input  intentReplayId;
    signal input  outputIndex;
    signal output out;
    component s = Poseidon2Sponge(4);
    s.in[0] <== TRANSACT_NOTE_SECRET_DOMAIN();
    s.in[1] <== noteSecretSeed;
    s.in[2] <== intentReplayId;
    s.in[3] <== outputIndex;
    out <== s.out;
}

// poseidon(INTENT_REPLAY_ID_DOMAIN, ownerNullifierKey, authorizingAddress, executionChainId, nonce)
template IntentReplayId() {
    signal input  ownerNullifierKey;
    signal input  authorizingAddress;
    signal input  executionChainId;
    signal input  nonce;
    signal output out;
    component s = Poseidon2Sponge(5);
    s.in[0] <== INTENT_REPLAY_ID_DOMAIN();
    s.in[1] <== ownerNullifierKey;
    s.in[2] <== authorizingAddress;
    s.in[3] <== executionChainId;
    s.in[4] <== nonce;
    out <== s.out;
}

// poseidon(OUTPUT_BINDING_DOMAIN, noteBodyCommitment, outputNoteDataHash)
template OutputBinding() {
    signal input  noteBodyCommitment;
    signal input  outputNoteDataHash;
    signal output out;
    component s = Poseidon2Sponge(3);
    s.in[0] <== OUTPUT_BINDING_DOMAIN();
    s.in[1] <== noteBodyCommitment;
    s.in[2] <== outputNoteDataHash;
    out <== s.out;
}

// poseidon(POLICY_COMMITMENT_DOMAIN, authVerifier, authDataCommitment, registrationBlinder)
template PolicyCommitment() {
    signal input  authVerifier;
    signal input  authDataCommitment;
    signal input  registrationBlinder;
    signal output out;
    component s = Poseidon2Sponge(4);
    s.in[0] <== POLICY_COMMITMENT_DOMAIN();
    s.in[1] <== authVerifier;
    s.in[2] <== authDataCommitment;
    s.in[3] <== registrationBlinder;
    out <== s.out;
}

// poseidon(AUTH_POLICY_DOMAIN, user, policyCommitment)
template AuthPolicyLeaf() {
    signal input  user;
    signal input  policyCommitment;
    signal output out;
    component s = Poseidon2Sponge(3);
    s.in[0] <== AUTH_POLICY_DOMAIN();
    s.in[1] <== user;
    s.in[2] <== policyCommitment;
    out <== s.out;
}

// poseidon(BLINDED_AUTH_COMMITMENT_DOMAIN, authDataCommitment, blindingFactor)
template BlindedAuthCommitment() {
    signal input  authDataCommitment;
    signal input  blindingFactor;
    signal output out;
    component s = Poseidon2Sponge(3);
    s.in[0] <== BLINDED_AUTH_COMMITMENT_DOMAIN();
    s.in[1] <== authDataCommitment;
    s.in[2] <== blindingFactor;
    out <== s.out;
}

// poseidon(HISTORICAL_NOTE_ROOT_LEAF_DOMAIN, noteRoot, rootLogIndex)
template HistoricalNoteRootLeaf() {
    signal input  noteRoot;
    signal input  rootLogIndex;
    signal output out;
    component s = Poseidon2Sponge(3);
    s.in[0] <== HISTORICAL_NOTE_ROOT_LEAF_DOMAIN();
    s.in[1] <== noteRoot;
    s.in[2] <== rootLogIndex;
    out <== s.out;
}

// poseidon(USER_REGISTRY_LEAF_DOMAIN, user, ownerNullifierKeyHash, noteSecretSeedHash)
template UserRegistryLeaf() {
    signal input  user;
    signal input  ownerNullifierKeyHash;
    signal input  noteSecretSeedHash;
    signal output out;
    component s = Poseidon2Sponge(4);
    s.in[0] <== USER_REGISTRY_LEAF_DOMAIN();
    s.in[1] <== user;
    s.in[2] <== ownerNullifierKeyHash;
    s.in[3] <== noteSecretSeedHash;
    out <== s.out;
}

// poseidon(TRANSACTION_INTENT_DIGEST_DOMAIN, authVerifier, authorizingAddress,
//          operationKind, tokenAddress, recipientAddress, amount,
//          feeRecipientAddress, feeAmount, executionConstraintsFlags,
//          lockedOutputBinding0, lockedOutputBinding1, lockedOutputBinding2,
//          nonce, validUntilSeconds, executionChainId)
//   = 1 (domain) + 15 fields = arity 16
template TransactionIntentDigest() {
    signal input  authVerifier;
    signal input  authorizingAddress;
    signal input  operationKind;
    signal input  tokenAddress;
    signal input  recipientAddress;
    signal input  amount;
    signal input  feeRecipientAddress;
    signal input  feeAmount;
    signal input  executionConstraintsFlags;
    signal input  lockedOutputBinding0;
    signal input  lockedOutputBinding1;
    signal input  lockedOutputBinding2;
    signal input  nonce;
    signal input  validUntilSeconds;
    signal input  executionChainId;
    signal output out;
    component s = Poseidon2Sponge(16);
    s.in[0]  <== TRANSACTION_INTENT_DIGEST_DOMAIN();
    s.in[1]  <== authVerifier;
    s.in[2]  <== authorizingAddress;
    s.in[3]  <== operationKind;
    s.in[4]  <== tokenAddress;
    s.in[5]  <== recipientAddress;
    s.in[6]  <== amount;
    s.in[7]  <== feeRecipientAddress;
    s.in[8]  <== feeAmount;
    s.in[9]  <== executionConstraintsFlags;
    s.in[10] <== lockedOutputBinding0;
    s.in[11] <== lockedOutputBinding1;
    s.in[12] <== lockedOutputBinding2;
    s.in[13] <== nonce;
    s.in[14] <== validUntilSeconds;
    s.in[15] <== executionChainId;
    out <== s.out;
}
