// Spec §15.6 / §16.1 hash-context wrappers. Each is a thin sponge
// instantiation with the ordered inputs from the spec formulas. Pool-scoped
// contexts absorb (executionChainId, poolAddress) so shared registry identity
// material never produces identical or linkable artifacts across pools.

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

// poseidon(OWNER_COMMITMENT_DOMAIN, executionChainId, poolAddress, ownerNullifierKeyHash, noteSecret)
template OwnerCommitment() {
    signal input  executionChainId;
    signal input  poolAddress;
    signal input  ownerNullifierKeyHash;
    signal input  noteSecret;
    signal output out;
    component s = Poseidon2Sponge(5);
    s.in[0] <== OWNER_COMMITMENT_DOMAIN();
    s.in[1] <== executionChainId;
    s.in[2] <== poolAddress;
    s.in[3] <== ownerNullifierKeyHash;
    s.in[4] <== noteSecret;
    out <== s.out;
}

// poseidon(NOTE_BODY_COMMITMENT_DOMAIN, ownerCommitment, amount, tokenAddress)
// NOT pool-scoped (spec §15.6): pool scope enters through ownerCommitment.
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

// poseidon(NOTE_COMMITMENT_DOMAIN, executionChainId, poolAddress, noteBodyCommitment, leafIndex)
template NoteCommitment() {
    signal input  executionChainId;
    signal input  poolAddress;
    signal input  noteBodyCommitment;
    signal input  leafIndex;
    signal output out;
    component s = Poseidon2Sponge(5);
    s.in[0] <== NOTE_COMMITMENT_DOMAIN();
    s.in[1] <== executionChainId;
    s.in[2] <== poolAddress;
    s.in[3] <== noteBodyCommitment;
    s.in[4] <== leafIndex;
    out <== s.out;
}

// poseidon(NULLIFIER_DOMAIN, executionChainId, poolAddress, noteCommitment, ownerNullifierKey)
template Nullifier() {
    signal input  executionChainId;
    signal input  poolAddress;
    signal input  noteCommitment;
    signal input  ownerNullifierKey;
    signal output out;
    component s = Poseidon2Sponge(5);
    s.in[0] <== NULLIFIER_DOMAIN();
    s.in[1] <== executionChainId;
    s.in[2] <== poolAddress;
    s.in[3] <== noteCommitment;
    s.in[4] <== ownerNullifierKey;
    out <== s.out;
}

// poseidon(PHANTOM_NULLIFIER_DOMAIN, executionChainId, poolAddress, ownerNullifierKey, intentReplayId, inputIndex)
template PhantomNullifier() {
    signal input  executionChainId;
    signal input  poolAddress;
    signal input  ownerNullifierKey;
    signal input  intentReplayId;
    signal input  inputIndex;
    signal output out;
    component s = Poseidon2Sponge(6);
    s.in[0] <== PHANTOM_NULLIFIER_DOMAIN();
    s.in[1] <== executionChainId;
    s.in[2] <== poolAddress;
    s.in[3] <== ownerNullifierKey;
    s.in[4] <== intentReplayId;
    s.in[5] <== inputIndex;
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

// poseidon(TRANSACT_NOTE_SECRET_DOMAIN, noteSecretSeed, executionChainId, poolAddress, intentReplayId, outputIndex)
template TransactNoteSecret() {
    signal input  noteSecretSeed;
    signal input  executionChainId;
    signal input  poolAddress;
    signal input  intentReplayId;
    signal input  outputIndex;
    signal output out;
    component s = Poseidon2Sponge(6);
    s.in[0] <== TRANSACT_NOTE_SECRET_DOMAIN();
    s.in[1] <== noteSecretSeed;
    s.in[2] <== executionChainId;
    s.in[3] <== poolAddress;
    s.in[4] <== intentReplayId;
    s.in[5] <== outputIndex;
    out <== s.out;
}

// poseidon(INTENT_REPLAY_ID_DOMAIN, ownerNullifierKey, authorizingAddress, executionChainId, poolAddress, nonce)
template IntentReplayId() {
    signal input  ownerNullifierKey;
    signal input  authorizingAddress;
    signal input  executionChainId;
    signal input  poolAddress;
    signal input  nonce;
    signal output out;
    component s = Poseidon2Sponge(6);
    s.in[0] <== INTENT_REPLAY_ID_DOMAIN();
    s.in[1] <== ownerNullifierKey;
    s.in[2] <== authorizingAddress;
    s.in[3] <== executionChainId;
    s.in[4] <== poolAddress;
    s.in[5] <== nonce;
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

// poseidon(IDENTITY_LEAF_DOMAIN, user, ownerNullifierKeyHash, noteSecretSeedHash, policySetCommitment)
template IdentityLeaf() {
    signal input  user;
    signal input  ownerNullifierKeyHash;
    signal input  noteSecretSeedHash;
    signal input  policySetCommitment;
    signal output out;
    component s = Poseidon2Sponge(5);
    s.in[0] <== IDENTITY_LEAF_DOMAIN();
    s.in[1] <== user;
    s.in[2] <== ownerNullifierKeyHash;
    s.in[3] <== noteSecretSeedHash;
    s.in[4] <== policySetCommitment;
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

// poseidon(TRANSACT_INTENT_FIELDS_DOMAIN, poolAddress, authVerifier,
//          authorizingAddress, operationKind, tokenAddress,
//          recipientOwnerNullifierKeyHash, amount,
//          feeNoteRecipientOwnerNullifierKeyHash, feeAmount,
//          publicRecipientAddress, authorizedSubmitter, downstreamActionCommitment,
//          executionConstraintsFlags, lockedOutputBinding0, lockedOutputBinding1,
//          lockedOutputBinding2, nonce, validUntilSeconds, executionChainId)
//   = 1 (domain) + 19 fields = arity 20 (spec §15.6)
template TransactIntentFieldsHash() {
    signal input  poolAddress;
    signal input  authVerifier;
    signal input  authorizingAddress;
    signal input  operationKind;
    signal input  tokenAddress;
    signal input  recipientOwnerNullifierKeyHash;
    signal input  amount;
    signal input  feeNoteRecipientOwnerNullifierKeyHash;
    signal input  feeAmount;
    signal input  publicRecipientAddress;
    signal input  authorizedSubmitter;
    signal input  downstreamActionCommitment;
    signal input  executionConstraintsFlags;
    signal input  lockedOutputBinding0;
    signal input  lockedOutputBinding1;
    signal input  lockedOutputBinding2;
    signal input  nonce;
    signal input  validUntilSeconds;
    signal input  executionChainId;
    signal output out;
    component s = Poseidon2Sponge(20);
    s.in[0]  <== TRANSACT_INTENT_FIELDS_DOMAIN();
    s.in[1]  <== poolAddress;
    s.in[2]  <== authVerifier;
    s.in[3]  <== authorizingAddress;
    s.in[4]  <== operationKind;
    s.in[5]  <== tokenAddress;
    s.in[6]  <== recipientOwnerNullifierKeyHash;
    s.in[7]  <== amount;
    s.in[8]  <== feeNoteRecipientOwnerNullifierKeyHash;
    s.in[9]  <== feeAmount;
    s.in[10] <== publicRecipientAddress;
    s.in[11] <== authorizedSubmitter;
    s.in[12] <== downstreamActionCommitment;
    s.in[13] <== executionConstraintsFlags;
    s.in[14] <== lockedOutputBinding0;
    s.in[15] <== lockedOutputBinding1;
    s.in[16] <== lockedOutputBinding2;
    s.in[17] <== nonce;
    s.in[18] <== validUntilSeconds;
    s.in[19] <== executionChainId;
    out <== s.out;
}

// poseidon(TRANSACTION_INTENT_DIGEST_DOMAIN, transactIntentFieldsHash, policyDataHash)
template TransactionIntentDigest() {
    signal input  transactIntentFieldsHash;
    signal input  policyDataHash;
    signal output out;
    component s = Poseidon2Sponge(3);
    s.in[0] <== TRANSACTION_INTENT_DIGEST_DOMAIN();
    s.in[1] <== transactIntentFieldsHash;
    s.in[2] <== policyDataHash;
    out <== s.out;
}

// poseidon(POLICY_TRANSACT_PUBLIC_TRANSITION_DOMAIN, ...21 public transition
// fields through downstreamActionCommitment) — spec §16.1, arity 22.
template TransactPublicTransitionHash() {
    signal input  noteCommitmentRoot;
    signal input  nullifier0;
    signal input  nullifier1;
    signal input  noteBodyCommitment0;
    signal input  noteBodyCommitment1;
    signal input  noteBodyCommitment2;
    signal input  publicAmountOut;
    signal input  publicRecipientAddress;
    signal input  publicTokenAddress;
    signal input  intentReplayId;
    signal input  validUntilSeconds;
    signal input  executionChainId;
    signal input  poolAddress;
    signal input  identityRoot;
    signal input  outputNoteDataHash0;
    signal input  outputNoteDataHash1;
    signal input  outputNoteDataHash2;
    signal input  authVerifier;
    signal input  blindedAuthCommitment;
    signal input  authorizedSubmitter;
    signal input  downstreamActionCommitment;
    signal output out;
    component s = Poseidon2Sponge(22);
    s.in[0]  <== POLICY_TRANSACT_PUBLIC_TRANSITION_DOMAIN();
    s.in[1]  <== noteCommitmentRoot;
    s.in[2]  <== nullifier0;
    s.in[3]  <== nullifier1;
    s.in[4]  <== noteBodyCommitment0;
    s.in[5]  <== noteBodyCommitment1;
    s.in[6]  <== noteBodyCommitment2;
    s.in[7]  <== publicAmountOut;
    s.in[8]  <== publicRecipientAddress;
    s.in[9]  <== publicTokenAddress;
    s.in[10] <== intentReplayId;
    s.in[11] <== validUntilSeconds;
    s.in[12] <== executionChainId;
    s.in[13] <== poolAddress;
    s.in[14] <== identityRoot;
    s.in[15] <== outputNoteDataHash0;
    s.in[16] <== outputNoteDataHash1;
    s.in[17] <== outputNoteDataHash2;
    s.in[18] <== authVerifier;
    s.in[19] <== blindedAuthCommitment;
    s.in[20] <== authorizedSubmitter;
    s.in[21] <== downstreamActionCommitment;
    out <== s.out;
}

// poseidon(POLICY_TRANSACT_OPERATION_DATA_DOMAIN, transactIntentFieldsHash, transactPublicTransitionHash)
template TransactOperationDataHash() {
    signal input  transactIntentFieldsHash;
    signal input  transactPublicTransitionHash;
    signal output out;
    component s = Poseidon2Sponge(3);
    s.in[0] <== POLICY_TRANSACT_OPERATION_DATA_DOMAIN();
    s.in[1] <== transactIntentFieldsHash;
    s.in[2] <== transactPublicTransitionHash;
    out <== s.out;
}
