// Section 8.9 transaction intent digest, matching `circuits/common/components.circom`
// and `circuits/pool/pool.circom`. 16 fields plus the domain tag -> arity-17 sponge.

use crate::constants::{
    TRANSACTION_INTENT_DIGEST_DOMAIN,
    INTENT_REPLAY_ID_DOMAIN,
    OUTPUT_BINDING_DOMAIN,
    BLINDED_AUTH_COMMITMENT_DOMAIN,
};
use crate::hash_utils::{p_hash3, p_hash5, p_hash17};

pub fn transaction_intent_digest(
    auth_verifier: Field,
    authorizing_address: Field,
    operation_kind: Field,
    token_address: Field,
    recipient_owner_nullifier_key_hash: Field,
    amount: Field,
    fee_note_recipient_owner_nullifier_key_hash: Field,
    fee_amount: Field,
    public_recipient_address: Field,
    execution_constraints_flags: Field,
    locked_output_binding0: Field,
    locked_output_binding1: Field,
    locked_output_binding2: Field,
    nonce: Field,
    valid_until_seconds: Field,
    execution_chain_id: Field,
) -> Field {
    p_hash17([
        TRANSACTION_INTENT_DIGEST_DOMAIN,
        auth_verifier,
        authorizing_address,
        operation_kind,
        token_address,
        recipient_owner_nullifier_key_hash,
        amount,
        fee_note_recipient_owner_nullifier_key_hash,
        fee_amount,
        public_recipient_address,
        execution_constraints_flags,
        locked_output_binding0,
        locked_output_binding1,
        locked_output_binding2,
        nonce,
        valid_until_seconds,
        execution_chain_id,
    ])
}

pub fn blinded_auth_commitment(auth_data_commitment: Field, blinding_factor: Field) -> Field {
    p_hash3([
        BLINDED_AUTH_COMMITMENT_DOMAIN,
        auth_data_commitment,
        blinding_factor,
    ])
}

pub fn output_binding(commitment: Field, output_note_data_hash: Field) -> Field {
    p_hash3([OUTPUT_BINDING_DOMAIN, commitment, output_note_data_hash])
}

pub fn intent_replay_id(
    owner_nullifier_key: Field,
    authorizing_address: Field,
    execution_chain_id: Field,
    nonce: Field,
) -> Field {
    p_hash5([
        INTENT_REPLAY_ID_DOMAIN,
        owner_nullifier_key,
        authorizing_address,
        execution_chain_id,
        nonce,
    ])
}

#[test]
fn test_transaction_intent_digest_deterministic() {
    let d1 = transaction_intent_digest(
        0x1234, 0xabc, 0, 0x1111, 0xdef, 1000, 0, 0, 0, 0, 0, 0, 0, 42, 1700000000, 1,
    );
    let d2 = transaction_intent_digest(
        0x1234, 0xabc, 0, 0x1111, 0xdef, 1000, 0, 0, 0, 0, 0, 0, 0, 42, 1700000000, 1,
    );
    assert(d1 == d2);
    assert(d1 != 0);
}

#[test]
fn test_different_auth_verifier_different_digest() {
    let d1 = transaction_intent_digest(
        0x1234, 0xabc, 0, 0x1111, 0xdef, 1000, 0, 0, 0, 0, 0, 0, 0, 42, 1700000000, 1,
    );
    let d2 = transaction_intent_digest(
        0x9999, 0xabc, 0, 0x1111, 0xdef, 1000, 0, 0, 0, 0, 0, 0, 0, 42, 1700000000, 1,
    );
    assert(d1 != d2);
}

#[test]
fn test_blinded_auth_commitment_changes_with_blinding_factor() {
    let b1 = blinded_auth_commitment(0xa1, 0xb1);
    let b2 = blinded_auth_commitment(0xa1, 0xb2);
    assert(b1 != b2);
}
