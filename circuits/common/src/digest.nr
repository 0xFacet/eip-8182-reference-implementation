use crate::constants::{
    INTENT_DIGEST_DOMAIN,
    INTENT_DOMAIN,
    OUTPUT_BINDING_DOMAIN,
};
use crate::hash_utils::{p_hash3, p_hash5, p_hash17};

pub fn intent_digest(
    policy_version: Field,
    authorizing_address: Field,
    operation_kind: Field,
    token_address: Field,
    recipient_address: Field,
    amount: Field,
    fee_recipient_address: Field,
    fee_amount: Field,
    origin_mode: Field,
    execution_constraints_flags: Field,
    locked_output_binding0: Field,
    locked_output_binding1: Field,
    locked_output_binding2: Field,
    nonce: Field,
    valid_until_seconds: Field,
    execution_chain_id: Field,
) -> Field {
    p_hash17([
        INTENT_DIGEST_DOMAIN,
        policy_version,
        authorizing_address,
        operation_kind,
        token_address,
        recipient_address,
        amount,
        fee_recipient_address,
        fee_amount,
        origin_mode,
        execution_constraints_flags,
        locked_output_binding0,
        locked_output_binding1,
        locked_output_binding2,
        nonce,
        valid_until_seconds,
        execution_chain_id,
    ])
}

pub fn output_binding(commitment: Field, output_note_data_hash: Field) -> Field {
    p_hash3([OUTPUT_BINDING_DOMAIN, commitment, output_note_data_hash])
}

pub fn intent_nullifier(
    nullifier_key: Field,
    authorizing_address: Field,
    execution_chain_id: Field,
    nonce: Field,
) -> Field {
    p_hash5([
        INTENT_DOMAIN,
        nullifier_key,
        authorizing_address,
        execution_chain_id,
        nonce,
    ])
}

#[test]
fn test_intent_digest_deterministic() {
    let d1 = intent_digest(1, 0xabc, 0, 0x1111, 0xdef, 1000, 0, 0, 0, 0, 0, 0, 0, 42, 1700000000, 1);
    let d2 = intent_digest(1, 0xabc, 0, 0x1111, 0xdef, 1000, 0, 0, 0, 0, 0, 0, 0, 42, 1700000000, 1);
    assert(d1 == d2);
    assert(d1 != 0);
}

#[test]
fn test_different_nonce_different_intent_digest() {
    let d1 = intent_digest(1, 0xabc, 0, 0x1111, 0xdef, 1000, 0, 0, 0, 0, 0, 0, 0, 42, 1700000000, 1);
    let d2 = intent_digest(1, 0xabc, 0, 0x1111, 0xdef, 1000, 0, 0, 0, 0, 0, 0, 0, 43, 1700000000, 1);
    assert(d1 != d2);
}

#[test]
fn test_execution_constraints_change_intent_digest() {
    let d1 = intent_digest(1, 0xabc, 0, 0x1111, 0xdef, 1000, 0, 0, 0, 0, 0, 0, 0, 42, 1700000000, 1);
    let d2 = intent_digest(1, 0xabc, 0, 0x1111, 0xdef, 1000, 0, 0, 0, 1, 0x1234, 0, 0, 42, 1700000000, 1);
    assert(d1 != d2);
}

#[test]
fn test_intent_nullifier_reuses_nonce_domain() {
    let n1 = intent_nullifier(0x9999, 0xabc, 1, 42);
    let n2 = intent_nullifier(0x9999, 0xabc, 1, 42);
    assert(n1 == n2);
    assert(n1 != 0);
}

#[test]
fn test_intent_nullifier_changes_with_nonce() {
    let n1 = intent_nullifier(0x9999, 0xabc, 1, 42);
    let n2 = intent_nullifier(0x9999, 0xabc, 1, 43);
    assert(n1 != n2);
}

#[test]
fn test_intent_nullifier_ignores_payment_fields() {
    let n1 = intent_nullifier(0x9999, 0xabc, 1, 42);
    let n2 = intent_nullifier(0x9999, 0xabc, 1, 42);
    assert(n1 == n2);
}
