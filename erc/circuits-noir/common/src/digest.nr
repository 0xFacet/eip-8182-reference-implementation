// Spec section 15.6 two-level transaction intent digest, matching
// `erc/circuits/common/components.circom` and the TS SDK derivations.
//   transactIntentFieldsHash: 19 fields + domain tag -> arity-20 sponge
//   transactionIntentDigest:  (fieldsHash, policyDataHash) -> arity-3 sponge

use crate::constants::{
    BLINDED_AUTH_COMMITMENT_DOMAIN,
    INTENT_REPLAY_ID_DOMAIN,
    OUTPUT_BINDING_DOMAIN,
    TRANSACT_INTENT_FIELDS_DOMAIN,
    TRANSACTION_INTENT_DIGEST_DOMAIN,
};
use crate::hash_utils::{p_hash3, p_hash6, p_hash20};

pub struct IntentFields {
    pub pool_address: Field,
    pub auth_verifier: Field,
    pub authorizing_address: Field,
    pub operation_kind: Field,
    pub token_address: Field,
    pub recipient_owner_nullifier_key_hash: Field,
    pub amount: Field,
    pub fee_note_recipient_owner_nullifier_key_hash: Field,
    pub fee_amount: Field,
    pub public_recipient_address: Field,
    pub authorized_submitter: Field,
    pub downstream_action_commitment: Field,
    pub execution_constraints_flags: Field,
    pub locked_output_binding0: Field,
    pub locked_output_binding1: Field,
    pub locked_output_binding2: Field,
    pub nonce: Field,
    pub valid_until_seconds: Field,
    pub execution_chain_id: Field,
}

pub fn transact_intent_fields_hash(f: IntentFields) -> Field {
    p_hash20([
        TRANSACT_INTENT_FIELDS_DOMAIN,
        f.pool_address,
        f.auth_verifier,
        f.authorizing_address,
        f.operation_kind,
        f.token_address,
        f.recipient_owner_nullifier_key_hash,
        f.amount,
        f.fee_note_recipient_owner_nullifier_key_hash,
        f.fee_amount,
        f.public_recipient_address,
        f.authorized_submitter,
        f.downstream_action_commitment,
        f.execution_constraints_flags,
        f.locked_output_binding0,
        f.locked_output_binding1,
        f.locked_output_binding2,
        f.nonce,
        f.valid_until_seconds,
        f.execution_chain_id,
    ])
}

pub fn transaction_intent_digest(transact_intent_fields_hash_value: Field, policy_data_hash: Field) -> Field {
    p_hash3([
        TRANSACTION_INTENT_DIGEST_DOMAIN,
        transact_intent_fields_hash_value,
        policy_data_hash,
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

// Spec section 15.6: pool-scoped intent replay id.
pub fn intent_replay_id(
    owner_nullifier_key: Field,
    authorizing_address: Field,
    execution_chain_id: Field,
    pool_address: Field,
    nonce: Field,
) -> Field {
    p_hash6([
        INTENT_REPLAY_ID_DOMAIN,
        owner_nullifier_key,
        authorizing_address,
        execution_chain_id,
        pool_address,
        nonce,
    ])
}

fn test_fields() -> IntentFields {
    IntentFields {
        pool_address: 0x1234,
        auth_verifier: 0x2222,
        authorizing_address: 0xabc,
        operation_kind: 0,
        token_address: 0x1111,
        recipient_owner_nullifier_key_hash: 0xdef,
        amount: 1000,
        fee_note_recipient_owner_nullifier_key_hash: 0,
        fee_amount: 0,
        public_recipient_address: 0,
        authorized_submitter: 0,
        downstream_action_commitment: 0,
        execution_constraints_flags: 0,
        locked_output_binding0: 0,
        locked_output_binding1: 0,
        locked_output_binding2: 0,
        nonce: 42,
        valid_until_seconds: 1700000000,
        execution_chain_id: 1,
    }
}

#[test]
fn test_two_level_digest_deterministic() {
    let fh1 = transact_intent_fields_hash(test_fields());
    let fh2 = transact_intent_fields_hash(test_fields());
    assert(fh1 == fh2);
    let d1 = transaction_intent_digest(fh1, 7);
    let d2 = transaction_intent_digest(fh2, 7);
    assert(d1 == d2);
    assert(d1 != 0);
}

#[test]
fn test_policy_data_hash_changes_digest() {
    let fh = transact_intent_fields_hash(test_fields());
    assert(transaction_intent_digest(fh, 7) != transaction_intent_digest(fh, 8));
}

#[test]
fn test_pool_address_changes_fields_hash() {
    let mut f2 = test_fields();
    f2.pool_address = 0x9999;
    assert(transact_intent_fields_hash(test_fields()) != transact_intent_fields_hash(f2));
}

#[test]
fn test_replay_id_pool_scoped() {
    let r1 = intent_replay_id(1, 2, 3, 0x1234, 5);
    let r2 = intent_replay_id(1, 2, 3, 0x5678, 5);
    assert(r1 != r2);
}
