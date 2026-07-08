// Appendix A reference auth circuit: EIP-712 / ECDSA-secp256k1 over the full
// 20-field PrivateTransferIntent, bound to the deployed pool identity
// (chainId, poolAddress).
//
// Public outputs (spec section 7.5): [blinded_auth_commitment, transaction_intent_digest]
//
// Relation (spec Appendix A):
//   1. Compute the EIP-712 digest for domain
//      (name "ERCXXXXPrivateTransfers", version "1", chainId = executionChainId,
//       verifyingContract = poolAddress) and primary type PrivateTransferIntent
//      over ALL 19 intent fields + policyDataHash.
//   2. Verify a low-s secp256k1 ECDSA signature over that digest.
//   3. Require keccak(pubkey)[-20:] == authorizingAddress.
//   4. chainId / poolAddress binding: the same witnesses feed the EIP-712
//      domain AND transactIntentFieldsHash, so the signature and the digest
//      commit to the same pool identity.
//   5. authVerifier binding: the signed authVerifier field feeds the fields
//      hash; the pool circuit recomputes the digest from its PUBLIC authVerifier
//      input and the pool dispatches verifyAuth to that same address. Digest
//      equality across the two proofs forces signed == dispatched.
//   6. authDataCommitment = poseidon(EIP712_AUTH_DATA_DOMAIN, authorizingAddress);
//      blinded = poseidon(BLINDED_AUTH_COMMITMENT_DOMAIN, authDataCommitment,
//      blindingFactor).
//   7. transactionIntentDigest = poseidon(TRANSACTION_INTENT_DIGEST_DOMAIN,
//      transactIntentFieldsHash, policyDataHash) - the two-level section 15.6 form.

mod secp256k1;
mod vector_test;

use keccak256::keccak256;
use privacy_pool_common::constants::{
    EIP712_DOMAIN_TYPE_HASH,
    EIP712_INTENT_TYPE_HASH,
    EIP712_NAME_HASH,
    EIP712_VERSION_HASH,
};
use privacy_pool_common::crypto::eip712_auth_data_commitment;
use privacy_pool_common::digest::{
    blinded_auth_commitment,
    IntentFields,
    transact_intent_fields_hash,
    transaction_intent_digest,
};
use privacy_pool_common::range::{
    assert_address,
    assert_amount,
    assert_execution_constraints_flags,
    assert_valid_until,
};
use crate::secp256k1::{Secp256k1PubKey, Signature};

global FIELD_MODULUS_BYTES: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
    0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

// secp256k1 half order (inclusive low-s bound): (n - 1) / 2
global SECP256K1_HALF_ORDER_BYTES: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
    0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

global U128_SHIFT: Field = 340282366920938463463374607431768211456;

fn main(
    // Signed intent fields (private; bound by the EIP-712 signature).
    execution_chain_id: Field,
    pool_address: Field,
    auth_verifier: Field,
    authorizing_address: Field,
    operation_kind: Field,
    token_address: Field,
    recipient_owner_nullifier_key_hash: Field,
    amount: Field,
    fee_note_recipient_owner_nullifier_key_hash: Field,
    fee_amount: Field,
    public_recipient_address: Field,
    authorized_submitter: Field,
    downstream_action_commitment: Field,
    execution_constraints_flags: Field,
    locked_output_binding0: Field,
    locked_output_binding1: Field,
    locked_output_binding2: Field,
    policy_data_hash: Field,
    nonce: [u8; 32],
    valid_until_seconds: Field,
    // credential
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    signature: [u8; 64],
    blinding_factor: Field,
) -> pub (Field, Field) {
    // Range checks on bounded semantic types. Poseidon-output-valued fields
    // (recipient/fee owner hashes, policyDataHash) are Fields; no range check.
    assert_address(pool_address);
    assert_address(auth_verifier);
    assert_address(authorizing_address);
    assert_address(token_address);
    assert_address(public_recipient_address);
    assert_address(authorized_submitter);
    assert_amount(amount);
    assert_amount(fee_amount);
    assert_valid_until(valid_until_seconds);
    assert_execution_constraints_flags(execution_constraints_flags);
    assert(operation_kind * (operation_kind - 1) == 0, "operation_kind must be 0 or 1");

    // Bind the authorizing address to the secp256k1 public key.
    let signer = Secp256k1PubKey { x: pubkey_x, y: pubkey_y };
    let derived_address = signer.ethereum_address();
    assert(
        derived_address == authorizing_address,
        "authorizing_address != keccak(pubkey)[-20:]",
    );

    // Build the EIP-712 typed-data signing digest.
    let nonce_field = nonce_bytes_to_field(nonce);
    let signing_hash = eip712_signing_hash(
        execution_chain_id,
        pool_address,
        auth_verifier,
        authorizing_address,
        operation_kind,
        token_address,
        recipient_owner_nullifier_key_hash,
        amount,
        fee_note_recipient_owner_nullifier_key_hash,
        fee_amount,
        public_recipient_address,
        authorized_submitter,
        downstream_action_commitment,
        execution_constraints_flags,
        locked_output_binding0,
        locked_output_binding1,
        locked_output_binding2,
        policy_data_hash,
        nonce,
        valid_until_seconds,
    );

    // Low-s + ECDSA verify (Noir stdlib).
    let approval = Signature { signature };
    approval.assert_low_s(SECP256K1_HALF_ORDER_BYTES);
    approval.verify(signing_hash, signer);

    // Appendix A: authDataCommitment binds the authorizing address.
    let auth_data_commitment = eip712_auth_data_commitment(authorizing_address);

    // Public outputs.
    let blinded = blinded_auth_commitment(auth_data_commitment, blinding_factor);
    let fields_hash = transact_intent_fields_hash(IntentFields {
        pool_address,
        auth_verifier,
        authorizing_address,
        operation_kind,
        token_address,
        recipient_owner_nullifier_key_hash,
        amount,
        fee_note_recipient_owner_nullifier_key_hash,
        fee_amount,
        public_recipient_address,
        authorized_submitter,
        downstream_action_commitment,
        execution_constraints_flags,
        locked_output_binding0,
        locked_output_binding1,
        locked_output_binding2,
        nonce: nonce_field,
        valid_until_seconds,
        execution_chain_id,
    });
    let intent_digest = transaction_intent_digest(fields_hash, policy_data_hash);

    (blinded, intent_digest)
}

fn eip712_signing_hash(
    execution_chain_id: Field,
    pool_address: Field,
    auth_verifier: Field,
    authorizing_address: Field,
    operation_kind: Field,
    token_address: Field,
    recipient_owner_nullifier_key_hash: Field,
    amount: Field,
    fee_note_recipient_owner_nullifier_key_hash: Field,
    fee_amount: Field,
    public_recipient_address: Field,
    authorized_submitter: Field,
    downstream_action_commitment: Field,
    execution_constraints_flags: Field,
    locked_output_binding0: Field,
    locked_output_binding1: Field,
    locked_output_binding2: Field,
    policy_data_hash: Field,
    nonce: [u8; 32],
    valid_until_seconds: Field,
) -> [u8; 32] {
    // hashStruct(PrivateTransferIntent) = keccak(typeHash || 20 encoded fields)
    // = 32 + 20*32 = 672 bytes, Appendix A field order.
    let mut struct_preimage: [u8; 672] = [0; 672];
    write_bytes32(EIP712_INTENT_TYPE_HASH, &mut struct_preimage, 0);
    write_field_as_u256(execution_chain_id,                      &mut struct_preimage, 32);
    write_field_as_u256(pool_address,                            &mut struct_preimage, 64);
    write_field_as_u256(auth_verifier,                           &mut struct_preimage, 96);
    write_field_as_u256(authorizing_address,                     &mut struct_preimage, 128);
    write_field_as_u256(operation_kind,                          &mut struct_preimage, 160);
    write_field_as_u256(token_address,                           &mut struct_preimage, 192);
    write_field_as_u256(recipient_owner_nullifier_key_hash,      &mut struct_preimage, 224);
    write_field_as_u256(amount,                                  &mut struct_preimage, 256);
    write_field_as_u256(fee_note_recipient_owner_nullifier_key_hash, &mut struct_preimage, 288);
    write_field_as_u256(fee_amount,                              &mut struct_preimage, 320);
    write_field_as_u256(public_recipient_address,                &mut struct_preimage, 352);
    write_field_as_u256(authorized_submitter,                    &mut struct_preimage, 384);
    write_field_as_u256(downstream_action_commitment,           &mut struct_preimage, 416);
    write_field_as_u256(execution_constraints_flags,             &mut struct_preimage, 448);
    write_field_as_u256(locked_output_binding0,                  &mut struct_preimage, 480);
    write_field_as_u256(locked_output_binding1,                  &mut struct_preimage, 512);
    write_field_as_u256(locked_output_binding2,                  &mut struct_preimage, 544);
    write_field_as_u256(policy_data_hash,                        &mut struct_preimage, 576);
    write_bytes32(nonce,                                         &mut struct_preimage, 608);
    write_field_as_u256(valid_until_seconds,                     &mut struct_preimage, 640);
    let struct_hash = keccak256(struct_preimage, 672);

    // domainSeparator = keccak(typeHash || nameHash || versionHash || chainId || verifyingContract)
    // with verifyingContract = poolAddress (spec section 9 / Appendix A).
    let mut domain_preimage: [u8; 160] = [0; 160];
    write_bytes32(EIP712_DOMAIN_TYPE_HASH, &mut domain_preimage, 0);
    write_bytes32(EIP712_NAME_HASH,        &mut domain_preimage, 32);
    write_bytes32(EIP712_VERSION_HASH,     &mut domain_preimage, 64);
    write_field_as_u256(execution_chain_id, &mut domain_preimage, 96);
    write_field_as_u256(pool_address,       &mut domain_preimage, 128);
    let domain_separator = keccak256(domain_preimage, 160);

    // signing_hash = keccak("\x19\x01" || domainSeparator || hashStruct)
    let mut signing_preimage: [u8; 66] = [0; 66];
    signing_preimage[0] = 0x19;
    signing_preimage[1] = 0x01;
    for i in 0..32 {
        signing_preimage[2 + i] = domain_separator[i];
        signing_preimage[34 + i] = struct_hash[i];
    }
    keccak256(signing_preimage, 66)
}

fn write_bytes32<let N: u32>(src: [u8; 32], buf: &mut [u8; N], offset: u32) {
    for i in 0..32 {
        buf[offset + i] = src[i];
    }
}

fn write_field_as_u256<let N: u32>(value: Field, buf: &mut [u8; N], offset: u32) {
    let bytes: [u8; 32] = value.to_be_bytes();
    for i in 0..32 {
        buf[offset + i] = bytes[i];
    }
}

fn nonce_bytes_to_field(bytes: [u8; 32]) -> Field {
    assert_nonce_lt_field_modulus(bytes);
    let mut hi: [u8; 16] = [0; 16];
    let mut lo: [u8; 16] = [0; 16];
    for i in 0..16 {
        hi[i] = bytes[i];
        lo[i] = bytes[16 + i];
    }
    let hi_field = Field::from_be_bytes::<16>(hi);
    let lo_field = Field::from_be_bytes::<16>(lo);
    hi_field * U128_SHIFT + lo_field
}

fn assert_nonce_lt_field_modulus(bytes: [u8; 32]) {
    let mut is_equal_prefix = true;
    let mut is_strictly_less = false;
    for i in 0..32 {
        if is_equal_prefix {
            if bytes[i] < FIELD_MODULUS_BYTES[i] {
                is_strictly_less = true;
                is_equal_prefix = false;
            } else if bytes[i] > FIELD_MODULUS_BYTES[i] {
                is_equal_prefix = false;
            }
        }
    }
    assert(is_strictly_less, "nonce must be < field modulus");
}

#[test]
fn test_nonce_bytes_to_field_accepts_canonical_nonce() {
    let mut nonce: [u8; 32] = [0; 32];
    nonce[31] = 42;
    assert(nonce_bytes_to_field(nonce) == 42);
}

#[test(should_fail_with = "nonce must be < field modulus")]
fn test_nonce_bytes_to_field_rejects_field_modulus() {
    let _rejected = nonce_bytes_to_field(FIELD_MODULUS_BYTES);
}
