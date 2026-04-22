use keccak256::keccak256;
use privacy_pool_common::range::{
    assert_address,
    assert_amount,
    assert_valid_until,
};
use inner::{
    assert_valid_operation_kind,
    default_eip712_verifying_contract,
    InnerOutputs,
    ValidatedExecutionConstraints,
    ValidatedIntent,
};
use inner::secp256k1::Signature;
use inner::single_sig::SingleSigPolicy;

global DOMAIN_TYPE_HASH: [u8; 32] = [
    0x8b, 0x73, 0xc3, 0xc6, 0x9b, 0xb8, 0xfe, 0x3d,
    0x51, 0x2e, 0xcc, 0x4c, 0xf7, 0x59, 0xcc, 0x79,
    0x23, 0x9f, 0x7b, 0x17, 0x9b, 0x0f, 0xfa, 0xca,
    0xa9, 0xa7, 0x5d, 0x52, 0x2b, 0x39, 0x40, 0x0f,
];

global NAME_HASH: [u8; 32] = [
    0x26, 0xf1, 0xe6, 0xe2, 0x2e, 0xf2, 0x19, 0xa0,
    0x45, 0x7d, 0xca, 0x33, 0xa2, 0xaa, 0xd2, 0xad,
    0x0c, 0x5a, 0x31, 0x54, 0xd4, 0x05, 0x47, 0x4d,
    0xa5, 0xa1, 0x92, 0x86, 0x7a, 0xf1, 0x79, 0xb1,
];

global VERSION_HASH: [u8; 32] = [
    0xc8, 0x9e, 0xfd, 0xaa, 0x54, 0xc0, 0xf2, 0x0c,
    0x7a, 0xdf, 0x61, 0x28, 0x82, 0xdf, 0x09, 0x50,
    0xf5, 0xa9, 0x51, 0x63, 0x7e, 0x03, 0x07, 0xcd,
    0xcb, 0x4c, 0x67, 0x2f, 0x29, 0x8b, 0x8b, 0xc6,
];

global AUTHORIZATION_TYPE_HASH: [u8; 32] = [
    0xda, 0x45, 0x3f, 0x7b, 0x71, 0x48, 0x4c, 0x64,
    0xd8, 0x7f, 0x0d, 0x8b, 0xa6, 0x06, 0xf9, 0xd8,
    0x14, 0xfe, 0x5b, 0x30, 0xbc, 0x54, 0x49, 0xaf,
    0xcb, 0x28, 0xa0, 0x4f, 0x05, 0x29, 0xfe, 0x19,
];

global FIELD_MODULUS_BYTES: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
    0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

global U128_SHIFT: Field = 340282366920938463463374607431768211456;

struct SingleSigAuthorization {
    policy_version: Field,
    operation_kind: Field,
    token_address: Field,
    recipient_address: Field,
    amount: Field,
    fee_recipient_address: Field,
    fee_amount: Field,
    nonce: [u8; 32],
    valid_until_seconds: Field,
}

fn main(
    authorization: SingleSigAuthorization,
    single_sig_policy: SingleSigPolicy,
    approval: Signature,
    execution_chain_id: Field,
    pool_address: Field,
) -> pub InnerOutputs {
    assert_address(pool_address);
    assert(
        pool_address == default_eip712_verifying_contract(),
        "unexpected verifying contract",
    );

    let challenge = authorization_signing_hash(
        authorization,
        execution_chain_id,
        pool_address,
    );
    approval.verify(challenge, single_sig_policy.signer);

    let authorizing_address = single_sig_policy.signer.ethereum_address();
    let intent = authorization.assert_valid(authorizing_address, execution_chain_id);
    intent.finalize(single_sig_policy.authorization())
}

impl SingleSigAuthorization {
    fn assert_valid(self, authorizing_address: Field, execution_chain_id: Field) -> ValidatedIntent {
        assert_valid_operation_kind(self.operation_kind);
        assert_address(self.token_address);
        assert_address(self.recipient_address);
        assert_amount(self.amount);
        assert_address(self.fee_recipient_address);
        assert_amount(self.fee_amount);
        assert_valid_until(self.valid_until_seconds);
        assert_address(authorizing_address);

        let execution_constraints = ValidatedExecutionConstraints {
            execution_constraints_flags: 0,
            locked_output_binding0: 0,
            locked_output_binding1: 0,
            locked_output_binding2: 0,
        };

        let nonce = nonce_bytes_to_field(self.nonce);

        ValidatedIntent {
            authorizing_address,
            policy_version: self.policy_version,
            operation_kind: self.operation_kind,
            token_address: self.token_address,
            recipient_address: self.recipient_address,
            amount: self.amount,
            fee_recipient_address: self.fee_recipient_address,
            fee_amount: self.fee_amount,
            execution_constraints,
            nonce,
            valid_until_seconds: self.valid_until_seconds,
            execution_chain_id,
        }
    }
}

fn authorization_signing_hash(
    authorization: SingleSigAuthorization,
    execution_chain_id: Field,
    pool_address: Field,
) -> [u8; 32] {
    let mut struct_preimage: [u8; 320] = [0; 320];
    write_bytes32(AUTHORIZATION_TYPE_HASH, &mut struct_preimage, 0);
    write_field_as_u256(authorization.policy_version, &mut struct_preimage, 32);
    write_field_as_u256(authorization.operation_kind, &mut struct_preimage, 64);
    write_field_as_u256(authorization.token_address, &mut struct_preimage, 96);
    write_field_as_u256(authorization.recipient_address, &mut struct_preimage, 128);
    write_field_as_u256(authorization.amount, &mut struct_preimage, 160);
    write_field_as_u256(authorization.fee_recipient_address, &mut struct_preimage, 192);
    write_field_as_u256(authorization.fee_amount, &mut struct_preimage, 224);
    write_bytes32(authorization.nonce, &mut struct_preimage, 256);
    write_field_as_u256(authorization.valid_until_seconds, &mut struct_preimage, 288);
    let struct_hash = keccak256(struct_preimage, 320);

    let mut domain_preimage: [u8; 160] = [0; 160];
    write_bytes32(DOMAIN_TYPE_HASH, &mut domain_preimage, 0);
    write_bytes32(NAME_HASH, &mut domain_preimage, 32);
    write_bytes32(VERSION_HASH, &mut domain_preimage, 64);
    write_field_as_u256(execution_chain_id, &mut domain_preimage, 96);
    write_field_as_u256(pool_address, &mut domain_preimage, 128);
    let domain_separator = keccak256(domain_preimage, 160);

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
    write_bytes32(bytes, buf, offset);
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
