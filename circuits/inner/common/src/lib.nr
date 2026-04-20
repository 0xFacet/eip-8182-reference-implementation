pub mod curve_point;
pub mod field_set;
pub mod multisig;
pub mod secp256k1;
pub mod single_sig;
use keccak256::keccak256;
use privacy_pool_common::constants::{
    LOCK_OUTPUT_BINDING_0,
    LOCK_OUTPUT_BINDING_1,
    LOCK_OUTPUT_BINDING_2,
    PRIVACY_POOL_ADDRESS,
    TRANSFER_OP,
    WITHDRAWAL_OP,
};
use privacy_pool_common::digest::transaction_intent_digest as common_transaction_intent_digest;
use privacy_pool_common::hash_utils::p_hash2;
use privacy_pool_common::range::{
    assert_address,
    assert_amount,
    assert_execution_constraints_flags,
    assert_origin_mode,
    assert_valid_until,
};

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

global EIP712_TYPE_HASH: [u8; 32] = [
    0x79, 0xfe, 0xac, 0x89, 0x9a, 0xf7, 0x27, 0x97,
    0x41, 0xdf, 0x55, 0x6d, 0x4c, 0x1f, 0x43, 0x26,
    0x78, 0x70, 0xaf, 0x5c, 0x8c, 0x06, 0x33, 0xde,
    0xc1, 0xf7, 0xe3, 0x68, 0x1d, 0xf5, 0xa6, 0xb3,
];

pub struct Authorization {
    pub auth_data_commitment: Field,
}

pub struct Eip712Context {
    pub auth_domain_tag: Field,
    pub verifying_contract: Field,
}

pub struct SigningHash {
    pub bytes: [u8; 32],
}

pub struct InnerOutputs {
    pub auth_data_commitment: Field,
    pub transaction_intent_digest: Field,
}

pub struct ExecutionConstraints {
    pub execution_constraints_flags: Field,
    pub locked_output_binding0: Field,
    pub locked_output_binding1: Field,
    pub locked_output_binding2: Field,
}

pub struct ValidatedExecutionConstraints {
    pub execution_constraints_flags: Field,
    pub locked_output_binding0: Field,
    pub locked_output_binding1: Field,
    pub locked_output_binding2: Field,
}

pub struct Intent {
    pub authorizing_address: Field,
    pub policy_version: Field,
    pub operation_kind: Field,
    pub token_address: Field,
    pub recipient_address: Field,
    pub amount: Field,
    pub fee_recipient_address: Field,
    pub fee_amount: Field,
    pub origin_mode: Field,
    pub execution_constraints: ExecutionConstraints,
    pub nonce: Field,
    pub valid_until_seconds: Field,
    pub execution_chain_id: Field,
}

pub struct ValidatedIntent {
    pub authorizing_address: Field,
    pub policy_version: Field,
    pub operation_kind: Field,
    pub token_address: Field,
    pub recipient_address: Field,
    pub amount: Field,
    pub fee_recipient_address: Field,
    pub fee_amount: Field,
    pub origin_mode: Field,
    pub execution_constraints: ValidatedExecutionConstraints,
    pub nonce: Field,
    pub valid_until_seconds: Field,
    pub execution_chain_id: Field,
}

impl Intent {
    pub fn assert_valid(self) -> ValidatedIntent {
        assert_address(self.authorizing_address);
        assert_valid_operation_kind(self.operation_kind);
        assert_address(self.token_address);
        assert_address(self.recipient_address);
        assert_amount(self.amount);
        assert_address(self.fee_recipient_address);
        assert_amount(self.fee_amount);
        assert_origin_mode(self.origin_mode);
        assert_valid_until(self.valid_until_seconds);
        let execution_constraints = self.execution_constraints.assert_valid();
        ValidatedIntent {
            authorizing_address: self.authorizing_address,
            policy_version: self.policy_version,
            operation_kind: self.operation_kind,
            token_address: self.token_address,
            recipient_address: self.recipient_address,
            amount: self.amount,
            fee_recipient_address: self.fee_recipient_address,
            fee_amount: self.fee_amount,
            origin_mode: self.origin_mode,
            execution_constraints,
            nonce: self.nonce,
            valid_until_seconds: self.valid_until_seconds,
            execution_chain_id: self.execution_chain_id,
        }
    }
}

impl ExecutionConstraints {
    pub fn assert_valid(self) -> ValidatedExecutionConstraints {
        assert_execution_constraints_flags(self.execution_constraints_flags);
        self.execution_constraints_flags.assert_max_bit_size::<3>();
        assert_zero_when_unlocked(
            self.execution_constraints_flags,
            LOCK_OUTPUT_BINDING_0,
            self.locked_output_binding0,
        );
        assert_zero_when_unlocked(
            self.execution_constraints_flags,
            LOCK_OUTPUT_BINDING_1,
            self.locked_output_binding1,
        );
        assert_zero_when_unlocked(
            self.execution_constraints_flags,
            LOCK_OUTPUT_BINDING_2,
            self.locked_output_binding2,
        );
        ValidatedExecutionConstraints {
            execution_constraints_flags: self.execution_constraints_flags,
            locked_output_binding0: self.locked_output_binding0,
            locked_output_binding1: self.locked_output_binding1,
            locked_output_binding2: self.locked_output_binding2,
        }
    }
}

impl ValidatedIntent {
    pub fn finalize(self, authorization: Authorization) -> InnerOutputs {
        InnerOutputs {
            auth_data_commitment: authorization.auth_data_commitment,
            transaction_intent_digest: self.transaction_intent_digest(),
        }
    }

    pub fn signing_hash(self, context: Eip712Context) -> SigningHash {
        SigningHash {
            bytes: self.eip712_signing_hash(context),
        }
    }

    pub fn eip712_signing_hash(
        self,
        context: Eip712Context,
    ) -> [u8; 32] {
        let intent = self;
        let execution_constraints = intent.execution_constraints;
        assert_address(context.verifying_contract);

        let mut struct_preimage: [u8; 544] = [0; 544];
        write_bytes32(EIP712_TYPE_HASH, &mut struct_preimage, 0);
        write_field_as_u256(intent.authorizing_address, &mut struct_preimage, 32);
        write_field_as_u256(intent.policy_version, &mut struct_preimage, 64);
        write_field_as_u256(context.auth_domain_tag, &mut struct_preimage, 96);
        write_field_as_u256(intent.operation_kind, &mut struct_preimage, 128);
        write_field_as_u256(intent.token_address, &mut struct_preimage, 160);
        write_field_as_u256(intent.recipient_address, &mut struct_preimage, 192);
        write_field_as_u256(intent.amount, &mut struct_preimage, 224);
        write_field_as_u256(intent.fee_recipient_address, &mut struct_preimage, 256);
        write_field_as_u256(intent.fee_amount, &mut struct_preimage, 288);
        write_field_as_u256(intent.origin_mode, &mut struct_preimage, 320);
        write_field_as_u256(intent.nonce, &mut struct_preimage, 352);
        write_field_as_u256(intent.valid_until_seconds, &mut struct_preimage, 384);
        write_field_as_u256(
            execution_constraints.execution_constraints_flags,
            &mut struct_preimage,
            416,
        );
        write_field_as_u256(
            execution_constraints.locked_output_binding0,
            &mut struct_preimage,
            448,
        );
        write_field_as_u256(
            execution_constraints.locked_output_binding1,
            &mut struct_preimage,
            480,
        );
        write_field_as_u256(
            execution_constraints.locked_output_binding2,
            &mut struct_preimage,
            512,
        );
        let struct_hash = keccak256(struct_preimage, 544);

        let mut domain_preimage: [u8; 160] = [0; 160];
        write_bytes32(DOMAIN_TYPE_HASH, &mut domain_preimage, 0);
        write_bytes32(NAME_HASH, &mut domain_preimage, 32);
        write_bytes32(VERSION_HASH, &mut domain_preimage, 64);
        write_field_as_u256(intent.execution_chain_id, &mut domain_preimage, 96);
        write_field_as_u256(context.verifying_contract, &mut domain_preimage, 128);
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

    pub fn transaction_intent_digest(self) -> Field {
        let intent = self;
        let execution_constraints = intent.execution_constraints;
        common_transaction_intent_digest(
            intent.policy_version,
            intent.authorizing_address,
            intent.operation_kind,
            intent.token_address,
            intent.recipient_address,
            intent.amount,
            intent.fee_recipient_address,
            intent.fee_amount,
            intent.origin_mode,
            execution_constraints.execution_constraints_flags,
            execution_constraints.locked_output_binding0,
            execution_constraints.locked_output_binding1,
            execution_constraints.locked_output_binding2,
            intent.nonce,
            intent.valid_until_seconds,
            intent.execution_chain_id,
        )
    }
}

pub fn default_eip712_verifying_contract() -> Field {
    PRIVACY_POOL_ADDRESS
}

pub fn eip712_context(auth_domain_tag: Field, verifying_contract: Field) -> Eip712Context {
    assert_address(verifying_contract);
    Eip712Context { auth_domain_tag, verifying_contract }
}

pub fn assert_all_distinct<let N: u32>(values: [u32; N]) {
    for i in 0..N {
        for j in 0..N {
            if j < i {
                assert(values[i] != values[j], "duplicate value");
            }
        }
    }
}

pub fn fold_fields<let N: u32>(seed: Field, fields: [Field; N]) -> Field {
    let mut acc = seed;
    for i in 0..N {
        acc = p_hash2([acc, fields[i]]);
    }
    acc
}

pub fn assert_valid_operation_kind(operation_kind: Field) {
    assert(
        (operation_kind - TRANSFER_OP) * (operation_kind - WITHDRAWAL_OP) == 0,
        "invalid operation kind",
    );
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

fn assert_zero_when_unlocked(constraint_flags: Field, bit: Field, value: Field) {
    if !is_flag_set(constraint_flags, bit) {
        assert(value == 0, "unlocked output binding must be zero");
    }
}

fn is_flag_set(constraint_flags: Field, bit: Field) -> bool {
    if bit == LOCK_OUTPUT_BINDING_0 {
        if constraint_flags == 1 {
            true
        } else if constraint_flags == 3 {
            true
        } else if constraint_flags == 5 {
            true
        } else {
            constraint_flags == 7
        }
    } else if bit == LOCK_OUTPUT_BINDING_1 {
        if constraint_flags == 2 {
            true
        } else if constraint_flags == 3 {
            true
        } else if constraint_flags == 6 {
            true
        } else {
            constraint_flags == 7
        }
    } else {
        if constraint_flags == 4 {
            true
        } else if constraint_flags == 5 {
            true
        } else if constraint_flags == 6 {
            true
        } else {
            constraint_flags == 7
        }
    }
}

fn sample_validated_intent(origin_mode: Field) -> ValidatedIntent {
    Intent {
        authorizing_address: 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf,
        policy_version: 1,
        operation_kind: TRANSFER_OP,
        token_address: 0,
        recipient_address: 0x1000000000000000000000000000000000000001,
        amount: 1000,
        fee_recipient_address: 0,
        fee_amount: 0,
        origin_mode: origin_mode,
        execution_constraints: ExecutionConstraints {
            execution_constraints_flags: 0,
            locked_output_binding0: 0,
            locked_output_binding1: 0,
            locked_output_binding2: 0,
        },
        nonce: 42,
        valid_until_seconds: 3600,
        execution_chain_id: 31337,
    }.assert_valid()
}

#[test]
fn test_transaction_intent_digest_changes_with_origin_mode() {
    let digest0 = sample_validated_intent(0).transaction_intent_digest();
    let digest1 = sample_validated_intent(1).transaction_intent_digest();
    assert(digest0 != digest1);
}

#[test]
fn test_eip712_signing_hash_changes_with_origin_mode() {
    let hash0 = sample_validated_intent(0).eip712_signing_hash(
        eip712_context(0x73696e676c655f61757468, default_eip712_verifying_contract()),
    );
    let hash1 = sample_validated_intent(1).eip712_signing_hash(
        eip712_context(0x73696e676c655f61757468, default_eip712_verifying_contract()),
    );

    let mut differs = false;
    for i in 0..32 {
        if hash0[i] != hash1[i] {
            differs = true;
        }
    }
    assert(differs);
}

#[test]
fn test_eip712_signing_hash_matches_expected_sample() {
    let actual = sample_validated_intent(0).eip712_signing_hash(
        eip712_context(0x73696e676c655f61757468, default_eip712_verifying_contract()),
    );
    let expected: [u8; 32] = [
        0x11, 0xa4, 0x08, 0xe6, 0x73, 0x2d, 0xf6, 0xe2,
        0x8d, 0xed, 0x79, 0x9c, 0x5c, 0xb8, 0xd8, 0x5f,
        0x8e, 0xd7, 0xbc, 0x90, 0x10, 0xbb, 0x5d, 0xa7,
        0x38, 0xed, 0xaa, 0x0b, 0x64, 0xf9, 0x10, 0xa5,
    ];

    for i in 0..32 {
        assert(actual[i] == expected[i], "unexpected eip712 signing hash");
    }
}

#[test]
fn test_transaction_intent_digest_changes_with_execution_constraints() {
    let digest0 = sample_validated_intent(0).transaction_intent_digest();
    let digest1 = Intent {
        authorizing_address: 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf,
        policy_version: 1,
        operation_kind: TRANSFER_OP,
        token_address: 0,
        recipient_address: 0x1000000000000000000000000000000000000001,
        amount: 1000,
        fee_recipient_address: 0,
        fee_amount: 0,
        origin_mode: 0,
        execution_constraints: ExecutionConstraints {
            execution_constraints_flags: LOCK_OUTPUT_BINDING_0,
            locked_output_binding0: 0x1234,
            locked_output_binding1: 0,
            locked_output_binding2: 0,
        },
        nonce: 42,
        valid_until_seconds: 3600,
        execution_chain_id: 31337,
    }.assert_valid().transaction_intent_digest();
    assert(digest0 != digest1);
}
