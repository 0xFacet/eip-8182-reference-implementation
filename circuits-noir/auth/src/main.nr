// Realistic EIP-712 / ECDSA-secp256k1 auth circuit for EIP-8182.
//
// Public outputs (per Section 8.1):
//   blinded_auth_commitment, transaction_intent_digest
//
// Adapted from the recursive-era auth circuit at commit 71e7d72. This Sepolia
// demo variant is transfer-only and assumes the user proves locally in the
// browser. The EIP-712 signature binds only the fields the wallet must approve:
// verifier, signer, token, private recipient owner hash, amount, nonce, and
// expiry. Mode fields, public withdrawal recipient, fee fields, output locks,
// and `blindingFactor` are not signed; the digest below supplies transfer/zero
// constants and keeps `blindingFactor` as a private witness.
//
// Other adaptations vs that historical version:
//   - 2-field public output `(blinded_auth_commitment, transaction_intent_digest)`
//     instead of the historical recursive `InnerOutputs`.
//   - In-circuit blinding step: blinded = poseidon(BLINDED_AUTH_COMMITMENT_DOMAIN,
//     auth_data_commitment, blinding_factor). The historical recursive design
//     left blinding to the outer wrapper proof; we don't have one.
//
// Section 8.1 item 1 binding (`intent.authVerifier == address(this)`).
//
// This circuit does NOT directly assert `auth_verifier == address(this)`.
// The binding to the calling verifier address is enforced by a chain of
// constraints, not a single in-circuit equality. Spelled out so the chain
// is auditable:
//
//  1. The user's ECDSA signature is computed over an EIP-712 typed-data
//     hash whose struct preimage's first 32-byte field is `authVerifier`
//     (see `eip712_signing_hash` below). The signature thus binds the
//     user's authorization to a specific signed value `V_signed`.
//  2. Inside the circuit, the same `auth_verifier_witness` used in the
//     EIP-712 hash is also used to compute
//     `transactionIntentDigest = poseidon(..., auth_verifier_witness, ...)`.
//     If the witness disagrees with `V_signed`, the ECDSA check fails.
//     So the public output's intent digest commits to `V_signed`.
//  3. The pool circuit's intent-digest formula (Section 8.9) takes
//     `authVerifier` from the pool proof's public inputs. The system
//     contract dispatches `IAuthVerifier.verifyAuth` to
//     `address(uint160(publicInputs.authVerifier))`, so the calling
//     contract's address is precisely that public-input value `V_pool`.
//  4. The system contract requires the auth proof's `transactionIntentDigest`
//     to equal the pool proof's `transactionIntentDigest`. This forces
//     `V_signed == V_pool`, i.e. the user signed for the verifier that's
//     actually verifying the proof.
//
// Cross-proof coupling alone (step 4 without step 1) would NOT be a binding;
// step 1 is what ties the verifier-address slot in the digest to a value
// the user actually authorized. Without `authVerifier` in the EIP-712
// struct, a delegated prover with the same signed credential could route
// it through a different verifier with different semantics. The seven-field
// `INTENT_TYPE_HASH` below puts `authVerifier` in slot 0 of the struct;
// removing it would break the binding.
//
// This is one valid mechanism per the spec ("Companion standards define
// how a verifier binds its own address"). Two alternatives that this
// circuit does NOT take:
//   - Bake the verifier address into the circuit at compile time (a
//     deployment-specific VK). Sound but requires per-deployment circuit
//     compilation.
//   - Change the `IAuthVerifier` ABI to carry raw intent fields and have
//     the wrapper recompute the digest with `address(this)` as the
//     verifier field. Sound but requires a protocol-level ABI change;
//     can't be done by a companion ERC alone.

mod secp256k1;
mod single_sig;
mod curve_point;

// Wrapper used by `SingleSigPolicy::authorization()` (recovered from 71e7d72
// circuits/inner/common/src/lib.nr -- the historical recursive design
// returned it as part of `InnerOutputs`; we just unwrap it here for the
// blinded auth commitment).
pub struct Authorization {
    pub auth_data_commitment: Field,
}

use keccak256::keccak256;
use privacy_pool_common::constants::{PRIVACY_POOL_ADDRESS, TRANSFER_OP};
use privacy_pool_common::digest::{blinded_auth_commitment, transaction_intent_digest};
use privacy_pool_common::range::{assert_address, assert_amount, assert_valid_until};
use crate::secp256k1::{Secp256k1PubKey, Signature};
use crate::single_sig::SingleSigPolicy;

// -- EIP-712 type hashes (computed by scripts/noir/eip712_typehash_compute.js) --

// keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
pub global DOMAIN_TYPE_HASH: [u8; 32] = [
    0x8b, 0x73, 0xc3, 0xc6, 0x9b, 0xb8, 0xfe, 0x3d,
    0x51, 0x2e, 0xcc, 0x4c, 0xf7, 0x59, 0xcc, 0x79,
    0x23, 0x9f, 0x7b, 0x17, 0x9b, 0x0f, 0xfa, 0xca,
    0xa9, 0xa7, 0x5d, 0x52, 0x2b, 0x39, 0x40, 0x0f,
];

// keccak256("EIP-8182 Auth")
pub global NAME_HASH: [u8; 32] = [
    0xb5, 0x38, 0xfe, 0xc1, 0x15, 0xcd, 0x6d, 0x79,
    0xee, 0xc0, 0xa7, 0x03, 0x56, 0x37, 0xb6, 0xab,
    0x51, 0x66, 0xb3, 0x46, 0x27, 0xe9, 0xa6, 0xd9,
    0x96, 0xcd, 0x23, 0x2c, 0x79, 0xd1, 0x77, 0x2a,
];

// keccak256("1")
pub global VERSION_HASH: [u8; 32] = [
    0xc8, 0x9e, 0xfd, 0xaa, 0x54, 0xc0, 0xf2, 0x0c,
    0x7a, 0xdf, 0x61, 0x28, 0x82, 0xdf, 0x09, 0x50,
    0xf5, 0xa9, 0x51, 0x63, 0x7e, 0x03, 0x07, 0xcd,
    0xcb, 0x4c, 0x67, 0x2f, 0x29, 0x8b, 0x8b, 0xc6,
];

// keccak256("TransactionIntent(address authVerifier,address authorizingAddress,address tokenAddress,uint256 recipientOwnerNullifierKeyHash,uint256 amount,bytes32 nonce,uint256 validUntilSeconds)")
pub global INTENT_TYPE_HASH: [u8; 32] = [
    0x29, 0xa3, 0xd4, 0x50, 0x48, 0x8d, 0x8d, 0x08,
    0x41, 0x00, 0x11, 0xca, 0x11, 0x9c, 0x05, 0x65,
    0x4e, 0x77, 0x16, 0xb6, 0x4e, 0x57, 0xc5, 0x4f,
    0x34, 0x52, 0xcb, 0xc4, 0xb0, 0x8c, 0x1d, 0x8c,
];

global FIELD_MODULUS_BYTES: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
    0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

global U128_SHIFT: Field = 340282366920938463463374607431768211456;

fn main(
    // Signed transfer intent fields (private; bound by the EIP-712 signature).
    auth_verifier: Field,
    authorizing_address: Field,
    token_address: Field,
    recipient_owner_nullifier_key_hash: Field,
    amount: Field,
    nonce: [u8; 32],
    valid_until_seconds: Field,
    execution_chain_id: Field,
    // credential
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    signature: [u8; 64],
    blinding_factor: Field,
) -> pub (Field, Field) {
    // Range checks on bounded semantic types. recipient_owner_nullifier_key_hash
    // is a field element (Poseidon output), not an address, so no 160-bit range
    // check applies.
    assert_address(auth_verifier);
    assert_address(authorizing_address);
    assert_address(token_address);
    assert_amount(amount);
    assert_valid_until(valid_until_seconds);

    // Bind the authorizing address to the secp256k1 public key.
    let signer = Secp256k1PubKey { x: pubkey_x, y: pubkey_y };
    let derived_address = signer.ethereum_address();
    assert(
        derived_address == authorizing_address,
        "authorizing_address != keccak(pubkey)[-20:]",
    );

    // Build the EIP-712 typed-data signing digest (3 keccak invocations).
    let nonce_field = nonce_bytes_to_field(nonce);
    let signing_hash = eip712_signing_hash(
        auth_verifier,
        authorizing_address,
        token_address,
        recipient_owner_nullifier_key_hash,
        amount,
        nonce,
        valid_until_seconds,
        execution_chain_id,
    );

    // ECDSA verify (Noir stdlib).
    let approval = Signature { signature };
    approval.verify(signing_hash, signer);

    // Auth-data commitment (4-input poseidon over pubkey halves; matches
    // privacy_pool_common::crypto::secp256k1_auth_commitment from 71e7d72).
    let policy = SingleSigPolicy { signer };
    let auth_data_commitment = policy.authorization().auth_data_commitment;

    // Public outputs.
    let blinded = blinded_auth_commitment(auth_data_commitment, blinding_factor);
    let intent_digest = transaction_intent_digest(
        auth_verifier,
        authorizing_address,
        TRANSFER_OP,
        token_address,
        recipient_owner_nullifier_key_hash,
        amount,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        nonce_field,
        valid_until_seconds,
        execution_chain_id,
    );

    (blinded, intent_digest)
}

fn eip712_signing_hash(
    auth_verifier: Field,
    authorizing_address: Field,
    token_address: Field,
    recipient_owner_nullifier_key_hash: Field,
    amount: Field,
    nonce: [u8; 32],
    valid_until_seconds: Field,
    execution_chain_id: Field,
) -> [u8; 32] {
    // hashStruct(TransactionIntent) = keccak(typeHash || encoded fields).
    // 7 fields x 32 bytes + 32 bytes typehash = 256 bytes.
    let mut struct_preimage: [u8; 256] = [0; 256];
    write_bytes32(INTENT_TYPE_HASH, &mut struct_preimage, 0);
    write_field_as_u256(auth_verifier,                                 &mut struct_preimage, 32);
    write_field_as_u256(authorizing_address,                           &mut struct_preimage, 64);
    write_field_as_u256(token_address,                                 &mut struct_preimage, 96);
    write_field_as_u256(recipient_owner_nullifier_key_hash,            &mut struct_preimage, 128);
    write_field_as_u256(amount,                                        &mut struct_preimage, 160);
    write_bytes32(nonce,                                               &mut struct_preimage, 192);
    write_field_as_u256(valid_until_seconds,                           &mut struct_preimage, 224);
    let struct_hash = keccak256(struct_preimage, 256);

    // domainSeparator = keccak(typeHash || nameHash || versionHash || chainId || verifyingContract).
    let mut domain_preimage: [u8; 160] = [0; 160];
    write_bytes32(DOMAIN_TYPE_HASH, &mut domain_preimage, 0);
    write_bytes32(NAME_HASH,        &mut domain_preimage, 32);
    write_bytes32(VERSION_HASH,     &mut domain_preimage, 64);
    write_field_as_u256(execution_chain_id, &mut domain_preimage, 96);
    write_field_as_u256(PRIVACY_POOL_ADDRESS, &mut domain_preimage, 128);
    let domain_separator = keccak256(domain_preimage, 160);

    // signing_hash = keccak("\x19\x01" || domainSeparator || hashStruct).
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
