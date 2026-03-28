use crate::constants::{AUTH_POLICY_TREE_DEPTH, COMMITMENT_TREE_DEPTH, USER_TREE_DEPTH};
use crate::hash_utils::merkle_hash2;

pub fn merkle_root_from_index(leaf: Field, leaf_index: u32, siblings: [Field; COMMITMENT_TREE_DEPTH]) -> Field {
    // LSB-first to match the contract's incremental tree: (idx >> i) & 1
    let bits: [u1; COMMITMENT_TREE_DEPTH] = (leaf_index as Field).to_le_bits();
    binary_root_from_bits(leaf, bits, siblings)
}

pub fn user_sparse_root(address_key: Field, leaf: Field, siblings: [Field; USER_TREE_DEPTH]) -> Field {
    let full_bits: [u1; 254] = address_key.to_le_bits();
    let mut bits: [u1; USER_TREE_DEPTH] = [0; USER_TREE_DEPTH];
    for i in 0..USER_TREE_DEPTH {
        bits[i] = full_bits[i];
    }
    binary_root_from_bits(leaf, bits, siblings)
}

pub fn auth_sparse_root(field_key: Field, leaf: Field, siblings: [Field; AUTH_POLICY_TREE_DEPTH]) -> Field {
    // field_key is a full Poseidon hash (~254 bits). Truncate to low 160 bits
    // to match the contract's uint160() truncation (per spec Section 3.4).
    let full_bits: [u1; 254] = field_key.to_le_bits();
    let mut bits: [u1; AUTH_POLICY_TREE_DEPTH] = [0; AUTH_POLICY_TREE_DEPTH];
    for i in 0..AUTH_POLICY_TREE_DEPTH {
        bits[i] = full_bits[i];
    }
    binary_root_from_bits(leaf, bits, siblings)
}

pub fn binary_root_from_bits<let DEPTH: u32>(leaf: Field, bits: [u1; DEPTH], siblings: [Field; DEPTH]) -> Field {
    let mut acc = leaf;
    for i in 0..DEPTH {
        if bits[i] == 0 {
            acc = merkle_hash2([acc, siblings[i]]);
        } else {
            acc = merkle_hash2([siblings[i], acc]);
        }
    }
    acc
}

#[test]
fn test_user_sparse_root_uses_leaf_up_bits() {
    let leaf = 0x123;
    let mut siblings: [Field; USER_TREE_DEPTH] = [0; USER_TREE_DEPTH];
    for i in 0..USER_TREE_DEPTH {
        siblings[i] = (i + 1) as Field;
    }

    let mut expected_bits: [u1; USER_TREE_DEPTH] = [0; USER_TREE_DEPTH];
    expected_bits[0] = 1;
    expected_bits[2] = 1; // 0b101

    let mut reversed_bits: [u1; USER_TREE_DEPTH] = [0; USER_TREE_DEPTH];
    reversed_bits[USER_TREE_DEPTH - 1] = 1;
    reversed_bits[USER_TREE_DEPTH - 3] = 1;

    let actual = user_sparse_root(0x5, leaf, siblings);
    let expected = binary_root_from_bits(leaf, expected_bits, siblings);
    let reversed = binary_root_from_bits(leaf, reversed_bits, siblings);
    assert(actual == expected);
    assert(actual != reversed);
}

#[test]
fn test_auth_sparse_root_uses_low_160_bits_leaf_up() {
    let leaf = 0x456;
    let mut siblings: [Field; AUTH_POLICY_TREE_DEPTH] = [0; AUTH_POLICY_TREE_DEPTH];
    for i in 0..AUTH_POLICY_TREE_DEPTH {
        siblings[i] = (i + 11) as Field;
    }

    let mut expected_bits: [u1; AUTH_POLICY_TREE_DEPTH] = [0; AUTH_POLICY_TREE_DEPTH];
    expected_bits[0] = 1;
    expected_bits[2] = 1; // low 160 bits of 0b101

    let mut reversed_bits: [u1; AUTH_POLICY_TREE_DEPTH] = [0; AUTH_POLICY_TREE_DEPTH];
    reversed_bits[AUTH_POLICY_TREE_DEPTH - 1] = 1;
    reversed_bits[AUTH_POLICY_TREE_DEPTH - 3] = 1;

    let actual = auth_sparse_root(0x5, leaf, siblings);
    let expected = binary_root_from_bits(leaf, expected_bits, siblings);
    let reversed = binary_root_from_bits(leaf, reversed_bits, siblings);
    assert(actual == expected);
    assert(actual != reversed);
}
