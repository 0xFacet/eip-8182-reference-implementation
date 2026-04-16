use crate::hash_utils::{p_hash3, p_hash4};
use crate::constants::{AUTH_POLICY_DOMAIN, AUTH_POLICY_KEY_DOMAIN, USER_REGISTRY_LEAF_DOMAIN};
use crate::merkle::{auth_sparse_root, user_sparse_root};
use crate::types::{
    AuthPolicyLeaf,
    AuthPolicyWitness,
    UserRegistryWitness,
    UserRegistryLeaf,
};

pub fn user_registry_leaf_hash(address_key: Field, leaf: UserRegistryLeaf) -> Field {
    p_hash4([
        USER_REGISTRY_LEAF_DOMAIN,
        address_key,
        leaf.owner_nullifier_key_hash,
        leaf.note_secret_seed_hash,
    ])
}

pub fn auth_policy_leaf_hash(leaf: AuthPolicyLeaf) -> Field {
    p_hash3([AUTH_POLICY_DOMAIN, leaf.auth_data_commitment, leaf.policy_version])
}

pub fn auth_policy_key(authorizing_address: Field, inner_vk_hash: Field) -> Field {
    p_hash3([AUTH_POLICY_KEY_DOMAIN, authorizing_address, inner_vk_hash])
}

#[test]
fn test_user_registry_leaf_hash_deterministic() {
    let leaf = UserRegistryLeaf {
        owner_nullifier_key_hash: 0xaaaa,
        note_secret_seed_hash: 0xbbbb,
    };
    let h1 = user_registry_leaf_hash(0x1234, leaf);
    let h2 = user_registry_leaf_hash(0x1234, leaf);
    assert(h1 == h2);
    assert(h1 != 0);
}

#[test]
fn test_different_address_different_leaf() {
    let leaf = UserRegistryLeaf {
        owner_nullifier_key_hash: 0xaaaa,
        note_secret_seed_hash: 0xbbbb,
    };
    let h1 = user_registry_leaf_hash(0x1234, leaf);
    let h2 = user_registry_leaf_hash(0x5678, leaf);
    assert(h1 != h2);
}

#[test]
fn test_auth_policy_key_deterministic() {
    let k1 = auth_policy_key(0xabc, 0xdef);
    let k2 = auth_policy_key(0xabc, 0xdef);
    assert(k1 == k2);
    assert(k1 != 0);
}

#[test]
fn test_auth_policy_leaf_hash_deterministic() {
    let leaf = AuthPolicyLeaf { auth_data_commitment: 0x1111, policy_version: 1 };
    let h1 = auth_policy_leaf_hash(leaf);
    let h2 = auth_policy_leaf_hash(leaf);
    assert(h1 == h2);
    assert(h1 != 0);
}

pub fn user_registry_membership_root(
    address_key: Field,
    leaf: UserRegistryLeaf,
    witness: UserRegistryWitness,
) -> Field {
    user_sparse_root(address_key, user_registry_leaf_hash(address_key, leaf), witness.siblings)
}

pub fn auth_membership_root(authorizing_address: Field, inner_vk_hash: Field, leaf: AuthPolicyLeaf, witness: AuthPolicyWitness) -> Field {
    let key = auth_policy_key(authorizing_address, inner_vk_hash);
    auth_sparse_root(key, auth_policy_leaf_hash(leaf), witness.siblings)
}
