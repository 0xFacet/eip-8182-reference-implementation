use crate::constants::{AUTH_POLICY_TREE_DEPTH, COMMITMENT_TREE_DEPTH, USER_TREE_DEPTH};

pub struct Note {
    pub amount: Field,
    pub note_secret: Field,
    pub owner_nullifier_key_hash: Field,
    pub token_address: Field,
}

pub struct UserRegistryLeaf {
    pub owner_nullifier_key_hash: Field,
    pub note_secret_seed_hash: Field,
}

pub struct AuthPolicyLeaf {
    pub auth_data_commitment: Field,
    pub policy_version: Field,
}

pub struct InputNoteWitness {
    pub is_phantom: bool,
    pub leaf_index: u32,
    pub note: Note,
    pub siblings: [Field; COMMITMENT_TREE_DEPTH],
}

pub struct UserRegistryWitness {
    pub siblings: [Field; USER_TREE_DEPTH],
}

pub struct AuthPolicyWitness {
    pub siblings: [Field; AUTH_POLICY_TREE_DEPTH],
}
