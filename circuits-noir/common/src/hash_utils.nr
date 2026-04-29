use poseidon::poseidon2::Poseidon2;

// Poseidon2 sponge wrappers. Every `poseidon(...)` expression in the spec
// resolves to a single Poseidon2 sponge call with capacity IV = (N << 64).
// The 2-input form is the length-tagged sponge (NOT the bare permutation) and
// is used as the Merkle tree internal hash.

pub fn merkle_hash2(input: [Field; 2]) -> Field {
    Poseidon2::hash(input, 2)
}

pub fn p_hash2(input: [Field; 2]) -> Field {
    Poseidon2::hash(input, 2)
}

pub fn p_hash3(input: [Field; 3]) -> Field {
    Poseidon2::hash(input, 3)
}

pub fn p_hash4(input: [Field; 4]) -> Field {
    Poseidon2::hash(input, 4)
}

pub fn p_hash5(input: [Field; 5]) -> Field {
    Poseidon2::hash(input, 5)
}

pub fn p_hash16(input: [Field; 16]) -> Field {
    Poseidon2::hash(input, 16)
}
