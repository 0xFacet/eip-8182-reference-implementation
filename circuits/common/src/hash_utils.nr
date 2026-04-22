use poseidon::poseidon2::Poseidon2;
use crate::constants::AUTH_VK_DOMAIN;

// --------------------------------------------------------------------------
// Poseidon2 sponge wrappers.
//
// Every `poseidon(...)` expression in the spec resolves to a single
// Poseidon2 sponge call with capacity IV = (N << 64). The 2-input form is
// the length-tagged sponge (NOT the bare permutation) and is used as the
// Merkle tree internal hash.
// --------------------------------------------------------------------------

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

// --------------------------------------------------------------------------
// Inner VK hash.
//
// innerVkHash = poseidon(AUTH_VK_DOMAIN, vk[0], vk[1], ..., vk[114])
//
// A single 116-input Poseidon2 sponge call over the concatenation of the
// domain tag and the 115 VK field elements. ceil(116/3) = 39 permutations,
// replacing the 116 Poseidon1 permutations required by the prior tree
// construction.
// --------------------------------------------------------------------------

pub fn hash_vk(inner_vk: [Field; 115]) -> Field {
    let mut buf: [Field; 116] = [0; 116];
    buf[0] = AUTH_VK_DOMAIN;
    for i in 0..115 {
        buf[i + 1] = inner_vk[i];
    }
    Poseidon2::hash(buf, 116)
}
