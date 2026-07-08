use crate::constants::EIP712_AUTH_DATA_DOMAIN;
use crate::hash_utils::p_hash2;

// Appendix A reference auth profile: the registered auth data binds the
// authorizing Ethereum address, not the public key.
//   authDataCommitment = poseidon(EIP712_AUTH_DATA_DOMAIN, uint160(authorizingAddress))
pub fn eip712_auth_data_commitment(authorizing_address: Field) -> Field {
    p_hash2([EIP712_AUTH_DATA_DOMAIN, authorizing_address])
}

pub fn split_bytes32(bytes: [u8; 32]) -> (Field, Field) {
    let mut hi: [u8; 16] = [0; 16];
    let mut lo: [u8; 16] = [0; 16];
    for i in 0..16 {
        hi[i] = bytes[i];
        lo[i] = bytes[16 + i];
    }
    (Field::from_be_bytes::<16>(hi), Field::from_be_bytes::<16>(lo))
}
