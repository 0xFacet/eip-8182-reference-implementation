use privacy_pool_common::crypto::secp256k1_auth_commitment;

pub fn xy_auth_commitment(x: [u8; 32], y: [u8; 32]) -> Field {
    secp256k1_auth_commitment(x, y)
}
