use crate::hash_utils::p_hash4;

pub fn secp256k1_auth_commitment(pub_key_x: [u8; 32], pub_key_y: [u8; 32]) -> Field {
    let (x_hi, x_lo) = split_bytes32(pub_key_x);
    let (y_hi, y_lo) = split_bytes32(pub_key_y);
    p_hash4([x_hi, x_lo, y_hi, y_lo])
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
