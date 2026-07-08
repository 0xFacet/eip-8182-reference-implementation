use super::keccak256;

#[oracle(getKeccak256)]
unconstrained fn keccak256_hash_oracle(input: [u8], message_size: u32) -> [u8; 32] {}

#[test]
unconstrained fn test_keccak256_1(input: [u8; 1], len: u32) {
    // Constrain len to be valid for the array size
    let actual_len = len % 2;
    let result = keccak256(input, actual_len);
    let expected = keccak256_hash_oracle(input, actual_len);
    assert_eq(result, expected);
}

#[test]
unconstrained fn test_keccak256_100(input: [u8; 100], len: u32) {
    let actual_len = len % 101;
    let result = keccak256(input, actual_len);
    let expected = keccak256_hash_oracle(input, actual_len);
    assert_eq(result, expected);
}

#[test]
unconstrained fn test_keccak256_135(input: [u8; 135], len: u32) {
    let actual_len = len % 136;
    let result = keccak256(input, actual_len);
    let expected = keccak256_hash_oracle(input, actual_len);
    assert_eq(result, expected);
}

#[test]
unconstrained fn test_keccak256_256(input: [u8; 256], len: u32) {
    let actual_len = len % 257;
    let result = keccak256(input, actual_len);
    let expected = keccak256_hash_oracle(input, actual_len);
    assert_eq(result, expected);
}
