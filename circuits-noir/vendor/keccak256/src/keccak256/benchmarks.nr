use super::keccak256;

#[export]
fn test_keccak256_1(input: [u8; 1], len: u32) -> [u8; 32] {
    keccak256(input, len)
}

#[export]
fn test_keccak256_100(input: [u8; 100], len: u32) -> [u8; 32] {
    keccak256(input, len)
}

#[export]
fn test_keccak256_135(input: [u8; 135], len: u32) -> [u8; 32] {
    keccak256(input, len)
}

#[export]
fn test_keccak256_256(input: [u8; 256], len: u32) -> [u8; 32] {
    keccak256(input, len)
}
