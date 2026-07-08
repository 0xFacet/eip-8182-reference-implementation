use keccak256::keccak256;

pub struct Secp256k1PubKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

pub struct Signature {
    pub signature: [u8; 64],
}

impl Secp256k1PubKey {
    pub fn ethereum_address(self) -> Field {
        let mut preimage: [u8; 64] = [0; 64];
        for i in 0..32 {
            preimage[i] = self.x[i];
            preimage[32 + i] = self.y[i];
        }

        let hash = keccak256(preimage, 64);
        let mut address: Field = 0;
        for i in 12..32 {
            address = address * 256 + hash[i] as Field;
        }

        address
    }
}

impl Signature {
    pub fn verify(self, signing_hash: [u8; 32], signer: Secp256k1PubKey) {
        let ok = std::ecdsa_secp256k1::verify_signature(
            signer.x,
            signer.y,
            self.signature,
            signing_hash,
        );
        assert(ok, "signature invalid");
    }

    // Appendix A: low-s ECDSA only. s (bytes 32..64) must be <= half_order.
    pub fn assert_low_s(self, half_order_be: [u8; 32]) {
        let mut is_equal_prefix = true;
        let mut is_strictly_less = false;
        for i in 0..32 {
            let s_byte = self.signature[32 + i];
            if is_equal_prefix {
                if s_byte < half_order_be[i] {
                    is_strictly_less = true;
                    is_equal_prefix = false;
                } else if s_byte > half_order_be[i] {
                    is_equal_prefix = false;
                }
            }
        }
        // equal to half order is also permitted (s <= (n-1)/2)
        assert(is_strictly_less | is_equal_prefix, "signature s must be low-s");
    }
}
