use crate::curve_point::xy_auth_commitment;
use keccak256::keccak256;

pub struct Secp256k1PubKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

pub struct Signature {
    pub signature: [u8; 64],
}

impl Secp256k1PubKey {
    pub fn auth_commitment(self) -> Field {
        xy_auth_commitment(self.x, self.y)
    }

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
}
