use crate::Authorization;
use crate::secp256k1::Secp256k1PubKey;

pub struct SingleSigPolicy {
    pub signer: Secp256k1PubKey,
}

impl SingleSigPolicy {
    pub fn authorization(self) -> Authorization {
        Authorization {
            auth_data_commitment: self.signer.auth_commitment(),
        }
    }
}
