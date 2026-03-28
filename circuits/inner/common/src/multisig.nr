use crate::{
    default_eip712_verifying_contract,
    eip712_context,
    fold_fields,
    Authorization,
    SigningHash,
    ValidatedIntent,
};
use crate::field_set::assert_canonical_fields;
use crate::secp256k1::Secp256k1PubKey;
use privacy_pool_common::hash_utils::p_hash3;

pub global AUTH_DOMAIN: Field = 0x6d756c74697369675f61757468;

pub struct MultisigApproval {
    pub signer_index: Field,
    pub signature: [u8; 64],
}

pub struct MultisigPolicy<let SIGNERS: u32, let THRESHOLD: u32> {
    pub signers: [Secp256k1PubKey; SIGNERS],
}

impl<let SIGNERS: u32, let THRESHOLD: u32> MultisigPolicy<SIGNERS, THRESHOLD> {
    pub fn authorization(self) -> Authorization {
        let auth_data_commitment = poseidon_hash_keys::<SIGNERS, THRESHOLD>(self.signers);

        Authorization {
            auth_data_commitment,
        }
    }
}

impl MultisigApproval {
    pub fn verify_member<let SIGNERS: u32>(
        self,
        signing_hash: SigningHash,
        signers: [Secp256k1PubKey; SIGNERS],
    ) -> u32 {
        verify_member_with_parts::<SIGNERS>(self.signer_index, self.signature, signing_hash.bytes, signers)
    }
}

pub fn eip712_signing_hash<let SIGNERS: u32, let THRESHOLD: u32>(
    intent: ValidatedIntent,
) -> SigningHash {
    intent.signing_hash(eip712_context(
        AUTH_DOMAIN,
        default_eip712_verifying_contract(),
    ))
}

pub fn poseidon_hash_keys<let SIGNERS: u32, let THRESHOLD: u32>(
    signers: [Secp256k1PubKey; SIGNERS],
) -> Field {
    assert(SIGNERS > 0, "multisig requires at least one signer");
    assert(THRESHOLD > 0, "multisig threshold must be non-zero");
    assert(THRESHOLD <= SIGNERS, "multisig threshold exceeds signer count");

    let mut signer_commitments: [Field; SIGNERS] = [0; SIGNERS];
    for i in 0..SIGNERS {
        signer_commitments[i] = signers[i].auth_commitment();
    }

    assert_canonical_fields(signer_commitments);
    fold_fields(p_hash3([AUTH_DOMAIN, SIGNERS as Field, THRESHOLD as Field]), signer_commitments)
}

fn verify_member_with_parts<let SIGNERS: u32>(
    signer_index_field: Field,
    signature: [u8; 64],
    signing_hash: [u8; 32],
    signers: [Secp256k1PubKey; SIGNERS],
) -> u32 {
    let signer_index = assert_valid_signer_index::<SIGNERS>(signer_index_field);
    let signer = select_signer::<SIGNERS>(signers, signer_index);
    let ok = std::ecdsa_secp256k1::verify_signature(
        signer.x,
        signer.y,
        signature,
        signing_hash,
    );
    assert(ok, "signature invalid");
    signer_index
}

fn assert_valid_signer_index<let SIGNERS: u32>(signer_index: Field) -> u32 {
    let mut selected: u32 = 0;
    let mut is_valid = false;

    for i in 0..SIGNERS {
        if signer_index == i as Field {
            selected = i;
            is_valid = true;
        }
    }

    assert(is_valid, "signer index out of range");
    selected
}

fn select_signer<let SIGNERS: u32>(
    signers: [Secp256k1PubKey; SIGNERS],
    signer_index: u32,
) -> Secp256k1PubKey {
    signers[signer_index]
}
