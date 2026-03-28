use inner::{
    assert_all_distinct,
    InnerOutputs,
    Intent,
};
use inner::multisig::{eip712_signing_hash as multisig_signing_hash, MultisigApproval, MultisigPolicy};

global SIGNERS: u32 = 3;
global THRESHOLD: u32 = 2;

fn main(
    intent: Intent,
    multisig_policy: MultisigPolicy<SIGNERS, THRESHOLD>,
    approvals: [MultisigApproval; THRESHOLD],
) -> pub InnerOutputs {
    let intent = intent.assert_valid();
    let signers = multisig_policy.signers;
    let signing_hash = multisig_signing_hash::<SIGNERS, THRESHOLD>(intent);
    let mut used_indices: [u32; THRESHOLD] = [0; THRESHOLD];
    for i in 0..THRESHOLD {
        used_indices[i] = approvals[i].verify_member(signing_hash, signers);
    }

    assert_all_distinct(used_indices);
    intent.finalize(multisig_policy.authorization())
}
