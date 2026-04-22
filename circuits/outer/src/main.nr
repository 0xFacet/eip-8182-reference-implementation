// Outer circuit for EIP-8182.
// Handles transfer and withdrawal. Deposits are contract-native and do not
// involve this circuit (EIP Section 4, Section 5.3).
//
// 17 public inputs per EIP Section 10. Recursively verifies the inner auth proof.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use privacy_pool_common::constants::{
    LOCK_OUTPUT_BINDING_0,
    LOCK_OUTPUT_BINDING_1,
    LOCK_OUTPUT_BINDING_2,
    TRANSFER_OP,
    WITHDRAWAL_OP,
};
use privacy_pool_common::digest::{
    output_binding,
    transaction_intent_digest as common_transaction_intent_digest,
    intent_replay_id as common_intent_replay_id,
};
use privacy_pool_common::hash_utils::hash_vk;
use privacy_pool_common::note::{
    dummy_owner_nullifier_key_hash,
    full_note_commitment,
    note_body_commitment,
    note_nullifier,
    note_secret,
    note_secret_seed_hash,
    owner_commitment,
    owner_nullifier_key_hash,
    phantom_nullifier,
};
use privacy_pool_common::range::{
    assert_address,
    assert_amount,
    assert_execution_constraints_flags,
    assert_valid_until,
};
use privacy_pool_common::registry::{auth_membership_root, user_registry_membership_root};
use privacy_pool_common::types::{
    AuthPolicyLeaf,
    AuthPolicyWitness,
    InputNoteWitness,
    Note,
    UserRegistryLeaf,
    UserRegistryWitness,
};

fn main(
    // --- 17 public inputs per EIP Section 10 ---
    note_commitment_root: pub Field,
    nullifier0_out: pub Field,
    nullifier1_out: pub Field,
    note_body_commitment0_out: pub Field,
    note_body_commitment1_out: pub Field,
    note_body_commitment2_out: pub Field,
    public_amount_out: pub Field,
    public_recipient: pub Field,
    public_token_address: pub Field,
    intent_replay_id: pub Field,
    registry_root: pub Field,
    valid_until_seconds: pub Field,
    execution_chain_id: pub Field,
    auth_policy_registry_root: pub Field,
    output_note_data_hash0: pub Field,
    output_note_data_hash1: pub Field,
    output_note_data_hash2: pub Field,

    // --- inner proof artifacts ---
    inner_vk: UltraHonkVerificationKey,
    inner_proof: UltraHonkZKProof,
    inner_bb_key_hash: Field,
    authorizing_address: Field,
    auth_data_commitment: Field,
    transaction_intent_digest: Field,

    // --- outer auth witnesses ---
    policy_version: Field,

    // --- outer private witnesses ---
    nonce: Field,
    execution_constraints_flags: Field,
    locked_output_binding0: Field,
    locked_output_binding1: Field,
    locked_output_binding2: Field,
    owner_nullifier_key: Field,
    note_secret_seed: Field,

    sender_leaf: UserRegistryLeaf,
    sender_witness: UserRegistryWitness,

    recipient_leaf: UserRegistryLeaf,
    recipient_witness: UserRegistryWitness,

    sponsor_leaf: UserRegistryLeaf,
    sponsor_witness: UserRegistryWitness,

    auth_witness: AuthPolicyWitness,

    input0: InputNoteWitness,
    input1: InputNoteWitness,

    // Intent fields
    transfer_recipient_address: Field,
    payment_amount: Field,
    private_token_address: Field,
    change_amount: Field,
    fee_recipient_address: Field,   // from signed intent (may be 0)
    fee_amount: Field,              // from signed intent
    fee_note_recipient_address: Field,          // prover-chosen fee note recipient (constrained below)
) {
    // == Common assertions ==
    assert(valid_until_seconds != 0);
    assert(auth_policy_registry_root != 0);
    assert(registry_root != 0);

    // Range checks
    assert_address(authorizing_address);
    assert_address(public_recipient);
    assert_address(public_token_address);
    assert_address(transfer_recipient_address);
    assert_address(private_token_address);
    assert_address(fee_recipient_address);
    assert_address(fee_note_recipient_address);
    assert_amount(public_amount_out);
    assert_amount(payment_amount);
    assert_amount(change_amount);
    assert_amount(fee_amount);
    assert_valid_until(valid_until_seconds);
    assert_execution_constraints_flags(execution_constraints_flags);
    execution_constraints_flags.assert_max_bit_size::<3>();

    // == Mode selection (transfer vs withdrawal only) ==
    let is_withdrawal = public_amount_out != 0;
    let is_transfer = !is_withdrawal;

    // == Mode-specific assertions ==
    if is_transfer {
        assert(public_recipient == 0);
        assert(public_token_address == 0);
        assert(payment_amount != 0);
        assert(transfer_recipient_address != 0);
    } else {
        // withdrawal
        assert(public_recipient != 0);
        assert(payment_amount == 0);
    }

    // == Inner proof verification (all modes) ==
    let inner_public_inputs = [
        auth_data_commitment,
        transaction_intent_digest,
    ];
    verify_honk_proof(inner_vk, inner_proof, inner_public_inputs, inner_bb_key_hash);

    // == VK hash + auth policy check (all modes) ==
    let inner_vk_hash = hash_vk(inner_vk);

    let auth_leaf = AuthPolicyLeaf { auth_data_commitment, policy_version };
    let auth_root = auth_membership_root(authorizing_address, inner_vk_hash, auth_leaf, auth_witness);
    assert(auth_root == auth_policy_registry_root, "auth policy root mismatch");

    // == Sender registry binding (all modes) ==
    let sender_root = user_registry_membership_root(authorizing_address, sender_leaf, sender_witness);
    assert(sender_root == registry_root, "sender root mismatch");

    let expected_owner_nullifier_key_hash = owner_nullifier_key_hash(owner_nullifier_key);
    assert(sender_leaf.owner_nullifier_key_hash == expected_owner_nullifier_key_hash);
    assert(sender_leaf.note_secret_seed_hash == note_secret_seed_hash(note_secret_seed));

    // == Determine token, recipient, amount based on mode ==
    let token_address = if is_transfer {
        private_token_address
    } else {
        public_token_address
    };

    let recipient_address = if is_transfer {
        transfer_recipient_address
    } else {
        public_recipient
    };

    let authorized_amount = if is_transfer {
        payment_amount
    } else {
        public_amount_out
    };

    let operation_kind = if is_transfer {
        TRANSFER_OP
    } else {
        WITHDRAWAL_OP
    };

    // == Transaction intent digest + verification (all modes) ==
    let transaction_intent_digest_value = common_transaction_intent_digest(
        policy_version,
        authorizing_address,
        operation_kind,
        token_address,
        recipient_address,
        authorized_amount,
        fee_recipient_address,
        fee_amount,
        execution_constraints_flags,
        locked_output_binding0,
        locked_output_binding1,
        locked_output_binding2,
        nonce,
        valid_until_seconds,
        execution_chain_id,
    );

    // == Intent replay id (all modes) ==
    let intent_replay_id_value = common_intent_replay_id(
        owner_nullifier_key,
        authorizing_address,
        execution_chain_id,
        nonce,
    );
    assert(intent_replay_id_value == intent_replay_id);

    // == Recipient registry proof (transfer only) ==
    if is_transfer {
        let recipient_root = user_registry_membership_root(recipient_address, recipient_leaf, recipient_witness);
        assert(recipient_root == registry_root);
    }

    // == Fee note resolution ==
    let has_fee = fee_amount != 0;

    if has_fee {
        // Constrain fee_note_recipient_address based on fee_recipient_address
        if fee_recipient_address != 0 {
            assert(fee_note_recipient_address == fee_recipient_address);
        } else {
            assert(fee_note_recipient_address != 0);
        }
        // Fee note recipient registry proof
        let sponsor_root = user_registry_membership_root(fee_note_recipient_address, sponsor_leaf, sponsor_witness);
        assert(sponsor_root == registry_root);
    } else {
        assert(fee_recipient_address == 0);
        assert(fee_note_recipient_address == 0);
    }

    // == Input notes ==
    assert(!(input0.is_phantom & input1.is_phantom));

    // The new nullifier (EIP Section 7.6) binds to the FINAL leaf-sealed note
    // commitment, so the prover must witness each input's `leaf_index` and we
    // rebuild the three-layer commitment for each real input.
    let nullifier0 = if input0.is_phantom {
        assert(input0.note.amount == 0);
        phantom_nullifier(owner_nullifier_key, intent_replay_id_value, 0)
    } else {
        assert_amount(input0.note.amount);
        assert(input0.note.owner_nullifier_key_hash == sender_leaf.owner_nullifier_key_hash);
        assert(input0.note.token_address == token_address);
        let leaf0 = full_note_commitment(input0.note, input0.leaf_index as Field);
        let root0 = privacy_pool_common::merkle::merkle_root_from_index(leaf0, input0.leaf_index, input0.siblings);
        assert(root0 == note_commitment_root);
        note_nullifier(leaf0, owner_nullifier_key)
    };

    let nullifier1 = if input1.is_phantom {
        assert(input1.note.amount == 0);
        phantom_nullifier(owner_nullifier_key, intent_replay_id_value, 1)
    } else {
        assert_amount(input1.note.amount);
        assert(input1.note.owner_nullifier_key_hash == sender_leaf.owner_nullifier_key_hash);
        assert(input1.note.token_address == token_address);
        let leaf1 = full_note_commitment(input1.note, input1.leaf_index as Field);
        let root1 = privacy_pool_common::merkle::merkle_root_from_index(leaf1, input1.leaf_index, input1.siblings);
        assert(root1 == note_commitment_root);
        note_nullifier(leaf1, owner_nullifier_key)
    };

    assert(nullifier0 == nullifier0_out);
    assert(nullifier1 == nullifier1_out);
    assert(nullifier0 != nullifier1);

    // == Note secrets (all modes, from noteSecretSeed) ==
    let out0_note_secret = note_secret(note_secret_seed, intent_replay_id_value, 0);
    let out1_note_secret = note_secret(note_secret_seed, intent_replay_id_value, 1);
    let out2_note_secret = note_secret(note_secret_seed, intent_replay_id_value, 2);

    // == Value conservation ==
    let input0_amount = if input0.is_phantom { 0 } else { input0.note.amount };
    let input1_amount = if input1.is_phantom { 0 } else { input1.note.amount };
    let input_sum = input0_amount + input1_amount;

    // == Output slot 0: recipient (transfer) or change (withdrawal) or dummy ==
    let out0_is_dummy = if is_transfer {
        false
    } else {
        change_amount == 0
    };

    let out0 = if is_transfer {
        // Transfer: recipient note
        Note {
            amount: payment_amount,
            note_secret: out0_note_secret,
            owner_nullifier_key_hash: recipient_leaf.owner_nullifier_key_hash,
            token_address,
        }
    } else if out0_is_dummy {
        Note {
            amount: 0,
            note_secret: out0_note_secret,
            owner_nullifier_key_hash: dummy_owner_nullifier_key_hash(),
            token_address: 0,
        }
    } else {
        // Withdrawal with change
        Note {
            amount: change_amount,
            note_secret: out0_note_secret,
            owner_nullifier_key_hash: sender_leaf.owner_nullifier_key_hash,
            token_address,
        }
    };

    // == Output slot 1: change (transfer) or dummy ==
    let out1_is_dummy = if is_transfer {
        change_amount == 0
    } else {
        true
    };

    let out1 = if out1_is_dummy {
        Note {
            amount: 0,
            note_secret: out1_note_secret,
            owner_nullifier_key_hash: dummy_owner_nullifier_key_hash(),
            token_address: 0,
        }
    } else {
        // Transfer change note
        Note {
            amount: change_amount,
            note_secret: out1_note_secret,
            owner_nullifier_key_hash: sender_leaf.owner_nullifier_key_hash,
            token_address,
        }
    };

    // == Output slot 2: fee note or dummy ==
    let out2_is_dummy = !has_fee;

    let out2 = if out2_is_dummy {
        Note {
            amount: 0,
            note_secret: out2_note_secret,
            owner_nullifier_key_hash: dummy_owner_nullifier_key_hash(),
            token_address: 0,
        }
    } else {
        Note {
            amount: fee_amount,
            note_secret: out2_note_secret,
            owner_nullifier_key_hash: sponsor_leaf.owner_nullifier_key_hash,
            token_address,
        }
    };

    assert_real_output_amount(out0_is_dummy, out0.amount);
    assert_real_output_amount(out1_is_dummy, out1.amount);
    assert_real_output_amount(out2_is_dummy, out2.amount);

    // == Value conservation ==
    let output_sum = out0.amount + out1.amount + out2.amount;
    assert(input_sum == output_sum + public_amount_out);

    // == Output body-commitment binding ==
    // The circuit exposes body commitments as public inputs; the contract
    // seals in the assigned leaf index to produce the final note commitment.
    let owner_commit0 = owner_commitment(out0.owner_nullifier_key_hash, out0.note_secret);
    let owner_commit1 = owner_commitment(out1.owner_nullifier_key_hash, out1.note_secret);
    let owner_commit2 = owner_commitment(out2.owner_nullifier_key_hash, out2.note_secret);

    let body0 = note_body_commitment(owner_commit0, out0.amount, out0.token_address);
    let body1 = note_body_commitment(owner_commit1, out1.amount, out1.token_address);
    let body2 = note_body_commitment(owner_commit2, out2.amount, out2.token_address);

    assert(body0 == note_body_commitment0_out);
    assert(body1 == note_body_commitment1_out);
    assert(body2 == note_body_commitment2_out);

    // EIP Section 7.7: output binding hashes the body commitment, not the final
    // (leaf-sealed) commitment. This lets the signer lock a slot without
    // knowing the contract-assigned leaf index.
    let output_binding0 = output_binding(body0, output_note_data_hash0);
    let output_binding1 = output_binding(body1, output_note_data_hash1);
    let output_binding2 = output_binding(body2, output_note_data_hash2);

    assert_output_binding_lock(
        execution_constraints_flags,
        LOCK_OUTPUT_BINDING_0,
        locked_output_binding0,
        output_binding0,
    );
    assert_output_binding_lock(
        execution_constraints_flags,
        LOCK_OUTPUT_BINDING_1,
        locked_output_binding1,
        output_binding1,
    );
    assert_output_binding_lock(
        execution_constraints_flags,
        LOCK_OUTPUT_BINDING_2,
        locked_output_binding2,
        output_binding2,
    );

    assert(transaction_intent_digest_value == transaction_intent_digest, "transaction intent digest mismatch");
}

fn assert_output_binding_lock(
    execution_constraints_flags: Field,
    bit: Field,
    locked_output_binding: Field,
    actual_output_binding: Field,
) {
    if flag_is_set(execution_constraints_flags, bit) {
        assert(locked_output_binding == actual_output_binding, "output binding mismatch");
    } else {
        assert(locked_output_binding == 0, "unlocked output binding must be zero");
    }
}

fn flag_is_set(execution_constraints_flags: Field, bit: Field) -> bool {
    if bit == LOCK_OUTPUT_BINDING_0 {
        if execution_constraints_flags == 1 {
            true
        } else if execution_constraints_flags == 3 {
            true
        } else if execution_constraints_flags == 5 {
            true
        } else {
            execution_constraints_flags == 7
        }
    } else if bit == LOCK_OUTPUT_BINDING_1 {
        if execution_constraints_flags == 2 {
            true
        } else if execution_constraints_flags == 3 {
            true
        } else if execution_constraints_flags == 6 {
            true
        } else {
            execution_constraints_flags == 7
        }
    } else {
        if execution_constraints_flags == 4 {
            true
        } else if execution_constraints_flags == 5 {
            true
        } else if execution_constraints_flags == 6 {
            true
        } else {
            execution_constraints_flags == 7
        }
    }
}

fn assert_real_output_amount(is_dummy: bool, amount: Field) {
    if !is_dummy {
        assert(amount != 0, "real output must have nonzero amount");
    }
}
