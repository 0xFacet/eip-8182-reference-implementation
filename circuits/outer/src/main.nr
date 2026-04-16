// Unified outer circuit for EIP-8182 demo.
// Handles all three operation modes: deposit, transfer, withdrawal.
// 3 output slots: slot 0 = recipient/change, slot 1 = change/dummy, slot 2 = fee/dummy.
// 19 public inputs. Recursively verifies the inner auth proof.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use privacy_pool_common::constants::{
    DEPOSIT_OP,
    LOCK_OUTPUT_BINDING_0,
    LOCK_OUTPUT_BINDING_1,
    LOCK_OUTPUT_BINDING_2,
    TRANSFER_OP,
    WITHDRAWAL_OP,
};
use privacy_pool_common::digest::{
    output_binding,
    transaction_intent_digest as common_transaction_intent_digest,
    transaction_replay_id as common_transaction_replay_id,
};
use privacy_pool_common::hash_utils::hash_vk;
use privacy_pool_common::note::{
    assert_origin_mode_constraints,
    deposit_origin_tag,
    dummy_owner_nullifier_key_hash,
    note_nullifier,
    origin_tag_for_spend,
    note_commitment,
    note_secret,
    note_secret_seed_hash,
    owner_nullifier_key_hash,
    phantom_nullifier,
};
use privacy_pool_common::range::{
    assert_address,
    assert_amount,
    assert_execution_constraints_flags,
    assert_origin_mode,
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
    // --- 19 public inputs ---
    note_commitment_root: pub Field,
    nullifier0_out: pub Field,
    nullifier1_out: pub Field,
    note_commitment0_out: pub Field,
    note_commitment1_out: pub Field,
    note_commitment2_out: pub Field,
    public_amount_in: pub Field,
    public_amount_out: pub Field,
    public_recipient: pub Field,
    public_token_address: pub Field,
    depositor_address: pub Field,
    transaction_replay_id: pub Field,
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
    origin_mode: Field, // signer-selected origin handling mode
    fee_note_owner: Field,          // prover-chosen fee note recipient (constrained below)
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
    assert_amount(public_amount_in);
    assert_amount(public_amount_out);
    assert_amount(payment_amount);
    assert_amount(change_amount);
    assert_amount(fee_amount);
    assert_origin_mode(origin_mode);
    assert_valid_until(valid_until_seconds);
    assert_execution_constraints_flags(execution_constraints_flags);
    execution_constraints_flags.assert_max_bit_size::<3>();

    // == Mode selection ==
    let is_deposit = depositor_address != 0;
    let is_withdrawal = !is_deposit & (public_amount_out != 0);
    let is_transfer = !is_deposit & !is_withdrawal;

    // == Mode-specific assertions ==
    if is_deposit {
        assert(public_amount_in != 0);
        assert(public_amount_out == 0);
        assert(public_recipient == 0);
        assert(authorizing_address == depositor_address);
        assert_address(depositor_address);
    } else if is_transfer {
        assert(public_amount_in == 0);
        assert(public_amount_out == 0);
        assert(public_recipient == 0);
        assert(public_token_address == 0);
        assert(depositor_address == 0);
        assert(payment_amount != 0);
        assert(transfer_recipient_address != 0);
    } else {
        // withdrawal
        assert(public_amount_in == 0);
        assert(public_recipient != 0);
        assert(depositor_address == 0);
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

    // == Sender/depositor registry binding (all modes) ==
    let sender_root = user_registry_membership_root(authorizing_address, sender_leaf, sender_witness);
    assert(sender_root == registry_root, "sender root mismatch");

    let expected_owner_nullifier_key_hash = owner_nullifier_key_hash(owner_nullifier_key);
    assert(sender_leaf.owner_nullifier_key_hash == expected_owner_nullifier_key_hash);
    assert(sender_leaf.note_secret_seed_hash == note_secret_seed_hash(note_secret_seed));

    // == Determine token, recipient, amount based on mode ==
    let token_address = if is_deposit {
        public_token_address
    } else if is_transfer {
        private_token_address
    } else {
        public_token_address
    };

    let recipient_address = if is_deposit {
        transfer_recipient_address
    } else if is_transfer {
        transfer_recipient_address
    } else {
        public_recipient
    };

    let authorized_amount = if is_deposit {
        payment_amount
    } else if is_transfer {
        payment_amount
    } else {
        public_amount_out
    };

    let operation_kind = if is_deposit {
        DEPOSIT_OP
    } else if is_transfer {
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
        origin_mode,
        execution_constraints_flags,
        locked_output_binding0,
        locked_output_binding1,
        locked_output_binding2,
        nonce,
        valid_until_seconds,
        execution_chain_id,
    );

    // == Transaction replay id (all modes) ==
    let transaction_replay_id_value = common_transaction_replay_id(
        owner_nullifier_key,
        authorizing_address,
        execution_chain_id,
        nonce,
    );
    assert(transaction_replay_id_value == transaction_replay_id);

    // == Recipient registry proof (deposit + transfer only) ==
    if is_deposit | is_transfer {
        let recipient_root = user_registry_membership_root(recipient_address, recipient_leaf, recipient_witness);
        assert(recipient_root == registry_root);
    }

    // == Fee note resolution ==
    let has_fee = fee_amount != 0;

    if has_fee {
        // Constrain fee_note_owner based on fee_recipient_address
        if fee_recipient_address != 0 {
            assert(fee_note_owner == fee_recipient_address);
        } else {
            assert(fee_note_owner != 0);
            assert_address(fee_note_owner);
        }
        // Fee note recipient registry proof
        let sponsor_root = user_registry_membership_root(fee_note_owner, sponsor_leaf, sponsor_witness);
        assert(sponsor_root == registry_root);
    } else {
        assert(fee_recipient_address == 0);
    }

    // == Input notes ==
    if is_deposit {
        assert(input0.is_phantom);
        assert(input1.is_phantom);
    } else {
        assert(!(input0.is_phantom & input1.is_phantom));
    }

    let nullifier0 = if input0.is_phantom {
        assert(input0.note.amount == 0);
        phantom_nullifier(owner_nullifier_key, transaction_replay_id_value, 0)
    } else {
        assert_amount(input0.note.amount);
        assert(input0.note.owner_address == authorizing_address);
        assert(input0.note.owner_nullifier_key_hash == sender_leaf.owner_nullifier_key_hash);
        assert(input0.note.token_address == token_address);
        let leaf0 = note_commitment(input0.note);
        let root0 = privacy_pool_common::merkle::merkle_root_from_index(leaf0, input0.leaf_index, input0.siblings);
        assert(root0 == note_commitment_root);
        note_nullifier(owner_nullifier_key, input0.note.note_secret)
    };

    let nullifier1 = if input1.is_phantom {
        assert(input1.note.amount == 0);
        phantom_nullifier(owner_nullifier_key, transaction_replay_id_value, 1)
    } else {
        assert_amount(input1.note.amount);
        assert(input1.note.owner_address == authorizing_address);
        assert(input1.note.owner_nullifier_key_hash == sender_leaf.owner_nullifier_key_hash);
        assert(input1.note.token_address == token_address);
        let leaf1 = note_commitment(input1.note);
        let root1 = privacy_pool_common::merkle::merkle_root_from_index(leaf1, input1.leaf_index, input1.siblings);
        assert(root1 == note_commitment_root);
        note_nullifier(owner_nullifier_key, input1.note.note_secret)
    };

    assert(nullifier0 == nullifier0_out);
    assert(nullifier1 == nullifier1_out);
    assert(nullifier0 != nullifier1);

    // == Note secrets (all modes, from noteSecretSeed) ==
    let out0_note_secret = note_secret(note_secret_seed, transaction_replay_id_value, 0);
    let out1_note_secret = note_secret(note_secret_seed, transaction_replay_id_value, 1);
    let out2_note_secret = note_secret(note_secret_seed, transaction_replay_id_value, 2);

    // == Origin tag derivation ==
    let propagated_origin_tag = if is_deposit {
        0
    } else {
        origin_tag_for_spend(
            input0.is_phantom,
            input0.note.origin_tag,
            input1.is_phantom,
            input1.note.origin_tag,
        )
    };
    let deposit_origin_tag_value = deposit_origin_tag(
        execution_chain_id,
        depositor_address,
        token_address,
        public_amount_in,
        transaction_replay_id_value,
    );
    let origin_tag = if is_deposit {
        if origin_mode == 0 { 0 } else { deposit_origin_tag_value }
    } else {
        propagated_origin_tag
    };

    // == Value conservation ==
    let input0_amount = if input0.is_phantom { 0 } else { input0.note.amount };
    let input1_amount = if input1.is_phantom { 0 } else { input1.note.amount };
    let input_sum = input0_amount + input1_amount + public_amount_in;

    // == Output slot 0: recipient (deposit/transfer) or change (withdrawal) or dummy ==
    let out0_is_dummy = if is_deposit {
        false
    } else if is_transfer {
        false
    } else {
        change_amount == 0
    };

    let out0 = if is_deposit {
        // Deposit: recipient note (amount from intent, not publicAmountIn which includes fee)
        Note {
            amount: authorized_amount,
            owner_address: recipient_address,
            note_secret: out0_note_secret,
            owner_nullifier_key_hash: recipient_leaf.owner_nullifier_key_hash,
            token_address,
            origin_tag,
        }
    } else if is_transfer {
        // Transfer: recipient note
        Note {
            amount: payment_amount,
            owner_address: recipient_address,
            note_secret: out0_note_secret,
            owner_nullifier_key_hash: recipient_leaf.owner_nullifier_key_hash,
            token_address,
            origin_tag,
        }
    } else if out0_is_dummy {
        Note {
            amount: 0,
            owner_address: 0,
            note_secret: out0_note_secret,
            owner_nullifier_key_hash: dummy_owner_nullifier_key_hash(),
            token_address: 0,
            origin_tag: 0,
        }
    } else {
        // Withdrawal with change
        Note {
            amount: change_amount,
            owner_address: authorizing_address,
            note_secret: out0_note_secret,
            owner_nullifier_key_hash: sender_leaf.owner_nullifier_key_hash,
            token_address,
            origin_tag,
        }
    };

    // == Output slot 1: change (transfer) or dummy ==
    let out1_is_dummy = if is_deposit {
        true
    } else if is_transfer {
        change_amount == 0
    } else {
        true
    };

    let out1 = if out1_is_dummy {
        Note {
            amount: 0,
            owner_address: 0,
            note_secret: out1_note_secret,
            owner_nullifier_key_hash: dummy_owner_nullifier_key_hash(),
            token_address: 0,
            origin_tag: 0,
        }
    } else {
        // Transfer change note
        Note {
            amount: change_amount,
            owner_address: authorizing_address,
            note_secret: out1_note_secret,
            owner_nullifier_key_hash: sender_leaf.owner_nullifier_key_hash,
            token_address,
            origin_tag,
        }
    };

    // == Output slot 2: fee note or dummy ==
    let out2_is_dummy = !has_fee;

    let out2 = if out2_is_dummy {
        Note {
            amount: 0,
            owner_address: 0,
            note_secret: out2_note_secret,
            owner_nullifier_key_hash: dummy_owner_nullifier_key_hash(),
            token_address: 0,
            origin_tag: 0,
        }
    } else {
        Note {
            amount: fee_amount,
            owner_address: fee_note_owner,
            note_secret: out2_note_secret,
            owner_nullifier_key_hash: sponsor_leaf.owner_nullifier_key_hash,
            token_address,
            origin_tag,
        }
    };

    assert_real_output_amount(out0_is_dummy, out0.amount);
    assert_real_output_amount(out1_is_dummy, out1.amount);
    assert_real_output_amount(out2_is_dummy, out2.amount);

    assert_origin_mode_constraints(
        origin_mode,
        is_deposit,
        input0.is_phantom,
        input0.note.origin_tag,
        input1.is_phantom,
        input1.note.origin_tag,
        out0_is_dummy,
        out0.origin_tag,
        out1_is_dummy,
        out1.origin_tag,
        out2_is_dummy,
        out2.origin_tag,
    );

    // == Value conservation ==
    let output_sum = out0.amount + out1.amount + out2.amount;
    assert(input_sum == output_sum + public_amount_out);

    // == Deposit-specific: publicAmountIn == amount + feeAmount ==
    if is_deposit {
        assert(public_amount_in == authorized_amount + fee_amount);
    }

    // == Commitment binding ==
    let note_commitment0 = note_commitment(out0);
    let note_commitment1 = note_commitment(out1);
    let note_commitment2 = note_commitment(out2);
    assert(note_commitment0 == note_commitment0_out);
    assert(note_commitment1 == note_commitment1_out);
    assert(note_commitment2 == note_commitment2_out);

    let output_binding0 = output_binding(note_commitment0, output_note_data_hash0);
    let output_binding1 = output_binding(note_commitment1, output_note_data_hash1);
    let output_binding2 = output_binding(note_commitment2, output_note_data_hash2);

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
