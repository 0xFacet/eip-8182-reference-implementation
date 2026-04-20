use crate::constants::{
    DUMMY_OWNER_NULLIFIER_KEY_PREIMAGE,
    ORIGIN_MODE_DEFAULT,
    ORIGIN_MODE_REQUIRE_TAGGED,
    NULLIFIER_DOMAIN,
    TRANSACT_NOTE_SECRET_DOMAIN,
    NOTE_SECRET_SEED_DOMAIN,
    OWNER_COMMITMENT_DOMAIN,
    NOTE_BODY_COMMITMENT_DOMAIN,
    NOTE_COMMITMENT_DOMAIN,
    OWNER_NULLIFIER_KEY_HASH_DOMAIN,
    PHANTOM_NULLIFIER_DOMAIN,
};
use crate::hash_utils::{p_hash2, p_hash3, p_hash4, p_hash5};
use crate::types::Note;

// Owner-side note commitment (EIP Section 7.3). Hides owner-identifying fields behind a
// domain-separated hash so observers can see only the commitment, not its inputs.
pub fn owner_commitment(owner_nullifier_key_hash: Field, note_secret: Field) -> Field {
    p_hash3([OWNER_COMMITMENT_DOMAIN, owner_nullifier_key_hash, note_secret])
}

// Semantic note body commitment (EIP Section 7.4). Input order is normative.
pub fn note_body_commitment(
    owner_commitment_value: Field,
    amount: Field,
    token_address: Field,
    origin_tag: Field,
) -> Field {
    p_hash5([
        NOTE_BODY_COMMITMENT_DOMAIN,
        owner_commitment_value,
        amount,
        token_address,
        origin_tag,
    ])
}

// Final leaf-sealed note commitment (EIP Section 7.5). `leaf_index` is the tree leaf
// index assigned at insertion - this is the structural uniqueness source.
pub fn note_commitment(note_body_commitment_value: Field, leaf_index: Field) -> Field {
    p_hash3([NOTE_COMMITMENT_DOMAIN, note_body_commitment_value, leaf_index])
}

// Full three-layer commitment for a note at a known leaf index. Convenience
// helper for the spend path where the prover knows the input note's leaf index
// and needs the final commitment to derive the nullifier.
pub fn full_note_commitment(note: Note, leaf_index: Field) -> Field {
    let oc = owner_commitment(note.owner_nullifier_key_hash, note.note_secret);
    let body = note_body_commitment(oc, note.amount, note.token_address, note.origin_tag);
    note_commitment(body, leaf_index)
}

pub fn owner_nullifier_key_hash(owner_nullifier_key: Field) -> Field {
    p_hash2([OWNER_NULLIFIER_KEY_HASH_DOMAIN, owner_nullifier_key])
}

pub fn dummy_owner_nullifier_key_hash() -> Field {
    p_hash2([OWNER_NULLIFIER_KEY_HASH_DOMAIN, DUMMY_OWNER_NULLIFIER_KEY_PREIMAGE])
}

// Real-note nullifier per EIP Section 7.6. Binds to the final (leaf-sealed) note
// commitment, so the prover MUST witness each input note's leaf index.
pub fn note_nullifier(note_commitment_value: Field, owner_nullifier_key: Field) -> Field {
    p_hash3([NULLIFIER_DOMAIN, note_commitment_value, owner_nullifier_key])
}

pub fn phantom_nullifier(
    owner_nullifier_key: Field,
    intent_replay_id: Field,
    input_index: Field,
) -> Field {
    p_hash4([PHANTOM_NULLIFIER_DOMAIN, owner_nullifier_key, intent_replay_id, input_index])
}

pub fn note_secret_seed_hash(note_secret_seed: Field) -> Field {
    p_hash2([NOTE_SECRET_SEED_DOMAIN, note_secret_seed])
}

pub fn note_secret(note_secret_seed: Field, intent_replay_id: Field, output_index: Field) -> Field {
    p_hash4([TRANSACT_NOTE_SECRET_DOMAIN, note_secret_seed, intent_replay_id, output_index])
}

pub fn origin_tag_for_spend(
    input0_is_phantom: bool,
    input0_origin_tag: Field,
    input1_is_phantom: bool,
    input1_origin_tag: Field,
) -> Field {
    if input0_is_phantom {
        input1_origin_tag
    } else if input1_is_phantom {
        input0_origin_tag
    } else if input0_origin_tag == input1_origin_tag {
        input0_origin_tag
    } else {
        0
    }
}

pub fn origin_mode_satisfied(
    origin_mode: Field,
    input0_is_phantom: bool,
    input0_origin_tag: Field,
    input1_is_phantom: bool,
    input1_origin_tag: Field,
    out0_is_dummy: bool,
    out0_origin_tag: Field,
    out1_is_dummy: bool,
    out1_origin_tag: Field,
    out2_is_dummy: bool,
    out2_origin_tag: Field,
) -> bool {
    if origin_mode == ORIGIN_MODE_DEFAULT {
        true
    } else if origin_mode == ORIGIN_MODE_REQUIRE_TAGGED {
        let inputs_ok = if input0_is_phantom {
            input1_origin_tag != 0
        } else if input1_is_phantom {
            input0_origin_tag != 0
        } else {
            if input0_origin_tag == input1_origin_tag {
                input0_origin_tag != 0
            } else {
                false
            }
        };
        let out0_ok = if out0_is_dummy { true } else { out0_origin_tag != 0 };
        let out1_ok = if out1_is_dummy { true } else { out1_origin_tag != 0 };
        let out2_ok = if out2_is_dummy { true } else { out2_origin_tag != 0 };
        if inputs_ok {
            if out0_ok {
                if out1_ok {
                    out2_ok
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    }
}

pub fn assert_origin_mode_constraints(
    origin_mode: Field,
    input0_is_phantom: bool,
    input0_origin_tag: Field,
    input1_is_phantom: bool,
    input1_origin_tag: Field,
    out0_is_dummy: bool,
    out0_origin_tag: Field,
    out1_is_dummy: bool,
    out1_origin_tag: Field,
    out2_is_dummy: bool,
    out2_origin_tag: Field,
) {
    assert(
        origin_mode_satisfied(
            origin_mode,
            input0_is_phantom,
            input0_origin_tag,
            input1_is_phantom,
            input1_origin_tag,
            out0_is_dummy,
            out0_origin_tag,
            out1_is_dummy,
            out1_origin_tag,
            out2_is_dummy,
            out2_origin_tag,
        ),
        "invalid origin mode",
    );
}

#[test]
fn test_full_note_commitment_deterministic() {
    let note = Note {
        amount: 1000,
        note_secret: note_secret(0xbeef, 0xaaaa, 0),
        owner_nullifier_key_hash: owner_nullifier_key_hash(0x9999),
        token_address: 0x1111,
        origin_tag: 0x5555,
    };
    let c1 = full_note_commitment(note, 7);
    let c2 = full_note_commitment(note, 7);
    assert(c1 == c2);
    assert(c1 != 0);
    let c3 = full_note_commitment(note, 8);
    assert(c3 != c1);
}

#[test]
fn test_owner_nullifier_key_hash_deterministic() {
    let h1 = owner_nullifier_key_hash(0x9999);
    let h2 = owner_nullifier_key_hash(0x9999);
    assert(h1 == h2);
    assert(h1 != 0);
    let h3 = owner_nullifier_key_hash(0x8888);
    assert(h3 != h1);
}

#[test]
fn test_dummy_owner_nullifier_key_hash() {
    let d = dummy_owner_nullifier_key_hash();
    assert(d != 0);
    let real = owner_nullifier_key_hash(0x9999);
    assert(d != real);
}

#[test]
fn test_note_nullifier_deterministic() {
    let note_commitment_value = 0x1234;
    let n1 = note_nullifier(note_commitment_value, 0x9999);
    let n2 = note_nullifier(note_commitment_value, 0x9999);
    assert(n1 == n2);
    assert(n1 != 0);
    let n3 = note_nullifier(0x5678, 0x9999);
    assert(n3 != n1);
}

#[test]
fn test_phantom_nullifier_differs_from_real() {
    let real = note_nullifier(0x1234, 0x9999);
    let phantom = phantom_nullifier(0x9999, 0xaaaa, 0);
    assert(real != phantom);
}

#[test]
fn test_note_secret_seed_hash_deterministic() {
    let h1 = note_secret_seed_hash(0xbeef);
    let h2 = note_secret_seed_hash(0xbeef);
    assert(h1 == h2);
    assert(h1 != 0);
    let h3 = note_secret_seed_hash(0xdead);
    assert(h3 != h1);
}

#[test]
fn test_note_secret_deterministic() {
    let r1 = note_secret(0xbeef, 0xaaaa, 0);
    let r2 = note_secret(0xbeef, 0xaaaa, 0);
    assert(r1 == r2);
    let r3 = note_secret(0xbeef, 0xaaaa, 1);
    assert(r3 != r1);
}

#[test]
fn test_origin_tag_for_spend_clears_on_mismatch() {
    let eff = origin_tag_for_spend(false, 0x5555, false, 0x6666);
    assert(eff == 0);
}

#[test]
fn test_origin_tag_for_spend_phantom_inherits() {
    let eff = origin_tag_for_spend(true, 0, false, 0x5555);
    assert(eff == 0x5555);
    let eff2 = origin_tag_for_spend(false, 0x5555, true, 0);
    assert(eff2 == 0x5555);
}

#[test]
fn test_origin_tag_for_spend_same_tag_preserved() {
    let eff = origin_tag_for_spend(false, 0x5555, false, 0x5555);
    assert(eff == 0x5555);
}

#[test]
fn test_origin_mode_default_allows_cleared_outputs() {
    assert(origin_mode_satisfied(
        ORIGIN_MODE_DEFAULT,
        false,
        0x5555,
        false,
        0x6666,
        false,
        0,
        true,
        0,
        true,
        0,
    ));
}

#[test]
fn test_origin_mode_require_tagged_rejects_mixed_real_inputs() {
    assert(!origin_mode_satisfied(
        ORIGIN_MODE_REQUIRE_TAGGED,
        false,
        0x5555,
        false,
        0x6666,
        false,
        0,
        true,
        0,
        true,
        0,
    ));
}

#[test]
fn test_origin_mode_require_tagged_accepts_shared_nonzero_inputs() {
    assert(origin_mode_satisfied(
        ORIGIN_MODE_REQUIRE_TAGGED,
        false,
        0x5555,
        false,
        0x5555,
        false,
        0x5555,
        true,
        0,
        true,
        0,
    ));
}

#[test]
fn test_origin_mode_require_tagged_rejects_zero_output_tag() {
    assert(!origin_mode_satisfied(
        ORIGIN_MODE_REQUIRE_TAGGED,
        true,
        0,
        true,
        0,
        false,
        0,
        true,
        0,
        true,
        0,
    ));
}

#[test]
fn test_origin_mode_rejects_invalid_kind() {
    assert(!origin_mode_satisfied(2, true, 0, true, 0, true, 0, true, 0, true, 0));
}
