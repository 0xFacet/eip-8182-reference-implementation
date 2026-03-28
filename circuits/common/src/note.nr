use crate::constants::{
    DUMMY_NK_PREIMAGE,
    NK_DOMAIN,
    NULLIFIER_DOMAIN,
    ORIGIN_MODE_DEFAULT,
    ORIGIN_MODE_REQUIRE_TAGGED,
    ORIGIN_TAG_DOMAIN,
    OUTPUT_SECRET_DOMAIN,
    PHANTOM_DOMAIN,
    RANDOMNESS_DOMAIN,
};
use crate::hash_utils::{p_hash2, p_hash3, p_hash4, p_hash6};
use crate::types::Note;

pub fn note_commitment(note: Note) -> Field {
    p_hash6([
        note.amount,
        note.owner_address,
        note.randomness,
        note.nullifier_key_hash,
        note.token_address,
        note.origin_tag,
    ])
}

pub fn nullifier_key_hash(nullifier_key: Field) -> Field {
    p_hash2([NK_DOMAIN, nullifier_key])
}

pub fn dummy_nullifier_key_hash() -> Field {
    p_hash2([NK_DOMAIN, DUMMY_NK_PREIMAGE])
}

pub fn real_nullifier(nullifier_key: Field, randomness: Field) -> Field {
    p_hash3([NULLIFIER_DOMAIN, nullifier_key, randomness])
}

pub fn phantom_nullifier(nullifier_key: Field, intent_nullifier: Field, slot_index: Field) -> Field {
    p_hash4([PHANTOM_DOMAIN, nullifier_key, intent_nullifier, slot_index])
}

pub fn output_secret_hash(output_secret: Field) -> Field {
    p_hash2([OUTPUT_SECRET_DOMAIN, output_secret])
}

pub fn output_randomness(output_secret: Field, intent_nullifier: Field, slot_index: Field) -> Field {
    p_hash4([RANDOMNESS_DOMAIN, output_secret, intent_nullifier, slot_index])
}

pub fn deposit_origin_tag(
    execution_chain_id: Field,
    depositor_address: Field,
    token_address: Field,
    public_amount_in: Field,
    intent_nullifier: Field,
) -> Field {
    p_hash6([
        ORIGIN_TAG_DOMAIN,
        execution_chain_id,
        depositor_address,
        token_address,
        public_amount_in,
        intent_nullifier,
    ])
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
    is_deposit: bool,
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
        let inputs_ok = if is_deposit {
            true
        } else if input0_is_phantom {
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
    is_deposit: bool,
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
            is_deposit,
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
fn test_note_commitment_deterministic() {
    let note = Note {
        amount: 1000,
        owner_address: 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf,
        randomness: 0x7777,
        nullifier_key_hash: nullifier_key_hash(0x9999),
        token_address: 0x1111,
        origin_tag: 0x5555,
    };
    let c1 = note_commitment(note);
    let c2 = note_commitment(note);
    assert(c1 == c2);
    assert(c1 != 0);
}

#[test]
fn test_nullifier_key_hash_deterministic() {
    let h1 = nullifier_key_hash(0x9999);
    let h2 = nullifier_key_hash(0x9999);
    assert(h1 == h2);
    assert(h1 != 0);
    let h3 = nullifier_key_hash(0x8888);
    assert(h3 != h1);
}

#[test]
fn test_dummy_nullifier_key_hash() {
    let d = dummy_nullifier_key_hash();
    assert(d != 0);
    let real = nullifier_key_hash(0x9999);
    assert(d != real);
}

#[test]
fn test_real_nullifier_deterministic() {
    let n1 = real_nullifier(0x9999, 0x7777);
    let n2 = real_nullifier(0x9999, 0x7777);
    assert(n1 == n2);
    assert(n1 != 0);
    let n3 = real_nullifier(0x9999, 0x8888);
    assert(n3 != n1);
}

#[test]
fn test_phantom_nullifier_differs_from_real() {
    let real = real_nullifier(0x9999, 0x7777);
    let phantom = phantom_nullifier(0x9999, 0xaaaa, 0);
    assert(real != phantom);
}

#[test]
fn test_output_secret_hash_deterministic() {
    let h1 = output_secret_hash(0xbeef);
    let h2 = output_secret_hash(0xbeef);
    assert(h1 == h2);
    assert(h1 != 0);
    let h3 = output_secret_hash(0xdead);
    assert(h3 != h1);
}

#[test]
fn test_output_randomness_deterministic() {
    let r1 = output_randomness(0xbeef, 0xaaaa, 0);
    let r2 = output_randomness(0xbeef, 0xaaaa, 0);
    assert(r1 == r2);
    let r3 = output_randomness(0xbeef, 0xaaaa, 1);
    assert(r3 != r1);
}

#[test]
fn test_deposit_origin_tag_deterministic() {
    let t1 = deposit_origin_tag(1, 0xabc, 0x1111, 1000, 0xffff);
    let t2 = deposit_origin_tag(1, 0xabc, 0x1111, 1000, 0xffff);
    assert(t1 == t2);
    assert(t1 != 0);
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
    assert(!origin_mode_satisfied(2, true, true, 0, true, 0, true, 0, true, 0, true, 0));
}
