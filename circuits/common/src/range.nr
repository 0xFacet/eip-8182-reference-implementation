use crate::constants::{
    ADDRESS_BITS,
    AMOUNT_BITS,
    EXECUTION_CONSTRAINTS_FLAGS_BITS,
    ORIGIN_MODE_DEFAULT,
    ORIGIN_MODE_REQUIRE_TAGGED,
    VALID_UNTIL_BITS,
};

pub fn assert_address(x: Field) {
    x.assert_max_bit_size::<ADDRESS_BITS>();
}

pub fn assert_amount(x: Field) {
    x.assert_max_bit_size::<AMOUNT_BITS>();
}

pub fn assert_valid_until(x: Field) {
    x.assert_max_bit_size::<VALID_UNTIL_BITS>();
}

pub fn assert_execution_constraints_flags(x: Field) {
    x.assert_max_bit_size::<EXECUTION_CONSTRAINTS_FLAGS_BITS>();
}

pub fn is_valid_origin_mode(x: Field) -> bool {
    if x == ORIGIN_MODE_DEFAULT {
        true
    } else {
        x == ORIGIN_MODE_REQUIRE_TAGGED
    }
}

pub fn assert_origin_mode(x: Field) {
    assert(is_valid_origin_mode(x), "invalid origin mode");
}
