use crate::constants::{
    ADDRESS_BITS,
    AMOUNT_BITS,
    EXECUTION_CONSTRAINTS_FLAGS_BITS,
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
