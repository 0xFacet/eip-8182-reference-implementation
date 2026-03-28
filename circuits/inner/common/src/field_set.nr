pub fn assert_canonical_fields<let N: u32>(values: [Field; N]) {
    for i in 0..N {
        for j in 0..N {
            if j < i {
                assert(values[j].lt(values[i]), "values must be sorted and unique");
            }
        }
    }
}
