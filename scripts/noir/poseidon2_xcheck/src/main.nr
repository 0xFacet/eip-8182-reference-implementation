// Tiny circuit that hashes a fixed input via the vendored Aztec Poseidon2
// (length-tagged sponge, capacity IV = N << 64, rate=3, t=4 BN254). The
// expected output is a public input; the JS cross-check fills it in with the
// value computed by scripts/witness/poseidon2.js (the project's existing
// length-tagged poseidon2). If they differ, witness execution fails and the
// xcheck script reports MISMATCH.

use poseidon::poseidon2::Poseidon2;

fn main(inputs: [Field; 16], in_len: pub u32, expected: pub Field) {
    let actual = Poseidon2::hash(inputs, in_len);
    assert(actual == expected, "vendored Poseidon2 disagrees with project poseidon2");
}
