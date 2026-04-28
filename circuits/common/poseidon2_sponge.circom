// Length-tagged Poseidon2 BN254 sponge per spec EIP-8182 Section 3.3.
//
//   poseidon(x_1, ..., x_N) = Poseidon2_sponge(x_1, ..., x_N)
//
//   Initialize state to [0, 0, 0, N << 64].
//   If N == 0: apply one permutation, return state[0].
//   Else: partition inputs into ceil(N/3) chunks of 3 (zero-pad final chunk),
//         absorb each chunk by adding to state[0..3) (rate=3) then permuting,
//         return state[0].
//
// We instantiate distinct circuits per N rather than supporting variable-length
// inputs in a single circuit, because the constraint count depends on N and
// each call site in the pool circuit knows its own N at compile time.

pragma circom 2.0.0;

include "poseidon2_perm.circom";

// Compile-time helper: number of permutations for a given N
//   N == 0 -> 1 perm (initial-state permutation)
//   N  > 0 -> ceil(N/3) perms
function poseidon2NumPerms(n) {
    if (n == 0) return 1;
    return (n + 2) \ 3;
}

// Length tag value placed in the capacity slot at initialization: N << 64
// (BN254 scalar field arithmetic, computed at compile time).
function poseidon2LenTag(n) {
    return n * 18446744073709551616; // 2^64
}

// Generic length-N sponge. Returns state[0] after the final permutation.
template Poseidon2Sponge(N) {
    signal input  in[N];
    signal output out;

    var nPerms = poseidon2NumPerms(N);
    component perms[nPerms];
    for (var p = 0; p < nPerms; p++) {
        perms[p] = Poseidon2Permutation();
    }

    if (N == 0) {
        perms[0].in[0] <== 0;
        perms[0].in[1] <== 0;
        perms[0].in[2] <== 0;
        perms[0].in[3] <== poseidon2LenTag(0);
        out <== perms[0].out[0];
    } else {
        // For each chunk c in [0, nPerms), compute the absorbed state going
        // into perms[c]. The state coming OUT of perms[c-1] is its `out` array;
        // for c==0 the state is the initial-state.
        //   absorbedIn[c][i] for i in {0,1,2}: state[i] + chunk_input[i]
        //                  for i == 3:        state[3] (capacity untouched)
        // chunk_input[j] is in[3*c + j] if that index < N, else 0.
        signal chunkIn[nPerms][4];
        for (var c = 0; c < nPerms; c++) {
            for (var j = 0; j < 3; j++) {
                var idx = 3 * c + j;
                if (c == 0) {
                    // Initial state[j] is 0 for j in {0,1,2}.
                    if (idx < N) chunkIn[c][j] <== in[idx];
                    else         chunkIn[c][j] <== 0;
                } else {
                    if (idx < N) chunkIn[c][j] <== perms[c-1].out[j] + in[idx];
                    else         chunkIn[c][j] <== perms[c-1].out[j];
                }
            }
            // Capacity slot: initial = lengthTag, otherwise carry through.
            if (c == 0) chunkIn[c][3] <== poseidon2LenTag(N);
            else        chunkIn[c][3] <== perms[c-1].out[3];

            for (var i = 0; i < 4; i++) {
                perms[c].in[i] <== chunkIn[c][i];
            }
        }

        out <== perms[nPerms-1].out[0];
    }
}
