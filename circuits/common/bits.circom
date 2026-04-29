// Bit decomposition + range check.
// y = sum_i bits[i] * 2^i, with each bit constrained to {0,1}.

pragma circom 2.0.0;

template Num2Bits(N) {
    signal input  in;
    signal output out[N];

    var lc = 0;
    var pow = 1;
    for (var i = 0; i < N; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (1 - out[i]) === 0;
        lc += out[i] * pow;
        pow *= 2;
    }
    in === lc;
}

// Range check: in < 2^N. Just decomposes; bit constraints + recomposition
// equality enforce the bound.
template RangeCheck(N) {
    signal input in;
    component d = Num2Bits(N);
    d.in <== in;
}

// Standard "is the input zero" gadget: out == 1 iff in == 0, else out == 0.
// Uses one witness signal `inv` for the in-circuit inverse, then constrains
// (out = 1 - in*inv) and (in*out = 0). Together these force the right value
// for `out` regardless of how `inv` was witnessed.
template IsZero() {
    signal input  in;
    signal output out;
    signal inv;
    inv <-- in != 0 ? 1 / in : 0;
    out <== 1 - in * inv;
    in * out === 0;
}
