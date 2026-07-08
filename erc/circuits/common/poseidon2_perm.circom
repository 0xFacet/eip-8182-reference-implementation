// Poseidon2 BN254 t=4 RF=8 RP=56, sbox = x^5.
//
// Implements the standard Poseidon2 permutation per the Poseidon2 paper
// (Grassi-Hazay-Khovratovich-Roy-Schofnegger 2023):
//
//   1. External round  (full S-box, M_E linear layer)
//      x  4 (first half)
//   2. Internal round  (S-box on state[0] only, M_I linear layer)
//      x 56
//   3. External round  (full S-box, M_E linear layer)
//      x  4 (second half)
//
// Round constants are added before the S-box layer of each round.
// In a partial round only the constant for state[0] is added.
//
// External matrix M_E for t=4 is the fixed circulant in the parameter asset.
// Internal matrix M_I = I + diag(internalDiagonal). Application:
//   y_i = sum(x) + internalDiagonal[i] * x[i]

pragma circom 2.0.0;

include "poseidon2_constants.circom";

// External matrix M_E: y = M_E * x, where M_E is the 4x4 in the asset.
// M_E rows (from asset):
//   [5,7,1,3]
//   [4,6,1,1]
//   [1,3,5,7]
//   [1,1,4,6]
// y[i] = sum_j M_E[i][j] * x[j]
template Poseidon2ExternalMatrix() {
    signal input  in[4];
    signal output out[4];
    out[0] <== 5*in[0] + 7*in[1] + 1*in[2] + 3*in[3];
    out[1] <== 4*in[0] + 6*in[1] + 1*in[2] + 1*in[3];
    out[2] <== 1*in[0] + 3*in[1] + 5*in[2] + 7*in[3];
    out[3] <== 1*in[0] + 1*in[1] + 4*in[2] + 6*in[3];
}

// Internal matrix M_I = I + diag(internalDiagonal):
//   y[i] = sum(x) + internalDiagonal[i] * x[i]
template Poseidon2InternalMatrix() {
    signal input  in[4];
    signal output out[4];
    signal sum;
    sum <== in[0] + in[1] + in[2] + in[3];
    out[0] <== sum + POSEIDON2_INT_DIAG(0) * in[0];
    out[1] <== sum + POSEIDON2_INT_DIAG(1) * in[1];
    out[2] <== sum + POSEIDON2_INT_DIAG(2) * in[2];
    out[3] <== sum + POSEIDON2_INT_DIAG(3) * in[3];
}

// S-box: y = x^5 (x^2 -> x^4 -> x^5)
template Pow5() {
    signal input  in;
    signal output out;
    signal x2; signal x4;
    x2 <== in * in;
    x4 <== x2 * x2;
    out <== x4 * in;
}

// Full round: add round constants (one per slot), then x^5 on every slot, then M_E.
//   roundIdx selects which 4-tuple of constants to use (0..HALF_RF-1).
//   half=0 picks first-half constants, half=1 picks second-half constants.
template Poseidon2FullRound(roundIdx, half) {
    signal input  in[4];
    signal output out[4];
    signal afterARC[4];
    signal afterSBox[4];
    component sbox[4];
    component mat = Poseidon2ExternalMatrix();
    for (var i = 0; i < 4; i++) {
        if (half == 0) {
            afterARC[i] <== in[i] + POSEIDON2_RC_FULL_FIRST(roundIdx * 4 + i);
        } else {
            afterARC[i] <== in[i] + POSEIDON2_RC_FULL_SECOND(roundIdx * 4 + i);
        }
        sbox[i] = Pow5();
        sbox[i].in <== afterARC[i];
        afterSBox[i] <== sbox[i].out;
        mat.in[i] <== afterSBox[i];
    }
    for (var i = 0; i < 4; i++) {
        out[i] <== mat.out[i];
    }
}

// Partial round: add one constant (slot 0), x^5 on slot 0, M_I on full state.
template Poseidon2PartialRound(roundIdx) {
    signal input  in[4];
    signal output out[4];
    signal afterARC0;
    component sbox = Pow5();
    component mat  = Poseidon2InternalMatrix();
    afterARC0 <== in[0] + POSEIDON2_RC_PARTIAL(roundIdx);
    sbox.in <== afterARC0;
    mat.in[0] <== sbox.out;
    mat.in[1] <== in[1];
    mat.in[2] <== in[2];
    mat.in[3] <== in[3];
    for (var i = 0; i < 4; i++) {
        out[i] <== mat.out[i];
    }
}

// Full Poseidon2 permutation: external M_E pre-mul, then RF/2 full, RP partial,
// RF/2 full rounds. Per the Poseidon2 paper, an initial M_E multiplication is
// applied to the input state before the first full round.
template Poseidon2Permutation() {
    signal input  in[4];
    signal output out[4];

    component preMul = Poseidon2ExternalMatrix();
    for (var i = 0; i < 4; i++) preMul.in[i] <== in[i];

    component firstFull[4];     // RF/2 = 4
    signal firstFullOut[4][4];  // [round][slot]

    for (var r = 0; r < 4; r++) {
        firstFull[r] = Poseidon2FullRound(r, 0);
        for (var i = 0; i < 4; i++) {
            if (r == 0) firstFull[r].in[i] <== preMul.out[i];
            else        firstFull[r].in[i] <== firstFullOut[r-1][i];
        }
        for (var i = 0; i < 4; i++) firstFullOut[r][i] <== firstFull[r].out[i];
    }

    component partialR[56];
    signal partialOut[56][4];
    for (var r = 0; r < 56; r++) {
        partialR[r] = Poseidon2PartialRound(r);
        for (var i = 0; i < 4; i++) {
            if (r == 0) partialR[r].in[i] <== firstFullOut[3][i];
            else        partialR[r].in[i] <== partialOut[r-1][i];
        }
        for (var i = 0; i < 4; i++) partialOut[r][i] <== partialR[r].out[i];
    }

    component secondFull[4];
    signal secondFullOut[4][4];
    for (var r = 0; r < 4; r++) {
        secondFull[r] = Poseidon2FullRound(r, 1);
        for (var i = 0; i < 4; i++) {
            if (r == 0) secondFull[r].in[i] <== partialOut[55][i];
            else        secondFull[r].in[i] <== secondFullOut[r-1][i];
        }
        for (var i = 0; i < 4; i++) secondFullOut[r][i] <== secondFull[r].out[i];
    }

    for (var i = 0; i < 4; i++) out[i] <== secondFullOut[3][i];
}
