// Generic depth-N binary Merkle path verifier per spec Section 3.4.
// Internal node hash: poseidon(left, right) = arity-2 sponge.
//
// pathBits[h] (0 or 1) is the bit at height h that selects whether the
// running hash is the LEFT child (bit=0) or RIGHT child (bit=1).
//
// Caller is responsible for supplying pathBits in the right convention:
//   - LSB-first on leafIndex/leafPosition: pathBits[h] = (key >> h) & 1
//   - MSB-first on uint160(user)         : pathBits[h] = (key >> (DEPTH-1-h)) & 1
//
// Each pathBits[h] is constrained to be a bit (0 or 1).

pragma circom 2.0.0;

include "poseidon2_sponge.circom";

// One Merkle node: parent = poseidon(left, right). bit selects swap:
//   bit=0 -> (left,right) = (current, sibling)
//   bit=1 -> (left,right) = (sibling, current)
template MerkleNode() {
    signal input  current;
    signal input  sibling;
    signal input  bit;
    signal output parent;

    bit * (1 - bit) === 0;          // boolean

    // Branch swap. Use degree-1 selector trick:
    //   left  = current + bit * (sibling - current)
    //   right = sibling + bit * (current - sibling)
    signal left;
    signal right;
    signal diff;
    diff <== sibling - current;
    left  <== current + bit * diff;
    right <== sibling - bit * diff;

    component h = Poseidon2Sponge(2);
    h.in[0] <== left;
    h.in[1] <== right;
    parent <== h.out;
}

// Full depth-N path verifier: given a leaf, DEPTH path bits and DEPTH siblings,
// returns the computed root.
template MerklePath(DEPTH) {
    signal input  leaf;
    signal input  pathBits[DEPTH];
    signal input  siblings[DEPTH];
    signal output root;

    component nodes[DEPTH];
    signal     levelOut[DEPTH];

    for (var h = 0; h < DEPTH; h++) {
        nodes[h] = MerkleNode();
        if (h == 0) nodes[h].current <== leaf;
        else        nodes[h].current <== levelOut[h-1];
        nodes[h].sibling <== siblings[h];
        nodes[h].bit     <== pathBits[h];
        levelOut[h] <== nodes[h].parent;
    }

    root <== levelOut[DEPTH-1];
}
