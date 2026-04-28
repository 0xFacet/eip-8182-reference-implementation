// JS Poseidon2 BN254 t=4 RF=8 RP=56 with the Section 3.3 length-tagged sponge.
// Loaded by both the witness generator and the helper library so off-circuit
// computations match the on-circuit and on-contract values.
//
// Re-export of scripts/witness/poseidon2.js for the public API surface.
module.exports = require("../../scripts/witness/poseidon2");
