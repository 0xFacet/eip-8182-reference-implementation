// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Poseidon2Sponge} from "../src/libraries/Poseidon2Sponge.sol";

/// Assert that `Poseidon2Sponge.hash(...)` in Solidity matches every entry in
/// `assets/eip-8182/poseidon2_vectors.json` (which is produced by the bb.js
/// Poseidon2Hash API and also consumed by the Noir stdlib). If all three
/// implementations agree on every arity, the cross-implementation sponge is
/// byte-identical.
contract Poseidon2VectorParityTest is Test {
    using stdJson for string;

    function test_VectorsMatchSponge() public {
        string memory path = "../assets/eip-8182/poseidon2_vectors.json";
        string memory blob = vm.readFile(path);
        // Use the outputs array length as the vector count (the JSON has equal-length
        // inputs[] and output[] per entry under `.poseidonVectors`).
        bytes memory outputsBytes = blob.parseRaw(".poseidonVectors[*].output");
        bytes32[] memory outputs = abi.decode(outputsBytes, (bytes32[]));
        uint256 count = outputs.length;

        for (uint256 i; i < count; ++i) {
            bytes memory inputsBytes = blob.parseRaw(
                string.concat(".poseidonVectors[", vm.toString(i), "].inputs")
            );
            bytes32[] memory inputsB32 = abi.decode(inputsBytes, (bytes32[]));
            uint256[] memory inputs = new uint256[](inputsB32.length);
            for (uint256 j; j < inputsB32.length; ++j) {
                inputs[j] = uint256(inputsB32[j]);
            }

            uint256 expected = uint256(outputs[i]);
            uint256 actual = Poseidon2Sponge.hash(inputs);
            assertEq(actual, expected, string.concat("vector ", vm.toString(i), " mismatch"));

            // Assert each fixed-arity fast path agrees with the generic sponge at its own arity.
            // Catches lane-swap bugs in the hand-rolled absorb logic (hashPair/hash3/hash4/5/6)
            // that would otherwise slip past a hash(inputs)-only parity test.
            uint256 n = inputs.length;
            if (n == 2) {
                assertEq(
                    Poseidon2Sponge.hashPair(inputs[0], inputs[1]),
                    expected,
                    string.concat("hashPair mismatch at vector ", vm.toString(i))
                );
            } else if (n == 3) {
                assertEq(
                    Poseidon2Sponge.hash3(inputs[0], inputs[1], inputs[2]),
                    expected,
                    string.concat("hash3 mismatch at vector ", vm.toString(i))
                );
            } else if (n == 4) {
                assertEq(
                    Poseidon2Sponge.hash4(inputs[0], inputs[1], inputs[2], inputs[3]),
                    expected,
                    string.concat("hash4 mismatch at vector ", vm.toString(i))
                );
            } else if (n == 5) {
                assertEq(
                    Poseidon2Sponge.hash5(inputs[0], inputs[1], inputs[2], inputs[3], inputs[4]),
                    expected,
                    string.concat("hash5 mismatch at vector ", vm.toString(i))
                );
            } else if (n == 6) {
                assertEq(
                    Poseidon2Sponge.hash6(inputs[0], inputs[1], inputs[2], inputs[3], inputs[4], inputs[5]),
                    expected,
                    string.concat("hash6 mismatch at vector ", vm.toString(i))
                );
            }
        }
    }
}
