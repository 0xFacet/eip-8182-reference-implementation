// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {LibPoseidon2Permute} from "./LibPoseidon2Permute.sol";

/// @notice Poseidon2 length-tagged sponge hash over BN254.
/// @dev Matches the normative `poseidon(x_1, ..., x_N) = Poseidon2_sponge(x_1, ..., x_N)`
///      construction in EIP-8182 §3.3. Initial state is `[0, 0, 0, N << 64]`; for N>0
///      the inputs are partitioned into ⌈N/3⌉ chunks (final chunk zero-padded if N mod 3 != 0),
///      and each chunk is absorbed into state[0..2] via field addition then followed by one
///      Poseidon2 permutation. For N=0 a single permutation is applied to the initial state.
///      Output is state[0].
///
///      The 2-input form `hashPair(a, b)` is used for Merkle tree internal nodes. It is the
///      length-tagged sponge form `[a, b, 0, 2 << 64]`, NOT the bare-permutation
///      `[a, b, 0, 0]` used by some Poseidon2 Merkle tree libraries.
library Poseidon2Sponge {
    uint256 private constant FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice Hash two inputs via the length-tagged sponge form — the canonical 2-input
    ///         hash used for Merkle tree internal nodes.
    function hashPair(uint256 a, uint256 b) internal pure returns (uint256) {
        (uint256 r0, , , ) = LibPoseidon2Permute.permute4(a, b, 0, 2 << 64);
        return r0;
    }

    /// @notice Hash three inputs in a single permutation.
    function hash3(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) {
        (uint256 r0, , , ) = LibPoseidon2Permute.permute4(a, b, c, 3 << 64);
        return r0;
    }

    /// @notice Variadic sponge hash. For N ≤ 3 invokes a single permutation; for N > 3
    ///         chains permutations via `permute4`.
    function hash(uint256[] memory inputs) internal pure returns (uint256) {
        uint256 n = inputs.length;
        uint256 s0;
        uint256 s1;
        uint256 s2;
        uint256 s3 = n << 64;

        if (n == 0) {
            (s0, , , ) = LibPoseidon2Permute.permute4(0, 0, 0, s3);
            return s0;
        }

        uint256 i = 0;
        // Absorb full rate-3 chunks
        while (i + 3 <= n) {
            s0 = addmod(s0, inputs[i], FIELD_MODULUS);
            s1 = addmod(s1, inputs[i + 1], FIELD_MODULUS);
            s2 = addmod(s2, inputs[i + 2], FIELD_MODULUS);
            (s0, s1, s2, s3) = LibPoseidon2Permute.permute4(s0, s1, s2, s3);
            i += 3;
        }

        // Handle trailing partial chunk (zero-padded)
        uint256 remainder = n - i;
        if (remainder != 0) {
            s0 = addmod(s0, inputs[i], FIELD_MODULUS);
            if (remainder > 1) {
                s1 = addmod(s1, inputs[i + 1], FIELD_MODULUS);
            }
            (s0, s1, s2, s3) = LibPoseidon2Permute.permute4(s0, s1, s2, s3);
        }

        return s0;
    }

    /// @notice Fixed-arity fast path for 4-element inputs (avoids allocating a memory array).
    function hash4(uint256 a, uint256 b, uint256 c, uint256 d) internal pure returns (uint256) {
        uint256 s3 = 4 << 64;
        (uint256 s0, uint256 s1, uint256 s2, uint256 ns3) = LibPoseidon2Permute.permute4(a, b, c, s3);
        s0 = addmod(s0, d, FIELD_MODULUS);
        (s0, , , ) = LibPoseidon2Permute.permute4(s0, s1, s2, ns3);
        return s0;
    }

    /// @notice Fixed-arity fast path for 5-element inputs.
    function hash5(uint256 a, uint256 b, uint256 c, uint256 d, uint256 e) internal pure returns (uint256) {
        uint256 s3 = 5 << 64;
        (uint256 s0, uint256 s1, uint256 s2, uint256 ns3) = LibPoseidon2Permute.permute4(a, b, c, s3);
        s0 = addmod(s0, d, FIELD_MODULUS);
        s1 = addmod(s1, e, FIELD_MODULUS);
        (s0, , , ) = LibPoseidon2Permute.permute4(s0, s1, s2, ns3);
        return s0;
    }

    /// @notice Fixed-arity fast path for 6-element inputs.
    function hash6(uint256 a, uint256 b, uint256 c, uint256 d, uint256 e, uint256 f) internal pure returns (uint256) {
        uint256 s3 = 6 << 64;
        (uint256 s0, uint256 s1, uint256 s2, uint256 ns3) = LibPoseidon2Permute.permute4(a, b, c, s3);
        s0 = addmod(s0, d, FIELD_MODULUS);
        s1 = addmod(s1, e, FIELD_MODULUS);
        s2 = addmod(s2, f, FIELD_MODULUS);
        (s0, , , ) = LibPoseidon2Permute.permute4(s0, s1, s2, ns3);
        return s0;
    }
}
