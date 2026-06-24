// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ShieldedPool} from "contracts/src/ShieldedPool.sol";
import {PoseidonFieldLib} from "contracts/src/libraries/PoseidonFieldLib.sol";

/// @notice Deployable demo variant of ShieldedPool with genesis state seeded in
///         the constructor instead of by the activation-fork state dump.
contract DemoShieldedPool is ShieldedPool {
    constructor() {
        _initializeGenesisState();
    }

    function _initializeGenesisState() private {
        noteCommitmentEmptyHashes[0] = 0;
        for (uint256 i = 1; i < COMMITMENT_TREE_DEPTH; ++i) {
            noteCommitmentEmptyHashes[i] = PoseidonFieldLib.merkleHash(
                noteCommitmentEmptyHashes[i - 1], noteCommitmentEmptyHashes[i - 1]
            );
        }
        currentNoteCommitmentRoot = PoseidonFieldLib.merkleHash(
            noteCommitmentEmptyHashes[COMMITMENT_TREE_DEPTH - 1],
            noteCommitmentEmptyHashes[COMMITMENT_TREE_DEPTH - 1]
        );

        authPolicySparseEmptyHashes[0] = 0;
        for (uint256 i = 1; i < AUTH_POLICY_TREE_DEPTH; ++i) {
            authPolicySparseEmptyHashes[i] = PoseidonFieldLib.merkleHash(
                authPolicySparseEmptyHashes[i - 1], authPolicySparseEmptyHashes[i - 1]
            );
        }
        currentAuthPolicyRoot = PoseidonFieldLib.merkleHash(
            authPolicySparseEmptyHashes[AUTH_POLICY_TREE_DEPTH - 1],
            authPolicySparseEmptyHashes[AUTH_POLICY_TREE_DEPTH - 1]
        );

        nextLeafPosition = 1;
    }
}
