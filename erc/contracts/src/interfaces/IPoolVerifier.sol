// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IShieldedPoolStructs} from "./IShieldedPool.sol";

/// @notice Canonical stateless pool verifier (spec section 7.2). One singleton
///         instance per chain at CANONICAL_POOL_VERIFIER_ADDRESS; every
///         conforming pool verifies pool proofs via staticcall to it.
interface IPoolVerifier is IShieldedPoolStructs {
    function verifyPoolProof(
        bytes calldata proof,
        PublicInputs calldata publicInputs
    ) external view returns (bool);
}
