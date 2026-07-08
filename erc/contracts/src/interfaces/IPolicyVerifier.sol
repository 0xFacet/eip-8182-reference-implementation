// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Optional pool-level policy verifier (spec section 16.1). The pool
///         staticcalls verifyPolicy with publicInputs =
///         abi.encode(policyOperationDigest).
interface IPolicyVerifier {
    function verifyPolicy(
        bytes calldata publicInputs,
        bytes calldata policyData
    ) external view returns (bool);
}
