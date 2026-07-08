// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Pluggable auth verifier (spec section 7.5). The pool staticcalls
///         verifyAuth with publicInputs = abi.encode(blindedAuthCommitment,
///         transactionIntentDigest). Declared `view` because the pool dispatches
///         it via staticcall; a state-modifying implementation reverts and is
///         treated as an auth proof failure.
interface IAuthVerifier {
    function verifyAuth(
        bytes calldata publicInputs,
        bytes calldata proof
    ) external view returns (bool);
}
