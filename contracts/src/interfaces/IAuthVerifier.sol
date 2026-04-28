// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice EIP-8182 Section 12 auth verifier interface. The system contract
///         calls `verifyAuth` via `staticcall` after the pool proof has been
///         verified. `publicInputs` is exactly
///         `abi.encode(blindedAuthCommitment, transactionIntentDigest)`,
///         taken from the pool proof's public-input vector.
interface IAuthVerifier {
    function verifyAuth(bytes calldata publicInputs, bytes calldata proof)
        external
        view
        returns (bool);
}
