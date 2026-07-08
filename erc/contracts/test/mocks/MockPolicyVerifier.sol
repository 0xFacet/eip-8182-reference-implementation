// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IPolicyVerifier} from "../../src/interfaces/IPolicyVerifier.sol";

/// @notice Unit-test double for a section 16.1 policy verifier.
/// @dev    The pool dispatches via `staticcall`, so the verifier cannot persist
///         the digest it receives (SSTORE is forbidden in the static context).
///         Tests therefore assert the exact dispatched digest with
///         `vm.expectCall`. This mock exposes `decodeDigest` (the value the pool
///         passes as `abi.encode(policyOperationDigest)`) and a `strict` mode
///         that returns false unless the decoded digest equals `expectedDigest`,
///         which lets a test prove the pool dispatched the exact digest even
///         without expectCall.
contract MockPolicyVerifier is IPolicyVerifier {
    bool internal _result = true;
    bool internal _strict;
    uint256 internal _expectedDigest;

    function setResult(bool result_) external {
        _result = result_;
    }

    /// @notice When enabled, verifyPolicy returns false for any digest other
    ///         than `expected`.
    function setExpectedDigest(uint256 expected) external {
        _strict = true;
        _expectedDigest = expected;
    }

    function decodeDigest(bytes calldata publicInputs) external pure returns (uint256) {
        return abi.decode(publicInputs, (uint256));
    }

    function verifyPolicy(bytes calldata publicInputs, bytes calldata) external view returns (bool) {
        if (_strict && abi.decode(publicInputs, (uint256)) != _expectedDigest) {
            return false;
        }
        return _result;
    }
}
