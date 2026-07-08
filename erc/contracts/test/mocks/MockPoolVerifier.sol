// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IPoolVerifier} from "../../src/interfaces/IPoolVerifier.sol";
import {IShieldedPoolStructs} from "../../src/interfaces/IShieldedPool.sol";

/// @notice Unit-test double for the canonical pool verifier. Returns a settable
///         bool; real proof verification is covered by CanonicalPoolVerifier.t.sol.
contract MockPoolVerifier is IPoolVerifier {
    bool internal _result = true;

    function setResult(bool result_) external {
        _result = result_;
    }

    function verifyPoolProof(bytes calldata, IShieldedPoolStructs.PublicInputs calldata)
        external
        view
        returns (bool)
    {
        return _result;
    }
}
