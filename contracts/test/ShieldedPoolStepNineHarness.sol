// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ShieldedPool} from "../src/ShieldedPool.sol";

/// @notice Test-only harness that exposes `_verifyPoolProof` directly.
///         Two callers converge on this hook:
///         1. Malformed-encoding negative tests — `verifyProof(pA, pB, pC,
///            pub)` cannot exercise wrong-length / garbage-byte cases because
///            the typed-array form has already passed the bytes-decode
///            boundary; the length check lives in `_verifyPoolProof`.
///         2. Step-9 gas measurement — the 256-byte calldata decode and
///            21-field `PublicInputs` repack on top of the raw `verifyProof`
///            cost. This is the path actually executed inside `transact`,
///            with `address(this)` already warm.
///
/// @dev    Etch at POOL_ADDRESS:
///             vm.etch(POOL_ADDRESS, type(ShieldedPoolStepNineHarness).runtimeCode);
contract ShieldedPoolStepNineHarness is ShieldedPool {
    function exposeVerifyPoolProof(bytes calldata proof, PublicInputs calldata pi) external view {
        _verifyPoolProof(proof, pi);
    }
}
