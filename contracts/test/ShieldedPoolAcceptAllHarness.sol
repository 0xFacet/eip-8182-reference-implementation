// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ShieldedPool} from "../src/ShieldedPool.sol";

/// @notice Test-only harness that no-ops `_verifyPoolProof`. Used by tests
///         that exercise non-verification logic (state transitions, public
///         action dispatch, error paths after step 9) and don't have a real
///         Groth16 proof at hand.
///
/// @dev    Etch the runtime code at POOL_ADDRESS:
///             vm.etch(POOL_ADDRESS, type(ShieldedPoolAcceptAllHarness).runtimeCode);
///         The merged contract exceeds EIP-170, so `new` would revert with
///         CreateContractSizeLimit. The runtime-code etch matches how
///         InstallSystemContracts.s.sol installs the production ShieldedPool.
contract ShieldedPoolAcceptAllHarness is ShieldedPool {
    function _verifyPoolProof(bytes calldata, PublicInputs calldata) internal pure override {}
}
