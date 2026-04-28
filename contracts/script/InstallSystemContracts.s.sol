// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {CommonBase} from "forge-std/Base.sol";
import {Vm} from "forge-std/Vm.sol";
import {console2} from "forge-std/console2.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {PoseidonFieldLib} from "../src/libraries/PoseidonFieldLib.sol";

/// @notice One-time genesis-state initializer for ShieldedPool. Extends the
///         production contract with an `initialize()` selector that fills the
///         four empty-subtree caches (note tree, user-registry sparse, auth
///         registration, auth revocation sparse) and seeds the corresponding
///         current roots so the very first append produces the correct value.
///
///         The harness is etched at SHIELDED_POOL_ADDRESS, `initialize()` is
///         called, and then the production runtime code is etched back. The
///         resulting state dump is what gets installed at activation-fork
///         genesis (Section 5.1).
contract ShieldedPoolInstallHarness is ShieldedPool {
    function initialize() external {
        // Note tree (depth 32, append-only).
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

        // User-registry sparse tree (depth 160).
        userRegistrySparseEmptyHashes[0] = 0;
        for (uint256 i = 1; i < REGISTRY_TREE_DEPTH; ++i) {
            userRegistrySparseEmptyHashes[i] = PoseidonFieldLib.merkleHash(
                userRegistrySparseEmptyHashes[i - 1], userRegistrySparseEmptyHashes[i - 1]
            );
        }
        currentUserRegistryRoot = PoseidonFieldLib.merkleHash(
            userRegistrySparseEmptyHashes[REGISTRY_TREE_DEPTH - 1],
            userRegistrySparseEmptyHashes[REGISTRY_TREE_DEPTH - 1]
        );

        // Auth-policy registration tree (depth 32, append-only).
        authPolicyRegistrationEmptyHashes[0] = 0;
        for (uint256 i = 1; i < AUTH_POLICY_TREE_DEPTH; ++i) {
            authPolicyRegistrationEmptyHashes[i] = PoseidonFieldLib.merkleHash(
                authPolicyRegistrationEmptyHashes[i - 1], authPolicyRegistrationEmptyHashes[i - 1]
            );
        }
        currentAuthPolicyRegistrationRoot = PoseidonFieldLib.merkleHash(
            authPolicyRegistrationEmptyHashes[AUTH_POLICY_TREE_DEPTH - 1],
            authPolicyRegistrationEmptyHashes[AUTH_POLICY_TREE_DEPTH - 1]
        );

        // Auth-policy revocation sparse tree (depth 32).
        authPolicyRevocationSparseEmptyHashes[0] = 0;
        for (uint256 i = 1; i < AUTH_POLICY_TREE_DEPTH; ++i) {
            authPolicyRevocationSparseEmptyHashes[i] = PoseidonFieldLib.merkleHash(
                authPolicyRevocationSparseEmptyHashes[i - 1], authPolicyRevocationSparseEmptyHashes[i - 1]
            );
        }
        currentAuthPolicyRevocationRoot = PoseidonFieldLib.merkleHash(
            authPolicyRevocationSparseEmptyHashes[AUTH_POLICY_TREE_DEPTH - 1],
            authPolicyRevocationSparseEmptyHashes[AUTH_POLICY_TREE_DEPTH - 1]
        );
    }
}

abstract contract InstallSystemContractsBase is CommonBase {
    address internal constant POOL_ADDRESS = 0x0000000000000000000000000000000000081820;

    function install()
        internal
        returns (
            uint256 noteCommitmentRoot,
            uint256 userRegistryRoot,
            uint256 authPolicyRegistrationRoot,
            uint256 authPolicyRevocationRoot
        )
    {
        vm.etch(POOL_ADDRESS, type(ShieldedPoolInstallHarness).runtimeCode);
        ShieldedPoolInstallHarness(POOL_ADDRESS).initialize();
        vm.etch(POOL_ADDRESS, type(ShieldedPool).runtimeCode);
        vm.setNonce(POOL_ADDRESS, 1);
        return ShieldedPool(POOL_ADDRESS).getCurrentRoots();
    }

    function writeStateDump(string memory outputPath) internal {
        vm.dumpState(outputPath);
        _filterStateDumpToPool(outputPath);
        _prettifyJson(outputPath);
    }

    function _filterStateDumpToPool(string memory outputPath) private {
        string[] memory jqCommand = new string[](7);
        jqCommand[0] = "jq";
        jqCommand[1] = "--arg";
        jqCommand[2] = "poolAddress";
        jqCommand[3] = vm.toString(POOL_ADDRESS);
        jqCommand[4] = "--sort-keys";
        jqCommand[5] = "with_entries(select((.key | ascii_downcase) == ($poolAddress | ascii_downcase)))";
        jqCommand[6] = outputPath;
        Vm.FfiResult memory r = vm.tryFfi(jqCommand);
        require(r.exitCode == 0, "jq filter failed");
        vm.writeFile(outputPath, string(r.stdout));
    }

    function _prettifyJson(string memory outputPath) private {
        string[] memory jqCommand = new string[](4);
        jqCommand[0] = "jq";
        jqCommand[1] = "--sort-keys";
        jqCommand[2] = ".";
        jqCommand[3] = outputPath;
        Vm.FfiResult memory r = vm.tryFfi(jqCommand);
        require(r.exitCode == 0, "jq prettify failed");
        vm.writeFile(outputPath, string(r.stdout));
    }
}

contract InstallSystemContracts is Script, InstallSystemContractsBase {
    function run() public {
        string memory stateDumpPath =
            vm.envOr("STATE_DUMP_PATH", string("build/shielded-pool-state.json"));

        (
            uint256 noteCommitmentRoot,
            uint256 userRegistryRoot,
            uint256 authPolicyRegistrationRoot,
            uint256 authPolicyRevocationRoot
        ) = install();
        writeStateDump(stateDumpPath);

        console2.log("state dump:", stateDumpPath);
        console2.log("pool:", POOL_ADDRESS);
        console2.log("commitment root:", noteCommitmentRoot);
        console2.log("user registry root:", userRegistryRoot);
        console2.log("auth policy registration root:", authPolicyRegistrationRoot);
        console2.log("auth policy revocation root:", authPolicyRevocationRoot);
    }
}
