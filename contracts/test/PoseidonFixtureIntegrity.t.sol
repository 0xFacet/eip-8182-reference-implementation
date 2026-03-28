// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {InstallSystemContractsBase} from "../script/InstallSystemContracts.s.sol";

contract PoseidonFixtureIntegrityTest is Test, InstallSystemContractsBase {
    function test_FixtureMatchesMainnetPoseidonRuntimeWhenRpcConfigured() public {
        string memory rpcUrl = vm.envOr("RPC_MAINNET", string(""));
        if (bytes(rpcUrl).length == 0) return;

        uint256 forkId = vm.createSelectFork(rpcUrl);
        vm.selectFork(forkId);

        bytes memory mainnetCode = POSEIDON_LIBRARY_ADDRESS.code;
        require(mainnetCode.length != 0, "mainnet poseidon missing");

        string memory runtimeHex = vm.trim(vm.readFile(POSEIDON_RUNTIME_FIXTURE_PATH));
        bytes memory fixtureCode = vm.parseBytes(runtimeHex);

        assertEq(mainnetCode.length, fixtureCode.length);
        assertEq(keccak256(mainnetCode), keccak256(fixtureCode));
    }
}
