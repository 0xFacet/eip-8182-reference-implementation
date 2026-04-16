// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, stdJson} from "forge-std/Test.sol";
import {InstallSystemContracts} from "../script/InstallSystemContracts.s.sol";
import {InstallSystemTestBase} from "./helpers/InstallSystemTestBase.sol";

contract InstallSystemContractsScriptTest is Test, InstallSystemTestBase {
    using stdJson for string;

    string private constant POOL_KEY = "0x0000000000000000000000000000000000081820";

    string private constant MANIFEST_PATH = "script-output/test-install.json";
    string private constant STATE_DUMP_PATH = "script-output/test-state.json";

    function test_RunInstallsSystemContractsAndWritesArtifacts() public {
        vm.setEnv("INSTALL_MANIFEST_PATH", MANIFEST_PATH);
        vm.setEnv("STATE_DUMP_PATH", STATE_DUMP_PATH);

        InstallSystemContracts installer = new InstallSystemContracts();
        installer.run();

        assertTrue(vm.exists(MANIFEST_PATH));
        assertTrue(vm.exists(STATE_DUMP_PATH));

        assertGt(POOL_ADDRESS.code.length, 0);
        assertEq(vm.getNonce(POOL_ADDRESS), 1);

        string memory manifest = vm.readFile(MANIFEST_PATH);
        assertEq(manifest.readAddress(".poolAddress"), POOL_ADDRESS);
        assertEq(manifest.readUint(".poolCodeSize"), POOL_ADDRESS.code.length);
        assertEq(manifest.readBytes32(".poolCodeHash"), keccak256(POOL_ADDRESS.code));
        assertGt(manifest.readUint(".derivedRoots.noteCommitmentRoot"), 0);

        string memory stateDump = vm.readFile(STATE_DUMP_PATH);
        string[] memory rootKeys = vm.parseJsonKeys(stateDump, ".");
        assertEq(rootKeys.length, 1);
        assertTrue(_containsString(rootKeys, POOL_KEY));
    }

    function _containsString(string[] memory values, string memory needle) private pure returns (bool) {
        for (uint256 i; i < values.length; ++i) {
            if (keccak256(bytes(values[i])) == keccak256(bytes(needle))) return true;
        }
        return false;
    }
}
