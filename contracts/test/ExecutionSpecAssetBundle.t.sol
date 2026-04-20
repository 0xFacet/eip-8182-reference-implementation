// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {InstallSystemTestBase} from "./helpers/InstallSystemTestBase.sol";

contract ExecutionSpecAssetBundleTest is Test, InstallSystemTestBase {
    string private constant HAPPY_PATH_ASSET = "../assets/eip-8182/outer_precompile_happy_path.json";
    string private constant INVALID_PROOF_ASSET = "../assets/eip-8182/outer_precompile_invalid_proof.json";
    string private constant MALFORMED_INPUT_ASSET = "../assets/eip-8182/outer_precompile_malformed_input.json";
    string private constant NON_CANONICAL_PRECOMPILE_ASSET =
        "../assets/eip-8182/outer_precompile_noncanonical_field.json";

    function test_CommittedHappyPathVectorIsAcceptedByPrecompileSimulation() public {
        installSystem();
        _assertPrecompileVector(HAPPY_PATH_ASSET);
    }

    function test_CommittedInvalidProofVectorReturnsEmptyBytes() public {
        installSystem();
        _assertPrecompileVector(INVALID_PROOF_ASSET);
    }

    function test_CommittedMalformedInputVectorReturnsEmptyBytes() public {
        installSystem();
        _assertPrecompileVector(MALFORMED_INPUT_ASSET);
    }

    function test_CommittedNonCanonicalFieldVectorReturnsEmptyBytes() public {
        installSystem();
        _assertPrecompileVector(NON_CANONICAL_PRECOMPILE_ASSET);
    }

    function _assertPrecompileVector(string memory assetPath) private view {
        string memory fixtureJson = vm.readFile(assetPath);
        bytes memory precompileInput = vm.parseJsonBytes(fixtureJson, ".precompileInput");
        bytes memory expectedReturnData = vm.parseJsonBytes(fixtureJson, ".expectedReturnData");

        (bool success, bytes memory returnData) = PROOF_VERIFY_PRECOMPILE_ADDRESS.staticcall(precompileInput);

        assertTrue(success);
        assertEq(returnData, expectedReturnData);
    }
}
