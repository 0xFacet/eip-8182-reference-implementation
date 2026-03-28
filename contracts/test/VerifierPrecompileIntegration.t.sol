// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {InstallSystemTestBase} from "./helpers/InstallSystemTestBase.sol";

contract VerifierPrecompileIntegrationTest is Test, InstallSystemTestBase {
    uint256 private constant FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    string private constant DEFAULT_FIXTURE_PATH = "test/.tmp-real-verifier-fixture.json";

    ShieldedPool private pool;
    bytes private proof;
    bytes32[] private fixturePublicInputs;
    bytes private fixtureNoteData0;
    bytes private fixtureNoteData1;
    bytes private fixtureNoteData2;

    function setUp() public {
        pool = installSystem();

        string memory fixturePath = vm.envOr("REAL_VERIFIER_FIXTURE_PATH", DEFAULT_FIXTURE_PATH);
        string memory fixtureJson = vm.readFile(fixturePath);
        proof = vm.parseJsonBytes(fixtureJson, ".proof");
        fixturePublicInputs = vm.parseJsonBytes32Array(fixtureJson, ".publicInputs");
        fixtureNoteData0 = vm.parseJsonBytes(fixtureJson, ".outputNoteData[0]");
        fixtureNoteData1 = vm.parseJsonBytes(fixtureJson, ".outputNoteData[1]");
        fixtureNoteData2 = vm.parseJsonBytes(fixtureJson, ".outputNoteData[2]");
    }

    function test_RealVerifierPrecompileAcceptsFixture() public view {
        ShieldedPool.PublicInputs memory publicInputs = _fixturePublicInputs();

        (bool success, bytes memory returnData) =
            PROOF_VERIFY_PRECOMPILE_ADDRESS.staticcall(abi.encode(proof, publicInputs));

        assertTrue(success);
        assertEq(returnData.length, 32);
        assertEq(abi.decode(returnData, (uint256)), 1);
    }

    function test_TransactUsesRealVerifierPrecompileWithSeededAcceptedRoots() public {
        ShieldedPool.PublicInputs memory publicInputs = _fixturePublicInputs();
        _assertFixtureNoteDataHashes(publicInputs);

        vm.chainId(publicInputs.executionChainId);
        vm.warp(publicInputs.validUntilSeconds - 1);

        applyAcceptedRootSeed(acceptedRootSeed(publicInputs, block.number));

        address depositor = address(uint160(publicInputs.depositorAddress));
        vm.deal(depositor, publicInputs.publicAmountIn + 1 ether);

        vm.prank(depositor);
        pool.transact{value: publicInputs.publicAmountIn}(
            proof, publicInputs, fixtureNoteData0, fixtureNoteData1, fixtureNoteData2
        );

        assertEq(address(pool).balance, publicInputs.publicAmountIn);
    }

    function _assertFixtureNoteDataHashes(ShieldedPool.PublicInputs memory publicInputs) private view {
        assertEq(_noteDataHash(fixtureNoteData0), publicInputs.outputNoteDataHash0);
        assertEq(_noteDataHash(fixtureNoteData1), publicInputs.outputNoteDataHash1);
        assertEq(_noteDataHash(fixtureNoteData2), publicInputs.outputNoteDataHash2);
    }

    function _fixturePublicInputs() private view returns (ShieldedPool.PublicInputs memory publicInputs) {
        assertEq(fixturePublicInputs.length, 19);

        publicInputs.merkleRoot = uint256(fixturePublicInputs[0]);
        publicInputs.nullifier0 = uint256(fixturePublicInputs[1]);
        publicInputs.nullifier1 = uint256(fixturePublicInputs[2]);
        publicInputs.commitment0 = uint256(fixturePublicInputs[3]);
        publicInputs.commitment1 = uint256(fixturePublicInputs[4]);
        publicInputs.commitment2 = uint256(fixturePublicInputs[5]);
        publicInputs.publicAmountIn = uint256(fixturePublicInputs[6]);
        publicInputs.publicAmountOut = uint256(fixturePublicInputs[7]);
        publicInputs.publicRecipientAddress = uint256(fixturePublicInputs[8]);
        publicInputs.publicTokenAddress = uint256(fixturePublicInputs[9]);
        publicInputs.depositorAddress = uint256(fixturePublicInputs[10]);
        publicInputs.intentNullifier = uint256(fixturePublicInputs[11]);
        publicInputs.registryRoot = uint256(fixturePublicInputs[12]);
        publicInputs.validUntilSeconds = uint256(fixturePublicInputs[13]);
        publicInputs.executionChainId = uint256(fixturePublicInputs[14]);
        publicInputs.authPolicyRegistryRoot = uint256(fixturePublicInputs[15]);
        publicInputs.outputNoteDataHash0 = uint256(fixturePublicInputs[16]);
        publicInputs.outputNoteDataHash1 = uint256(fixturePublicInputs[17]);
        publicInputs.outputNoteDataHash2 = uint256(fixturePublicInputs[18]);
    }

    function _noteDataHash(bytes memory noteData) private pure returns (uint256) {
        return uint256(keccak256(noteData)) % FIELD_MODULUS;
    }
}
