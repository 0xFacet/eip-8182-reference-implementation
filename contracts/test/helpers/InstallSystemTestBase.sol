// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ShieldedPool} from "../../src/ShieldedPool.sol";
import {InstallSystemContractsBase} from "../../script/InstallSystemContracts.s.sol";
import {HonkVerifier} from "../generated/HonkVerifier.sol";
import {MockProofVerifierPrecompile} from "../mocks/MockProofVerifierPrecompile.sol";
import {RealProofVerifierPrecompile} from "../mocks/RealProofVerifierPrecompile.sol";

contract ShieldedPoolTestHarness is ShieldedPool {
    function seedAcceptedRootsForTest(
        uint256 commitmentRoot,
        uint256 userRegistryRoot,
        uint256 authPolicyRoot,
        uint256 snapshotBlock
    ) external {
        uint256 userSlot = snapshotBlock % (USER_REGISTRY_ROOT_HISTORY_BLOCKS + 1);
        uint256 authSlot = snapshotBlock % (AUTH_POLICY_ROOT_HISTORY_BLOCKS + 1);

        currentCommitmentRoot = commitmentRoot;
        currentUserRegistryRoot = userRegistryRoot;
        currentAuthPolicyRoot = authPolicyRoot;

        commitmentRootHistoryCount = 1;
        commitmentRootHistory[0] = commitmentRoot;

        userRegistryLastSnapshotBlock = snapshotBlock;
        userRegistryRootHistory[userSlot] = userRegistryRoot;
        userRegistryRootBlock[userSlot] = snapshotBlock;

        authPolicyLastSnapshotBlock = snapshotBlock;
        authPolicyRootHistory[authSlot] = authPolicyRoot;
        authPolicyRootBlock[authSlot] = snapshotBlock;
    }

    function setNextLeafIndexForTest(uint256 nextLeafIndex_) external {
        nextLeafIndex = nextLeafIndex_;
    }

    function setCommitmentRootHistoryCountForTest(uint256 commitmentRootHistoryCount_) external {
        commitmentRootHistoryCount = commitmentRootHistoryCount_;
    }

    function emptyHashCacheInitializedForTest() external view returns (bool) {
        return commitmentEmptyHashes[COMMITMENT_TREE_DEPTH - 1] != 0 && sparseEmptyHashes[REGISTRY_TREE_DEPTH - 1] != 0;
    }
}

abstract contract InstallSystemTestBase is InstallSystemContractsBase {
    string internal constant ZK_TRANSCRIPT_ARTIFACT_PATH = "out/HonkVerifier.sol/ZKTranscriptLib.json";
    address internal constant INSTALLER_DEPLOYER = 0x6f6aF94A8a2d5d5F52c1a7fe6F15D8a48Ea3D1A1;
    address internal constant PROOF_VERIFY_PRECOMPILE_ADDRESS = 0x0000000000000000000000000000000000000030;
    address internal constant VERIFIER_IMPLEMENTATION_ADDRESS = 0x0000000000000000000000000000000000008183;
    address internal constant ZK_TRANSCRIPT_LIBRARY_ADDRESS = 0x441DC930704671aa1F8b089739Eb4317e196f124;

    struct AcceptedRootsSeed {
        uint256 commitmentRoot;
        uint256 userRegistryRoot;
        uint256 authPolicyRoot;
        uint256 snapshotBlock;
    }

    function installSystem() internal returns (ShieldedPool pool) {
        install();
        _installRealVerifierSimulation();
        pool = ShieldedPool(POOL_ADDRESS);
    }

    function installMockSystem() internal returns (ShieldedPool pool) {
        install();
        vm.etch(PROOF_VERIFY_PRECOMPILE_ADDRESS, type(MockProofVerifierPrecompile).runtimeCode);
        pool = ShieldedPool(POOL_ADDRESS);
    }

    function acceptedRootSeed(ShieldedPool.PublicInputs memory publicInputs, uint256 snapshotBlock)
        internal
        pure
        returns (AcceptedRootsSeed memory seed)
    {
        seed.commitmentRoot = publicInputs.merkleRoot;
        seed.userRegistryRoot = publicInputs.registryRoot;
        seed.authPolicyRoot = publicInputs.authPolicyRegistryRoot;
        seed.snapshotBlock = snapshotBlock;
    }

    function applyAcceptedRootSeed(AcceptedRootsSeed memory seed) internal {
        bytes memory poolCode = _swapInTestHarness();
        vm.startPrank(INSTALLER_DEPLOYER);
        ShieldedPoolTestHarness(POOL_ADDRESS).seedAcceptedRootsForTest(
            seed.commitmentRoot, seed.userRegistryRoot, seed.authPolicyRoot, seed.snapshotBlock
        );
        vm.stopPrank();
        _restorePoolCode(poolCode);
    }

    function setNextLeafIndexForTest(uint256 nextLeafIndex_) internal {
        bytes memory poolCode = _swapInTestHarness();
        vm.startPrank(INSTALLER_DEPLOYER);
        ShieldedPoolTestHarness(POOL_ADDRESS).setNextLeafIndexForTest(nextLeafIndex_);
        vm.stopPrank();
        _restorePoolCode(poolCode);
    }

    function isEmptyHashCacheSeededForTest() internal returns (bool seeded) {
        bytes memory poolCode = _swapInTestHarness();
        vm.startPrank(INSTALLER_DEPLOYER);
        seeded = ShieldedPoolTestHarness(POOL_ADDRESS).emptyHashCacheInitializedForTest();
        vm.stopPrank();
        _restorePoolCode(poolCode);
    }

    function setCommitmentRootHistoryCountForTest(uint256 commitmentRootHistoryCount_) internal {
        bytes memory poolCode = _swapInTestHarness();
        vm.startPrank(INSTALLER_DEPLOYER);
        ShieldedPoolTestHarness(POOL_ADDRESS).setCommitmentRootHistoryCountForTest(commitmentRootHistoryCount_);
        vm.stopPrank();
        _restorePoolCode(poolCode);
    }

    function _swapInTestHarness() private returns (bytes memory poolCode) {
        poolCode = POOL_ADDRESS.code;
        require(poolCode.length != 0, "pool code missing");
        vm.etch(POOL_ADDRESS, type(ShieldedPoolTestHarness).runtimeCode);
    }

    function _restorePoolCode(bytes memory poolCode) private {
        vm.etch(POOL_ADDRESS, poolCode);
    }

    function _installRealVerifierSimulation() private {
        _ensureTranscriptLibraryCode();

        vm.startPrank(INSTALLER_DEPLOYER);
        HonkVerifier verifier = new HonkVerifier();
        bytes memory verifierCode = address(verifier).code;
        address adapter = address(new RealProofVerifierPrecompile(VERIFIER_IMPLEMENTATION_ADDRESS));
        vm.stopPrank();

        vm.etch(VERIFIER_IMPLEMENTATION_ADDRESS, verifierCode);
        vm.etch(PROOF_VERIFY_PRECOMPILE_ADDRESS, adapter.code);
    }

    function _ensureTranscriptLibraryCode() private {
        if (ZK_TRANSCRIPT_LIBRARY_ADDRESS.code.length != 0) return;

        bytes memory transcriptCode = _readArtifactBytes(ZK_TRANSCRIPT_ARTIFACT_PATH, ".deployedBytecode.object");
        _patchLibraryRuntimeAddress(transcriptCode, ZK_TRANSCRIPT_LIBRARY_ADDRESS);
        vm.etch(ZK_TRANSCRIPT_LIBRARY_ADDRESS, transcriptCode);
    }

    function _readArtifactBytes(string memory artifactPath, string memory key) private view returns (bytes memory value) {
        require(vm.exists(artifactPath), string.concat("missing artifact: ", artifactPath));
        string memory artifact = vm.readFile(artifactPath);
        value = vm.parseJsonBytes(artifact, key);
        require(value.length != 0, string.concat("empty artifact bytes: ", artifactPath));
    }

    function _patchLibraryRuntimeAddress(bytes memory runtimeCode, address libraryAddress) private pure {
        require(runtimeCode.length > 21, "short library runtime");
        require(runtimeCode[0] == bytes1(0x73), "unexpected library prefix");

        bytes20 addressBytes = bytes20(libraryAddress);
        for (uint256 i; i < 20; ++i) {
            runtimeCode[i + 1] = addressBytes[i];
        }
    }
}
