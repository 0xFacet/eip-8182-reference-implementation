// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {CommonBase} from "forge-std/Base.sol";
import {Vm} from "forge-std/Vm.sol";
import {console2} from "forge-std/console2.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {PoseidonFieldLib} from "../src/libraries/PoseidonFieldLib.sol";

contract ShieldedPoolInstallHarness is ShieldedPool {
    function initialize() external {
        uint256 noteCommitmentRoot = _deriveEmptyRoot(COMMITMENT_TREE_DEPTH);
        uint256 userRegistryRoot = _deriveEmptyRoot(REGISTRY_TREE_DEPTH);
        uint256 authPolicyRoot = userRegistryRoot;

        _seedEmptyHashCache();
        currentNoteCommitmentRoot = noteCommitmentRoot;
        currentUserRegistryRoot = userRegistryRoot;
        currentAuthPolicyRoot = authPolicyRoot;
    }

    function _seedEmptyHashCache() private {
        noteCommitmentEmptyHashes[0] = 0;
        for (uint256 level = 1; level < COMMITMENT_TREE_DEPTH; ++level) {
            noteCommitmentEmptyHashes[level] =
                PoseidonFieldLib.hash2Raw(noteCommitmentEmptyHashes[level - 1], noteCommitmentEmptyHashes[level - 1]);
        }

        sparseEmptyHashes[0] = 0;
        for (uint256 level = 1; level < REGISTRY_TREE_DEPTH; ++level) {
            sparseEmptyHashes[level] =
                PoseidonFieldLib.hash2Raw(sparseEmptyHashes[level - 1], sparseEmptyHashes[level - 1]);
        }
    }

    function _deriveEmptyRoot(uint256 depth) private pure returns (uint256 root) {
        for (uint256 level; level < depth; ++level) {
            root = PoseidonFieldLib.hash2Raw(root, root);
        }
    }
}

abstract contract InstallSystemContractsBase is CommonBase {
    uint256 internal constant INSTALL_COMMITMENT_TREE_DEPTH = 32;
    uint256 internal constant INSTALL_REGISTRY_TREE_DEPTH = 160;
    address internal constant POOL_ADDRESS = 0x0000000000000000000000000000000000081820;
    address internal constant POSEIDON_LIBRARY_ADDRESS = 0x3333333C0A88F9BE4fd23ed0536F9B6c427e3B93;
    string internal constant POSEIDON_RUNTIME_FIXTURE_PATH = "test/fixtures/poseidon_t3_runtime.hex";

    function install() internal returns (uint256 noteCommitmentRoot, uint256 userRegistryRoot, uint256 authPolicyRoot) {
        _installPoseidonLibrary();
        _initializePool();
        (noteCommitmentRoot, userRegistryRoot, authPolicyRoot) = ShieldedPool(POOL_ADDRESS).getCurrentRoots();
        _assertExpectedRoots(noteCommitmentRoot, userRegistryRoot, authPolicyRoot);
    }

    function writeManifest(
        uint256 noteCommitmentRoot,
        uint256 userRegistryRoot,
        uint256 authPolicyRoot,
        string memory outputPath
    ) internal {
        bytes memory poolCode = POOL_ADDRESS.code;
        string memory manifestKey = "manifest";
        vm.serializeJson(manifestKey, "{}");
        vm.serializeAddress(manifestKey, "poolAddress", POOL_ADDRESS);
        vm.serializeUint(manifestKey, "installBlockNumber", block.number);
        vm.serializeBytes32(manifestKey, "poolCodeHash", bytes32(keccak256(poolCode)));
        string memory manifestJson = vm.serializeUint(manifestKey, "poolCodeSize", poolCode.length);
        vm.writeJson(manifestJson, outputPath);
        vm.writeJson(_derivedRootsJson(noteCommitmentRoot, userRegistryRoot, authPolicyRoot), outputPath, ".derivedRoots");
        _prettifyJson(outputPath);
    }

    function writeStateDump(string memory outputPath) internal {
        vm.dumpState(outputPath);
        _filterStateDumpToPool(outputPath);
        _prettifyJson(outputPath);
    }

    function _initializePool() private {
        vm.etch(POOL_ADDRESS, type(ShieldedPoolInstallHarness).runtimeCode);
        ShieldedPoolInstallHarness(POOL_ADDRESS).initialize();
        vm.etch(POOL_ADDRESS, type(ShieldedPool).runtimeCode);
        vm.setNonce(POOL_ADDRESS, 1);
    }

    function _installPoseidonLibrary() internal {
        string memory poseidonRuntimeHex = vm.trim(vm.readFile(POSEIDON_RUNTIME_FIXTURE_PATH));
        bytes memory poseidonCode = vm.parseBytes(poseidonRuntimeHex);
        require(poseidonCode.length != 0, "empty poseidon code");
        vm.etch(POSEIDON_LIBRARY_ADDRESS, poseidonCode);
    }

    function _assertExpectedRoots(uint256 noteCommitmentRoot, uint256 userRegistryRoot, uint256 authPolicyRoot) private pure {
        uint256 expectedCommitmentRoot = _deriveEmptyRoot(INSTALL_COMMITMENT_TREE_DEPTH);
        uint256 expectedSparseRoot = _deriveEmptyRoot(INSTALL_REGISTRY_TREE_DEPTH);

        require(noteCommitmentRoot == expectedCommitmentRoot, "unexpected commitment root");
        require(userRegistryRoot == expectedSparseRoot, "unexpected user registry root");
        require(authPolicyRoot == expectedSparseRoot, "unexpected auth policy root");
    }

    function _deriveEmptyRoot(uint256 depth) private pure returns (uint256 root) {
        for (uint256 level; level < depth; ++level) {
            root = PoseidonFieldLib.hash2Raw(root, root);
        }
    }

    function _derivedRootsJson(uint256 noteCommitmentRoot, uint256 userRegistryRoot, uint256 authPolicyRoot)
        private
        returns (string memory derivedRoots)
    {
        string memory derivedRootsKey = "derivedRoots";
        vm.serializeJson(derivedRootsKey, "{}");
        vm.serializeUint(derivedRootsKey, "noteCommitmentRoot", noteCommitmentRoot);
        vm.serializeUint(derivedRootsKey, "userRegistryRoot", userRegistryRoot);
        derivedRoots = vm.serializeUint(derivedRootsKey, "authPolicyRoot", authPolicyRoot);
    }

    function _prettifyJson(string memory outputPath) private {
        string[] memory jqCommand = new string[](4);
        jqCommand[0] = "jq";
        jqCommand[1] = "--sort-keys";
        jqCommand[2] = ".";
        jqCommand[3] = outputPath;
        Vm.FfiResult memory jqResult = vm.tryFfi(jqCommand);
        require(jqResult.exitCode == 0, string.concat("jq failed for ", outputPath));
        vm.writeFile(outputPath, string(jqResult.stdout));
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
        Vm.FfiResult memory jqResult = vm.tryFfi(jqCommand);
        require(jqResult.exitCode == 0, string.concat("jq filter failed for ", outputPath));
        vm.writeFile(outputPath, string(jqResult.stdout));
    }
}

contract InstallSystemContracts is Script, InstallSystemContractsBase {
    function run() public {
        string memory manifestPath = _envManifestPath();
        string memory stateDumpPath = _envStateDumpPath();
        (uint256 noteCommitmentRoot, uint256 userRegistryRoot, uint256 authPolicyRoot) =
            install();
        writeManifest(noteCommitmentRoot, userRegistryRoot, authPolicyRoot, manifestPath);
        writeStateDump(stateDumpPath);
        _logInstall(noteCommitmentRoot, userRegistryRoot, authPolicyRoot, manifestPath, stateDumpPath);
    }

    function _envManifestPath() internal view returns (string memory) {
        return vm.envOr("INSTALL_MANIFEST_PATH", string("script-output/shielded-pool-install.json"));
    }

    function _envStateDumpPath() internal view returns (string memory) {
        return vm.envOr("STATE_DUMP_PATH", string("script-output/shielded-pool-state.json"));
    }

    function _logInstall(
        uint256 noteCommitmentRoot,
        uint256 userRegistryRoot,
        uint256 authPolicyRoot,
        string memory manifestPath,
        string memory stateDumpPath
    ) internal pure {
        console2.log("manifest:", manifestPath);
        console2.log("state dump:", stateDumpPath);
        console2.log("pool:", POOL_ADDRESS);
        console2.log("commitment root:", noteCommitmentRoot);
        console2.log("user registry root:", userRegistryRoot);
        console2.log("auth policy root:", authPolicyRoot);
    }
}
