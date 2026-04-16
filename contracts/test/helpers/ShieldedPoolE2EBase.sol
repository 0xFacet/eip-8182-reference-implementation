// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ShieldedPool} from "../../src/ShieldedPool.sol";
import {PoseidonFieldLib} from "../../src/libraries/PoseidonFieldLib.sol";
import {InstallSystemTestBase} from "./InstallSystemTestBase.sol";

abstract contract ShieldedPoolE2EBase is Test, InstallSystemTestBase {
    uint256 internal constant TREE_DEPTH = 32;
    uint256 internal constant REGISTRY_TREE_DEPTH = 160;
    uint256 internal constant FIELD_SIZE =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint32 internal constant DELIVERY_SCHEME_ID = 1;
    uint256 internal constant DEPOSIT_AMOUNT = 1 ether;
    uint256 internal constant TRANSFER_AMOUNT = 0.35 ether;
    uint256 internal constant WITHDRAW_AMOUNT = 0.4 ether;
    uint256 internal constant RECOVERED_WITHDRAW_AMOUNT = 0.2 ether;

    address internal constant ALICE = 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf;
    address internal constant BOB = 0x14791697260E4c9A71f18484C9f997B308e59325;
    uint256 internal constant NK = 0x9999;
    uint256 internal constant OS = 0xbeef;
    uint256 internal constant DS = 0xcafe;
    uint256 internal constant BOB_NK = 0x7777;
    uint256 internal constant BOB_OS = 0xd00d;
    uint256 internal constant BOB_DS = 0xf00d;

    string internal constant ALICE_SIGNING_PRIVATE_KEY =
        "0x0000000000000000000000000000000000000000000000000000000000000001";
    string internal constant BOB_SIGNING_PRIVATE_KEY =
        "0x0123456789012345678901234567890123456789012345678901234567890123";
    string internal constant MULTISIG_SIGNING_PRIVATE_KEY_0 =
        "0x1111111111111111111111111111111111111111111111111111111111111111";
    string internal constant MULTISIG_SIGNING_PRIVATE_KEY_1 =
        "0x2222222222222222222222222222222222222222222222222222222222222222";
    string internal constant MULTISIG_SIGNING_PRIVATE_KEY_2 =
        "0x3333333333333333333333333333333333333333333333333333333333333333";

    struct PreparedUser {
        uint256 ownerNullifierKeyHash;
        uint256 noteSecretSeedHash;
        uint256 authDataCommitment;
        uint256 innerVkHash;
        bytes deliveryPubKey;
    }

    struct PreparedAuthPolicy {
        uint256 authDataCommitment;
        uint256 innerVkHash;
    }

    struct UserSecrets {
        address account;
        uint256 ownerNullifierKey;
        uint256 noteSecretSeed;
        uint256 deliverySecret;
        string signingPrivateKey;
    }

    struct ProofFixture {
        bytes proof;
        ShieldedPool.PublicInputs pubInputs;
        bytes noteData0;
        bytes noteData1;
        bytes noteData2;
        uint256 note0Amount;
        uint256 note0NoteSecret;
        uint256 note0OriginTag;
        uint256 note1Amount;
        uint256 note1NoteSecret;
        uint256 note1OriginTag;
    }

    struct TransferRequest {
        uint256 policyVersion;
        uint256 commitRoot;
        uint256 userRegRoot;
        uint256 authPolicyRoot;
        uint256 inputLeafIndex;
        uint256 inputAmount;
        uint256 inputNoteSecret;
        uint256 inputOriginTag;
        address recipient;
        uint256 recipientOwnerNullifierKeyHash;
        uint256 recipientNoteSecretSeedHash;
        uint256 transferAmount;
        uint256 changeAmount;
        uint256[TREE_DEPTH] inputSiblings;
        uint256[REGISTRY_TREE_DEPTH] userSiblings;
        uint256[REGISTRY_TREE_DEPTH] recipientSiblings;
    }

    struct WithdrawRequest {
        uint256 policyVersion;
        uint256 commitRoot;
        uint256 userRegRoot;
        uint256 authPolicyRoot;
        uint256 inputLeafIndex;
        uint256 inputAmount;
        uint256 inputNoteSecret;
        uint256 inputOriginTag;
        address publicRecipient;
        uint256 withdrawAmount;
        uint256[TREE_DEPTH] inputSiblings;
        uint256[REGISTRY_TREE_DEPTH] userSiblings;
    }

    struct RecoveredNote {
        bool found;
        uint256 commitment;
        uint256 leafIndex;
        uint256 amount;
        uint256 ownerAddress;
        uint256 noteSecret;
        uint256 ownerNullifierKeyHash;
        uint256 tokenAddress;
        uint256 originTag;
    }

    struct SyncedTransactFixture {
        uint256 leafIndex0;
        ProofFixture fixture;
    }

    struct PoolStorageLayout {
        uint256 nextLeafIndexSlot;
        uint256 userTreeNodesSlot;
        uint256 authTreeNodesSlot;
    }

    ShieldedPool internal pool;
    PoolStorageLayout internal poolStorageLayout;

    function setUp() public virtual {
        pool = installSystem();
        _loadPoolStorageLayout();
    }

    function _assertAndExecuteDepositFixture(ProofFixture memory fixture) internal {
        assertEq(fixture.pubInputs.noteCommitmentRoot, _currentNoteCommitmentRoot(), "commit root");
        assertEq(fixture.pubInputs.registryRoot, _currentUserRegistryRoot(), "user root");
        assertEq(fixture.pubInputs.authPolicyRegistryRoot, _currentAuthPolicyRoot(), "auth root");
        assertEq(fixture.noteData0.length, 1328, "note0 ciphertext length");
        assertEq(fixture.noteData1.length, 1328, "note1 ciphertext length");
        assertEq(fixture.noteData2.length, 1328, "note2 ciphertext length");
        assertGt(fixture.note0Amount, 0, "deposit recipient note amount");

        vm.chainId(fixture.pubInputs.executionChainId);
        vm.warp(fixture.pubInputs.validUntilSeconds - 100);

        vm.deal(ALICE, 3 ether);
        bytes memory tamperedNoteData = abi.encodePacked(fixture.noteData0, bytes1(0x01));
        vm.expectRevert(abi.encodeWithSelector(ShieldedPool.InvalidOutputNoteDataHash.selector, uint8(0)));
        vm.prank(ALICE);
        pool.transact{value: fixture.pubInputs.publicAmountIn}(
            fixture.proof, fixture.pubInputs, tamperedNoteData, fixture.noteData1, fixture.noteData2
        );

        _assertVerifierAccepts(fixture);
        _executeDepositFixture(fixture);

        assertEq(_nextLeafIndex(), 3, "3 commitments inserted");
        assertEq(address(pool).balance, DEPOSIT_AMOUNT, "pool has deposit");
        assertEq(_noteDataHash(fixture.noteData0), fixture.pubInputs.outputNoteDataHash0, "noteData0 hash mismatch");

        vm.expectRevert(ShieldedPool.NullifierAlreadySpent.selector);
        vm.prank(ALICE);
        pool.transact{value: fixture.pubInputs.publicAmountIn}(
            fixture.proof, fixture.pubInputs, fixture.noteData0, fixture.noteData1, fixture.noteData2
        );
    }

    function _registerAlice(PreparedUser memory user) internal returns (uint256 currentPolicyVersion) {
        vm.prank(ALICE);
        pool.registerUser(user.ownerNullifierKeyHash, user.noteSecretSeedHash, DELIVERY_SCHEME_ID, user.deliveryPubKey);

        (uint32 schemeId, bytes memory storedDeliveryKey) = pool.getDeliveryKey(ALICE);
        assertEq(schemeId, DELIVERY_SCHEME_ID, "delivery scheme stored");
        assertEq(keccak256(storedDeliveryKey), keccak256(user.deliveryPubKey), "delivery key stored");

        currentPolicyVersion = _registerAuthPolicy(ALICE, user.innerVkHash, user.authDataCommitment);
        assertEq(currentPolicyVersion, 1, "policy version");
    }

    function _registerUserWithoutAuth(address account, PreparedUser memory user) internal {
        vm.prank(account);
        pool.registerUser(user.ownerNullifierKeyHash, user.noteSecretSeedHash, DELIVERY_SCHEME_ID, user.deliveryPubKey);

        (uint32 schemeId, bytes memory storedDeliveryKey) = pool.getDeliveryKey(account);
        assertEq(schemeId, DELIVERY_SCHEME_ID, "delivery scheme stored");
        assertEq(keccak256(storedDeliveryKey), keccak256(user.deliveryPubKey), "delivery key stored");
    }

    function _deriveTestUser(
        uint256 ownerNullifierKey,
        uint256 noteSecretSeed,
        uint256 deliverySecret,
        string memory signingPrivateKey
    ) internal returns (PreparedUser memory user) {
        string memory params = string(
            abi.encodePacked(
                '{"ownerNullifierKey":"',
                vm.toString(ownerNullifierKey),
                '","noteSecretSeed":"',
                vm.toString(noteSecretSeed),
                '","deliverySecret":"',
                vm.toString(deliverySecret),
                '","signingPrivateKey":"',
                signingPrivateKey,
                '"}'
            )
        );

        string memory json = _runJsonScript("../integration/src/derive_test_user.ts", params);
        user.ownerNullifierKeyHash = vm.parseUint(vm.parseJsonString(json, ".ownerNullifierKeyHash"));
        user.noteSecretSeedHash = vm.parseUint(vm.parseJsonString(json, ".noteSecretSeedHash"));
        user.authDataCommitment = vm.parseUint(vm.parseJsonString(json, ".authDataCommitment"));
        user.innerVkHash = vm.parseUint(vm.parseJsonString(json, ".innerVkHash"));
        user.deliveryPubKey = vm.parseJsonBytes(json, ".deliveryPubKey");
    }

    function _deriveMultisigPolicy() internal returns (PreparedAuthPolicy memory policy) {
        string memory objectKey = "multisigPolicyParams";
        vm.serializeString(objectKey, "signingPrivateKey0", MULTISIG_SIGNING_PRIVATE_KEY_0);
        vm.serializeString(objectKey, "signingPrivateKey1", MULTISIG_SIGNING_PRIVATE_KEY_1);
        string memory params = vm.serializeString(objectKey, "signingPrivateKey2", MULTISIG_SIGNING_PRIVATE_KEY_2);
        return _deriveAuthPolicyFromScript("../integration/src/derive_multisig_policy.ts", params);
    }

    function _deriveAuthPolicyFromScript(string memory scriptPath, string memory params)
        internal
        returns (PreparedAuthPolicy memory policy)
    {
        string memory json = _runJsonScript(scriptPath, params);
        policy.authDataCommitment = vm.parseUint(vm.parseJsonString(json, ".authDataCommitment"));
        policy.innerVkHash = vm.parseUint(vm.parseJsonString(json, ".innerVkHash"));
    }

    function _generateDepositFixture(
        PreparedUser memory user,
        uint256 policyVersion,
        uint256 commitRoot,
        uint256 userRegRoot,
        uint256 authPolicyRoot
    ) internal returns (ProofFixture memory fixture) {
        fixture = _runProofGenerator(_buildDepositParams(user, policyVersion, commitRoot, userRegRoot, authPolicyRoot));
    }

    function _generateTransferFixture(PreparedUser memory user, TransferRequest memory request)
        internal
        returns (ProofFixture memory fixture)
    {
        fixture = _runProofGenerator(_buildTransferParams(user, request));
    }

    function _generateMultisigDepositFixture(
        PreparedUser memory user,
        uint256 policyVersion,
        uint256 commitRoot,
        uint256 userRegRoot,
        uint256 authPolicyRoot,
        uint256[REGISTRY_TREE_DEPTH] memory authSiblings
    ) internal returns (ProofFixture memory fixture) {
        fixture = _runMultisigProofGenerator(
            _buildMultisigDepositParams(user, policyVersion, commitRoot, userRegRoot, authPolicyRoot, authSiblings)
        );
    }

    function _generateMultisigTransferFixture(
        PreparedUser memory user,
        TransferRequest memory request,
        uint256[REGISTRY_TREE_DEPTH] memory authSiblings
    ) internal returns (ProofFixture memory fixture) {
        fixture = _runMultisigProofGenerator(_buildMultisigTransferParams(user, request, authSiblings));
    }

    function _generateMultisigWithdrawFixture(
        PreparedUser memory user,
        WithdrawRequest memory request,
        uint256[REGISTRY_TREE_DEPTH] memory authSiblings
    ) internal returns (ProofFixture memory fixture) {
        fixture = _runMultisigProofGenerator(_buildMultisigWithdrawParams(user, request, authSiblings));
    }

    function _generateWithdrawFixture(PreparedUser memory user, WithdrawRequest memory request)
        internal
        returns (ProofFixture memory fixture)
    {
        fixture = _runProofGenerator(_buildWithdrawParams(user, request));
    }

    function _generateWithdrawFixtureForActor(
        PreparedUser memory user,
        UserSecrets memory actor,
        WithdrawRequest memory request
    ) internal returns (ProofFixture memory fixture) {
        fixture = _runProofGenerator(_buildWithdrawParamsForActor(user, actor, request));
    }

    function _executeDepositFixture(ProofFixture memory fixture) internal {
        vm.chainId(fixture.pubInputs.executionChainId);
        vm.warp(fixture.pubInputs.validUntilSeconds - 100);
        vm.deal(ALICE, 2 ether);
        vm.prank(ALICE);
        pool.transact{value: fixture.pubInputs.publicAmountIn}(
            fixture.proof, fixture.pubInputs, fixture.noteData0, fixture.noteData1, fixture.noteData2
        );
    }

    function _assertTransferFixture(ProofFixture memory fixture, uint256 expectedChange) internal view {
        assertEq(fixture.pubInputs.noteCommitmentRoot, _currentNoteCommitmentRoot(), "transfer root");
        assertEq(fixture.pubInputs.registryRoot, _currentUserRegistryRoot(), "transfer user root");
        assertEq(fixture.pubInputs.authPolicyRegistryRoot, _currentAuthPolicyRoot(), "transfer auth root");
        assertEq(fixture.pubInputs.publicAmountIn, 0, "transfer amount in");
        assertEq(fixture.pubInputs.publicAmountOut, 0, "transfer amount out");
        assertEq(fixture.pubInputs.publicRecipientAddress, 0, "transfer recipient field");
        assertEq(fixture.noteData0.length, 1328, "transfer note0 ciphertext length");
        assertEq(fixture.noteData1.length, 1328, "transfer note1 ciphertext length");
        assertEq(fixture.noteData2.length, 1328, "transfer note2 ciphertext length");
        assertEq(fixture.note1Amount, expectedChange, "change amount");
        assertEq(_noteDataHash(fixture.noteData0), fixture.pubInputs.outputNoteDataHash0, "transfer note0 hash");
        assertEq(_noteDataHash(fixture.noteData1), fixture.pubInputs.outputNoteDataHash1, "transfer note1 hash");
    }

    function _executeTransferFixture(ProofFixture memory fixture) internal {
        vm.chainId(fixture.pubInputs.executionChainId);
        vm.warp(fixture.pubInputs.validUntilSeconds - 100);
        pool.transact(fixture.proof, fixture.pubInputs, fixture.noteData0, fixture.noteData1, fixture.noteData2);

        assertEq(address(pool).balance, DEPOSIT_AMOUNT, "pool balance unchanged after transfer");
        assertEq(_nextLeafIndex(), 6, "transfer inserted 3 commitments");

        vm.expectRevert(ShieldedPool.NullifierAlreadySpent.selector);
        pool.transact(fixture.proof, fixture.pubInputs, fixture.noteData0, fixture.noteData1, fixture.noteData2);
    }

    function _assertWithdrawFixture(
        ProofFixture memory fixture,
        address publicRecipient,
        uint256 expectedWithdrawAmount,
        uint256 expectedChange
    ) internal view {
        assertEq(fixture.pubInputs.noteCommitmentRoot, _currentNoteCommitmentRoot(), "withdraw root");
        assertEq(fixture.pubInputs.registryRoot, _currentUserRegistryRoot(), "withdraw user root");
        assertEq(fixture.pubInputs.authPolicyRegistryRoot, _currentAuthPolicyRoot(), "withdraw auth root");
        assertEq(fixture.pubInputs.publicAmountOut, expectedWithdrawAmount, "withdraw amount");
        assertEq(address(uint160(fixture.pubInputs.publicRecipientAddress)), publicRecipient, "withdraw recipient");
        assertEq(fixture.noteData0.length, 1328, "withdraw note0 ciphertext length");
        assertEq(fixture.noteData1.length, 1328, "withdraw note1 ciphertext length");
        assertEq(fixture.noteData2.length, 1328, "withdraw note2 ciphertext length");
        assertEq(fixture.note0Amount, expectedChange, "withdraw change amount");
        assertEq(_noteDataHash(fixture.noteData0), fixture.pubInputs.outputNoteDataHash0, "withdraw note0 hash");
    }

    function _executeWithdrawFixture(ProofFixture memory fixture) internal {
        vm.chainId(fixture.pubInputs.executionChainId);
        vm.warp(fixture.pubInputs.validUntilSeconds - 100);
        uint256 balanceBefore = address(pool).balance;
        uint256 nextLeafIndexBefore = _nextLeafIndex();
        pool.transact(fixture.proof, fixture.pubInputs, fixture.noteData0, fixture.noteData1, fixture.noteData2);

        assertEq(address(pool).balance, balanceBefore - fixture.pubInputs.publicAmountOut, "pool keeps change");
        assertEq(_nextLeafIndex(), nextLeafIndexBefore + 3, "withdraw inserted 3 commitments");

        vm.expectRevert(ShieldedPool.NullifierAlreadySpent.selector);
        pool.transact(fixture.proof, fixture.pubInputs, fixture.noteData0, fixture.noteData1, fixture.noteData2);
    }

    function _runProofGenerator(string memory params) internal returns (ProofFixture memory fixture) {
        fixture = _runProofScript("../integration/src/generate_eip712_proof.ts", params);
    }

    function _runMultisigProofGenerator(string memory params) internal returns (ProofFixture memory fixture) {
        fixture = _runProofScript("../integration/src/generate_multisig_proof.ts", params);
    }

    function _runProofScript(string memory scriptPath, string memory params)
        internal
        returns (ProofFixture memory fixture)
    {
        string memory json = _runJsonScript(scriptPath, params);
        bytes32[] memory publicInputs = vm.parseJsonBytes32Array(json, ".publicInputs");
        fixture.proof = vm.parseJsonBytes(json, ".proof");
        fixture.noteData0 = vm.parseJsonBytes(json, ".outputNoteData[0]");
        fixture.noteData1 = vm.parseJsonBytes(json, ".outputNoteData[1]");
        fixture.noteData2 = vm.parseJsonBytes(json, ".outputNoteData[2]");
        fixture.pubInputs = _publicInputsFromArray(publicInputs);
        fixture.note0Amount = vm.parseUint(vm.parseJsonString(json, ".note0.amount"));
        fixture.note0NoteSecret = vm.parseUint(vm.parseJsonString(json, ".note0.noteSecret"));
        fixture.note0OriginTag = vm.parseUint(vm.parseJsonString(json, ".note0.originTag"));
        fixture.note1Amount = vm.parseUint(vm.parseJsonString(json, ".note1.amount"));
        fixture.note1NoteSecret = vm.parseUint(vm.parseJsonString(json, ".note1.noteSecret"));
        fixture.note1OriginTag = vm.parseUint(vm.parseJsonString(json, ".note1.originTag"));
    }

    function _runJsonScript(string memory scriptPath, string memory params) internal returns (string memory json) {
        Vm.FfiResult memory result = _tryJsonScript(scriptPath, params);
        if (result.exitCode != 0) {
            revert(string(result.stderr));
        }
        return string(result.stdout);
    }

    function _tryJsonScript(string memory scriptPath, string memory params)
        internal
        returns (Vm.FfiResult memory result)
    {
        string[] memory cmd = new string[](5);
        cmd[0] = "node";
        cmd[1] = "test/helpers/run_tsx_with_timeout.mjs";
        cmd[2] = scriptPath;
        cmd[3] = params;
        cmd[4] = "900000";
        result = vm.tryFfi(cmd);
    }

    function _expectProofGenerationFailure(string memory params, string memory expectedMessage) internal {
        Vm.FfiResult memory result = _tryJsonScript("../integration/src/generate_eip712_proof.ts", params);
        assertTrue(result.exitCode != 0, "expected proof generation failure");
        string memory revertMessage = string(result.stderr);
        assertTrue(_stringContains(revertMessage, expectedMessage), revertMessage);
    }

    function _stringContains(string memory haystack, string memory needle) internal pure returns (bool) {
        bytes memory haystackBytes = bytes(haystack);
        bytes memory needleBytes = bytes(needle);
        if (needleBytes.length == 0) return true;
        if (needleBytes.length > haystackBytes.length) return false;

        for (uint256 i; i <= haystackBytes.length - needleBytes.length; ++i) {
            bool matchFound = true;
            for (uint256 j; j < needleBytes.length; ++j) {
                if (haystackBytes[i + j] != needleBytes[j]) {
                    matchFound = false;
                    break;
                }
            }
            if (matchFound) return true;
        }

        return false;
    }

    function _withExecutionConstraints(
        string memory params,
        uint256 executionConstraintsFlags,
        uint256 lockedOutputBinding0,
        uint256 lockedOutputBinding1,
        uint256 lockedOutputBinding2
    ) internal view returns (string memory) {
        bytes memory source = bytes(params);
        require(source.length != 0 && source[source.length - 1] == bytes1("}"), "invalid params json");

        bytes memory prefix = new bytes(source.length - 1);
        for (uint256 i; i < source.length - 1; ++i) {
            prefix[i] = source[i];
        }

        return string(
            abi.encodePacked(
                prefix,
                ',"executionConstraints":{"executionConstraintsFlags":',
                vm.toString(executionConstraintsFlags),
                ',"lockedOutputBinding0":',
                vm.toString(lockedOutputBinding0),
                ',"lockedOutputBinding1":',
                vm.toString(lockedOutputBinding1),
                ',"lockedOutputBinding2":',
                vm.toString(lockedOutputBinding2),
                "}}"
            )
        );
    }

    function _serializeRegisteredDeliveryKey(
        string memory objectKey,
        string memory schemeField,
        string memory keyField,
        address account
    ) internal {
        (uint32 schemeId, bytes memory deliveryKey) = pool.getDeliveryKey(account);
        vm.serializeUint(objectKey, schemeField, schemeId);
        vm.serializeBytes(objectKey, keyField, deliveryKey);
    }

    function _buildDepositParams(
        PreparedUser memory user,
        uint256 policyVersion,
        uint256 commitRoot,
        uint256 userRegRoot,
        uint256 authPolicyRoot
    ) internal returns (string memory) {
        string memory objectKey = "depositParams";
        vm.serializeString(objectKey, "mode", "deposit");
        vm.serializeAddress(objectKey, "depositorAddress", ALICE);
        vm.serializeUint(objectKey, "amount", DEPOSIT_AMOUNT);
        vm.serializeUint(objectKey, "tokenAddress", 0);
        vm.serializeUint(objectKey, "ownerNullifierKey", NK);
        vm.serializeUint(objectKey, "noteSecretSeed", OS);
        vm.serializeUint(objectKey, "policyVersion", policyVersion);
        vm.serializeUint(objectKey, "nonce", 42);
        vm.serializeUint(objectKey, "validUntilSeconds", block.timestamp + 3600);
        vm.serializeUint(objectKey, "executionChainId", block.chainid);
        vm.serializeUint(objectKey, "noteCommitmentRoot", commitRoot);
        vm.serializeUint(objectKey, "userRegistryRoot", userRegRoot);
        vm.serializeUint(objectKey, "authPolicyRoot", authPolicyRoot);
        vm.serializeString(objectKey, "userSiblings", _registrySiblingStrings(_userRegistrySiblings(ALICE)));
        vm.serializeString(objectKey, "recipientSiblings", _registrySiblingStrings(_userRegistrySiblings(ALICE)));
        vm.serializeString(
            objectKey, "authSiblings", _registrySiblingStrings(_authPolicySiblings(ALICE, user.innerVkHash))
        );
        _serializeRegisteredDeliveryKey(objectKey, "deliverySchemeId", "deliveryPubKey", ALICE);
        return vm.serializeString(objectKey, "signingPrivateKey", ALICE_SIGNING_PRIVATE_KEY);
    }

    function _buildMultisigDepositParams(
        PreparedUser memory,
        uint256 policyVersion,
        uint256 commitRoot,
        uint256 userRegRoot,
        uint256 authPolicyRoot,
        uint256[REGISTRY_TREE_DEPTH] memory authSiblings
    ) internal returns (string memory) {
        string memory objectKey = "multisigDepositParams";
        vm.serializeString(objectKey, "mode", "deposit");
        vm.serializeAddress(objectKey, "depositorAddress", ALICE);
        vm.serializeUint(objectKey, "amount", DEPOSIT_AMOUNT);
        vm.serializeUint(objectKey, "tokenAddress", 0);
        vm.serializeUint(objectKey, "ownerNullifierKey", NK);
        vm.serializeUint(objectKey, "noteSecretSeed", OS);
        vm.serializeUint(objectKey, "policyVersion", policyVersion);
        vm.serializeUint(objectKey, "nonce", 45);
        vm.serializeUint(objectKey, "validUntilSeconds", block.timestamp + 3600);
        vm.serializeUint(objectKey, "executionChainId", block.chainid);
        vm.serializeUint(objectKey, "noteCommitmentRoot", commitRoot);
        vm.serializeUint(objectKey, "userRegistryRoot", userRegRoot);
        vm.serializeUint(objectKey, "authPolicyRoot", authPolicyRoot);
        vm.serializeString(objectKey, "userSiblings", _registrySiblingStrings(_userRegistrySiblings(ALICE)));
        vm.serializeString(objectKey, "recipientSiblings", _registrySiblingStrings(_userRegistrySiblings(ALICE)));
        vm.serializeString(objectKey, "authSiblings", _registrySiblingStrings(authSiblings));
        _serializeRegisteredDeliveryKey(objectKey, "deliverySchemeId", "deliveryPubKey", ALICE);
        vm.serializeString(objectKey, "signingPrivateKey0", MULTISIG_SIGNING_PRIVATE_KEY_0);
        vm.serializeString(objectKey, "signingPrivateKey1", MULTISIG_SIGNING_PRIVATE_KEY_1);
        vm.serializeString(objectKey, "signingPrivateKey2", MULTISIG_SIGNING_PRIVATE_KEY_2);
        vm.serializeUint(objectKey, "signerAIndex", 0);
        return vm.serializeUint(objectKey, "signerBIndex", 2);
    }

    function _buildTransferParams(PreparedUser memory user, TransferRequest memory request)
        internal
        returns (string memory)
    {
        string memory objectKey = "transferParams";
        _serializeTransferParams(objectKey, user, request);
        return vm.serializeString(objectKey, "signingPrivateKey", ALICE_SIGNING_PRIVATE_KEY);
    }

    function _buildTransferParamsWithOuterWitnessOverrides(
        PreparedUser memory user,
        TransferRequest memory request,
        address outerAuthorizingAddress,
        uint256 outerPolicyVersion
    ) internal returns (string memory) {
        string memory objectKey = "transferParamsWithOuterWitnessOverrides";
        _serializeTransferParams(objectKey, user, request);
        vm.serializeAddress(objectKey, "outerAuthorizingAddress", outerAuthorizingAddress);
        vm.serializeUint(objectKey, "outerPolicyVersion", outerPolicyVersion);
        return vm.serializeString(objectKey, "signingPrivateKey", ALICE_SIGNING_PRIVATE_KEY);
    }

    function _serializeTransferParams(string memory objectKey, PreparedUser memory user, TransferRequest memory request)
        internal
    {
        vm.serializeString(objectKey, "mode", "transfer");
        vm.serializeAddress(objectKey, "senderAddress", ALICE);
        vm.serializeAddress(objectKey, "recipientAddress", request.recipient);
        vm.serializeUint(objectKey, "amount", request.transferAmount);
        vm.serializeUint(objectKey, "tokenAddress", 0);
        vm.serializeUint(objectKey, "ownerNullifierKey", NK);
        vm.serializeUint(objectKey, "noteSecretSeed", OS);
        vm.serializeUint(objectKey, "policyVersion", request.policyVersion);
        vm.serializeUint(objectKey, "nonce", 44);
        vm.serializeUint(objectKey, "validUntilSeconds", block.timestamp + 3600);
        vm.serializeUint(objectKey, "executionChainId", block.chainid);
        vm.serializeUint(objectKey, "noteCommitmentRoot", request.commitRoot);
        vm.serializeUint(objectKey, "userRegistryRoot", request.userRegRoot);
        vm.serializeUint(objectKey, "authPolicyRoot", request.authPolicyRoot);
        vm.serializeUint(objectKey, "inputLeafIndex", request.inputLeafIndex);
        vm.serializeUint(objectKey, "inputAmount", request.inputAmount);
        vm.serializeUint(objectKey, "inputNoteSecret", request.inputNoteSecret);
        vm.serializeUint(objectKey, "inputOriginTag", request.inputOriginTag);
        vm.serializeUint(objectKey, "recipientOwnerNullifierKeyHash", request.recipientOwnerNullifierKeyHash);
        vm.serializeUint(objectKey, "recipientNoteSecretSeedHash", request.recipientNoteSecretSeedHash);
        vm.serializeUint(objectKey, "changeAmount", request.changeAmount);
        vm.serializeString(objectKey, "inputSiblings", _siblingStrings(request.inputSiblings));
        vm.serializeString(objectKey, "userSiblings", _registrySiblingStrings(request.userSiblings));
        vm.serializeString(objectKey, "recipientSiblings", _registrySiblingStrings(request.recipientSiblings));
        vm.serializeString(
            objectKey, "authSiblings", _registrySiblingStrings(_authPolicySiblings(ALICE, user.innerVkHash))
        );
        _serializeRegisteredDeliveryKey(
            objectKey, "recipientDeliverySchemeId", "recipientDeliveryPubKey", request.recipient
        );
        _serializeRegisteredDeliveryKey(objectKey, "changeDeliverySchemeId", "changeDeliveryPubKey", ALICE);
    }

    function _buildWithdrawParams(PreparedUser memory user, WithdrawRequest memory request)
        internal
        returns (string memory)
    {
        UserSecrets memory actor = _aliceSecrets();
        return _buildWithdrawParamsForActor(user, actor, request);
    }

    function _buildWithdrawParamsForActor(
        PreparedUser memory user,
        UserSecrets memory actor,
        WithdrawRequest memory request
    ) internal returns (string memory) {
        string memory objectKey = "withdrawParams";
        vm.serializeString(objectKey, "mode", "withdraw");
        vm.serializeAddress(objectKey, "senderAddress", actor.account);
        vm.serializeAddress(objectKey, "recipientAddress", request.publicRecipient);
        vm.serializeUint(objectKey, "amount", request.withdrawAmount);
        vm.serializeUint(objectKey, "tokenAddress", 0);
        vm.serializeUint(objectKey, "ownerNullifierKey", actor.ownerNullifierKey);
        vm.serializeUint(objectKey, "noteSecretSeed", actor.noteSecretSeed);
        vm.serializeUint(objectKey, "policyVersion", request.policyVersion);
        vm.serializeUint(objectKey, "nonce", 43);
        vm.serializeUint(objectKey, "validUntilSeconds", block.timestamp + 3600);
        vm.serializeUint(objectKey, "executionChainId", block.chainid);
        vm.serializeUint(objectKey, "noteCommitmentRoot", request.commitRoot);
        vm.serializeUint(objectKey, "userRegistryRoot", request.userRegRoot);
        vm.serializeUint(objectKey, "authPolicyRoot", request.authPolicyRoot);
        vm.serializeUint(objectKey, "inputLeafIndex", request.inputLeafIndex);
        vm.serializeUint(objectKey, "inputAmount", request.inputAmount);
        vm.serializeUint(objectKey, "inputNoteSecret", request.inputNoteSecret);
        vm.serializeUint(objectKey, "inputOriginTag", request.inputOriginTag);
        vm.serializeUint(objectKey, "changeAmount", request.inputAmount - request.withdrawAmount);
        vm.serializeString(objectKey, "inputSiblings", _siblingStrings(request.inputSiblings));
        vm.serializeString(objectKey, "userSiblings", _registrySiblingStrings(request.userSiblings));
        vm.serializeString(objectKey, "recipientSiblings", _registrySiblingStrings(request.userSiblings));
        vm.serializeString(
            objectKey, "authSiblings", _registrySiblingStrings(_authPolicySiblings(actor.account, user.innerVkHash))
        );
        _serializeRegisteredDeliveryKey(objectKey, "deliverySchemeId", "deliveryPubKey", actor.account);
        return vm.serializeString(objectKey, "signingPrivateKey", actor.signingPrivateKey);
    }

    function _buildMultisigTransferParams(
        PreparedUser memory,
        TransferRequest memory request,
        uint256[REGISTRY_TREE_DEPTH] memory authSiblings
    ) internal returns (string memory) {
        string memory objectKey = "multisigTransferParams";
        vm.serializeString(objectKey, "mode", "transfer");
        vm.serializeAddress(objectKey, "senderAddress", ALICE);
        vm.serializeAddress(objectKey, "recipientAddress", request.recipient);
        vm.serializeUint(objectKey, "amount", request.transferAmount);
        vm.serializeUint(objectKey, "tokenAddress", 0);
        vm.serializeUint(objectKey, "ownerNullifierKey", NK);
        vm.serializeUint(objectKey, "noteSecretSeed", OS);
        vm.serializeUint(objectKey, "policyVersion", request.policyVersion);
        vm.serializeUint(objectKey, "nonce", 45);
        vm.serializeUint(objectKey, "validUntilSeconds", block.timestamp + 3600);
        vm.serializeUint(objectKey, "executionChainId", block.chainid);
        vm.serializeUint(objectKey, "noteCommitmentRoot", request.commitRoot);
        vm.serializeUint(objectKey, "userRegistryRoot", request.userRegRoot);
        vm.serializeUint(objectKey, "authPolicyRoot", request.authPolicyRoot);
        vm.serializeUint(objectKey, "inputLeafIndex", request.inputLeafIndex);
        vm.serializeUint(objectKey, "inputAmount", request.inputAmount);
        vm.serializeUint(objectKey, "inputNoteSecret", request.inputNoteSecret);
        vm.serializeUint(objectKey, "inputOriginTag", request.inputOriginTag);
        vm.serializeUint(objectKey, "recipientOwnerNullifierKeyHash", request.recipientOwnerNullifierKeyHash);
        vm.serializeUint(objectKey, "recipientNoteSecretSeedHash", request.recipientNoteSecretSeedHash);
        vm.serializeUint(objectKey, "changeAmount", request.changeAmount);
        vm.serializeString(objectKey, "inputSiblings", _siblingStrings(request.inputSiblings));
        vm.serializeString(objectKey, "userSiblings", _registrySiblingStrings(request.userSiblings));
        vm.serializeString(objectKey, "recipientSiblings", _registrySiblingStrings(request.recipientSiblings));
        vm.serializeString(objectKey, "authSiblings", _registrySiblingStrings(authSiblings));
        _serializeRegisteredDeliveryKey(
            objectKey, "recipientDeliverySchemeId", "recipientDeliveryPubKey", request.recipient
        );
        _serializeRegisteredDeliveryKey(objectKey, "changeDeliverySchemeId", "changeDeliveryPubKey", ALICE);
        vm.serializeString(objectKey, "signingPrivateKey0", MULTISIG_SIGNING_PRIVATE_KEY_0);
        vm.serializeString(objectKey, "signingPrivateKey1", MULTISIG_SIGNING_PRIVATE_KEY_1);
        vm.serializeString(objectKey, "signingPrivateKey2", MULTISIG_SIGNING_PRIVATE_KEY_2);
        vm.serializeUint(objectKey, "signerAIndex", 0);
        return vm.serializeUint(objectKey, "signerBIndex", 2);
    }

    function _buildMultisigWithdrawParams(
        PreparedUser memory,
        WithdrawRequest memory request,
        uint256[REGISTRY_TREE_DEPTH] memory authSiblings
    ) internal returns (string memory) {
        string memory objectKey = "multisigWithdrawParams";
        vm.serializeString(objectKey, "mode", "withdraw");
        vm.serializeAddress(objectKey, "senderAddress", ALICE);
        vm.serializeAddress(objectKey, "recipientAddress", request.publicRecipient);
        vm.serializeUint(objectKey, "amount", request.withdrawAmount);
        vm.serializeUint(objectKey, "tokenAddress", 0);
        vm.serializeUint(objectKey, "ownerNullifierKey", NK);
        vm.serializeUint(objectKey, "noteSecretSeed", OS);
        vm.serializeUint(objectKey, "policyVersion", request.policyVersion);
        vm.serializeUint(objectKey, "nonce", 46);
        vm.serializeUint(objectKey, "validUntilSeconds", block.timestamp + 3600);
        vm.serializeUint(objectKey, "executionChainId", block.chainid);
        vm.serializeUint(objectKey, "noteCommitmentRoot", request.commitRoot);
        vm.serializeUint(objectKey, "userRegistryRoot", request.userRegRoot);
        vm.serializeUint(objectKey, "authPolicyRoot", request.authPolicyRoot);
        vm.serializeUint(objectKey, "inputLeafIndex", request.inputLeafIndex);
        vm.serializeUint(objectKey, "inputAmount", request.inputAmount);
        vm.serializeUint(objectKey, "inputNoteSecret", request.inputNoteSecret);
        vm.serializeUint(objectKey, "inputOriginTag", request.inputOriginTag);
        vm.serializeUint(objectKey, "changeAmount", request.inputAmount - request.withdrawAmount);
        vm.serializeString(objectKey, "inputSiblings", _siblingStrings(request.inputSiblings));
        vm.serializeString(objectKey, "userSiblings", _registrySiblingStrings(request.userSiblings));
        vm.serializeString(objectKey, "recipientSiblings", _registrySiblingStrings(request.userSiblings));
        vm.serializeString(objectKey, "authSiblings", _registrySiblingStrings(authSiblings));
        _serializeRegisteredDeliveryKey(objectKey, "deliverySchemeId", "deliveryPubKey", ALICE);
        vm.serializeString(objectKey, "signingPrivateKey0", MULTISIG_SIGNING_PRIVATE_KEY_0);
        vm.serializeString(objectKey, "signingPrivateKey1", MULTISIG_SIGNING_PRIVATE_KEY_1);
        vm.serializeString(objectKey, "signingPrivateKey2", MULTISIG_SIGNING_PRIVATE_KEY_2);
        vm.serializeUint(objectKey, "signerAIndex", 0);
        return vm.serializeUint(objectKey, "signerBIndex", 2);
    }

    function _commitmentSiblings(uint256[] memory leaves, uint256 leafIndex)
        internal
        pure
        returns (uint256[TREE_DEPTH] memory siblings)
    {
        uint256[] memory currentLevel = leaves;
        uint256 currentIndex = leafIndex;
        uint256 levelSize = currentLevel.length;
        uint256[TREE_DEPTH] memory empties = _emptyCommitmentHashes();

        for (uint256 level; level < TREE_DEPTH; ++level) {
            uint256 siblingIndex = currentIndex ^ 1;
            siblings[level] = siblingIndex < levelSize ? currentLevel[siblingIndex] : empties[level];

            uint256 nextSize = (levelSize + 1) / 2;
            uint256[] memory nextLevel = new uint256[](nextSize);
            for (uint256 i; i < nextSize; ++i) {
                uint256 left = 2 * i < levelSize ? currentLevel[2 * i] : empties[level];
                uint256 right = 2 * i + 1 < levelSize ? currentLevel[2 * i + 1] : empties[level];
                nextLevel[i] = PoseidonFieldLib.hash2Raw(left, right);
            }

            currentLevel = nextLevel;
            levelSize = nextSize;
            currentIndex >>= 1;
        }
    }

    function _userRegistrySiblings(address user) internal view returns (uint256[REGISTRY_TREE_DEPTH] memory siblings) {
        uint256[REGISTRY_TREE_DEPTH] memory emptyHashes = _emptySparseHashes();
        uint256 key = uint256(uint160(user));
        for (uint256 i; i < REGISTRY_TREE_DEPTH; ++i) {
            uint256 siblingIndex = (key >> i) ^ 1;
            bytes32 slot = _nestedMappingSlot(i, siblingIndex, poolStorageLayout.userTreeNodesSlot);
            uint256 value = uint256(vm.load(address(pool), slot));
            siblings[i] = value == 0 ? emptyHashes[i] : value;
        }
    }

    function _authPolicySiblings(address owner, uint256 innerVkHash)
        internal
        view
        returns (uint256[REGISTRY_TREE_DEPTH] memory siblings)
    {
        uint256[REGISTRY_TREE_DEPTH] memory emptyHashes = _emptySparseHashes();
        uint256 key = PoseidonFieldLib.authPolicyTreeKey(owner, innerVkHash);
        for (uint256 i; i < REGISTRY_TREE_DEPTH; ++i) {
            uint256 siblingIndex = (key >> i) ^ 1;
            bytes32 slot = _nestedMappingSlot(i, siblingIndex, poolStorageLayout.authTreeNodesSlot);
            uint256 value = uint256(vm.load(address(pool), slot));
            siblings[i] = value == 0 ? emptyHashes[i] : value;
        }
    }

    function _assertAuthWitnessMatchesCurrentRoot(
        address owner,
        uint256 innerVkHash,
        uint256 authDataCommitment,
        uint256 policyVersion
    ) internal view {
        uint256[REGISTRY_TREE_DEPTH] memory siblings = _authPolicySiblings(owner, innerVkHash);
        uint256 current = PoseidonFieldLib.authPolicyLeaf(authDataCommitment, policyVersion);
        uint256 key = PoseidonFieldLib.authPolicyTreeKey(owner, innerVkHash);

        for (uint256 i; i < REGISTRY_TREE_DEPTH; ++i) {
            uint256 bit = (key >> i) & 1;
            if (bit == 0) {
                current = PoseidonFieldLib.hash2Raw(current, siblings[i]);
            } else {
                current = PoseidonFieldLib.hash2Raw(siblings[i], current);
            }
        }

        assertEq(current, _currentAuthPolicyRoot(), "auth witness root mismatch");
    }

    function _emptyCommitmentHashes() internal pure returns (uint256[TREE_DEPTH] memory hashes) {
        hashes[0] = 0;
        for (uint256 i = 1; i < TREE_DEPTH; ++i) {
            hashes[i] = PoseidonFieldLib.hash2Raw(hashes[i - 1], hashes[i - 1]);
        }
    }

    function _emptySparseHashes() internal pure returns (uint256[REGISTRY_TREE_DEPTH] memory hashes) {
        hashes[0] = 0;
        for (uint256 i = 1; i < REGISTRY_TREE_DEPTH; ++i) {
            hashes[i] = PoseidonFieldLib.hash2Raw(hashes[i - 1], hashes[i - 1]);
        }
    }

    function _nestedMappingSlot(uint256 key1, uint256 key2, uint256 baseSlot) internal pure returns (bytes32) {
        bytes32 outer = keccak256(abi.encode(key1, baseSlot));
        return keccak256(abi.encode(key2, outer));
    }

    function _siblingStrings(uint256[TREE_DEPTH] memory siblings) internal view returns (string[] memory values) {
        values = new string[](TREE_DEPTH);
        for (uint256 i; i < TREE_DEPTH; ++i) {
            values[i] = vm.toString(siblings[i]);
        }
    }

    function _registrySiblingStrings(uint256[REGISTRY_TREE_DEPTH] memory siblings)
        internal
        view
        returns (string[] memory values)
    {
        values = new string[](REGISTRY_TREE_DEPTH);
        for (uint256 i; i < REGISTRY_TREE_DEPTH; ++i) {
            values[i] = vm.toString(siblings[i]);
        }
    }

    function _addressStrings(address[2] memory values) internal view returns (string[] memory encoded) {
        encoded = new string[](2);
        encoded[0] = vm.toString(values[0]);
        encoded[1] = vm.toString(values[1]);
    }

    function _uintStrings(uint256[2] memory values) internal view returns (string[] memory encoded) {
        encoded = new string[](2);
        encoded[0] = vm.toString(values[0]);
        encoded[1] = vm.toString(values[1]);
    }

    function _stringArray2(string memory a, string memory b) internal pure returns (string[] memory values) {
        values = new string[](2);
        values[0] = a;
        values[1] = b;
    }

    function _assertVerifierAccepts(ProofFixture memory fixture) internal view {
        (bool success, bytes memory returnData) =
            PROOF_VERIFY_PRECOMPILE_ADDRESS.staticcall(abi.encode(fixture.proof, fixture.pubInputs));

        assertTrue(success, "precompile call failed");
        assertEq(returnData.length, 32, "precompile return length");
        assertEq(abi.decode(returnData, (uint256)), 1, "verifier rejected proof");
    }

    function _registerAuthPolicy(address account, uint256 innerVkHash, uint256 authDataCommitment)
        internal
        returns (uint256 currentPolicyVersion)
    {
        vm.prank(account);
        pool.registerAuthPolicy(innerVkHash, authDataCommitment);
        (bool active, uint256 currentAuthDataCommitment, uint256 version) =
            pool.getAuthPolicy(account, innerVkHash);
        assertTrue(active, "auth policy inactive after registration");
        assertEq(currentAuthDataCommitment, authDataCommitment, "auth policy commitment mismatch");
        currentPolicyVersion = version;
    }

    function _publicInputsFromArray(bytes32[] memory pis) internal pure returns (ShieldedPool.PublicInputs memory pi) {
        pi.noteCommitmentRoot = uint256(pis[0]);
        pi.nullifier0 = uint256(pis[1]);
        pi.nullifier1 = uint256(pis[2]);
        pi.noteCommitment0 = uint256(pis[3]);
        pi.noteCommitment1 = uint256(pis[4]);
        pi.noteCommitment2 = uint256(pis[5]);
        pi.publicAmountIn = uint256(pis[6]);
        pi.publicAmountOut = uint256(pis[7]);
        pi.publicRecipientAddress = uint256(pis[8]);
        pi.publicTokenAddress = uint256(pis[9]);
        pi.depositorAddress = uint256(pis[10]);
        pi.transactionReplayId = uint256(pis[11]);
        pi.registryRoot = uint256(pis[12]);
        pi.validUntilSeconds = uint256(pis[13]);
        pi.executionChainId = uint256(pis[14]);
        pi.authPolicyRegistryRoot = uint256(pis[15]);
        pi.outputNoteDataHash0 = uint256(pis[16]);
        pi.outputNoteDataHash1 = uint256(pis[17]);
        pi.outputNoteDataHash2 = uint256(pis[18]);
    }

    function _depositAliceSingleSig()
        internal
        returns (PreparedUser memory user, uint256 policyVersion, ProofFixture memory fixture)
    {
        user = _deriveTestUser(NK, OS, DS, ALICE_SIGNING_PRIVATE_KEY);
        policyVersion = _registerAlice(user);
        fixture = _generateDepositFixture(
            user, policyVersion, _currentNoteCommitmentRoot(), _currentUserRegistryRoot(), _currentAuthPolicyRoot()
        );
        _assertAndExecuteDepositFixture(fixture);
    }

    function _depositLeaves(ProofFixture memory fixture) internal pure returns (uint256[] memory leaves) {
        leaves = new uint256[](3);
        leaves[0] = fixture.pubInputs.noteCommitment0;
        leaves[1] = fixture.pubInputs.noteCommitment1;
        leaves[2] = fixture.pubInputs.noteCommitment2;
    }

    function _combinedLeaves(ProofFixture memory first, ProofFixture memory second)
        internal
        pure
        returns (uint256[] memory leaves)
    {
        leaves = new uint256[](6);
        leaves[0] = first.pubInputs.noteCommitment0;
        leaves[1] = first.pubInputs.noteCommitment1;
        leaves[2] = first.pubInputs.noteCommitment2;
        leaves[3] = second.pubInputs.noteCommitment0;
        leaves[4] = second.pubInputs.noteCommitment1;
        leaves[5] = second.pubInputs.noteCommitment2;
    }

    function _prepareBob(address bob) internal returns (PreparedUser memory bobUser) {
        bobUser = _deriveTestUser(BOB_NK, BOB_OS, BOB_DS, BOB_SIGNING_PRIVATE_KEY);
        _registerUserWithoutAuth(bob, bobUser);
    }

    function _recoverSingleChainNote(
        address owner,
        uint256 ownerNullifierKey,
        uint256 deliverySecret,
        uint256 leafIndex,
        bytes memory encryptedData,
        uint256 commitment
    ) internal returns (RecoveredNote memory note) {
        string memory params = string(
            abi.encodePacked(
                '{"ownerAddress":"',
                vm.toString(uint256(uint160(owner))),
                '","ownerNullifierKey":"',
                vm.toString(ownerNullifierKey),
                '","deliverySecret":"',
                vm.toString(deliverySecret),
                '","leafIndex":"',
                vm.toString(leafIndex),
                '","encryptedData":"',
                vm.toString(encryptedData),
                '","commitment":"',
                vm.toString(commitment),
                '"}'
            )
        );

        string memory json = _runJsonScript("../prover/src/recover_note.ts", params);
        note.found = vm.parseJsonBool(json, ".found");
        if (!note.found) {
            return note;
        }

        note.commitment = vm.parseUint(vm.parseJsonString(json, ".note.commitment"));
        note.leafIndex = vm.parseJsonUint(json, ".note.leafIndex");
        note.amount = vm.parseUint(vm.parseJsonString(json, ".note.amount"));
        note.ownerAddress = vm.parseUint(vm.parseJsonString(json, ".note.ownerAddress"));
        note.noteSecret = vm.parseUint(vm.parseJsonString(json, ".note.noteSecret"));
        note.ownerNullifierKeyHash = vm.parseUint(vm.parseJsonString(json, ".note.ownerNullifierKeyHash"));
        note.tokenAddress = vm.parseUint(vm.parseJsonString(json, ".note.tokenAddress"));
        note.originTag = vm.parseUint(vm.parseJsonString(json, ".note.originTag"));
    }

    function _recoverFirstUnspentNoteFromHistory(
        address owner,
        uint256 ownerNullifierKey,
        uint256 deliverySecret,
        SyncedTransactFixture[] memory history
    ) internal returns (RecoveredNote memory note) {
        string memory transactsJson = "[";
        for (uint256 i; i < history.length; ++i) {
            ProofFixture memory fixture = history[i].fixture;
            if (i != 0) {
                transactsJson = string.concat(transactsJson, ",");
            }
            transactsJson = string.concat(
                transactsJson,
                '{"leafIndex0":"',
                vm.toString(history[i].leafIndex0),
                '","nullifier0":"',
                vm.toString(fixture.pubInputs.nullifier0),
                '","nullifier1":"',
                vm.toString(fixture.pubInputs.nullifier1),
                '","noteCommitment0":"',
                vm.toString(fixture.pubInputs.noteCommitment0),
                '","noteCommitment1":"',
                vm.toString(fixture.pubInputs.noteCommitment1),
                '","noteCommitment2":"',
                vm.toString(fixture.pubInputs.noteCommitment2),
                '","outputNoteData0":"',
                vm.toString(fixture.noteData0),
                '","outputNoteData1":"',
                vm.toString(fixture.noteData1),
                '","outputNoteData2":"',
                vm.toString(fixture.noteData2),
                '"}'
            );
        }
        transactsJson = string.concat(transactsJson, "]");

        string memory params = string(
            abi.encodePacked(
                '{"ownerAddress":"',
                vm.toString(uint256(uint160(owner))),
                '","ownerNullifierKey":"',
                vm.toString(ownerNullifierKey),
                '","deliverySecret":"',
                vm.toString(deliverySecret),
                '","leafIndex":"0","encryptedData":"0x","commitment":"0","transacts":',
                transactsJson,
                "}"
            )
        );

        string memory json = _runJsonScript("../prover/src/recover_note.ts", params);
        note.found = vm.parseJsonBool(json, ".found");
        if (!note.found) {
            return note;
        }

        note.commitment = vm.parseUint(vm.parseJsonString(json, ".note.commitment"));
        note.leafIndex = vm.parseJsonUint(json, ".note.leafIndex");
        note.amount = vm.parseUint(vm.parseJsonString(json, ".note.amount"));
        note.ownerAddress = vm.parseUint(vm.parseJsonString(json, ".note.ownerAddress"));
        note.noteSecret = vm.parseUint(vm.parseJsonString(json, ".note.noteSecret"));
        note.ownerNullifierKeyHash = vm.parseUint(vm.parseJsonString(json, ".note.ownerNullifierKeyHash"));
        note.tokenAddress = vm.parseUint(vm.parseJsonString(json, ".note.tokenAddress"));
        note.originTag = vm.parseUint(vm.parseJsonString(json, ".note.originTag"));
    }

    function _currentNoteCommitmentRoot() internal view returns (uint256 root) {
        (root,,) = pool.getCurrentRoots();
    }

    function _currentUserRegistryRoot() internal view returns (uint256 root) {
        (, root,) = pool.getCurrentRoots();
    }

    function _currentAuthPolicyRoot() internal view returns (uint256 root) {
        (,, root) = pool.getCurrentRoots();
    }

    function _nextLeafIndex() internal view returns (uint256) {
        return uint256(vm.load(address(pool), bytes32(poolStorageLayout.nextLeafIndexSlot)));
    }

    function _noteDataHash(bytes memory data) internal pure returns (uint256) {
        return uint256(keccak256(data)) % FIELD_SIZE;
    }

    function _aliceSecrets() internal pure returns (UserSecrets memory actor) {
        actor = UserSecrets({
            account: ALICE,
            ownerNullifierKey: NK,
            noteSecretSeed: OS,
            deliverySecret: DS,
            signingPrivateKey: ALICE_SIGNING_PRIVATE_KEY
        });
    }

    function _bobSecrets(address bob) internal pure returns (UserSecrets memory actor) {
        actor = UserSecrets({
            account: bob,
            ownerNullifierKey: BOB_NK,
            noteSecretSeed: BOB_OS,
            deliverySecret: BOB_DS,
            signingPrivateKey: BOB_SIGNING_PRIVATE_KEY
        });
    }

    function _loadPoolStorageLayout() internal {
        string memory json = vm.readFile("out/ShieldedPool.sol/ShieldedPool.json");
        bool foundNextLeafIndex;
        bool foundUserTreeNodes;
        bool foundAuthTreeNodes;
        uint256 i;

        while (true) {
            string memory itemPath = string.concat(".storageLayout.storage[", vm.toString(i), "]");
            if (!vm.keyExistsJson(json, itemPath)) {
                break;
            }

            string memory label = vm.parseJsonString(json, string.concat(itemPath, ".label"));
            uint256 slot = vm.parseUint(vm.parseJsonString(json, string.concat(itemPath, ".slot")));

            if (keccak256(bytes(label)) == keccak256(bytes("nextLeafIndex"))) {
                poolStorageLayout.nextLeafIndexSlot = slot;
                foundNextLeafIndex = true;
            } else if (keccak256(bytes(label)) == keccak256(bytes("userTreeNodes"))) {
                poolStorageLayout.userTreeNodesSlot = slot;
                foundUserTreeNodes = true;
            } else if (keccak256(bytes(label)) == keccak256(bytes("authTreeNodes"))) {
                poolStorageLayout.authTreeNodesSlot = slot;
                foundAuthTreeNodes = true;
            }

            unchecked {
                ++i;
            }
        }

        assertTrue(foundNextLeafIndex, "missing nextLeafIndex slot");
        assertTrue(foundUserTreeNodes, "missing userTreeNodes slot");
        assertTrue(foundAuthTreeNodes, "missing authTreeNodes slot");
    }
}
