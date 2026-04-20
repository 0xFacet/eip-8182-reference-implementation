// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {ERC20AssetLib} from "../src/libraries/ERC20AssetLib.sol";
import {PoseidonFieldLib} from "../src/libraries/PoseidonFieldLib.sol";
import {Poseidon2Sponge} from "../src/libraries/Poseidon2Sponge.sol";
import {InstallSystemTestBase} from "./helpers/InstallSystemTestBase.sol";
import {FeeOnTransferTestToken, TestToken} from "./mocks/TestToken.sol";

contract ShieldedPoolTest is Test, InstallSystemTestBase {
    uint256 private constant FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant COMMITMENT_TREE_DEPTH = 32;
    uint256 private constant REGISTRY_TREE_DEPTH = 160;
    uint256 private constant MAX_COMMITMENT_LEAF_INDEX = type(uint32).max;
    uint256 private constant MAX_VALID_UNTIL_SECONDS = type(uint32).max;
    uint256 private constant NOTE_COMMITMENT_ROOT_HISTORY_SIZE = 500;
    uint256 private constant USER_REGISTRY_ROOT_HISTORY_BLOCKS = 500;
    uint256 private constant AUTH_POLICY_ROOT_HISTORY_BLOCKS = 64;

    address private constant ALICE = address(0xA11CE);
    address private constant BOB = address(0xB0B);

    ShieldedPool private pool;
    RejectEtherReceiver private rejectEtherReceiver;

    function setUp() public {
        pool = installMockSystem();
        rejectEtherReceiver = new RejectEtherReceiver();
    }

    function test_InitialRootsAreNonZero() public view {
        (uint256 noteCommitmentRoot, uint256 userRoot, uint256 authRoot) = pool.getCurrentRoots();

        assertTrue(noteCommitmentRoot != 0);
        assertTrue(userRoot != 0);
        assertTrue(authRoot != 0);
        assertTrue(pool.isAcceptedNoteCommitmentRoot(noteCommitmentRoot));
        assertTrue(pool.isAcceptedUserRegistryRoot(userRoot));
        assertTrue(pool.isAcceptedAuthPolicyRoot(authRoot));
        assertFalse(pool.isAcceptedUserRegistryRoot(0));
        assertFalse(pool.isAcceptedAuthPolicyRoot(0));

        (bool registered, uint256 ownerNullifierKeyHash, uint256 noteSecretSeedHash) = pool.getUserRegistryEntry(ALICE);
        assertFalse(registered);
        assertEq(ownerNullifierKeyHash, 0);
        assertEq(noteSecretSeedHash, 0);
    }

    function test_InstallerSeedsEmptyHashCache() public {
        assertTrue(isEmptyHashCacheSeededForTest());
    }

    function test_PoseidonFieldDomainsMatchDerivedFormula_registryAndBinding() public pure {
        assertEq(
            PoseidonFieldLib.noteSecretSeedHash(123),
            Poseidon2Sponge.hashPair(_deriveEip8182Domain("note_secret_seed"), 123)
        );
        assertEq(
            PoseidonFieldLib.outputBinding(456, 789),
            Poseidon2Sponge.hash3(_deriveEip8182Domain("output_binding"), 456, 789)
        );
        address user = address(0xA11CE);
        assertEq(
            PoseidonFieldLib.userRegistryLeaf(user, 11, 22),
            Poseidon2Sponge.hash4(_deriveEip8182Domain("user_registry_leaf"), uint256(uint160(user)), 11, 22)
        );
        assertEq(
            PoseidonFieldLib.authPolicyLeaf(200, 3),
            Poseidon2Sponge.hash3(_deriveEip8182Domain("auth_policy"), 200, 3)
        );
        assertEq(
            PoseidonFieldLib.authPolicyTreeKey(user, 100),
            uint256(
                uint160(
                    Poseidon2Sponge.hash3(_deriveEip8182Domain("auth_policy_key"), uint256(uint160(user)), 100)
                )
            )
        );
        assertEq(
            PoseidonFieldLib.dummyOwnerNullifierKeyHash(),
            Poseidon2Sponge.hashPair(_deriveEip8182Domain("owner_nullifier_key_hash"), 0xdead)
        );
    }

    function test_PoseidonFieldDomainsMatchDerivedFormula_noteCommitmentLayers() public pure {
        uint256 oc = PoseidonFieldLib.ownerCommitment(11, 777);
        assertEq(oc, Poseidon2Sponge.hash3(_deriveEip8182Domain("owner_commitment"), 11, 777));

        uint256 body = PoseidonFieldLib.noteBodyCommitment(oc, 1 ether, 0, 0xdeadbeef);
        assertEq(
            body,
            Poseidon2Sponge.hash5(
                _deriveEip8182Domain("note_body_commitment"), oc, 1 ether, 0, 0xdeadbeef
            )
        );

        assertEq(
            PoseidonFieldLib.noteCommitment(body, 5),
            Poseidon2Sponge.hash3(_deriveEip8182Domain("note_commitment"), body, 5)
        );
    }

    function test_RegisterUserStoresDeliveryKey() public {
        vm.prank(ALICE);
        pool.registerUser(11, 22, 1, hex"1234");

        (bool registered, uint256 ownerNullifierKeyHash, uint256 noteSecretSeedHash) = pool.getUserRegistryEntry(ALICE);
        assertTrue(registered);
        assertEq(ownerNullifierKeyHash, 11);
        assertEq(noteSecretSeedHash, 22);

        (uint32 schemeId, bytes memory keyBytes) = pool.getDeliveryKey(ALICE);
        assertEq(schemeId, 1);
        assertEq(keccak256(keyBytes), keccak256(hex"1234"));
    }

    function test_RegisterUserRootMatchesProverEmptyHashSemantics() public {
        vm.prank(ALICE);
        pool.registerUser(11, 22);

        (, uint256 userRoot,) = pool.getCurrentRoots();
        uint256 userLeaf = PoseidonFieldLib.userRegistryLeaf(ALICE, 11, 22);
        assertEq(userRoot, _expectedSparseRoot(uint256(uint160(ALICE)), userLeaf));
    }

    function test_RegisterUserRootUsesLeafUpPathBits() public {
        address user = address(uint160((uint160(1) << 159) | 2));

        vm.prank(user);
        pool.registerUser(11, 22);

        (, uint256 userRoot,) = pool.getCurrentRoots();
        uint256 userLeaf = PoseidonFieldLib.userRegistryLeaf(user, 11, 22);
        uint256 userKey = uint256(uint160(user));
        assertEq(userRoot, _expectedSparseRoot(userKey, userLeaf));
        assertTrue(userRoot != _expectedSparseRootReversed(userKey, userLeaf));
    }

    function test_RotateOutputSecretUpdatesEntry() public {
        vm.prank(ALICE);
        pool.registerUser(11, 22);

        vm.prank(ALICE);
        pool.rotateNoteSecretSeed(33);

        (bool registered, uint256 ownerNullifierKeyHash, uint256 noteSecretSeedHash) = pool.getUserRegistryEntry(ALICE);
        assertTrue(registered);
        assertEq(ownerNullifierKeyHash, 11);
        assertEq(noteSecretSeedHash, 33);
    }

    function test_AuthPolicyVersionPersistsAcrossDeregistration() public {
        vm.prank(ALICE);
        pool.registerUser(11, 22);

        vm.prank(ALICE);
        pool.registerAuthPolicy(100, 200);

        (bool active0, uint256 authDataCommitment0, uint256 version0) = pool.getAuthPolicy(ALICE, 100);
        assertTrue(active0);
        assertEq(authDataCommitment0, 200);
        assertEq(version0, 1);

        vm.prank(ALICE);
        pool.deregisterAuthPolicy(100);

        (bool active1, uint256 authDataCommitment1, uint256 version1) = pool.getAuthPolicy(ALICE, 100);
        assertFalse(active1);
        assertEq(authDataCommitment1, 200);
        assertEq(version1, 1);

        vm.prank(ALICE);
        pool.registerAuthPolicy(100, 201);

        (bool active2, uint256 authDataCommitment2, uint256 version2) = pool.getAuthPolicy(ALICE, 100);
        assertTrue(active2);
        assertEq(authDataCommitment2, 201);
        assertEq(version2, 2);
    }

    function test_RegisterAuthPolicyRootMatchesProverEmptyHashSemantics() public {
        vm.prank(ALICE);
        pool.registerUser(11, 22);

        vm.prank(ALICE);
        pool.registerAuthPolicy(100, 200);

        (,, uint256 authRoot) = pool.getCurrentRoots();
        uint256 authKey = PoseidonFieldLib.authPolicyTreeKey(ALICE, 100);
        uint256 authLeaf = PoseidonFieldLib.authPolicyLeaf(200, 1);
        assertEq(authRoot, _expectedSparseRoot(authKey, authLeaf));
    }

    function test_RegisterAuthPolicyRootUsesLeafUpPathBits() public {
        address user = address(uint160((uint160(1) << 159) | 1));

        vm.prank(user);
        pool.registerUser(11, 22);

        vm.prank(user);
        pool.registerAuthPolicy(0x1234, 200);

        (,, uint256 authRoot) = pool.getCurrentRoots();
        uint256 authKey = PoseidonFieldLib.authPolicyTreeKey(user, 0x1234);
        uint256 authLeaf = PoseidonFieldLib.authPolicyLeaf(200, 1);
        assertEq(authRoot, _expectedSparseRoot(authKey, authLeaf));
        assertTrue(authRoot != _expectedSparseRootReversed(authKey, authLeaf));
    }

    function test_GetAuthPolicyRejectsNonCanonicalVkHash() public {
        vm.expectRevert(ShieldedPool.FieldElementNotCanonical.selector);
        pool.getAuthPolicy(ALICE, FIELD_MODULUS);
    }

    function test_RegisterAuthPolicyRequiresRegisteredUser() public {
        vm.prank(ALICE);
        vm.expectRevert(ShieldedPool.UserNotRegistered.selector);
        pool.registerAuthPolicy(100, 200);
    }

    function test_TransactRejectsInvalidProof() public {
        ShieldedPool.PublicInputs memory pi = _basePublicInputs();

        vm.expectRevert(ShieldedPool.InvalidProof.selector);
        pool.transact(hex"00", pi, "", "", "");
    }

    function test_TransactRejectsNonCanonicalProofDerivedFields() public {
        ShieldedPool.PublicInputs memory pi = _basePublicInputs();

        pi.noteCommitmentRoot = FIELD_MODULUS;
        _expectNonCanonicalTransactRevert(pi);

        pi = _basePublicInputs();
        pi.nullifier0 = FIELD_MODULUS;
        _expectNonCanonicalTransactRevert(pi);

        pi = _basePublicInputs();
        pi.nullifier1 = FIELD_MODULUS;
        _expectNonCanonicalTransactRevert(pi);

        pi = _basePublicInputs();
        pi.noteBodyCommitment0 = FIELD_MODULUS;
        _expectNonCanonicalTransactRevert(pi);

        pi = _basePublicInputs();
        pi.noteBodyCommitment1 = FIELD_MODULUS;
        _expectNonCanonicalTransactRevert(pi);

        pi = _basePublicInputs();
        pi.noteBodyCommitment2 = FIELD_MODULUS;
        _expectNonCanonicalTransactRevert(pi);

        pi = _basePublicInputs();
        pi.intentReplayId = FIELD_MODULUS;
        _expectNonCanonicalTransactRevert(pi);

        pi = _basePublicInputs();
        pi.registryRoot = FIELD_MODULUS;
        _expectNonCanonicalTransactRevert(pi);

        pi = _basePublicInputs();
        pi.authPolicyRegistryRoot = FIELD_MODULUS;
        _expectNonCanonicalTransactRevert(pi);

        pi = _basePublicInputs();
        pi.outputNoteDataHash0 = FIELD_MODULUS;
        _expectNonCanonicalTransactRevert(pi);

        pi = _basePublicInputs();
        pi.outputNoteDataHash1 = FIELD_MODULUS;
        _expectNonCanonicalTransactRevert(pi);

        pi = _basePublicInputs();
        pi.outputNoteDataHash2 = FIELD_MODULUS;
        _expectNonCanonicalTransactRevert(pi);
    }

    function test_TransactRejectsValidUntilSecondsOutsideUint32() public {
        ShieldedPool.PublicInputs memory pi = _basePublicInputs();
        pi.validUntilSeconds = MAX_VALID_UNTIL_SECONDS + 1;

        vm.expectRevert(ShieldedPool.IntentExpired.selector);
        pool.transact(hex"01", pi, "", "", "");
    }

    function test_TransactTransferEmitsCommitmentsAndPreventsReplay() public {
        ShieldedPool.PublicInputs memory pi = _basePublicInputs();

        assertFalse(pool.isNullifierSpent(pi.nullifier0));
        assertFalse(pool.isNullifierSpent(pi.nullifier1));
        assertFalse(pool.isIntentReplayIdUsed(pi.intentReplayId));

        vm.recordLogs();
        pool.transact(hex"01", pi, "", "", "");

        assertTrue(pool.isNullifierSpent(pi.nullifier0));
        assertTrue(pool.isNullifierSpent(pi.nullifier1));
        assertTrue(pool.isIntentReplayIdUsed(pi.intentReplayId));

        Vm.Log[] memory logs = vm.getRecordedLogs();
        Vm.Log memory txnLog = logs[logs.length - 1];

        assertEq(
            txnLog.topics[0],
            keccak256(
                "ShieldedPoolTransact(uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256,bytes,bytes,bytes)"
            )
        );
        assertEq(uint256(txnLog.topics[1]), pi.nullifier0);
        assertEq(uint256(txnLog.topics[2]), pi.nullifier1);
        assertEq(uint256(txnLog.topics[3]), pi.intentReplayId);

        (
            uint256 noteCommitment0,
            uint256 noteCommitment1,
            uint256 noteCommitment2,
            uint256 leafIndex0,
            uint256 postInsertionCommitmentRoot,
            bytes memory noteData0,
            bytes memory noteData1,
            bytes memory noteData2
        ) = abi.decode(txnLog.data, (uint256, uint256, uint256, uint256, uint256, bytes, bytes, bytes));

        // The event carries the final leaf-sealed commitments, not the body commitments.
        assertEq(noteCommitment0, PoseidonFieldLib.noteCommitment(pi.noteBodyCommitment0, leafIndex0));
        assertEq(noteCommitment1, PoseidonFieldLib.noteCommitment(pi.noteBodyCommitment1, leafIndex0 + 1));
        assertEq(noteCommitment2, PoseidonFieldLib.noteCommitment(pi.noteBodyCommitment2, leafIndex0 + 2));
        assertEq(leafIndex0, 0);
        assertTrue(postInsertionCommitmentRoot != pi.noteCommitmentRoot);
        assertEq(noteData0.length, 0);
        assertEq(noteData1.length, 0);
        assertEq(noteData2.length, 0);

        vm.expectRevert(ShieldedPool.NullifierAlreadySpent.selector);
        pool.transact(hex"01", pi, "", "", "");
    }

    function test_CommitmentHistoryAcceptsPreviousPreInsertionRoot() public {
        ShieldedPool.PublicInputs memory firstTx = _basePublicInputs();
        uint256 emptyRoot = firstTx.noteCommitmentRoot;

        pool.transact(hex"01", firstTx, "", "", "");

        ShieldedPool.PublicInputs memory secondTx = _basePublicInputs();
        secondTx.noteCommitmentRoot = emptyRoot;
        secondTx.nullifier0 = 21;
        secondTx.nullifier1 = 22;
        secondTx.intentReplayId = 23;
        secondTx.noteBodyCommitment0 = 31;
        secondTx.noteBodyCommitment1 = 32;
        secondTx.noteBodyCommitment2 = 33;

        pool.transact(hex"01", secondTx, "", "", "");
    }

    function test_TransactAllowsFinalThreeLeavesThenRevertsTreeFull() public {
        setNextLeafIndexForTest(MAX_COMMITMENT_LEAF_INDEX - 2);

        ShieldedPool.PublicInputs memory finalTx = _basePublicInputs();

        vm.recordLogs();
        pool.transact(hex"01", finalTx, "", "", "");

        Vm.Log[] memory logs = vm.getRecordedLogs();
        Vm.Log memory txnLog = logs[logs.length - 1];
        (,,, uint256 leafIndex0,,,,) =
            abi.decode(txnLog.data, (uint256, uint256, uint256, uint256, uint256, bytes, bytes, bytes));

        assertEq(leafIndex0, MAX_COMMITMENT_LEAF_INDEX - 2);

        (uint256 currentRoot,,) = pool.getCurrentRoots();
        assertTrue(currentRoot != 0);

        ShieldedPool.PublicInputs memory overflowTx = _basePublicInputs();
        overflowTx.nullifier0 = 101;
        overflowTx.nullifier1 = 102;
        overflowTx.intentReplayId = 103;
        overflowTx.noteBodyCommitment0 = 111;
        overflowTx.noteBodyCommitment1 = 112;
        overflowTx.noteBodyCommitment2 = 113;

        vm.expectRevert(ShieldedPool.TreeFull.selector);
        pool.transact(hex"01", overflowTx, "", "", "");
    }

    function test_CommitmentHistoryRejectsRootAfterWraparound() public {
        uint256 evictedRoot = _basePublicInputs().noteCommitmentRoot;

        pool.transact(hex"01", _sequencedPublicInputs(1), "", "", "");
        setCommitmentRootHistoryCountForTest(NOTE_COMMITMENT_ROOT_HISTORY_SIZE);
        pool.transact(hex"01", _sequencedPublicInputs(2), "", "", "");

        ShieldedPool.PublicInputs memory staleRootTx = _sequencedPublicInputs(1000);
        staleRootTx.noteCommitmentRoot = evictedRoot;

        vm.expectRevert(ShieldedPool.UnknownNoteCommitmentRoot.selector);
        pool.transact(hex"01", staleRootTx, "", "", "");
    }

    function test_AuthPolicyHistoryAcceptsRecentRootAndRejectsExpiredRoot() public {
        vm.prank(ALICE);
        pool.registerUser(11, 22);

        vm.prank(ALICE);
        pool.registerAuthPolicy(100, 200);
        (,, uint256 oldAuthRoot) = pool.getCurrentRoots();

        vm.roll(block.number + 1);
        vm.prank(ALICE);
        pool.registerAuthPolicy(100, 201);

        ShieldedPool.PublicInputs memory recentRootTx = _basePublicInputs();
        recentRootTx.authPolicyRegistryRoot = oldAuthRoot;
        pool.transact(hex"01", recentRootTx, "", "", "");

        vm.roll(block.number + AUTH_POLICY_ROOT_HISTORY_BLOCKS + 1);

        ShieldedPool.PublicInputs memory expiredRootTx = _sequencedPublicInputs(2000);
        expiredRootTx.authPolicyRegistryRoot = oldAuthRoot;

        vm.expectRevert(ShieldedPool.UnknownAuthPolicyRoot.selector);
        pool.transact(hex"01", expiredRootTx, "", "", "");
    }

    function test_UserRegistryHistoryAcceptsRecentRootAndRejectsExpiredRoot() public {
        vm.prank(ALICE);
        pool.registerUser(11, 22);
        (, uint256 oldUserRoot,) = pool.getCurrentRoots();

        vm.roll(block.number + 1);
        vm.prank(ALICE);
        pool.rotateNoteSecretSeed(33);

        ShieldedPool.PublicInputs memory recentRootTx = _basePublicInputs();
        recentRootTx.registryRoot = oldUserRoot;
        pool.transact(hex"01", recentRootTx, "", "", "");

        vm.roll(block.number + USER_REGISTRY_ROOT_HISTORY_BLOCKS + 1);

        ShieldedPool.PublicInputs memory expiredRootTx = _basePublicInputs();
        expiredRootTx.registryRoot = oldUserRoot;
        expiredRootTx.nullifier0 = 51;
        expiredRootTx.nullifier1 = 52;
        expiredRootTx.intentReplayId = 53;
        expiredRootTx.noteBodyCommitment0 = 61;
        expiredRootTx.noteBodyCommitment1 = 62;
        expiredRootTx.noteBodyCommitment2 = 63;

        vm.expectRevert(ShieldedPool.UnknownUserRegistryRoot.selector);
        pool.transact(hex"01", expiredRootTx, "", "", "");
    }

    function test_TransactRejectsBadOutputHash() public {
        ShieldedPool.PublicInputs memory pi = _basePublicInputs();

        vm.expectRevert(abi.encodeWithSelector(ShieldedPool.InvalidOutputNoteDataHash.selector, 0));
        pool.transact(hex"01", pi, hex"deadbeef", "", "");
    }

    // `transact` is non-payable per EIP Section 5.4 — Solidity rejects msg.value
    // at the dispatch layer before entering the function body.
    function test_TransactRejectsEthValue() public {
        ShieldedPool.PublicInputs memory pi = _basePublicInputs();
        vm.deal(ALICE, 1 ether);
        vm.prank(ALICE);
        (bool ok,) = address(pool).call{value: 1}(
            abi.encodeCall(pool.transact, (hex"01", pi, "", "", ""))
        );
        assertFalse(ok, "non-payable transact must reject msg.value");
    }

    function test_WithdrawalCallFailureDoesNotConsumeNullifiers() public {
        vm.deal(address(pool), 1 ether);

        ShieldedPool.PublicInputs memory pi = _basePublicInputs();
        pi.publicAmountOut = 1 ether;
        pi.publicRecipientAddress = uint256(uint160(address(rejectEtherReceiver)));

        vm.expectRevert(ShieldedPool.EthTransferFailed.selector);
        pool.transact(hex"01", pi, "", "", "");

        rejectEtherReceiver.setAcceptsEth(true);
        pool.transact(hex"01", pi, "", "", "");

        assertEq(address(rejectEtherReceiver).balance, 1 ether);
    }

    function test_WithdrawalERC20RejectsNoCodeTokenAddress() public {
        TestToken token = new TestToken();
        token.mint(address(pool), 5 ether);

        ShieldedPool.PublicInputs memory pi = _basePublicInputs();
        pi.publicAmountOut = 1 ether;
        pi.publicRecipientAddress = uint256(uint160(ALICE));
        pi.publicTokenAddress = uint256(uint160(address(0xB0B)));

        vm.expectRevert(ERC20AssetLib.ERC20CallFailed.selector);
        pool.transact(hex"01", pi, "", "", "");
    }

    // -- Deposit tests (contract-native deposit per EIP Section 5.3 / 5.4.2) --

    function test_DepositEthCreatesLeafSealedCommitment() public {
        uint256 ownerCommitment = PoseidonFieldLib.ownerCommitment(0xabc, 0xdef);
        uint256 leafIndex = 0;
        uint256 expectedBody = PoseidonFieldLib.noteBodyCommitment(ownerCommitment, 1 ether, 0, 0);
        uint256 expectedFinal = PoseidonFieldLib.noteCommitment(expectedBody, leafIndex);

        vm.deal(ALICE, 2 ether);
        vm.recordLogs();
        vm.prank(ALICE);
        pool.deposit{value: 1 ether}(address(0), 1 ether, 0, ownerCommitment, hex"");

        assertEq(address(pool).balance, 1 ether);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        Vm.Log memory dep = logs[logs.length - 1];
        assertEq(
            dep.topics[0],
            keccak256(
                "ShieldedPoolDeposit(address,uint256,uint256,uint256,uint256,uint256,uint256,bytes)"
            )
        );
        (
            uint256 noteCommitment,
            uint256 eventLeafIndex,
            uint256 amount,
            uint256 tokenAddress,
            uint256 originTag,
            uint256 postInsertionCommitmentRoot,
            bytes memory outputNoteData
        ) = abi.decode(dep.data, (uint256, uint256, uint256, uint256, uint256, uint256, bytes));
        assertEq(noteCommitment, expectedFinal);
        assertEq(eventLeafIndex, leafIndex);
        assertEq(amount, 1 ether);
        assertEq(tokenAddress, 0);
        assertEq(originTag, 0);
        assertTrue(postInsertionCommitmentRoot != 0);
        assertEq(outputNoteData.length, 0);
    }

    function test_DepositEthTaggedOriginIncludesOriginTag() public {
        uint256 ownerCommitment = PoseidonFieldLib.ownerCommitment(0xabc, 0xdef);
        uint256 leafIndex = 0;
        uint256 expectedOriginTag = PoseidonFieldLib.depositOriginTag(
            block.chainid, uint256(uint160(ALICE)), 0, 1 ether, leafIndex
        );

        vm.deal(ALICE, 2 ether);
        vm.recordLogs();
        vm.prank(ALICE);
        pool.deposit{value: 1 ether}(address(0), 1 ether, 1, ownerCommitment, hex"");

        Vm.Log[] memory logs = vm.getRecordedLogs();
        Vm.Log memory dep = logs[logs.length - 1];
        (, , , , uint256 originTag, ,) =
            abi.decode(dep.data, (uint256, uint256, uint256, uint256, uint256, uint256, bytes));
        assertEq(originTag, expectedOriginTag);
    }

    function test_DepositEthRejectsValueMismatch() public {
        uint256 ownerCommitment = PoseidonFieldLib.ownerCommitment(0xabc, 0xdef);
        vm.deal(ALICE, 2 ether);
        vm.prank(ALICE);
        vm.expectRevert(ShieldedPool.EthAmountMismatch.selector);
        pool.deposit{value: 0.5 ether}(address(0), 1 ether, 0, ownerCommitment, hex"");
    }

    function test_DepositRejectsZeroOwnerCommitment() public {
        vm.deal(ALICE, 2 ether);
        vm.prank(ALICE);
        vm.expectRevert(ShieldedPool.InvalidOwnerCommitment.selector);
        pool.deposit{value: 1 ether}(address(0), 1 ether, 0, 0, hex"");
    }

    function test_DepositRejectsZeroAmount() public {
        vm.deal(ALICE, 2 ether);
        vm.prank(ALICE);
        vm.expectRevert(ShieldedPool.InvalidDepositAmount.selector);
        pool.deposit{value: 0}(address(0), 0, 0, 1, hex"");
    }

    function test_DepositRejectsInvalidOriginMode() public {
        uint256 ownerCommitment = PoseidonFieldLib.ownerCommitment(0xabc, 0xdef);
        vm.deal(ALICE, 2 ether);
        vm.prank(ALICE);
        vm.expectRevert(ShieldedPool.InvalidOriginMode.selector);
        pool.deposit{value: 1 ether}(address(0), 1 ether, 2, ownerCommitment, hex"");
    }

    function test_DepositERC20RejectsFeeOnTransferTokens() public {
        FeeOnTransferTestToken token = new FeeOnTransferTestToken(100);
        token.mint(ALICE, 10 ether);
        uint256 ownerCommitment = PoseidonFieldLib.ownerCommitment(0xabc, 0xdef);

        vm.startPrank(ALICE);
        token.approve(address(pool), type(uint256).max);
        vm.expectRevert(ERC20AssetLib.ERC20TransferAmountMismatch.selector);
        pool.deposit(address(token), 5 ether, 0, ownerCommitment, hex"");
        vm.stopPrank();
    }

    // -- Registration canonicality edge cases --

    function test_RegisterUserRejectsNonCanonicalNullifierKeyHash() public {
        vm.prank(ALICE);
        vm.expectRevert(ShieldedPool.FieldElementNotCanonical.selector);
        pool.registerUser(FIELD_MODULUS, 22);
    }

    function test_RegisterUserRejectsNonCanonicalOutputSecretHash() public {
        vm.prank(ALICE);
        vm.expectRevert(ShieldedPool.FieldElementNotCanonical.selector);
        pool.registerUser(11, FIELD_MODULUS);
    }

    function test_RotateOutputSecretRejectsNonCanonicalHash() public {
        vm.prank(ALICE);
        pool.registerUser(11, 22);

        vm.prank(ALICE);
        vm.expectRevert(ShieldedPool.FieldElementNotCanonical.selector);
        pool.rotateNoteSecretSeed(FIELD_MODULUS);
    }

    function test_RegisterAuthPolicyRejectsNonCanonicalInnerVkHash() public {
        vm.prank(ALICE);
        pool.registerUser(11, 22);

        vm.prank(ALICE);
        vm.expectRevert(ShieldedPool.FieldElementNotCanonical.selector);
        pool.registerAuthPolicy(FIELD_MODULUS, 200);
    }

    function test_RegisterAuthPolicyRejectsNonCanonicalAuthDataCommitment() public {
        vm.prank(ALICE);
        pool.registerUser(11, 22);

        vm.prank(ALICE);
        vm.expectRevert(ShieldedPool.FieldElementNotCanonical.selector);
        pool.registerAuthPolicy(100, FIELD_MODULUS);
    }

    function test_RegisterUserRejectsReservedOwnerNullifierKeyHash() public {
        vm.prank(ALICE);
        vm.expectRevert(ShieldedPool.ReservedOwnerNullifierKeyHash.selector);
        pool.registerUser(PoseidonFieldLib.dummyOwnerNullifierKeyHash(), 22);
    }

    function test_RegisterUserRejectsZeroOwnerNullifierKeyHash() public {
        vm.prank(ALICE);
        vm.expectRevert(ShieldedPool.ReservedOwnerNullifierKeyHash.selector);
        pool.registerUser(0, 22);
    }

    function test_RegisterUserRejectsReusedOwnerNullifierKeyHashAcrossAddresses() public {
        vm.prank(ALICE);
        pool.registerUser(11, 22);

        vm.prank(BOB);
        vm.expectRevert(ShieldedPool.OwnerNullifierKeyHashAlreadyUsed.selector);
        pool.registerUser(11, 33);
    }

    function test_RegisterUserAcceptsDistinctOwnerNullifierKeyHashPerAddress() public {
        vm.prank(ALICE);
        pool.registerUser(11, 22);

        vm.prank(BOB);
        pool.registerUser(12, 33);

        (bool bobRegistered,,) = pool.getUserRegistryEntry(BOB);
        assertTrue(bobRegistered);
    }

    function test_DeregisterAuthPolicyRejectsNonCanonicalInnerVkHash() public {
        vm.prank(ALICE);
        vm.expectRevert(ShieldedPool.FieldElementNotCanonical.selector);
        pool.deregisterAuthPolicy(FIELD_MODULUS);
    }

    // -- Nullifier distinctness --

    function test_TransactRejectsDuplicateNullifiers() public {
        ShieldedPool.PublicInputs memory pi = _basePublicInputs();
        pi.nullifier0 = 42;
        pi.nullifier1 = 42;

        vm.expectRevert(ShieldedPool.DuplicateNullifier.selector);
        pool.transact(hex"01", pi, "", "", "");
    }

    // -- Intent replay id --

    function test_TransactRejectsReusedIntentReplayId() public {
        ShieldedPool.PublicInputs memory firstTx = _basePublicInputs();
        pool.transact(hex"01", firstTx, "", "", "");

        ShieldedPool.PublicInputs memory secondTx = _sequencedPublicInputs(500);
        secondTx.intentReplayId = firstTx.intentReplayId;

        vm.expectRevert(ShieldedPool.IntentReplayIdAlreadyUsed.selector);
        pool.transact(hex"01", secondTx, "", "", "");
    }

    // -- Public-input range rejection --

    function test_TransactRejectsPublicAmountOutAbove248Bits() public {
        ShieldedPool.PublicInputs memory pi = _basePublicInputs();
        pi.publicAmountOut = 1 << 248;
        pi.publicRecipientAddress = uint256(uint160(ALICE));

        vm.expectRevert(ShieldedPool.AmountOutOfRange.selector);
        pool.transact(hex"01", pi, "", "", "");
    }

    function test_TransactRejectsPublicRecipientAddressAbove160Bits() public {
        ShieldedPool.PublicInputs memory pi = _basePublicInputs();
        pi.publicAmountOut = 1 ether;
        pi.publicRecipientAddress = 1 << 160;

        vm.expectRevert(ShieldedPool.AddressOutOfRange.selector);
        pool.transact(hex"01", pi, "", "", "");
    }

    function test_TransactRejectsPublicTokenAddressAbove160Bits() public {
        ShieldedPool.PublicInputs memory pi = _basePublicInputs();
        pi.publicTokenAddress = 1 << 160;

        vm.expectRevert(ShieldedPool.AddressOutOfRange.selector);
        pool.transact(hex"01", pi, "", "", "");
    }

    function _basePublicInputs() private view returns (ShieldedPool.PublicInputs memory pi) {
        (pi.noteCommitmentRoot, pi.registryRoot, pi.authPolicyRegistryRoot) = pool.getCurrentRoots();
        pi.nullifier0 = 1;
        pi.nullifier1 = 2;
        pi.noteBodyCommitment0 = 11;
        pi.noteBodyCommitment1 = 12;
        pi.noteBodyCommitment2 = 13;
        pi.intentReplayId = 3;
        pi.validUntilSeconds = block.timestamp + 1 hours;
        pi.executionChainId = block.chainid;

        uint256 emptyHash = uint256(keccak256(bytes(""))) % FIELD_MODULUS;
        pi.outputNoteDataHash0 = emptyHash;
        pi.outputNoteDataHash1 = emptyHash;
        pi.outputNoteDataHash2 = emptyHash;
    }

    function _deriveEip8182Domain(string memory context) private pure returns (uint256) {
        return uint256(keccak256(bytes(string.concat("eip-8182.", context)))) % FIELD_MODULUS;
    }

    function _sequencedPublicInputs(uint256 seed) private view returns (ShieldedPool.PublicInputs memory pi) {
        pi = _basePublicInputs();
        uint256 offset = seed * 10;
        pi.nullifier0 = offset + 1;
        pi.nullifier1 = offset + 2;
        pi.intentReplayId = offset + 3;
        pi.noteBodyCommitment0 = offset + 4;
        pi.noteBodyCommitment1 = offset + 5;
        pi.noteBodyCommitment2 = offset + 6;
    }

    function _expectNonCanonicalTransactRevert(ShieldedPool.PublicInputs memory pi) private {
        vm.expectRevert(ShieldedPool.FieldElementNotCanonical.selector);
        pool.transact(hex"01", pi, "", "", "");
    }

    function _expectedSparseRoot(uint256 key, uint256 leaf) private pure returns (uint256 root) {
        root = leaf;
        uint256 empty = _emptyHashBase();

        for (uint256 level; level < REGISTRY_TREE_DEPTH; ++level) {
            uint256 bit = (key >> level) & 1;
            if (bit == 0) {
                root = PoseidonFieldLib.merkleHash(root, empty);
            } else {
                root = PoseidonFieldLib.merkleHash(empty, root);
            }
            empty = PoseidonFieldLib.merkleHash(empty, empty);
        }
    }

    function _expectedSparseRootReversed(uint256 key, uint256 leaf) private pure returns (uint256 root) {
        root = leaf;
        uint256 empty = _emptyHashBase();

        for (uint256 level; level < REGISTRY_TREE_DEPTH; ++level) {
            uint256 bit = (key >> (REGISTRY_TREE_DEPTH - 1 - level)) & 1;
            if (bit == 0) {
                root = PoseidonFieldLib.merkleHash(root, empty);
            } else {
                root = PoseidonFieldLib.merkleHash(empty, root);
            }
            empty = PoseidonFieldLib.merkleHash(empty, empty);
        }
    }

    function _emptyHashBase() private pure returns (uint256) {
        return 0;
    }
}

contract RejectEtherReceiver {
    bool private acceptsEth;

    function setAcceptsEth(bool acceptsEth_) external {
        acceptsEth = acceptsEth_;
    }

    receive() external payable {
        require(acceptsEth, "reject eth");
    }
}
