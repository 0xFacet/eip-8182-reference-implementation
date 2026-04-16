// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {ERC20AssetLib} from "../src/libraries/ERC20AssetLib.sol";
import {PoseidonFieldLib} from "../src/libraries/PoseidonFieldLib.sol";
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

    function test_PoseidonFieldDomainsMatchDerivedFormula() public pure {
        uint256 noteSecretSeed = 123;
        uint256 commitment = 456;
        uint256 outputNoteDataHash = 789;
        address user = address(0xA11CE);
        uint256 ownerNullifierKeyHash = 11;
        uint256 noteSecretSeedHashValue = 22;
        uint256 authDataCommitment = 200;
        uint256 policyVersion = 3;
        uint256 innerVkHash = 100;

        assertEq(
            PoseidonFieldLib.noteSecretSeedHash(noteSecretSeed),
            PoseidonFieldLib.poseidon2(_deriveEip8182Domain("note_secret_seed"), noteSecretSeed)
        );
        assertEq(
            PoseidonFieldLib.outputBinding(commitment, outputNoteDataHash),
            PoseidonFieldLib.poseidon3(_deriveEip8182Domain("output_binding"), commitment, outputNoteDataHash)
        );
        assertEq(
            PoseidonFieldLib.userRegistryLeaf(user, ownerNullifierKeyHash, noteSecretSeedHashValue),
            PoseidonFieldLib.poseidon4(
                _deriveEip8182Domain("user_registry_leaf"),
                uint256(uint160(user)),
                ownerNullifierKeyHash,
                noteSecretSeedHashValue
            )
        );
        assertEq(
            PoseidonFieldLib.authPolicyLeaf(authDataCommitment, policyVersion),
            PoseidonFieldLib.poseidon3(_deriveEip8182Domain("auth_policy"), authDataCommitment, policyVersion)
        );
        assertEq(
            PoseidonFieldLib.authPolicyTreeKey(user, innerVkHash),
            uint256(
                uint160(
                    PoseidonFieldLib.poseidon3(
                        _deriveEip8182Domain("auth_policy_key"), uint256(uint160(user)), innerVkHash
                    )
                )
            )
        );
        assertEq(
            PoseidonFieldLib.dummyOwnerNullifierKeyHash(),
            PoseidonFieldLib.poseidon2(_deriveEip8182Domain("owner_nullifier_key_hash"), 0xdead)
        );
    }

    function test_FirstInsertionRootMatchesProverEmptyHashSemantics() public {
        ShieldedPool.PublicInputs memory pi = _basePublicInputs();
        uint256[] memory commitments = new uint256[](3);
        commitments[0] = pi.noteCommitment0;
        commitments[1] = pi.noteCommitment1;
        commitments[2] = pi.noteCommitment2;

        pool.transact(hex"01", pi, "", "", "");

        (uint256 noteCommitmentRoot,,) = pool.getCurrentRoots();
        assertEq(noteCommitmentRoot, _expectedCommitmentRoot(0, commitments));
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
        pi.noteCommitment0 = FIELD_MODULUS;
        _expectNonCanonicalTransactRevert(pi);

        pi = _basePublicInputs();
        pi.noteCommitment1 = FIELD_MODULUS;
        _expectNonCanonicalTransactRevert(pi);

        pi = _basePublicInputs();
        pi.noteCommitment2 = FIELD_MODULUS;
        _expectNonCanonicalTransactRevert(pi);

        pi = _basePublicInputs();
        pi.transactionReplayId = FIELD_MODULUS;
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
        assertFalse(pool.isTransactionReplayIdUsed(pi.transactionReplayId));

        vm.recordLogs();
        pool.transact(hex"01", pi, "", "", "");

        assertTrue(pool.isNullifierSpent(pi.nullifier0));
        assertTrue(pool.isNullifierSpent(pi.nullifier1));
        assertTrue(pool.isTransactionReplayIdUsed(pi.transactionReplayId));

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
        assertEq(uint256(txnLog.topics[3]), pi.transactionReplayId);

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

        assertEq(noteCommitment0, pi.noteCommitment0);
        assertEq(noteCommitment1, pi.noteCommitment1);
        assertEq(noteCommitment2, pi.noteCommitment2);
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
        secondTx.transactionReplayId = 23;
        secondTx.noteCommitment0 = 31;
        secondTx.noteCommitment1 = 32;
        secondTx.noteCommitment2 = 33;

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
        overflowTx.transactionReplayId = 103;
        overflowTx.noteCommitment0 = 111;
        overflowTx.noteCommitment1 = 112;
        overflowTx.noteCommitment2 = 113;

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
        expiredRootTx.transactionReplayId = 53;
        expiredRootTx.noteCommitment0 = 61;
        expiredRootTx.noteCommitment1 = 62;
        expiredRootTx.noteCommitment2 = 63;

        vm.expectRevert(ShieldedPool.UnknownUserRegistryRoot.selector);
        pool.transact(hex"01", expiredRootTx, "", "", "");
    }

    function test_TransactRejectsBadOutputHash() public {
        ShieldedPool.PublicInputs memory pi = _basePublicInputs();

        vm.expectRevert(abi.encodeWithSelector(ShieldedPool.InvalidOutputNoteDataHash.selector, 0));
        pool.transact(hex"01", pi, hex"deadbeef", "", "");
    }

    function test_DepositETHTransfersValueIntoPool() public {
        ShieldedPool.PublicInputs memory pi = _basePublicInputs();
        pi.depositorAddress = uint256(uint160(ALICE));
        pi.publicAmountIn = 1 ether;
        pi.publicAmountOut = 0;
        pi.publicRecipientAddress = 0;

        vm.deal(ALICE, 2 ether);
        vm.prank(ALICE);
        pool.transact{value: 1 ether}(hex"01", pi, "", "", "");

        assertEq(address(pool).balance, 1 ether);
    }

    function test_DepositEthMismatchDoesNotConsumeNullifiers() public {
        ShieldedPool.PublicInputs memory pi = _basePublicInputs();
        pi.depositorAddress = uint256(uint160(ALICE));
        pi.publicAmountIn = 1 ether;

        vm.deal(ALICE, 2 ether);

        vm.prank(ALICE);
        vm.expectRevert(ShieldedPool.EthAmountMismatch.selector);
        pool.transact{value: 0.5 ether}(hex"01", pi, "", "", "");

        vm.prank(ALICE);
        pool.transact{value: 1 ether}(hex"01", pi, "", "", "");

        assertEq(address(pool).balance, 1 ether);
    }

    function test_UnexpectedEthDoesNotConsumeNullifiers() public {
        ShieldedPool.PublicInputs memory pi = _basePublicInputs();

        vm.expectRevert(ShieldedPool.UnexpectedEth.selector);
        pool.transact{value: 1}(hex"01", pi, "", "", "");

        pool.transact(hex"01", pi, "", "", "");
    }

    function test_InvalidPublicActionConfigurationDoesNotConsumeNullifiers() public {
        ShieldedPool.PublicInputs memory pi = _basePublicInputs();
        pi.depositorAddress = uint256(uint160(ALICE));
        pi.publicAmountIn = 1 ether;
        pi.publicRecipientAddress = uint256(uint160(address(0xB0B)));

        vm.deal(ALICE, 2 ether);

        vm.prank(ALICE);
        vm.expectRevert(ShieldedPool.InvalidPublicActionConfiguration.selector);
        pool.transact{value: 1 ether}(hex"01", pi, "", "", "");

        pi.publicRecipientAddress = 0;

        vm.prank(ALICE);
        pool.transact{value: 1 ether}(hex"01", pi, "", "", "");

        assertEq(address(pool).balance, 1 ether);
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

    function test_DepositERC20RejectsFeeOnTransferTokens() public {
        FeeOnTransferTestToken token = new FeeOnTransferTestToken(100);
        token.mint(ALICE, 10 ether);

        ShieldedPool.PublicInputs memory pi = _basePublicInputs();
        pi.depositorAddress = uint256(uint160(ALICE));
        pi.publicAmountIn = 5 ether;
        pi.publicAmountOut = 0;
        pi.publicRecipientAddress = 0;
        pi.publicTokenAddress = uint256(uint160(address(token)));

        vm.startPrank(ALICE);
        token.approve(address(pool), type(uint256).max);
        vm.expectRevert(ERC20AssetLib.ERC20TransferAmountMismatch.selector);
        pool.transact(hex"01", pi, "", "", "");
        vm.stopPrank();
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

    // ── Address/amount range rejection ──────────────────────────────────

    function test_TransactRejectsPublicAmountInAbove248Bits() public {
        ShieldedPool.PublicInputs memory pi = _basePublicInputs();
        pi.depositorAddress = uint256(uint160(ALICE));
        pi.publicAmountIn = 1 << 248;
        pi.publicAmountOut = 0;
        pi.publicRecipientAddress = 0;

        vm.expectRevert(ShieldedPool.AmountOutOfRange.selector);
        pool.transact(hex"01", pi, "", "", "");
    }

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

    function test_TransactRejectsDepositorAddressAbove160Bits() public {
        ShieldedPool.PublicInputs memory pi = _basePublicInputs();
        pi.depositorAddress = 1 << 160;

        vm.expectRevert(ShieldedPool.AddressOutOfRange.selector);
        pool.transact(hex"01", pi, "", "", "");
    }

    // ── Registration canonicality edge cases ────────────────────────────

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

    function test_DeregisterAuthPolicyRejectsNonCanonicalInnerVkHash() public {
        vm.prank(ALICE);
        vm.expectRevert(ShieldedPool.FieldElementNotCanonical.selector);
        pool.deregisterAuthPolicy(FIELD_MODULUS);
    }

    // ── Nullifier distinctness ──────────────────────────────────────────

    function test_TransactRejectsDuplicateNullifiers() public {
        ShieldedPool.PublicInputs memory pi = _basePublicInputs();
        pi.nullifier0 = 42;
        pi.nullifier1 = 42;

        vm.expectRevert(ShieldedPool.DuplicateNullifier.selector);
        pool.transact(hex"01", pi, "", "", "");
    }

    // ── Intent nullifier replay ─────────────────────────────────────────

    function test_TransactRejectsReusedTransactionReplayId() public {
        ShieldedPool.PublicInputs memory firstTx = _basePublicInputs();
        pool.transact(hex"01", firstTx, "", "", "");

        ShieldedPool.PublicInputs memory secondTx = _sequencedPublicInputs(500);
        secondTx.transactionReplayId = firstTx.transactionReplayId;

        vm.expectRevert(ShieldedPool.TransactionReplayIdAlreadyUsed.selector);
        pool.transact(hex"01", secondTx, "", "", "");
    }

    // ── Zero commitment rejection ───────────────────────────────────────

    function test_TransactRejectsZeroNoteCommitment0() public {
        ShieldedPool.PublicInputs memory pi = _basePublicInputs();
        pi.noteCommitment0 = 0;

        vm.expectRevert(ShieldedPool.ZeroNoteCommitment.selector);
        pool.transact(hex"01", pi, "", "", "");
    }

    function test_TransactRejectsZeroNoteCommitment1() public {
        ShieldedPool.PublicInputs memory pi = _basePublicInputs();
        pi.noteCommitment1 = 0;

        vm.expectRevert(ShieldedPool.ZeroNoteCommitment.selector);
        pool.transact(hex"01", pi, "", "", "");
    }

    function test_TransactRejectsZeroNoteCommitment2() public {
        ShieldedPool.PublicInputs memory pi = _basePublicInputs();
        pi.noteCommitment2 = 0;

        vm.expectRevert(ShieldedPool.ZeroNoteCommitment.selector);
        pool.transact(hex"01", pi, "", "", "");
    }

    function _basePublicInputs() private view returns (ShieldedPool.PublicInputs memory pi) {
        (pi.noteCommitmentRoot, pi.registryRoot, pi.authPolicyRegistryRoot) = pool.getCurrentRoots();
        pi.nullifier0 = 1;
        pi.nullifier1 = 2;
        pi.noteCommitment0 = 11;
        pi.noteCommitment1 = 12;
        pi.noteCommitment2 = 13;
        pi.transactionReplayId = 3;
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
        pi.transactionReplayId = offset + 3;
        pi.noteCommitment0 = offset + 4;
        pi.noteCommitment1 = offset + 5;
        pi.noteCommitment2 = offset + 6;
    }

    function _expectNonCanonicalTransactRevert(ShieldedPool.PublicInputs memory pi) private {
        vm.expectRevert(ShieldedPool.FieldElementNotCanonical.selector);
        pool.transact(hex"01", pi, "", "", "");
    }

    function _expectedCommitmentRoot(uint256 startingIndex, uint256[] memory commitments)
        private
        pure
        returns (uint256)
    {
        uint256[COMMITMENT_TREE_DEPTH] memory emptyHashes;
        uint256[COMMITMENT_TREE_DEPTH] memory filledNoteCommitmentSubtrees;
        uint256 nextIndex_ = startingIndex;
        uint256 root = _emptyHashBase();

        emptyHashes[0] = root;
        for (uint256 level = 1; level < COMMITMENT_TREE_DEPTH; ++level) {
            emptyHashes[level] = PoseidonFieldLib.hash2Raw(emptyHashes[level - 1], emptyHashes[level - 1]);
        }

        for (uint256 commitmentIndex; commitmentIndex < commitments.length; ++commitmentIndex) {
            uint256 index = nextIndex_;
            uint256 currentHash = commitments[commitmentIndex];

            for (uint256 level; level < COMMITMENT_TREE_DEPTH; ++level) {
                if (((index >> level) & 1) == 0) {
                    filledNoteCommitmentSubtrees[level] = currentHash;
                    currentHash = PoseidonFieldLib.hash2Raw(currentHash, emptyHashes[level]);
                } else {
                    currentHash = PoseidonFieldLib.hash2Raw(filledNoteCommitmentSubtrees[level], currentHash);
                }
            }

            root = currentHash;
            nextIndex_ = index + 1;
        }

        return root;
    }

    function _expectedSparseRoot(uint256 key, uint256 leaf) private pure returns (uint256 root) {
        root = leaf;
        uint256 empty = _emptyHashBase();

        for (uint256 level; level < REGISTRY_TREE_DEPTH; ++level) {
            uint256 bit = (key >> level) & 1;
            if (bit == 0) {
                root = PoseidonFieldLib.hash2Raw(root, empty);
            } else {
                root = PoseidonFieldLib.hash2Raw(empty, root);
            }
            empty = PoseidonFieldLib.hash2Raw(empty, empty);
        }
    }

    function _expectedSparseRootReversed(uint256 key, uint256 leaf) private pure returns (uint256 root) {
        root = leaf;
        uint256 empty = _emptyHashBase();

        for (uint256 level; level < REGISTRY_TREE_DEPTH; ++level) {
            uint256 bit = (key >> (REGISTRY_TREE_DEPTH - 1 - level)) & 1;
            if (bit == 0) {
                root = PoseidonFieldLib.hash2Raw(root, empty);
            } else {
                root = PoseidonFieldLib.hash2Raw(empty, root);
            }
            empty = PoseidonFieldLib.hash2Raw(empty, empty);
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
