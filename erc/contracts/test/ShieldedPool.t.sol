// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";

import {ShieldedPool} from "../src/ShieldedPool.sol";
import {IShieldedPool, IShieldedPoolStructs} from "../src/interfaces/IShieldedPool.sol";
import {IPolicyVerifier} from "../src/interfaces/IPolicyVerifier.sol";
import {PrivacyIdentityRegistry} from "../src/PrivacyIdentityRegistry.sol";
import {PoseidonFieldLib} from "../src/libraries/PoseidonFieldLib.sol";
import {ERC20AssetLib} from "../src/libraries/ERC20AssetLib.sol";
import {ErcConstants} from "../src/generated/ErcConstants.sol";

import {MockPoolVerifier} from "./mocks/MockPoolVerifier.sol";
import {MockAuthVerifier} from "./mocks/MockAuthVerifier.sol";
import {MockPolicyVerifier} from "./mocks/MockPolicyVerifier.sol";
import {StandardToken} from "./mocks/tokens/StandardToken.sol";
import {ReturnsNothingToken} from "./mocks/tokens/ReturnsNothingToken.sol";
import {ReturnsFalseToken} from "./mocks/tokens/ReturnsFalseToken.sol";
import {FeeOnTransferToken} from "./mocks/tokens/FeeOnTransferToken.sol";
import {ReentrantToken} from "./mocks/tokens/ReentrantToken.sol";

/// @dev Rejects all ETH so a withdrawal CALL fails (EthTransferFailed).
contract RejectingReceiver {
    fallback() external payable {
        revert("no eth");
    }
}

/// @notice Unit tests for ShieldedPool (spec sections 4/5/7/16.1). Verifiers are
///         mocked; real proof acceptance is covered by CanonicalPoolVerifier.t.sol.
contract ShieldedPoolTest is Test {
    uint256 internal constant P = ErcConstants.P;
    uint256 internal constant MAX_UINT248 = type(uint248).max;
    uint256 internal constant MAX_UINT160 = type(uint160).max;

    bytes internal constant OND0 = hex"a1a1a1";
    bytes internal constant OND1 = hex"b2b2";
    bytes internal constant OND2 = hex"c3";

    PrivacyIdentityRegistry internal registry;
    MockPoolVerifier internal poolVerifier;
    MockAuthVerifier internal authVerifier;
    MockPolicyVerifier internal policyVerifier;

    ShieldedPool internal ungated; // policyVerifier = 0, applies = 0

    address internal constant IDENTITY_USER = address(0xA11CE);
    address internal constant EOA = address(0xE0A);

    uint256 internal identityRoot;
    uint256 internal noteRoot; // fresh EMPTY[32], identical for every pool

    function setUp() public {
        vm.warp(1_000_000);

        registry = new PrivacyIdentityRegistry();
        poolVerifier = new MockPoolVerifier();
        authVerifier = new MockAuthVerifier();
        policyVerifier = new MockPolicyVerifier();

        vm.prank(IDENTITY_USER);
        registry.setIdentity(111, 222, 333);
        identityRoot = registry.getCurrentIdentityRoot();

        ungated = new ShieldedPool(registry, poolVerifier, address(0), 0);
        (noteRoot,) = ungated.getCurrentRoots();

        vm.deal(address(this), 100 ether);
    }

    // -------------------------------- helpers --------------------------------

    function _kf(bytes memory d) internal pure returns (uint256) {
        return uint256(keccak256(d)) % P;
    }

    function _baseline(address poolAddr)
        internal
        view
        returns (IShieldedPoolStructs.PublicInputs memory pi)
    {
        // 24-field literals blow the stack; assign field-by-field.
        pi.noteCommitmentRoot = noteRoot;
        pi.nullifier0 = 1001;
        pi.nullifier1 = 1002;
        pi.noteBodyCommitment0 = 11;
        pi.noteBodyCommitment1 = 12;
        pi.noteBodyCommitment2 = 13;
        pi.publicAmountOut = 0; // transfer
        pi.publicRecipientAddress = 0;
        pi.publicTokenAddress = 0;
        pi.intentReplayId = 5;
        pi.validUntilSeconds = block.timestamp + 3600;
        pi.executionChainId = block.chainid;
        pi.poolAddress = uint256(uint160(poolAddr));
        pi.identityRoot = identityRoot;
        pi.outputNoteDataHash0 = _kf(OND0);
        pi.outputNoteDataHash1 = _kf(OND1);
        pi.outputNoteDataHash2 = _kf(OND2);
        pi.authVerifier = uint256(uint160(address(authVerifier)));
        pi.blindedAuthCommitment = 777;
        pi.transactionIntentDigest = 888;
        pi.policyOperationDataHash = 0; // ungated
        pi.policyDataHash = _kf("");
        pi.authorizedSubmitter = 0; // anyone may submit
        pi.downstreamActionCommitment = 0;
    }

    function _transact(ShieldedPool p, IShieldedPoolStructs.PublicInputs memory pi, bytes memory pd)
        internal
    {
        p.transact(hex"00", hex"00", pi, OND0, OND1, OND2, pd);
    }

    struct TransactLog {
        uint256 n0;
        uint256 n1;
        uint256 replayId;
        uint256 c0;
        uint256 c1;
        uint256 c2;
        uint256 leafIndex0;
        uint256 postRoot;
    }

    function _findTransactLog() internal returns (TransactLog memory out) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].topics[0] == IShieldedPool.ShieldedPoolTransact.selector) {
                out.n0 = uint256(logs[i].topics[1]);
                out.n1 = uint256(logs[i].topics[2]);
                out.replayId = uint256(logs[i].topics[3]);
                // First 6 head words are the static fields; trailing bytes come after.
                (, out.c0, out.c1, out.c2, out.leafIndex0, out.postRoot) =
                    abi.decode(logs[i].data, (address, uint256, uint256, uint256, uint256, uint256));
                return out;
            }
        }
        revert("transact log not found");
    }

    function _expectedCommitment(address poolAddr, uint256 nbc, uint256 leafIndex)
        internal
        view
        returns (uint256)
    {
        return PoseidonFieldLib.noteCommitment(block.chainid, uint256(uint160(poolAddr)), nbc, leafIndex);
    }

    // ================================================================
    // 1. Section 7.1 preconditions, one mutation per test
    // ================================================================

    function test_rejectWrongChainId() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        vm.chainId(block.chainid + 1);
        vm.expectRevert(ShieldedPool.WrongChainId.selector);
        _transact(ungated, pi, "");
    }

    function test_rejectPoolAddressMismatch() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.poolAddress = uint256(uint160(address(0xBEEF)));
        vm.expectRevert(ShieldedPool.PoolAddressMismatch.selector);
        _transact(ungated, pi, "");
    }

    function test_rejectValidUntilZero() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.validUntilSeconds = 0;
        vm.expectRevert(ShieldedPool.IntentExpired.selector);
        _transact(ungated, pi, "");
    }

    function test_rejectValidUntilExpired() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.validUntilSeconds = block.timestamp - 1;
        vm.expectRevert(ShieldedPool.IntentExpired.selector);
        _transact(ungated, pi, "");
    }

    function test_rejectValidUntilTooFar() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.validUntilSeconds = block.timestamp + 86400 + 1;
        vm.expectRevert(ShieldedPool.IntentLifetimeTooLong.selector);
        _transact(ungated, pi, "");
    }

    function test_rejectUnknownNoteRoot() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.noteCommitmentRoot = uint256(keccak256("not a root")) % P;
        vm.expectRevert(ShieldedPool.UnknownNoteCommitmentRoot.selector);
        _transact(ungated, pi, "");
    }

    function test_rejectZeroIdentityRoot() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.identityRoot = 0;
        vm.expectRevert(ShieldedPool.ZeroIdentityRoot.selector);
        _transact(ungated, pi, "");
    }

    function test_rejectUnknownIdentityRoot() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.identityRoot = identityRoot + 1;
        vm.expectRevert(ShieldedPool.UnknownIdentityRoot.selector);
        _transact(ungated, pi, "");
    }

    function test_rejectEqualNullifiers() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.nullifier1 = pi.nullifier0;
        vm.expectRevert(ShieldedPool.DuplicateNullifier.selector);
        _transact(ungated, pi, "");
    }

    function test_rejectAmountOutOfRange() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.publicAmountOut = MAX_UINT248 + 1;
        vm.expectRevert(ShieldedPool.AmountOutOfRange.selector);
        _transact(ungated, pi, "");
    }

    function test_rejectRecipientOutOfRange() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.publicRecipientAddress = MAX_UINT160 + 1;
        vm.expectRevert(ShieldedPool.AddressOutOfRange.selector);
        _transact(ungated, pi, "");
    }

    function test_rejectTokenOutOfRange() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.publicTokenAddress = MAX_UINT160 + 1;
        vm.expectRevert(ShieldedPool.AddressOutOfRange.selector);
        _transact(ungated, pi, "");
    }

    function test_rejectAuthVerifierOutOfRange() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.authVerifier = MAX_UINT160 + 1;
        vm.expectRevert(ShieldedPool.AddressOutOfRange.selector);
        _transact(ungated, pi, "");
    }

    function test_rejectAuthVerifierZero() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.authVerifier = 0;
        vm.expectRevert(ShieldedPool.AuthVerifierMissing.selector);
        _transact(ungated, pi, "");
    }

    function test_rejectPolicyOperationDataHashNonCanonical() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.policyOperationDataHash = P;
        vm.expectRevert(ShieldedPool.FieldElementNotCanonical.selector);
        _transact(ungated, pi, "");
    }

    function test_rejectPolicyDataHashNonCanonical() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.policyDataHash = P;
        vm.expectRevert(ShieldedPool.FieldElementNotCanonical.selector);
        _transact(ungated, pi, "");
    }

    function test_rejectPolicyDataBindingMismatch() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.policyDataHash = 1; // canonical but != keccakField("")
        vm.expectRevert(ShieldedPool.InvalidPolicyData.selector);
        _transact(ungated, pi, "");
    }

    function test_rejectOutputNoteDataHash0() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.outputNoteDataHash0 ^= 1;
        vm.expectRevert(abi.encodeWithSelector(ShieldedPool.InvalidOutputNoteDataHash.selector, uint8(0)));
        _transact(ungated, pi, "");
    }

    function test_rejectOutputNoteDataHash1() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.outputNoteDataHash1 ^= 1;
        vm.expectRevert(abi.encodeWithSelector(ShieldedPool.InvalidOutputNoteDataHash.selector, uint8(1)));
        _transact(ungated, pi, "");
    }

    function test_rejectOutputNoteDataHash2() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.outputNoteDataHash2 ^= 1;
        vm.expectRevert(abi.encodeWithSelector(ShieldedPool.InvalidOutputNoteDataHash.selector, uint8(2)));
        _transact(ungated, pi, "");
    }

    // ================================================================
    // 2. Verifier dispatch failure taxonomy
    // ================================================================

    function test_poolProofRejected() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        poolVerifier.setResult(false);
        vm.expectRevert(ShieldedPool.PoolProofRejected.selector);
        _transact(ungated, pi, "");
    }

    function test_authVerifierMissingNoCode() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.authVerifier = uint256(uint160(address(0xDEAD))); // nonzero, no code
        vm.expectRevert(ShieldedPool.AuthVerifierMissing.selector);
        _transact(ungated, pi, "");
    }

    function test_authProofRejectedOnRevert() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        authVerifier.setMode(MockAuthVerifier.Mode.Revert);
        vm.expectRevert(ShieldedPool.AuthProofRejected.selector);
        _transact(ungated, pi, "");
    }

    function test_authProofRejectedOnWrongLength() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        authVerifier.setMode(MockAuthVerifier.Mode.WrongLength);
        vm.expectRevert(ShieldedPool.AuthProofRejected.selector);
        _transact(ungated, pi, "");
    }

    function test_authProofRejectedOnFalse() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        authVerifier.setMode(MockAuthVerifier.Mode.ReturnFalse);
        vm.expectRevert(ShieldedPool.AuthProofRejected.selector);
        _transact(ungated, pi, "");
    }

    // ================================================================
    // 3. Policy dispatch (section 16.1) + constructor gating
    // ================================================================

    function test_ungatedRejectsNonzeroPolicyOpHash() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.policyOperationDataHash = 123;
        vm.expectRevert(ShieldedPool.InvalidPolicyOperationDataHash.selector);
        _transact(ungated, pi, "");
    }

    function test_ungatedRejectsNonemptyPolicyData() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        bytes memory pd = hex"1234";
        pi.policyDataHash = _kf(pd); // pass the binding so we reach the ungated check
        vm.expectRevert(ShieldedPool.InvalidPolicyData.selector);
        _transact(ungated, pi, pd);
    }

    function _gatedTransactPool() internal returns (ShieldedPool) {
        // applies = TRANSFER | WITHDRAWAL = 6
        return new ShieldedPool(registry, poolVerifier, address(policyVerifier), 6);
    }

    function test_gatedTransactRequiresNonzeroPolicyOpHash() public {
        ShieldedPool gated = _gatedTransactPool();
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(gated));
        pi.policyOperationDataHash = 0;
        vm.expectRevert(ShieldedPool.InvalidPolicyOperationDataHash.selector);
        _transact(gated, pi, "");
    }

    function test_gatedTransactDispatchesExactDigest() public {
        ShieldedPool gated = _gatedTransactPool();
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(gated));
        bytes memory pd = hex"abcd";
        pi.policyOperationDataHash = 424242;
        pi.policyDataHash = _kf(pd);

        uint256 digest = PoseidonFieldLib.policyOperationDigest(
            block.chainid,
            uint256(uint160(address(gated))),
            uint256(uint160(address(policyVerifier))),
            ErcConstants.POLICY_OPERATION_TRANSACT,
            pi.policyOperationDataHash
        );
        // Belt: strict mode makes the mock reject any other digest.
        policyVerifier.setExpectedDigest(digest);
        // Suspenders: assert the exact dispatched calldata.
        vm.expectCall(
            address(policyVerifier),
            abi.encodeCall(IPolicyVerifier.verifyPolicy, (abi.encode(digest), pd))
        );
        _transact(gated, pi, pd);
    }

    function test_gatedTransactPolicyRejected() public {
        ShieldedPool gated = _gatedTransactPool();
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(gated));
        pi.policyOperationDataHash = 424242;
        policyVerifier.setResult(false);
        vm.expectRevert(ShieldedPool.PolicyRejected.selector);
        _transact(gated, pi, "");
    }

    function test_constructorRejectsInvalidPolicyConfig() public {
        // verifier == 0 but applies != 0
        vm.expectRevert(ShieldedPool.InvalidPolicyConfiguration.selector);
        new ShieldedPool(registry, poolVerifier, address(0), 2);

        // verifier != 0 but applies == 0
        vm.expectRevert(ShieldedPool.InvalidPolicyConfiguration.selector);
        new ShieldedPool(registry, poolVerifier, address(policyVerifier), 0);

        // applies >= 16 (undefined bits)
        vm.expectRevert(ShieldedPool.InvalidPolicyConfiguration.selector);
        new ShieldedPool(registry, poolVerifier, address(policyVerifier), 16);
    }

    function test_constructorIntrospection() public view {
        assertEq(ungated.policyVerifier(), address(0));
        assertEq(ungated.policyAppliesToOperations(), 0);
    }

    // ================================================================
    // 4. transact success path + replay protection
    // ================================================================

    function test_transactSuccessMarksStateAndEmits() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));

        vm.recordLogs();
        _transact(ungated, pi, "");

        assertTrue(ungated.isNullifierSpent(1001));
        assertTrue(ungated.isNullifierSpent(1002));
        assertTrue(ungated.isIntentReplayIdUsed(5));

        // Root advanced; the pre-insertion root is retained in history.
        (uint256 newRoot,) = ungated.getCurrentRoots();
        assertTrue(newRoot != noteRoot, "root advanced");
        assertTrue(ungated.isAcceptedNoteCommitmentRoot(noteRoot), "old root retained");
        assertTrue(ungated.isAcceptedNoteCommitmentRoot(newRoot), "new root accepted");

        TransactLog memory ev = _findTransactLog();
        assertEq(ev.n0, 1001);
        assertEq(ev.n1, 1002);
        assertEq(ev.replayId, 5);
        assertEq(ev.leafIndex0, 0);
        assertEq(ev.postRoot, newRoot);
        assertEq(ev.c0, _expectedCommitment(address(ungated), 11, 0));
        assertEq(ev.c1, _expectedCommitment(address(ungated), 12, 1));
        assertEq(ev.c2, _expectedCommitment(address(ungated), 13, 2));
    }

    function test_transactRejectsSpentNullifier() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        _transact(ungated, pi, "");

        IShieldedPoolStructs.PublicInputs memory pi2 = _baseline(address(ungated));
        pi2.nullifier0 = 1001; // reused
        pi2.nullifier1 = 2002; // fresh
        pi2.intentReplayId = 6; // fresh
        vm.expectRevert(ShieldedPool.NullifierAlreadySpent.selector);
        _transact(ungated, pi2, "");
    }

    function test_transactRejectsReusedIntentReplayId() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        _transact(ungated, pi, "");

        IShieldedPoolStructs.PublicInputs memory pi2 = _baseline(address(ungated));
        pi2.nullifier0 = 3001; // fresh
        pi2.nullifier1 = 3002; // fresh
        pi2.intentReplayId = 5; // reused
        vm.expectRevert(ShieldedPool.IntentReplayIdAlreadyUsed.selector);
        _transact(ungated, pi2, "");
    }

    // ================================================================
    // 5. Withdrawal branch (public action)
    // ================================================================

    function test_ethWithdrawalPaysEoa() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.publicAmountOut = 1000;
        pi.publicRecipientAddress = uint256(uint160(EOA));
        pi.publicTokenAddress = 0;
        vm.deal(address(ungated), 1000);

        uint256 before = EOA.balance;
        _transact(ungated, pi, "");
        assertEq(EOA.balance - before, 1000);
        assertEq(address(ungated).balance, 0);
    }

    function test_ethWithdrawalRejectingReceiverReverts() public {
        RejectingReceiver rr = new RejectingReceiver();
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.publicAmountOut = 1000;
        pi.publicRecipientAddress = uint256(uint160(address(rr)));
        vm.deal(address(ungated), 1000);
        vm.expectRevert(ShieldedPool.EthTransferFailed.selector);
        _transact(ungated, pi, "");
    }

    function test_erc20Withdrawal() public {
        StandardToken token = new StandardToken();
        token.mint(address(ungated), 5000);

        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.publicAmountOut = 1000;
        pi.publicRecipientAddress = uint256(uint160(EOA));
        pi.publicTokenAddress = uint256(uint160(address(token)));

        _transact(ungated, pi, "");
        assertEq(token.balanceOf(EOA), 1000);
        assertEq(token.balanceOf(address(ungated)), 4000);
    }

    function test_publicActionConfigInvariants() public {
        // amountOut == 0 but recipient != 0
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.publicRecipientAddress = uint256(uint160(EOA));
        vm.expectRevert(ShieldedPool.InvalidPublicActionConfiguration.selector);
        _transact(ungated, pi, "");

        // amountOut == 0 but token != 0
        pi = _baseline(address(ungated));
        pi.publicTokenAddress = uint256(uint160(address(0xABCD)));
        vm.expectRevert(ShieldedPool.InvalidPublicActionConfiguration.selector);
        _transact(ungated, pi, "");

        // amountOut > 0 but recipient == 0
        pi = _baseline(address(ungated));
        pi.publicAmountOut = 1000;
        vm.expectRevert(ShieldedPool.InvalidPublicActionConfiguration.selector);
        _transact(ungated, pi, "");
    }

    // ================================================================
    // 5b. Submitter authorization (section 7.1)
    // ================================================================

    function test_authorizedSubmitterWrongSenderReverts() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.authorizedSubmitter = uint256(uint160(address(0xF00D)));
        vm.prank(EOA); // not the authorized submitter
        vm.expectRevert(ShieldedPool.UnauthorizedSubmitter.selector);
        _transact(ungated, pi, "");
    }

    function test_authorizedSubmitterCorrectSenderPasses() public {
        address submitter = address(0xF00D);
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.authorizedSubmitter = uint256(uint160(submitter));

        vm.prank(submitter);
        _transact(ungated, pi, "");

        assertTrue(ungated.isNullifierSpent(1001));
        assertTrue(ungated.isIntentReplayIdUsed(5));
    }

    function test_authorizedSubmitterOutOfRangeReverts() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.authorizedSubmitter = MAX_UINT160 + 1;
        vm.expectRevert(ShieldedPool.AddressOutOfRange.selector);
        _transact(ungated, pi, "");
    }

    function test_downstreamActionNonCanonicalReverts() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.downstreamActionCommitment = P;
        vm.expectRevert(ShieldedPool.FieldElementNotCanonical.selector);
        _transact(ungated, pi, "");
    }

    function test_downstreamActionRequiresSubmitter() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        pi.authorizedSubmitter = 0;
        pi.downstreamActionCommitment = 12345; // nonzero commitment, no submitter
        vm.expectRevert(ShieldedPool.DownstreamActionRequiresSubmitter.selector);
        _transact(ungated, pi, "");
    }

    // ================================================================
    // 6. deposit (section 7.3 / 7.4)
    // ================================================================

    function test_depositEthSuccessEmits() public {
        uint256 amount = 1000;
        uint256 oc = 42;

        vm.recordLogs();
        ungated.deposit{value: amount}(address(0), amount, oc, OND0, "");

        Vm.Log[] memory logs = vm.getRecordedLogs();
        (uint256 nc, uint256 leafIndex, uint256 amt, uint256 tokenAddr, uint256 postRoot) =
            _decodeDepositLog(logs);

        uint256 body = PoseidonFieldLib.noteBodyCommitment(oc, amount, 0);
        uint256 expected = PoseidonFieldLib.noteCommitment(
            block.chainid, uint256(uint160(address(ungated))), body, 0
        );
        assertEq(nc, expected);
        assertEq(leafIndex, 0);
        assertEq(amt, amount);
        assertEq(tokenAddr, 0);
        (uint256 curRoot,) = ungated.getCurrentRoots();
        assertEq(postRoot, curRoot);
        assertEq(address(ungated).balance, amount);
    }

    function _decodeDepositLog(Vm.Log[] memory logs)
        internal
        pure
        returns (uint256 nc, uint256 leafIndex, uint256 amount, uint256 tokenAddr, uint256 postRoot)
    {
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].topics[0] == IShieldedPool.ShieldedPoolDeposit.selector) {
                (nc, leafIndex, amount, tokenAddr, postRoot) =
                    abi.decode(logs[i].data, (uint256, uint256, uint256, uint256, uint256));
                return (nc, leafIndex, amount, tokenAddr, postRoot);
            }
        }
        revert("deposit log not found");
    }

    function test_depositEthAmountMismatch() public {
        vm.expectRevert(ShieldedPool.EthAmountMismatch.selector);
        ungated.deposit{value: 999}(address(0), 1000, 42, OND0, "");
    }

    function test_depositErc20WithEthReverts() public {
        StandardToken token = new StandardToken();
        token.mint(address(this), 5000);
        token.approve(address(ungated), type(uint256).max);
        vm.expectRevert(ShieldedPool.UnexpectedEth.selector);
        ungated.deposit{value: 1}(address(token), 1000, 42, OND0, "");
    }

    function test_depositAmountZero() public {
        vm.expectRevert(ShieldedPool.InvalidDepositAmount.selector);
        ungated.deposit(address(0), 0, 42, OND0, "");
    }

    function test_depositAmountTooLarge() public {
        vm.expectRevert(ShieldedPool.InvalidDepositAmount.selector);
        ungated.deposit(address(0), MAX_UINT248 + 1, 42, OND0, "");
    }

    function test_depositOwnerCommitmentZero() public {
        vm.expectRevert(ShieldedPool.InvalidOwnerCommitment.selector);
        ungated.deposit{value: 1000}(address(0), 1000, 0, OND0, "");
    }

    function test_depositOwnerCommitmentNonCanonical() public {
        vm.expectRevert(ShieldedPool.FieldElementNotCanonical.selector);
        ungated.deposit{value: 1000}(address(0), 1000, P, OND0, "");
    }

    function test_depositFeeOnTransferRejected() public {
        FeeOnTransferToken token = new FeeOnTransferToken(1);
        token.mint(address(this), 5000);
        token.approve(address(ungated), type(uint256).max);
        // pullExact's balance-delta check fires before the redundant
        // Erc20DeliveredLess check in deposit.
        vm.expectRevert(ERC20AssetLib.ERC20TransferAmountMismatch.selector);
        ungated.deposit(address(token), 1000, 42, OND0, "");
    }

    function test_depositReturnsNothingTokenAccepted() public {
        ReturnsNothingToken token = new ReturnsNothingToken();
        token.mint(address(this), 5000);
        token.approve(address(ungated), type(uint256).max);
        ungated.deposit(address(token), 1000, 42, OND0, "");
        assertEq(token.balanceOf(address(ungated)), 1000);
    }

    function test_depositReturnsFalseTokenRejected() public {
        ReturnsFalseToken token = new ReturnsFalseToken();
        token.mint(address(this), 5000);
        token.approve(address(ungated), type(uint256).max);
        vm.expectRevert(ERC20AssetLib.ERC20CallFailed.selector);
        ungated.deposit(address(token), 1000, 42, OND0, "");
    }

    function test_depositStandardErc20() public {
        StandardToken token = new StandardToken();
        token.mint(address(this), 5000);
        token.approve(address(ungated), type(uint256).max);
        ungated.deposit(address(token), 1000, 42, OND0, "");
        assertEq(token.balanceOf(address(ungated)), 1000);
    }

    function test_depositUngatedRequiresEmptyPolicyData() public {
        vm.expectRevert(ShieldedPool.InvalidPolicyData.selector);
        ungated.deposit{value: 1000}(address(0), 1000, 42, OND0, hex"1234");
    }

    function _depositGatedPool() internal returns (ShieldedPool) {
        // applies = DEPOSIT = 1
        return new ShieldedPool(registry, poolVerifier, address(policyVerifier), 1);
    }

    function test_depositGatedDispatchesExactDigest() public {
        ShieldedPool gated = _depositGatedPool();
        uint256 amount = 1000;
        uint256 oc = 42;
        bytes memory pd = hex"5678";

        uint256 opData = PoseidonFieldLib.depositOperationDataHash(
            block.chainid,
            uint256(uint160(address(gated))),
            uint256(uint160(address(this))),
            0, // token == address(0)
            amount,
            oc,
            _kf(OND0)
        );
        uint256 digest = PoseidonFieldLib.policyOperationDigest(
            block.chainid,
            uint256(uint160(address(gated))),
            uint256(uint160(address(policyVerifier))),
            ErcConstants.POLICY_OPERATION_DEPOSIT,
            opData
        );
        policyVerifier.setExpectedDigest(digest);
        vm.expectCall(
            address(policyVerifier),
            abi.encodeCall(IPolicyVerifier.verifyPolicy, (abi.encode(digest), pd))
        );
        gated.deposit{value: amount}(address(0), amount, oc, OND0, pd);
    }

    function test_depositGatedPolicyRejected() public {
        ShieldedPool gated = _depositGatedPool();
        policyVerifier.setResult(false);
        vm.expectRevert(ShieldedPool.PolicyRejected.selector);
        gated.deposit{value: 1000}(address(0), 1000, 42, OND0, "");
    }

    // ================================================================
    // 7. Reentrancy
    // ================================================================

    function test_depositReentrancyBlocked() public {
        ReentrantToken token = new ReentrantToken();
        token.setPool(ungated);
        token.mint(address(this), 5000);
        token.approve(address(ungated), type(uint256).max);

        ungated.deposit(address(token), 1000, 42, OND0, "");

        assertTrue(token.attempted(), "reentry attempted");
        assertEq(
            token.reentryRevertSelector(),
            ShieldedPool.ReentrantCall.selector,
            "reentry blocked by guard"
        );
        assertEq(token.balanceOf(address(ungated)), 1000);
    }

    // ================================================================
    // 8. transact is non-payable
    // ================================================================

    function test_transactNonPayable() public {
        IShieldedPoolStructs.PublicInputs memory pi = _baseline(address(ungated));
        (bool ok,) = address(ungated).call{value: 1}(
            abi.encodeCall(IShieldedPool.transact, (hex"00", hex"00", pi, OND0, OND1, OND2, hex""))
        );
        assertFalse(ok, "transact must reject ETH");
    }
}
