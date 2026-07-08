// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {SelfServeAllowlistPolicyVerifier} from "../src/policy/SelfServeAllowlistPolicyVerifier.sol";
import {ErcConstants} from "../src/generated/ErcConstants.sol";
import {Poseidon2Sponge} from "../src/libraries/Poseidon2Sponge.sol";
import {PoseidonFieldLib} from "../src/libraries/PoseidonFieldLib.sol";

contract SelfServeAllowlistPolicyVerifierTest is Test {
    SelfServeAllowlistPolicyVerifier internal policy;

    address internal pool = address(0x9000);
    address internal sender = address(0xA11CE);
    address internal other = address(0xB0B);
    address internal token = address(0);

    function setUp() public {
        policy = new SelfServeAllowlistPolicyVerifier();
    }

    function test_joinAllowlistRegistersCaller() public {
        assertFalse(policy.isAllowed(sender));

        vm.prank(sender);
        policy.joinAllowlist();

        assertTrue(policy.isAllowed(sender));
        assertFalse(policy.isAllowed(other));
    }

    function test_depositPolicyAcceptsJoinedSender() public {
        vm.prank(sender);
        policy.joinAllowlist();

        uint256 amount = 1000;
        uint256 ownerCommitment = 12345;
        uint256 outputNoteDataHash = 67890;
        bytes memory details = abi.encode(sender, token, amount, ownerCommitment, outputNoteDataHash);
        bytes memory policyData = abi.encode(uint8(ErcConstants.POLICY_OPERATION_DEPOSIT), details);
        uint256 digest = _depositDigest(sender, token, amount, ownerCommitment, outputNoteDataHash);

        vm.prank(pool);
        assertTrue(policy.verifyPolicy(abi.encode(digest), policyData));
    }

    function test_depositPolicyRejectsUnjoinedSender() public {
        uint256 amount = 1000;
        uint256 ownerCommitment = 12345;
        uint256 outputNoteDataHash = 67890;
        bytes memory details = abi.encode(sender, token, amount, ownerCommitment, outputNoteDataHash);
        bytes memory policyData = abi.encode(uint8(ErcConstants.POLICY_OPERATION_DEPOSIT), details);
        uint256 digest = _depositDigest(sender, token, amount, ownerCommitment, outputNoteDataHash);

        vm.prank(pool);
        assertFalse(policy.verifyPolicy(abi.encode(digest), policyData));
    }

    function test_depositPolicyRejectsTamperedAmount() public {
        vm.prank(sender);
        policy.joinAllowlist();

        uint256 amount = 1000;
        uint256 ownerCommitment = 12345;
        uint256 outputNoteDataHash = 67890;
        bytes memory details = abi.encode(sender, token, amount + 1, ownerCommitment, outputNoteDataHash);
        bytes memory policyData = abi.encode(uint8(ErcConstants.POLICY_OPERATION_DEPOSIT), details);
        uint256 digest = _depositDigest(sender, token, amount, ownerCommitment, outputNoteDataHash);

        vm.prank(pool);
        assertFalse(policy.verifyPolicy(abi.encode(digest), policyData));
    }

    function test_transactPolicyAcceptsJoinedAuthorizer() public {
        vm.prank(sender);
        policy.joinAllowlist();

        SelfServeAllowlistPolicyVerifier.TransactDetails memory d = _transactDetails(sender);
        bytes memory policyData = abi.encode(uint8(ErcConstants.POLICY_OPERATION_TRANSACT), abi.encode(d));
        uint256 digest = _transactDigest(d);

        vm.prank(pool);
        assertTrue(policy.verifyPolicy(abi.encode(digest), policyData));
    }

    function test_transactPolicyRejectsUnjoinedAuthorizer() public {
        SelfServeAllowlistPolicyVerifier.TransactDetails memory d = _transactDetails(sender);
        bytes memory policyData = abi.encode(uint8(ErcConstants.POLICY_OPERATION_TRANSACT), abi.encode(d));
        uint256 digest = _transactDigest(d);

        vm.prank(pool);
        assertFalse(policy.verifyPolicy(abi.encode(digest), policyData));
    }

    function test_transactPolicyRejectsTamperedPublicTransition() public {
        vm.prank(sender);
        policy.joinAllowlist();

        SelfServeAllowlistPolicyVerifier.TransactDetails memory d = _transactDetails(sender);
        uint256 digest = _transactDigest(d);
        d.nullifier0 ^= 1;
        bytes memory policyData = abi.encode(uint8(ErcConstants.POLICY_OPERATION_TRANSACT), abi.encode(d));

        vm.prank(pool);
        assertFalse(policy.verifyPolicy(abi.encode(digest), policyData));
    }

    function test_malformedPolicyDataRejected() public {
        vm.prank(sender);
        policy.joinAllowlist();

        vm.startPrank(pool);
        assertFalse(policy.verifyPolicy(hex"", hex""));
        assertFalse(policy.verifyPolicy(abi.encode(uint256(1)), hex""));
        assertFalse(policy.verifyPolicy(abi.encode(uint256(1)), abi.encode(uint8(9), bytes(""))));
        vm.stopPrank();
    }

    function _depositDigest(
        address depositor,
        address asset,
        uint256 amount,
        uint256 ownerCommitment,
        uint256 outputNoteDataHash
    ) internal view returns (uint256) {
        uint256 opData = PoseidonFieldLib.depositOperationDataHash(
            block.chainid,
            uint256(uint160(pool)),
            uint256(uint160(depositor)),
            uint256(uint160(asset)),
            amount,
            ownerCommitment,
            outputNoteDataHash
        );
        return _policyDigest(ErcConstants.POLICY_OPERATION_DEPOSIT, opData);
    }

    function _transactDigest(SelfServeAllowlistPolicyVerifier.TransactDetails memory d)
        internal
        view
        returns (uint256)
    {
        uint256 opData = PoseidonFieldLib.transactOperationDataHash(
            _transactIntentFieldsHash(d),
            _transactPublicTransitionHash(d)
        );
        return _policyDigest(ErcConstants.POLICY_OPERATION_TRANSACT, opData);
    }

    function _policyDigest(uint256 kind, uint256 opData) internal view returns (uint256) {
        return PoseidonFieldLib.policyOperationDigest(
            block.chainid,
            uint256(uint160(pool)),
            uint256(uint160(address(policy))),
            kind,
            opData
        );
    }

    function _transactDetails(address authorizer)
        internal
        view
        returns (SelfServeAllowlistPolicyVerifier.TransactDetails memory d)
    {
        d.authVerifier = address(0xA001);
        d.authorizingAddress = authorizer;
        d.operationKind = ErcConstants.WITHDRAWAL_OP;
        d.token = address(0);
        d.recipientOwnerNullifierKeyHash = 0;
        d.amount = 250;
        d.feeNoteRecipientOwnerNullifierKeyHash = 0;
        d.feeAmount = 0;
        d.publicRecipientAddress = address(0xCAFE);
        d.authorizedSubmitter = address(0);
        d.downstreamActionCommitment = 0;
        d.executionConstraintsFlags = 0;
        d.lockedOutputBinding0 = 0;
        d.lockedOutputBinding1 = 0;
        d.lockedOutputBinding2 = 0;
        d.nonce = 0x123;
        d.validUntilSeconds = block.timestamp + 3600;
        d.noteCommitmentRoot = 0x111;
        d.nullifier0 = 0x222;
        d.nullifier1 = 0x333;
        d.noteBodyCommitment0 = 0x444;
        d.noteBodyCommitment1 = 0x555;
        d.noteBodyCommitment2 = 0x666;
        d.publicAmountOut = 250;
        d.publicTokenAddress = address(0);
        d.intentReplayId = 0x777;
        d.identityRoot = 0x888;
        d.outputNoteDataHash0 = 0x999;
        d.outputNoteDataHash1 = 0xaaa;
        d.outputNoteDataHash2 = 0xbbb;
        d.blindedAuthCommitment = 0xccc;
    }

    function _transactIntentFieldsHash(SelfServeAllowlistPolicyVerifier.TransactDetails memory d)
        internal
        view
        returns (uint256)
    {
        uint256[] memory inputs = new uint256[](20);
        inputs[0] = ErcConstants.TRANSACT_INTENT_FIELDS_DOMAIN;
        inputs[1] = uint256(uint160(pool));
        inputs[2] = uint256(uint160(d.authVerifier));
        inputs[3] = uint256(uint160(d.authorizingAddress));
        inputs[4] = d.operationKind;
        inputs[5] = uint256(uint160(d.token));
        inputs[6] = d.recipientOwnerNullifierKeyHash;
        inputs[7] = d.amount;
        inputs[8] = d.feeNoteRecipientOwnerNullifierKeyHash;
        inputs[9] = d.feeAmount;
        inputs[10] = uint256(uint160(d.publicRecipientAddress));
        inputs[11] = uint256(uint160(d.authorizedSubmitter));
        inputs[12] = d.downstreamActionCommitment;
        inputs[13] = d.executionConstraintsFlags;
        inputs[14] = d.lockedOutputBinding0;
        inputs[15] = d.lockedOutputBinding1;
        inputs[16] = d.lockedOutputBinding2;
        inputs[17] = d.nonce;
        inputs[18] = d.validUntilSeconds;
        inputs[19] = block.chainid;
        return Poseidon2Sponge.hash(inputs);
    }

    function _transactPublicTransitionHash(SelfServeAllowlistPolicyVerifier.TransactDetails memory d)
        internal
        view
        returns (uint256)
    {
        uint256[] memory inputs = new uint256[](22);
        inputs[0] = ErcConstants.POLICY_TRANSACT_PUBLIC_TRANSITION_DOMAIN;
        inputs[1] = d.noteCommitmentRoot;
        inputs[2] = d.nullifier0;
        inputs[3] = d.nullifier1;
        inputs[4] = d.noteBodyCommitment0;
        inputs[5] = d.noteBodyCommitment1;
        inputs[6] = d.noteBodyCommitment2;
        inputs[7] = d.publicAmountOut;
        inputs[8] = uint256(uint160(d.publicRecipientAddress));
        inputs[9] = uint256(uint160(d.publicTokenAddress));
        inputs[10] = d.intentReplayId;
        inputs[11] = d.validUntilSeconds;
        inputs[12] = block.chainid;
        inputs[13] = uint256(uint160(pool));
        inputs[14] = d.identityRoot;
        inputs[15] = d.outputNoteDataHash0;
        inputs[16] = d.outputNoteDataHash1;
        inputs[17] = d.outputNoteDataHash2;
        inputs[18] = uint256(uint160(d.authVerifier));
        inputs[19] = d.blindedAuthCommitment;
        inputs[20] = uint256(uint160(d.authorizedSubmitter));
        inputs[21] = d.downstreamActionCommitment;
        return Poseidon2Sponge.hash(inputs);
    }
}
