// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ShieldedPoolE2EBase} from "./helpers/ShieldedPoolE2EBase.sol";

contract SmokeE2ETest is ShieldedPoolE2EBase {
    function test_Smoke_FullFlowAndRecovery() public {
        (PreparedUser memory aliceUser, uint256 alicePolicyVersion, ProofFixture memory depositFixture) =
            _depositAliceSingleSig();

        address bob = BOB;
        PreparedUser memory bobUser = _prepareBob(bob);
        TransferRequest memory request = _standardTransferRequest(alicePolicyVersion, depositFixture, bob, bobUser);

        ProofFixture memory transferFixture = _generateTransferFixture(aliceUser, request);
        _assertVerifierAccepts(transferFixture);
        _assertTransferFixture(transferFixture, depositFixture.note0Amount - TRANSFER_AMOUNT);

        uint256 bobLeafIndex = _nextLeafIndex();
        _executeTransferFixture(transferFixture);

        _assertTransferredNoteCanBeWithdrawn(bob, bobUser, bobLeafIndex, depositFixture, transferFixture);
    }

    function _standardTransferRequest(
        uint256 policyVersion,
        ProofFixture memory depositFixture,
        address recipient,
        PreparedUser memory recipientUser
    ) internal view returns (TransferRequest memory request) {
        request = TransferRequest({
            policyVersion: policyVersion,
            commitRoot: _currentCommitmentRoot(),
            userRegRoot: _currentUserRegistryRoot(),
            authPolicyRoot: _currentAuthPolicyRoot(),
            inputLeafIndex: 0,
            inputAmount: depositFixture.note0Amount,
            inputRandomness: depositFixture.note0Randomness,
            inputOriginTag: depositFixture.note0OriginTag,
            recipient: recipient,
            recipientNkHash: recipientUser.nkHash,
            recipientOsHash: recipientUser.osHash,
            transferAmount: TRANSFER_AMOUNT,
            changeAmount: depositFixture.note0Amount - TRANSFER_AMOUNT,
            inputSiblings: _commitmentSiblings(_depositLeaves(depositFixture), 0),
            userSiblings: _userRegistrySiblings(ALICE),
            recipientSiblings: _userRegistrySiblings(recipient)
        });
    }

    function _assertTransferredNoteCanBeWithdrawn(
        address bob,
        PreparedUser memory bobUser,
        uint256 bobLeafIndex,
        ProofFixture memory depositFixture,
        ProofFixture memory transferFixture
    ) internal {
        RecoveredNote memory bobNote = _recoverSingleChainNote(
            bob, BOB_NK, BOB_DS, bobLeafIndex, transferFixture.noteData0, transferFixture.pubInputs.commitment0
        );
        assertTrue(bobNote.found, "recipient note not recovered");
        assertEq(bobNote.amount, TRANSFER_AMOUNT, "recovered amount mismatch");

        uint256 bobPolicyVersion = _registerAuthPolicy(bob, bobUser.innerVkHash, bobUser.authDataCommitment);
        UserSecrets memory bobSecrets = _bobSecrets(bob);
        address publicRecipient = makeAddr("smokeWithdrawRecipient");
        uint256 balanceBefore = publicRecipient.balance;
        uint256[] memory combinedLeaves = _combinedLeaves(depositFixture, transferFixture);
        WithdrawRequest memory request;
        request.policyVersion = bobPolicyVersion;
        request.commitRoot = _currentCommitmentRoot();
        request.userRegRoot = _currentUserRegistryRoot();
        request.authPolicyRoot = _currentAuthPolicyRoot();
        request.inputLeafIndex = bobLeafIndex;
        request.inputAmount = bobNote.amount;
        request.inputRandomness = bobNote.randomness;
        request.inputOriginTag = bobNote.originTag;
        request.publicRecipient = publicRecipient;
        request.withdrawAmount = RECOVERED_WITHDRAW_AMOUNT;
        request.inputSiblings = _commitmentSiblings(combinedLeaves, bobLeafIndex);
        request.userSiblings = _userRegistrySiblings(bob);
        ProofFixture memory withdrawFixture = _generateWithdrawFixtureForActor(
            bobUser,
            bobSecrets,
            request
        );

        _assertVerifierAccepts(withdrawFixture);
        _assertWithdrawFixture(
            withdrawFixture, publicRecipient, RECOVERED_WITHDRAW_AMOUNT, TRANSFER_AMOUNT - RECOVERED_WITHDRAW_AMOUNT
        );
        _executeWithdrawFixture(withdrawFixture);
        assertEq(publicRecipient.balance - balanceBefore, RECOVERED_WITHDRAW_AMOUNT, "recipient received ETH");
    }
}
