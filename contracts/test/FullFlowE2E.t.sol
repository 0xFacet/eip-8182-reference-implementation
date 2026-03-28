// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ShieldedPoolE2EBase} from "./helpers/ShieldedPoolE2EBase.sol";

contract FullFlowE2ETest is ShieldedPoolE2EBase {
    struct RecoveredTransferContext {
        address bob;
        PreparedUser bobUser;
        UserSecrets bobSecrets;
        uint256 bobPolicyVersion;
        uint256 transferLeafIndex0;
        ProofFixture depositFixture;
        ProofFixture transferFixture;
    }

    function test_FullFlow_TransferAfterDeposit() public {
        PreparedUser memory aliceUser = _deriveTestUser(NK, OS, DS, ALICE_SIGNING_PRIVATE_KEY);
        uint256 currentPolicyVersion = _registerAlice(aliceUser);

        ProofFixture memory depositFixture = _generateDepositFixture(
            aliceUser,
            currentPolicyVersion,
            _currentCommitmentRoot(),
            _currentUserRegistryRoot(),
            _currentAuthPolicyRoot()
        );
        _assertAndExecuteDepositFixture(depositFixture);

        address bob = BOB;
        PreparedUser memory bobUser = _prepareBob(bob);

        ProofFixture memory transferFixture = _generateTransferFixture(
            aliceUser,
            TransferRequest({
                policyVersion: currentPolicyVersion,
                commitRoot: _currentCommitmentRoot(),
                userRegRoot: _currentUserRegistryRoot(),
                authPolicyRoot: _currentAuthPolicyRoot(),
                inputLeafIndex: 0,
                inputAmount: depositFixture.note0Amount,
                inputRandomness: depositFixture.note0Randomness,
                inputOriginTag: depositFixture.note0OriginTag,
                recipient: bob,
                recipientNkHash: bobUser.nkHash,
                recipientOsHash: bobUser.osHash,
                transferAmount: TRANSFER_AMOUNT,
                changeAmount: depositFixture.note0Amount - TRANSFER_AMOUNT,
                inputSiblings: _commitmentSiblings(_depositLeaves(depositFixture), 0),
                userSiblings: _userRegistrySiblings(ALICE),
                recipientSiblings: _userRegistrySiblings(bob)
            })
        );

        _assertTransferFixture(transferFixture, depositFixture.note0Amount - TRANSFER_AMOUNT);
        _executeTransferFixture(transferFixture);
    }

    function test_FullFlow_TransferAfterDeposit_With2of3MultisigAuth() public {
        (PreparedUser memory aliceUser,, ProofFixture memory depositFixture) = _depositAliceSingleSig();

        address bob = BOB;
        PreparedUser memory bobUser = _prepareBob(bob);

        PreparedAuthPolicy memory multisigPolicy = _deriveMultisigPolicy();
        uint256 multisigPolicyVersion =
            _registerAuthPolicy(ALICE, multisigPolicy.innerVkHash, multisigPolicy.authDataCommitment);
        assertEq(multisigPolicyVersion, 1, "multisig policy version");

        uint256[REGISTRY_TREE_DEPTH] memory authSiblings = _authPolicySiblings(ALICE, multisigPolicy.innerVkHash);
        TransferRequest memory request = TransferRequest({
            policyVersion: multisigPolicyVersion,
            commitRoot: _currentCommitmentRoot(),
            userRegRoot: _currentUserRegistryRoot(),
            authPolicyRoot: _currentAuthPolicyRoot(),
            inputLeafIndex: 0,
            inputAmount: depositFixture.note0Amount,
            inputRandomness: depositFixture.note0Randomness,
            inputOriginTag: depositFixture.note0OriginTag,
            recipient: bob,
            recipientNkHash: bobUser.nkHash,
            recipientOsHash: bobUser.osHash,
            transferAmount: TRANSFER_AMOUNT,
            changeAmount: depositFixture.note0Amount - TRANSFER_AMOUNT,
            inputSiblings: _commitmentSiblings(_depositLeaves(depositFixture), 0),
            userSiblings: _userRegistrySiblings(ALICE),
            recipientSiblings: _userRegistrySiblings(bob)
        });

        ProofFixture memory transferFixture = _generateMultisigTransferFixture(aliceUser, request, authSiblings);

        _assertTransferFixture(transferFixture, depositFixture.note0Amount - TRANSFER_AMOUNT);
        _assertVerifierAccepts(transferFixture);
        _executeTransferFixture(transferFixture);
    }

    function test_FullFlow_Deposit_With2of3MultisigAuth() public {
        PreparedUser memory aliceUser = _deriveTestUser(NK, OS, DS, ALICE_SIGNING_PRIVATE_KEY);
        _registerUserWithoutAuth(ALICE, aliceUser);

        PreparedAuthPolicy memory multisigPolicy = _deriveMultisigPolicy();
        uint256 multisigPolicyVersion =
            _registerAuthPolicy(ALICE, multisigPolicy.innerVkHash, multisigPolicy.authDataCommitment);
        assertEq(multisigPolicyVersion, 1, "multisig policy version");

        ProofFixture memory depositFixture = _generateMultisigDepositFixture(
            aliceUser,
            multisigPolicyVersion,
            _currentCommitmentRoot(),
            _currentUserRegistryRoot(),
            _currentAuthPolicyRoot(),
            _authPolicySiblings(ALICE, multisigPolicy.innerVkHash)
        );

        _assertVerifierAccepts(depositFixture);
        _assertAndExecuteDepositFixture(depositFixture);
    }

    function test_FullFlow_DepositDefaultOriginModeLeavesOutputUntagged() public {
        PreparedUser memory aliceUser = _deriveTestUser(NK, OS, DS, ALICE_SIGNING_PRIVATE_KEY);
        uint256 currentPolicyVersion = _registerAlice(aliceUser);

        ProofFixture memory depositFixture = _generateDepositFixture(
            aliceUser,
            currentPolicyVersion,
            _currentCommitmentRoot(),
            _currentUserRegistryRoot(),
            _currentAuthPolicyRoot()
        );

        assertEq(depositFixture.note0OriginTag, 0, "default origin mode should leave recipient note untagged");
        _assertAndExecuteDepositFixture(depositFixture);
    }

    function test_FullFlow_DepositTaggedOriginModeProducesNonzeroOriginTag() public {
        PreparedUser memory aliceUser = _deriveTestUser(NK, OS, DS, ALICE_SIGNING_PRIVATE_KEY);
        uint256 currentPolicyVersion = _registerAlice(aliceUser);

        string memory params = _buildDepositParams(
            aliceUser,
            currentPolicyVersion,
            _currentCommitmentRoot(),
            _currentUserRegistryRoot(),
            _currentAuthPolicyRoot()
        );
        vm.serializeUint("depositParams", "originMode", 1);
        params = vm.serializeString("depositParams", "signingPrivateKey", ALICE_SIGNING_PRIVATE_KEY);

        ProofFixture memory depositFixture = _runProofGenerator(params);

        assertGt(depositFixture.note0OriginTag, 0, "tagged origin mode should derive a nonzero origin tag");
        _assertAndExecuteDepositFixture(depositFixture);
    }

    function test_FullFlow_WithdrawAfterDeposit_With2of3MultisigAuth() public {
        PreparedUser memory aliceUser = _deriveTestUser(NK, OS, DS, ALICE_SIGNING_PRIVATE_KEY);
        _registerUserWithoutAuth(ALICE, aliceUser);

        PreparedAuthPolicy memory multisigPolicy = _deriveMultisigPolicy();
        uint256 multisigPolicyVersion =
            _registerAuthPolicy(ALICE, multisigPolicy.innerVkHash, multisigPolicy.authDataCommitment);
        assertEq(multisigPolicyVersion, 1, "multisig policy version");

        uint256[REGISTRY_TREE_DEPTH] memory authSiblings = _authPolicySiblings(ALICE, multisigPolicy.innerVkHash);
        ProofFixture memory depositFixture = _generateMultisigDepositFixture(
            aliceUser,
            multisigPolicyVersion,
            _currentCommitmentRoot(),
            _currentUserRegistryRoot(),
            _currentAuthPolicyRoot(),
            authSiblings
        );
        _assertAndExecuteDepositFixture(depositFixture);

        address publicRecipient = makeAddr("multisigWithdrawRecipient");
        uint256 balanceBefore = publicRecipient.balance;
        ProofFixture memory withdrawFixture = _generateMultisigWithdrawFixture(
            aliceUser,
            WithdrawRequest({
                policyVersion: multisigPolicyVersion,
                commitRoot: _currentCommitmentRoot(),
                userRegRoot: _currentUserRegistryRoot(),
                authPolicyRoot: _currentAuthPolicyRoot(),
                inputLeafIndex: 0,
                inputAmount: depositFixture.note0Amount,
                inputRandomness: depositFixture.note0Randomness,
                inputOriginTag: depositFixture.note0OriginTag,
                publicRecipient: publicRecipient,
                withdrawAmount: WITHDRAW_AMOUNT,
                inputSiblings: _commitmentSiblings(_depositLeaves(depositFixture), 0),
                userSiblings: _userRegistrySiblings(ALICE)
            }),
            authSiblings
        );

        _assertWithdrawFixture(
            withdrawFixture, publicRecipient, WITHDRAW_AMOUNT, depositFixture.note0Amount - WITHDRAW_AMOUNT
        );
        _assertVerifierAccepts(withdrawFixture);
        _executeWithdrawFixture(withdrawFixture);
        assertEq(publicRecipient.balance - balanceBefore, WITHDRAW_AMOUNT, "recipient received ETH");
    }

    function test_FullFlow_WithdrawAfterDeposit() public {
        PreparedUser memory aliceUser = _deriveTestUser(NK, OS, DS, ALICE_SIGNING_PRIVATE_KEY);
        uint256 currentPolicyVersion = _registerAlice(aliceUser);

        ProofFixture memory depositFixture = _generateDepositFixture(
            aliceUser,
            currentPolicyVersion,
            _currentCommitmentRoot(),
            _currentUserRegistryRoot(),
            _currentAuthPolicyRoot()
        );
        _assertAndExecuteDepositFixture(depositFixture);

        address publicRecipient = makeAddr("withdrawRecipient");
        uint256 balanceBefore = publicRecipient.balance;
        ProofFixture memory withdrawFixture = _generateWithdrawFixture(
            aliceUser,
            WithdrawRequest({
                policyVersion: currentPolicyVersion,
                commitRoot: _currentCommitmentRoot(),
                userRegRoot: _currentUserRegistryRoot(),
                authPolicyRoot: _currentAuthPolicyRoot(),
                inputLeafIndex: 0,
                inputAmount: depositFixture.note0Amount,
                inputRandomness: depositFixture.note0Randomness,
                inputOriginTag: depositFixture.note0OriginTag,
                publicRecipient: publicRecipient,
                withdrawAmount: WITHDRAW_AMOUNT,
                inputSiblings: _commitmentSiblings(_depositLeaves(depositFixture), 0),
                userSiblings: _userRegistrySiblings(ALICE)
            })
        );

        _assertWithdrawFixture(
            withdrawFixture, publicRecipient, WITHDRAW_AMOUNT, depositFixture.note0Amount - WITHDRAW_AMOUNT
        );
        _executeWithdrawFixture(withdrawFixture);
        assertEq(publicRecipient.balance - balanceBefore, WITHDRAW_AMOUNT, "recipient received ETH");
    }

    function test_FullFlow_DepositToRegisteredRecipient_CanBeWithdrawnByRecipient() public {
        PreparedUser memory aliceUser = _deriveTestUser(NK, OS, DS, ALICE_SIGNING_PRIVATE_KEY);
        uint256 alicePolicyVersion = _registerAlice(aliceUser);

        address bob = BOB;
        PreparedUser memory bobUser = _prepareBob(bob);

        ProofFixture memory depositFixture = _runProofGenerator(
            _buildDepositParamsForRecipient(
                aliceUser,
                alicePolicyVersion,
                _currentCommitmentRoot(),
                _currentUserRegistryRoot(),
                _currentAuthPolicyRoot(),
                bob,
                bobUser
            )
        );
        _assertAndExecuteDepositFixture(depositFixture);

        uint256 bobPolicyVersion = _registerAuthPolicy(bob, bobUser.innerVkHash, bobUser.authDataCommitment);
        UserSecrets memory bobSecrets = _bobSecrets(bob);
        address publicRecipient = makeAddr("depositRecipientWithdraw");
        uint256 balanceBefore = publicRecipient.balance;
        ProofFixture memory withdrawFixture = _generateWithdrawFixtureForActor(
            bobUser,
            bobSecrets,
            WithdrawRequest({
                policyVersion: bobPolicyVersion,
                commitRoot: _currentCommitmentRoot(),
                userRegRoot: _currentUserRegistryRoot(),
                authPolicyRoot: _currentAuthPolicyRoot(),
                inputLeafIndex: 0,
                inputAmount: depositFixture.note0Amount,
                inputRandomness: depositFixture.note0Randomness,
                inputOriginTag: depositFixture.note0OriginTag,
                publicRecipient: publicRecipient,
                withdrawAmount: WITHDRAW_AMOUNT,
                inputSiblings: _commitmentSiblings(_depositLeaves(depositFixture), 0),
                userSiblings: _userRegistrySiblings(bob)
            })
        );

        _assertWithdrawFixture(
            withdrawFixture, publicRecipient, WITHDRAW_AMOUNT, depositFixture.note0Amount - WITHDRAW_AMOUNT
        );
        _executeWithdrawFixture(withdrawFixture);
        assertEq(publicRecipient.balance - balanceBefore, WITHDRAW_AMOUNT, "recipient received ETH");
    }

    function test_FullFlow_DepositProofRejectsZeroValueRealRecipientNote() public {
        PreparedUser memory aliceUser = _deriveTestUser(NK, OS, DS, ALICE_SIGNING_PRIVATE_KEY);
        uint256 alicePolicyVersion = _registerAlice(aliceUser);

        string memory params = _buildDepositParamsWithFee(
            aliceUser,
            alicePolicyVersion,
            _currentCommitmentRoot(),
            _currentUserRegistryRoot(),
            _currentAuthPolicyRoot(),
            ALICE,
            aliceUser,
            DEPOSIT_AMOUNT
        );
        vm.serializeUint("depositParams", "amount", 0);
        params = vm.serializeString("depositParams", "signingPrivateKey", ALICE_SIGNING_PRIVATE_KEY);

        _expectProofGenerationFailure(params, "real output must have nonzero amount");
    }

    function test_FullFlow_DepositWithFeeNote_FeeRecipientCanRecoverAndWithdraw() public {
        PreparedUser memory aliceUser = _deriveTestUser(NK, OS, DS, ALICE_SIGNING_PRIVATE_KEY);
        uint256 alicePolicyVersion = _registerAlice(aliceUser);

        address feeCollector = BOB;
        PreparedUser memory feeCollectorUser = _prepareBob(feeCollector);
        uint256 feeAmount = 0.1 ether;

        ProofFixture memory depositFixture = _runProofGenerator(
            _buildDepositParamsWithFee(
                aliceUser,
                alicePolicyVersion,
                _currentCommitmentRoot(),
                _currentUserRegistryRoot(),
                _currentAuthPolicyRoot(),
                feeCollector,
                feeCollectorUser,
                feeAmount
            )
        );

        assertEq(depositFixture.pubInputs.publicAmountIn, DEPOSIT_AMOUNT + feeAmount, "deposit amount in");
        _assertVerifierAccepts(depositFixture);

        vm.chainId(depositFixture.pubInputs.executionChainId);
        vm.warp(depositFixture.pubInputs.validUntilSeconds - 100);
        vm.deal(ALICE, depositFixture.pubInputs.publicAmountIn + 1 ether);
        vm.prank(ALICE);
        pool.transact{value: depositFixture.pubInputs.publicAmountIn}(
            depositFixture.proof,
            depositFixture.pubInputs,
            depositFixture.noteData0,
            depositFixture.noteData1,
            depositFixture.noteData2
        );
        assertEq(address(pool).balance, DEPOSIT_AMOUNT + feeAmount, "pool has deposit plus fee");

        RecoveredNote memory feeNote = _recoverSingleChainNote(
            feeCollector,
            BOB_NK,
            BOB_DS,
            2,
            depositFixture.noteData2,
            depositFixture.pubInputs.commitment2
        );
        assertTrue(feeNote.found, "fee note not recovered");
        assertEq(feeNote.amount, feeAmount, "fee amount mismatch");

        uint256 feeCollectorPolicyVersion =
            _registerAuthPolicy(feeCollector, feeCollectorUser.innerVkHash, feeCollectorUser.authDataCommitment);
        UserSecrets memory feeCollectorSecrets = _bobSecrets(feeCollector);
        address publicRecipient = makeAddr("feeWithdrawRecipient");
        uint256 balanceBefore = publicRecipient.balance;
        ProofFixture memory withdrawFixture = _generateWithdrawFixtureForActor(
            feeCollectorUser,
            feeCollectorSecrets,
            WithdrawRequest({
                policyVersion: feeCollectorPolicyVersion,
                commitRoot: _currentCommitmentRoot(),
                userRegRoot: _currentUserRegistryRoot(),
                authPolicyRoot: _currentAuthPolicyRoot(),
                inputLeafIndex: 2,
                inputAmount: feeNote.amount,
                inputRandomness: feeNote.randomness,
                inputOriginTag: feeNote.originTag,
                publicRecipient: publicRecipient,
                withdrawAmount: feeAmount,
                inputSiblings: _commitmentSiblings(_depositLeaves(depositFixture), 2),
                userSiblings: _userRegistrySiblings(feeCollector)
            })
        );

        _assertWithdrawFixture(withdrawFixture, publicRecipient, feeAmount, 0);
        _executeWithdrawFixture(withdrawFixture);
        assertEq(publicRecipient.balance - balanceBefore, feeAmount, "fee recipient withdrew note");
    }

    function test_FullFlow_SimplifiedSingleSigTransferRejectsExecutionConstraints() public {
        (PreparedUser memory aliceUser, uint256 currentPolicyVersion, ProofFixture memory depositFixture) =
            _depositAliceSingleSig();

        address bob = BOB;
        PreparedUser memory bobUser = _prepareBob(bob);

        _expectProofGenerationFailure(
            _buildTransferParamsWithExecutionConstraints(
                aliceUser,
                _standardTransferRequest(currentPolicyVersion, depositFixture, bob, bobUser),
                1,
                0
            ),
            "eip712 only supports unconstrained execution constraints"
        );
    }

    function test_FullFlow_TransferProofFailsForMismatchedOuterAuthorizingAddressWitness() public {
        (PreparedUser memory aliceUser, uint256 currentPolicyVersion, ProofFixture memory depositFixture) =
            _depositAliceSingleSig();

        address bob = BOB;
        PreparedUser memory bobUser = _prepareBob(bob);

        _expectProofGenerationFailure(
            _buildTransferParamsWithOuterWitnessOverrides(
                aliceUser,
                _standardTransferRequest(currentPolicyVersion, depositFixture, bob, bobUser),
                bob,
                currentPolicyVersion
            ),
            "auth policy root mismatch"
        );
    }

    function test_FullFlow_TransferProofFailsForMismatchedOuterPolicyVersionWitness() public {
        (PreparedUser memory aliceUser, uint256 currentPolicyVersion, ProofFixture memory depositFixture) =
            _depositAliceSingleSig();

        address bob = BOB;
        PreparedUser memory bobUser = _prepareBob(bob);

        _expectProofGenerationFailure(
            _buildTransferParamsWithOuterWitnessOverrides(
                aliceUser,
                _standardTransferRequest(currentPolicyVersion, depositFixture, bob, bobUser),
                ALICE,
                currentPolicyVersion + 1
            ),
            "auth policy root mismatch"
        );
    }

    function test_FullFlow_RecipientRecoversTransferNoteAndWithdraws() public {
        RecoveredTransferContext memory ctx = _prepareRecoveredTransferContext();
        SyncedTransactFixture[] memory history = new SyncedTransactFixture[](2);
        uint256 originalTransferCommitment0 = ctx.transferFixture.pubInputs.commitment0;
        ProofFixture memory corruptedTransferFixture = ctx.transferFixture;
        corruptedTransferFixture.pubInputs.commitment0 = originalTransferCommitment0 + 1;
        history[0] = SyncedTransactFixture({leafIndex0: 0, fixture: ctx.depositFixture});
        history[1] = SyncedTransactFixture({leafIndex0: ctx.transferLeafIndex0, fixture: corruptedTransferFixture});

        RecoveredNote memory missingNote = _recoverFirstUnspentNoteFromHistory(
            ctx.bob, ctx.bobSecrets.nullifierKey, ctx.bobSecrets.deliverySecret, history
        );
        assertFalse(missingNote.found, "corrupted commitment should not recover");

        ctx.transferFixture.pubInputs.commitment0 = originalTransferCommitment0;
        history[1] = SyncedTransactFixture({leafIndex0: ctx.transferLeafIndex0, fixture: ctx.transferFixture});

        RecoveredNote memory aliceChangeNote = _recoverFirstUnspentNoteFromHistory(ALICE, NK, DS, history);
        assertTrue(aliceChangeNote.found, "sender change note not recovered");
        assertEq(aliceChangeNote.leafIndex, ctx.transferLeafIndex0 + 1, "change leaf index mismatch");
        assertEq(
            aliceChangeNote.amount, ctx.depositFixture.note0Amount - TRANSFER_AMOUNT, "sender change amount mismatch"
        );

        RecoveredNote memory bobNote = _recoverFirstUnspentNoteFromHistory(
            ctx.bob, ctx.bobSecrets.nullifierKey, ctx.bobSecrets.deliverySecret, history
        );
        assertTrue(bobNote.found, "recipient note not recovered");
        assertEq(bobNote.leafIndex, ctx.transferLeafIndex0, "leaf index mismatch");
        assertEq(bobNote.amount, TRANSFER_AMOUNT, "recovered amount mismatch");
        assertEq(bobNote.ownerAddress, uint256(uint160(ctx.bob)), "recovered owner mismatch");
        assertEq(bobNote.nullifierKeyHash, ctx.bobUser.nkHash, "recovered nk hash mismatch");

        address publicRecipient = makeAddr("recoveredWithdrawRecipient");
        uint256 balanceBefore = publicRecipient.balance;
        ProofFixture memory withdrawFixture = _buildRecoveredWithdrawFixture(ctx, bobNote, publicRecipient);

        _assertWithdrawFixture(
            withdrawFixture, publicRecipient, RECOVERED_WITHDRAW_AMOUNT, TRANSFER_AMOUNT - RECOVERED_WITHDRAW_AMOUNT
        );
        _executeWithdrawFixture(withdrawFixture);
        assertEq(publicRecipient.balance - balanceBefore, RECOVERED_WITHDRAW_AMOUNT, "recipient received ETH");

        SyncedTransactFixture[] memory postWithdrawHistory = new SyncedTransactFixture[](3);
        postWithdrawHistory[0] = history[0];
        postWithdrawHistory[1] = history[1];
        postWithdrawHistory[2] = SyncedTransactFixture({
            leafIndex0: ctx.transferLeafIndex0 + 3,
            fixture: withdrawFixture
        });

        RecoveredNote memory bobChangeNote = _recoverFirstUnspentNoteFromHistory(
            ctx.bob, ctx.bobSecrets.nullifierKey, ctx.bobSecrets.deliverySecret, postWithdrawHistory
        );
        assertTrue(bobChangeNote.found, "recipient change note not recovered");
        assertEq(bobChangeNote.leafIndex, ctx.transferLeafIndex0 + 3, "recipient change leaf index mismatch");
        assertEq(
            bobChangeNote.amount,
            TRANSFER_AMOUNT - RECOVERED_WITHDRAW_AMOUNT,
            "recipient change amount mismatch"
        );
    }

    function test_FullFlow_TransferUsesCurrentOnChainRecipientDeliveryKey() public {
        (PreparedUser memory aliceUser, uint256 currentPolicyVersion, ProofFixture memory depositFixture) =
            _depositAliceSingleSig();

        address bob = BOB;
        PreparedUser memory bobUser = _prepareBob(bob);

        uint256 rotatedDeliverySecret = 0xface;
        PreparedUser memory rotatedBobUser =
            _deriveTestUser(BOB_NK, BOB_OS, rotatedDeliverySecret, BOB_SIGNING_PRIVATE_KEY);
        vm.prank(bob);
        pool.setDeliveryKey(DELIVERY_SCHEME_ID, rotatedBobUser.deliveryPubKey);

        ProofFixture memory transferFixture = _generateTransferFixture(
            aliceUser,
            TransferRequest({
                policyVersion: currentPolicyVersion,
                commitRoot: _currentCommitmentRoot(),
                userRegRoot: _currentUserRegistryRoot(),
                authPolicyRoot: _currentAuthPolicyRoot(),
                inputLeafIndex: 0,
                inputAmount: depositFixture.note0Amount,
                inputRandomness: depositFixture.note0Randomness,
                inputOriginTag: depositFixture.note0OriginTag,
                recipient: bob,
                recipientNkHash: bobUser.nkHash,
                recipientOsHash: bobUser.osHash,
                transferAmount: TRANSFER_AMOUNT,
                changeAmount: depositFixture.note0Amount - TRANSFER_AMOUNT,
                inputSiblings: _commitmentSiblings(_depositLeaves(depositFixture), 0),
                userSiblings: _userRegistrySiblings(ALICE),
                recipientSiblings: _userRegistrySiblings(bob)
            })
        );

        uint256 transferLeafIndex0 = _nextLeafIndex();
        _executeTransferFixture(transferFixture);

        RecoveredNote memory staleKeyNote = _recoverSingleChainNote(
            bob, BOB_NK, BOB_DS, transferLeafIndex0, transferFixture.noteData0, transferFixture.pubInputs.commitment0
        );
        assertFalse(staleKeyNote.found, "stale delivery key unexpectedly recovered note");

        RecoveredNote memory rotatedKeyNote = _recoverSingleChainNote(
            bob,
            BOB_NK,
            rotatedDeliverySecret,
            transferLeafIndex0,
            transferFixture.noteData0,
            transferFixture.pubInputs.commitment0
        );
        assertTrue(rotatedKeyNote.found, "rotated delivery key did not recover note");
        assertEq(rotatedKeyNote.amount, TRANSFER_AMOUNT, "rotated delivery key recovered wrong note");
    }

    function test_FullFlow_TransferProofFailsForUnsupportedRecipientDeliveryScheme() public {
        (PreparedUser memory aliceUser, uint256 currentPolicyVersion, ProofFixture memory depositFixture) =
            _depositAliceSingleSig();

        address bob = BOB;
        PreparedUser memory bobUser = _prepareBob(bob);

        vm.prank(bob);
        pool.setDeliveryKey(2, bobUser.deliveryPubKey);

        _expectProofGenerationFailure(
            _buildTransferParams(
                aliceUser, _standardTransferRequest(currentPolicyVersion, depositFixture, bob, bobUser)
            ),
            "deliveryPubKey required for non-dummy notes"
        );
    }

    function test_FullFlow_TransferProofFailsForMalformedRecipientDeliveryKey() public {
        (PreparedUser memory aliceUser, uint256 currentPolicyVersion, ProofFixture memory depositFixture) =
            _depositAliceSingleSig();

        address bob = BOB;
        PreparedUser memory bobUser = _prepareBob(bob);

        vm.prank(bob);
        pool.setDeliveryKey(DELIVERY_SCHEME_ID, hex"1234");

        _expectProofGenerationFailure(
            _buildTransferParams(
                aliceUser, _standardTransferRequest(currentPolicyVersion, depositFixture, bob, bobUser)
            ),
            "deliveryPubKey required for non-dummy notes"
        );
    }

    function test_FullFlow_TaggedDepositTransferPreservesOriginTag() public {
        PreparedUser memory aliceUser = _deriveTestUser(NK, OS, DS, ALICE_SIGNING_PRIVATE_KEY);
        uint256 currentPolicyVersion = _registerAlice(aliceUser);

        // Deposit with originMode=1 (tagged)
        string memory params = _buildDepositParams(
            aliceUser,
            currentPolicyVersion,
            _currentCommitmentRoot(),
            _currentUserRegistryRoot(),
            _currentAuthPolicyRoot()
        );
        vm.serializeUint("depositParams", "originMode", 1);
        params = vm.serializeString("depositParams", "signingPrivateKey", ALICE_SIGNING_PRIVATE_KEY);

        ProofFixture memory depositFixture = _runProofGenerator(params);
        assertGt(depositFixture.note0OriginTag, 0, "deposit should produce nonzero origin tag");
        _assertAndExecuteDepositFixture(depositFixture);

        // Transfer using the tagged note
        address bob = BOB;
        PreparedUser memory bobUser = _prepareBob(bob);

        ProofFixture memory transferFixture = _generateTransferFixture(
            aliceUser,
            TransferRequest({
                policyVersion: currentPolicyVersion,
                commitRoot: _currentCommitmentRoot(),
                userRegRoot: _currentUserRegistryRoot(),
                authPolicyRoot: _currentAuthPolicyRoot(),
                inputLeafIndex: 0,
                inputAmount: depositFixture.note0Amount,
                inputRandomness: depositFixture.note0Randomness,
                inputOriginTag: depositFixture.note0OriginTag,
                recipient: bob,
                recipientNkHash: bobUser.nkHash,
                recipientOsHash: bobUser.osHash,
                transferAmount: TRANSFER_AMOUNT,
                changeAmount: depositFixture.note0Amount - TRANSFER_AMOUNT,
                inputSiblings: _commitmentSiblings(_depositLeaves(depositFixture), 0),
                userSiblings: _userRegistrySiblings(ALICE),
                recipientSiblings: _userRegistrySiblings(bob)
            })
        );

        assertEq(
            transferFixture.note0OriginTag,
            depositFixture.note0OriginTag,
            "transfer recipient note should preserve origin tag"
        );
        assertEq(
            transferFixture.note1OriginTag,
            depositFixture.note0OriginTag,
            "transfer change note should preserve origin tag"
        );
        _assertTransferFixture(transferFixture, depositFixture.note0Amount - TRANSFER_AMOUNT);
        _executeTransferFixture(transferFixture);
    }

    function test_FullFlow_TaggedDepositWithdrawPreservesOriginTag() public {
        PreparedUser memory aliceUser = _deriveTestUser(NK, OS, DS, ALICE_SIGNING_PRIVATE_KEY);
        uint256 currentPolicyVersion = _registerAlice(aliceUser);

        // Deposit with originMode=1 (tagged)
        string memory params = _buildDepositParams(
            aliceUser,
            currentPolicyVersion,
            _currentCommitmentRoot(),
            _currentUserRegistryRoot(),
            _currentAuthPolicyRoot()
        );
        vm.serializeUint("depositParams", "originMode", 1);
        params = vm.serializeString("depositParams", "signingPrivateKey", ALICE_SIGNING_PRIVATE_KEY);

        ProofFixture memory depositFixture = _runProofGenerator(params);
        assertGt(depositFixture.note0OriginTag, 0, "deposit should produce nonzero origin tag");
        _assertAndExecuteDepositFixture(depositFixture);

        // Withdraw part of the tagged note
        address publicRecipient = makeAddr("taggedWithdrawRecipient");
        ProofFixture memory withdrawFixture = _generateWithdrawFixture(
            aliceUser,
            WithdrawRequest({
                policyVersion: currentPolicyVersion,
                commitRoot: _currentCommitmentRoot(),
                userRegRoot: _currentUserRegistryRoot(),
                authPolicyRoot: _currentAuthPolicyRoot(),
                inputLeafIndex: 0,
                inputAmount: depositFixture.note0Amount,
                inputRandomness: depositFixture.note0Randomness,
                inputOriginTag: depositFixture.note0OriginTag,
                publicRecipient: publicRecipient,
                withdrawAmount: WITHDRAW_AMOUNT,
                inputSiblings: _commitmentSiblings(_depositLeaves(depositFixture), 0),
                userSiblings: _userRegistrySiblings(ALICE)
            })
        );

        assertEq(
            withdrawFixture.note0OriginTag,
            depositFixture.note0OriginTag,
            "withdrawal change note should preserve origin tag"
        );
        _assertWithdrawFixture(
            withdrawFixture, publicRecipient, WITHDRAW_AMOUNT, depositFixture.note0Amount - WITHDRAW_AMOUNT
        );
        _executeWithdrawFixture(withdrawFixture);
    }

    function test_FullFlow_UntaggedDepositTransferLeavesOutputUntagged() public {
        PreparedUser memory aliceUser = _deriveTestUser(NK, OS, DS, ALICE_SIGNING_PRIVATE_KEY);
        uint256 currentPolicyVersion = _registerAlice(aliceUser);

        ProofFixture memory depositFixture = _generateDepositFixture(
            aliceUser,
            currentPolicyVersion,
            _currentCommitmentRoot(),
            _currentUserRegistryRoot(),
            _currentAuthPolicyRoot()
        );
        assertEq(depositFixture.note0OriginTag, 0, "default origin mode should leave note untagged");
        _assertAndExecuteDepositFixture(depositFixture);

        address bob = BOB;
        PreparedUser memory bobUser = _prepareBob(bob);

        ProofFixture memory transferFixture = _generateTransferFixture(
            aliceUser,
            TransferRequest({
                policyVersion: currentPolicyVersion,
                commitRoot: _currentCommitmentRoot(),
                userRegRoot: _currentUserRegistryRoot(),
                authPolicyRoot: _currentAuthPolicyRoot(),
                inputLeafIndex: 0,
                inputAmount: depositFixture.note0Amount,
                inputRandomness: depositFixture.note0Randomness,
                inputOriginTag: depositFixture.note0OriginTag,
                recipient: bob,
                recipientNkHash: bobUser.nkHash,
                recipientOsHash: bobUser.osHash,
                transferAmount: TRANSFER_AMOUNT,
                changeAmount: depositFixture.note0Amount - TRANSFER_AMOUNT,
                inputSiblings: _commitmentSiblings(_depositLeaves(depositFixture), 0),
                userSiblings: _userRegistrySiblings(ALICE),
                recipientSiblings: _userRegistrySiblings(bob)
            })
        );

        assertEq(transferFixture.note0OriginTag, 0, "transfer from untagged note should stay untagged");
        assertEq(transferFixture.note1OriginTag, 0, "change from untagged note should stay untagged");
        _assertTransferFixture(transferFixture, depositFixture.note0Amount - TRANSFER_AMOUNT);
        _executeTransferFixture(transferFixture);
    }

    function _prepareRecoveredTransferContext() internal returns (RecoveredTransferContext memory ctx) {
        PreparedUser memory aliceUser = _deriveTestUser(NK, OS, DS, ALICE_SIGNING_PRIVATE_KEY);
        uint256 alicePolicyVersion = _registerAlice(aliceUser);

        ctx.depositFixture = _generateDepositFixture(
            aliceUser,
            alicePolicyVersion,
            _currentCommitmentRoot(),
            _currentUserRegistryRoot(),
            _currentAuthPolicyRoot()
        );
        _assertAndExecuteDepositFixture(ctx.depositFixture);

        ctx.bob = BOB;
        ctx.bobUser = _prepareBob(ctx.bob);
        ctx.bobSecrets = _bobSecrets(ctx.bob);
        ctx.bobPolicyVersion = _registerAuthPolicy(ctx.bob, ctx.bobUser.innerVkHash, ctx.bobUser.authDataCommitment);
        _assertAuthWitnessMatchesCurrentRoot(
            ALICE, aliceUser.innerVkHash, aliceUser.authDataCommitment, alicePolicyVersion
        );
        _assertAuthWitnessMatchesCurrentRoot(
            ctx.bob, ctx.bobUser.innerVkHash, ctx.bobUser.authDataCommitment, ctx.bobPolicyVersion
        );

        ctx.transferFixture = _generateTransferFixture(
            aliceUser,
            TransferRequest({
                policyVersion: alicePolicyVersion,
                commitRoot: _currentCommitmentRoot(),
                userRegRoot: _currentUserRegistryRoot(),
                authPolicyRoot: _currentAuthPolicyRoot(),
                inputLeafIndex: 0,
                inputAmount: ctx.depositFixture.note0Amount,
                inputRandomness: ctx.depositFixture.note0Randomness,
                inputOriginTag: ctx.depositFixture.note0OriginTag,
                recipient: ctx.bob,
                recipientNkHash: ctx.bobUser.nkHash,
                recipientOsHash: ctx.bobUser.osHash,
                transferAmount: TRANSFER_AMOUNT,
                changeAmount: ctx.depositFixture.note0Amount - TRANSFER_AMOUNT,
                inputSiblings: _commitmentSiblings(_depositLeaves(ctx.depositFixture), 0),
                userSiblings: _userRegistrySiblings(ALICE),
                recipientSiblings: _userRegistrySiblings(ctx.bob)
            })
        );

        ctx.transferLeafIndex0 = _nextLeafIndex();
        _assertTransferFixture(ctx.transferFixture, ctx.depositFixture.note0Amount - TRANSFER_AMOUNT);
        _executeTransferFixture(ctx.transferFixture);
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

    function _buildRecoveredWithdrawFixture(
        RecoveredTransferContext memory ctx,
        RecoveredNote memory bobNote,
        address publicRecipient
    ) internal returns (ProofFixture memory withdrawFixture) {
        WithdrawRequest memory request = WithdrawRequest({
            policyVersion: ctx.bobPolicyVersion,
            commitRoot: _currentCommitmentRoot(),
            userRegRoot: _currentUserRegistryRoot(),
            authPolicyRoot: _currentAuthPolicyRoot(),
            inputLeafIndex: bobNote.leafIndex,
            inputAmount: bobNote.amount,
            inputRandomness: bobNote.randomness,
            inputOriginTag: bobNote.originTag,
            publicRecipient: publicRecipient,
            withdrawAmount: RECOVERED_WITHDRAW_AMOUNT,
            inputSiblings: _commitmentSiblings(
                _combinedLeaves(ctx.depositFixture, ctx.transferFixture), bobNote.leafIndex
            ),
            userSiblings: _userRegistrySiblings(ctx.bob)
        });

        withdrawFixture = _generateWithdrawFixtureForActor(ctx.bobUser, ctx.bobSecrets, request);
    }

    function _buildDepositParamsForRecipient(
        PreparedUser memory user,
        uint256 policyVersion,
        uint256 commitRoot,
        uint256 userRegRoot,
        uint256 authPolicyRoot,
        address recipient,
        PreparedUser memory recipientUser
    ) internal returns (string memory params) {
        params = _buildDepositParams(user, policyVersion, commitRoot, userRegRoot, authPolicyRoot);
        vm.serializeAddress("depositParams", "recipientAddress", recipient);
        vm.serializeUint("depositParams", "recipientNkHash", recipientUser.nkHash);
        vm.serializeUint("depositParams", "recipientOsHash", recipientUser.osHash);
        vm.serializeString("depositParams", "recipientSiblings", _registrySiblingStrings(_userRegistrySiblings(recipient)));
        _serializeRegisteredDeliveryKey("depositParams", "recipientDeliverySchemeId", "recipientDeliveryPubKey", recipient);
        params = vm.serializeString("depositParams", "signingPrivateKey", ALICE_SIGNING_PRIVATE_KEY);
    }

    function _buildDepositParamsWithFee(
        PreparedUser memory user,
        uint256 policyVersion,
        uint256 commitRoot,
        uint256 userRegRoot,
        uint256 authPolicyRoot,
        address feeRecipient,
        PreparedUser memory feeRecipientUser,
        uint256 feeAmount
    ) internal returns (string memory params) {
        params = _buildDepositParams(user, policyVersion, commitRoot, userRegRoot, authPolicyRoot);
        vm.serializeAddress("depositParams", "feeRecipientAddress", feeRecipient);
        vm.serializeUint("depositParams", "feeAmount", feeAmount);
        vm.serializeUint("depositParams", "feeNkHash", feeRecipientUser.nkHash);
        vm.serializeUint("depositParams", "feeOsHash", feeRecipientUser.osHash);
        vm.serializeString("depositParams", "feeSiblings", _registrySiblingStrings(_userRegistrySiblings(feeRecipient)));
        _serializeRegisteredDeliveryKey("depositParams", "feeDeliverySchemeId", "feeDeliveryPubKey", feeRecipient);
        params = vm.serializeString("depositParams", "signingPrivateKey", ALICE_SIGNING_PRIVATE_KEY);
    }

    function _buildTransferParamsWithExecutionConstraints(
        PreparedUser memory user,
        TransferRequest memory request,
        uint256 executionConstraintsFlags,
        uint256 lockedOutputBinding0
    ) internal returns (string memory params) {
        return _withExecutionConstraints(_buildTransferParams(user, request), executionConstraintsFlags, lockedOutputBinding0, 0, 0);
    }
}
