// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ERC20AssetLib} from "./libraries/ERC20AssetLib.sol";
import {PoseidonFieldLib} from "./libraries/PoseidonFieldLib.sol";
import {ErcConstants} from "./generated/ErcConstants.sol";
import {IAuthVerifier} from "./interfaces/IAuthVerifier.sol";
import {IPolicyVerifier} from "./interfaces/IPolicyVerifier.sol";
import {IPoolVerifier} from "./interfaces/IPoolVerifier.sol";
import {IPrivacyIdentityRegistry} from "./interfaces/IPrivacyIdentityRegistry.sol";
import {IShieldedPool} from "./interfaces/IShieldedPool.sol";

/// @title  ERC app-layer private transfers — conforming shielded pool
/// @notice Reference implementation of the spec section 4/5/7 pool profile:
///         an ordinary deployed contract holding the note-commitment tree,
///         nullifier and replay sets, verifying pool proofs via staticcall to
///         the canonical singleton verifier and reading identity state from
///         the canonical privacy identity registry. Immutable: no admin, no
///         pause, no upgrade path.
/// @dev    Deployed twice for the reference deployment: policy-free
///         (policyVerifier = 0, applies = 0) and allowlist-gated
///         (applies = DEPOSIT|WITHDRAWAL). The registry and verifier
///         constructor args MUST be the canonical singleton addresses for a
///         conforming deployment; they are constructor parameters (rather
///         than hardcoded constants) so the test suite can instantiate local
///         copies — the deploy script pins them to the canonical addresses
///         and asserts runtime code hashes.
contract ShieldedPool is IShieldedPool {
    // -------------------------------- Constants --------------------------------

    uint256 internal constant MAX_INTENT_LIFETIME = 86400;
    uint256 internal constant NOTE_COMMITMENT_ROOT_HISTORY_SIZE = 500;
    uint256 internal constant COMMITMENT_TREE_DEPTH = 32;
    uint256 internal constant MAX_LEAF_INDEX = type(uint32).max;
    uint256 internal constant MAX_ADDRESS_VALUE = type(uint160).max;
    uint256 internal constant MAX_AMOUNT_VALUE = type(uint248).max;
    uint256 internal constant MAX_VALID_UNTIL_SECONDS = type(uint32).max;
    uint256 internal constant MAX_EXECUTION_CHAIN_ID = type(uint32).max;

    // -------------------------------- Immutable config --------------------------------

    /// @notice Canonical privacy identity registry (spec section 6).
    IPrivacyIdentityRegistry public immutable REGISTRY;
    /// @notice Canonical stateless pool verifier (spec section 7.2).
    IPoolVerifier public immutable POOL_VERIFIER;

    address internal immutable POLICY_VERIFIER;
    uint256 internal immutable POLICY_APPLIES;

    // -------------------------------- Errors --------------------------------

    error AddressOutOfRange();
    error AmountOutOfRange();
    error AuthProofRejected();
    error AuthVerifierMissing();
    error DuplicateNullifier();
    error EthAmountMismatch();
    error EthTransferFailed();
    error Erc20DeliveredLess();
    error FieldElementNotCanonical();
    error IntentExpired();
    error IntentLifetimeTooLong();
    error IntentReplayIdAlreadyUsed();
    error InvalidDepositAmount();
    error InvalidOutputNoteDataHash(uint8 slot);
    error InvalidOwnerCommitment();
    error InvalidPolicyConfiguration();
    error InvalidPolicyData();
    error InvalidPolicyOperationDataHash();
    error InvalidPublicActionConfiguration();
    error NullifierAlreadySpent();
    error PolicyRejected();
    error PoolAddressMismatch();
    error PoolProofRejected();
    error DownstreamActionRequiresSubmitter();
    error UnauthorizedSubmitter();
    error ReentrantCall();
    error TreeFull();
    error UnexpectedEth();
    error UnknownIdentityRoot();
    error UnknownNoteCommitmentRoot();
    error WrongChainId();
    error ZeroIdentityRoot();
    error ZeroNoteCommitment();

    // -------------------------------- Storage --------------------------------

    // Note-commitment tree (depth-32 append-only).
    uint256 internal nextLeafIndex;
    uint256 internal currentNoteCommitmentRoot;
    uint256 internal noteCommitmentRootHistoryCount;
    mapping(uint256 => uint256) internal filledNoteCommitmentSubtrees;
    mapping(uint256 => uint256) internal noteCommitmentRootHistory;

    mapping(uint256 => bool) private nullifierSpent;
    mapping(uint256 => bool) private intentReplayIdUsed;

    // Empty-subtree hashes; level 0 is the empty leaf hash (0).
    uint256[COMMITMENT_TREE_DEPTH] internal noteCommitmentEmptyHashes;

    // -------------------------------- Constructor --------------------------------

    constructor(
        IPrivacyIdentityRegistry registry_,
        IPoolVerifier poolVerifier_,
        address policyVerifier_,
        uint256 policyApplies_
    ) {
        require(address(registry_).code.length != 0, InvalidPolicyConfiguration());
        require(address(poolVerifier_).code.length != 0, InvalidPolicyConfiguration());
        // spec section 16.1: applies == 0 <=> verifier == 0
        require((policyApplies_ == 0) == (policyVerifier_ == address(0)), InvalidPolicyConfiguration());
        require(policyApplies_ < 16, InvalidPolicyConfiguration()); // only the 4 defined bits
        REGISTRY = registry_;
        POOL_VERIFIER = poolVerifier_;
        POLICY_VERIFIER = policyVerifier_;
        POLICY_APPLIES = policyApplies_;

        // EMPTY[0] = 0; EMPTY[h+1] = poseidon(EMPTY[h], EMPTY[h]) (spec section 15.4).
        uint256 empty = 0;
        for (uint256 level; level < COMMITMENT_TREE_DEPTH; ++level) {
            noteCommitmentEmptyHashes[level] = empty;
            empty = PoseidonFieldLib.merkleHash(empty, empty);
        }
        currentNoteCommitmentRoot = empty; // EMPTY[32]
    }

    // -------------------------------- Modifier --------------------------------

    bytes32 private constant GUARD_SLOT = keccak256("ShieldedPool.reentrancy.guard");

    modifier nonReentrant() {
        _enterGuard();
        _;
        _exitGuard();
    }

    function _enterGuard() private {
        bytes32 slot = GUARD_SLOT;
        uint256 lockValue;
        assembly ("memory-safe") {
            lockValue := tload(slot)
        }
        require(lockValue == 0, ReentrantCall());
        assembly ("memory-safe") {
            tstore(slot, 1)
        }
    }

    function _exitGuard() private {
        bytes32 slot = GUARD_SLOT;
        assembly ("memory-safe") {
            tstore(slot, 0)
        }
    }

    // -------------------------------- transact --------------------------------

    /// @notice spec section 7.1 — the 31-step transact sequence, in order.
    function transact(
        bytes calldata poolProof,
        bytes calldata authProof,
        PublicInputs calldata publicInputs,
        bytes calldata outputNoteData0,
        bytes calldata outputNoteData1,
        bytes calldata outputNoteData2,
        bytes calldata policyData
    ) external nonReentrant {
        // Non-payable: any msg.value > 0 reverts on entry.

        // 1. chain id.
        require(publicInputs.executionChainId == block.chainid, WrongChainId());
        // 2. pool identity.
        require(publicInputs.poolAddress == uint256(uint160(address(this))), PoolAddressMismatch());
        // 2a. spec section 7.1 submitter authorization. authorizedSubmitter == 0
        //     means anyone may submit; nonzero pins the caller. A nonzero
        //     downstreamActionCommitment (opaque to the pool) requires a bound
        //     submitter. Enforced early, before any state write.
        require(publicInputs.authorizedSubmitter <= MAX_ADDRESS_VALUE, AddressOutOfRange());
        require(
            publicInputs.downstreamActionCommitment < PoseidonFieldLib.FIELD_MODULUS,
            FieldElementNotCanonical()
        );
        if (publicInputs.downstreamActionCommitment != 0) {
            require(publicInputs.authorizedSubmitter != 0, DownstreamActionRequiresSubmitter());
        }
        if (publicInputs.authorizedSubmitter != 0) {
            require(
                msg.sender == address(uint160(publicInputs.authorizedSubmitter)),
                UnauthorizedSubmitter()
            );
        }
        // 3-5. intent expiry window.
        require(publicInputs.validUntilSeconds != 0, IntentExpired());
        require(block.timestamp <= publicInputs.validUntilSeconds, IntentExpired());
        require(
            publicInputs.validUntilSeconds <= block.timestamp + MAX_INTENT_LIFETIME,
            IntentLifetimeTooLong()
        );
        // 6. note root.
        require(
            isAcceptedNoteCommitmentRoot(publicInputs.noteCommitmentRoot),
            UnknownNoteCommitmentRoot()
        );
        // 7. identity root via the canonical registry.
        require(publicInputs.identityRoot != 0, ZeroIdentityRoot());
        require(
            REGISTRY.isAcceptedIdentityRoot(publicInputs.identityRoot),
            UnknownIdentityRoot()
        );
        // 8. nullifier uniqueness within the call.
        require(publicInputs.nullifier0 != publicInputs.nullifier1, DuplicateNullifier());
        // 9-17. range checks.
        require(publicInputs.publicAmountOut <= MAX_AMOUNT_VALUE, AmountOutOfRange());
        require(publicInputs.publicRecipientAddress <= MAX_ADDRESS_VALUE, AddressOutOfRange());
        require(publicInputs.publicTokenAddress <= MAX_ADDRESS_VALUE, AddressOutOfRange());
        require(publicInputs.poolAddress <= MAX_ADDRESS_VALUE, AddressOutOfRange());
        require(publicInputs.authVerifier <= MAX_ADDRESS_VALUE, AddressOutOfRange());
        require(publicInputs.authVerifier != 0, AuthVerifierMissing());
        require(
            publicInputs.policyOperationDataHash < PoseidonFieldLib.FIELD_MODULUS,
            FieldElementNotCanonical()
        );
        require(
            publicInputs.policyDataHash < PoseidonFieldLib.FIELD_MODULUS,
            FieldElementNotCanonical()
        );
        require(publicInputs.validUntilSeconds <= MAX_VALID_UNTIL_SECONDS, IntentExpired());
        require(publicInputs.executionChainId <= MAX_EXECUTION_CHAIN_ID, WrongChainId());
        // 18. policyData binding.
        require(
            PoseidonFieldLib.keccakField(policyData) == publicInputs.policyDataHash,
            InvalidPolicyData()
        );
        // 19. outputNoteData binding.
        _assertOutputNoteHash(outputNoteData0, publicInputs.outputNoteDataHash0, 0);
        _assertOutputNoteHash(outputNoteData1, publicInputs.outputNoteDataHash1, 1);
        _assertOutputNoteHash(outputNoteData2, publicInputs.outputNoteDataHash2, 2);
        // 20. pool proof via the canonical singleton verifier.
        _verifyPoolProof(poolProof, publicInputs);
        // 21. auth proof via authVerifier staticcall.
        _verifyAuthProof(
            address(uint160(publicInputs.authVerifier)),
            publicInputs.blindedAuthCommitment,
            publicInputs.transactionIntentDigest,
            authProof
        );
        // 22. section 16.1 policy application for the selected operation.
        _applyTransactPolicy(publicInputs, policyData);
        // 23. consume nullifiers.
        require(!nullifierSpent[publicInputs.nullifier0], NullifierAlreadySpent());
        require(!nullifierSpent[publicInputs.nullifier1], NullifierAlreadySpent());
        nullifierSpent[publicInputs.nullifier0] = true;
        nullifierSpent[publicInputs.nullifier1] = true;
        // 24. consume intent replay id.
        require(!intentReplayIdUsed[publicInputs.intentReplayId], IntentReplayIdAlreadyUsed());
        intentReplayIdUsed[publicInputs.intentReplayId] = true;
        // 25. public asset movement.
        _executePublicAction(publicInputs);
        // 26-31. leaf assignment, sealing, insertion, event.
        _finalizeTransact(publicInputs, outputNoteData0, outputNoteData1, outputNoteData2);
    }

    function _finalizeTransact(
        PublicInputs calldata publicInputs,
        bytes calldata outputNoteData0,
        bytes calldata outputNoteData1,
        bytes calldata outputNoteData2
    ) private {
        uint256 leafIndex0 = nextLeafIndex;
        require(leafIndex0 + 3 <= MAX_LEAF_INDEX + 1, TreeFull());
        uint256[3] memory commitments = _sealTransactCommitments(publicInputs, leafIndex0);
        _pushNoteCommitmentRootHistory(currentNoteCommitmentRoot);
        _insertNoteCommitmentBatch3(commitments);
        _emitTransact(publicInputs, commitments, leafIndex0, outputNoteData0, outputNoteData1, outputNoteData2);
    }

    function _emitTransact(
        PublicInputs calldata publicInputs,
        uint256[3] memory commitments,
        uint256 leafIndex0,
        bytes calldata outputNoteData0,
        bytes calldata outputNoteData1,
        bytes calldata outputNoteData2
    ) private {
        emit ShieldedPoolTransact(
            publicInputs.nullifier0,
            publicInputs.nullifier1,
            publicInputs.intentReplayId,
            address(uint160(publicInputs.authVerifier)),
            commitments[0],
            commitments[1],
            commitments[2],
            leafIndex0,
            currentNoteCommitmentRoot,
            outputNoteData0,
            outputNoteData1,
            outputNoteData2
        );
    }

    function _executePublicAction(PublicInputs calldata publicInputs) private {
        if (publicInputs.publicAmountOut == 0) {
            require(publicInputs.publicRecipientAddress == 0, InvalidPublicActionConfiguration());
            require(publicInputs.publicTokenAddress == 0, InvalidPublicActionConfiguration());
            return;
        }
        require(publicInputs.publicRecipientAddress != 0, InvalidPublicActionConfiguration());
        address recipient = address(uint160(publicInputs.publicRecipientAddress));
        address token = address(uint160(publicInputs.publicTokenAddress));
        if (token == address(0)) {
            // spec section 7.1: low-level CALL with all remaining gas; require success.
            (bool ok,) = recipient.call{value: publicInputs.publicAmountOut}("");
            require(ok, EthTransferFailed());
        } else {
            ERC20AssetLib.safeTransfer(token, recipient, publicInputs.publicAmountOut);
        }
    }

    /// @dev spec section 15.6: final commitments are pool-scoped —
    ///      poseidon(NOTE_COMMITMENT_DOMAIN, executionChainId, poolAddress, nbc, leafIndex).
    function _sealTransactCommitments(PublicInputs calldata publicInputs, uint256 leafIndex0)
        private
        view
        returns (uint256[3] memory commitments)
    {
        uint256 chainId = block.chainid;
        uint256 poolAddr = uint256(uint160(address(this)));
        commitments[0] =
            PoseidonFieldLib.noteCommitment(chainId, poolAddr, publicInputs.noteBodyCommitment0, leafIndex0);
        commitments[1] =
            PoseidonFieldLib.noteCommitment(chainId, poolAddr, publicInputs.noteBodyCommitment1, leafIndex0 + 1);
        commitments[2] =
            PoseidonFieldLib.noteCommitment(chainId, poolAddr, publicInputs.noteBodyCommitment2, leafIndex0 + 2);
        require(
            commitments[0] != 0 && commitments[1] != 0 && commitments[2] != 0,
            ZeroNoteCommitment()
        );
    }

    /// @notice spec section 7.2 — verify via staticcall to the canonical
    ///         verifier. Failure taxonomy: revert, returndata != 32 bytes, or
    ///         decoded false.
    function _verifyPoolProof(bytes calldata proof, PublicInputs calldata publicInputs)
        internal
        view
    {
        (bool success, bytes memory ret) = address(POOL_VERIFIER).staticcall(
            abi.encodeCall(IPoolVerifier.verifyPoolProof, (proof, publicInputs))
        );
        require(
            success && ret.length == 32 && abi.decode(ret, (bool)),
            PoolProofRejected()
        );
    }

    /// @notice spec section 7.5 — auth dispatch. Failure taxonomy: no code,
    ///         revert, returndata != 32 bytes, or decoded false.
    function _verifyAuthProof(
        address verifier,
        uint256 blindedAuthCommitment,
        uint256 transactionIntentDigest,
        bytes calldata proof
    ) private view {
        require(verifier.code.length != 0, AuthVerifierMissing());
        bytes memory pubInputs = abi.encode(blindedAuthCommitment, transactionIntentDigest);
        (bool success, bytes memory ret) = verifier.staticcall(
            abi.encodeCall(IAuthVerifier.verifyAuth, (pubInputs, proof))
        );
        require(
            success && ret.length == 32 && abi.decode(ret, (bool)),
            AuthProofRejected()
        );
    }

    /// @notice spec section 16.1 transact policy:
    ///         gated   => policyOperationDataHash != 0 (the circuit
    ///                    authenticates it as transactOperationDataHash),
    ///                    dispatch policyOperationDigest to the verifier;
    ///         ungated => policyOperationDataHash == 0 and empty policyData.
    function _applyTransactPolicy(PublicInputs calldata publicInputs, bytes calldata policyData)
        private
        view
    {
        uint256 appliesBit = publicInputs.publicAmountOut == 0
            ? ErcConstants.POLICY_APPLIES_TRANSFER
            : ErcConstants.POLICY_APPLIES_WITHDRAWAL;
        if (POLICY_APPLIES & appliesBit != 0) {
            require(publicInputs.policyOperationDataHash != 0, InvalidPolicyOperationDataHash());
            uint256 digest = PoseidonFieldLib.policyOperationDigest(
                block.chainid,
                uint256(uint160(address(this))),
                uint256(uint160(POLICY_VERIFIER)),
                ErcConstants.POLICY_OPERATION_TRANSACT,
                publicInputs.policyOperationDataHash
            );
            _dispatchPolicy(digest, policyData);
        } else {
            require(publicInputs.policyOperationDataHash == 0, InvalidPolicyOperationDataHash());
            require(policyData.length == 0, InvalidPolicyData());
        }
    }

    function _dispatchPolicy(uint256 policyOperationDigest, bytes calldata policyData) private view {
        (bool success, bytes memory ret) = POLICY_VERIFIER.staticcall(
            abi.encodeCall(IPolicyVerifier.verifyPolicy, (abi.encode(policyOperationDigest), policyData))
        );
        require(
            success && ret.length == 32 && abi.decode(ret, (bool)),
            PolicyRejected()
        );
    }

    function _assertOutputNoteHash(
        bytes calldata outputNoteData,
        uint256 expectedHash,
        uint8 slot
    ) private pure {
        require(
            PoseidonFieldLib.keccakField(outputNoteData) == expectedHash,
            InvalidOutputNoteDataHash(slot)
        );
    }

    // -------------------------------- deposit --------------------------------

    /// @notice spec section 7.3 — proof-free deposit path.
    function deposit(
        address token,
        uint256 amount,
        uint256 ownerCommitment,
        bytes calldata outputNoteData,
        bytes calldata policyData
    ) external payable nonReentrant {
        // 1-4. range checks.
        require(amount > 0 && amount <= MAX_AMOUNT_VALUE, InvalidDepositAmount());
        require(ownerCommitment != 0, InvalidOwnerCommitment());
        require(ownerCommitment < PoseidonFieldLib.FIELD_MODULUS, FieldElementNotCanonical());

        // 5-6. policy application (section 16.1 deposit operation).
        if (POLICY_APPLIES & ErcConstants.POLICY_APPLIES_DEPOSIT != 0) {
            uint256 opData = PoseidonFieldLib.depositOperationDataHash(
                block.chainid,
                uint256(uint160(address(this))),
                uint256(uint160(msg.sender)),
                uint256(uint160(token)),
                amount,
                ownerCommitment,
                PoseidonFieldLib.keccakField(outputNoteData)
            );
            uint256 digest = PoseidonFieldLib.policyOperationDigest(
                block.chainid,
                uint256(uint160(address(this))),
                uint256(uint160(POLICY_VERIFIER)),
                ErcConstants.POLICY_OPERATION_DEPOSIT,
                opData
            );
            _dispatchPolicy(digest, policyData);
        } else {
            require(policyData.length == 0, InvalidPolicyData());
        }

        // 7-8. receive public assets.
        if (token == address(0)) {
            require(msg.value == amount, EthAmountMismatch());
        } else {
            require(msg.value == 0, UnexpectedEth());
            uint256 balBefore = ERC20AssetLib.balanceOf(token, address(this));
            ERC20AssetLib.pullExact(token, msg.sender, address(this), amount);
            uint256 balAfter = ERC20AssetLib.balanceOf(token, address(this));
            require(balAfter - balBefore == amount, Erc20DeliveredLess());
        }

        // 9. leaf assignment.
        uint256 leafIndex = nextLeafIndex;
        require(leafIndex + 1 <= MAX_LEAF_INDEX + 1, TreeFull());

        // 10-11. pool-scoped sealing.
        uint256 body = PoseidonFieldLib.noteBodyCommitment(
            ownerCommitment,
            amount,
            uint256(uint160(token))
        );
        uint256 finalCommitment = PoseidonFieldLib.noteCommitment(
            block.chainid,
            uint256(uint160(address(this))),
            body,
            leafIndex
        );
        require(finalCommitment != 0, ZeroNoteCommitment());

        // 12-13. insert.
        _pushNoteCommitmentRootHistory(currentNoteCommitmentRoot);
        _insertNoteCommitment(finalCommitment);

        // 14. emit.
        emit ShieldedPoolDeposit(
            msg.sender,
            finalCommitment,
            leafIndex,
            amount,
            uint256(uint160(token)),
            currentNoteCommitmentRoot,
            outputNoteData
        );
    }

    // -------------------------------- Views / introspection --------------------------------

    function getCurrentRoots()
        external
        view
        returns (uint256 noteCommitmentRoot, uint256 identityRoot)
    {
        return (currentNoteCommitmentRoot, REGISTRY.getCurrentIdentityRoot());
    }

    /// @notice SHA-256 of the Poseidon2 parameter asset published with the ERC.
    function poseidonParametersDigest() external pure returns (bytes32) {
        return ErcConstants.POSEIDON_PARAMETERS_DIGEST;
    }

    function outputNoteDataSuite() external pure returns (string memory) {
        return ErcConstants.OUTPUT_NOTE_DATA_SUITE;
    }

    function policyVerifier() external view returns (address) {
        return POLICY_VERIFIER;
    }

    function policyAppliesToOperations() external view returns (uint256) {
        return POLICY_APPLIES;
    }

    function isNullifierSpent(uint256 nullifier) external view returns (bool) {
        return nullifierSpent[nullifier];
    }

    function isIntentReplayIdUsed(uint256 intentReplayId) external view returns (bool) {
        return intentReplayIdUsed[intentReplayId];
    }

    function isAcceptedNoteCommitmentRoot(uint256 root) public view returns (bool) {
        if (root == currentNoteCommitmentRoot) return true;
        uint256 historyLength = noteCommitmentRootHistoryCount;
        if (historyLength > NOTE_COMMITMENT_ROOT_HISTORY_SIZE) {
            historyLength = NOTE_COMMITMENT_ROOT_HISTORY_SIZE;
        }
        for (uint256 slot; slot < historyLength; ++slot) {
            if (noteCommitmentRootHistory[slot] == root) return true;
        }
        return false;
    }

    // -------------------------------- Tree maintenance --------------------------------

    function _pushNoteCommitmentRootHistory(uint256 root) private {
        noteCommitmentRootHistory[
            noteCommitmentRootHistoryCount % NOTE_COMMITMENT_ROOT_HISTORY_SIZE
        ] = root;
        unchecked {
            ++noteCommitmentRootHistoryCount;
        }
    }

    function _insertNoteCommitment(uint256 commitment) internal {
        uint256 index = nextLeafIndex;
        uint256 currentHash = commitment;
        for (uint256 level; level < COMMITMENT_TREE_DEPTH; ++level) {
            if (((index >> level) & 1) == 0) {
                filledNoteCommitmentSubtrees[level] = currentHash;
                currentHash = PoseidonFieldLib.merkleHash(currentHash, noteCommitmentEmptyHashes[level]);
            } else {
                currentHash = PoseidonFieldLib.merkleHash(filledNoteCommitmentSubtrees[level], currentHash);
            }
        }
        currentNoteCommitmentRoot = currentHash;
        nextLeafIndex = index + 1;
    }

    /// @dev Batched 3-leaf insertion. Functionally equivalent to three sequential
    ///      `_insertNoteCommitment` calls, but pairs internal siblings within the
    ///      batch before climbing, saving ~63 Poseidon2 hashes and ~60 SSTOREs
    ///      per transfer.
    function _insertNoteCommitmentBatch3(uint256[3] memory commitments) internal {
        uint256 i0 = nextLeafIndex;
        require(i0 + 3 <= MAX_LEAF_INDEX + 1, TreeFull());

        uint256[3] memory activeIdx;
        uint256[3] memory activeHash;
        uint256 activeCount = 3;
        activeIdx[0] = i0;
        activeIdx[1] = i0 + 1;
        activeIdx[2] = i0 + 2;
        activeHash[0] = commitments[0];
        activeHash[1] = commitments[1];
        activeHash[2] = commitments[2];

        for (uint256 h; h < COMMITMENT_TREE_DEPTH; ++h) {
            uint256[3] memory nextIdxArr;
            uint256[3] memory nextHashArr;
            uint256 nextCount;
            uint256 filledWriteValue;
            bool filledWritePending;

            uint256 k;
            while (k < activeCount) {
                uint256 idx = activeIdx[k];
                uint256 hsh = activeHash[k];

                if ((idx & 1) == 0) {
                    filledWriteValue = hsh;
                    filledWritePending = true;

                    uint256 combined;
                    if (k + 1 < activeCount && activeIdx[k + 1] == idx + 1) {
                        combined = PoseidonFieldLib.merkleHash(hsh, activeHash[k + 1]);
                        k += 2;
                    } else {
                        combined = PoseidonFieldLib.merkleHash(hsh, noteCommitmentEmptyHashes[h]);
                        ++k;
                    }
                    nextIdxArr[nextCount] = idx >> 1;
                    nextHashArr[nextCount] = combined;
                    ++nextCount;
                } else {
                    uint256 combined = PoseidonFieldLib.merkleHash(filledNoteCommitmentSubtrees[h], hsh);
                    nextIdxArr[nextCount] = idx >> 1;
                    nextHashArr[nextCount] = combined;
                    ++nextCount;
                    ++k;
                }
            }

            if (filledWritePending) {
                filledNoteCommitmentSubtrees[h] = filledWriteValue;
            }

            activeCount = nextCount;
            for (uint256 j; j < nextCount; ++j) {
                activeIdx[j] = nextIdxArr[j];
                activeHash[j] = nextHashArr[j];
            }
        }

        currentNoteCommitmentRoot = activeHash[0];
        nextLeafIndex = i0 + 3;
    }
}
