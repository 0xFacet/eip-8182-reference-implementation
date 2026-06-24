// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ERC20AssetLib} from "./libraries/ERC20AssetLib.sol";
import {PoseidonFieldLib} from "./libraries/PoseidonFieldLib.sol";
import {IAuthVerifier} from "./interfaces/IAuthVerifier.sol";
import {PoolGroth16Verifier} from "./PoolGroth16Verifier.sol";

/// @title  EIP-8182 Shielded Pool
/// @notice Reference implementation matching the Groth16 + split-proof spec.
/// @dev    Installed at SHIELDED_POOL_ADDRESS via the activation-fork state
///         dump (Section 5.1). Not deployed via CREATE/CREATE2, so EIP-170 does
///         not constrain bytecode size. The pool-proof verification key is
///         embedded in the bytecode via inheritance from PoolGroth16Verifier;
///         see Section 5.5 for the inline-verification path. The inherited
///         `verifyProof` external entry point is a pure read-only helper, not
///         part of the normative protocol surface.
contract ShieldedPool is PoolGroth16Verifier {
    // -------------------------------- Constants --------------------------------

    uint256 internal constant MAX_INTENT_LIFETIME = 86400;
    uint256 internal constant NOTE_COMMITMENT_ROOT_HISTORY_SIZE = 500;
    uint256 internal constant AUTH_POLICY_ROOT_HISTORY_BLOCKS = 64;
    uint256 internal constant COMMITMENT_TREE_DEPTH = 32;
    uint256 internal constant AUTH_POLICY_TREE_DEPTH = 32;
    /// @dev Section 3.2 constant; the depth-8 per-user policy-set tree is
    ///      computed off-chain by the wallet and committed in the leaf as
    ///      `policySetCommitment`. The contract does not maintain it.
    uint256 internal constant POLICY_SET_DEPTH = 8;
    uint256 internal constant MAX_LEAF_INDEX = type(uint32).max;
    uint256 internal constant MAX_ADDRESS_VALUE = type(uint160).max;
    uint256 internal constant MAX_AMOUNT_VALUE = type(uint248).max;
    uint256 internal constant MAX_VALID_UNTIL_SECONDS = type(uint32).max;
    uint256 internal constant MAX_EXECUTION_CHAIN_ID = type(uint32).max;

    // -------------------------------- Types --------------------------------

    /// @notice 19 public inputs per EIP-8182 Section 5.3 / Section 9.
    struct PublicInputs {
        uint256 noteCommitmentRoot;
        uint256 nullifier0;
        uint256 nullifier1;
        uint256 noteBodyCommitment0;
        uint256 noteBodyCommitment1;
        uint256 noteBodyCommitment2;
        uint256 publicAmountOut;
        uint256 publicRecipientAddress;
        uint256 publicTokenAddress;
        uint256 intentReplayId;
        uint256 validUntilSeconds;
        uint256 executionChainId;
        uint256 authPolicyRoot;
        uint256 outputNoteDataHash0;
        uint256 outputNoteDataHash1;
        uint256 outputNoteDataHash2;
        uint256 authVerifier;
        uint256 blindedAuthCommitment;
        uint256 transactionIntentDigest;
    }

    /// @notice Section 5.3 — per-address auth-policy state.
    struct UserEntry {
        uint32 leafPosition;
        uint256 ownerNullifierKeyHash;
        uint256 noteSecretSeedHash;
        uint256 policySetCommitment;
    }

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
    error InvalidPublicActionConfiguration();
    error NullifierAlreadySpent();
    error OwnerNullifierKeyHashAlreadyUsed();
    error OwnerNullifierKeyHashImmutable();
    error PoolProofRejected();
    error ReentrantCall();
    error ReservedOwnerNullifierKeyHash();
    error TreeFull();
    error UnexpectedEth();
    error UnknownAuthPolicyRoot();
    error UnknownNoteCommitmentRoot();
    error WrongChainId();
    error ZeroAuthPolicyRoot();
    error ZeroLeaf();
    error ZeroNoteCommitment();
    error ZeroNoteSecretSeedHash();

    // -------------------------------- Events --------------------------------

    event ShieldedPoolTransact(
        uint256 indexed nullifier0,
        uint256 indexed nullifier1,
        uint256 indexed intentReplayId,
        address authVerifier,
        uint256 noteCommitment0,
        uint256 noteCommitment1,
        uint256 noteCommitment2,
        uint256 leafIndex0,
        uint256 postInsertionCommitmentRoot,
        bytes outputNoteData0,
        bytes outputNoteData1,
        bytes outputNoteData2
    );

    event ShieldedPoolDeposit(
        address indexed depositor,
        uint256 noteCommitment,
        uint256 leafIndex,
        uint256 amount,
        uint256 tokenAddress,
        uint256 postInsertionCommitmentRoot,
        bytes outputNoteData
    );

    event AuthPolicySet(
        address indexed user,
        uint256 ownerNullifierKeyHash,
        uint256 noteSecretSeedHash,
        uint256 policySetCommitment,
        uint256 leafPosition,
        uint256 leafValue,
        uint256 postUpdateAuthPolicyRoot
    );

    // -------------------------------- Storage --------------------------------

    // Note-commitment tree (depth-32 append-only).
    uint256 internal nextLeafIndex;
    uint256 internal currentNoteCommitmentRoot;
    uint256 internal noteCommitmentRootHistoryCount;
    mapping(uint256 => uint256) internal filledNoteCommitmentSubtrees;
    mapping(uint256 => uint256) internal noteCommitmentRootHistory;

    // Auth-policy registry (depth-32 sparse mutable, LSB-first key on
    // leafPosition). Slot 0 reserved as the "unassigned" sentinel; first
    // setAuthPolicy from an address claims slot `nextLeafPosition`, which
    // starts at 1.
    uint256 internal nextLeafPosition;
    uint256 internal currentAuthPolicyRoot;
    uint256 internal authPolicyLastSnapshotBlock;
    mapping(uint256 => mapping(uint256 => uint256)) private authPolicyTreeNodes;
    mapping(uint256 => uint256) internal authPolicyRootHistory;
    mapping(uint256 => uint256) internal authPolicyRootBlock;

    // Per-address auth-policy state.
    mapping(address => UserEntry) private userEntries;
    mapping(uint256 => address) private ownerNullifierKeyHashIndex;

    mapping(uint256 => bool) private nullifierSpent;
    mapping(uint256 => bool) private intentReplayIdUsed;

    // Empty-subtree hashes precomputed at deployment by the genesis builder
    // (scripts/contracts/deploy_shielded_pool.ts) and persisted into the
    // state dump. Indexed [level] where level 0 is the empty leaf hash.
    uint256[COMMITMENT_TREE_DEPTH] internal noteCommitmentEmptyHashes;
    uint256[AUTH_POLICY_TREE_DEPTH] internal authPolicySparseEmptyHashes;

    // -------------------------------- Modifier --------------------------------

    modifier nonReentrant() {
        bytes32 slot = keccak256("ShieldedPool.reentrancy.guard");
        uint256 lockValue;
        assembly {
            lockValue := tload(slot)
        }
        require(lockValue == 0, ReentrantCall());
        assembly {
            tstore(slot, 1)
        }
        _;
        assembly {
            tstore(slot, 0)
        }
    }

    // -------------------------------- transact --------------------------------

    /// @notice Section 5.4.1 — verifies pool + auth proofs, consumes nullifiers,
    ///         executes the public asset movement, inserts the three output
    ///         commitments, and emits ShieldedPoolTransact.
    function transact(
        bytes calldata poolProof,
        bytes calldata authProof,
        PublicInputs calldata publicInputs,
        bytes calldata outputNoteData0,
        bytes calldata outputNoteData1,
        bytes calldata outputNoteData2
    ) external nonReentrant {
        // Function is non-payable, so the EVM auto-reverts any msg.value > 0
        // (Section 5.4.1 step 12: "transact is non-payable; any msg.value > 0
        // reverts on entry").

        // Step 1: chain id.
        require(publicInputs.executionChainId == block.chainid, WrongChainId());

        // Step 2: intent expiry.
        require(publicInputs.validUntilSeconds != 0, IntentExpired());
        require(publicInputs.validUntilSeconds <= MAX_VALID_UNTIL_SECONDS, IntentExpired());
        require(block.timestamp <= publicInputs.validUntilSeconds, IntentExpired());
        require(
            publicInputs.validUntilSeconds <= block.timestamp + MAX_INTENT_LIFETIME,
            IntentLifetimeTooLong()
        );

        // Steps 3-4: roots.
        require(
            isAcceptedNoteCommitmentRoot(publicInputs.noteCommitmentRoot),
            UnknownNoteCommitmentRoot()
        );
        require(publicInputs.authPolicyRoot != 0, ZeroAuthPolicyRoot());
        require(
            isAcceptedAuthPolicyRoot(publicInputs.authPolicyRoot),
            UnknownAuthPolicyRoot()
        );

        // Step 5: nullifier uniqueness within the call.
        require(publicInputs.nullifier0 != publicInputs.nullifier1, DuplicateNullifier());

        // Step 6: range checks. Canonical-field checks for the verifier are
        // handled inside the inlined Groth16 verifier (Section 5.5), but
        // address/amount aliasing is an EVM-side concern and MUST be enforced
        // here too.
        require(publicInputs.publicAmountOut <= MAX_AMOUNT_VALUE, AmountOutOfRange());
        require(publicInputs.publicRecipientAddress <= MAX_ADDRESS_VALUE, AddressOutOfRange());
        require(publicInputs.publicTokenAddress <= MAX_ADDRESS_VALUE, AddressOutOfRange());
        require(publicInputs.authVerifier <= MAX_ADDRESS_VALUE, AddressOutOfRange());
        require(publicInputs.authVerifier != 0, AuthVerifierMissing());
        require(publicInputs.validUntilSeconds <= MAX_VALID_UNTIL_SECONDS, IntentExpired());
        require(publicInputs.executionChainId <= MAX_EXECUTION_CHAIN_ID, WrongChainId());

        // Step 7: pool proof verified inline against the embedded VK.
        _verifyPoolProof(poolProof, publicInputs);

        // Step 8: auth proof via authVerifier staticcall.
        _verifyAuthProof(
            address(uint160(publicInputs.authVerifier)),
            publicInputs.blindedAuthCommitment,
            publicInputs.transactionIntentDigest,
            authProof
        );

        // Steps 9-10: consume nullifiers and intent replay id.
        require(!nullifierSpent[publicInputs.nullifier0], NullifierAlreadySpent());
        require(!nullifierSpent[publicInputs.nullifier1], NullifierAlreadySpent());
        nullifierSpent[publicInputs.nullifier0] = true;
        nullifierSpent[publicInputs.nullifier1] = true;
        require(!intentReplayIdUsed[publicInputs.intentReplayId], IntentReplayIdAlreadyUsed());
        intentReplayIdUsed[publicInputs.intentReplayId] = true;

        // Step 11: bind output payloads to proof.
        _assertOutputNoteHash(outputNoteData0, publicInputs.outputNoteDataHash0, 0);
        _assertOutputNoteHash(outputNoteData1, publicInputs.outputNoteDataHash1, 1);
        _assertOutputNoteHash(outputNoteData2, publicInputs.outputNoteDataHash2, 2);

        // Step 12: public asset movement.
        _executePublicAction(publicInputs);

        // Step 13: assign leaf indices, insert the three commitments, and
        // emit ShieldedPoolTransact. Folded into _finalizeTransact to avoid
        // stack-too-deep without enabling via_ir (which roughly halves
        // compile time on the Poseidon library here).
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
            (bool ok,) = recipient.call{value: publicInputs.publicAmountOut}("");
            require(ok, EthTransferFailed());
        } else {
            ERC20AssetLib.safeTransfer(token, recipient, publicInputs.publicAmountOut);
        }
    }

    function _sealTransactCommitments(PublicInputs calldata publicInputs, uint256 leafIndex0)
        private
        pure
        returns (uint256[3] memory commitments)
    {
        commitments[0] = PoseidonFieldLib.noteCommitment(publicInputs.noteBodyCommitment0, leafIndex0);
        commitments[1] = PoseidonFieldLib.noteCommitment(publicInputs.noteBodyCommitment1, leafIndex0 + 1);
        commitments[2] = PoseidonFieldLib.noteCommitment(publicInputs.noteBodyCommitment2, leafIndex0 + 2);
        require(
            commitments[0] != 0 && commitments[1] != 0 && commitments[2] != 0,
            ZeroNoteCommitment()
        );
    }

    /// @notice Section 5.5 — verifies the 256-byte Groth16 BN254 pool proof
    ///         against the 19-field public-input vector using the verification
    ///         key embedded in this contract's bytecode (inherited from
    ///         PoolGroth16Verifier). Reverts on any failure mode: malformed
    ///         proof encoding, non-canonical public input, off-curve / wrong-
    ///         subgroup point, or pairing-equation failure.
    /// @dev    Uses self-staticcall rather than a normal internal call because
    ///         the snarkjs-generated `verifyProof` body returns via raw
    ///         `assembly { return(0, 0x20) }` — a direct internal call would
    ///         terminate the entire `transact` call frame instead of returning
    ///         to step 8.
    function _verifyPoolProof(bytes calldata proof, PublicInputs calldata publicInputs)
        internal
        view
        virtual
    {
        require(proof.length == 256, PoolProofRejected());

        // Split the 256-byte proof into Groth16 (A, B, C) elements. The byte
        // layout is the EIP-8182 / EIP-197 canonical form documented in
        // Section 5.5: A (64) || B (128, x.c1||x.c0||y.c1||y.c0) || C (64).
        uint256[2] memory pA = [_proofWord(proof, 0), _proofWord(proof, 32)];
        uint256[2][2] memory pB = [
            [_proofWord(proof, 64),  _proofWord(proof, 96)],
            [_proofWord(proof, 128), _proofWord(proof, 160)]
        ];
        uint256[2] memory pC = [_proofWord(proof, 192), _proofWord(proof, 224)];

        uint256[19] memory pub;
        pub[0]  = publicInputs.noteCommitmentRoot;
        pub[1]  = publicInputs.nullifier0;
        pub[2]  = publicInputs.nullifier1;
        pub[3]  = publicInputs.noteBodyCommitment0;
        pub[4]  = publicInputs.noteBodyCommitment1;
        pub[5]  = publicInputs.noteBodyCommitment2;
        pub[6]  = publicInputs.publicAmountOut;
        pub[7]  = publicInputs.publicRecipientAddress;
        pub[8]  = publicInputs.publicTokenAddress;
        pub[9]  = publicInputs.intentReplayId;
        pub[10] = publicInputs.validUntilSeconds;
        pub[11] = publicInputs.executionChainId;
        pub[12] = publicInputs.authPolicyRoot;
        pub[13] = publicInputs.outputNoteDataHash0;
        pub[14] = publicInputs.outputNoteDataHash1;
        pub[15] = publicInputs.outputNoteDataHash2;
        pub[16] = publicInputs.authVerifier;
        pub[17] = publicInputs.blindedAuthCommitment;
        pub[18] = publicInputs.transactionIntentDigest;

        (bool success, bytes memory ret) = address(this).staticcall(
            abi.encodeCall(this.verifyProof, (pA, pB, pC, pub))
        );
        require(
            success && ret.length == 32 && abi.decode(ret, (uint256)) == 1,
            PoolProofRejected()
        );
    }

    function _proofWord(bytes calldata src, uint256 offset) private pure returns (uint256 w) {
        assembly { w := calldataload(add(src.offset, offset)) }
    }

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

    function _assertOutputNoteHash(
        bytes calldata outputNoteData,
        uint256 expectedHash,
        uint8 slot
    ) private pure {
        uint256 actual = uint256(keccak256(outputNoteData)) % PoseidonFieldLib.FIELD_MODULUS;
        require(actual == expectedHash, InvalidOutputNoteDataHash(slot));
    }

    // -------------------------------- deposit --------------------------------

    function deposit(
        address token,
        uint256 amount,
        uint256 ownerCommitment,
        bytes calldata outputNoteData
    ) external payable nonReentrant {
        require(amount > 0 && amount <= MAX_AMOUNT_VALUE, InvalidDepositAmount());
        require(ownerCommitment != 0, InvalidOwnerCommitment());
        require(ownerCommitment < PoseidonFieldLib.FIELD_MODULUS, FieldElementNotCanonical());

        if (token == address(0)) {
            require(msg.value == amount, EthAmountMismatch());
        } else {
            require(msg.value == 0, UnexpectedEth());
            uint256 balBefore = ERC20AssetLib.balanceOf(token, address(this));
            ERC20AssetLib.pullExact(token, msg.sender, address(this), amount);
            uint256 balAfter = ERC20AssetLib.balanceOf(token, address(this));
            require(balAfter - balBefore == amount, Erc20DeliveredLess());
        }

        uint256 leafIndex = nextLeafIndex;
        require(leafIndex + 1 <= MAX_LEAF_INDEX + 1, TreeFull());

        uint256 body = PoseidonFieldLib.noteBodyCommitment(
            ownerCommitment,
            amount,
            uint256(uint160(token))
        );
        uint256 finalCommitment = PoseidonFieldLib.noteCommitment(body, leafIndex);
        require(finalCommitment != 0, ZeroNoteCommitment());

        _pushNoteCommitmentRootHistory(currentNoteCommitmentRoot);
        _insertNoteCommitment(finalCommitment);

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

    // -------------------------------- Auth-policy registry --------------------------------

    /// @notice Section 6.1 — register or update msg.sender's auth-policy leaf.
    ///         First call from an address assigns a leafPosition, locks
    ///         ownerNullifierKeyHash, and claims the global onkHash index entry.
    ///         Subsequent calls require ownerNullifierKeyHash to match the
    ///         locked value; noteSecretSeedHash and policySetCommitment are
    ///         rotatable.
    function setAuthPolicy(
        uint256 ownerNullifierKeyHash,
        uint256 noteSecretSeedHashValue,
        uint256 policySetCommitment
    ) external returns (uint256 leafPosition) {
        require(ownerNullifierKeyHash < PoseidonFieldLib.FIELD_MODULUS, FieldElementNotCanonical());
        require(noteSecretSeedHashValue < PoseidonFieldLib.FIELD_MODULUS, FieldElementNotCanonical());
        require(policySetCommitment < PoseidonFieldLib.FIELD_MODULUS, FieldElementNotCanonical());
        require(ownerNullifierKeyHash != 0, ReservedOwnerNullifierKeyHash());
        require(
            ownerNullifierKeyHash != PoseidonFieldLib.dummyOwnerNullifierKeyHash(),
            ReservedOwnerNullifierKeyHash()
        );
        require(noteSecretSeedHashValue != 0, ZeroNoteSecretSeedHash());

        UserEntry storage entry = userEntries[msg.sender];
        if (entry.leafPosition == 0) {
            // First registration from this address.
            require(
                ownerNullifierKeyHashIndex[ownerNullifierKeyHash] == address(0),
                OwnerNullifierKeyHashAlreadyUsed()
            );
            uint256 newPosition = nextLeafPosition;
            require(newPosition <= MAX_LEAF_INDEX, TreeFull());
            unchecked {
                nextLeafPosition = newPosition + 1;
            }
            entry.leafPosition = uint32(newPosition);
            entry.ownerNullifierKeyHash = ownerNullifierKeyHash;
            ownerNullifierKeyHashIndex[ownerNullifierKeyHash] = msg.sender;
            leafPosition = newPosition;
        } else {
            require(
                entry.ownerNullifierKeyHash == ownerNullifierKeyHash,
                OwnerNullifierKeyHashImmutable()
            );
            leafPosition = entry.leafPosition;
        }
        entry.noteSecretSeedHash = noteSecretSeedHashValue;
        entry.policySetCommitment = policySetCommitment;

        uint256 leafValue = PoseidonFieldLib.authPolicyLeaf(
            msg.sender,
            ownerNullifierKeyHash,
            noteSecretSeedHashValue,
            policySetCommitment
        );
        require(leafValue != 0, ZeroLeaf());

        _snapshotAuthPolicyRoot();
        _writeAuthPolicyTreeLeaf(leafPosition, leafValue);

        emit AuthPolicySet(
            msg.sender,
            ownerNullifierKeyHash,
            noteSecretSeedHashValue,
            policySetCommitment,
            leafPosition,
            leafValue,
            currentAuthPolicyRoot
        );
    }

    // -------------------------------- View helpers --------------------------------

    function getCurrentRoots()
        external
        view
        returns (uint256 noteCommitmentRoot, uint256 authPolicyRoot)
    {
        return (currentNoteCommitmentRoot, currentAuthPolicyRoot);
    }

    function getAuthPolicyEntry(address user)
        external
        view
        returns (bool registered, UserEntry memory entry)
    {
        entry = userEntries[user];
        registered = entry.leafPosition != 0;
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

    function isAcceptedAuthPolicyRoot(uint256 root) public view returns (bool) {
        if (root == 0) return false;
        if (root == currentAuthPolicyRoot) return true;
        for (uint256 slot; slot <= AUTH_POLICY_ROOT_HISTORY_BLOCKS; ++slot) {
            if (
                authPolicyRootHistory[slot] == root
                    && block.number - authPolicyRootBlock[slot] <= AUTH_POLICY_ROOT_HISTORY_BLOCKS
            ) return true;
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

    function _snapshotAuthPolicyRoot() private {
        if (authPolicyLastSnapshotBlock == block.number) return;
        uint256 slot = block.number % (AUTH_POLICY_ROOT_HISTORY_BLOCKS + 1);
        authPolicyRootHistory[slot] = currentAuthPolicyRoot;
        authPolicyRootBlock[slot] = block.number;
        authPolicyLastSnapshotBlock = block.number;
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

    function _writeAuthPolicyTreeLeaf(uint256 key, uint256 leaf) private {
        // depth-32 sparse Merkle, LSB-first key on leafPosition per Section 3.4.
        uint256 index = key;
        uint256 currentHash = leaf;
        authPolicyTreeNodes[0][index] = leaf;
        for (uint256 level; level < AUTH_POLICY_TREE_DEPTH; ++level) {
            uint256 siblingIndex = index ^ 1;
            uint256 sibling = authPolicyTreeNodes[level][siblingIndex];
            if (sibling == 0) sibling = authPolicySparseEmptyHashes[level];
            if ((index & 1) == 0) {
                currentHash = PoseidonFieldLib.merkleHash(currentHash, sibling);
            } else {
                currentHash = PoseidonFieldLib.merkleHash(sibling, currentHash);
            }
            index >>= 1;
            authPolicyTreeNodes[level + 1][index] = currentHash;
        }
        currentAuthPolicyRoot = currentHash;
    }

}
