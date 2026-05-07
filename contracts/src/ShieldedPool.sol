// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ERC20AssetLib} from "./libraries/ERC20AssetLib.sol";
import {PoseidonFieldLib} from "./libraries/PoseidonFieldLib.sol";
import {IAuthVerifier} from "./interfaces/IAuthVerifier.sol";

/// @title  EIP-8182 Shielded Pool
/// @notice Reference implementation matching the Groth16 + split-proof spec.
/// @dev    Installed at SHIELDED_POOL_ADDRESS via the activation-fork state
///         dump (Section 5.1). Not deployed via CREATE/CREATE2, so EIP-170 does
///         not constrain bytecode size.
contract ShieldedPool {
    // -------------------------------- Constants --------------------------------

    uint256 internal constant MAX_INTENT_LIFETIME = 86400;
    uint256 internal constant NOTE_COMMITMENT_ROOT_HISTORY_SIZE = 500;
    uint256 internal constant USER_REGISTRY_ROOT_HISTORY_BLOCKS = 500;
    uint256 internal constant AUTH_POLICY_REGISTRATION_ROOT_HISTORY_SIZE = 500;
    uint256 internal constant AUTH_POLICY_ROOT_HISTORY_BLOCKS = 64;
    uint256 internal constant COMMITMENT_TREE_DEPTH = 32;
    uint256 internal constant REGISTRY_TREE_DEPTH = 160;
    uint256 internal constant AUTH_POLICY_TREE_DEPTH = 32;
    uint256 internal constant MAX_LEAF_INDEX = type(uint32).max;
    uint256 internal constant MAX_ADDRESS_VALUE = type(uint160).max;
    uint256 internal constant MAX_AMOUNT_VALUE = type(uint248).max;
    uint256 internal constant MAX_VALID_UNTIL_SECONDS = type(uint32).max;
    uint256 internal constant MAX_EXECUTION_CHAIN_ID = type(uint32).max;

    address internal constant PROOF_VERIFY_PRECOMPILE_ADDRESS =
        0x0000000000000000000000000000000000000030;

    // -------------------------------- Types --------------------------------

    /// @notice 21 public inputs per EIP-8182 Section 5.3 / Section 10.
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
        uint256 registryRoot;
        uint256 validUntilSeconds;
        uint256 executionChainId;
        uint256 authPolicyRegistrationRoot;
        uint256 authPolicyRevocationRoot;
        uint256 outputNoteDataHash0;
        uint256 outputNoteDataHash1;
        uint256 outputNoteDataHash2;
        uint256 authVerifier;
        uint256 blindedAuthCommitment;
        uint256 transactionIntentDigest;
    }

    struct UserRegistryEntry {
        bool registered;
        uint256 ownerNullifierKeyHash;
        uint256 noteSecretSeedHash;
    }

    enum PublicAction {
        Transfer,
        Withdrawal
    }

    // -------------------------------- Errors --------------------------------

    error AddressOutOfRange();
    error AmountOutOfRange();
    error AuthPolicyAlreadyRevoked();
    error AuthPolicyNotOwned();
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
    error InvalidPolicyCommitment();
    error InvalidPublicActionConfiguration();
    error LeafPositionOutOfRange();
    error NullifierAlreadySpent();
    error OwnerNullifierKeyHashAlreadyUsed();
    error PoolProofRejected();
    error ReentrantCall();
    error ReservedOwnerNullifierKeyHash();
    error TreeFull();
    error UnexpectedEth();
    error UnknownAuthPolicyRegistrationRoot();
    error UnknownAuthPolicyRevocationRoot();
    error UnknownNoteCommitmentRoot();
    error UnknownUserRegistryRoot();
    error UserAlreadyRegistered();
    error UserNotRegistered();
    error WrongChainId();
    error ZeroLeaf();
    error ZeroNoteCommitment();
    error ZeroRegistrationRoot();
    error ZeroRegistryRoot();
    error ZeroRevocationRoot();

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

    event UserRegistered(
        address indexed user,
        uint256 ownerNullifierKeyHash,
        uint256 noteSecretSeedHash
    );

    event NoteSecretSeedRotated(address indexed user, uint256 noteSecretSeedHash);

    event AuthPolicyRegistered(
        address indexed user,
        uint256 leafPosition,
        uint256 leafValue,
        uint256 postInsertionRegistrationRoot
    );

    event AuthPolicyDeregistered(address indexed user, uint256 leafPosition);

    // -------------------------------- Storage --------------------------------

    // Note-commitment tree (depth-32 append-only).
    uint256 internal nextLeafIndex;
    uint256 internal currentNoteCommitmentRoot;
    uint256 internal noteCommitmentRootHistoryCount;
    mapping(uint256 => uint256) private filledNoteCommitmentSubtrees;
    mapping(uint256 => uint256) internal noteCommitmentRootHistory;

    // User-registry tree (depth-160 sparse, MSB-first key).
    uint256 internal currentUserRegistryRoot;
    uint256 internal userRegistryLastSnapshotBlock;
    mapping(uint256 => mapping(uint256 => uint256)) private userTreeNodes;
    mapping(uint256 => uint256) internal userRegistryRootHistory;
    mapping(uint256 => uint256) internal userRegistryRootBlock;
    mapping(address => UserRegistryEntry) private userRegistryEntries;
    mapping(uint256 => address) private ownerNullifierKeyHashIndex;

    // Auth-policy registration tree (depth-32 append-only). Circular-buffer
    // root history because every successful `registerAuthPolicy` advances the
    // tree.
    uint256 internal nextAuthPolicyLeafPosition;
    uint256 internal currentAuthPolicyRegistrationRoot;
    uint256 internal authPolicyRegistrationRootHistoryCount;
    mapping(uint256 => uint256) private filledAuthPolicyRegistrationSubtrees;
    mapping(uint256 => uint256) internal authPolicyRegistrationRootHistory;
    mapping(uint256 => address) private authPolicyOwner;

    // Auth-policy revocation tree (depth-32 sparse, LSB-first key on leafPosition).
    uint256 internal currentAuthPolicyRevocationRoot;
    uint256 internal authPolicyRevocationLastSnapshotBlock;
    mapping(uint256 => mapping(uint256 => uint256)) private authPolicyRevocationNodes;
    mapping(uint256 => uint256) internal authPolicyRevocationRootHistory;
    mapping(uint256 => uint256) internal authPolicyRevocationRootBlock;

    mapping(uint256 => bool) private nullifierSpent;
    mapping(uint256 => bool) private intentReplayIdUsed;

    // Empty-subtree hashes precomputed at deployment by the genesis builder
    // (scripts/contracts/deploy_shielded_pool.ts) and persisted into the
    // state dump. Indexed [level] where level 0 is the empty leaf hash.
    uint256[COMMITMENT_TREE_DEPTH] internal noteCommitmentEmptyHashes;
    uint256[REGISTRY_TREE_DEPTH] internal userRegistrySparseEmptyHashes;
    uint256[AUTH_POLICY_TREE_DEPTH] internal authPolicyRegistrationEmptyHashes;
    uint256[AUTH_POLICY_TREE_DEPTH] internal authPolicyRevocationSparseEmptyHashes;

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
        // (Section 5.4.1 step 14: "transact is non-payable; any msg.value > 0
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

        // Steps 3-6: roots.
        require(
            isAcceptedNoteCommitmentRoot(publicInputs.noteCommitmentRoot),
            UnknownNoteCommitmentRoot()
        );
        require(publicInputs.registryRoot != 0, ZeroRegistryRoot());
        require(
            isAcceptedUserRegistryRoot(publicInputs.registryRoot),
            UnknownUserRegistryRoot()
        );
        require(publicInputs.authPolicyRegistrationRoot != 0, ZeroRegistrationRoot());
        require(
            isAcceptedAuthPolicyRegistrationRoot(publicInputs.authPolicyRegistrationRoot),
            UnknownAuthPolicyRegistrationRoot()
        );
        require(publicInputs.authPolicyRevocationRoot != 0, ZeroRevocationRoot());
        require(
            isAcceptedAuthPolicyRevocationRoot(publicInputs.authPolicyRevocationRoot),
            UnknownAuthPolicyRevocationRoot()
        );

        // Step 7: nullifier uniqueness within the call.
        require(publicInputs.nullifier0 != publicInputs.nullifier1, DuplicateNullifier());

        // Step 8: range checks. Canonical-field checks for the verifier are
        // handled inside the precompile, but address/amount aliasing is an
        // EVM-side concern and MUST be enforced here too.
        require(publicInputs.publicAmountOut <= MAX_AMOUNT_VALUE, AmountOutOfRange());
        require(publicInputs.publicRecipientAddress <= MAX_ADDRESS_VALUE, AddressOutOfRange());
        require(publicInputs.publicTokenAddress <= MAX_ADDRESS_VALUE, AddressOutOfRange());
        require(publicInputs.authVerifier <= MAX_ADDRESS_VALUE, AddressOutOfRange());
        require(publicInputs.authVerifier != 0, AuthVerifierMissing());
        require(publicInputs.validUntilSeconds <= MAX_VALID_UNTIL_SECONDS, IntentExpired());
        require(publicInputs.executionChainId <= MAX_EXECUTION_CHAIN_ID, WrongChainId());

        // Step 9: pool proof via precompile.
        _verifyPoolProof(poolProof, publicInputs);

        // Step 10: auth proof via authVerifier staticcall.
        _verifyAuthProof(
            address(uint160(publicInputs.authVerifier)),
            publicInputs.blindedAuthCommitment,
            publicInputs.transactionIntentDigest,
            authProof
        );

        // Steps 11-12: consume nullifiers and intent replay id.
        require(!nullifierSpent[publicInputs.nullifier0], NullifierAlreadySpent());
        require(!nullifierSpent[publicInputs.nullifier1], NullifierAlreadySpent());
        nullifierSpent[publicInputs.nullifier0] = true;
        nullifierSpent[publicInputs.nullifier1] = true;
        require(!intentReplayIdUsed[publicInputs.intentReplayId], IntentReplayIdAlreadyUsed());
        intentReplayIdUsed[publicInputs.intentReplayId] = true;

        // Step 13: bind output payloads to proof.
        _assertOutputNoteHash(outputNoteData0, publicInputs.outputNoteDataHash0, 0);
        _assertOutputNoteHash(outputNoteData1, publicInputs.outputNoteDataHash1, 1);
        _assertOutputNoteHash(outputNoteData2, publicInputs.outputNoteDataHash2, 2);

        // Step 14: public asset movement.
        _executePublicAction(publicInputs);

        // Step 15: assign leaf indices and insert the three commitments.
        // Step 16: event. Both folded into _finalizeTransact to avoid
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
        _insertNoteCommitment(commitments[0]);
        _insertNoteCommitment(commitments[1]);
        _insertNoteCommitment(commitments[2]);
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

    function _verifyPoolProof(bytes calldata proof, PublicInputs calldata publicInputs) private view {
        (bool success, bytes memory ret) =
            PROOF_VERIFY_PRECOMPILE_ADDRESS.staticcall(abi.encode(proof, publicInputs));
        require(
            success && ret.length == 32 && abi.decode(ret, (uint256)) == 1,
            PoolProofRejected()
        );
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

    // -------------------------------- User registry --------------------------------

    function registerUser(uint256 ownerNullifierKeyHash, uint256 noteSecretSeedHash) external {
        _registerUser(msg.sender, ownerNullifierKeyHash, noteSecretSeedHash);
    }

    function rotateNoteSecretSeed(uint256 newNoteSecretSeedHash) external {
        require(newNoteSecretSeedHash < PoseidonFieldLib.FIELD_MODULUS, FieldElementNotCanonical());
        UserRegistryEntry storage entry = userRegistryEntries[msg.sender];
        require(entry.registered, UserNotRegistered());

        uint256 leaf = PoseidonFieldLib.userRegistryLeaf(
            msg.sender,
            entry.ownerNullifierKeyHash,
            newNoteSecretSeedHash
        );
        require(leaf != 0, ZeroLeaf());

        _snapshotUserRegistryRoot();
        _writeUserTreeLeaf(uint256(uint160(msg.sender)), leaf);

        entry.noteSecretSeedHash = newNoteSecretSeedHash;
        emit NoteSecretSeedRotated(msg.sender, newNoteSecretSeedHash);
    }

    function _registerUser(
        address user,
        uint256 ownerNullifierKeyHash,
        uint256 noteSecretSeedHash
    ) private {
        require(ownerNullifierKeyHash < PoseidonFieldLib.FIELD_MODULUS, FieldElementNotCanonical());
        require(noteSecretSeedHash < PoseidonFieldLib.FIELD_MODULUS, FieldElementNotCanonical());
        require(ownerNullifierKeyHash != 0, ReservedOwnerNullifierKeyHash());
        require(
            ownerNullifierKeyHash != PoseidonFieldLib.dummyOwnerNullifierKeyHash(),
            ReservedOwnerNullifierKeyHash()
        );
        require(
            ownerNullifierKeyHashIndex[ownerNullifierKeyHash] == address(0),
            OwnerNullifierKeyHashAlreadyUsed()
        );

        UserRegistryEntry storage entry = userRegistryEntries[user];
        require(!entry.registered, UserAlreadyRegistered());

        uint256 leaf = PoseidonFieldLib.userRegistryLeaf(user, ownerNullifierKeyHash, noteSecretSeedHash);
        require(leaf != 0, ZeroLeaf());

        _snapshotUserRegistryRoot();
        _writeUserTreeLeaf(uint256(uint160(user)), leaf);

        userRegistryEntries[user] = UserRegistryEntry({
            registered: true,
            ownerNullifierKeyHash: ownerNullifierKeyHash,
            noteSecretSeedHash: noteSecretSeedHash
        });
        ownerNullifierKeyHashIndex[ownerNullifierKeyHash] = user;
        emit UserRegistered(user, ownerNullifierKeyHash, noteSecretSeedHash);
    }

    // -------------------------------- Auth-policy registry --------------------------------

    function registerAuthPolicy(uint256 policyCommitment) external returns (uint256 leafPosition) {
        require(userRegistryEntries[msg.sender].registered, UserNotRegistered());
        require(policyCommitment != 0, InvalidPolicyCommitment());
        require(policyCommitment < PoseidonFieldLib.FIELD_MODULUS, FieldElementNotCanonical());

        uint256 leafValue = PoseidonFieldLib.authPolicyLeaf(msg.sender, policyCommitment);
        require(leafValue != 0, ZeroLeaf());

        leafPosition = nextAuthPolicyLeafPosition;
        require(leafPosition + 1 <= MAX_LEAF_INDEX + 1, TreeFull());

        _pushAuthPolicyRegistrationRootHistory(currentAuthPolicyRegistrationRoot);
        _insertAuthPolicyRegistrationLeaf(leafValue);
        authPolicyOwner[leafPosition] = msg.sender;

        emit AuthPolicyRegistered(
            msg.sender,
            leafPosition,
            leafValue,
            currentAuthPolicyRegistrationRoot
        );
    }

    function deregisterAuthPolicy(uint256 leafPosition) external {
        require(userRegistryEntries[msg.sender].registered, UserNotRegistered());
        require(leafPosition <= MAX_LEAF_INDEX, LeafPositionOutOfRange());
        require(authPolicyOwner[leafPosition] == msg.sender, AuthPolicyNotOwned());
        require(
            authPolicyRevocationNodes[0][leafPosition] != 1,
            AuthPolicyAlreadyRevoked()
        );

        _snapshotAuthPolicyRevocationRoot();
        _writeAuthPolicyRevocationLeaf(leafPosition, 1);

        emit AuthPolicyDeregistered(msg.sender, leafPosition);
    }

    function isRevokedAuthPolicy(uint256 leafPosition) external view returns (bool) {
        require(leafPosition <= MAX_LEAF_INDEX, LeafPositionOutOfRange());
        return authPolicyRevocationNodes[0][leafPosition] == 1;
    }

    // -------------------------------- View helpers --------------------------------

    function getCurrentRoots()
        external
        view
        returns (
            uint256 noteCommitmentRoot,
            uint256 registryRoot,
            uint256 authPolicyRegistrationRoot,
            uint256 authPolicyRevocationRoot
        )
    {
        return (
            currentNoteCommitmentRoot,
            currentUserRegistryRoot,
            currentAuthPolicyRegistrationRoot,
            currentAuthPolicyRevocationRoot
        );
    }

    function getUserRegistryEntry(address user)
        external
        view
        returns (bool registered, uint256 ownerNullifierKeyHash, uint256 noteSecretSeedHash)
    {
        UserRegistryEntry storage entry = userRegistryEntries[user];
        return (entry.registered, entry.ownerNullifierKeyHash, entry.noteSecretSeedHash);
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

    function isAcceptedUserRegistryRoot(uint256 root) public view returns (bool) {
        if (root == 0) return false;
        if (root == currentUserRegistryRoot) return true;
        for (uint256 slot; slot <= USER_REGISTRY_ROOT_HISTORY_BLOCKS; ++slot) {
            if (
                userRegistryRootHistory[slot] == root
                    && block.number - userRegistryRootBlock[slot] <= USER_REGISTRY_ROOT_HISTORY_BLOCKS
            ) return true;
        }
        return false;
    }

    function isAcceptedAuthPolicyRegistrationRoot(uint256 root) public view returns (bool) {
        if (root == 0) return false;
        if (root == currentAuthPolicyRegistrationRoot) return true;
        uint256 historyLength = authPolicyRegistrationRootHistoryCount;
        if (historyLength > AUTH_POLICY_REGISTRATION_ROOT_HISTORY_SIZE) {
            historyLength = AUTH_POLICY_REGISTRATION_ROOT_HISTORY_SIZE;
        }
        for (uint256 slot; slot < historyLength; ++slot) {
            if (authPolicyRegistrationRootHistory[slot] == root) return true;
        }
        return false;
    }

    function isAcceptedAuthPolicyRevocationRoot(uint256 root) public view returns (bool) {
        if (root == 0) return false;
        if (root == currentAuthPolicyRevocationRoot) return true;
        for (uint256 slot; slot <= AUTH_POLICY_ROOT_HISTORY_BLOCKS; ++slot) {
            if (
                authPolicyRevocationRootHistory[slot] == root
                    && block.number - authPolicyRevocationRootBlock[slot] <= AUTH_POLICY_ROOT_HISTORY_BLOCKS
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

    function _pushAuthPolicyRegistrationRootHistory(uint256 root) private {
        authPolicyRegistrationRootHistory[
            authPolicyRegistrationRootHistoryCount % AUTH_POLICY_REGISTRATION_ROOT_HISTORY_SIZE
        ] = root;
        unchecked {
            ++authPolicyRegistrationRootHistoryCount;
        }
    }

    function _snapshotUserRegistryRoot() private {
        if (userRegistryLastSnapshotBlock == block.number) return;
        uint256 slot = block.number % (USER_REGISTRY_ROOT_HISTORY_BLOCKS + 1);
        userRegistryRootHistory[slot] = currentUserRegistryRoot;
        userRegistryRootBlock[slot] = block.number;
        userRegistryLastSnapshotBlock = block.number;
    }

    function _snapshotAuthPolicyRevocationRoot() private {
        if (authPolicyRevocationLastSnapshotBlock == block.number) return;
        uint256 slot = block.number % (AUTH_POLICY_ROOT_HISTORY_BLOCKS + 1);
        authPolicyRevocationRootHistory[slot] = currentAuthPolicyRevocationRoot;
        authPolicyRevocationRootBlock[slot] = block.number;
        authPolicyRevocationLastSnapshotBlock = block.number;
    }

    function _insertNoteCommitment(uint256 commitment) private {
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

    function _insertAuthPolicyRegistrationLeaf(uint256 leaf) private {
        uint256 index = nextAuthPolicyLeafPosition;
        uint256 currentHash = leaf;
        for (uint256 level; level < AUTH_POLICY_TREE_DEPTH; ++level) {
            if (((index >> level) & 1) == 0) {
                filledAuthPolicyRegistrationSubtrees[level] = currentHash;
                currentHash = PoseidonFieldLib.merkleHash(
                    currentHash,
                    authPolicyRegistrationEmptyHashes[level]
                );
            } else {
                currentHash = PoseidonFieldLib.merkleHash(
                    filledAuthPolicyRegistrationSubtrees[level],
                    currentHash
                );
            }
        }
        currentAuthPolicyRegistrationRoot = currentHash;
        nextAuthPolicyLeafPosition = index + 1;
    }

    function _writeUserTreeLeaf(uint256 key, uint256 leaf) private {
        // depth-160 sparse Merkle, MSB-first key per Section 3.4.
        //
        // Bottom-up traversal: at level h we test bit h of `key`. With the
        // top-down convention "MSB-first key" — root tests MSB, leaf tests
        // LSB — this maps to bottom-up pathBits == bitsLSB(key, depth), which
        // is the same indexing the pool circuit uses. No bit reversal is
        // required.
        uint256 index = key;
        uint256 currentHash = leaf;
        userTreeNodes[0][index] = leaf;
        for (uint256 level; level < REGISTRY_TREE_DEPTH; ++level) {
            uint256 siblingIndex = index ^ 1;
            uint256 sibling = userTreeNodes[level][siblingIndex];
            if (sibling == 0) sibling = userRegistrySparseEmptyHashes[level];
            if ((index & 1) == 0) {
                currentHash = PoseidonFieldLib.merkleHash(currentHash, sibling);
            } else {
                currentHash = PoseidonFieldLib.merkleHash(sibling, currentHash);
            }
            index >>= 1;
            userTreeNodes[level + 1][index] = currentHash;
        }
        currentUserRegistryRoot = currentHash;
    }

    function _writeAuthPolicyRevocationLeaf(uint256 key, uint256 leaf) private {
        // depth-32 sparse Merkle, LSB-first key on leafPosition per Section 3.4.
        uint256 index = key;
        uint256 currentHash = leaf;
        authPolicyRevocationNodes[0][index] = leaf;
        for (uint256 level; level < AUTH_POLICY_TREE_DEPTH; ++level) {
            uint256 siblingIndex = index ^ 1;
            uint256 sibling = authPolicyRevocationNodes[level][siblingIndex];
            if (sibling == 0) sibling = authPolicyRevocationSparseEmptyHashes[level];
            if ((index & 1) == 0) {
                currentHash = PoseidonFieldLib.merkleHash(currentHash, sibling);
            } else {
                currentHash = PoseidonFieldLib.merkleHash(sibling, currentHash);
            }
            index >>= 1;
            authPolicyRevocationNodes[level + 1][index] = currentHash;
        }
        currentAuthPolicyRevocationRoot = currentHash;
    }

}
