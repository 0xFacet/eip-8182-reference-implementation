// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ERC20AssetLib} from "./libraries/ERC20AssetLib.sol";
import {PoseidonFieldLib} from "./libraries/PoseidonFieldLib.sol";

// System contract: installed at SHIELDED_POOL_ADDRESS (0x...081820) via state
// dump at the EIP-8182 activation fork (spec §5.1). Not deployed via
// CREATE/CREATE2, so EIP-170's 24,576-byte contract size limit does not apply.
// Readability and spec conformance take priority over bytecode size.
contract ShieldedPool {
    uint256 internal constant MAX_INTENT_LIFETIME = 86400;
    uint256 internal constant NOTE_COMMITMENT_ROOT_HISTORY_SIZE = 500;
    uint256 internal constant USER_REGISTRY_ROOT_HISTORY_BLOCKS = 500;
    uint256 internal constant AUTH_POLICY_ROOT_HISTORY_BLOCKS = 64;
    uint256 internal constant COMMITMENT_TREE_DEPTH = 32;
    uint256 internal constant REGISTRY_TREE_DEPTH = 160;
    uint256 internal constant MAX_NOTE_COMMITMENT_LEAF_INDEX = type(uint32).max;
    uint256 internal constant MAX_ADDRESS_VALUE = type(uint160).max;
    uint256 internal constant MAX_AMOUNT_VALUE = type(uint248).max;
    uint256 internal constant MAX_VALID_UNTIL_SECONDS = type(uint32).max;

    address internal constant PROOF_VERIFY_PRECOMPILE_ADDRESS = 0x0000000000000000000000000000000000000030;

    uint8 internal constant ORIGIN_MODE_DEFAULT = 0;
    uint8 internal constant ORIGIN_MODE_REQUIRE_TAGGED = 1;

    /// 17 public inputs per EIP-8182 Section 10.
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
        uint256 authPolicyRegistryRoot;
        uint256 outputNoteDataHash0;
        uint256 outputNoteDataHash1;
        uint256 outputNoteDataHash2;
    }

    struct DeliveryEndpoint {
        uint32 schemeId;
        bytes keyBytes;
    }

    struct UserRegistryEntry {
        bool registered;
        uint256 ownerNullifierKeyHash;
        uint256 noteSecretSeedHash;
    }

    struct AuthPolicyState {
        bool active;
        uint256 authDataCommitment;
        uint256 policyVersion;
    }

    enum PublicAction {
        Transfer,
        Withdrawal
    }

    struct PreparedPublicAction {
        PublicAction kind;
        address recipient;
        address token;
        uint256 amountOut;
    }

    error AddressOutOfRange();
    error AmountOutOfRange();
    error AuthPolicyAlreadyInactive();
    error InvalidDeliveryKey();
    error DeliveryKeyNotSet();
    error DuplicateNullifier();
    error EthAmountMismatch();
    error EthTransferFailed();
    error Erc20DeliveredLess();
    error FieldElementNotCanonical();
    error IntentExpired();
    error IntentLifetimeTooLong();
    error IntentReplayIdAlreadyUsed();
    error InvalidDepositAmount();
    error InvalidOriginMode();
    error InvalidOriginTag();
    error InvalidOutputNoteDataHash(uint8 slot);
    error InvalidOwnerCommitment();
    error InvalidPublicActionConfiguration();
    error InvalidProof();
    error NullifierAlreadySpent();
    error OwnerNullifierKeyHashAlreadyUsed();
    error ReentrantCall();
    error ReservedOwnerNullifierKeyHash();
    error TreeFull();
    error UnexpectedEth();
    error UnknownNoteCommitmentRoot();
    error UnknownAuthPolicyRoot();
    error UnknownUserRegistryRoot();
    error UserAlreadyRegistered();
    error UserNotRegistered();
    error WrongChainId();
    error ZeroNoteCommitment();
    error ZeroLeaf();

    event ShieldedPoolTransact(
        uint256 indexed nullifier0,
        uint256 indexed nullifier1,
        uint256 indexed intentReplayId,
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
        uint256 originTag,
        uint256 postInsertionCommitmentRoot,
        bytes outputNoteData
    );

    event UserRegistered(address indexed user, uint256 ownerNullifierKeyHash, uint256 noteSecretSeedHash);

    event NoteSecretSeedRotated(address indexed user, uint256 noteSecretSeedHash);

    event AuthPolicyRegistered(
        address indexed user, uint256 innerVkHash, uint256 authDataCommitment, uint256 policyVersion
    );

    event AuthPolicyDeregistered(address indexed user, uint256 innerVkHash);

    event DeliveryKeySet(address indexed user, uint32 indexed schemeId, bytes keyBytes);

    event DeliveryKeyRemoved(address indexed user, uint32 indexed schemeId);

    uint256 internal nextLeafIndex;
    uint256 internal currentNoteCommitmentRoot;
    uint256 internal noteCommitmentRootHistoryCount;
    mapping(uint256 => uint256) private filledNoteCommitmentSubtrees;
    mapping(uint256 => uint256) internal noteCommitmentRootHistory;

    uint256 internal currentUserRegistryRoot;
    uint256 internal userRegistryLastSnapshotBlock;
    mapping(uint256 => mapping(uint256 => uint256)) private userTreeNodes;
    mapping(uint256 => uint256) internal userRegistryRootHistory;
    mapping(uint256 => uint256) internal userRegistryRootBlock;
    mapping(address => UserRegistryEntry) private userRegistryEntries;
    mapping(uint256 => address) private ownerNullifierKeyHashIndex;
    mapping(address => DeliveryEndpoint) private deliveryEndpoints;

    uint256 internal currentAuthPolicyRoot;
    uint256 internal authPolicyLastSnapshotBlock;
    mapping(uint256 => mapping(uint256 => uint256)) private authTreeNodes;
    mapping(uint256 => uint256) internal authPolicyRootHistory;
    mapping(uint256 => uint256) internal authPolicyRootBlock;
    mapping(address => mapping(uint256 => AuthPolicyState)) private authPolicies;
    mapping(bytes32 => uint256) private policyVersions;

    mapping(uint256 => bool) private nullifierSpent;
    mapping(uint256 => bool) private intentReplayIdUsed;
    uint256[COMMITMENT_TREE_DEPTH] internal noteCommitmentEmptyHashes;
    uint256[REGISTRY_TREE_DEPTH] internal sparseEmptyHashes;

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

    function transact(
        bytes calldata proof,
        PublicInputs calldata publicInputs,
        bytes calldata outputNoteData0,
        bytes calldata outputNoteData1,
        bytes calldata outputNoteData2
    ) external nonReentrant {
        _validateTransactPublicInputs(proof, publicInputs);

        PreparedPublicAction memory action = _preparePublicAction(publicInputs);

        _consumeNullifiersAndReplayId(publicInputs);

        uint256 leafIndex0 = nextLeafIndex;
        require(leafIndex0 + 2 <= MAX_NOTE_COMMITMENT_LEAF_INDEX, TreeFull());

        uint256[3] memory finalCommitments = _sealTransactCommitments(publicInputs, leafIndex0);

        _pushNoteCommitmentRoot(_currentNoteCommitmentRoot());
        _insertNoteCommitment(finalCommitments[0]);
        _insertNoteCommitment(finalCommitments[1]);
        _insertNoteCommitment(finalCommitments[2]);

        _assertOutputNoteHash(outputNoteData0, publicInputs.outputNoteDataHash0, 0);
        _assertOutputNoteHash(outputNoteData1, publicInputs.outputNoteDataHash1, 1);
        _assertOutputNoteHash(outputNoteData2, publicInputs.outputNoteDataHash2, 2);

        _executePublicAction(action);

        _emitTransactEvent(
            publicInputs,
            finalCommitments,
            leafIndex0,
            outputNoteData0,
            outputNoteData1,
            outputNoteData2
        );
    }

    function _validateTransactPublicInputs(bytes calldata proof, PublicInputs calldata publicInputs) private view {
        _verifyProof(proof, publicInputs);
        _ensureCanonicalProofFields(publicInputs);

        require(publicInputs.executionChainId == block.chainid, WrongChainId());
        require(publicInputs.validUntilSeconds != 0, IntentExpired());
        require(publicInputs.validUntilSeconds <= MAX_VALID_UNTIL_SECONDS, IntentExpired());
        require(block.timestamp <= publicInputs.validUntilSeconds, IntentExpired());
        require(publicInputs.validUntilSeconds <= block.timestamp + MAX_INTENT_LIFETIME, IntentLifetimeTooLong());

        require(isAcceptedNoteCommitmentRoot(publicInputs.noteCommitmentRoot), UnknownNoteCommitmentRoot());
        require(isAcceptedUserRegistryRoot(publicInputs.registryRoot), UnknownUserRegistryRoot());
        require(isAcceptedAuthPolicyRoot(publicInputs.authPolicyRegistryRoot), UnknownAuthPolicyRoot());
    }

    function _consumeNullifiersAndReplayId(PublicInputs calldata publicInputs) private {
        require(publicInputs.nullifier0 != publicInputs.nullifier1, DuplicateNullifier());
        require(!nullifierSpent[publicInputs.nullifier0], NullifierAlreadySpent());
        require(!nullifierSpent[publicInputs.nullifier1], NullifierAlreadySpent());
        nullifierSpent[publicInputs.nullifier0] = true;
        nullifierSpent[publicInputs.nullifier1] = true;

        require(!intentReplayIdUsed[publicInputs.intentReplayId], IntentReplayIdAlreadyUsed());
        intentReplayIdUsed[publicInputs.intentReplayId] = true;
    }

    function _sealTransactCommitments(PublicInputs calldata publicInputs, uint256 leafIndex0)
        private
        pure
        returns (uint256[3] memory finalCommitments)
    {
        finalCommitments[0] = PoseidonFieldLib.noteCommitment(publicInputs.noteBodyCommitment0, leafIndex0);
        finalCommitments[1] = PoseidonFieldLib.noteCommitment(publicInputs.noteBodyCommitment1, leafIndex0 + 1);
        finalCommitments[2] = PoseidonFieldLib.noteCommitment(publicInputs.noteBodyCommitment2, leafIndex0 + 2);
        require(
            finalCommitments[0] != 0 && finalCommitments[1] != 0 && finalCommitments[2] != 0,
            ZeroNoteCommitment()
        );
    }

    function _emitTransactEvent(
        PublicInputs calldata publicInputs,
        uint256[3] memory finalCommitments,
        uint256 leafIndex0,
        bytes calldata outputNoteData0,
        bytes calldata outputNoteData1,
        bytes calldata outputNoteData2
    ) private {
        emit ShieldedPoolTransact(
            publicInputs.nullifier0,
            publicInputs.nullifier1,
            publicInputs.intentReplayId,
            finalCommitments[0],
            finalCommitments[1],
            finalCommitments[2],
            leafIndex0,
            currentNoteCommitmentRoot,
            outputNoteData0,
            outputNoteData1,
            outputNoteData2
        );
    }

    /// Contract-native deposit per EIP Section 5.3 / Section 5.4.2.
    function deposit(
        address token,
        uint256 amount,
        uint8 originMode,
        uint256 ownerCommitment,
        bytes calldata outputNoteData
    ) external payable nonReentrant {
        require(amount > 0 && amount <= MAX_AMOUNT_VALUE, InvalidDepositAmount());
        require(ownerCommitment != 0, InvalidOwnerCommitment());
        _ensureCanonicalField(ownerCommitment);
        require(
            originMode == ORIGIN_MODE_DEFAULT || originMode == ORIGIN_MODE_REQUIRE_TAGGED,
            InvalidOriginMode()
        );

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
        require(leafIndex <= MAX_NOTE_COMMITMENT_LEAF_INDEX, TreeFull());

        uint256 originTag = _computeDepositOriginTag(originMode, token, amount, leafIndex);
        uint256 finalNoteCommitment =
            _sealDepositNoteCommitment(ownerCommitment, amount, uint256(uint160(token)), originTag, leafIndex);

        _pushNoteCommitmentRoot(_currentNoteCommitmentRoot());
        _insertNoteCommitment(finalNoteCommitment);

        emit ShieldedPoolDeposit(
            msg.sender,
            finalNoteCommitment,
            leafIndex,
            amount,
            uint256(uint160(token)),
            originTag,
            currentNoteCommitmentRoot,
            outputNoteData
        );
    }

    function _sealDepositNoteCommitment(
        uint256 ownerCommitment,
        uint256 amount,
        uint256 tokenAsUint,
        uint256 originTag,
        uint256 leafIndex
    ) private pure returns (uint256) {
        uint256 body = PoseidonFieldLib.noteBodyCommitment(ownerCommitment, amount, tokenAsUint, originTag);
        uint256 finalCommitment = PoseidonFieldLib.noteCommitment(body, leafIndex);
        require(finalCommitment != 0, ZeroNoteCommitment());
        return finalCommitment;
    }

    function _computeDepositOriginTag(uint8 originMode, address token, uint256 amount, uint256 leafIndex)
        private
        view
        returns (uint256)
    {
        if (originMode == ORIGIN_MODE_DEFAULT) return 0;

        uint256 originTag = PoseidonFieldLib.depositOriginTag(
            block.chainid,
            uint256(uint160(msg.sender)),
            uint256(uint160(token)),
            amount,
            leafIndex
        );
        require(originTag != 0, InvalidOriginTag());
        return originTag;
    }

    function getCurrentRoots()
        external
        view
        returns (uint256 noteCommitmentRoot, uint256 registryRoot, uint256 authPolicyRegistryRoot)
    {
        noteCommitmentRoot = _currentNoteCommitmentRoot();
        registryRoot = _currentUserRegistryRoot();
        authPolicyRegistryRoot = _currentAuthPolicyRoot();
    }

    function getUserRegistryEntry(address user)
        external
        view
        returns (bool registered, uint256 ownerNullifierKeyHash, uint256 noteSecretSeedHash)
    {
        UserRegistryEntry storage entry = userRegistryEntries[user];
        return (entry.registered, entry.ownerNullifierKeyHash, entry.noteSecretSeedHash);
    }

    function getAuthPolicy(address user, uint256 innerVkHash)
        external
        view
        returns (bool active, uint256 authDataCommitment, uint256 policyVersion)
    {
        _ensureCanonicalField(innerVkHash);

        AuthPolicyState storage policy = authPolicies[user][innerVkHash];
        return (policy.active, policy.authDataCommitment, policy.policyVersion);
    }

    function isNullifierSpent(uint256 nullifier) external view returns (bool) {
        return nullifierSpent[nullifier];
    }

    function isIntentReplayIdUsed(uint256 intentReplayId) external view returns (bool) {
        return intentReplayIdUsed[intentReplayId];
    }

    function registerUser(uint256 ownerNullifierKeyHash, uint256 noteSecretSeedHash) external {
        _registerUser(msg.sender, ownerNullifierKeyHash, noteSecretSeedHash);
    }

    function registerUser(uint256 ownerNullifierKeyHash, uint256 noteSecretSeedHash, uint32 schemeId, bytes calldata keyBytes)
        external
    {
        _registerUser(msg.sender, ownerNullifierKeyHash, noteSecretSeedHash);
        _setDeliveryKey(msg.sender, schemeId, keyBytes);
    }

    function rotateNoteSecretSeed(uint256 newNoteSecretSeedHash) external {
        _ensureCanonicalField(newNoteSecretSeedHash);

        UserRegistryEntry storage entry = userRegistryEntries[msg.sender];
        require(entry.registered, UserNotRegistered());

        uint256 leaf = PoseidonFieldLib.userRegistryLeaf(msg.sender, entry.ownerNullifierKeyHash, newNoteSecretSeedHash);
        require(leaf != 0, ZeroLeaf());

        _snapshotUserRegistryRoot();
        _writeUserTreeLeaf(uint256(uint160(msg.sender)), leaf);

        entry.noteSecretSeedHash = newNoteSecretSeedHash;

        emit NoteSecretSeedRotated(msg.sender, newNoteSecretSeedHash);
    }

    function setDeliveryKey(uint32 schemeId, bytes calldata keyBytes) external {
        UserRegistryEntry storage entry = userRegistryEntries[msg.sender];
        require(entry.registered, UserNotRegistered());
        _setDeliveryKey(msg.sender, schemeId, keyBytes);
    }

    function removeDeliveryKey() external {
        UserRegistryEntry storage entry = userRegistryEntries[msg.sender];
        require(entry.registered, UserNotRegistered());

        DeliveryEndpoint storage endpoint = deliveryEndpoints[msg.sender];
        require(endpoint.schemeId != 0, DeliveryKeyNotSet());

        uint32 oldSchemeId = endpoint.schemeId;
        delete deliveryEndpoints[msg.sender];

        emit DeliveryKeyRemoved(msg.sender, oldSchemeId);
    }

    function getDeliveryKey(address user) external view returns (uint32 schemeId, bytes memory keyBytes) {
        DeliveryEndpoint storage endpoint = deliveryEndpoints[user];
        return (endpoint.schemeId, endpoint.keyBytes);
    }

    function registerAuthPolicy(uint256 innerVkHash, uint256 authDataCommitment) external {
        _ensureCanonicalField(innerVkHash);
        _ensureCanonicalField(authDataCommitment);

        UserRegistryEntry storage entry = userRegistryEntries[msg.sender];
        require(entry.registered, UserNotRegistered());

        bytes32 versionKey = keccak256(abi.encodePacked(msg.sender, innerVkHash));
        uint256 nextPolicyVersion = policyVersions[versionKey] + 1;
        _ensureCanonicalField(nextPolicyVersion);
        uint256 leaf = PoseidonFieldLib.authPolicyLeaf(authDataCommitment, nextPolicyVersion);
        require(leaf != 0, ZeroLeaf());

        _snapshotAuthPolicyRoot();
        _writeAuthTreeLeaf(PoseidonFieldLib.authPolicyTreeKey(msg.sender, innerVkHash), leaf);

        policyVersions[versionKey] = nextPolicyVersion;
        authPolicies[msg.sender][innerVkHash] =
            AuthPolicyState({active: true, authDataCommitment: authDataCommitment, policyVersion: nextPolicyVersion});

        emit AuthPolicyRegistered(msg.sender, innerVkHash, authDataCommitment, nextPolicyVersion);
    }

    function deregisterAuthPolicy(uint256 innerVkHash) external {
        _ensureCanonicalField(innerVkHash);

        AuthPolicyState storage policy = authPolicies[msg.sender][innerVkHash];
        require(policy.active, AuthPolicyAlreadyInactive());

        _snapshotAuthPolicyRoot();
        _writeAuthTreeLeaf(PoseidonFieldLib.authPolicyTreeKey(msg.sender, innerVkHash), 0);

        policy.active = false;

        emit AuthPolicyDeregistered(msg.sender, innerVkHash);
    }

    function _registerUser(address user, uint256 ownerNullifierKeyHash, uint256 noteSecretSeedHash) private {
        _ensureCanonicalField(ownerNullifierKeyHash);
        _ensureCanonicalField(noteSecretSeedHash);

        require(ownerNullifierKeyHash != 0, ReservedOwnerNullifierKeyHash());
        require(
            ownerNullifierKeyHash != PoseidonFieldLib.dummyOwnerNullifierKeyHash(),
            ReservedOwnerNullifierKeyHash()
        );
        require(ownerNullifierKeyHashIndex[ownerNullifierKeyHash] == address(0), OwnerNullifierKeyHashAlreadyUsed());

        UserRegistryEntry storage entry = userRegistryEntries[user];
        require(!entry.registered, UserAlreadyRegistered());

        uint256 leaf = PoseidonFieldLib.userRegistryLeaf(user, ownerNullifierKeyHash, noteSecretSeedHash);
        require(leaf != 0, ZeroLeaf());

        _snapshotUserRegistryRoot();
        _writeUserTreeLeaf(uint256(uint160(user)), leaf);

        userRegistryEntries[user] = UserRegistryEntry({
            registered: true, ownerNullifierKeyHash: ownerNullifierKeyHash, noteSecretSeedHash: noteSecretSeedHash
        });
        ownerNullifierKeyHashIndex[ownerNullifierKeyHash] = user;

        emit UserRegistered(user, ownerNullifierKeyHash, noteSecretSeedHash);
    }

    function _setDeliveryKey(address user, uint32 schemeId, bytes calldata keyBytes) private {
        require(schemeId != 0 && keyBytes.length != 0, InvalidDeliveryKey());

        deliveryEndpoints[user] = DeliveryEndpoint({schemeId: schemeId, keyBytes: keyBytes});
        emit DeliveryKeySet(user, schemeId, keyBytes);
    }

    function _executeWithdrawal(address publicRecipient, address publicToken, uint256 publicAmountOut) private {
        if (publicToken == address(0)) {
            (bool success,) = publicRecipient.call{value: publicAmountOut}("");
            require(success, EthTransferFailed());
        } else {
            ERC20AssetLib.safeTransfer(publicToken, publicRecipient, publicAmountOut);
        }
    }

    function _executePublicAction(PreparedPublicAction memory action) private {
        if (action.kind == PublicAction.Withdrawal) {
            _executeWithdrawal(action.recipient, action.token, action.amountOut);
        }
    }

    function _preparePublicAction(PublicInputs calldata publicInputs)
        private
        pure
        returns (PreparedPublicAction memory action)
    {
        require(publicInputs.publicAmountOut <= MAX_AMOUNT_VALUE, AmountOutOfRange());
        require(publicInputs.publicRecipientAddress <= MAX_ADDRESS_VALUE, AddressOutOfRange());
        require(publicInputs.publicTokenAddress <= MAX_ADDRESS_VALUE, AddressOutOfRange());

        if (publicInputs.publicAmountOut != 0) {
            action.kind = PublicAction.Withdrawal;
        } else {
            action.kind = PublicAction.Transfer;
        }

        action.recipient = address(uint160(publicInputs.publicRecipientAddress));
        action.token = address(uint160(publicInputs.publicTokenAddress));
        action.amountOut = publicInputs.publicAmountOut;

        if (action.kind == PublicAction.Withdrawal) {
            _validateWithdrawalAction(action);
        } else {
            _validateTransferAction(action);
        }
    }

    function _validateWithdrawalAction(PreparedPublicAction memory action) private pure {
        require(
            action.amountOut != 0 && action.recipient != address(0),
            InvalidPublicActionConfiguration()
        );
    }

    function _validateTransferAction(PreparedPublicAction memory action) private pure {
        require(
            action.amountOut == 0 && action.recipient == address(0) && action.token == address(0),
            InvalidPublicActionConfiguration()
        );
    }

    function _verifyProof(bytes calldata proof, PublicInputs calldata publicInputs) private view {
        (bool success, bytes memory returnData) =
            PROOF_VERIFY_PRECOMPILE_ADDRESS.staticcall(abi.encode(proof, publicInputs));

        require(success && returnData.length == 32 && abi.decode(returnData, (uint256)) == 1, InvalidProof());
    }

    function _assertOutputNoteHash(bytes calldata outputNoteData, uint256 expectedHash, uint8 slot) private pure {
        uint256 actualHash = uint256(keccak256(outputNoteData)) % PoseidonFieldLib.FIELD_MODULUS;
        require(actualHash == expectedHash, InvalidOutputNoteDataHash(slot));
    }

    function _ensureCanonicalProofFields(PublicInputs calldata publicInputs) private pure {
        _ensureCanonicalField(publicInputs.noteCommitmentRoot);
        _ensureCanonicalField(publicInputs.nullifier0);
        _ensureCanonicalField(publicInputs.nullifier1);
        _ensureCanonicalField(publicInputs.noteBodyCommitment0);
        _ensureCanonicalField(publicInputs.noteBodyCommitment1);
        _ensureCanonicalField(publicInputs.noteBodyCommitment2);
        _ensureCanonicalField(publicInputs.intentReplayId);
        _ensureCanonicalField(publicInputs.registryRoot);
        _ensureCanonicalField(publicInputs.authPolicyRegistryRoot);
        _ensureCanonicalField(publicInputs.outputNoteDataHash0);
        _ensureCanonicalField(publicInputs.outputNoteDataHash1);
        _ensureCanonicalField(publicInputs.outputNoteDataHash2);
    }

    function _ensureCanonicalField(uint256 value) private pure {
        require(value < PoseidonFieldLib.FIELD_MODULUS, FieldElementNotCanonical());
    }

    function _currentNoteCommitmentRoot() private view returns (uint256) {
        return currentNoteCommitmentRoot;
    }

    function _currentUserRegistryRoot() private view returns (uint256) {
        return currentUserRegistryRoot;
    }

    function _currentAuthPolicyRoot() private view returns (uint256) {
        return currentAuthPolicyRoot;
    }

    function isAcceptedNoteCommitmentRoot(uint256 root) public view returns (bool) {
        if (root == _currentNoteCommitmentRoot()) return true;

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
        if (root == _currentUserRegistryRoot()) return true;

        for (uint256 slot; slot <= USER_REGISTRY_ROOT_HISTORY_BLOCKS; ++slot) {
            if (
                userRegistryRootHistory[slot] == root
                    && block.number - userRegistryRootBlock[slot] <= USER_REGISTRY_ROOT_HISTORY_BLOCKS
            ) {
                return true;
            }
        }

        return false;
    }

    function isAcceptedAuthPolicyRoot(uint256 root) public view returns (bool) {
        if (root == 0) return false;
        if (root == _currentAuthPolicyRoot()) return true;

        for (uint256 slot; slot <= AUTH_POLICY_ROOT_HISTORY_BLOCKS; ++slot) {
            if (
                authPolicyRootHistory[slot] == root
                    && block.number - authPolicyRootBlock[slot] <= AUTH_POLICY_ROOT_HISTORY_BLOCKS
            ) {
                return true;
            }
        }

        return false;
    }

    function _pushNoteCommitmentRoot(uint256 root) private {
        noteCommitmentRootHistory[noteCommitmentRootHistoryCount % NOTE_COMMITMENT_ROOT_HISTORY_SIZE] = root;
        unchecked {
            ++noteCommitmentRootHistoryCount;
        }
    }

    function _snapshotUserRegistryRoot() private {
        if (userRegistryLastSnapshotBlock == block.number) return;

        uint256 slot = block.number % (USER_REGISTRY_ROOT_HISTORY_BLOCKS + 1);
        userRegistryRootHistory[slot] = _currentUserRegistryRoot();
        userRegistryRootBlock[slot] = block.number;
        userRegistryLastSnapshotBlock = block.number;
    }

    function _snapshotAuthPolicyRoot() private {
        if (authPolicyLastSnapshotBlock == block.number) return;

        uint256 slot = block.number % (AUTH_POLICY_ROOT_HISTORY_BLOCKS + 1);
        authPolicyRootHistory[slot] = _currentAuthPolicyRoot();
        authPolicyRootBlock[slot] = block.number;
        authPolicyLastSnapshotBlock = block.number;
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

    function _writeUserTreeLeaf(uint256 key, uint256 leaf) private {
        uint256 index = key;
        uint256 currentHash = leaf;

        userTreeNodes[0][index] = leaf;

        for (uint256 level; level < REGISTRY_TREE_DEPTH; ++level) {
            uint256 siblingIndex = index ^ 1;
            uint256 sibling = userTreeNodes[level][siblingIndex];
            if (sibling == 0) sibling = sparseEmptyHashes[level];

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

    function _writeAuthTreeLeaf(uint256 key, uint256 leaf) private {
        uint256 index = key;
        uint256 currentHash = leaf;

        authTreeNodes[0][index] = leaf;

        for (uint256 level; level < REGISTRY_TREE_DEPTH; ++level) {
            uint256 siblingIndex = index ^ 1;
            uint256 sibling = authTreeNodes[level][siblingIndex];
            if (sibling == 0) sibling = sparseEmptyHashes[level];

            if ((index & 1) == 0) {
                currentHash = PoseidonFieldLib.merkleHash(currentHash, sibling);
            } else {
                currentHash = PoseidonFieldLib.merkleHash(sibling, currentHash);
            }

            index >>= 1;
            authTreeNodes[level + 1][index] = currentHash;
        }

        currentAuthPolicyRoot = currentHash;
    }
}
