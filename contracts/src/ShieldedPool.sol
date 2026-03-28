// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ERC20AssetLib} from "./libraries/ERC20AssetLib.sol";
import {PoseidonFieldLib} from "./libraries/PoseidonFieldLib.sol";

contract ShieldedPool {
    uint256 internal constant MAX_INTENT_LIFETIME = 86400;
    uint256 internal constant COMMITMENT_ROOT_HISTORY_SIZE = 500;
    uint256 internal constant USER_REGISTRY_ROOT_HISTORY_BLOCKS = 500;
    uint256 internal constant AUTH_POLICY_ROOT_HISTORY_BLOCKS = 64;
    uint256 internal constant COMMITMENT_TREE_DEPTH = 32;
    uint256 internal constant REGISTRY_TREE_DEPTH = 160;
    uint256 internal constant MAX_COMMITMENT_LEAF_INDEX = type(uint32).max;
    uint256 internal constant MAX_ADDRESS_VALUE = type(uint160).max;
    uint256 internal constant MAX_AMOUNT_VALUE = type(uint248).max;
    uint256 internal constant MAX_VALID_UNTIL_SECONDS = type(uint32).max;

    address internal constant PROOF_VERIFY_PRECOMPILE_ADDRESS = 0x0000000000000000000000000000000000000030;

    struct PublicInputs {
        uint256 merkleRoot;
        uint256 nullifier0;
        uint256 nullifier1;
        uint256 commitment0;
        uint256 commitment1;
        uint256 commitment2;
        uint256 publicAmountIn;
        uint256 publicAmountOut;
        uint256 publicRecipientAddress;
        uint256 publicTokenAddress;
        uint256 depositorAddress;
        uint256 intentNullifier;
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
        uint256 nullifierKeyHash;
        uint256 outputSecretHash;
    }

    struct AuthPolicyState {
        bool active;
        uint256 authDataCommitment;
        uint256 policyVersion;
    }

    enum PublicAction {
        Transfer,
        Deposit,
        Withdrawal
    }

    struct PreparedPublicAction {
        PublicAction kind;
        address depositor;
        address recipient;
        address token;
        uint256 amountIn;
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
    error FieldElementNotCanonical();
    error IntentExpired();
    error IntentLifetimeTooLong();
    error IntentNullifierAlreadyUsed();
    error InvalidOutputNoteDataHash(uint8 slot);
    error InvalidPublicActionConfiguration();
    error InvalidProof();
    error NullifierAlreadySpent();
    error ReentrantCall();
    error TreeFull();
    error UnexpectedEth();
    error UnknownCommitmentRoot();
    error UnknownAuthPolicyRoot();
    error UnknownUserRegistryRoot();
    error UserAlreadyRegistered();
    error UserNotRegistered();
    error WrongChainId();
    error WrongDepositor();
    error ZeroCommitment();
    error ZeroLeaf();

    event ShieldedPoolTransact(
        uint256 indexed nullifier0,
        uint256 indexed nullifier1,
        uint256 indexed intentNullifier,
        uint256 commitment0,
        uint256 commitment1,
        uint256 commitment2,
        uint256 leafIndex0,
        uint256 postInsertionRoot,
        bytes outputNoteData0,
        bytes outputNoteData1,
        bytes outputNoteData2
    );

    event UserRegistered(address indexed user, uint256 nullifierKeyHash, uint256 outputSecretHash);

    event OutputSecretRotated(address indexed user, uint256 outputSecretHash);

    event AuthPolicyRegistered(
        address indexed user, uint256 innerVkHash, uint256 authDataCommitment, uint256 policyVersion
    );

    event AuthPolicyDeregistered(address indexed user, uint256 innerVkHash);

    event DeliveryKeySet(address indexed user, uint32 indexed schemeId, bytes keyBytes);

    event DeliveryKeyRemoved(address indexed user, uint32 indexed schemeId);

    uint256 internal nextLeafIndex;
    uint256 internal currentCommitmentRoot;
    uint256 internal commitmentRootHistoryCount;
    mapping(uint256 => uint256) private filledSubtrees;
    mapping(uint256 => uint256) internal commitmentRootHistory;

    uint256 internal currentUserRegistryRoot;
    uint256 internal userRegistryLastSnapshotBlock;
    mapping(uint256 => mapping(uint256 => uint256)) private userTreeNodes;
    mapping(uint256 => uint256) internal userRegistryRootHistory;
    mapping(uint256 => uint256) internal userRegistryRootBlock;
    mapping(address => UserRegistryEntry) private userRegistryEntries;
    mapping(address => DeliveryEndpoint) private deliveryEndpoints;

    uint256 internal currentAuthPolicyRoot;
    uint256 internal authPolicyLastSnapshotBlock;
    mapping(uint256 => mapping(uint256 => uint256)) private authTreeNodes;
    mapping(uint256 => uint256) internal authPolicyRootHistory;
    mapping(uint256 => uint256) internal authPolicyRootBlock;
    mapping(address => mapping(uint256 => AuthPolicyState)) private authPolicies;
    mapping(bytes32 => uint256) private policyVersions;

    mapping(uint256 => bool) private nullifierSpent;
    mapping(uint256 => bool) private intentNullifierUsed;
    uint256[COMMITMENT_TREE_DEPTH] internal commitmentEmptyHashes;
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
    ) external payable nonReentrant {
        _verifyProof(proof, publicInputs);
        _ensureCanonicalProofFields(publicInputs);

        require(publicInputs.executionChainId == block.chainid, WrongChainId());
        require(publicInputs.validUntilSeconds != 0, IntentExpired());
        require(publicInputs.validUntilSeconds <= MAX_VALID_UNTIL_SECONDS, IntentExpired());
        require(block.timestamp <= publicInputs.validUntilSeconds, IntentExpired());
        require(publicInputs.validUntilSeconds <= block.timestamp + MAX_INTENT_LIFETIME, IntentLifetimeTooLong());

        require(isAcceptedCommitmentRoot(publicInputs.merkleRoot), UnknownCommitmentRoot());
        require(isAcceptedUserRegistryRoot(publicInputs.registryRoot), UnknownUserRegistryRoot());
        require(isAcceptedAuthPolicyRoot(publicInputs.authPolicyRegistryRoot), UnknownAuthPolicyRoot());

        PreparedPublicAction memory action = _preparePublicAction(publicInputs);

        require(publicInputs.nullifier0 != publicInputs.nullifier1, DuplicateNullifier());
        require(!nullifierSpent[publicInputs.nullifier0], NullifierAlreadySpent());
        require(!nullifierSpent[publicInputs.nullifier1], NullifierAlreadySpent());
        nullifierSpent[publicInputs.nullifier0] = true;
        nullifierSpent[publicInputs.nullifier1] = true;

        require(!intentNullifierUsed[publicInputs.intentNullifier], IntentNullifierAlreadyUsed());
        intentNullifierUsed[publicInputs.intentNullifier] = true;

        require(
            publicInputs.commitment0 != 0 && publicInputs.commitment1 != 0 && publicInputs.commitment2 != 0,
            ZeroCommitment()
        );

        uint256 leafIndex0 = nextLeafIndex;
        require(leafIndex0 + 2 <= MAX_COMMITMENT_LEAF_INDEX, TreeFull());

        uint256 preInsertionRoot = _currentCommitmentRoot();
        _pushCommitmentRoot(preInsertionRoot);

        _insertCommitment(publicInputs.commitment0);
        _insertCommitment(publicInputs.commitment1);
        _insertCommitment(publicInputs.commitment2);

        _assertOutputNoteHash(outputNoteData0, publicInputs.outputNoteDataHash0, 0);
        _assertOutputNoteHash(outputNoteData1, publicInputs.outputNoteDataHash1, 1);
        _assertOutputNoteHash(outputNoteData2, publicInputs.outputNoteDataHash2, 2);

        _executePublicAction(action);

        _emitTransactEvent(publicInputs, leafIndex0, outputNoteData0, outputNoteData1, outputNoteData2);
    }

    function getCurrentRoots()
        external
        view
        returns (uint256 commitmentRoot, uint256 registryRoot, uint256 authPolicyRegistryRoot)
    {
        commitmentRoot = _currentCommitmentRoot();
        registryRoot = _currentUserRegistryRoot();
        authPolicyRegistryRoot = _currentAuthPolicyRoot();
    }

    function getUserRegistryEntry(address user)
        external
        view
        returns (bool registered, uint256 nullifierKeyHash, uint256 outputSecretHash)
    {
        UserRegistryEntry storage entry = userRegistryEntries[user];
        return (entry.registered, entry.nullifierKeyHash, entry.outputSecretHash);
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

    function isIntentNullifierUsed(uint256 intentNullifier) external view returns (bool) {
        return intentNullifierUsed[intentNullifier];
    }

    function registerUser(uint256 nullifierKeyHash, uint256 outputSecretHash) external {
        _registerUser(msg.sender, nullifierKeyHash, outputSecretHash);
    }

    function registerUser(uint256 nullifierKeyHash, uint256 outputSecretHash, uint32 schemeId, bytes calldata keyBytes)
        external
    {
        _registerUser(msg.sender, nullifierKeyHash, outputSecretHash);
        _setDeliveryKey(msg.sender, schemeId, keyBytes);
    }

    function rotateOutputSecret(uint256 newOutputSecretHash) external {
        _ensureCanonicalField(newOutputSecretHash);

        UserRegistryEntry storage entry = userRegistryEntries[msg.sender];
        require(entry.registered, UserNotRegistered());

        uint256 leaf = PoseidonFieldLib.userRegistryLeaf(msg.sender, entry.nullifierKeyHash, newOutputSecretHash);
        require(leaf != 0, ZeroLeaf());

        _snapshotUserRegistryRoot();
        _writeUserTreeLeaf(uint256(uint160(msg.sender)), leaf);

        entry.outputSecretHash = newOutputSecretHash;

        emit OutputSecretRotated(msg.sender, newOutputSecretHash);
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

    function _registerUser(address user, uint256 nullifierKeyHash, uint256 outputSecretHash) private {
        _ensureCanonicalField(nullifierKeyHash);
        _ensureCanonicalField(outputSecretHash);

        UserRegistryEntry storage entry = userRegistryEntries[user];
        require(!entry.registered, UserAlreadyRegistered());

        uint256 leaf = PoseidonFieldLib.userRegistryLeaf(user, nullifierKeyHash, outputSecretHash);
        require(leaf != 0, ZeroLeaf());

        _snapshotUserRegistryRoot();
        _writeUserTreeLeaf(uint256(uint160(user)), leaf);

        userRegistryEntries[user] = UserRegistryEntry({
            registered: true, nullifierKeyHash: nullifierKeyHash, outputSecretHash: outputSecretHash
        });

        emit UserRegistered(user, nullifierKeyHash, outputSecretHash);
    }

    function _setDeliveryKey(address user, uint32 schemeId, bytes calldata keyBytes) private {
        require(schemeId != 0 && keyBytes.length != 0, InvalidDeliveryKey());

        deliveryEndpoints[user] = DeliveryEndpoint({schemeId: schemeId, keyBytes: keyBytes});
        emit DeliveryKeySet(user, schemeId, keyBytes);
    }

    function _executeDeposit(address publicToken, uint256 publicAmountIn) private {
        if (publicToken != address(0)) {
            ERC20AssetLib.pullExact(publicToken, msg.sender, address(this), publicAmountIn);
        }
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
        if (action.kind == PublicAction.Deposit) {
            _executeDeposit(action.token, action.amountIn);
        } else if (action.kind == PublicAction.Withdrawal) {
            _executeWithdrawal(action.recipient, action.token, action.amountOut);
        }
    }

    function _emitTransactEvent(
        PublicInputs calldata publicInputs,
        uint256 leafIndex0,
        bytes calldata outputNoteData0,
        bytes calldata outputNoteData1,
        bytes calldata outputNoteData2
    ) private {
        emit ShieldedPoolTransact(
            publicInputs.nullifier0,
            publicInputs.nullifier1,
            publicInputs.intentNullifier,
            publicInputs.commitment0,
            publicInputs.commitment1,
            publicInputs.commitment2,
            leafIndex0,
            currentCommitmentRoot,
            outputNoteData0,
            outputNoteData1,
            outputNoteData2
        );
    }

    function _preparePublicAction(PublicInputs calldata publicInputs)
        private
        view
        returns (PreparedPublicAction memory action)
    {
        require(publicInputs.publicAmountIn <= MAX_AMOUNT_VALUE, AmountOutOfRange());
        require(publicInputs.publicAmountOut <= MAX_AMOUNT_VALUE, AmountOutOfRange());
        require(publicInputs.publicRecipientAddress <= MAX_ADDRESS_VALUE, AddressOutOfRange());
        require(publicInputs.publicTokenAddress <= MAX_ADDRESS_VALUE, AddressOutOfRange());
        require(publicInputs.depositorAddress <= MAX_ADDRESS_VALUE, AddressOutOfRange());

        if (publicInputs.depositorAddress != 0) {
            action.kind = PublicAction.Deposit;
        } else if (publicInputs.publicAmountOut != 0) {
            action.kind = PublicAction.Withdrawal;
        } else {
            action.kind = PublicAction.Transfer;
        }

        action.depositor = address(uint160(publicInputs.depositorAddress));
        action.recipient = address(uint160(publicInputs.publicRecipientAddress));
        action.token = address(uint160(publicInputs.publicTokenAddress));
        action.amountIn = publicInputs.publicAmountIn;
        action.amountOut = publicInputs.publicAmountOut;

        if (action.kind == PublicAction.Deposit) {
            _validateDepositAction(action);
        } else if (action.kind == PublicAction.Withdrawal) {
            _validateWithdrawalAction(action);
        } else {
            _validateTransferAction(action);
        }
    }

    function _validateDepositAction(PreparedPublicAction memory action) private view {
        require(
            action.amountIn != 0 && action.amountOut == 0 && action.recipient == address(0),
            InvalidPublicActionConfiguration()
        );
        require(msg.sender == action.depositor, WrongDepositor());

        if (action.token == address(0)) {
            require(msg.value == action.amountIn, EthAmountMismatch());
        } else {
            require(msg.value == 0, UnexpectedEth());
        }
    }

    function _validateWithdrawalAction(PreparedPublicAction memory action) private view {
        require(
            action.amountIn == 0 && action.amountOut != 0 && action.recipient != address(0),
            InvalidPublicActionConfiguration()
        );
        require(msg.value == 0, UnexpectedEth());
    }

    function _validateTransferAction(PreparedPublicAction memory action) private view {
        require(
            action.depositor == address(0) && action.amountIn == 0 && action.amountOut == 0
                && action.recipient == address(0) && action.token == address(0),
            InvalidPublicActionConfiguration()
        );
        require(msg.value == 0, UnexpectedEth());
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
        _ensureCanonicalField(publicInputs.merkleRoot);
        _ensureCanonicalField(publicInputs.nullifier0);
        _ensureCanonicalField(publicInputs.nullifier1);
        _ensureCanonicalField(publicInputs.commitment0);
        _ensureCanonicalField(publicInputs.commitment1);
        _ensureCanonicalField(publicInputs.commitment2);
        _ensureCanonicalField(publicInputs.intentNullifier);
        _ensureCanonicalField(publicInputs.registryRoot);
        _ensureCanonicalField(publicInputs.authPolicyRegistryRoot);
        _ensureCanonicalField(publicInputs.outputNoteDataHash0);
        _ensureCanonicalField(publicInputs.outputNoteDataHash1);
        _ensureCanonicalField(publicInputs.outputNoteDataHash2);
    }

    function _ensureCanonicalField(uint256 value) private pure {
        require(value < PoseidonFieldLib.FIELD_MODULUS, FieldElementNotCanonical());
    }

    function _currentCommitmentRoot() private view returns (uint256) {
        return currentCommitmentRoot;
    }

    function _currentUserRegistryRoot() private view returns (uint256) {
        return currentUserRegistryRoot;
    }

    function _currentAuthPolicyRoot() private view returns (uint256) {
        return currentAuthPolicyRoot;
    }

    function isAcceptedCommitmentRoot(uint256 root) public view returns (bool) {
        if (root == _currentCommitmentRoot()) return true;

        uint256 historyLength = commitmentRootHistoryCount;
        if (historyLength > COMMITMENT_ROOT_HISTORY_SIZE) {
            historyLength = COMMITMENT_ROOT_HISTORY_SIZE;
        }

        for (uint256 slot; slot < historyLength; ++slot) {
            if (commitmentRootHistory[slot] == root) return true;
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

    function _pushCommitmentRoot(uint256 root) private {
        commitmentRootHistory[commitmentRootHistoryCount % COMMITMENT_ROOT_HISTORY_SIZE] = root;
        unchecked {
            ++commitmentRootHistoryCount;
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

    function _insertCommitment(uint256 commitment) private {
        uint256 index = nextLeafIndex;
        uint256 currentHash = commitment;

        for (uint256 level; level < COMMITMENT_TREE_DEPTH; ++level) {
            if (((index >> level) & 1) == 0) {
                filledSubtrees[level] = currentHash;
                currentHash = PoseidonFieldLib.hash2Raw(currentHash, commitmentEmptyHashes[level]);
            } else {
                currentHash = PoseidonFieldLib.hash2Raw(filledSubtrees[level], currentHash);
            }
        }

        currentCommitmentRoot = currentHash;
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
                currentHash = PoseidonFieldLib.hash2Raw(currentHash, sibling);
            } else {
                currentHash = PoseidonFieldLib.hash2Raw(sibling, currentHash);
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
                currentHash = PoseidonFieldLib.hash2Raw(currentHash, sibling);
            } else {
                currentHash = PoseidonFieldLib.hash2Raw(sibling, currentHash);
            }

            index >>= 1;
            authTreeNodes[level + 1][index] = currentHash;
        }

        currentAuthPolicyRoot = currentHash;
    }
}
