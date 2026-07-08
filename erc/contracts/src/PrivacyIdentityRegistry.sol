// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IPrivacyIdentityRegistry} from "./interfaces/IPrivacyIdentityRegistry.sol";
import {PoseidonFieldLib} from "./libraries/PoseidonFieldLib.sol";
import {ErcConstants} from "./generated/ErcConstants.sol";

/// @notice Canonical privacy identity registry (spec section 6): the chain
///         singleton binding an Ethereum address to validity-critical identity
///         material (identity plane) and ML-KEM-768 receive-key material
///         (delivery plane). Deployed once per chain via the deterministic
///         CREATE2 factory; no admin, no upgrade path, no constructor args.
///
///         Identity plane: depth-32 sparse Merkle tree of identity leaves,
///         block-based root history with window IDENTITY_ROOT_HISTORY_BLOCKS,
///         global ownerNullifierKeyHash uniqueness, immutable onk per address.
///         The identity root is part of every conforming pool's validity
///         relation on this chain.
///
///         Receive plane: latest ML-KEM-768 public key + metadataVersion per
///         address. Never part of the identity leaf or root (spec section 6).
contract PrivacyIdentityRegistry is IPrivacyIdentityRegistry {
    uint256 internal constant IDENTITY_TREE_DEPTH = 32;
    uint256 internal constant ROOT_HISTORY_BLOCKS = 64; // IDENTITY_ROOT_HISTORY_BLOCKS
    uint256 internal constant MAX_LEAF_POSITION = type(uint32).max;
    uint256 internal constant ML_KEM_768_PUBLIC_KEY_LENGTH = 1184;

    error FieldElementNotCanonical();
    error ReservedOwnerNullifierKeyHash();
    error ZeroNoteSecretSeedHash();
    error OwnerNullifierKeyHashAlreadyUsed();
    error OwnerNullifierKeyHashImmutable();
    error TreeFull();
    error ZeroLeaf();
    error InvalidMlKemPublicKeyLength();

    // Identity plane
    uint256 internal nextLeafPosition = 1; // slot 0 is the unassigned sentinel
    uint256 internal currentIdentityRoot;
    // Sentinel that cannot equal any real block number, so the first mutation
    // in any block (including block 0) always snapshots its start-of-block root.
    uint256 internal lastSnapshotBlock = type(uint256).max;
    // treeNodes[level][index]; level 0 = leaves keyed by leafPosition (LSB-first path)
    mapping(uint256 => mapping(uint256 => uint256)) private treeNodes;
    // ring buffer of W+1 = 65 (root, blockNumber) pairs at slot N mod 65
    mapping(uint256 => uint256) internal rootHistory;
    mapping(uint256 => uint256) internal rootBlock;
    mapping(address => IdentityEntry) private identityEntries;
    mapping(uint256 => address) private ownerNullifierKeyHashIndex;
    uint256[IDENTITY_TREE_DEPTH] internal sparseEmptyHashes;

    // Receive plane
    mapping(address => ReceiveEntry) private receiveEntries;
    mapping(address => bool) private receiveRegisteredFlag;

    constructor() {
        // EMPTY[0] = 0; EMPTY[h+1] = poseidon(EMPTY[h], EMPTY[h]) (spec section 15.4).
        uint256 empty = 0;
        for (uint256 level; level < IDENTITY_TREE_DEPTH; ++level) {
            sparseEmptyHashes[level] = empty;
            empty = PoseidonFieldLib.merkleHash(empty, empty);
        }
        currentIdentityRoot = empty; // EMPTY[32]
    }

    // -------------------------------- Identity plane --------------------------------

    /// @inheritdoc IPrivacyIdentityRegistry
    function setIdentity(
        uint256 ownerNullifierKeyHash,
        uint256 noteSecretSeedHash,
        uint256 policySetCommitment
    ) external returns (uint32 leafPosition) {
        return _setIdentity(ownerNullifierKeyHash, noteSecretSeedHash, policySetCommitment);
    }

    /// @inheritdoc IPrivacyIdentityRegistry
    function setReceiveProfile(
        bytes calldata mlKem768PublicKey,
        uint32 metadataVersion
    ) external {
        _setReceiveProfile(mlKem768PublicKey, metadataVersion);
    }

    /// @inheritdoc IPrivacyIdentityRegistry
    function setFullProfile(
        uint256 ownerNullifierKeyHash,
        uint256 noteSecretSeedHash,
        uint256 policySetCommitment,
        bytes calldata mlKem768PublicKey,
        uint32 metadataVersion
    ) external returns (uint32 leafPosition) {
        leafPosition = _setIdentity(ownerNullifierKeyHash, noteSecretSeedHash, policySetCommitment);
        _setReceiveProfile(mlKem768PublicKey, metadataVersion);
    }

    /// @inheritdoc IPrivacyIdentityRegistry
    function clearReceiveProfile(uint32 metadataVersion) external {
        delete receiveEntries[msg.sender];
        receiveRegisteredFlag[msg.sender] = false;
        emit ReceiveProfileCleared(msg.sender, metadataVersion);
    }

    function _setIdentity(
        uint256 ownerNullifierKeyHash,
        uint256 noteSecretSeedHash,
        uint256 policySetCommitment
    ) internal returns (uint32 leafPosition) {
        require(ownerNullifierKeyHash < PoseidonFieldLib.FIELD_MODULUS, FieldElementNotCanonical());
        require(noteSecretSeedHash < PoseidonFieldLib.FIELD_MODULUS, FieldElementNotCanonical());
        require(policySetCommitment < PoseidonFieldLib.FIELD_MODULUS, FieldElementNotCanonical());
        require(ownerNullifierKeyHash != 0, ReservedOwnerNullifierKeyHash());
        require(
            ownerNullifierKeyHash != ErcConstants.DUMMY_OWNER_NULLIFIER_KEY_HASH,
            ReservedOwnerNullifierKeyHash()
        );
        require(noteSecretSeedHash != 0, ZeroNoteSecretSeedHash());

        IdentityEntry storage entry = identityEntries[msg.sender];
        if (entry.leafPosition == 0) {
            // First registration from this address.
            require(
                ownerNullifierKeyHashIndex[ownerNullifierKeyHash] == address(0),
                OwnerNullifierKeyHashAlreadyUsed()
            );
            uint256 newPosition = nextLeafPosition;
            require(newPosition <= MAX_LEAF_POSITION, TreeFull());
            unchecked {
                nextLeafPosition = newPosition + 1;
            }
            entry.leafPosition = uint32(newPosition);
            entry.ownerNullifierKeyHash = ownerNullifierKeyHash;
            ownerNullifierKeyHashIndex[ownerNullifierKeyHash] = msg.sender;
            leafPosition = uint32(newPosition);
        } else {
            require(
                entry.ownerNullifierKeyHash == ownerNullifierKeyHash,
                OwnerNullifierKeyHashImmutable()
            );
            leafPosition = entry.leafPosition;
        }
        entry.noteSecretSeedHash = noteSecretSeedHash;
        entry.policySetCommitment = policySetCommitment;

        uint256 leafValue = PoseidonFieldLib.identityLeaf(
            msg.sender,
            ownerNullifierKeyHash,
            noteSecretSeedHash,
            policySetCommitment
        );
        require(leafValue != 0, ZeroLeaf());

        _snapshotIdentityRoot();
        _writeIdentityTreeLeaf(leafPosition, leafValue);

        emit IdentitySet(
            msg.sender,
            ownerNullifierKeyHash,
            noteSecretSeedHash,
            policySetCommitment,
            leafPosition,
            leafValue,
            currentIdentityRoot
        );
    }

    function _setReceiveProfile(bytes calldata mlKem768PublicKey, uint32 metadataVersion) internal {
        require(mlKem768PublicKey.length == ML_KEM_768_PUBLIC_KEY_LENGTH, InvalidMlKemPublicKeyLength());
        ReceiveEntry storage entry = receiveEntries[msg.sender];
        entry.mlKem768PublicKey = mlKem768PublicKey;
        entry.metadataVersion = metadataVersion;
        receiveRegisteredFlag[msg.sender] = true;
        emit ReceiveProfileSet(msg.sender, mlKem768PublicKey, metadataVersion);
    }

    /// @dev spec section 6: on the FIRST identity mutation in block N, snapshot
    ///      the root accepted at the start of block N at slot N mod (W+1).
    ///      Later same-block mutations do not create additional entries.
    function _snapshotIdentityRoot() private {
        if (lastSnapshotBlock == block.number) return;
        uint256 slot = block.number % (ROOT_HISTORY_BLOCKS + 1);
        rootHistory[slot] = currentIdentityRoot;
        rootBlock[slot] = block.number;
        lastSnapshotBlock = block.number;
    }

    function _writeIdentityTreeLeaf(uint256 key, uint256 leaf) private {
        // depth-32 sparse Merkle, LSB-first key on leafPosition (spec section 15.4).
        uint256 index = key;
        uint256 currentHash = leaf;
        treeNodes[0][index] = leaf;
        for (uint256 level; level < IDENTITY_TREE_DEPTH; ++level) {
            uint256 siblingIndex = index ^ 1;
            uint256 sibling = treeNodes[level][siblingIndex];
            if (sibling == 0) sibling = sparseEmptyHashes[level];
            if ((index & 1) == 0) {
                currentHash = PoseidonFieldLib.merkleHash(currentHash, sibling);
            } else {
                currentHash = PoseidonFieldLib.merkleHash(sibling, currentHash);
            }
            index >>= 1;
            treeNodes[level + 1][index] = currentHash;
        }
        currentIdentityRoot = currentHash;
    }

    // -------------------------------- Views --------------------------------

    /// @inheritdoc IPrivacyIdentityRegistry
    function getIdentityEntry(address user)
        external
        view
        returns (bool registered, IdentityEntry memory entry)
    {
        entry = identityEntries[user];
        registered = entry.leafPosition != 0;
    }

    /// @inheritdoc IPrivacyIdentityRegistry
    function getReceiveEntry(address user)
        external
        view
        returns (bool registered, ReceiveEntry memory entry)
    {
        entry = receiveEntries[user];
        registered = receiveRegisteredFlag[user];
    }

    /// @inheritdoc IPrivacyIdentityRegistry
    function getPrivacyProfile(address user)
        external
        view
        returns (
            bool identityRegistered,
            IdentityEntry memory identity,
            bool receiveRegistered,
            ReceiveEntry memory receiveEntry
        )
    {
        identity = identityEntries[user];
        identityRegistered = identity.leafPosition != 0;
        receiveEntry = receiveEntries[user];
        receiveRegistered = receiveRegisteredFlag[user];
    }

    /// @inheritdoc IPrivacyIdentityRegistry
    function getCurrentIdentityRoot() external view returns (uint256) {
        return currentIdentityRoot;
    }

    /// @inheritdoc IPrivacyIdentityRegistry
    function isAcceptedIdentityRoot(uint256 root) external view returns (bool) {
        if (root == 0) return false;
        if (root == currentIdentityRoot) return true;
        for (uint256 slot; slot <= ROOT_HISTORY_BLOCKS; ++slot) {
            if (
                rootHistory[slot] == root
                    && block.number - rootBlock[slot] <= ROOT_HISTORY_BLOCKS
            ) return true;
        }
        return false;
    }

    /// @inheritdoc IPrivacyIdentityRegistry
    function ercXXXXPrivacyRegistryId() external pure returns (bytes32) {
        return ErcConstants.REGISTRY_ID;
    }

    /// @inheritdoc IPrivacyIdentityRegistry
    function outputNoteDataSuite() external pure returns (string memory) {
        return ErcConstants.OUTPUT_NOTE_DATA_SUITE;
    }
}
