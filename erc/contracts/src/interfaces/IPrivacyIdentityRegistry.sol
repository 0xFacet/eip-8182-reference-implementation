// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Canonical privacy identity registry (spec section 6). One singleton
///         instance per chain at CANONICAL_PRIVACY_REGISTRY_ADDRESS.
interface IPrivacyIdentityRegistry {
    struct IdentityEntry {
        uint32 leafPosition;
        uint256 ownerNullifierKeyHash;
        uint256 noteSecretSeedHash;
        uint256 policySetCommitment;
    }

    struct ReceiveEntry {
        bytes mlKem768PublicKey;
        uint32 metadataVersion;
    }

    event IdentitySet(
        address indexed user,
        uint256 ownerNullifierKeyHash,
        uint256 noteSecretSeedHash,
        uint256 policySetCommitment,
        uint32 leafPosition,
        uint256 leafValue,
        uint256 postUpdateIdentityRoot
    );

    event ReceiveProfileSet(
        address indexed user,
        bytes mlKem768PublicKey,
        uint32 metadataVersion
    );

    event ReceiveProfileCleared(
        address indexed user,
        uint32 metadataVersion
    );

    function setIdentity(
        uint256 ownerNullifierKeyHash,
        uint256 noteSecretSeedHash,
        uint256 policySetCommitment
    ) external returns (uint32 leafPosition);

    function setReceiveProfile(
        bytes calldata mlKem768PublicKey,
        uint32 metadataVersion
    ) external;

    function setFullProfile(
        uint256 ownerNullifierKeyHash,
        uint256 noteSecretSeedHash,
        uint256 policySetCommitment,
        bytes calldata mlKem768PublicKey,
        uint32 metadataVersion
    ) external returns (uint32 leafPosition);

    function clearReceiveProfile(uint32 metadataVersion) external;

    function getIdentityEntry(address user)
        external
        view
        returns (bool registered, IdentityEntry memory entry);

    function getReceiveEntry(address user)
        external
        view
        returns (bool registered, ReceiveEntry memory entry);

    function getPrivacyProfile(address user)
        external
        view
        returns (
            bool identityRegistered,
            IdentityEntry memory identity,
            bool receiveRegistered,
            ReceiveEntry memory receiveEntry
        );

    function getCurrentIdentityRoot() external view returns (uint256);
    function isAcceptedIdentityRoot(uint256 root) external view returns (bool);
    function ercXXXXPrivacyRegistryId() external pure returns (bytes32);
    function outputNoteDataSuite() external pure returns (string memory);
}
