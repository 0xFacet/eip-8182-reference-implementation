// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {PoseidonFieldLib} from "contracts/src/libraries/PoseidonFieldLib.sol";

/// @notice Demo recipient discovery for Sepolia UX. Not part of EIP-8182.
contract RecipientRegistry {
    uint256 internal constant ML_KEM_768_PUBLIC_KEY_BYTES = 1184;

    struct Recipient {
        uint256 ownerNullifierKeyHash;
        bytes mlKem768PublicKey;
        bytes32 x25519PublicKey;
        uint32 metadataVersion;
    }

    error DuplicateOwnerNullifierKeyHash();
    error FieldElementNotCanonical();
    error InvalidMlKemPublicKey();
    error InvalidX25519PublicKey();
    error OwnerNullifierKeyHashImmutable();
    error RecipientNotRegistered();
    error ReservedOwnerNullifierKeyHash();

    event RecipientPublished(
        address indexed recipient,
        uint256 indexed ownerNullifierKeyHash,
        bytes mlKem768PublicKey,
        bytes32 x25519PublicKey,
        uint32 metadataVersion
    );
    event RecipientCleared(address indexed recipient, uint256 indexed ownerNullifierKeyHash);

    mapping(address => Recipient) private recipients;
    mapping(uint256 => address) private ownerNullifierKeyHashOwners;

    function publishRecipient(
        uint256 ownerNullifierKeyHash,
        bytes calldata mlKem768PublicKey,
        bytes32 x25519PublicKey,
        uint32 metadataVersion
    ) external {
        _validateOwnerNullifierKeyHash(ownerNullifierKeyHash);
        require(mlKem768PublicKey.length == ML_KEM_768_PUBLIC_KEY_BYTES, InvalidMlKemPublicKey());
        require(x25519PublicKey != bytes32(0), InvalidX25519PublicKey());

        Recipient storage recipient = recipients[msg.sender];
        uint256 previousHash = recipient.ownerNullifierKeyHash;
        if (previousHash == 0) {
            address existingOwner = ownerNullifierKeyHashOwners[ownerNullifierKeyHash];
            require(existingOwner == address(0), DuplicateOwnerNullifierKeyHash());
            ownerNullifierKeyHashOwners[ownerNullifierKeyHash] = msg.sender;
        } else {
            require(previousHash == ownerNullifierKeyHash, OwnerNullifierKeyHashImmutable());
        }

        recipient.ownerNullifierKeyHash = ownerNullifierKeyHash;
        recipient.mlKem768PublicKey = mlKem768PublicKey;
        recipient.x25519PublicKey = x25519PublicKey;
        recipient.metadataVersion = metadataVersion;

        emit RecipientPublished(
            msg.sender,
            ownerNullifierKeyHash,
            mlKem768PublicKey,
            x25519PublicKey,
            metadataVersion
        );
    }

    function clearRecipient() external {
        uint256 previousHash = recipients[msg.sender].ownerNullifierKeyHash;
        require(previousHash != 0, RecipientNotRegistered());

        delete recipients[msg.sender];
        delete ownerNullifierKeyHashOwners[previousHash];

        emit RecipientCleared(msg.sender, previousHash);
    }

    function getRecipient(address recipientAddress)
        external
        view
        returns (bool registered, Recipient memory recipient)
    {
        recipient = recipients[recipientAddress];
        registered = recipient.ownerNullifierKeyHash != 0;
    }

    function ownerOf(uint256 ownerNullifierKeyHash) external view returns (address) {
        return ownerNullifierKeyHashOwners[ownerNullifierKeyHash];
    }

    function _validateOwnerNullifierKeyHash(uint256 ownerNullifierKeyHash) private pure {
        require(ownerNullifierKeyHash < PoseidonFieldLib.FIELD_MODULUS, FieldElementNotCanonical());
        require(ownerNullifierKeyHash != 0, ReservedOwnerNullifierKeyHash());
        require(
            ownerNullifierKeyHash != PoseidonFieldLib.dummyOwnerNullifierKeyHash(),
            ReservedOwnerNullifierKeyHash()
        );
    }
}
