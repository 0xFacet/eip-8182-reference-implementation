// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Poseidon2Sponge} from "./Poseidon2Sponge.sol";

/// @notice Convenience wrappers around the EIP-8182 Section 11 hash contexts.
///         Domain tags are derived as `keccak256("eip-8182.<context>") mod p_bn254`
///         and MUST match circuits/common/domain_tags.circom.
library PoseidonFieldLib {
    uint256 internal constant FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    uint256 internal constant OWNER_NULLIFIER_KEY_HASH_DOMAIN =
        uint256(keccak256("eip-8182.owner_nullifier_key_hash")) % FIELD_MODULUS;
    uint256 internal constant OWNER_COMMITMENT_DOMAIN =
        uint256(keccak256("eip-8182.owner_commitment")) % FIELD_MODULUS;
    uint256 internal constant NOTE_BODY_COMMITMENT_DOMAIN =
        uint256(keccak256("eip-8182.note_body_commitment")) % FIELD_MODULUS;
    uint256 internal constant NOTE_COMMITMENT_DOMAIN =
        uint256(keccak256("eip-8182.note_commitment")) % FIELD_MODULUS;
    uint256 internal constant NULLIFIER_DOMAIN =
        uint256(keccak256("eip-8182.nullifier")) % FIELD_MODULUS;
    uint256 internal constant NOTE_SECRET_SEED_DOMAIN =
        uint256(keccak256("eip-8182.note_secret_seed")) % FIELD_MODULUS;
    uint256 internal constant AUTH_POLICY_DOMAIN =
        uint256(keccak256("eip-8182.auth_policy")) % FIELD_MODULUS;
    uint256 internal constant USER_REGISTRY_LEAF_DOMAIN =
        uint256(keccak256("eip-8182.user_registry_leaf")) % FIELD_MODULUS;
    uint256 internal constant HISTORICAL_NOTE_ROOT_LEAF_DOMAIN =
        uint256(keccak256("eip-8182.historical_note_root_leaf")) % FIELD_MODULUS;

    function merkleHash(uint256 left, uint256 right) internal pure returns (uint256) {
        return Poseidon2Sponge.hashPair(left, right);
    }

    function noteBodyCommitment(
        uint256 ownerCommitmentValue,
        uint256 amount,
        uint256 tokenAddress
    ) internal pure returns (uint256) {
        return Poseidon2Sponge.hash4(
            NOTE_BODY_COMMITMENT_DOMAIN,
            ownerCommitmentValue,
            amount,
            tokenAddress
        );
    }

    function noteCommitment(uint256 noteBodyCommitmentValue, uint256 leafIndex)
        internal
        pure
        returns (uint256)
    {
        return Poseidon2Sponge.hash3(NOTE_COMMITMENT_DOMAIN, noteBodyCommitmentValue, leafIndex);
    }

    function noteSecretSeedHash(uint256 noteSecretSeed) internal pure returns (uint256) {
        return Poseidon2Sponge.hashPair(NOTE_SECRET_SEED_DOMAIN, noteSecretSeed);
    }

    function userRegistryLeaf(
        address user,
        uint256 ownerNullifierKeyHash,
        uint256 noteSecretSeedHashValue
    ) internal pure returns (uint256) {
        return Poseidon2Sponge.hash4(
            USER_REGISTRY_LEAF_DOMAIN,
            uint256(uint160(user)),
            ownerNullifierKeyHash,
            noteSecretSeedHashValue
        );
    }

    /// @notice Section 6.4 / 9.1: leaf the contract appends to the auth-policy
    ///         registration tree on `registerAuthPolicy`. The user field is
    ///         pinned to msg.sender by construction.
    function authPolicyLeaf(address user, uint256 policyCommitment)
        internal
        pure
        returns (uint256)
    {
        return Poseidon2Sponge.hash3(
            AUTH_POLICY_DOMAIN,
            uint256(uint160(user)),
            policyCommitment
        );
    }

    function dummyOwnerNullifierKeyHash() internal pure returns (uint256) {
        return Poseidon2Sponge.hashPair(OWNER_NULLIFIER_KEY_HASH_DOMAIN, 0xdead);
    }

    function historicalNoteRootLeaf(uint256 noteRoot, uint256 rootLogIndex)
        internal
        pure
        returns (uint256)
    {
        return Poseidon2Sponge.hash3(
            HISTORICAL_NOTE_ROOT_LEAF_DOMAIN,
            noteRoot,
            rootLogIndex
        );
    }
}
