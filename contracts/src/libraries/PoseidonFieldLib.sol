// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Poseidon2Sponge} from "./Poseidon2Sponge.sol";

library PoseidonFieldLib {
    uint256 internal constant FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    uint256 internal constant OWNER_NULLIFIER_KEY_HASH_DOMAIN =
        uint256(keccak256("eip-8182.owner_nullifier_key_hash")) % FIELD_MODULUS;
    uint256 internal constant OUTPUT_BINDING_DOMAIN =
        uint256(keccak256("eip-8182.output_binding")) % FIELD_MODULUS;
    uint256 internal constant NOTE_SECRET_SEED_DOMAIN =
        uint256(keccak256("eip-8182.note_secret_seed")) % FIELD_MODULUS;
    uint256 internal constant AUTH_POLICY_DOMAIN =
        uint256(keccak256("eip-8182.auth_policy")) % FIELD_MODULUS;
    uint256 internal constant AUTH_POLICY_KEY_DOMAIN =
        uint256(keccak256("eip-8182.auth_policy_key")) % FIELD_MODULUS;
    uint256 internal constant USER_REGISTRY_LEAF_DOMAIN =
        uint256(keccak256("eip-8182.user_registry_leaf")) % FIELD_MODULUS;
    uint256 internal constant OWNER_COMMITMENT_DOMAIN =
        uint256(keccak256("eip-8182.owner_commitment")) % FIELD_MODULUS;
    uint256 internal constant NOTE_BODY_COMMITMENT_DOMAIN =
        uint256(keccak256("eip-8182.note_body_commitment")) % FIELD_MODULUS;
    uint256 internal constant NOTE_COMMITMENT_DOMAIN =
        uint256(keccak256("eip-8182.note_commitment")) % FIELD_MODULUS;
    uint256 internal constant NULLIFIER_DOMAIN =
        uint256(keccak256("eip-8182.nullifier")) % FIELD_MODULUS;

    /// @notice Merkle-internal-node hash — length-tagged 2-input sponge form.
    function merkleHash(uint256 left, uint256 right) internal pure returns (uint256) {
        return Poseidon2Sponge.hashPair(left, right);
    }

    /// @notice Owner-side note commitment per EIP §7.3.
    function ownerCommitment(uint256 ownerNullifierKeyHash, uint256 noteSecret) internal pure returns (uint256) {
        return Poseidon2Sponge.hash3(OWNER_COMMITMENT_DOMAIN, ownerNullifierKeyHash, noteSecret);
    }

    /// @notice Semantic note commitment per EIP §7.4. Input order is normative.
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

    /// @notice Final leaf-sealed note commitment per EIP §7.5.
    function noteCommitment(uint256 noteBodyCommitmentValue, uint256 leafIndex) internal pure returns (uint256) {
        return Poseidon2Sponge.hash3(NOTE_COMMITMENT_DOMAIN, noteBodyCommitmentValue, leafIndex);
    }

    function outputBinding(uint256 noteCommitmentValue, uint256 outputNoteDataHash) internal pure returns (uint256) {
        return Poseidon2Sponge.hash3(OUTPUT_BINDING_DOMAIN, noteCommitmentValue, outputNoteDataHash);
    }

    function noteSecretSeedHash(uint256 noteSecretSeed) internal pure returns (uint256) {
        return Poseidon2Sponge.hashPair(NOTE_SECRET_SEED_DOMAIN, noteSecretSeed);
    }

    function userRegistryLeaf(address user, uint256 ownerNullifierKeyHash, uint256 noteSecretSeedHashValue)
        internal
        pure
        returns (uint256)
    {
        return Poseidon2Sponge.hash4(
            USER_REGISTRY_LEAF_DOMAIN,
            uint256(uint160(user)),
            ownerNullifierKeyHash,
            noteSecretSeedHashValue
        );
    }

    function authPolicyLeaf(uint256 authDataCommitment, uint256 policyVersion) internal pure returns (uint256) {
        return Poseidon2Sponge.hash3(AUTH_POLICY_DOMAIN, authDataCommitment, policyVersion);
    }

    function authPolicyTreeKey(address user, uint256 innerVkHash) internal pure returns (uint256) {
        return uint256(
            uint160(Poseidon2Sponge.hash3(AUTH_POLICY_KEY_DOMAIN, uint256(uint160(user)), innerVkHash))
        );
    }

    function dummyOwnerNullifierKeyHash() internal pure returns (uint256) {
        return Poseidon2Sponge.hashPair(OWNER_NULLIFIER_KEY_HASH_DOMAIN, 0xdead);
    }
}
