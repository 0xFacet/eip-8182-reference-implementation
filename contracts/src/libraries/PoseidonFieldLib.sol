// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";

library PoseidonFieldLib {
    uint256 internal constant FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    uint256 internal constant ORIGIN_TAG_DOMAIN =
        uint256(keccak256("eip-8182.origin_tag")) % FIELD_MODULUS;
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

    function hash2Raw(uint256 left, uint256 right) internal pure returns (uint256 result) {
        uint256[2] memory input;
        input[0] = left;
        input[1] = right;
        result = PoseidonT3.hash(input);
    }

    function poseidon2(uint256 x0, uint256 x1) internal pure returns (uint256) {
        return hash2Raw(2, hash2Raw(x0, x1));
    }

    function poseidon3(uint256 x0, uint256 x1, uint256 x2) internal pure returns (uint256) {
        return hash2Raw(3, hash2Raw(hash2Raw(x0, x1), x2));
    }

    function poseidon4(uint256 x0, uint256 x1, uint256 x2, uint256 x3) internal pure returns (uint256) {
        return hash2Raw(4, hash2Raw(hash2Raw(x0, x1), hash2Raw(x2, x3)));
    }

    function outputBinding(uint256 noteCommitment, uint256 outputNoteDataHash) internal pure returns (uint256) {
        return poseidon3(OUTPUT_BINDING_DOMAIN, noteCommitment, outputNoteDataHash);
    }

    function noteSecretSeedHash(uint256 noteSecretSeed) internal pure returns (uint256) {
        return poseidon2(NOTE_SECRET_SEED_DOMAIN, noteSecretSeed);
    }

    function userRegistryLeaf(address user, uint256 ownerNullifierKeyHash, uint256 noteSecretSeedHashValue)
        internal
        pure
        returns (uint256)
    {
        return poseidon4(USER_REGISTRY_LEAF_DOMAIN, uint256(uint160(user)), ownerNullifierKeyHash, noteSecretSeedHashValue);
    }

    function authPolicyLeaf(uint256 authDataCommitment, uint256 policyVersion) internal pure returns (uint256) {
        return poseidon3(AUTH_POLICY_DOMAIN, authDataCommitment, policyVersion);
    }

    function authPolicyTreeKey(address user, uint256 innerVkHash) internal pure returns (uint256) {
        return uint256(uint160(poseidon3(AUTH_POLICY_KEY_DOMAIN, uint256(uint160(user)), innerVkHash)));
    }

    function dummyOwnerNullifierKeyHash() internal pure returns (uint256) {
        return poseidon2(OWNER_NULLIFIER_KEY_HASH_DOMAIN, 0xdead);
    }
}
