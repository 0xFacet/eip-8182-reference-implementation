// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Poseidon2Sponge} from "./Poseidon2Sponge.sol";
import {ErcConstants} from "../generated/ErcConstants.sol";
import {IShieldedPoolStructs} from "../interfaces/IShieldedPool.sol";

/// @notice Convenience wrappers around the ERC spec section 15.6 / 16.1 hash
///         contexts the CONTRACTS need. Domain tags are generated constants
///         (`keccak256("erc-app-layer-private-transfers.<context>") mod p`)
///         and MUST match circuits/common/domain_tags.circom, the Noir
///         constants, and the TS SDK.
library PoseidonFieldLib {
    uint256 internal constant FIELD_MODULUS = ErcConstants.P;

    function merkleHash(uint256 left, uint256 right) internal pure returns (uint256) {
        return Poseidon2Sponge.hashPair(left, right);
    }

    /// @notice keccak256(data) mod p — outputNoteDataHash / policyDataHash binding.
    function keccakField(bytes calldata data) internal pure returns (uint256) {
        return uint256(keccak256(data)) % FIELD_MODULUS;
    }

    /// @notice spec section 15.6 (unscoped): poseidon(NOTE_BODY_COMMITMENT_DOMAIN,
    ///         ownerCommitment, amount, tokenAddress)
    function noteBodyCommitment(
        uint256 ownerCommitmentValue,
        uint256 amount,
        uint256 tokenAddress
    ) internal pure returns (uint256) {
        return Poseidon2Sponge.hash4(
            ErcConstants.NOTE_BODY_COMMITMENT_DOMAIN,
            ownerCommitmentValue,
            amount,
            tokenAddress
        );
    }

    /// @notice spec section 15.6 (pool-scoped): poseidon(NOTE_COMMITMENT_DOMAIN,
    ///         executionChainId, poolAddress, noteBodyCommitment, leafIndex)
    function noteCommitment(
        uint256 executionChainId,
        uint256 poolAddress,
        uint256 noteBodyCommitmentValue,
        uint256 leafIndex
    ) internal pure returns (uint256) {
        return Poseidon2Sponge.hash5(
            ErcConstants.NOTE_COMMITMENT_DOMAIN,
            executionChainId,
            poolAddress,
            noteBodyCommitmentValue,
            leafIndex
        );
    }

    /// @notice spec section 6: identity leaf written by the canonical registry.
    ///         The user field is pinned to msg.sender by construction.
    function identityLeaf(
        address user,
        uint256 ownerNullifierKeyHash,
        uint256 noteSecretSeedHashValue,
        uint256 policySetCommitment
    ) internal pure returns (uint256) {
        return Poseidon2Sponge.hash5(
            ErcConstants.IDENTITY_LEAF_DOMAIN,
            uint256(uint160(user)),
            ownerNullifierKeyHash,
            noteSecretSeedHashValue,
            policySetCommitment
        );
    }

    /// @notice spec section 16.1: policyOperationDigest = poseidon(
    ///         POLICY_OPERATION_DOMAIN, chainId, poolAddress, policyVerifier,
    ///         policyOperationKind, operationDataHash)
    function policyOperationDigest(
        uint256 chainId,
        uint256 poolAddress,
        uint256 policyVerifierField,
        uint256 policyOperationKind,
        uint256 operationDataHash
    ) internal pure returns (uint256) {
        return Poseidon2Sponge.hash6(
            ErcConstants.POLICY_OPERATION_DOMAIN,
            chainId,
            poolAddress,
            policyVerifierField,
            policyOperationKind,
            operationDataHash
        );
    }

    /// @notice spec section 16.1: depositOperationDataHash = poseidon(
    ///         POLICY_DEPOSIT_OPERATION_DATA_DOMAIN, chainId, poolAddress,
    ///         sender, token, amount, ownerCommitment, outputNoteDataHash)
    function depositOperationDataHash(
        uint256 chainId,
        uint256 poolAddress,
        uint256 sender,
        uint256 token,
        uint256 amount,
        uint256 ownerCommitmentValue,
        uint256 outputNoteDataHashValue
    ) internal pure returns (uint256) {
        uint256[] memory inputs = new uint256[](8);
        inputs[0] = ErcConstants.POLICY_DEPOSIT_OPERATION_DATA_DOMAIN;
        inputs[1] = chainId;
        inputs[2] = poolAddress;
        inputs[3] = sender;
        inputs[4] = token;
        inputs[5] = amount;
        inputs[6] = ownerCommitmentValue;
        inputs[7] = outputNoteDataHashValue;
        return Poseidon2Sponge.hash(inputs);
    }

    /// @notice spec section 16.1: transactPublicTransitionHash over the first
    ///         19 public inputs (through blindedAuthCommitment) plus the two
    ///         appended fields authorizedSubmitter and downstreamActionCommitment,
    ///         arity 22.
    function transactPublicTransitionHash(IShieldedPoolStructs.PublicInputs calldata pi)
        internal
        pure
        returns (uint256)
    {
        uint256[] memory inputs = new uint256[](22);
        inputs[0] = ErcConstants.POLICY_TRANSACT_PUBLIC_TRANSITION_DOMAIN;
        inputs[1] = pi.noteCommitmentRoot;
        inputs[2] = pi.nullifier0;
        inputs[3] = pi.nullifier1;
        inputs[4] = pi.noteBodyCommitment0;
        inputs[5] = pi.noteBodyCommitment1;
        inputs[6] = pi.noteBodyCommitment2;
        inputs[7] = pi.publicAmountOut;
        inputs[8] = pi.publicRecipientAddress;
        inputs[9] = pi.publicTokenAddress;
        inputs[10] = pi.intentReplayId;
        inputs[11] = pi.validUntilSeconds;
        inputs[12] = pi.executionChainId;
        inputs[13] = pi.poolAddress;
        inputs[14] = pi.identityRoot;
        inputs[15] = pi.outputNoteDataHash0;
        inputs[16] = pi.outputNoteDataHash1;
        inputs[17] = pi.outputNoteDataHash2;
        inputs[18] = pi.authVerifier;
        inputs[19] = pi.blindedAuthCommitment;
        inputs[20] = pi.authorizedSubmitter;
        inputs[21] = pi.downstreamActionCommitment;
        return Poseidon2Sponge.hash(inputs);
    }

    /// @notice spec section 16.1: transactOperationDataHash = poseidon(
    ///         POLICY_TRANSACT_OPERATION_DATA_DOMAIN, transactIntentFieldsHash,
    ///         transactPublicTransitionHash). Only used by tests/tooling: the
    ///         pool never recomputes it on-chain (the circuit authenticates it).
    function transactOperationDataHash(
        uint256 transactIntentFieldsHashValue,
        uint256 transactPublicTransitionHashValue
    ) internal pure returns (uint256) {
        return Poseidon2Sponge.hash3(
            ErcConstants.POLICY_TRANSACT_OPERATION_DATA_DOMAIN,
            transactIntentFieldsHashValue,
            transactPublicTransitionHashValue
        );
    }
}
