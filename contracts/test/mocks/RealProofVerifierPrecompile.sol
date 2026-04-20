// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ShieldedPool} from "../../src/ShieldedPool.sol";

interface IHonkVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

contract RealProofVerifierPrecompile {
    IHonkVerifier private immutable verifier;

    constructor(address verifier_) {
        verifier = IHonkVerifier(verifier_);
    }

    function decodePrecompileInput(bytes calldata input)
        external
        pure
        returns (bytes memory proof, ShieldedPool.PublicInputs memory publicInputs)
    {
        return abi.decode(input, (bytes, ShieldedPool.PublicInputs));
    }

    fallback(bytes calldata input) external returns (bytes memory output) {
        bytes memory proof;
        ShieldedPool.PublicInputs memory publicInputs;
        try this.decodePrecompileInput(input) returns (
            bytes memory proof_,
            ShieldedPool.PublicInputs memory publicInputs_
        ) {
            proof = proof_;
            publicInputs = publicInputs_;
        } catch {
            return bytes("");
        }

        bytes32[] memory verifierPublicInputs = new bytes32[](17);
        verifierPublicInputs[0] = bytes32(publicInputs.noteCommitmentRoot);
        verifierPublicInputs[1] = bytes32(publicInputs.nullifier0);
        verifierPublicInputs[2] = bytes32(publicInputs.nullifier1);
        verifierPublicInputs[3] = bytes32(publicInputs.noteBodyCommitment0);
        verifierPublicInputs[4] = bytes32(publicInputs.noteBodyCommitment1);
        verifierPublicInputs[5] = bytes32(publicInputs.noteBodyCommitment2);
        verifierPublicInputs[6] = bytes32(publicInputs.publicAmountOut);
        verifierPublicInputs[7] = bytes32(publicInputs.publicRecipientAddress);
        verifierPublicInputs[8] = bytes32(publicInputs.publicTokenAddress);
        verifierPublicInputs[9] = bytes32(publicInputs.intentReplayId);
        verifierPublicInputs[10] = bytes32(publicInputs.registryRoot);
        verifierPublicInputs[11] = bytes32(publicInputs.validUntilSeconds);
        verifierPublicInputs[12] = bytes32(publicInputs.executionChainId);
        verifierPublicInputs[13] = bytes32(publicInputs.authPolicyRegistryRoot);
        verifierPublicInputs[14] = bytes32(publicInputs.outputNoteDataHash0);
        verifierPublicInputs[15] = bytes32(publicInputs.outputNoteDataHash1);
        verifierPublicInputs[16] = bytes32(publicInputs.outputNoteDataHash2);

        (bool success, bytes memory returnData) = address(verifier).staticcall(
            abi.encodeCall(IHonkVerifier.verify, (proof, verifierPublicInputs))
        );
        if (!success || returnData.length != 32) {
            return bytes("");
        }

        bool verified = abi.decode(returnData, (bool));
        if (!verified) {
            return bytes("");
        }

        return abi.encode(uint256(1));
    }
}
