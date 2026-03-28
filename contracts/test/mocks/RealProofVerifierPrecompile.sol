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

    fallback(bytes calldata input) external returns (bytes memory output) {
        (bytes memory proof, ShieldedPool.PublicInputs memory publicInputs) =
            abi.decode(input, (bytes, ShieldedPool.PublicInputs));

        bytes32[] memory verifierPublicInputs = new bytes32[](19);
        verifierPublicInputs[0] = bytes32(publicInputs.merkleRoot);
        verifierPublicInputs[1] = bytes32(publicInputs.nullifier0);
        verifierPublicInputs[2] = bytes32(publicInputs.nullifier1);
        verifierPublicInputs[3] = bytes32(publicInputs.commitment0);
        verifierPublicInputs[4] = bytes32(publicInputs.commitment1);
        verifierPublicInputs[5] = bytes32(publicInputs.commitment2);
        verifierPublicInputs[6] = bytes32(publicInputs.publicAmountIn);
        verifierPublicInputs[7] = bytes32(publicInputs.publicAmountOut);
        verifierPublicInputs[8] = bytes32(publicInputs.publicRecipientAddress);
        verifierPublicInputs[9] = bytes32(publicInputs.publicTokenAddress);
        verifierPublicInputs[10] = bytes32(publicInputs.depositorAddress);
        verifierPublicInputs[11] = bytes32(publicInputs.intentNullifier);
        verifierPublicInputs[12] = bytes32(publicInputs.registryRoot);
        verifierPublicInputs[13] = bytes32(publicInputs.validUntilSeconds);
        verifierPublicInputs[14] = bytes32(publicInputs.executionChainId);
        verifierPublicInputs[15] = bytes32(publicInputs.authPolicyRegistryRoot);
        verifierPublicInputs[16] = bytes32(publicInputs.outputNoteDataHash0);
        verifierPublicInputs[17] = bytes32(publicInputs.outputNoteDataHash1);
        verifierPublicInputs[18] = bytes32(publicInputs.outputNoteDataHash2);

        if (!verifier.verify(proof, verifierPublicInputs)) {
            return bytes("");
        }

        return abi.encode(uint256(1));
    }
}
