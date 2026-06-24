// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IAuthVerifier} from "contracts/src/interfaces/IAuthVerifier.sol";

interface IHonkVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs)
        external
        view
        returns (bool);
}

/// @notice Sepolia-demo auth wrapper for a pool-address-specific Noir circuit.
///         Not part of the EIP-8182 reference implementation.
contract DemoRealAuthVerifier is IAuthVerifier {
    error InvalidCaller();

    IHonkVerifier public immutable VERIFIER;
    address public immutable POOL;
    uint256 public immutable EXPECTED_PROOF_LENGTH;

    constructor(IHonkVerifier verifier_, address pool_, uint256 expectedProofLength_) {
        VERIFIER = verifier_;
        POOL = pool_;
        EXPECTED_PROOF_LENGTH = expectedProofLength_;
    }

    function verifyAuth(bytes calldata publicInputs, bytes calldata proof)
        external
        view
        override
        returns (bool)
    {
        if (msg.sender != POOL) revert InvalidCaller();
        if (publicInputs.length != 64 || proof.length != EXPECTED_PROOF_LENGTH) {
            return false;
        }

        (uint256 blindedAuthCommitment, uint256 transactionIntentDigest) =
            abi.decode(publicInputs, (uint256, uint256));

        bytes32[] memory pubs = new bytes32[](2);
        pubs[0] = bytes32(blindedAuthCommitment);
        pubs[1] = bytes32(transactionIntentDigest);

        try VERIFIER.verify(proof, pubs) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }
}
