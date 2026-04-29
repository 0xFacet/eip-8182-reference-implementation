// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IAuthVerifier} from "../interfaces/IAuthVerifier.sol";
import {HonkVerifier} from "./HonkRealAuthVerifier.sol";

/// @notice IAuthVerifier impl backed by an UltraHonk verifier (auto-generated
///         from the realistic Noir auth circuit at circuits-noir/auth via
///         `bb write_solidity_verifier --scheme ultra_honk -t evm`).
///
/// @dev    Wire format:
///           publicInputs (bytes) = abi.encode(uint256 blindedAuthCommitment,
///                                             uint256 transactionIntentDigest)
///                                  i.e. exactly 64 bytes, same as
///                                  DemoAuthVerifier.
///           proof        (bytes) = bb-emitted UltraHonk proof bytes.
contract RealAuthVerifier is IAuthVerifier {
    HonkVerifier public immutable verifier;
    uint256 public immutable expectedProofLength;

    constructor(HonkVerifier verifier_, uint256 expectedProofLength_) {
        verifier = verifier_;
        expectedProofLength = expectedProofLength_;
    }

    function verifyAuth(bytes calldata publicInputs, bytes calldata proof)
        external
        view
        override
        returns (bool)
    {
        if (publicInputs.length != 64 || proof.length != expectedProofLength) {
            return false;
        }

        (uint256 blindedAuthCommitment, uint256 transactionIntentDigest) =
            abi.decode(publicInputs, (uint256, uint256));

        bytes32[] memory pubs = new bytes32[](2);
        pubs[0] = bytes32(blindedAuthCommitment);
        pubs[1] = bytes32(transactionIntentDigest);

        try verifier.verify(proof, pubs) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }
}
