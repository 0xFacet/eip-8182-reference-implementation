// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AuthDemoGroth16Verifier} from "../AuthDemoGroth16Verifier.sol";
import {IAuthVerifier} from "../interfaces/IAuthVerifier.sol";

/// @notice Auth verifier contract for the demo auth circuit at
///         circuits/auth-demo/auth_demo.circom. Implements the EIP-8182
///         Section 12 IAuthVerifier interface so the system contract can call
///         it via `staticcall`.
///
/// @dev    For a production secp256k1 / EIP-712 ECDSA companion (Section 14),
///         the only contract-side difference is that the underlying
///         Groth16Verifier verifies a different circuit; the wrapper
///         shape — decode 2 public inputs, decode 256-byte proof, return a
///         single bool — is identical.
contract DemoAuthVerifier is IAuthVerifier {
    AuthDemoGroth16Verifier public immutable verifier;

    constructor(AuthDemoGroth16Verifier verifier_) {
        verifier = verifier_;
    }

    function verifyAuth(bytes calldata publicInputs, bytes calldata proof)
        external
        view
        override
        returns (bool)
    {
        if (publicInputs.length != 64 || proof.length != 256) return false;

        (uint256 blindedAuthCommitment, uint256 transactionIntentDigest) =
            abi.decode(publicInputs, (uint256, uint256));

        // Decompose the 256-byte canonical proof into Groth16 elements.
        // Layout: A (G1, 64) || B (G2, 128, EIP-197 [c1,c0]) || C (G1, 64).
        uint256[2] memory pA = [_word(proof, 0), _word(proof, 32)];
        uint256[2][2] memory pB = [
            [_word(proof, 64),  _word(proof, 96)],
            [_word(proof, 128), _word(proof, 160)]
        ];
        uint256[2] memory pC = [_word(proof, 192), _word(proof, 224)];

        uint256[2] memory pub = [blindedAuthCommitment, transactionIntentDigest];

        try verifier.verifyProof(pA, pB, pC, pub) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }

    function _word(bytes calldata src, uint256 offset) private pure returns (uint256 w) {
        assembly {
            w := calldataload(add(src.offset, offset))
        }
    }
}
