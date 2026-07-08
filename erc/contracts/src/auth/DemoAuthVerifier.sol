// SPDX-License-Identifier: GPL-3.0
// (inherits the snarkjs-generated verifier core's license)
pragma solidity ^0.8.28;

import {AuthDemoGroth16VerifierCore} from "../generated/AuthDemoGroth16VerifierCore.sol";
import {IAuthVerifier} from "../interfaces/IAuthVerifier.sol";

/// @notice NON-NORMATIVE demo auth verifier (dev/test only). Wraps the
///         snarkjs-generated Groth16 core for the minimal auth-demo circuit
///         (circuits/auth-demo/auth_demo.circom). The demo credential is a
///         single field element rather than an ECDSA signature; production
///         deployments use EcdsaEip712AuthVerifier instead.
///
/// @dev    Wire format (spec section 7.5), identical to the normative wrapper:
///           publicInputs (bytes) = abi.encode(uint256 blindedAuthCommitment,
///                                              uint256 transactionIntentDigest)
///                                  i.e. exactly 64 bytes.
///           proof        (bytes) = canonical 256-byte Groth16 layout
///                                  (spec section 7.2):
///             A.x || A.y || B.x.c1 || B.x.c0 || B.y.c1 || B.y.c0 || C.x || C.y
///           each coordinate a 32-byte big-endian integer.
///
///         The circuit's public signals are [blindedAuthCommitment,
///         transactionIntentDigest], in that order.
contract DemoAuthVerifier is AuthDemoGroth16VerifierCore, IAuthVerifier {
    /// @inheritdoc IAuthVerifier
    /// @dev Returns false for a malformed length; the core's assembly returns
    ///      false for non-canonical field elements, invalid points, and
    ///      pairing failures.
    function verifyAuth(bytes calldata publicInputs, bytes calldata proof)
        external
        view
        override
        returns (bool)
    {
        if (publicInputs.length != 64 || proof.length != 256) {
            return false;
        }

        (uint256 blindedAuthCommitment, uint256 transactionIntentDigest) =
            abi.decode(publicInputs, (uint256, uint256));

        uint256[2] memory pA;
        uint256[2][2] memory pB;
        uint256[2] memory pC;
        pA[0] = uint256(bytes32(proof[0:32]));
        pA[1] = uint256(bytes32(proof[32:64]));
        pB[0][0] = uint256(bytes32(proof[64:96])); // B.x.c1
        pB[0][1] = uint256(bytes32(proof[96:128])); // B.x.c0
        pB[1][0] = uint256(bytes32(proof[128:160])); // B.y.c1
        pB[1][1] = uint256(bytes32(proof[160:192])); // B.y.c0
        pC[0] = uint256(bytes32(proof[192:224]));
        pC[1] = uint256(bytes32(proof[224:256]));

        uint256[2] memory signals;
        signals[0] = blindedAuthCommitment;
        signals[1] = transactionIntentDigest;

        // The generated core takes calldata arrays; an external self-call
        // (STATICCALL) re-encodes the memory arrays as calldata without
        // touching the generated assembly.
        return this.verifyProof(pA, pB, pC, signals);
    }
}
