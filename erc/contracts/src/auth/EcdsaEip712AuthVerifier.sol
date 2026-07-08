// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IAuthVerifier} from "../interfaces/IAuthVerifier.sol";
import {HonkVerifier} from "../generated/HonkVerifier.sol";

/// @notice Normative Appendix A auth verifier: a thin wrapper around the
///         bb-generated UltraHonk verifier for the EIP-712 / ECDSA-secp256k1
///         Noir auth circuit (circuits-noir/auth).
///
/// @dev    Wire format (spec section 7.5):
///           publicInputs (bytes) = abi.encode(uint256 blindedAuthCommitment,
///                                              uint256 transactionIntentDigest)
///                                  i.e. exactly 64 bytes.
///           proof        (bytes) = bb-emitted UltraHonk proof bytes. The 16
///                                  pairing-point-object field elements are
///                                  carried INSIDE the proof, so the public
///                                  inputs array passed to the Honk verifier is
///                                  exactly the circuit's 2 Noir outputs, in
///                                  the order [blindedAuthCommitment,
///                                  transactionIntentDigest].
///
///         Pool-agnostic by design: there is NO msg.sender / pool gating here.
///         The pool binds itself to a specific verifier via the
///         `authVerifier` public input, and the intent digest commits to the
///         pool identity; the auth proof only attests the signature over that
///         digest.
contract EcdsaEip712AuthVerifier is IAuthVerifier {
    HonkVerifier public immutable verifier;

    constructor(HonkVerifier verifier_) {
        verifier = verifier_;
    }

    /// @inheritdoc IAuthVerifier
    /// @dev Malformed publicInputs length returns false. Reverts from the
    ///      underlying verifier bubble up (the pool treats revert and false
    ///      identically as auth failure).
    function verifyAuth(bytes calldata publicInputs, bytes calldata proof)
        external
        view
        override
        returns (bool)
    {
        if (publicInputs.length != 64) {
            return false;
        }

        (uint256 blindedAuthCommitment, uint256 transactionIntentDigest) =
            abi.decode(publicInputs, (uint256, uint256));

        bytes32[] memory pubs = new bytes32[](2);
        pubs[0] = bytes32(blindedAuthCommitment);
        pubs[1] = bytes32(transactionIntentDigest);

        return verifier.verify(proof, pubs);
    }
}
