// SPDX-License-Identifier: GPL-3.0
// (inherits the snarkjs-generated verifier core's license)
pragma solidity ^0.8.28;

import {PoolGroth16VerifierCore} from "./generated/PoolGroth16VerifierCore.sol";
import {IPoolVerifier} from "./interfaces/IPoolVerifier.sol";

/// @notice Canonical stateless pool verifier (spec section 7.2): the chain
///         singleton every conforming pool staticcalls to verify pool proofs.
///         Embeds the canonical Groth16 BN254 verification key (see
///         assets/pool_vk.bin + .sha256) via the snarkjs-generated core.
///         Deployed once per chain via the deterministic CREATE2 factory; no
///         admin, no upgrade path, no constructor args, no state.
///
///         Proof encoding (spec section 7.2, exactly 256 bytes):
///           A.x || A.y || B.x.c1 || B.x.c0 || B.y.c1 || B.y.c0 || C.x || C.y
///         each coordinate a 32-byte big-endian integer. This matches the
///         snarkjs calldata order (pA, pB[[x.c1,x.c0],[y.c1,y.c0]], pC).
contract CanonicalPoolVerifier is PoolGroth16VerifierCore, IPoolVerifier {
    /// @inheritdoc IPoolVerifier
    /// @dev Returns false for a malformed length; the core's assembly rejects
    ///      non-canonical field elements, invalid curve points, and pairing
    ///      failures by returning false. The pool treats revert, returndata
    ///      length != 32, and false identically as pool-proof failure.
    function verifyPoolProof(
        bytes calldata proof,
        PublicInputs calldata publicInputs
    ) external view returns (bool) {
        if (proof.length != 256) return false;

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

        uint256[24] memory signals;
        signals[0] = publicInputs.noteCommitmentRoot;
        signals[1] = publicInputs.nullifier0;
        signals[2] = publicInputs.nullifier1;
        signals[3] = publicInputs.noteBodyCommitment0;
        signals[4] = publicInputs.noteBodyCommitment1;
        signals[5] = publicInputs.noteBodyCommitment2;
        signals[6] = publicInputs.publicAmountOut;
        signals[7] = publicInputs.publicRecipientAddress;
        signals[8] = publicInputs.publicTokenAddress;
        signals[9] = publicInputs.intentReplayId;
        signals[10] = publicInputs.validUntilSeconds;
        signals[11] = publicInputs.executionChainId;
        signals[12] = publicInputs.poolAddress;
        signals[13] = publicInputs.identityRoot;
        signals[14] = publicInputs.outputNoteDataHash0;
        signals[15] = publicInputs.outputNoteDataHash1;
        signals[16] = publicInputs.outputNoteDataHash2;
        signals[17] = publicInputs.authVerifier;
        signals[18] = publicInputs.blindedAuthCommitment;
        signals[19] = publicInputs.transactionIntentDigest;
        signals[20] = publicInputs.policyOperationDataHash;
        signals[21] = publicInputs.policyDataHash;
        signals[22] = publicInputs.authorizedSubmitter;
        signals[23] = publicInputs.downstreamActionCommitment;

        // The generated core takes calldata arrays; an external self-call
        // (STATICCALL) re-encodes the memory arrays as calldata without
        // touching the generated assembly.
        return this.verifyProof(pA, pB, pC, signals);
    }
}
