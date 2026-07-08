// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IPolicyVerifier} from "../interfaces/IPolicyVerifier.sol";

/// @notice Example pool-level policy verifier (spec section 16.1). Accepts an
///         operation iff `policyData` carries an ECDSA signature by a fixed
///         off-chain attestor over the policy operation digest.
///
/// @dev    Wire format:
///           publicInputs (bytes) = abi.encode(uint256 policyOperationDigest)
///           policyData   (bytes) = abi.encode(uint8 v, bytes32 r, bytes32 s)
///
///         The signed message is
///           keccak256("\x19ERC-allowlist-attestation-v1" || digest32)
///         where digest32 is the 32-byte big-endian policy operation digest.
///         This is a self-contained reference policy; it is not normative.
contract AllowlistPolicyVerifier is IPolicyVerifier {
    /// @notice The off-chain signer whose attestation authorizes operations.
    address public immutable attestor;

    error ZeroAttestor();

    constructor(address attestor_) {
        require(attestor_ != address(0), ZeroAttestor());
        attestor = attestor_;
    }

    /// @inheritdoc IPolicyVerifier
    /// @dev Returns false (never reverts) for malformed policyData or a
    ///      signature that does not recover to the attestor, so the pool's
    ///      staticcall dispatch treats it uniformly as a policy rejection.
    function verifyPolicy(bytes calldata publicInputs, bytes calldata policyData)
        external
        view
        override
        returns (bool)
    {
        if (publicInputs.length != 32 || policyData.length != 96) {
            return false;
        }

        uint256 digest = abi.decode(publicInputs, (uint256));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(policyData, (uint8, bytes32, bytes32));

        // Reject the malleable high-s / non-{27,28} half so each attestation has
        // a single canonical byte form (EIP-2 low-s).
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return false;
        }
        if (v != 27 && v != 28) {
            return false;
        }

        bytes32 message = keccak256(
            abi.encodePacked("\x19ERC-allowlist-attestation-v1", digest)
        );
        address recovered = ecrecover(message, v, r, s);
        return recovered != address(0) && recovered == attestor;
    }
}
