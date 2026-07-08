// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {AllowlistPolicyVerifier} from "../src/policy/AllowlistPolicyVerifier.sol";

contract AllowlistPolicyVerifierTest is Test {
    AllowlistPolicyVerifier internal policy;

    uint256 internal attestorKey;
    address internal attestor;

    uint256 internal digest = 0x27a0532a9d5b66be24a7e65e2de68b5bec4904f92a899b8816179aba09031b10;

    function setUp() public {
        attestorKey = 0xA11CE;
        attestor = vm.addr(attestorKey);
        policy = new AllowlistPolicyVerifier(attestor);
    }

    function _message(uint256 d) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19ERC-allowlist-attestation-v1", d));
    }

    function _sign(uint256 key, uint256 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, _message(d));
        return abi.encode(v, r, s);
    }

    function test_constructorRejectsZeroAttestor() public {
        vm.expectRevert(AllowlistPolicyVerifier.ZeroAttestor.selector);
        new AllowlistPolicyVerifier(address(0));
    }

    function test_validAttestationAccepted() public view {
        bytes memory policyData = _sign(attestorKey, digest);
        assertTrue(policy.verifyPolicy(abi.encode(digest), policyData), "attestor signature accepted");
    }

    function test_wrongSignerRejected() public {
        uint256 wrongKey = 0xB0B;
        bytes memory policyData = _sign(wrongKey, digest);
        assertFalse(policy.verifyPolicy(abi.encode(digest), policyData), "non-attestor signature rejected");
    }

    function test_signatureOverWrongDigestRejected() public view {
        // Signature is valid but was produced over a different digest.
        bytes memory policyData = _sign(attestorKey, digest ^ 1);
        assertFalse(policy.verifyPolicy(abi.encode(digest), policyData), "digest mismatch rejected");
    }

    function test_malformedPolicyDataRejected() public view {
        // Wrong length (not 96 bytes) -> false, never reverts.
        assertFalse(policy.verifyPolicy(abi.encode(digest), hex""), "empty policyData rejected");
        assertFalse(policy.verifyPolicy(abi.encode(digest), hex"1234"), "short policyData rejected");
        bytes memory tooLong = bytes.concat(_sign(attestorKey, digest), hex"00");
        assertFalse(policy.verifyPolicy(abi.encode(digest), tooLong), "over-length policyData rejected");
    }

    function test_malformedPublicInputsRejected() public view {
        bytes memory policyData = _sign(attestorKey, digest);
        assertFalse(policy.verifyPolicy(hex"", policyData), "empty publicInputs rejected");
        assertFalse(policy.verifyPolicy(hex"1234", policyData), "short publicInputs rejected");
    }

    function test_garbageSignatureDoesNotRecoverAttestor() public view {
        // v/r/s that make ecrecover return address(0) must be rejected.
        bytes memory policyData = abi.encode(uint8(27), bytes32(0), bytes32(0));
        assertFalse(policy.verifyPolicy(abi.encode(digest), policyData), "zero-recover rejected");
    }

    function test_malleatedHighSRejected() public view {
        // secp256k1 group order.
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attestorKey, _message(digest));
        // vm.sign yields the canonical low-s form; it is accepted.
        assertTrue(
            policy.verifyPolicy(abi.encode(digest), abi.encode(v, r, s)),
            "canonical low-s accepted"
        );
        // The malleated twin (s' = n - s, v flipped) recovers the SAME attestor
        // but is the high-s form, which EIP-2 gating now rejects.
        bytes32 sHigh = bytes32(n - uint256(s));
        uint8 vFlipped = v == 27 ? 28 : 27;
        assertFalse(
            policy.verifyPolicy(abi.encode(digest), abi.encode(vFlipped, r, sHigh)),
            "malleated high-s rejected"
        );
    }
}
