// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {DemoAuthVerifier} from "../src/auth/DemoAuthVerifier.sol";
import {EcdsaEip712AuthVerifier} from "../src/auth/EcdsaEip712AuthVerifier.sol";
import {HonkVerifier} from "../src/generated/HonkVerifier.sol";
import {IAuthVerifier} from "../src/interfaces/IAuthVerifier.sol";

contract AuthVerifiersTest is Test {
    using stdJson for string;

    DemoAuthVerifier internal demo;
    EcdsaEip712AuthVerifier internal ecdsa;

    function setUp() public {
        demo = new DemoAuthVerifier();
        ecdsa = new EcdsaEip712AuthVerifier(new HonkVerifier());
    }

    function _loadFixture(string memory name)
        internal
        view
        returns (bytes memory proof, bytes memory publicInputs, uint256 blinded, uint256 digest)
    {
        string memory json = vm.readFile(string.concat("test/fixtures/", name, ".json"));
        proof = json.readBytes(".proof");
        uint256[] memory sigs = json.readUintArray(".publicSignals");
        require(sigs.length == 2, "fixture must have 2 public signals");
        blinded = sigs[0];
        digest = sigs[1];
        publicInputs = abi.encode(blinded, digest);
    }

    /// @dev fail = returns false OR reverts; both are auth failure per section 7.5.
    function _verifyLenient(IAuthVerifier v, bytes memory publicInputs, bytes memory proof)
        internal
        returns (bool)
    {
        try v.verifyAuth(publicInputs, proof) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }

    // --------------------------------- Demo (Groth16) ---------------------------------

    function test_demo_validProof() public view {
        (bytes memory proof, bytes memory publicInputs,,) = _loadFixture("auth_demo_proof_transfer");
        assertTrue(demo.verifyAuth(publicInputs, proof), "valid demo auth proof verifies");
    }

    function test_demo_rejectsBitFlippedProof() public {
        (bytes memory proof, bytes memory publicInputs,,) = _loadFixture("auth_demo_proof_transfer");
        uint256[3] memory offsets = [uint256(5), 100, 230];
        for (uint256 i; i < 3; i++) {
            bytes memory corrupted = bytes.concat(proof);
            corrupted[offsets[i]] = corrupted[offsets[i]] ^ 0x01;
            assertFalse(_verifyLenient(demo, publicInputs, corrupted), "bit-flipped demo proof rejected");
        }
    }

    function test_demo_rejectsMutatedPublicInputs() public {
        (bytes memory proof,, uint256 blinded, uint256 digest) = _loadFixture("auth_demo_proof_transfer");
        assertFalse(
            _verifyLenient(demo, abi.encode(blinded ^ 1, digest), proof),
            "mutated blindedAuthCommitment rejected"
        );
        assertFalse(
            _verifyLenient(demo, abi.encode(blinded, digest ^ 1), proof),
            "mutated transactionIntentDigest rejected"
        );
        assertFalse(
            _verifyLenient(demo, abi.encode(digest, blinded), proof),
            "swapped public signals rejected"
        );
    }

    function test_demo_rejectsWrongLengthProof() public view {
        (bytes memory proof, bytes memory publicInputs,,) = _loadFixture("auth_demo_proof_transfer");
        assertFalse(demo.verifyAuth(publicInputs, bytes.concat(proof, hex"00")), "257-byte proof rejected");
        assertFalse(demo.verifyAuth(publicInputs, hex""), "empty proof rejected");
        assertFalse(demo.verifyAuth(hex"1234", proof), "short publicInputs rejected");
    }

    function test_demo_garbageProofRejected() public {
        (, bytes memory publicInputs,,) = _loadFixture("auth_demo_proof_transfer");
        bytes memory garbage = new bytes(256);
        for (uint256 i; i < 256; i++) garbage[i] = bytes1(uint8(i));
        assertFalse(_verifyLenient(demo, publicInputs, garbage), "garbage 256-byte proof rejected");
    }

    // --------------------------------- Ecdsa/Honk (UltraHonk) ---------------------------------

    function test_honk_validProof() public view {
        (bytes memory proof, bytes memory publicInputs,,) = _loadFixture("auth_honk_proof_transfer");
        assertTrue(ecdsa.verifyAuth(publicInputs, proof), "valid honk auth proof verifies");
    }

    function test_honk_rejectsBitFlippedProof() public {
        (bytes memory proof, bytes memory publicInputs,,) = _loadFixture("auth_honk_proof_transfer");
        // Flip a bit deep inside the proof body (past the pairing-point object).
        uint256[3] memory offsets = [uint256(600), 3000, 9000];
        for (uint256 i; i < 3; i++) {
            bytes memory corrupted = bytes.concat(proof);
            corrupted[offsets[i]] = corrupted[offsets[i]] ^ 0x01;
            assertFalse(_verifyLenient(ecdsa, publicInputs, corrupted), "bit-flipped honk proof rejected");
        }
    }

    function test_honk_rejectsMutatedPublicInputs() public {
        (bytes memory proof,, uint256 blinded, uint256 digest) = _loadFixture("auth_honk_proof_transfer");
        assertFalse(
            _verifyLenient(ecdsa, abi.encode(blinded ^ 1, digest), proof),
            "mutated blindedAuthCommitment rejected"
        );
        assertFalse(
            _verifyLenient(ecdsa, abi.encode(blinded, digest ^ 1), proof),
            "mutated transactionIntentDigest rejected"
        );
    }

    function test_honk_garbageProofRejected() public {
        (, bytes memory publicInputs,,) = _loadFixture("auth_honk_proof_transfer");
        bytes memory garbage = new bytes(64);
        for (uint256 i; i < 64; i++) garbage[i] = bytes1(uint8(i + 1));
        assertFalse(_verifyLenient(ecdsa, publicInputs, garbage), "garbage short proof rejected");
        assertFalse(_verifyLenient(ecdsa, publicInputs, hex""), "empty proof rejected");
    }

    function test_honk_malformedPublicInputsLengthRejected() public view {
        (bytes memory proof,,,) = _loadFixture("auth_honk_proof_transfer");
        assertFalse(ecdsa.verifyAuth(hex"1234", proof), "short publicInputs rejected");
    }
}
