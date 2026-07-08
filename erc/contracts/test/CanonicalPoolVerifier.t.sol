// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {CanonicalPoolVerifier} from "../src/CanonicalPoolVerifier.sol";
import {IShieldedPoolStructs} from "../src/interfaces/IShieldedPool.sol";

contract CanonicalPoolVerifierTest is Test {
    using stdJson for string;

    CanonicalPoolVerifier internal verifier;

    function setUp() public {
        verifier = new CanonicalPoolVerifier();
    }

    function _loadFixture(string memory name)
        internal
        view
        returns (bytes memory proof, IShieldedPoolStructs.PublicInputs memory pi)
    {
        string memory json = vm.readFile(string.concat("test/fixtures/", name, ".json"));
        proof = json.readBytes(".proof");
        uint256[] memory arr = json.readUintArray(".publicInputs");
        require(arr.length == 24, "fixture must have 24 public inputs");
        pi.noteCommitmentRoot = arr[0];
        pi.nullifier0 = arr[1];
        pi.nullifier1 = arr[2];
        pi.noteBodyCommitment0 = arr[3];
        pi.noteBodyCommitment1 = arr[4];
        pi.noteBodyCommitment2 = arr[5];
        pi.publicAmountOut = arr[6];
        pi.publicRecipientAddress = arr[7];
        pi.publicTokenAddress = arr[8];
        pi.intentReplayId = arr[9];
        pi.validUntilSeconds = arr[10];
        pi.executionChainId = arr[11];
        pi.poolAddress = arr[12];
        pi.identityRoot = arr[13];
        pi.outputNoteDataHash0 = arr[14];
        pi.outputNoteDataHash1 = arr[15];
        pi.outputNoteDataHash2 = arr[16];
        pi.authVerifier = arr[17];
        pi.blindedAuthCommitment = arr[18];
        pi.transactionIntentDigest = arr[19];
        pi.policyOperationDataHash = arr[20];
        pi.policyDataHash = arr[21];
        pi.authorizedSubmitter = arr[22];
        pi.downstreamActionCommitment = arr[23];
    }

    /// @dev fail = returns false OR reverts; both are pool-proof failure per section 7.2.
    function _verifyLenient(bytes memory proof, IShieldedPoolStructs.PublicInputs memory pi)
        internal
        view
        returns (bool)
    {
        try verifier.verifyPoolProof(proof, pi) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }

    function test_validTransferProof() public view {
        (bytes memory proof, IShieldedPoolStructs.PublicInputs memory pi) =
            _loadFixture("pool_proof_transfer");
        assertTrue(verifier.verifyPoolProof(proof, pi), "valid transfer proof verifies");
    }

    function test_validWithdrawalProof() public view {
        (bytes memory proof, IShieldedPoolStructs.PublicInputs memory pi) =
            _loadFixture("pool_proof_withdrawal");
        assertTrue(verifier.verifyPoolProof(proof, pi), "valid withdrawal proof verifies");
    }

    function test_validGatedWithdrawalProof() public view {
        (bytes memory proof, IShieldedPoolStructs.PublicInputs memory pi) =
            _loadFixture("pool_proof_withdrawal_gated");
        assertTrue(verifier.verifyPoolProof(proof, pi), "gated withdrawal proof verifies");
    }

    function test_rejectsWrongLengthProof() public view {
        (bytes memory proof, IShieldedPoolStructs.PublicInputs memory pi) =
            _loadFixture("pool_proof_transfer");
        bytes memory truncated = new bytes(255);
        for (uint256 i; i < 255; i++) truncated[i] = proof[i];
        assertFalse(_verifyLenient(truncated, pi), "255-byte proof rejected");
        assertFalse(_verifyLenient(bytes.concat(proof, hex"00"), pi), "257-byte proof rejected");
        assertFalse(_verifyLenient(hex"", pi), "empty proof rejected");
    }

    function test_rejectsBitFlippedProof() public view {
        (bytes memory proof, IShieldedPoolStructs.PublicInputs memory pi) =
            _loadFixture("pool_proof_transfer");
        // flip one bit in each proof element region (A, B, C)
        uint256[3] memory offsets = [uint256(5), 100, 230];
        for (uint256 i; i < 3; i++) {
            bytes memory corrupted = bytes.concat(proof);
            corrupted[offsets[i]] = corrupted[offsets[i]] ^ 0x01;
            assertFalse(_verifyLenient(corrupted, pi), "bit-flipped proof rejected");
        }
    }

    function test_rejectsMutatedPublicInputs() public view {
        (bytes memory proof, IShieldedPoolStructs.PublicInputs memory pi) =
            _loadFixture("pool_proof_transfer");
        IShieldedPoolStructs.PublicInputs memory bad;

        bad = pi;
        bad.noteCommitmentRoot ^= 1;
        assertFalse(_verifyLenient(proof, bad), "mutated root rejected");

        bad = pi;
        bad.nullifier0 ^= 1;
        assertFalse(_verifyLenient(proof, bad), "mutated nullifier rejected");

        bad = pi;
        bad.publicAmountOut += 1;
        assertFalse(_verifyLenient(proof, bad), "mutated amount rejected");

        bad = pi;
        bad.policyDataHash ^= 1;
        assertFalse(_verifyLenient(proof, bad), "mutated policyDataHash rejected");
    }

    function test_rejectsNonCanonicalPublicInput() public view {
        (bytes memory proof, IShieldedPoolStructs.PublicInputs memory pi) =
            _loadFixture("pool_proof_transfer");
        uint256 p = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        IShieldedPoolStructs.PublicInputs memory bad = pi;
        bad.noteCommitmentRoot = bad.noteCommitmentRoot + p; // x + p aliases x mod p
        assertFalse(_verifyLenient(proof, bad), "non-canonical public input rejected");
    }

    function test_swappedPublicInputsRejected() public view {
        (bytes memory proof, IShieldedPoolStructs.PublicInputs memory pi) =
            _loadFixture("pool_proof_transfer");
        IShieldedPoolStructs.PublicInputs memory bad = pi;
        (bad.nullifier0, bad.nullifier1) = (bad.nullifier1, bad.nullifier0);
        assertFalse(_verifyLenient(proof, bad), "swapped nullifiers rejected");
    }

    function test_runtimeSizeUnderEip170() public view {
        assertLt(address(verifier).code.length, 24_576, "verifier must fit EIP-170");
    }
}
