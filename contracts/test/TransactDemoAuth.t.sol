// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {InstallSystemContractsBase} from "../script/InstallSystemContracts.s.sol";
import {MockPoolPrecompile} from "../src/MockPoolPrecompile.sol";
import {PoolGroth16Verifier} from "../src/PoolGroth16Verifier.sol";
import {AuthDemoGroth16Verifier} from "../src/AuthDemoGroth16Verifier.sol";
import {DemoAuthVerifier} from "../src/auth/DemoAuthVerifier.sol";
import {PoseidonFieldLib} from "../src/libraries/PoseidonFieldLib.sol";
import {Poseidon2Sponge} from "../src/libraries/Poseidon2Sponge.sol";
import {MockERC20} from "./MockERC20.sol";

/// @notice End-to-end transact() against the demo Groth16 auth circuit:
///         mirrors the worst-case witness from
///         scripts/witness/gen_pool_witness_input.js. Sets up registry
///         leaves, deposits the two input notes, registers one auth policy,
///         then submits the pool + auth proofs from
///         build/integration/session.json and asserts the receipt.
contract TransactDemoAuthTest is Test, InstallSystemContractsBase {
    using stdJson for string;

    address internal constant PROOF_VERIFY_PRECOMPILE_ADDRESS =
        0x0000000000000000000000000000000000000030;

    // Hard-coded witness identities — must match
    // scripts/witness/gen_pool_witness_input.js.
    address internal constant SENDER       = 0x1111111111111111111111111111111111111111;
    address internal constant RECIPIENT0   = 0x3333333333333333333333333333333333333333;
    address internal constant RECIPIENT2   = 0x4444444444444444444444444444444444444444;
    address internal constant TOKEN_ADDR   = 0x2222222222222222222222222222222222222222;
    address internal constant AUTH_VERIFIER_ADDR = 0xA1A1a1a1A1A1A1A1A1a1a1a1a1a1A1A1a1A1a1a1;

    uint256 internal constant SENDER_NULLIFIER_KEY  = 0xCAFE0001;
    uint256 internal constant SENDER_SECRET_SEED    = 0xCAFE0002;
    uint256 internal constant R0_NULLIFIER_KEY      = 0xBABE0001;
    uint256 internal constant R0_SECRET_SEED        = 0xC0DE01;
    uint256 internal constant R2_NULLIFIER_KEY      = 0xBABE0003;
    uint256 internal constant R2_SECRET_SEED        = 0xC0DE03;

    uint256 internal constant IN0_AMOUNT = 10;
    uint256 internal constant IN1_AMOUNT = 5;
    uint256 internal constant IN0_NOTE_SECRET = 0xDEADBEEF01;
    uint256 internal constant IN1_NOTE_SECRET = 0xDEADBEEF02;

    uint256 internal constant AUTH_SECRET           = 0xA0701337;
    uint256 internal constant REGISTRATION_BLINDER  = 0xCC00CC00CC00CC00;

    ShieldedPool internal pool;
    DemoAuthVerifier internal authVerifierImpl;
    AuthDemoGroth16Verifier internal authGroth16;
    PoolGroth16Verifier internal poolGroth16;
    MockPoolPrecompile internal poolPrecompile;
    MockERC20 internal mockTokenImpl;

    string internal session;

    function setUp() public {
        vm.chainId(1);
        // The witness pins validUntilSeconds = 1735689600 (Jan 1 2025 UTC).
        // Warp the test chain to a few hours before that.
        vm.warp(1735689600 - 600);

        install();
        pool = ShieldedPool(POOL_ADDRESS);

        poolGroth16 = new PoolGroth16Verifier();
        poolPrecompile = new MockPoolPrecompile(poolGroth16);
        authGroth16 = new AuthDemoGroth16Verifier();
        authVerifierImpl = new DemoAuthVerifier(authGroth16);
        mockTokenImpl = new MockERC20();

        // Etch the precompile bytecode at the canonical address. The baked
        // immutable in MockPoolPrecompile keeps pointing at the deployed
        // verifier instance after etching.
        vm.etch(PROOF_VERIFY_PRECOMPILE_ADDRESS, address(poolPrecompile).code);

        // Etch DemoAuthVerifier at the witness-baked authVerifier address so
        // that publicInputs.authVerifier resolves to a working verifier.
        vm.etch(AUTH_VERIFIER_ADDR, address(authVerifierImpl).code);

        // Etch a mock ERC-20 at the witness-baked token address.
        vm.etch(TOKEN_ADDR, address(mockTokenImpl).code);

        session = vm.readFile("build/integration/session.json");
    }

    function testTransactDemoAuthSucceeds() public {
        // 1. Register sender + the two non-self recipients with the same
        //    nullifier-key + seed values the witness used.
        _register(SENDER, SENDER_NULLIFIER_KEY, SENDER_SECRET_SEED);
        _register(RECIPIENT0, R0_NULLIFIER_KEY, R0_SECRET_SEED);
        _register(RECIPIENT2, R2_NULLIFIER_KEY, R2_SECRET_SEED);

        // 2. Deposit the two input notes the witness will spend, into leaf
        //    indices 0 and 1.
        uint256 senderOnkHash = PoseidonFieldLib.merkleHash(
            PoseidonFieldLib.OWNER_NULLIFIER_KEY_HASH_DOMAIN,
            SENDER_NULLIFIER_KEY
        );
        uint256 ownerCommitment0 = Poseidon2Sponge.hash3(
            uint256(keccak256("eip-8182.owner_commitment")) % PoseidonFieldLib.FIELD_MODULUS,
            senderOnkHash,
            IN0_NOTE_SECRET
        );
        uint256 ownerCommitment1 = Poseidon2Sponge.hash3(
            uint256(keccak256("eip-8182.owner_commitment")) % PoseidonFieldLib.FIELD_MODULUS,
            senderOnkHash,
            IN1_NOTE_SECRET
        );

        // Mint the depositor's balance, then approve + deposit. The depositor
        // can be anyone — `deposit()` doesn't gate on identity.
        MockERC20(TOKEN_ADDR).mint(address(this), IN0_AMOUNT + IN1_AMOUNT);
        pool.deposit(TOKEN_ADDR, IN0_AMOUNT, ownerCommitment0, "");
        pool.deposit(TOKEN_ADDR, IN1_AMOUNT, ownerCommitment1, "");

        // 3. Register one auth policy at leafPosition 0 with policyCommitment
        //    matching the witness.
        uint256 authDataCommitment = Poseidon2Sponge.hashPair(
            uint256(keccak256("eip-8182.policy_commitment")) % PoseidonFieldLib.FIELD_MODULUS,
            AUTH_SECRET
        );
        uint256 policyCommitment = Poseidon2Sponge.hash4(
            uint256(keccak256("eip-8182.policy_commitment")) % PoseidonFieldLib.FIELD_MODULUS,
            uint256(uint160(AUTH_VERIFIER_ADDR)),
            authDataCommitment,
            REGISTRATION_BLINDER
        );
        vm.prank(SENDER);
        uint256 leafPosition = pool.registerAuthPolicy(policyCommitment);
        assertEq(leafPosition, 0, "first auth registration must land at slot 0");

        // 4. Sanity-check: roots match what the witness was generated against.
        ShieldedPool.PublicInputs memory pi = _readPublicInputs();
        (
            uint256 onChainNoteRoot,
            uint256 onChainRegistryRoot,
            uint256 onChainAuthRegRoot,
            uint256 onChainAuthRevRoot
        ) = pool.getCurrentRoots();
        (uint256 onChainAccRoot, uint32 onChainAccNextIndex) =
            pool.getCurrentHistoricalNoteRootAccumulatorRoot();
        assertEq(onChainAccRoot, pi.historicalNoteRootAccumulatorRoot,
            "historical note-root accumulator root mismatch (witness vs contract)");
        assertEq(uint256(onChainAccNextIndex), 2,
            "expected two accumulator leaves after two deposits");
        assertEq(onChainRegistryRoot, pi.registryRoot,
            "user registry root mismatch");
        assertEq(onChainAuthRegRoot, pi.authPolicyRegistrationRoot,
            "auth-policy registration root mismatch");
        assertEq(onChainAuthRevRoot, pi.authPolicyRevocationRoot,
            "auth-policy revocation root mismatch");
        // Use onChainNoteRoot for a sanity assertion that the note tree did
        // advance with both deposits (private to the prover, no spend role).
        assertTrue(onChainNoteRoot != 0, "note tree must have post-deposit root");

        // 5. Submit the proof.
        bytes memory poolProof = vm.parseBytes(stdJson.readString(session, ".pool.proofHex"));
        bytes memory authProof = vm.parseBytes(stdJson.readString(session, ".auth.proofHex"));

        // outputNoteData strings must match what the witness keccak'd into
        // outputNoteDataHash{0,1,2}.
        bytes memory ond0 = bytes("eip-8182-output-0");
        bytes memory ond1 = bytes("eip-8182-output-1");
        bytes memory ond2 = bytes("eip-8182-output-2");

        vm.recordLogs();
        pool.transact(poolProof, authProof, pi, ond0, ond1, ond2);

        // 6. Post-state assertions.
        assertTrue(pool.isNullifierSpent(pi.nullifier0), "nullifier0 must be marked spent");
        assertTrue(pool.isNullifierSpent(pi.nullifier1), "nullifier1 must be marked spent");
        assertTrue(pool.isIntentReplayIdUsed(pi.intentReplayId), "intentReplayId must be consumed");
        (uint256 noteRootAfter,,,) = pool.getCurrentRoots();
        assertTrue(noteRootAfter != onChainNoteRoot, "note root must advance after transact");
        (uint256 accRootAfter, uint32 accNextIndexAfter) =
            pool.getCurrentHistoricalNoteRootAccumulatorRoot();
        assertTrue(accRootAfter != onChainAccRoot, "accumulator root must advance after transact");
        assertEq(uint256(accNextIndexAfter), 3, "transact appends one accumulator leaf");
    }

    function _register(address user, uint256 nullifierKey, uint256 noteSecretSeed) private {
        uint256 onkHash = PoseidonFieldLib.merkleHash(
            PoseidonFieldLib.OWNER_NULLIFIER_KEY_HASH_DOMAIN,
            nullifierKey
        );
        uint256 seedHash = PoseidonFieldLib.noteSecretSeedHash(noteSecretSeed);
        vm.prank(user);
        pool.registerUser(onkHash, seedHash);
    }

    function _readPublicInputs() private view returns (ShieldedPool.PublicInputs memory pi) {
        uint256[] memory ps = new uint256[](21);
        for (uint256 i; i < 21; ++i) {
            ps[i] = stdJson.readUint(
                session, string.concat(".pool.publicSignals[", vm.toString(i), "]")
            );
        }
        pi.historicalNoteRootAccumulatorRoot = ps[0];
        pi.nullifier0 = ps[1];
        pi.nullifier1 = ps[2];
        pi.noteBodyCommitment0 = ps[3];
        pi.noteBodyCommitment1 = ps[4];
        pi.noteBodyCommitment2 = ps[5];
        pi.publicAmountOut = ps[6];
        pi.publicRecipientAddress = ps[7];
        pi.publicTokenAddress = ps[8];
        pi.intentReplayId = ps[9];
        pi.registryRoot = ps[10];
        pi.validUntilSeconds = ps[11];
        pi.executionChainId = ps[12];
        pi.authPolicyRegistrationRoot = ps[13];
        pi.authPolicyRevocationRoot = ps[14];
        pi.outputNoteDataHash0 = ps[15];
        pi.outputNoteDataHash1 = ps[16];
        pi.outputNoteDataHash2 = ps[17];
        pi.authVerifier = ps[18];
        pi.blindedAuthCommitment = ps[19];
        pi.transactionIntentDigest = ps[20];
    }
}
