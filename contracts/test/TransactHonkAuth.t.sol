// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {InstallSystemContractsBase} from "../script/InstallSystemContracts.s.sol";
import {MockPoolPrecompile} from "../src/MockPoolPrecompile.sol";
import {PoolGroth16Verifier} from "../src/PoolGroth16Verifier.sol";
import {RealAuthVerifier} from "../src/auth/RealAuthVerifier.sol";
import {HonkVerifier} from "../src/auth/HonkRealAuthVerifier.sol";
import {PoseidonFieldLib} from "../src/libraries/PoseidonFieldLib.sol";
import {Poseidon2Sponge} from "../src/libraries/Poseidon2Sponge.sol";
import {MockERC20} from "./MockERC20.sol";

/// @notice End-to-end transact() against the realistic Honk auth circuit:
///         pool proof (Groth16/BN254, mock precompile) + auth proof
///         (UltraHonk via bb, deployed Solidity verifier). Mirrors
///         TransactDemoAuth.t.sol's structure but with RealAuthVerifier
///         instead of DemoAuthVerifier. Reads
///         build/integration_honk/session.json (produced by
///         scripts/integration/build_honk_session.js).
contract TransactHonkAuthTest is Test, InstallSystemContractsBase {
    using stdJson for string;

    address internal constant PROOF_VERIFY_PRECOMPILE_ADDRESS =
        0x0000000000000000000000000000000000000030;

    // --- Pinned witness identities (must match scripts/noir/gen_honk_pool_witness_input.js) ---
    // Sender == authorizing address == pubkey-derived ethereum address of the
    // deterministic test keypair (Anvil's account #1 private key).
    address internal constant SENDER = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;

    // Recipients that pool gen reuses verbatim from the demo flow.
    address internal constant RECIPIENT0 = 0x3333333333333333333333333333333333333333;
    address internal constant RECIPIENT2 = 0x4444444444444444444444444444444444444444;

    address internal constant TOKEN_ADDR = 0x2222222222222222222222222222222222222222;
    address internal constant AUTH_VERIFIER_ADDR = 0x8182aaaa8182aaAA8182AaAa8182aAAa8182aAaa;

    uint256 internal constant SENDER_NULLIFIER_KEY = 0xCAFE0001;
    uint256 internal constant SENDER_SECRET_SEED   = 0xCAFE0002;
    uint256 internal constant R0_NULLIFIER_KEY     = 0xBABE0001;
    uint256 internal constant R0_SECRET_SEED       = 0xC0DE01;
    uint256 internal constant R2_NULLIFIER_KEY     = 0xBABE0003;
    uint256 internal constant R2_SECRET_SEED       = 0xC0DE03;

    uint256 internal constant IN0_AMOUNT       = 10;
    uint256 internal constant IN1_AMOUNT       = 5;
    uint256 internal constant IN0_NOTE_SECRET  = 0xDEADBEEF01;
    uint256 internal constant IN1_NOTE_SECRET  = 0xDEADBEEF02;

    uint256 internal constant REGISTRATION_BLINDER = 0xCC00CC00CC00CC00;
    // Pubkey-derived authDataCommitment is read from session.json's sidecar
    // at runtime (set in setUp) so changes to the auth circuit's auth-data
    // commitment formula don't require updating a pinned constant here.
    uint256 internal authDataCommitment;

    ShieldedPool internal pool;
    RealAuthVerifier internal authVerifierImpl;
    HonkVerifier internal honkVerifier;
    PoolGroth16Verifier internal poolGroth16;
    MockPoolPrecompile internal poolPrecompile;
    MockERC20 internal mockTokenImpl;

    string internal session;

    bool internal sessionAvailable;

    function setUp() public {
        vm.chainId(1);
        // The witness pins validUntilSeconds = 1735689600.
        vm.warp(1735689600 - 600);

        install();
        pool = ShieldedPool(POOL_ADDRESS);

        poolGroth16 = new PoolGroth16Verifier();
        poolPrecompile = new MockPoolPrecompile(poolGroth16);
        honkVerifier = new HonkVerifier();
        mockTokenImpl = new MockERC20();

        // Honk session is produced by scripts/integration/build_honk_session.js,
        // which requires bb/nargo. Gracefully skip the test when it isn't
        // present so `forge test` works without those binaries installed.
        try vm.readFile("build/integration_honk/session.json") returns (string memory s) {
            session = s;
            sessionAvailable = true;
            bytes memory authProofBytes = vm.parseBytes(stdJson.readString(session, ".auth.proofHex"));
            authVerifierImpl = new RealAuthVerifier(honkVerifier, authProofBytes.length);
            authDataCommitment = stdJson.readUint(session, ".sidecar.auth_data_commitment_dec");
            vm.etch(AUTH_VERIFIER_ADDR, address(authVerifierImpl).code);
        } catch {
            sessionAvailable = false;
        }

        vm.etch(PROOF_VERIFY_PRECOMPILE_ADDRESS, address(poolPrecompile).code);
        vm.etch(TOKEN_ADDR, address(mockTokenImpl).code);
    }

    function testTransactHonkAuthSucceeds() public {
        if (!sessionAvailable) {
            emit log("build/integration_honk/session.json missing; skipping (run scripts/integration/build_honk_session.js)");
            return;
        }
        _register(SENDER,     SENDER_NULLIFIER_KEY, SENDER_SECRET_SEED);
        _register(RECIPIENT0, R0_NULLIFIER_KEY,     R0_SECRET_SEED);
        _register(RECIPIENT2, R2_NULLIFIER_KEY,     R2_SECRET_SEED);

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

        MockERC20(TOKEN_ADDR).mint(address(this), IN0_AMOUNT + IN1_AMOUNT);
        pool.deposit(TOKEN_ADDR, IN0_AMOUNT, ownerCommitment0, "");
        pool.deposit(TOKEN_ADDR, IN1_AMOUNT, ownerCommitment1, "");

        // Realistic policyCommitment uses the pubkey-derived authDataCommitment.
        uint256 policyCommitment = Poseidon2Sponge.hash4(
            uint256(keccak256("eip-8182.policy_commitment")) % PoseidonFieldLib.FIELD_MODULUS,
            uint256(uint160(AUTH_VERIFIER_ADDR)),
            authDataCommitment,
            REGISTRATION_BLINDER
        );
        vm.prank(SENDER);
        uint256 leafPosition = pool.registerAuthPolicy(policyCommitment);
        assertEq(leafPosition, 0, "first auth registration must land at slot 0");

        ShieldedPool.PublicInputs memory pi = _readPublicInputs();

        (
            uint256 onChainNoteRoot,
            uint256 onChainRegistryRoot,
            uint256 onChainAuthRegRoot,
            uint256 onChainAuthRevRoot
        ) = pool.getCurrentRoots();
        (uint256 onChainAccRoot, ) =
            pool.getCurrentHistoricalNoteRootAccumulatorRoot();
        assertEq(onChainAccRoot, pi.historicalNoteRootAccumulatorRoot,
            "historical note-root accumulator root mismatch");
        assertEq(onChainRegistryRoot, pi.registryRoot,
            "user registry root mismatch");
        assertEq(onChainAuthRegRoot, pi.authPolicyRegistrationRoot,
            "auth-policy registration root mismatch");
        assertEq(onChainAuthRevRoot, pi.authPolicyRevocationRoot,
            "auth-policy revocation root mismatch");

        bytes memory poolProof = vm.parseBytes(stdJson.readString(session, ".pool.proofHex"));
        bytes memory authProof = vm.parseBytes(stdJson.readString(session, ".auth.proofHex"));

        bytes memory ond0 = bytes("eip-8182-output-0");
        bytes memory ond1 = bytes("eip-8182-output-1");
        bytes memory ond2 = bytes("eip-8182-output-2");

        vm.recordLogs();
        uint256 gasBefore = gasleft();
        pool.transact(poolProof, authProof, pi, ond0, ond1, ond2);
        uint256 gasUsed = gasBefore - gasleft();
        emit log_named_uint("transact() gas (full)", gasUsed);

        assertTrue(pool.isNullifierSpent(pi.nullifier0), "nullifier0 must be marked spent");
        assertTrue(pool.isNullifierSpent(pi.nullifier1), "nullifier1 must be marked spent");
        assertTrue(pool.isIntentReplayIdUsed(pi.intentReplayId), "intentReplayId must be consumed");
        (uint256 noteRootAfter,,,) = pool.getCurrentRoots();
        assertTrue(noteRootAfter != onChainNoteRoot, "note root must advance");
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
        pi.nullifier0                 = ps[1];
        pi.nullifier1                 = ps[2];
        pi.noteBodyCommitment0        = ps[3];
        pi.noteBodyCommitment1        = ps[4];
        pi.noteBodyCommitment2        = ps[5];
        pi.publicAmountOut            = ps[6];
        pi.publicRecipientAddress     = ps[7];
        pi.publicTokenAddress         = ps[8];
        pi.intentReplayId             = ps[9];
        pi.registryRoot               = ps[10];
        pi.validUntilSeconds          = ps[11];
        pi.executionChainId           = ps[12];
        pi.authPolicyRegistrationRoot = ps[13];
        pi.authPolicyRevocationRoot   = ps[14];
        pi.outputNoteDataHash0        = ps[15];
        pi.outputNoteDataHash1        = ps[16];
        pi.outputNoteDataHash2        = ps[17];
        pi.authVerifier               = ps[18];
        pi.blindedAuthCommitment      = ps[19];
        pi.transactionIntentDigest    = ps[20];
    }
}
