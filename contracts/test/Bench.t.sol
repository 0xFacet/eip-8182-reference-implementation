// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {InstallSystemContractsBase} from "../script/InstallSystemContracts.s.sol";
import {MockPoolPrecompile} from "../src/MockPoolPrecompile.sol";
import {PoolGroth16Verifier} from "../src/PoolGroth16Verifier.sol";
import {RealAuthVerifier} from "../src/auth/RealAuthVerifier.sol";
import {HonkVerifier} from "../src/auth/HonkRealAuthVerifier.sol";
import {DemoAuthVerifier} from "../src/auth/DemoAuthVerifier.sol";
import {AuthDemoGroth16Verifier} from "../src/AuthDemoGroth16Verifier.sol";
import {IAuthVerifier} from "../src/interfaces/IAuthVerifier.sol";
import {PoseidonFieldLib} from "../src/libraries/PoseidonFieldLib.sol";
import {Poseidon2Sponge} from "../src/libraries/Poseidon2Sponge.sol";
import {MockERC20} from "./MockERC20.sol";

/// @notice On-chain gas benchmarks for EIP-8182. Each `test_bench_*` function
///         measures total gas of a user-facing operation in a fresh-state /
///         cold-access setting (so the headline number reflects the cost a
///         first-time user pays), then reverts and re-measures isolated
///         buckets — also from cold — using `vm.cool` to undo any address
///         warming the prior measurements caused.
///
///         Buckets:
///           - Pool proof verify (mocked): the EIP-8182 spec defines a native
///             precompile at 0x...30. We etch `MockPoolPrecompile` (Solidity
///             Groth16 verifier) at that address. The number reported here
///             is therefore an upper bound; a native precompile would charge
///             a fixed gas amount per the spec's gas schedule (TBD).
///           - Auth proof verify: implementer's choice. We bench Honk
///             (UltraHonk via bb's emitted Solidity verifier). Other auth
///             circuits — Groth16, ECDSA-only — produce different numbers.
///           - Asset movement: ETH transfer or ERC-20 transferFrom/transfer.
///           - Pool/auth proof calldata: 16 gas/non-zero, 4 gas/zero per byte
///             of proof bytes. Lets readers see the proof-size cost component
///             separately, since auth proof size scales with verifier choice.
///
///         What's NOT directly bucketed (lumped into the residual):
///         tree insertion (3 leaves at depth 32), nullifier set writes,
///         intent replay set write, output-hash keccaks, history push,
///         event emission, Solidity dispatch, range checks.
///
///         Withdraw benches require pre-built session JSONs (one per mode).
///         To avoid stale files leaking into a default run, the withdraw
///         tests are gated behind the `BENCH_WITHDRAW` env var.
contract BenchTest is Test, InstallSystemContractsBase {
    using stdJson for string;

    address internal constant PROOF_VERIFY_PRECOMPILE_ADDRESS =
        0x0000000000000000000000000000000000000030;

    // Pinned to match scripts/noir/gen_honk_pool_witness_input.js:
    address internal constant SENDER     = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
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
    uint256 internal constant IN0_AMOUNT           = 10;
    uint256 internal constant IN1_AMOUNT           = 5;
    uint256 internal constant IN0_NOTE_SECRET      = 0xDEADBEEF01;
    uint256 internal constant IN1_NOTE_SECRET      = 0xDEADBEEF02;
    uint256 internal constant REGISTRATION_BLINDER = 0xCC00CC00CC00CC00;

    ShieldedPool internal pool;
    RealAuthVerifier internal authVerifierImpl;
    HonkVerifier internal honkVerifier;
    PoolGroth16Verifier internal poolGroth16;
    MockPoolPrecompile internal poolPrecompile;
    MockERC20 internal mockTokenImpl;

    // Groth16 auth verifier used to model the gas a gas-optimized
    // implementer would pay (same proof system as the pool, 2 public inputs).
    DemoAuthVerifier internal demoAuthVerifierImpl;
    AuthDemoGroth16Verifier internal authDemoGroth16Impl;

    function setUp() public {
        vm.chainId(1);
        vm.warp(1735689600 - 600); // witness pins validUntilSeconds = 1735689600

        install();
        pool = ShieldedPool(POOL_ADDRESS);

        poolGroth16 = new PoolGroth16Verifier();
        poolPrecompile = new MockPoolPrecompile(poolGroth16);
        honkVerifier = new HonkVerifier();
        mockTokenImpl = new MockERC20();

        // Groth16 auth verifier (gas-optimized model).
        authDemoGroth16Impl = new AuthDemoGroth16Verifier();
        demoAuthVerifierImpl = new DemoAuthVerifier(authDemoGroth16Impl);

        // Auth wrapper is sized once a session is read (its constructor takes
        // the proof length); transact benches re-deploy after reading their
        // session JSON. The non-transact benches don't dispatch to it.
        vm.etch(PROOF_VERIFY_PRECOMPILE_ADDRESS, address(poolPrecompile).code);
        vm.etch(TOKEN_ADDR, address(mockTokenImpl).code);
    }

    // =========================================================================
    // deposit
    // =========================================================================

    function test_bench_DepositETH() public {
        uint256 amount = 1 ether;
        uint256 commit = uint256(keccak256("eip-8182-bench.deposit-eth")) % PoseidonFieldLib.FIELD_MODULUS;
        bytes memory ond = bytes("bench-eth");
        vm.deal(address(this), amount);

        uint256 g0 = gasleft();
        pool.deposit{value: amount}(address(0), amount, commit, ond);
        uint256 execGas = g0 - gasleft();

        bytes memory cd = abi.encodeCall(pool.deposit, (address(0), amount, commit, ond));
        _writeOpBench("deposit_eth", execGas, _calldataGas(cd));
    }

    function test_bench_DepositERC20() public {
        uint256 amount = 100;
        uint256 commit = uint256(keccak256("eip-8182-bench.deposit-erc20")) % PoseidonFieldLib.FIELD_MODULUS;
        bytes memory ond = bytes("bench-erc20");
        MockERC20(TOKEN_ADDR).mint(address(this), amount);

        // Mint warmed the token address. Cool it before the deposit
        // measurement so the headline reflects a cold-token user tx.
        vm.cool(TOKEN_ADDR);
        uint256 g0 = gasleft();
        pool.deposit(TOKEN_ADDR, amount, commit, ond);
        uint256 execGas = g0 - gasleft();

        // Asset-movement bucket: re-execute the same call shape on cold token.
        vm.cool(TOKEN_ADDR);
        uint256 assetGas = _measureErc20DepositPath(TOKEN_ADDR, amount);

        bytes memory cd = abi.encodeCall(pool.deposit, (TOKEN_ADDR, amount, commit, ond));
        string[] memory keys = new string[](3);
        uint256[] memory vals = new uint256[](3);
        keys[0] = "exec_gas";        vals[0] = execGas;
        keys[1] = "tx_calldata_gas"; vals[1] = _calldataGas(cd);
        keys[2] = "asset";           vals[2] = assetGas;
        _writeBench("deposit_erc20", keys, vals);
    }

    // =========================================================================
    // register
    // =========================================================================

    function test_bench_RegisterUser() public {
        // Cost a first-time user pays to make themselves spendable in the pool.
        uint256 onkHash = PoseidonFieldLib.merkleHash(
            PoseidonFieldLib.OWNER_NULLIFIER_KEY_HASH_DOMAIN,
            uint256(keccak256("eip-8182-bench.register-user.onk"))
        );
        uint256 seedHash = PoseidonFieldLib.noteSecretSeedHash(
            uint256(keccak256("eip-8182-bench.register-user.seed"))
        );
        address actor = address(0xBEEF1);
        vm.prank(actor);
        uint256 g0 = gasleft();
        pool.registerUser(onkHash, seedHash);
        uint256 execGas = g0 - gasleft();

        // registerUser is overloaded; use the explicit (uint256,uint256) selector.
        bytes memory cd = bytes.concat(
            bytes4(keccak256("registerUser(uint256,uint256)")),
            abi.encode(onkHash, seedHash)
        );
        _writeOpBench("register_user", execGas, _calldataGas(cd));
    }

    function test_bench_RegisterAuthPolicy() public {
        // Need the user to be registered first (registerAuthPolicy requires
        // the caller to be in the user registry). The bench doesn't include
        // that registration in the measured number — that's what the
        // register_user bench is for.
        _register(SENDER, SENDER_NULLIFIER_KEY, SENDER_SECRET_SEED);

        uint256 policyCommitment = Poseidon2Sponge.hash4(
            uint256(keccak256("eip-8182.policy_commitment")) % PoseidonFieldLib.FIELD_MODULUS,
            uint256(uint160(AUTH_VERIFIER_ADDR)),
            uint256(keccak256("eip-8182-bench.register-auth-policy.adc")) % PoseidonFieldLib.FIELD_MODULUS,
            REGISTRATION_BLINDER
        );

        vm.prank(SENDER);
        uint256 g0 = gasleft();
        pool.registerAuthPolicy(policyCommitment);
        uint256 execGas = g0 - gasleft();

        bytes memory cd = abi.encodeCall(pool.registerAuthPolicy, (policyCommitment));
        _writeOpBench("register_auth_policy", execGas, _calldataGas(cd));
    }

    // =========================================================================
    // transact (transfer + withdraw)
    // =========================================================================

    function test_bench_Transfer() public {
        if (!_sessionExists("build/integration_honk/session.json")) {
            _writeBenchSkipped("transfer", "build/integration_honk/session.json missing");
            return;
        }
        _runTransactBench("transfer", "build/integration_honk/session.json", AssetMode.NONE);
    }

    function test_bench_WithdrawETH() public {
        if (!_sessionExists("build/integration_honk/withdraw_eth_session.json")) {
            _writeBenchSkipped("withdraw_eth", "build/integration_honk/withdraw_eth_session.json missing");
            return;
        }
        _runTransactBench("withdraw_eth", "build/integration_honk/withdraw_eth_session.json", AssetMode.ETH);
    }

    function test_bench_WithdrawERC20() public {
        if (!_sessionExists("build/integration_honk/withdraw_erc20_session.json")) {
            _writeBenchSkipped(
                "withdraw_erc20",
                "build/integration_honk/withdraw_erc20_session.json missing"
            );
            return;
        }
        _runTransactBench(
            "withdraw_erc20",
            "build/integration_honk/withdraw_erc20_session.json",
            AssetMode.ERC20
        );
    }

    enum AssetMode { NONE, ETH, ERC20 }

    function _runTransactBench(string memory name, string memory sessionPath, AssetMode mode) internal {
        TransactCtx memory ctx = _loadTransactCtx(sessionPath);
        _setupForTransact(ctx, mode);

        uint256 snap = vm.snapshotState();

        // ---- Total (measured first, addresses cooled) ----
        // Setup (registerUser × 3, deposit × 2, registerAuthPolicy) warmed the
        // verifier and token addresses; in production, those would be cold
        // when the transact tx starts. Re-cool them so the total reflects the
        // user-facing cost. Pool address is auto-warm as the call target
        // (matches production). Storage slots warmed by setup remain warm —
        // that residual bias is on the order of 10K gas (~0.2%) and not
        // surfaced separately.
        vm.cool(PROOF_VERIFY_PRECOMPILE_ADDRESS);
        vm.cool(AUTH_VERIFIER_ADDR);
        vm.cool(TOKEN_ADDR);
        uint256 total = _runTransact(ctx);

        // ---- Bucket measurements: revert + cool the touched addresses ----
        vm.revertToState(snap);
        vm.cool(POOL_ADDRESS);
        vm.cool(PROOF_VERIFY_PRECOMPILE_ADDRESS);
        vm.cool(AUTH_VERIFIER_ADDR);
        vm.cool(TOKEN_ADDR);

        uint256 poolVerifyGas = _measurePoolVerify(ctx);
        vm.cool(PROOF_VERIFY_PRECOMPILE_ADDRESS);

        uint256 authVerifyGas = _measureAuthVerify(ctx);
        vm.cool(AUTH_VERIFIER_ADDR);

        uint256 assetGas = 0;
        if (mode == AssetMode.ETH) {
            assetGas = _measureEthTransfer(
                address(uint160(ctx.pi.publicRecipientAddress)),
                ctx.pi.publicAmountOut
            );
        } else if (mode == AssetMode.ERC20) {
            assetGas = _measureErc20Transfer(
                TOKEN_ADDR,
                address(uint160(ctx.pi.publicRecipientAddress)),
                ctx.pi.publicAmountOut
            );
        }

        // Model the gas-optimized auth: a Groth16 verifier with 2 public
        // inputs (same proof system as the pool). For Honk we have a real
        // 9.7 KB proof + 2.6M-gas verifier; for Groth16 we use the existing
        // demo Groth16 auth circuit's proof (256 B, ~250K-gas verifier) which
        // is what a gas-conscious implementer would deploy.
        (bytes memory g16AuthProof, bytes memory g16AuthPub) = _loadDemoAuthProofPublics();
        vm.cool(address(demoAuthVerifierImpl));
        uint256 g16AuthVerifyGas = _measureGroth16AuthVerify(g16AuthPub, g16AuthProof);

        _emitTransactBench(name, ctx, total, poolVerifyGas, authVerifyGas, g16AuthVerifyGas, g16AuthProof, assetGas);
    }

    function _emitTransactBench(
        string memory name,
        TransactCtx memory ctx,
        uint256 execGas,
        uint256 poolVerifyGas,
        uint256 authVerifyHonkGas,
        uint256 authVerifyGroth16Gas,
        bytes memory g16AuthProof,
        uint256 assetGas
    ) internal {
        string[] memory keys = new string[](11);
        uint256[] memory vals = new uint256[](11);
        keys[0]  = "exec_gas";                     vals[0]  = execGas;
        keys[1]  = "tx_calldata_gas_honk";         vals[1]  = _transactCalldataGas(ctx, ctx.authProof);
        keys[2]  = "tx_calldata_gas_groth16";      vals[2]  = _transactCalldataGas(ctx, g16AuthProof);
        keys[3]  = "pool_verify_mocked";           vals[3]  = poolVerifyGas;
        keys[4]  = "auth_verify_honk";             vals[4]  = authVerifyHonkGas;
        keys[5]  = "auth_verify_groth16";          vals[5]  = authVerifyGroth16Gas;
        keys[6]  = "asset_movement";               vals[6]  = assetGas;
        keys[7]  = "pool_calldata_gas";            vals[7]  = _calldataGas(ctx.poolProof);
        keys[8]  = "auth_calldata_gas_honk";       vals[8]  = _calldataGas(ctx.authProof);
        keys[9]  = "auth_calldata_gas_groth16";    vals[9]  = _calldataGas(g16AuthProof);
        keys[10] = "auth_proof_bytes_honk";        vals[10] = ctx.authProof.length;
        _writeBench(name, keys, vals);
    }

    function _transactCalldataGas(TransactCtx memory ctx, bytes memory authProof) internal pure returns (uint256) {
        bytes memory cd = abi.encodeCall(
            ShieldedPool.transact,
            (
                ctx.poolProof,
                authProof,
                ctx.pi,
                bytes("eip-8182-output-0"),
                bytes("eip-8182-output-1"),
                bytes("eip-8182-output-2")
            )
        );
        return _calldataGas(cd);
    }

    function _loadDemoAuthProofPublics() internal returns (bytes memory proof, bytes memory pubInputs) {
        require(_sessionExists("build/integration/session.json"),
            "bench: build/integration/session.json missing; run scripts/integration/build_session.js");
        string memory s = vm.readFile("build/integration/session.json");
        proof = vm.parseBytes(stdJson.readString(s, ".auth.proofHex"));
        require(proof.length == 256, "bench: demo auth proof not 256 B");
        uint256 b = stdJson.readUint(s, ".auth.publicSignals[0]");
        uint256 d = stdJson.readUint(s, ".auth.publicSignals[1]");
        pubInputs = abi.encode(b, d);
    }

    function _measureGroth16AuthVerify(bytes memory pubInputs, bytes memory proof)
        internal
        view
        returns (uint256)
    {
        uint256 g0 = gasleft();
        bool ok = demoAuthVerifierImpl.verifyAuth(pubInputs, proof);
        uint256 used = g0 - gasleft();
        require(ok, "bench: groth16 auth verify must verify (demo session stale?)");
        return used;
    }

    // -------- Loading + setup --------

    struct TransactCtx {
        bytes poolProof;
        bytes authProof;
        ShieldedPool.PublicInputs pi;
        uint256 authDataCommitment;
    }

    function _loadTransactCtx(string memory sessionPath) internal returns (TransactCtx memory ctx) {
        string memory session = vm.readFile(sessionPath);
        ctx.poolProof = vm.parseBytes(stdJson.readString(session, ".pool.proofHex"));
        ctx.authProof = vm.parseBytes(stdJson.readString(session, ".auth.proofHex"));
        ctx.pi = _readPI(session);
        ctx.authDataCommitment = stdJson.readUint(session, ".sidecar.auth_data_commitment_dec");

        authVerifierImpl = new RealAuthVerifier(honkVerifier, ctx.authProof.length);
        vm.etch(AUTH_VERIFIER_ADDR, address(authVerifierImpl).code);
    }

    function _setupForTransact(TransactCtx memory ctx, AssetMode mode) internal {
        _registerSenderAndRecipients();
        if (mode == AssetMode.NONE || mode == AssetMode.ERC20) {
            _depositSenderInputsERC20();
        } else {
            _depositSenderInputsETH();
        }
        if (mode == AssetMode.ETH)   vm.deal(address(pool), ctx.pi.publicAmountOut);
        if (mode == AssetMode.ERC20) MockERC20(TOKEN_ADDR).mint(address(pool), ctx.pi.publicAmountOut);
        _registerAuthPolicyForSender(ctx.authDataCommitment);
    }

    // -------- Setup helpers --------

    function _registerSenderAndRecipients() internal {
        _register(SENDER,     SENDER_NULLIFIER_KEY, SENDER_SECRET_SEED);
        _register(RECIPIENT0, R0_NULLIFIER_KEY,     R0_SECRET_SEED);
        _register(RECIPIENT2, R2_NULLIFIER_KEY,     R2_SECRET_SEED);
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

    function _depositSenderInputsERC20() internal {
        (uint256 oc0, uint256 oc1) = _senderOwnerCommitments();
        MockERC20(TOKEN_ADDR).mint(address(this), IN0_AMOUNT + IN1_AMOUNT);
        pool.deposit(TOKEN_ADDR, IN0_AMOUNT, oc0, "");
        pool.deposit(TOKEN_ADDR, IN1_AMOUNT, oc1, "");
    }

    function _depositSenderInputsETH() internal {
        (uint256 oc0, uint256 oc1) = _senderOwnerCommitments();
        vm.deal(address(this), IN0_AMOUNT + IN1_AMOUNT);
        pool.deposit{value: IN0_AMOUNT}(address(0), IN0_AMOUNT, oc0, "");
        pool.deposit{value: IN1_AMOUNT}(address(0), IN1_AMOUNT, oc1, "");
    }

    function _senderOwnerCommitments() internal pure returns (uint256, uint256) {
        uint256 onk = PoseidonFieldLib.merkleHash(
            PoseidonFieldLib.OWNER_NULLIFIER_KEY_HASH_DOMAIN,
            SENDER_NULLIFIER_KEY
        );
        return (
            Poseidon2Sponge.hash3(PoseidonFieldLib.OWNER_COMMITMENT_DOMAIN, onk, IN0_NOTE_SECRET),
            Poseidon2Sponge.hash3(PoseidonFieldLib.OWNER_COMMITMENT_DOMAIN, onk, IN1_NOTE_SECRET)
        );
    }

    function _registerAuthPolicyForSender(uint256 authDataCommitment) internal {
        uint256 policyCommitment = Poseidon2Sponge.hash4(
            uint256(keccak256("eip-8182.policy_commitment")) % PoseidonFieldLib.FIELD_MODULUS,
            uint256(uint160(AUTH_VERIFIER_ADDR)),
            authDataCommitment,
            REGISTRATION_BLINDER
        );
        vm.prank(SENDER);
        pool.registerAuthPolicy(policyCommitment);
    }

    function _readPI(string memory session) internal pure returns (ShieldedPool.PublicInputs memory pi) {
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

    // -------- Bucket measurement helpers --------

    function _runTransact(TransactCtx memory ctx) internal returns (uint256) {
        bytes memory ond0 = bytes("eip-8182-output-0");
        bytes memory ond1 = bytes("eip-8182-output-1");
        bytes memory ond2 = bytes("eip-8182-output-2");
        uint256 g0 = gasleft();
        pool.transact(ctx.poolProof, ctx.authProof, ctx.pi, ond0, ond1, ond2);
        return g0 - gasleft();
    }

    function _measurePoolVerify(TransactCtx memory ctx) internal view returns (uint256) {
        bytes memory cd = abi.encode(ctx.poolProof, ctx.pi);
        uint256 g0 = gasleft();
        (bool ok, bytes memory ret) = PROOF_VERIFY_PRECOMPILE_ADDRESS.staticcall(cd);
        uint256 used = g0 - gasleft();
        require(ok && ret.length == 32 && abi.decode(ret, (uint256)) == 1, "bench: pool verify fail");
        return used;
    }

    function _measureAuthVerify(TransactCtx memory ctx) internal view returns (uint256) {
        bytes memory pubInputs = abi.encode(
            ctx.pi.blindedAuthCommitment,
            ctx.pi.transactionIntentDigest
        );
        uint256 g0 = gasleft();
        bool ok = IAuthVerifier(AUTH_VERIFIER_ADDR).verifyAuth(pubInputs, ctx.authProof);
        uint256 used = g0 - gasleft();
        require(ok, "bench: auth verify fail");
        return used;
    }

    function _measureEthTransfer(address to, uint256 amount) internal returns (uint256) {
        vm.deal(address(this), amount);
        uint256 g0 = gasleft();
        (bool ok, ) = payable(to).call{value: amount}("");
        uint256 used = g0 - gasleft();
        require(ok, "bench: eth transfer fail");
        return used;
    }

    function _measureErc20Transfer(address token, address to, uint256 amount) internal returns (uint256) {
        MockERC20(token).mint(address(this), amount);
        uint256 g0 = gasleft();
        MockERC20(token).transfer(to, amount);
        return g0 - gasleft();
    }

    /// @dev Mirrors `ShieldedPool.deposit`'s ERC-20 path: balanceOf + pullExact
    /// (which itself does balanceOf + transferFrom + balanceOf) + balanceOf.
    /// 4× balanceOf + 1× transferFrom on a fresh actor + cold token.
    function _measureErc20DepositPath(address token, uint256 amount) internal returns (uint256) {
        address probe = address(0xDEAD2);
        MockERC20(token).mint(probe, amount);
        // mint warmed the token; re-cool so the measurement matches a fresh tx.
        vm.cool(token);
        uint256 g0 = gasleft();
        MockERC20(token).balanceOf(address(this));
        MockERC20(token).balanceOf(address(this));
        vm.prank(probe);
        MockERC20(token).transferFrom(probe, address(this), amount);
        MockERC20(token).balanceOf(address(this));
        MockERC20(token).balanceOf(address(this));
        return g0 - gasleft();
    }

    /// @dev EIP-2028 calldata cost: 16 gas per non-zero byte, 4 gas per zero byte.
    function _calldataGas(bytes memory data) internal pure returns (uint256) {
        uint256 nz;
        for (uint256 i; i < data.length; ++i) {
            if (data[i] != 0) ++nz;
        }
        return 16 * nz + 4 * (data.length - nz);
    }

    // -------- JSON helpers --------

    function _writeBench(string memory name, string[] memory keys, uint256[] memory vals) internal {
        require(keys.length == vals.length, "bench: kv length mismatch");
        string memory body = "";
        for (uint256 i; i < keys.length; ++i) {
            if (i > 0) body = string.concat(body, ",");
            body = string.concat(body, '"', keys[i], '":', vm.toString(vals[i]));
        }
        string memory json = string.concat('{"name":"', name, '","skipped":false,', body, '}');
        vm.writeFile(string.concat("build/bench/raw/", name, ".json"), json);
    }

    function _writeOpBench(string memory name, uint256 execGas, uint256 txCalldataGas) internal {
        string[] memory keys = new string[](2);
        uint256[] memory vals = new uint256[](2);
        keys[0] = "exec_gas";        vals[0] = execGas;
        keys[1] = "tx_calldata_gas"; vals[1] = txCalldataGas;
        _writeBench(name, keys, vals);
    }

    function _writeBenchSkipped(string memory name, string memory reason) internal {
        string memory json = string.concat(
            '{"name":"', name, '","skipped":true,"reason":"', reason, '"}'
        );
        vm.writeFile(string.concat("build/bench/raw/", name, ".json"), json);
    }

    function _sessionExists(string memory path) internal view returns (bool) {
        try vm.fsMetadata(path) returns (Vm.FsMetadata memory) {
            return true;
        } catch {
            return false;
        }
    }
}
