// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {InstallSystemContractsBase} from "../script/InstallSystemContracts.s.sol";
import {PoseidonFieldLib} from "../src/libraries/PoseidonFieldLib.sol";
import {IAuthVerifier} from "../src/interfaces/IAuthVerifier.sol";
import {ShieldedPoolAcceptAllHarness} from "./ShieldedPoolAcceptAllHarness.sol";

contract _AcceptAllAuth is IAuthVerifier {
    function verifyAuth(bytes calldata, bytes calldata) external pure override returns (bool) {
        return true;
    }
}

contract GasBreakdownTest is Test, InstallSystemContractsBase {
    ShieldedPool internal pool;
    address internal authVerifierAddr;

    function setUp() public {
        install();
        // Replace the production ShieldedPool runtime at POOL_ADDRESS with the
        // accept-all harness, so `_verifyPoolProof` is a no-op and we can
        // measure gas without supplying a real Groth16 proof. State is
        // preserved because vm.etch only swaps code.
        vm.etch(POOL_ADDRESS, type(ShieldedPoolAcceptAllHarness).runtimeCode);
        pool = ShieldedPool(POOL_ADDRESS);

        _AcceptAllAuth authMock = new _AcceptAllAuth();
        authVerifierAddr = address(authMock);
    }

    function testGas_RegisterUser() public {
        vm.prank(address(0xAAAA));
        uint256 gasBefore = gasleft();
        pool.registerUser(0xa1, 0xa2);
        uint256 used = gasBefore - gasleft();
        emit log_named_uint("registerUser gas", used);
    }

    function testGas_RegisterAuthPolicy() public {
        vm.prank(address(0xAAAA));
        pool.registerUser(0xa1, 0xa2);

        vm.prank(address(0xAAAA));
        uint256 gasBefore = gasleft();
        pool.registerAuthPolicy(0xa3);
        uint256 used = gasBefore - gasleft();
        emit log_named_uint("registerAuthPolicy gas", used);
    }

    function testGas_Deposit() public {
        vm.deal(address(this), 1 ether);
        uint256 gasBefore = gasleft();
        pool.deposit{value: 1 ether}(address(0), 1 ether, 0xc0ffee, "");
        uint256 used = gasBefore - gasleft();
        emit log_named_uint("deposit (ETH) gas", used);
    }

    function testGas_Transact() public {
        // Register prerequisite state cheaply.
        vm.prank(address(0xAAAA));
        pool.registerUser(0xa1, 0xa2);
        vm.prank(address(0xAAAA));
        pool.registerAuthPolicy(0xa3);

        (
            uint256 noteRoot,
            uint256 userRoot,
            uint256 authReg,
            uint256 authRev
        ) = pool.getCurrentRoots();

        ShieldedPool.PublicInputs memory pi = ShieldedPool.PublicInputs({
            noteCommitmentRoot: noteRoot,
            nullifier0: 0x111,
            nullifier1: 0x222,
            noteBodyCommitment0: 0xb1,
            noteBodyCommitment1: 0xb2,
            noteBodyCommitment2: 0xb3,
            publicAmountOut: 0,
            publicRecipientAddress: 0,
            publicTokenAddress: 0,
            intentReplayId: 0xdeadbeef,
            registryRoot: userRoot,
            validUntilSeconds: uint256(block.timestamp + 600),
            executionChainId: block.chainid,
            authPolicyRegistrationRoot: authReg,
            authPolicyRevocationRoot: authRev,
            outputNoteDataHash0: uint256(keccak256("o0")) % PoseidonFieldLib.FIELD_MODULUS,
            outputNoteDataHash1: uint256(keccak256("o1")) % PoseidonFieldLib.FIELD_MODULUS,
            outputNoteDataHash2: uint256(keccak256("o2")) % PoseidonFieldLib.FIELD_MODULUS,
            authVerifier: uint256(uint160(authVerifierAddr)),
            blindedAuthCommitment: 0xc0ffee,
            transactionIntentDigest: 0xb16b00b5
        });

        bytes memory dummyProof = new bytes(256);
        bytes memory dummyAuth = new bytes(256);

        uint256 gasBefore = gasleft();
        pool.transact(dummyProof, dummyAuth, pi, "o0", "o1", "o2");
        uint256 used = gasBefore - gasleft();
        emit log_named_uint("transact (mocked verifiers) gas", used);
    }
}
