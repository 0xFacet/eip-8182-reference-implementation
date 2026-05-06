// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {InstallSystemContractsBase} from "../script/InstallSystemContracts.s.sol";
import {PoseidonFieldLib} from "../src/libraries/PoseidonFieldLib.sol";
import {IAuthVerifier} from "../src/interfaces/IAuthVerifier.sol";

contract _AcceptAllAuth is IAuthVerifier {
    function verifyAuth(bytes calldata, bytes calldata) external pure override returns (bool) {
        return true;
    }
}

contract _AcceptAllPool {
    fallback(bytes calldata) external returns (bytes memory) {
        return abi.encode(uint256(1));
    }
}

contract GasBreakdownTest is Test, InstallSystemContractsBase {
    address internal constant PROOF_VERIFY_PRECOMPILE_ADDRESS =
        0x0000000000000000000000000000000000000030;

    ShieldedPool internal pool;
    address internal authVerifierAddr;

    function setUp() public {
        install();
        pool = ShieldedPool(POOL_ADDRESS);

        _AcceptAllPool poolMock = new _AcceptAllPool();
        vm.etch(PROOF_VERIFY_PRECOMPILE_ADDRESS, address(poolMock).code);
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
            ,
            uint256 userRoot,
            uint256 authReg,
            uint256 authRev
        ) = pool.getCurrentRoots();
        (uint256 accRoot, ) = pool.getCurrentHistoricalNoteRootAccumulatorRoot();

        ShieldedPool.PublicInputs memory pi = ShieldedPool.PublicInputs({
            historicalNoteRootAccumulatorRoot: accRoot,
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
