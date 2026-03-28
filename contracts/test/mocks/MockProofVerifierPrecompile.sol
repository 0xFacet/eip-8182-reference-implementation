// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ShieldedPool} from "../../src/ShieldedPool.sol";

contract MockProofVerifierPrecompile {
    fallback(bytes calldata input) external returns (bytes memory output) {
        (bytes memory proof,) = abi.decode(input, (bytes, ShieldedPool.PublicInputs));

        if (proof.length == 1 && proof[0] == bytes1(0x00)) {
            return bytes("");
        }

        return abi.encode(uint256(1));
    }
}
