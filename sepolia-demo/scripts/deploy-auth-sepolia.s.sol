// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {HonkVerifier} from "contracts/src/auth/HonkRealAuthVerifier.sol";
import {DemoRealAuthVerifier, IHonkVerifier} from "../src/DemoRealAuthVerifier.sol";

contract DeploySepoliaDemoAuth is Script {
    function run() external {
        address pool = vm.envAddress("DEMO_POOL_ADDRESS");
        address existingHonkVerifier = vm.envOr("DEMO_HONK_VERIFIER", address(0));
        uint256 expectedProofLength = vm.envOr("DEMO_AUTH_PROOF_LENGTH", uint256(9792));

        vm.startBroadcast();
        IHonkVerifier honkVerifier;
        if (existingHonkVerifier == address(0)) {
            honkVerifier = IHonkVerifier(address(new HonkVerifier()));
        } else {
            honkVerifier = IHonkVerifier(existingHonkVerifier);
        }
        DemoRealAuthVerifier authVerifier =
            new DemoRealAuthVerifier(honkVerifier, pool, expectedProofLength);
        vm.stopBroadcast();

        console2.log("HonkVerifier:", address(honkVerifier));
        console2.log("DemoRealAuthVerifier:", address(authVerifier));
        console2.log("Pool:", pool);
        console2.log("ExpectedProofLength:", expectedProofLength);
    }
}
