// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {DemoShieldedPool} from "../src/DemoShieldedPool.sol";
import {RecipientRegistry} from "../src/RecipientRegistry.sol";

/// @notice Deploys only the demo contracts that do not depend on a regenerated
///         pool-address-specific Noir auth verifier.
contract DeploySepoliaDemoBase is Script {
    function run() external {
        vm.startBroadcast();
        DemoShieldedPool pool = new DemoShieldedPool();
        RecipientRegistry registry = new RecipientRegistry();
        vm.stopBroadcast();

        console2.log("DemoShieldedPool:", address(pool));
        console2.log("RecipientRegistry:", address(registry));
    }
}
