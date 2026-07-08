// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IShieldedPool} from "../../../src/interfaces/IShieldedPool.sol";

/// @notice ERC-20 that attempts to re-enter `pool.deposit` during its own
///         `transferFrom` (invoked from inside the pool's deposit while the
///         reentrancy guard is held). The reentry is caught so the outer deposit
///         can complete; the captured revert selector proves the guard fired.
contract ReentrantToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    IShieldedPool public pool;
    bool public attempted;
    bytes4 public reentryRevertSelector;

    function setPool(IShieldedPool pool_) external {
        pool = pool_;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        attempted = true;
        // Re-enter the pool while it holds the reentrancy guard. The guard runs
        // before any deposit body, so args are irrelevant — it reverts first.
        try pool.deposit(address(this), 1, 1, "", "") {
            reentryRevertSelector = bytes4(0);
        } catch (bytes memory err) {
            reentryRevertSelector = err.length >= 4 ? bytes4(err) : bytes4(0);
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
