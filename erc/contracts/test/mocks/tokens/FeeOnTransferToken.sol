// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice ERC-20 that skims a fee on transfer so the recipient receives less
///         than `amount`. Incompatible per section 7.4/7.3 step 8: the pool's
///         balance-delta check must reject it.
contract FeeOnTransferToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    uint256 public immutable fee;

    constructor(uint256 fee_) {
        fee = fee_;
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
        uint256 delivered = amount - fee;
        balanceOf[to] += delivered;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }
        balanceOf[from] -= amount;
        uint256 delivered = amount - fee;
        balanceOf[to] += delivered;
        return true;
    }
}
