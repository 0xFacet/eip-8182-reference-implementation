// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Minimal ERC-20 stub used only for the realistic-transact
///         integration test. Etched at the witness's hard-coded
///         tokenAddress (0x2222...) via vm.etch so the deposits and the
///         withdrawal in `transact()` resolve against a real token contract.
contract MockERC20 {
    mapping(address => uint256) private _balances;

    function mint(address to, uint256 amount) external {
        _balances[to] += amount;
    }

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _balances[msg.sender] -= amount;
        _balances[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        _balances[from] -= amount;
        _balances[to] += amount;
        return true;
    }
}
