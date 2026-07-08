// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Test-only external action target for the PublicActionRouter §17
///         swap-reshield path. It produces a realized output that is NOT known
///         at plan time (a haircut / fixed-rate conversion), which is exactly the
///         case the variable-output reshield (DEPOSIT_USES_EVENT_PUBLICS) exists
///         for. Not part of the canonical deployment.
contract MockSwapAdapter {
    /// @notice Consume the forwarded ETH `msg.value`, keep `feeBps` of it, and
    ///         return the remainder to the caller (the router). The realized
    ///         output (`msg.value - fee`) is a runtime value.
    function ethHaircut(uint256 feeBps) external payable {
        uint256 out = msg.value - (msg.value * feeBps) / 10_000;
        (bool ok,) = msg.sender.call{value: out}("");
        require(ok, "eth return failed");
    }

    /// @notice Pull `amountIn` of `tokenIn` from the caller (router must have
    ///         approved), then send `amountOut` of `tokenOut` (from this adapter's
    ///         own reserve) back to the caller.
    function erc20Swap(address tokenIn, uint256 amountIn, address tokenOut, uint256 amountOut) external {
        require(_call(tokenIn, abi.encodeWithSelector(0x23b872dd, msg.sender, address(this), amountIn)), "pull failed"); // transferFrom
        require(_call(tokenOut, abi.encodeWithSelector(0xa9059cbb, msg.sender, amountOut)), "send failed"); // transfer
    }

    function _call(address token, bytes memory data) private returns (bool) {
        (bool ok, bytes memory ret) = token.call(data);
        if (!ok) return false;
        return ret.length == 0 || abi.decode(ret, (bool));
    }

    receive() external payable {}
}
