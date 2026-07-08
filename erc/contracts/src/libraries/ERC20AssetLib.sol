// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library ERC20AssetLib {
    error ERC20CallFailed();
    error ERC20TransferAmountMismatch();

    bytes4 private constant BALANCE_OF_SELECTOR = 0x70a08231;
    bytes4 private constant TRANSFER_SELECTOR = 0xa9059cbb;
    bytes4 private constant TRANSFER_FROM_SELECTOR = 0x23b872dd;

    function balanceOf(address token, address account) internal view returns (uint256 balance) {
        (bool success, bytes memory returnData) = token.staticcall(abi.encodeWithSelector(BALANCE_OF_SELECTOR, account));
        if (!success || returnData.length != 32) revert ERC20CallFailed();
        balance = abi.decode(returnData, (uint256));
    }

    function safeTransfer(address token, address to, uint256 amount) internal {
        _callOptionalBool(token, abi.encodeWithSelector(TRANSFER_SELECTOR, to, amount));
    }

    function safeTransferFrom(address token, address from, address to, uint256 amount) internal {
        _callOptionalBool(token, abi.encodeWithSelector(TRANSFER_FROM_SELECTOR, from, to, amount));
    }

    function pullExact(address token, address from, address to, uint256 amount) internal {
        uint256 balanceBefore = balanceOf(token, to);
        safeTransferFrom(token, from, to, amount);
        uint256 balanceAfter = balanceOf(token, to);
        if (balanceAfter < balanceBefore || balanceAfter - balanceBefore != amount) {
            revert ERC20TransferAmountMismatch();
        }
    }

    function _callOptionalBool(address token, bytes memory data) private {
        (bool success, bytes memory returnData) = token.call(data);
        if (!success) revert ERC20CallFailed();
        if (returnData.length == 0) {
            if (token.code.length == 0) revert ERC20CallFailed();
            return;
        }
        if (returnData.length != 32) revert ERC20CallFailed();
        if (!abi.decode(returnData, (bool))) {
            revert ERC20CallFailed();
        }
    }
}
