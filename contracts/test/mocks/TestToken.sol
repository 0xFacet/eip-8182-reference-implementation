// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract TestToken {
    string public name = "Test Token";
    string public symbol = "TEST";
    uint8 public constant decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external virtual returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external virtual returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }

        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal virtual {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }
}

contract FeeOnTransferTestToken is TestToken {
    uint256 public immutable feeBps;

    constructor(uint256 feeBps_) {
        feeBps = feeBps_;
    }

    function _transfer(address from, address to, uint256 amount) internal override {
        uint256 fee = (amount * feeBps) / 10_000;
        uint256 received = amount - fee;

        balanceOf[from] -= amount;
        balanceOf[to] += received;

        emit Transfer(from, to, received);
        if (fee != 0) {
            emit Transfer(from, address(0), fee);
        }
    }
}

contract OverlongBalanceOfToken {
    function balanceOf(address) external pure returns (uint256) {
        assembly {
            mstore(0x00, 0)
            mstore(0x20, 1)
            return(0x00, 0x40)
        }
    }
}

contract OverlongTransferFromReturnToken is TestToken {
    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }

        _transfer(from, to, amount);

        assembly {
            mstore(0x00, 1)
            mstore(0x20, 2)
            return(0x00, 0x40)
        }
    }
}

contract OverlongTransferReturnToken is TestToken {
    function transfer(address to, uint256 amount) external override returns (bool) {
        _transfer(msg.sender, to, amount);

        assembly {
            mstore(0x00, 1)
            mstore(0x20, 2)
            return(0x00, 0x40)
        }
    }
}

contract BalanceDecreaseOnTransferFromToken is TestToken {
    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }

        balanceOf[from] -= amount;
        balanceOf[to] -= 1;
        emit Transfer(from, to, amount);
        return true;
    }
}
