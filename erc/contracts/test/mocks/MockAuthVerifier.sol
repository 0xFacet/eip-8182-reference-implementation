// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Unit-test double for a section 7.5 auth verifier. `mode` selects the
///         returndata shape so the failure taxonomy (revert / wrong length /
///         false) can be exercised individually.
contract MockAuthVerifier {
    enum Mode {
        ReturnTrue, // 0: 32 bytes decoding to true
        ReturnFalse, // 1: 32 bytes decoding to false
        Revert, // 2: revert
        WrongLength // 3: 31 bytes of returndata
    }

    Mode internal _mode = Mode.ReturnTrue;

    function setMode(Mode mode_) external {
        _mode = mode_;
    }

    /// @dev View so the pool's staticcall succeeds when a bool is returned. The
    ///      assembly return overrides the declared bool ABI to force a 31-byte
    ///      body in WrongLength mode.
    function verifyAuth(bytes calldata, bytes calldata) external view returns (bool) {
        Mode m = _mode;
        if (m == Mode.ReturnTrue) {
            return true;
        }
        if (m == Mode.ReturnFalse) {
            return false;
        }
        if (m == Mode.Revert) {
            revert("MockAuthVerifier: revert");
        }
        // WrongLength: emit exactly 31 bytes.
        assembly ("memory-safe") {
            mstore(0x00, 1)
            return(0x00, 31)
        }
    }
}
