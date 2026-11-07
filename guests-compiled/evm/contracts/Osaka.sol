// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.37;

/// The Osaka fixture: `CLZ` (EIP-7939), which solc 0.8.37 accepts in inline assembly from
/// `--evm-version osaka` on. Compiled with `--evm-version osaka`.
contract Osaka {
    function lz(uint256 x) external pure returns (uint256 r) {
        assembly { r := clz(x) }
    }
}
