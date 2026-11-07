// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.37;

/// The Cancun fixture: a counter behind a reentrancy lock held in transient storage (`TSTORE`/
/// `TLOAD`, EIP-1153), and a memory-to-memory bytes copy (`bytes.concat`, which solc lowers to
/// `MCOPY`, EIP-5656, from `--evm-version cancun` on). Compiled with `--evm-version cancun`.
contract Cancun {
    /// Transient slot 0: never in the storage tree, empty at the start of every call.
    uint256 transient locked;
    /// Storage slot 0.
    uint256 public counter;

    modifier nonReentrant() {
        require(locked == 0, "reentrant");
        locked = 1;
        _;
        locked = 0;
    }

    /// Bumps the counter under the lock and returns it with `data` twice over.
    function bump(bytes calldata data) external nonReentrant returns (uint256, bytes memory) {
        counter += 1;
        bytes memory m = data;
        return (counter, bytes.concat(m, m));
    }

    /// Whether the lock is held (always false outside `bump`, and in a fresh call).
    function isLocked() external view returns (bool) {
        return locked != 0;
    }
}
