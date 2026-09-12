# How `erc20.runtime.hex` was produced

`solc` is on none of the build machines and no test needs it: `ERC20.sol` was compiled **once**,
by hand, with the pinned static release binary below, and only the runtime bytecode is committed.
`make contracts` in `guests-compiled/evm` re-runs the same command when a `solc` *is* on `PATH`
(or `SOLC=/path/to/solc make contracts`) and diffs the result against the committed hex, so a
reviewer can reproduce it without the repo carrying a 32 MB compiler.

## The compiler

| | |
|---|---|
| version | `0.8.37+commit.f401782d.Darwin.appleclang` (`solc --version`) |
| release | <https://github.com/ethereum/solidity/releases/tag/v0.8.37> (2026-09-10, the latest 0.8.x) |
| asset | `solc-macos` (this machine is macOS arm64; `solc-static-linux` is the same release for Linux) |
| download URL | <https://github.com/ethereum/solidity/releases/download/v0.8.37/solc-macos> |
| sha256 of the binary | `a27396e7732aa52e80ff89ad7bd8a2e46fec2a6dcc4ef20cd16e5e0c502d6821` |

The binary itself is **not** in the repo (it lived in the session's scratchpad for the one
compile). The M4.3 plan's brief named 0.8.28; the pinned release is the latest 0.8 line instead,
per the task's instruction, and `ERC20.sol`'s pragma is the exact `0.8.37` that produced the
committed hex.

## The command

Run from `guests-compiled/evm`:

```sh
solc --optimize --optimize-runs 200 --evm-version shanghai --bin-runtime contracts/ERC20.sol
```

The last line of that output is `contracts/erc20.runtime.hex` verbatim (one line, no `0x`).

- `--optimize --optimize-runs 200` — a deployed-contract profile; the plan's figure.
- `--evm-version shanghai` — the machine's EVM subset is Shanghai (the plan's gas schedule and
  opcode list). This matters: on a 0.8.37 default (`prague`) the compiler emits `MCOPY`, which
  the interpreter traps. Shanghai gives `PUSH0` (supported) and no `MCOPY`.
- No `--metadata-hash none`: the 51-byte CBOR metadata trailer is part of the runtime bytecode a
  real chain would hold, it is never executed (it sits after the dispatcher's final `INVALID`),
  and `codehash` binds it, so the committed hex is exactly what a deployment would contain.

## What the bytecode is, and what it needs

1 296 bytes, all of it inside EIP-170's 24 576. Every opcode the reachable code uses is in the
M4.3 subset: `ADD SUB LT GT SLT EQ ISZERO AND SHL SHR KECCAK256 CALLER CALLVALUE CALLDATALOAD
CALLDATASIZE POP MLOAD MSTORE SLOAD SSTORE JUMP JUMPI JUMPDEST PUSH0 PUSHn DUPn SWAPn LOG3
RETURN REVERT INVALID` — no `CALL`, no block context, no `MCOPY`.

There is no constructor to run: `--bin-runtime` is the deployed code, so the state a constructor
would have written (`_balances[ALICE]`, `_totalSupply`) is seeded as storage witnesses in the
pre-state tree instead (`research/src/evm.rs::erc20_transfer`). Because all six functions are
non-payable, `solc` hoists one `CALLVALUE`-is-zero check to the top of the dispatcher: a call with
a non-zero `callvalue` reverts before dispatch, so the fixtures pass zero.
