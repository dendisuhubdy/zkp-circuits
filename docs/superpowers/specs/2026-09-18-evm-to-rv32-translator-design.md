# `evm2rv` — the Solidity bytecode to RV32 translator (v0.4, piece 3 of 3)

Status: **approved by the user 2026-09-18; spec written, plan after piece 1's plan.** Runs as a
parallel track with piece 2 once `rand-guest` (piece 1) exists.

Related: `docs/superpowers/specs/2026-09-18-rand-guest-toolchain-design.md` (the pipeline),
`guests-compiled/evm-core/` (the interpreter this must agree with byte for byte on the public
output: `interp.rs`, `u256.rs`, `storage.rs`, `abi.rs`), `research/docs/04-guests.md` ("The
Solidity path", the coprocessor table), `research/docs/01-isa.md`.

## 1. What this is

The EVM interpreter proves a Solidity contract by running its bytecode opcode by opcode inside
the zkVM: an ERC-20 transfer costs 121 638 executed cycles over 18 009 program words, most of
it dispatch. This translator compiles the bytecode to native RV32IM ahead of time. The chain
sees the same object as before: the translated program reuses the interpreter's ABI harness, so
it takes the same input vector (calldata, environment, storage witnesses) and publishes the same
`EVM_OUT` digest with the same status word (1 success, 0 revert, 2 trap) and the same gas
accounting. Translation is off-chain (user ruling 2026-09-18); the developer runs `evm2rv`, then
`rand-guest build`, then deploys.

```
contract.bin (EVM bytecode, solc) ──▶ evm2rv ──▶ <name>/ ├── contract.c   (the translated blocks)
                                                       ├── Cargo.toml   (shim: evm-core + guest-sdk + cc)
                                                       └── src/main.rs  (run_call with the translated entry)
                                   ──▶ rand-guest build ──▶ image.bin ──▶ rand program deploy
```

## 2. Input

EVM bytecode up to the interpreter's `MAX_CODE_BYTES` (24 KiB), as `solc` emits it (the
runtime bytecode, not the creation code). The translator computes the same jumpdest bitmap the
interpreter computes (`scan_jumpdests`: a `JUMPDEST` inside a `PUSHn` immediate is not a
destination). The code hash the digest binds is not the translator's: the harness hashes the
input vector's code, as the interpreter does (§6).

## 3. Stage one: the memory-stack translation

**Blocks.** The code is split into basic blocks at every `JUMPDEST` and after every `JUMP`,
`JUMPI`, `STOP`, `RETURN`, `REVERT`, `INVALID` and `SELFDESTRUCT`. Each block is a C label;
falling off the end of the code is `STOP`, as in the interpreter.

**The stack.** A 1024-entry array of `u256` (eight `uint32_t` limbs) in the shim's `.bss` with
a depth counter. Every opcode checks its pops and pushes against the depth (underflow and
overflow trap, status 2) exactly where the interpreter does; the check is emitted per block as
one comparison against the block's minimum depth and maximum growth, computed at translation,
so the per-opcode checks disappear in straight-line code.

**Opcodes.** Each is an inline C sequence on the stack array or a call into the runtime (§5):

| group | translation |
|---|---|
| arithmetic, comparison, bitwise, shifts, `SIGNEXTEND`, `BYTE`, `EXP`, `ADDMOD`, `MULMOD` | runtime calls into the eight-limb library (the interpreter's `u256.rs` semantics, ported to C) |
| `PUSH0..32`, `DUP1..16`, `SWAP1..16`, `POP` | inline array moves; a `PUSHn` immediate is a constant |
| `MLOAD`, `MSTORE`, `MSTORE8`, `MSIZE`, `CALLDATALOAD`, `CALLDATACOPY`, `CODECOPY`, `RETURNDATACOPY`, `KECCAK256` | runtime calls over the interpreter's memory model, with memory expansion charged as it charges it; `KECCAK256` on the coprocessor via the SDK |
| `SLOAD`, `SSTORE` | runtime calls into the interpreter's Merkle-witness `StorageTree` (Rust, exposed to C by `extern "C"` shims), including the warm/cold and refund rules |
| `JUMP`, `JUMPI` | `switch (dest_low_word) { case <pc>: goto L_<pc>; … default: trap(BadJump) }` over the jumpdest set, after checking the high limbs are zero; `JUMPI` tests the condition first |
| `PC`, `JUMPDEST`, `GAS` | a constant; nothing (its gas is charged); the runtime's gas counter |
| environment: `ADDRESS`, `CALLER`, `CALLVALUE`, `CALLDATASIZE`, `CODESIZE`, `RETURNDATASIZE` | the decoded call's `Env`, calldata and code, exactly as the interpreter reads them; the input vector is the interpreter's, with no extra words |
| `CHAINID` | a translation-time constant: `evm2rv --chain-id N` bakes `N` into the C, so the image hash `hc` binds it |
| `ORIGIN` | `CALLER` — the same binding `CALLER` already has (one call, no relayer) |
| `GASPRICE`, `COINBASE`, `TIMESTAMP`, `NUMBER`, `PREVRANDAO`, `GASLIMIT`, `SELFBALANCE`, `BASEFEE`, `BLOCKHASH` | the trap the interpreter raises (`Halt::Trap(opcode)`, status 2), until a public-segment binding for them is designed (a follow-up for the user). A private input word is bound only to the salted `H_IN`, which a verifier cannot open, so it cannot carry a chain fact a prover could not forge |
| `LOG0..4` | runtime calls that append to the logs the harness hashes |
| `STOP`, `RETURN`, `REVERT`, `INVALID` | set the outcome and leave |
| precompile calls: `CALL`/`STATICCALL` to addresses 1–9 | the runtime's software implementations (§5) with the precompile's gas |
| the cross-contract family: `CALL`/`CALLCODE`/`DELEGATECALL`/`STATICCALL` to any other address, `BALANCE`, `EXTCODESIZE`, `EXTCODECOPY`, `EXTCODEHASH`, `CREATE`, `CREATE2`, `SELFDESTRUCT` | the trap the interpreter raises (status 2). A single proof carries one contract's witnessed storage; a multi-contract witness model is a chain design, not a translator. This is the one thing "broad Shanghai coverage" does not mean, and `evm2rv` prints a warning at translation naming each such opcode present in the code |

**Gas.** The Shanghai static schedule the interpreter implements is summed per basic block at
translation and charged once at the block head; the dynamic parts (memory expansion, `KECCAK256`
per word, copy costs per word, `SSTORE`/`SLOAD` warm and cold and refunds, `LOG` data and
topics, `EXP` per byte, precompile costs) are charged inside the runtime calls, with the
interpreter's exact formulas. Out of gas traps where the interpreter traps: since the static
charge is taken at the block head rather than per opcode, a block that would have run out of gas
part way through fails at its head instead, with the same status and the same reported
`gas_used` (the whole block's static cost), which the differential tests pin as the contract.

## 4. Stage two: register lifting

Same runtime, same tests, a cycle target rather than new semantics. A per-block stack-depth
analysis assigns each stack slot whose depth is static within the block to a C local (`u256`
value), so straight-line arithmetic never touches the array; slots live across a dynamic jump
are spilled to the array at the block end and reloaded at the target. Stage two lands after
stage one's exit gate and reports the ERC-20 cycle count again.

## 5. The runtime

`evm-rt`: the eight-limb `u256` library in C (add, sub, mul, div, mod, sdiv, smod, addmod,
mulmod, exp, signextend, comparisons, shifts, byte, bit and byte length), the memory model with
expansion accounting, the gas counter, the logs buffer, the trap path, and `extern "C"` shims
over the interpreter's Rust `StorageTree`, `keccak256` (SDK coprocessor), `sha256` (SDK
coprocessor) and the harness's input reader. Precompiles in software: `ecrecover`
(secp256k1 recovery over the reference field arithmetic), `sha256`, `ripemd160`, `identity`,
`modexp`, the bn128 `add`/`mul`/`pairing`, `blake2f`. Each is correct and slow; each is
measured in cycles and listed as the coprocessor backlog — a machine milestone, not this tool's.

## 6. The shim crate and the ABI

The generated `src/main.rs` is the interpreter's `evm/src/main.rs` with `run_call_with_executor`
given a closure that enters the translated code at block 0 instead of constructing an
`Interpreter`. Input decoding, the storage tree's pre-root and witnesses, `logs_hash`,
`public_output` and the `EVM_OUT` digest are `evm-core::abi` unchanged. The code hash the digest
binds is the hash of the **EVM bytecode in the input vector**, computed by the harness as the
interpreter computes it. A verifier checks both: `hc == translate(bytecode)` (re-running `evm2rv`
on the published bytecode, with the same `--chain-id`, exactly as for sBPF) and the code hash in
`EVM_OUT` against the same bytecode — so the translated program and the code it claims to run
cannot come apart.

## 7. Testing

- **Interpreter parity.** Every EVM vector `evm-core` tests (the ERC-20 transfer, and `approve`
  and `transferFrom` added here, plus revert and out-of-gas cases) runs through the interpreter
  on the host and the translated program under `rand-guest run`; the digest, the status and
  `gas_used` must be identical.
- **Differential fuzzing.** A generator emits random bytecode from the full opcode set with
  valid jumpdests and bounded loops; each runs in both, and outputs, status and gas must agree.
  Ten thousand cases in CI's fast set.
- **Per-opcode directed tests** over edge values: every arithmetic op at zero, one, maximum and
  minimum signed; every shift at 0, 255, 256; memory at the expansion boundaries; stack at depth
  1024.
- **Precompiles** against known-answer vectors (the Ethereum test suite's).
- **Cycles.** The ERC-20 transfer's cycle count against 121 638, reported after stage one and
  after stage two.
- **A real proof.** The translated ERC-20 transfer proves under the test profile and verifies,
  once, as each stage's exit gate.

## 8. Out of scope

Cross-contract calls and creation; Cancun opcodes (`TLOAD`, `TSTORE`, `MCOPY`, blobs); the
coprocessors themselves; on-chain translation; anything in `fullnode`.
