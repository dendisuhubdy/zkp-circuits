# `evm2rv` — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Translate EVM bytecode into C that `rand-guest` builds into a zkVM image whose public output, status and gas are identical to the EVM interpreter's on every input.

**Architecture:** A new standalone crate `evm2rv/` (binary `evm2rv`) in the circuits repo. It splits the bytecode into basic blocks with the interpreter's own jumpdest rule, sums the static gas per block, and emits `contract.c` over a memory stack plus a shim crate that reuses `evm-core`'s ABI harness through one new entry point, `abi::run_call_with_executor`. A C runtime `evm-rt/` provides the eight-limb `u256` library, the memory model, the gas counter, logs, traps, the precompiles, and `extern "C"` shims over the interpreter's Rust `StorageTree` and hashing. Stage two (register lifting) is its own final task on the same runtime and tests.

**Tech Stack:** Rust 1.98.1, `evm-core` (path), `rand-guest` (through its Task 6), Homebrew LLVM clang, `cc` in the shim's `build.rs`, `rand_zkvm` for `run`.

**Spec:** `docs/superpowers/specs/2026-09-18-evm-to-rv32-translator-design.md`

**Prerequisite:** the `rand-guest` plan through Task 6.

## Global Constraints

- The eight `EVM_OUT` words, the status (1 success, 0 revert, 2 trap) and `gas_used` must equal the interpreter's on every vector; `abi::{decode_input, logs_hash, public_output}`, `StorageTree` and the harness are reused, never reimplemented.
- The interpreter's `Halt` variants are the contract: `Stop`, `Return`, `Revert`, `OutOfGas`, `StackUnderflow`, `StackOverflow`, `BadJump`, `Invalid`, `Trap(u8)`, `NoWitness`, `BadWitness`, `OutOfBounds`. `MAX_CODE_BYTES` 24 KiB, the stack 1024 deep, the Shanghai static gas schedule as `interp.rs` has it (its `G_*` constants are copied, not re-derived).
- Static gas is charged once at each block head; dynamic gas inside runtime calls with the interpreter's exact formulas; an out-of-gas that the interpreter would raise mid-block is raised at the block head with the same `gas_used` (the whole block's static cost) — pinned by the parity tests.
- The cross-contract family (`CALL`/`CALLCODE`/`DELEGATECALL`/`STATICCALL` to a non-precompile address, `BALANCE`, `EXTCODESIZE`, `EXTCODECOPY`, `EXTCODEHASH`, `CREATE`, `CREATE2`, `SELFDESTRUCT`) compiles to the trap the interpreter raises for those opcodes (`Halt::Trap(opcode)`), and `evm2rv` warns at translation naming each one present.
- Environment words the interpreter lacks (`ORIGIN`, `GASPRICE`, `COINBASE`, `TIMESTAMP`, `NUMBER`, `PREVRANDAO`, `GASLIMIT`, `CHAINID`, `SELFBALANCE`, `BASEFEE`, `BLOCKHASH`) come from **trailing words appended to the input vector**; an input without them decodes exactly as before and those words read as zero, so every existing vector is unchanged.
- The C is compiled with the toolchain's flags; never `rv32imc`.
- Commit prefixes `evm2rv:`, `evm-core:`, `evm-rt:`, `docs:`; the two attribution lines from the session's system reminder.

---

## File structure

| path | responsibility |
|---|---|
| `evm2rv/Cargo.toml`, `src/main.rs`, `src/lib.rs` | CLI: `evm2rv <contract.bin> --out <dir>` |
| `evm2rv/src/blocks.rs` | jumpdest scan (the interpreter's rule), basic blocks, per-block static gas and min-depth/max-growth |
| `evm2rv/src/emit.rs` | stage one: each opcode to C over the memory stack; the jump switch |
| `evm2rv/src/lift.rs` | stage two: the per-block stack-to-locals pass |
| `evm2rv/src/shim.rs` | the generated shim crate |
| `evm-rt/u256.h`, `u256.c` | the eight-limb library, semantics of `evm-core/src/u256.rs` |
| `evm-rt/evm_rt.h`, `evm_rt.c` | stack, memory with expansion gas, gas counter, logs, traps, calldata/code copies, keccak via the SDK |
| `evm-rt/precompiles.c` | ecrecover, sha256, ripemd160, identity, modexp, bn128 add/mul/pairing, blake2f |
| `guests-compiled/evm-core/src/abi.rs` | `run_call_with_executor`; the trailing environment words; `extern "C"` storage shims in a new `ffi.rs` |
| `evm2rv/tests/parity.rs`, `tests/fuzz.rs`, `tests/opcodes.rs`, `tests/precompiles.rs` | the oracle tests |

---

### Task 1: `run_call_with_executor`, the storage FFI and the trailing environment words in `evm-core`

**Files:**
- Modify: `guests-compiled/evm-core/src/abi.rs`; Create: `guests-compiled/evm-core/src/ffi.rs`
- Test: `evm-core`'s existing vector test file (one new test each)

**Interfaces:**

```rust
pub struct EnvExt { pub origin: U256, pub gasprice: U256, pub coinbase: U256, pub timestamp: u64, pub number: u64, pub prevrandao: U256, pub gaslimit: u64, pub chainid: U256, pub selfbalance: U256, pub basefee: U256, pub blockhash: U256 }  // zeros when the input has no trailing words
pub type Executor<'a, H> = &'a mut dyn FnMut(&mut H, &[u8], &[u8], Env, &EnvExt, &mut StorageTree, &mut Buffers) -> Outcome;
pub fn run_call_with_executor<H: Host, F: FnMut(u32) -> u32>(h: &mut H, w: &mut Workspace, read: F, len: u32, exec: Executor<'_, H>) -> ([u32; 8], Outcome);
// ffi.rs, for the C runtime, over a `*mut StorageTree` the shim hands it:
#[no_mangle] pub extern "C" fn evm_sload(tree: *mut StorageTree, host: *mut c_void, slot: *const u32, out: *mut u32) -> u32;   // 0 ok, else the StorageError as Halt code
#[no_mangle] pub extern "C" fn evm_sstore(tree: *mut StorageTree, host: *mut c_void, slot: *const u32, value: *const u32) -> u32;
#[no_mangle] pub extern "C" fn evm_keccak256(host: *mut c_void, ptr: *const u8, len: u32, out: *mut u8);
```

- [ ] **Step 1: failing tests** — (a) the executor hook with the interpreter as the executor gives the interpreter's output on the ERC-20 vector; (b) a vector with eleven trailing words decodes to an `EnvExt` carrying them and the same output as without them for a contract that never reads them; (c) `evm_sload`/`evm_sstore` through the FFI on a two-slot tree match `StorageTree::load`/`store`.
- [ ] **Step 2: run, fail.** **Step 3: implement** (move the `Interpreter::new(...).run()` call behind the executor; extend `decode_input` to read the optional trailing words; write `ffi.rs` with the host passed as a `*mut dyn Host`-equivalent thin wrapper — a `struct HostBox<'a, H>(&'a mut H)` cast through `c_void`). **Step 4:** the whole `evm-core` suite passes and the `evm` guest's image sha256 is unchanged (`rand-guest build`). **Step 5: commit** — `evm-core: run_call_with_executor, the storage and keccak FFI, and the optional trailing environment words`.

---

### Task 2: `evm-rt` — the `u256` library and the memory model, host-tested

**Files:**
- Create: `evm-rt/u256.h`, `u256.c`, `evm_rt.h`, `evm_rt.c`, `test/u256_test.c`, `test/mem_test.c`

**Interfaces (C):**

```c
typedef struct { uint32_t l[8]; } u256;   // little-endian limbs
void u256_add(u256*, const u256*, const u256*); … sub mul div mod sdiv smod addmod mulmod exp signextend lt gt slt sgt eq iszero and or xor not byte shl shr sar
extern u256 evm_stack[1024]; extern uint32_t evm_sp;
extern uint64_t evm_gas;                            // remaining
void evm_charge(uint64_t g);                        // traps OutOfGas
uint32_t evm_mexpand(uint32_t offset, uint32_t len); // charges expansion, traps on overflow
void evm_mload(uint32_t off, u256*); void evm_mstore(uint32_t off, const u256*); void evm_mstore8(uint32_t off, uint32_t b);
void evm_calldataload(uint32_t off, u256*); void evm_copy_calldata(uint32_t dst, uint32_t src, uint32_t len); … code, returndata
void evm_keccak(uint32_t off, uint32_t len, u256*);  // charges per word, calls evm_keccak256
void evm_log(uint32_t n_topics, uint32_t off, uint32_t len);
__attribute__((noreturn)) void evm_halt(uint32_t halt_code, uint32_t arg);   // Stop/Return/Revert/traps; longjmp to the shim
```

- [ ] **Step 1:** host tests first: `u256` against known vectors for every op (edge values: 0, 1, 2^255, 2^256−1, division by zero → 0, `sdiv` of `MIN/−1` → `MIN`, shifts by 0/255/256, `signextend` at every byte), memory expansion gas against the interpreter's formula (`3·words + words²/512`), copies at boundaries.
- [ ] **Step 2:** implement (port each function of `evm-core/src/u256.rs` limb by limb; the memory model from `interp.rs`'s `Buffers` and its expansion accounting; the gas constants copied from `interp.rs` with their names).
- [ ] **Step 3:** `cc -o t test/*.c *.c && ./t` clean; commit — `evm-rt: the eight-limb u256 library and the EVM memory model, host-tested against the interpreter's semantics`.

---

### Task 3: blocks and static gas

**Files:**
- Create: `evm2rv/Cargo.toml` (deps: `evm-core` path, `clap`, `anyhow`; `[workspace]`), `src/lib.rs`, `src/blocks.rs`, `src/main.rs` (stub)
- Test: `evm2rv/tests/blocks.rs`

**Interfaces:**

```rust
pub struct Block { pub start: usize, pub end: usize, pub ops: Vec<Op>, pub static_gas: u64, pub min_depth: usize, pub max_growth: usize, pub term: Term }
pub enum Term { Fallthrough(usize), Jump, JumpI(usize), Stop, Return, Revert, Invalid, TrapOp(u8) }
pub struct Op { pub pc: usize, pub opcode: u8, pub push: Option<[u8; 32]> }
pub fn jumpdests(code: &[u8]) -> Vec<usize>;                 // the interpreter's rule
pub fn blocks(code: &[u8]) -> Vec<Block>;
pub fn warnings(code: &[u8]) -> Vec<(usize, u8)>;           // the cross-contract family present
```

- [ ] **Step 1:** tests: `jumpdests` equals `evm_core::interp::scan_jumpdests`'s bitmap on the ERC-20 bytecode (expose the scan as `pub` if it is not); blocks split exactly at jumpdests and after terminators; a block's `static_gas` is the sum of the interpreter's `G_*` for its ops (assert on a hand-built sequence `PUSH1 PUSH1 ADD STOP` = 3+3+3+0); `min_depth`/`max_growth` on `DUP1 SWAP1 POP`.
- [ ] **Step 2–4:** implement, pass, commit — `evm2rv: jumpdests, basic blocks, static gas and the stack bounds per block`.

---

### Task 4: the stage-one emitter, the shim, and ERC-20 parity

**Files:**
- Create: `evm2rv/src/emit.rs`, `src/shim.rs`, the CLI
- Test: `evm2rv/tests/emit.rs`, `tests/parity.rs`

**Interfaces:**
- CLI: `evm2rv <contract.bin> --out <dir> [--name <crate>] [--stage 1|2]` → `contract.c`, `Cargo.toml`, `build.rs`, `src/main.rs`; prints blocks, opcodes, warnings.
- Emitted C shape:

```c
uint32_t evm_entry(void) {            // returns nothing useful; the halt is via evm_halt's longjmp
    goto L_0;
L_0:  evm_charge(9); if (evm_sp < 0 || evm_sp + 3 > 1024) evm_halt(HALT_STACK, 0);
      /* PUSH1 0x80 */ u256_from_u32(&evm_stack[evm_sp++], 0x80);
      /* PUSH1 0x40 */ …
      /* MSTORE */ evm_mstore(u256_low_u32(&evm_stack[evm_sp-1]), &evm_stack[evm_sp-2]); evm_sp -= 2;
      …
      /* JUMPI */ { uint32_t d = u256_low_u32(&evm_stack[evm_sp-1]); int c = !u256_iszero(&evm_stack[evm_sp-2]); evm_sp -= 2; if (c) { if (!u256_hi_zero(&evm_stack[evm_sp+1])) evm_halt(HALT_BADJUMP,0); goto *jumpdest(d); } }
      goto L_43;
…
}
static void *jumpdest(uint32_t d) { switch (d) { case 0x2b: return &&L_43; … default: evm_halt(HALT_BADJUMP, d); } }
```

Use a `switch` with `goto` labels (computed gotos are a GNU extension clang supports; the plain `switch` in a dispatcher function is portable — pick the `switch` inside `evm_entry` itself, `case` labels jumping with `goto`, so no function pointers are needed).

- [ ] **Step 1: parity test first** — `tests/parity.rs`: `evm2rv` on the interpreter's ERC-20 test bytecode, `rand-guest build` the output dir, `rand-guest run` with the transfer vector's input words, compare the eight outputs, then decode `gas_used` and status from the vector the harness prints (or from a debug output slot the shim writes in test builds — the harness's `Outcome` is not in the public words; add a `--emit-outcome` shim feature that writes `gas_used` to output slot 7 for tests only, gated by a cargo feature the parity test enables). Same for `approve`, `transferFrom`, a revert (transfer more than the balance), an out-of-gas (a tiny gas limit).
- [ ] **Step 2: emit tests** — each opcode's C against the spec's table (`ADD` → `u256_add(&evm_stack[evm_sp-2], &evm_stack[evm_sp-2], &evm_stack[evm_sp-1]); evm_sp--;`, etc.).
- [ ] **Step 3: implement** `emit.rs` (every opcode of the spec's table; the block-head charge and bounds check; the jump switch; `PC` as a constant; the trap opcodes as `evm_halt(HALT_TRAP, opcode)`; the environment opcodes reading `evm_env` and `evm_env_ext` structs the shim fills from `Env`/`EnvExt`), `shim.rs` (the interpreter's `evm/src/main.rs` with `run_call_with_executor` and an executor that fills the C globals, `setjmp`s, calls `evm_entry`, and maps the halt code, gas, return data and logs back into an `Outcome`), and the CLI.
- [ ] **Step 4: run parity and emit tests; commit** — `evm2rv: the stage-one emitter, the shim and the CLI — the ERC-20 transfer, approve and transferFrom match the interpreter on digest, status and gas`.

---

### Task 5: precompiles

- [ ] `evm-rt/precompiles.c` with known-answer tests from the Ethereum test suite (`test/precompiles_test.c`, host-run): `ecrecover` (a reference secp256k1 over `uint64_t` limbs), `sha256` (via the SDK compress on target, a C compress on the host), `ripemd160`, `identity`, `modexp`, `bn128` add/mul/pairing (reference field arithmetic, the pairing as the slow Miller loop), `blake2f`; each charged per the Shanghai schedule; `CALL`/`STATICCALL` to addresses 1–9 emitted as the runtime dispatch with the call's gas, return data and success flag pushed as the EVM does.
- [ ] Commit — `evm-rt: the nine precompiles in software, known-answer tested`.

---

### Task 6: differential fuzzing over the full opcode set

- [ ] `evm2rv/src/gen.rs` (test-only): random bytecode from every non-trap opcode with valid jumpdests, bounded loops via a counter in storage or memory, random calldata; `tests/fuzz.rs` runs each case in the interpreter and in the emitted C compiled for the host (with `evm_rt.c`, `u256.c` and host stubs for keccak/storage that call the Rust FFI directly) and compares status, gas and return data; 10 000 cases; fix every divergence; each fixed case becomes a directed test in `tests/opcodes.rs`.
- [ ] Commit — `evm2rv: differential fuzzing against the interpreter over every Shanghai opcode`.

---

### Task 7: cycles and a real proof (stage one)

- [ ] `rand-guest run` on the translated ERC-20 transfer: cycles, tier, words, against the interpreter's 121 638 (from `rand-guest run` on `guests-compiled/bin/evm.bin` with the same input); numbers into `evm2rv/README.md`.
- [ ] One real proof under the test profile (an `#[ignore]`d test with the command in its doc comment), run once, timing into the README.
- [ ] Commit — `evm2rv: the measured cycles and one real proof of the stage-one ERC-20`.

---

### Task 8: stage two — register lifting

**Files:**
- Create: `evm2rv/src/lift.rs`; Modify: `emit.rs` (`--stage 2`)
- Test: the whole of Tasks 4–6 re-run under `--stage 2`; `tests/lift.rs` for the analysis

- [ ] **Step 1:** `lift.rs`: per block, simulate the stack symbolically from the block's entry depth; every slot pushed and consumed inside the block becomes a `u256` local; slots live at block entry or exit are the array. Emit the same runtime calls on locals; spill live locals to the array before a `JUMP`/`JUMPI`/fallthrough into a block whose entry depth they belong to, and reload at block entry.
- [ ] **Step 2:** the analysis test: on `PUSH1 1 PUSH1 2 ADD PUSH1 3 MUL STOP` no array access is emitted; on a block ending in `JUMPI` the live slots are spilled.
- [ ] **Step 3:** every parity, opcode, precompile and fuzz test passes under `--stage 2`; the ERC-20 cycle count is re-measured and recorded beside stage one's.
- [ ] Commit — `evm2rv: stage two, register lifting per block — the same tests, fewer cycles`.

---

### Task 9: docs

- [ ] `evm2rv/README.md` (usage, the trap boundary and its warning, the numbers for both stages, the coprocessor backlog with measured cycles per precompile), the root README row, an AGENTS.md entry, `research/docs/04-guests.md`'s "Solidity path" gains a paragraph. Commit — `docs: evm2rv`.
