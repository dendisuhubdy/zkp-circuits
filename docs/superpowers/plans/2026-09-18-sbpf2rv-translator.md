# `sbpf2rv` — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Translate an sBPF ELF into C that `rand-guest` builds into a zkVM image whose public output is identical to the sBPF interpreter's on every input.

**Architecture:** A new standalone crate `sbpf2rv/` (binary `sbpf2rv`) in the circuits repo. It loads the ELF with `sbpf-core`'s own loader, scans the text into functions and basic blocks, and emits `program.c` plus a shim crate that reuses `sbpf-core`'s ABI harness through one new entry point, `abi::run_call_with_executor`, which runs a caller-supplied executor over the interpreter's own `Memory` instead of `Vm::run`. A C runtime `sbpf-rt/` provides region translation, traps, and the syscalls. Parity with the interpreter is the test oracle throughout.

**Tech Stack:** Rust 1.98.1, `sbpf-core` (path), `rand-guest` (Task 1 of its plan onward: `build --lang c` is not used; the shim is a Rust crate with a `build.rs` compiling C via the `cc` crate with the toolchain's clang flags), Homebrew LLVM clang, `rand_zkvm` for `run`.

**Spec:** `docs/superpowers/specs/2026-09-18-sbpf-to-rv32-translator-design.md`

**Prerequisite:** the `rand-guest` plan through Task 6 (the C flags, `guest.h`, `find_clang`).

## Global Constraints

- The public output (the eight `SBPF_OUT` words) of the translated program must equal the interpreter's for every vector, including every failing one; `abi::{decode_input, check_region, canonical_input_hash, output_hash, public_output}` are reused, never reimplemented.
- The interpreter's `Halt` variants and status mapping are the contract: `Exit`, `AccessViolation`, `BadInsn`, `DivByZero`, `UnknownSyscall`, `CallDepth`, `InstructionLimit`, `BadElf`, `BadJump`, `StackOverflow`, `Trap`. `MAX_CALL_DEPTH = 8`, `STACK_FRAME = 4096`, `HEAP_BYTES = 32 768`, the four regions at `0x1..0x4 << 32`.
- Registers are `uint64_t` C locals. **Amended 2026-09-18** (ruling on Task 2's SPL Token finding): an instruction naming `dst > 10` or `src > 10`, an unassigned opcode byte, or a static jump/call target outside the function's text is *not* refused at translation — none of it is a load-time check in `interp.rs`/`elf.rs` either (the interpreter only halts on it when it *executes* that instruction), and the committed SPL Token ELF itself contains unreached code Solana's own toolchain emitted that this translator must still accept (see the CPI amendment below; the same reasoning applies uniformly). Each becomes a runtime trap identical to the `Halt` the interpreter would raise (`BadInsn`/`BadJump`) plus a scanner-level warning naming the pc, so a vector that never reaches it still translates and runs.
- Cross-program invocation (`sol_invoke_signed_c`, `sol_invoke_signed_rust`, any `sol_invoke*` this scanner can name from a hash). **Amended 2026-09-18**: not refused at translation — the interpreter only checks a syscall hash against `syscalls::SUPPORTED` when the `call imm` naming it is actually executed, and the committed SPL Token ELF calls two syscalls (`sol_set_return_data`, `sol_get_sysvar`) neither implemented, from instruction handlers the `Transfer` vector never reaches (`research/tests/sbpf_elf.rs`); refusing the whole program over that broke parity with the interpreter, which loads and runs this exact file today. CPI and every other unrecognised syscall hash alike become an ordinary syscall call site translated as a runtime trap (`Halt::UnknownSyscall`) plus a warning naming the syscall (or the raw hash, if it names nothing this scanner recognises).
- The C is compiled with exactly the toolchain's flags (`--target=riscv32-unknown-none-elf -march=rv32im -mabi=ilp32 -mno-relax -nostdlib -ffreestanding -fno-builtin -Os`); no `rv32imc`.
- The instruction-limit check is per basic block at the block head and must halt within the block that crosses the limit (never earlier).
- Commit prefixes `sbpf2rv:`, `sbpf-core:`, `sbpf-rt:`, `docs:`; the two attribution lines from the session's system reminder.

---

## File structure

| path | responsibility |
|---|---|
| `sbpf2rv/Cargo.toml`, `src/main.rs` | CLI: `sbpf2rv <program.so> --out <dir>`; writes `program.c`, `Cargo.toml`, `build.rs`, `src/main.rs` |
| `sbpf2rv/src/scan.rs` | functions (entry + `call` targets), basic blocks, jump targets, `callx` table, the refusals |
| `sbpf2rv/src/emit.rs` | the C emitter: one function per sBPF function, one statement per instruction |
| `sbpf2rv/src/shim.rs` | the generated shim crate's four files as templates |
| `sbpf-rt/sbpf_rt.h`, `sbpf-rt/sbpf_rt.c` | regions, `tr`, `sbpf_trap`, the syscalls, the software Ed25519/secp256k1 |
| `guests-compiled/sbpf-core/src/abi.rs` | `run_call_with_executor` (new), `run_call_with` reimplemented over it |
| `sbpf2rv/tests/parity.rs`, `tests/fuzz.rs`, `tests/emit.rs` | the oracle tests |

---

### Task 1: `run_call_with_executor` in `sbpf-core`

**Files:**
- Modify: `guests-compiled/sbpf-core/src/abi.rs` (`run_call_with` becomes a thin wrapper)
- Test: `guests-compiled/sbpf-core/tests/` (whichever file holds the SPL Token vector; add one test)

**Interfaces:**
- Produces:

```rust
/// What runs the loaded program over the interpreter's memory: `Vm::run` for the interpreter,
/// a translated program's entry for `sbpf2rv`. Gets the loaded program (text, rodata, entry)
/// and the memory it runs over; returns what `Vm::run` returns.
pub type Executor<'a, H> = &'a mut dyn FnMut(&mut H, &elf::Program<'_>, Memory<'_>) -> Result<u64, Halt>;

pub fn run_call_with_executor<H: Host, FP: FnMut(u32) -> u32, FS: FnMut(u32) -> u32>(
    h: &mut H, ws: &mut Workspace, read_public: FP, n_public: u32, read_private: FS, n_private: u32,
    exec: Executor<'_, H>,
) -> ([u32; 8], Result<u64, Halt>);
```

- [ ] **Step 1: Write the failing test** — in the sBPF test file that runs the SPL Token transfer vector, add:

```rust
#[test]
fn an_executor_that_delegates_to_the_vm_gives_the_interpreter_output() {
    // Same vector, same output, through the executor hook with the Vm as the executor.
    let (want, _) = sbpf_core::abi::run_call(&mut host(), &mut ws(), read_public, n_public, read_private, n_private);
    let mut run_vm = |h: &mut Host_, p: &sbpf_core::elf::Program<'_>, mem: sbpf_core::memory::Memory<'_>| sbpf_core::interp::Vm::new(h, p, mem).run();
    let (got, _) = sbpf_core::abi::run_call_with_executor(&mut host(), &mut ws(), read_public, n_public, read_private, n_private, &mut run_vm);
    assert_eq!(got, want);
}
```

Use the file's existing helper names for the host, workspace and readers.

- [ ] **Step 2: Run to verify it fails** — `cd guests-compiled/sbpf-core && cargo test an_executor` → missing function.

- [ ] **Step 3: Implement** — move the body of `run_call_with` from `let result = match elf::load(...)` onward into `run_call_with_executor`, replacing `Vm::new(h, &program, mem).run()` with `exec(h, &program, mem)`; make `run_call_with` call it with `&mut |h, p, mem| Vm::new(h, p, mem).run()`. Everything before (decode, hashes, zeroing) and after (the status mapping, `public_output`) stays exactly as is.

- [ ] **Step 4: Run the whole sbpf-core suite** — `cargo test` in `sbpf-core`; and rebuild the `sbpf` guest with `rand-guest build ../guests-compiled/sbpf` and confirm its image sha256 is unchanged (the executor closure must inline to the same code; if the image moves, mark the wrapper `#[inline(always)]` and keep the interpreter's path monomorphic — the pinned image is the gate).

- [ ] **Step 5: Commit** — `sbpf-core: run_call_with_executor — the harness takes the thing that runs the program, so a translated program can reuse everything around it`.

---

### Task 2: the scanner

**Files:**
- Create: `sbpf2rv/Cargo.toml` (deps: `sbpf-core = { path = "../guests-compiled/sbpf-core" }`, `clap`, `anyhow`; `[workspace]`), `src/main.rs` (stub), `src/lib.rs`, `src/scan.rs`
- Test: `sbpf2rv/tests/scan.rs`

**Interfaces:**

**Amended 2026-09-18, twice, both same-day rulings on this task's own findings (see the task-2
report's fix notes for the full reasoning — parity with the interpreter, which never checks any of
this except when it executes the instruction in question, and the committed SPL Token ELF contains
unreached code that fails every one of these checks). `scan` is now infallible: there is no
`Refusal` type. Everything the first ruling (below) still lists as a refusal was refused only
because pass 1 checked it before pass 2 even began; the second ruling removed pass 1's checks
entirely and folded them into pass 2, where every other check already lived.**

- Produces:

```rust
pub struct Function { pub entry: usize, pub blocks: Vec<Block> }                     // pcs in slots
pub struct Block { pub start: usize, pub end: usize, pub insns: Vec<sbpf_core::isa::Insn>, pub term: Term }
pub enum Term { Fallthrough(usize), Jump(usize), CondJump { taken: usize, not: usize }, Exit, Call { target: usize, next: usize }, Syscall { hash: u32, next: usize }, CallX { next: usize }, Trap(TrapKind) }
pub enum TrapKind { BadInsn(u8), BadJump }             // exactly interp.rs's Halt, so Task 4 needs no cross-reference
pub struct Scan { pub functions: Vec<Function>, pub entry: usize, pub callx_targets: Vec<usize>, pub warnings: Vec<Warning> }
pub enum Warning { UnknownSyscall { pc: usize, hash: u32 }, Cpi { pc: usize, name: &'static str }, RegisterOutOfRange { pc: usize, opc: u8 }, UnknownOpcode { pc: usize, opc: u8 }, JumpOutOfText { pc: usize, target: i64 } }
pub fn scan(program: &sbpf_core::elf::Program<'_>) -> Scan;                          // infallible
```

A bad jump/call *target* has no in-text pc a `Term` field can name, so every function shares one
synthetic pc (one past its text's last real slot) that a bad edge redirects to instead: a `Block`
with no instructions and `term: Term::Trap(TrapKind::BadJump)`. The one exception is an internal
call whose *target* (not its return point) is bad: there is no function to call, so the call site
traps directly (`Term::Trap`, no `Term::Call` at all) rather than naming a non-function as a
target.

- [x] **Step 1: Write the failing tests** — build tiny programs with `sbpf_core::isa::encode` (an
  `exit`; a function with a `call` to a second function; a `ja` past the text; a `mov r11, 0`; a
  `call` whose hash is `murmur3_32(b"sol_invoke_signed_c", 0)`) and assert: the function count, the
  block splits at every jump target and after every jump/call/exit, and — following both rulings
  above — that none of this refuses the scan: each becomes a `Warning` plus a `Term::Trap` (or, for
  the two syscall cases, an ordinary `Term::Syscall`) instead.

- [x] **Step 2: Run to verify they fail.**

- [x] **Step 3: Implement `scan`** — decode every slot with `isa::decode` (an `lddw` occupies two);
  walk from the entry and every internal call target, splitting blocks at jump targets and after
  terminators; classify a `call imm` as internal when `src == 0` and as a syscall when `src == 1`,
  the immediate a `syscalls::SUPPORTED` hash if implemented, else a `Warning` either way (`Cpi` for
  a `sol_invoke*` name this scanner can check a hash against, `UnknownSyscall` otherwise) plus an
  ordinary `Term::Syscall` regardless — Task 4 emits a runtime trap for an unrecognised hash rather
  than a real call; collect `callx` targets as every function entry; every register-range,
  opcode-validity and jump/call-target check happens once per reachable pc in this same walk (not
  in a separate whole-text pass), producing a `Warning` plus `Term::Trap` rather than refusing.

- [x] **Step 4: Run the tests; commit** — `sbpf2rv: the scanner — functions, blocks, targets, and
  the four refusals`, then the two same-day amendment commits.

---

### Task 3: the runtime `sbpf-rt`

**Files:**
- Create: `sbpf-rt/sbpf_rt.h`, `sbpf-rt/sbpf_rt.c`
- Test: `sbpf-rt/test/host_test.c` (compiled and run on the host with `cc`, no zkVM: the region table and the memcpy/memmove/memcmp/memset semantics against the interpreter's expectations)

**Interfaces:**

```c
typedef struct { const uint8_t *text; uint64_t text_va; uint32_t text_len;
                 const uint8_t *rodata; uint64_t rodata_va; uint32_t rodata_len;
                 uint8_t *stack; uint8_t *heap; uint8_t *input; uint32_t input_len; } sbpf_regions;
extern sbpf_regions sbpf_r;                     // set by the shim before entry
uint64_t sbpf_load(uint64_t addr, uint32_t size);           // traps AccessViolation
void     sbpf_store(uint64_t addr, uint32_t size, uint64_t v);
__attribute__((noreturn)) void sbpf_trap(uint32_t halt_code, uint64_t arg);   // halt codes mirror Halt's discriminants
uint64_t sbpf_sys_<name>(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);  // one per supported syscall
extern int64_t sbpf_budget;                     // instructions remaining; the emitter decrements per block
```

`sbpf_trap` longjmps to the shim's entry (a `setjmp` in the shim's executor closure), which maps the code back to `Halt`. `sbpf_sys_sha256` calls `rand_sha256_compress` from `guest.h` through the SDK's padding loop (port `guest_sdk::sha256`'s message schedule to C). Ed25519 verify and secp256k1 recover: straightforward reference implementations (field arithmetic on `uint64_t` limbs; no tables), each behind its own file so its cycle cost is measurable.

- [ ] Steps: write the host test first (region translation edge cases, overlapping memmove, memcmp sign), run it with `cc -o t test/host_test.c sbpf_rt.c && ./t`, implement, pass, commit `sbpf-rt: the C runtime — regions, traps, the syscalls, software ed25519 and secp256k1`.

---

### Task 4: the emitter and the shim

**Files:**
- Create: `sbpf2rv/src/emit.rs`, `sbpf2rv/src/shim.rs`, the CLI in `src/main.rs`
- Test: `sbpf2rv/tests/emit.rs` (the C text for each instruction class is exactly the spec's table), `tests/parity.rs` (SPL Token transfer through interpreter and translation)

**Interfaces:**
- CLI: `sbpf2rv <program.so> --out <dir> [--name <crate>]` → `<dir>/program.c`, `Cargo.toml`, `build.rs`, `src/main.rs`; prints functions, blocks, instructions, refusals.
- The shim's `src/main.rs`:

```rust
#![no_std] #![no_main]
use sbpf_core::abi::{run_call_with_executor, Workspace};
extern "C" { fn sbpf_entry(regions: *const SbpfRegions, budget: i64, r1: u64, r2: u64, r3: u64, r4: u64, r5: u64) -> u64; static mut sbpf_halt_code: u32; static mut sbpf_halt_arg: u64; }
// … the interpreter's Syscalls host, the Workspace static …
#[no_mangle] pub extern "C" fn main() -> ! {
    let w = unsafe { &mut *core::ptr::addr_of_mut!(W) };
    let mut exec = |_h: &mut Syscalls, p: &sbpf_core::elf::Program<'_>, mem: sbpf_core::memory::Memory<'_>| -> Result<u64, sbpf_core::interp::Halt> {
        let regions = SbpfRegions::from(p, &mem);          // pointers and lengths
        let r = unsafe { sbpf_entry(&regions, INSTRUCTION_LIMIT, /* r1..r5 as the interpreter sets them at entry */ …) };
        match unsafe { sbpf_halt_code } { 0 => Ok(r), code => Err(halt_from(code, unsafe { sbpf_halt_arg })) }
    };
    let out = run_call_with_executor(&mut Syscalls, w, guest_sdk::read_public, u32::MAX, guest_sdk::read_input, u32::MAX, &mut exec);
    for (slot, word) in out.0.iter().enumerate() { guest_sdk::write_output(slot as u32, *word); }
    guest_sdk::halt()
}
```

`sbpf_entry` in the emitted C sets `sbpf_r`, `sbpf_budget`, does `setjmp`, and calls the entry function with the interpreter's initial register state (read `Vm::new`/`run` for what `r1` and `r10` are at entry: `r1` = the input region's start address, `r10` = the top of frame 0). The emitted C's entry name is fixed; `build.rs` compiles `program.c` and `../../sbpf-rt/sbpf_rt.c` with `cc::Build` and the toolchain's flags (`.compiler(find_clang())`, `.flag("--target=riscv32-unknown-none-elf")`, …).

- [ ] **Step 1: parity test first** — `tests/parity.rs` runs `sbpf2rv` on the SPL Token ELF the interpreter's tests use, `rand-guest build` on the output dir (Rust shim with C via `build.rs`), `rand-guest run` with the vector's inputs (public = the ELF words, private = the instruction words, exactly as the interpreter's test feeds them), and compares the eight outputs to `sbpf_core::abi::run_call` on the host. Also the failing vectors (a bad account count, an access violation).

- [ ] **Step 2: emit tests** — per instruction class, `emit_insn(&Insn) -> String` equals the spec's C exactly (e.g. `alu64 add reg` → `r3 = r3 + r4;`, `lsh32 imm` → `r1 = (uint32_t)((uint32_t)r1 << (5 & 31));`, `jsgt` → `if ((int64_t)r1 > (int64_t)r2) goto L_12;`).

- [ ] **Step 3: implement** `emit.rs` (the table from the spec §3, signed/unsigned casts, zero-extension after every alu32, `lddw` as one statement, per-block budget decrement `if ((sbpf_budget -= N) < 0) sbpf_trap(HALT_INSTRUCTION_LIMIT, 0);`, the region-folded stack access when `src == 10`), `shim.rs`, and the CLI.

- [ ] **Step 4: run parity and emit tests; commit** — `sbpf2rv: the emitter, the shim crate and the CLI — the SPL Token transfer translates and matches the interpreter word for word`.

---

### Task 5: differential fuzzing and the full instruction set

**Files:**
- Create: `sbpf2rv/tests/fuzz.rs`, `sbpf2rv/src/gen.rs` (the generator, test-only)

- [ ] **Step 1:** a generator that emits random well-formed function bodies: every opcode class, both ALU widths, the signed/v2 family, byte swaps, loads/stores into a small scratch region of the stack, bounded loops via a countdown register, valid jump targets, an `exit`. Seeded by an integer; 10 000 cases under `cargo test`, `FUZZ_CASES` env to raise.
- [ ] **Step 2:** each case runs in the interpreter (host) and through the emitted C **compiled for the host** (`cc` at test time, with `sbpf_rt.c`, no zkVM in the loop — the C is target-independent apart from `guest.h` calls, which the host build stubs) and compares `r0` and the halt kind. This is the fast loop; the zkVM path is covered by Task 4's parity.
- [ ] **Step 3:** fix every divergence in the emitter until 10 000 cases agree; add each fixed case as a directed test.
- [ ] **Step 4:** commit — `sbpf2rv: differential fuzzing against the interpreter over the full instruction set`.

---

### Task 6: mint and burn, cycles, a real proof

- [ ] Add SPL Token `MintTo` and `Burn` vectors to the parity test (build the instruction inputs the way the interpreter's transfer vector is built).
- [ ] `rand-guest run` on the translated transfer: record cycles, tier and image words in `sbpf2rv/README.md` next to the interpreter's numbers (get the interpreter's from `rand-guest run` on `guests-compiled/bin/sbpf.bin` with the same inputs).
- [ ] Prove the translated transfer once under the research prover's test profile (`research`'s `prove_bundle`-style test harness: `Machine::new(FriProfile::Test).prove(&program, &inputs, &public, None)` then `verify`), as an `#[ignore]`d test with the command in its doc comment; run it once and paste the timing into the README.
- [ ] Commit — `sbpf2rv: mint and burn parity, the measured cycles, one real proof`.

---

### Task 7: docs

- [ ] `sbpf2rv/README.md` (usage, what is refused, the numbers, the coprocessor backlog with measured cycles for the software ed25519/secp256k1), the root README row, an AGENTS.md entry, `research/docs/04-guests.md`'s "Solana path" gains a paragraph pointing here. Commit — `docs: sbpf2rv`.
