# `sbpf2rv` — the Solana bytecode to RV32 translator (v0.4, piece 2 of 3)

Status: **approved by the user 2026-09-18; spec written, plan after piece 1's plan.** Runs as a
parallel track with piece 3 once `rand-guest` (piece 1) exists, because it emits into it.

Related: `docs/superpowers/specs/2026-09-18-rand-guest-toolchain-design.md` (the pipeline this
targets), `guests-compiled/sbpf-core/` (the interpreter this must agree with, byte for byte on
the public output: `isa.rs`, `interp.rs`, `memory.rs`, `syscalls.rs`, `abi.rs`, `elf.rs`),
`research/docs/04-guests.md` ("The Solana path"; the translator it calls "a natural later
optimisation"), `research/docs/01-isa.md` (the target).

## 1. What this is

The sBPF interpreter proves an SPL program by executing its ELF one instruction at a time inside
the zkVM, paying dispatch and 64-bit-as-two-32-bit overhead per instruction. This translator
turns the same ELF into native RV32IM ahead of time, so the proof executes the program directly.
What the chain sees does not change: the translated program reuses the interpreter's ABI
harness, so it takes the same input vector and publishes the same `SBPF_OUT` digest. The
translation is off-chain (user ruling 2026-09-18): the developer runs `sbpf2rv`, then
`rand-guest build`, then deploys the image; the chain never sees the sBPF.

```
program.so (sBPF ELF) ──▶ sbpf2rv ──▶ <name>/  ├── program.c      (the translated functions)
                                               ├── Cargo.toml      (the shim crate: sbpf-core + guest-sdk + cc)
                                               └── src/main.rs     (the interpreter's main with run_call
                                                                    calling the translated entry instead of Vm::run)
                     ──▶ rand-guest build <name>/ ──▶ image.bin ──▶ rand program deploy image.bin
```

## 2. Input

The ELF is loaded with `sbpf-core::elf` exactly as the interpreter loads it: text, read-only
data rebased into `REGION_PROGRAM`, the entrypoint, the syscall relocations (a `call` whose
immediate is a murmur3 hash resolved through `syscalls::SUPPORTED`), and the internal call
targets (a `call` whose immediate is a pc offset). Both sBPF v1 and v2 encodings are accepted;
which one the ELF declares selects the v2-only instruction semantics below. An ELF the
interpreter would refuse (`elf.rs`'s errors) is refused here with the same message.

## 3. The translation

**Functions.** The entrypoint, every `call` target found by a scan over the text, and every
`callx`-plausible constant (**amended 2026-09-18, review round 1**: a post-relocation `lddw`
immediate or a read-only-data word past the text that points 8-aligned at a real instruction
start — `sbpf2rv/src/scan.rs`'s `lddw_and_rodata_function_roots`; a function reached *only*
through `callx`, never a `call imm`, is otherwise invisible to the scan, which is exactly the
committed SPL Token ELF's pc 12244) become one C function each. **Amended 2026-09-18 (Task 4)**:
an earlier draft had `f_<pc>(r1..r5)` returning `r0`, which is narrower than `interp.rs`'s call —
a callee sees *every* register the caller had (`r0` and `r6..r9` included) and hands back `r0..r5`
as it left them (`exit` restores only `r6..r10`). So every function is
`sbpf_ret f_<pc>(uint64_t r0, …, uint64_t r9, uint64_t r10)` with
`typedef struct { uint64_t r0, r1, r2, r3, r4, r5; } sbpf_ret`: a call passes `r0..r9` and `r10`
advanced by one `STACK_FRAME`, and copies back `r0..r5`; `r6..r10` are the caller's own C locals,
which the call cannot touch. Both lists are narrowed per call site by an interprocedural liveness
pass (`sbpf2rv/src/emit.rs`, `Calls`, a least fixpoint over the call graph with `callx` as a call to
every known function). For a direct `call imm`, whose one callee is known statically, a register
the callee cannot read before writing is passed as 0, and one it cannot write is not copied
back — neither is observable, since exactly that callee runs. **Amended 2026-09-18 (Task 5,
`bafe72a`)**: `callx`'s single call site cannot do this per-target narrowing, because which of the
known functions actually runs is a runtime value — the emitted switch has one uniform parameter
list for every candidate. So a `callx` passes, and copies back, `callx_live | callx_mod`: the
*union* of every target's reads and of every target's possible writes, not just what is live. A
register that only some targets write must still receive its caller's real value on the way in,
because whichever target actually runs might be one that does not write it and simply passes it
through unchanged; passing 0 for a register no target *reads* but some target *writes* corrupted
the caller's value under exactly that mismatch (the fix's regression case: `main` sets r2, calls
through a `callx` whose live target writes only r0, while a different, unreached target of the
same `callx` would have written r2 — the old code passed r2 as 0 and lost it). It is false that
such a register "is passed as 0" for `callx`; only a direct `call imm` narrows that way. `callx`
goes through `sbpf_callx_target(addr)`, which maps `interp.rs`'s `(addr - text_va) / 8` to a
function pointer over the known function set, or traps `BadJump`. A function whose entry lies
inside another's code
is emitted once, as an extra entry label of the larger one (`Hosts`; the caller sets `sbpf_sel`).
`r10` is an ordinary local: a program may write it. Unreachable text is not translated.
Registers are `uint64_t` locals, so clang, not this tool, chooses the RV32 register pairs and
spills — the "direct lowering with register pairs" of the approved design, done by the compiler.

**Instructions.** Every opcode in `isa.rs`, one C statement each, in `classify`'s classes:

| class | translation |
|---|---|
| `ld` (`lddw` imm64) | a constant |
| `ldx` / `st` / `stx`, all four widths | `rd = sbpf_ldN(rs, off)` / `sbpf_stN(rd, off, v)` (**amended, Task 4**: never a pointer cast — there is no alignment rule — and the runtime forms `interp.rs`'s wrapped `base + off`, which is also the fault payload); little-endian as sBPF is |
| `alu32` / `alu64`: add sub mul div or and lsh rsh neg mod xor mov arsh | the C operator on `uint32_t` or `uint64_t`; shifts mask the count to 31 / 63 (**amended, Task 4**: as the interpreter does, alu32 `add`/`sub`/`mul` *sign*-extend their result and every other alu32 op zero-extends) |
| v2 signed ops (`sdiv`, `srem`, the pqr product/quotient/remainder family), `hor64` | (**amended, Task 4**: not v1 opcodes — `isa::classify` assigns none of them, so, like the interpreter, the translation traps `BadInsn` on each) |
| `le` / `be` byte swaps (16/32/64) | `__builtin_bswap*` or a mask |
| `ja` / `jeq` / `jgt` / `jge` / `jlt` / `jle` / `jset` / `jne` / `jsgt` / `jsge` / `jslt` / `jsle` (imm and reg) | `if (…) goto L_<pc>;` |
| `call imm` (internal) | `SBPF_CALL(f_<target>(r0, …, r10 + STACK_FRAME), <copy-back>)`: the depth check, then the call (see **Functions**) |
| `call imm` (syscall by hash) | `r0 = sbpf_sys_<name>(r1, r2, r3, r4, r5)` from the runtime (§5); an unimplemented hash is `sbpf_trap(UnknownSyscall, hash)` |
| `callx` | the depth check, then a call through `sbpf_callx_target(reg)` — a `switch` over the known function set, `default: trap(BadJump)` (**amended 2026-09-18, review round 1**: an unknown target is a bad *fetch*, `interp.rs`'s `slot_at` — `Halt::BadJump`, not `BadInsn`; an earlier draft of this row said `BadInsn`) |
| `exit` | `return (sbpf_ret){r0, …, r5}` |

Every instruction that can trap does so through `sbpf_trap(code)`, which unwinds to the harness
with the interpreter's `Halt` value so the canonical failure output is byte-identical: division
by zero, a bad jump (`Halt::BadJump` — a `ja`/`j*`/internal-`call` target outside the function's
text, or a `callx` to an unknown target), a bad instruction (`Halt::BadInsn` — a register nibble
above `r10`, or an opcode byte `isa::classify` does not assign), an unrecognised syscall hash
(`Halt::UnknownSyscall`, including a cross-program-invocation name, §5), call depth over
`MAX_CALL_DEPTH`, and the instruction limit, kept as a counter decremented by the block's length
at the head of each basic block and checked there. **Amended 2026-09-18** (Task 3 review ruling;
an earlier draft said the check "halts at the same or a later instruction, never earlier", which
a head check does not meet): the halt lands at the head of the block that would cross the limit,
and the halt kind may differ from the interpreter's — which counts one instruction at a time —
only in that block (a fault part-way through it may be reported as `InstructionLimit`). The status
and the eight public words are equal either way, since every exceptional halt publishes status 2
over the pre-state. **Deferred checks (Task 4, ruled final in its review)**: a block may skip its
check only if it does not end in `exit`/`call`/`callx`, has no self-loop, and every in-function
neighbour checks (`sbpf2rv/src/emit.rs`, `choose_checked`). Such a block only *charges* its
length; if it is the one that crosses the limit, it runs to its end and the next block's head
halts `InstructionLimit` (or it faults on the way: a different kind, but only in the crossing
block), and no run the interpreter completes is ever halted. It is what fits the SPL Token program
into the machine's 65 535-word program cap. **Amended
2026-09-18**: a static `ja`/`j*`/internal-`call` target outside the text, and a bad register or
opcode, are *runtime* traps like everything else in this paragraph, not rejected at translation
as an earlier draft of this spec had it — none of it is a load-time check in the interpreter
either (`interp.rs` raises each only when it executes the instruction in question), and the
committed SPL Token ELF contains reachable-but-unexercised code that fails some of these checks,
so a translator that refused them outright would refuse a program the interpreter runs
successfully today. The scanner (`sbpf2rv/src/scan.rs`) still finds every one of these
statically and reports it (a `Warning`), it just no longer *refuses* the program over it.

**Memory.** The interpreter's four regions (`memory.rs`) are kept as the address model: a
64-bit virtual address is `region << 32 | offset`; `tr(addr, n)` looks the region up in a
four-entry table of `(base, len, writable)`, bounds-checks `offset + n`, and traps on a miss
exactly as `Memory` does. The stack (`STACK_FRAME × MAX_CALL_DEPTH`), heap (`HEAP_BYTES`) and
input region live in the shim crate's `.bss` as today's `Workspace`. When an address is
syntactically `r10 ± imm`, the translator emits the stack access with the frame's static bounds
check folded and no table lookup.

## 4. The shim crate and the ABI

The generated `src/main.rs` is the interpreter's `sbpf/src/main.rs` with one change:
`run_call_with` receives a closure that calls the translated entry `f_<entry>` instead of
constructing a `Vm`. Input decoding, `check_region`, `canonical_input_hash`, `output_hash`,
`public_output` and the `SBPF_OUT` digest are `sbpf-core::abi` unchanged. The ELF still arrives
as the **public** input segment and is still hashed into the digest as `program_id`, so the
chain binds the translated program to the sBPF it came from even though it never executes the
sBPF: a verifier can re-run `sbpf2rv` on the published ELF and check `hc`. The C file is
compiled by `rand-guest` through the crate's `build.rs` (`cc` with the toolchain's clang flags).

## 5. The runtime

`sbpf-rt`, a small C library the toolchain ships: the region table and `tr`; `sbpf_trap`; the
twelve syscalls `SUPPORTED` lists today, with `sol_sha256` on the coprocessor via the SDK,
`sol_memcpy_`/`memmove_`/`memset_`/`memcmp_` as bounds-checked region loops,
`sol_alloc_free_` as the bump allocator over the heap region, the log family as no-ops that
return 0, `abort` and `sol_panic_` as traps; `sol_poseidon` where the interpreter has it. Beyond
the interpreter, **`sol_ed25519` verify and `sol_secp256k1_recover` exist as pure C**
(`sbpf-rt/sbpf_ed25519.c`, `sbpf-rt/sbpf_secp256k1.c`: reference-style field and group
arithmetic, no lookup tables), correct and slow, but **not linked into any generated shim, and
not in `sbpf_syscall`'s dispatch** (**amended 2026-09-18, Task 3/7**: an earlier draft of this
spec implied they were reachable; ruled out for parity, since the interpreter itself only ever
raises `Halt::UnknownSyscall` for both hashes — neither is in `syscalls::SUPPORTED` — so a
translated call that actually reached the C implementation would disagree with the interpreter it
must match byte for byte). They are measured in cycles (`sbpf2rv/README.md`'s coprocessor-backlog
section) and left in the tree, unlinked, as a coprocessor backlog for a future machine milestone,
not this tool's; a `call imm` naming either hash traps `UnknownSyscall` exactly like any other
unimplemented syscall, below. **Cross-program invocation (`sol_invoke_signed*`) is translated, not refused**: a proof
carries one program's execution and a multi-program model is a chain design, so `sbpf-rt` has
nothing to call for it, but the call site itself is ordinary translated code — `sbpf_trap` with
the interpreter's own `Halt::UnknownSyscall`, the same as any other syscall hash `sbpf-rt` has no
implementation for. **Amended 2026-09-18**: an earlier draft of this spec refused CPI at
translation; ruled out because the interpreter itself only ever raises `UnknownSyscall` when a
`call imm` naming it is executed, never at load, so refusing the whole program over an unreached
CPI call would refuse programs the interpreter accepts (the committed SPL Token ELF's own
unreached, unsupported syscalls are the same case). The scanner still reports every CPI call site
it finds (a `Warning`), it just no longer refuses the program over one.

## 6. Testing

- **Interpreter parity.** Every sBPF vector `sbpf-core` tests (the SPL Token transfer among
  them, plus mint and burn added here) runs through the interpreter on the host and through the
  translated program under `rand-guest run`; the eight output words must be identical, and so
  must the status on every failing vector.
- **Differential fuzzing.** A generator emits random well-formed sBPF function bodies over the
  full opcode set (bounded loops, valid jump targets, all widths, both ALU sizes, the signed and
  v2 families, byte swaps); each runs in both, and outputs or trap kinds must agree. Ten
  thousand cases in CI's fast set, more on demand.
- **Every class has a directed test** that the translation of each opcode is exactly the C
  statement the table above specifies, over the edge values (zero divisor, shift by width,
  minimum signed values, unaligned region boundaries).
- **Cycles.** The SPL Token transfer's cycle count under `rand-guest run`, reported against the
  interpreter's, is the milestone's number; the spec sets no target, since the point of v0.4 is
  to measure it.
- **A real proof.** The translated SPL Token transfer proves under the research prover's test
  profile and verifies, once, as the exit gate.

## 7. Out of scope

Register lifting beyond what clang does; a JIT; CPI; the coprocessors themselves; on-chain
translation; anything in `fullnode`.
