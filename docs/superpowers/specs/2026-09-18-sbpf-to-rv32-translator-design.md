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

**Functions.** The entrypoint and every `call` target found by a scan over the text become one C
function each: `static uint64_t f_<pc>(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4,
uint64_t r5)` returning `r0`. `r6..r9` are C locals saved and restored around calls, which is
the sBPF calling convention; `r10` (the frame pointer) is a local advanced by `STACK_FRAME` per
call depth. Unreachable text is not translated. Registers are `uint64_t` locals, so clang, not
this tool, chooses the RV32 register pairs and spills — the "direct lowering with register
pairs" of the approved design, done by the compiler.

**Instructions.** Every opcode in `isa.rs`, one C statement each, in `classify`'s classes:

| class | translation |
|---|---|
| `ld` (`lddw` imm64) | a constant |
| `ldx` / `st` / `stx`, all four widths | `rd = *(uintN_t*)tr(addr, N)` / `*(uintN_t*)tr(addr, N) = v`, with `tr` the region translation below; little-endian as sBPF is |
| `alu32` / `alu64`: add sub mul div or and lsh rsh neg mod xor mov arsh | the C operator on `uint32_t` (alu32 zero-extends the result, as the interpreter does) or `uint64_t`; shifts mask the count to 31 / 63 |
| v2 signed ops (`sdiv`, `srem`, the pqr product/quotient/remainder family), `hor64` | the matching signed C operator on `int32_t` / `int64_t`, with the interpreter's exact overflow and zero rules |
| `le` / `be` byte swaps (16/32/64) | `__builtin_bswap*` or a mask |
| `ja` / `jeq` / `jgt` / `jge` / `jlt` / `jle` / `jset` / `jne` / `jsgt` / `jsge` / `jslt` / `jsle` (imm and reg) | `if (…) goto L_<pc>;` |
| `call imm` (internal) | `r0 = f_<target>(r1..r5)` after the depth check |
| `call imm` (syscall by hash) | `r0 = sol_<name>(r1..r5)` from the runtime (§5) |
| `callx` | `switch (reg) { case <pc>: r0 = f_<pc>(…); break; … default: trap(BadInsn) }` over the known function set |
| `exit` | `return r0` |

Every instruction that can trap does so through `sbpf_trap(code)`, which unwinds to the harness
with the interpreter's `Halt` value so the canonical failure output is byte-identical: division
by zero, a bad jump (a `ja`/`j*` target outside the function's text is rejected at translation;
a `callx` to an unknown target traps at runtime), call depth over `MAX_CALL_DEPTH`, and the
instruction limit, kept as a counter decremented by the block's length at the head of each basic
block and checked there (the interpreter counts one per instruction; the block-granular check
halts at the same or a later instruction, never earlier, and never past the limit plus one
block — the spec pins this as "halts within the block that crosses the limit", and the
differential tests compare outputs, not the exact halting pc).

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
the interpreter, **`sol_ed25519` verify and `sol_secp256k1_recover` are provided as pure C**
(the reference-style field and group arithmetic, no lookup tables), correct and slow: they are
measured in cycles and listed as the coprocessor backlog, which is a machine milestone, not this
tool's. **Cross-program invocation (`sol_invoke_signed*`) is refused at translation** with a
message: a proof carries one program's execution, and a multi-program model is a chain design.

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
