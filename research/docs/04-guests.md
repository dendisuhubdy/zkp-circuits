# Guests: how Solidity and Solana enter R_exec

Only RISC-V executes natively in this machine. The other two chains the
protocol targets run as *software inside it*: an interpreter for their
bytecode, compiled to RV32IM like any other guest, with the target program's
own bytecode passed in as private input. Publishing a "confidential
contract" is registering `hc` for the interpreter plus a commitment to the
bytecode — never generating a new circuit per contract. This is the same
choice the whitepaper makes for its zkVM comparison.

## The Solidity path

`solc` compiles a contract to EVM bytecode as it always would. A `no_std`
EVM interpreter, itself compiled to RV32IM, receives that bytecode (as
private input, via `READ_INPUT`) and the call's calldata, and executes it
opcode by opcode inside the guest. Cheap opcodes (arithmetic, stack, memory,
control flow) map onto a handful of native RV32IM instructions each; the
expensive ones need dedicated coprocessor tables rather than a naive
byte-by-byte simulation, or Solidity guests would be orders of magnitude
slower than the RISC-V native path:

| EVM opcode(s) | Coprocessor needed | Notes |
|---|---|---|
| `KECCAK256` | Keccak-f\[1600\] table | the vendored Plonky3 0.7 set has `p3-keccak` (the permutation) but no `p3-keccak-air` — M4.2 hand-writes the chip (`docs/superpowers/specs/2026-09-11-zkvm-m4-design.md` §3) |
| `ADDMOD`, `MULMOD`, `EXP` | 256-bit modular arithmetic | native words are 32-bit; a 256-bit value is eight limbs, and mulmod/expmod need a dedicated multi-limb multiplier, not four chained 32-bit ALU ops |
| `ECRECOVER` (and any signature-checking precompile) | secp256k1 recovery | needs field/group arithmetic over a non-Goldilocks curve; this is exactly the CPI/secp256k1 gap noted for `randprotocol-svm` and is shared work |
| `SLOAD`/`SSTORE` | Merkle-witness syscalls | EVM storage is a sparse Merkle tree keyed by 256-bit slots; each access becomes a `MERKLE_VERIFY`-style syscall against a public state root, which is milestone 3 machinery, not milestone 4's |

## The Solana path

An sBPF ELF (the compiled form of an SPL program) is interpreted the same
way: an sBPF interpreter compiled to RV32IM, ELF bytes as private input.
sBPF is itself a small load/store ISA — 11 general registers, 64-bit
values — so unlike the EVM's stack machine, a direct sBPF→RV32 *translator*
(compiling sBPF instructions to native RV32IM ahead of execution, rather
than interpreting them one at a time) is a natural later optimisation once
correctness is established through the interpreter. Coprocessors this path
wants:

| SVM primitive | Coprocessor needed | Notes |
|---|---|---|
| `sol_sha256` | SHA-256 table | same shape of problem as Keccak: a fixed permutation run many times |
| `sol_ed25519` verify | Ed25519 | needed for signature-verifying programs; today's `randprotocol-svm` has no secp256k1 *or* Ed25519 support and no Instructions sysvar, which blocks this and the bridge use case alike |
| 64-bit multiply/shift | limb doubling | every sBPF register is 64 bits; each op costs roughly two RV32 operations interpreted, the RV64-vs-RV32 tradeoff from `docs/01-isa.md` showing up concretely here |

## Estimated cycle multipliers

Rough, not measured (no interpreter exists yet): a native RV32IM instruction
costs 1 cycle by definition. An interpreted EVM opcode costs on the order of
5–20 cycles (fetch bytecode byte, dispatch, execute — mostly dispatch
overhead for cheap opcodes); an interpreted sBPF instruction costs on the
order of 2–5 cycles for arithmetic (mostly the 64-bit-as-two-32-bit tax) but
1 for anything already word-sized. `KECCAK256`/`SHA-256`/`ECRECOVER`/
`sol_ed25519` are each worth thousands of native cycles if simulated
bit-by-bit — which is exactly why each needs its own AIR table rather than
running through the general-purpose ALU.

## What milestone 4 builds first

The EVM interpreter, because it is the more immediately useful target (an
ERC-20 `transfer` proving under `R_exec` is the milestone's own exit
criterion). The vendored Plonky3 0.7 set has no `p3-keccak-air` (only the
bare `p3-keccak` permutation — corrected above), so M4.2 hand-writes the
Keccak-f[1600] chip rather than reusing an upstream one; this is now a
known, scoped cost rather than an unknown. The sBPF interpreter and its
coprocessors follow once the general "interpreter guest + coprocessor
table" pattern is proven out once, on the EVM.

## Compiled guests (M4.1)

Before M4.1, every guest in this crate was hand-assembled directly against
`asm.rs`'s mnemonic helpers — there was no RISC-V cross toolchain on the
development machine. M4.1 adds one:

- **`guest-sdk`** (`no_std`, `#![no_std]`): syscall wrappers as
  `#[inline(always)]` `asm!` blocks matching `docs/01-isa.md`'s ABI exactly
  (`read_input`, `write_output`, `poseidon2`), the guest entry point
  (`_start`, a `global_asm!` block that sets `sp` from the linker-provided
  `__stack_top` and calls `main`, falling through to a `HALT` ecall as
  defense in depth if `main` ever returns), a panic handler (halts with
  output slot 7 set to `0xdead_beef`), and `guest.ld`, the linker script
  placing RAM at `ORIGIN = 0x1000` with a 64 KiB stack region.
- **`guests-compiled/<name>/`**: one crate per compiled guest, targeting
  `riscv32im-unknown-none-elf` (`.cargo/config.toml`: `-C
  link-arg=-T../../guest-sdk/guest.ld` — a path relative to the crate
  root, since the linker's cwd during the link step is the guest crate's
  own directory, one level below where `guest.ld` lives; `-C
  target-feature=-unaligned-scalar-mem`, explicit even though it is this
  target's default, since a misaligned load/store is a constraint
  violation in this machine, not something the compiler may assume the
  hardware tolerates). Each guest's `Makefile` resolves `llvm-objcopy` out
  of the toolchain's own sysroot (`rustc --print sysroot`, not a hardcoded
  host triple — it isn't on `PATH`), builds with `cargo +1.98.1 build
  --release`, and converts the ELF to a flat image with `llvm-objcopy -O
  binary`; the Makefile header records the exact `rustc +1.98.1 --version`
  the committed `.bin` was built with, and a clean rebuild reproduces the
  identical sha256. The resulting `.bin` is committed (alongside its own
  `.sha256`) so a reviewer without the target installed can still run
  every test — `research/src/guests.rs`'s `compiled` module loads it with
  `include_bytes!` + `Program::from_flat_binary(0x1000, BIN)`.

The loader only ever populates the instruction space from the flat image
— RAM starts zero and nothing copies `.rodata`/`.data` bytes into it — so
a guest built this way must keep those sections empty (loading data into
RAM is future work, needed before M4.3).

One deviation worth knowing about: `guest-sdk::halt()` does **not** use
`asm!`'s `options(noreturn)` (a literal reading of the design spec's own
snippet would). On this bare-metal target, `rustc` unconditionally
lowers the IR block LLVM synthesizes after a `noreturn` `asm!` into a
genuine trap instruction (`0xc0001073`, disassembling as `unimp` — not
`ECALL`/`EBREAK`, so `Instr::decode` correctly rejects it at load time).
`halt()` instead ends with a real trailing `loop {}`, giving the compiler
a genuine backward branch to satisfy `-> !` without needing to synthesize
`unreachable` at all — the function still never returns, and the trailing
word is never actually executed (the preceding `ecall` halts first), it
only needs to be *decodable*, which it now is.

Measured numbers for the first guest built this way:

| Guest | Source | Tier | Cycles | Proof size |
|---|---|---|---|---|
| `fib(20)`, compiled (`guests::compiled::fib`) | `guests-compiled/fib` | `Tier(10)` | 136 | 271,600–275,889 bytes over three proofs (varies per proof with the hiding salt; measured after the input table landed — the 253,208 figure recorded before it is not comparable) |

Measured by `research/tests/e2e.rs`'s `compiled_fib_proves_and_verifies`
(`cargo +1.98.1 test -p rand_zkvm --test e2e compiled_fib -- --nocapture`,
`FriProfile::Test`), and confirmed against the hand-written
`guests::fib` guest by `compiled_fib_matches_the_hand_written_guest` (same
output, same public values, run through the same emulator).

## Hand-written note-layer guests (not this milestone's pipeline)

`guests::transfer` (M3.3) and `guests::bundle` (shielded pool phase Z Task 3)
are not compiled-guest-toolchain guests — like every other guest in this
crate before M4.1, they are written directly against `asm.rs`'s mnemonic
helpers, not built by `guest-sdk`/`guests-compiled` above. `bundle` is this
crate's second hand-written note-layer guest, proving the shielded pool's
2-in-2-out transfer relation (fee/burn conservation, dummy notes that skip
membership) instead of `transfer`'s 1-in-1-out one. See
`docs/06-viewing-keys.md`'s "Notes and what the guest proves" and "The
`bundle` relation" sections for what each proves and their measured
words/cycles/permutations/tier.
