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
| `KECCAK256` | Keccak-f\[1600\] table | **done (M4.2)** — the vendored Plonky3 0.7 set had `p3-keccak` (the permutation) but no `p3-keccak-air`, so the chip was hand-written: `tables::keccak`, 2 612 main columns, one row per round in 32-row blocks, `docs/02-tables-and-buses.md`'s `keccak` section. The sponge (rate, padding, squeeze) stays in guest code |
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
criterion). The vendored Plonky3 0.7 set had no `p3-keccak-air` (only the
bare `p3-keccak` permutation — corrected above), so M4.2 hand-wrote the
Keccak-f[1600] chip rather than reusing an upstream one. That is now done and
measured, not an estimate: 2 612 main columns (the design spec guessed
~2,650), max constraint degree 3, one `SYS_KECCAK` cpu row per permutation,
and the chip sending its own 100 memory accesses. The one number the design
did not anticipate is what a 2 612-column table costs in *proof size* — about
705 KB at the production profile, whatever its row count, because FRI openings
scale with a batch's column count (`docs/03-privacy.md`'s M4.2 measurement).
As first built, every proof paid that, since the table's height floored at one
padding block; M4.2's Task 6 made the table **optional per proof**
(`keccak_log_height = 0`, no keccak instance in the batch), so only a guest
that actually calls `KECCAK` pays it.
The sBPF interpreter and its coprocessors follow once the general
"interpreter guest + coprocessor table" pattern is proven out once, on the
EVM; M4.3's SHA-256 chip should plan its column budget against that number —
and should be optional the same way.

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

Measured numbers, `FriProfile::Test`, re-measured on the M4.2 branch (every
proof carries the keccak table now, so the earlier figures are not
comparable — `fib`'s 271,600–275,889 bytes was measured before it existed):

| Guest | Source | Words | Tier | Cycles | Proof size |
|---|---|---|---|---|---|
| `fib(20)`, compiled (`guests::compiled::fib`) | `guests-compiled/fib` | — | `Tier(10)` | 136 | 729,254 bytes |
| `keccak256(135 bytes)`, compiled (`guests::compiled::keccak256`) | `guests-compiled/keccak256` | 461 | `Tier(12)` | 2,848 | 745,151 bytes |

`fib` is measured by `research/tests/e2e.rs`'s
`compiled_fib_proves_and_verifies` (`cargo +1.98.1 test --release --test e2e
compiled_fib -- --nocapture`) and confirmed against the hand-written
`guests::fib` by `compiled_fib_matches_the_hand_written_guest` (same output,
same public values, same emulator).

### The `keccak256` guest — M4.2's exit test

`guests-compiled/keccak256` is the milestone's exit criterion made
executable: Keccak-256 of a message, computed by a *compiled* guest, matching
the host `keccak::keccak256`. The message arrives as private input
(`input[0]` the byte length, `input[1..]` four bytes per word,
little-endian); the 32-byte digest goes to output slots 0..7 the same way.
The sponge — the 136-byte rate, the `0x01`/`0x80` padding, the squeeze — is
`guest_sdk::keccak256`, ordinary compiled guest code; only the permutation is
the `KECCAK` syscall. `research/tests/keccak.rs` transcribes that same loop
and checks it against the host at every block-boundary case (0, 1, 135, 136,
137, 272 bytes), since `guest-sdk` itself only builds for
`riscv32im-unknown-none-elf` and cannot be linked into the test binary.

`compiled_keccak256_matches_the_host_in_one_permutation` runs it on a
135-byte message — one byte shy of the rate, so the padding fits the same
block and the whole hash is exactly **one** permutation
(`keccak_log_height = 5`, the floor). Measured: 461 program words, 2 848
cycles, `Tier(12)`, `mem_log_height = 14` (tier 12's own floor — one
permutation's 100 accesses do not move it), 745 151-byte proof, 23.5 s prove
and 853 ms verify at `FriProfile::Test`. The cycle count is dominated by the
guest's byte-at-a-time input unpacking (one `READ_INPUT` per four bytes plus
a per-byte shift/store loop), not by the hash: the permutation itself is a
single cpu row.

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
