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
| `sol_sha256` | SHA-256 table | **done (M4.4)** — `tables::sha256`, 466 main columns + 10 preprocessed, one row per round in 64-row blocks with no idle rows, behind `SYS_SHA256 = 5` (one compression per cpu row, the chip sending its own 32 memory accesses). Optional per proof like keccak's, and measured: +92 KB at `FriProfile::Test`, +400 KB at the production profile. `docs/02-tables-and-buses.md`'s `sha256` section; padding and the Merkle–Damgård loop stay in guest code (`guest_sdk::sha256`) |
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
1.91 MB at the production profile, whatever its row count, because FRI openings
scale with a batch's column count (~705 KB at the 27 queries M4.2 measured, 80
since the 2026-09-12 revert; `docs/03-privacy.md`'s M4.2 measurement).
As first built, every proof paid that, since the table's height floored at one
padding block; M4.2's Task 6 made the table **optional per proof**
(`keccak_log_height = 0`, no keccak instance in the batch), so only a guest
that actually calls `KECCAK` pays it.
The sBPF interpreter and its coprocessors follow once the general
"interpreter guest + coprocessor table" pattern is proven out once, on the
EVM; M4.3's SHA-256 chip should plan its column budget against that number —
and should be optional the same way.

**That is what M4.4's chip did, and the arithmetic held.** `tables::sha256` is
466 main columns + 10 preprocessed against keccak's 2 612 + 99, and its measured
proof-size cost is +400 563 bytes at the production profile against keccak's
+1.91 MB — a ratio of 0.21 where the column ratio is 0.176, so proof size really
does track a chip's *width* nearly linearly and a chip can be budgeted for before
it is built. It is optional the same way (`sha256_log_height = 0`, no instance in
the batch), and independently, so a guest pays for the hash it actually calls and
nothing else.

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

The hand-written `guests::sha256_demo` (M4.4) is the sha256 analogue of
`keccak_demo`: a 55-byte message, padded at assembly time into a single 512-bit
block, one `SYS_SHA256` call, the 8 digest words published — 116 program words and
116 cycles at tier 10, `sha256_log_height = 6` (the floor), 1 615 520 bytes at the
production profile, checked against the host `sha256::sha256` by
`tests/e2e.rs::sha256_demo_proves_and_verifies_with_one_sha256_block`. The general
Merkle–Damgård loop and runtime padding live in `guest_sdk::sha256`, where
`keccak256`'s sponge lives; a compiled guest over it is M4.4's later business.

Measured numbers, `FriProfile::Test`, re-measured on the M4.2 branch. `fib`
makes no `KECCAK` call, so since Task 6 made the keccak table optional its
proof is back where it was before M4.2 (271,600–275,889 bytes then, 271,987
now); the mid-milestone figure, when every proof carried the table, was
729,254 bytes. `keccak256` does call it, and pays for it:

| Guest | Source | Words | Tier | Cycles | Proof size |
|---|---|---|---|---|---|
| `fib(20)`, compiled (`guests::compiled::fib`) | `guests-compiled/fib` | 26 | `Tier(10)` | 136 | 271,987 bytes |
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

### The `sbpf` guest — M4.4's exit test, and the one number that did not hold

`guests-compiled/sbpf` is an **sBPF interpreter** compiled to RV32IM: 91 v1
opcodes, the four memory regions, twelve syscalls, an ELF64 loader that applies
relocations in place, and the ABI that binds a run — all of it `sbpf-core`, a
`no_std` `#![forbid(unsafe_code)]` library unit-tested natively and
differentially tested against `solana-sbpf` 0.11.1 (M4.4 Task 5). `src/main.rs`
is forty lines: a `Host` whose `sha256_compress` is `SYS_SHA256` and whose
`poseidon2` is `SYS_POSEIDON2`, one `static mut Workspace` in `.bss`, and
`abi::run_call`.

The program it runs is the real thing: `guests-compiled/sbpf/programs/spl_token.so`,
108 600 bytes fetched once from mainnet-beta's program-data account and committed
with its sha256 (`programs/SPL_TOKEN.md` has the RPC calls, the slot, and what the
fetch actually found — the account is owned by the **upgradeable** loader, not the
`BPFLoader2` the plan expected, so the ELF sits behind a 45-byte header on a second
account). `research/tests/sbpf_elf.rs::spl_token_elf_loads_with_relocations_applied`
loads it and compares the **relocated bytes** against `solana-sbpf`'s own relocated
image: the 2 848 bytes of read-only data past the text match byte for byte, and of
the 12 826 text slots the only ones that differ are the 141 bpf-to-bpf calls, at each
of which the reference's registry key is checked to be the one derived from this
crate's slot-relative immediate. The loader touched exactly the 219 slots the file's
own relocation and call tables name and nothing else.

**Measured** (`cargo +1.98.1 test --release --test e2e compiled_sbpf -- --nocapture`),
an SPL Token `Transfer` of 250 tokens between two accounts owned by one signer, with
the mint as a fourth read-only account:

| | |
|---|---|
| program words | 7 715 (6 427 text + a 1 288-word data prologue for 1 856 bytes of `.rodata`) |
| input words | 37 609 (27 151 ELF + 10 458 instruction region) |
| cycles | **1 753 945** |
| sBPF instructions executed | 143 |
| frame-depth high-water mark | **0** |
| SHA-256 compressions | 2 368 |
| `sha256_log_height` | 18 (2 368 blocks × 64 rows = 151 552) |
| `mem_log_height` | not measurable — it is computed inside `build_traces_salted`, which no tier reaches |
| tier, proof size | **none — above `Tier(20)`'s 1 048 575-cycle budget** |

Two of those numbers are the milestone's real findings.

**The frame-depth high-water mark is 0, and 512-byte frames were never viable.**
The plan allocated 64 × 512 bytes on the reasoning that `process_transfer` "uses
well under that". It does not use more *frames* — it uses **no** nested call at
all, because the release build inlines `entrypoint::deserialize`,
`Processor::process` and `process_transfer` into one function — but that one
function's frame is around 2 KiB, and with 512-byte frames the program faults on
its first instruction at `0x1_ffff_f9e8`, 1 560 bytes below the stack region.
A frame size is not a budget the host may choose: it is part of the ABI the
program was compiled against. `sbpf-core` now uses Solana's own 4 KiB frames and
**8** of them: the plan's 32 KiB stack is kept, and what gives way is depth rather
than frame width — eight frames of headroom against a workload that uses one.

**The exit test does not prove, and `program_hash` is why.** 1 753 945 cycles is
not a tuning problem; it is 6.7× the plan's tier-18 budget and 1.7× the largest
tier this machine has. The breakdown, by pc histogram over the guest's symbols
(`sbpf_cycle_breakdown_by_pc`):

| what | cycles | share |
|---|---|---|
| `Sha256::update`/`compress` — 2 368 compressions at ~451 cycles each | 1 066 950 | 60.8 % |
| `run_call_with` inlined into `main`: the input tape, the interpreter, the fills | 600 725 | 34.2 % |
| `memset` (zeroing the 32 KiB stack and 32 KiB heap) | 51 535 | 2.9 % |
| `elf::load` (section walk, call-marker pass, 107 relocations) | ~22 000 | 1.3 % |

and the 2 368 compressions decompose exactly: **1 698 for `program_hash`** over the
108 600-byte ELF, 654 for `input_hash` over the 41 825-byte instruction region, and
8 + 8 for the pre- and post-state account walks. So the ELF — carried on the input
tape (27 151 of the 37 609 words, 72 %) and then hashed (72 % of the compressions) —
costs about **1.20 M of the 1.75 M cycles**, to bind a program of which the run
actually executes 143 instructions.

The plan foresaw the shape of this ("the ELF's ~1 600 compressions dominate the row
count; a follow-up may bind the program by a cached digest instead") while also
making tier ≤ 18 an exit criterion. For a 108 KB program those two cannot both hold,
and no amount of guest-side care closes a 6.7× gap: the *floor* for reading 27 151
words off the tape and compressing 1 698 blocks is several hundred thousand cycles
even with one cycle per word and per byte. Two ruling changes would:

1. **Do not recompute `program_hash` in the guest.** It is a digest of a value the
   verifier already has committed — `hc` binds the guest's own program, and the
   ELF arrives through `H_IN`, so a *declared* `program_hash` checked against the
   input commitment costs nothing in-circuit. Saves ~1.20 M cycles.
2. **Hash a canonical instruction encoding, not the aligned region.** 40 960 of the
   region's 41 825 bytes are `MAX_PERMITTED_DATA_INCREASE` realloc padding — 98 %
   zeros — so 640 of `input_hash`'s 654 compressions hash nothing at all. Hashing
   the accounts' real fields instead (which is what `output_hash` already does)
   leaves ~14 blocks. Saves ~290 K cycles.

With both, the remaining work is ~250 K cycles: tier 18, as the plan asked. Neither
is Task 6's to decide — both change the plan's "Public output" ruling — so
`compiled_sbpf_spl_token_transfer_proves_and_verifies` is committed in full and
`#[ignore]`d with the measurement in its ignore message, and the executor-level
half of the exit test (which passes, and which checks the guest's eight output
words against the native run byte for byte) is what pins the behaviour meanwhile.

Two smaller things the measurement bought, both fixed in `sbpf-core` and both worth
knowing for any future guest on this target:

* **`copy_from_slice` with a run-time length is a `compiler_builtins::mem::memcpy`
  call, and its byte-at-a-time loop costs ~9.5 cycles per byte.** It was 1 448 018
  cycles — 38 % of the first measurement's 3 853 588 — inside `Sha256::update`
  copying each 64-byte block into a scratch buffer that is then read once. Hashing
  whole blocks straight out of the caller's slice, and splitting `InputCursor::bytes`
  into a constant-width-4 bulk loop and a 1–3 byte tail, took the run from 3 853 588
  to 1 753 945 cycles.
* **Read two bytes, not eight, when two will do.** `elf::load`'s call-marker pass
  wants an opcode and a register nibble; decoding the whole `u64` cost 430 570 cycles
  across 12 826 slots.

### Syscalls: what traps, and why

`sbpf-core` implements `abort`, `sol_panic_`, `sol_log_`, `sol_log_64_`,
`sol_log_compute_units_`, `sol_log_pubkey`, `sol_memcpy_`, `sol_memmove_`,
`sol_memset_`, `sol_memcmp_`, `sol_alloc_free_` and `sol_sha256` — the last through
the M4.4 chip. Everything else is `Halt::UnknownSyscall`, which is status 2 over the
pre-state: nothing happened. The committed SPL Token ELF names seven syscalls, five
of them implemented; the two that trap are

* `sol_set_return_data` — `GetAccountDataSize`, `AmountToUiAmount`, `UiAmountToAmount`;
* `sol_get_sysvar` — the rent read `InitializeAccount` does.

Neither is on the `Transfer` path, so this is a scope boundary rather than dead code:
those instructions are out of scope, not broken. The out-of-scope list the design spec
names is unchanged and unreached here — `sol_ed25519_verify`, `sol_secp256k1_recover`,
`sol_keccak256`, `sol_invoke_signed_*`, `sol_get_*_sysvar`, and the two PDA
derivations (`sol_create_program_address`, `sol_try_find_program_address`), which need
`sol_sha256` with the `"ProgramDerivedAddress"` marker *and* an Ed25519 curve check —
the curve check being the Ed25519 work this path does not have. Compute-unit costs are
not modelled at all; the only meter is `MAX_INSTRUCTIONS = 200 000`.

Two more caps are measured rather than assumed. `MAX_INPUT_BYTES` is **49 152**, not
the plan's 16 384: the aligned format the entrypoint deserializes skips 10 240 bytes
of realloc headroom after *every* account unconditionally, so a three-account
`Transfer` is 31 401 bytes and the plan's cap could never have held its own exit test.
`MAX_ACCOUNTS = 64` (Solana's per-transaction limit) still bounds `output_hash`'s
duplicate-resolution table; a region claiming more is walked only that far.

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
