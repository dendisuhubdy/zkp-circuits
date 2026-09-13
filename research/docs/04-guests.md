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
| `ADDMOD`, `MULMOD`, `EXP` | 256-bit modular arithmetic | native words are 32-bit; a 256-bit value is eight limbs, and mulmod/expmod need a dedicated multi-limb multiplier, not four chained 32-bit ALU ops. **M4.3 ships them in software** (`evm-core::u256`: schoolbook multiply into a 16-limb product, Knuth algorithm D for division, checked against `num-bigint`), which is correct but is part of why an interpreted opcode costs what it does — a chip here is still the optimisation |
| `ECRECOVER` (and any signature-checking precompile) | secp256k1 recovery | needs field/group arithmetic over a non-Goldilocks curve; this is exactly the CPI/secp256k1 gap noted for `randprotocol-svm` and is shared work |
| `SLOAD`/`SSTORE` | Merkle-witness syscalls | EVM storage is a sparse Merkle tree keyed by 256-bit slots. **M4.3 does this in guest code**, not as a syscall: a depth-32 tree over the note layer's own domain-tagged Poseidon2 hashes, one witness per slot touched, verified and updated in Rust (`evm-core::storage`). That needed no machine change, and it is the single biggest line in the cycle budget below — 132 `POSEIDON2` calls for one `transfer` — so a looped `MERKLE_VERIFY`-shaped syscall (or a wider sponge rate) is the named follow-up |

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

The flat loader only ever populates the instruction space — RAM starts zero
and nothing copies `.rodata`/`.data` bytes into it — so a guest loaded that
way must keep those sections empty, which a hand-written sponge loop manages
and a real compiler output never does. **M4.3 closed that** with the image
container (`docs/01-isa.md`'s "The image container"): `.text ‖ data` in one
file, and `Program::from_flat_image` synthesises the `li`/`sw` prologue that
writes the data to its link addresses before the guest's entry, so `hc` binds
the constants and `fib`/`keccak256` keep their byte-identical flat images
(`n_data = 0` is the same `Program`, the same `hc`).

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

### The `evm` guest — M4.3's exit test

`guests-compiled/evm` is the Solidity path made executable: **an ERC-20
`transfer`, compiled by `solc` and executed by an EVM interpreter inside the
zkVM, under `R_exec`, with the contract's storage supplied as Merkle
witnesses.** Nothing in the machine changed for it — no table, no syscall, no
public value; it is one more compiled guest and one more `hc`. Two caveats stated
up front, both measured below: the call costs tier 18, not the plan's tier ≤ 16,
and at that size its *proof* does not fit the development machine's memory, so
the in-suite proof of this guest is a smaller call and the transfer's own proof is
an `#[ignore]`d test.

**The `evm-core` / `Host` split.** The interpreter is a `no_std` library crate
(`guests-compiled/evm-core`, ~1 950 lines: `u256`, `storage`, `interp`, `abi`)
generic over a two-method `Host` trait — the Keccak-f[1600] permutation and the
Poseidon2 sponge, the only two things the guest cannot compute for itself. On
the target those are the `KECCAK` and `POSEIDON2` syscalls (the guest's whole
`src/main.rs` is 50 lines, comments included); on the host they are this crate's
own `keccak::keccak_f` and `hash::sponge_hash` (`rand_zkvm::evm::HostRef`), so
every opcode, the 256-bit
arithmetic and the storage tree are unit-tested natively, and differentially
against `revm 43.0.2` and `num-bigint`, on exactly the arithmetic the guest
will run in-circuit. **`evm-core` is tested on the host and compiled into the
guest**: `research/tests/evm_{u256,storage,interp,abi}.rs` are host tests of
the same code the committed `.bin` contains.

**The call, in and out.** One `READ_INPUT` vector carries the whole call —
`[n_code, code…, n_calldata, calldata…, address(8), caller(8), callvalue(8),
gas_limit(1), pre_root(8), n_witnesses(1), witness…]`, each witness 272 words
(`slot(8) ‖ value(8) ‖ 32 siblings × 8`), 256-bit values as their own
little-endian limbs. It is private and hiding (`H_IN`), and a read past it is
unsatisfiable in-circuit, which is what lets the guest pass `u32::MAX` as its
cursor bound: a truncated vector produces no proof rather than a short read.
The eight public outputs are `out0 = status` (1 success, 0 `REVERT`, 2
exceptional halt) and `out1..out7` = words 0..6 of

```text
hash(EVM_OUT, [codehash(8) ‖ pre_root(8) ‖ post_root(8) ‖ return_hash(8) ‖ logs_hash(8)])
```

— 40 words through the domain-tagged sponge: a 224-bit binding of the
contract, **both** state roots, the return data and the logs. A status other
than 1 binds `post_root = pre_root` and an empty log set (a status of 2 binds
empty return data as well), so a failed call can never publish a state change;
`abi::public_output` is the single place that rule lives.

**Storage.** A depth-32 sparse Merkle tree over 256-bit slots, hashed with the
note layer's own domain-tagged Poseidon2 sponge rather than Keccak: leaf
position is the top 32 bits, big-endian, of `keccak256(slot)` (bit `i`
choosing left/right at level `i` — `emit_merkle_verify`'s convention), the leaf
is `hash(STORAGE_LEAF, [slot ‖ value])` and a node `hash(NODE, [left ‖ right])`,
the note tree's own. The leaf is **canonical in the value**: a zero value
hashes to one fixed leaf whatever the slot, so an absent slot, a never-written
slot and a slot written back to zero are the same and the root is
history-independent. The guest never holds the tree — it holds the pre-state
root and one witness per slot the run touches, verifies each the first time it
is used, and on a store refreshes exactly the sibling every *other* witness
holds at the level where its path diverges (independent witnesses against the
pre-root otherwise go stale the moment one leaf changes). A slot the bytecode
touches with no witness is an exceptional halt, so the witness list is the
call's access list. `MAX_WITNESSES = 16`.

**Known limitation (storage index).** The leaf position is only the top 32
bits of `keccak256(slot)`, so two slots can be ground into one position at
about 2^32 work. That is **not** a forgery: a position holds one slot, and the
colliding slot simply has no witness that verifies, so the call halts
exceptionally (status 2, state unchanged). It is a griefing vector — an
attacker who grinds a collision against a known contract can make one pair of
slots unusable together — and it is fail-closed. The remedy, when it matters,
is a deeper index (the full 256-bit slot hash over a depth-256 tree, or a
sparse index with 64+ bits), which is a tree-shape change, not a protocol one.

**Traps.** `Halt` is `Stop`, `Return`, `Revert`, `OutOfGas`, `StackUnderflow`,
`StackOverflow` (1024), `BadJump`, `Invalid` (`0xfe`), `Trap(op)` for anything
outside the subset, `NoWitness`, `BadWitness`, and `OutOfBounds` (a memory
range past 64 KiB, return data past 1 KiB, more logs than `MAX_LOGS`, an
over-long code or calldata). Everything but `Stop`/`Return`/`Revert` is status
2 and burns the whole gas limit. None of them is a panic: every length
involved is prover-supplied, and a panicking guest aborts *without* producing a
proof, where an exceptional halt produces a proof that says the call was
invalid.

**Out of scope, and why each one traps rather than being stubbed:**

| Opcodes | Why not |
|---|---|
| `CALL`, `CALLCODE`, `DELEGATECALL`, `STATICCALL`, `CREATE`, `CREATE2` | needs `CALL` semantics: a second frame, a second code/storage pair, return-data plumbing and revert scoping. One contract per proof is M4.3's scope |
| every precompile (`ECRECOVER`, `MODEXP`, the BN254 pairs, `BLAKE2F`, …) | needs a chip each (secp256k1 recovery, a modular-arithmetic chip, a pairing) — the table above |
| `BLOCKHASH`, `TIMESTAMP`, `NUMBER`, `COINBASE`, `DIFFICULTY`/`PREVRANDAO`, `GASLIMIT`, `CHAINID`, `BASEFEE`, `BLOBHASH` | needs block context, i.e. public values the chain would have to supply and the verifier check. Nothing in the ERC-20 subset reads them |
| `BALANCE`, `SELFBALANCE`, `ORIGIN`, `GASPRICE`, `EXTCODESIZE`/`EXTCODECOPY`/`EXTCODEHASH` | needs account state beyond one contract's storage — a second tree and a second witness kind |
| `SELFDESTRUCT` | needs account deletion semantics *and* balance transfer |
| `TLOAD`/`TSTORE`, `MCOPY` | Cancun; the guest targets Shanghai, and `solc --evm-version shanghai` emits neither. (This is why the contract is compiled with that flag: on a 0.8.37 default, `MCOPY` appears and traps) |
| `RETURNDATACOPY` with a non-zero length | there is no inner call, so the return-data buffer is always empty; `RETURNDATASIZE` is 0 and a zero-length copy is legal |

**Measured**, `FriProfile::Test`, `research/tests/e2e.rs`'s `compiled_evm_*`
tests (`cargo +1.98.1 test --release --test e2e compiled_evm -- --nocapture`):
an ERC-20 `transfer` of 250 from a pre-state balance of 1 000, two storage
slots touched, one `Transfer` log.

| | |
|---|---|
| contract | `guests-compiled/evm/contracts/ERC20.sol`, `solc 0.8.37`, `--optimize --optimize-runs 200 --evm-version shanghai`, 1 296 bytes of runtime bytecode (committed as hex; `contracts/SOLC.md` records the binary's sha256 and the exact command) |
| guest program | **17 978 words** — 16 348 of text plus a 1 630-instruction data prologue for 2 428 bytes of `.rodata` (the opcode dispatch's jump tables and the panic locations) — and 4 495 program-digest rows |
| input vector | 921 words (the bytecode, 68 bytes of calldata, the env, two 272-word witnesses) → 232 input-digest rows |
| cycles | **121 630 executed**, 126 357 total with both digest prefixes |
| Poseidon2 | 1 070 absorb rows (132 sponge calls: four 32-level Merkle walks, plus the leaves and the output digest), 5 797 permutations in all with the digest prefixes |
| Keccak | 17 permutations (`codehash` over 1 296 bytes is ten of them; two mapping-slot hashes; the return-data and logs hashes) |
| tier | **`Tier(18)`** — `keccak_log_height` would be 10 (17 permutations = 544 rows, padded to 1 024) |
| the proof | **not produced on the development machine**: a tier-18 batch is 2^18 cpu rows, 2^20 memory and poseidon2 rows and a 2 612-column keccak table, and proving it peaked at ~25 GB resident and was OOM-killed twice on a 48 GB machine. `compiled_evm_erc20_transfer_proves_at_tier_18` is therefore `#[ignore]`d — run it where there is room. Everything that does not need 25 GB (the guest's outputs, the digest binding, the tier arithmetic) is asserted by `compiled_evm_erc20_transfer_binds_the_state_root_transition`, which always runs |

**The in-suite proof.** `compiled_evm_storage_read_write_and_return_proves_and_verifies`
proves **the same `evm.bin`, the same `hc` and the same `EVM_OUT` digest** on a
smaller call — 18 bytes of bytecode that `SLOAD` slot 1, add one, `SSTORE` it back
and `RETURN` it, with one witness verified and one Merkle path recomputed — and
verifies it. That is the test that says the EVM interpreter guest is provable: the
storage tree, the 256-bit arithmetic, the `POSEIDON2` walk and the public output
are all in-circuit in it. It lands at `Tier(16)` because 18 bytes of code need
neither the ERC-20's 1 296-byte `codehash` nor its second Merkle walk:

| | |
|---|---|
| cycles | 28 197 executed |
| tier | `Tier(16)`, `keccak_log_height = 7`, `mem_log_height = 18` |
| proof | 776 248 bytes; 421 s to prove, 14.8 s to verify |

`compiled_evm_balance_of_approve_and_a_revert_execute_correctly` runs three
more call shapes through the *same* binary and the same `hc` — `balanceOf`
(a view call: one witness, no state change), `approve` (the nested
`_allowances[owner][spender]` mapping, one `Approval` log with three topics)
and a `transfer` of 5 000 against a balance of 1 000, which reverts with
Solidity's ABI-encoded `Error(string)` — selector, offset, length,
`"ERC20: transfer amount exceeds balance"`, right-padded to a word — and moves
no storage. (That encoding is the reason the contract keeps `require` messages
rather than custom errors: it is the only way a message reaches a chain, through
the output digest's return-data hash.) All four calls agree with a native `evm-core` run word for word, and
no two of them share a public output.

**Tier: a deviation from the plan.** The M4.3 plan's exit criterion was tier
≤ 16 and the design spec's estimate was tier 14; the measured cost is **tier
18** — the next rung, since `machine::TIERS` is `[10, 12, 14, 16, 18, 20]` and a
workload one cycle over tier 16's 65 535 pays for 2^18 rows. Getting to tier 16
therefore means halving the call, not trimming it.
The dominant costs, measured by fixture rather than guessed (the plan's Task 5
report has the full table):

| | cycles |
|---|---|
| the interpreter itself (~250 opcodes: dispatch, software 256-bit arithmetic) | ~51 200 |
| the four Merkle walks (132 17-word `POSEIDON2` calls at ~207 cycles each, measured as the slope of 1, 2 and 3 `SLOAD`s) | ~27 300 |
| the code: decoding 1 296 bytes, the jumpdest scan, and `codehash` over it | 23 021 |
| fixed overhead of any call: the cursor, the interpreter's setup, the output digest | 13 922 |
| decoding the two 272-word witnesses | 6 334 |
| the program- and input-digest prefixes | 4 727 |

Local levers took the first working cut from 224 212 total cycles to 126 357
(both tier 18, but the first was 1.7× the second), each measured rather than
assumed:

- `Interpreter::new` clears only the memory a previous run dirtied instead of
  all 64 KiB — **−51 606**, most of a tier's budget spent zeroing an array the
  machine already guarantees starts zeroed.
- every sponge call marshals a 17-word buffer in place, instead of building a
  16-word message array and copying it into a zeroed 48-word one — the storage
  walks went from ~112 300 cycles to ~27 300, i.e. ~850 → ~207 cycles a call, of
  which 8 are the syscall itself.
- the input cursor unpacks words with byte stores rather than a
  `copy_from_slice` per word, which was a `memcpy` *call* each: ~29 → ~4 cycles
  a byte. (It is `#[inline(never)]`: inlined into both call sites the loop
  unrolled into 20 KB of extra program, and program words are digest rows, which
  are cycles.)
- Keccak absorbs full blocks straight out of the message, staging only the
  padded final block.
- the opcode dispatch keeps its **jump tables** — measured both ways, they are
  1 667 cycles cheaper all in than a compare-and-branch chain, which is a result
  the image container makes possible at all.

What is left is not marshalling: it is 132 sponge calls and a software 256-bit
interpreter. The named follow-ups, in the order they pay, are a looped
`MERKLE_VERIFY`-style storage syscall (or a sponge that absorbs more than four
words a permutation), then the dispatch loop and a modular-arithmetic chip.
`opt-level = "s"` was measured and rejected: it halves the program (8 666
words) but nearly doubles execution (238 319 cycles), and `opt-level = 2` is
worse than 3 on both counts once digest rows are counted.

**Proof size on the fullnode.** The keccak table is present in this proof, so
at the production profile it is about 3.2 MB (1.25 MB + the table's ~1.91 MB).
The fullnode's `MAX_PROOF_BYTES` is 2 MiB (constraint set 5), so **a vendoring
that carries M4.3 needs a 4 MiB proof cap** (and `fullnode/docs/block-space.md`'s
block-cap question revisited with it). That is a fullnode-side change, made at
vendoring time, not here.

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
