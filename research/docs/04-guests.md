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

**The translator, `evm2rv`, is done (2026-09-18, `circuits/evm2rv`).** It compiles the bytecode to
C over `evm-rt/` ahead of time, in a shim crate `rand-guest build` turns into an image. The shim
reuses the interpreter's ABI harness, so the input vector and the eight public output words do not
change. Stage two (register lifting, the default) runs the ERC-20 `transfer` in 66 235 cycles
against the interpreter's 121 638, at 11 686 program words against 18 009. The harness it shares
with the interpreter (decoding, storage witnesses, the ABI's hashes, the digest) is now about 60%
of those cycles, so further gains must come from the harness or the coprocessors below. One `hc`
per contract: the image carries a digest of its source bytecode and refuses any other code
(status 2), because `CODECOPY` reads the input code. All nine precompiles run in software;
ecrecover (14.5 M cycles), bn256 mul (3.1 M), the pairing (about 1.9 G) and large modexp and
blake2f are over 2^20 and wait on the coprocessors in this table. `evm2rv/README.md` has the
walkthrough with real command output and every number.

| EVM opcode(s) | Coprocessor needed | Notes |
|---|---|---|
| `KECCAK256` | Keccak-f\[1600\] table | **done (M4.2)** — the vendored Plonky3 0.7 set had `p3-keccak` (the permutation) but no `p3-keccak-air`, so the chip was hand-written: `tables::keccak`, 2 612 main columns, one row per round in 32-row blocks, `docs/02-tables-and-buses.md`'s `keccak` section. The sponge (rate, padding, squeeze) stays in guest code |
| `ADDMOD`, `MULMOD`, `EXP` | 256-bit modular arithmetic | native words are 32-bit; a 256-bit value is eight limbs, and mulmod/expmod need a dedicated multi-limb multiplier, not four chained 32-bit ALU ops. **M4.3 ships them in software** (`evm-core::u256`: schoolbook multiply into a 16-limb product, Knuth algorithm D for division, checked against `num-bigint`), which is correct but is part of why an interpreted opcode costs what it does — a chip here is still the optimisation |
| `ECRECOVER` (and any signature-checking precompile) | secp256k1 recovery | needs field/group arithmetic over a non-Goldilocks curve; this is exactly the CPI/secp256k1 gap noted for `randprotocol-svm` and is shared work |
| `SLOAD`/`SSTORE` | Merkle-witness syscalls | EVM storage is a sparse Merkle tree keyed by 256-bit slots. **M4.3 does this in guest code**, not as a syscall: a depth-32 tree over the note layer's own domain-tagged Poseidon2 hashes, one witness per slot touched, verified and updated in Rust (`evm-core::storage`). That needed no machine change, and it is the single biggest line in the cycle budget below — 132 `POSEIDON2` calls for one `transfer` — so a looped `MERKLE_VERIFY`-shaped syscall (or a wider sponge rate) is the named follow-up |

## The Solana path

An sBPF ELF (the compiled form of an SPL program) is interpreted the same
way: an sBPF interpreter compiled to RV32IM, ELF bytes as input. As shipped
(M4.4) they were *private* input; since constraint set 6 they are the
**public** input segment, so the chain publishes the ELF and `H_PUB` binds it
rather than the guest hashing it in-circuit — see "The `sbpf` guest" below for
what that is worth and what it costs.
sBPF is itself a small load/store ISA — 11 general registers, 64-bit
values — so unlike the EVM's stack machine, a direct sBPF→RV32 *translator*
(compiling sBPF instructions to native RV32IM ahead of execution, rather
than interpreting them one at a time) is a natural later optimisation once
correctness is established through the interpreter.

**That translator, `sbpf2rv`, is done (2026-09-18, `circuits/sbpf2rv`)**: it emits one C
function per sBPF function into a shim crate `rand-guest build` turns into an image, reusing the
interpreter's own ABI harness so the chain-visible contract does not change. It refuses nothing —
unknown syscalls, CPI, bad registers/opcodes/jumps become scanner warnings plus the interpreter's
own runtime trap, never a translation-time refusal, matching `interp.rs`'s raise-only-on-execution
rule. The committed SPL Token `Transfer`/`MintTo`/`Burn` all match the interpreter word for word
(the eight public output words and the halt) at 65 096 of the 65 535-word cap. Measured on this
translated program: about 2.4–2.5× fewer cycles per sBPF instruction, but the shared harness
(decoding both tapes, `elf::load`, the region scan) is about 98% of every run's cycles either way,
and the translated image adds 73 k for its ELF guard, so for SPL Token the translation is dearer
(766 k cycles against 694 k for the transfer) and both sides land in tier 20 — translation only
pays off once a program's own execution, not the harness, dominates the run. The ELF guard is what
makes `hc` bind what ran: the ELF is on the public tape (bound by `H_PUB`, not by
`public_output`, whose preimage has no ELF; `program_id` comes from the instruction region), and the
image bakes the digest of the loaded program (text, rodata, addresses, entry) it was translated
from and refuses any other with `BadElf` — the loaded program being everything a run observes of
the ELF. `sbpf2rv/README.md` has the full
walkthrough with real command output, the trust rule (a proof against `hc` is a run of the source
ELF's loaded program; rebuild with Rust 1.98.1, clang 23.1.1 and `cc` 1.4.6 to check `hc == translate(ELF)`; the
chain does not record the ELF's hash), and the coprocessor backlog below. Coprocessors this
path wants:

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
  `riscv32im-unknown-none-elf`, with a linker script placing RAM at
  `guest-sdk/guest.ld`'s `ORIGIN` (or a raised one, for a guest with data —
  `docs/01-isa.md`'s "The image container"). Built by the `rand-guest`
  toolchain crate, not by hand — `guests-compiled/README.md` has the exact
  command and what each pin is; `rand-guest/README.md` lists the compiler
  flags and the target. The resulting `.bin` is
  committed (alongside its own `.sha256`) so a reviewer without the target
  installed can still run every test — `research/src/guests.rs`'s `compiled`
  module loads it with `include_bytes!` + `Program::from_flat_binary(0x1000,
  BIN)`.

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
about 2^32 work. A colliding pair is **refused at the input**: `push` rejects a
witness whose leaf position a previous witness already claimed, which
`decode_input` turns into a parse error and so into the canonical malformed
output (status 2, `post_root = pre_root`). One position therefore carries one
witness per call, and a call that needs both slots of a ground pair cannot be
proved at all. That is a griefing vector — an attacker who grinds a collision
against a known contract can make one pair of slots unusable together — and it
is fail-closed.

The refusal is what makes it fail-closed, and it is not belt-and-braces. The
leaf is canonical in the value, so both witnesses of a ground pair verify
while the position is empty (the same `H(STORAGE_LEAF, [0; 16])` leaf under the
same siblings). Accepting them would let a contract that reads both slots
before writing both bind a `post_root` carrying only the *second* store — the
sibling refresh never touches a witness at the updated witness's own index, and
the second store folds its original siblings — while the interpreter carried on
for the rest of the call believing both writes had landed. That is a divergence
between the bound root and the executed call, i.e. a forgery, not griefing;
refusing the pair where it enters is the five-line fix, and it is why the
witness set's positions are checked for distinctness rather than assumed
distinct. The remedy for the collision itself, when it matters, is a deeper
index (the full 256-bit slot hash over a depth-256 tree, or a sparse index with
64+ bits), which is a tree-shape change, not a protocol one.

**Known limitation (the output binds no caller).** `caller`, `address` and
`callvalue` are private inputs, and nothing in the eight public outputs commits
to them: `out1..out7` digests `(codehash, pre_root, post_root, return_hash,
logs_hash)` and no more, and `H_IN` is salted and hiding (M4.1), so it opens
nothing to a verifier. What a verified proof therefore attests is *"there exists
a `(caller, address, callvalue, calldata)` under which `codehash` maps
`pre_root` to `post_root`, producing this return data and these log topics"* —
and nothing about who was entitled to it. For the ERC-20 that is concrete: a
prover who holds the witnesses can set `caller` to any holder and produce an
accepted `transfer` out of that holder's balance. `logs_hash` binds the
`Transfer` event's `from`/`to` topics, but a topic is only what the bytecode
emitted; no signature is checked anywhere in the guest. The same applies to
`ADDRESS` and `CALLVALUE`: a contract keying on `address(this)` or `msg.value`
gets whatever the prover supplied.

This is not a defect the guest can close on its own, and M4.3 does not claim to:
**authorisation has to come from the chain that consumes the proof** — the spend
authority on the bundle that carries it, an in-guest signature check, or the
shielded pool's nullifier model — or from a later constraint set in which
`EVM_OUT` gains a caller field. Until one of those exists, nothing downstream
may treat this digest as authorisation for the transition it binds; it is
evidence that the transition is a correct execution, not that it was allowed.
The open item is recorded in the spec's §8.

**Traps.** `Halt` is `Stop`, `Return`, `Revert`, `OutOfGas`, `StackUnderflow`,
`StackOverflow` (1024), `BadJump`, `Invalid` (`0xfe`), `Trap(op)` for anything
outside the subset, `NoWitness`, `BadWitness`, and `OutOfBounds` (a memory
range past 64 KiB, return data past 1 KiB, more logs than `MAX_LOGS`, an
over-long code or calldata, and every `ParseError` — including two witnesses at
one leaf position). Everything but `Stop`/`Return`/`Revert` is status
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
| guest program | **18 009 words** — 16 370 of text plus a 1 639-instruction data prologue for 2 444 bytes of `.rodata` (the opcode dispatch's jump tables and the panic locations) — and 4 503 program-digest rows |
| input vector | 921 words (the bytecode, 68 bytes of calldata, the env, two 272-word witnesses) → 232 input-digest rows |
| cycles | **121 638 executed**, 126 373 total with both digest prefixes |
| Poseidon2 | 1 070 absorb rows (132 sponge calls: four 32-level Merkle walks, plus the leaves and the output digest), 5 805 permutations in all with the digest prefixes |
| Keccak | 17 permutations (`codehash` over 1 296 bytes is ten of them; two mapping-slot hashes; the return-data and logs hashes) |
| tier | **`Tier(18)`** — `keccak_log_height` would be 10 (17 permutations = 544 rows, padded to 1 024) |
| the proof | **not produced on the development machine (48 GB): three attempts, ≥ 28.5 GB resident at SIGKILL.** A tier-18 batch is 2^18 cpu rows, 2^20 memory and poseidon2 rows and a 2 612-column keccak table; the OS killed every attempt while the resident set was still growing, so the requirement is *above* 28.5 GB and a **≥ 64 GB machine** is the safe figure. `compiled_evm_erc20_transfer_proves_at_tier_18` is therefore `#[ignore]`d. Everything that does not need that memory — the guest's outputs against a native run, the digest binding, the tier arithmetic — is asserted by `compiled_evm_erc20_transfer_binds_the_state_root_transition`, which always runs |

To produce it, on a machine with the memory:

```sh
cd research && cargo +1.98.1 test --release --test e2e \
    compiled_evm_erc20_transfer_proves_at_tier_18 -- --ignored --nocapture
```

(The three attempts above were `cargo test` *without* `--release` — the dev `[profile.test]`, i.e.
opt-level 1 with debug assertions on, which makes the prover both slower and hungrier. A release
attempt on this laptop is untested, and is not expected to close a 2× gap.)

Two things would close it for good, in order of effort: **a ≥ 64 GB machine**, which needs nothing
from this crate; or the **storage `MERKLE_VERIFY`-style syscall** follow-up (or a wider sponge rate)
bringing the whole call under tier 16's 65 535 cycles, where the proof is the 774 KB, 438-second one
measured just below rather than a 28 GB one. The second is the same follow-up the tier deviation
names, which is the argument for doing it rather than buying memory.

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
| cycles | 28 201 executed |
| tier | `Tier(16)`, `keccak_log_height = 7`, `mem_log_height = 18` |
| proof | 773 848 bytes; 438 s to prove, 14.2 s to verify |

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
| decoding the two 272-word witnesses | 6 342 |
| the program- and input-digest prefixes | 4 735 |

Local levers took the first working cut from 224 212 total cycles to 126 373
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

### The `sbpf` guest — M4.4's exit test, and what constraint set 6 did to it

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

**M4.4 shipped this guest unprovable at any tier, and constraint set 6 is what
fixed it.** The history is below, because the reason it was unprovable is a real
constraint on how a zkVM can bind a program and not a bug that was patched. In
short: the ELF was a private input, so the guest had to hash it in-circuit for
the output digest to mean anything, and hashing 108 600 bytes cost more than the
machine's largest tier had. The fix was **option (B)** below — a second, unsalted
input segment whose digest a verifier can recompute — taken as constraint set 6
(design spec §9, `docs/02-tables-and-buses.md`'s `public` table).

**The binding now.** The ELF is the **public** input segment: the chain publishes
it, `H_PUB = pv::PUB0..7` binds it word for word, and `Machine::verify_public`
recomputes that digest from the published words. The guest therefore hashes
nothing of the program at all — `program_hash` is gone from the output digest,
whose preimage is 16 words rather than 24 (`notes::domain::SBPF_OUT`):

```text
out[0] = status          1 = the program returned r0 == 0, 0 = ProgramError, 2 = exceptional halt
out[1..8]                Poseidon2(SBPF_OUT, [input_hash(8 words), output_hash(8 words)])
```

Two *different* ELFs that both fail over the same instruction now publish
byte-identical output words; what distinguishes them is `H_PUB`, not anything the
guest computes (`tests/sbpf_abi.rs`). That is the whole trade: the binding moved
from something the guest pays cycles for to something the verifier checks for
free, at the price of the program being public.

**`input_hash` is over a canonical, unpadded encoding**, not `sha256` of the
aligned region — the second half of what bought the cycles. The preimage
(`abi::canonical_input_hash`, host twin `sbpf::canonical_preimage`) is:

```text
program_id(32) ‖ u64 n_accounts
  per entry, in entry order: marker(1) ‖ key(32) ‖ owner(32) ‖ u64 lamports
                             ‖ u64 data_len ‖ data ‖ is_signer ‖ is_writable
                             ‖ executable ‖ u64 rent_epoch
‖ u64 instruction_data_len ‖ instruction data
```

For the `Transfer` fixture that is **837 bytes** against the aligned region's
41 825 — 14 SHA-256 compressions instead of 654, of which 640 hashed nothing but
`MAX_PERMITTED_DATA_INCREASE` realloc padding. Every length prefix is
load-bearing: without `n_accounts` and the per-field `data_len`/
`instruction_data_len` the concatenation is ambiguous between different account
splits. `n_accounts` is the region's **exact** `u64` count, and a region claiming
more than `MAX_ACCOUNTS = 64` is refused outright rather than clamped, so the
count in the preimage is always the count the walk produced. `marker` is the byte
the entry physically carries — `0xff` for a full entry, the duplicated entry's
ordinal for a duplicate — so the *shape* of the account list is bound and not
only its contents: a duplicate entry aliases one buffer where a repeated full
entry is two, and the program can tell the difference.

**What the encoding omits, `check_region` pins, and that is what makes leaving it
out sound.** The omitted bytes are inside the region the program can read, so a
prover free to choose them could change what an honest-looking run does while the
verifier's recomputed `input_hash` still matched. At entry, therefore, the guest
refuses (as `ParseError::MalformedRegion`, which takes the ordinary malformed
path: status 2 over two all-zero digests, nothing run) any region with

* a non-zero byte in the 4-byte `original_data_len` slot, the 10 240-byte realloc
  headroom, the alignment padding, or a duplicate entry's seven padding bytes —
  agave's aligned serializer writes zeros in all of them, and it is the
  program-side entrypoint deserializer that later stores `original_data_len` into
  its slot, inside the guest's own memory and after the digest is taken;
* an `is_signer`/`is_writable`/`executable` byte above 1 — the program reads the
  raw byte and the preimage hashes the normalised one, so the two are kept equal
  by refusing the rest;
* a tail that is not exactly `u64 instruction_data_len ‖ instruction data ‖
  program_id(32)` ending at the region's last byte;
* an account list that does not walk to its own end, or claims more than
  `MAX_ACCOUNTS`.

So every byte of an accepted region is either hashed by `canonical_input_hash` or
pinned to a fixed value by `check_region`. The scan is not free — see the cycle
table below — but it costs a sixth of what hashing those bytes cost.

**Measured** (`cargo +1.98.1 test --release --test e2e compiled_sbpf -- --nocapture`),
an SPL Token `Transfer` of 250 tokens between two accounts owned by one signer, with
the mint as a fourth read-only account:

| | M4.4 | constraint set 6 |
|---|---|---|
| program words (`p.len()`) | 7 715 (6 427 text + prologue) | **8 317** (7 029 text + a 1 288-word data prologue for 1 856 bytes of `.rodata`) |
| guest image `bin/sbpf.bin` | 27 588 B | **29 996 B** |
| private input words | 37 609 (27 151 ELF + 10 458 instruction region) | **10 458** — the instruction region alone |
| public input words | — | **27 151** — the ELF, `[n_elf, elf bytes…]` |
| cycles | 1 753 945 | **694 498** |
| sBPF instructions executed | 143 | 143 |
| frame-depth high-water mark | 0 | 0 |
| SHA-256 compressions | 2 368 | **30** (14 canonical `input_hash` + 8 + 8 account walks) |
| `sha256_log_height` | 18 (2 368 × 64 = 151 552 rows) | **11** (30 × 64 = 1 920 rows) |
| tier | **none — above `Tier(20)`'s 1 048 575-cycle budget** | **`Tier(20)`** — 694 498 against 1 048 575; above `Tier(18)`'s 262 143 |
| `public_log_height`, `mem_log_height`, proof size | not measurable | not measured here — they are computed inside `build_traces_salted`, and no proof was produced on this machine (below) |

The 2.5× cycle saving is where the projection said it would be. Spec §9.5
projected **~699 000** cycles from M4.4's own pc histogram; the measurement is
694 498, inside 1 %. Of it, **~116 000** are `check_region`'s zero scan over the
**40 988** bytes the canonical encoding no longer hashes, at ~2.8 cycles a byte —
the third-largest single cost in the guest, and the price of binding those bytes
by pinning rather than by hashing.

40 988 is exactly `41 825 − 837`, the aligned region minus the canonical
preimage, which is the arithmetic form of "every byte of an accepted region is
either hashed or pinned". It decomposes as **40 960** bytes of realloc headroom
(four accounts × `MAX_PERMITTED_DATA_INCREASE`), **16** bytes of
`original_data_len` slot (four × 4), and **12** bytes of alignment padding before
each entry's `rent_epoch` (3 + 3 + 0 + 6, following this fixture's 165/165/0/82-byte
account data). The three flag bytes per entry are *not* in this figure: they are
hashed, in normalised form, and pinned to `{0, 1}` by a separate scan. (Task 4's
own note said 40 972, which counted the headroom and the padding but dropped the
four `original_data_len` slots.)

The binary grew by 602 program words in a change that only removed work, which is
worth knowing for any guest on this target: `InputCursor<F>` is now instantiated
twice (one reader per segment) and `AccountWalk` has four drivers (`output_hash`,
`canonical_input_hash`, `program_id`, `check_region`). With four, LLVM outlines
`step` rather than inlining it, which is why the image is *smaller* than the
first cut of this work (9 625 program words) despite `check_region` being added
after it.

**The frame-depth high-water mark is 0, and 512-byte frames were never viable.**
The M4.4 plan allocated 64 × 512 bytes on the reasoning that `process_transfer`
"uses well under that". It does not use more *frames* — it uses **no** nested call
at all, because the release build inlines `entrypoint::deserialize`,
`Processor::process` and `process_transfer` into one function — but that one
function's frame is around 2 KiB, and with 512-byte frames the program faults on
its first instruction at `0x1_ffff_f9e8`, 1 560 bytes below the stack region.
A frame size is not a budget the host may choose: it is part of the ABI the
program was compiled against. `sbpf-core` uses Solana's own 4 KiB frames and
**8** of them: the plan's 32 KiB stack is kept, and what gives way is depth rather
than frame width — eight frames of headroom against a workload that uses one.

**The tier-20 proof itself has not been produced here, and this is M4.3's
problem, not M4.4's.** The guest is provable now; the batch is the obstacle. A
tier-20 batch is 2^20 cpu rows, 2^22 memory and poseidon2 rows and a 466-column
sha256 table — **four times the cpu rows** of the tier-18 EVM proof, which was
SIGKILLed on this same otherwise quiet 48 GB machine three times over with a
maximum resident set of **28.5–28.9 GB and still growing**. This one was not
attempted: macOS swaps rather than failing fast, so the attempt costs hours and
tells you nothing the EVM proof has not already said. **≥ 64 GB** is the figure
M4.3 arrived at for a tier-18 batch and is the floor here, not the estimate; a
tier-20 batch wants more than that again. On such a machine:

```text
cd research && cargo +1.98.1 test --release --test e2e \
    compiled_sbpf_spl_token_transfer_proves_and_verifies -- --ignored --nocapture
```

`compiled_sbpf_spl_token_transfer_proves_and_verifies` is written out in full
against the current API and stays `#[ignore]`d with that measurement in its
message. What pins the behaviour in the suite is
`compiled_sbpf_spl_token_transfer_executes_and_publishes_the_bound_digest`, which
always runs: it checks the guest's eight output words against a native run of
`sbpf-core`, pins the compression count at 30 and `sha256_log_height` at 11, and
tripwires the cycle count in **both** directions — `<= 720 000` catches a runaway,
and `> Tier(18).max_cycles()` fires the day the guest fits a smaller tier, at
which point the proof and this table are re-measured and re-tiered.

**Getting to tier 18 needs the tape, and that is the remaining lever.** What did
*not* come off in the move to the public segment is the cost of *reading* the
program: the guest still walks all 27 151 ELF words to run them, now with
`READ_PUBLIC` instead of `READ_INPUT` and at the same ~15.8 cycles per word —
about 430 K of the 694 498, well over half. One cpu row per word is the whole of
that cost, so the lever is a **bulk public-read syscall**: "read `n` public words
into memory", one cpu row per four words the way an absorb row already works.
That is out of constraint set 6's scope and recorded as an open item in spec
§9.5. Nothing guest-side closes it — the words have to cross into the machine one
way or another.

### What does *not* work: declaring `program_hash` instead of computing it

This was the first thing M4.4 proposed, and it is **unsound**. It is kept here
because it is the obvious idea, the reason it fails is not obvious, and the
resolution — the public segment — is only intelligible as an answer to it.

`H_IN` has been **salted and hiding** since M4.1 (`docs/03-privacy.md`, "Private
inputs are bound to `H_IN`"). The salt never leaves the prover and folds
non-invertibly into the digest, precisely so that `H_IN` reveals nothing about the
input words. That is also exactly why it cannot *check* anything about them: a
verifier holding `H_IN` cannot test a claimed digest of the inputs against it. So a
`program_hash` the guest does not recompute is bound to **nothing** — a prover could
run any ELF at all, commit it under a fresh salt, and declare the SPL Token hash in
the public output. The in-circuit recomputation is not redundancy with `H_IN`; it *is*
the binding. For an ELF that arrives as **private** input, that remains true today:
hashing it in-circuit is the only thing that makes the output digest mean anything.

**What constraint set 6 changed is not that argument but its premise.** The ELF no
longer arrives as private input. `H_PUB` is unsalted, so a declared digest *is*
checkable — by a verifier who holds the words, natively, at no in-circuit cost —
and the guest can stop recomputing what the chain already checks. The soundness
gap the argument identifies is closed by making the commitment checkable, not by
trusting the guest. `docs/03-privacy.md`'s leak table carries what that costs.

### The two sound paths, and which one was taken

**(B) — a public, unsalted segment in the input commitment — was taken**, as
constraint set 6. (A) is recorded below because the comparison is the reason for
the choice, and because A's own obstacles are facts about this machine that
outlive this decision.

**(A) Bake the ELF into the guest's data segment, so `hc` binds it.** The image
container above makes a guest's data part of `Program::words`, and therefore part of
`hc` — a binding the verifier already checks, with no salt and nothing prover-chosen,
because the stored values are immediates in the prologue's own instructions. With the
ELF in the data segment, `program_hash` need not be computed at all: `hc` says which
program ran. The arithmetic, estimated from M4.4's breakdown rather than measured:

| | |
|---|---|
| ELF as data words | ~27 150 |
| synthesised `li`/`sw` prologue, at the measured ~2.8 instructions per non-zero data word | ~**72–76 K program words**, and the same in cycles |
| removed: the ELF's 1 698 compressions | ~−766 K cycles |
| removed: the ELF's 27 151 input words | ~−430 K cycles |
| estimated total | ~**0.6 M cycles — tier 20** |

So A lands at the same tier B measured at, and pays for it twice over.

**A does not fit today, and this is what settled the choice.** A program is capped
at **65 535 words** in *both* loaders (`LoadError::TooLong`), and the cap is not
arbitrary: the program's word count is `HASH_LEFT` on the first digest row, a
16-bit value in the cpu AIR's `LEFT0..1` byte limbs, so a longer program cannot
satisfy the constraints at any tier. A's prologue alone is ~72–76 K words, and
with this guest's own text the image is ~78–82 K — **over the cap by about 20 %**.
Two things would have to happen together: the prologue lever the M4.4 plan noted
but never needed (dedupe the `lui` half across consecutive data words, worth ~25 %
of prologue words) brings it to ~60–63 K, which fits with only a couple of thousand
words of margin; anything less, or a program much larger than SPL Token's 108 KB,
needs `HASH_LEFT` widened, which is itself a constraint-set change. So A is not the
"no machine change" option it looks like — it is a machine change deferred by one
program size, and B is a machine change made once, for every guest, with no cap
problem of its own (`n_pub` is capped at 65 535 by the same 16-bit `HASH_LEFT`, and
27 151 words is comfortably inside it).

A also makes the guest **program-specific**: one committed binary per Solana program,
which is a real departure from this document's opening claim that publishing a contract
means registering `hc` for the *interpreter* plus a commitment to the bytecode. B keeps
one interpreter binary for every Solana program, which is the model.

**B's price, stated plainly:** the ELF words are public. For this guest that is
close to free — SPL Token's bytecode is on mainnet — but it is a real change to
the privacy posture, and it is not the machine's default. A guest that wants its
program hidden keeps it on the private tape and pays M4.4's cycles.
`docs/03-privacy.md`'s leak table has the full accounting, including the fact that
the EVM guest (M4.3) is untouched by this work and still hides its bytecode.

### Where M4's exit criterion actually stands

"An ERC-20 `transfer` and an SPL `Transfer` each prove under `R_exec`" is still met
on neither side as an actually-produced proof on the development hardware — but
after constraint set 6 the two sides fail for the **same** reason, which is a
different and much better place to be standing than M4.4 was:

* **EVM (M4.3)** — the interpreter proves and verifies at **tier 16** for a storage
  call through the same committed binary. The tier-18 ERC-20 `transfer` proof was
  **not produced** here; the run did not complete on this machine. The path is
  demonstrated; the specific exit artefact is outstanding for want of hardware.
* **SPL (M4.4 + constraint set 6)** — the interpreter **runs** a real `Transfer`,
  binds its outputs, and the eight public words match the native interpreter byte
  for byte. It is no longer unprovable: at **694 498 cycles it fits `Tier(20)`**,
  where M4.4 left it at 1 753 945 against that tier's 1 048 575 budget. What is
  outstanding is the artefact, for the same reason as the EVM's — a tier-20 batch
  needs a **≥ 64 GB** machine, and this one has 48. The remaining *design* gap is
  the tier itself: tier 18 was the milestone's wording and needs the tape cost
  addressed (a bulk public-read syscall, spec §9.5's open item), not another
  binding change.

So both sides are now "demonstrated, artefact pending hardware", and neither is
blocked on anything this crate can do to a guest.

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
