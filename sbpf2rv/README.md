# sbpf2rv

Translates an sBPF ELF into C that runs natively in the Rand zkVM: a shim crate that
`rand-guest build` turns into an image whose eight public output words equal the sBPF
interpreter's (`guests-compiled/bin/sbpf.bin`) for the same ELF and instruction.

```text
sbpf2rv <program.so> --out <dir inside a circuits checkout> [--name <crate>]
rand-guest build <dir> --max-words 65535 --allow-panic
```

`--allow-panic`: the shim links `core`'s panic machinery through the ABI harness, which
`rand-guest build` otherwise rejects (`rand-guest/README.md`, "Rejecting").

The rules of the translation are `src/emit.rs`'s module docs and the design spec
(`docs/superpowers/specs/2026-09-18-sbpf-to-rv32-translator-design.md`). The oracle tests are
`tests/parity.rs` (the real pipeline against `run_call` and `sbpf.bin`), `tests/fuzz.rs`
(differential fuzzing on the host), `tests/emit.rs` and `tests/scan.rs`.

The pinned toolchain is **Rust 1.98.1** (`rust-toolchain.toml`), **clang 23.1.1** (Homebrew LLVM;
`rand-guest` and the generated `build.rs` refuse any other version unless
`RAND_GUEST_CLANG_UNPINNED=1`, and then `hc` will not match) and **`cc` 1.4.6** (pinned in the
generated `Cargo.toml` and `Cargo.lock`). `rand-guest build` scrubs the builder's environment and
refuses a `.cargo/config.toml` anywhere cargo would read one (`rand-guest/README.md`), so the same
ELF gives the same `hc` on any machine with that toolchain.

The clang pin is not only about `hc`. Every translated function is `minsize`, which turns on
LLVM's machine outliner, and clang 21.1.6's outliner miscompiles this target: it reaches a shared
`OUTLINED_FUNCTION_n` with `tail` (`auipc t1 ; jalr zero, t1`) while `t1` still holds a value the
outlined code stores, so a function reached through `callx` can hand back the address of that
`auipc` as the low word of `r5` (ZKVM-101; `tests/parity.rs`,
`a_callx_returns_r5_as_the_callee_left_it_not_the_address_of_a_tail_call`). The C is the same
under every clang and has no undefined behaviour there; clang 18.1.8 and the pinned 23.1.1 compile
it correctly. `rand-guest check` refuses an image with that shape (`TailScratch`), so
`RAND_GUEST_CLANG_UNPINNED=1` with an affected clang fails the build rather than the parity.

## Usage: a real SPL Token walkthrough

Every command below was run on this machine (2026-09-18; the outputs re-taken 2026-11-18 after
ZKVM-116, with LLVM's own clang 23.1.1 for macOS), against the committed ELF
`guests-compiled/sbpf/programs/spl_token.so` — the interpreter's own test fixture
(`sbpf-core`'s `spl_transfer`, `SPL_TOKEN_ELF`). Output is pasted, not summarized, and
abbreviated only where it repeats. This is the walkthrough the website docs should copy.

### 1. Translate

```text
$ sbpf2rv guests-compiled/sbpf/programs/spl_token.so --out <dir> --name spl-token
entry pc 225: 30 function(s), 3546 block(s), 12061 instruction(s), 30 callx target(s), 0 refusal(s), 0 warning(s)
  fn 225: 2065 block(s)
  fn 0: 41 block(s)
  fn 117: 52 block(s)
  ...                                              (30 functions in all)
wrote <dir>/program.c (477259 bytes of C) and the spl-token shim crate: rand-guest build <dir>
```

`0 refusal(s)`: nothing about the ELF's instructions is refused (see "What is refused, and what
traps" below). `0 warning(s)`: every syscall the ELF calls is one `sbpf-rt` implements. Before
ZKVM-116 there were four — three call sites of `sol_set_return_data` (hash `2720453611`) and one
of `sol_get_sysvar` (hash `331461893`), translated as the `UnknownSyscall` trap — and the code
behind them was dead in the image; it is live now (`GetAccountDataSize`, `AmountToUiAmount`,
`UiAmountToAmount`, and the `Rent::get()` of `InitializeAccount2`/`3`, `InitializeMint2` and
`InitializeMultisig2`).

### 2. Build

```text
$ rand-guest build <dir> --max-words 65535 --allow-panic
   Compiling sbpf-core v0.1.0 (…/guests-compiled/sbpf-core)
   Compiling guest-sdk v0.1.0 (…/guest-sdk)
   Compiling cc v1.4.6
   Compiling spl-token v0.1.0 (<dir>)
warning: spl-token@0.1.0: sbpf2rv: clang clang version 23.1.1 (https://github.com/llvm/llvm-project 6dfe1677ab8dffbc6ec13d53a1e0215d75147689)
    Finished `release` profile [optimized] target(s) in 5.53s
64465 words against a cap of 65535 (fits); 2 ecall(s) with a non-static a7
OK
wrote <dir>/image.bin and its .sha256 (64465 words, hc bae423b49d0c762e403f0331663321dc59209b6192caf3f93d2cc8b2118b755a, program id b9af92f6884207c86c70acf866577fb65a08b810b1d82644bf85d9a3b392c3df)
```

`hc` is the image's own digest; `program id` is the id `rand-guest` derives for the deployed
program. `program.c` ends with the ELF guard's constant, the digest of the loaded program (text,
rodata, addresses, entry) it was translated from, so `hc` binds that program (see "Trust and
verification" below).

### 3. Run, and compare with the interpreter

The `Transfer` 250 vector's inputs are two word lists, exactly as `tests/parity.rs` builds them
from `SbpfCall::public_words()` / `input_words()`: **27 152 public words** (the ELF itself,
word-encoded — this is why the image still carries the whole ELF, not just its hash — and then the
sysvar block, here its length word alone: 0, this call carries no sysvars; a call that does
carries 57 bytes after it, Clock then Rent) and **10 458 private words** (the serialized instruction: the accounts `spl_transfer` builds, then
the `Transfer` discriminant and the amount). `rand-guest run` takes them as `--public w0 w1 …`
and `--input w0 w1 …`. Abbreviated to the first handful of words of each list:

```text
$ rand-guest run <dir>/image.bin \
    --public 108600 1179403647 65794 0 0 17235971 1 2088 … 0 (27 152 words)
    --input  41825 4 0 65791 0 50529027 50529027 50529027 …  (10 458 words)
out[0] = 1
out[1] = 3392882403
out[2] = 2131909648
out[3] = 3952069092
out[4] = 1651185809
out[5] = 567649743
out[6] = 4049030460
out[7] = 1478577172
cycles 753424
tier 20
```

The same two word lists, unchanged, against the interpreter's own committed guest:

```text
$ rand-guest run guests-compiled/bin/sbpf.bin \
    --public 108600 1179403647 65794 0 0 17235971 1 2088 … 0 (27 152 words)
    --input  41825 4 0 65791 0 50529027 50529027 50529027 …  (10 458 words)
out[0] = 1
out[1] = 3392882403
out[2] = 2131909648
out[3] = 3952069092
out[4] = 1651185809
out[5] = 567649743
out[6] = 4049030460
out[7] = 1478577172
cycles 685749
tier 20
```

All eight words are identical, word for word. The interpreter costs 685 749 cycles against the
translated program's 753 424: the translated image is 67 675 cycles dearer, because the ELF guard
costs about 73 k (copying the loaded program's 26 364 words into its hash buffer and hashing
them) against the program's own 13 k saving. Both land in tier 20; "Does translation pay off for
SPL Token?" below has the split.

### 4. Deploy

```text
rand program deploy <dir>/image.bin
```

deploys the image, on a chain whose genesis sets `max_program_words >= 64 465` — this image's own
word count. **Today's chain 12 caps a deploy at 4 096 words**
(`docs/superpowers/specs/2026-09-18-rand-guest-toolchain-design.md` §8's
`MAX_PROGRAM_WORDS`), about 16× too small for this image, so the command above is not runnable
on the live chain today: it needs a chain cut with the raised cap. **Not run here.**

## Trust and verification

What each part of a proof binds:

* **The ELF arrives on the public tape** (step 3 above), so the proof's public-input digest
  `H_PUB` binds it word for word — and nothing else in the published output does.
  `public_output` has no ELF in its preimage (it is `status` and the digest of
  `input_hash ‖ output_hash ‖ return_hash`), and `program_id` is read from the *instruction
  region* on the private tape, not derived from the ELF.
* **The sysvars arrive on the public tape too**, after the ELF: Clock and Rent are the chain's
  facts, so `H_PUB` is what binds them and the chain checks them against its own. Nothing a
  sysvar getter returns is ever read from the private tape (`sbpf_core::abi`).
* **The return data is in the output digest.** `return_hash` is `sha256` of what
  `sol_set_return_data` last set, for a run that returns success (of nothing, otherwise).
* **The image bakes the translated text, and the ELF guard.** The harness hands the translated
  code the text, `.rodata` and their addresses loaded from the tape's ELF, and the interpreter
  would start at its entry, so without a guard one image could be run over a different,
  caller-chosen ELF and behave differently under the same `hc`. So `program.c` carries the
  **digest of the loaded program (text, rodata, addresses, entry)** it was translated from, and
  before running anything the executor hashes the program `elf::load` made of the tape's ELF the
  same way and compares: any other halts `BadElf`, status 2, over the pre-state (accepted
  divergence #3 below). **`hc` therefore binds the loaded program**: a proof that verifies
  against this `hc` is a run of that program.
  * The view (`shim::view_words`) is every field of `sbpf_core::elf::Program` read at run time:
    `text_va`, `text.len()`, `rodata_va`, `rodata.len()`, `entry_pc`, the read-only run's bytes,
    and the text's bytes (in every v1 file the text is a span of the run, so they are hashed once,
    with the span's offset in the header). `execute` and `sbpf-rt` read the text, the run and both
    addresses (the program region's loads, `callx`'s `(addr - text_va) / 8`); the interpreter also
    reads `entry_pc`, which the translation bakes. Nothing reads `relocs_applied`.
  * The digest is the `POSEIDON2` sponge over those words, chained in 4 096-word calls
    (`shim::view_digest`). The coprocessor writes its digest over the words it hashed, so the
    borrowed program bytes are copied into a 16 KiB buffer a chunk at a time.
  * **Why the loaded program and not the file is the property that matters.** Everything a run can
    observe of the ELF — on the interpreter as on the translation — is the loaded program: its
    code, its read-only data, where they sit, where execution starts. The rest of the file (headers,
    symbol and string tables, relocation entries, padding) only shapes what `elf::load` produces.
    Two ELFs that load to the same program run identically on both sides, so the translation
    accepts both (`tests/parity.rs` runs one whose header padding differs); one that loads to any
    other program is refused. The ELF's own bytes remain bound by `H_PUB`.
* **Whether `hc` is the faithful translation of that ELF** is checked by rebuilding: run the pinned
  `sbpf2rv` on the ELF and `rand-guest build` with the pinned toolchain (Rust 1.98.1, clang
  23.1.1, `cc` 1.4.6), and compare `hc` — the same rule the EVM translator uses (design spec §6).
  The build is reproducible for exactly this (`rand-guest`'s environment scrub and config
  refusal, the clang pin, the relative paths and prefix maps, the complete `Cargo.lock`).

The chain does not record the source ELF's hash: fullnode stores the image and its program id
only. A deployer who wants the ELF known publishes it beside the program, and anyone can rebuild
it to the deployed `hc`.

## What is refused, and what traps

Nothing is refused at translation. An ELF `sbpf-core::elf` itself would refuse (a malformed
file) is refused here with the same message, but nothing about the *instructions* inside a
well-formed ELF is — the real run above shows `0 refusal(s)` on the committed SPL Token ELF, and
its `4 warning(s)` sit on syscalls the `Transfer` instruction never reaches. A warning is a
static finding the scanner (`src/scan.rs`) reports so a reviewer can see what a program *could*
hit; whether it ever does, at runtime, is the interpreter's own rule, matched exactly:

| the scanner finds (`Warning`) | what it is | what the translated program does if it runs |
|---|---|---|
| `UnknownSyscall` | a `call imm` syscall hash `sbpf-rt` has no `sbpf_sys_*` for | `sbpf_trap(UnknownSyscall, hash)` |
| `Cpi` | a syscall hash matching a cross-program-invocation name (`sol_invoke_signed*`) | the same `UnknownSyscall` trap — CPI is a multi-program model this translator does not implement, but an unreached call site does not block the rest of the program |
| `RegisterOutOfRange` | a `dst`/`src` nibble naming `r11..r15`, or a `callx` register immediate above `r10` | `sbpf_trap(BadInsn, opc)` |
| `UnknownOpcode` | an opcode byte `isa::classify` assigns no v1 class (incl. the v2-only `sdiv`/`srem`/pqr family, `hor64`) | `sbpf_trap(BadInsn, opc)` |
| `JumpOutOfText` | a `ja`/conditional-jump/internal-`call` target, or an instruction's fall-through, that lands outside the function's own text | `sbpf_trap(BadJump)` |
| `BadCallImmSrc` | a `call imm` whose `src` is `2..=10` (only from a hand-built ELF — `elf::load` never writes anything but 0 or 1 there) | `sbpf_trap(BadInsn, 0x85)` |
| *(a runtime value, not a static warning)* any `callx` target outside the set the scanner found | — | `sbpf_trap(BadJump)`: accepted divergence #1 below |

Every one of these is a *runtime* trap carrying the interpreter's own `Halt` value and payload,
never a translation-time refusal — matching `interp.rs`, which only ever raises them when the
instruction actually executes. A translator that refused a program over unreached code would
refuse programs the interpreter runs successfully today, and the committed SPL Token ELF is
that case until ZKVM-116: its `sol_set_return_data`/`sol_get_sysvar` calls were unreached by
the transfer.

### The accepted divergences

Three places where the translation may halt where the interpreter would not, or halt differently.
Each errs on the safe side: the translation never completes a run the interpreter halts.

1. **`callx` outside the scanned set.** Any `callx` target outside the set the scanner found
   (function entries, `lddw` constants and read-only-data words that point at real instructions)
   gives `BadJump`, where the interpreter may execute real code at that address. Fuzzed
   117-for-117: re-running each such case with the target added as a named entry makes both sides
   agree exactly (Task 5).
2. **A run that passes the compute budget halts at the next check, not at the instruction.**
   The interpreter counts one unit an instruction and charges each syscall as it is made; the
   translation charges a basic block's whole count at the block's head, and only **153** of SPL
   Token's 3 546 block heads also *check* the budget: a function's entries, a block that closes a
   loop, and a block ending in `exit` (`emit.rs`, `choose_checked`). A syscall's
   length-dependent charge (`sol_memcpy_` above 2 750 bytes, each hashed slice, a long
   `sol_log_`) is added by `sbpf-rt` to a counter the heads do not see, and settled exactly when
   the program returns (`sbpf_rt_settle`). So the charges are the interpreter's, unit for unit,
   and no run inside the budget is ever halted; but a run that crosses it carries on — through
   blocks that form no cycle and cannot return from the program — until a check, the settlement,
   or a fault of its own. Its halt *kind* may then differ from the interpreter's
   `InstructionLimit`; the published status and eight words are equal either way, since every
   exceptional halt publishes status 2 over the pre-state and no return data. The fuzzer accepts
   exactly this difference and no other (22 of 10 000 cases reach it, each re-run with a smaller
   loop count to show the fault is the interpreter's own). What it buys is size — see "Size" in
   `emit.rs`: with a check at every block next to an unchecked one (the rule before ZKVM-116,
   2 041 checks) the whole SPL Token, with the code behind `sol_get_sysvar` and
   `sol_set_return_data` now live, is 69 178 words, 3 643 over the machine's cap.
3. **Only the source program runs.** An image refuses, with `BadElf` (status 2 over the pre-state),
   any ELF on the public tape that loads to a program other than the one it was translated from
   (text, rodata, addresses, entry), where the interpreter runs whatever ELF it is given.
   `tests/parity.rs` changes one `.rodata` byte of SPL Token that the transfer never reads: the
   interpreter (host and `sbpf.bin`) runs it to the same eight words, and the translation refuses
   it. An ELF that differs only where `elf::load` does not look (the header's padding, in the
   test) loads to the same program and runs on both. The price is the guard's cycles (below).

## Measured: SPL Token, translated against interpreted

Every number here is from a run on this machine (a 16-core macOS laptop with 48 GB): the
images and the vector table on 2026-11-18, after ZKVM-116; the stage split below it on 2026-09-18,
on the images before ZKVM-116. The cycles and tier are what `rand-guest run` prints; the
instruction counts are `sbpf_core`'s meter natively. Regenerate the table with

```text
cd sbpf2rv && cargo +1.98.1 test --test parity the_spl_token -- --nocapture
```

**Images.** Translated SPL Token: **64 465** program words against the 65 535-word cap (1 070
spare), `hc bae423b4…755a`. Interpreter `sbpf.bin`: **10 227** program words. Both need the same
inputs: the ELF and the sysvar block on the public tape (27 152 words with no sysvars, 27 167
with them), the serialized instruction on the private one.

How the image got smaller while gaining six syscalls and about 5 000 words of SPL code that had
been dead behind two trapping ones (words of RV32, measured on this ELF at each step): the call
depth pushed and popped by the callee instead of at each call site, and the handed-over budget a
32-bit word (−1 239); the 1-, 2- and 4-byte load and store entries of `sbpf-rt` returning and
taking 32 bits, so a narrow load's zero high word is known to the compiler (−1 080); budget
checks only at entries, loop heads and exits (−4 554).

| vector | result | status | sBPF insns | compute units | translated cycles | tier | `sbpf.bin` cycles | tier | translated saves |
|---|---|---|---|---|---|---|---|---|---|
| `Transfer` 250 | `Ok(0)` | 1 | 143 | 143 | 753 424 | 20 | 685 749 | 20 | −67 675 |
| `Transfer` more than the balance | `Ok(1)` `InsufficientFunds` | 0 | 133 | | 736 340 | 20 | 670 931 | 20 | −65 409 |
| `MintTo` 250 | `Ok(0)` | 1 | 120 | | 696 234 | 20 | 625 347 | 20 | −70 887 |
| `MintTo` 250 signed by someone other than the mint authority | `Ok(4)` `OwnerMismatch` | 0 | 134 | | 684 212 | 20 | 618 371 | 20 | −65 841 |
| `Burn` 250 | `Ok(0)` | 1 | 131 | | 697 850 | 20 | 628 119 | 20 | −69 731 |
| `Burn` 1 000 001 of a 1 000 000 balance | `Ok(1)` `InsufficientFunds` | 0 | 121 | | 682 969 | 20 | 615 729 | 20 | −67 240 |
| `Transfer` with two accounts | `Ok(0xb_0000_0000)` `NotEnoughAccountKeys` | 0 | 69 | | 632 511 | 20 | 559 873 | 20 | −72 638 |
| an account count above `MAX_ACCOUNTS` (refused by the harness) | `Err(BadElf)` | 2 | 0 | | 304 306 | 20 | 304 792 | 20 | 486 |
| `InitializeAccount` (rent from its fourth account) | `Ok(0)` | 1 | 153 | 153 | 750 444 | 20 | 683 394 | 20 | −67 050 |
| `InitializeAccount`, one lamport short of rent-exempt | `Ok(1 << 32)` `NotRentExempt` | 0 | 158 | | 735 518 | 20 | 672 435 | 20 | −63 083 |
| `InitializeAccount3` (rent through `sol_get_sysvar`, from the public tape) | `Ok(0)` | 1 | 127 | 237 | 649 946 | 20 | 579 611 | 20 | −70 335 |
| `InitializeAccount3` under a rent twice as dear on the public tape | `Ok(1 << 32)` `NotRentExempt` | 0 | 133 | | 636 735 | 20 | 570 549 | 20 | −66 186 |
| `InitializeAccount3` with no sysvars on the tape | `Err(Trap("sysvar unavailable"))` | 2 | 49 | | 632 401 | 20 | 557 130 | 20 | −75 271 |
| `GetAccountDataSize` (returns 165 as return data) | `Ok(0)` | 1 | 79 | 179 | 589 610 | 20 | 513 448 | 20 | −76 162 |
| `AmountToUiAmount` 1 234 567 (returns `"1.234567"`) | `Ok(0)` | 1 | 292 | 412 | 594 082 | 20 | 540 866 | 20 | −53 216 |

(The compute-unit column is `research/tests/sbpf_syscalls.rs`'s pin, where it has one.)

Before the ELF guard (at `16580bf`) the translated column was about 73 k lower on every row that
runs the program; the row the harness refuses never reaches the guard.

`tier` is `Tier::for_workload` over the executed cycles plus the digest rows, which is what
`prove` picks. Every vector lands in tier 20 on both sides (tier 18 is 262 143 cycles).

### Where the cycles go

About 98 % of every run is the harness, the same `sbpf-core` code on both sides (plus, in the
translated image, the ELF guard). The program's own execution is 1–3 %. **This split is the
2026-09-18 one, of the images before ZKVM-116** (translated `hc 8ca905ae…`, 765 851 cycles for
the transfer; `sbpf.bin` `d49f10…b759`, 694 498): the totals moved by about 1 % since (table
above) and the stages were not re-profiled. Split by stage, for the three successful vectors
(`cargo +1.98.1 test --test parity where_the_cycles_go -- --ignored --nocapture`):

| stage | `Transfer` translated | `Transfer` `sbpf.bin` | `MintTo` translated | `MintTo` `sbpf.bin` | `Burn` translated | `Burn` `sbpf.bin` |
|---|---|---|---|---|---|---|
| decode_input: read both tapes | 302 881 | 302 880 | 281 873 | 281 872 | 281 873 | 281 872 |
| elf::load: parse, relocate, hash syscall names | 177 012 | 173 859 | 177 012 | 173 859 | 177 012 | 173 859 |
| check_region: the zero scan pinning the region | 103 829 | 103 824 | 77 895 | 77 891 | 77 895 | 77 891 |
| zero the sBPF stack and heap | 49 181 | 49 181 | 49 181 | 49 181 | 49 181 | 49 181 |
| output_hash | 25 994 | 20 348 | 20 912 | 14 784 | 21 468 | 15 338 |
| canonical input_hash | 18 620 | 16 225 | 15 071 | 12 365 | 15 038 | 12 332 |
| the ELF guard: hash the loaded program view | 72 949 | — | 72 949 | — | 72 949 | — |
| public output words, program id | 3 753 | 3 504 | 3 506 | 3 258 | 3 506 | 3 258 |
| other: entry, glue | 2 724 | 2 646 | 2 724 | 2 646 | 2 724 | 2 646 |
| **program: sBPF execution** | **8 908** | **22 031** | **7 525** | **18 567** | **8 599** | **20 661** |
| total | 765 851 | 694 498 | 708 648 | 634 423 | 710 245 | 637 038 |
| sBPF instructions | 143 | 143 | 120 | 120 | 131 | 131 |

How the split is made: both images are built without debug info and the harness is inlined into
`main`, so the test rebuilds each crate with `profile.release.debug = "line-tables-only"` into a
separate target directory, requires the rebuilt ELF to pack to the **same image bytes** (debug
info changes no code: the translated twin gives `hc 8ca905ae…`, the interpreter's twin
`sbpf.bin`'s `d49f10…b759`), runs the production image on the emulator, replays the pc sequence
with a shadow call stack, and names each cycle's stage from `llvm-symbolizer --inlining` over the
twin's line tables.

What the stages are:

* **decode_input** reads both tapes a word at a time: 37 609 words for the transfer (27 151 ELF +
  10 458 instruction), about 8.05 cycles a word. The ELF alone is about 219 k.
* **the ELF guard** hashes the loaded program view — an 8-word header and the read-only run's
  26 364 words (the text is a span of it) — with the `POSEIDON2` coprocessor: 72 949 cycles, about
  2.75 a word. The coprocessor writes its digest over the words it hashed, and the program's bytes
  are borrowed read-only, so each 4 088-word chunk is first copied into a 16 KiB buffer (volatile
  loads, eight at a time, 2.5 cycles a word); the hash itself is a quarter of a row a word (about
  6 600 Poseidon2 permutations, well inside tier 20's budget). An earlier version hashed the raw
  tape instead, staging every public word as it was read: 116 028 cycles and 120 words, replaced
  by this one on the ruling that the loaded program, not the file, is what the guard must bind.
* **elf::load** parses and relocates the ELF (and hashes its syscall names) before anything runs.
* **check_region** scans the 40 988 bytes the canonical encoding leaves out (realloc headroom,
  padding) and requires them to be zero.
* **zero the sBPF stack and heap** is `Workspace`'s 64 KiB of fresh sBPF memory.
* **input_hash / output_hash / public output** are the SHA-256 digests and the eight words.
* **program** is everything the executor does: `Vm::run` and its memory in `sbpf.bin`, the
  translated functions and `sbpf-rt` (`sbpf_ld*`/`sbpf_st*`, the syscalls) in the shim.

### Does translation pay off for SPL Token?

**Not today.** Translated execution is about 2.4–2.5× cheaper per sBPF instruction: about 62
cycles against about 154 on the transfer, most of the 62 in `sbpf_load`'s bounds and region
checks. That saves 11.0–13.1 k cycles on these vectors' 120–143 instructions. But the shim's
harness costs 11.5–12.3 k more than `sbpf.bin`'s (`output_hash` +5.6 k, `elf::load` +3.0 k,
`input_hash` +2.4 k on the transfer), because the shim crate itself is built at `opt-level = "s"`
(its dependencies at 3) to fit the 65 535-word cap, and those generic functions are instantiated in
it; and the ELF guard costs 73 k. Net: the translated image is 69–75 k cycles dearer a vector, and
every vector stays in tier 20.

Translation starts to matter only where the program's own execution is a real share of the run,
at thousands of sBPF instructions a call and up. At the measured ~90 cycles saved an instruction, a
program executing 10 000 instructions saves about 0.9 M cycles, and one near the 200 000-instruction
limit about 18 M. For SPL Token the levers are on the harness side:

* A bulk public-read syscall (`research/docs/04-guests.md`, spec §9.5's open item) for the tape.
* For a translated image specifically, not reading or loading the ELF at run time at all. With the
  ELF guard, `hc` already binds the one loaded program the image accepts, so the image could carry
  that program's read-only data itself and take no ELF on the tape. On the measured split that
  removes about 219 k (reading the ELF) + 177 k (`elf::load`) + 73 k (the guard) of the transfer's
  766 k, leaving about 297 k: still above tier 18's 262 143 without the region scan's cost coming
  down too. This is an estimate from the split, not a measurement, and it changes the public-input
  layout the interpreter's guest defines, which is why it is not done here.

## Coprocessor backlog: software Ed25519 and secp256k1

`sbpf-rt/sbpf_ed25519.c` and `sbpf-rt/sbpf_secp256k1.c` implement the two syscalls Solana
programs most often need for signature checking, in portable C over `sbpf-rt/sbpf_bn.c`'s
256-bit Montgomery arithmetic. Neither is wired into a translated program:

* the interpreter itself only ever raises `Halt::UnknownSyscall` for both hashes — neither
  `sol_ed25519_verify` nor `sol_secp256k1_recover` is in `syscalls::SUPPORTED` — so for parity
  `sbpf_syscall` traps on them the same way; routing a translated call to the C implementation
  would make the translation disagree with the interpreter it has to match;
* the generated `build.rs` compiles `sbpf-rt/sbpf_rt.c` only. `sbpf_bn.c`, `sbpf_ed25519.c` and
  `sbpf_secp256k1.c` are not linked into the shim crate — they live in `sbpf-rt/` unlinked,
  tested and measured on their own, as a coprocessor backlog rather than something this
  translator ships.

Measured on the emulator (`rand-guest/tests/sbpf_rt.rs`, its cycle cap raised for the purpose):

| operation | cycles |
|---|---|
| `sol_secp256k1_recover` (go-ethereum's ecrecover vector) | 15 730 633 |
| `sol_ed25519_verify`, per call (two verifies measured together, 28 581 563 total) | about 14 290 782 |

Both are well past the largest tier's cap, 1 048 576 cycles (2^20) — nothing in this milestone's
tiers holds either call even once. A 2–4× speedup looks plausible (a reduction specialised to
each prime, a dedicated doubling formula, windowing), but that would still fall short of a tier;
this needs a dedicated coprocessor table, the same shape as `sol_sha256`'s.

Two things whoever builds that table needs to know:

* **`sol_ed25519_verify` here is RFC 8032 §6** (cofactorless, canonical `y`), not
  `ed25519-dalek`'s `verify_strict`, which Agave's real precompile uses. The two agree except on
  adversarial encodings (small-order `A`/`R`, non-canonical `y`) — worth knowing for a
  coprocessor meant to match Solana's actual behavior rather than the reference algorithm.
* **Both need their text based at `0x10000`.** Either file pulls in `.rodata` (SHA-512's
  constants, for Ed25519), which the loader turns into a data prologue that must fit below the
  text; `sbpf.ld` already reserves the room. A standalone guest that links the crypto needs the
  same origin — `sbpf-rt/test/rv32/rv32.ld` is the worked example.

## One real proof

`the_translated_spl_token_transfer_proves_and_verifies` (`tests/parity.rs`, `#[ignore]`d) proves the
translated `Transfer` with `Machine::new(FriProfile::Test).prove(&program, &inputs, &public, None)`,
then checks `verify` against the image's `hc` and `verify_public` against the ELF words:

```text
cd sbpf2rv && cargo +1.98.1 test --release --test parity \
    the_translated_spl_token_transfer_proves_and_verifies -- --ignored --nocapture
```

**No proof was produced here.** The run was made once, on 2026-09-18, under
`/usr/bin/time -l`, with a watchdog set to stop it at 24 GB or 45 minutes:

| | |
|---|---|
| workload | 692 854 cycles, `Tier(20)`: 64 825 program words, 10 458 private words, 27 151 public words (the image before the ELF guard; today's is 765 851 cycles and 65 096 words, the same tier) |
| stopped | after **225 s** of wall time, still proving: the process's physical footprint went from 18.9 GB to **30.4 GB** between two samples 5 s apart |
| peak memory | **30.77 GB** peak memory footprint and 20.5 GB maximum resident set (`time -l`) |
| verify | not reached |

It was not retried. The interpreter's own tier-20 proof
(`research/tests/e2e.rs::compiled_sbpf_spl_token_transfer_proves_and_verifies`) is `#[ignore]`d for
the same reason. A tier-20 batch is 2^20 cpu rows, and the tier-18 EVM proof was already
SIGKILLed on this 48 GB machine at 28.5 GB and growing. Translation does not change the tier,
because the harness sets it (above), so the translated proof needs the same large machine
(≥ 64 GB, research's figure for tier 18) as the interpreter's. The real proof is deferred to such
a machine (a DO droplet, or the fleet's biggest box); it is not yet proven on a 48 GB laptop.
