# evm2rv

Translates EVM bytecode (solc's runtime bytecode) into C over `evm-rt/`, for `rand-guest` to build
into a zkVM image. See Tasks 1-9's briefs and reports under
`.superpowers/sdd/2026-09-18-evm2rv-translator/` for the design and every ruling.

This page is the measurement of both translation stages: the translated ERC-20's cycles against
the interpreter's (`guests-compiled/bin/evm.bin`), split into harness/ABI work and contract
execution, and one real proof (stage one, Task 7).

- **Stage one** (Task 4, `src/emit.rs`): every opcode over `evm-rt`'s memory stack.
  `evm2rv --stage 1`.
- **Stage two** (Task 8, `src/lift.rs`): the same blocks, block heads, runtime calls and gas, with
  each block's words in C locals, constants folded (with the interpreter's own `U256`) and
  resolved at translation, and the memory stack written only where another block or the runtime
  reads it. It passes every test stage one passes and is the CLI's **default** (Task 8, ruling 1).
  The two are different programs, each with its own pinned `hc`.

**Toolchain.** `cargo +1.98.1`. The RV32 shim is built with Homebrew clang, found by `build.rs` the
way `rand-guest` finds it (`$CLANG`, then Homebrew's LLVM, then `clang` on `PATH`, each probed for
`riscv32` in `--print-targets`): on the machine these numbers were measured on, that resolved to

```
$ /opt/homebrew/opt/llvm/bin/clang --version
Homebrew clang version 23.1.1
Target: arm64-apple-darwin25.6.0
```

## Cycles, tier and words

Measured with `rand-guest run` (`rand-guest info` for words and `hc`) on the vectors `tests/parity.rs`
and `tests/precompiles.rs` already pin; both print, for every stage, the cycles and the tier
`rand-guest run` picks. Every translated image is the **default build** (what a chain would
deploy, `emit-outcome` off). `evm.bin` is unmodified (`guests-compiled/bin/evm.bin`, sha256
`5500886f…440d`).

| program | words | hc |
|---|---:|---|
| interpreted (`evm.bin`) | 18 009 | `7e1aea2b…854c08` |
| ERC-20, stage one | 15 637 | `3307bfc4aaf87e4021941d18a9e813441354bb6fa19b357c5b604839e516579d` (pinned) |
| ERC-20, stage two | 11 519 | `87aba574b1dff3591631fbfc2ebd9e993098e9929219126ddc94ecaf2c60ccad` (pinned) |
| sha256 + ecrecover contract, stage one | 15 691 | `338c1588…822285` |
| sha256 + ecrecover contract, stage two | 15 463 | `96bae05f…3c2914` |

Cycles, with the tier in parentheses:

| vector | interpreted (`evm.bin`) | stage one | stage two | stage two / stage one |
|---|---:|---:|---:|---:|
| `transfer(BOB, 250)`, balance 1 000 | 121 638 (18) | 79 203 (18) | **65 227** (18) | 82.4% |
| `approve(BOB, 5)` | 85 645 (18) | 55 255 (16) | **47 113** (16) | 85.3% |
| `transferFrom(ALICE, BOB, 100)` | 161 434 (18) | 109 064 (18) | **87 814** (18) | 80.5% |
| transfer of 5 000 of 1 000 (reverts) | 88 092 (18) | 53 248 (16) | 45 822 (16) | 86.1% |
| transfer, out of gas at 100 | 49 504 (16) | 31 823 (16) | 31 374 (16) | 98.6% |
| transfer, out of gas at 20 000 | 103 736 (18) | 66 807 (18) | 56 419 (16) | 84.5% |
| transfer, out of gas at 29 955 | 120 235 (18) | 77 545 (18) | 64 030 (18) | 82.6% |
| sha256("abc") + ecrecover (underfunded, 2 999 of 3 000) | — | 22 367 (16) | 21 303 (16) | 95.2% |

The precompile vector (`tests/precompiles.rs`'s Task 5 end-to-end contract, STATICCALL to sha256
then to ecrecover with one gas short) has no interpreted row: `evm-core`'s interpreter traps on
every `CALL`-family opcode (Task 5's ruling 1), so it is not an oracle for a contract that calls
out, and the comparison in this README is translated-only.

Stage one's cycles are consistently **64.5-67.6% of the interpreter's** across every ERC-20 vector —
a 32-35% cut (`transfer` 65.1%, `approve` 64.5%, `transferFrom` 67.6%): block-level static gas
charging and direct dispatch (`goto`s, not a decode-execute loop) remove some of the interpreter's
per-opcode overhead, but — see the harness/ABI split below — most of what is left in the translated
program is not opcode dispatch either.

Stage two takes the ERC-20 vectors to **53.6-55.0% of the interpreter's** (`transfer` 53.6%,
`approve` 55.0%, `transferFrom` 54.4%): another 15-20% off stage one on the successful calls, and a
quarter fewer program words. The precompile contract gains least (4.8%): nearly all of its
cycles are the harness and `evm_call`, not its handful of opcodes.

**The tier.** Stage two's `transfer` (65 227 cycles) runs under tier 16's 65 535-cycle budget but
stays at tier 18: the tier `rand-guest run` reports (and `Machine::prove` would take) is
`Tier::for_workload` over the cycles **plus** the digest rows — one per four program words
(2 880 for 11 519 words) and one per four input words, plus one. Tier 16 would need at least
2 572 fewer cycles or rows, more once the input's rows are counted. The out-of-gas-at-20 000 vector does drop a tier (18 to
16).

### Harness/ABI work vs. contract execution

The brief asks the translated program's cycles to be split into harness/ABI work — decoding the
input vector, verifying a storage witness the first time a slot is touched, the ABI's own
`keccak256` calls (the runtime bytecode's `codehash`, and `return_hash`/`logs_hash` at the end),
and building the output digest — versus contract execution: `evm_entry` itself (the translated
opcodes) plus the shared `evm-rt`/`u256.c` primitives every opcode structurally needs (gas
charging, memory, stack arithmetic, calldata, logs, the `KECCAK256`/`SLOAD`/`SSTORE` opcodes'
own dispatch code).

No `rand-guest`/emulator mode emits a pc histogram or a symbolised sample directly, so this is a
small one-off tool built for Task 7 (not committed — every number below is reproducible from the
shim's own RV32 ELF, kept under `target/` by `rand-guest build`): `llvm-nm --print-size` on the
shim's ELF gives every function's `[start, start+size)`, each classified by name (`evm_entry`,
`evm_rt_*`, `evm_charge`, `evm_mexpand`, `evm_m{load,store}`, `evm_calldataload`, `evm_keccak`,
`evm_log`, `evm_storage_{load,store}`, `evm_{sload,sstore,keccak256}`, `u256_*`, `shl_by`/`shr_by`,
`mem{cmp,set,cpy}`, `_start` count as contract execution; everything else — the ABI's own
`keccak256` monomorphisation, `public_output`, `run_call_with_executor`, `InputCursor::bytes`,
`StorageTree::{find,verify}`, `main`, the syscall trampolines and unreached panic handlers — counts
as harness). `rand_zkvm::emulator::execute` (the same emulator `rand-guest run` uses) is then run
directly — no 2^20 cap needed, since every one of these vectors fits it — and each `CycleEvent`'s
`pc` is looked up in that table.

| vector | total | contract execution | harness/ABI | unclassified* |
|---|---:|---:|---:|---:|
| transfer | 79 203 | 33 688 (42.5%) | 45 071 (56.9%) | 444 (0.6%) |
| transfer, **stage two** (Task 8) | 65 227 | 27 450 (42.1%) | 37 259 (57.1%) | 518 (0.8%) |
| approve | 55 255 | 20 588 (37.3%) | 34 223 (61.9%) | 444 (0.8%) |
| transferFrom | 109 064 | 50 286 (46.1%) | 58 334 (53.5%) | 444 (0.4%) |
| sha256 + ecrecover (underfunded) | 22 367 | 9 300 (41.6%) | 11 819 (52.8%) | 1 248 (5.6%) |

\* pc that landed outside every symbol's `[start, start+size)` — chiefly `_start`'s own prologue
(reported by `llvm-nm` at size 0, so only its first instruction is covered) and small gaps between
functions. It is not attributed to either bucket; at 0.4-0.8% for the ERC-20 vectors and 5.6% for
the precompile contract (which links more `evm-rt` object files, so more such gaps) it does not
change the conclusion below.

Even with contract execution generously defined (every opcode-support primitive, not just
`evm_entry`'s own control flow), **harness/ABI work is 53-62% of the translated program's
cycles** — storage-witness verification (paid once per slot on first touch: the ERC-20 vectors
each touch one or two) and the ABI's own three `keccak256` calls dominate it. The 79 203-cycle
`transfer` is still only 65.1% of the interpreter's 121 638, so the harness overhead is not what
makes the translation faster than the interpreter — it is paid by both, and the interpreter pays
its own equivalent decode/witness/hash costs inline rather than in separately-counted functions —
but it is the visible floor under which no amount of opcode-level translation work can shrink a
call.

**Stage two's split (Task 8), and a correction to the rule above.** The table's stage-two row is
this rule applied again, with the tool rebuilt for Task 8 (not committed either; the rebuilt
tool puts stage one's `transfer` at 33 502 / 45 257 / 444, within 186 cycles of the row above).
By that rule, stage two's `transfer` spends 8 000 fewer cycles in the *harness* — which cannot be
right, since the harness is the same code in both images. The name rule counts
`compiler_builtins::memcpy` (a mangled Rust symbol, not the C `memcpy` it lists) as harness, and
most of its calls in stage one are the contract's own: every 32-byte `DUP`/`SWAP` of the memory
stack is a struct assignment that clang lowers to `memcpy`. Charging each `memcpy`, `memset` and
`memcmp` call to the function that made it (the pc of the call site; all three are leaves) gives
the split that separates the two:

| transfer | total | contract execution | harness/ABI | unclassified* |
|---|---:|---:|---:|---:|
| stage one, calls charged to their caller | 79 203 | 39 839 (50.3%) | 38 920 (49.1%) | 444 (0.6%) |
| stage two, calls charged to their caller | 65 227 | 25 789 (39.5%) | 38 920 (59.7%) | 518 (0.8%) |

The harness is exactly 38 920 cycles in both (as it must be), and **stage two cuts the
contract's own execution by 35% (39 839 to 25 789)**: of stage one's `memcpy` cycles, 12 728 were
the contract's and 4 472 remain (spills, and the runtime's own copies). The harness is now 60% of
a `transfer`. Stage two's unclassified cycles grow by 74: its constants live in the image's data,
which the loader's prologue writes before `_start`.

## One real proof

(Stage one, Task 7. Task 8 ran no proof, as its notes direct; a stage-two proof is the same
machine over a smaller program with fewer cycles, at the same tier for `transfer`.)

An `#[ignore]`d test (`tests/proof.rs`) proves and verifies the translated ERC-20 `transfer` (and,
as a second `#[ignore]`d test, `evm.bin` on the same vector) with
`Machine::new(FriProfile::Test).prove(&program, &inputs, &[], None)`, then `verify`
(`research/tests/backend.rs:44-61` is the API these two tests follow). Each test's own doc comment
carries the exact command; both are meant to be run once, by hand, under `/usr/bin/time -l`, never
as part of an ordinary `cargo test`.

**The translated `transfer` was run once, as specified.** It did not finish:

```
$ cd evm2rv && /usr/bin/time -l cargo +1.98.1 test --release --test proof \
    the_translated_erc20_transfer_proves_and_verifies -- --ignored --exact --nocapture
...
test the_translated_erc20_transfer_proves_and_verifies has been running for over 60 seconds
error: test failed, to rerun pass `--test proof`
Caused by:
  process didn't exit successfully: `.../proof-006b5d858b317c53 the_translated_erc20_transfer_proves_and_verifies --ignored --exact --nocapture` (signal: 9, SIGKILL: kill)
     1015.76 real       857.71 user        33.00 sys
         24706367488  maximum resident set size
```

1 015.76 s (about 16.9 minutes) of wall time in, at a peak resident set of 24 706 367 488 bytes
(23.0 GiB / 24.7 GB) — over the notes' "about 24 GB" budget — the process was killed by SIGKILL
(the OS, not a limit this test enforces itself; a concurrent `ps`-based watch never saw the process
above 22.8 GiB at its own 15-second sampling interval, so the true peak was reached and gone
between samples). No proof was produced, and the run was not repeated: the notes ask for one run,
recorded, and to stop at this budget.

**`evm.bin` on the same vector was not attempted.** The notes make it conditional on the translated
proof fitting the same limits ("if that fits the same limits, so the README can compare proof times
directly") — it did not. `evm.bin` is also the larger and more expensive program on every measure
above (18 009 words against 15 637, 121 638 cycles against 79 203 on this exact vector), so it would
not plausibly fit a budget the smaller, cheaper program already exceeded; running it to confirm
that would cost another ~17 minutes for a predictable answer.

**Reading.** `Machine::prove`'s CPU path (`build_traces_salted` then `prove_traces`, no GPU
backend) builds a full trace matrix — one row per cycle, one column per chip, for every chip the
tier needs — before it commits to anything; nothing here streams. At `FriProfile::Test` (16
queries, 4 PoW bits — deliberately weak, for a fast `cargo test`) the query and PoW cost is small,
so this is a trace-construction and low-degree-extension cost, not a FRI cost. A stage-one program
this size proving CPU-only past a 24-25 GB peak on this 48 GB laptop (shared with other proving
work during this measurement) is squarely the concern Task 5's report and Task 7's own concerns
list flag as the coprocessor/aggregation backlog, not a defect in the translation itself — see
`Machine::prove_with(Backend::Cuda, …)` (`research/tests/backend.rs`) for the GPU path this stage
did not exercise.

## Concerns

- The harness/ABI-vs-contract-execution split is a symbol-based classification built for this
  measurement, not a `rand-guest`/emulator feature; it is reproducible (the method is described
  above) but not automated, and a future task that wants it on demand should give `rand-guest run`
  or the emulator a pc-histogram mode instead of re-deriving symbol ranges by hand. (Task 8 had
  to rebuild it, and found the name rule mis-files the contract's `memcpy` calls; the
  caller-charged split above is the one to trust.)
- Stage two's cycles were measured, not proved: no stage-two proof was run (Task 8's notes).
- Neither proof ran to completion. The cycle/tier/words table above is the full, real comparison
  the brief asks for; the proof-time column it also asks for could not be filled in for either
  program within the stated budget. A GPU-backed or aggregation-based proving path (already
  planned, per the concerns above) is the likely fix, not a change to the translation.
