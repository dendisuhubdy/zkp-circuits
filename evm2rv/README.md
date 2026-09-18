# evm2rv

Translates EVM bytecode (solc's runtime bytecode) into C over `evm-rt/`, for `rand-guest` to build
into a zkVM image. See Tasks 1-9's briefs and reports under
`.superpowers/sdd/2026-09-18-evm2rv-translator/` for the design and every ruling.

This page is Task 7's measurement: the translated ERC-20's cycles against the interpreter's
(`guests-compiled/bin/evm.bin`), split into harness/ABI work and contract execution, and one real
proof.

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
and `tests/precompiles.rs` already pin. Every translated image is the **default build** (what a
chain would deploy, `emit-outcome` off). The ERC-20's `hc` is the pinned
`3307bfc4aaf87e4021941d18a9e813441354bb6fa19b357c5b604839e516579d`; `evm.bin` is unmodified
(`guests-compiled/bin/evm.bin`, sha256 `5500886f…440d`).

| vector | program | words | hc | cycles | tier |
|---|---|---:|---|---:|---:|
| `transfer(BOB, 250)`, balance 1 000 | interpreted (`evm.bin`) | 18 009 | `7e1aea2b…854c08` | 121 638 | 18 |
| `transfer(BOB, 250)`, balance 1 000 | translated | 15 637 | `3307bfc4…16579d` | 79 203 | 18 |
| `approve(BOB, 5)` | interpreted (`evm.bin`) | 18 009 | `7e1aea2b…854c08` | 85 645 | 18 |
| `approve(BOB, 5)` | translated | 15 637 | `3307bfc4…16579d` | 55 255 | 16 |
| `transferFrom(ALICE, BOB, 100)` | interpreted (`evm.bin`) | 18 009 | `7e1aea2b…854c08` | 161 434 | 18 |
| `transferFrom(ALICE, BOB, 100)` | translated | 15 637 | `3307bfc4…16579d` | 109 064 | 18 |
| sha256("abc") + ecrecover (underfunded, 2 999 of 3 000) | translated | 15 691 | `338c1588…822285` | 22 367 | 16 |

The precompile vector (`tests/precompiles.rs`'s Task 5 end-to-end contract, STATICCALL to sha256
then to ecrecover with one gas short) has no interpreted row: `evm-core`'s interpreter traps on
every `CALL`-family opcode (Task 5's ruling 1), so it is not an oracle for a contract that calls
out, and the comparison in this README is translated-only.

Translated cycles are consistently **64.5-67.6% of the interpreter's** across every ERC-20 vector —
a 32-35% cut (`transfer` 65.1%, `approve` 64.5%, `transferFrom` 67.6%): block-level static gas
charging and direct dispatch (`goto`s, not a decode-execute loop) remove some of the interpreter's
per-opcode overhead, but — see the harness/ABI split below — most of what is left in the translated
program is not opcode dispatch either.

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

## One real proof

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
  or the emulator a pc-histogram mode instead of re-deriving symbol ranges by hand.
- Neither proof ran to completion. The cycle/tier/words table above is the full, real comparison
  the brief asks for; the proof-time column it also asks for could not be filled in for either
  program within the stated budget. A GPU-backed or aggregation-based proving path (already
  planned, per the concerns above) is the likely fix, not a change to the translation.
