# sbpf2rv

Translates an sBPF ELF into C that runs natively in the Rand zkVM: a shim crate that
`rand-guest build` turns into an image whose eight public output words equal the sBPF
interpreter's (`guests-compiled/bin/sbpf.bin`) for the same ELF and instruction.

```text
sbpf2rv <program.so> --out <dir inside a circuits checkout> [--name <crate>]
rand-guest build <dir> --max-words 65535
```

The rules of the translation are `src/emit.rs`'s module docs and the design spec
(`docs/superpowers/specs/2026-09-18-sbpf-to-rv32-translator-design.md`). The oracle tests are
`tests/parity.rs` (the real pipeline against `run_call` and `sbpf.bin`), `tests/fuzz.rs`
(differential fuzzing on the host), `tests/emit.rs` and `tests/scan.rs`.

## Measured: SPL Token, translated against interpreted

Every number here is from a run on this machine (a 16-core macOS laptop with 48 GB), 2026-09-18,
at the commit that added this section. The cycles and tier are what `rand-guest run` prints; the
instruction counts are `sbpf_core`'s meter natively. Regenerate the table with

```text
cd sbpf2rv && cargo +1.98.1 test --test parity the_spl_token -- --nocapture
```

**Images.** Translated SPL Token: **64 825** program words against the 65 535-word cap (710 spare),
`hc f382dd28…920e`. Interpreter `sbpf.bin`: **8 317** program words. Both need the same inputs:
the ELF on the public tape (27 151 words), the serialized instruction on the private one.

| vector | result | status | sBPF insns | translated cycles | tier | `sbpf.bin` cycles | tier | translated saves |
|---|---|---|---|---|---|---|---|---|
| `Transfer` 250 | `Ok(0)` | 1 | 143 | 692 854 | 20 | 694 498 | 20 | 1 644 |
| `Transfer` more than the balance | `Ok(1)` `InsufficientFunds` | 0 | 133 | 675 839 | 20 | 679 814 | 20 | 3 975 |
| `MintTo` 250 | `Ok(0)` | 1 | 120 | 635 651 | 20 | 634 423 | 20 | −1 228 |
| `MintTo` 250 signed by someone other than the mint authority | `Ok(4)` `OwnerMismatch` | 0 | 134 | 623 697 | 20 | 627 241 | 20 | 3 544 |
| `Burn` 250 | `Ok(0)` | 1 | 131 | 637 248 | 20 | 637 038 | 20 | −210 |
| `Burn` 1 000 001 of a 1 000 000 balance | `Ok(1)` `InsufficientFunds` | 0 | 121 | 622 437 | 20 | 624 781 | 20 | 2 344 |
| `Transfer` with two accounts | `Ok(0xb_0000_0000)` `NotEnoughAccountKeys` | 0 | 69 | 572 018 | 20 | 569 656 | 20 | −2 362 |
| an account count above `MAX_ACCOUNTS` (refused by the harness) | `Err(BadElf)` | 2 | 0 | 303 909 | 20 | 304 616 | 20 | 707 |

`tier` is `Tier::for_workload` over the executed cycles plus the digest rows, which is what
`prove` picks. Every vector lands in tier 20 on both sides (tier 18 is 262 143 cycles).

### Where the cycles go

About 98 % of every run is the harness, the same `sbpf-core` code on both sides. The program's
own execution is 1–3 %. Split by stage, for the three successful vectors
(`cargo +1.98.1 test --test parity where_the_cycles_go -- --ignored --nocapture`):

| stage | `Transfer` translated | `Transfer` `sbpf.bin` | `MintTo` translated | `MintTo` `sbpf.bin` | `Burn` translated | `Burn` `sbpf.bin` |
|---|---|---|---|---|---|---|
| decode_input: read both tapes | 302 881 | 302 880 | 281 873 | 281 872 | 281 873 | 281 872 |
| elf::load: parse, relocate, hash syscall names | 176 900 | 173 859 | 176 900 | 173 859 | 176 900 | 173 859 |
| check_region: the zero scan pinning the region | 103 829 | 103 824 | 77 895 | 77 891 | 77 895 | 77 891 |
| zero the sBPF stack and heap | 49 181 | 49 181 | 49 181 | 49 181 | 49 181 | 49 181 |
| output_hash | 25 994 | 20 348 | 20 912 | 14 784 | 21 468 | 15 338 |
| canonical input_hash | 18 620 | 16 225 | 15 071 | 12 365 | 15 038 | 12 332 |
| public output words, program id | 3 753 | 3 504 | 3 506 | 3 258 | 3 506 | 3 258 |
| other: entry, glue | 2 788 | 2 646 | 2 788 | 2 646 | 2 788 | 2 646 |
| **program: sBPF execution** | **8 908** | **22 031** | **7 525** | **18 567** | **8 599** | **20 661** |
| total | 692 854 | 694 498 | 635 651 | 634 423 | 637 248 | 637 038 |
| sBPF instructions | 143 | 143 | 120 | 120 | 131 | 131 |

How the split is made: both images are built without debug info and the harness is inlined into
`main`, so the test rebuilds each crate with `profile.release.debug = "line-tables-only"` into a
separate target directory, requires the rebuilt ELF to pack to the **same image bytes** (debug
info changes no code: the translated twin gives `hc f382dd28…`, the interpreter's twin
`sbpf.bin`'s `d49f10…b759`), runs the production image on the emulator, replays the pc sequence
with a shadow call stack, and names each cycle's stage from `llvm-symbolizer --inlining` over the
twin's line tables.

What the stages are:

* **decode_input** reads both tapes a word at a time: 37 609 words for the transfer (27 151 ELF +
  10 458 instruction), about 8.05 cycles a word. The ELF alone is about 219 k.
* **elf::load** parses and relocates the ELF (and hashes its syscall names) before anything runs.
* **check_region** scans the 40 988 bytes the canonical encoding leaves out (realloc headroom,
  padding) and requires them to be zero.
* **zero the sBPF stack and heap** is `Workspace`'s 64 KiB of fresh sBPF memory.
* **input_hash / output_hash / public output** are the SHA-256 digests and the eight words.
* **program** is everything the executor does: `Vm::run` and its memory in `sbpf.bin`, the
  translated functions and `sbpf-rt` (`sbpf_ld*`/`sbpf_st*`, the syscalls) in the shim.

### Does translation pay off for SPL Token?

**Not today.** Translated execution is about 2.5× cheaper per sBPF instruction: about 62 cycles against
about 154 on the transfer, most of the 62 in `sbpf_load`'s bounds and region checks. That saves
11.0–13.1 k cycles on these vectors' 120–143 instructions. But the shim's harness costs 11.5–12.3 k
more than `sbpf.bin`'s (`output_hash` +5.6 k, `elf::load` +3.0 k, `input_hash` +2.4 k on the
transfer), because the shim crate itself is built at `opt-level = "s"` (its dependencies at 3) to fit
the 65 535-word cap, and those generic functions are instantiated in it. Net: from −2.4 k to +4.0 k
cycles a vector, and every vector stays in tier 20.

Translation starts to matter only where the program's own execution is a real share of the run,
at thousands of sBPF instructions a call and up. At the measured ~90 cycles saved an instruction, a
program executing 10 000 instructions saves about 0.9 M cycles, and one near the 200 000-instruction
limit about 18 M. For SPL Token the levers are on the harness side:

* A bulk public-read syscall (`research/docs/04-guests.md`, spec §9.5's open item) for the tape.
* For a translated image specifically, not reading or loading the ELF at run time at all. The
  verifier's rule is already `hc == translate(ELF)`, so the image could carry the ELF's read-only data
  itself. On the measured split that removes about 219 k (reading the ELF) + 177 k (`elf::load`) of
  the transfer's 693 k, leaving about 297 k: still above tier 18's 262 143 without the region scan's
  cost coming down too. This is an estimate from the split, not a measurement.

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
| workload | 692 854 cycles, `Tier(20)`: 64 825 program words, 10 458 private words, 27 151 public words |
| stopped | after **225 s** of wall time, still proving: the process's physical footprint went from 18.9 GB to **30.4 GB** between two samples 5 s apart |
| peak memory | **30.77 GB** peak memory footprint and 20.5 GB maximum resident set (`time -l`) |
| verify | not reached |

It was not retried. The interpreter's own tier-20 proof
(`research/tests/e2e.rs::compiled_sbpf_spl_token_transfer_proves_and_verifies`) is `#[ignore]`d for
the same reason. A tier-20 batch is 2^20 cpu rows, and the tier-18 EVM proof was already
SIGKILLed on this 48 GB machine at 28.5 GB and growing. Translation does not change the tier,
because the harness sets it (above), so the translated proof needs the same large machine
(≥ 64 GB, research's figure for tier 18) as the interpreter's.
