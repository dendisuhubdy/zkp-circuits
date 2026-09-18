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

## Usage: a real SPL Token walkthrough

Every command below was run on this machine, 2026-09-18, against the committed ELF
`guests-compiled/sbpf/programs/spl_token.so` — the interpreter's own test fixture
(`sbpf-core`'s `spl_transfer`, `SPL_TOKEN_ELF`). Output is pasted, not summarized, and
abbreviated only where it repeats. This is the walkthrough the website docs should copy.

### 1. Translate

```text
$ sbpf2rv guests-compiled/sbpf/programs/spl_token.so --out <dir> --name spl-token
entry pc 225: 30 function(s), 3546 block(s), 12061 instruction(s), 30 callx target(s), 0 refusal(s), 4 warning(s)
  fn 225: 2065 block(s)
  fn 0: 41 block(s)
  fn 117: 52 block(s)
  ...                                              (30 functions in all)
  warning: UnknownSyscall { pc: 7803, hash: 2720453611 }
  warning: UnknownSyscall { pc: 9530, hash: 2720453611 }
  warning: UnknownSyscall { pc: 8698, hash: 2720453611 }
  warning: UnknownSyscall { pc: 11547, hash: 331461893 }
wrote <dir>/program.c (521757 bytes of C) and the spl-token shim crate: rand-guest build <dir>
```

`0 refusal(s)`: nothing about the ELF's instructions is refused (see "What is refused, and what
traps" below). The four warnings are real syscalls the ELF calls but the `Transfer` instruction
never reaches: hash `2720453611` is `sol_set_return_data` (three call sites), hash `331461893`
is `sol_get_sysvar` (one).

### 2. Build

```text
$ rand-guest build <dir> --max-words 65535
   Compiling sbpf-core v0.1.0 (…/guests-compiled/sbpf-core)
   Compiling guest-sdk v0.1.0 (…/guest-sdk)
   Compiling cc v1.4.6
   Compiling spl-token v0.1.0 (<dir>)
    Finished `release` profile [optimized] target(s) in 6.02s
64825 words against a cap of 65535 (fits); 2 ecall(s) with a non-static a7
OK
wrote <dir>/image.bin and its .sha256 (64825 words, hc f382dd28e4c363709afed9dc7cacd11508e61739617626f7a1a4d69e93d1920e, program id d9a57acf0bf8f1a0e1b5e83d858148609ce68ae30b3f0fbfdecedb8f5405eef8)
```

`hc` is the image's own digest; `program id` is the id `rand-guest` derives for the deployed
program. Both matter for the trust rule below.

### 3. Run, and compare with the interpreter

The `Transfer` 250 vector's inputs are two word lists, exactly as `tests/parity.rs` builds them
from `SbpfCall::public_words()` / `input_words()`: **27 151 public words** (the ELF itself,
word-encoded — this is why the image still carries the whole ELF, not just its hash) and
**10 458 private words** (the serialized instruction: the accounts `spl_transfer` builds, then
the `Transfer` discriminant and the amount). `rand-guest run` takes them as `--public w0 w1 …`
and `--input w0 w1 …`. Abbreviated to the first handful of words of each list:

```text
$ rand-guest run <dir>/image.bin \
    --public 108600 1179403647 65794 0 0 17235971 1 2088 …   (27 151 words)
    --input  41825 4 0 65791 0 50529027 50529027 50529027 …  (10 458 words)
out[0] = 1
out[1] = 2892832079
out[2] = 376091303
out[3] = 1311040261
out[4] = 2015764099
out[5] = 3682593600
out[6] = 3311553006
out[7] = 141115266
cycles 692854
tier 20
```

The same two word lists, unchanged, against the interpreter's own committed guest:

```text
$ rand-guest run guests-compiled/bin/sbpf.bin \
    --public 108600 1179403647 65794 0 0 17235971 1 2088 …   (27 151 words)
    --input  41825 4 0 65791 0 50529027 50529027 50529027 …  (10 458 words)
out[0] = 1
out[1] = 2892832079
out[2] = 376091303
out[3] = 1311040261
out[4] = 2015764099
out[5] = 3682593600
out[6] = 3311553006
out[7] = 141115266
cycles 694498
tier 20
```

All eight words are identical, word for word. The interpreter costs 694 498 cycles against the
translated program's 692 854 — the 1 644-cycle saving this vector's row in the measured table
below reports. Both land in tier 20; "Does translation pay off for SPL Token?" below is why the
harness, not this saving, decides the tier.

### 4. Deploy

```text
rand program deploy <dir>/image.bin
```

deploys the image, on a chain whose genesis sets `max_program_words >= 64 825` — this image's own
word count. **Today's chain 12 caps a deploy at 4 096 words**
(`docs/superpowers/specs/2026-09-18-rand-guest-toolchain-design.md` §8's
`MAX_PROGRAM_WORDS`), about 16× too small for this image, so the command above is not runnable
on the live chain today: it needs a chain cut with the raised cap. **Not run here.**

## Trust and verification

The image does not check which ELF it was given: the translated functions are baked in, but the
ELF still arrives on the public tape (step 3 above) and is what `program_id` and the digest are
computed from — nothing in the image re-derives `program.c` from the ELF bytes and compares. So
the rule that binds the two is external, the same one the EVM translator uses (design spec §6):
**a verifier checks `hc == translate(ELF)`** — rebuild the shim crate from the published ELF
with the pinned `sbpf2rv`/`rand-guest`/toolchain versions and compare the image digest. The chain
side's part of this is to record the source ELF's hash beside the deployed program id at deploy
time, so a later verifier has something to check `hc` against without trusting the deployer's
word for which ELF produced the image.

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
| *(a runtime value, not a static warning)* `callx` to a real instruction that is some function's valid target but not *that* function's own entry | — | `sbpf_trap(BadJump)`, an accepted, safety-favoring divergence: the interpreter may execute real code at that address, the translation always refuses it (fuzzed 117-for-117: re-running each such case with the target added as a named entry makes both sides agree exactly, Task 5) |

Every one of these is a *runtime* trap carrying the interpreter's own `Halt` value and payload,
never a translation-time refusal — matching `interp.rs`, which only ever raises them when the
instruction actually executes. A translator that refused a program over unreached code would
refuse programs the interpreter runs successfully today, and the committed SPL Token ELF is
exactly that case: its `sol_set_return_data`/`sol_get_sysvar` calls, warned about above, are dead
code on the transfer path.

**Budget checks may be deferred one basic block.** To fit SPL Token under the 65 535-word cap,
1 505 of its 3 546 blocks skip their own instruction-limit check and only decrement the counter;
the next block's head then halts `InstructionLimit` if the limit was crossed. The one place the
translation's halt *kind* can differ from the interpreter's own one-instruction-at-a-time count
is inside that single limit-crossing block (a fault partway through it may be reported as
`InstructionLimit` instead) — never anywhere else — and the published status and eight words are
equal either way, since every exceptional halt publishes status 2 over the pre-state.

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
