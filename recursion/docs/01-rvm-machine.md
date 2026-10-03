# 01 — The rVM machine: tables, buses, tiers, and the measured cost of one verified bundle proof

The rVM's proving machine (design spec: `docs/superpowers/specs/2026-09-13-zkvm-m5-recursion-vm-design.md`;
the M5.2 plan: `docs/superpowers/plans/2026-09-14-zkvm-m5-2.md`; the measurement it is cut from and
the three row cuts: `docs/00-recursion-vm.md`). M5.2 builds the machine itself: the tables, the
batch prover/verifier, the tiers, the cheating suite, and — here — the measured numbers for the
exit shape, including the production exit's resource requirement.

Every number in this document was measured on 2026-09-15 on this machine (macOS, 16 cores, 48 GB)
with the crate's documented command, `cargo +1.98.1 test` run from `recursion/`, and is pinned by
a test where the plan asks for one: `tests/pins.json` for the cycle numbers,
`src/programs/verify_rv32.digest` for the program digest, `tests/tables.rs` for the widths and
constraint degrees. Estimates are labelled with their derivation.

## The tables

Seven instances in every batch, plus the reduce chip when the proof declares it (`reduce_log_height
== 0` means no instance — the keccak pattern):

| instance | height rule | width (pinned) | max constraint degree (pinned) | role |
|---|---|---:|---:|---|
| `program` | `pad_height(len + 1, 4)` | 3 witness + 4 preprocessed | 2 | the encoded program, committed by the verifier key's preprocessed cap (R1 — no in-circuit `hc`) |
| `cpu` | `2^tier` | 82 | 8 | fetch (from `program`), 28 one-hot decode selectors, base + extension ALU, the `INV`/`EINV` hint-and-check, control, the `REG`/`RAM`/`POSEIDON2`/`SPONGE`/`REDUCE`/`PUBLIC`/`COMPRESS` sends, `HINTN`'s eight tape-word columns `W0..W7` and their eight `RAM` writes, the 5-bit register-index and 3-byte address-limb range checks — both ends of every multi-cell access since ZKQ-3 (2026-09-27; 66 before ZKQ-3, 72 before phase 2's `HINTN` (+9) and `COMPRESS` (+1) selectors and words, 2026-10-03) |
| `reg_memory` | declared, `[4, 26]` | 11 | 4 | the register file as cells `2^24 + k`, `k < 32` (R4) — sorted `(addr, ts)`, read-after-write by transition |
| `ram_memory` | declared, `[4, 26]` | 11 | 4 | RAM below `2^24`, same AIR on the `RAM` bus |
| `poseidon2` | declared, `[4, 20]` | 343 | 4 | permutation-per-row, three row kinds (`IS_PERM`, `IS_SPONGE`, and since phase 2 `IS_COMPRESS` — one Merkle level: `BIT` orders `[digest ‖ sibling]`, `SRC_PTR` is the sibling, 4 + 4 reads and 4 writes), round constants baked into `eval` (R9); 341 wide before `IS_COMPRESS`/`BIT` |
| `public` | fixed at 8 | 7 | 2 | one row per published word; owns the batch's 4 public values (R5, the interface digest) |
| `range` | fixed at 256 | 1 witness + 1 preprocessed | 2 | the `RANGE8` provider |
| `reduce` (optional) | declared, `[4, 20]` | 39 | 3 | the batch-opening reduction, one chip row per column, chained by the descriptor and the clock (Task 8; the clock chain, the real-row-only row kinds, the run-end rule and the 18 address-limb columns are the 2026-09-27 zk scan's — 21 wide before) |

**Buses (9; 8 under plan R7, `COMPRESS` added by phase 2):** `REG`, `RAM` (both `[addr, ts,
value, is_write]`, multiset), `POSEIDON2 [clk, ptr]`, `SPONGE [clk, state_ptr, src_ptr]`,
`PROGRAM [pc, w0..3]`, `RANGE8`, `PUBLIC [idx, value]`, `REDUCE [clk, descr_ptr]`,
`COMPRESS [clk, state_ptr, sib_ptr, bit]`. Every send count is a selector expression forced
to zero on rows that do not perform the access (`research/AGENTS.md` invariant 2), and every
message column is constrained on every row kind that sends it (invariant 1); `tests/cheating.rs`
proves each one.

**Tiers:** `TIERS = [8, 10, 12, 14, 16, 18, 19, 20, 21, 22, 23]` (plan R2, amended M5.4): stride
2 through the cheap sizes, 19 the post-cut test-profile verifier rung, 21 the production exit
rung, 22 the safety rung, and — added with the CUDA backend (M5.4 Task 2) — **23, the
production N=3 aggregate rung**: host ≥ 160 GB (M5.3's derived ~127 GB oracle), device 80 GB
class (`docs/03-gpu-and-self-recursion.md`'s device model). A rung no CPU-only box in this
fleet has, pinned by `for_cycles`, not by a proof. Since phase 2's row cuts (2026-10-03,
`docs/04-phase2-row-cuts.md`) every proof is one rung lower at equal N: the test twin is tier 18,
the production exit and N=1 aggregate tier 20, production N=2 tier 21, N=3 and N=4 tier 22. The
host classes quoted in this paragraph are the withdrawn oracle model's; docs/04 has the measured
live heap.

## The measured numbers

**Current (phase 2, 2026-10-03; `docs/04-phase2-row-cuts.md` has the per-stage record).** Per
verified inner proof at constraint set 8 after the three row cuts, pinned in `tests/pins.json`
(production digest `723218da65a50f1f1581013f79fa5c5b1816b7ab46796dbaa4672c52bce2d0d1`), declared
heights from `machine::build_traces` over the same executions:

| | `FriProfile::Test` (16 q) | `FriProfile::Production` (80 q) |
|---|---:|---:|
| cpu rows | 230 950 | **893 606** |
| Poseidon2 permutations | 11 875 | 54 515 |
| memory accesses (RAM) | 504 365 | 2 213 181 |
| register accesses | 582 743 | 2 147 159 |
| reduce-chip rows | 34 624 | 173 120 |
| program instructions | 233 067 | 903 739 |
| witness words | 45 899 | 210 763 |
| **declared heights** | 18, 20, 19, 14, 16, 18 | 20, 22, 22, 16, 18, 20 |
| tier | 18 | **20** |

Constraint set 8 before the cuts was 461 988 / 2 047 268 rows at tiers 19 / 21, declared heights
19, 21, 20, 14, 16, 19 and 21, 23, 22, 16, 18, 21 (re-measured on the base tree for docs/04).
The poseidon2 and reduce tables keep their heights through the cuts (same permutations, same
reduce rows), and the production RAM table stays at `2^22` (2 213 181 accesses, 116 029 over
`2^21`).

**History.** Final, per verified inner proof (one RV32 bundle proof at **constraint set 6**, **9 instances**),
from the emulator's own event log and pinned in `tests/pins.json` (production digest
`8901cec9c1681c9674f1e5582805d625c60b20d9f69be546da982622f36e0bda`):

| | `FriProfile::Test` (16 q) | `FriProfile::Production` (80 q) |
|---|---:|---:|
| cpu rows | 441 643 | **1 968 619** |
| Poseidon2 permutations | 11 205 | **51 605** |
| memory accesses (RAM) | 597 021 | 2 705 197 |
| register accesses | 992 729 | 4 278 681 |
| reduce-chip rows | 31 232 | 156 160 |
| program instructions | 443 686 | 1 978 422 |
| witness words | 43 344 | 199 760 |
| **declared heights** | 19, 20, 20, 14, 15, 19 | 21, 23, 22, 16, 18, 21 |

This is the constraint-set-6 measurement, kept because the register-access, reduce-row and
declared-height columns were not re-taken. Constraint set 7 with VERIFIER-1 (chain 16, measured on
the integrated `feat/cs7` tree) is **461 082 / 2 044 506** cpu rows, 11 852 / 54 428 permutations,
630 292 / 2 845 220 memory accesses, 463 199 / 2 054 639 instructions, 45 758 / 210 174 witness
words, production digest `8f15919989c3975106b7663722fe892c20e14e9658948e073626662cc999e1e7` — still
tier 21 at production (`docs/00-recursion-vm.md`, "The measured number", has the breakdown).

(Heights in `chips()` order: cpu, reg, ram, poseidon2, reduce, program; public is fixed at 2^3
and range at 2^8.)

### The three cuts and the gates (spec §7's decision, executed)

| stage | cpu rows (production) | Δ | the plan's prediction | gate |
|---|---:|---:|---|---|
| M5.1 + Task 4 (R5) | 5 683 021 | — | — | over 2^21 · 0.75 — liveness runs |
| Task 7 (liveness) | 4 052 455 | −28.7 % | ~3.6 M (guessed 85–90 % of 2 454 511 spill/reload rows; measured kill 66 %) | 4 052 455 > 1 572 864 — **fires** |
| Task 8 (`REDUCE`) | 2 240 988 | −44.7 % | ~2.5 M (beat it: the compiled reduction was ~11.6 rows/column, not ~7) | 2 240 988 > 1 572 864 — **fires** |
| Task 9 (`SPONGE`) | 1 968 619 | −12.1 % | ~1.9–2.0 M (in band; absorb bookkeeping ~8.8 rows/block, not ~15–20) | **tier 21: 1 968 619 < 2^21, 6.1 % headroom** |

## The test-profile twin (Task 10's in-suite exit shape)

(Since phase 2's row cuts the twin is 230 950 rows at **tier 18**, `tests/exit.rs`; the
measurements below are the 2026-09-15 constraint-set-6 run at tier 19. Its "peak resident" row is
macOS RSS, which excludes compressed and swapped pages — not a memory number; the same tier-19
shape at constraint set 8 measured 94.2 GB on Linux and 78.7 GB live when killed on this box,
`docs/04-phase2-row-cuts.md` §"The prover's live heap".)

The twin proves the post-cut verifier program's execution over one real `FriProfile::Test` bundle
proof and verifies the rVM proof natively (`tests/exit.rs::twin_...`, `#[ignore]`d with the wall
times). Measured 2026-09-15:

| | measured |
|---|---:|
| cpu rows / tier | 441 643 / **19** |
| prove time | **1 707.7 s** (on this box, at load ~5 with other cargo sessions running) |
| verify time | **18.31 s** — dominated by the 2^19-row preprocessed program key build; the batch verify itself is sub-second |
| proof size | **327 321 bytes** |
| peak resident | **~15 GB observed** (watchdog samples; the completed run sampled ≤ 10.4 GB, the earlier timed-out attempt 15.0 GB) |

## The production exit's resource requirement (derived, not measured)

**The ≥ 64 GB requirement below is withdrawn (2026-10-03).** The committed-oracle model counted
one of the prover's four memory terms — main LDE and tree; the permutation (LogUp) LDE and tree;
the quotient-chunk LDEs, each chunk salted with four columns of its own; the quotient tree and
the FRI phases — and the other three are ~4× it. The measured record and the live model are
`docs/04-phase2-row-cuts.md` §"The prover's live heap" (a tier-19 proof: 78.7 GB live when killed
on a 48 GB box, 94.2 GB peak on Linux). Since phase 2's row cuts the exit is 893 606 rows at
**tier 20**; docs/04 derives ≈ 190–240 GB for it from the measured terms — a ≥ 256 GB host,
until it is proved.

**Measured 2026-09-30 (constraint set 8, a 503 GB box, fullnode #45): the exit proves in
8 164.8 s, verifies in 99.3 s, is 1 566 619 bytes, and peaks at 376.9 GB resident** — 7.8× the
oracle model below, which was calibrated on the cs5 rehearsal and never re-fitted after
constraint sets 7 and 8 widened every table. The firm requirement is ≥ 512 GB, not ≥ 64 GB;
`docs/02-aggregate.md`, "Constraint set 8, proved", has every rung's measured peak. The
derivation is kept below as the record of how the 64 GB class was arrived at.

The production exit is the same proof at `FriProfile::Production` over one real cs6 bundle proof:
2 240 988 fewer rows than the pre-cut rehearsal, tier 21. Its peak resident memory is derived from
the measured declared heights and the calibrated oracle model (the model the M5.2 plan's sizing
section calibrates against the rehearsal, which peaked at 28.5 GB RSS against a 32.1 GB modelled
oracle — a factor of 0.89):

| instance | height | width | committed oracle (`2^(h+4) · (w+4) · 8 B`) |
|---|---:|---:|---:|
| cpu | 2^21 | 66 | 18.79 GB |
| reg_memory | 2^23 | 11 | 16.11 GB |
| ram_memory | 2^22 | 11 | 8.05 GB |
| poseidon2 | 2^16 | 341 | 2.89 GB |
| program | 2^21 | 3 | 1.88 GB |
| reduce | 2^18 | 21 | 0.84 GB |
| public / range | 2^3 / 2^8 | 7 / 1 | ~0 |
| **total** | | | **48.6 GB** |

(At the 2026-09-27 widths — cpu 72, reduce 39, after ZKQ-3's address range checks — the same
heights model to 20.40 GB and 1.44 GB for those two rows, 50.8 GB in all; not re-measured.)

Peak estimate: the oracle floor of **48.6 GB**, times the rehearsal's observed 0.89
(≈ **43 GB best case**) to the conservative 1.25 multiplier (≈ **61 GB**). So:

- **(Withdrawn, see above.) The firm requirement is ≥ 64 GB** — the same class `research/docs/04-guests.md` documents for
  the tier-18 EVM and tier-20 sBPF proofs. The exit is `#[ignore]`d with that requirement and its
  command; it is not attempted on this 48 GB machine.
- **48 GB does not fit**: the committed oracle alone (48.6 GB) exceeds the box before any
  quotient, permutation or FRI-tree working set — and the two pre-cut rehearsal attempts died by
  jetsam below 30 GB under concurrent cargo load. 48 GB + swap is not plausible: the working set
  is the oracle itself, and the NTT/Merkle phases page randomly over the whole of it.
- The proof size at this shape is estimated at ~0.5–0.6 MB (the plan's derivation: ~640 opened
  columns per query × 80 queries × ~8 B + commitments/paths), inside the fullnode's 2 MiB cap
  with ~3.5× headroom; the twin's measured size above is the test-profile anchor for it. Task 10's
  production run measures the real number.

## The cheating suite

26 tests in `tests/cheating.rs`, one per soundness item, each a `rejects()` — spec §7's list
against the final machine: a wrong arithmetic result, a broken pc chain, a bad `INV` hint, an
address ≥ 2^24 with forged limbs, a register write to `r0` surfacing, a fetch count short by one,
a skipped permutation and an extra one, a memory `VALUE` tamper (the "wrong Merkle sibling"/"wrong
fold value" shape), a forged public value (batch and table), a proof of one program verified
against another (R1), a wrong tier, an out-of-range tier, the padding-row selector tamper
(invariant 2), a memory delta-limb forgery, a published value out of order, and the Task 8/9
tranches (the reduce chip's chain, a dropped column, a forged descriptor field, a dispatch with no
chip run, a declared-no-table degree mismatch; the absorb row's wrong source cell, a skipped
absorb, a sponge row claiming the plain kind). The permutation-equality contract — the chip's
permutation equals the reference on 1 000 random states — is a proof in `tests/cpu.rs`, its
sponge twin in `tests/precompiles.rs`.

## What M5.3 adds

`docs/02-aggregate.md`: the N-generic aggregate program — one counted loop over `N` inner
proofs of one shape, the interface digest over `[inner_vk_digest ‖ N ‖ B(8) ‖ 35·N]` (B: AGG-2's binding), one registered
program digest per shape — with the measured per-N economics (test profile N=1..3 in
`tests/pins.json`), the chain-facing `aggregate` / `verify_aggregate` API, the two chain-side
corrections (sealed history carries every covered bundle's declared shape; admission
shape-checks every covered bundle), and the fullnode admission stub's specification and test
vectors.
