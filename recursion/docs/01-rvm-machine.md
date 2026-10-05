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
| `cpu` | `2^tier` | 84 | 8 | fetch (from `program`), 30 one-hot decode selectors, base + extension ALU, the `INV`/`EINV` hint-and-check, control, the `REG`/`RAM`/`POSEIDON2`/`SPONGE`/`REDUCE`/`PUBLIC`/`COMPRESS`/`FOLD`/`POW` sends (`FOLD` and `POW` read their whole `rd` pair: the fold point `u`, the `(G, base)` pair), `HINTN`'s eight tape-word columns `W0..W7` and their eight `RAM` writes, the 5-bit register-index and 3-byte address-limb range checks — both ends of every multi-cell access since ZKQ-3 (2026-09-27; 66 before ZKQ-3, 72 before phase 2's `HINTN` (+9) and `COMPRESS` (+1) selectors and words, 2026-10-03; 82 before phase 3's `FOLD` and `POW` selectors, +1 each, 2026-10-05) |
| `reg_memory` | declared, `[4, 26]` | 11 | 4 | the register file as cells `2^24 + k`, `k < 32` (R4) — sorted `(addr, ts)`, read-after-write by transition |
| `ram_memory` | declared, `[4, 26]` | 11 | 4 | RAM below `2^24`, same AIR on the `RAM` bus |
| `poseidon2` | declared, `[4, 20]` | 343 | 4 | permutation-per-row, three row kinds (`IS_PERM`, `IS_SPONGE`, and since phase 2 `IS_COMPRESS` — one Merkle level: `BIT` orders `[digest ‖ sibling]`, `SRC_PTR` is the sibling, 4 + 4 reads and 4 writes), round constants baked into `eval` (R9); 341 wide before `IS_COMPRESS`/`BIT` |
| `public` | fixed at 8 | 7 | 2 | one row per published word; owns the batch's 4 public values (R5, the interface digest) |
| `range` | fixed at 256 | 1 witness + 1 preprocessed | 2 | the `RANGE8` provider |
| `reduce` (optional) | declared, `[4, 20]` | 81 witness + 20 preprocessed | 8 | three row kinds, in this order then padding. **Run** rows (`IS_REAL`): the batch-opening reduction, one chip row per column; each run looks up its layout entry on its first row (`REDUCE_LAYOUT`, a preprocessed provider region with a witness `MULT`, committed by the verifier key — phase 3's Cut D), and a chain carries its accumulator across consecutive entries and clocks. **Fold** rows (`IS_FOLD`, Cut E2): one `FOLD` is a `2a`-row run — an inverse DFT whose coefficients are looked up from a 14-row preprocessed table (`FOLD_COEFF`), then Horner at `u`. **Pow** rows (`IS_POW`, Cut F): one `POW` is an `L`-row run, one index bit a row, squaring `G` and stepping the product. (Task 8 built it 21 wide; the 2026-09-27 zk scan's clock chain, row kinds, run-end rule and 18 address-limb columns made it 39; Cut D's preprocessed layout 30 + 9 preprocessed, Cut E2 70 + 20, Cut F 81 + 20. Its degree is 8 — this config's ceiling — and has been since Task 8: the table listed 3 until 2026-10-05, a misprint against `tests/tables.rs`'s pin) |

**Buses (13; 8 under plan R7, `COMPRESS` added by phase 2, `REDUCE_LAYOUT`, `FOLD`, `FOLD_COEFF`
and `POW` by phase 3):** `REG`, `RAM` (both `[addr, ts, value, is_write]`, multiset),
`POSEIDON2 [clk, ptr]`, `SPONGE [clk, state_ptr, src_ptr]`, `PROGRAM [pc, w0..3]`, `RANGE8`,
`PUBLIC [idx, value]`, `REDUCE [clk, entry]` (was `[clk, descr_ptr]` before Cut D),
`REDUCE_LAYOUT [entry, vals, row, row_end, key, alpha, res, chain_start + 2·carry]` (the reduce
chip's own provider region, looked up by each run's first row), `COMPRESS [clk, state_ptr,
sib_ptr, bit]`, `FOLD [clk, msg, u0, u1, a]`, `FOLD_COEFF [a, k, c0..c7]` (the chip's own
coefficient table) and `POW [clk, buf, off + 256·L, G, base]`. Every send count is a selector expression forced
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
the production exit and N=1 aggregate tier 20, production N=2 tier 21, N=3 and N=4 tier 22. Since
phase 3 (2026-10-05, `docs/06`) the production N=3 aggregate is tier 21 too (1 757 062 rows) and
N=4 is tier 22; the test-profile N=3 aggregate is tier 19 (508 102 rows). The host classes quoted
in this paragraph are the withdrawn oracle model's; docs/04 has the measured live heap and docs/06
§3 its phase-3 figures.

**Appended opcodes.** The M5.1 ISA's 24 instructions (`docs/00`) are frozen; every opcode since is
appended at the next number, so no earlier program's digest moves (`tests/isa.rs`):

| opcode | mnemonic | added | what it does |
|---:|---|---|---|
| 24 | `REDUCE` | M5.2 Task 8 | one run of the batch-opening reduction: layout entry `imm` (since phase 3's Cut D) |
| 25 | `SPONGE` | M5.2 Task 9 | one absorb block of the leaf sponge, in the poseidon2 chip |
| 26 | `HINTN` | phase 2, Cut B | eight tape words to `mem[ra + imm ..]` in one row |
| 27 | `COMPRESS` | phase 2, Cut C | one Merkle level, in the poseidon2 chip |
| 28 | `FOLD` | phase 3, Cut E2 | one FRI fold round of arity `imm ∈ {2, 4, 8}` at `u` (the `rd` pair), in the reduce chip |
| 29 | `POW` | phase 3, Cut F | the index power `base·g^{rev(bits)}` from `L` bits of a 65-cell buffer, in the reduce chip |

`Op::COUNT` = `NUM_SELECTORS` = 30.

## The measured numbers

**Current (phase 3, 2026-10-05; `docs/06-phase3-fold-reduce.md` has the per-cut record).** Per
verified inner proof at constraint set 8 after phase 2's three row cuts and phase 3's four,
pinned in `tests/pins.json` (production digest
`cf5a350a62fa00bb6e84fa0de311a726aac7c610d23ce272b8c80795bac51788`), declared heights from
`machine::build_traces` over the same executions:

| | `FriProfile::Test` (16 q) | `FriProfile::Production` (80 q) |
|---|---:|---:|
| cpu rows | 169 366 | **585 686** |
| Poseidon2 permutations | 11 875 | 54 515 |
| memory accesses (RAM) | 442 445 | 1 903 581 |
| register accesses | 411 319 | 1 290 039 |
| reduce-chip rows (run + fold + pow) | 39 296 (34 624 + 1 216 + 3 456) | 196 480 (173 120 + 6 080 + 17 280) |
| program instructions | 171 771 | 597 259 |
| witness words | 46 187 | 212 203 |
| **declared heights** | 18, 19, 19, 14, 16, 18 | 20, 21, 21, 16, 18, 20 |
| tier | 18 | **20** |

(Declared heights in `chips()` order: cpu / reg / ram / poseidon2 / reduce / program; public is
fixed at 2^3 and range at 2^8.)

Phase 2's end (`docs/04`) was 230 950 / 893 606 rows at tiers 18 / 20, declared heights
18, 20, 19, 14, 16, 18 and 20, 22, 22, 16, 18, 20. Phase 3 lowered no tier — the production
inner proof is 61 399 rows above the `2^19 − 1` gate — but **both production memory tables
dropped from `2^22` to `2^21`** (and the test profile's register table from `2^20` to `2^19`): REG
2 147 159 → 1 290 039 and RAM 2 213 181 → 1 903 581. The poseidon2 table keeps its height
(same permutations); the reduce table keeps its height too, though it now also holds the fold
and pow runs.

Constraint set 8 before phase 2's cuts was 461 988 / 2 047 268 rows at tiers 19 / 21, declared
heights 19, 21, 20, 14, 16, 19 and 21, 23, 22, 16, 18, 21 (re-measured on the base tree for
docs/04).

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

This is the constraint-set-6 measurement, kept as the record; its register-access, reduce-row and
declared-height columns were not re-taken for constraint set 7, and are re-taken for phase 2 in the
current table above. Constraint set 7 with VERIFIER-1 (chain 16, measured on
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

(Since phase 2's row cuts the twin is at **tier 18** — 230 950 rows then, 169 366 since phase 3,
proved on this 48 GB box at 26.88 GB peak live, `docs/06` §3 — `tests/exit.rs`; the
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
the quotient-chunk LDEs, each chunk salted with four columns of its own (one matrix per instance, salted once, since the quotient-layout fork — `docs/05-quotient-layout.md`); the quotient tree and
the FRI phases — and the other three are ~4× it. The measured record and the live model are
`docs/04-phase2-row-cuts.md` §"The prover's live heap" (a tier-19 proof: 78.7 GB live when killed
on a 48 GB box, 94.2 GB peak on Linux). Since phase 2's row cuts the exit is 893 606 rows at
**tier 20**; docs/04 derives ≈ 190–240 GB for it from the measured terms — a ≥ 256 GB host,
until it is proved. Since phase 3 (`docs/06-phase3-fold-reduce.md` §3) it is 585 686 rows, still
tier 20, with both memory tables at `2^21`; the same cell-weighted model projects **≈ 110–130 GB**
(108 GB anchored on the tier-18 twin measured at 26.88 GB live on this box, 123–127 GB anchored on
docs/05's projection) — a ≥ 160 GB host, until it is proved.

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
