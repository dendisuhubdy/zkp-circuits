# 04 — Phase 2 row cuts: the inner verifier at tier 20, and the prover's live heap

Design: `docs/superpowers/specs/2026-10-03-rvm-phase2-row-cuts-design.md`. Plan:
`docs/superpowers/plans/2026-10-03-rvm-phase2-row-cuts.md`. Branch `feat/rvm-phase2`, base
`cba8468` (constraint set 8). Every row count here comes from the emulator's event log through
`tests/profile.rs` (`cargo test --release -p recursion --test profile -- --ignored --nocapture`).
That test was run after each cut and again on the final tree for this record. Every pin is in
`tests/pins.json` or a test literal. The declared heights come from `machine::build_traces` over
the same executions. Every figure in the live-heap section is the 2026-10-03 run of
`tests/memprofile.rs` (raw log: `docs/measurements/2026-10-03-tier19-memprofile.log`) or is
labelled as derived.

**Result:** one verified production inner proof dropped from **2 047 268 to 893 606 cpu rows**
(−56.4 %). It now lands at **tier 20**, with 154 969 rows of headroom under `2^20 − 1`. The test
profile dropped from 461 988 to 230 950 rows, tier 19 → 18. Poseidon2 permutations are unchanged
at 54 515: the cuts removed bookkeeping around the chips, never hashing.

## The measurement that gated it (before, constraint set 8)

These are the spec's §1 tables, measured on the base tree. One verified RV32 bundle proof, the
shipped program (`Liveness::On`, `Precompiles::On`):

| | Test (16 queries) | Production (80 queries) |
|---|---:|---:|
| cpu rows | 461 988 | **2 047 268** |
| Poseidon2 permutations (POSEIDON2 + SPONGE rows) | 11 875 | 54 515 |
| RAM accesses | 632 057 | 2 851 913 |
| witness words | 45 899 | 210 763 |
| program instructions | 464 105 | 2 057 401 |
| tier | 19 | 21 |

| phase | Test | Production | share (prod.) |
|---|---:|---:|---:|
| 0–4 header, transcript, commitments, terminal sum | 1 273 | 1 273 | 0.1 % |
| 5 constraint evaluation at ζ | 26 404 | 26 404 | 1.3 % |
| 6 preamble: claimed evals, betas, final poly, PoW, indices | 50 979 | 100 595 | 4.9 % |
| query segments: tape reads | 84 219 | 421 115 | 20.5 % |
| queries: Merkle walks, reduction, folds | 300 740 | 1 507 524 | 73.3 % |
| 8 interface digest | 489 | 489 | 0.0 % |

LOAD and STORE were 54 % of all rows and HINT another 10 %. Field arithmetic was under 20 %. The
spec's decomposition of the query phase:

| item | rows (production) |
|---|---:|
| Merkle levels: about 16 500 levels × 32 rows of child select | ≈ 530 000 |
| copying opened rows into per-height sponge buffers | ≈ 336 000 |
| REDUCE descriptors | ≈ 240 000 |
| fold-chain sibling selection | ≈ 64 000 |
| the rest | ≈ 340 000 |

Three of those items are bookkeeping around work a chip already does, and those are what this
phase cut. Cut A measured the copy at ~1 570 cells per query, not ~2 100. The table above is the
spec's estimate as written.

## The three cuts, each measured

| stage | commit | cpu rows (prod.) | gate band (landing rows) | Δ measured | Δ projected | RAM accesses | permutations | instructions (prod.) | test rows | tier |
|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|
| before (cs8) | `cba8468` | 2 047 268 | — | — | — | 2 851 913 | 54 515 | 2 057 401 | 461 988 | 21 |
| A: hint into the height-group buffer | `43a52f3` | 1 787 805 | 1 455 000–1 968 000 | −259 463 | −336 000 | 2 600 290 | 54 515 | 1 797 938 | 409 821 | 21 |
| B: `HINTN` (opcode 26) | `e850d8a` | 1 427 355 | 1 330 000–1 465 000 | −360 450 | −390 000 | 2 600 290 | 54 515 | 1 437 488 | 337 371 | 21 |
| C: `COMPRESS` (opcode 27) | `63d1691` | **893 606** | 817 000–977 000 | −533 749 | −530 000 | 2 213 181 | 54 515 | 903 739 | 230 950 | **20** |
| total | | | | **−1 153 662** | −1 256 000 | −638 732 | 0 | −1 153 662 | −231 038 | −1 |

The plan's gate (spec §6 ruling 1) is ±15 % on the **landing row count** — the cpu rows after the
cut against the projected landing, restated from each previous stage's measurement — not on the
size of the cut, so a cut can deliver less than 85 % of its projected Δ and still land inside its
band. Each landed inside its band (table above); against the projected Δ:

- **Cut A** delivered 77 % of its projection. The removed rows are exactly the copy's LOAD/STORE
  pairs plus some FADDI: LOAD −109 784, STORE −141 839, FADDI −7 840. 251 623 copy rows over 80
  queries and 2 rows a cell is ~1 572 cells a query, against the spec's ~2 100. RAM accesses fell
  by 251 623, not the projected 672 000.
- **Cut B** delivered 92 % of its projection. 24 030 `HINTN` rows replace 192 240 `HINT; STORE`
  pairs (384 480 rows). The shortfall is the `n mod 8` tails, which are still compiled: 14 175
  `HINT` rows remain. RAM accesses and witness words are unchanged, since every word is still
  one write.
- **Cut C** delivered 101 % of its projection. There are 16 240 `COMPRESS` rows, and POSEIDON2
  rows fell by the same 16 240 (18 718 → 2 478). The child select's arithmetic went:
  - FSUB −113 920
  - FMUL −56 960
  - FADD −56 960

  Those are 14 240 levels × (8, 4, 4). By inference, the other 2 000 `COMPRESS` rows replace
  bit-zero compressions (injections and the standalone `compress`), which had no select. FADDI rose by
  exactly 16 240 (one per `COMPRESS`; see "still ahead"). RAM accesses fell by 387 109, against
  the projected 260 000.

Reports: `.superpowers/sdd/2026-10-03-rvm-phase2-row-cuts/task-{1,2,3}-report.md` hold each
stage's full `== profile` output. The final stage's numbers below were re-run for this record on
the final tree (`797541a` plus this re-pin).

### The final profile (after A+B+C)

```
== profile Test: inner tier Tier(14), 230950 cpu rows, 11875 permutations, 504365 mem accesses, 45899 witness words, 233067 program instrs
== profile Production: inner tier Tier(14), 893606 cpu rows, 54515 permutations, 2213181 mem accesses, 210763 witness words, 903739 program instrs
-- builder stats (production): spills 14906 reloads 218283 perms 54515 cells 352224 live_max 25
-- reduce dispatches 9520 (production), 1904 (test)
-- ram accesses (production): 1417580 reads, 795601 writes; max_addr 4540130
```

| phase | Test | Production | Δ vs before (prod.) | share (prod.) |
|---|---:|---:|---:|---:|
| 0–4 header, transcript, commitments, terminal sum | 1 093 | 1 093 | −180 | 0.1 % |
| 5 constraint evaluation at ζ | 26 404 | 26 404 | 0 | 2.9 % |
| 6 preamble: claimed evals, betas, final poly, PoW, indices | 50 709 | 100 325 | −270 | 11.1 % |
| query segments: tape reads | 10 043 | 50 235 | −370 880 | 5.6 % |
| queries: Merkle walks, reduction, folds | 144 328 | 725 192 | −782 332 | 80.2 % |
| 8 interface digest | 489 | 489 | 0 | 0.1 % |
| total (instructions in emission order, as `profile.rs` counts them; the executed rows are 230 950 / 893 606, since assertion traps are emitted but not executed) | 233 066 | 903 738 | −1 153 662 | |

Executed opcodes (production, before → after):

| opcode | before | after | Δ | share after |
|---|---:|---:|---:|---:|
| `LOAD` | 539 964 | 245 950 | −294 014 | 27.5 % |
| `FADDI` | 136 027 | 144 427 | +8 400 | 16.2 % |
| `STORE` | 564 607 | 92 609 | −471 998 | 10.4 % |
| `FMUL` | 130 098 | 73 138 | −56 960 | 8.2 % |
| `LOADE` | 55 715 | 55 715 | 0 | 6.2 % |
| `STOREE` | 50 756 | 50 756 | 0 | 5.7 % |
| `SPONGE` | 35 797 | 35 797 | 0 | 4.0 % |
| `HINTN` | — | 24 030 | +24 030 | 2.7 % |
| `FADD` | 79 823 | 22 863 | −56 960 | 2.6 % |
| `FSUB` | 133 884 | 19 964 | −113 920 | 2.2 % |
| `MOV` | 16 784 | 16 784 | 0 | 1.9 % |
| `COMPRESS` | — | 16 240 | +16 240 | 1.8 % |
| `HINT` | 206 415 | 14 175 | −192 240 | 1.6 % |
| `EMUL` | 13 664 | 13 664 | 0 | 1.5 % |
| `EADD` | 12 295 | 12 295 | 0 | 1.4 % |
| `JEQ` | 10 133 | 10 133 | 0 | 1.1 % |
| `REDUCE` | 9 520 | 9 520 | 0 | 1.1 % |
| `EMULF` | 9 206 | 9 206 | 0 | 1.0 % |
| `FMULI` | 8 863 | 8 863 | 0 | 1.0 % |
| `ESUB` | 7 913 | 7 913 | 0 | 0.9 % |
| `EINV` | 4 187 | 4 187 | 0 | 0.5 % |
| `POSEIDON2` | 18 718 | 2 478 | −16 240 | 0.3 % |
| `HINTE` | 2 174 | 2 174 | 0 | 0.2 % |
| `INV` | 720 | 720 | 0 | 0.1 % |
| `PUBLIC` | 4 | 4 | 0 | 0.0 % |
| `HALT` | 1 | 1 | 0 | 0.0 % |

Test profile, after: LOAD 65 774, FADDI 31 211, STORE 23 489, LOADE 18 723, STOREE 14 788, FMUL
14 706, EMUL 7 840, SPONGE 7 189, MOV 6 928, EADD 5 191, HINTN 4 830, FADD 4 623, FSUB 4 076,
COMPRESS 3 248, ESUB 3 049, HINT 2 911, HINTE 2 174, JEQ 2 117, EMULF 1 910, REDUCE 1 904, FMULI
1 823, POSEIDON2 1 438, EINV 859, INV 144, PUBLIC 4, HALT 1.

LOAD is the largest term now. The builder reports 218 283 reloads, so most of it is the register
allocator's spill traffic in the reduction and fold chains, not memory-structured hashing. That
is the next phase's question.

### Still ahead (recorded, not in this phase)

1. **The REDUCE descriptor**, ≈ 240 000 rows: the 11-cell build plus two read-backs per
   dispatch, 9 520 dispatches. A per-point descriptor *table* the chip walks would make it about
   160 dispatches a proof.
2. **The fold-chain sibling select**, ≈ 64 000 rows: arity ≤ 8, about 800 rows a query.
3. **The inner FRI profile**: rate ¼ with about 40 queries halves everything in the query phase,
   at the wallet's expense. This is `compute-optimization.md` §4.4's measured decision. (Correction, 2026-10-06: the count is wrong. 40 is the
   *conjectured* count at rate ¼; at the proven security the production profile keeps, rate ¼
   needs ~120 queries — 1.5× the query phase, not half. `docs/06-phase3-fold-reduce.md` §7.)
4. **The per-level `FADDI` that `compress_step` pays for the sibling pointer's delta** (flagged by
   the Task-3 implementer). `ptr_reg` folds a delta-carrying sibling `Ptr` into a register with
   one `FADDI` before each `COMPRESS`. FADDI rose by exactly the 16 240 `COMPRESS` rows at Cut C.
   An immediate-offset `COMPRESS` form (the offset in `b`, as `LOAD`/`STORE` carry theirs) would
   remove up to that many rows, about 16 k. `merkle_walk`'s doc gives the shipped cost as
   `2·levels + 15` rows.
5. A minor point from the same task: `hash::compress` falls back to the compiled form when `out`
   aliases `right`, and the alias check is exact equality only. No caller in the shipped program
   hits the fallback.

## What moved

| pin | before (constraint set 8) | after (phase 2) | where |
|---|---|---|---|
| single-proof program digest, production shape | `454592b35ccfd6feefe93b7d2353bc484fca8ff260f74deae4e0865f7da2f2b3` | `723218da65a50f1f1581013f79fa5c5b1816b7ab46796dbaa4672c52bce2d0d1` | `src/programs/verify_rv32.digest` |
| `aggregate_program_digest`, production bundle shape (what a chain's aggregation section pins) | `1831f036a2d3524249df17a66a220457878f8aeed669c77db08d58026461ddd7` | `c90b3f0a7758c7e306042f27a94cc1f123441b0284c7352cb3f426048c7a74d8` | `tests/aggregate.rs` (`the_production_n1_aggregate_is_the_m52_pin_plus_loop_overhead`, ignored, emulation only); `docs/02` |
| `aggregate_program_digest`, test fixture shape | `9eba73805fa23361708d9ca1c58d904ac830aeb6810470ec7788c4f36880193d` | `5f1f69010b8aa4cbb6072ffd8a631fa05897c18ed3663ae2bcd136455d2612df` | `tests/verifier.rs` |
| Off replay, production shape (`Liveness::Off`, `Precompiles::Off`) | `af7728191e4ec0c1b8f6cc3d60aff36b04dc0d1b48b494aa9fbf107ebc708425` | `39bb6b8d94e62dd282001384d0b65294e7f024e6ef9b47381c8c96c6e1fd3352` | `tests/verifier.rs` (Cut A's value; B and C are `On`-only) |
| self-verifier digest, toy fixture shape | `6b2f058e60ffdf6a77091b932710513191688e4bdc59b2ecdc65b0dd5039033b` | `18514c2aa0ad8d6a5aa7ea8baa65754f9137db5f1ad1d60943930add0becde67` | `tests/self_verify.rs` |
| self-verifier `CycleReport` (rows, perms, mem, instrs, words), toy | (276 560, 7 498, 405 853, 278 408, 29 575) | (152 527, 7 660, 345 333, 154 375, 30 255) | `tests/self_verify.rs` |
| the same, busy fixture | (368 770, 9 132, 481 628, 370 882, 35 407) | (188 390, 9 310, 388 321, 190 502, 36 087) | `tests/self_verify.rs` |
| self-verifier phase 5, toy / busy | 7 365 / 7 645 | 7 845 / 8 125 | `tests/self_verify.rs` |
| `pins.json` production rows / perms / mem / instrs / words | 2 047 268 / 54 515 / 2 851 913 / 2 057 401 / 210 763 | 893 606 / 54 515 / 2 213 181 / 903 739 / 210 763 | `tests/pins.json` |
| `pins.json` aggregate test N=1/2/3 cpu rows | 462 262 / 924 115 / 1 385 968 | 231 224 / 462 039 / 692 854 | `tests/pins.json` |
| `pins.json` aggregate test N=1/2/3 mem accesses | 632 206 / 1 263 738 / 1 895 270 | 504 514 / 1 008 354 / 1 512 194 | `tests/pins.json` |
| `LOOP_OVERHEAD` (test and production) | 274 | 274 (unchanged) | `tests/aggregate.rs` |
| `N3_ROWS` | 1 385 968 | 692 854 | `tests/aggregate.rs` |
| twin rows / tier (`tests/exit.rs`) | 461 988 / 19 | 230 950 / 18 | `tests/exit.rs` |
| exit rows / tier (`tests/exit.rs`) | 2 047 268 / 21 | 893 606 / 20 | `tests/exit.rs` |
| `inner_vk_digest`, the admission stub vectors, the interface list | — | unchanged | the inner machine did not move |

Notes on the table:

- The Off replay moved because Cut A changes the shared pipeline. The `Off` program hints into
  the same height-group buffers, and the tape's segment 11 follows that order.
- The self-verifier opens the rVM's own wider tables, and both the shared pipeline's cuts and the
  rVM's wider AIR reach its program and its phase 5.
- Permutations (11 877 / 23 724 / 35 571) and witness words are unchanged in the aggregate pins.
- The N=1 aggregate is 231 224 = 230 950 + 274 rows, and the production N=1 aggregate is
  893 880 = 893 606 + 274 (`the_production_n1_aggregate_is_the_m52_pin_plus_loop_overhead`). The
  cuts are inside the per-proof body; the loop around it did not move.

**The machine.** The ISA appends two opcodes; 0–25 never move.

- **`HINTN` = 26** writes eight tape words to `mem[ra .. ra+8]` in one row. The cpu row carries
  them in `W0..W7`, and the range groups cover `A0` and `A0 + 7`.
- **`COMPRESS` = 27** does one Merkle level in one cpu row and one Poseidon2-chip row. `rd` is
  the index bit (`D0`, read through `READ_RD`), `ra` the 4-cell running digest and `rb` the
  4-cell sibling (`B_REG`).

`Op::COUNT` and `NUM_SELECTORS` go from 26 to 28.

- **cpu width:** 72 → 81 (Cut B: one selector and eight word columns) → **82** (Cut C: one
  selector). Every column after `SEL0` moved; they are named constants.
- **poseidon2 width:** 341 → **343** (`IS_COMPRESS`, `BIT`). The chip now has **three row
  kinds**: `IS_PERM + IS_SPONGE + IS_COMPRESS = IS_REAL`. `SRC_PTR` is reused as the sibling
  pointer, and `SRC_PTR` and `BIT` are zero on every row kind that does not use them.
- **The compress row's permutation input** is the ordered pair `[digest ‖ sibling]` when `BIT =
  0` and `[sibling ‖ digest]` when `BIT = 1`, written as degree-2 expressions of `IN` and `BIT`.
  The row makes 4 reads at the state, 4 reads at the sibling, and 4 writes of `OUT[0..4]` to the
  state, at slots 0–11.
- **Degree pins** are unchanged: `[2, 8, 4, 4, 4, 2, 2]`, reduce 8. The fallback of eight `CH`
  columns was not needed.
- **Buses: nine** — `REG`, `RAM`, `POSEIDON2`, `SPONGE`, `PROGRAM`, `RANGE8`, `PUBLIC`, `REDUCE`,
  and the new **`COMPRESS [clk, state_ptr, sib_ptr, bit]`**. The cpu row sends `[CLK, A0, B0,
  D0]`; the chip's compress row receives it.
- **The emulator** refuses a non-boolean bit (`ExecError::NonBooleanBit { pc }`). `PermEvent`'s
  `src: Option<u64>` became `kind: PermKind { Perm, Sponge { src }, Compress { sib, bit } }`.

**The tape.** `WitnessTape::build`'s `Segment::InputOpenings` (step 11) now emits each query's
matrices per round **in height-group order**, not committed order. Groups are the distinct
heights, tallest first: the reference's `sorted_by_key(Reverse(height))`, stable within a height.
For the fixture's degree bits `[13,15,17,16,9,9,17,11,3]` the groups are
`[[2,6],[3],[1],[0],[7],[4,5],[8]]`. The tape is the aggregator's private witness. Its only
contract is that the program and the tape agree, and the exit tests over real proofs check it.

**What did not move:**
- the RV32 machine (constraint set 8) and its proofs;
- the inner verifier key and `inner_vk_digest`;
- the FRI profiles;
- the hashing (the compress row computes the same `TruncatedPermutation<Perm,2,4,8>`);
- the aggregate's interface `[vk ‖ N ‖ B(8) ‖ 35·N]` and `verify_aggregate`'s API;
- the chain's consensus rules.

**Testing.** Each cut carries its forgeries in `tests/cheating.rs` (Cut B's `HINTN` rows, Cut
C's `COMPRESS` rows, each refused by `Machine::verify`) and its range gating at the AIR in
`tests/cpu.rs`'s ZKQ-3 cases. The spec's §5 COMPRESS case "an output lane written to the sibling
instead of the state" has no test: it is not expressible by a trace edit, since the chip's write
address is the expression `PTR + k`, never a free column. The suite at `7a0ae83`
(`cargo test --release --no-fail-fast -- --skip a_one_proof_aggregate_round_trips`): 208 passed,
0 failed, 20 ignored, 1 skipped (the tier-18 round trip).

The fullnode re-vendors this tree and re-pins `admitted_shapes[].aggregate_program_digest`
(`c90b3f0a…74d8` at the production bundle shape) at the next chain cut. No running chain has
aggregation enabled.

## The N-economics at the new tiers

Production cpu rows and declared log-heights were emulated on this tree (`build_traces` over the
real executions, no proving). N=1 is the pin plus the measured 274-row overhead. N=2 and N=3 are
`production_n{2,3}_aggregate_emulates_within_bounds`. N=4 is a one-off emulation over four
cached production proofs, run for this record. Derivation check: the per-proof body is
(2 680 822 − 893 880) / 2 = 893 471, so N=4 ≈ 2 680 822 + 893 471 = 3 574 293, which is exactly
what the emulation measured.

| N | tier | cpu rows | headroom under the tier | declared log-heights cpu / reg / ram / poseidon2 / reduce / program | before (cs8): tier, rows |
|---:|---:|---:|---:|---|---|
| 1 | **20** | 893 880 | 154 695 | 20 / 22 / 22 / 16 / 18 / 20 | 21, 2 047 542 |
| 2 | **21** | 1 787 351 | 309 800 | 21 / 23 / 23 / 17 / 19 / 20 | 22, 4 094 675 |
| 3 | 22 | 2 680 822 | 1 513 481 | — (not built) | 23, 6 141 808 |
| 4 | **22** | 3 574 293 | 620 010 | 22 / 24 / 24 / 18 / 20 / 20 | 23, 8 188 941 |

N=5 is ≈ 4 467 764 rows, tier 23, the top rung.

Production N=2 and N=3 also stay inside the address and timestamp bounds:

- max address 4 540 120;
- max timestamp 28 597 631 for N=2 and 42 893 167 for N=3, both under `2^27`;
- 109 004 and 163 491 permutations, and 4 425 986 and 6 638 642 RAM accesses.

Test profile (`tests/pins.json`):

| N | tier | cpu rows | declared log-heights | before (cs8) |
|---:|---:|---:|---|---|
| 1 | 18 | 231 224 | 18 / 20 / 19 / 14 / 16 / 18 | 19, 462 262 |
| 2 | 19 | 462 039 | 19 / 21 / 20 / 15 / 17 / 18 | 20, 924 115 |
| 3 | 20 | 692 854 | 20 / 21 / 21 / 16 / 17 / 18 | 21, 1 385 968 |

At equal N, every rung is one tier lower. **The cpu, register and program tables are one height
shorter at every N. The others are not:**

- The **poseidon2** table keeps its height, because the permutation count did not change.
- The **reduce** table keeps its height, because its rows did not change: 34 624 test and
  173 120 production. Its test-shape height is `2^16`, not the `2^15` the spec's §3.1 originally listed (corrected 2026-10-04) for the
  tier-19 run. The base tree's own `build_traces` gives 16.
- The **production RAM table stays at `2^22`**: 2 213 181 accesses against `2^21` = 2 097 152,
  so 116 029 over the line. The spec projected ~1.92 M.

The machine class for each rung is in the next section: no committed-oracle column. That model is
withdrawn (`docs/01`).

## The prover's live heap

`docs/02-aggregate.md` records peak RSS (`/usr/bin/time -v`) on the 503 GB Linux box
(2026-09-30): 94.2–94.5 GB for a tier-19 rVM proof and 376.9 GB for a tier-21 production one.
That is 4–8× the committed-oracle model of `docs/01`. The working hypothesis was allocator
retention. **The measurement refutes it.**

### Tier-19 exit twin, live heap by phase (2026-10-03, this 48 GB box, `tests/memprofile.rs`)

The harness has two instruments:
- a counting global allocator, tracking live bytes and the high-water mark of every allocation;
- a `tracing` subscriber that prints both at every Plonky3 span boundary.

The run was single-threaded. The shape is `tests/exit.rs`'s twin at constraint set 8: one real
test-profile bundle proof, 461 988 rows, tier 19. Raw log:
`docs/measurements/2026-10-03-tier19-memprofile.log`.

| phase (Plonky3 span) | wall | Δ live | live after | note |
|---|---:|---:|---:|---|
| key build: preprocessed LDE + Merkle tree | 22 s | +2.0 GB | 2.05 GB | `with_zero_cols`, `coset_lde_batch`, `build merkle tree` |
| main trace commit: `randomize polys` + 8 × `coset_lde_batch_with_transform` | 24 s | +13.2 GB | 15.3 GB | the hiding doubling and the four salt columns included |
| main `build merkle tree` | 273 s | +4.3 GB | 19.6 GB | single-threaded Poseidon2 over the tallest LDE |
| `generate lookup permutation` × 8 | 1 s | +0.3 GB | 19.9 GB | |
| permutation trace commit (LDE) | 16 s | +7.0 GB | 27.0 GB | |
| permutation `build merkle tree` | 187 s | +4.3 GB | 31.3 GB | |
| `compute quotient` × 8 (program, cpu, reg, ram, poseidon2, public, range, reduce) | 245 s | +1.8, +6.5, **+13.7**, +6.8, +0.1, 0, 0, +0.8 GB | **61.0 GB** | the quotient-chunk LDEs are kept for the commit; the reg table (the tallest, degree 4 → 8 chunks under zk) is the largest single item |
| quotient `commit_ldes` (Merkle tree) | killed 20 s in | +17.7 GB and rising | **78.7 GB** | **SIGKILL by the kernel at 782 s** |

**macOS RSS is not a memory number.** macOS's `maximum resident set size` for this run was
19.8 GB, and its `rss` samples read 7–17 GB throughout. On macOS, RSS excludes compressed and
swapped pages. So the September "15 GB / 30 GB observed" laptop figures in `docs/01` and
`docs/02` measured the compressor's output, not the working set. The September tier-19 proof that
"completed on 48 GB" did so through ~50 GB of compressed swap. The Linux `/usr/bin/time -v`
figures are the honest ones, and these docs never use a macOS RSS figure as a memory number again.

**The live model, from this run.** Tier 19, declared heights cpu 2^19, reg 2^21, ram 2^20,
poseidon2 2^14, reduce 2^16 (the spec's §3.1 originally listed 2^15, corrected 2026-10-04; `build_traces` on the base tree gives
16), program 2^19. `log_blowup 3`, hiding.

| term | GB | share of the 94 GB Linux peak |
|---|---:|---:|
| main LDE + salts + tree (the `docs/01` "committed oracle" term) | 17.6 | 19 % |
| permutation (LogUp) LDE + tree | 11.3 | 12 % |
| quotient LDEs (8 instances, 2–16 chunks each at blowup 2^(3+1)) | 29.7 | 32 % |
| quotient tree, random-polynomial commitment, FRI opening and commit phase | ≈ 33 (by difference) | 35 % |

The `docs/01` oracle model counted only the first row. The other three rows together are about
4× it, which is the 4–8× the box measured. Nothing is kept that the opening does not need: every
committed LDE is read again at the FRI query phase. The batch prover's peak is inherent to
committing everything before opening anything.

**Why the quotient is a third of the memory.** This was probed on 2026-10-03 at tier 14, with a
local `p3-fri` copy printing each chunk's buffer sizes (raw log:
`docs/measurements/2026-10-03-tier14-quotient-probe.log`). `HidingFriPcs::get_quotient_ldes`
commits every quotient chunk as its own matrix, and the hiding MMCS appends its **four salt
columns to each**. So a chunk that is 2 columns of quotient (one extension element) is committed
as 6 (`evals 16384x6`). The cpu's 16 chunks and the memory tables' 8 all pay 200 % salt overhead.
With that overhead counted, the tier-19 figures close exactly:
- cpu: 16 × 2^23 × 6 × 8 B = 6.4 GB, measured 6.46;
- reg: 8 × 2^25 × 6 × 8 B = 12.9 GB, measured 13.7.

Committing one instance's chunks as **one matrix** would cut the quotient term from 29.7 GB to
≈ 11 GB at tier 19, −20 % of the proof's peak: 16 chunks would become one 32-column matrix at the
same height, with four salts once. (Correction, 2026-10-05: a round opens with one Merkle path per query already — the MMCS batches every matrix of a round into one tree — so the recursive verifier's saving is the salts and hidden values it no longer absorbs, not Merkle paths.) The cost is a fork of `p3-batch-stark`'s prover *and*
verifier (the chunk openings move inside one row), plus the rVM program's phase-6 reader. The
LDE of each chunk also allocates two transient copies of its own size (`random_eval`,
`vanishing_poly_coeffs`). Those are transient, not part of the retained term. **Done:** `docs/05-quotient-layout.md` (the fork, measured 2026-10-05).

### What follows for the hardware plan

- **The ≥ 64 GB "committed oracle" requirement in `docs/01` is withdrawn.** It counted one of
  four terms. Until the cuts below are proved, the measured peaks are the requirement: 376.9 GB
  for a tier-21 production proof, 94.2 GB at tier 19.
- **The three cuts shrink it directly** (derived, below). Even so, the result is not
  `compute-optimization.md` §4.4's ≤ 64 GB. The rest is structural and is the next phase's
  measured decision. Candidates, in order of leverage:
  1. **the quotient's share (32 %)**: one matrix per instance's chunks, as above — done, `docs/05`. A degree-2
     memory AIR (fewer chunks for the two tallest tables) is a second lever on the same term.
  2. **the register table's height** (4× the cpu table): about 2.5 `REG` messages per cpu row
     after the cuts (582 743 accesses over 230 950 rows at the test shape, up from ~2.3, since
     the cuts removed mostly LOAD/STORE rows). A wider cpu row that reads fewer registers is the
     lever.
  3. **`log_blowup 3 → 2`** (rate ¼): halves every LDE at the price of ~1.5× the queries. This is
     the inner profile decision §4.4 of the fullnode page already names, applied to the rVM's own
     profile.
  4. **the GPU backend**: as built, it changes none of this, because traces live on the host. A
     device-resident LDE and tree would, and that is the real reason to want the 80 GB device
     class.
- **Threads.** The recursion crate proved single-threaded. The two Merkle trees alone are 460 s
  of the run's 782 s. Task 6 brings the fullnode's two-crate Plonky3 patch in behind a `parallel`
  feature and measures it: 4.7× on 16 threads at tier 16, no heap cost (§"Threads", below).

### What the cuts change (derived from the measured terms)

At equal N, every rung is one tier lower, and the cpu, register and program tables are one height
shorter. If every term halved, as the spec's §3.2 assumed:
- the tier-19 twin (now tier 18) would land near **≈ 47 GB**;
- the production N=1 aggregate (now tier 20) near **≈ 190 GB**.

The declared heights above refine that. The poseidon2 and reduce tables keep their heights at
every shape. At production, the RAM table also stays at 2^22. Weighting the main-trace and
quotient terms by their committed cells (height × (width + 4 salts), and height × chunks × 6) and
scaling the measured peaks by the result:

| proof | tier | main + quotient cells vs the measured shape | projected peak | measured anchor |
|---|---:|---:|---:|---|
| exit twin, test, N=1 | 18 | 0.53 × the tier-19 twin | **≈ 50 GB** | 94.2 GB (tier 19, Linux) |
| production N=1 (and the exit) | 20 | 0.64 × the tier-21 exit | **≈ 240 GB** | 376.9 GB (tier 21, Linux) |
| production N=2 | 21 | 1.26 × the tier-21 exit | ≈ 475 GB | 376.9 GB |
| production N=4 | 22 | 2.5 × the tier-21 exit | ≈ 950 GB | 376.9 GB |

The projection assumes the permutation and FRI terms scale like the main and quotient ones. The
tier-19 calibration supports that: the cell model gives 12.7 GB of main LDE and 27.5 GB of
quotient, against 13.2 and 29.7 measured. The weighted projection still calls for a **256 GB host**
for the production N=1 aggregate, now tight rather than comfortable.

The 50 GB the halving misses at production is the RAM table: 116 029 accesses over `2^21`. One
height off it brings the production N=1 to ≈ 200 GB. Every one of these is a projection until the
tier-20 production proof runs on the big machine. The `tests/exit.rs` and `tests/aggregate.rs`
ignore notes carry the projected numbers, and the test-profile tiers they assert (18 / 19 / 20)
come from `Tier::for_cycles` over the pinned rows.

### Threads (Task 6, measured 2026-10-04, this 48 GB box)

`--features parallel` turns on Plonky3's own rayon feature (`p3-maybe-rayon/parallel`) for the
prover. The proofs are the same proofs: same config, transcript and FRI parameters, verified by
the stock verifier. The two crates whose hiding RNG lock deadlocked under rayon (`p3-fri`'s
`hiding_pcs.rs`, `p3-merkle-tree`'s `hiding_mmcs.rs`; upstream Plonky3 #2363 / PR #2368) are the
fullnode's patched copies, vendored at `vendor/` (`vendor/PROVENANCE.md`) and patched in for every
build, feature on or off. The benchmark is `tests/memprofile.rs::tier16_synthetic_threads`: 1 250
rounds of 16 hinted words stored and sponged (5 000 `SPONGE` absorbs), **63 762 rows, tier 16**,
proved once and verified, on this box's 16 cores (12 performance + 4 efficiency).

| build | prove (wall) | peak live heap |
|---|---:|---:|
| feature off (the stock single-threaded prover) | 170.6 s | 9.09 GB |
| `--features parallel`, `RAYON_NUM_THREADS=1` | 171.1 s | 9.09 GB |
| `--features parallel`, `RAYON_NUM_THREADS=16` | **36.4 s** | 9.09 GB |

**4.7× on 16 threads** (171.1 → 36.4 s), against the RV32 prover's 7.7× in the fullnode. Not
measured here, but the likely limits are this box's four efficiency cores and the prover's serial
parts (trace generation, the transcript). The patched build on one thread costs nothing (+0.3 %,
within run-to-run noise). **The memory delta is nil**: the peak live heap is 9.09 GB all three
ways (the same to within 10 MB). Rayon's per-thread scratch does not register against the
committed LDEs and trees, which are the same allocations whatever the pool. So the heap model
above holds under threads, and the thread count is a pure wall-time lever.
