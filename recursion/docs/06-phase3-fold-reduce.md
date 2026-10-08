# 06 — Phase 3: the reduce chip takes the reduction layout, the fold and the index powers

Design: `docs/superpowers/specs/2026-10-05-rvm-phase3-fold-reduce-design.md`. Plan:
`docs/superpowers/plans/2026-10-05-rvm-phase3-fold-reduce.md`. Branch `feat/rvm-phase3`, base
`2c1f068`, rebased onto `origin/main` `40e4657` (the quotient-layout merge, which owns
`docs/05-quotient-layout.md`; this record is docs/06 for that reason). Every row count here comes
from the emulator's event log through `tests/profile.rs`
(`cargo test --release -p recursion --test profile -- --ignored --nocapture`), run after each cut
and again on the final tree for this record; every pin is in `tests/pins.json` or a test literal;
the declared heights come from `machine::build_traces` over the same executions. Every figure in
the memory section is a run of `tests/memprofile.rs` on this 48 GB box (16 cores,
`--features parallel`, `RAYON_NUM_THREADS=16`; raw log of the final run:
`docs/measurements/2026-10-06-tier18-twin-memprofile-phase3.log`) or is labelled as a projection
with its derivation.

**Result:** one verified production inner proof dropped from **893 606 to 585 686 cpu rows**
(−34.5 %), each of the four cuts landing in its band or (E1) below it by a ruled margin. It stays
at **tier 20**: the phase's gate — one inner verification in tier 19, `≤ 2^19 − 1 = 524 287`
rows — was **not reached**, and it was not widened (spec §6 ruling 6). The landing is 61 399 rows
above it; even Cut F's band floor (569 942) was. What the phase delivered in full is the memory
half: **both production memory tables dropped from `2^22` to `2^21`** (REG 2 147 159 →
1 290 039, RAM 2 213 181 → 1 903 581), and the tier-18 exit twin's peak live heap went
33.27 → 24.86 GB at Cut D (26.88 GB at the phase's end, the reduce chip now 81 columns wide). The
test profile dropped from 230 950 to 169 366 rows (tier 18), and the test N=3 aggregate from tier
20 to 19; the production N=3 aggregate from tier 22 to 21. Poseidon2 permutations are unchanged
at 54 515: the cuts removed bookkeeping around the chips, never hashing. The next lever, with its
numbers, is §7: the two Merkle spans, 368 791 rows, 133 827 of them reloads.

## 1. Where the rows go (Task 0, measured 2026-10-05, production fixture)

```
== profile Production: inner tier Tier(14), 893606 cpu rows, 54515 permutations, 2213181 mem accesses, 2147159 reg accesses, 210763 witness words, 903739 program instrs
-- shape: log_arities [1, 1, 2, 2, 2, 1, 3, 3, 2] (sum of arities 38), degree_bits [13, 15, 17, 16, 9, 9, 17, 11, 8], queries 80
-- rows per call site (executed; reloads and spills inside it; per query; top opcodes)
      116498   13.0%  (none)               reload   21160 spill   5429  /query   1456.2  [HINTN 24030, LOAD 21467, STORE 19302, LOADE 9555, HINT 8910, FADDI 7082]
       57276    6.4%  sample_bits          reload   12736 spill   4993  /query    716.0  [LOAD 12816, FMUL 7938, FSUB 5427, JEQ 5427, HINT 5265, FADDI 5184]
      248151   27.8%  input_root           reload   97987 spill      3  /query   3101.9  [LOAD 121107, FADDI 41521, SPONGE 33520, STORE 24723, COMPRESS 9200, FMUL 8000]
      163601   18.3%  reduce               reload   18480 spill   2881  /query   2045.0  [STOREE 40480, FADDI 40320, LOADE 37040, STORE 29041, REDUCE 9520, MOV 4480]
       87920    9.8%  bit_selected_power   reload   17280 spill    240  /query   1099.0  [FADDI 35840, FMUL 34560, LOAD 17280, STOREE 240]
       50960    5.7%  select               reload   12240 spill    480  /query    637.0  [LOAD 12240, EADD 6080, ESUB 6080, EMULF 6080, LOADE 5360, FADD 4320]
       36640    4.1%  fold_round           reload    1840 spill    880  /query    458.0  [MOV 7520, EMUL 6080, FMUL 4400, FMULI 3760, FSUB 3040, EMULF 3040]
      129600   14.5%  commit_root          reload   35280 spill      0  /query   1620.0  [LOAD 60240, FMUL 14400, STORE 14400, FADDI 11440, FADD 8640, COMPRESS 7040]
        2960    0.3%  roll_in              reload    1280 spill      0  /query     37.0  [LOADE 1280, EMUL 1200, EADD 480]
```

Spans nest and the innermost wins: `bit_selected_power` rows called from inside `reduce` and `fold_round` are
counted under `bit_selected_power`, not under their caller. Totals: reloads 218 283, spills 14 906, REDUCE
dispatches 9 520. Inside `reduce`, beyond the top six: FSUB 1 120, EINV 1 120, LOAD 480 (MOV 4 480 is in the list).

Q = 80, R = 9, E = 119 (9 520 / 80), H = 7 (the global height 20 plus the six roll-ins at 19, 18, 16, 14, 12, 11),
K = 14 (1 120 EINV in `reduce` / 80 = inverse keys per query). Spec §1's derived table, against this one:

- REDUCE descriptor build: 133 280 code minimum, ≈ 238 000 with reloads → `reduce` 163 601 (17.2 rows per
  dispatch; 18 480 reloads, 2 881 spills inside it).
- Fold chain (select + fold + roll-ins): 73 840 op-count minimum, up to ≈ 228 000 → `select` 50 960 + `fold_round`
  36 640 + `roll_in` 2 960 = 90 560 (1 132 per query).
- Arity schedule: Σa = 38 over 9 rounds (3 × 2, 4 × 4, 2 × 8) → measured `[1, 1, 2, 2, 2, 1, 3, 3, 2]`, as derived.
- `bit_selected_power`: ≈ 32 000–64 000 → 87 920 (1 099 per query), 37 % above the derived ceiling. *Corrected
  in Task 5 (the Task-0 review): the query asks for **216 bits**, not ≈ 274* — Σ L over its 16 calls, the seven
  query-point heights and the nine rounds' `log_folded` (the same 216 Cut F measured as `POW` chip rows a query).
  At 4 rows a bit plus one base constant a call that is 880 rows (`FADDI` 448 = 216 + 216 + 16, `FMUL` 432 = 2·216
  a query, both exactly); the other 219 are **reload traffic** — one `LOAD` a bit, 216 a query (17 280), and 3
  spills (`STOREE` 240). The overage over the ceiling is the allocator's, not more bits.
- Allocator reloads 218 283 / spills 14 906 → 218 283 / 14 906, as derived; by site: `input_root` 97 987,
  `commit_root` 35 280, `(none)` 21 160, `reduce` 18 480, `bit_selected_power` 17 280, `sample_bits` 12 736,
  `select` 12 240, `fold_round` 1 840, `roll_in` 1 280.
- Memory: REG 2 147 159, RAM 2 213 181, as spec §1.

## 2. The landing bands (±15 % of each cut's projected delta; phase 2 §6 ruling 1)

T₀ = 893 606. Each band is [T_prev − 1.15·Δ, T_prev − 0.85·Δ], with T_prev the previous cut's *measured* rows.

| cut | Δ (projected rows removed) | formula | band (Task 0) | measured | in band |
|---|---:|---|---|---:|---|
| D | 145 441 | rows(reduce) − [EINV+MOV+FSUB in reduce] − Q·(E + H + K + 3) | 726 349–769 981 | 749 846 (Δ −143 760) | yes |
| E1 | 35 120 (ruled; was 54 160) | rows(select) − Q·Σ_r(2·la_r + 5) − Q·Σ_r(a_r + 9) | 709 458–719 994 | 703 766 (Δ −46 080) | **no** (below; accepted) |
| E2 | 40 800 (re-read after E1; was 33 760) | rows(fold_round, re-read after E1) − 4·Q·R | 656 846–669 086 (from E1's measured 703 766) | 664 886 (Δ −38 880) | yes |
| F | 82 560 (re-read after E2; was 82 800) | rows(bit_selected_power, re-read after E2) − 4·Q·(H + R) | 569 942–594 710 (from E2's measured 664 886) | 585 686 (Δ −79 200) | yes |

Inputs: D = 163 601 − (1 120 + 4 480 + 1 120) − 80·(119 + 7 + 14 + 3); E1 = 50 960 − 80·79 − 80·119 (Σla = 17,
Σa = 38); E2 = 43 680 − 4·80·9, with `fold_round` re-read after E1 (36 720 → 43 680: the row loads moved into it);
F = 87 680 − 4·80·16, with `bit_selected_power` re-read after E2 (87 680, unchanged since Cut D).

**E1's sign (controller ruling, Task 2).** The plan wrote E1's last term with a `+`, which gave Δ_E1 = 54 160, more
than the whole `select` span (50 960). The ruled formula subtracts it: Δ_E1 = 35 120 (spec §2.2's "−35 000 to
−40 000"), band [749 846 − 1.15·35 120, 749 846 − 0.85·35 120] = 709 458–719 994.

**E1 measured below its band (Task 2).** Production lands at 703 766 rows (Δ −46 080, 10 958 rows past the
projection). The miss is `commit_root`, which the formula prices as unchanged: the leaf is now sponged in place, so
each round no longer stores the `arity` row values into a fresh buffer (Σa = 38 STOREE a query) or copies its four
salts (2 rows a cell, 72 a query). `commit_root` 129 600 → 120 640 (−8 960). The other spans: `select`
50 960 → 7 680 (−43 280; Q·Σ(2·la + 5) = 6 320 derived, 96 a query measured, with 17 reloads a query), `fold_round`
36 720 → 43 680 (+6 960; the formula's Q·Σ(a + 9) = 9 520 credit), `(none)` 116 498 → 115 778 (−720: the
tape reads, HINTN +240, HINT −480, STORE −480), `roll_in` 2 960 → 2 880 (−80). Sum −46 080.
**Ruling (controller, 2026-10-05): accepted.** 703 766 is E1's landing point. The band's model kept the per-round
row store and salt copy that sponging the leaf in place removes. That is an omission in the band's model, not an
anomaly in the cut. The correctness evidence is the On/Off differential, the tamper tables and the own-slot refusal.
The miss is recorded in spec §2.5. E2's band above (Δ 40 800, 656 846–669 086) stands.

**E2 measured in band (Task 3).** Production lands at 664 886 rows (Δ −38 880 against a projected −40 800).
`fold_round` 43 680 → 5 040 is 7 rows a round, not the formula's 4: `INV`, `EMULF`, `FOLD`, the result's `LOADE`,
and three reloads (`LOAD` 1 440 + `LOADE` 720 = 2 160 reloads in the span). `roll_in` 2 880 → 2 640 (−240) moved with
the allocator's schedule; every other span is unchanged. The F band is recomputed from the post-E2
`bit_selected_power` span (87 680): Δ_F = 82 560, band 569 942–594 710. E2's 664 886 is above 524 287, so Cut F
is built (Task 4). Even F's band floor (569 942) is above the 2^19 gate: reaching 524 287 needs Δ_F ≥ 140 599,
58 039 more than F's projection.

**F measured in band (Task 4).** Production lands at 585 686 rows (Δ −79 200 against a projected −82 560).
`bit_selected_power` 87 680 → 7 680 is 6 rows a call, not the formula's 4: the `(G, base)` pair's two `FADDI`s, two
reloads (`LOAD`), the `POW` and the output's `LOAD`, 16 calls a query (H + R = 7 + 9). `sample_bits` 57 276 → 58 076
(+800, 10 a query): under `On` the 64 bits are hinted into a 65-cell buffer by eight `HINTN`s and loaded back, instead
of 64 `HINT`s. Every other span is unchanged. **The phase ends here, above the gate: 585 686 − 524 287 = 61 399 rows
short of tier 19** (controller ruling 6: F does not widen the gate). Cut F was the last cut the plan holds.

**The rulings, together.** (1) E1's band formula had a sign error (Δ 54 160 > the whole `select`
span); the ruled Δ is 35 120 (Task 0's concern 1, the controller's ruling). (2) E1 landed **below**
its band (703 766 against 709 458–719 994) and was **accepted** as its landing point: the band's
model omitted a saving the cut itself causes (the in-place leaf sponge's `commit_root` −8 960), and
the gate exists to catch over-promising; E2's band was re-derived from the measured 703 766 (spec
§2.5 carries the ruling line). (3) E2 landed in band; its 664 886 is above 524 287, so **Cut F was
built**, and its recomputed band's floor (569 942) was already above the gate. (4) F landed **in
band** at 585 686. (5) **The gate was not reached** and, under spec §6 ruling 6, not widened: the
phase stops at the measured point, the memory heights are the delivered result, and §7 names the
next lever. (6) Two soundness rules the Cut-F implementer added beyond the brief — a pow row
entered from a reduce or fold row must start a run, and the registration check `off + L ≤ 64` —
were accepted as requirements the brief omitted. (7) Moving the Off replay's digest with the
shared fold-result cells (E2) was accepted; whether `Precompiles::Off` should be byte-stable is §7's.

Memory targets (spec §1): REG 2 147 159 → under 2 097 152 (needed −50 008); RAM 2 213 181 → under
2 097 152. **Both met at Cut D** (1 785 559 and 1 913 981) and held through F (1 290 039 and
1 903 581): F's `POW` added 15 440 RAM accesses (the bits buffer), 193 570 under the `≤ 2 097 151` line.

## 3. Memory (measured 2026-10-05 and 2026-10-06)

**The declared memory tables.** Both rVM memory tables are sized `pad_height(accesses + 1)`
(`machine::build_traces`). Production, before → after the phase: REG 2 147 159 → **1 290 039**
accesses, RAM 2 213 181 → **1 903 581**. Both are under 2 097 152, so both tables declare
**2^21** (they were 2^22); Cut D made the drop, and E1–F kept it (§4's table has REG and RAM after
each cut). The cpu and program tables stay at `2^20` (585 686 rows, tier 20), poseidon2 at `2^16`,
reduce at `2^18` (196 480 rows: 173 120 run rows, 6 080 fold rows, 17 280 pow rows). Test profile
(the twin's shape): REG **411 319** → `2^19` (it was 582 743 → `2^20` before Cut D), RAM
**442 445** → `2^19`, cpu 169 366 rows → tier 18, reduce `2^16` (39 296 rows).

**The reduce chip's N ceiling (the final fix wave, 2026-10-06).** The reduce rows are a
compile-time function of the program (`tables::reduce::program_rows`: a layout entry's length a
`REDUCE`, `2a` a `FOLD`, `L` a `POW`), and an N-proof aggregate runs them N times. With
`REDUCE_MAX_LOG_HEIGHT = 20` — **not raised in this phase** — an aggregate is verifiable only
while `N × rows + 1 ≤ 2^20`:

| profile | reduce rows a proof | canonical reduce height by N | N ceiling |
|---|---:|---|---:|
| production | 196 480 | `2^18` (N=1), `2^19` (N=2), `2^20` (N=3–5) | **N ≤ 5** |
| test | 39 296 | `2^16` (N=1), `2^17` (N=2–3), `2^18` (N=4–6), `2^19` (N=7–13), `2^20` (N=14–26) | **N ≤ 26** |

Phase 3 moved the production ceiling down by one: the reduction's 173 120 run rows alone
would hold N ≤ 6 (the review's "was N ≥ 7"), and the fold and pow row kinds (Cuts E2 and F) add
6 080 + 17 280 = 23 360 rows a proof.
Production N=6 and N=7 still fit tier 22 by cpu rows (§"N-economics" in docs/02: tier 22 holds
N ≤ 7), so **the ceiling inside tier 22 is the reduce chip's, not the tier's** — the node's
admission range for tier 22 (N=4–7) has to stop at 5 until the constant is raised (a key-shape
change for a later phase: one more rung of `REDUCE_MAX_LOG_HEIGHT` doubles the N range).
`Machine::prove` now refuses a run past the ceiling before any trace is built
(`ProveError::ReduceRows`), and `aggregate` refuses the N before the tape
(`AggregateError::TooManyProofs`); before this fix a prover would have produced a proof `verify`
refuses. `tests/aggregate.rs` pins both rows, both ceilings and the canonical heights, and checks
the static count against emulated runs (the single-proof program, the test N=1 and N=2
aggregates).

**The exit twin at tier 18** (`tests/memprofile.rs::tier19_exit_twin`, run alone, `--features
parallel`, 16 threads, this 48 GB box). The first column is docs/05 §"The exit twin at tier 18"
(`docs/measurements/2026-10-05-tier18-twin-memprofile.log`); the second is Cut D's run (Task 1b,
2026-10-05); the third is the phase's end (Task 5, 2026-10-06,
`docs/measurements/2026-10-06-tier18-twin-memprofile-phase3.log`).

| phase (Plonky3 span) | before: live after (ends at) | after Cut D | after Cut F (the phase's end) |
|---|---:|---:|---:|
| main trace `build merkle tree` | 10.78 GB (40.2 s), Δ +1.07 | 8.81 GB (31.5 s), Δ +0.54 | **9.49 GB** (32.3 s), Δ +0.54 |
| permutation `build merkle tree` | 16.95 GB (62.0 s), Δ +1.07 | 13.30 GB (46.3 s), Δ +0.54 | **14.20 GB** (47.6 s), Δ +0.54 |
| `compute quotient` (outermost close) | 23.65 GB (134.8 s), peak 30.09 | 18.27 GB (107.3 s), peak 24.86 | **19.16 GB** (114.3 s), peak **26.88** |
| quotient `build merkle tree` | 25.84 GB (147.8 s) | 19.65 GB (114.9 s) | **20.55 GB** (122.1 s) |
| the next commit round's `build merkle tree` | 29.70 GB (162.7 s) | 22.31 GB (124.4 s) | **23.20 GB** (131.5 s) |
| `FRI prover` (commit phase) | 31.35 GB (184.8 s) | 23.09 GB (133.1 s) | **23.98 GB** (140.8 s) |
| **run peak** | **33.27 GB**, in the FRI commit phase | 24.86 GB (−25 %), inside `compute quotient` | **26.88 GB** (−19 % against before), inside `compute quotient` (between 96.1 s and 112.9 s) |
| rows / tier | 230 950 / 18 | 202 198 / 18 | 169 366 / 18 |
| prove / verify / proof | 185.4 s / 5.46 s / 268 417 B | 133.2 s / 6.59 s / 259 720 B | **141.3 s / 6.67 s / 268 168 B** |
| outcome | proved | proved | **proved** (`== exit twin (tier 18): 169366 rows, tier 18, proof 268168 B, prove 141.3 s; peak live heap 26.88 GB`) |

macOS `maximum resident set size` for the final run: 24.6 GB — as docs/04 says, not a memory
number. **Why the end is 2.0 GB above Cut D with 32 832 fewer cpu rows:** the cpu table's height
did not move (`2^18` throughout), nor did the memory tables' (`2^19` since Cut D); what grew is
the reduce chip, `2^16` rows at 30 columns after Cut D and 81 after Cut F (the fold and pow row
kinds), with its 16 quotient chunks, and the cpu by two selector columns. Every committed tree is
+0.7–0.9 GB against Cut D's, and the peak, a transient inside `compute quotient`, +2.0 GB.

**The cell model, re-calibrated.** docs/04's projection weights each instance by its committed
cells: `height × (width + 4 salts)` for the main trace plus, since docs/05, `height × (2·chunks + 4)`
for its one quotient matrix (chunks after the ZK doubling: program 4, cpu 16, reg / ram /
poseidon2 8, public / range 4, reduce 16). In units of `2^14` rows the twin weighs 6 299 before
Cut D, 5 143 after it and 5 379 at the phase's end. Against the three measured peaks the model
predicted the Cut-D step as ×0.82 (measured ×0.75) and the E+F step as ×1.046 (measured ×1.081):
**within 10 %** either way, which is the error bar on every projection below. One unit is
26.88 / 5 379 = 0.0050 GB at the end of the phase.

**Projections (labelled; not measured).** The derivation is the cell ratio against a measured or
earlier-projected anchor, with the declared heights `build_traces` gives for each shape:

| proof | tier | declared heights cpu / reg / ram / poseidon2 / reduce / program | units | projected peak live |
|---|---:|---|---:|---|
| exit twin = test N=1 aggregate (the anchor) | 18 | 18 / 19 / 19 / 14 / 16 / 18 | 5 379 | **26.88 GB measured** |
| test N=2 aggregate | 19 | 19 / 20 / 20 / 15 / 17 / 18 | 10 454 | ≈ 52 GB |
| test N=3 aggregate | 19 | 19 / 21 / 21 / 16 / 17 / 18 | 15 668 | ≈ 78 GB |
| production exit / N=1 aggregate | 20 | 20 / 21 / 21 / 16 / 18 / 20 | 21 516 | **≈ 110–130 GB** |
| production N=2 | 21 | 21 / 22 / 22 / 17 / 19 / 20 | 41 816 | ≈ 210–245 GB |
| production N=3 | 21 | 21 / 22 / 23 / 18 / 20 / 20 | 57 584 | ≈ 290–340 GB |
| production N=4 | 22 | 22 / 23 / 23 / 18 / 20 / 20 | 82 416 | ≈ 410–490 GB |

The production range has two anchors. From the measured twin: 21 516 × 0.0050 = **108 GB**. From
docs/05's own production projection (≈ 170–175 GB for the phase-2 shape, itself a ratio off the
503 GB box's tier-21 run): that shape weighs 29 676 units (cpu `2^20` at 82 columns, REG and RAM
`2^22`, reduce `2^18` at 39 columns), and 21 516 / 29 676 = 0.725 gives **123–127 GB**. The two
disagree by about the model's own error bar, so the table carries both ends. **This replaces Task
1b's "≈ 130 GB"**, which applied the twin's measured ×0.75 to production: at production the cpu
and program tables do not halve (`2^20` before and after) while both memory tables do (at the twin
only the register table did), so the production ratio for Cut D alone is ×0.69 by the same cells,
not ×0.75 — and the reduce chip's widening then takes back +4.6 %. Every line above is a
projection until the proof runs on a large host; the host classes they imply are in §6.

## 4. The cuts, measured

| stage | commit | cpu rows (prod.) | gate band (landing rows) | Δ measured | Δ projected | REG accesses | RAM accesses | reg / ram log-heights | instructions (prod.) | test rows | tier |
|---|---|---:|---|---:|---:|---:|---:|---|---:|---:|---:|
| before (phase 2 + the quotient layout; Task 0's spans) | `7b8d2cd` | 893 606 | — | — | — | 2 147 159 | 2 213 181 | 22 / 22 | 903 739 | 230 950 | 20 |
| D: the reduction layout preprocessed | `bb8767f`, `a39582d` (machine), `47e9a45` (program) | 749 846 | 726 349–769 981 | −143 760 | −145 441 | 1 785 559 | 1 913 981 | **21 / 21** | 759 979 | 202 198 | 20 |
| E1: the own slot by one `LOADE` | `637a37c` | 703 766 | 709 458–719 994 (**below**; accepted) | −46 080 | −35 120 | 1 612 439 | 1 891 821 | 21 / 21 | 715 339 | 192 982 | 20 |
| E2: `FOLD` (opcode 28) | `7380c0d`, `0c3f671` (tests) | 664 886 | 656 846–669 086 | −38 880 | −40 800 | 1 477 239 | 1 888 141 | 21 / 21 | 676 459 | 185 206 | 20 |
| F: `POW` (opcode 29) | `439ca7a` | **585 686** | 569 942–594 710 | −79 200 | −82 560 | 1 290 039 | 1 903 581 | 21 / 21 | 597 259 | 169 366 | **20** |
| total | | | | **−307 920** | −303 921 | −857 120 | −309 600 | −1 / −1 | −306 480 | −61 584 | 0 |

Every cut landed in its band but E1, which landed 5 692 rows *below* it (more rows removed than
projected) and was accepted (§2). Against the projections the cuts delivered 99 % (D), 131 % (E1),
95 % (E2) and 96 % (F), 101 % in all. The gate needed −369 319; the plan's cuts, as projected,
held −303 921 of it, and the measured −307 920 leaves **61 399 rows** — the residual §7 prices.

**The spans after each cut** (production, executed rows; spans nest and the innermost wins):

| span | before | after D | after E1 | after E2 | after F | Δ phase |
|---|---:|---:|---:|---:|---:|---:|
| `(none)`: tape reads, preamble, phase 5 | 116 498 | 116 498 | 115 778 | 115 778 | 115 778 | −720 |
| `sample_bits` | 57 276 | 57 276 | 57 276 | 57 276 | 58 076 | +800 |
| `input_root` | 248 151 | 248 151 | 248 151 | 248 151 | 248 151 | 0 |
| `reduce` | 163 601 | **20 001** | 20 001 | 20 001 | 20 001 | −143 600 |
| `bit_selected_power` | 87 920 | 87 680 | 87 680 | 87 680 | **7 680** | −80 240 |
| `select` | 50 960 | 50 960 | **7 680** | 7 680 | 7 680 | −43 280 |
| `fold_round` | 36 640 | 36 720 | 43 680 | **5 040** | 5 040 | −31 600 |
| `commit_root` | 129 600 | 129 600 | 120 640 | 120 640 | 120 640 | −8 960 |
| `roll_in` | 2 960 | 2 960 | 2 880 | 2 640 | 2 640 | −320 |
| **total** | **893 606** | **749 846** | **703 766** | **664 886** | **585 686** | **−307 920** |
| reloads / spills | 218 283 / 14 906 | 201 323 / 12 186 | 194 443 / 12 106 | 191 003 / 10 746 | 176 283 / 10 826 | −42 000 / −4 080 |

The four spans the phase targeted (`reduce`, `select`, `fold_round`, `bit_selected_power`)
went from 339 121 rows to 40 401 (−88 %). The two Merkle spans did not move except for E1's
in-place leaf sponge (`commit_root` −8 960) and are now 63 % of the program.

The per-cut records follow, as each cut task wrote them (its `== profile` line, its span table,
and every pin it re-measured).

### Cut D (Task 1a machine side, Task 1b program side)

| cut | measured cpu rows | Δ | band | in band | REG (≤ 2 097 151) | RAM (≤ 2 097 151) | `reduce` span | REDUCE dispatches |
|---|---:|---:|---|---|---:|---:|---:|---:|
| D | 749 846 | −143 760 (projected −145 441) | 726 349–769 981 | **yes** | 1 785 559, met | 1 913 981, met | 163 601 → **20 001** | 9 520 |

```
== profile Production: inner tier Tier(14), 749846 cpu rows, 54515 permutations, 1913981 mem accesses, 1785559 reg accesses, 210763 witness words, 759979 program instrs
== profile Test: inner tier Tier(14), 202198 cpu rows, 11875 permutations, 444525 mem accesses, 510423 reg accesses, 45899 witness words, 204315 program instrs
-- rows per call site (production)
      116498   15.5%  (none)               reload   21160 spill   5429  /query   1456.2
       57276    7.6%  sample_bits          reload   12736 spill   4993  /query    716.0
      248151   33.1%  input_root           reload   97987 spill      3  /query   3101.9
       20001    2.7%  reduce               reload    1520 spill    321  /query    250.0  [REDUCE 9520, MOV 4480, LOADE 2080, STOREE 1520, FSUB 1120, EINV 1120]
       87680   11.7%  bit_selected_power   reload   17280 spill      0  /query   1096.0
       50960    6.8%  select               reload   12240 spill    480  /query    637.0
       36720    4.9%  fold_round           reload    1840 spill    960  /query    459.0
      129600   17.3%  commit_root          reload   35280 spill      0  /query   1620.0
        2960    0.4%  roll_in              reload    1280 spill      0  /query     37.0
-- reloads 201323, spills 12186; reduce dispatches 9520
```

Per query: 119 REDUCE rows (one per layout entry), 7 chains (one per opened height), 14 inverse keys (14 EINV), one
key buffer and one result buffer. `reduce` is 250 rows a query (was 2 045). Outside `reduce`, two spans moved
slightly because the allocator's schedule changed: `bit_selected_power` 87 920 → 87 680 and `fold_round`
36 640 → 36 720.

Pins and literals re-measured (the Re-pin Procedure):
- `tests/pins.json`: cpu rows 893 606 → 749 846; mem accesses 2 213 181 → 1 913 981; program instrs 903 739 → 759 979;
  REG 2 147 159 → 1 785 559; aggregate Test N = 1/2/3 cpu rows 231 224 / 462 039 / 692 854 → 202 472 / 404 535 /
  606 598 (mem 504 514 / 1 008 354 / 1 512 194 → 444 674 / 888 674 / 1 332 674). Permutations and witness words did not move.
- `LOOP_OVERHEAD` 274, unchanged. `N3_ROWS` 692 854 → 606 598. Aggregate tiers 18 / 19 / 20, unchanged.
- The production `verify_rv32` digest (`src/programs/verify_rv32.digest`): `723218da…d0d1` → `ef9b5b38…a388`.
- The aggregate digest at the Test shape: `5f1f6901…12df` → `8a2d166f…8509`. At the production shape:
  `c90b3f0a…74d8` → `a183de6e…6637`.
- The Off replay (`39bb6b8d…3352`) did not move: `Precompiles::Off` still compiles the reduction.
- Self-verifier digest `91e50e14…bd13` → `40eb7077…8487`. Toy CycleReport (131 739, 6 130, 276 847, 133 587, 24 135) →
  (120 955, 6 130, 254 575, 122 803, 24 135). Busy (167 746, 7 780, 320 075, 169 858, 29 967) → (156 466, 7 780,
  297 259, 158 578, 29 967). Phase 5 7 845 / 8 125, unchanged.
- The exit twin is 230 950 → 202 198 rows at tier 18. The production exit is 893 606 → 749 846 rows at tier 20.

### Cut E1 (Task 2)

| cut | measured cpu rows | Δ | band | in band | REG (≤ 2 097 151) | RAM (≤ 2 097 151) | `select` span | `fold_round` span | `commit_root` span |
|---|---:|---:|---|---|---:|---:|---:|---:|---:|
| E1 | 703 766 | −46 080 (projected −35 120) | 709 458–719 994 | **no** (below by 5 692; accepted) | 1 612 439, met | 1 891 821, met | 50 960 → **7 680** | 36 720 → 43 680 | 129 600 → 120 640 |

```
== profile Production: inner tier Tier(14), 703766 cpu rows, 54515 permutations, 1891821 mem accesses, 1612439 reg accesses, 212203 witness words, 715339 program instrs
== profile Test: inner tier Tier(14), 192982 cpu rows, 11875 permutations, 440093 mem accesses, 475799 reg accesses, 46187 witness words, 195387 program instrs
-- rows per call site (production)
      115778   16.5%  (none)               reload   21160 spill   5429  /query   1447.2
       57276    8.1%  sample_bits          reload   12736 spill   4993  /query    716.0
      248151   35.3%  input_root           reload   97987 spill      3  /query   3101.9
       20001    2.8%  reduce               reload    1520 spill    321  /query    250.0
       87680   12.5%  bit_selected_power   reload   17280 spill      0  /query   1096.0
        7680    1.1%  select               reload    1360 spill      0  /query     96.0  [MOV 1440, JEQ 1440, FMULI 1360, LOAD 1360, ESUB 720, LOADE 720]
       43680    6.2%  fold_round           reload    5360 spill   1360  /query    546.0
      120640   17.1%  commit_root          reload   35840 spill      0  /query   1508.0
        2880    0.4%  roll_in              reload   1200 spill      0  /query     36.0
-- reloads 194443, spills 12106; reduce dispatches 9520
```

The tape: `CommitPhaseOpenings` carries the whole row (2·a words a round, was 2·(a − 1)), so witness words
210 763 → 212 203 (+2 words × 9 rounds × 80 queries). `select` is one `LOADE` at a register offset (720 = 9 × 80),
the offset arithmetic (`FMULI` 1 360 = Σla × 80, `FADD`) and the two-lane equality (`ESUB` 720, `JEQ`
1 440 = 2 a round). Per query: 18 MOV + 18 JEQ + 17 FMULI + 17 LOAD + 9 ESUB + 9 LOADE = 88, and 8 more outside the top six (Σ(la − 1) = 8 offset `FADD`s, derived) = 96.

Re-pinned (the Re-pin Procedure, after the controller accepted the landing point):
- `tests/pins.json`: cpu rows 749 846 → 703 766; mem accesses 1 913 981 → 1 891 821; witness words 210 763 → 212 203;
  program instrs 759 979 → 715 339; REG 1 785 559 → 1 612 439; spans select 50 960 → 7 680, fold_round 36 720 →
  43 680, commit_root 129 600 → 120 640; reloads 201 323 → 194 443, spills 12 186 → 12 106. Permutations unchanged.
  Aggregate Test N = 1/2/3 cpu rows 202 472 / 404 535 / 606 598 → 193 256 / 386 103 / 578 950 (mem 444 674 /
  888 674 / 1 332 674 → 440 242 / 879 810 / 1 319 378; witness words 45 908 / 91 807 / 137 706 → 46 196 / 92 383 /
  138 570).
- `LOOP_OVERHEAD` 274, unchanged (193 256 = 192 982 + 274). `N3_ROWS` 606 598 → 578 950. Aggregate tiers 18 / 19 / 20,
  unchanged.
- The production `verify_rv32` digest: `ef9b5b38…a388` → `75576ad7…c8ba`.
- The aggregate digest at the Test shape: `8a2d166f…8509` → `9a43596f…4aa9`. At the production shape:
  `a183de6e…6637` → `9a619401…e649`.
- The Off replay moves this time, because the tape and the Off pipeline changed: `39bb6b8d…3352` → `af0c16e8…6c7b`.
- Self-verifier digest `40eb7077…8487` → `f60f0f5c…579b`. Toy CycleReport (120 955, 6 130, 254 575, 122 803, 24 135) →
  (114 955, 6 130, 251 855, 116 963, 24 295). Busy (156 466, 7 780, 297 259, 158 578, 29 967) → (146 626, 7 780,
  292 843, 149 026, 30 255). Phase 5 7 845 / 8 125, unchanged.
- The exit twin is 202 198 → 192 982 rows at tier 18. The production exit is 749 846 → 703 766 rows at tier 20.
- The reduce key (`WANT_REDUCE`) is unchanged: E1 does not touch the reduce chip's preprocessed region.

### Cut E2 (Task 3)

| cut | measured cpu rows | Δ | band | in band | REG (≤ 2 097 151) | RAM (≤ 2 097 151) | `fold_round` span | FOLD dispatches | reduce chip |
|---|---:|---:|---|---|---:|---:|---:|---:|---|
| E2 | 664 886 | −38 880 (projected −40 800) | 656 846–669 086 | **yes** | 1 477 239, met | 1 888 141, met | 43 680 → **5 040** | 720 | width 30 → 70, preprocessed 9 → 20, degree 8 → 8 |

```
== profile Production: inner tier Tier(14), 664886 cpu rows, 54515 permutations, 1888141 mem accesses, 1477239 reg accesses, 212203 witness words, 676459 program instrs
== profile Test: inner tier Tier(14), 185206 cpu rows, 11875 permutations, 439357 mem accesses, 448759 reg accesses, 46187 witness words, 187611 program instrs
-- rows per call site (production)
      115778   17.4%  (none)               reload   21160 spill   5429  /query   1447.2
       57276    8.6%  sample_bits          reload   12736 spill   4993  /query    716.0
      248151   37.3%  input_root           reload   97987 spill      3  /query   3101.9
       20001    3.0%  reduce               reload    1520 spill    321  /query    250.0
       87680   13.2%  bit_selected_power   reload   17280 spill      0  /query   1096.0
        7680    1.2%  select               reload    1360 spill      0  /query     96.0
        5040    0.8%  fold_round           reload    2160 spill      0  /query     63.0  [LOAD 1440, LOADE 1440, EMULF 720, INV 720, FOLD 720]
      120640   18.1%  commit_root          reload   35840 spill      0  /query   1508.0
        2640    0.4%  roll_in              reload    960 spill      0  /query     33.0
-- reloads 191003, spills 10746; reduce dispatches 9520
```

Each fold round is now `s` from the index bits (`bit_selected_power`, its own span, unchanged), `u = β·s⁻¹` (one `INV`,
one `EMULF`), one `FOLD` and the result's `LOADE`: 720 = 9 × 80 of each. The fold itself is a run of `2a` rows in the
reduce chip (Σ 2a = 76 a query, 6 080 chip rows in production — the reduce table is not the tallest, so its height does
not set the proof's). REG falls 1 612 439 → 1 477 239 (−135 200): the compiled barycentric fold's register traffic is
gone. RAM falls 1 891 821 → 1 888 141: the row's `2a` value reads move from the cpu's `LOADE`s to the chip's slot-0/1
reads, and the result is one write pair and one read pair. **Cut F is needed: 664 886 > 524 287.**

Pins and literals re-measured (the Re-pin Procedure):
- `tests/pins.json`: cpu rows 703 766 → 664 886; mem accesses 1 891 821 → 1 888 141; program instrs 715 339 → 676 459;
  REG 1 612 439 → 1 477 239; spans fold_round 43 680 → 5 040; reloads 194 443 → 191 003, spills 12 106 → 10 746.
  Permutations and witness words unchanged. Aggregate Test N = 1/2/3 cpu rows 193 256 / 386 103 / 578 950 →
  185 480 / 370 551 / 555 622 (mem 440 242 / 879 810 / 1 319 378 → 439 506 / 878 338 / 1 317 170).
- `LOOP_OVERHEAD` 274, unchanged (185 480 = 185 206 + 274). `N3_ROWS` 578 950 → 555 622. Aggregate tiers 18 / 19 / 20,
  unchanged.
- The production `verify_rv32` digest: `75576ad7…c8ba` → `5c30bf74…0d15`.
- The aggregate digest at the Test shape: `9a43596f…4aa9` → `f66aa580…6f63`. At the production shape:
  `9a619401…e649` → `b362024c…fc55`.
- The Off replay moves: `af0c16e8…6c7b` → `c580415b…5e6c`. Each committed row's buffer gains the two fold-result cells
  after its salts (`hint_array_padded`) in both builds, so every later cell address moves; the Off arithmetic is unchanged.
- Self-verifier digest `f60f0f5c…579b` → `b475a9f9…c348`. Toy CycleReport (114 955, 6 130, 251 855, 116 963, 24 295) →
  (105 485, 6 133, 246 774, 107 493, 24 355). Busy (146 626, 7 780, 292 843, 149 026, 30 255) → (139 267, 7 783,
  292 273, 141 667, 30 315). Phase 5 7 845 / 8 125 → 7 889 / 8 169 (the cpu's 29th selector, its FOLD limbs and the
  `FOLD` dispatch).
- The reduce key (`WANT_REDUCE`) moves: the preprocessed region carries the 14-row coefficient table,
  `1136b74d…` → `1465f60a…`. `WANT` (no reduce chip) is unchanged.
- The exit twin is 192 982 → 185 206 rows at tier 18. The production exit is 703 766 → 664 886 rows at tier 20.

### Cut F (Task 4)

| cut | measured cpu rows | Δ | band | in band | REG (≤ 2 097 151) | RAM (≤ 2 097 151) | `bit_selected_power` span | POW dispatches | reduce chip |
|---|---:|---:|---|---|---:|---:|---:|---:|---|
| F | 585 686 | −79 200 (projected −82 560) | 569 942–594 710 | **yes** | 1 290 039, met | 1 903 581, met | 87 680 → **7 680** | 1 280 | width 70 → 81, preprocessed 20 (unchanged), degree 8 → 8 |

```
== profile Production: inner tier Tier(14), 585686 cpu rows, 54515 permutations, 1903581 mem accesses, 1290039 reg accesses, 212203 witness words, 597259 program instrs
== profile Test: inner tier Tier(14), 169366 cpu rows, 11875 permutations, 442445 mem accesses, 411319 reg accesses, 46187 witness words, 171771 program instrs
-- rows per call site (production)
      115778   19.8%  (none)               reload   21160 spill   5429  /query   1447.2
       58076    9.9%  sample_bits          reload   12736 spill   5073  /query    726.0
      248151   42.4%  input_root           reload   97987 spill      3  /query   3101.9
       20001    3.4%  reduce               reload    1520 spill    321  /query    250.0
        7680    1.3%  bit_selected_power   reload    2560 spill      0  /query     96.0  [LOAD 3840, FADDI 2560, POW 1280]
        7680    1.3%  select               reload    1360 spill      0  /query     96.0
        5040    0.9%  fold_round           reload    2160 spill      0  /query     63.0
      120640   20.6%  commit_root          reload   35840 spill      0  /query   1508.0
        2640    0.5%  roll_in              reload    960 spill      0  /query     33.0
-- reloads 176283, spills 10826; reduce dispatches 9520
```

Test-profile spans: `bit_selected_power` 17 536 → 1 536, `sample_bits` 12 156; the other spans as after E2.

Each index power is one `POW` dispatch: `(G, base)` in one extension register pair, the query's 65-cell bits buffer in
`ra`, `off + 256·L` the immediate. The chip runs `L` rows, one a bit, high bit first: row `K` reads the bit at
`buf + off + L − 1 − K`, carries `G^{2^K}` by squaring and steps `S ← S·(1 + bit·(G^{2^K} − 1))`; the last row writes `S`
to cell 64, which the program loads back. Σ L = 216 a query (the seven query-point heights and the nine rounds'
`log_folded`), 17 280 chip rows in production. The bits buffer is the one `sample_bits` checks: under `On` it hints the
sixty-four bits into the buffer and runs its booleanity, canonicality and decomposition checks on handles loaded from
those cells, which nothing writes again (`POW` writes only cell 64). The chip also checks each bit boolean itself, so
it does not rely on that upstream check (`a_pow_row_with_a_non_boolean_bit_is_rejected`). REG falls 1 477 239 →
1 290 039 (−187 200): the ladder's register traffic is gone. RAM rises 1 888 141 → 1 903 581 (+15 440): the bits
buffer's writes and loads (10 240), the chip's bit reads (17 280) and the output's write and read (2 560), less 14 720
reloads and plus 80 spills.

**The gap.** 585 686 rows is 61 399 above 524 287, so the inner proof stays at tier 20; the phase ends at this measured
point (controller ruling 6). What is left, by span: `input_root` 248 151 (42.4 %; 97 987 of it reloads), `commit_root`
120 640 (20.6 %; 35 840 reloads), `(none)` 115 778 (the tape reads, the preamble and phase 5; 21 160 reloads),
`sample_bits` 58 076 (12 736 reloads), `reduce` 20 001, `bit_selected_power` 7 680, `select` 7 680, `fold_round`
5 040, `roll_in` 2 640. Reloads are 176 283 of the 585 686 (30 %), 133 827 of them inside the two Merkle spans.

Pins and literals re-measured (the Re-pin Procedure):
- `tests/pins.json`: cpu rows 664 886 → 585 686; mem accesses 1 888 141 → 1 903 581; program instrs 676 459 → 597 259;
  REG 1 477 239 → 1 290 039; spans bit_selected_power 87 680 → 7 680, sample_bits 57 276 → 58 076; reloads 191 003 →
  176 283, spills 10 746 → 10 826. Permutations and witness words unchanged. Aggregate Test N = 1/2/3 cpu rows
  185 480 / 370 551 / 555 622 → 169 640 / 338 871 / 508 102 (mem 439 506 / 878 338 / 1 317 170 → 442 594 / 884 514 /
  1 326 434).
- `LOOP_OVERHEAD` 274, unchanged (169 640 = 169 366 + 274). `N3_ROWS` 555 622 → 508 102. Aggregate tiers 18 / 19 / 20 →
  18 / 19 / **19**: the Test-profile N = 3 aggregate now fits tier 19 (508 102 ≤ 524 287).
- The production `verify_rv32` digest: `5c30bf74…0d15` → `cf5a350a…1788`.
- The aggregate digest at the Test shape: `f66aa580…6f63` → `df3a18b8…1073`. At the production shape:
  `b362024c…fc55` → `dc350ecf…8ba0`.
- The Off replay does not move (`c580415b…5e6c`): `Off` keeps `sample_bits`' sixty-four `HINT`s and the compiled ladder.
- Self-verifier digest `b475a9f9…c348` → `e9c9720d…4bb0`. Toy CycleReport (105 485, 6 133, 246 774, 107 493, 24 355) →
  (101 460, 6 168, 250 619, 103 468, 24 415). Busy (139 267, 7 783, 292 273, 141 667, 30 315) → (127 322, 7 802,
  296 262, 129 722, 30 375). Phase 5 7 889 / 8 169 → 7 933 / 8 213 (the cpu's 30th selector, POW's limb terms and the
  `POW` dispatch).
- The reduce key (`WANT_REDUCE`) is unchanged: F adds no preprocessed column.
- The exit twin is 185 206 → 169 366 rows at tier 18. The production exit is 664 886 → 585 686 rows at tier 20.

## 5. What moved

| pin | before (phase 2 + the quotient layout) | after (phase 3) | where |
|---|---|---|---|
| single-proof program digest, production shape | `723218da65a50f1f1581013f79fa5c5b1816b7ab46796dbaa4672c52bce2d0d1` | `cf5a350a62fa00bb6e84fa0de311a726aac7c610d23ce272b8c80795bac51788` | `src/programs/verify_rv32.digest` |
| `aggregate_program_digest`, production bundle shape (what a chain's aggregation section pins) | `c90b3f0a7758c7e306042f27a94cc1f123441b0284c7352cb3f426048c7a74d8` | `dc350ecf6b60af74f4bb032bdf607c3fa0fbd6317705f0b1077e71b455e38ba0` | `tests/aggregate.rs` (`the_production_n1_aggregate_is_the_m52_pin_plus_loop_overhead`, ignored, emulation only); `docs/02` |
| `aggregate_program_digest`, test fixture shape | `5f1f69010b8aa4cbb6072ffd8a631fa05897c18ed3663ae2bcd136455d2612df` | `df3a18b8d3294a591a2e8fd79f5430550cd9f09afcff6fc8aea89cc1bfaf1073` | `tests/verifier.rs` |
| Off replay, production shape (`Liveness::Off`, `Precompiles::Off`) | `39bb6b8d94e62dd282001384d0b65294e7f024e6ef9b47381c8c96c6e1fd3352` | `c580415bdaccf7888e7602e793198874e39e0bda8951d11ef6e47ed029455e6c` | `tests/verifier.rs` (moved at E1 — the tape — and E2 — the fold-result cells; D and F are `On`-only) |
| self-verifier digest, toy fixture shape | `91e50e140a8669385902e88bcbb18d5d9e5c270262d3f24bb2b67b4a469fbd13` | `e9c9720db4ea38438eee075c3cd5cd2362d60672b2c550d632519627e2724bb0` | `tests/self_verify.rs` |
| self-verifier `CycleReport` (rows, perms, mem, instrs, words), toy | (131 739, 6 130, 276 847, 133 587, 24 135) | (101 460, 6 168, 250 619, 103 468, 24 415) | `tests/self_verify.rs` |
| the same, busy fixture | (167 746, 7 780, 320 075, 169 858, 29 967) | (127 322, 7 802, 296 262, 129 722, 30 375) | `tests/self_verify.rs` |
| self-verifier phase 5, toy / busy | 7 845 / 8 125 | 7 933 / 8 213 | `tests/self_verify.rs` |
| the rVM verifier key with the reduce chip declared (`WANT_REDUCE`, a tier-8 cap) | = `WANT` (`dd11c3f0…`; the chip had no preprocessed columns) | `1465f60a95152d43, 208336379a094499, …` (Cut D's layout region `1136b74d…`, then E2's coefficient table) | `tests/verifier_key.rs`; `WANT` (no reduce chip) unchanged |
| `pins.json` production rows / perms / mem / instrs / words | 893 606 / 54 515 / 2 213 181 / 903 739 / 210 763 | 585 686 / 54 515 / 1 903 581 / 597 259 / 212 203 | `tests/pins.json` |
| `pins.json` `phase3_attribution` (new in Task 0): REG; `reduce` / `select` / `fold_round` / `bit_selected_power` / `commit_root` / `sample_bits`; reloads / spills | 2 147 159; 163 601 / 50 960 / 36 640 / 87 920 / 129 600 / 57 276; 218 283 / 14 906 | 1 290 039; 20 001 / 7 680 / 5 040 / 7 680 / 120 640 / 58 076; 176 283 / 10 826 | `tests/pins.json` (REG asserted by the budget test) |
| `pins.json` aggregate test N=1/2/3 cpu rows | 231 224 / 462 039 / 692 854 | 169 640 / 338 871 / 508 102 | `tests/pins.json` |
| `pins.json` aggregate test N=1/2/3 mem accesses | 504 514 / 1 008 354 / 1 512 194 | 442 594 / 884 514 / 1 326 434 | `tests/pins.json` |
| `pins.json` aggregate test N=1/2/3 witness words | 45 908 / 91 807 / 137 706 | 46 196 / 92 383 / 138 570 | `tests/pins.json` (E1's whole committed row) |
| `LOOP_OVERHEAD` (test and production) | 274 | 274 (unchanged) | `tests/aggregate.rs` |
| `N3_ROWS`; the test aggregates' tier asserts N=1/2/3 | 692 854; 18 / 19 / 20 | 508 102; 18 / 19 / **19** | `tests/aggregate.rs` |
| the production N=3 aggregate's tier (prove and B3 emulation, ignored) | 22 | **21** | `tests/aggregate.rs` |
| twin rows / tier | 230 950 / 18 | 169 366 / 18 | `tests/exit.rs` |
| exit rows / tier | 893 606 / 20 | 585 686 / 20 | `tests/exit.rs` |
| the budget test's regime assertion | `cpu_rows > 2^19` (M5.1's decision regime) | `cpu_rows == 585 686`, `Tier::for_cycles == 20`, above `2^19 − 1` (the landing, the gate not reached) | `tests/exit.rs` (`the_cycle_budget_per_inner_proof_is_pinned`) |
| `inner_vk_digest`, the admission stub vectors, the interface list | — | unchanged | the inner machine did not move |

Notes on the table:

- Commit `a337b12`'s subject says "isolating forgeries for five more rules"; the sweep added six
  forgeries (the entry step and five pow rules — the run carry split into three) plus the
  provider-rule test in `tests/tables.rs` (§6's table is the count). The history is left as it is.

- The self-verifier opens the rVM's own wider tables and shares the RV32 verifier's FRI
  pipeline, so both the pipeline's cuts and the rVM's wider AIR reach its program and its
  phase 5: its rows fell 23 % (toy) and 24 % (busy) against docs/05; its permutations rose by 38
  and 22 (+3 at E2, +35 / +19 at F): the rVM's wider cpu and reduce rows cost more sponge blocks
  where the self-verifier hashes them as opened rows.
- Permutations (11 877 / 23 724 / 35 571) are unchanged in the aggregate pins.
- The N=1 aggregate is 169 640 = 169 366 + 274 rows, and the production N=1 aggregate is
  585 960 = 585 686 + 274 (`the_production_n1_aggregate_is_the_m52_pin_plus_loop_overhead`). The
  cuts are inside the per-proof body; the loop around it did not move.

**The machine.** The ISA appends two opcodes; 0–27 never move.

- **`FOLD` = 28** (Cut E2): `rd` the pair holding `u = β·s⁻¹`, `ra` the committed row's base
  (`2a` cells, then the row's four salts), `imm` the arity `a ∈ {2, 4, 8}`. The reduce chip's
  fold run writes `Σ_m B_m·u^m` to the two cells after the salts. The emulator refuses another
  arity (`ExecError::FoldArity`).
- **`POW` = 29** (Cut F): `rd` the pair `(G, base)`, `ra` a 65-cell bits buffer, `imm = off +
  256·L`. The reduce chip's pow run writes `base·Π_t (1 + bit_{off+L−1−t}·(G^{2^t} − 1))` to cell
  64. The emulator refuses a non-boolean bit (`NonBooleanBit`) and a run leaving the buffer
  (`PowShape`), and so does registration (`DecodeError::PowShape`, `off + L ≤ 64`, `L ≥ 1`).
- **`REDUCE` = 24 changed meaning** (Cut D): its immediate names a **layout entry**, not a
  descriptor pointer. `Program` carries `reduce_layout: Vec<ReduceEntry>` (`vals`, `row`, `len`,
  `key`, `alpha`, `res`, `chain_start`, `carry`), absorbed into `Program::digest` after the
  instructions (two permutations an entry; a program without a layout keeps its digest) and
  committed by the verifier key. Registration checks it (`DecodeError::Layout`: every base and
  the length below `2^24` before any sum, every top below `2^24`, the chain flags consistent);
  the emulator refuses the same entries (`ExecError::ReduceLayout`) and a broken hand-over
  (`ReduceChain`).

`Op::COUNT` and `NUM_SELECTORS` go from 28 to 30.

- **cpu width:** 82 → 83 (E2's selector) → **84** (F's selector). Every column after `SEL0`
  moved (`A0` 35 → 37, `W0` 74 → 76); they are named constants. `FOLD` and `POW` read the whole
  `rd` pair (`READ_RD`, `EXT_READ_RD`); the range groups check `A0 + 2B + 5` for `FOLD` and
  `A0 + 64` for `POW`.
- **reduce width:** 39 → **30** + 9 preprocessed (Cut D: the runtime descriptor and its
  address-limb range columns replaced by the preprocessed layout and its lookup) → 70 + 20 (E2: the fold row kind, 40 columns, and the 11-column
  coefficient table) → **81 + 20** (F: the pow row kind, 11 columns). **Three row kinds**, in
  this order, then padding: run (`IS_REAL`), fold (`IS_FOLD`), pow (`IS_POW`); every boundary
  between them is covered by a rule that forces the entered run to start (a headless run sends
  no dispatch message, and would write at a clock of the prover's choosing). The preprocessed
  region is a provider of `max(layout, 14)` rows with witness multiplicities `MULT` and `MULT_C`.
- **Degree pins** are unchanged: `[2, 8, 4, 4, 4, 2, 2]`, reduce **8** (this config's ceiling;
  docs/01's table listed the reduce chip as 3 — a misprint, corrected there). The pow product
  step is degree 5 after gating.
- **Buses: thirteen** — `REG`, `RAM`, `POSEIDON2`, `SPONGE`, `PROGRAM`, `RANGE8`, `PUBLIC`,
  `REDUCE [clk, entry]` (was `[clk, descr_ptr]`), `COMPRESS`, and the new **`REDUCE_LAYOUT
  [entry, vals, row, row_end, key, alpha, res, flags]`**, **`FOLD [clk, msg, u0, u1, a]`**,
  **`FOLD_COEFF [a, k, c0..c7]`** and **`POW [clk, buf, off + 256·L, G, base]`**. The cpu sends
  `REDUCE`, `FOLD` and `POW`; the reduce chip receives them and provides its own `REDUCE_LAYOUT`
  and `FOLD_COEFF` regions.

**The verifier's reduce height is canonical (the final fix wave, 2026-10-06; the whole-branch
review's Important 2, INTERFACE-4 / AGG-3).** The verifier key is built at the proof's reduce
height (the preprocessed region is committed there), and until this fix `Machine::verify` took
that height from the proof: any value in `4..=20` with room for the provider region was a fresh
key build — 30–70 s at production — and a slot in the node's 64-entry key cache. Now
`Machine::verify_n(program, proof, n)` recomputes the one honest height,
`machine::canonical_reduce_log_height(program, n)` (= `build_traces`' rule at `n ×
program_rows(program)`), and refuses any other declared height as
`VerifyError::ReduceHeightNotCanonical { declared, canonical }` before any key work.
`Machine::verify` is `n = 1`; `aggregate::verify_aggregate` passes the N of its digest-bound
list. `program_rows` reads the program the key already commits — no new `Program` field, no
digest change. It is exact for programs that run each `REDUCE`/`FOLD`/`POW` once per inner proof:
the single-proof program (straight-line) and the aggregate program, all of whose such
instructions sit in the N-loop's body. **What the node must do:** verify through
`verify_aggregate` (or `verify_n` with the proof's N) — its DoS guard reduces to that signature,
since a `(program, tier, N)` now admits exactly one reduce height (three at production N ≤ 5:
`2^18`, `2^19`, `2^20`); its startup warm loop warms `canonical_reduce_log_height(program, N)` for
each admitted N instead of guessing heights; and it admits production N ≤ 5 only (§3's ceiling).

**The tape.** `CommitPhaseOpenings` carries each round's committed row **whole**: `2·a` words a
round (was `2·(a − 1)`, the siblings only), then the four salts, so `open_stride = Σ (2^a·2 +
4)` and witness words rise 210 763 → 212 203. The program hints each row into a buffer padded by
two cells for the fold result (`Builder::hint_array_padded`), in both builds. Under `On`,
`sample_bits` hints the 64 query bits into a 65-cell buffer (`sample_bits_mem`) the `POW`s read;
under `Off` it keeps its 64 `HINT`s. The tape is the aggregator's private witness; its only
contract is that the program and the tape agree, and the exit tests over real proofs check it.

**`Precompiles::Off` stays buildable and is the reference**: the compiled reduction
(`reduce_compiled`), the compiled barycentric fold and `bit_selected_power`. Every fixture's
acceptance and tamper tables run both builds, and `Precompiles::On` refuses no fixture that
`Off` accepts.

**What did not move:**
- the RV32 machine (constraint set 8) and its proofs;
- the inner verifier key and `inner_vk_digest`;
- the FRI profiles;
- the hashing (54 515 permutations, the same sponges and compressions);
- the aggregate's interface `[vk ‖ N ‖ B(8) ‖ 35·N]` and `verify_aggregate`'s API;
- the chain's consensus rules.

The fullnode re-vendors this tree and re-pins `admitted_shapes[].aggregate_program_digest`
(`dc350ecf…8ba0` at the production bundle shape) and the rVM verifier keys (the reduce chip's
preprocessed region is new) at the next chain cut, and adopts the canonical-height verify and
the N ≤ 5 production ceiling above. No running chain has aggregation enabled.

## 6. The suite, and the proofs run and not run (Task 5, 2026-10-06)

**The suite** (`cargo test --release --no-fail-fast -- --skip a_one_proof_aggregate_round_trips`,
docs/04's invocation, on the final tree: `a337b12`, `7098629` and this record's `tests/exit.rs` pin): **278 passed, 0 failed, 20 ignored, 1
skipped**, across 28 test binaries. Phase 2 ended at 208 / 20 / 1; Task 0 measured 210 on the
pre-rebase tree (base `2c1f068`); the rebase onto main's quotient-layout merge brought in its
216-test suite (docs/05), and the cuts took it to 269 at Cut F. Task 5's sweep added nine tests (six forgeries in
`tests/cheating.rs`, one rule test in `tests/tables.rs`, the reload-in-span test in `tests/dsl.rs`,
the top-cell legality test in `tests/program.rs`) and widened four (the layout digest's fields,
the own-slot check's cases at the unit and the whole-program level, the padding rule's columns). The ignored tests that run on
the cached fixtures, run alone after it, all green:

- `exit the_cycle_budget_per_inner_proof_is_pinned` — the production pin, the REG count and the
  landing pin (585 686, tier 20);
- `aggregate the_production_n1_aggregate_is_the_m52_pin_plus_loop_overhead` — 585 960 rows and
  the production `aggregate_program_digest`;
- `aggregate production_n2_aggregate_emulates_within_bounds` and
  `production_n3_aggregate_emulates_within_bounds` — 1 171 511 and 1 757 062 rows, both tier 21
  (the N=3 pin moved 22 → 21 this task), max address 4 438 040, top timestamps 18 744 191 and
  28 113 007;
- `exit fifty_tampered_production_proofs_are_refused_at_the_same_step_as_the_native_verifier` —
  every one of the fifty tampered production proofs refused at its named step;
- `profile where_the_rows_go` — the `== profile` lines of §4's Cut F record, reproduced.

**The forgeries' mutation evidence.** Each new forgery was checked in a `git archive` scratch copy
of the tree, its rule deleted from `ReduceAir::eval` by an exact single-match edit, the one test
run, and the file restored byte for byte:

| rule deleted | test | with the rule deleted |
|---|---|---|
| `carry·(n(ENTRY) − ENTRY − 1)` | `a_carry_followed_by_the_wrong_entry_is_rejected_by_the_entry_step` | FAILED: "a carry from entry 0 into entry 2 VERIFIED, skipping entry 1" |
| `CLK` in the pow run carry | `a_pow_run_moving_its_clock_mid_run_is_rejected_by_the_clock_carry` | FAILED: "… VERIFIED" |
| `P_OFF` in the pow run carry | `a_pow_run_moving_its_offset_mid_run_is_rejected_by_the_offset_carry` | FAILED: "… VERIFIED" |
| `P_L` in the pow run carry | `a_pow_run_changing_its_length_mid_run_is_rejected_by_the_length_carry` | FAILED: "… VERIFIED" |
| `P_FIRST·P_K` | `a_pow_run_starting_past_k_zero_is_rejected_by_the_first_index_rule` | FAILED: "a pow run starting at K = 1 VERIFIED, never reading its highest bit" |
| first row `IS_POW·(1 − P_FIRST)` | `a_headless_pow_row_at_the_tables_first_row_is_rejected` | FAILED: "… VERIFIED, writing 777 to cell 664" |
| `MULT·(1 − L_IS_ENTRY)` | `a_multiplicity_off_the_layout_is_refused_by_the_provider_rule`; `no_admissible_padding_reduce_row_sends_a_message` | FAILED: no constraint violated; padding rows send |
| `MULT_C·(1 − C_IS_ROW)` | the same two | FAILED, the same |

The entry-step forgery's first draft did not isolate its rule (the relabelled `REDUCE` row's
immediate operand was left at 1, and the cpu's `B0 = B` refused it first); with the operand
carried it does, and the table's line is the corrected test's.

**The proofs this box ran** (each alone, nothing else building, `--features parallel`, 16
threads):

| proof | command | result |
|---|---|---|
| the tier-18 exit twin under the heap profiler | `cargo test --release --features parallel --test memprofile tier19 -- --ignored --nocapture` | **proved**: 169 366 rows, tier 18, prove 141.3 s, verify 6.67 s, 268 168 B, **peak live heap 26.88 GB** (§3; `docs/measurements/2026-10-06-tier18-twin-memprofile-phase3.log`) |
| the tier-18 exit twin (`tests/exit.rs`, its row and tier pins and R1 at full scale) | `cargo test --release --features parallel --test exit twin -- --ignored --nocapture` | **proved**: prove 92.3 s, verify 6.70 s, 270 760 B; the proof refused against a one-word-different program's key |
| the suite's skipped test: the N=1 test aggregate round trip and its tampered variants (`a_one_proof_aggregate_round_trips_and_tampered_variants_are_refused`, the twin's shape plus the 274-row loop) | `cargo test --release --features parallel --test aggregate a_one_proof_aggregate_round_trips -- --nocapture` | **proved**: 105.2 s for the test binary (the round trip and its four tampered variants), 269 833 B, every variant refused — skipped in the suite on this box since docs/04 for memory (Task 0 found the `aggregate` binary OOM-killed with it), proved here alone |

macOS's `maximum resident set size` for the three runs was 24.6, 30.7 and 26.2 GB; as docs/04
says, not memory numbers — the live figure is the profiler's 26.88 GB.

**The proofs it did not run**, each recorded with the model's figure (§3) and the host it needs:

| proof | tier | why not here | projected peak live | host |
|---|---:|---|---:|---|
| test N=3 aggregate twin (`aggregate twin`; its tier assertion moved 20 → 19 this phase) | 19 | the model says it does not fit 48 GB | ≈ 78 GB | ≥ 128 GB |
| test N=2 aggregate (`two_test_profile`) | 19 | the same | ≈ 52 GB | ≥ 64 GB, comfortably ≥ 128 GB |
| the production exit (`exit exit_…`) and N=1 aggregate | 20 | the same | ≈ 110–130 GB | ≥ 160 GB |
| production N=2 / N=3 aggregates | 21 | the same | ≈ 210–245 / 290–340 GB | ≥ 256 / ≥ 512 GB |

So the test N=3 aggregate's tier assertion (19) is exercised by its emulation and pins
(`n3_aggregate_publishes_the_host_interface_digest`, `tests/pins.json`) but by no proof until a
large host runs it — the cost the Task-5 ruling named.

**The final fix wave (2026-10-06, after the whole-branch review).** The review returned "ready
after fixes": the fold kind's structure rules and the reduce kind's in-run `ROW_END` carry were
pinned by no test (fourteen single-rule deletions left `cheating` and `tables` green), the
verifier key followed the proof's declared reduce height, and the N ceiling had moved down
undocumented. Eleven isolating forgeries (`tests/cheating.rs`, the "Final fix wave" block), each
mutation-checked as above:

| rule deleted | test | with the rule deleted |
|---|---|---|
| `F_MSG` in the fold run carry | `a_fold_run_moving_its_row_base_mid_run_is_rejected_by_the_base_carry` | FAILED: "… VERIFIED, writing its result 20 cells away" |
| `CLK` in the fold run carry | `a_fold_run_moving_its_clock_mid_run_is_rejected_by_the_clock_carry` | FAILED: "… VERIFIED" |
| `F_A` in the fold run carry | `a_fold_run_changing_its_arity_mid_run_is_rejected_by_the_arity_carry` | FAILED: "… VERIFIED, ending two rows early in the salt cells" |
| `U0` / `U1` in the fold run carry | `a_fold_run_moving_u0_mid_run_…_u0_carry` / `…_u1_…_u1_carry` | FAILED: "… VERIFIED" (each) |
| `F_FIRST·D = 0` | `a_fold_run_starting_with_a_dirty_accumulator_is_rejected_by_the_zero_start_rule` | FAILED: "… VERIFIED, writing 3 for the zero row's 0" (the review's example) |
| `F_FIRST·K = 0` | `a_fold_run_starting_past_k_zero_is_rejected_by_the_first_index_rule` | FAILED: "… VERIFIED, never reading y_0" |
| `n(K) = K + 1` | `a_fold_run_skipping_an_index_is_rejected_by_the_index_step` | FAILED: "… VERIFIED, never reading y_1" |
| `F_LAST·(K − 2a + 1)` | `a_fold_run_ending_before_k_two_a_minus_one_is_rejected_by_the_end_rule` | FAILED: "… VERIFIED, one Horner step short" |
| the fold must-continue rule | `a_fold_run_stopping_before_its_last_row_is_rejected_by_the_must_continue_rule` | FAILED: "… VERIFIED, never writing its result" |
| `ROW_END` in the reduce run carry | `a_reduce_run_ending_early_is_rejected_by_the_row_end_carry` | FAILED: "… VERIFIED, publishing 51 against an honest 267" |

`a_fold_run_cut_short_is_rejected` became `…_by_its_missing_result_write`: with the must-continue
rule deleted it is still refused (the `RAM` bus). `tests/tables.rs`'s carry rule, which had been
narrowed to the reduce kind's 30 columns, now runs per kind — reduce (with `ROW_END`), fold
(`CLK`, `F_MSG`, `F_A`, `F_K`, `U0`, `U1`, on phase-2 rows so the switch does not mask the K
step) and pow (`CLK`, `P_BASE`, `P_OFF`, `P_L`, `P_K`) — and goes red under each fold carry and
step deletion, the `ROW_END` deletion, and the pow `P_K` step, `P_BASE` and `CLK` deletions. The
reduce kind's `ENTRY`/`CARRY` carries and the fold phase-1-prefix rule are recorded as redundant
in `ReduceAir::eval` (for in-order programs, and with the `FOLD_COEFF` lookup); no forgery
isolates them. The canonical-height refusal (§5) and the prove-side ceiling (§3) came with five
tests (`tests/cheating.rs` two, `tests/aggregate.rs` three); with the canonical check deleted the
one-above forgery reaches the batch verifier, past the key build. The suite after the wave (the same
invocation): **294 passed, 0 failed, 20 ignored, 1 skipped** — the 278 above plus the sixteen new
tests; no AIR, program or pin moved.

## 7. Still ahead (recorded, not in this phase)

The phase ends at the measured point (spec §2.5): 585 686 rows, **61 399 above the tier-19
gate**. In order of leverage:

1. **The Merkle spans — the next lever.** `input_root` (248 151 rows, 42.4 %) and `commit_root`
   (120 640, 20.6 %) are **368 791 rows, 63 % of the program**, and **133 827** of them are the
   allocator's reloads (97 987 and 35 840) — 36 % of the two spans, more than twice the residual.
   Per query: `input_root` 3 101.9 rows over the seven opened heights (leaf sponges and walks),
   `commit_root` 1 508 over the nine rounds. By opcode (production, Task 5's profile, which now
   prints every opcode a span executed): `input_root` is `LOAD` 121 107 (97 987 of them reloads),
   `FADDI` 41 521, `SPONGE` 33 520, `STORE` 24 723, `COMPRESS` 9 200 (115 levels a query),
   15 200 rows of field arithmetic, and 2 880 rows of other opcodes (`JEQ` 1 600, `POSEIDON2`
   1 280); `commit_root` is `LOAD` 58 880 (35 840 reloads), 27 360 rows
   of `FMUL`/`FADD`/`FSUB`, `STORE` 11 520, `FADDI` 10 720, `COMPRESS` 7 040 (88 levels a query),
   `SPONGE` 2 240, and 2 880 rows of other opcodes (`JEQ`). The two spans spend ≈ 23 rows for every `COMPRESS` row they issue. The spans
   did not move in this phase except for E1's in-place leaf sponge, and phase 2's Cut C is their
   last change (`COMPRESS`). Candidates, to be priced by the same span profile before any is
   built: keep the walk's running digest and its pointers in registers across levels (most of
   the spans' `LOAD`s are reloads — handles the walk re-reads level after level; the profile
   does not split them further); `COMPRESS` with an
   immediate-offset sibling (docs/04 item 4: one `FADDI` a level, ≈ 16 k rows); a path-level
   precompile — a run of compress rows in the poseidon2 chip, one cpu row a path instead of one
   a level — the `MERKLE` that docs/00 still leaves absent. Halving the two spans' reloads alone
   (≈ −67 000) would cross the gate; whether any one candidate does is a measurement, not this
   record's claim.
2. **The inner FRI profile decision, with the query count corrected.** docs/04's item 3 read
   "rate ¼ with about 40 queries halves everything in the query phase". The count is wrong. The
   production profile is rate ⅛ (`log_blowup 3`), 80 queries and 20 PoW bits, chosen for its
   *proven* bound (`research/src/machine.rs`, `FriProfile::Production`: ~86 proven bits at
   q = 80, g = 20; consensus-facing, genesis-bound). The proven bound's per-query term scales
   with `−log2 √ρ`, the Johnson radius — 1.5 at rate ⅛, 1.0 at rate ¼ (the ~86 bits at q = 80
   are that term less the bound's slack) — so rate ¼ at the same proven security needs **~120
   queries, not 40**: 1.5× the queries, not half. (40 is the *conjectured* count at rate ¼ —
   `log2 1/ρ` = 2 bits a query, 40·2 + 20 = 100 bits — the trade the profile's own note, finding
   ZM1, records rejecting at rate ⅛ for the proven floor.) For the rVM that is *more* rows, not
   fewer: the query phase is ≈ 5 874 rows a query (585 686 less the 115 778
   outside every per-query span, over 80), and each Merkle path is one level shorter at rate ¼, so
   40 more queries cost ≈ +220 000 rows (≈ 800 000, still tier 20). The inner profile is
   therefore a wallet-side lever (the inner prover's LDEs halve) paid for by the aggregator, and
   a consensus decision for the paper and the node, not a row cut for this crate. The rVM's
   *own* profile is a separate lever with the opposite sign for memory: `log_blowup 3 → 2` for
   rVM proofs halves every LDE term of §3's table at ~1.5× the rVM's own queries (docs/04's
   memory candidate 3) — the lever for §3's ≈ 110–130 GB, not for the cpu rows. **Done
   (2026-10-06, `docs/07`):** at 92 queries and 24 grinding bits — equal to 80/8/20 under the
   paper's unique-decoding theorem (`92 × 0.678 + 24 = 86.38` against 86.41, and the same under
   `p3-security` over the real chip shapes), not the ~120 queries reasoned above, which is where
   the field term saturates; measured, the tier-18 twin's peak live heap 26.88 → 15.64 GB (×0.58),
   and the production N=1 projected at ≈ 64–75 GB.
3. **The rest of the program, for scale.** Outside the query spans: the tape reads, preamble and
   phase 5 (`(none)`, 115 778 rows, 21 160 reloads) and `sample_bits` (58 076, 12 736 reloads).
   The reduce chip's own "read `px` once for a matrix's two points" (spec §2.5) would cut chip
   rows, not cpu rows: the `reduce` span is 20 001 cpu rows now, 3.4 %, and not a gate lever.
4. **The proofs this box cannot run** (§6): the test N=2 and N=3 aggregates (≈ 52 and ≈ 78 GB
   projected; the N=3 one's tier assertion moved 20 → 19 this phase and no proof has exercised
   it), the production exit and N=1 aggregate (≈ 110–130 GB), and the production N≥2
   aggregates. They want a ≥ 128 GB host for the test shapes and ≥ 160 GB for production N=1;
   the projections in §3 become measurements there.
5. **The reduce chip's N ceiling** (§3, the final fix wave): `REDUCE_MAX_LOG_HEIGHT = 20` caps
   production at N ≤ 5 — inside tier 22, which holds cpu rows to N = 7. Raising it one rung
   (N ≤ 10) is a verifier-key shape change for a later phase, with the node's admission range.
6. **`Precompiles::Off` byte-stability** (the E2 ruling's deferred question): the Off replay's
   digest moved at E2 because both builds share the fold-result cells after each committed row.
   Off's arithmetic is unchanged; if the replay tripwire is meant to catch layout drift as well
   as arithmetic, the padding should become `On`-only. Not needed for soundness.

## Conclusion

**The gate was not met.** Phase 3 built what its spec planned — the reduction's layout
preprocessed in the reduce chip, the own slot checked by one `LOADE`, `FOLD` and `POW` as reduce-chip
row kinds — and each cut landed in its band (E1 below it, accepted): 893 606 → **585 686** rows,
−34.5 %, permutations unchanged. The inner proof stays at **tier 20, 61 399 rows above
`2^19 − 1`**; spec §6 ruling 6 holds, and the gate is not widened. The memory half of the
milestone is met in full: both production memory tables are `2^21`, the tier-18 twin proves on
this 48 GB box at 26.88 GB live, and the production N=1 is projected at ≈ 110–130 GB where it was
≈ 170–175 GB. The residual is the two Merkle spans — 368 791 rows, 133 827 of them reloads — and
the inner FRI profile is not the row lever docs/04 took it for (rate ¼ needs ~120 queries, not
40). Both go to a phase-4 decision with the numbers above.
