# 08 — Tree aggregation: a leaf of L bundle proofs, 2-to-1 interior steps, every level recomputed

Design: `docs/superpowers/specs/2026-10-08-tree-aggregation-design.md`. Plan: `docs/superpowers/plans/2026-10-08-tree-aggregation.md`.

## 1. The child, measured (Task 0, production)

**Laptop, 2026-10-09: the shape, by emulation (nothing proved).** The production L = 2 leaf
(`rv32n` over production fixtures 0 and 1, binding `TEST_BINDING`) was executed and its traces
built with the prover's own height rule (`machine::build_traces`), so every height below is the
one an honest leaf proof declares. `rv32r` was then built for that `RvmShape` with its `RvmKey`
(the preprocessed commit of the program, range and reduce-layout tables: well under 1 GB; the
whole run peaked at 6.33 GB live, most of it the leaf's traces) and its rows **counted, not
executed**. No real leaf proof exists to execute it over: the leaf is a ≈ 122–142 GB proof at
rate ¼ (projected, docs/07 §4; ≈ 210–245 GB at rate ⅛) and this host has 48 GB.

**Rate ¼ (2026-10-09, after the rebase onto circuits main 71e1a04: the rVM's FRI at blowup 4, 92
queries) superseded the rate-⅛ figures (80 queries)**: C 575 246 → **648 518**, the band
[977 893, 1 323 033] → **[1 102 455, 1 491 559]**, the production step 1 148 417 → **1 294 577**
(tier 21 both). The leaf (an inner-RV32 verifier) is unchanged.

The count's method is the accepting walk (`tests/tree_measure.rs`'s `accepting_rows`). `rv32r`'s
only control flow is the DSL's assertion: a `JEQ` to `pc + 2` over a one-row trap
(`INV r1, r0`). The walk asserts this for every jump, and any `JMP` or `JNE` (a loop, an `if_eq`)
would panic it. An accepting run therefore takes every such `JEQ` and visits every other
instruction once, in order, up to `HALT`, at one cpu row per visit. Falling through a `JEQ` runs
the trap, which is an error, not a shorter trace. So the count is a property of the program
alone, and it is what any honest leaf proof of this shape executes. The walk is held to the
emulator in-suite by `the_accepting_walk_counts_what_rv32r_executes`: `rv32r` executed over a
real test-profile rVM proof gives the same rows, in total and phase by phase.
(`the_self_verifier_is_straight_line_in_the_proofs_data` alone does not establish this: it
compares two proofs of one toy shape.)

| run | host | rows | tier | heights reg / ram / poseidon2 / reduce (program) | prove | verify | proof | peak live | max RSS |
|---|---|---:|---:|---|---:|---:|---:|---:|---:|
| leaf: `rv32n`, L = 2 (fixtures 0–1), **emulated** | laptop | 1 171 511 | 21 | 22 / 22 / 17 / 19 (2^20, 597 665 instrs) | — | — | — | — | — |
| `rv32r` at the leaf's shape (k = 1, baked cap), **counted** | laptop | 648 910 | 20 | — (canonical reduce height at n = 1: 18) | — | — | — | — | — |
| leaf: `rv32n`, L = 2 (fixtures 0–1), proved | 256 GB | *pending (Step 6)* | | | | | | | |
| `rv32r` over the leaf (k = 1, baked cap), proved | 256 GB (tier 20 at rate ¼) | *pending (Steps 7–8)* | | | | | | | |

The leaf's canonical reduce height at n = 2 is `2^19`, the same as the height `build_traces`
declares (asserted). The leaf's rows and heights equal docs/02's production N = 2 row exactly.
`rv32r`'s program is 663 308 instructions, of which 14 398 are traps. Its rows by phase:
phases 0–4 919, phase 5 20 785, phase 6 preamble 97 175, query tape reads 60 716,
queries 468 922, phase 8 392. Against rate ⅛ only the query-count terms moved (phase 6
preamble +8 661, reads +8 401, queries +56 210: 92 queries where there were 80, one Merkle
level fewer each).

C (the child verification: `rv32r` rows less phase 8) = **648 518, emulated**
(`tree_measure.child_cpu_rows_emulated`; 575 246 at rate ⅛). The spec §1 projection was
0.85–1.45 M, so C is **below** it, at about 0.76 of the projection's low end. The droplet run replaces "emulated" with
"measured": `production_rv32r_over_the_leaf_emulates` executes the same program over the real
leaf, and its `child_cpu_rows` must equal 648 518. Phase 8 has no assertion, so its static and
executed counts agree (asserted).
Logs: `docs/measurements/2026-10-09-tree-rv32r-emulated-leaf-shape-laptop-rate-quarter.log`
(rate ¼; the rate-⅛ run is `…-laptop.log`). Droplet logs:
`docs/measurements/<date>-tree-leaf-l2-production.log`, `…-tree-rv32r-over-leaf-production.log`
(pending).

## 2. The band and the stop rule

Stop rule (spec §5): C ≤ 1 500 000. It **holds** on the emulated C = 648 518, which is 43 % of the
limit (38 % at rate ⅛). The interior step band (M5) is 2C + O ± 15 %, with O the step's overhead, **measured** by
Task 1a at the test profile: **O = −29** (`tree_test.step_overhead`; spec §3 had projected +300;
re-measured at rate ¼, unchanged):

2C − 29 = 1 297 007, so the band is **[1 102 455, 1 491 559]** (`tree_measure.step_band_lo/hi`).
The band is **tier 21 end to end**: tier 20 holds up to 2^20 − 1 = 1 048 575 rows, below the low
end, and tier 21 up to 2 097 151, above the high end. (At rate ⅛ the band [977 893, 1 323 033]
spanned tiers 20 and 21.) R6 pins the root's tier exactly, and the measured step (Task 2) still
decides the pinned tier.
`the_pinned_band_is_the_emulated_childs` holds the pinned band to this formula and to these tiers.

**Why O is negative.** O = (step rows) − 2C, where C is `rv32r`'s rows less its phase 8. The step's
own fixed rows are 511 at the test profile: the preamble 413 (B and the cap hinted, `vk_c`
sponged in-program over the cap, the interface state, the eight binding absorbs), the loop
region 88 (each pass's four public-word absorbs and the back edge) and the final permutation 10.
But 2C also counts, twice, rows the loop body does not run: `rv32r`'s baked cap (sixteen
constants and stores, 32 rows) and its binding read (16 rows) sit in its phases 0–4, which are
135 rows more over two children (96 of them these, the rest allocation); and the body's register allocation differs from the straight-line `rv32r`'s
(phase 5 +108, the queries −512 over two children). Net: 511 − 135 + 108 − 512 = −28 ≈ −29 (the
phase split of the first rows is approximate by one row). The query term scales with the query
count, so O is profile-dependent; the production step (below) is the number that matters.

**The production step, by the looped walk (laptop, 2026-10-09, nothing proved).** `rv32t_leaf`
built at the emulated production leaf shape of §1 (the step reads only the shape words, so no
leaf key or proof is needed), its rows counted by `tests/tree_measure.rs`'s
`accepting_rows_looped`: the assertion walk of §1 extended through the counted loop's back edge
(taken once) and `absorb_staged`'s branch, whose outcome is the absorb schedule's alone
(`the_looped_walk_counts_what_rv32t_executes` holds it to the emulator over two real toy
proofs, in total and per phase).

| run | rows | tier | program | canonical reduce height (n = 2) |
|---|---:|---:|---:|---:|
| `rv32t_leaf` at the production leaf shape, **counted** | **1 294 577** | 21 | 661 936 instrs | 2^19 |

That is 2C − 2 459: **inside the band** (−0.19 % from its centre; at rate ⅛ it was 1 148 417 =
2C − 2 075). Its phases: preamble 415, phases 0–4 1 703, phase 5 41 678, phase 6 preamble
194 350, query reads 121 432, queries 934 900, loop region 88, final permutation 10. Against
2 × `rv32r`'s: the queries are 2 944 rows fewer (the body's allocation, 32 per query, was 2 560
at 80 queries), phases 0–4 135 fewer, phase 5 108 more. Pinned as
`tree_measure.step_cpu_rows_emulated` / `step_tier_emulated`; Task 2's proved step replaces it.
Log: `docs/measurements/2026-10-09-tree-rv32t-emulated-leaf-shape-laptop-rate-quarter.log`
(rate ¼; the rate-⅛ run is `…-laptop.log`).

**Tiers at rate ¼, all measured by emulation or the walk:** the production leaf 1 171 511 rows,
tier 21; `rv32r` over it 648 910, tier 20 (the child C 648 518); the production step 1 294 577,
tier 21 — under tier 22's floor (2 097 152) by 802 575 rows.

Memory, projected: the `rv32r` peak × (step cells / `rv32r` cells) by docs/06 §3's cell weights.
This is *pending* the droplet's `rv32r` peak (Step 8), and Task 2 replaces it.

## 3. The production tree, per step (Task 2)

## 4. The interior step against the band, the fixed point, the genesis values (Task 2)

## 5. The test-profile tree (Tasks 1a, 1b)

**Task 1a (laptop, 2026-10-09): the step by emulation over real leaves.** Four test-profile
leaves (`rv32n` over bundle fixtures k = 0..3, L = 1, `TEST_BINDING`) were proved here, one at a
time, and cached as `$RECURSION_FIXTURES/tree/Test-leaf-{0..3}.rvmproof`. `rv32t_leaf` was then
*executed* (never proved) over leaves 0 and 1, and `rv32r` over leaf 0 for C.

| | value |
|---|---|
| C (`rv32r` over leaf 0, less phase 8 389) | **143 568** rows (144 829 at rate ⅛) |
| `rv32t_leaf` over leaves 0, 1 | **287 107** rows, **tier 19** (289 629 at rate ⅛) |
| O = rows − 2C | **−29** (fixed rows 511; see §2; unchanged by rate ¼) |
| `rv32t_leaf` program | 146 204 instrs; digest `2c586636…206ccd34` (`tests/tree.rs`; `bf80794d…ff4d5389` at rate ⅛) |
| canonical reduce height | `verify_n(program, proof, 2)`'s equals `build_traces`' (asserted) |

Pins: `tree_test.{child_cpu_rows 143 568, step_leaf_cpu_rows 287 107, step_overhead −29,
step_leaf_tier 19}`. Log: `docs/measurements/2026-10-09-tree-rv32t-test-profile-laptop-rate-quarter.log`
(rate ¼; the rate-⅛ run is `…-laptop.log`). The four test leaves were re-proved at rate ¼.

**Memory (docs/07 §4's table, rate ¼):** tier 18 = 15.64 GB live, measured (26.88 GB at rate ⅛);
tier 19 ≈ 30 GB, projected (≈ 52 GB at rate ⅛), and the test N = 2 aggregate, a tier-19 proof,
has been proved on this 48 GB box. Task 1b was planned for the 256 GB droplet when tier 19 was
past the laptop (R7); at rate ¼ the test-profile step may fit here, which Task 1b should measure
rather than assume.

## 6. The chain (Tasks 3a, 3b)

## 7. What moved, and the suite (Task 4)
