# 07 — Tree aggregation: a leaf of L bundle proofs, 2-to-1 interior steps, every level recomputed

Design: `docs/superpowers/specs/2026-10-08-tree-aggregation-design.md`. Plan: `docs/superpowers/plans/2026-10-08-tree-aggregation.md`.

## 1. The child, measured (Task 0, production)

**Laptop, 2026-10-09: the shape, by emulation (nothing proved).** The production L = 2 leaf
(`rv32n` over production fixtures 0 and 1, binding `TEST_BINDING`) was executed and its traces
built with the prover's own height rule (`machine::build_traces`), so every height below is the
one an honest leaf proof declares. `rv32r` was then built for that `RvmShape` with its `RvmKey`
(the preprocessed commit of the program, range and reduce-layout tables: well under 1 GB; the
whole run peaked at 8.31 GB live, most of it the leaf's traces) and its rows **counted, not
executed**. No real leaf proof exists to execute it over: the leaf is a ≈ 210–245 GB proof
(projected) and this host has 48 GB.

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
| `rv32r` at the leaf's shape (k = 1, baked cap), **counted** | laptop | 575 638 | 20 | — (canonical reduce height at n = 1: 18) | — | — | — | — | — |
| leaf: `rv32n`, L = 2 (fixtures 0–1), proved | 256 GB | *pending (Step 6)* | | | | | | | |
| `rv32r` over the leaf (k = 1, baked cap), proved | 503 GB | *pending (Steps 7–8)* | | | | | | | |

The leaf's canonical reduce height at n = 2 is `2^19`, the same as the height `build_traces`
declares (asserted). The leaf's rows and heights equal docs/02's production N = 2 row exactly.
`rv32r`'s program is 588 172 instructions, of which 12 534 are traps. Its rows by phase:
phases 0–4 919, phase 5 20 785, phase 6 preamble 88 514, query tape reads 52 315,
queries 412 712, phase 8 392.

C (the child verification: `rv32r` rows less phase 8) = **575 246, emulated**
(`tree_measure.child_cpu_rows_emulated`). The spec §1 projection was 0.85–1.45 M, so C is
**below** it, at about 0.68 of the projection's low end. The droplet run replaces "emulated" with
"measured": `production_rv32r_over_the_leaf_emulates` executes the same program over the real
leaf, and its `child_cpu_rows` must equal 575 246. Phase 8 has no assertion, so its static and
executed counts agree (asserted).
Logs: `docs/measurements/2026-10-09-tree-rv32r-emulated-leaf-shape-laptop.log`. Droplet logs:
`docs/measurements/<date>-tree-leaf-l2-production.log`, `…-tree-rv32r-over-leaf-production.log`
(pending).

## 2. The band and the stop rule

Stop rule (spec §5): C ≤ 1 500 000. It **held** on the emulated C = 575 246, which is 38 % of the
limit. The interior step band (M5) is 2C + O ± 15 %, with O = 300 projected (Task 1a measures
it at the test profile):

2C + 300 = 1 150 792, so the band is **[978 173, 1 323 411]**, tier 21 (cpu height 2^21; both
ends are inside tier 21). Spec §3 projected 1.7–2.9 M rows at tier 21 or 22, so the step is now
expected at the bottom of that range's tier and not tier 22. For comparison, O's analogue in
`rv32r` is its phase 8 (392 rows: the in-program vk digest and the 17-word interface sponge).
`rv32t` adds the cap read (32 rows) and the in-program `vk_c` sponge to that, and hints B once
where 2C counts it twice (−16). 300 stays the projection until Task 1a measures it.

Memory, projected: the `rv32r` peak × (step cells / `rv32r` cells) by docs/06 §3's cell weights.
This is *pending* the droplet's `rv32r` peak (Step 8), and Task 2 replaces it.

## 3. The production tree, per step (Task 2)

## 4. The interior step against the band, the fixed point, the genesis values (Task 2)

## 5. The test-profile tree (Tasks 1a, 1b)

## 6. The chain (Tasks 3a, 3b)

## 7. What moved, and the suite (Task 4)
