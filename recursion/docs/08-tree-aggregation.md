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

**Pending (droplet).** The API landed on the laptop (tree Task 2, `verify_tree`, `prove_tree_step`,
`aggregate_tree`, `TreeShapes`/`TreeKeys` as per-level lists, spec §4.1 R2–R4); nothing at
production has been proved yet. At the rVM's rate ¼, docs/07 §4 projects a tier-21 proof at
≈ 122–197 GB, so the three remaining leaves, both `rv32t_leaf` steps (1 294 577 rows emulated,
tier 21, band [1 102 455, 1 491 559]) and the `rv32t_int` root all run on the **256 GB droplet**,
one proving process at a time (not the 503 GB box the plan named). The table below gets one row
per proof (4 leaves, 2 steps, 1 root): host, rows, tier, the heights, prove, verify, proof bytes,
peak live and maximum RSS, and the log path.

Run, on `$HOST256` (`/root/scripts/step.sh` as in Task 0; each under `nohup … &` with a `.done`
poll if the session cannot stay open):

```bash
H=$HOST256
ssh -A root@$H 'cd /root/circuits && git fetch origin && git checkout --detach origin/feat/tree-aggregation && git rev-parse HEAD > COMMIT'
rsync -a $RECURSION_FIXTURES/Production-{0,1,2,3,4,5,6,7}.proof root@$H:/root/recursion-fixtures/
rsync -a $RECURSION_FIXTURES/tree/Production-leaf-0.rvmproof root@$H:/root/recursion-fixtures/tree/
for k in 1 2 3; do ssh root@$H "TREE_LEAF=$k RAYON_NUM_THREADS=32 /root/scripts/step.sh 40-tree-leaf-$k cargo test --release --features parallel --test tree_measure production_tree_leaf -- --ignored --exact --nocapture"; done
for k in 0 1; do ssh root@$H "TREE_STEP=$k RAYON_NUM_THREADS=32 /root/scripts/step.sh 41-tree-step-$k cargo test --release --features parallel --test tree_measure production_tree_step -- --ignored --exact --nocapture"; done
ssh root@$H 'RAYON_NUM_THREADS=32 /root/scripts/step.sh 42-tree-root cargo test --release --features parallel --test tree_measure production_tree_root -- --ignored --exact --nocapture'
ssh root@$H '/root/scripts/step.sh 43-tree-genesis cargo test --release --test tree_measure production_tree_genesis_values -- --ignored --exact --nocapture'
for n in 40-tree-leaf-1 40-tree-leaf-2 40-tree-leaf-3 41-tree-step-0 41-tree-step-1 42-tree-root 43-tree-genesis; do scp root@$H:/root/out/$n.log docs/measurements/$(date -u +%F)-tree-${n#4?-tree-}-production.log; done
rsync -a root@$H:/root/recursion-fixtures/tree/ $RECURSION_FIXTURES/tree/
```

Expected: every `.done` holds `0`; `41-tree-step-0` prints `== step 0 emulated: … band [1102455,
1491559] IN`; `42-tree-root` prints `verify_tree … s` and the fixed-point verdict. **Stop** if a
step or the root is killed for memory: record the `.rss` file's last line here and halt for a
decision (spec ruling 1: the memory track first).

## 4. The interior step against the band, the fixed point, the genesis values (Task 2)

**Pending (droplet).** To be filled from `41-tree-step-*`, `42-tree-root` and `43-tree-genesis`:
the step against the band (in or out, and the correction if out); the root against the step
(`rv32t_int` vs `rv32t_leaf` rows); the fixed-point verdict and the production list length
(`production_step_list`: 2 when `rv32t_int`'s proofs declare S_1's words, 3 when level 3, emulated
at the root's shape over (root, root), repeats S_2 — Task 1b's test-profile method — else ≥ 4 and
`max_depth` 3 until a level-3 step is proved); and the genesis values verbatim: the
`aggregate_program_digest` line, then the `aggregation_tree` section as the exact JSON the node's
`TreeConfig` deserializes, ready for `rand-node genesis --aggregation-tree TREE.JSON` (`shape`,
`leaf_size`, `max_depth`, `leaf`, `vk_leaf`, and `steps[k] = {heights, program_digest, key}` — the
spec's `step_tiers[k]` is `steps[k].heights.tier`, `step_digests[k]` is
`steps[k].program_digest`, `step_keys[k]` is `steps[k].key`; every digest four canonical u64
limbs, the last entry repeating). The test tree's own section is `tests/tree-test-genesis.json`,
held by `the_test_tree_genesis_section_prints_as_the_nodes_tree_config`. Then the
`tree_measure` pins (`step_cpu_rows`, `step_tier`, `step_peak_live_mb`, `step_prove_s`,
`step_proof_bytes`, `root_cpu_rows`, `root_tier`, `root_peak_live_mb`, `root_prove_s`,
`root_proof_bytes`, `verify_tree_ms`) and the plan's Step 7 row-pin test.

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
tier 19 ≈ 30 GB, projected (≈ 52 GB at rate ⅛). Task 1b was planned for the 256 GB droplet when
tier 19 was past the laptop (R7); at rate ¼ it is not, and Task 1b proved the whole test tree on
this 48 GB laptop (below).

**Task 1b (this 48 GB laptop, 16 cores, 2026-10-09): the depth-2 test tree, proved.** Eight proofs,
one proving process at a time, cached as `$RECURSION_FIXTURES/tree/Test-*.rvmproof` (git-ignored;
`generate_test_tree_fixtures` proves whatever `tree/` lacks, and the suite never proves a step).

| proof | program | over | rows | tier | heights reg/ram/p2/reduce | bytes | max RSS (process, measured) | process wall (log) |
|---|---|---|---|---|---|---|---|---|
| leaf-0..3 | `rv32n`, L = 1 | bundle fixtures 0–3 | 169 640 | 18 | 19/19/14/16 | 262 377–264 907 | (Task 1a; 15.64 GB live, docs/07) | (Task 1a) |
| step-0, step-1 | `rv32t_leaf` | leaves 0–1, 2–3 | 287 107 | 19 | 20/20/15/16 | 280 133, 280 772 | **34.35 GB** (step-1 alone) | 177 s (step-1 alone) |
| root | `rv32t_int` | step-0, step-1 | 306 985 | 19 | 20/20/15/17 | 283 172 | **33.21 GB** (alone) | 182 s (alone) |
| foreign-0 | leaf program + one `HALT` (R5) | bundle fixture 0 | 169 640 | 18 | 19/19/14/16 | 264 267 | **21.39 GB** (alone) | 114 s (alone) |

The generator's first run proved step-0, step-1, the root and the foreign leaf in one process:
513 s wall, **34.11 GB** maximum RSS (`/usr/bin/time -l`). Each kind's own peak was then measured
by deleting only that file and re-running the generator (so the process proves that proof alone,
plus loading and verifying the cached rest): step 34.35 GB / 177 s, root 33.21 GB / 182 s, foreign
21.39 GB / 114 s. These are process maximum RSS, not the live-heap profile docs/07 reports
(15.64 GB live for tier 18 vs 21.39 GB RSS here). No swapping beyond the box's background level
(swap used 3.2 → 7.7 GB of compressed swap while other work was running). The generator is not a
profile. Log: `docs/measurements/2026-10-09-tree-test-fixtures-laptop.log`. The root and the foreign
leaf in the cache are the isolation runs' (byte counts above); step-0 is the first run's.

Process wall times include building the programs and loading and verifying the cached rest; the
log has no prove-only times. `rv32t_leaf` 287 107 rows vs `rv32t_int` 306 985 (+19 878): the same
pipeline twice over another child shape. A step child is a tier-19 proof, its traces twice a
tier-18 leaf's height, so each pass of the loop opens longer Merkle paths and folds one bit
further.

Every level publishes exactly the host's `[vk_c ‖ 2 ‖ B ‖ D_a ‖ D_b]` in cover order: `vk_leaf` at
level 1 (both steps), `vk_t_leaf` at level 2 (the root). The child keys are computed by the test
(`RvmKey::of`), never read off `VerifierProgram.key` (a zero placeholder for `rv32t`). A foreign
program's children (R5, second half) pass every in-program check, publish `vk_foreign`, and fail
the recompute with `vk_leaf`.

**The fixed point (R3, amended in fix round 1) is reached at level 3, not level 2.** `rv32t_int`
is built for S_T (an `rv32t_leaf` proof's shape). Its own root declares other header words, and a
third program, `rv32t` at the root's shape S_root, reproduces S_root over (root, root):

| | tier, reg, ram, p2, **reduce**, program, queries | log arities |
|---|---|---|
| S_T (`rv32t_leaf` proof, proved) | 19, 20, 20, 15, **16**, 18, 16 | 1, 1, **2, 1**, 3, 3, 1, 3, 2, 3, 1 |
| S_root (`rv32t_int` proof, proved) | 19, 20, 20, 15, **17**, 18, 16 | 1, 1, **1, 2**, 3, 3, 1, 3, 2, 3, 1 |
| S_fix (`rv32t` at S_root over (root, root), emulated) | 19, 20, 20, 15, **17**, 18, 16 | 1, 1, **1, 2**, 3, 3, 1, 3, 2, 3, 1 |

The cause is the reduce table, whose height is static (`program_rows × 2`, `canonical_reduce_log_height`).
`rv32t_leaf` runs 2 × 32 272 = **64 544** reduce rows, 991 under 2^16 = 65 536. `rv32t_int`'s
children are tier-19 proofs with one more FRI fold bit than a tier-18 leaf, which costs exactly
1 024 reduce rows a pass: 2 × 33 296 = **66 592**, over 2^16, so the table is 2^17. That moves
the distinct degree bits and so the arity schedule. Every other height is unchanged. The level-3
program (2 × 33 328 = 66 656 reduce rows, still 2^17; 306 923 cpu rows, tier 19) declares
S_root again, so the program built for its own proofs is itself: the fixed point.

So the test profile's lists are **3 step programs** (`rv32t_leaf`, `rv32t_int`, `rv32t_fix`) and **4 keys**
(`vk_leaf`, `vk_t_leaf`, `vk_int`, `vk_fix`), the last entry of each repeating for every deeper level.
`max_depth` is not capped by R3. Spec §4.1 R2–R4 and R6 are amended to per-level lists. Two live
tests guard this, both on cached fixtures with no proving (≈ 2.1 GB max RSS for the whole tree binary):
- `the_interior_step_does_not_verify_its_own_output_at_the_test_profile` pins both header-word
  lists and the reduce rows, and checks the tape builder refuses the root as a child of S_T.
- `a_third_step_program_at_the_roots_shape_is_the_fixed_point` emulates the level-3 program over
  (root, root) and sizes its tables with `build_traces`. It checks the method first: the same
  emulation over (step-0, step-1) reproduces the proved root's shape.

The fixed point rests on emulation, not on a proved level-3 step. Production's list length is
decided by the same emulation over Task 2's proved production depth-2 tree.

| digest | value |
|---|---|
| `T_LEAF_TEST` (`rv32t_leaf` at the test leaf shape) | `2c586636c4c0f94cdf13b410154679d995eefad11e27371e0786e89e206ccd34` |
| `T_INT_TEST` (`rv32t_int` at S_T) | `04b1677122526e51c0d278375b0c30ebd37f94ba8a2afed3cd3e019ecdc3c226` |
| `T_FIX_TEST` (`rv32t` at S_root, the fixed point) | `08abf188e201e55d7b494f89394651f3ef10c6ebdfd00f825ce4c7b0795ff396` |
| `vk_leaf` (the test leaf's key; children of level 1) | `188d4b1498d166b041fa080181c893e7e200202ac0ad28e7ab79ef9dd2acfdcb` |
| `vk_t_leaf` (S_T's key; children of level 2) | `6b04244466ffac1c530e8b70b4907c2dedcb2964466a9589234843eab8d8507a` |
| `vk_int` (S_root's key; children of level 3) | `a92a0baa3ae1888f61a35820655f0d6cadf7b2de2ca48a6f434a0c4ca3efbb70` |
| `vk_fix` (S_fix's key; children of levels ≥ 4) | `4203726cfe1113e0ffe095a42dc3e2e7be94c18134327268963a4b43b7e6e355` |
| `vk_foreign` (the foreign leaf's key) | `989ff1e996cd551191590f5603626615e66f1a73e4cc820a111713073815cc2f` |

(Key digests are the four `inner_vk_digest` limbs as canonical u64, 16 hex digits each.)
Pins: `tree_test.{step_int_cpu_rows 306 985, step_int_tier 19, step_leaf_reduce_rows_per_child 32 272,
step_int_reduce_rows_per_child 33 296, step_fix_cpu_rows 306 923, step_proof_bytes_max 290 000}`.
Proof sizes are not pinned exactly: postcard's varint length moves with the ZK randomness (root
280 804 → 283 172 on a re-proof). `step_proof_bytes_max` bounds every step and the root at
290 000 B, about 2.4 % over the largest seen (283 172), and catches a real growth such as more
openings or a wider table. The test prints the actual sizes.

## 6. The chain (Tasks 3a, 3b)

Fullnode branch `feat/tree-aggregation` (`~/rand-worktrees/fullnode-tree`), not pushed: `2d002ee5`
and `202a8b10` (Task 3a, core), `bf888100` (the re-vendor of circuits `92b750e`), `153c7204` and
`43d0687f` (Task 3b, node). The rules as built are fullnode `docs/aggregation.md` §3.8; this is
their summary, and the per-level wording is the spec's §4.1.

- **Genesis section.** `aggregation_tree` (beside `aggregation`, which it requires): `shape`,
  `leaf_size` L, `max_depth`, the leaf's heights and `vk_leaf`, and a per-level `steps` list
  (`steps[k-1]` is level k: its heights and tier, program digest, the key digest of its proofs).
  The last entry repeats for deeper levels, sound only at a fixed point. Bounds: 1 <= L <= 5,
  1 <= `max_depth` <= 8, a non-empty list no longer than `max_depth`, an admitted shape, no zero
  pin. The genesis hash appends `"aggregation_tree" || bincode(section)` after `multisig`, only
  when present; a genesis without it hashes as before.
- **Layout.** `Action::Aggregate` carries `layout: flat | tree` (a trailing 4-byte enum index;
  `serde(default)` flat). A tree covers exactly L * 2^d bundles, 1 <= d <= `max_depth`; another
  count is `TreeLayout` / `TreeDepth`, refused at preflight before the register is read. The cap
  is the layout's: flat is bounded by `max_covers`, a tree by L * 2^`max_depth`.
- **Signing domains.** `rand-aggregate-tree-1` (the ChainId form) and `rand-aggregate-tree-2` (the
  genesis-bound form): the flat preimage under another tag, so flipping the layout is
  `BadSignature`.
- **Admission.** 6t (a section for the covered shape, and the count is a tree), 7a (the root's
  declared tier equals the tier pinned for level d, `TreeTier`), 7b (the executor rebuilds the
  leaf and every listed step; the root's program is level d's digest, then `vk_leaf` and each
  step key the recompute uses are the pins; `TreeKeyPin { level }` is numbered by the consuming
  level), 8 (the executor's `verify_tree`: first the root's other four declared heights against
  level d's pins, off the header (`aggregate_header_tree`), then the bottom-up recompute under the
  chain's one binding, compared with the root's four public values, then `verify_n(root program,
  root, 2)`).
- **ZKQ-5, implemented.** The tie is the recompute (docs/02 ZKQ-5), not an in-program equality:
  a root with any level made under another binding is `TreeRootDigest`.
- **Errors**: `TreeNotAdmitted`, `TreeLayout`, `TreeDepth`, `TreeTier`, `TreeKeyPin`,
  `CoveredPublicValues`, `TreeRootDigest`; all but `TreeKeyPin` are permanent verdicts in the
  admission refusal cache.
- **Startup.** A node with the section rebuilds it and compares every listed level's program
  digest and key and `vk_leaf` before opening its store (`aggregation_tree pins: ok`, else
  `refusing to start`). It also refuses a section the rVM cannot serve: L past the shape's N
  ceiling, a non-canonical pinned reduce height, or `max_depth` past the list when the last entry
  is not a fixed point. `rand-node genesis --aggregation-tree <TREE.JSON>` runs the same check
  before writing. `rand-node aggregate --layout tree` proves one whole tree per pass.
- **Test-profile values on the chain side.** The node's rebuilt digests and keys over docs/08 §5's
  heights equal this crate's `pins.json` (`the_rebuilt_test_tree_keys_are_the_circuits_pins`).
- **Pending.** The production section's values (§3-§4) and the cluster run. The cluster run is
  blocked by the existing startup refusal of any `aggregation` genesis (fullnode
  `docs/aggregation.md`, "Before enabling aggregation").

## 7. What moved, and the suite (Task 4)

| what | change |
|---|---|
| `src/programs/rv32t.rs` (new) | `verify_rv32t`, `rv32t_leaf`, `rv32t_int`, `tree_step_program_digest`, `TREE_ARITY = 2`: the 2-to-1 step over a compile-time child shape, the child key a published tape value |
| `src/programs/rv32.rs` | `emit_proof` is now `emit_proof_with(b, shape, cap_closure)`; `emit_proof` calls it with the constant cap. Task 1a's step 3 confirmed the split moved nothing (every existing digest unchanged) |
| `src/aggregate.rs` | `verify_tree`, `tree_root_digest`, `prove_tree_step`, `aggregate_tree`, `TreeKeys { vk_leaf, step_keys }`, `TreeShapes { leaf, steps }`; `VerifyTreeError`, `AggregateError::{TreeLayout, TreeShape}` |
| `src/shape.rs` | `RvmHeights`, `RvmShape::{heights, try_of_heights, same_step_words}`, `ShapeError::EmptyTreeSteps` |
| `src/public_values.rs`, `src/witness.rs` | `tree_step_words` (21 words); `WitnessTape::build_tree_step`, `TREE_TAPE_PREAMBLE = 24` |
| `tests/tree.rs`, `tests/tree_measure.rs` (new) | the in-suite tree tests over the cached test tree; the ignored production runs |
| `tests/pins.json` | new blocks `tree_measure` (emulated production rows, band) and `tree_test` (test-profile rows, tiers, `vk_*` limbs) |
| new test-profile digests | `T_LEAF_TEST` `2c586636...206ccd34`, `T_INT_TEST` `04b16771...ecdc3c226`, `T_FIX_TEST` `08abf188...4795ff396` (§5), and `vk_leaf`, `vk_t_leaf`, `vk_int`, `vk_fix`, `vk_foreign` |
| production digests, genesis values | pending (256 GB droplet): the per-level `step_digests[k]`, `step_keys[k]`, `step_tiers[k]`, `aggregate_program_digest`, `leaf_size`, the leaf heights and `vk_leaf`, as printed by `production_tree_genesis_values` (the section as `TreeConfig` JSON) |
| no opcode, AIR or key-shape change | the ISA stays at 30 instructions; the machine's AIRs, the flat `aggregate_program_digest` and `RvmKey`/`InnerKey` shapes are untouched |
| docs | docs/08 (this file); docs/02 ZKQ-5 and API; docs/03; `research/AGENTS.md` |

**The suite.** `cargo test --release` in `recursion/` (one process, no proving tests, no
generator; the tree tests read the cached test-tree fixtures): **323 passed, 0 failed, 31 ignored** across 32 test binaries
(HEAD `92b750e` plus these docs; the ignored are the droplet-class proofs, the generator and the
production runs). Task R's run before the tree API was 310 passed, 26 ignored; Task 2's 322 passed,
31 ignored.

## 8. Conclusion: the gate

**Circuits half: met at the test profile, pending at production.**
- The stop rule held: C = 648 518 emulated (43 % of the 1 500 000 limit), the production step
  1 294 577 rows emulated, inside its band [1 102 455, 1 491 559], tier 21 (§1-§2).
- The whole test tree was proved on this 48 GB laptop: 4 leaves (tier 18), 2 `rv32t_leaf` steps
  (287 107 rows, tier 19, 34.35 GB max RSS), the `rv32t_int` root (306 985 rows, tier 19,
  33.21 GB), and `verify_tree` accepts the root over the 4 bundles' public values (§5). Every
  refusal named in the spec (swapped pair, swapped subtrees, another binding, wrong level key,
  foreign program, short or aliased run) is refused in-suite (the foreign case through the
  recompute, with an emulated foreign step's public values on a real step proof; no foreign step was proved).
- The fixed point holds at the test profile at level 3 (3 step programs, 4 keys), by emulation,
  not by a proved level-3 step. Production's list length is decided by the same emulation over
  the proved production depth-2 tree (not run).
- Not run: the production tree (3 more leaves, 2 `rv32t_leaf` steps, the `rv32t_int` root;
  §3). Every production row, tier, peak and genesis value above is pending the 256 GB droplet
  (`tests/tree_measure.rs`: `production_tree_leaf`, `production_tree_step`, `production_tree_root`,
  `production_tree_genesis_values`, commands in §3).

**Chain half: implemented and tested, production pending.** `verify_tree` is wired into
admission, startup pin check, genesis tooling and the aggregator daemon (§6). The node-side
production check is the ignored `agg_executor::tests::production_tree` (fullnode, 8 bundles
`Production-0..7`; run on the 256 GB host after the circuits `production_tree_*` runs). The
cluster run is blocked by the pre-existing startup refusal of any aggregation genesis.

**Host classes.** At rate 1/4 (docs/07 §4) a tier-21 proof projects at 122-197 GB, so the
production leaves, steps and root run on the **256 GB** class, one proving process at a time
(the 503 GB box a fallback). The test tree needs 34 GB (tier 19, measured), within 48 GB.

**Next lever.** The memory track (spec ruling 1), not the row count: a tier-21 step at 122-197 GB
projected against the 64 GB target.
