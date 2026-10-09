# Tree aggregation — bounded steps over rVM proofs: a leaf of L bundle proofs, 2-to-1 interior steps, and a chain that recomputes every level

Status: design, approved in conversation 2026-10-08. Base: circuits `main` 9bf3844 (rVM phase 3 merged at 3316e11); fullnode `main` for the chain side (the phase-3 re-vendor is a prerequisite, see §7).
Prior: `docs/superpowers/specs/2026-10-05-rvm-phase3-fold-reduce-design.md`; the record `recursion/docs/06-phase3-fold-reduce.md`; `recursion/docs/02-aggregate.md` §ZKQ-5; `recursion/docs/03-gpu-and-self-recursion.md` (the self-verifier `rv32r`).

This is sub-project 2 of the recursion critical path: chips (phase 3, done) → **tree aggregation with bounded steps** → the leaf covering the auth proof (sub-project 3). It is designed against the hosts that exist (a 256 GB and a 503 GB droplet), not against the 64 GB figure of `fullnode/docs/compute-optimization.md` §4.4; that figure moves to the memory track (§8). Every number marked *projected* is derived from docs/06's cell model and is replaced by Task 0's measurement before a program is built.

## 1. What exists and what the numbers say

| fact | value | source |
|---|---|---|
| one production inner (bundle) proof verified | 585 686 cpu rows, tier 20; memory tables 2^21 | docs/06 |
| flat aggregate `rv32n` at production N | rows 409 + 585 551·N; N=1 tier 20, N=2–3 tier 21, N=4–5 tier 22; **N ≤ 5** (reduce-chip ceiling at `REDUCE_MAX_LOG_HEIGHT` 20) | docs/06 §3, §5 |
| projected peak memory, production | N=1 110–130 GB; N=2 210–245 GB; N=3 290–340 GB; N=4–5 410–490 GB | docs/06 §3 (*projected*) |
| measured memory | tier-18 test twin 26.88 GB live | docs/06 §3 |
| self-verifier `rv32r` | straight-line, verifies ONE rVM proof of a compile-time `RvmShape`; the child's key cap is baked as constants (`constant_cap`); interface `[rvm_vk(4) ‖ 1 ‖ B(8) ‖ D_in(4)]`; measured only at toy/busy test shapes (101 460 / 127 322 rows); never run over a real verifier proof | `src/programs/rv32r.rs`, `tests/self_verify.rs` |
| a verified rVM proof, derived | 0.85–1.45 M cpu rows per child; a 2-child step 1.7–2.9 M rows → tier 21–22; memory like production N=3–5 (290–500 GB) | §B of the 2026-10-06 research (*projected*) |
| chain admission today | one `AdmittedShape { shape, hc, aggregate_program_digest }`; `validate_aggregate` recomputes the flat list from the covered bundles and the chain's binding B, then `verify_aggregate` (which asserts the flat list length) | `fullnode/crates/randprotocol-core/src/ledger/aggregation.rs` |
| ZKQ-5 (decided 2026-09-28) | no in-program `B_out == B_in`; the chain recomputes every level's digest bottom-up | docs/02 |
| hosts | 48 GB laptop (test twin only); `m-32vcpu-256gb` (production N=1–2 by projection); 503 GB 64-vCPU droplet (N=3–5 by projection); no GPU node in the fleet | node-hardware.md |

Two consequences fix the design. (1) **The circular key**: a program that verifies proofs of itself would embed its own commitment; so the child's key enters as a tape value that the program publishes and the chain checks (§3), and the child's *shape* stays a compile-time constant. (2) **Shapes are deterministic only for fixed workloads**: declared heights come from the workload, so one program over inputs of one fixed shape always declares the same shape. That forces the layout rule of §2.

## 2. The tree

- **Leaf**: the existing `rv32n` over exactly **L** bundle proofs; L is a genesis constant (production **L = 2**: tier 21, 210–245 GB *projected*, the 256 GB class; test profile L = 1 for the laptop). Leaf list `[inner_vk(4) ‖ L ‖ B(8) ‖ 35·L]` as today.
- **Interior step**: a new program family `rv32t` verifies exactly **two** child rVM proofs of one compile-time child shape and emits one rVM proof. Two instantiations: `rv32t_leaf` (child = the leaf shape at L) and `rv32t_int` (child = `rv32t`'s own output shape, the same at every level ≥ 2 because the workload is fixed).
- **Layout rule**: a tree aggregate covers exactly **L·2^d** bundles, d ≥ 1, leaves filled left to right in cover order, fan-out 2, a complete binary tree. No lone-node promotion and no padding proofs: a count that is not L·2^d is not a tree and takes today's flat path (n ≤ 5), which is unchanged. `max_depth` is a genesis constant; `max_covers = L·2^max_depth`.
- **Depth sizing (derived)**: production L = 2, depth 3 covers 16 bundles with 8 leaves, 4 + 2 + 1 interior steps = 15 proofs per aggregate; at ~7 transfers per 20 MiB block an aggregate of 16 covers spans a few blocks.

## 3. The `rv32t` program (circuits)

Tape: `[B(8) ‖ cap_c(16) ‖ region(child 1) ‖ region(child 2)]` built by a new `WitnessTape::build_tree_step`.

Program body, in order (all under Task 0's spans so the bands key on them):
1. `B` hinted into cells (as `rv32r` does); `cap_c` hinted with `read_cap` (16 tape words, 32 rows).
2. `vk_c = H(RVM_VK_DOMAIN ‖ shape_words(S_c) ‖ cap_c)` computed **in-program** over the hinted cap, `shape_words` as compile-time constants (today `vk_digest_in_program` stores the whole digest as constants; this moves the sponge in-program so the published key binds the cap the proofs were checked against).
3. Child i ∈ {1, 2}: `emit_proof(S_c, cap_c)` with a fresh challenger (the `rv32n` loop body, specialised to `RvmShape`), its 4 public words `D_i` absorbed. Checkpoint names `"tree child[i] …"` per refusal step.
4. Publish the interface list `[vk_c(4) ‖ 2 ‖ B(8) ‖ D_1(4) ‖ D_2(4)]` = 21 words, sponged under `RVM_PUB_DOMAIN` with the count in the capacity lane, as `rv32r` does; the 4 output words are the digest.

Rules: no `B_out == B_in` in-program (ZKQ-5); a hinted cap is bound only through the published `vk_c`; the two children are verified in tape order and `D_1`, `D_2` are published in that order (the chain recomputes in cover order). `rv32r` stays as the k = 1 program with its tests; `rv32t` reuses its tape builder.

Cost (*projected*): 2 × (0.85–1.45 M) + ~300 rows → 1.7–2.9 M cpu rows, tier 21 or 22; reduce chip ~250–320 k run rows at canonical height 2^19 (`verify_n(program, proof, 2)`); memory 290–500 GB, i.e. the 503 GB class. Task 0 replaces these.

## 4. The chain (fullnode)

- **Action**: `Aggregate` gains `layout: Flat | Tree`. Flat keeps every rule as today. Tree requires `covers.len() == L·2^d`, 1 ≤ d ≤ max_depth.
- **Genesis pins** (under the admitted shape; §4.1 R2–R4 and R6 make the step digests, keys and tier per-level lists whose last entry repeats): `tree { leaf_size: L, max_depth, t_leaf_digest, t_int_digest, vk_leaf: [u64;4], vk_int: [u64;4] }`. `vk_leaf` is the key digest of `rv32n` at the leaf shape (L), `vk_int` that of `rv32t` at the interior shape; the node rebuilds both at startup (`warm_aggregation`) and refuses to start on a mismatch. The leaf's own program digest is today's `aggregate_program_digest`.
- **Recompute (ZKQ-5, bottom-up)**: leaf i: the flat list over its L bundles' public values with the chain's B → `D_leaf_i` (the existing `interface_words_bound`); level 1: `[vk_leaf ‖ 2 ‖ B ‖ D_a ‖ D_b]` → D; level j ≥ 2: `[vk_int ‖ 2 ‖ B ‖ D_a ‖ D_b]`; the root digest must equal the root proof's four public words. A wrong hinted cap publishes a different `vk_c` and fails at the root; a wrong B at any level fails at the root. Steps 4 (count), 6 (shape equality), 7 (`HC == hc` per cover) and 7a (tier gate on the **root's** tier, AGG-3) apply unchanged; 7b (AGG-6) checks the root program's digest (`t_int_digest`, or `t_leaf_digest` when d = 1) and the pinned key digests; step 8 becomes `verify_tree`.
- **`verify_tree`** (circuits `src/aggregate.rs`): takes the root program, the proof, the covered public values, B, L, d and the two pinned key digests; recomputes the root digest; then `verify_n(program, proof, 2)` so the canonical reduce-height rule holds for interior steps. Flat `verify_aggregate` is unchanged.
- **Errors**: `TreeLayout { covers, leaf_size }`, `TreeDepth`, `TreeKeyPin { level }`, `TreeRootDigest`, `TreeTier`; in-program refusals keep their checkpoint names.
- **Docs**: `fullnode/docs/aggregation.md` gains the tree rules (AGG-6 per level, AGG-3 on the root, the layout rule, the recompute) and drops "ZKQ-5: decide before trees ship"; `compute-optimization.md` §4.2–§4.4 is corrected (§8).

## 4.1 Resolutions made while planning (binding; they correct §2–§4 where they differ)

The plan (`docs/superpowers/plans/2026-10-08-tree-aggregation.md`, "Design resolutions" R1–R10) found these, and they govern:

- **R1** — `rv32t` is `rv32n`'s counted loop with the constant count 2, not two straight-line emissions, so `verify_n(program, proof, 2)`'s canonical reduce height (static rows × n) is exact. Per-child refusal names are dropped; tamper tests identify the child by the region they corrupt.
- **R2** (amended by R3, tree Task 1b fix round 1) — the pinned key digests are a per-level list, not two: `vk_leaf` (children of level 1), then the key of each level's step proofs (children of the next level), the **last entry repeating** for every deeper level. At the test profile that is four keys: `vk_leaf`, `vk_t_leaf` (children of level 2), `vk_int` (the key of a level-2 step's proofs, children of level 3), and `vk_fix` (the fixed-point program's own proofs, children of levels ≥ 4). Production's list length is decided by emulation over Task 2's proved production depth-2 tree.
- **R3** (amended, tree Task 1b fix round 1) — the step program is a per-level list whose **last entry repeats** (the fixed point): level k's program is `rv32t` at the declared shape of level k − 1's proofs, iterated until a program's own proofs declare the shape it was built for; that program serves every deeper level. "One `rv32t_int` for every level ≥ 2" is the special case of a list of length 2. At the test profile it is not: `rv32t_int` (built for S_T) crosses the reduce table from 2^16 to 2^17 (2 × 32 272 = 64 544 rows vs 2 × 33 296 = 66 592), so its proofs declare S_root ≠ S_T; a third program at S_root reproduces S_root over (root, root) (emulated, `a_third_step_program_at_the_roots_shape_is_the_fixed_point`). The test profile's lists are **3 step programs and 4 keys** (R2), and `max_depth` is not capped by R3. Production's list length is decided by emulation over Task 2's proved production depth-2 tree (docs/08 §5).
- **R4** — the genesis carries the leaf and per-level step heights (R3's list) in a top-level `aggregation_tree` section naming its admitted shape, so the node can rebuild every program and key on the lists; existing genesis hashes do not move.
- **R5** — the wrong-cap tamper is two tests: with honest children it is refused in-program (`quotient identity[0]`); with children of a foreign program of identical shape it is refused only at the root recompute.
- **R6** (amended by R3) — the step tier pin is a per-level list whose last entry repeats: the root's tier must equal the pinned tier for the root's level exactly (`TreeTier`); the flat path keeps `admitted_tiers`.
- **R7** — the test-profile steps are tier 19. Projected at ≈ 52 GB at rate ⅛, they were planned for the 256 GB droplet; at rate ¼ they were proved on the 48 GB laptop (34.35 GB max RSS a step, 33.21 GB the root, docs/08 §5) and are cached for the in-suite tests, which never prove a step.
- **R8** — a `Tree` aggregate is signed under a new domain `rand-aggregate-tree-1`; `Flat` signing is byte-identical to today.
- **R9** — errors: a root-program digest mismatch reuses `AggregateProgramMismatch` (AGG-6); new `TreeNotAdmitted`, `TreeKeyPin { level }`, `TreeLayout`, `TreeDepth`, `TreeRootDigest`, `TreeTier`.
- **R10** — the heap harness moves to `tests/heap/mod.rs`, shared by `memprofile.rs` and `tree_measure.rs`.

## 5. Tasks (one task, one review, one re-pin each) and the gate

0. **Measure first.** Prove one production leaf (L = 2) on the 256 GB droplet; run `rv32r` over it on the 503 GB droplet (the existing k = 1 program, baked cap). Pin: the child verification's rows, tier, live heap and time; the leaf's rows/tier/heap/time/proof bytes. From that, set the band for the interior step (2 × child + overhead, ±15 %). **Stop rule**: if one child verification lands above 1.5 M cpu rows, the k = 2 step exceeds tier 22 and the spec stops for a decision (k = 1 chains, a bigger tier, or the memory track first).
1. **`rv32t`** (circuits): the program, `build_tree_step`, the in-program `vk_c`, the two instantiations, the test-profile end-to-end (L = 1, depth 2, laptop) with the tamper table per level; digests and pins.
2. **`verify_tree`** and the production acceptance run (circuits): one production tree of depth 2 on the droplets, rows/tier/heap/time per step recorded; the interior step measured against Task 0's band.
3. **Chain** (fullnode, after the phase-3 re-vendor): the action field, the genesis pins, the recompute, the admission tests on crafted roots, the devnet runbook with a tree aggregate; docs.
4. **Landing**: the record `recursion/docs/08-tree-aggregation.md`, `docs/02`/`03` updated, the compute-optimization correction, the suite.

**Gate**: a production tree of depth ≥ 2 over real bundle proofs verifies on chain end to end; every step's rows, tier, memory and time measured and pinned; the admission rules written. Not a gate: any memory figure (§8).

## 6. Testing (the repository's discipline, applied)

- Circuits: `tests/tree.rs` — the test-profile tree end to end (prove leaves, `rv32t_leaf`, `rv32t_int`; `verify_tree`); the tamper table (a swapped child digest; a wrong hinted cap — must fail at the root recompute, not in-program; a wrong B; swapped child order; a flat proof presented as a tree; a child of the wrong shape refused by the tape builder); the k = 1 `rv32r` tests kept; digest and shape pins (`tests/pins.json`); `the_reduce_height_is_canonical…` extended to `rv32t`.
- Fullnode: admission tests on crafted roots for every error in §4; the devnet runbook step; the warm-start key-pin check.
- Measurement: every production run on the droplets logged under `recursion/docs/measurements/` as docs/04–06 did; macOS RSS is never used.

## 7. Prerequisites and ordering

- The fullnode re-vendor of phase 3 (`verifier_key(program, tier, reduce_log_height)`, `Program::reduce_layout`, `verify_n`, the N ≤ 5 cap, the new digests — docs/06 §5) lands before Task 3. Tasks 0–2 are circuits-only and do not wait for it.
- The droplets: Task 0 needs the 256 GB and 503 GB classes for a few hours each; the user provisions them.

## 8. Rulings

1. **Design against the hosts that exist; the 64 GB target moves to the memory track** (rVM blowup 3 → 2, register-table height, device-resident GPU). The tree's hard parts (per-level programs, root interface, chain recompute) do not depend on memory. Costs if wrong: a tree whose interior steps need a 503 GB host until the memory track lands.
2. **Key as a tape value, published and chain-checked; shape compile-time** — one `rv32t_int` for every interior level, three digests on chain. The baked-cap alternative (one program per level, fixed depth) and a fixed-point digest were rejected: the first multiplies builds and pins per level and cannot handle a self-shaped child; the second has no known construction. Costs if wrong: one extra sponge per step (~a few hundred rows) and one new chain rule.
3. **Exactly L bundles per leaf and L·2^d leaves; no promotion, no padding** — shapes are workload-deterministic, so mixed-shape parents would need program variants per mix. Smaller sets use the flat path. Costs if wrong: an aggregator must wait for L·2^d covers or use the flat path for the remainder.
4. **Interior fan-out 2** — a k = 2 step is 1.7–2.9 M rows (tier 21–22); k = 4 would be ~3.4–5.8 M (tier 22–23, 2× memory) for one fewer level. Costs if wrong: one more level per doubling of covers.
5. **Task 0 before any program** — no `rv32r` run over a real verifier proof exists; the interior step's tier and host class are unknown until one does. Costs if wrong: a few droplet-hours.
6. **The production L = 2** — N=2 is the largest flat aggregate the 256 GB class holds by projection; L = 4 would push leaves to the 503 GB class. Re-decided when Task 0 measures. Costs if wrong: a genesis constant.
7. **Auth proofs are sub-project 3** — the reduce ceiling makes the production leaf 2 bundle + 2 auth proofs at most; that design is written after this tree verifies on chain.
