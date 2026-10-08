# Tree Aggregation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make an aggregate a tree with bounded steps. A leaf is today's `rv32n` over exactly L bundle proofs. An interior step is a new program, `rv32t`, that verifies exactly two child rVM proofs of one compile-time child shape. The chain recomputes every level's interface digest bottom-up. The gate: a production tree of depth ≥ 2 over real bundle proofs verifies through the chain's admission code, with every step's rows, tier, live heap and time measured and pinned.

**Architecture:** Task 0 measures before any program is built. It proves one production leaf (L = 2) on the 256 GB droplet, then runs the existing k = 1 self-verifier `rv32r` over it on the 503 GB droplet. That gives the child-verification cost, the interior step's band and the stop rule's verdict. Task 1a builds `rv32t` as `rv32n`'s counted loop with the constant count 2. The child key cap is read off the tape, `vk_c` is computed in-program over that cap, and the 21-word interface is `[vk_c ‖ 2 ‖ B ‖ D_1 ‖ D_2]`. Task 1a checks it by emulation over real test-profile leaves. Task 1b proves a depth-2 test tree and checks the fixed point that lets one `rv32t_int` serve every level ≥ 2. Task 2 adds the chain-facing `verify_tree`, the prover-side `prove_tree_step`/`aggregate_tree` and `TreeShapes`, then runs the production depth-2 tree on the droplets. Tasks 3a and 3b are the fullnode: the `layout` field, the genesis section, the admission branch and the node's executor. Task 4 lands the record.

**Tech Stack:** Rust 1.98.1 (pinned by `recursion/rust-toolchain.toml`), Plonky3 0.7.0 (`p3-*` exact pins; `p3-fri`/`p3-merkle-tree`/`p3-batch-stark` patched from `../vendor/`), and the `recursion` crate's own DSL, emulator and AIR tables. On the fullnode side, `randprotocol-core` and `randprotocol-node`, with the rVM vendored as `crates/randprotocol-rvm`. Tests are `cargo test` with real bundle-proof fixtures.

**Spec:** `docs/superpowers/specs/2026-10-08-tree-aggregation-design.md`. Read it first: §2 is the layout rule, §3 the program, §4 the chain, §5 the tasks, the gate and the stop rule, §6 the testing and §8 the rulings. Until Task 0 measures it, every cost number from spec §1/§3 that appears below is **projected**: child verification 0.85–1.45 M rows, an interior step 1.7–2.9 M rows at tier 21–22 with 290–500 GB, a production L = 2 leaf at 210–245 GB.

## Design resolutions (the spec left these open or got them wrong; the code below follows them)

- **R1 — `rv32t` is a counted loop with the constant count 2, not two straight-line emissions.** Spec §4 verifies the root with `verify_n(program, proof, 2)`. `machine::canonical_reduce_log_height(program, n)` multiplies the *static* reduce rows (`tables::reduce::program_rows`) by `n`, so `n = 2` is only correct when the program text holds one child's pipeline and runs it twice. That is exactly `rv32n`'s loop body (spec §3: "the `rv32n` loop body, specialised to `RvmShape`"). Two straight-line emissions would double `program_rows`, make the canonical `n` equal 1, and double the program table. The cost is that refusal names cannot carry the child's index: the loop emits one body, so a refusal is named by `emit_proof`'s own checkpoints (`"header word 0"`, `"quotient identity[0]"`, …), and the tamper tests identify the child by the region they corrupted. Spec §3's `"tree child[i] …"` names are dropped. The span `"tree child"` still attributes the body's rows.
- **R2 — three key digests, not two.** Spec §4 recomputes level 1 with `vk_leaf` and every level ≥ 2 with `vk_int`. But level 2's children are `rv32t_leaf` proofs and level 3's are `rv32t_int` proofs. Those are two programs, so they have two preprocessed caps and two key digests. Let `S_T` be the step shape. The chain pins `vk_leaf` (= `inner_vk_digest(S_L, cap(rv32n))`, used at level 1), `vk_t_leaf` (= `inner_vk_digest(S_T, cap(rv32t_leaf))`, used at level 2) and `vk_int` (= `inner_vk_digest(S_T, cap(rv32t_int))`, used at levels ≥ 3). `TreeKeys::at_level` is the one place that selects among them.
- **R3 — the fixed point is a measured condition, not an assumption.** `rv32t_int` is `verify_rv32t(S_T)`, where `S_T` is the declared shape of an `rv32t_leaf` proof. It verifies its *own* proofs only if they declare the same shape words: `RvmShape::same_step_words(S_int_out, S_T)`. The two programs' workloads differ (their children differ), so their outputs need not agree. Task 1b checks this at the test profile and Task 2 at production, from the depth-2 root's own header. If it fails on a profile, that profile's `max_depth` is 2: depth 2 needs only `rv32t_leaf` children. The failure is recorded in docs/07, and no third program is added (spec ruling 2's reason).
- **R4 — the genesis carries the leaf and step heights, in a top-level `aggregation_tree` section that names its admitted shape.** The node rebuilds `rv32n`, `rv32t_leaf` and `rv32t_int` and their three keys from `(admitted shape, leaf heights, step heights)`. Without the heights it could not. The section is top-level and appended last to the genesis commitment (`genesis.rs:1535` pattern), so `AggregationConfig`'s bincode bytes — hashed into the genesis — do not move. The spec's "under the admitted shape" is the section's `shape` field, which must equal an `admitted_shapes[i].shape`.
- **R5 — the wrong-cap tamper is two tests.** A wrong hinted cap with *honest* children is refused in-program at `"quotient identity[0]"`, because the transcript observes the cap in phase 2. Children of a *foreign program of identical shape words*, with that program's honest cap, are accepted in-program and publish a different `vk_c`, so the root recompute refuses them. The second is the binding claim spec §6 means by "must fail at the root recompute". The foreign program is the leaf program with one unreachable `HALT` appended: the execution and heights are unchanged, but the digest and cap differ.
- **R6 — `TreeTier` is exact.** An honest root is a fixed workload, so its tier is the pinned `step.tier`. The chain refuses any other tier before building anything (AGG-3's purpose, tightened). The flat path keeps `admitted_tiers`.
- **R7 — the in-suite test tree is cached proofs.** The leaves (tier 18, 26.88 GB live measured — docs/06 §3) prove on the laptop. The steps are *projected* at tier 19 (≈ 52 GB by docs/06 §3's cell model), which is past the 48 GB laptop. They are proved once by an ignored generator on the 256 GB droplet into `$RECURSION_FIXTURES/tree/` and copied back. The in-suite tests load and re-verify the cached files and emulate over them. A missing cache is a loud failure that names the generator.
- **R8 — the layout is signed.** A `Tree` aggregate signs under a new domain (`rand-aggregate-tree-1`). A `Flat` aggregate's signing hash is byte-identical to today's, so every existing vector holds.
- **R9 — errors.** A root-program digest mismatch reuses `AggregateProgramMismatch`, because it is the same rule (AGG-6). A `Tree` layout on a chain without the section, or for another shape, is the new `TreeNotAdmitted`. `TreeKeyPin { level }` (0 = `vk_leaf`, 1 = `vk_t_leaf`, 2 = `vk_int`) is raised at admission's step 7b and by the node's startup check. `TreeRootDigest` travels from the executor as a structured `ConfidentialError::TreeRootDigest`, not as a string.
- **R10 — one heap harness.** The counting allocator and span logger move from `tests/memprofile.rs` to `tests/heap/mod.rs`. `memprofile.rs` and the new `tree_measure.rs` both use it.

## Global Constraints

- Circuits: work in `~/rand-worktrees/circuits-tree` on branch `feat/tree-aggregation` (off `main` 9bf3844, rVM phase 3 merged; the spec is commit c7fd979). Every circuits command runs from `~/rand-worktrees/circuits-tree/recursion`. The crate is its own cargo root and never a workspace member.
- Laptop environment, before any test: `export RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures` and `export CARGO_TARGET_DIR=$HOME/rand-worktrees/circuits-phase2/recursion/target`. Build with `cargo test --release` for anything that proves or emulates the full program.
- **Droplets** (provisioned by the user, spec §7): `$HOST256` is the `m-32vcpu-256gb` droplet (32 vCPU) and `$HOST503` the 503 GB, 64-vCPU droplet. Each runs from a **fresh clone at the branch's commit**: `git push origin feat/tree-aggregation` from the laptop, then `ssh -A root@$HOST 'rm -rf /root/circuits && git clone --branch feat/tree-aggregation git@github.com:dendisuhubdy/zkp-circuits.git /root/circuits && git -C /root/circuits rev-parse HEAD > /root/circuits/COMMIT'`. Confirm that `ssh root@$HOST cat /root/circuits/COMMIT` equals the laptop's `git rev-parse HEAD`. The layout is the 2026-09-30 run's: `/root/recursion-fixtures`, `/root/out`, and `/root/scripts/step.sh` (copied with `rsync -a ~/rand-agg-512-results/scripts/ root@$HOST:/root/scripts/`). `step.sh <name> <cmd…>` logs the command, then `/usr/bin/time -v`, to `/root/out/<name>.log`, samples RSS every 10 s, and writes `<name>.done`. Prove with `--features parallel` and `RAYON_NUM_THREADS` = the box's vCPUs, **one proof per process**, one heavy process per box at a time. The memory number is the live heap (`tests/heap`) and Linux `Maximum resident set size`. **macOS RSS is never a memory number** (docs/04).
- Do not touch `research/`. **Opcodes 0–29 never move.** No AIR, chip, bus or table changes in this plan: `src/tables/`, `src/machine.rs`'s `chips`/`build_traces`/`verify_inner` and `src/isa.rs` are read-only. If a step finds itself editing them, stop. Every shipped digest is unchanged by this plan: `src/programs/verify_rv32.digest`, the aggregate digest pins (`tests/verifier.rs`, `tests/aggregate.rs`), the self-verifier's `e9c9720d…` (`tests/self_verify.rs:142`). Task 1a proves that its refactor moved none of them.
- **AGENTS.md invariants** (`research/AGENTS.md` §"Invariants that have actually been broken here", binding for `recursion/`): (1) every bus message's address and value columns are constrained on every row kind that sends it; (2) every send count is a selector expression. The emulator is the reference semantics. This plan adds no AIR, so it adds no exposure here, and that is why the "read-only" rule above exists.
- **Projected until measured:** every cost from the spec is *projected* until Task 0 (child, leaf) or Task 2 (step, root) measures it. Do not quote a projected number as a result anywhere.
- Fullnode (Tasks 3a, 3b): `~/Github/randprotocol/fullnode`, on a branch `feat/tree-aggregation` cut from `main` **after the phase-3 re-vendor lands**. **fullnode `main` does not carry it today.** Tasks 3a/3b are written against the post-re-vendor API that docs/06 §5 names: `Machine::verifier_key(program, tier, reduce_log_height: u8)`, `Program::reduce_layout`, `Machine::verify_n`, and production N ≤ 5. If the re-vendor has not landed, Task 3 does not start.
- Commit after every task, in the repository's voice (what moved and the measured number). End every commit message with exactly these two lines:
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`
  `Claude-Session: https://claude.ai/code/session_01AUWKAos28PQquiLZRVC6jP`

## The Measure-and-Pin Procedure (every measuring step runs the parts it names)

Every pin below is a *measured* value: run the command, read the value off the output, and write it in.

- **M1 — emulate before proving.** Each production proof's rows and tier are asserted by emulation inside the same test, before `prove` starts. A drift fails in minutes, not in hours of proving.
- **M2 — log.** On a droplet, every run goes through `step.sh`. Copy its log to `recursion/docs/measurements/$(date -u +%F)-tree-<what>.log` with `scp root@$HOST:/root/out/<name>.log recursion/docs/measurements/$(date -u +%F)-tree-<what>.log`. Read off: the `== <what>: <rows> rows, tier <t>, proof <bytes> B, prove <s> s; peak live heap <GB> GB …` line, the `verify <s> s` line, the `== heights:` line, and `/usr/bin/time -v`'s `Maximum resident set size (kbytes)` and `Elapsed (wall clock) time`.
- **M3 — `tests/pins.json` blocks.** `tree_measure` (production; Tasks 0 and 2) and `tree_test` (test profile; Tasks 1a and 1b) are hand-written nested blocks of integers. Write them with an editor and keep the file valid JSON. `common::aggregate_pins()` preserves every nested block across a re-measure (Task 0 makes that generic). `common::pin(block, key)` reads one. Live heap is recorded in MB (`round(GB × 1000)`), times in whole seconds.
- **M4 — digests.** Test-profile program digests are hex literals in `tests/tree.rs` with a history comment, like `tests/self_verify.rs:122-143`. Production digests, keys and heights go in docs/07 §4 as the chain's genesis values.
- **M5 — bands and stops.** The interior step's band (docs/07 §2) is `[0.85·(2C + O), 1.15·(2C + O)]`, where C is Task 0's child rows and O the step overhead (projected 300, measured by Task 1a). Outside the band: write the measured value and the correction into docs/07 §2 and spec §3's cost line, then continue. The band is not a gate. **Stops:** C > 1 500 000 (Task 0, spec §5), and an out-of-memory kill on the 503 GB box (Task 2). Each records the point reached in docs/07 and halts the plan for a decision.
- **M6 — the suite.** `cargo test --release --no-fail-fast -- --skip a_one_proof_aggregate_round_trips --skip two_test_profile_bundle_proofs_aggregate_and_verify_natively 2>&1 | tee target/tree-suite.txt | grep -E '^test result|FAILED'`. Expected: 0 failed.

## Review Focus

Each line names an input or condition that the spec implies but no existing test exercises. The owning task adds the named test.

1. **Children of a foreign program with identical shape words and their own honest cap.** In-program acceptance must coincide with root refusal. Task 1b adds `a_foreign_program_child_pair_passes_in_program_and_fails_the_root_recompute`.
2. **`rv32t_int` over two of its own proofs (level 3),** which only works if the fixed point R3 holds. Task 1b adds `the_interior_step_verifies_its_own_output`.
3. **The hinted cap and the interface sponge in absolute cells, read by both loop iterations.** A tamper in child 2's region must be refused on the second pass exactly as one in child 1's is on the first. Task 1a adds `a_tamper_in_either_child_is_refused_at_the_named_step`.
4. **The per-level key at depth ≥ 3** (R2: `vk_leaf`, then `vk_t_leaf`, then `vk_int`). No proof of depth 3 exists. Task 2 adds `verify_tree_selects_vk_leaf_vk_t_leaf_vk_int_by_level`.
5. **The layout boundaries on chain:** `L·2^max_depth` admitted, `L·2^(max_depth+1)` → `TreeDepth`, `L·2^d ± 1` and `L` itself → `TreeLayout`, and `Tree` on a chain without the section → `TreeNotAdmitted`. Task 3a adds `tree_layout_boundaries_are_named`.

---

### Task 0: Measure first — one production leaf, and `rv32r` over it

No `rv32r` run over a real verifier proof exists (spec ruling 5). This task produces one. It measures the child verification C, sets the interior step's band, and applies the stop rule. Two droplets, a few hours each.

**Files:**
- Create: `tests/heap/mod.rs`, moved verbatim from `tests/memprofile.rs:32-191` (`Counting`, `LIVE`, `PEAK`, `bump`, the `#[global_allocator]`, `gb`, `rss_gb`, `Spans` and its `Subscriber` impl, `install`, `report`), with `pub` added to `LIVE`, `PEAK`, `gb`, `rss_gb`, `install` and `report`
- Modify: `tests/memprofile.rs` (the moved block becomes `mod heap; use heap::*;`; the runs from `:193` on are unchanged)
- Create: `tests/tree_measure.rs`
- Modify: `src/shape.rs` (`RvmShape::of_proof`, after `RvmShape::try_of` ends at `:997`)
- Modify: `tests/common/mod.rs` (`aggregate_pins` keeps every nested block, `:249-271`; new `pin_block`, `pin`)
- Modify: `tests/pins.json` (the `tree_measure` block)
- Create: `docs/07-tree-aggregation.md` (the skeleton; §1–§2 filled), and two logs under `docs/measurements/`

**Interfaces:**
- Produces: `RvmShape::of_proof(profile: FriProfile, program: &Arc<isa::Program>, proof: &machine::Proof) -> RvmShape`.
- Produces: `common::pin_block(name: &str) -> Vec<(String, usize)>` and `common::pin(block: &str, key: &str) -> usize`.
- Produces: `tests/heap`'s `pub fn install() -> Instant` and `pub fn report(what: &str, t0: Instant, rows: usize, tier: recursion::machine::Tier, proof_bytes: usize, prove_s: f64)`.
- Produces: the file `$RECURSION_FIXTURES/tree/Production-leaf-0.rvmproof` (postcard `recursion::machine::Proof`, `rv32n` over production fixtures 0 and 1, binding `common::TEST_BINDING`).
- Produces: pins `tree_measure.{leaf_cpu_rows, leaf_tier, leaf_peak_live_mb, leaf_prove_s, leaf_proof_bytes, rv32r_cpu_rows, child_cpu_rows, rv32r_tier, rv32r_peak_live_mb, rv32r_prove_s, rv32r_proof_bytes, step_band_lo, step_band_hi}`.
- Consumes: `aggregate`, `aggregate_program`, `verify_aggregate`, `InnerVerifierKey` (`src/aggregate.rs`); `verify_rv32r(shape, key, cp)` (`src/programs/rv32r.rs:25`); `WitnessTape::build_n`/`build_for_with_binding` (`src/witness.rs:206`, `:236`); `VerifierProgram::phase_rows`.

- [ ] **Step 1: Move the heap harness**

Create `tests/heap/mod.rs` as described in Files. Its first lines:

```rust
//! The live-heap harness shared by `tests/memprofile.rs` and `tests/tree_measure.rs`: a counting
//! global allocator (live bytes and the high-water mark) and a `tracing` subscriber printing
//! live/peak at every Plonky3 span boundary. Moved verbatim from `memprofile.rs` (2026-10-08).
#![allow(dead_code)]
```

In `tests/memprofile.rs`, delete `:32-191` (from `use std::alloc::…` through `report`) and put `mod heap;` and `use heap::*;` after `mod common;`. Keep only the `use` lines the remaining runs need: `std::time::Instant` and `std::sync::atomic::Ordering::Relaxed`.

Run: `cargo test --release --test memprofile tier8 -- --ignored --nocapture 2>&1 | grep '^=='`
Expected: one line `== tier8 toy: … rows, tier 8, …`. The smoke run still works through the moved harness.

- [ ] **Step 2: `RvmShape::of_proof`**

In `src/shape.rs`, inside `impl RvmShape`, after `try_of`:

```rust
    /// The shape a proof of `program` declares: [`RvmShape::of`] over the proof's own header
    /// (tier and the four declared heights). How a tree step's child shape is read off a child.
    pub fn of_proof(
        profile: FriProfile,
        program: &std::sync::Arc<crate::isa::Program>,
        proof: &crate::machine::Proof,
    ) -> Self {
        Self::of(
            profile,
            program,
            proof.tier,
            proof.reg_log_height,
            proof.ram_log_height,
            proof.poseidon2_log_height,
            proof.reduce_log_height,
        )
    }
```

- [ ] **Step 3: Keep every nested pin block, and read one**

In `tests/common/mod.rs`, in `aggregate_pins()`, replace the comment and the `let block = …;` statement (`:249-253`) with:

```rust
    // Every hand-written nested block (`phase3_attribution`, `tree_measure`, `tree_test`)
    // survives a re-measure, in file order.
    let mut blocks: Vec<String> = Vec::new();
    let mut from = 0;
    while let Some(rel) = s[from..].find("\": {") {
        let open = from + rel;
        let start = s[..open].rfind('"').expect("a block name opens with a quote");
        let close = open + s[open..].find('}').expect("the block closes");
        blocks.push(s[start..=close].to_string());
        from = close + 1;
    }
```

Change the per-N comma to `let comma = if n == 3 && blocks.is_empty() { "" } else { "," };`. Replace `if let Some(b) = &block { json += &format!("  {b}\n"); }` with:

```rust
    for (i, b) in blocks.iter().enumerate() {
        let comma = if i + 1 < blocks.len() { "," } else { "" };
        json += &format!("  {b}{comma}\n");
    }
```

Append to the file:

```rust
/// A nested block of `tests/pins.json` (`tree_measure`, `tree_test`, …) as `(key, value)` pairs
/// in file order. Panics, naming the block, when the file has none: the first measuring run
/// is what writes it.
#[allow(dead_code)]
pub fn pin_block(name: &str) -> Vec<(String, usize)> {
    let s = std::fs::read_to_string(pins_path()).expect("tests/pins.json");
    let at = s.find(&format!("\"{name}\": {{")).unwrap_or_else(|| panic!("tests/pins.json has no `{name}` block yet"));
    let block = &s[at..at + s[at..].find('}').expect("the block closes")];
    block
        .lines()
        .skip(1)
        .filter_map(|line| {
            let (k, v) = line.trim().trim_end_matches(',').split_once(": ")?;
            Some((k.trim_matches('"').to_string(), v.parse::<usize>().expect("a numeric field")))
        })
        .collect()
}

/// One value of a nested pin block.
#[allow(dead_code)]
pub fn pin(block: &str, key: &str) -> usize {
    pin_block(block)
        .into_iter()
        .find(|(k, _)| k == key)
        .unwrap_or_else(|| panic!("tests/pins.json's `{block}` block has no `{key}`"))
        .1
}
```

Run: `cargo test --release --test aggregate the_per_n_cycle_budget_is_pinned`
Expected: PASS, and `git diff --stat tests/pins.json` shows nothing (the file round-trips unchanged).

- [ ] **Step 4: Write `tests/tree_measure.rs`**

```rust
//! Tree aggregation, Task 0 (spec §5, ruling 5): measure before any program is built. One
//! production leaf (`rv32n` over L = 2 real bundle proofs) is proved on the 256 GB droplet. The
//! existing k = 1 self-verifier `rv32r`, with its cap baked, is then run over that leaf proof on
//! the 503 GB droplet: emulated first (the stop rule), then proved under the heap profiler. Every
//! run is logged under `docs/measurements/`. The numbers land in `tests/pins.json`'s
//! `tree_measure` block and `docs/07-tree-aggregation.md` §1–§2. All tests here are ignored and
//! run on a droplet, one per process.
mod common;
mod heap;

use heap::{gb, install, report, LIVE};
use rand_zkvm::machine::{FriProfile, Proof};
use recursion::aggregate::{aggregate, aggregate_program, verify_aggregate, InnerVerifierKey};
use recursion::dsl::Checkpoints;
use recursion::emulator::execute;
use recursion::isa::Program;
use recursion::machine::{Machine, Tier};
use recursion::programs::{verify_rv32r, VerifierProgram};
use recursion::shape::{InnerKey, InnerShape, RvmKey, RvmShape};
use recursion::witness::WitnessTape;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Instant;

const MAX_CYCLES: usize = 1 << 24;
/// The production leaf size (spec §2, ruling 6).
const L: usize = 2;
const P: FriProfile = FriProfile::Production;
/// Spec §5's stop rule: one child verification above this, and the k = 2 step exceeds tier 22.
const STOP_CHILD_ROWS: usize = 1_500_000;

/// `$RECURSION_FIXTURES/tree/{name}.rvmproof`: postcard `recursion::machine::Proof` bytes.
fn tree_file(name: &str) -> std::path::PathBuf {
    common::cache_dir().join("tree").join(format!("{name}.rvmproof"))
}

/// Production bundle fixtures `k0..k0 + n` (cached; `common::bundle_proof_at`).
fn bundles(k0: usize, n: usize) -> Vec<Proof> {
    let m = rand_zkvm::machine::Machine::new(P);
    (k0..k0 + n).map(|k| common::bundle_proof_at(&m, P, k).proof).collect()
}

fn inner(p: &Proof) -> InnerVerifierKey {
    let shape = InnerShape::of(P, p.tier, p.program_log_height, p.input_log_height, p.keccak_log_height,
        p.sha256_log_height, p.public_log_height, p.mem_log_height);
    let key = InnerKey::of(P, &shape);
    InnerVerifierKey { shape, key }
}

/// A cached tree proof, re-verified on load at its canonical `n`: a stale file is a loud
/// failure, never a vacuous pass.
fn load(name: &str, program: &Program, n: u64) -> recursion::machine::Proof {
    let path = tree_file(name);
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|_| panic!("{} is missing: run the test that writes it (docs/07 §1) and copy the file here", path.display()));
    let p: recursion::machine::Proof = postcard::from_bytes(&bytes).expect("a cached rVM proof decodes");
    Machine::new(P).verify_n(program, &p, n).expect("the cached proof verifies");
    p
}

fn save(name: &str, p: &recursion::machine::Proof) {
    let path = tree_file(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, p.to_bytes()).unwrap();
}

fn heights(what: &str, p: &recursion::machine::Proof) {
    println!("== heights {what}: tier {} reg {} ram {} poseidon2 {} reduce {}", p.tier.0, p.reg_log_height,
        p.ram_log_height, p.poseidon2_log_height, p.reduce_log_height);
}

/// Leaf `k` of the production tree: `rv32n` over fixtures `2k`, `2k + 1`, emulated (M1), proved,
/// verified, saved as `tree/Production-leaf-{k}`. Task 0 runs k = 0; Task 2 runs k = 1, 2, 3.
fn prove_leaf(k: usize) {
    let proofs = bundles(L * k, L);
    let vk = inner(&proofs[0]);
    let program = aggregate_program(&vk);
    let tape = WitnessTape::build_n(P, &vk.shape, &vk.key, &proofs, &common::TEST_BINDING).unwrap();
    let rows = execute(&program, &tape.words, MAX_CYCLES).expect("the leaf emulates").cpu_rows();
    assert_eq!(Tier::for_cycles(rows), Some(Tier(21)), "the production L = 2 leaf is tier 21 ({rows} rows; docs/02 B3: 1 171 511)");
    println!("leaf {k}: program built, {rows} rows emulated, live {:.2} GB", gb(LIVE.load(Relaxed)));
    let t0 = install();
    let m = Machine::new(P);
    let t = Instant::now();
    let a = aggregate(&m, &vk, &proofs, &common::TEST_BINDING, None).expect("the production leaf proves");
    let prove_s = t.elapsed().as_secs_f64();
    let tv = Instant::now();
    verify_aggregate(&m, &program, &a, &common::TEST_BINDING).expect("the production leaf verifies");
    println!("verify {:.2} s", tv.elapsed().as_secs_f64());
    save(&format!("Production-leaf-{k}"), &a.proof);
    heights(&format!("leaf {k}"), &a.proof);
    report(&format!("tree leaf {k} L=2 (production)"), t0, rows, a.proof.tier, a.proof.size(), prove_s);
}

/// Task 0, run 1 (the 256 GB droplet).
#[test]
#[ignore = "tree Task 0: the production rv32n leaf at L = 2 (1 171 511 rows, tier 21; 210-245 GB projected, docs/06 §3) — the 256 GB droplet"]
fn production_leaf_l2() {
    prove_leaf(0);
}

/// `rv32r` at the leaf's own declared shape over the cached leaf, emulated. Returns the program,
/// the tape, the rows, and C: the child verification, which is every row except phase 8 (the
/// interface list), i.e. what one iteration of `rv32t`'s loop body costs, give or take the
/// baked-cap stores.
fn rv32r_over_leaf() -> (VerifierProgram<RvmShape>, WitnessTape, usize, usize) {
    let proofs = bundles(0, L);
    let leaf_program = Arc::new(aggregate_program(&inner(&proofs[0])));
    let leaf = load("Production-leaf-0", &leaf_program, L as u64);
    let shape = RvmShape::of_proof(P, &leaf_program, &leaf);
    let key = RvmKey::of(P, &shape);
    let vp = verify_rv32r(&shape, &key, Checkpoints::Off);
    let tape = WitnessTape::build_for_with_binding(P, &shape, &key, &leaf, &common::TEST_BINDING).unwrap();
    let rows = execute(&vp.program, &tape.words, MAX_CYCLES).expect("rv32r accepts the production leaf").cpu_rows();
    let phase8: usize = vp.phase_rows.iter().filter(|(n, _)| n.starts_with("phase 8")).map(|(_, r)| *r).sum();
    (vp, tape, rows, rows - phase8)
}

/// Task 0, run 2 (the 503 GB droplet, minutes): the stop rule, before anything is proved.
#[test]
#[ignore = "tree Task 0: rv32r over the production leaf, emulated — spec §5's stop rule; needs tree/Production-leaf-0.rvmproof"]
fn production_rv32r_over_the_leaf_emulates() {
    let (vp, _tape, rows, child) = rv32r_over_leaf();
    println!("== rv32r over the production leaf: {rows} rows, tier {:?}, child {child} rows, program {} instrs",
        Tier::for_cycles(rows), vp.program.instrs.len());
    println!("-- phases {:?}", vp.phase_rows);
    assert!(child <= STOP_CHILD_ROWS,
        "STOP (spec §5): one child verification is {child} rows, above {STOP_CHILD_ROWS}: the k = 2 step exceeds tier 22. \
         Record it in docs/07 §2 and stop for a decision (k = 1 chains, a bigger tier, or the memory track first)");
}

/// Task 0, run 3 (the 503 GB droplet, hours): the same program proved, under the heap profiler.
#[test]
#[ignore = "tree Task 0: rv32r over the production leaf, proved (tier 21 projected, 210-340 GB) — the 503 GB droplet"]
fn production_rv32r_over_the_leaf_proves() {
    let (vp, tape, rows, child) = rv32r_over_leaf();
    assert!(child <= STOP_CHILD_ROWS, "the stop rule holds before anything is proved");
    let t0 = install();
    let m = Machine::new(P);
    let t = Instant::now();
    let (proof, exec) = m.prove(&vp.program, &tape.words, None).expect("rv32r over the leaf proves");
    let prove_s = t.elapsed().as_secs_f64();
    assert_eq!(exec.cpu_rows(), rows, "the proved run is the emulated run");
    let tv = Instant::now();
    m.verify(&vp.program, &proof).expect("rv32r's proof verifies (straight-line: n = 1)");
    println!("verify {:.2} s", tv.elapsed().as_secs_f64());
    heights("rv32r over the leaf", &proof);
    report("tree child: rv32r over the production leaf", t0, rows, proof.tier, proof.size(), prove_s);
}

/// The pins against a fresh emulation (production, minutes; needs the cached leaf).
#[test]
#[ignore = "tree Task 0: the tree_measure pins against a fresh emulation; needs tree/Production-leaf-0.rvmproof"]
fn the_tree_measure_pins_are_the_emulated_rows() {
    let (_vp, _tape, rows, child) = rv32r_over_leaf();
    assert_eq!(rows, common::pin("tree_measure", "rv32r_cpu_rows"));
    assert_eq!(child, common::pin("tree_measure", "child_cpu_rows"));
}
```

Run: `cargo test --release --test tree_measure -- --list 2>/dev/null | grep ': test'`
Expected: the four tests listed. Nothing runs (all ignored).

- [ ] **Step 5: Commit the harness before the droplets clone it**

```bash
git add tests/heap/mod.rs tests/memprofile.rs tests/tree_measure.rs src/shape.rs tests/common/mod.rs
git commit -m "recursion: tree Task 0's harness — the heap profiler shared, RvmShape::of_proof, nested pin blocks kept

tests/tree_measure.rs proves a production L = 2 leaf and runs rv32r over it, emulation first
(spec §5's stop rule at 1.5 M child rows). No program changes; every digest pin unchanged.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AUWKAos28PQquiLZRVC6jP"
git push origin feat/tree-aggregation
```

- [ ] **Step 6: The leaf, on the 256 GB droplet**

```bash
H=$HOST256
rsync -a ~/rand-agg-512-results/scripts/ root@$H:/root/scripts/
ssh -A root@$H 'rm -rf /root/circuits && git clone --branch feat/tree-aggregation git@github.com:dendisuhubdy/zkp-circuits.git /root/circuits && git -C /root/circuits rev-parse HEAD > /root/circuits/COMMIT && mkdir -p /root/recursion-fixtures/tree /root/out'
[ "$(ssh root@$H cat /root/circuits/COMMIT)" = "$(git rev-parse HEAD)" ] && echo same-commit
rsync -a $RECURSION_FIXTURES/Production-0.proof $RECURSION_FIXTURES/Production-1.proof root@$H:/root/recursion-fixtures/
ssh root@$H 'source /root/.cargo/env && cd /root/circuits/recursion && cargo test --release --features parallel --test tree_measure --no-run'
ssh root@$H 'RAYON_NUM_THREADS=32 nohup /root/scripts/step.sh 20-tree-leaf-l2 cargo test --release --features parallel --test tree_measure production_leaf_l2 -- --ignored --exact --nocapture >/dev/null 2>&1 &'
```

(`step.sh` sources the toolchain and sets `RECURSION_FIXTURES=/root/recursion-fixtures`. If `rustup` is absent on a fresh box, first run `curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.98.1 && apt-get install -y build-essential pkg-config time`.) Wait for `/root/out/20-tree-leaf-l2.done`, which holds the exit code; poll with `ssh root@$H cat /root/out/20-tree-leaf-l2.done`. Expected: `0`. A non-zero code with `Maximum resident set size` near 256 GB means the L = 2 leaf does not fit the class. Record it in docs/07 §1 as a measured point and stop: spec ruling 6 is re-decided with that number. Then fetch:

```bash
scp root@$H:/root/out/20-tree-leaf-l2.log docs/measurements/$(date -u +%F)-tree-leaf-l2-production.log
scp root@$H:/root/recursion-fixtures/tree/Production-leaf-0.rvmproof $RECURSION_FIXTURES/tree/
```

Read off (M2): rows, tier, proof bytes, prove s, peak live heap, verify s, the `== heights leaf 0:` line, and maximum RSS.

- [ ] **Step 7: `rv32r` over the leaf, on the 503 GB droplet: the stop rule first**

```bash
H=$HOST503
rsync -a ~/rand-agg-512-results/scripts/ root@$H:/root/scripts/
ssh -A root@$H 'rm -rf /root/circuits && git clone --branch feat/tree-aggregation git@github.com:dendisuhubdy/zkp-circuits.git /root/circuits && git -C /root/circuits rev-parse HEAD > /root/circuits/COMMIT && mkdir -p /root/recursion-fixtures/tree /root/out'
rsync -a $RECURSION_FIXTURES/Production-0.proof $RECURSION_FIXTURES/Production-1.proof root@$H:/root/recursion-fixtures/
rsync -a $RECURSION_FIXTURES/tree/Production-leaf-0.rvmproof root@$H:/root/recursion-fixtures/tree/
ssh root@$H 'source /root/.cargo/env && cd /root/circuits/recursion && cargo test --release --features parallel --test tree_measure --no-run'
ssh root@$H '/root/scripts/step.sh 21-tree-rv32r-emulate cargo test --release --features parallel --test tree_measure production_rv32r_over_the_leaf_emulates -- --ignored --exact --nocapture'
ssh root@$H 'grep -E "^== rv32r|STOP|test result" /root/out/21-tree-rv32r-emulate.log'
```

Expected: `== rv32r over the production leaf: <rows> rows, tier Some(Tier(<t>)), child <C> rows, …` and `test result: ok`. If the log says `STOP`: copy the log to `docs/measurements/$(date -u +%F)-tree-rv32r-emulate-production.log`, write C and the stop into docs/07 §2, commit (Step 10's message with "STOPPED at the child rule"), and **halt the plan**.

- [ ] **Step 8: `rv32r` over the leaf, proved**

```bash
ssh root@$HOST503 'RAYON_NUM_THREADS=64 nohup /root/scripts/step.sh 22-tree-rv32r-prove cargo test --release --features parallel --test tree_measure production_rv32r_over_the_leaf_proves -- --ignored --exact --nocapture >/dev/null 2>&1 &'
```

When `22-tree-rv32r-prove.done` holds `0`:

```bash
scp root@$HOST503:/root/out/22-tree-rv32r-prove.log docs/measurements/$(date -u +%F)-tree-rv32r-over-leaf-production.log
```

Read off (M2): rows (equal to Step 7's), tier, proof bytes, prove s, verify s, peak live heap, maximum RSS, and the `== heights` line.

- [ ] **Step 9: Pins and the docs/07 skeleton**

Add to `tests/pins.json` before its closing `}`, after a `,` on the last block. Every value is from Steps 6–8. Compute the band with the formula, with `O = 300` (spec §3's projected overhead; Task 1a replaces it with the measured value):

```json
  "tree_measure": {
    "leaf_cpu_rows": <Step 6 rows>,
    "leaf_tier": <Step 6 tier>,
    "leaf_peak_live_mb": <Step 6 peak live GB × 1000, rounded>,
    "leaf_prove_s": <Step 6 prove s, rounded>,
    "leaf_proof_bytes": <Step 6 proof bytes>,
    "rv32r_cpu_rows": <Step 7 rows>,
    "child_cpu_rows": <Step 7 C>,
    "rv32r_tier": <Step 8 tier>,
    "rv32r_peak_live_mb": <Step 8 peak live GB × 1000, rounded>,
    "rv32r_prove_s": <Step 8 prove s, rounded>,
    "rv32r_proof_bytes": <Step 8 proof bytes>,
    "step_band_lo": <floor(0.85 × (2C + 300))>,
    "step_band_hi": <ceil(1.15 × (2C + 300))>
  }
```

Then create `docs/07-tree-aggregation.md`:

````markdown
# 07 — Tree aggregation: a leaf of L bundle proofs, 2-to-1 interior steps, every level recomputed

Design: `docs/superpowers/specs/2026-10-08-tree-aggregation-design.md`. Plan: `docs/superpowers/plans/2026-10-08-tree-aggregation.md`.

## 1. The child, measured (Task 0, <date>, production)

| run | host | rows | tier | heights reg / ram / poseidon2 / reduce | prove | verify | proof | peak live | max RSS |
|---|---|---:|---:|---|---:|---:|---:|---:|---:|
| leaf: `rv32n`, L = 2 (fixtures 0–1) | 256 GB | <Step 6> | | | | | | | |
| `rv32r` over the leaf (k = 1, baked cap) | 503 GB | <Step 7/8> | | | | | | | |

C (the child verification: `rv32r` rows less phase 8) = <C>. Projected 0.85–1.45 M (spec §1): <in / below / above>.
Logs: `docs/measurements/<date>-tree-leaf-l2-production.log`, `…-tree-rv32r-over-leaf-production.log`.

## 2. The band and the stop rule

Stop rule (spec §5): C ≤ 1 500 000 — <held / STOPPED>. Interior step band (M5): 2C + O ± 15 %,
O = 300 projected (Task 1a measures it at the test profile) = [<lo>, <hi>] → tier <Tier::for_cycles(2C+300)>.
Memory, projected: the `rv32r` peak × (step cells / `rv32r` cells) by docs/06 §3's cell weights; Task 2 replaces it.

## 3. The production tree, per step (Task 2)

## 4. The interior step against the band, the fixed point, the genesis values (Task 2)

## 5. The test-profile tree (Tasks 1a, 1b)

## 6. The chain (Tasks 3a, 3b)

## 7. What moved, and the suite (Task 4)
````

Fill every `<…>` in §1–§2 from Steps 6–9.

Run: `cargo test --release --test aggregate the_per_n_cycle_budget_is_pinned` (the block parses and survives), and on the 503 GB box after pulling this commit, `step.sh 23-tree-pins cargo test --release --test tree_measure the_tree_measure_pins_are_the_emulated_rows -- --ignored --exact`.
Expected: both PASS.

- [ ] **Step 10: Commit**

```bash
git add tests/pins.json docs/07-tree-aggregation.md docs/measurements/
git commit -m "recursion: tree Task 0 — the production L = 2 leaf <rows> rows tier <t>, rv32r over it <rows> rows tier <t>; child C = <C>

Leaf: prove <s> s, <GB> GB live, <bytes> B (256 GB droplet). rv32r: prove <s> s, <GB> GB live,
<bytes> B (503 GB droplet). Stop rule (C ≤ 1.5 M) held; the interior step's band is
[<lo>, <hi>] (2C + 300 ± 15 %), tier <t>. docs/07 §1–§2, pins tree_measure.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AUWKAos28PQquiLZRVC6jP"
```

---

### Task 1a: `rv32t` — the program, the tape, the in-program key, emulated over real leaves

**Files:**
- Modify: `src/programs/rv32.rs`: `CAP_WORDS` (`:41`, becomes `pub(super)`), `emit_proof` (`:79-310`; its body moves into `emit_proof_with`, and the one `constant_cap` call at `:136` becomes the closure's), new `vk_digest_over_cap` after `vk_digest_in_program` (`:312-327`)
- Create: `src/programs/rv32t.rs`
- Modify: `src/programs/mod.rs` (`:13-20`: `mod rv32t;` and its `pub use`)
- Modify: `src/public_values.rs` (new `tree_step_words` after `interface_words_bound`, `:77-91`)
- Modify: `src/witness.rs` (new `WitnessTape::build_tree_step` after `build_n_for`, `:256-282`; new `pub const TREE_TAPE_PREAMBLE`)
- Modify: `src/shape.rs` (`RvmShape::same_step_words`, beside Task 0's `of_proof`)
- Create: `tests/tree.rs`
- Modify: `tests/pins.json` (the `tree_test` block), `docs/07-tree-aggregation.md` (§2's O, §5's first rows)

**Interfaces:**
- Produces: `pub(super) fn emit_proof_with<S: VerifierShape>(b: &mut Builder, shape: &S, cap_of: impl FnOnce(&mut Builder) -> [Digest; 4]) -> (Array<Felt>, Vec<Phase5Cost>)`; `emit_proof(b, shape, key)` is `emit_proof_with(b, shape, |b| constant_cap(b, key.cap()))`, so it emits the same instructions in the same order.
- Produces: `pub(super) fn vk_digest_over_cap<S: VerifierShape>(b: &mut Builder, shape: &S, cap: Ptr) -> Digest`. Its host twin is `shape::inner_vk_digest(shape, &RvmKey { cap })`.
- Produces: `programs::{verify_rv32t, rv32t_leaf, rv32t_int, tree_step_program_digest, TREE_ARITY}`: `verify_rv32t(child: &RvmShape, cp: Checkpoints) -> VerifierProgram<RvmShape>`; `rv32t_leaf(leaf: &RvmShape, cp)` and `rv32t_int(step: &RvmShape, cp)` are the same call, named for the level; `tree_step_program_digest(child: &RvmShape) -> [F; 4]`; `TREE_ARITY: u64 = 2`.
- Produces: `public_values::tree_step_words(vk_c: &[F; 4], binding: &[u32; 8], d_a: &[F; 4], d_b: &[F; 4]) -> Vec<F>` (21 words).
- Produces: `WitnessTape::build_tree_step(profile: FriProfile, child: &RvmShape, children: [&crate::machine::Proof; 2], binding: &[u32; 8]) -> Result<WitnessTape, TapeError>`; `witness::TREE_TAPE_PREAMBLE: usize = 24` (B(8) ‖ cap(16)).
- Produces: `RvmShape::same_step_words(&self, other: &RvmShape) -> bool`.
- Produces: pins `tree_test.{child_cpu_rows, step_leaf_cpu_rows, step_overhead, step_leaf_tier}`.
- Consumes: `Builder::{alloc_absolute, hint, store, load, constant, copy_cells, zero_cells, poseidon2, addr_of, counted_loop_mem, span, release_hash_scratch, public, offset}`, `hash::{absorb_staged, sponge, WIDTH}`, `RVM_PUB_DOMAIN` (17), `RVM_VK_DOMAIN` (16); `RvmShape::of_proof` (Task 0); `common::pin` (Task 0).

The child's *shape* (`shape_words`, `header_words`) is compile-time and its *cap* is a tape value. The program reads nothing else of the child shape: `ProgramAir::eval` reads no instruction (`src/tables/program.rs:71-90`), and the cap is the only content-dependent value `emit_proof` uses (`rv32.rs:136`). `the_tree_step_program_reads_the_child_shape_words_only` pins this.

- [ ] **Step 1: Write the failing tests**

Create `tests/tree.rs`:

```rust
//! Tree aggregation (spec §3, §6): `rv32t` verifies two child rVM proofs of one compile-time
//! shape and publishes `[vk_c ‖ 2 ‖ B ‖ D_1 ‖ D_2]`, with `vk_c` computed in-program over the
//! hinted cap. Task 1a runs the program by emulation over real test-profile leaves (`rv32n` over
//! L = 1 bundle proof each, proved here and cached). Task 1b proves a depth-2 tree, and Task 2
//! verifies it through `verify_tree`.
mod common;

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use rand_zkvm::machine::{FriProfile, Proof as BundleProof};
use recursion::aggregate::{aggregate, aggregate_program, InnerVerifierKey};
use recursion::dsl::Checkpoints;
use recursion::emulator::{execute, ExecError, Execution};
use recursion::isa::{Op, Program, F};
use recursion::machine::{Machine, Proof, Tier};
use recursion::programs::{rv32t_int, rv32t_leaf, verify_rv32r, verify_rv32t};
use recursion::public_values::{public_digest, tree_step_words};
use recursion::shape::{inner_vk_digest, InnerKey, InnerShape, RvmKey, RvmShape, VerifierShape};
use recursion::witness::{Segment, TapeError, WitnessTape, TREE_TAPE_PREAMBLE};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

const MAX_CYCLES: usize = 1 << 24;
const P: FriProfile = FriProfile::Test;
const B: &[u32; 8] = &common::TEST_BINDING;

/// Set only by the ignored generator (Task 1b): an in-suite run never starts a tier-19 proof
/// on a box that cannot hold it (R7). Leaves are exempt: tier 18, 26.88 GB live (docs/06 §3).
static ALLOW_STEP_PROVING: AtomicBool = AtomicBool::new(false);

fn tree_file(name: &str) -> std::path::PathBuf {
    common::cache_dir().join("tree").join(format!("{name}.rvmproof"))
}

/// The cached proof `name` if it decodes and verifies at `n`, else `prove()`'s, verified and
/// stored: the bundle-fixture cache's discipline (`common::load_cached`), one level up.
fn load_or_prove(name: &str, program: &Program, n: u64, may_prove: bool, prove: impl FnOnce() -> Proof) -> Proof {
    let m = Machine::new(P);
    if let Some(p) = std::fs::read(tree_file(name)).ok().and_then(|b| postcard::from_bytes::<Proof>(&b).ok()) {
        if m.verify_n(program, &p, n).is_ok() {
            return p;
        }
    }
    assert!(may_prove, "{} is missing or stale: run `cargo test --release --test tree generate_test_tree_fixtures \
        -- --ignored --nocapture` on a host with the docs/07 §5 memory and copy tree/ into $RECURSION_FIXTURES", tree_file(name).display());
    let p = prove();
    m.verify_n(program, &p, n).expect("a freshly proved tree proof verifies");
    let path = tree_file(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, p.to_bytes()).unwrap();
    p
}

/// Four test-profile leaves, `rv32n` over bundle fixture k = 0..3 each (L = 1; 169 640 rows,
/// tier 18 — `tests/pins.json`'s `aggregate_test_n1_cpu_rows`).
struct Leaves {
    inner: InnerVerifierKey,
    program: Arc<Program>,
    shape: RvmShape,
    key: RvmKey,
    bundles: Vec<BundleProof>,
    proofs: Vec<Proof>,
}

fn leaves() -> &'static Leaves {
    static L: OnceLock<Leaves> = OnceLock::new();
    L.get_or_init(|| {
        let bundles: Vec<BundleProof> = common::bundle_proofs(P, 4).into_iter().map(|b| b.proof).collect();
        let p = &bundles[0];
        let shape = InnerShape::of(P, p.tier, p.program_log_height, p.input_log_height, p.keccak_log_height,
            p.sha256_log_height, p.public_log_height, p.mem_log_height);
        let key = InnerKey::of(P, &shape);
        let inner = InnerVerifierKey { shape, key };
        let program = Arc::new(aggregate_program(&inner));
        let proofs: Vec<Proof> = (0..4)
            .map(|k| {
                load_or_prove(&format!("Test-leaf-{k}"), &program, 1, true, || {
                    aggregate(&Machine::new(P), &inner, std::slice::from_ref(&bundles[k]), B, None)
                        .expect("a test leaf proves")
                        .proof
                })
            })
            .collect();
        let shape = RvmShape::of_proof(P, &program, &proofs[0]);
        assert!(proofs.iter().all(|p| shape.matches(p)), "the four leaves declare one shape (a fixed workload)");
        let key = RvmKey::of(P, &shape);
        Leaves { inner, program, shape, key, bundles, proofs }
    })
}

/// A proof's four public values, the interface digest it publishes.
fn d(p: &Proof) -> [F; 4] {
    std::array::from_fn(|k| F::from_u64(p.public_values[k]))
}

/// The host's step digest over `(a, b)` in that order, as the emulator's public words.
fn host_step(vk: &[F; 4], binding: &[u32; 8], a: &Proof, b: &Proof) -> Vec<F> {
    public_digest(&tree_step_words(vk, binding, &d(a), &d(b))).to_vec()
}

fn emulate_step(child: &RvmShape, program: &Program, a: &Proof, b: &Proof, binding: &[u32; 8]) -> Result<Execution, ExecError> {
    let tape = WitnessTape::build_tree_step(P, child, [a, b], binding).expect("children of the shape build a tape");
    execute(program, &tape.words, MAX_CYCLES)
}

/// The leaf program with one unreachable `HALT` appended (R5's foreign program): the same
/// execution, so the same declared heights and shape words; another digest, so another cap.
fn foreign_leaf_program(p: &Program) -> Program {
    let mut q = p.clone();
    let halt = q.instrs.last().cloned().expect("a program ends");
    assert_eq!(halt.op, Op::Halt, "the builder ends every program with HALT");
    q.instrs.push(halt);
    assert_eq!(recursion::machine::program_log_height(q.instrs.len()), recursion::machine::program_log_height(p.instrs.len()),
        "the extra word must not cross a program-table power of two");
    q
}

// ── Task 1a: the program, by emulation ───────────────────────────────────────────────────────

/// `rv32t`'s pre-loop state (the binding, the cap, the interface sponge and its cursor) lives in
/// absolute cells. Building is the replay's loop-invariant check.
#[test]
fn the_tree_step_builds_under_the_replays_loop_invariant() {
    let l = leaves();
    let a = verify_rv32t(&l.shape, Checkpoints::Off).program;
    let b = verify_rv32t(&l.shape, Checkpoints::Off).program;
    assert_eq!(a.digest(), b.digest(), "the build is deterministic");
}

/// The program reads the child shape's words and never its committed program: a child program
/// that differs only past its `HALT` builds the identical step.
#[test]
fn the_tree_step_program_reads_the_child_shape_words_only() {
    let l = leaves();
    let foreign = Arc::new(foreign_leaf_program(&l.program));
    let other = RvmShape::of(P, &foreign, Tier(l.shape.tier), l.shape.reg_log_height, l.shape.ram_log_height,
        l.shape.poseidon2_log_height, l.shape.reduce_log_height);
    assert!(other.same_step_words(&l.shape), "one word past HALT moves no shape word");
    assert_ne!(foreign.digest(), l.program.digest());
    assert_ne!(RvmKey::of(P, &other), l.key, "another program is another cap");
    assert_eq!(verify_rv32t(&other, Checkpoints::Off).program.digest(), verify_rv32t(&l.shape, Checkpoints::Off).program.digest());
}

/// Two real leaves, in order: accepted, the whole tape consumed, and exactly the host's
/// `[vk_leaf ‖ 2 ‖ B ‖ D_0 ‖ D_1]` published. Measures C (the k = 1 self-verifier over one leaf,
/// less phase 8) and the step's overhead O = rows − 2C (docs/07 §2's band term).
#[test]
fn the_tree_step_accepts_two_real_leaves_and_publishes_the_host_digest() {
    let l = leaves();
    let vp = rv32t_leaf(&l.shape, Checkpoints::Off);
    let tape = WitnessTape::build_tree_step(P, &l.shape, [&l.proofs[0], &l.proofs[1]], B).unwrap();
    let exec = execute(&vp.program, &tape.words, MAX_CYCLES).expect("rv32t_leaf accepts two real leaves");
    assert_eq!(exec.hints_read, tape.len(), "the program consumes the whole tape");
    let vk_leaf = inner_vk_digest(&l.shape, &l.key);
    assert_eq!(exec.public, host_step(&vk_leaf, B, &l.proofs[0], &l.proofs[1]), "[vk_leaf ‖ 2 ‖ B ‖ D_0 ‖ D_1], exactly");

    let r = verify_rv32r(&l.shape, &l.key, Checkpoints::Off);
    let rt = WitnessTape::build_for_with_binding(P, &l.shape, &l.key, &l.proofs[0], B).unwrap();
    let rexec = execute(&r.program, &rt.words, MAX_CYCLES).expect("rv32r accepts the leaf");
    let phase8: usize = r.phase_rows.iter().filter(|(n, _)| n.starts_with("phase 8")).map(|(_, x)| *x).sum();
    let child = rexec.cpu_rows() - phase8;
    let rows = exec.cpu_rows();
    let overhead = rows as i64 - 2 * child as i64;
    eprintln!("TREE_TEST child {child} step_leaf {rows} overhead {overhead} tier {:?} program {} instrs",
        Tier::for_cycles(rows), vp.program.instrs.len());
    assert_eq!(child, common::pin("tree_test", "child_cpu_rows"));
    assert_eq!(rows, common::pin("tree_test", "step_leaf_cpu_rows"));
    assert_eq!(overhead, common::pin("tree_test", "step_overhead") as i64);
    assert_eq!(Tier::for_cycles(rows).unwrap().0, common::pin("tree_test", "step_leaf_tier"));
}

/// The counted loop runs one child's static reduce rows twice, so `verify_n(program, proof, 2)`
/// (spec §4) declares exactly the height `build_traces` produces. Extends
/// `tests/aggregate.rs`'s `the_reduce_height_is_canonical_in_the_program_and_n_at_the_test_profile`
/// to the tree step.
#[test]
fn the_reduce_height_is_canonical_in_the_tree_step_at_n2() {
    use recursion::machine::canonical_reduce_log_height;
    use recursion::tables::reduce::{fold_events, fold_rows, pow_events, pow_rows, program_rows, provider_rows, reduce_events, reduce_log_height, reduce_rows};
    let l = leaves();
    let t = rv32t_leaf(&l.shape, Checkpoints::Off).program;
    let r = verify_rv32r(&l.shape, &l.key, Checkpoints::Off).program;
    let per = program_rows(&t);
    assert_eq!(per, program_rows(&r), "the loop body is the self-verifier's pipeline: one child's reduce rows");
    let exec = emulate_step(&l.shape, &t, &l.proofs[0], &l.proofs[1], B).unwrap();
    let rows = (reduce_rows(&reduce_events(&exec.events)) + fold_rows(&fold_events(&exec.events)) + pow_rows(&pow_events(&exec.events))) as u64;
    assert_eq!(rows, 2 * per, "two children run the body's static rows twice");
    assert_eq!(canonical_reduce_log_height(&t, recursion::programs::TREE_ARITY),
        Some(reduce_log_height(rows as usize, provider_rows(&t.reduce_layout))),
        "verify_n(program, proof, 2)'s height is the one build_traces declares");
}

/// Review Focus 3: a tamper in either child's region is refused at `emit_proof`'s own named
/// step, on the loop's first pass (child 0) or its second (child 1). The names are the
/// self-verifier's (`tests/self_verify.rs`'s table) because the body is the same pipeline (R1).
#[test]
fn a_tamper_in_either_child_is_refused_at_the_named_step() {
    let l = leaves();
    let vp = rv32t_leaf(&l.shape, Checkpoints::Off);
    let honest = WitnessTape::build_tree_step(P, &l.shape, [&l.proofs[0], &l.proofs[1]], B).unwrap();
    let table = [
        (Segment::Header, "header word 0"),
        (Segment::PublicValues, "quotient identity[0]"),
        (Segment::Commitments, "quotient identity[0]"),
        (Segment::LookupTerminals, "lookup terminal sum"),
    ];
    for child in 0..2 {
        for (seg, want) in table {
            let r = honest.segment_refs().into_iter().find(|r| r.proof == child && r.segment == seg).expect("the segment exists");
            let mut t = honest.clone();
            t.words[r.start] += F::ONE;
            match execute(&vp.program, &t.words, MAX_CYCLES) {
                Err(ExecError::InverseOfZero { pc }) => {
                    assert_eq!(vp.program.checkpoint_at(pc), Some(want), "child {child}, {seg:?}: refused at the wrong step")
                }
                other => panic!("child {child}, {seg:?}: expected a refusal, got {:?}", other.map(|e| e.cpu_rows())),
            }
        }
    }
}

/// R5, first half: a wrong hinted cap under honest children is refused in-program. The
/// transcript observes the preprocessed cap in phase 2, so every later challenge moves, and the
/// first check that reads one is the quotient identity.
#[test]
fn a_wrong_hinted_cap_with_honest_children_is_refused_in_program() {
    let l = leaves();
    let vp = rv32t_leaf(&l.shape, Checkpoints::Off);
    let honest = WitnessTape::build_tree_step(P, &l.shape, [&l.proofs[0], &l.proofs[1]], B).unwrap();
    for k in [8usize, TREE_TAPE_PREAMBLE - 1] {
        let mut t = honest.clone();
        t.words[k] += F::ONE;
        match execute(&vp.program, &t.words, MAX_CYCLES) {
            Err(ExecError::InverseOfZero { pc }) => assert_eq!(vp.program.checkpoint_at(pc), Some("quotient identity[0]"), "cap word {}", k - 8),
            other => panic!("cap word {}: expected a refusal, got {:?}", k - 8, other.map(|e| e.cpu_rows())),
        }
    }
}

/// ZKQ-5's tie is the chain's recompute. The program accepts a swapped pair and a step made
/// under another binding, and each publishes a digest that the chain's cover-order,
/// chain-binding recompute never produces (Task 2 turns both into `TreeRootDigest`).
#[test]
fn swapped_children_and_another_binding_publish_digests_the_chain_never_computes() {
    let l = leaves();
    let t = rv32t_leaf(&l.shape, Checkpoints::Off).program;
    let vk_leaf = inner_vk_digest(&l.shape, &l.key);
    let want = host_step(&vk_leaf, B, &l.proofs[0], &l.proofs[1]);
    let swapped = emulate_step(&l.shape, &t, &l.proofs[1], &l.proofs[0], B).expect("both orders are valid in-program");
    assert_eq!(swapped.public, host_step(&vk_leaf, B, &l.proofs[1], &l.proofs[0]), "children are published in tape order");
    assert_ne!(swapped.public, want, "a swapped pair fails the cover-order recompute");
    let rebound = emulate_step(&l.shape, &t, &l.proofs[0], &l.proofs[1], &[7u32; 8]).expect("no in-program B_out == B_in (ZKQ-5)");
    assert_ne!(rebound.public, want, "a step made under another binding fails the recompute");
}

/// A child whose declared shape is not the step's is refused by the tape builder, before any
/// word is written (the self-verifier's `a_wrong_shape_proof_is_refused`, one level up).
#[test]
fn a_child_of_the_wrong_shape_is_refused_by_the_tape_builder() {
    let l = leaves();
    let wrong = RvmShape::of(P, &l.program, Tier(l.shape.tier), l.shape.reg_log_height, l.shape.ram_log_height + 1,
        l.shape.poseidon2_log_height, l.shape.reduce_log_height);
    assert_eq!(
        WitnessTape::build_tree_step(P, &wrong, [&l.proofs[0], &l.proofs[1]], B).err(),
        Some(TapeError::Replay(recursion::reference::ReplayError::Shape))
    );
}
```

Run: `cargo test --release --test tree 2>&1 | grep -E '^error' | sort -u | head`
Expected: compile errors naming `verify_rv32t`, `rv32t_leaf`, `rv32t_int`, `tree_step_words`, `build_tree_step`, `TREE_TAPE_PREAMBLE`, `same_step_words`, `TREE_ARITY` (unresolved imports and methods).

- [ ] **Step 2: Split `emit_proof`, and the in-program key over a hinted cap**

In `src/programs/rv32.rs`, change `:41` to `pub(super) const CAP_WORDS: usize = (1 << crate::shape::CAP_HEIGHT) * DIGEST_ELEMS;`. Replace `emit_proof`'s signature and its first line with:

```rust
pub(super) fn emit_proof<S: VerifierShape>(
    b: &mut Builder,
    shape: &S,
    key: &S::Key,
) -> (Array<Felt>, Vec<Phase5Cost>)
where
    S::Air: BaseAir<F> + Air<InteractionSymbolicBuilder<F, EF>>,
{
    emit_proof_with(b, shape, |b| constant_cap(b, key.cap()))
}

/// [`emit_proof`] with the preprocessed cap supplied by `cap_of`, which is called at exactly
/// the point `emit_proof` builds its constant cap (phase 2, after the preprocessed widths), so
/// `emit_proof` emits the same instructions in the same order as before the split. The tree
/// step (`super::rv32t`) passes the hinted cap's four digests: offsets of an absolute
/// allocation, which emit nothing.
pub(super) fn emit_proof_with<S: VerifierShape>(
    b: &mut Builder,
    shape: &S,
    cap_of: impl FnOnce(&mut Builder) -> [Digest; 4],
) -> (Array<Felt>, Vec<Phase5Cost>)
where
    S::Air: BaseAir<F> + Air<InteractionSymbolicBuilder<F, EF>>,
{
    let n = shape.instances();
```

The rest of the old body follows unchanged, except `:136`, which becomes `let pre_cap = cap_of(b);`. After `vk_digest_in_program`, add:

```rust
/// The verifier-key digest over a cap the program did not bake: `[RVM_VK_DOMAIN] ‖
/// shape_words ‖ cap(16)` sponged in-program, with the domain and the shape words as constants
/// and the cap copied from `cap` (sixteen cells). The host twin is `shape::inner_vk_digest(shape,
/// &RvmKey { cap })`. The tree step publishes this as `vk_c`, so the key a child pair was
/// checked against is a value the chain compares (spec §3 step 2; ruling 2).
pub(super) fn vk_digest_over_cap<S: VerifierShape>(b: &mut Builder, shape: &S, cap: Ptr) -> Digest {
    let words = shape.shape_words();
    let n = 1 + words.len() + CAP_WORDS;
    let src = b.alloc(n as u64);
    let dom = b.constant(F::from_u64(RVM_VK_DOMAIN));
    b.store(src, 0, dom);
    for (k, v) in words.iter().enumerate() {
        let c = b.constant(*v);
        b.store(src, 1 + k as i64, c);
    }
    b.copy_cells(src, (1 + words.len()) as i64, cap, 0, CAP_WORDS);
    let vk = Digest(b.alloc(DIGEST_ELEMS as u64));
    hash::sponge(b, src, n, vk);
    vk
}
```

- [ ] **Step 3: Confirm the split moved no shipped digest**

Run: `cargo test --release --test self_verify the_self_program_digest_is_deterministic_and_distinct the_self_verifiers_measured_cost_at_two_fixture_shapes && cargo test --release --test verifier the_aggregate_program_digest_is_unchanged_by_rvm_constraint_fixes the_admission_stub_vectors && cargo test --release --test aggregate the_aggregate_program_digest_is_deterministic_and_distinct n1_aggregate_publishes_the_bound_interface_digest_at_a_pinned_overhead`
Expected: all PASS with no literal edited (`e9c9720d…`, the test-shape aggregate digest, `LOOP_OVERHEAD` 274). If any fails, the closure was called at a different point than `:136`. Fix that; do not re-pin.

- [ ] **Step 4: `RvmShape::same_step_words`**

In `src/shape.rs`, beside `of_proof`:

```rust
    /// Whether a tree step built for `self` verifies proofs of `other`: everything the program
    /// reads of a child shape agrees (the vk preimage's shape words, and the tape header words it
    /// pins). The committed program is not read: its cap is a tape value (R3's fixed-point test).
    pub fn same_step_words(&self, other: &RvmShape) -> bool {
        self.shape_words() == other.shape_words() && self.header_words() == other.header_words()
    }
```

- [ ] **Step 5: The program**

Create `src/programs/rv32t.rs`:

```rust
//! The tree step (tree aggregation, spec §3): the rVM verifying **two** rVM proofs of one
//! compile-time child shape and publishing `[vk_c ‖ 2 ‖ B(8) ‖ D_1 ‖ D_2]` — 21 words, sponged
//! under `RVM_PUB_DOMAIN` with the count in the capacity lane, the digest's four lanes public.
//!
//! The child's *shape* is compile-time; its *key* is not. The cap is hinted (tape words 8..24),
//! `vk_c = H(RVM_VK_DOMAIN ‖ shape_words ‖ cap)` is computed in-program over it, and both children
//! are checked against that same cap. A wrong cap therefore either fails in-program (honest
//! children of another key) or publishes another `vk_c` (children of the program the cap
//! belongs to), which the chain's bottom-up recompute refuses (spec §4; ruling 2). That is what
//! breaks the circular key: `rv32t_int` verifies proofs of itself without embedding its own
//! commitment.
//!
//! The body is `rv32n`'s counted loop with the constant count `TREE_ARITY` (R1): one emission of
//! the per-proof pipeline, run twice with a fresh challenger each time, so the program's static
//! reduce rows are one child's and `Machine::verify_n(program, proof, 2)` is the canonical
//! height. The interface list is never materialised: `hash::absorb_staged` over a dedicated
//! eight-cell state, `rv32n`'s schedule word for word (block zero `vk_c`, then `N`, the eight
//! binding words, and each child's four public words as its iteration accepts them). No
//! `B_out == B_in` in-program (ZKQ-5, `docs/02-aggregate.md`): the chain recomputes every level.

use crate::dsl::hash;
use crate::dsl::{Builder, Checkpoints, Digest, DIGEST_ELEMS};
use crate::isa::F;
use crate::public_values::RVM_PUB_DOMAIN;
use crate::shape::{RvmKey, RvmShape, VerifierShape};
use p3_field::PrimeCharacteristicRing;

use super::rv32::{emit_proof_with, vk_digest_over_cap, CAP_WORDS};
use super::VerifierProgram;

/// The permutation width, in cells: the interface sponge's state size.
const WIDTH: usize = hash::WIDTH;

/// The children one step verifies (spec ruling 4: fan-out 2), and the `n` of its
/// `Machine::verify_n`.
pub const TREE_ARITY: u64 = 2;

/// Builds the tree step for children of `child`'s shape. Only the shape words are read (see
/// `RvmShape::same_step_words`); the child key is a tape value.
pub fn verify_rv32t(child: &RvmShape, cp: Checkpoints) -> VerifierProgram<RvmShape> {
    let mut b = Builder::with_opts(cp, crate::dsl::Liveness::On, super::Precompiles::On);
    let npv = child.num_public_values()[child.pv_instance()];
    assert_eq!(npv, DIGEST_ELEMS, "an rVM proof publishes exactly its four-word interface digest");

    let (st, cursor, n) = b.span("tree preamble", |b| {
        // ── B (audit v3, AGG-2), hinted. Absolute: the loop never reads it, but nothing pre-loop
        // may claim a register the replay's loop invariant could see moved.
        let bind = b.alloc_absolute(8);
        for k in 0..8i64 {
            let w = b.hint();
            b.store(bind, k, w);
        }
        // ── the child cap, hinted: sixteen words, two rows each. Absolute, because both loop
        // iterations read it, as their preprocessed commitment.
        let cap = b.alloc_absolute(CAP_WORDS as u64);
        for k in 0..CAP_WORDS as i64 {
            let w = b.hint();
            b.store(cap, k, w);
        }
        // ── the interface state: zero lanes, the domain and the fixed length 4 + 1 + 8 + 4·2 = 21
        // in the capacity lanes, then vk_c (computed over the hinted cap) as block zero, then N.
        let st = b.alloc_absolute(WIDTH as u64);
        b.zero_cells(st, 0, WIDTH);
        let dom = b.constant(F::from_u64(RVM_PUB_DOMAIN));
        b.store(st, 4, dom);
        let len = b.constant(F::from_u64((DIGEST_ELEMS + 1 + 8 + TREE_ARITY as usize * npv) as u64));
        b.store(st, 5, len);
        let vk = vk_digest_over_cap(b, child, cap);
        // `rv32n`'s rule: the vk sponge's hash scratch is pre-loop state the body would see moved.
        b.release_hash_scratch();
        b.copy_cells(st, 0, vk.0, 0, DIGEST_ELEMS);
        b.poseidon2(st);
        let n = b.constant(F::from_u64(TREE_ARITY));
        b.store(st, 0, n);
        let cursor = b.alloc_absolute(1);
        let first = b.constant(F::from_u64(b.addr_of(st) + 1));
        b.store(cursor, 0, first);
        for k in 0..8i64 {
            let v = b.load(bind, k);
            hash::absorb_staged(b, st, cursor, v);
        }
        ((st, cap), cursor, n)
    });
    let (st, cap) = st;
    b.note_phase("tree preamble: the binding, the child cap, vk_c, the interface state");

    // ── the two children: the fresh-challenger pipeline against the hinted cap, then the child's
    // four public words absorbed. Everything the body needs is created inside it or is absolute.
    let counter = b.alloc_absolute(1);
    let mut phase5 = Vec::new();
    b.counted_loop_mem(counter, n, |b| {
        let (pvs, cost) = b.span("tree child", |b| {
            emit_proof_with(b, child, |b| std::array::from_fn(|i| Digest(b.offset(cap, (i * DIGEST_ELEMS) as i64))))
        });
        phase5 = cost;
        for k in 0..npv {
            let v = b.get(pvs, k);
            hash::absorb_staged(b, st, cursor, v);
        }
    });
    b.note_phase("the two-child loop");

    // ── a block is always pending (`absorb_staged` defers each permutation), so exactly one
    // final permutation; its four lanes are the program's only public values.
    b.poseidon2(st);
    for lane in 0..DIGEST_ELEMS as i64 {
        let v = b.load(st, lane);
        b.public(v);
    }
    b.note_phase("post-loop: the final permutation");

    let checkpoint_names = b.checkpoint_names().to_vec();
    let (program, mut stats) = b.finish_stats();
    let phase_rows = std::mem::take(&mut stats.phase_rows);
    VerifierProgram {
        program,
        shape: child.clone(),
        // No key is baked: the cap is a tape value, published as `vk_c`. Nothing reads this field
        // (`cycle_report` reads the program and the run).
        key: RvmKey { cap: [[F::ZERO; 4]; 4] },
        checkpoints: cp,
        stats,
        phase5,
        phase_rows,
        checkpoint_names,
    }
}

/// Level 1: children are leaves, `rv32n` proofs over L bundle proofs, at the leaf's declared
/// shape (`RvmShape::of_proof(profile, aggregate_program, leaf)`).
pub fn rv32t_leaf(leaf: &RvmShape, cp: Checkpoints) -> VerifierProgram<RvmShape> {
    verify_rv32t(leaf, cp)
}

/// Levels ≥ 2: children are steps at the step shape, the declared shape of an `rv32t_leaf`
/// proof. It is also `rv32t_int`'s own output shape when the fixed point holds (R3,
/// `the_interior_step_verifies_its_own_output`).
pub fn rv32t_int(step: &RvmShape, cp: Checkpoints) -> VerifierProgram<RvmShape> {
    verify_rv32t(step, cp)
}

/// What a chain pins (spec §4, `t_leaf_digest`/`t_int_digest`): the step's program digest at a
/// child shape, checkpoints off.
pub fn tree_step_program_digest(child: &RvmShape) -> [F; 4] {
    verify_rv32t(child, Checkpoints::Off).program.digest()
}
```

The span closure returns `((st, cap), cursor, n)` because `b.span` returns one value. All three handles are absolute pointers, or `n`, a constant, which `counted_loop_mem` stores into its counter cell first.

In `src/programs/mod.rs`, add `mod rv32t;` after `mod rv32r;` and `pub use rv32t::{rv32t_int, rv32t_leaf, tree_step_program_digest, verify_rv32t, TREE_ARITY};` after the `rv32r` re-export.

- [ ] **Step 6: The host list and the tape**

In `src/public_values.rs`, after `interface_words_bound`:

```rust
/// The tree step's interface list (tree aggregation, spec §3–§4): `[vk_c(4) ‖ 2 ‖ B(8) ‖ D_a(4)
/// ‖ D_b(4)]`, 21 words, `D_a` and `D_b` the two children's published digests in cover order.
/// `rv32t`'s staged sponge absorbs exactly this; the chain recomputes it at every level ≥ 1 with
/// that level's pinned `vk_c` (`aggregate::TreeKeys::at_level`).
pub fn tree_step_words(vk_c: &[F; 4], binding: &[u32; 8], d_a: &[F; 4], d_b: &[F; 4]) -> Vec<F> {
    let mut w = vk_c.to_vec();
    w.push(F::from_u64(2));
    w.extend(binding.iter().map(|x| F::from_u64(*x as u64)));
    w.extend_from_slice(d_a);
    w.extend_from_slice(d_b);
    w
}
```

In `src/witness.rs`, add `use crate::shape::{RvmKey, RvmShape};` next to the existing `crate::shape` import, and after `build_n_for`:

```rust
    /// The tree step's tape (spec §3): `[B(8) ‖ cap(16) ‖ region(child a) ‖ region(child b)]`.
    /// `cap` is the child's own preprocessed cap, `RvmKey::of(profile, child)`, so `child` must
    /// carry the program the children were proved for (the step *program* reads only its shape
    /// words). Both children are shape-checked before any word is written. The regions are
    /// `build_for`'s, so `segment_refs` numbers them proof 0 and proof 1.
    pub fn build_tree_step(
        profile: FriProfile,
        child: &RvmShape,
        children: [&crate::machine::Proof; 2],
        binding: &[u32; 8],
    ) -> Result<Self, TapeError> {
        for p in children {
            if !child.matches(p) {
                return Err(ReplayError::Shape.into());
            }
        }
        let key = RvmKey::of(profile, child);
        let mut w = Writer::new();
        for word in binding {
            w.usize(*word as usize);
        }
        for v in key.flatten() {
            w.f(v);
        }
        for p in children {
            write_proof(&mut w, profile, child, &key, p)?;
        }
        Ok(WitnessTape { words: w.words, segments: w.segments })
    }
```

and at module level, after `SEGMENTS_PER_PROOF`:

```rust
/// The tree step tape's preamble ahead of the regions: the binding (8) and the child cap (16).
pub const TREE_TAPE_PREAMBLE: usize = 8 + 16;
```

(`ShapeKey::flatten` must be in scope for `key.flatten()`: `witness.rs:24` already imports `ShapeKey`, currently unused, which is the warning in the 2026-10-06 log.)

- [ ] **Step 7: Run green, measure, pin**

Run: `cargo test --release --test tree -- --nocapture 2>&1 | grep -E '^TREE_TEST|^test |test result'`
Expected: the first run proves the four leaves (about 2.5 min each on 16 threads with `--features parallel`; without it, longer), then every test passes except `the_tree_step_accepts_two_real_leaves_and_publishes_the_host_digest`, which panics with `tests/pins.json has no \`tree_test\` block yet` after printing `TREE_TEST child <C> step_leaf <rows> overhead <O> tier Some(Tier(<t>)) program <n> instrs`. Add the block (M3):

```json
  "tree_test": {
    "child_cpu_rows": <C>,
    "step_leaf_cpu_rows": <rows>,
    "step_overhead": <O>,
    "step_leaf_tier": <t>
  }
```

Re-run the same command. Expected: `test result: ok. 8 passed`.

- [ ] **Step 8: docs/07 §2 and §5**

In docs/07 §2, replace "O = 300 projected" with the measured O, recompute `[lo, hi]` and the tier with it, and update `tree_measure.step_band_lo/hi` in `tests/pins.json` to match. Under §5, write: the test-profile C, the step's rows, O and tier, the program's instruction count, and the memory projection for proving that tier (docs/06 §3's table: tier 18 = 26.88 GB measured, tier 19 ≈ 52 GB projected). The projection decides where Task 1b proves (R7).

- [ ] **Step 9: Commit**

```bash
git add src/programs/rv32.rs src/programs/rv32t.rs src/programs/mod.rs src/public_values.rs src/witness.rs src/shape.rs tests/tree.rs tests/pins.json docs/07-tree-aggregation.md
git commit -m "recursion: rv32t — the tree step, two rVM proofs of one shape, vk_c in-program over the hinted cap; <rows> rows at the test profile, tier <t>

rv32n's counted loop with the constant count 2 (verify_n(…, 2) canonical), the cap a tape
value bound only through the published vk_c, interface [vk_c ‖ 2 ‖ B ‖ D_1 ‖ D_2]. emit_proof
split into emit_proof_with: every shipped digest unchanged. Test profile: child C = <C>, step
<rows> = 2C + <O>. Tampers refused at emit_proof's named steps in either child.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AUWKAos28PQquiLZRVC6jP"
```

---

### Task 1b: The test tree, proved — depth 2, the fixed point, the foreign program, the digests

The depth-2 test tree is **7 proofs**: 4 leaves (`rv32n`, L = 1, bundle fixtures 0–3; tier 18, 26.88 GB live measured), 2 `rv32t_leaf` steps (leaves 0–1, 2–3) and 1 `rv32t_int` root (over the two steps). One more proof, the foreign leaf (R5: the leaf program plus one `HALT`, over fixture 0, tier 18), makes **8** in all. The steps and the root are at the tier Task 1a pinned (`tree_test.step_leaf_tier`). By docs/06 §3's cell model that is ≈ 52 GB if it is tier 19 (*projected*), and the 48 GB laptop cannot prove it. The generator runs on the 256 GB droplet and the files come back (R7). The four leaves and the foreign leaf can be proved on the laptop.

**Files:**
- Modify: `tests/tree.rs` (the `TestTree` fixture, the generator, five tests)
- Modify: `tests/pins.json` (`tree_test`: `step_int_cpu_rows`, `step_int_tier`, `step_proof_bytes`)
- Modify: `docs/07-tree-aggregation.md` §5

**Interfaces:**
- Consumes: Task 1a's `verify_rv32t`, `rv32t_leaf`, `rv32t_int`, `build_tree_step`, `tree_step_words`, `same_step_words`; Task 0's `RvmShape::of_proof`.
- Produces: `$RECURSION_FIXTURES/tree/Test-{leaf-0..3, step-0, step-1, root, foreign-0}.rvmproof`.
- Produces: the test-profile digests `T_LEAF_TEST` and `T_INT_TEST` (hex literals in `tests/tree.rs`), and the fixed-point verdict (docs/07 §5).

- [ ] **Step 1: The fixture and the five tests**

Append to `tests/tree.rs`:

```rust
// ── Task 1b: the proved test tree ───────────────────────────────────────────────────────────

struct TestTree {
    t_leaf: Arc<Program>,
    steps: Vec<Proof>,
    /// S_T: an `rv32t_leaf` proof's declared shape, carrying `rv32t_leaf`'s program.
    s_step: RvmShape,
    t_int: Arc<Program>,
    root: Proof,
    /// The root's declared shape, carrying `rv32t_int`'s program. R3: its words must equal S_T's.
    s_root: RvmShape,
    foreign: Proof,
    s_foreign: RvmShape,
}

fn test_tree() -> &'static TestTree {
    static T: OnceLock<TestTree> = OnceLock::new();
    T.get_or_init(|| {
        let l = leaves();
        let may = ALLOW_STEP_PROVING.load(Ordering::SeqCst);
        let m = Machine::new(P);
        let prove_step = |child: &RvmShape, program: &Program, a: &Proof, b: &Proof| -> Proof {
            let tape = WitnessTape::build_tree_step(P, child, [a, b], B).unwrap();
            m.prove(program, &tape.words, None).expect("a test tree step proves").0
        };
        let t_leaf = Arc::new(rv32t_leaf(&l.shape, Checkpoints::Off).program);
        let steps: Vec<Proof> = (0..2)
            .map(|k| load_or_prove(&format!("Test-step-{k}"), &t_leaf, 2, may, || {
                prove_step(&l.shape, &t_leaf, &l.proofs[2 * k], &l.proofs[2 * k + 1])
            }))
            .collect();
        let s_step = RvmShape::of_proof(P, &t_leaf, &steps[0]);
        assert!(s_step.matches(&steps[1]), "both level-1 steps declare one shape");
        let t_int = Arc::new(rv32t_int(&s_step, Checkpoints::Off).program);
        let root = load_or_prove("Test-root", &t_int, 2, may, || prove_step(&s_step, &t_int, &steps[0], &steps[1]));
        let s_root = RvmShape::of_proof(P, &t_int, &root);
        let fprog = Arc::new(foreign_leaf_program(&l.program));
        let foreign = load_or_prove("Test-foreign-0", &fprog, 1, true, || {
            let tape = WitnessTape::build_n(P, &l.inner.shape, &l.inner.key, std::slice::from_ref(&l.bundles[0]), B).unwrap();
            m.prove(&fprog, &tape.words, None).expect("the foreign leaf proves").0
        });
        let s_foreign = RvmShape::of_proof(P, &fprog, &foreign);
        TestTree { t_leaf, steps, s_step, t_int, root, s_root, foreign, s_foreign }
    })
}

fn u64s(v: &[F]) -> Vec<u64> {
    v.iter().map(|f| f.as_canonical_u64()).collect()
}

/// The generator (R7): proves whatever `tree/` lacks. Run it once where docs/07 §5 says, then
/// copy `$RECURSION_FIXTURES/tree/` to every box that runs the suite.
#[test]
#[ignore = "tree Task 1b: proves the test tree's steps and root (tier per tests/pins.json tree_test.step_leaf_tier; ≈ 52 GB projected at tier 19) — the 256 GB droplet"]
fn generate_test_tree_fixtures() {
    ALLOW_STEP_PROVING.store(true, Ordering::SeqCst);
    let t = test_tree();
    let l = leaves();
    for (name, p) in [("leaf-0", &l.proofs[0]), ("step-0", &t.steps[0]), ("root", &t.root), ("foreign-0", &t.foreign)] {
        eprintln!("TREE_TEST_FIXTURE {name}: tier {} reg {} ram {} poseidon2 {} reduce {} bytes {}",
            p.tier.0, p.reg_log_height, p.ram_log_height, p.poseidon2_log_height, p.reduce_log_height, p.size());
    }
}

/// The depth-2 tree, every level: each step and the root publish exactly the host's
/// `[vk_c ‖ 2 ‖ B ‖ D_a ‖ D_b]` in cover order, with level 1's `vk_c = vk_leaf` and level 2's
/// `vk_c = vk_t_leaf` (R2). The root's rows, as emulated, are pinned.
#[test]
fn the_test_tree_proves_and_every_level_publishes_the_host_digest() {
    let (l, t) = (leaves(), test_tree());
    let vk_leaf = inner_vk_digest(&l.shape, &l.key);
    let vk_t_leaf = inner_vk_digest(&t.s_step, &RvmKey::of(P, &t.s_step));
    for k in 0..2 {
        assert_eq!(t.steps[k].public_values, u64s(&host_step(&vk_leaf, B, &l.proofs[2 * k], &l.proofs[2 * k + 1])), "step {k}");
    }
    assert_eq!(t.root.public_values, u64s(&host_step(&vk_t_leaf, B, &t.steps[0], &t.steps[1])), "the root");
    let exec = emulate_step(&t.s_step, &t.t_int, &t.steps[0], &t.steps[1], B).expect("rv32t_int accepts the two steps");
    eprintln!("TREE_TEST_INT rows {} tier {} step_bytes {} root_bytes {}", exec.cpu_rows(), t.root.tier.0, t.steps[0].size(), t.root.size());
    assert_eq!(exec.cpu_rows(), common::pin("tree_test", "step_int_cpu_rows"));
    assert_eq!(t.root.tier.0, common::pin("tree_test", "step_int_tier"));
    assert_eq!(t.steps[0].size(), common::pin("tree_test", "step_proof_bytes"));
}

/// Review Focus 2 (R3): `rv32t_int` is built for S_T, the shape of an `rv32t_leaf` proof, and
/// must verify proofs of *itself* at level 3. Its own root declares S_T's words, so the root
/// twice over is a valid level-3 pair: accepted, publishing `vk_int`, which is not `vk_t_leaf`.
#[test]
fn the_interior_step_verifies_its_own_output() {
    let t = test_tree();
    assert!(
        t.s_root.same_step_words(&t.s_step),
        "R3: rv32t_int's own proofs declare another shape: {:?} vs {:?}. Record both in docs/07 §5 and set the test \
         profile's max_depth to 2 (no third program)",
        t.s_root.header_words(),
        t.s_step.header_words()
    );
    let vk_int = inner_vk_digest(&t.s_root, &RvmKey::of(P, &t.s_root));
    let vk_t_leaf = inner_vk_digest(&t.s_step, &RvmKey::of(P, &t.s_step));
    assert_ne!(vk_int, vk_t_leaf, "level 2 and level 3 publish different child keys (R2)");
    let exec = emulate_step(&t.s_root, &t.t_int, &t.root, &t.root, B).expect("rv32t_int accepts two of its own proofs");
    assert_eq!(exec.public, host_step(&vk_int, B, &t.root, &t.root));
}

/// Review Focus 1 (R5, second half): children of a foreign program with identical shape words,
/// under that program's honest cap, pass every in-program check. The step publishes the key it
/// checked against, and the chain's recompute with the pinned `vk_leaf` refuses it. The children's
/// digests equal the honest leaf's (the same run), so `vk_c` is the only difference.
#[test]
fn a_foreign_program_child_pair_passes_in_program_and_fails_the_root_recompute() {
    let (l, t) = (leaves(), test_tree());
    assert!(t.s_foreign.same_step_words(&l.shape));
    assert_eq!(t.foreign.public_values, l.proofs[0].public_values, "the same run publishes the same digest");
    let step = rv32t_leaf(&l.shape, Checkpoints::Off).program;
    let exec = emulate_step(&t.s_foreign, &step, &t.foreign, &t.foreign, B).expect("accepted in-program");
    let vk_foreign = inner_vk_digest(&t.s_foreign, &RvmKey::of(P, &t.s_foreign));
    let vk_leaf = inner_vk_digest(&l.shape, &l.key);
    assert_ne!(vk_foreign, vk_leaf);
    assert_eq!(exec.public, host_step(&vk_foreign, B, &t.foreign, &t.foreign), "it publishes the key it checked against");
    assert_ne!(exec.public, host_step(&vk_leaf, B, &t.foreign, &t.foreign), "the chain's recompute refuses it (Task 2: TreeRootDigest)");
}

/// The two step programs' digests at the test-profile shapes (M4). History: first pinned by tree
/// Task 1b.
const T_LEAF_TEST: &str = "";
const T_INT_TEST: &str = "";

#[test]
fn the_test_tree_program_digests_are_pinned() {
    let t = test_tree();
    let (a, b) = (recursion::programs::digest_hex(&t.t_leaf), recursion::programs::digest_hex(&t.t_int));
    eprintln!("TREE_TEST_DIGESTS t_leaf {a} t_int {b}");
    assert_ne!(a, b, "two programs");
    assert_eq!(a, T_LEAF_TEST, "rv32t_leaf at the test leaf shape");
    assert_eq!(b, T_INT_TEST, "rv32t_int at the test step shape");
}
```

`T_LEAF_TEST` and `T_INT_TEST` are written in Step 4 from the printed line. They are measured pins, not placeholders.

- [ ] **Step 2: Prove the leaves and the foreign leaf on the laptop**

Run: `cargo test --release --features parallel --test tree the_test_tree_program_digests_are_pinned -- --nocapture 2>&1 | grep -E 'missing|panicked' | head -3`
Expected: a panic naming `tree/Test-step-0.rvmproof is missing or stale: run … generate_test_tree_fixtures …`. The four leaves are cached by now (Task 1a) and the foreign leaf has just been proved (tier 18), but the steps are generator-only. If `tree_test.step_leaf_tier` ≤ 18, run the generator here instead: `cargo test --release --features parallel --test tree generate_test_tree_fixtures -- --ignored --nocapture`, and skip Step 3.

- [ ] **Step 3: The steps and the root on the 256 GB droplet**

```bash
git push origin feat/tree-aggregation
H=$HOST256
ssh -A root@$H 'rm -rf /root/circuits && git clone --branch feat/tree-aggregation git@github.com:dendisuhubdy/zkp-circuits.git /root/circuits && git -C /root/circuits rev-parse HEAD > /root/circuits/COMMIT && mkdir -p /root/recursion-fixtures/tree'
rsync -a $RECURSION_FIXTURES/Test-{0,1,2,3}.proof root@$H:/root/recursion-fixtures/
rsync -a $RECURSION_FIXTURES/tree/Test-leaf-{0,1,2,3}.rvmproof $RECURSION_FIXTURES/tree/Test-foreign-0.rvmproof root@$H:/root/recursion-fixtures/tree/
ssh root@$H 'RAYON_NUM_THREADS=32 /root/scripts/step.sh 30-tree-test-fixtures cargo test --release --features parallel --test tree generate_test_tree_fixtures -- --ignored --exact --nocapture'
scp root@$H:/root/out/30-tree-test-fixtures.log docs/measurements/$(date -u +%F)-tree-test-fixtures.log
rsync -a root@$H:/root/recursion-fixtures/tree/ $RECURSION_FIXTURES/tree/
```

Expected: `30-tree-test-fixtures.done` holds `0`, and the log has four `TREE_TEST_FIXTURE` lines. Read off (M2) the maximum RSS and the wall time. The log covers three proofs (step-0, step-1, root) in one process. This is the generator, not a profile, and docs/07 §5 says so.

- [ ] **Step 4: Pin, and run the whole binary**

Run: `cargo test --release --test tree -- --nocapture 2>&1 | grep -E '^TREE_TEST_(INT|DIGESTS)|panicked|test result'`
Expected: `TREE_TEST_INT rows <r> tier <t> step_bytes <s> root_bytes <q>` and `TREE_TEST_DIGESTS t_leaf <hex> t_int <hex>`, then panics at the missing pins. Add `"step_int_cpu_rows": <r>`, `"step_int_tier": <t>` and `"step_proof_bytes": <s>` to the `tree_test` block. Set `T_LEAF_TEST` and `T_INT_TEST` to the two printed hex strings. Re-run.
Expected: `test result: ok. 12 passed; 0 failed; 1 ignored`. If `the_interior_step_verifies_its_own_output` fails at its first assertion, R3 applies: copy the two header-word lists it printed into docs/07 §5, mark the test `#[ignore = "R3: the test-profile fixed point does not hold (docs/07 §5); max_depth 2"]`, and continue. That is a recorded result, not a defect to fix here.

- [ ] **Step 5: docs/07 §5**

Under §5, add: the 8 proofs and where each was proved, with its rows, tier, bytes and the generator's maximum RSS; `rv32t_leaf` vs `rv32t_int` rows (the workloads differ: children of `rv32n` vs children of `rv32t`); the fixed-point verdict (S_T's header words, and the root's); the two test digests; and the four test-profile key digests, printed by adding `eprintln!` of `inner_vk_digest` for `vk_leaf`, `vk_t_leaf` and `vk_int` once and removing it after reading.

- [ ] **Step 6: Commit**

```bash
git add tests/tree.rs tests/pins.json docs/07-tree-aggregation.md docs/measurements/
git commit -m "recursion: the depth-2 test tree proved — 4 leaves, 2 rv32t_leaf, 1 rv32t_int; rv32t_int verifies its own output (fixed point <holds / does not hold>)

rv32t_leaf <rows> rows, rv32t_int <rows> rows, tier <t>, <bytes> B a step; every level publishes
the host's [vk_c ‖ 2 ‖ B ‖ D_a ‖ D_b] (vk_leaf at level 1, vk_t_leaf at level 2, vk_int ≠ vk_t_leaf).
A foreign program's children pass in-program and fail the recompute. Steps proved on the 256 GB
droplet (<GB> max RSS), cached under tree/.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AUWKAos28PQquiLZRVC6jP"
```

---

### Task 2: `verify_tree`, the prover side, and the production depth-2 tree on the droplets

**Files:**
- Modify: `src/aggregate.rs` (after `verify_aggregate`, `:132-168`: `TreeKeys`, `TreeShapes`, `VerifyTreeError`, `tree_root_digest`, `verify_tree`, `prove_tree_step`, `aggregate_tree`; `AggregateError` `:50-68` gains `TreeLayout` and `TreeShape`)
- Modify: `src/shape.rs` (`RvmHeights`, `RvmHeights::of_proof`, `RvmShape::heights`, `RvmShape::try_of_heights`)
- Modify: `tests/tree.rs` (four tests), `tests/tree_measure.rs` (the production tree runs), `tests/pins.json` (`tree_measure` gains the step and root), `docs/07-tree-aggregation.md` §3–§4

**Interfaces:**
- Produces, in `shape.rs`: `pub struct RvmHeights { pub tier: crate::machine::Tier, pub reg_log_height: u8, pub ram_log_height: u8, pub poseidon2_log_height: u8, pub reduce_log_height: u8 }` (`Clone, Copy, Debug, PartialEq, Eq`); `RvmHeights::of_proof(&machine::Proof) -> RvmHeights`; `RvmShape::heights(&self) -> RvmHeights`; `RvmShape::try_of_heights(profile, program: &Arc<Program>, h: RvmHeights) -> Result<RvmShape, ShapeError>`.
- Produces, in `aggregate.rs`:
  - `pub struct TreeKeys { pub vk_leaf: [F; 4], pub vk_t_leaf: [F; 4], pub vk_int: [F; 4] }` with `fn at_level(&self, level: u32) -> [F; 4]` (1 → `vk_leaf`, 2 → `vk_t_leaf`, ≥ 3 → `vk_int`).
  - `pub struct TreeShapes { pub leaf: RvmShape, pub t_leaf: RvmShape, pub t_int: RvmShape }` with `fn build(profile, inner: &InnerVerifierKey, leaf: RvmHeights, step: RvmHeights) -> Result<TreeShapes, ShapeError>`, `fn keys(&self) -> TreeKeys`, `fn child_at(&self, level: u32) -> &RvmShape`, `fn root_program(&self, depth: u32) -> &Program`.
  - `pub enum VerifyTreeError { TreeDepth { depth: u32 }, TreeLayout { covers: usize, leaf_size: usize }, TreeRootDigest, Verify(VerifyError) }`.
  - `pub fn tree_root_digest(inner: &InnerVerifierKey, covered: &[Vec<u64>], binding: &[u32; 8], leaf_size: usize, depth: u32, keys: &TreeKeys) -> Result<[F; 4], VerifyTreeError>`.
  - `pub fn verify_tree(m: &Machine, root_program: &Program, proof: &crate::machine::Proof, inner: &InnerVerifierKey, covered: &[Vec<u64>], binding: &[u32; 8], leaf_size: usize, depth: u32, keys: &TreeKeys) -> Result<Vec<[u32; 8]>, VerifyTreeError>`.
  - `pub fn prove_tree_step(m: &Machine, child: &RvmShape, children: [&crate::machine::Proof; 2], binding: &[u32; 8], tier: Option<Tier>) -> Result<crate::machine::Proof, AggregateError>`.
  - `pub fn aggregate_tree(m: &Machine, inner: &InnerVerifierKey, shapes: &TreeShapes, proofs: &[InnerProof], binding: &[u32; 8], leaf_size: usize) -> Result<(crate::machine::Proof, u32), AggregateError>`, returning the root and its depth.
  - `AggregateError::{TreeLayout { covers: usize, leaf_size: usize }, TreeShape { level: u32 }}`.
- Consumes: Task 1a's `verify_rv32t`, `TREE_ARITY`, `build_tree_step`, `tree_step_words`; `interface_words_bound`, `public_digest`, `inner_vk_digest`; `Machine::verify_n`.

`verify_tree` is spec §4's recompute plus R2's per-level key: the layout check, the bottom-up digest, the compare, then `verify_n(root_program, proof, 2)`. It is cheap before expensive, in `verify_aggregate`'s order. Choosing `root_program` (t_leaf at depth 1, t_int otherwise) and pinning the keys belong to the caller: in the chain's case, admission's step 7b.

- [ ] **Step 1: Write the failing tests**

Append to `tests/tree.rs`:

```rust
// ── Task 2: verify_tree ──────────────────────────────────────────────────────────────────────

use recursion::aggregate::{tree_root_digest, verify_tree, TreeKeys, TreeShapes, VerifyTreeError};
use recursion::shape::RvmHeights;

fn covered(n: usize) -> Vec<Vec<u64>> {
    leaves().bundles[..n].iter().map(|b| b.public_values.clone()).collect()
}

fn test_keys() -> TreeKeys {
    let (l, t) = (leaves(), test_tree());
    TreeKeys {
        vk_leaf: inner_vk_digest(&l.shape, &l.key),
        vk_t_leaf: inner_vk_digest(&t.s_step, &RvmKey::of(P, &t.s_step)),
        vk_int: inner_vk_digest(&t.s_root, &RvmKey::of(P, &t.s_root)),
    }
}

/// The proved depth-2 test tree verifies through the chain-facing call, returning the four
/// covered bundles' `OUT0..7` in cover order.
#[test]
fn verify_tree_accepts_the_test_tree() {
    let (l, t) = (leaves(), test_tree());
    let outs = verify_tree(&Machine::new(P), &t.t_int, &t.root, &l.inner, &covered(4), B, 1, 2, &test_keys())
        .expect("the depth-2 test tree verifies");
    for (j, out) in outs.iter().enumerate() {
        let want: [u32; 8] = std::array::from_fn(|k| u32::try_from(l.bundles[j].public_values[rand_zkvm::tables::cpu::pv::OUT0 + k]).unwrap());
        assert_eq!(*out, want, "bundle {j}");
    }
}

/// Every refusal by name, each before `verify_n` builds a key except the last: a count that is
/// not L·2^d, depth 0, a swapped cover order, another binding, a leaf presented as a depth-1 root
/// (a flat proof as a tree), the foreign-cap step (Task 1b), and the root verified as the wrong
/// program.
#[test]
fn verify_tree_names_every_refusal() {
    let (l, t) = (leaves(), test_tree());
    let m = Machine::new(P);
    let k = test_keys();
    let c4 = covered(4);
    assert!(matches!(verify_tree(&m, &t.t_int, &t.root, &l.inner, &c4[..3], B, 1, 2, &k), Err(VerifyTreeError::TreeLayout { covers: 3, leaf_size: 1 })));
    assert!(matches!(verify_tree(&m, &t.t_int, &t.root, &l.inner, &c4[..1], B, 1, 0, &k), Err(VerifyTreeError::TreeDepth { depth: 0 })));
    let swapped = vec![c4[1].clone(), c4[0].clone(), c4[2].clone(), c4[3].clone()];
    assert!(matches!(verify_tree(&m, &t.t_int, &t.root, &l.inner, &swapped, B, 1, 2, &k), Err(VerifyTreeError::TreeRootDigest)));
    assert!(matches!(verify_tree(&m, &t.t_int, &t.root, &l.inner, &c4, &[7; 8], 1, 2, &k), Err(VerifyTreeError::TreeRootDigest)));
    assert!(matches!(verify_tree(&m, &t.t_leaf, &l.proofs[0], &l.inner, &c4[..2], B, 1, 1, &k), Err(VerifyTreeError::TreeRootDigest)),
        "a flat proof (a leaf) is not a depth-1 tree");
    let wrong_keys = TreeKeys { vk_t_leaf: k.vk_int, ..k };
    assert!(matches!(verify_tree(&m, &t.t_int, &t.root, &l.inner, &c4, B, 1, 2, &wrong_keys), Err(VerifyTreeError::TreeRootDigest)),
        "a level recomputed under another level's key");
    assert!(matches!(verify_tree(&m, &t.t_leaf, &t.root, &l.inner, &c4, B, 1, 2, &k), Err(VerifyTreeError::Verify(_))),
        "the root verified as rv32t_leaf's proof");
}

/// Review Focus 4 (R2): at depth 3 the levels use `vk_leaf`, `vk_t_leaf`, `vk_int` in that
/// order. A host-only recompute over eight covered lists, against a hand-rolled one, with three
/// distinct keys; swapping any two moves the root.
#[test]
fn verify_tree_selects_vk_leaf_vk_t_leaf_vk_int_by_level() {
    let l = leaves();
    let pvs: Vec<Vec<u64>> = (0..8).map(|j| (0..35).map(|k| 1000 * j + k).collect()).collect();
    let keys = TreeKeys { vk_leaf: [F::from_u64(1); 4], vk_t_leaf: [F::from_u64(2); 4], vk_int: [F::from_u64(3); 4] };
    let leaf_d: Vec<[F; 4]> = pvs.iter().map(|p| public_digest(&recursion::public_values::interface_words_bound(&l.inner.shape, &l.inner.key, B, std::slice::from_ref(p)))).collect();
    let step = |vk: [F; 4], a: [F; 4], b: [F; 4]| public_digest(&tree_step_words(&vk, B, &a, &b));
    let l1: Vec<[F; 4]> = leaf_d.chunks(2).map(|p| step(keys.vk_leaf, p[0], p[1])).collect();
    let l2: Vec<[F; 4]> = l1.chunks(2).map(|p| step(keys.vk_t_leaf, p[0], p[1])).collect();
    let root = step(keys.vk_int, l2[0], l2[1]);
    assert_eq!(tree_root_digest(&l.inner, &pvs, B, 1, 3, &keys).unwrap(), root);
    for swapped in [TreeKeys { vk_t_leaf: keys.vk_int, vk_int: keys.vk_t_leaf, ..keys }, TreeKeys { vk_leaf: keys.vk_t_leaf, vk_t_leaf: keys.vk_leaf, ..keys }] {
        assert_ne!(tree_root_digest(&l.inner, &pvs, B, 1, 3, &swapped).unwrap(), root);
    }
}

/// What the node rebuilds from a genesis (`TreeShapes::build` over the pinned heights) is the
/// test tree's own programs and keys.
#[test]
fn the_tree_shapes_rebuild_the_test_tree_programs_and_keys() {
    let (l, t) = (leaves(), test_tree());
    let s = TreeShapes::build(P, &l.inner, RvmHeights::of_proof(&l.proofs[0]), RvmHeights::of_proof(&t.steps[0])).unwrap();
    assert_eq!(s.t_leaf.program.digest(), t.t_leaf.digest(), "rv32t_leaf");
    assert_eq!(s.t_int.program.digest(), t.t_int.digest(), "rv32t_int");
    assert_eq!(s.keys(), test_keys());
}
```

Run: `cargo test --release --test tree verify_tree 2>&1 | grep -E '^error' | sort -u | head`
Expected: unresolved `tree_root_digest`, `verify_tree`, `TreeKeys`, `TreeShapes`, `VerifyTreeError`, `RvmHeights`.

- [ ] **Step 2: The heights**

In `src/shape.rs`, after `RvmKey`'s `impl ShapeKey`:

```rust
/// The five words an rVM proof declares: what a chain pins for a tree's leaf and step shapes
/// (R4), from which the node rebuilds `RvmShape`s, the step programs and their keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RvmHeights {
    pub tier: crate::machine::Tier,
    pub reg_log_height: u8,
    pub ram_log_height: u8,
    pub poseidon2_log_height: u8,
    pub reduce_log_height: u8,
}

impl RvmHeights {
    pub fn of_proof(p: &crate::machine::Proof) -> Self {
        RvmHeights { tier: p.tier, reg_log_height: p.reg_log_height, ram_log_height: p.ram_log_height,
            poseidon2_log_height: p.poseidon2_log_height, reduce_log_height: p.reduce_log_height }
    }
}
```

and in `impl RvmShape`:

```rust
    pub fn heights(&self) -> RvmHeights {
        RvmHeights { tier: crate::machine::Tier(self.tier), reg_log_height: self.reg_log_height, ram_log_height: self.ram_log_height,
            poseidon2_log_height: self.poseidon2_log_height, reduce_log_height: self.reduce_log_height }
    }

    /// [`RvmShape::try_of`] over pinned heights: a genesis's numbers, which this node did not choose.
    pub fn try_of_heights(profile: FriProfile, program: &std::sync::Arc<crate::isa::Program>, h: RvmHeights) -> Result<Self, ShapeError> {
        Self::try_of(profile, program, h.tier, h.reg_log_height, h.ram_log_height, h.poseidon2_log_height, h.reduce_log_height)
    }
```

- [ ] **Step 3: `verify_tree` and the prover side**

In `src/aggregate.rs`, add to the imports `use crate::programs::{verify_rv32t, TREE_ARITY};`, `use crate::public_values::tree_step_words;`, `use crate::shape::{inner_vk_digest, RvmHeights, RvmKey, RvmShape, ShapeError};`, `use p3_field::PrimeCharacteristicRing;` and `use std::sync::Arc;`. Add to `AggregateError`:

```rust
    /// A tree covers exactly `leaf_size · 2^d` proofs, `d ≥ 1` (spec §2's layout rule).
    TreeLayout { covers: usize, leaf_size: usize },
    /// A proof produced at tree level `level` (0 = a leaf) does not declare the pinned shape:
    /// the next level's program could not verify it, and the chain would refuse the root.
    TreeShape { level: u32 },
```

After `verify_aggregate`:

```rust
// ── tree aggregation (spec §2–§4; plan R2–R4) ─────────────────────────────────────────────────

/// The child key digests a tree's levels publish (R2): level 1's children are `rv32n` leaves,
/// level 2's are `rv32t_leaf` steps, every higher level's are `rv32t_int` steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeKeys {
    pub vk_leaf: [F; 4],
    pub vk_t_leaf: [F; 4],
    pub vk_int: [F; 4],
}

impl TreeKeys {
    /// The `vk_c` a level-`level` step publishes (1-based).
    pub fn at_level(&self, level: u32) -> [F; 4] {
        match level {
            1 => self.vk_leaf,
            2 => self.vk_t_leaf,
            _ => self.vk_int,
        }
    }
}

/// A tree's three child shapes, each carrying its own program: the leaf (`rv32n`), level 1's
/// output (`rv32t_leaf`'s proofs) and level ≥ 2's output (`rv32t_int`'s). `rv32t_int` is built
/// over `t_leaf`. When the fixed point holds (R3), its own proofs declare the same heights, so
/// `t_int` is `t_leaf`'s heights over `rv32t_int`'s program.
#[derive(Clone, Debug)]
pub struct TreeShapes {
    pub leaf: RvmShape,
    pub t_leaf: RvmShape,
    pub t_int: RvmShape,
}

impl TreeShapes {
    /// From the pinned leaf and step heights (R4): build `rv32n`, then `rv32t_leaf` over the
    /// leaf shape, then `rv32t_int` over `rv32t_leaf`'s output shape.
    pub fn build(profile: crate::machine::FriProfile, inner: &InnerVerifierKey, leaf: RvmHeights, step: RvmHeights) -> Result<Self, ShapeError> {
        let p_leaf = Arc::new(aggregate_program(inner));
        let leaf = RvmShape::try_of_heights(profile, &p_leaf, leaf)?;
        let p_t_leaf = Arc::new(verify_rv32t(&leaf, crate::dsl::Checkpoints::Off).program);
        let t_leaf = RvmShape::try_of_heights(profile, &p_t_leaf, step)?;
        let p_t_int = Arc::new(verify_rv32t(&t_leaf, crate::dsl::Checkpoints::Off).program);
        let t_int = RvmShape::try_of_heights(profile, &p_t_int, step)?;
        Ok(TreeShapes { leaf, t_leaf, t_int })
    }

    pub fn keys(&self) -> TreeKeys {
        let vk = |s: &RvmShape| inner_vk_digest(s, &RvmKey::of(s.profile, s));
        TreeKeys { vk_leaf: vk(&self.leaf), vk_t_leaf: vk(&self.t_leaf), vk_int: vk(&self.t_int) }
    }

    /// The shape of level `level`'s children (1-based): what that level's tape is built against.
    pub fn child_at(&self, level: u32) -> &RvmShape {
        match level {
            1 => &self.leaf,
            2 => &self.t_leaf,
            _ => &self.t_int,
        }
    }

    /// The root's program at `depth`: `rv32t_leaf` for a depth-1 tree, `rv32t_int` otherwise.
    pub fn root_program(&self, depth: u32) -> &Program {
        if depth == 1 { &self.t_leaf.program } else { &self.t_int.program }
    }
}

/// Why a tree aggregate did not verify (spec §4's errors that are the verifier's; the chain adds
/// its own around them).
#[derive(Debug)]
pub enum VerifyTreeError {
    TreeDepth { depth: u32 },
    TreeLayout { covers: usize, leaf_size: usize },
    /// The bottom-up recompute is not the proof's four public values.
    TreeRootDigest,
    Verify(VerifyError),
}

/// The root digest the chain expects (ZKQ-5's rule): leaf `i` is the flat bound list over its
/// `leaf_size` covered public-value runs, and each level `j ≥ 1` is `[keys.at_level(j) ‖ 2 ‖ B ‖
/// D_a ‖ D_b]` over adjacent pairs, in cover order, under the one `binding`.
pub fn tree_root_digest(
    inner: &InnerVerifierKey,
    covered: &[Vec<u64>],
    binding: &[u32; 8],
    leaf_size: usize,
    depth: u32,
    keys: &TreeKeys,
) -> Result<[F; 4], VerifyTreeError> {
    if depth == 0 || depth >= usize::BITS {
        return Err(VerifyTreeError::TreeDepth { depth });
    }
    if leaf_size == 0 || covered.len() != leaf_size << depth {
        return Err(VerifyTreeError::TreeLayout { covers: covered.len(), leaf_size });
    }
    let mut level: Vec<[F; 4]> = covered
        .chunks(leaf_size)
        .map(|leaf| public_digest(&interface_words_bound(&inner.shape, &inner.key, binding, leaf)))
        .collect();
    for j in 1..=depth {
        let vk = keys.at_level(j);
        level = level.chunks(2).map(|p| public_digest(&tree_step_words(&vk, binding, &p[0], &p[1]))).collect();
    }
    debug_assert_eq!(level.len(), 1, "L·2^d covers fold to one root");
    Ok(level[0])
}

/// Spec §4's `verify_tree`: the layout, the bottom-up recompute against the proof's public
/// values, then `Machine::verify_n(root_program, proof, 2)`, so the canonical reduce height holds
/// for the step (R1). Returns each covered bundle's `OUT0..7`, as `verify_aggregate` does.
#[allow(clippy::too_many_arguments)]
pub fn verify_tree(
    m: &Machine,
    root_program: &Program,
    proof: &crate::machine::Proof,
    inner: &InnerVerifierKey,
    covered: &[Vec<u64>],
    binding: &[u32; 8],
    leaf_size: usize,
    depth: u32,
    keys: &TreeKeys,
) -> Result<Vec<[u32; 8]>, VerifyTreeError> {
    let root = tree_root_digest(inner, covered, binding, leaf_size, depth, keys)?;
    let want: Vec<u64> = root.iter().map(|f| f.as_canonical_u64()).collect();
    if proof.public_values != want {
        return Err(VerifyTreeError::TreeRootDigest);
    }
    m.verify_n(root_program, proof, TREE_ARITY).map_err(VerifyTreeError::Verify)?;
    Ok(covered
        .iter()
        .map(|pvs| {
            std::array::from_fn(|k| {
                u32::try_from(pvs[pv::OUT0 + k]).expect("OUT words are u32-range by the inner machine's construction")
            })
        })
        .collect())
}

/// One interior step proved: the tape, the proof, and the host's own `[vk_c ‖ 2 ‖ B ‖ D_a ‖ D_b]`
/// compared with what the proof publishes, at prove time (`aggregate`'s R6 discipline).
pub fn prove_tree_step(
    m: &Machine,
    child: &RvmShape,
    children: [&crate::machine::Proof; 2],
    binding: &[u32; 8],
    tier: Option<Tier>,
) -> Result<crate::machine::Proof, AggregateError> {
    let program = verify_rv32t(child, crate::dsl::Checkpoints::Off).program;
    let tape = WitnessTape::build_tree_step(m.profile, child, children, binding).map_err(AggregateError::Tape)?;
    let (proof, _exec) = m.prove(&program, &tape.words, tier).map_err(AggregateError::Prove)?;
    let vk = inner_vk_digest(child, &RvmKey::of(m.profile, child));
    let d = |p: &crate::machine::Proof| -> [F; 4] { std::array::from_fn(|k| F::from_u64(p.public_values[k])) };
    let want: Vec<u64> = public_digest(&tree_step_words(&vk, binding, &d(children[0]), &d(children[1])))
        .iter()
        .map(|f| f.as_canonical_u64())
        .collect();
    if proof.public_values != want {
        return Err(AggregateError::DigestMismatch);
    }
    Ok(proof)
}

/// A whole tree on one machine (the aggregate daemon's `--layout tree`): `L·2^d` bundle proofs →
/// `2^d` leaves → `d` levels of steps. Every produced proof is checked against its pinned shape
/// before the next level is built on it. Returns the root and `d`.
pub fn aggregate_tree(
    m: &Machine,
    inner: &InnerVerifierKey,
    shapes: &TreeShapes,
    proofs: &[InnerProof],
    binding: &[u32; 8],
    leaf_size: usize,
) -> Result<(crate::machine::Proof, u32), AggregateError> {
    let leaves = proofs.len().checked_div(leaf_size).unwrap_or(0);
    if leaf_size == 0 || proofs.len() % leaf_size != 0 || leaves < 2 || !leaves.is_power_of_two() {
        return Err(AggregateError::TreeLayout { covers: proofs.len(), leaf_size });
    }
    let depth = leaves.trailing_zeros();
    let mut level: Vec<crate::machine::Proof> = Vec::with_capacity(leaves);
    for chunk in proofs.chunks(leaf_size) {
        let p = aggregate(m, inner, chunk, binding, None)?.proof;
        if !shapes.leaf.matches(&p) {
            return Err(AggregateError::TreeShape { level: 0 });
        }
        level.push(p);
    }
    for j in 1..=depth {
        let child = shapes.child_at(j);
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let p = prove_tree_step(m, child, [&pair[0], &pair[1]], binding, None)?;
            let out = if j == 1 { &shapes.t_leaf } else { &shapes.t_int };
            if !out.matches(&p) {
                return Err(AggregateError::TreeShape { level: j });
            }
            next.push(p);
        }
        level = next;
    }
    Ok((level.pop().expect("one root"), depth))
}
```

`aggregate()` already returns `AggregateError`, so `?` composes. `F::from_u64` needs `PrimeCharacteristicRing` (imported above). `pv` is the existing `rand_zkvm::tables::cpu::pv` import (`:18`).

Run: `cargo test --release --test tree -- --nocapture 2>&1 | grep -E 'test result|FAILED|panicked'`
Expected: `test result: ok. 16 passed; 0 failed; 1 ignored`.

- [ ] **Step 4: Commit the API before the droplets clone it**

```bash
git add src/aggregate.rs src/shape.rs tests/tree.rs
git commit -m "recursion: verify_tree — the bottom-up recompute with vk_leaf, vk_t_leaf, vk_int by level, then verify_n(…, 2); prove_tree_step and aggregate_tree

The test-profile depth-2 tree verifies; a count not L·2^d, depth 0, a swapped cover order,
another binding, a flat proof presented as a tree and a level under another level's key are
each refused by name before any key build. TreeShapes rebuilds the programs and keys from the
pinned heights (what the node does at startup).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AUWKAos28PQquiLZRVC6jP"
git push origin feat/tree-aggregation
```

- [ ] **Step 5: The production tree runs**

Append to `tests/tree_measure.rs` (add `use recursion::aggregate::{prove_tree_step, verify_tree, TreeKeys};`, `use recursion::programs::{verify_rv32t, TREE_ARITY};` and `use recursion::shape::inner_vk_digest;`):

```rust
// ── Task 2: the production depth-2 tree (4 leaves of L = 2; 2 rv32t_leaf; 1 rv32t_int) ──────────

fn env_index(var: &str, max: usize) -> usize {
    let k: usize = std::env::var(var).unwrap_or_else(|_| panic!("set {var}")).parse().expect("an index");
    assert!(k <= max, "{var} ≤ {max}");
    k
}

/// Leaves 1–3 (the 256 GB droplet, one per process): `TREE_LEAF=k`. Leaf 0 is Task 0's.
#[test]
#[ignore = "tree Task 2: production leaf k (TREE_LEAF=1..3) — the 256 GB droplet"]
fn production_tree_leaf() {
    let k = env_index("TREE_LEAF", 3);
    assert!(k >= 1, "leaf 0 is Task 0's production_leaf_l2");
    prove_leaf(k);
}

/// The production leaf shape and program, read off cached leaf 0.
fn production_leaf_shape() -> (InnerVerifierKey, Arc<Program>, RvmShape) {
    let proofs = bundles(0, L);
    let vk = inner(&proofs[0]);
    let program = Arc::new(aggregate_program(&vk));
    let leaf = load("Production-leaf-0", &program, L as u64);
    let shape = RvmShape::of_proof(P, &program, &leaf);
    (vk, program, shape)
}

/// Step `TREE_STEP=k` ∈ {0, 1}: `rv32t_leaf` over leaves (2k, 2k + 1). Emulated first, against
/// docs/07 §2's band (M5), then proved under the heap profiler. The 503 GB droplet.
#[test]
#[ignore = "tree Task 2: production rv32t_leaf step k (TREE_STEP=0|1), 1.7-2.9 M rows projected, 290-500 GB — the 503 GB droplet"]
fn production_tree_step() {
    let k = env_index("TREE_STEP", 1);
    let (_vk, program, shape) = production_leaf_shape();
    let a = load(&format!("Production-leaf-{}", 2 * k), &program, L as u64);
    let b = load(&format!("Production-leaf-{}", 2 * k + 1), &program, L as u64);
    let vp = verify_rv32t(&shape, Checkpoints::Off);
    let tape = WitnessTape::build_tree_step(P, &shape, [&a, &b], &common::TEST_BINDING).unwrap();
    let rows = execute(&vp.program, &tape.words, MAX_CYCLES).expect("rv32t_leaf accepts two production leaves").cpu_rows();
    let (lo, hi) = (common::pin("tree_measure", "step_band_lo"), common::pin("tree_measure", "step_band_hi"));
    println!("== step {k} emulated: {rows} rows, tier {:?}, band [{lo}, {hi}] {}", Tier::for_cycles(rows),
        if (lo..=hi).contains(&rows) { "IN" } else { "OUT: write the correction into docs/07 §2 (M5)" });
    let t0 = install();
    let m = Machine::new(P);
    let t = Instant::now();
    let proof = prove_tree_step(&m, &shape, [&a, &b], &common::TEST_BINDING, None).expect("the step proves");
    let prove_s = t.elapsed().as_secs_f64();
    let tv = Instant::now();
    m.verify_n(&vp.program, &proof, TREE_ARITY).expect("the step verifies at n = 2");
    println!("verify {:.2} s", tv.elapsed().as_secs_f64());
    save(&format!("Production-step-{k}"), &proof);
    heights(&format!("step {k}"), &proof);
    report(&format!("tree step {k}: rv32t_leaf (production)"), t0, rows, proof.tier, proof.size(), prove_s);
}

/// The root: `rv32t_int` over steps 0 and 1, proved, then verified through `verify_tree` with
/// the production keys, and the fixed point (R3) read off its header. The 503 GB droplet.
#[test]
#[ignore = "tree Task 2: production rv32t_int root over the two steps, then verify_tree — the 503 GB droplet"]
fn production_tree_root() {
    let (vk, _program, leaf_shape) = production_leaf_shape();
    let t_leaf = Arc::new(verify_rv32t(&leaf_shape, Checkpoints::Off).program);
    let s0 = load("Production-step-0", &t_leaf, TREE_ARITY);
    let s1 = load("Production-step-1", &t_leaf, TREE_ARITY);
    let s_step = RvmShape::of_proof(P, &t_leaf, &s0);
    let vp = verify_rv32t(&s_step, Checkpoints::Off);
    let tape = WitnessTape::build_tree_step(P, &s_step, [&s0, &s1], &common::TEST_BINDING).unwrap();
    let rows = execute(&vp.program, &tape.words, MAX_CYCLES).expect("rv32t_int accepts the two steps").cpu_rows();
    println!("== root emulated: {rows} rows, tier {:?}", Tier::for_cycles(rows));
    let t0 = install();
    let m = Machine::new(P);
    let t = Instant::now();
    let root = prove_tree_step(&m, &s_step, [&s0, &s1], &common::TEST_BINDING, None).expect("the root proves");
    let prove_s = t.elapsed().as_secs_f64();
    save("Production-root", &root);
    let s_root = RvmShape::of_proof(P, &Arc::new(vp.program.clone()), &root);
    let keys = TreeKeys {
        vk_leaf: inner_vk_digest(&leaf_shape, &RvmKey::of(P, &leaf_shape)),
        vk_t_leaf: inner_vk_digest(&s_step, &RvmKey::of(P, &s_step)),
        vk_int: inner_vk_digest(&s_root, &RvmKey::of(P, &s_root)),
    };
    let covered: Vec<Vec<u64>> = bundles(0, 4 * L).iter().map(|p| p.public_values.clone()).collect();
    let tv = Instant::now();
    verify_tree(&m, &vp.program, &root, &vk, &covered, &common::TEST_BINDING, L, 2, &keys).expect("the production tree verifies");
    println!("verify_tree {:.2} s", tv.elapsed().as_secs_f64());
    println!("== fixed point (R3): {}", if s_root.same_step_words(&s_step) { "HOLDS" } else { "FAILS — production max_depth 2" });
    heights("root", &root);
    report("tree root: rv32t_int (production)", t0, rows, root.tier, root.size(), prove_s);
}

/// The chain's genesis values (docs/07 §4; Task 3a's `aggregation_tree`), printed from the cached
/// leaf, step and root: the heights, the two program digests, the three key digests.
#[test]
#[ignore = "tree Task 2: prints the production aggregation_tree genesis values from the cached tree"]
fn production_tree_genesis_values() {
    let (_vk, program, leaf_shape) = production_leaf_shape();
    let t_leaf = Arc::new(verify_rv32t(&leaf_shape, Checkpoints::Off).program);
    let s0 = load("Production-step-0", &t_leaf, TREE_ARITY);
    let s_step = RvmShape::of_proof(P, &t_leaf, &s0);
    let t_int = Arc::new(verify_rv32t(&s_step, Checkpoints::Off).program);
    let s_int = RvmShape::try_of_heights(P, &t_int, s_step.heights()).unwrap();
    let hex = |d: [recursion::isa::F; 4]| d.map(|f| p3_field::PrimeField64::as_canonical_u64(&f));
    println!("== aggregate_program_digest {:?}", hex(program.digest()));
    println!("== leaf heights {:?}", leaf_shape.heights());
    println!("== step heights {:?}", s_step.heights());
    println!("== t_leaf_digest {:?}", hex(t_leaf.digest()));
    println!("== t_int_digest {:?}", hex(t_int.digest()));
    println!("== vk_leaf {:?}", hex(inner_vk_digest(&leaf_shape, &RvmKey::of(P, &leaf_shape))));
    println!("== vk_t_leaf {:?}", hex(inner_vk_digest(&s_step, &RvmKey::of(P, &s_step))));
    println!("== vk_int {:?}", hex(inner_vk_digest(&s_int, &RvmKey::of(P, &s_int))));
}
```

Run: `cargo test --release --test tree_measure -- --list 2>/dev/null | grep -c ': test'`
Expected: `8`.

- [ ] **Step 6: Run the tree**

The leaves, on `$HOST256`, one at a time (each ≈ Task 0's leaf: same rows, same memory):

```bash
H=$HOST256
ssh -A root@$H 'cd /root/circuits && git fetch origin && git checkout --detach origin/feat/tree-aggregation && git rev-parse HEAD > COMMIT'
rsync -a $RECURSION_FIXTURES/Production-{2,3,4,5,6,7}.proof root@$H:/root/recursion-fixtures/
for k in 1 2 3; do ssh root@$H "TREE_LEAF=$k RAYON_NUM_THREADS=32 /root/scripts/step.sh 40-tree-leaf-$k cargo test --release --features parallel --test tree_measure production_tree_leaf -- --ignored --exact --nocapture"; done
for k in 1 2 3; do scp root@$H:/root/out/40-tree-leaf-$k.log docs/measurements/$(date -u +%F)-tree-leaf-$k-production.log; done
rsync -a root@$H:/root/recursion-fixtures/tree/ $RECURSION_FIXTURES/tree/
```

(Run them under `nohup … &` with a `.done` poll, as in Task 0 Step 6, if the session cannot stay open for the hours each takes.) Then the steps and the root, on `$HOST503`:

```bash
H=$HOST503
ssh -A root@$H 'cd /root/circuits && git fetch origin && git checkout --detach origin/feat/tree-aggregation && git rev-parse HEAD > COMMIT'
rsync -a $RECURSION_FIXTURES/Production-{0,1,2,3,4,5,6,7}.proof root@$H:/root/recursion-fixtures/
rsync -a $RECURSION_FIXTURES/tree/Production-leaf-{0,1,2,3}.rvmproof root@$H:/root/recursion-fixtures/tree/
for k in 0 1; do ssh root@$H "TREE_STEP=$k RAYON_NUM_THREADS=64 /root/scripts/step.sh 41-tree-step-$k cargo test --release --features parallel --test tree_measure production_tree_step -- --ignored --exact --nocapture"; done
ssh root@$H 'RAYON_NUM_THREADS=64 /root/scripts/step.sh 42-tree-root cargo test --release --features parallel --test tree_measure production_tree_root -- --ignored --exact --nocapture'
ssh root@$H '/root/scripts/step.sh 43-tree-genesis cargo test --release --test tree_measure production_tree_genesis_values -- --ignored --exact --nocapture'
for n in 41-tree-step-0 41-tree-step-1 42-tree-root 43-tree-genesis; do scp root@$H:/root/out/$n.log docs/measurements/$(date -u +%F)-tree-${n#4?-tree-}-production.log; done
rsync -a root@$H:/root/recursion-fixtures/tree/ $RECURSION_FIXTURES/tree/
```

Expected: every `.done` holds `0`. `41-tree-step-0` prints `== step 0 emulated: … band [lo, hi] IN`. `42-tree-root` prints `verify_tree … s` and `== fixed point (R3): HOLDS`. **Stop:** a step or the root killed for memory on the 503 GB box. Record the peak it reached (the `.rss` file's last line) in docs/07 §3 and halt for a decision (spec ruling 1: the memory track first).

- [ ] **Step 7: Pins, docs/07 §3–§4**

Add to the `tree_measure` block (M3): `step_cpu_rows`, `step_tier`, `step_peak_live_mb`, `step_prove_s`, `step_proof_bytes` (from step 0; step 1 must have equal rows, which docs/07 records), and `root_cpu_rows`, `root_tier`, `root_peak_live_mb`, `root_prove_s`, `root_proof_bytes`, `verify_tree_ms`. Add to `tests/tree_measure.rs`:

```rust
#[test]
#[ignore = "tree Task 2: the production step's rows against a fresh emulation; needs the cached leaves 0 and 1"]
fn the_production_step_rows_are_pinned() {
    let (_vk, program, shape) = production_leaf_shape();
    let a = load("Production-leaf-0", &program, L as u64);
    let b = load("Production-leaf-1", &program, L as u64);
    let vp = verify_rv32t(&shape, Checkpoints::Off);
    let tape = WitnessTape::build_tree_step(P, &shape, [&a, &b], &common::TEST_BINDING).unwrap();
    assert_eq!(execute(&vp.program, &tape.words, MAX_CYCLES).unwrap().cpu_rows(), common::pin("tree_measure", "step_cpu_rows"));
}
```

docs/07 §3: one table row per proof (4 leaves, 2 steps, 1 root) with host, rows, tier, the heights, prove, verify, proof bytes, peak live and maximum RSS, plus the log path. §4: the step measured against Task 0's band (in or out, and the correction if out); the root against the step (`rv32t_int` vs `rv32t_leaf` rows); the fixed-point verdict and the production `max_depth` it implies (3 if it holds, 2 if not); the genesis values, verbatim from `43-tree-genesis` (aggregate program digest, leaf and step heights, `t_leaf_digest`, `t_int_digest`, `vk_leaf`, `vk_t_leaf`, `vk_int`); the host class each proof needs; and the gate's circuits half met (depth 2, real bundle proofs, every step measured).

Run on `$HOST503`: `step.sh 44-tree-pins cargo test --release --test tree_measure the_production_step_rows_are_pinned -- --ignored --exact`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add tests/tree_measure.rs tests/pins.json docs/07-tree-aggregation.md docs/measurements/
git commit -m "recursion: the production depth-2 tree — 4 leaves (L = 2), 2 rv32t_leaf at <rows> rows tier <t>, rv32t_int root <rows> rows; verify_tree accepts it

Steps: prove <s> s, <GB> GB live, <bytes> B (503 GB droplet); band [<lo>, <hi>]: <in/out>.
Root: prove <s> s, <GB> GB live; verify_tree <ms> ms. Fixed point <holds/fails> → production
max_depth <3/2>. Genesis values in docs/07 §4.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AUWKAos28PQquiLZRVC6jP"
```

---

### Task 3a: The chain, core — the layout, the genesis section, the admission branch

**Prerequisite:** fullnode `main` carries the phase-3 re-vendor (Global Constraints). Branch `feat/tree-aggregation` off it. Every command runs from `~/Github/randprotocol/fullnode`.

**Files:**
- Modify: `crates/randprotocol-core/src/types/transaction.rs` (`Action::Aggregate`, `:210-220`, gains `layout`; `blanked` `:649-660`; the test `sample` row 13, `:1912`), plus every destructuring site the compiler names
- Modify: `crates/randprotocol-core/src/types/binding.rs` (`aggregate_tree_signing_hash` beside `aggregate_signing_hash`, `:228-246`), `crates/randprotocol-core/src/types/actions.rs` (the `ChainId`-domain twin beside `:601-612`)
- Modify: `crates/randprotocol-core/src/ledger/aggregation.rs` (`TreeConfig`, `RvmHeights`, `tree_depth`; errors `:124-194`; `validate_aggregate` `:427-559`; `preflight_aggregate` `:588-631`; the tests)
- Modify: `crates/randprotocol-core/src/genesis.rs` (`aggregation_tree` beside `aggregation`, `:348-353`; its check after `check_aggregation`'s call, `:767-769`; the hash commit after `perps`, `:1535-1538`), `crates/randprotocol-core/src/ledger/mod.rs` (`set_aggregation_tree`/`aggregation_tree` beside `:1467-1475`)
- Modify: `crates/randprotocol-core/src/confidential.rs` (`ConfidentialError::TreeRootDigest`; three trait methods after `verify_aggregate`, `:286-301`; the `StubExecutor` arms after `:739-766`)

**Interfaces:**
- Produces: `types::AggregateLayout { Flat, Tree }` (`Clone, Copy, Debug, Default = Flat, PartialEq, Eq, Serialize, Deserialize`), and `Action::Aggregate { …, layout: AggregateLayout }` as the last field.
- Produces: `ledger::aggregation::{RvmHeights { tier, reg_log_height, ram_log_height, poseidon2_log_height, reduce_log_height: u8 }, TreeConfig { shape: DeclaredShape, leaf_size: u8, max_depth: u8, leaf: RvmHeights, step: RvmHeights, t_leaf_digest, t_int_digest, vk_leaf, vk_t_leaf, vk_int: [u64; 4] }, TreeDigests { t_leaf, t_int, vk_leaf, vk_t_leaf, vk_int: [u64; 4] }}`, `TreeConfig::check(&self, cfg: &AggregationConfig) -> Result<(), String>`, `pub fn tree_depth(covers: usize, tree: &TreeConfig) -> Result<u32, AggregationError>`.
- Produces: `AggregationError::{TreeNotAdmitted, TreeLayout { covers: usize, leaf_size: u8 }, TreeDepth { depth: u32, max: u8 }, TreeTier { declared: u8, pinned: u8 }, TreeKeyPin { level: u8 }, TreeRootDigest}`.
- Produces, on `ConfidentialExecutor`: `fn aggregate_proof_tier(&self, proof: &[u8]) -> Result<u8, ConfidentialError>`, `fn tree_digests(&self, tree: &TreeConfig) -> Result<TreeDigests, ConfidentialError>`, and `fn verify_tree(&self, tree: &TreeConfig, covered: &[CoveredBundle], proof: &[u8], binding: &[u32; 8], depth: u32) -> Result<Vec<[u32; 8]>, ConfidentialError>`. Each defaults to `Err(AggregationUnsupported)`. Adds `ConfidentialError::TreeRootDigest`.
- Produces: `BindingDomain::aggregate_tree_signing_hash(...)`, with the same arguments as `aggregate_signing_hash`.

- [ ] **Step 1: Write the failing admission tests**

In `aggregation.rs`'s `admission_tests` module: extend `setup()`'s `covers(4)` to `covers(8)`. Give `aggregate_tx` a `layout: AggregateLayout` parameter: `Flat` signs with `aggregate_signing_hash`, as today, and `Tree` with `aggregate_tree_signing_hash`. Every existing call passes `AggregateLayout::Flat`. Add:

```rust
    fn tree_cfg() -> TreeConfig {
        let d = StubExecutor.tree_digests_for_tests();
        let h = RvmHeights { tier: 19, reg_log_height: 20, ram_log_height: 20, poseidon2_log_height: 15, reduce_log_height: 17 };
        TreeConfig { shape: shape(), leaf_size: 1, max_depth: 2, leaf: h, step: h, t_leaf_digest: d.t_leaf, t_int_digest: d.t_int,
            vk_leaf: d.vk_leaf, vk_t_leaf: d.vk_t_leaf, vk_int: d.vk_int }
    }

    fn tree_setup() -> (Ledger, Keypair) {
        let (mut l, kp) = setup();
        l.set_aggregation_tree(Some(tree_cfg()));
        (l, kp)
    }

    fn tree_tx(kp: &Keypair, n: usize, tier: u8, depth: u8, binding_of: &Ledger) -> Transaction {
        let binding = binding_of.binding_domain().aggregate_binding(7, &kp.public_key().address(), 0);
        aggregate_tx(kp, 0, 100, covers(n), StubExecutor::make_tree_proof(tier, depth, &binding), AggregateLayout::Tree)
    }

    /// Review Focus 5: the layout boundaries, each by name, before any executor call.
    #[test]
    fn tree_layout_boundaries_are_named() {
        let (l, kp) = tree_setup();
        let at = |n: usize, d: u8| l.validate_aggregate(&tree_tx(&kp, n, 19, d, &l), &covered_records(&shape(), &(1..=n as u8).collect::<Vec<_>>()), &StubExecutor);
        assert!(at(2, 1).is_ok(), "L·2^1");
        assert!(at(4, 2).is_ok(), "L·2^max_depth");
        assert!(matches!(at(8, 3), Err(TxError::Aggregation(AggregationError::TreeDepth { depth: 3, max: 2 }))));
        for n in [1usize, 3, 5] {
            assert!(matches!(at(n, 1), Err(TxError::Aggregation(AggregationError::TreeLayout { covers, leaf_size: 1 })) if covers == n), "{n} covers");
        }
        let (ungated, kp2) = setup();
        assert!(matches!(ungated.validate_aggregate(&tree_tx(&kp2, 2, 19, 1, &ungated), &covered_records(&shape(), &[1, 2]), &StubExecutor),
            Err(TxError::Aggregation(AggregationError::TreeNotAdmitted))));
    }

    #[test]
    fn a_tree_root_at_another_tier_is_refused_before_any_build() {
        let (l, kp) = tree_setup();
        let r = l.validate_aggregate(&tree_tx(&kp, 2, 20, 1, &l), &covered_records(&shape(), &[1, 2]), &StubExecutor);
        assert!(matches!(r, Err(TxError::Aggregation(AggregationError::TreeTier { declared: 20, pinned: 19 }))), "{r:?}");
    }

    /// Step 7b checks the keys a depth uses, and only those: a wrong `vk_t_leaf` refuses depth 2
    /// and not depth 1. A wrong root-program pin is AGG-6's `AggregateProgramMismatch`.
    #[test]
    fn the_tree_pins_are_checked_per_depth() {
        let (mut l, kp) = tree_setup();
        let mut t = tree_cfg();
        t.vk_t_leaf = [0xdead; 4];
        l.set_aggregation_tree(Some(t));
        assert!(l.validate_aggregate(&tree_tx(&kp, 2, 19, 1, &l), &covered_records(&shape(), &[1, 2]), &StubExecutor).is_ok());
        assert!(matches!(l.validate_aggregate(&tree_tx(&kp, 4, 19, 2, &l), &covered_records(&shape(), &[1, 2, 3, 4]), &StubExecutor),
            Err(TxError::Aggregation(AggregationError::TreeKeyPin { level: 1 }))));
        let mut t = tree_cfg();
        t.t_int_digest = [0xbeef; 4];
        l.set_aggregation_tree(Some(t));
        assert!(matches!(l.validate_aggregate(&tree_tx(&kp, 4, 19, 2, &l), &covered_records(&shape(), &[1, 2, 3, 4]), &StubExecutor),
            Err(TxError::Aggregation(AggregationError::AggregateProgramMismatch { .. }))));
    }

    /// The recompute's refusals reach the ledger as `TreeRootDigest`: the stub models a root made
    /// at another depth or under another binding (a re-signed or replayed tree).
    #[test]
    fn a_root_the_recompute_refuses_is_tree_root_digest() {
        let (l, kp) = tree_setup();
        let binding = l.binding_domain().aggregate_binding(7, &kp.public_key().address(), 0);
        let lying = aggregate_tx(&kp, 0, 100, covers(4), StubExecutor::make_tree_proof(19, 1, &binding), AggregateLayout::Tree);
        assert!(matches!(l.validate_aggregate(&lying, &covered_records(&shape(), &[1, 2, 3, 4]), &StubExecutor),
            Err(TxError::Aggregation(AggregationError::TreeRootDigest))));
        let other = aggregate_tx(&kp, 0, 100, covers(2), StubExecutor::make_tree_proof(19, 1, &[9; 8]), AggregateLayout::Tree);
        assert!(matches!(l.validate_aggregate(&other, &covered_records(&shape(), &[1, 2]), &StubExecutor),
            Err(TxError::Aggregation(AggregationError::TreeRootDigest))));
    }

    /// R8: the layout is signed. Flipping it on a signed transaction breaks the signature, and a
    /// `Flat` aggregate's signing hash is today's, byte for byte.
    #[test]
    fn the_layout_is_signed_and_flat_signs_as_before() {
        let (l, kp) = tree_setup();
        let mut tx = tree_tx(&kp, 2, 19, 1, &l);
        if let Action::Aggregate { layout, .. } = &mut tx.action { *layout = AggregateLayout::Flat; }
        assert!(matches!(l.validate_aggregate(&tx, &covered_records(&shape(), &[1, 2]), &StubExecutor), Err(TxError::Aggregation(AggregationError::BadSignature))));
        let r = [9; 8];
        let a = aggregate_signing_hash(7, 0, 100, &r, &covers(2), &Hash::digest(b"p"), &envelope_digest(&env()));
        assert_eq!(a, BindingDomain::ChainId.aggregate_signing_hash(7, 0, 100, &r, &covers(2), &Hash::digest(b"p"), &envelope_digest(&env())));
        assert_ne!(a, BindingDomain::ChainId.aggregate_tree_signing_hash(7, 0, 100, &r, &covers(2), &Hash::digest(b"p"), &envelope_digest(&env())));
    }
```

In `genesis.rs`'s tests, add `an_aggregation_tree_section_is_checked_and_moves_only_its_own_hash`. A genesis with `aggregation` and no `aggregation_tree` hashes as before (compare against the existing aggregation genesis test's hash). Adding the section moves the hash. `leaf_size` 0 or 6, `max_depth` 0, `L·2^max_depth > max_covers`, any zero digest, and a `shape` matching no admitted shape are each `GenesisError::BadAggregationConfig`. The section without `aggregation` is refused.

Run: `cargo test -p randprotocol-core 2>&1 | grep -E '^error' | sort -u | head`
Expected: unresolved `AggregateLayout`, `TreeConfig`, `RvmHeights`, `set_aggregation_tree`, `make_tree_proof`, `tree_digests_for_tests`, `aggregate_tree_signing_hash`, and the extra `aggregate_tx` argument.

- [ ] **Step 2: The action, the signing hash, the stub**

In `transaction.rs`: define `AggregateLayout`, documented as "a tree covers `L·2^d` bundles and is verified level by level (`docs/aggregation.md` §Trees); `Flat` is today's single aggregate". Append `layout: AggregateLayout` to `Action::Aggregate`. `blanked` copies it, and `sample` row 13 sets `layout: AggregateLayout::Tree`, so the roundtrip covers the new field. The wire encoding of variant 13 gains a trailing 4-byte enum index. This is safe because aggregation is refused on every live chain (`node::check_build_runs_genesis`), so no committed transaction carries the variant. State that in the doc comment. `cargo check --workspace` then names every `Action::Aggregate { … }` pattern without `..`. Add `layout` (or `..`) to each.

In `actions.rs`, `aggregate_tree_signing_hash` is `aggregate_signing_hash` with the domain `b"rand-aggregate-tree-1"`. In `binding.rs`, the `Genesis` arm is `Self::bound(b"rand-aggregate-tree-1", g, &(chain_id, nonce, time, r, covers, proof_hash, envelope_digest))`. `validate_aggregate`'s and `preflight_aggregate`'s `signed_by` closures pick the hash by `layout`.

In `confidential.rs`:

```rust
    /// Tree aggregation: the recomputed root digest is not the proof's public values (a level
    /// under another binding, another key, another order). A permanent admission verdict.
    #[error("the tree's recomputed root digest is not the proof's")]
    TreeRootDigest,
```

and the three trait methods with `Err(ConfidentialError::AggregationUnsupported)` defaults. `StubExecutor` gets `const STUB_TREE_TAG: &[u8] = b"rand-stub-tree"`, `pub fn make_tree_proof(tier: u8, depth: u8, binding: &[u32; 8]) -> Vec<u8>` (`TAG ‖ tier ‖ depth ‖ binding`), and `pub fn tree_digests_for_tests(&self) -> TreeDigests` (five distinct constants, e.g. `[0x7472_0001; 4]` … `[0x7472_0005; 4]`). Its `aggregate_proof_tier` returns the tier byte after the tag (or `MalformedProof`). Its `tree_digests` returns `tree_digests_for_tests()`. Its `verify_tree` returns `TreeRootDigest` when the proof's depth byte ≠ `depth` or its binding ≠ `binding`, and otherwise the covered `OUT0..7`, as its `verify_aggregate` does.

- [ ] **Step 3: The genesis section**

In `aggregation.rs`, after `AdmittedShape`:

```rust
/// The five words an rVM proof declares (`randprotocol_rvm::shape::RvmHeights`, mirrored: core
/// never names the rVM).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RvmHeights { pub tier: u8, pub reg_log_height: u8, pub ram_log_height: u8, pub poseidon2_log_height: u8, pub reduce_log_height: u8 }

/// Tree aggregation (circuits `docs/07-tree-aggregation.md` §4, plan R2/R4): the leaf size, the
/// deepest tree, the leaf and step heights the node rebuilds the three programs from, and the
/// five digests it must rebuild to (two programs, three child keys).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TreeConfig {
    /// The admitted shape this tree aggregates; must be one of `admitted_shapes`.
    pub shape: DeclaredShape,
    pub leaf_size: u8,
    pub max_depth: u8,
    pub leaf: RvmHeights,
    pub step: RvmHeights,
    pub t_leaf_digest: [u64; 4],
    pub t_int_digest: [u64; 4],
    pub vk_leaf: [u64; 4],
    pub vk_t_leaf: [u64; 4],
    pub vk_int: [u64; 4],
}

/// What an executor rebuilds from a `TreeConfig` (step 7b and the startup check compare it).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TreeDigests { pub t_leaf: [u64; 4], pub t_int: [u64; 4], pub vk_leaf: [u64; 4], pub vk_t_leaf: [u64; 4], pub vk_int: [u64; 4] }

impl TreeConfig {
    /// The largest depth a genesis may name (`L·2^8` covers is far past any block).
    pub const MAX_DEPTH: u8 = 8;
    /// The rVM's production reduce ceiling on one aggregate (circuits docs/06 §3): a leaf is one.
    pub const MAX_LEAF: u8 = 5;

    pub fn check(&self, cfg: &AggregationConfig) -> Result<(), String> {
        if !(1..=Self::MAX_LEAF).contains(&self.leaf_size) {
            return Err(format!("aggregation_tree.leaf_size {} is outside 1..={} (the rVM's reduce ceiling)", self.leaf_size, Self::MAX_LEAF));
        }
        if !(1..=Self::MAX_DEPTH).contains(&self.max_depth) {
            return Err(format!("aggregation_tree.max_depth {} is outside 1..={}", self.max_depth, Self::MAX_DEPTH));
        }
        let most = (self.leaf_size as u64) << self.max_depth;
        if most > cfg.max_covers as u64 {
            return Err(format!("a tree covers up to L·2^max_depth = {most}, above max_covers {}", cfg.max_covers));
        }
        if !cfg.admitted_shapes.iter().any(|a| a.shape == self.shape) {
            return Err("aggregation_tree.shape is not an admitted shape".into());
        }
        let zero = [self.t_leaf_digest, self.t_int_digest, self.vk_leaf, self.vk_t_leaf, self.vk_int].iter().any(|d| *d == [0; 4]);
        if zero {
            return Err("aggregation_tree has a zero digest (the activation placeholder)".into());
        }
        Ok(())
    }
}

/// The layout rule (spec §2): exactly `L·2^d` covers, `1 ≤ d ≤ max_depth`. Returns `d`.
pub fn tree_depth(covers: usize, tree: &TreeConfig) -> Result<u32, AggregationError> {
    let l = tree.leaf_size as usize;
    let leaves = covers / l;
    if covers % l != 0 || leaves < 2 || !leaves.is_power_of_two() {
        return Err(AggregationError::TreeLayout { covers, leaf_size: tree.leaf_size });
    }
    let d = leaves.trailing_zeros();
    if d > tree.max_depth as u32 {
        return Err(AggregationError::TreeDepth { depth: d, max: tree.max_depth });
    }
    Ok(d)
}
```

In `genesis.rs`, add `#[serde(default, skip_serializing_if = "Option::is_none")] pub aggregation_tree: Option<crate::ledger::aggregation::TreeConfig>` after `aggregation`. Its doc comment: "R4: top-level so `aggregation`'s hashed bytes do not move; appended last to the commitment". In the check, refuse it without `aggregation` (`BadAggregationConfig("aggregation_tree without aggregation")`) and call `tree.check(aggregation).map_err(GenesisError::BadAggregationConfig)?`. After the `perps` block (`:1535-1538`), append `if let Some(t) = &self.aggregation_tree { commit.extend_from_slice(b"aggregation_tree"); commit.extend_from_slice(&bincode::serialize(t).expect("serializes")); }`, with the house comment that every genesis cut before it hashes byte for byte as before. Where the ledger is built (`:1119`), add `ledger.set_aggregation_tree(self.aggregation_tree);`. Add the setter and getter in `ledger/mod.rs`, beside `set_aggregation`.

- [ ] **Step 4: The admission branch**

Add the six errors to `AggregationError`, with `#[error]` lines naming their fields. In `validate_aggregate`, destructure `layout` (and pass it to the `signed_by` closure's hash choice). Right after step 6 finds `admitted`, insert:

```rust
    // 6t. The tree layout (tree aggregation spec §2): a `Tree` names the chain's tree section for
    //     this shape, and the cover count is exactly L·2^d, 1 ≤ d ≤ max_depth. Integer work, before
    //     step 7's compares and everything after.
    let tree = match layout {
        AggregateLayout::Flat => None,
        AggregateLayout::Tree => {
            let t = ledger.aggregation_tree().filter(|t| t.shape == first.shape).ok_or(AggregationError::TreeNotAdmitted)?;
            Some((t, tree_depth(covers.len(), t)?))
        }
    };
```

Replace step 7a's line with:

```rust
    match tree {
        None => executor.check_aggregate_header(proof).map_err(TxError::InvalidAggregateProof)?,
        // R6: an honest root is a fixed workload at the pinned step tier; any other tier is
        // refused before 7b's builds (AGG-3, tightened).
        Some((t, _)) => {
            let declared = executor.aggregate_proof_tier(proof).map_err(TxError::InvalidAggregateProof)?;
            if declared != t.step.tier {
                return Err(AggregationError::TreeTier { declared, pinned: t.step.tier }.into());
            }
        }
    }
```

Wrap step 7b's existing `match` as the `None` arm of `if let Some((t, d)) = tree { … } else { <existing match> }`, with the tree arm:

```rust
        // 7b, per level (AGG-6): the root's program and every child key the depth uses, rebuilt by
        // the executor from the pinned heights and compared with the pins.
        if let Ok(built) = executor.tree_digests(t) {
            let (pinned, root) = if d == 1 { (t.t_leaf_digest, built.t_leaf) } else { (t.t_int_digest, built.t_int) };
            if root != pinned {
                return Err(AggregationError::AggregateProgramMismatch { pinned, built: root }.into());
            }
            let keys = [(0u8, t.vk_leaf, built.vk_leaf), (1, t.vk_t_leaf, built.vk_t_leaf), (2, t.vk_int, built.vk_int)];
            for (level, pinned, got) in keys.into_iter().take(d.min(3) as usize) {
                if got != pinned {
                    return Err(AggregationError::TreeKeyPin { level }.into());
                }
            }
        }
```

(`Err` from `tree_digests` falls through to step 8, which says what it cannot do, as 7b's flat arm does today.) Replace step 8's call with:

```rust
    let verdict = match tree {
        None => executor.verify_aggregate(&first.shape, covered, proof, &binding),
        Some((t, d)) => executor.verify_tree(t, covered, proof, &binding, d),
    };
    let outs = verdict.map_err(|e| match e {
        ConfidentialError::TreeRootDigest => TxError::Aggregation(AggregationError::TreeRootDigest),
        e => TxError::InvalidAggregateProof(e),
    })?;
```

Run: `cargo test -p randprotocol-core 2>&1 | grep -E 'test result|FAILED'`
Expected: 0 failed, including the five new admission tests and the genesis test. Then `cargo test --workspace --no-run` to confirm every crate compiles against the new field.

- [ ] **Step 5: Commit**

```bash
git add crates/randprotocol-core
git commit -m "core: tree aggregation — Aggregate.layout, the aggregation_tree genesis section, the L·2^d layout rule, per-level pins and the TreeRootDigest verdict

Tree aggregates sign under rand-aggregate-tree-1 (flat signing hashes unchanged); admission
adds 6t (TreeNotAdmitted, TreeLayout, TreeDepth), 7a's exact root tier (TreeTier), 7b's
program and per-depth key pins (AggregateProgramMismatch, TreeKeyPin) and step 8's
verify_tree. The section is top-level and appended last: every existing genesis hash holds.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AUWKAos28PQquiLZRVC6jP"
```

---

### Task 3b: The chain, node — the re-vendor, the executor, the startup pin check, the runbook, the docs

**Files:**
- Modify: `crates/randprotocol-rvm/**` (re-vendored at the circuits commit of Task 2 Step 8)
- Modify: `crates/randprotocol-node/src/agg_executor.rs` (the three trait methods after `verify_aggregate`, `:452-500`; `check_tree_pins`; the tests after `crafted_proof`, `:598-618`)
- Modify: `crates/randprotocol-node/src/node.rs` (call `check_tree_pins` beside `check_build_runs_genesis`, `:1925`, before the warm thread at `:2244`)
- Modify: `crates/randprotocol-node/src/main.rs` (`Cmd::Aggregate` gains `--layout`, `:852-866`; `prove_aggregate`, `:2516-2543`; `aggregate_pass`, `:2560-2640`), `crates/randprotocol-node/src/rpc.rs` (`rand_status.aggregation.tree`)
- Modify: `crates/randprotocol-node/tests/cluster.rs` (a tree twin of the capstone, `:1794`)
- Modify: `docs/aggregation.md` (§"Before enabling aggregation" `:142-209`; a new §"Trees"), `docs/deploy.md` (§"Chain 9 activation", `:1258-1290`), `docs/compute-optimization.md` (§4.2–§4.4, `:215-263`)

**Interfaces:**
- Consumes: Task 2's `TreeShapes::build`, `TreeShapes::{keys, root_program}`, `verify_tree`, `aggregate_tree`, `RvmHeights`; Task 3a's trait methods, `TreeConfig`, `TreeDigests`.
- Produces: `pub fn check_tree_pins(ex: &AggExecutor, tree: &TreeConfig) -> Result<(), AggregationError>`. A mismatch is `TreeKeyPin { level }` or `AggregateProgramMismatch`, and the node refuses to start on it.

- [ ] **Step 1: Re-vendor**

Run only the recursion section of `deploy/sync-zkvm.sh` (`:443` to the end of that section; the research section would carry research's older drift, as the script's own comment says), with `RVM_SRC=$HOME/rand-worktrees/circuits-tree/recursion`. Keep the two hand fixes the section names: `Cargo.toml`'s `license.workspace` line and `tests/backend.rs`'s doc comment. Update `CIRCUITS_PIN` in `.github/workflows/ci.yml` and `PROVENANCE.md` to the circuits commit, as `728dec0c` did. Then run `cargo test -p randprotocol-rvm --release --test tree verify_tree_selects_vk_leaf_vk_t_leaf_vk_int_by_level` with `RECURSION_FIXTURES` set. Expected: PASS (host-only beyond the cached leaves).

- [ ] **Step 2: The executor**

In `agg_executor.rs`, memoise one `TreeShapes` per `TreeConfig` beside `programs` (a `Mutex<HashMap<[u64; 4], Arc<BuiltTree>>>` keyed by `t_int_digest`). `BuiltTree` holds `{ inner: InnerVerifierKey, shapes: TreeShapes, keys: TreeKeys, digests: TreeDigests }`, built with `TreeShapes::build(zkvm_profile(tree.shape.profile), &inner_key(&tree.shape)?, heights(tree.leaf), heights(tree.step))`, where `heights` maps core's `RvmHeights` onto the rVM's (`Tier(h.tier as usize)`). Then:

```rust
    fn aggregate_proof_tier(&self, proof: &[u8]) -> Result<u8, ConfidentialError> {
        let p: randprotocol_rvm::machine::Proof = postcard::from_bytes(proof).map_err(|_| ConfidentialError::MalformedProof)?;
        if p.to_bytes() != proof {
            return Err(ConfidentialError::MalformedProof);
        }
        u8::try_from(p.tier.0).map_err(|_| ConfidentialError::InvalidAggregateProof(format!("tree root at tier {}", p.tier.0)))
    }

    fn tree_digests(&self, tree: &TreeConfig) -> Result<TreeDigests, ConfidentialError> {
        Ok(self.built_tree(tree)?.digests)
    }

    fn verify_tree(&self, tree: &TreeConfig, covered: &[CoveredBundle], proof: &[u8], binding: &[u32; 8], depth: u32)
        -> Result<Vec<[u32; 8]>, ConfidentialError> {
        let root = self.aggregate_header_tree(proof, tree.step.tier)?;
        let built = self.built_tree(tree)?;
        let pvs: Vec<Vec<u64>> = covered.iter().map(|c| c.public_values.to_vec()).collect();
        let out = randprotocol_rvm::aggregate::verify_tree(&self.rvm, built.shapes.root_program(depth), &root, &built.inner, &pvs,
            binding, tree.leaf_size as usize, depth, &built.keys)
            .map_err(|e| match e {
                randprotocol_rvm::aggregate::VerifyTreeError::TreeRootDigest => ConfidentialError::TreeRootDigest,
                e => ConfidentialError::InvalidAggregateProof(format!("{e:?}")),
            })?;
        AGGREGATE_VERIFICATIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(out)
    }
```

`aggregate_header_tree` is `aggregate_header` (`:116-140`) with the tier compared against the pinned `step.tier` instead of `admitted_tiers`: the decode, the canonical bytes, then the exact tier. `check_tree_pins` compares `built_tree(tree)?.digests` with all five pins (levels 0–2, and both programs, whatever the depth), so the startup check is stricter than admission's per-depth one. In `node.rs`, after `check_build_runs_genesis` and before the warm thread, `if let Some(t) = gs.ledger.aggregation_tree() { agg_executor::check_tree_pins(&ex, t).map_err(|e| anyhow::anyhow!("aggregation_tree pins: {e}; refusing to start"))?; }`. That builds the three programs and keys once, *projected* at a few minutes at production. `warm_aggregation` then also warms the root's key at `step.tier` and the canonical reduce height (`canonical_reduce_log_height(t_int, 2)`).

Tests, with crafted roots in `crafted_proof`'s pattern (a decodable, canonical `machine::Proof` with the header fields given, the recomputed root digest as its public values, the degree bits `log_ext_degrees` wants, and an all-zero batch). Build the test `TreeConfig` from docs/07 §5's test-profile heights and digests:

```rust
    /// The test-profile tree section, built the way a genesis cut computes it: the heights read
    /// off the cached test leaf and step (`$RECURSION_FIXTURES/tree/`, circuits Task 1b), the
    /// digests from the rVM's own `TreeShapes`.
    fn test_tree_cfg() -> TreeConfig {
        use p3_field::PrimeField64;
        let h = |p: &randprotocol_rvm::machine::Proof| RvmHeights { tier: p.tier.0 as u8, reg_log_height: p.reg_log_height,
            ram_log_height: p.ram_log_height, poseidon2_log_height: p.poseidon2_log_height, reduce_log_height: p.reduce_log_height };
        let (leaf, step) = (load_tree("Test-leaf-0"), load_tree("Test-step-0"));
        let (shape, _) = covered(0);
        let inner = AggExecutor::inner_key(&shape).unwrap();
        let s = randprotocol_rvm::aggregate::TreeShapes::build(FriProfile::Test, &inner,
            randprotocol_rvm::shape::RvmHeights::of_proof(&leaf), randprotocol_rvm::shape::RvmHeights::of_proof(&step)).unwrap();
        let u = |d: [randprotocol_rvm::isa::F; 4]| d.map(|f| f.as_canonical_u64());
        let k = s.keys();
        TreeConfig { shape, leaf_size: 1, max_depth: 2, leaf: h(&leaf), step: h(&step),
            t_leaf_digest: u(s.t_leaf.program.digest()), t_int_digest: u(s.t_int.program.digest()),
            vk_leaf: u(k.vk_leaf), vk_t_leaf: u(k.vk_t_leaf), vk_int: u(k.vk_int) }
    }

    /// The startup check (spec §4: "refuses to start on a mismatch"): the honest section passes,
    /// and each of the five pins, flipped, is named.
    #[test]
    fn the_tree_pins_are_checked_at_startup() {
        let ex = AggExecutor::new(FriProfile::Test);
        let good = test_tree_cfg();
        check_tree_pins(&ex, &good).expect("the cached test tree's own pins");
        let flip = |f: fn(&mut TreeConfig)| { let mut t = good; f(&mut t); check_tree_pins(&ex, &t) };
        assert!(matches!(flip(|t| t.vk_leaf = [1; 4]), Err(AggregationError::TreeKeyPin { level: 0 })));
        assert!(matches!(flip(|t| t.vk_t_leaf = [1; 4]), Err(AggregationError::TreeKeyPin { level: 1 })));
        assert!(matches!(flip(|t| t.vk_int = [1; 4]), Err(AggregationError::TreeKeyPin { level: 2 })));
        assert!(matches!(flip(|t| t.t_leaf_digest = [1; 4]), Err(AggregationError::AggregateProgramMismatch { .. })));
        assert!(matches!(flip(|t| t.t_int_digest = [1; 4]), Err(AggregationError::AggregateProgramMismatch { .. })));
    }

    /// Crafted roots (`crafted_proof`'s pattern, at the step's heights and the root program's
    /// degree bits): another tier is refused by the header, with no key built; the digest the
    /// recompute makes under another binding is `TreeRootDigest`, with no key built; the right
    /// digest over an all-zero batch reaches the rVM verify and is refused there.
    #[test]
    fn crafted_tree_roots_are_refused_at_their_step() {
        use p3_field::PrimeField64;
        let ex = AggExecutor::new(FriProfile::Test);
        let t = test_tree_cfg();
        let covered: Vec<CoveredBundle> = (0..2).map(|k| covered(k).1).collect();
        let pvs: Vec<Vec<u64>> = covered.iter().map(|c| c.public_values.to_vec()).collect();
        let inner = AggExecutor::inner_key(&t.shape).unwrap();
        let s = randprotocol_rvm::aggregate::TreeShapes::build(FriProfile::Test, &inner,
            randprotocol_rvm::shape::RvmHeights::of_proof(&load_tree("Test-leaf-0")), randprotocol_rvm::shape::RvmHeights::of_proof(&load_tree("Test-step-0"))).unwrap();
        let root_for = |binding: &[u32; 8], tier: usize| -> Vec<u8> {
            let d = randprotocol_rvm::aggregate::tree_root_digest(&inner, &pvs, binding, 1, 1, &s.keys()).unwrap();
            let digest: Vec<u64> = d.iter().map(|f| f.as_canonical_u64()).collect();
            let st = t.step;
            let mut bytes = postcard::to_allocvec(&(tier, st.reg_log_height, st.ram_log_height, st.poseidon2_log_height, st.reduce_log_height, digest)).unwrap();
            bytes.extend_from_slice(&[0u8; 4096]);
            let mut p: randprotocol_rvm::machine::Proof = postcard::from_bytes(&bytes).unwrap();
            p.batch.degree_bits = randprotocol_rvm::machine::log_ext_degrees(s.root_program(1), randprotocol_rvm::machine::Tier(tier),
                st.reg_log_height, st.ram_log_height, st.poseidon2_log_height, st.reduce_log_height);
            p.to_bytes()
        };
        let b = [3u32; 8];
        let before = ex.rvm.cached_keys();
        assert!(matches!(ex.verify_tree(&t, &covered, &root_for(&b, t.step.tier as usize + 1), &b, 1), Err(ConfidentialError::InvalidAggregateProof(m)) if m.contains("tier")));
        assert!(matches!(ex.verify_tree(&t, &covered, &root_for(&[4; 8], t.step.tier as usize), &b, 1), Err(ConfidentialError::TreeRootDigest)));
        assert_eq!(ex.rvm.cached_keys(), before, "neither refusal built a key");
        assert!(matches!(ex.verify_tree(&t, &covered, &root_for(&b, t.step.tier as usize), &b, 1), Err(ConfidentialError::InvalidAggregateProof(_))));
    }

Add `fn load_tree(name: &str) -> randprotocol_rvm::machine::Proof` beside `fixture_proof` (`:538`): it reads `$RECURSION_FIXTURES/tree/{name}.rvmproof` with `fixture_proof`'s loud-failure discipline. `check_tree_pins` must build its digests the same way (`TreeShapes::build` over the section's heights), so a test-cfg built from the cache passes by construction and every flip is the only difference.

Run: `RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures cargo test -p randprotocol-node --release agg_executor 2>&1 | grep -E 'test result|FAILED'`
Expected: 0 failed.

- [ ] **Step 3: The daemon, the status, the runbook**

`rand_status.aggregation` gains `"tree": { "leaf_size", "max_depth", "leaf": {…heights}, "step": {…} }` when the section is set. `rand-node aggregate --layout tree|flat` (default `flat`). With `tree`, `aggregate_pass` takes `n = L·2^d` covers for the largest `d ≤ max_depth` with `L·2^d ≤` the unsealed work list, and returns `None` if fewer than `2L` are unsealed. `prove_aggregate` calls `randprotocol_rvm::aggregate::aggregate_tree(&m, &vk, &TreeShapes::build(…)?, &proofs, binding, L)`. The action carries `layout: AggregateLayout::Tree` and signs with `aggregate_tree_signing_hash`. Add to `aggregate_pass`'s existing test: a `tree` status with 5 unsealed and L = 1, max_depth 2 takes 4 covers.

`tests/cluster.rs`: add `a_tree_aggregate_over_four_bundles_commits_with_one_rvm_verify`, the capstone's flow with four bundles, `aggregation_tree` from docs/07 §5 (test profile, L = 1, max_depth 2) and `--layout tree`. Mark it `#[ignore]` with the capstone's own reason (aggregation is refused at startup until the admitted shape is re-measured). It is un-ignored with the capstone, and it needs a ≥ 256 GB host for the test-profile steps (docs/07 §5). In `docs/deploy.md` §"Chain 9 activation", add step 5a: on a tree chain, aggregators run `rand-node aggregate --watch --layout tree` on a host of docs/07 §4's step class (503 GB at production by Task 2's measurement), and the ops check is `rand_status.aggregation.tree` plus the startup log's `aggregation_tree pins: ok` line.

- [ ] **Step 4: The docs**

`docs/aggregation.md`: add §"Trees". It covers the layout rule (exactly `L·2^d` covers, `1 ≤ d ≤ max_depth`, else the flat path at N ≤ 5), the bottom-up recompute (leaf lists, then `[vk_c ‖ 2 ‖ B ‖ D_a ‖ D_b]` with `vk_leaf`/`vk_t_leaf`/`vk_int` by level), AGG-6 per level (step 7b), AGG-3 on the root's exact tier (7a), the signature domain, and the six errors. In "Before enabling aggregation" (`:195`), replace "The `rv32r` self-verifier's binding is not tied to the inner aggregate's (ZKQ-5): decide before trees of aggregates ship" with "ZKQ-5, decided 2026-09-28 and implemented for trees in circuits docs/07: no in-program `B_out == B_in`; admission recomputes every level from the covered bundles under the transaction's one binding (§Trees)". Add the measured tree numbers from circuits docs/07 §3 to §6's table.

`docs/compute-optimization.md`: add a dated "Correction (2026-10-08, circuits docs/06–07)" note at the head of §4.2, listing the nine stale points it replaces. (1) §4.1's "two dedicated chips" are built: `SPONGE`/`COMPRESS` in the poseidon2 chip, and `FOLD`/`POW` row kinds in the reduce chip; one inner proof is 585 686 rows, tier 20 (docs/06). (2) §4.1's "N = 16 around 2^24" is unreachable: the reduce chip caps a flat aggregate at N ≤ 5 at production. (3) §4.2's "B = 16 per leaf" is L = 2 (spec ruling 6). (4) "memory per step is a constant" holds, but the constant is a 256 GB leaf and a 503 GB step (docs/07 §3), not a GPU host. (5) "The root's interface is unchanged … only N grows" is wrong: the root publishes `[vk_c ‖ 2 ‖ B ‖ D_a ‖ D_b]`, admission recomputes every level, and the action carries a layout. (6) "ZKQ-5, still open" was decided 2026-09-28 (the chain's recompute). (7) §4.3's "32 inner verifications per leaf" is at most 2 bundle + 2 auth proofs under the reduce ceiling (spec ruling 7, sub-project 3). (8) §4.4's ≤ 64 GB leaf and step targets move to the memory track (spec ruling 1). (9) §4.4's "80 queries, rate ½" is rate ⅛ (`log_blowup 3`), and rate ¼ needs ~120 queries at the same proven bound, not 40 (docs/06 §7 item 2). The old N = 1 "377 GB" is ≈ 110–130 GB projected since phase 3.

- [ ] **Step 5: Run and commit**

Run: `cargo test --workspace --release --no-fail-fast 2>&1 | tee target/tree-fullnode.txt | grep -E '^test result|FAILED'`
Expected: 0 failed beyond the documented `RECURSION_FIXTURES`/laptop-OOM exclusions in `docs/deploy.md:716`.

```bash
git add crates/ docs/ .github/workflows/ci.yml
git commit -m "node, rvm: tree aggregation — re-vendor circuits <sha>, AggExecutor::verify_tree, the startup pin check, aggregate --layout tree

verify_tree forwards to the rVM's bottom-up recompute and verify_n(…, 2) and names
TreeRootDigest; the node refuses to start on an aggregation_tree pin this build does not
rebuild. docs/aggregation.md gains §Trees (ZKQ-5 implemented); compute-optimization §4.2–4.4
corrected on nine points from circuits docs/06–07.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AUWKAos28PQquiLZRVC6jP"
```

---

### Task 4: The landing — docs/07 in full, docs/02 and docs/03, AGENTS.md, the suite

**Files:**
- Modify: `recursion/docs/07-tree-aggregation.md` (§6, §7, a conclusion), `recursion/docs/02-aggregate.md` (§"ZKQ-5" `:315-348`'s last paragraph; §"The API" `:435`), `recursion/docs/03-gpu-and-self-recursion.md` (§"The self-verifier, measured" `:106`; `:229-232`'s "tree-of-aggregates question"), `research/AGENTS.md` (the recursion paragraph, `:19-55`)

- [ ] **Step 1: docs/07 in full**

§6: the chain rules as Task 3a built them, and the fullnode commits. §7: a "What moved" table: new files; the `emit_proof`/`emit_proof_with` split with every digest unchanged; the new pins (`tree_measure`, `tree_test`, `T_LEAF_TEST`, `T_INT_TEST`); the three production digests and the five genesis values; no opcode, AIR or key-shape change. Then the suite counts from Step 3. Conclusion: whether the gate was met. Its circuits half is Task 2 Step 7. Its chain half is the node's `verify_tree` over the production root (run `cargo test -p randprotocol-node --release agg_executor -- --ignored production_tree` on `$HOST503` if Task 3b added that ignored check; otherwise say so). The cluster run is blocked by the pre-existing startup refusal of any aggregation genesis (`docs/aggregation.md` "Before enabling aggregation"). Also: the host classes, the fixed point, and the memory track as the next lever (spec ruling 1).

- [ ] **Step 2: docs/02, docs/03, AGENTS.md**

docs/02 §ZKQ-5: replace "The rule for whoever registers a tree (no chain does today …)" with the implemented rule and a pointer to docs/07 §4 and `aggregate::verify_tree`. §"The API" gains `verify_tree`, `tree_root_digest`, `prove_tree_step`, `aggregate_tree`, `TreeKeys`, `TreeShapes`. docs/03 §"The self-verifier, measured": `rv32r` is the k = 1 case and stays with its tests; `rv32t` is its k = 2 loop (docs/07); add the measured production child from Task 0 beside the toy and busy pins. Rewrite `:229-232`'s "the tree-of-aggregates question answered to a number" with docs/07 §3's measured step class. `research/AGENTS.md`: after the phase-3 sentence, add "and tree aggregation (2026-10, branch `feat/tree-aggregation`, `recursion/docs/07`): `rv32t`, the 2-to-1 step over a compile-time child shape with the child key a published tape value, `verify_tree`'s bottom-up recompute, and a production depth-2 tree measured on the 256/503 GB droplets", and add `07` to the list of measured records.

- [ ] **Step 3: The suite**

Run M6. Expected: 0 failed. Record the passed / ignored / skipped counts in docs/07 §7 (phase 3's are in docs/06 §6).

- [ ] **Step 4: Commit**

```bash
git add docs/ ../research/AGENTS.md
git commit -m "recursion docs: tree aggregation landed — docs/07 in full; rv32r the k = 1 case, rv32t k = 2; ZKQ-5's tree rule implemented

Production depth-2 tree: leaf <rows>/<t>, step <rows>/<t>, root <rows>/<t>; fixed point
<holds/fails>. Suite: <passed> passed, 0 failed, <ignored> ignored.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AUWKAos28PQquiLZRVC6jP"
```

---

## Self-review notes

- **Spec coverage.** §2 (the leaf, the interior step, the layout rule, depth sizing): Tasks 1a, 2 (`tree_root_digest`, `aggregate_tree`) and 3a (`tree_depth`). §3 (the tape, the hinted `B` and cap, the in-program `vk_c`, the two children, the 21-word list, no `B_out == B_in`): Task 1a, with R1 and R5 recording the departures. §4 (the action, the genesis pins, the recompute, steps 4/6/7/7a/7b/8, `verify_tree`, the errors, the docs): Tasks 2, 3a and 3b, with R2, R4, R6, R8 and R9 recording the departures. §5 (Tasks 0–4, the gate, the stop rule): Task 0 (stop rule), Task 2 Step 6 (the 503 GB stop), and Task 4 Step 1 (the gate's two halves, with the cluster run's pre-existing blocker named). §6: `tests/tree.rs` (end to end, the tamper table — swapped order, a wrong cap both ways, a wrong `B`, a flat proof as a tree, a wrong-shape child — the k = 1 tests untouched, the digest and shape pins, the canonical reduce height at N = 2); the fullnode admission tests per error, the startup pin check and the runbook step; and logs under `docs/measurements/`, never macOS RSS.
- **Placeholder scan.** `grep -nE 'TBD|TODO|similar to Task|add validation' <this file>` returns nothing. Angle-bracket slots appear only in commit messages, pin JSON, docs/07 text and the measured digest literals (`T_LEAF_TEST`/`T_INT_TEST`, empty until Task 1b Step 4). Each is a measured value, and the step around it names the command and the line to read. `$HOST256`/`$HOST503` are the user's droplet addresses (spec §7).
- **Type consistency.** `verify_rv32t(child: &RvmShape, cp)` returns `VerifierProgram<RvmShape>` throughout. `build_tree_step(profile, child, [&Proof; 2], binding)` is the same in Tasks 1a, 1b and 2. `TreeKeys { vk_leaf, vk_t_leaf, vk_int }` and `at_level` are the same in Task 2's code, its tests and the production run. Core mirrors them as `TreeConfig`/`TreeDigests` (Task 3a) and the node maps one onto the other (3b). `RvmHeights` exists twice by design: rVM (`tier: Tier`) and core (`tier: u8`). `VerifyTreeError::TreeRootDigest` → `ConfidentialError::TreeRootDigest` → `AggregationError::TreeRootDigest` is the one path. `TREE_ARITY = 2` is the `n` of every step's `verify_n`.
- **Review Focus pinned.** 1 → Task 1b `a_foreign_program_child_pair_passes_in_program_and_fails_the_root_recompute`. 2 → Task 1b `the_interior_step_verifies_its_own_output`. 3 → Task 1a `a_tamper_in_either_child_is_refused_at_the_named_step`. 4 → Task 2 `verify_tree_selects_vk_leaf_vk_t_leaf_vk_int_by_level`. 5 → Task 3a `tree_layout_boundaries_are_named`.
- **Not pinned down from the code:** the fullnode post-re-vendor signatures are docs/06 §5's, not read (fullnode `main` lacks them). The exact `rand_status` emitter line for `aggregation` in `rpc.rs` was not located (only its test at `:4568`). The cluster test needs `aggregation` genesis startup, which `check_build_runs_genesis` refuses today.
