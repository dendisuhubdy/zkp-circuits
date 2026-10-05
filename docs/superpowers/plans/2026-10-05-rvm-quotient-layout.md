# rVM Quotient Layout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Commit each rVM instance's quotient chunks as one hiding matrix (width `2·chunks + 4`) instead of one 6-column matrix per chunk, cutting the prover's largest memory term, through a vendored `p3-batch-stark` fork with a layout switch that leaves every other prover byte-identical.

**Architecture:** `vendor/p3-batch-stark` is crates.io 0.7.0 plus a `QuotientLayout { PerChunk, PerInstance }` enum and `_with_layout` variants of `prove_batch`, `verify_batch` and `commitments_with_opening_points`; the old names delegate with `PerChunk`. The rVM `Machine` pins `PerInstance` in one constant; `VerifierShape` grows `quotient_layout()` so the host replay (`reference.rs`), the witness tape and the self-verifier program (`rv32r`) read rVM proofs in the new layout while the aggregate programs (RV32 shape, `PerChunk`) emit byte-identical code. The proof struct keeps per-chunk opened values, so constraint recomposition is untouched.

**Tech Stack:** Rust 1.98.1 (`rust-toolchain.toml`), Plonky3 0.7.0 (`p3-*` pinned `=0.7.0`), the recursion crate `recursion/` (its own package root; `[patch.crates-io]` on `../vendor/`), `cargo test --release`.

**Spec:** `docs/superpowers/specs/2026-10-04-rvm-quotient-layout-design.md` (read it first; §1.1 is the soundness reading every task leans on).

**Worktree:** `~/rand-worktrees/circuits-quotient`, branch `feat/rvm-quotient-layout` off circuits `main` 2899bdc. All `cargo` commands run from `~/rand-worktrees/circuits-quotient/recursion` unless a step says otherwise. The RV32 fixture cache is warm at `RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures`; prefix every test command with it on the same line.

## Global Constraints

- The RV32 machine (`research/`), every wallet proof, the inner verifier key `inner_vk_digest` `346ee184…`, the aggregate program digest `c90b3f0a7758c7e306042f27a94cc1f123441b0284c7352cb3f426048c7a74d8` and `src/programs/verify_rv32.digest` must not move (spec §3.2). `research/` is not patched to the fork.
- `PerChunk` is byte-identical to upstream (spec §1.2): with the fork patched in and no caller passing a layout, every existing proof verifies as before.
- A layout mismatch is a refused proof (`VerifyError::Batch`), never a panic (spec §1.3).
- Every change to a vendored file is marked `// RandProtocol patch (2026-10-04): quotient layout`, and `vendor/PROVENANCE.md` names every changed file.
- Pins that move (`tests/self_verify.rs`) are re-recorded with the before value in the comment, the way the file already does; pins that must not move are asserted by running their tests, not assumed.
- Measurements are this box (16 cores, 48 GB), `--features parallel`, `RAYON_NUM_THREADS=16`; raw stdout goes under `recursion/docs/measurements/2026-10-0X-<what>.log`. Numbers in docs are the measured ones; projections are labelled.
- Commit after every task with the message style in `git log` (`recursion: …`, `vendor: …`, `recursion docs: …`) and the trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`. The pre-existing `ShapeKey` unused-import warning in `src/witness.rs` is out of scope.

## Review Focus

Inputs the spec implies but no existing test exercises; each line's test is added to the task named.

1. **An instance with the minimum chunk count (2: program, public, range tables)** — the wide matrix is `2·2 + 4 = 8` columns and must open and recompose exactly like a 16-chunk one. Task 2's round trip covers all seven chip instances of the toy proof; Task 2 Step 3's structural test asserts the per-instance widths including the width-8 ones.
2. **A non-hiding PCS (zero random codewords)** — `concat_chunk_rows` must handle a chunk width equal to `DIMENSION` (no salt columns to carry). Task 2 Step 1's unit test in the fork covers `salts = 0` and `salts = 4`.
3. **A `PerInstance` proof that crosses a serialisation boundary** — the backend path (`prove_on`) postcard-round-trips the batch proof; the opened-values parsing on the way back must not depend on the layout. Task 2 Step 3's `a_per_instance_proof_survives_postcard` covers it.
4. **A proof with the reduce table (eight instances, 16 reduce chunks)** — the eighth instance's chunks are the widest case beside the cpu's. Task 2 Step 6 runs the existing `tests/cheating.rs` reduce suite under the new layout.
5. **A flipped random-codeword hint on the wide quotient row** — four hints per instance now carry the salts of 2–16 chunks; a flipped one must still fail the Merkle row, not be silently ignored. Task 2 Step 3's `a_flipped_quotient_random_hint_is_refused` covers it.

---

### Task 0: Baseline measurement on this branch

**Files:**
- Create: `recursion/docs/measurements/2026-10-05-tier16-before.log`

**Interfaces:**
- Produces: the "before" row of the spec §4 table (peak live heap and wall at tier 16, 16 threads) for Task 5 and the docs in Task 6.

- [ ] **Step 1: Run the tier-16 synthetic under the heap profiler, 16 threads, before any code change**

Run (from `~/rand-worktrees/circuits-quotient/recursion`):
```bash
RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures RAYON_NUM_THREADS=16 \
  cargo test --release --features parallel --test memprofile tier16_synthetic_threads -- --ignored --nocapture \
  2>&1 | tee docs/measurements/2026-10-05-tier16-before.log | tail -5
```
Expected: the `report(...)` line prints `tier16 synthetic` with `rows 63762`, `tier 16`, a peak live near 9.09 GB and a prove wall near 36 s (docs/04 §"Threads").

- [ ] **Step 2: Commit the log**

```bash
cd ~/rand-worktrees/circuits-quotient
git add recursion/docs/measurements/2026-10-05-tier16-before.log
git commit -q -m "recursion docs: tier-16 memprofile baseline before the quotient-layout cut

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 1: Vendor `p3-batch-stark` as a drop-in with the layout switch (no behaviour change yet)

**Files:**
- Create: `vendor/p3-batch-stark/Cargo.toml`, `vendor/p3-batch-stark/src/**` (copied), `vendor/p3-batch-stark/README.md`, `vendor/p3-batch-stark/CHANGELOG.md`, `vendor/p3-batch-stark/src/layout.rs`
- Modify: `vendor/p3-batch-stark/src/lib.rs`, `vendor/p3-batch-stark/src/prover.rs` (signature only), `vendor/p3-batch-stark/src/verifier/mod.rs` (signatures only), `recursion/Cargo.toml:86-89` (the `[patch.crates-io]` table), `vendor/PROVENANCE.md`

**Interfaces:**
- Produces:
  - `p3_batch_stark::QuotientLayout` — `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum QuotientLayout { PerChunk, PerInstance }`
  - `p3_batch_stark::prove_batch_with_layout(config: &SC, instances: &[StarkInstance<'_, SC, A>], prover_data: &ProverData<SC>, layout: QuotientLayout) -> BatchProof<SC>` (same bounds as `prove_batch`)
  - `p3_batch_stark::verify_batch_with_layout(config: &SC, airs: &[A], proof: &BatchProof<SC>, public_values: &[Vec<Val<SC>>], common: &CommonData<SC>, layout: QuotientLayout) -> Result<(), BatchVerificationError<PcsError<SC>>>`
  - `p3_batch_stark::verifier::commitments_with_opening_points_with_layout(config, airs, zeta, commitments, opened_values, common, degree_bits, preprocessed_widths, log_num_quotient_chunks, layout) -> Result<OpeningArgumentWithQuotientDomains<SC>, BatchVerificationError<PcsError<SC>>>`
  - `prove_batch`, `verify_batch`, `commitments_with_opening_points` keep their signatures and call the `_with_layout` forms with `QuotientLayout::PerChunk`.
- Consumes: nothing from other tasks.

- [ ] **Step 1: Copy the crate from the cargo registry, less its tests, benches and lock file**

```bash
cd ~/rand-worktrees/circuits-quotient
SRC=$(ls -d ~/.cargo/registry/src/*/p3-batch-stark-0.7.0 | head -1)
mkdir -p vendor/p3-batch-stark
cp -R "$SRC/src" vendor/p3-batch-stark/src
cp "$SRC/README.md" "$SRC/CHANGELOG.md" vendor/p3-batch-stark/
ls vendor/p3-batch-stark/src vendor/p3-batch-stark/src/verifier
```
Expected: `check_constraints.rs common.rs config.rs error.rs lib.rs proof.rs prover.rs symbolic.rs transcript.rs verifier` and `data.rs mod.rs`.

- [ ] **Step 2: Write the standalone manifest (model: `vendor/p3-fri/Cargo.toml`, which de-workspaced the same way)**

Create `vendor/p3-batch-stark/Cargo.toml`:
```toml
# RandProtocol fork of Plonky3's p3-batch-stark 0.7.0 — see ../PROVENANCE.md. The crates.io manifest
# inherits from Plonky3's workspace; this one spells the same values out. Upstream's tests and
# benches are not carried (they need ten sibling crates as dev-dependencies); the fork's tests
# live in ../../recursion/tests/quotient_layout.rs, against the machine that uses the patch.
[package]
name = "p3-batch-stark"
version = "0.7.0"
edition = "2024"
license = "MIT OR Apache-2.0"
description = "Batched STARK wrapper atop p3-uni-stark that reuses FRI openings across instances. RandProtocol fork: a quotient-layout switch."
repository = "https://github.com/Plonky3/Plonky3"

[lib]
name = "p3_batch_stark"
path = "src/lib.rs"

[features]
parallel = ["p3-maybe-rayon/parallel"]

[dependencies]
p3-air = "=0.7.0"
p3-challenger = "=0.7.0"
p3-commit = "=0.7.0"
p3-field = "=0.7.0"
p3-lookup = "=0.7.0"
p3-matrix = "=0.7.0"
p3-maybe-rayon = "=0.7.0"
p3-uni-stark = "=0.7.0"
p3-util = "=0.7.0"
hashbrown = "0.17.1"
serde = { version = "1.0", default-features = false, features = ["derive", "alloc"] }
thiserror = { version = "2.0", default-features = false }
tracing = { version = "0.1.44", default-features = false, features = ["attributes"] }
```

- [ ] **Step 3: Add the layout enum and export it**

Create `vendor/p3-batch-stark/src/layout.rs`:
```rust
//! RandProtocol patch (2026-10-04): quotient layout.

/// How an instance's quotient chunks are committed in the quotient round.
///
/// Plonky3 0.7.0 commits one matrix per chunk: `Challenge::DIMENSION` data columns, plus whatever
/// a hiding PCS appends to every matrix (random codewords) and the hiding MMCS salts per row. For an
/// instance with sixteen chunks that is sixteen matrices of 2 + 4 columns at one height, 200 %
/// overhead on the data. `PerInstance` commits one matrix per instance — every chunk's data
/// columns side by side, the random codewords once — at the same height. The two-adic PCS reads
/// nothing of a matrix but its height and its rows, so the chunk polynomials, their ZK
/// randomisation and the verifier's recomposition are unchanged; only the commitment and the
/// opening rows are laid out differently. A proof made under one layout is refused under the
/// other by the PCS (a matrix-count or row-width mismatch), never silently accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotientLayout {
    /// One committed matrix per quotient chunk — upstream Plonky3 0.7.0's layout. The default
    /// every caller of `prove_batch` / `verify_batch` keeps.
    PerChunk,
    /// One committed matrix per instance: `chunks · DIMENSION` data columns, then the hiding
    /// PCS's random codewords once.
    PerInstance,
}
```

In `vendor/p3-batch-stark/src/lib.rs`, after `pub mod error;` add `pub mod layout;` and at the re-exports replace the two lines
```rust
pub use prover::{StarkInstance, prove_batch};
pub use transcript::BatchTranscript;
pub use verifier::{VerifierData, verify_batch};
```
with
```rust
pub use layout::QuotientLayout;
pub use prover::{StarkInstance, prove_batch, prove_batch_with_layout};
pub use transcript::BatchTranscript;
pub use verifier::{
    VerifierData, commitments_with_opening_points, commitments_with_opening_points_with_layout,
    verify_batch, verify_batch_with_layout,
};
```

- [ ] **Step 4: Split the three entry points into a `_with_layout` body and a `PerChunk` wrapper (the layout is accepted and not yet used)**

In `vendor/p3-batch-stark/src/prover.rs`: rename the existing `pub fn prove_batch<...>(config, instances, prover_data) -> BatchProof<SC>` to `pub fn prove_batch_with_layout<...>(config, instances, prover_data, layout: QuotientLayout) -> BatchProof<SC>` (same generics, same `where` clause, same `#[instrument(skip_all)]`), add `use crate::layout::QuotientLayout;` to the imports, add `let _ = layout; // used from Task 2 on` as the body's first line, and add above it:
```rust
/// Generate a batch STARK proof for all provided instances under upstream's quotient layout
/// ([`QuotientLayout::PerChunk`]). See [`prove_batch_with_layout`].
#[instrument(skip_all)]
pub fn prove_batch<
    SC,
    #[cfg(debug_assertions)] A: for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>
        + Air<InteractionSymbolicBuilder<Val<SC>, SC::Challenge>>
        + for<'a> Air<ProverConstraintFolderWithLookups<'a, SC>>
        + Clone,
    #[cfg(not(debug_assertions))] A: for<'a> Air<InteractionSymbolicBuilder<Val<SC>, SC::Challenge>>
        + for<'a> Air<ProverConstraintFolderWithLookups<'a, SC>>
        + Clone,
>(
    config: &SC,
    instances: &[StarkInstance<'_, SC, A>],
    prover_data: &ProverData<SC>,
) -> BatchProof<SC>
where
    SC: SGC,
    Val<SC>: PrimeField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SC::Challenge>,
    Domain<SC>: Send + Sync,
    SC::Pcs: Sync,
    <SC::Pcs as p3_commit::Pcs<SC::Challenge, SC::Challenger>>::ProverData: Sync,
    <SC::Pcs as p3_commit::Pcs<SC::Challenge, SC::Challenger>>::Commitment: Sync,
{
    // RandProtocol patch (2026-10-04): quotient layout — upstream's entry point, upstream's layout.
    prove_batch_with_layout(config, instances, prover_data, QuotientLayout::PerChunk)
}
```
(The `where` clause is copied verbatim from the existing function — check `prover.rs:117-125` and copy whatever is there.)

In `vendor/p3-batch-stark/src/verifier/mod.rs`: the same split for `commitments_with_opening_points` (add a tenth parameter `layout: QuotientLayout` to the `_with_layout` form; the wrapper passes `QuotientLayout::PerChunk` and keeps `#[expect(clippy::too_many_arguments)]`) and for `verify_batch` (sixth parameter `layout`; the body's single call to `commitments_with_opening_points(` becomes `commitments_with_opening_points_with_layout(` with `layout` appended). Add `use crate::layout::QuotientLayout;`.

- [ ] **Step 5: Patch the recursion crate to the fork and check it builds unchanged**

In `recursion/Cargo.toml`, the `[patch.crates-io]` table (the last lines of the file) becomes:
```toml
[patch.crates-io]
p3-fri = { path = "../vendor/p3-fri" }
p3-merkle-tree = { path = "../vendor/p3-merkle-tree" }
# The quotient-layout fork (`../vendor/PROVENANCE.md`, `docs/05-quotient-layout.md`): `PerChunk`
# is upstream byte for byte; this machine selects `PerInstance` (`machine::QUOTIENT_LAYOUT`).
p3-batch-stark = { path = "../vendor/p3-batch-stark" }
```
Run: `cd ~/rand-worktrees/circuits-quotient/recursion && cargo build --release 2>&1 | tail -3`
Expected: `Finished`, with `Compiling p3-batch-stark v0.7.0 (/Users/.../vendor/p3-batch-stark)` earlier in the output, and no new warnings from the vendored crate.

- [ ] **Step 6: Prove the fork is a drop-in — the pins that must not move, and a proof round trip**

Run:
```bash
RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures cargo test --release --test machine --test verifier --test verifier_key --test self_verify 2>&1 | grep -E "^test result|FAILED"
```
Expected: four `test result: ok` lines, 0 failed (self_verify's pins are unchanged because nothing changed behaviourally yet).

- [ ] **Step 7: Record the provenance**

Append to `vendor/PROVENANCE.md`:
```markdown

## p3-batch-stark 0.7.0 — the quotient-layout fork (2026-10-04)

- The crates.io source (`src/`, `README.md`, `CHANGELOG.md`), less `tests/`, `benches/`, `Cargo.lock`
  and the workspace-inheriting manifest, which `Cargo.toml` here spells out. Changed files, each
  marked `RandProtocol patch (2026-10-04): quotient layout`: `src/layout.rs` (new: `QuotientLayout`),
  `src/lib.rs` (exports), `src/prover.rs` (`prove_batch_with_layout`; the per-instance quotient
  matrix), `src/verifier/mod.rs` (`verify_batch_with_layout`,
  `commitments_with_opening_points_with_layout`; the per-instance quotient round).
- Why: `docs/superpowers/specs/2026-10-04-rvm-quotient-layout-design.md` and
  `recursion/docs/05-quotient-layout.md` — one committed matrix per instance's quotient chunks
  instead of one per chunk, the prover's largest memory term. No upstream issue; `PerChunk` is
  upstream's behaviour byte for byte and is what every caller but the rVM gets.
- Used by `recursion/` (its `[patch.crates-io]`). `research/` is not patched: the RV32 machine
  keeps crates.io's crate and the `PerChunk` layout.
- Review: `diff -r --exclude Cargo.toml --exclude Cargo.lock --exclude tests --exclude benches
  $(ls -d ~/.cargo/registry/src/*/p3-batch-stark-0.7.0) vendor/p3-batch-stark` shows exactly the
  marked hunks.
```

- [ ] **Step 8: Commit**

```bash
cd ~/rand-worktrees/circuits-quotient
git add vendor/p3-batch-stark vendor/PROVENANCE.md recursion/Cargo.toml recursion/Cargo.lock
git commit -q -m "vendor: p3-batch-stark 0.7.0 forked with a QuotientLayout switch — PerChunk (upstream) is the default, every caller unchanged

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: The per-instance quotient matrix — fork prover and verifier, the machine switch, the tests

**Files:**
- Modify: `vendor/p3-batch-stark/src/prover.rs` (the quotient section, `prover.rs:342-460` upstream numbering; the opened-values parsing, `:596-610`), `vendor/p3-batch-stark/src/verifier/mod.rs` (the quotient round, `:223-239`), `recursion/src/machine.rs:10` (imports), `:475-499` (`prove_traces`), `:574` (`prove_on`), `:618` (`verify`)
- Create: `recursion/tests/quotient_layout.rs`

**Interfaces:**
- Consumes: Task 1's `QuotientLayout`, `prove_batch_with_layout`, `verify_batch_with_layout`.
- Produces:
  - `recursion::machine::QUOTIENT_LAYOUT: QuotientLayout` (= `PerInstance`)
  - `Machine::prove_traces_with_layout(&self, program: &Program, traces: &Traces, tier: Tier, layout: QuotientLayout) -> Proof`; `prove_traces` calls it with `QUOTIENT_LAYOUT`.
  - a `PerInstance` rVM proof has, in the quotient round (round index 2 of `opening_proof`), one matrix per instance.

- [ ] **Step 1: Write the fork's row-concatenation helper with its unit test (fails: function missing)**

Append to `vendor/p3-batch-stark/src/prover.rs`:
```rust
/// RandProtocol patch (2026-10-04): quotient layout. One instance's chunk LDEs, already
/// bit-reversed at one height, laid side by side into one matrix: every chunk's first
/// `data_width` columns in chunk order, then the **first** chunk's remaining columns — the hiding
/// PCS's random codewords, kept once as the wide matrix's own (a non-hiding PCS has none, and then
/// nothing is appended). The other chunks' random columns are dropped: they were LDE'd for a
/// matrix that is no longer committed.
///
/// # Panics
/// If the chunk matrices do not share one height and one width, or a width is below `data_width`.
pub(crate) fn concat_chunk_rows<T: Clone + Default + Send + Sync>(
    chunks: &[RowMajorMatrix<T>],
    data_width: usize,
) -> RowMajorMatrix<T> {
    let n = chunks.len();
    assert!(n >= 1, "an instance has at least one quotient chunk");
    let h = chunks[0].height();
    let w = chunks[0].width();
    assert!(w >= data_width, "a chunk matrix carries at least its data columns");
    for m in chunks {
        assert_eq!((m.height(), m.width()), (h, w), "one instance's chunks share a shape");
    }
    let extra = w - data_width;
    let out_w = n * data_width + extra;
    let mut values = vec![T::default(); h * out_w];
    values
        .par_chunks_mut(out_w)
        .enumerate()
        .for_each(|(r, dst)| {
            for (c, m) in chunks.iter().enumerate() {
                dst[c * data_width..(c + 1) * data_width]
                    .clone_from_slice(&m.values[r * w..r * w + data_width]);
            }
            dst[n * data_width..].clone_from_slice(&chunks[0].values[r * w + data_width..(r + 1) * w]);
        });
    RowMajorMatrix::new(values, out_w)
}

#[cfg(test)]
mod layout_tests {
    use super::*;

    #[test]
    fn concat_lays_data_columns_side_by_side_and_keeps_the_first_chunks_salts_once() {
        // Three chunks, two rows, data width 2, two "salt" columns each: rows are [d0 d1 s0 s1].
        let c0 = RowMajorMatrix::new(vec![1u32, 2, 90, 91, 3, 4, 92, 93], 4);
        let c1 = RowMajorMatrix::new(vec![5u32, 6, 80, 81, 7, 8, 82, 83], 4);
        let c2 = RowMajorMatrix::new(vec![9u32, 10, 70, 71, 11, 12, 72, 73], 4);
        let wide = concat_chunk_rows(&[c0, c1, c2], 2);
        assert_eq!(wide.width(), 3 * 2 + 2);
        assert_eq!(wide.height(), 2);
        assert_eq!(wide.values, vec![1, 2, 5, 6, 9, 10, 90, 91, 3, 4, 7, 8, 11, 12, 92, 93]);
    }

    #[test]
    fn concat_without_salt_columns_is_a_plain_horizontal_join() {
        let c0 = RowMajorMatrix::new(vec![1u32, 2, 3, 4], 2);
        let c1 = RowMajorMatrix::new(vec![5u32, 6, 7, 8], 2);
        let wide = concat_chunk_rows(&[c0, c1], 2);
        assert_eq!(wide.width(), 4);
        assert_eq!(wide.values, vec![1, 2, 5, 6, 3, 4, 7, 8]);
    }
}
```
(`RowMajorMatrix::values` is a public field; `par_chunks_mut` comes from the already-imported `p3_maybe_rayon::prelude::*` and is serial without the `parallel` feature. `vec!` is `alloc::vec!`, already imported.)

- [ ] **Step 2: Run the unit tests (they pass once the helper compiles; this pins the helper before it is wired in)**

Run: `cd ~/rand-worktrees/circuits-quotient/vendor/p3-batch-stark && cargo test --release layout_tests 2>&1 | grep -E "^test |test result"`
Expected: both tests `ok`, `test result: ok. 2 passed`.

- [ ] **Step 3: Write the rVM-level tests (they fail: `QUOTIENT_LAYOUT` and `prove_traces_with_layout` do not exist yet)**

Create `recursion/tests/quotient_layout.rs`:
```rust
//! The quotient-layout fork (`docs/05-quotient-layout.md`): the rVM commits each instance's
//! quotient chunks as one matrix. What this file pins: the machine's layout constant, the proof's
//! quotient-round structure, the proof's survival of serialisation, and the refusals — a flipped
//! chunk value, a flipped random hint, and a proof made under upstream's layout.
mod common;

use p3_batch_stark::QuotientLayout;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use recursion::isa::{Instr, Op, Program, F};
use recursion::machine::{Machine, Tier, VerifyError, QUOTIENT_LAYOUT};
use rand_zkvm::machine::FriProfile;

fn instr(op: Op, rd: u8, ra: u8, b: u64) -> Instr {
    Instr { op, rd, ra, b: F::from_u64(b) }
}

/// `tests/machine.rs`'s toy with the four-word interface digest.
fn toy_program() -> Program {
    Program {
        instrs: vec![
            instr(Op::Faddi, 1, 0, 7),
            instr(Op::Faddi, 2, 0, 5),
            instr(Op::Fadd, 3, 1, 2),
            instr(Op::Public, 0, 3, 0),
            instr(Op::Public, 0, 1, 0),
            instr(Op::Public, 0, 2, 0),
            instr(Op::Public, 0, 3, 0),
            instr(Op::Halt, 0, 0, 0),
        ],
        checkpoints: vec![],
    }
}

/// The quotient round's index in `opening_proof`: `random` (0), `main` (1), `quotient_chunks` (2),
/// then `preprocessed` and `permutation` (`p3-batch-stark/src/prover.rs`, "Round 2").
const QUOTIENT_ROUND: usize = 2;
const NUM_RANDOM_CODEWORDS: usize = 4;
const DIMENSION: usize = <recursion::machine::Challenge as BasedVectorSpace<recursion::machine::Val>>::DIMENSION;

#[test]
fn the_machine_pins_the_per_instance_layout() {
    assert_eq!(QUOTIENT_LAYOUT, QuotientLayout::PerInstance, "the rVM's own proofs take the fork's layout");
}

#[test]
fn a_per_instance_proof_has_one_quotient_matrix_per_instance_and_verifies() {
    let p = toy_program();
    let m = Machine::new(FriProfile::Test);
    let (proof, _) = m.prove(&p, &[], None).unwrap();
    m.verify(&p, &proof).unwrap();

    let n = proof.batch.degree_bits.len();
    let (rand_openings, fri) = &proof.batch.opening_proof;
    // The hiding PCS's hidden halves: one set of four per instance, not one per chunk.
    assert_eq!(rand_openings[QUOTIENT_ROUND].len(), n, "one quotient matrix per instance");
    for mat in &rand_openings[QUOTIENT_ROUND] {
        assert_eq!(mat.len(), 1, "opened at zeta only");
        assert_eq!(mat[0].len(), NUM_RANDOM_CODEWORDS);
    }
    // The committed rows: `chunks · DIMENSION + 4` base columns, chunks as the proof's per-chunk
    // opened values count them (16 for the cpu table, 2 for the program table).
    for q in 0..fri.input_openings[QUOTIENT_ROUND].opened_values.len() {
        let rows = &fri.input_openings[QUOTIENT_ROUND].opened_values[q];
        assert_eq!(rows.len(), n);
        for (i, row) in rows.iter().enumerate() {
            let chunks = proof.batch.opened_values.instances[i].base_opened_values.quotient_chunks.len();
            assert!(chunks >= 2, "ZK doubles every chunk count");
            assert_eq!(row.len(), chunks * DIMENSION + NUM_RANDOM_CODEWORDS, "instance {i}");
        }
    }
    // The per-chunk opened values keep upstream's shape, so recomposition is untouched.
    for inst in &proof.batch.opened_values.instances {
        for chunk in &inst.base_opened_values.quotient_chunks {
            assert_eq!(chunk.len(), DIMENSION);
        }
    }
}

#[test]
fn a_per_instance_proof_survives_postcard() {
    let p = toy_program();
    let m = Machine::new(FriProfile::Test);
    let (proof, _) = m.prove(&p, &[], None).unwrap();
    let bytes = proof.to_bytes();
    let back: recursion::machine::Proof = postcard::from_bytes(&bytes).unwrap();
    m.verify(&p, &back).unwrap();
}

#[test]
fn a_flipped_quotient_chunk_value_is_refused() {
    let p = toy_program();
    let m = Machine::new(FriProfile::Test);
    let (mut proof, _) = m.prove(&p, &[], None).unwrap();
    // Instance 1 is the cpu table (16 chunks); flip one lane of chunk 3 inside the wide row.
    let v = &mut proof.batch.opened_values.instances[1].base_opened_values.quotient_chunks[3][0];
    *v += recursion::machine::Challenge::ONE;
    match m.verify(&p, &proof) {
        Err(VerifyError::Batch(_)) => {}
        other => panic!("a flipped quotient value must be refused by the batch verifier, got {other:?}"),
    }
}

#[test]
fn a_flipped_quotient_random_hint_is_refused() {
    let p = toy_program();
    let m = Machine::new(FriProfile::Test);
    let (mut proof, _) = m.prove(&p, &[], None).unwrap();
    // The wide row's four hidden values are the instance's one salt set now; flip one.
    let v = &mut proof.batch.opening_proof.0[QUOTIENT_ROUND][1][0][0];
    *v += recursion::machine::Challenge::ONE;
    match m.verify(&p, &proof) {
        Err(VerifyError::Batch(_)) => {}
        other => panic!("a flipped random hint must fail the Merkle row, got {other:?}"),
    }
}

#[test]
fn a_proof_made_under_upstreams_layout_is_refused_not_panicked() {
    let p = toy_program();
    let m = Machine::new(FriProfile::Test);
    let exec = recursion::emulator::execute(&p, &[], Tier(8).max_cycles()).unwrap();
    let tier = Tier::for_cycles(exec.cpu_rows()).unwrap();
    let traces = recursion::machine::build_traces(&p, &exec, tier).unwrap();
    let honest = m.prove_traces_with_layout(&p, &traces, tier, QUOTIENT_LAYOUT);
    m.verify(&p, &honest).unwrap();
    let per_chunk = m.prove_traces_with_layout(&p, &traces, tier, QuotientLayout::PerChunk);
    match m.verify(&p, &per_chunk) {
        Err(VerifyError::Batch(msg)) => {
            assert!(
                msg.contains("Mismatch") || msg.contains("InvalidOpeningArgument"),
                "the refusal names the layout disagreement: {msg}"
            );
        }
        other => panic!("a PerChunk proof must be refused by a PerInstance verifier, got {other:?}"),
    }
}
```
Names checked against the tree while planning: `Proof::to_bytes` (`machine.rs:282`; there is no `from_bytes`, hence `postcard::from_bytes` — `postcard` is a dependency of the crate), `pub fn build_traces(program, exec, tier) -> Result<Traces, ProveError>` (`machine.rs:414`), `Challenge`/`Val` re-exported from `rand_zkvm::machine` (`machine.rs:24-29`), `recursion::emulator::execute` (`emulator.rs:167`), `Machine.config` is `pub`.

- [ ] **Step 4: Run the new test file to see it fail for the right reason**

Run: `RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures cargo test --release --test quotient_layout 2>&1 | grep -E "^error|cannot find|test result" | head`
Expected: compile errors `cannot find value QUOTIENT_LAYOUT` and `no method named prove_traces_with_layout`.

- [ ] **Step 5: Implement `PerInstance` in the fork's prover**

In `vendor/p3-batch-stark/src/prover.rs`, inside `prove_batch_with_layout`, delete the `let _ = layout;` line. In the per-instance quotient closure (upstream `prover.rs:345-445`), replace
```rust
            // Compute low-degree extensions of each chunk for commitment.
            let evals = chunk_domains.iter().zip(chunk_mats).map(|(d, m)| (*d, m));
            let ldes = pcs.get_quotient_ldes(evals, n_chunks);

            (chunk_domains, ldes)
```
with
```rust
            // Compute low-degree extensions of each chunk for commitment.
            let evals = chunk_domains.iter().zip(chunk_mats).map(|(d, m)| (*d, m));
            let ldes = pcs.get_quotient_ldes(evals, n_chunks);

            // RandProtocol patch (2026-10-04): quotient layout. Under `PerInstance` the chunk LDEs
            // become one matrix here, inside the instance's own step, so the per-chunk copies are
            // dropped before the next instance is processed. The one stand-in domain is the first
            // chunk's: every chunk domain of an instance has the same size, which is all the PCS
            // reads of a committed matrix's domain.
            match layout {
                QuotientLayout::PerChunk => (chunk_domains, ldes),
                QuotientLayout::PerInstance => {
                    let wide = concat_chunk_rows(&ldes, SC::Challenge::DIMENSION);
                    drop(ldes);
                    (vec![chunk_domains[0]], vec![wide])
                }
            }
```
`SC::Challenge::DIMENSION` needs `BasedVectorSpace` in scope — it is already imported at the top of `prover.rs` (`use p3_field::{Algebra, BasedVectorSpace, ...}`). `quotient_chunk_ranges` then holds `(i, i + 1)` per instance under `PerInstance`, so "Round 2: quotient chunks, each opened at zeta only" (`round2_points`) needs no change.

In the opened-values parsing ("Quotient chunks: collect the zeta-point opening of each chunk"), replace
```rust
        // Quotient chunks: collect the zeta-point opening of each chunk.
        let mut qcs = Vec::with_capacity(e - s);
        for _ in s..e {
            let mat_vals = quotient_openings_iter
                .next()
                .expect("chunk index in bounds");
            qcs.push(mat_vals[0].clone());
        }
```
with
```rust
        // Quotient chunks: collect the zeta-point opening of each chunk.
        // RandProtocol patch (2026-10-04): quotient layout. Under `PerInstance` the one matrix's
        // row is every chunk's `DIMENSION` values in chunk order; the proof keeps upstream's
        // per-chunk shape, so the verifier's recomposition does not know the layout.
        let n_chunks_i = num_quotient_chunks[i];
        let mut qcs = Vec::with_capacity(n_chunks_i);
        match layout {
            QuotientLayout::PerChunk => {
                for _ in s..e {
                    let mat_vals = quotient_openings_iter
                        .next()
                        .expect("chunk index in bounds");
                    qcs.push(mat_vals[0].clone());
                }
            }
            QuotientLayout::PerInstance => {
                debug_assert_eq!(e - s, 1);
                let mat_vals = quotient_openings_iter
                    .next()
                    .expect("one quotient matrix per instance");
                let row = &mat_vals[0];
                let d = SC::Challenge::DIMENSION;
                assert_eq!(row.len(), n_chunks_i * d, "the wide row is every chunk's values");
                qcs.extend(row.chunks_exact(d).map(|c| c.to_vec()));
            }
        }
```

- [ ] **Step 6: Implement `PerInstance` in the fork's verifier**

In `vendor/p3-batch-stark/src/verifier/mod.rs`, inside `commitments_with_opening_points_with_layout`, replace the quotient round loop
```rust
    // Build the per-matrix openings for the aggregated quotient commitment.
    let mut qc_round = Vec::new();
    for (i, domains) in randomized_quotient_chunks_domains.iter().enumerate() {
        let inst_qcs = &opened_values.instances[i]
            .base_opened_values
            .quotient_chunks;
        for (d, vals) in zip_eq(
            domains.iter(),
            inst_qcs,
            VerificationError::from(InvalidProofShapeError::QuotientDomainsCountMismatch {
                air: i,
            }),
        )? {
            qc_round.push((*d, vec![(zeta, vals.clone())]));
        }
    }
    coms_to_verify.push((commitments.quotient_chunks.clone(), qc_round));
```
with
```rust
    // Build the per-matrix openings for the aggregated quotient commitment.
    // RandProtocol patch (2026-10-04): quotient layout. `PerChunk` is upstream: one matrix per
    // chunk, instance-major. `PerInstance`: one matrix per instance whose claimed row is every
    // chunk's values in chunk order, at the first chunk's domain (same size as all of them). A
    // proof of the other layout fails inside the PCS — the hiding verifier's matrix-count check
    // or the MMCS row-width check — and surfaces as `InvalidOpeningArgument`.
    let mut qc_round = Vec::new();
    for (i, domains) in randomized_quotient_chunks_domains.iter().enumerate() {
        let inst_qcs = &opened_values.instances[i]
            .base_opened_values
            .quotient_chunks;
        match layout {
            QuotientLayout::PerChunk => {
                for (d, vals) in zip_eq(
                    domains.iter(),
                    inst_qcs,
                    VerificationError::from(InvalidProofShapeError::QuotientDomainsCountMismatch {
                        air: i,
                    }),
                )? {
                    qc_round.push((*d, vec![(zeta, vals.clone())]));
                }
            }
            QuotientLayout::PerInstance => {
                if inst_qcs.len() != domains.len() {
                    return Err(VerificationError::from(
                        InvalidProofShapeError::QuotientDomainsCountMismatch { air: i },
                    )
                    .into());
                }
                let row: Vec<Challenge<SC>> =
                    inst_qcs.iter().flat_map(|chunk| chunk.iter().cloned()).collect();
                qc_round.push((domains[0], vec![(zeta, row)]));
            }
        }
    }
    coms_to_verify.push((commitments.quotient_chunks.clone(), qc_round));
```
(If the `.into()` on the error does not type-check, follow the file's existing conversion for the same error two lines above — `VerificationError::from(...)` wrapped by `?` on a `Result<_, VerificationError<_>>` collected into the outer `BatchVerificationError`; mirror whatever `zip_eq`'s error path does.)

- [ ] **Step 7: Pin the layout in the rVM machine and add the layout-taking prover entry**

In `recursion/src/machine.rs`:
- line 10: `use p3_batch_stark::{prove_batch, verify_batch, BatchProof, CommonData, ProverData, StarkInstance};` → `use p3_batch_stark::{prove_batch_with_layout, verify_batch_with_layout, BatchProof, CommonData, ProverData, QuotientLayout, StarkInstance};`
- after the `pub type Config = …;` line add:
```rust
/// How this machine commits each instance's quotient chunks (`docs/05-quotient-layout.md`): one
/// matrix per instance, salted once, instead of Plonky3's one matrix per chunk — the prover's
/// largest memory term cut by about 60 % of itself. A property of the machine, pinned here like the
/// FRI profile and the degree pins, and deliberately *not* a field of [`Proof`]: a verifier must
/// not let a proof choose how it is checked. A proof made under the other layout is refused by
/// `verify` (the PCS's matrix-count or row-width check), never accepted. The RV32 machine
/// (`research/`) keeps upstream's `PerChunk`; flipping it is a constraint-set cut.
pub const QUOTIENT_LAYOUT: QuotientLayout = QuotientLayout::PerInstance;
```
- `prove_traces` (`:475`): rename the existing body to
```rust
    pub fn prove_traces(&self, program: &Program, traces: &Traces, tier: Tier) -> Proof {
        self.prove_traces_with_layout(program, traces, tier, QUOTIENT_LAYOUT)
    }

    /// [`prove_traces`](Self::prove_traces) under an explicit quotient layout — the layout tests'
    /// entry point, so a proof under upstream's `PerChunk` layout can be built and shown refused.
    /// Every proof this machine publishes is `QUOTIENT_LAYOUT`'s.
    pub fn prove_traces_with_layout(&self, program: &Program, traces: &Traces, tier: Tier, layout: QuotientLayout) -> Proof {
        … the old body, with
        let batch = prove_batch(&self.config, &instances, &prover_data);
        becoming
        let batch = prove_batch_with_layout(&self.config, &instances, &prover_data, layout);
    }
```
- `prove_on` (`:574`): `prove_batch(cfg, &instances, &prover_data)` → `prove_batch_with_layout(cfg, &instances, &prover_data, QUOTIENT_LAYOUT)`.
- `verify` (`:618`): `verify_batch(&self.config, &airs, &proof.batch, &pvs, &common)` → `verify_batch_with_layout(&self.config, &airs, &proof.batch, &pvs, &common, QUOTIENT_LAYOUT)`.
- The module doc at the top of `machine.rs` ("reuses the RV32 machine's exact proof-system configuration") gains one sentence: "Since the quotient-layout fork (`docs/05`) the rVM's own proofs commit their quotient chunks one matrix per instance (`QUOTIENT_LAYOUT`); the inner RV32 proofs it verifies do not."

- [ ] **Step 8: Run the new tests and the existing machine/cheating suites**

Run:
```bash
RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures cargo test --release --test quotient_layout --test machine --test cheating 2>&1 | grep -E "^test |test result|panicked" | grep -v " ok$" ; echo "---"; RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures cargo test --release --test quotient_layout --test machine --test cheating 2>&1 | grep -E "^test result"
```
Expected: no failures listed; three `test result: ok` lines (quotient_layout 6 passed; machine as before; cheating 47 passed, 1 ignored — the reduce, sponge and HINTN suites prove and verify under the new layout).

- [ ] **Step 9: Check the backend path still compiles (the `prove_on` call site is feature-gated)**

Run: `cargo check --release --features reference-backend 2>&1 | tail -2`
Expected: `Finished` (the CPU-twin backend builds without a GPU; if `rand-zkvm-cuda` fails to build for an unrelated reason on this box, record the error in the task report and move on — the one-line change at `prove_on` is reviewed by eye).

- [ ] **Step 10: Commit**

```bash
cd ~/rand-worktrees/circuits-quotient
git add vendor/p3-batch-stark recursion/src/machine.rs recursion/tests/quotient_layout.rs
git commit -q -m "recursion, vendor: the rVM commits each instance's quotient chunks as one matrix (QuotientLayout::PerInstance) — fork prover and verifier, the machine's pin, six layout tests

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: The self-verifier reads the new layout — `VerifierShape::quotient_layout`, the replay, the program, the pins

**Files:**
- Modify: `recursion/src/shape.rs:655-690` (the trait), `:689` (`impl VerifierShape for InnerShape`), `:1107` (`impl VerifierShape for RvmShape`); `recursion/src/reference.rs:277-287`; `recursion/src/programs/constraints.rs:90-110` (`RawInstance`), `:184-200` (its construction); `recursion/src/programs/rv32.rs:489-499`; `recursion/tests/self_verify.rs:130`, `:342-367`

**Interfaces:**
- Consumes: Task 2's `QUOTIENT_LAYOUT`; Task 1's `commitments_with_opening_points_with_layout`.
- Produces: `VerifierShape::quotient_layout(&self) -> QuotientLayout` (InnerShape → `PerChunk`, RvmShape → `machine::QUOTIENT_LAYOUT`); `RawInstance.quotient_run: Array<Ext>`; new self-verifier pins.

- [ ] **Step 1: Run the self-verifier suite to see what the layout change broke (the tape and program still assume per-chunk rows)**

Run: `RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures cargo test --release --test self_verify 2>&1 | grep -E "^test |test result|panicked" | head -20`
Expected: `the_self_verifier_accepts_a_real_rvm_proof` and the cost/tamper tests FAIL (the replay builds a per-chunk opening argument for a per-instance proof and the PCS refuses it, or the tape's segment lengths disagree with the program). Note the exact failure for the task report.

- [ ] **Step 2: Add the trait method and both impls**

In `recursion/src/shape.rs`, in `pub trait VerifierShape`, after `fn log_num_quotient_chunks(&self) -> &[usize];` add:
```rust
    /// How the proofs of this shape commit their quotient chunks (`docs/05-quotient-layout.md`):
    /// the RV32 machine's proofs one matrix per chunk (Plonky3's layout, which the aggregate
    /// program's emitted code — and digest — is pinned to); the rVM's own proofs one matrix per
    /// instance (`machine::QUOTIENT_LAYOUT`). The replay, the tape and the program's quotient
    /// round all follow this one answer.
    fn quotient_layout(&self) -> p3_batch_stark::QuotientLayout;
```
In `impl VerifierShape for InnerShape` add
```rust
    fn quotient_layout(&self) -> p3_batch_stark::QuotientLayout {
        p3_batch_stark::QuotientLayout::PerChunk
    }
```
and in `impl VerifierShape for RvmShape`
```rust
    fn quotient_layout(&self) -> p3_batch_stark::QuotientLayout {
        crate::machine::QUOTIENT_LAYOUT
    }
```

- [ ] **Step 3: The host replay builds the opening argument under the shape's layout**

In `recursion/src/reference.rs`, the call `commitments_with_opening_points::<Config, ShapeAir>(` (line ~277) becomes `commitments_with_opening_points_with_layout::<Config, ShapeAir>(` with a tenth argument `shape.quotient_layout(),` after `shape.log_num_quotient_chunks(),`; fix the `use` line that imports `commitments_with_opening_points` to import `commitments_with_opening_points_with_layout` instead (`grep -n commitments_with_opening_points recursion/src/reference.rs`). The replay's `input_rounds` geometry (`reference.rs:488-505`) is derived from the rounds it just built, so it follows without change; so does the tape (`witness.rs` writes segments 6, 11 and 12 from the proof's own nesting and the replay's geometry).

- [ ] **Step 4: The program's quotient round under `PerInstance`**

In `recursion/src/programs/constraints.rs`, `RawInstance` gains a field right after `quotient_chunks`:
```rust
    /// The same values as one contiguous run — the per-instance quotient matrix's claimed row under
    /// `QuotientLayout::PerInstance` (`docs/05`). `quotient_chunks` are slices of it.
    pub quotient_run: Array<Ext>,
```
and its construction (`:184-200`) sets `quotient_run: chunk_run,` beside `quotient_chunks,`.

In `recursion/src/programs/rv32.rs`, replace the quotient round of `observe_claimed` (`:489-499`):
```rust
    // `quotient_chunks`: one matrix per committed chunk, instance-major (`verifier/mod.rs:203-212`).
    let mut mats = Vec::new();
    for i in 0..n {
        for c in 0..committed_chunks(shape, i) {
            let pts =
                vec![point(b, ch, zeta, o.raw[i].quotient_chunks[c], NUM_RANDOM_CODEWORDS)];
            mats.push(MatrixOpening { log_height: h_of(i), points: pts });
        }
    }
    rounds.push(mats);
    metas.push(RoundMeta { name: "quotient", cap: caps.quotient });
```
with
```rust
    // `quotient_chunks`: under the RV32 machine's `PerChunk` layout one matrix per committed chunk,
    // instance-major (`verifier/mod.rs:203-212`); under the rVM's own `PerInstance` layout
    // (`docs/05-quotient-layout.md`, the fork) one matrix per instance whose claimed row is every
    // chunk's `DIMENSION` values in order, with the four hidden values once. The aggregate programs
    // verify RV32 proofs and take the first branch, so their emitted code does not move.
    let mut mats = Vec::new();
    for i in 0..n {
        match shape.quotient_layout() {
            p3_batch_stark::QuotientLayout::PerChunk => {
                for c in 0..committed_chunks(shape, i) {
                    let pts =
                        vec![point(b, ch, zeta, o.raw[i].quotient_chunks[c], NUM_RANDOM_CODEWORDS)];
                    mats.push(MatrixOpening { log_height: h_of(i), points: pts });
                }
            }
            p3_batch_stark::QuotientLayout::PerInstance => {
                let pts = vec![point(b, ch, zeta, o.raw[i].quotient_run, NUM_RANDOM_CODEWORDS)];
                mats.push(MatrixOpening { log_height: h_of(i), points: pts });
            }
        }
    }
    rounds.push(mats);
    metas.push(RoundMeta { name: "quotient", cap: caps.quotient });
```
(`point` observes the public values then the hidden ones in order, which is the verifier's `observe_algebra_slice` of the merged row — the transcript agrees by construction.)

- [ ] **Step 5: The aggregate programs did not move — assert it before touching any pin**

Run: `RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures cargo test --release --test verifier --test aggregate --test verifier_key --test tape_n 2>&1 | grep -E "^test result|FAILED|panicked"`
Expected: all `ok`, 0 failed — `verify_rv32.digest`, the production aggregate digest pin and the admission vectors are unchanged.

- [ ] **Step 6: Run the self-verifier suite and read the new numbers**

Run: `RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures cargo test --release --test self_verify -- --nocapture 2>&1 | grep -E "TOY_TIER8|BUSY|^test |panicked|left:|right:" | head -40`
Expected: `the_self_verifier_accepts_a_real_rvm_proof`, `a_wrong_shape_proof_is_refused`, `thirteen_tampered_rvm_proofs_are_refused_at_the_named_steps`, `the_self_verifier_is_straight_line_in_the_proofs_data` and `a_rewritten_commit_phase_pow_word_in_an_rvm_proof_is_refused` pass; `the_self_program_digest_is_deterministic_and_distinct` fails on the digest hex and `the_self_verifiers_measured_cost_at_two_fixture_shapes` fails on the `CycleReport` tuples and the phase-5 pair, each printing `left:` (the new value). Copy the new digest, the two `CycleReport` tuples (`TOY_TIER8 …` / `BUSY …` lines) and the phase-5 pair. If any *other* test fails, stop: the tape and program disagree, and the failure's named step says where (`TapeError`/`ExecError` at a `quotient`-named checkpoint) — fix before re-pinning anything.

- [ ] **Step 7: Re-pin, recording the before values**

In `recursion/tests/self_verify.rs`:
- line 130: the digest hex becomes the printed one; append to the comment above it: `// The quotient-layout fork (2026-10-05, docs/05): the rVM proof's quotient round is one matrix per instance, so the program's round reader changed shape (was 18514c2a…).`
- lines 342-350: the two tuples become the printed ones, with a new comment paragraph before them in the file's style: `// The quotient-layout fork (2026-10-05, `docs/05-quotient-layout.md`): the quotient round of an rVM proof is one matrix per instance — 7 (or 8) rows with four hidden values and four salts each instead of one per chunk (54 at the toy shape), so the program hints, absorbs and hashes fewer words at every query: toy … → …, busy … → … (was (152527, 7660, 345333, 154375, 30255) and (188390, 9310, 388321, 190502, 36087)).` — fill the arrows with the measured values.
- line 367: the phase-5 pair becomes the printed one with the sentence `// The quotient-layout fork moved phase 5 by …/… (was 7845 / 8125): …` — if the pair is unchanged (phase 5 is the constraint evaluation, which the layout does not touch), say so in one sentence instead of changing the numbers.

- [ ] **Step 8: Run the suite that pins the self-verifier again, and the whole program-side suite**

Run: `RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures cargo test --release --test self_verify --test verifier --test aggregate --test dsl --test program --test precompiles --test transcript --test binding 2>&1 | grep -E "^test result|FAILED"`
Expected: all `ok`, 0 failed.

- [ ] **Step 9: Commit**

```bash
cd ~/rand-worktrees/circuits-quotient
git add recursion/src/shape.rs recursion/src/reference.rs recursion/src/programs/constraints.rs recursion/src/programs/rv32.rs recursion/tests/self_verify.rs
git commit -q -m "recursion: the self-verifier reads the per-instance quotient round — VerifierShape::quotient_layout, the replay and program follow it; self_verify pins re-recorded; the aggregate programs' digests unchanged

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: The full suite, green

**Files:** none (a gate).

- [ ] **Step 1: Run the whole recursion suite with the same skips the phase-2 record used**

Run:
```bash
RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures cargo test --release --no-fail-fast -- --skip a_one_proof_aggregate_round_trips 2>&1 | tee /tmp/suite-quotient.log | grep -E "^test result|FAILED|panicked"
grep -E "^test result" /tmp/suite-quotient.log | awk '{p+=$4; f+=$6; i+=$8} END {print "passed",p,"failed",f,"ignored",i}'
```
Expected: `failed 0`; passed ≥ 213 (208 before plus the six new tests, minus nothing). Record the three totals for `docs/05`.

- [ ] **Step 2: The fork's own unit tests, once more from its directory**

Run: `cd ~/rand-worktrees/circuits-quotient/vendor/p3-batch-stark && cargo test --release 2>&1 | grep -E "test result"`
Expected: `2 passed`.

- [ ] **Step 3: Record the counts (no commit; Task 6 writes them into docs/05)**

---

### Task 5: Measure — tier 16 after, the tier-18 twin's phase trace

**Files:**
- Create: `recursion/docs/measurements/2026-10-05-tier16-after.log`, `recursion/docs/measurements/2026-10-05-tier18-twin-memprofile.log`

**Interfaces:**
- Produces: the measured rows of the spec §4 table for Task 6.

- [ ] **Step 1: Tier 16, 16 threads, after**

Run (from `recursion/`):
```bash
RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures RAYON_NUM_THREADS=16 \
  cargo test --release --features parallel --test memprofile tier16_synthetic_threads -- --ignored --nocapture \
  2>&1 | tee docs/measurements/2026-10-05-tier16-after.log | tail -5
```
Expected: `rows 63762`, `tier 16`; peak live below Task 0's 9.09 GB by the quotient share of that shape (the model predicts the quotient LDE term falls to ~40 % of itself; record whatever the harness prints). Compare the prove wall with Task 0's: a rise above ~5 % is the discarded salt NTTs and goes in docs/05 §"Out of scope" as the trigger for the p3-fri follow-up.

- [ ] **Step 2: The exit twin (tier 18 since phase 2) under the heap profiler, 16 threads**

Run (from `recursion/`; ~10–30 min; watch `Activity Monitor` memory pressure — if the box starts swapping heavily above ~44 GB live, the run will be killed by the kernel as the tier-19 one was, and the phase rows printed up to the kill are still the record):
```bash
RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures RAYON_NUM_THREADS=16 \
  cargo test --release --features parallel --test memprofile tier19_exit_twin -- --ignored --nocapture \
  2>&1 | tee docs/measurements/2026-10-05-tier18-twin-memprofile.log | grep -E "compute quotient|commit_ldes|prove done|verify|live|killed" | tail -30
```
Expected: the span log's "compute quotient" rows sum to roughly 0.4 × the per-instance figures docs/04 recorded at tier 19 scaled to tier 18 (the spec §4 model); `live after` the quotient phase well under the 61 GB of the tier-19 trace. If `prove done` prints, the real tier-18 twin proved on 48 GB: record `peak`, `rss` and the prove wall — that is the phase's exit run. If the kernel kills it, record the last `live` figure and the phase it died in.

- [ ] **Step 3: Commit the logs**

```bash
cd ~/rand-worktrees/circuits-quotient
git add recursion/docs/measurements/2026-10-05-tier16-after.log recursion/docs/measurements/2026-10-05-tier18-twin-memprofile.log
git commit -q -m "recursion docs: memprofile after the quotient-layout cut — tier 16 and the tier-18 exit twin

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 6: Documentation

**Files:**
- Create: `recursion/docs/05-quotient-layout.md`
- Modify: `recursion/docs/01-rvm-machine.md:134-140`, `recursion/docs/04-phase2-row-cuts.md:364-368` and `:378-382`, `research/AGENTS.md` (the recursion/rVM state paragraph — `grep -n "phase 2\|rVM" research/AGENTS.md | head`), `recursion/tests/memprofile.rs:276-277` (the twin's doc comment and ignore string, if it proved)

- [ ] **Step 1: Write `recursion/docs/05-quotient-layout.md`** with these sections, numbers from Tasks 0, 4 and 5 (no projections where a measurement exists; every projection labelled):

```markdown
# 05 — Quotient layout: one committed matrix per instance, the prover's largest memory term cut

<one paragraph: what and why — docs/04's 32 % quotient term, the 200 % salt overhead per chunk;
the fork; rVM proofs only>

## What changed
<the fork (`vendor/p3-batch-stark`, `QuotientLayout`, the three `_with_layout` entry points,
PerChunk = upstream); `machine::QUOTIENT_LAYOUT`; `VerifierShape::quotient_layout`; the
replay/tape/program; what did not change (chunk polynomials, ZK randomisers, recomposition,
transcript, BatchProof, the RV32 machine, the aggregate programs' digests)>

## Why it is sound
<spec §1.1's four bullets, each with the file:line it was read at>

## Measured
| | before | after |
|---|---|---|
| tier-16 synthetic, peak live heap (16 threads) | <Task 0> | <Task 5> |
| tier-16 synthetic, prove wall | <Task 0> | <Task 5> |
| tier-18 exit twin, live after "compute quotient" | 61.0 GB at tier 19 (2026-10-03) | <Task 5> |
| tier-18 exit twin, peak live / outcome | killed at 78.7 GB (tier 19) | <proved at X GB in Y s / killed at X GB in phase Z> |

<the per-instance quotient terms from the tier-18 trace's "compute quotient" rows against the
spec §4 projection; the salt-NTT cost (prove wall delta) and whether the p3-fri follow-up is
triggered>

## What it means for the hardware plan
<re-projection of production N=1 (tier 20) from the measured ratio, labelled a projection:
≈ 240 → ≈ <measured ratio × 240> GB; the tier-18 twin's real figure if it proved; the next
levers in order: the register table's height, log_blowup 3 → 2, device-resident LDEs>

## What moved
| pin | before | after | where |
<self_verify digest, CycleReport tuples, phase 5; `rand_openings[2].len()` = instances; the
aggregate pins unchanged — listed as such>

## Testing
<tests/quotient_layout.rs's six tests, the fork's two unit tests, the suite count from Task 4
(`cargo test --release --no-fail-fast -- --skip a_one_proof_aggregate_round_trips`: N passed,
0 failed, M ignored, 1 skipped)>

## Out of scope, recorded
<spec §7 verbatim, with the measured salt-NTT delta deciding the p3-fri item>
```

- [ ] **Step 2: Pointers and the correction in the older docs**

`recursion/docs/01-rvm-machine.md`, in the paragraph beginning "**The ≥ 64 GB requirement below is withdrawn (2026-10-03).**", after "the quotient-chunk LDEs, each chunk salted with four columns of its own;" insert " (one matrix per instance, salted once, since the quotient-layout fork — `docs/05-quotient-layout.md`)".

`recursion/docs/04-phase2-row-cuts.md`, the paragraph "Committing one instance's chunks as **one matrix** would cut the quotient term…": replace the sentence "For the recursive verifier it would also replace 16 Merkle paths per query with one for that round." with "(Correction, 2026-10-05: a round opens with one Merkle path per query already — the MMCS batches every matrix of a round into one tree — so the recursive verifier's saving is the salts and hidden values it no longer absorbs, not Merkle paths.)" and append to the paragraph: " **Done:** `docs/05-quotient-layout.md` (the fork, measured 2026-10-05)." In §"What follows for the hardware plan" candidate 1, append " — done, `docs/05`."

`research/AGENTS.md`: in the paragraph that records the phase-2 state of the rVM, add one sentence: "The quotient-layout fork (2026-10-05, `recursion/docs/05-quotient-layout.md`, `vendor/p3-batch-stark`): rVM proofs commit one quotient matrix per instance; `machine::QUOTIENT_LAYOUT`; the RV32 machine and the aggregate program digest `c90b3f0a…` unchanged; measured <peak before → after> at tier 16."

If the tier-18 twin proved in Task 5, update `recursion/tests/memprofile.rs`'s `tier19_exit_twin` doc comment and ignore string to say so ("proved on this 48 GB box at X GB live, 2026-10-05, since the quotient-layout fork").

- [ ] **Step 3: Commit**

```bash
cd ~/rand-worktrees/circuits-quotient
git add recursion/docs research/AGENTS.md recursion/tests/memprofile.rs
git commit -q -m "recursion docs: docs/05 — the quotient layout, measured; docs/01 and docs/04 pointers and the one-path-per-round correction

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 7: Fullnode follow-through (after the circuits branch is merged to `main` and pushed to the `randprotocol` remote)

**Precondition (the operator's step, not this task's):** `feat/rvm-quotient-layout` merged into circuits `main` and pushed to both remotes (`git push org main && git push origin main`), so the new `CIRCUITS_PIN` is fetchable. Record the merged commit as `<PIN>`.

**Files (in a fullnode worktree off `main`, e.g. `git -C ~/Github/randprotocol/fullnode worktree add ~/rand-worktrees/fullnode-quotient -b feat/rvm-quotient-layout-vendor main`):**
- Create: `vendor/p3-batch-stark/**` (copied from circuits `vendor/p3-batch-stark`)
- Modify: `Cargo.toml:92-99` (`[patch.crates-io]` and its comment), `deploy/sync-zkvm.sh` (the recursion-section header), `.github/workflows/ci.yml:66` (`CIRCUITS_PIN`), `crates/randprotocol-rvm/**` (by the sync), `crates/randprotocol-zkvm/Cargo.toml` and `crates/randprotocol-rvm/Cargo.toml` (`rand-zkvm-cuda` rev, by the sync), `crates/randprotocol-zkvm/guests-compiled/PROVENANCE.md`, `vendor/circuits/PROVENANCE.md`, `vendor/circuits/SHA256SUMS` (by the sync), `docs/node-hardware.md` §4, `docs/compute-optimization.md` §4.1, `AGENTS.md` (the top "rVM phase 2 re-vendored" paragraph gains the fork)

- [ ] **Step 1: Vendor the fork and patch the workspace**

```bash
cd ~/rand-worktrees/fullnode-quotient
cp -R ~/Github/randprotocol/circuits/vendor/p3-batch-stark vendor/p3-batch-stark
```
In `Cargo.toml`, the `[patch.crates-io]` table becomes
```toml
[patch.crates-io]
p3-fri = { path = "vendor/p3-fri" }
p3-merkle-tree = { path = "vendor/p3-merkle-tree" }
# The quotient-layout fork (circuits `vendor/PROVENANCE.md`, `recursion/docs/05-quotient-layout.md`):
# `QuotientLayout::PerChunk` is crates.io's behaviour byte for byte and is what `randprotocol-zkvm`
# (the RV32 machine, every wallet proof) gets; `randprotocol-rvm` pins `PerInstance`.
p3-batch-stark = { path = "vendor/p3-batch-stark" }
```
and the comment above the table gains the sentence "`vendor/p3-batch-stark` is a third: p3-batch-stark 0.7.0 with a quotient-layout switch (`QuotientLayout`), the circuits fork copied verbatim."

- [ ] **Step 2: Re-vendor the rVM and move the pin**

```bash
RVM_SRC=~/Github/randprotocol/circuits/recursion deploy/sync-zkvm.sh ~/Github/randprotocol/circuits/research 2>&1 | tail -3
sed -i '' "s/^  CIRCUITS_PIN: .*/  CIRCUITS_PIN: <PIN>/" .github/workflows/ci.yml
grep -n "^license\|^\[patch" crates/randprotocol-rvm/Cargo.toml
```
Expected: `synced recursion VM … (pin 75b7893)` (update that echo and the recursion-section header comment in `deploy/sync-zkvm.sh` to name `<PIN>` and the fork: "then at `<PIN>` (the quotient-layout fork: `machine::QUOTIENT_LAYOUT = PerInstance`, `VerifierShape::quotient_layout`, `tests/quotient_layout.rs`; the aggregate program digest and the admission vectors unchanged; upstream's `[patch.crates-io]` now names three crates and is cut with the profiles as before — the workspace root carries the same three)"); `license.workspace = true` once; no `[patch` line in the vendored manifest.

- [ ] **Step 3: Build and run the gates**

```bash
cargo build --release --workspace 2>&1 | tail -1
RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures cargo test --release -p randprotocol-rvm --no-fail-fast -- --skip round_trips --skip two_test_profile 2>&1 | grep -E "^test result" | awk '{p+=$4; f+=$6} END {print "passed",p,"failed",f}'
cargo test --release -p randprotocol-zkvm --test guest_provenance 2>&1 | grep "^test result"
RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures cargo test --release -p randprotocol-node agg_executor 2>&1 | grep "^test result" | head -1
```
Expected: `Finished`; rvm `failed 0` (passed ≥ 213); guest_provenance 14 passed; agg_executor 12 passed, 1 ignored (the aggregate program digest and the admission vectors did not move, so nothing there changes).

- [ ] **Step 4: Docs**

`docs/node-hardware.md` §4, after the phase-2 paragraph: one paragraph "**Quotient layout (circuits `<PIN>`, 2026-10-05; `recursion/docs/05-quotient-layout.md`).** The rVM commits each instance's quotient chunks as one matrix; measured on the 48 GB laptop: <tier-16 before → after>, <tier-18 twin outcome>. The production N=1 projection moves ≈ 240 → ≈ <X> GB (a projection until proved)." and the projected table's production N=1 row gains the new figure in a third column or a footnote.

`docs/compute-optimization.md` §4.1, after the "Measured, not assumed, on memory" paragraph: "**Landed 2026-10-05 (quotient layout, circuits `<PIN>`):** one committed quotient matrix per instance; <before → after at tier 16>; production N=1 projected ≈ <X> GB." and in "Still ahead" strike the first bullet's "commit one instance's chunks as one matrix" (done), keeping the degree-2 memory AIR lever.

`AGENTS.md`: the "rVM phase 2 re-vendored" paragraph gains "Re-vendored again at `<PIN>` (the quotient-layout fork, `vendor/p3-batch-stark` here too): rVM proofs one quotient matrix per instance, the aggregate program digest unchanged."

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -q -m "zkvm, rvm, vendor: re-vendor circuits <PIN> — the quotient-layout fork (p3-batch-stark vendored, PerChunk for the RV32 machine, PerInstance for the rVM); docs carry the measured memory

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```
Then report the branch for the operator's merge and push; CI's `clean-clone` and `guest-provenance` need `<PIN>` on the `randprotocol` remote (AGENTS.md trap 4).

---

## Self-review notes (done while writing)

- Spec §1 (change) → Task 2; §1.1 (soundness) → Task 2's round trip and refusal tests, docs/05 in Task 6; §1.2 (switch) → Task 1; §1.3 (mismatch) → Task 2's `a_proof_made_under_upstreams_layout_is_refused_not_panicked`; §2 (fork + provenance) → Task 1 (the fork's tests moved to `recursion/tests/quotient_layout.rs` because the registry copy's dev-dependencies are ten sibling path crates — recorded in the manifest comment and PROVENANCE); §3.1 → Task 2 Step 7; §3.2–3.4 → Task 3; §4 → Tasks 0, 5, 6; §5 → Tasks 2, 3, 4, 5; §6 → Tasks 6, 7; §7 → docs/05 in Task 6.
- Names used across tasks: `QuotientLayout::{PerChunk, PerInstance}`, `prove_batch_with_layout`, `verify_batch_with_layout`, `commitments_with_opening_points_with_layout`, `concat_chunk_rows`, `QUOTIENT_LAYOUT`, `prove_traces_with_layout`, `VerifierShape::quotient_layout`, `RawInstance::quotient_run` — each defined once (Tasks 1–3) and used by name afterwards.
- Review Focus items 1–5 each have a named test in Task 2 (items 1, 2, 3, 5) or a named suite run (item 4).
