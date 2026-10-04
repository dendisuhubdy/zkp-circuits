# rVM quotient layout — one committed matrix per instance, the prover's largest memory term cut

**Date:** 2026-10-04. **Scope:** `recursion/` (the rVM) and a vendored fork of `p3-batch-stark`.
**Decided with the operator:** memory is the lever of this phase (not rows, not the FRI profile);
rVM proofs only, through a layout switch the RV32 machine can flip at a later constraint-set cut;
the concatenation lives in the batch-stark fork alone, with no change to the PCS trait or to the
existing `p3-fri` / `p3-merkle-tree` patches. The fullnode follow-through is in scope.

## 0. Why

`docs/04-phase2-row-cuts.md` §"The prover's live heap" measured the tier-19 rVM proof at 78.7 GB
live when the kernel killed it, and decomposed the 94 GB Linux peak: the quotient-chunk LDEs are
29.7 GB of it, **32 %**, the largest single term. The cause is layout, not mathematics:
`HidingFriPcs::get_quotient_ldes` returns one matrix per quotient chunk, each chunk being two
columns of extension-field quotient (`Challenge::DIMENSION = 2`), and the hiding PCS appends its
four random-codeword columns to **every matrix**. A chunk is therefore committed as 6 columns for 2
of data — 200 % overhead — and the hiding MMCS salts every matrix's rows once more. At tier 19
the figures close exactly on that model (cpu 16 chunks × 2^23 × 6 × 8 B = 6.4 GB, measured 6.46;
reg 8 × 2^25 × 6 × 8 B = 12.9 GB, measured 13.7).

Committing one matrix per instance — all of an instance's chunks side by side, salted once — is
what this phase does. Projected from the measured terms (§4), it takes the quotient term at tier
19 from 29.7 GB to about 12.5 GB and the production N=1 aggregate from the ≈ 240 GB projected in
`docs/04` to **≈ 190 GB**. Rows barely move (the self-verifier saves some sponge absorbs and
hints); the tier does not. This is the hardware track's cut.

## 1. What is being changed, precisely

Plonky3 0.7.0's batch-STARK prover (`p3-batch-stark/src/prover.rs:342-460`), per instance `i`:

1. computes the quotient on the quotient domain and splits it into `n_i` chunks
   (`quotient_domain.split_evals`, `split_domains`);
2. `pcs.get_quotient_ldes(evals, n_i)` → `n_i` LDE matrices, each `height_i × (2 + 4)`, each with
   its own four random-codeword columns (hiding) and its ZK randomiser `v_{H_i}(X)·t_i(X)` folded
   into the data columns (the randomisers sum to zero over the chunks, the last one absorbing the
   rest);
3. concatenates every instance's chunk matrices into one `Vec` in instance-major order and commits
   them in **one** MMCS batch (`pcs.commit_ldes`) — one Merkle tree, one commitment, one path per
   query, every matrix a leaf row at its height.

The verifier (`verifier/mod.rs:223-239`) rebuilds the same round: one `(domain, [(zeta,
chunk_values)])` entry per committed chunk, instance-major, and hands it to the PCS with the
quotient commitment.

**The change.** Under the new layout the prover, after step 2, builds for each instance one matrix
of width `2·n_i + 4`: the two data columns of every chunk in chunk order, then the **first chunk's
four random-codeword columns** as the matrix's salts; the other chunks' random columns are dropped
(they were LDE'd for nothing — compute only, see §7). Step 3 commits one matrix per instance. The
open rounds list one `(matrix, [zeta])` per instance. The verifier's quotient round has one entry
per instance whose claimed values are the instance's per-chunk opened values concatenated in the
same order. Nothing else moves: the chunk polynomials, their ZK randomisation, the constraint
recomposition from chunks (`recompose_quotient_from_chunks` over the per-chunk `zps`), the
transcript (one quotient commitment observed; the chunk count per instance observed as before),
and the `BatchProof` struct with its per-chunk `OpenedValues::quotient_chunks` are upstream's.

### 1.1 Why it is sound (the properties the code was read for)

- **The PCS evaluates a committed matrix by its height alone.** `TwoAdicFriPcs::verify`
  (`two_adic_pcs.rs`, the `verify` body) derives each matrix's `log_height` from the matrix and
  computes the query point `x` on the natural LDE coset `GENERATOR·H`; the chunk domains' shifts
  are consumed at commit time (`coset_lde_batch(evals, log_blowup + 1, GENERATOR / shift)` maps
  every chunk to that one coset) and never again. All of an instance's chunk LDEs share a height,
  so they can be rows of one matrix. The verifier's per-chunk domains are
  `natural_domain_for_degree(size << is_zk)` — identical objects for one instance already.
- **Hiding is per committed matrix, and every committed matrix keeps its four random codewords.**
  The hiding PCS's argument (eprint 2024/1037 §4.2) needs each committed matrix to carry random
  columns so a leaf row is unpredictable; the wide matrix carries four, as every matrix does
  today. The hiding MMCS salts each matrix's rows independently of this; one matrix, one salt row
  set. The chunk randomisers `t_i` are untouched, so the quotient chunks' openings reveal nothing
  more than before.
- **The verifier's hidden-half merge nests by round → matrix → point** (`hiding_pcs.rs:382-458`):
  one wide matrix means one set of four random openings per point, which is exactly what the
  prover's `open_with_preprocessing` splits off (`opened_values_for_point.len() − 4`). The
  `HidingRandomOpening*CountMismatch` errors are the layout-mismatch refusals (§1.3).
- **The MMCS batch opening** (`hiding_mmcs.rs:171-203`, `check_widths`) checks each opened row's
  width against the committed dimensions: a per-chunk proof fed to a per-instance verifier fails
  the width check or the matrix-count check before any hashing.

### 1.2 The switch

```rust
pub enum QuotientLayout { PerChunk, PerInstance }
pub fn prove_batch_with_layout(config, instances, prover_data, layout) -> BatchProof
pub fn verify_batch_with_layout(config, airs, proof, public_values, common, layout) -> Result<..>
// unchanged signatures, unchanged behaviour:
pub fn prove_batch(..)  = prove_batch_with_layout(.., PerChunk)
pub fn verify_batch(..) = verify_batch_with_layout(.., PerChunk)
```

`PerChunk` is byte-identical to upstream: `research/` (the RV32 machine, every wallet proof) does
not change, and a `--locked` build of the fullnode with the fork patched in proves and verifies
exactly what it proved before. `PerInstance` is selected by the rVM's `Machine` alone.

### 1.3 Behaviour on a layout mismatch

A proof made under one layout and verified under the other is refused, never a panic: the
verifier's quotient round lists a different matrix count from the proof's opening (hiding
verify's level-2 check) or a different width (MMCS `check_widths`). `Machine::verify` maps either
to `VerifyError::Batch` as it maps every PCS error today. The layout is **not** carried in the
proof: it is a property of the machine, pinned like the FRI profile and the degree pins, and
`tests/machine.rs` pins it.

## 2. The vendored fork: `vendor/p3-batch-stark`

- crates.io `p3-batch-stark` 0.7.0, copied whole less `Cargo.lock`/`target`, under
  `vendor/p3-batch-stark/`, listed in `vendor/PROVENANCE.md` beside the two existing patched
  crates (what changed, why, the upstream state — there is no upstream issue for this; the
  provenance names this spec).
- Changed files: `src/prover.rs` (the quotient commit and open rounds under `PerInstance`),
  `src/verifier/mod.rs` (the quotient round construction), `src/lib.rs` (the enum and the two
  `_with_layout` entry points; the old names delegate). Every change is marked
  `// RandProtocol patch (2026-10-04): quotient layout` the way the p3-fri patch is marked.
- `recursion/Cargo.toml`'s `[patch.crates-io]` gains `p3-batch-stark = { path =
  "../vendor/p3-batch-stark" }`. `research/` is not patched (its build stays crates.io's).
- The fork carries its own tests: a two-instance round trip at a small degree under each layout
  (the wide matrix's values recompose to the same quotient), and the cross-layout refusal both
  ways with the named error.

## 3. The rVM

### 3.1 `Machine`

`prove_traces`, `prove_on` and `verify` (`recursion/src/machine.rs:475-618`) call the
`_with_layout` variants with `QuotientLayout::PerInstance`. One constant,
`machine::QUOTIENT_LAYOUT`, is the single point of truth; the doc comment says why it is not in
`Proof`. `log_ext_degrees`, `verifier_key`, `check_declared_heights` and the degree pins are
untouched: the chunk *counts* do not change, only how they are committed.

### 3.2 The self-verifier program (`rv32r`) and `VerifierShape`

The rVM's programs read proofs through `VerifierShape` (`shape.rs:664-722`). It gains
`fn quotient_layout(&self) -> QuotientLayout`. The RV32 inner shape (`InnerShape`) answers
`PerChunk`; the rVM's own shape (what `rv32r` verifies) answers `PerInstance`. In
`programs/rv32.rs`'s query-openings builder (the `quotient_chunks` round, `rv32.rs:489-499`):

- `PerChunk`: as today — one `MatrixOpening` per committed chunk, each `point(.., chunk_values,
  NUM_RANDOM_CODEWORDS)`.
- `PerInstance`: one `MatrixOpening` per instance, `log_height = h_of(i)`, one point at `zeta`
  whose values are the instance's chunk openings in order (`committed_chunks(shape, i) ·
  DIMENSION` extension values — `constraints.rs:184` already hints them as one contiguous
  `chunk_run`) followed by `NUM_RANDOM_CODEWORDS` random hints.

The aggregate program verifies RV32 proofs, so it takes the `PerChunk` branch and **its emitted
program is byte-identical**: `tests/aggregate.rs`'s pinned production digest
`c90b3f0a7758c7e306042f27a94cc1f123441b0284c7352cb3f426048c7a74d8` and `verify_rv32.digest`
must not move, and the suite checks that they do not.

### 3.3 The witness tape

`WitnessTape::build` (`witness.rs`) writes, per query, `Segment::InputOpenings` (per round, per
height group, the opened rows), `Segment::RandomOpenings`, the MMCS salts and
`Segment::InputPaths` from the proof's opening structure. For an rVM proof the quotient round now
has one row per instance in the height group it belongs to, with one random-hint set and one
salt set. The tape follows the proof (it is the aggregator's private witness; its only contract
is that program and tape agree), and `tests/self_verify.rs`'s real-proof round trips are what
check that they do.

### 3.4 `rv32`, `rv32n` (the aggregate programs)

No change in emitted code. The shared builder gains a branch the RV32 shape never takes.

## 4. Projection, to be replaced by measurement

Per instance the committed quotient cells go from `6·n_i` to `2·n_i + 4` columns at the same
height. Committed chunk counts on this machine (degree pins `[2, 8, 4, 4, 4, 2, 2]` + reduce 8,
chunks `= 2^⌈log₂(degree−1)⌉ · 2` for ZK): program 2, cpu 16, reg 8, ram 8, poseidon2 8,
public 2, range 2, reduce 16.

| instance | chunks | columns before → after | tier-19 twin measured (GB) → projected |
|---|---:|---:|---:|
| cpu | 16 | 96 → 36 | 6.46 → 2.4 |
| reg | 8 | 48 → 20 | 13.7 → 5.7 |
| ram | 8 | 48 → 20 | 6.8 → 2.8 |
| program | 2 | 12 → 8 | 1.8 → 1.2 |
| reduce | 16 | 96 → 36 | 0.8 → 0.3 |
| poseidon2, public, range | 8, 2, 2 | — | 0.1 → 0.05 |
| **quotient LDEs, total** | | | **29.7 → ≈ 12.5** |

Plus the hiding MMCS salt rows, one set per matrix instead of one per chunk (not separately
measured; the memprofile run will show it in the "quotient `commit_ldes`" phase). Live after
"compute quotient" at tier 19: 61.0 GB → ≈ 44 GB. The quotient Merkle tree shrinks with its
leaves' width only slightly (leaf hashes are fixed-size); the FRI opening phase shrinks by the
dropped columns' quotient accumulations.

Scaling `docs/04`'s cell-weighted projection: production N=1 (tier 20) **≈ 240 → ≈ 190 GB**;
the tier-18 exit twin **≈ 50 → ≈ 40 GB**, which may fit this 48 GB box — if it does, the real
proof is this phase's exit run, not a projection. Every number here is replaced by the
measurement in §6 before the phase closes.

## 5. Testing (the repository's discipline, applied)

1. **Fork tests** (§2): round trips under both layouts; cross-layout refusal both ways by name.
2. **`tests/machine.rs`**: the toy program proves and verifies under `PerInstance`; a proof's
   quotient-round opening count is one per instance (pinned); the machine's layout constant is
   pinned.
3. **`tests/cheating.rs`**, two new forgeries, each refused by `Machine::verify` (not a panic): a
   flipped quotient-chunk opened value inside the wide row (the recomposition identity fails or
   the MMCS row fails); a flipped random-codeword hint (the MMCS row fails). Plus the
   layout-mismatch case: a `PerChunk` proof of the same traces, verified by the machine → refused
   by name.
4. **`tests/self_verify.rs`**: the rVM proof of the toy and busy fixtures round-trips through
   `rv32r`; its digest, `CycleReport` and phase-5 pins move and are re-recorded with before/after
   in `docs/05`. The aggregate pins (`tests/aggregate.rs`, `tests/verifier.rs`,
   `verify_rv32.digest`, `pins.json`'s production row) **do not move** — asserted, not assumed.
5. **`tests/memprofile.rs`**: the tier-16 synthetic (`tier16_synthetic_threads`, 63 762 rows,
   9.09 GB peak live today, 36.4 s on 16 threads) before and after, same box, same thread count;
   the tier-19 twin's phase trace (`2026-10-03-tier19-memprofile.log`'s shape) once, for the
   "compute quotient" and "quotient `commit_ldes`" rows. If the tier-18 production-shaped twin
   fits 48 GB after the cut, it is proved to completion and its peak recorded.
6. **The full suite** (`cargo test --release --no-fail-fast -- --skip a_one_proof_aggregate_round_trips`)
   green, count recorded in `docs/05`.

Every measurement run's stdout is kept under `recursion/docs/measurements/` with the date in the
name, as the phase-2 logs are.

## 6. Documentation and the fullnode

- **`recursion/docs/05-quotient-layout.md`**: what changed, the soundness argument of §1.1, the
  measured before/after terms (§4's table with the measured column filled), the re-projection
  for production N=1 and the tier-18 twin, the pins that moved, the suite count.
- **`docs/01`** (the memory section) and **`docs/04`** (§"What follows for the hardware plan",
  candidate 1) get one-line pointers to `docs/05`. `docs/04`'s sentence "it would also replace 16
  Merkle paths per query with one for that round" is corrected: a round opens with one path per
  query already (the MMCS batches every matrix into one tree); the saving for the verifier is the
  salts and random hints it no longer absorbs.
- **`vendor/PROVENANCE.md`**: the third crate.
- **Fullnode** (a separate commit on a fullnode branch, after the circuits branch merges):
  `vendor/p3-batch-stark` copied verbatim with the workspace `[patch.crates-io]` entry;
  `deploy/sync-zkvm.sh` re-vendors recursion (the fork patch line is dropped with the profiles,
  as the p3-fri one is); `vendor/PROVENANCE.md`, `docs/node-hardware.md` §4 and
  `docs/compute-optimization.md` §4.1 carry the measured terms and the new projection. The
  aggregate program digest does not move, so `admitted_shapes` and the admission vectors are
  untouched; `admitted_tiers` are untouched.

## 7. Out of scope (recorded so they are not re-litigated)

- **Flipping the RV32 machine to `PerInstance`.** It changes every wallet proof's transcript — a
  constraint-set cut (cs9), a wallet release, the aggregate program digest and every admission
  vector. The switch is there for it; this phase does not pull it.
- **A per-instance quotient method in the p3-fri patch** (salting once, no wasted salt NTTs). Only
  if the tier-16 measurement shows the discarded salt columns' LDEs above ~5 % of proving time.
  The transient they cause is bounded by one instance's chunk set and is freed before the next
  instance; the retained term is what this phase cuts.
- The REDUCE descriptor table, the fold-chain sibling select, the FADDI per `COMPRESS`, the inner
  FRI profile, `log_blowup 3 → 2` for the rVM: `docs/04` §"Still ahead".

## 8. Risks and how each is closed

| risk | closed by |
|---|---|
| the PCS verifier uses a chunk domain's shift somewhere this reading missed | the fork's round trip under `PerInstance` with the stock `p3-fri` verifier; a wrong `x` fails every query |
| the hiding argument needs a random column *per chunk polynomial*, not per committed matrix | the hiding is a property of the committed leaf rows (2024/1037 §4.2); each committed matrix keeps its four codewords and its MMCS salt — recorded in `docs/05` for the next audit to challenge |
| the aggregate program's emitted code drifts through the shared builder | the pinned production digest and `verify_rv32.digest`, asserted in the suite |
| the tape and the program disagree on the new round layout | `tests/self_verify.rs` over real rVM proofs; a disagreement is a refused proof, never a wrong pass |
| the fork drifts from crates.io 0.7.0 beyond the marked patch | `vendor/PROVENANCE.md` names the files; `diff -r` against the registry copy is a review step |

## 9. Rulings

- Memory first; rows and the tier are not this phase's targets.
- rVM proofs only; the RV32 flip waits for a cut.
- One fork, no PCS trait change; measure before touching p3-fri again.
- Projections are labelled projections until the run exists; the phase's closing numbers are
  measured on this box, and the fullnode docs quote only those.
