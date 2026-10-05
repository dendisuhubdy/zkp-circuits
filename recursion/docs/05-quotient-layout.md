# 05 — Quotient layout: one committed matrix per instance, the prover's largest memory term cut

Design: `docs/superpowers/specs/2026-10-04-rvm-quotient-layout-design.md`. Plan:
`docs/superpowers/plans/2026-10-05-rvm-quotient-layout.md`. Branch `feat/rvm-quotient-layout`,
base `2899bdc`. Every figure in the measured sections is a 2026-10-05 run of
`tests/memprofile.rs` on this 48 GB box (16 cores, `RAYON_NUM_THREADS=16`, `--features parallel`),
kept under `docs/measurements/2026-10-05-*.log`, or the 2026-10-03 tier-19 record
(`docs/measurements/2026-10-03-tier19-memprofile.log`, docs/04) that the before column cites, or a
pin in a test file; every projection is labelled as one.

`docs/04-phase2-row-cuts.md` §"The prover's live heap" found the quotient-chunk LDEs to be the
largest single term of the rVM prover's heap: 29.7 GB of the tier-19 proof's 94 GB Linux peak,
**32 %**. The cause was layout, not mathematics. Plonky3 0.7.0's batch prover commits every
quotient chunk as its own matrix, two columns of extension-field data, and the hiding PCS appends
four random-codeword columns to every matrix: 6 columns committed for 2 of data, 200 % overhead,
and one set of MMCS salt rows per chunk on top. This phase commits one matrix per instance, all of
its chunks side by side and salted once, through a vendored fork of `p3-batch-stark` with a layout
switch. Only the rVM's own proofs take the new layout; the RV32 machine, every wallet proof and the
aggregate programs that verify them are byte-for-byte what they were.

**Result:** at tier 16 (same program, same box, same threads) the peak live heap fell **9.09 →
6.41 GB (−29 %)**, the prove wall 40.7 → 32.9 s and the proof 273 804 → 221 714 B. The tier-18
exit twin, never run on this box before (the tier-19 one was killed at 78.7 GB live), **proved to
completion at 33.27 GB peak live** in 185.4 s.

## What changed

**The fork, `vendor/p3-batch-stark`** (crates.io 0.7.0, every change marked `RandProtocol patch
(2026-10-04): quotient layout`; `vendor/PROVENANCE.md`):

- `src/layout.rs` (new): `pub enum QuotientLayout { PerChunk, PerInstance }`. `PerChunk` is
  upstream's layout and every existing caller's default.
- Three `_with_layout` entry points: `prove_batch_with_layout`, `verify_batch_with_layout`, and
  `verifier::commitments_with_opening_points_with_layout` (the round list the recursive replay
  reads). `prove_batch`, `verify_batch` and `commitments_with_opening_points` keep their
  signatures and delegate with `PerChunk`, so they are upstream's behaviour unchanged.
- `src/prover.rs`: under `PerInstance`, after `get_quotient_ldes` returns an instance's chunk
  LDEs, `concat_chunk_rows` lays the chunks' `DIMENSION` data columns side by side in chunk order
  and keeps the **first chunk's four random-codeword columns once**; the other chunks' random
  columns are dropped. One matrix of width `2·n_i + 4` per instance goes to `commit_ldes`, and the
  opened wide row is split back into per-chunk slices, so `BatchProof` and its per-chunk
  `OpenedValues::quotient_chunks` keep upstream's shape.
- `src/verifier/mod.rs`: the quotient round lists one `(domain, [(zeta, values)])` per instance,
  `values` being the instance's per-chunk opened values concatenated in the same order, after a
  chunk-count check (`QuotientDomainsCountMismatch`).

**The rVM:**

- `machine::QUOTIENT_LAYOUT = QuotientLayout::PerInstance` (`src/machine.rs:44`) is the single
  point of truth; `prove_traces`, `prove_on` and `verify` pass it. It is a property of the
  machine, pinned like the FRI profile, and is not carried in `Proof`.
- `VerifierShape::quotient_layout()` (`src/shape.rs:670`): `InnerShape` (the RV32 proofs the
  aggregate verifies) answers `PerChunk`; `RvmShape` (what the self-verifier `rv32r` verifies)
  answers `QUOTIENT_LAYOUT`.
- The host replay (`src/reference.rs`) calls `commitments_with_opening_points_with_layout` with
  `shape.quotient_layout()`, after a new shape check: the opened instance count and each
  instance's chunk count and chunk length must be the shape's, or the proof is refused with
  `ReplayError::Shape`.
- The program (`src/programs/rv32.rs`, the quotient round of `observe_claimed`): under
  `PerInstance` one `MatrixOpening` per instance at its height, its one point at `zeta` carrying
  the instance's contiguous chunk run (`RawInstance::quotient_run`) followed by the four random
  hints. The witness tape follows the proof's opening structure, so it needed no change of its
  own.

**What did not change:** the chunk polynomials and their count per instance; their ZK randomisers
`v_H(X)·t_i(X)`; the recomposition of the quotient from the per-chunk values; the transcript (one
quotient commitment observed, the chunk counts as before); the `BatchProof` struct; the RV32
machine (constraint set 8) and every proof it makes; the aggregate programs' emitted code and
digests (`verify_rv32.digest`, `c90b3f0a…74d8`), and `inner_vk_digest`. `research/` is not patched.

## Why it is sound

The four properties the change rests on, each read at the source (spec §1.1; vendored copies at
`vendor/p3-fri` and `vendor/p3-merkle-tree` are crates.io 0.7.0 plus the 2026-10-01 RNG patch):

- **The PCS evaluates a committed matrix by its height alone.** `TwoAdicFriPcs::verify`
  (`p3-fri/src/two_adic_pcs.rs:675`, the `verify` body, into `verifier::open_inputs`) derives
  each matrix's `log_height` from its domain's size and computes the query point on the natural
  LDE coset, `x = GENERATOR · g^rev(index)` (`p3-fri/src/verifier.rs:797-801`; "the shift is
  assumed to always be Val::GENERATOR", `:731-732`). The chunk domains' shifts are consumed at
  commit time (`coset_lde_batch(evals, log_blowup + 1, GENERATOR / shift)`,
  `vendor/p3-fri/src/hiding_pcs.rs:236-245`), which maps every chunk to that one coset, and never
  again. All of an instance's chunk LDEs share a height, so they can be columns of one matrix. The
  verifier's per-chunk domains are `natural_domain_for_degree(size << is_zk)`
  (`vendor/p3-batch-stark/src/verifier/mod.rs:260`): identical objects for one instance already.
- **Hiding is per committed matrix, and every committed matrix keeps its four random codewords.**
  The hiding PCS's argument (eprint 2024/1037 §4.2) needs each committed matrix to carry random
  columns so that a leaf row is unpredictable; the wide matrix carries four, as every matrix did.
  Quantitatively: at an instance's quotient height the random-codeword columns drop from `4·nᵢ`
  (four per chunk matrix, `nᵢ` chunks — 64 for a 16-chunk instance) to `4` (one wide matrix).
  Four is upstream's per-matrix minimum, and the level its single-matrix rounds (main,
  permutation, random) already run at: every such matrix, of any width, carries exactly four.
  The hiding MMCS salts each matrix's rows independently of this: one salt of
  `SALT_ELEMS = 4` field elements per committed matrix row (`RowMajorMatrix::rand(.., mat.height(),
  SALT_ELEMS)`, `vendor/p3-merkle-tree/src/hiding_mmcs.rs:146`; the constant as
  `recursion/src/witness.rs:33` mirrors it), so the wide matrix's row carries one salt where the
  `nᵢ` chunk matrices' rows at that index carried `nᵢ`.
  The chunk randomisers `t_i` are untouched, so the quotient chunks' openings reveal nothing more
  than before. (Spec §8 records this as the property for the next audit to challenge.)
- **The verifier's hidden-half merge nests by round → matrix → point**
  (`vendor/p3-fri/src/hiding_pcs.rs:382-458`): one wide matrix means one set of four random
  openings per point, which is exactly what the prover's `open_with_preprocessing` splits off
  (`opened_values_for_point.len() − num_random_codewords`, `hiding_pcs.rs:370`). Its
  `HidingRandomOpening{Round,Matrix,Point}CountMismatch` errors (`:421`, `:433`, `:444`) are the
  layout-mismatch refusals.
- **The MMCS batch opening checks each opened row's width** against the committed dimensions
  before salting (`check_widths`, `vendor/p3-merkle-tree/src/hiding_mmcs.rs:189`, in
  `verify_batch` at `:177-210`; the spec's citation was `:171-203`): a per-chunk proof fed to a
  per-instance verifier fails the width check or the matrix-count check before any hashing.

A proof made under one layout and verified under the other is therefore refused by name, never
accepted and never a panic; `tests/quotient_layout.rs` checks it (below).

## Measured

| | before | after | source |
|---|---:|---:|---|
| tier-16 synthetic (63 762 rows), peak live heap | 9.09 GB | **6.41 GB** (−29 %) | `2026-10-05-tier16-{before,after}.log`, `==` line |
| tier-16 synthetic, prove | 40.7 s | **32.9 s** (×0.81) | the same |
| tier-16 synthetic, proof size | 273 804 B | **221 714 B** (−19 %) | the same |
| exit twin, live after the last `compute quotient` | 61.0 GB (tier 19, single-threaded, 2026-10-03) | **23.65 GB** (tier 18) | `2026-10-03-tier19-memprofile.log` / `2026-10-05-tier18-twin-memprofile.log:231` |
| exit twin, peak live / outcome | killed at 78.7 GB live (tier 19, 2026-10-03) | **proved: 33.27 GB peak, prove 185.4 s, verify 5.46 s, 268 417 B** (tier 18, 230 950 rows) | the same logs, `prove done` and `==` lines |

The before column of the twin is a different tier: the tier-18 twin was never run before this cut
(docs/04 §"What the cuts change" projected it at ≈ 50 GB from the tier-19 trace; the ≈ 47–50 GB
range is the one `tests/memprofile.rs` and `tests/exit.rs` carried). The only before/after pair at
one shape is tier 16.

Spec §4's projections for this cut, against the measurement: the twin's peak ≈ 40 GB at tier 18,
measured **33.27 GB**; live after `compute quotient` ≈ 44 GB at tier 19 (61.0 GB less the
projected quotient saving), measured **23.65 GB** at tier 18 (a different tier, so the comparison
is indicative, not like for like; the tier-16 phase table below is the same-shape check).

### Tier 16, phase by phase (the same program, before → after)

| phase | before | after | log lines (before / after) |
|---|---:|---:|---|
| `compute quotient`: Δ live, wall | +2.75 GB, 15.8 s | **+1.17 GB**, 13.5 s | 282 / 192 |
| live after `compute quotient` | 6.14 GB | 4.57 GB | 282 / 192 |
| live at the quotient tree's start (the gap: the leaf matrices and their salt rows, no span of their own) | 7.92 GB (+1.78) | 4.78 GB (+0.21) | 283 / 193 |
| quotient `build merkle tree`: wall | 7.0 s | **2.2 s** | 286 / 195 |
| live at `FRI prover` start | 8.95 GB | 5.80 GB | 637 / 367 |
| where the peak is reached | `FRI prover` (9.09 GB) | inside `compute quotient` (6.41 GB) | 640 / 192 |

The retained quotient term fell to 0.43 of itself (+2.75 → +1.17 GB), against the spec §4 model's
≈ 0.42 (29.7 → 12.5 GB at tier 19). The term between the quotient and its tree, which the spec
said it could not separate, is the one-salt-set-per-matrix saving: 1.78 → 0.21 GB.

**The prove wall fell, it did not rise.** Spec §7's follow-up (a per-instance method in the
`p3-fri` patch so the dropped chunks' random columns are never LDE'd) was to be triggered if the
discarded salt NTTs showed as a prove-wall rise above ~5 %. The wall fell 19 % (40.7 → 32.9 s):
fewer committed matrices to hash and open. The quotient tree hashes 7 salted matrices instead of
52 (7.0 → 2.2 s) — the same seven instances and chunk counts as the self-verifier fixtures (the
synthetic declares no reduce table, and chunk counts depend on the constraint degree, not the
height; no log line prints them) — and `compute quotient` itself got shorter (15.8 → 13.5 s):
7.1 s of the 7.8 s gain, with the discarded NTTs already inside the second figure, so **the
`p3-fri` follow-up is not triggered.** (The two runs are one each;
docs/04's 36.4 s for the same benchmark on 2026-10-04 shows ~10 % run-to-run spread, so read the
wall delta as "faster", not as a precise 19 %.)

### The exit twin at tier 18 (`tests/memprofile.rs::tier19_exit_twin`)

The shape is `tests/exit.rs`'s twin since phase 2: the verifier program over one real
test-profile bundle proof, 230 950 rows, tier 18. Raw log:
`docs/measurements/2026-10-05-tier18-twin-memprofile.log`.

| phase (Plonky3 span) | ends at | live after | Δ live | wall |
|---|---:|---:|---:|---:|
| main trace `build merkle tree` | 40.2 s | 10.78 GB | +1.07 GB | 14.4 s |
| permutation `build merkle tree` | 62.0 s | 16.95 GB | +1.07 GB | 9.3 s |
| `compute quotient` (all instances, outermost close) | 134.8 s | **23.65 GB** (peak 30.09) | +6.69 GB | 72.8 s |
| quotient `build merkle tree` (the quotient commit; no `commit_ldes` span appears) | 147.8 s | 25.84 GB | +1.07 GB | 12.4 s |
| the next commit round's LDE + `build merkle tree` | 162.7 s | 29.70 GB | +1.07 GB (tree) | 6.6 s (tree) |
| opening: inverse denominators, `evaluate matrix`, `reduce matrix quotient` | 165.6 s | 31.84 GB | | |
| `FRI prover` (commit phase) | 184.8 s | 31.35 GB | | 19.2 s |
| **run peak** | in the FRI commit phase | **33.27 GB** | | |

With 16 threads the instances' `compute quotient` spans run concurrently and nest in the log, and
the span log carries no per-instance label, so the per-table rows of docs/04's tier-19 table cannot
be read back from this run. The six closes, in log order (outermost last), are the record:

| close | live after | Δ live (from the span's own start) |
|---:|---:|---:|
| 103.9 s | 17.57 GB | +0.62 GB |
| 108.1 s | 18.63 GB | +1.68 GB |
| 108.5 s | 18.42 GB | +1.43 GB |
| 118.4 s | 20.25 GB | +3.30 GB |
| 121.9 s | 21.38 GB | +4.43 GB |
| 134.8 s (outermost) | **23.65 GB** | **+6.69 GB** |

Across tiers (derived): docs/04's cell model scales the tier-19 twin by 0.53 at tier 18, which
puts the uncut live-after-quotient figure near 61.0 × 0.53 ≈ 32 GB; 23.65 GB measured is ×0.73 of
that. The run's 33.27 GB peak is now in the FRI phase, not in the quotient.

## What it means for the hardware plan

- **Measured:** the test-profile N=1 aggregate's shape (the tier-18 exit twin) proves on a 48 GB
  machine at 33.3 GB peak live, so a **64 GB host runs it with margin**. This replaces docs/04's
  ≈ 50 GB projection for that proof.
- **Projection (labelled):** the production N=1 aggregate (tier 20) was projected at **≈ 240 GB**
  in docs/04 (§"What the cuts change"). This cut gives one measured ratio, ×0.705 (the tier-16
  peak, the one same-shape pair), and one derived, ×0.73 (the 16-thread tier-18 quotient phase
  against the cell-scaled, single-threaded tier-19 figure, above).
  Applied to 240 GB: **≈ 170–175 GB**, against the spec's ≈ 190 GB model. This is a projection
  until the tier-20 production proof runs on a ≥ 256 GB host; until then the host class stays
  ≥ 256 GB, now with room rather than tight.
- **The next levers, in order:** the register table's height (4× the cpu table; a wider cpu row
  that reads fewer registers); `log_blowup 3 → 2` for the rVM's profile (halves every LDE at
  ~1.5× the queries); device-resident LDEs and trees on the GPU backend (docs/04 candidates 2–4).

## What moved

| pin | before | after | where |
|---|---|---|---|
| self-verifier program digest, toy fixture shape | `18514c2aa0ad8d6a5aa7ea8baa65754f9137db5f1ad1d60943930add0becde67` | `91e50e140a8669385902e88bcbb18d5d9e5c270262d3f24bb2b67b4a469fbd13` | `tests/self_verify.rs` |
| self-verifier `CycleReport` (rows, perms, mem, instrs, words), toy | (152 527, 7 660, 345 333, 154 375, 30 255) | (131 739, 6 130, 276 847, 133 587, 24 135) | `tests/self_verify.rs` |
| the same, busy fixture | (188 390, 9 310, 388 321, 190 502, 36 087) | (167 746, 7 780, 320 075, 169 858, 29 967) | `tests/self_verify.rs` |
| self-verifier phase 5, toy / busy | 7 845 / 8 125 | 7 845 / 8 125 (unchanged, measured) | `tests/self_verify.rs` |
| an rVM proof's quotient-round matrices, `rand_openings[2].len()` | one per committed chunk | one per instance | `tests/quotient_layout.rs` |
| `machine::QUOTIENT_LAYOUT` | — | `PerInstance` | `tests/quotient_layout.rs` |
| `verify_rv32.digest`; production `aggregate_program_digest` `c90b3f0a7758c7e306042f27a94cc1f123441b0284c7352cb3f426048c7a74d8`; `inner_vk_digest` `346ee184…`; `tests/pins.json`; `tests/aggregate.rs`; `tests/verifier.rs` | — | **unchanged, asserted** (Task 3 ran these suites before any re-pin: aggregate 17 passed, verifier 21, tape_n 4, verifier_key 1) | the files named |

The self-verifier's rows fell 14 % (toy 152 527 → 131 739, busy 188 390 → 167 746). At both
fixture shapes the rVM proof has 7 instances with log chunk counts `[1, 3, 2, 2, 2, 1, 1]`, so 52
committed chunk matrices (2 + 8 + 4 + 4 + 4 + 2 + 2, doubled for ZK) become 7. The program hints,
absorbs and hashes one salted row with four hidden values per instance instead of 52 per query:
that is where the rows, the 20 % of permutations and the witness words went. It is not Merkle
paths: a round already opens with one path per query, since the MMCS batches every matrix of a
round into one tree (docs/04's sentence saying otherwise is corrected there). Phase 5 did not move:
the constraint evaluation recomposes the quotient from the same per-chunk slices.

## Testing

- **`tests/quotient_layout.rs`** (new, 6 tests): `the_machine_pins_the_per_instance_layout`;
  `a_per_instance_proof_has_one_quotient_matrix_per_instance_and_verifies`;
  `a_per_instance_proof_survives_postcard`; `a_flipped_quotient_chunk_value_is_refused`;
  `a_flipped_quotient_random_hint_is_refused`;
  `a_proof_made_under_upstreams_layout_is_refused_not_panicked` (a `PerChunk` proof of the same
  traces, refused by `Machine::verify` by name).
- **The fork's unit tests** (`vendor/p3-batch-stark/src/prover.rs`, `mod layout_tests`):
  `concat_lays_data_columns_side_by_side_and_keeps_the_first_chunks_salts_once`,
  `concat_without_salt_columns_is_a_plain_horizontal_join`. `cargo +1.98.1 test --release` inside
  the fork: 3 passed (these two and upstream's in-crate test), 0 failed.
- **`tests/self_verify.rs`**: the self-verifier accepts real rVM proofs under the new layout at the
  toy and busy shapes, refuses the thirteen tampered proofs, and its pins are re-recorded (above).
- **The suite** (`cargo test --release --no-fail-fast -- --skip a_one_proof_aggregate_round_trips`,
  2026-10-05): **214 passed, 0 failed, 20 ignored, 1 skipped** (the tier-18 round trip) across 28
  test binaries; docs/04's count was 208, and the six new tests are the difference.

## Out of scope, recorded

Spec §7, verbatim:

- **Flipping the RV32 machine to `PerInstance`.** It changes every wallet proof's transcript — a
  constraint-set cut (cs9), a wallet release, the aggregate program digest and every admission
  vector. The switch is there for it; this phase does not pull it.
- **A per-instance quotient method in the p3-fri patch** (salting once, no wasted salt NTTs). Only
  if the tier-16 measurement shows the discarded salt columns' LDEs above ~5 % of proving time.
  The transient they cause is bounded by one instance's chunk set and is freed before the next
  instance; the retained term is what this phase cuts.
- The REDUCE descriptor table, the fold-chain sibling select, the FADDI per `COMPRESS`, the inner
  FRI profile, `log_blowup 3 → 2` for the rVM: `docs/04` §"Still ahead".

The measurement decides the second item: the tier-16 prove wall fell 19 % (40.7 → 32.9 s), so the
discarded salt NTTs are not visible above the savings, and the `p3-fri` method is not pursued.
