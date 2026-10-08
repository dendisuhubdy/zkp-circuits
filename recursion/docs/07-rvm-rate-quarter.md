# 07 — The rVM at rate ¼: its own FRI profile, at equal proven security

Design: `docs/superpowers/specs/2026-10-06-rvm-rate-quarter-design.md`. Plan:
`docs/superpowers/plans/2026-10-06-rvm-rate-quarter.md`. Branch `feat/rvm-rate-quarter`, base
`3316e11` (phase 3 merged). Every security figure here is a line `tests/security.rs` prints
(`cargo test --release --test security -- --nocapture`); every memory and time figure is a run of
`tests/memprofile.rs` or `tests/aggregate.rs` on this 48 GB box (16 cores, `--features parallel`,
`RAYON_NUM_THREADS=16`), with its raw log under `docs/measurements/2026-10-06-*.log` (the runs
were made on 2026-10-08; the files carry the phase's date); every other number is labelled a
projection, with its derivation.

**Result:** the recursion machine's *own* proofs — the proofs it makes, not the inner RV32 proofs
it verifies — move from rate ⅛ to rate ¼ (`log_blowup 3 → 2`), with **92 queries and 24
query-grinding bits** at Production in place of 80 and 20. `docs/06` §3 measured where the
prover's memory goes: every term of its table (main LDE and tree, the LogUp permutation LDE and
tree, the one quotient matrix per instance since `docs/05`, the FRI commit-phase trees) is an
evaluation over a domain of `height × 2^(log_blowup + 1)` rows, so halving the blowup halves all of
them at once; `docs/06` §7 item 2 recorded this as "the lever for §3's ≈ 110–130 GB". The query
and grinding counts are the price of keeping the proven floor where the paper's 80/8/20 put it:
under the whitepaper's own unique-decoding theorem the new regime gives **86.38 bits** against
today's **86.41**, and `p3-security`'s best proven bound over the rVM's real chip shapes gives the
same two figures. Measured on the test profile: the tier-18 exit twin's peak live heap
**26.88 → 15.64 GB (×0.58)**, its verify 7.07 → 3.53 s, its prove time about the same (+2 %);
the test N=2 aggregate (tier 19), projected at ≈ 52 GB in `docs/06` and never run before,
**proved and verified on this box**. Projected from the twin's ratio, the production N=1
aggregate falls from ≈ 110–130 GB to **≈ 64–75 GB** — a ≥ 96 GB host, not yet the ≤ 64 GB
class.

## 1. The security argument

**Two theorems, both proven.** The whitepaper (`randprotocol_implementation.tex`, "FRI soundness
as instantiated") bounds the FRI query term with the **unique-decoding** radius:
`q · log2(2 / (1 + ρ)) + g` bits — 0.830 bits a query at rate ⅛, 0.678 at rate ¼. `p3-security`
0.7.0 (the estimator `research/src/machine.rs`'s `fri_soundness_tests` already uses) reports that
regime (UDR) and, beside it, the **list-decoding** regime (LDR: the BCSS25 proximity-gaps theorem,
also proven) and takes the better of the two; its report also carries the commit-phase error, the
batch-combination term over the number of codewords FRI combines, the constraint-combination term
and the LogUp fingerprint (`logup::security_term`). The paper stands on the first column, so the
rule this phase pins is equality under **both**: neither the paper's closed form nor
`p3-security`'s best proven figure may fall by more than 0.5 bits.

**The real shape** (`tests/security.rs::real_shape`, printed verbatim): 708 constraints of
degree 8 over the production chips; `log_trace_length 22` (the tallest production table is `2^21`,
`2^22` after the ZK doubling); a 128-bit field (Goldilocks²) and 128-bit collision resistance; a
LogUp bus of 126 messages a row, the widest 10 elements; and **1 692 batched functions** — every
column of every committed matrix at every point it is opened (random 16, main 1 146, quotient 168,
preprocessed 50, permutation 312), not the 35 committed matrices.

| regime (log_blowup, q, g) | paper's UDR formula | `p3-security` best proven (what binds) | conjectured (random words) | legacy ethSTARK `b·q + g` |
|---|---:|---:|---:|---:|
| today: (3, 80, 20) | **86.41** | **86.41** (low-degree test, unique decoding) | 95.44 | 260 |
| new: (2, 92, 24) | **86.38** | **86.38** (low-degree test, unique decoding — the same term) | 95.44 | 208 |

Equal to **0.03 bits** under both bounds; the assertion's margin is 0.47 bits (86.38 ≥ 86.41 −
0.5). The conjectured bound is 95.44 either way: the field term caps it, not the rate. The legacy
ethSTARK bound the paper's remark quotes (`3·80 + 20 = 260`) stays far above 100 (`2·92 + 24 =
208`).

**Why the codeword count, and why the spec's first draft's 88.0 does not hold.** The batch
combination folds every codeword FRI opens into one with powers of a single challenge; its error
grows with the number of codewords, so the count has to be what the prover actually combines —
each column (including the four hiding columns of each matrix) at each opening point (`zeta` and,
for the rows with a next-row constraint, `zeta·g`). Counted that way it is 1 692. Counted by
committed matrix (35, the test's first version) the same regime gives 87.46 bits — list decoding
winning through the batch-combination term at `m = 3` — and the spec's first draft, over a
synthetic shape of 24 functions, gave 88.0. At the real count the list-decoding regime's
batch-combination term falls below the unique-decoding figure, and the low-degree test binds in
both regimes: **86.38 is the proven figure, under the paper's theorem and under `p3-security`
alike**. The test prints both counts' reports and asserts on the codeword count, the conservative
one (spec §0.1's last paragraph records the withdrawal).

**Why 92 / 24 and not 80 / 24.** At rate ¼, 80 queries with four more grinding bits is equal
only under list decoding over the synthetic shape (86.2); under the theorem the paper states it
is `80 × 0.678 + 24 = 78.2` bits, eight below today's. The equal point under the paper's own
formula is 92 queries at 24 bits (`92 × 0.678 + 24 = 86.38`). It is also not the "~120 queries"
`docs/06` §7 item 2 reasoned from the Johnson radius alone: 120 is where the field term saturates
the bound (spec §0.1's table), not where equality is.

**The rule, not the digit.** `the_new_rvm_profile_is_not_below_todays_proven_floor` asserts
today's paper figure is 86.4 ± 0.2; the paper's UDR bits at `RvmFri::of(Production)` ≥ today's −
0.5; `p3-security`'s best proven bits ≥ today's − 0.5; conjectured ≥ 95; legacy ≥ 100. Had the
real shape wanted one more query or grinding bit, the constant would have followed the test; it
did not (`NEW` stayed (2, 92, 24)). `the_test_regime_keeps_its_shape` pins the Test profile's
structure (rate ¼, 16 queries, 4 bits).

## 2. What changed

- **`machine::RvmFri`** — the rVM's own FRI parameters, an object of their own:
  `RvmFri::of(Production) = { log_blowup: 2, num_queries: 92, query_pow_bits: 24 }`,
  `RvmFri::of(Test) = { 2, 16, 4 }`. `generic_config`, `key_config` and the two cfg-gated backend
  configs (`machine/backend.rs`, reference and CUDA) take it; `max_log_arity 3`,
  `log_final_poly_len 0`, the zero commit-phase PoW and the four hiding codewords are unchanged.
  The verifier builds its config from the profile, never from the proof: a proof made at rate ⅛
  is refused by `Machine::verify` by name (`VerifyError::Batch`,
  `a_rate_eighth_proof_is_refused_by_name`), never accepted and never a panic.
- **The blowup is the shape's.** The crate constant `LOG_BLOWUP = 3` is retired:
  `shape::INNER_LOG_BLOWUP = 3` mirrors research's config for the inner proofs (cross-checked over
  a real inner proof by `tests/verifier.rs`), and `VerifierShape::log_blowup()` answers 3 for
  `InnerShape` and `RvmFri::of(profile).log_blowup` (2) for `RvmShape`. Every former reader —
  the FRI schedule, `log_global_max_height`, the replay's `FriParameters` and round geometry
  (`reference.rs`), `h_of` and the reduced-opening accumulator in `programs/rv32.rs` — takes it
  from the shape it is reading; `RvmShape`'s `num_queries` (92 at Production) and
  `query_pow_bits` come from `RvmFri::of(profile)` (`shape.rs`).
- **The self-verifier** (`rv32r`) reads rVM proofs at rate ¼: one Merkle level fewer per path,
  so its digest and `CycleReport` pins moved (§5). The witness tape follows the replay.
- **The Test profile moved to rate ¼ too**, with its 16 queries and 4 bits: the suite runs the
  code paths the production machine runs, and every measurement in §3 is at the Test profile.
- **What did not move:** the inner RV32 machine and every wallet proof; the aggregate programs
  (`rv32`/`rv32n` read inner proofs, `log_blowup()` is 3 for them, every emitted instruction is
  the one emitted before) and so their digests; cpu rows and tiers; `tests/pins.json`; the
  admission vectors; `research/` (its config literal stays 3; only `FriProfile`'s doc gained a
  sentence).

## 3. Measured

Three runs before and after, same box, 16 threads, `--features parallel`, Test profile (rate
⅛ → ¼; 16 queries and 4 grinding bits on both sides). Logs: `2026-10-06-tier16-before.log`,
`-tier16-after.log`, `-twin-before.log`, `-twin-after.log`, `-aggregate-n2.log`.

| | before (phase 3's tree, `d944166`) | after (`2fbd45b`) | ratio |
|---|---:|---:|---:|
| tier-16 synthetic (63 762 rows): peak live heap | 6.01 GB | **3.83 GB** | ×0.64 |
| — prove wall | 32.3 s | 28.6 s | ×0.89 |
| — proof bytes | 225 522 B | 218 962 B | ×0.971 |
| exit twin (tier 18, 169 366 rows): peak live heap | 26.88 GB | **15.64 GB** | **×0.58** |
| — prove wall | 148.9 s | 152.0 s | ×1.02 |
| — verify | 7.07 s | **3.53 s** | ×0.50 |
| — proof bytes | 270 024 B | 264 296 B | ×0.979 |
| test N=2 aggregate (tier 19) | not run (≈ 52 GB projected, `docs/06` §3) | **proved and verified natively**, 273 957 B, test wall 156.6 s | — |

The tier-16 and twin lines are each run's `== …` summary line and its `prove done:` / `verify` lines
(`tests/memprofile.rs` prints `verify` from its own timer around `Machine::verify`). The twin's
run-to-run spread is visible against `docs/06`'s own record of the same shape (prove 141.3 s,
verify 6.67 s, 268 168 B, same 26.88 GB peak); the before column here is today's rerun.

**The test N=2 aggregate** (`two_test_profile_bundle_proofs_aggregate_and_verify_natively`, run
alone): it proved, its `RvmTier(19)` assertion held, it verified natively and its eight outputs
matched. The test prints **no heap figure** — it is not under the heap profiler — so its peak live
heap is not measured. What is measured is the outcome: a tier-19 rVM proof that `docs/06` §6
listed among "the proofs this box cannot run" now runs here.

**Why the twin's heap fell and its prove time did not.** The twin's span log (`prove_batch`,
141.7 → 148.5 s) shows three phases that got faster and one that got slower: `compute quotient`
67.8 → 62.1 s; the four `build merkle tree` commits, its siblings under `prove_batch` (two before
it, two after), 29.4 → 26.3 s (10.4 + 6.2 + 8.9 + 3.9 → 11.7 + 7.1 + 4.1 + 3.4); the `FRI
prover` 7.4 → 4.2 s — and the two `randomize polys` spans
**25.6 → 41.7 s** (16.6 + 9.0 → 28.0 + 13.7), the time inside their `with_random_cols` children.
The +16.1 s of `randomize polys` cancels the ≈ 12 s saved elsewhere. The span log shows where the
time went; it does not say why `randomize polys` is slower over a smaller domain, and this record
does not guess. The tier-16 synthetic shows no such rise (`randomize polys` 3.9 + 2.1 → 4.0 +
2.2 s) and its prove fell ×0.89.

**Verify and proof bytes.** At the Test profile the query count did not change, so the spec's
"+15 % queries" does not apply to these runs: the measured change is the rate alone. The twin's
verify window is dominated by the verifier key's own commitment — the preprocessed program
table's coset LDE and Merkle tree, built inside `verify` (`build merkle tree` 0.8 → 0.4 s) — and
an unspanned interval between the two, 6.0 s before (149.1 → 155.1 s) and 2.9 s after (152.2 →
155.1 s), which the span log does not name. Both halved; that is the ×0.50. Proof bytes fell
2–3 %: one Merkle level fewer per opened path at 16 queries. The production profile's +12
queries (+15 % of the query-phase work and of the query-dependent bytes) is **not measured**
here; no production rVM proof runs on this box.

## 4. What it means for the hardware plan

`docs/06` §3's cell model still holds its shapes (no row or declared height moved), and one unit
(`2^14` committed LDE rows) now weighs 15.64 / 5 379 = **0.0029 GB** (0.0050 GB at phase 3's
end). Applying the twin's measured ×0.58 to `docs/06` §3's table — the same proof shapes, every
LDE term halved, the error bar the model's own ±10 % — gives:

| proof | tier | `docs/06` §3 (rate ⅛) | at rate ¼ | host class |
|---|---:|---|---|---|
| exit twin = test N=1 aggregate (the anchor) | 18 | 26.88 GB measured | **15.64 GB measured** | this 48 GB box |
| test N=2 aggregate | 19 | ≈ 52 GB (projection) | **proved on this 48 GB box** (heap not printed); ≈ 30 GB by the ratio (projection) | this 48 GB box |
| test N=3 aggregate | 19 | ≈ 78 GB (projection) | ≈ 45 GB (projection) | ≥ 64 GB (at the edge of 48 GB; not run) |
| production exit / N=1 aggregate | 20 | ≈ 110–130 GB (projection) | **≈ 64–75 GB** (projection) | **≥ 96 GB** |
| production N=2 | 21 | ≈ 210–245 GB (projection) | ≈ 122–142 GB (projection) | ≥ 192 GB |
| production N=3 | 21 | ≈ 290–340 GB (projection) | ≈ 168–197 GB (projection) | ≥ 256 GB |
| production N=4 | 22 | ≈ 410–490 GB (projection) | ≈ 238–284 GB (projection) | ≥ 384 GB |

Each projected range is `docs/06`'s range × 0.58. By the re-weighted unit, `docs/06`'s
twin-anchored production figure (108 GB) becomes 21 516 × 0.0029 = 63 GB, inside the error bar of
the table's 64 (which starts from `docs/06`'s rounded 110). **The ≤ 64 GB class (the fullnode
repository's `docs/compute-optimization.md` §4.4) is at the edge, not met:** the low end of the
range touches it, the range does not fit under it, and nothing at production has been measured.
The ×0.58 is the twin's; the tier-16 synthetic measured ×0.64, so the ratio depends on the shape
and the high end is the planning figure. The production profile's 92 queries add query-phase
transients that the Test-profile twin does not carry (the committed terms are unaffected). Every
line above except the two measured ones is a projection until a production proof runs on a
≥ 96 GB host.

## 5. What moved

| pin | before (rate ⅛) | after (rate ¼) | where |
|---|---|---|---|
| rVM verifier key cap, no reduce chip (`WANT`) | `dd11c3f0…` | `4e14ef4f…` | `tests/verifier_key.rs` |
| rVM verifier key cap, reduce chip (`WANT_REDUCE`) | `1465f60a…` | `5205f8d6…` | `tests/verifier_key.rs` |
| self-verifier program digest | `e9c9720d…` | `b42ae772…` | `tests/self_verify.rs` |
| toy `CycleReport` | (101460, 6168, 250619, 103468, 24415) | (101209, 6008, 247568, 103217, 23775) | `tests/self_verify.rs` |
| busy `CycleReport` | (127322, 7802, 296262, 129722, 30375) | (126541, 7578, 291961, 128941, 29479) | `tests/self_verify.rs` |
| phase 5 | (7933, 8213) | **unchanged** — the blowup does not reach the constraint evaluation | `tests/self_verify.rs` |
| `RvmShape.num_queries` at Production | 80 | 92 | `shape.rs`, from `RvmFri::of` |
| `RvmFri::of` | — | Production (2, 92, 24), Test (2, 16, 4) | `tests/machine.rs` |

Both key caps are the same at either profile (the Production run passes the Test print's
assertion). **Asserted unchanged, before and after the code change and before any re-pin**
(`tests/verifier.rs`, `tests/aggregate.rs`, `tests/tape_n.rs`, `tests/binding.rs`,
`tests/exit.rs` — the same pass, fail and ignore counts): the aggregate program digests (the
production aggregate `dc350ecf…`, `tests/aggregate.rs`), `src/programs/verify_rv32.digest`,
`tests/pins.json`, the admission vectors, and the cpu rows and tiers (585 686 rows, tier 20 for
one production inner proof; 169 366, tier 18 for the twin).

## 6. Testing

- **`tests/security.rs`** — the phase's gate, run before any pin was touched: the two assertions
  of §1 over the real chip shapes at the codeword count, plus the conjectured and legacy floors,
  and the Test regime's structure (2 passed).
- **`tests/machine.rs`** — `RvmFri::of` pinned for both profiles; a rate-⅛ proof of the toy,
  made with `Machine::with_fri`, refused by `Machine::verify` by name (10 passed).
- **`tests/shape.rs`** — `the_fri_schedule_is_a_function_of_the_blowup` (4 passed).
- **`tests/verifier_key.rs`** and **`tests/self_verify.rs`** — the re-pins of §5 with the before
  values in their comments; the self-verifier's round trips at the toy and busy shapes, the
  thirteen tampered proofs still refused at their named steps (8 passed).
- **The suite**: `cargo test --release --no-fail-fast -- --skip a_one_proof_aggregate_round_trips`
  — **30 binaries, 299 passed, 0 failed, 20 ignored** (294 passed at phase 3's end; the five new
  are security's two, machine's two and shape's one).
- `cargo check --release --features reference-backend` and `--features mock-cuda` build (the
  cfg-gated backend configs take `RvmFri`).

## 7. Out of scope, recorded

- **The inner RV32 profile** stays 80/8/20. It is a wallet-side lever paid for by the aggregator
  (`docs/06` §7 item 2) and a chain cut if ever made.
- **Raising grinding further, or trading queries for bits beyond equality.** The rule is equality
  with today's proven floor; another target is the paper's decision.
- **The Merkle spans** (`docs/06` §7 item 1), the reduce chip's N ceiling, device-resident LDEs.
- **The production measurements**: the production exit / N=1 aggregate at rate ¼, its verify
  time and proof bytes at 92 queries — on a ≥ 96 GB host.
- **The whitepaper row and the fullnode follow-through** (re-vendor; the node's hardware,
  aggregation and genesis docs naming the two parameter sets a `fri_profile` binds) are the
  plan's Tasks 7 and 8.

## Conclusion

The rVM proves its own proofs at rate ¼ with 92 queries and 24 grinding bits, at **86.38 proven
bits against 86.41** under the paper's theorem and under `p3-security` over the real shape — the
floor the 2026-09-12 audit (ZM1) insisted on, kept. The tier-18 twin's peak live heap is
**15.64 GB, ×0.58**, its verify halves, its prove time does not move (the `randomize polys` spans
take back what the quotient, the trees and FRI save), and the test N=2 aggregate — a tier-19 proof
— now runs on this 48 GB box. The production N=1 aggregate is projected at ≈ 64–75 GB: a ≥ 96 GB
host where `docs/06` asked ≥ 160 GB, and the edge of the ≤ 64 GB class, not inside it.
