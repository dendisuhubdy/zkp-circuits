# rVM at rate ¼ — the recursion machine's own FRI profile moves to `log_blowup 2` at equal proven security (92 queries, 24 grinding bits)

**Date:** 2026-10-06. **Scope:** `recursion/` (the rVM), `research/src/machine.rs`'s profile doc,
the whitepaper's parameter table (one row, on a branch), the fullnode follow-through.
**Base:** circuits `main` 3316e11 (phase 3 merged). **Decided with the operator:** the lever is
the rVM's *own* FRI profile, not the inner one; the equal-security point is **92 queries with 24
query-grinding bits** — equal under the whitepaper's own (unique-decoding) theorem, not only under
`p3-security`'s list-decoding regime (§0.1); the whitepaper edit is in scope.

## 0. Why

Phase 3 (`docs/06`) ends with the production N=1 aggregate projected at ≈ 110–130 GB and records
(§7 item 2) that the rVM's own profile is "a separate lever with the opposite sign for memory:
`log_blowup 3 → 2` for rVM proofs halves every LDE term of §3's table". Every term in that table —
main LDE and tree, LogUp permutation LDE and tree, the one quotient matrix per instance since
`docs/05`, the FRI commit-phase trees — is an evaluation over the LDE domain of size
`height × 2^(log_blowup + 1)` (hiding doubles once more). Halving the blowup halves all of them at
once, and the Merkle paths the verifier walks lose one level each.

The profile is consensus-facing: the whitepaper fixes FRI at 80 queries / blowup 8 / 20 grinding
bits, and the 2026-09-12 audit (finding ZM1) reverted a 27-query retune because it kept only the
*conjectured* bound and abandoned the *proven* floor (~86 bits). So this phase is first a
security argument and only then a code change, and the argument is made with the estimator
Plonky3 ships (`p3-security` 0.7.0, the one `research/src/machine.rs`'s `fri_soundness_tests`
uses), not by hand.

### 0.1 The arithmetic (throwaway run, 2026-10-06, `p3-security` 0.7.0 over Goldilocks²)

Assumed shape for the run: `log_trace_length 22` (the production rVM's tallest table, `2^21`, plus
the ZK doubling), AIR degree 8, 24 committed functions, a LogUp bus. The run reproduces the paper's
figure for today's profile, which is the calibration:

The whitepaper's FRI theorem (`randprotocol_implementation.tex`, "FRI soundness as instantiated")
bounds the query term with the **unique-decoding** radius: `q · log2(2/(1+ρ)) + g` — 0.830 bits a
query at rate ⅛, 0.678 at rate ¼. `p3-security` reports that regime (UDR) and, beside it, the
**list-decoding** regime (LDR: the BCSS25 proximity-gaps theorem, also proven) and takes the better.
Both columns matter: the paper stands on the first.

| rVM regime | paper's UDR formula | `p3-security` best proven (regime that binds) | conjectured (random-words) | legacy ethSTARK `b·q + g` |
|---|---:|---:|---:|---:|
| today: rate ⅛, q 80, g 20 | **86.4** | 86.4 (low-degree test, UDR) | 95.8 | 260 |
| rate ¼, q 80, g 24 | 78.2 | 86.2 (batch combination, LDR m = 4) | 95.8 | 184 |
| rate ¼, **q 92, g 24** | **86.4** | **88.0** (batch combination, LDR m = 3) | 95.8 | 208 |
| rate ¼, q 98, g 20 | 86.5 | 88.0 | 95.8 | 216 |
| rate ¼, q 80, g 32 | 86.2 | 88.0 | 95.8 | 192 |
| rate ¼, q 110, g 20 | 94.6 | 94.6 (low-degree test, UDR) | 95.8 | 240 |
| rate ¼, q 120, g 20 | 101.4 | 95.8 (the LogUp fingerprint — the field term — binds) | 95.8 | 260 |

Four things the table settles. (1) At rate ¼, 80 queries with four more grinding bits is equal
only under list decoding; under the theorem the paper states it loses eight bits. The equal point
under *both* is **92 queries at 24 grinding bits** (`92 × 0.678 + 24 = 86.38` against today's
`86.41`; 88.0 under list decoding) — the operator's choice (2026-10-06), after the 80/24 option was
first presented without the paper's own column and then withdrawn. (2) It is not the "~120 queries"
`docs/06` §7 reasoned from the Johnson radius alone: 120 is where the field term saturates. (3) The
conjectured bound is 95.8 either way — the field term (Goldilocks² is 128 bits) caps it, not the
rate. (4) The legacy ethSTARK bound the paper's remark quotes (`3·80+20 = 260`) stays far above 100
(`2·92+24 = 208`).

The cost of the twelve extra queries is linear in the query count: +15 % on the rVM's verify
time, on the self-verifier's query phase (the rows that dominate it) and on the proof's
query-dependent bytes; the prover pays `2^24` expected Poseidon2 duplex evaluations once per proof,
which Plonky3 grinds in parallel (`grinding_challenger.rs`, `into_par_iter().find_map_any`) —
seconds. Against that, every LDE and tree in the prover halves.

**Measured over the real chip shapes (Task 1, 2026-10-08, `tests/security.rs`: 708 constraints,
degree 8, `log_trace_length 22`, 126 bus messages a row of width ≤ 10, and the codewords FRI
combines counted per column and opening point — 1 692, not the 35 committed matrices):** today's
(3, 80, 20) gives 86.41 bits under the paper's formula and 86.41 under `p3-security` (the
low-degree test binds, unique decoding); the chosen (2, 92, 24) gives 86.38 and 86.38 (the same
term binds — at the real codeword count the list-decoding regime no longer wins, so the synthetic
table's 88.0 does not hold; the conjectured bound is 95.44). Equal to 0.03 bits under both.

**The numbers above are the design's premise, not its pin.** §4 makes the same computation a test
with two assertions: the paper's closed-form UDR bits at the new regime ≥ today's − 0.5, and
`p3-security`'s best proven bits over the rVM's *real* chip shapes at the new regime ≥ today's
− 0.5. If the real-shape report wants one more query or grinding bit, the constant follows the
test; the rule, not the digit, is the design.

### 0.2 What it buys (projection; replaced by measurement in §6)

Halving the LDE factor halves every committed term (the +15 % queries touch the FRI query
phase's transients, not the committed terms). Against `docs/06` §3's projections:

| proof | tier | docs/06 projection | at rate ¼ (projection) |
|---|---:|---|---|
| exit twin = test N=1 aggregate | 18 | **26.88 GB measured** | ≈ 14 GB |
| test N=2 / N=3 aggregates | 19 | ≈ 52 / ≈ 78 GB | ≈ 26 / ≈ 39 GB (both fit this 48 GB box) |
| production exit / N=1 aggregate | 20 | ≈ 110–130 GB | **≈ 55–65 GB** — `compute-optimization.md` §4.4's ≤ 64 GB class |
| production N=2 | 21 | ≈ 210–245 GB | ≈ 105–125 GB |
| production N=4 | 22 | ≈ 410–490 GB | ≈ 205–245 GB |

Prove time falls with the LDE sizes (the NTTs and the Merkle trees are over half the rows);
verify time moves by +15 % queries less one Merkle level per path; proof size by the same two
terms with opposite signs. None of these is claimed until measured.

## 1. What changes, precisely

### 1.1 The rVM's FRI parameters become its own object

`recursion/src/machine.rs`:

```rust
/// The rVM's own FRI parameters — not the inner RV32 machine's. The inner profile (research's
/// `FriProfile`: 80 queries, rate ⅛, 20 grinding bits) sizes the proofs this machine *verifies*;
/// these size the proofs it *makes*. Rate ¼ halves every LDE and tree the prover holds; twelve
/// more queries and four more grinding bits keep the proven floor where the paper's 80/8/20 put
/// it — 86.38 proven bits against 86.41, under the paper's own unique-decoding theorem and under
/// `p3-security`'s proven bound over the real shape alike; `tests/security.rs` pins both (docs/07).
/// Consensus-facing like the inner profile: the chain's `fri_profile` name binds both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RvmFri { pub log_blowup: usize, pub num_queries: usize, pub query_pow_bits: usize }

impl RvmFri {
    pub const fn of(profile: FriProfile) -> RvmFri {
        match profile {
            FriProfile::Test => RvmFri { log_blowup: 2, num_queries: 16, query_pow_bits: 4 },
            FriProfile::Production => RvmFri { log_blowup: 2, num_queries: 92, query_pow_bits: 24 },
        }
    }
}
```

`generic_config` (`machine.rs:107-125`) reads `RvmFri::of(profile)` for `log_blowup`,
`num_queries` and `query_proof_of_work_bits` in place of the literal `3` and the profile's inner
numbers. `max_log_arity 3`, `log_final_poly_len 0`, `commit_proof_of_work_bits 0` and the four
hiding codewords are unchanged. Every backend goes through this one function, so the reference and
CUDA backends inherit the parameters (no blowup literal exists in `rand-zkvm-cuda`).

The Test profile moves to rate ¼ too, with its 16 queries and 4 bits unchanged: the suite then
exercises the same code paths the production machine runs, and the test twin's memory is the
phase's measured anchor.

### 1.2 The blowup stops being a crate constant

`recursion/src/shape.rs:34` has `pub const LOG_BLOWUP: usize = 3` "from research's
`generic_config`", used by both machines' shapes. It becomes two things:

- `INNER_LOG_BLOWUP: usize = 3` — the inner RV32 machine's, still mirroring research, and
  cross-checked against research's *real* config by `tests/verifier.rs:86` over a real inner
  proof (`Σ log_arities + INNER_LOG_BLOWUP == log_global_max_height`): a changed literal in
  research would fail that assertion.
- `VerifierShape::log_blowup(&self) -> usize`: `InnerShape` answers `INNER_LOG_BLOWUP`, `RvmShape`
  answers `RvmFri::of(self.profile).log_blowup`.

Every reader of `LOG_BLOWUP` takes it from the shape it is reading — the audit of the tree
(2026-10-06, `grep -rn LOG_BLOWUP recursion/src`): `shape.rs` (`log_global_max_height` ×2, the
arity schedule `log_arities`/`height_groups` at :451-459, the doc at :112), `reference.rs` (the
replay's `FriParameters` at :187, the arity cross-check at :435, the round geometry at :439 and
:513, the final height at :539), `programs/rv32.rs` (`h_of` at :469; the reduced-opening
accumulator keyed by the blowup height at :912 and :985), `witness.rs:560` (a doc comment).
`log_final_poly_len` stays 0 for both machines.

The RvmShape's profile recovery (`shape.rs:301-311`, "recovered from `(num_queries,
query_pow_bits)`") matches against `RvmFri::of(p)` for `p` in both profiles, not against the inner
profile's numbers — the two no longer coincide at Production.

### 1.3 What the programs do

- `rv32` / `rv32n` (the aggregate programs) read inner proofs: `shape.log_blowup()` is 3, every
  emitted instruction is the one emitted today. **Their digests do not move** — asserted, as in
  `docs/05`: the production aggregate digest `dc350ecf…` (`docs/06` §5), `verify_rv32.digest`
  `cf5a350a…`, the admission vectors, `pins.json`.
- `rv32r` (the self-verifier) reads rVM proofs: Merkle walks are one level shorter at every
  height, `h_of` is `degree_bits + 2`, the final-polynomial height is `2 + 0`. Its digest and
  `CycleReport` pins move (fewer rows — one `COMPRESS` level and its reloads per path per query).
  The witness tape follows the replay's geometry as it does today.

### 1.4 What else moves

- **The rVM's query count** is 92 at Production: `RvmShape.num_queries` and the self-verifier's
  query loop follow it; the inner shapes keep 80.
- **The rVM verifier keys** (`tests/verifier_key.rs`, `WANT` / `WANT_REDUCE`): the preprocessed
  program table's Merkle cap is over its LDE, whose height halves. Both pins move once and are
  re-recorded with the before values. (The inner keys and `inner_vk_digest` do not move.)
- **Every rVM proof's bytes and transcript**: a proof at rate ⅛ fed to the new verifier is refused
  (the arity schedule and the commit-phase round count differ; `check_declared_heights`/the FRI
  verifier's height cross-check), never accepted — pinned by a test that proves under a rate-⅛
  config and verifies under the machine.
- **The node** (fullnode follow-through): `agg_executor` verifies aggregates through the vendored
  `Machine`, so it inherits the new parameters at the re-vendor; `warm_aggregation`'s key build
  halves; `admitted_tiers` and the admission vectors are untouched; `docs/aggregation.md` and the
  genesis page state that a chain's `fri_profile` name binds two parameter sets, inner 80/8/20
  and rVM 92/4/24, both constants of the vendored constraint set. No genesis field is added.

### 1.5 What does not move

cpu rows and tiers (the aggregate program is unchanged, 585 686 rows at tier 20), `pins.json`,
the reduce chip's N ceiling, the inner RV32 machine and every wallet proof, `research/` (its
config literal stays 3; only `FriProfile`'s doc gains a sentence), the quotient layout, the
fullnode's `admitted_tiers`.

## 2. Soundness and the transcript

- **The FRI verifier reads the blowup from its parameters**, never from the proof: the rVM's
  `verify` builds the config from `RvmFri::of(self.profile)`, so a proof cannot choose its rate.
  The replay and the self-verifier program take it from the shape, which is a function of the
  profile and the program, not of the proof.
- **The proven bound, twice.** The paper's closed-form unique-decoding bits at the new regime are
  ≥ today's − 0.5 (`92 × log2(2/1.25) + 24` against `80 × log2(2/1.125) + 20`), and
  `p3-security`'s `proven_security_report` over the rVM's real shape at the new regime is ≥ the
  old regime's − 0.5 bits (§4's test; the digits follow the test — measured 86.41 → 86.38 both ways, 2026-10-08). The commit-phase bound (`commit_phase_error_*`) is included by the report; the
  LogUp fingerprint term is included (`logup::security_term`); the batch-combination term at the
  real `num_batched_functions` is included. Nothing in the argument depends on the conjecture.
- **Hiding is unchanged in kind**: four random codewords per committed matrix and a salt per leaf
  row; the LDE domain is smaller but the hiding argument (eprint 2024/1037 §4.2) is over the
  number of random columns (unchanged) and the query count, which went 80 → 92 at Production
  (16 at Test, unchanged). More openings would weaken a hiding bound, but hiding is not a privacy
  requirement for the rVM: its witness — the bundle proofs and the public values — is public.
- **The grinding witness** is checked by the verifier exactly as today (24 bits instead of 20);
  the commit-phase PoW stays at 0 bits with VERIFIER-1's zero-word assertion.

## 3. Governance surface

- `research/src/machine.rs` `FriProfile`'s doc: one sentence — the rVM's own proofs take
  `recursion::machine::RvmFri` (92 / 4 / 24 at Production), equal proven floor under the paper's
  own theorem, `docs/07`.
- Whitepaper (`whitepapers/randprotocol_implementation.tex`): in the deployed-parameters table and
  the "choice of 80 queries" remark, one row and one sentence: *the aggregate (rVM) proof: 92
  queries, blowup 4, 24 grinding bits — `92 × 0.678 + 24 ≈ 86.4` proven bits under the same
  theorem, equal to the bundle proof's; the rate is halved for the aggregator's memory, the
  queries and grinding bits raised to keep the floor; measured in `recursion/docs/07`.* Written on a branch of the whitepapers repository, not pushed: publishing
  is the operator's.
- The node's genesis/aggregation docs (fullnode follow-through), as in §1.4.

## 4. Testing (the repository's discipline, applied)

1. **`tests/security.rs`** (new): `StarkAirParams::from_air` over each production chip with its
   real `AirLayout` (preprocessed + main + permutation widths, as `p3-security`'s doc requires for
   lookup AIRs) and `max_combo` from the chip's degree; `InstanceShape` at the production exit's
   declared heights (`log_trace_length 22`: the tallest table is `2^21` declared and `2^22` after
   the ZK doubling, the number §0.1 used; 128-bit
   field, 128-bit collision resistance, the real committed-matrix count); `LogUpAir` from the
   machine's bus (interaction count, max message width). Two reports per regime — old (3, 80, 20)
   and new (`RvmFri::of(Production)`) — printed and asserted: the paper's closed-form UDR bits
   `new ≥ old − 0.5`; `p3-security`'s best proven `new ≥ old − 0.5`; `new.conjectured ≥ 95`;
   legacy `2·q + g ≥ 100`. A second assertion pins the Test regime's structure (rate ¼, 16, 4).
   This is the phase's gate: it runs before any pin is touched.
2. **`tests/machine.rs`**: `RvmFri::of` pinned for both profiles; a rate-⅛ proof of the toy (made
   with a test-only config builder taking an explicit `RvmFri`) refused by `Machine::verify` by a
   named error, never a panic.
3. **`tests/verifier_key.rs`**: the rVM caps re-pinned with the before values in the comment.
4. **`tests/self_verify.rs`**: round trips at the toy and busy shapes under the new profile; the
   digest, `CycleReport` tuples and phase 5 re-recorded with before values; the thirteen tampered
   proofs still refused at their named steps.
5. **Aggregate pins asserted unchanged before any re-pin**: `tests/verifier.rs`,
   `tests/aggregate.rs`, `tests/tape_n.rs`, `tests/binding.rs`, `verify_rv32.digest`,
   `pins.json`.
6. **`tests/memprofile.rs`**: the tier-16 synthetic and the exit twin before and after, same box,
   16 threads (`--features parallel`); both logs kept under `docs/measurements/`.
7. **The suite**: `cargo test --release --no-fail-fast -- --skip a_one_proof_aggregate_round_trips`
   green; the count recorded (294 passed at phase 3's end).

## 5. Projection, to be replaced

§0.2's table, re-derived in `docs/07` from the measured twin with `docs/06`'s cell model (one
unit is `2^14` LDE rows; the unit's weight halves). The test N=2 and N=3 aggregates (≈ 26 and
≈ 39 GB projected) are run on this box if the twin's measurement supports it — that would turn
two of `docs/06` §7's "proofs this box cannot run" into measurements.

## 6. Documentation and the fullnode

- `recursion/docs/07-rvm-rate-quarter.md`: the security argument with the real-shape report
  tables (old and new regime), the measured terms, the pins that moved, the re-projections, the
  suite count.
- `docs/06` §7 item 2: a pointer ("done at 92 / 4 / 24 — `docs/07`; the equal-security count is
  twelve more queries and four more grinding bits, not ~120 queries"). `docs/01`'s memory section: one
  line. `research/AGENTS.md`: one sentence.
- Fullnode (after the circuits merge and push): re-vendor; `docs/node-hardware.md` §4,
  `docs/compute-optimization.md` §4.1 and §4.4 (the ≤ 64 GB row), `docs/aggregation.md`,
  `docs/genesis` (the profile-name sentence), `AGENTS.md`.

## 7. Out of scope (recorded)

- **The inner RV32 profile.** A wallet-side lever paid for by the aggregator (`docs/06` §7 item 2):
  not this phase, and a chain cut if ever.
- **Raising grinding further or trading queries for bits beyond equality.** The rule is equality
  with today's proven floor; a different target is the paper's decision.
- **The Merkle-span cuts** (`docs/06` §7 item 1), the reduce N ceiling, device-resident LDEs.

## 8. Risks and how each is closed

| risk | closed by |
|---|---|
| the real-shape security report comes out below equality at 92 / 24 | the test decides the digits (one more query or bit); the rule, not the digit, is the design |
| a `LOG_BLOWUP` reader missed by the audit still assumes 3 for rVM proofs | the self-verifier round trip over real rVM proofs refuses on any disagreement; the grep list in §1.2 is the checklist and the constant is deleted, so a missed site fails to compile |
| the inner programs drift through the shared shape trait | the aggregate pins asserted before any re-pin (§4 item 5) |
| the CUDA/reference backend sizes its NTT from a hardcoded blowup | `cargo check --features reference-backend`; the backend's own round-trip tests under `reference-backend` if the box runs them; no blowup literal found in `rand-zkvm-cuda` |
| the node accepts a rate-⅛ aggregate after re-vendor | the machine refuses it (§1.4); the node's admission goes through `Machine::verify` only |

## 9. Rulings

- The rVM's own profile is the lever; the inner profile is untouched.
- Equality with today's proven floor under the paper's own theorem *and* under `p3-security`'s
  best proven regime: 92 queries, 24 grinding bits, the digits following the pinned test.
- The constant `LOG_BLOWUP` is retired, not kept beside a second one.
- Projections are projections until the run exists; the twin's run is the anchor.
- This branch bases on the merged phase 3 and is pushed only after phase 3 is.
