# 02 — The aggregate program: N bundle proofs in one rVM proof, and what it costs

M5.3 (plan: `docs/superpowers/plans/2026-09-15-zkvm-m5-3.md`; the machine and its single-proof
numbers: `docs/01-rvm-machine.md`). One **N-generic aggregate program per inner shape** (R1):
a counted loop over the tape's `N`, each iteration the single-proof verifier's phases 0–7 over
that proof's tape region with a fresh challenger (R2), then the interface digest over
`[inner_vk_digest ‖ N ‖ 34·N]` (R5). The fullnode registers one program digest per inner shape
(R6); the program covers every `N` the tape holds, because the loop count is a tape value, not a
build-time constant.

Every number below was measured on 2026-09-15 on this machine (macOS, 16 cores, 48 GB) with the
crate's documented command and is pinned by a test where the plan asks for one: the per-N cycle
numbers in `tests/pins.json` (`tests/aggregate.rs::the_per_n_cycle_budget_is_pinned`), the N=1
differential and the tamper table in the same file, the stub vectors in
`the_admission_stub_vectors`. Estimates are labelled with their derivation.

## The N-economics, measured (test profile)

The shipped program (`Checkpoints::Off`, liveness and precompiles on) over the fixture shape;
the tape is `1 + 43 344·N` words exactly. The program itself is 443 893 instructions — once,
independent of `N`.

| N | tier | cpu rows | permutations | mem accesses | witness words |
|---:|---:|---:|---:|---:|---:|
| 1 | 19 | 441 782 | 11 205 | 597 043 | 43 345 |
| 2 | 20 | 883 240 | 22 382 | 1 193 489 | 86 689 |
| 3 | 21 | 1 324 694 | 33 558 | 1 789 918 | 130 033 |

The row model, measured and closed: `rows(N) = 328 + N · 441 454 + 4·⌊N/2⌋`. The 328 is the
preamble and post-loop (the count word and its guard, the interface sponge's state, the vk
digest absorb, the final partial-block permutation, the four published words); the 441 454 is
the per-proof body — the single-proof program's 441 643 rows with its phase-8 list build and
one-shot `sponge_seeded` *replaced* by the 34-word staged absorb, 189 rows cheaper per proof;
and the parity term is the absorb's rate-fill schedule: the fill phase advances two lanes per
proof (34 mod 4), so every odd iteration permutes nine times where an even one permutes eight,
at four rows the difference (the permutation row, the absolute-address fold, the two rewind
rows). The N=1 pin equals the single-proof rows plus the 139-row loop overhead, and the budget
test asserts the two pins agree exactly — the loop's cost is a measured number, not a guess.

The permutation model: `perms(N) = 29 + 11 176·N + ⌊N/2⌋` — the interface digest costs the same
permutations as the single-proof program's phase 8 did (the absorb schedule *is* the same
sponge), so the per-proof count is the single-proof's 11 205 minus the 29 the preamble pays
once.

## The N-economics, derived (production)

The production inner proof's rows are M5.2's pin (1 968 619 rows, 51 605 permutations); the
per-N scaling is the measured test-profile law applied to the same structure. The loop overhead
at the production shape is **measured**, not assumed: 1 968 758 rows for the production N=1
aggregate — the pin plus the same 139 rows (`the_production_n1_aggregate_is_the_m52_pin_plus_loop_overhead`,
which also re-asserts the M5.2 pin itself):

| N | tier | cpu rows | oracle memory | machine class |
|---:|---:|---:|---:|---|
| 1 | 21 | 1 968 758 (measured) | 48.6 GB (M5.2's measured derivation) | ≥ 64 GB |
| 2 | 22 | ~3.94 M (derived: 2× the N=1 body, plus the preamble) | ~95.3 GB | ≥ 128 GB |
| 3 | 23 — **no such rung** | ~5.91 M (same derivation) | ~127 GB | ≥ 160 GB |

`TIERS` stops at 22 (`01-rvm-machine.md`): a production N=3 aggregate returns
`Tier::for_cycles == None` — unprovable anywhere, by construction, and N=2 needs a 128 GB
machine. The production N≥2 aggregates are therefore *written, not executed here* (R4): per the
2026-09-15 ruling they will be executed on a ≥64 GB machine after chain-side aggregation lands,
and M5.4's GPU backend is the path beyond that (the tier-23 rung exists nowhere until the GPU
memory model is measured). The M5.3 exit is the test-profile N=3 twin below, at the same
*structure* of work the production N=1 has.

## The exit, measured

The exit (spec §7, R4's profile ruling): an aggregate of **three real test-profile bundle
proofs** proves and verifies natively. What this box admitted on 2026-09-15, and the plan's
fallback applied honestly:

| run | prove | verify | proof size | peak RSS |
|---|---:|---:|---:|---:|
| N=1, tier 19 (round-trip) | three completed runs: ~30 min wall contended (the full suite alongside), then 1 614 s and 1 578 s for the whole test binary on the quieter box (the M5.2 anchor for the same shape is 1 707.7 s) | not split out this run (M5.2's 18.31 s key-build anchor applies at the same 2^19) | **328 121 bytes** (M5.2's single-proof twin: 327 321 — the aggregate's declared heights carry the loop's small overhead) | 30 GB (watchdog-sampled) |
| N=2, tier 20 | **jetsam'd twice** (SIGKILL), reaching 33.7 GB and 33.3 GB sampled — above this box's practical line (~33 GB today) | — | — | 33.7 GB before the kill |
| N=3, tier 21 (the twin) | **jetsam'd** (SIGKILL) ~55 s into the prove, reaching 31.5 GB sampled — the box's line moved down as pressure spiked; the tier-21 prove never entered its NTT phases | — | — | 31.5 GB before the kill |

The plan's fallback clause: *if the heavy run dies to contention, record the heaviest completed
run as the in-scope proof and the rest as deferred with the measured peak reached*. The
completed in-scope proof is the **N=1 tier-19 aggregate** (the round-trip test: proves,
verifies, returns the bundle's `OUT0..7`, and both tampered variants are refused); N=2 and N=3
are proven *structurally* — the N=2/N=3 emulations accept and publish the host's §4.4 digest
(`n3_aggregate_publishes_the_host_interface_digest`, in-suite) and their rows are pinned in
`tests/pins.json` — and deferred as native proofs with the peaks above. **The 2026-09-15
ruling on every deferred run:** the heavy proofs — the test-profile N=2/N=3 twins here and the
production-profile ones (M5.2's tier-21 exit, the production N≥2 aggregates below) — are
*written* now, and they will be *executed on a ≥64 GB machine after chain-side aggregation
lands*. That is a scheduled run, not "as soon as hardware allows": the M5.2 era already
completed a tier-21 rVM proof on this machine class under a 42 GiB watchdog, so the line is
contention, not structure. The two `#[ignore]`d tests (`two_test_profile_…`, `twin_three_…`)
carry the watchdog command lines.

## The API

`recursion/src/aggregate.rs` — spec §6, amended by M5.2's R5/R6 and M5.3's R6:

- `InnerProof = rand_zkvm::machine::Proof` — the 34 public values ride inside it; the empty
  public segment's `H_PUB` is a prover-computed constant of the shape.
- `InnerVerifierKey { shape, key }` — what an aggregate proves under: one inner shape and its
  preprocessed cap.
- `aggregate_program(vk) -> Program` and `aggregate_program_digest(shape, key) -> [F; 4]` — the
  registered artifact and its name: the N-generic program, built once, pinned by digest.
- `aggregate(m, vk, proofs, tier) -> Result<AggregateProof, AggregateError>` — refuses the
  empty set (`Empty`), shape-checks every inner proof before any tape work
  (`WrongShape { index }`), builds the N-proof tape (`Tape`), proves (`Prove`), and asserts the
  executed program's published digest equals the host-computed one at prove time
  (`DigestMismatch`, R6). Returns the proof and its §4.4 list.
- `verify_aggregate(m, program, a) -> Result<Vec<[u32; 8]>, VerifyAggregateError>` — recomputes
  the §4.4 digest from `a.public` and compares it against the proof's batch public values
  (`DigestMismatch` — the `verify_public` pattern), then runs the ordinary rVM
  `Machine::verify` (`Verify`), and returns each covered bundle's `OUT0..7` in proof order.

The derive lists the plan sketched narrow to what compiles: `AggregateError` and
`VerifyAggregateError` are `Debug`-only (`ProveError`/`VerifyError` have no `Clone`/`PartialEq`),
and `AggregateProof` has no derives at all (`BatchProof` has neither trait) — a second handle
is a `to_bytes` round-trip, the fixture cache's own move.

## Startup: the key-build story

The fullnode builds the N-generic program once at startup and registers its digest. The program
*build* (DSL emission plus the allocator's replay, 443 893 instructions) measures seconds; it is
not the cost. The cost is the verifier key — the preprocessed commitment over the program table
— built lazily per `(tier, program digest, reduce)` triple by the machine's 64-entry FIFO
`KeyCache` (`src/machine.rs`), so a node pays it on the first verification of a given tier and
never again while the entry lives. The measured anchor is M5.2's twin: 18.31 s for the 2^19
test-profile build, key-build-dominated. The 2^21 production build is estimated at ~30–70 s
(same construction, four times the program-table rows; the measurement is the ignored
production test's business, not the suite's).

## What the chain must carry (R5's two corrections)

Both flow from the interface digest binding *one* shape, not from preference:

1. **Sealed history must carry each covered bundle's declared shape** — `tier` plus the six
   declared log-heights (`program`, `input`, `keccak`, `sha256`, `public`, `mem`), the 9 bytes
   per bundle the plan sizes it at. Without them the admission stub cannot reconstruct the
   shape, and `Machine::verify` would refuse the aggregate only *after* the rVM work.
2. **Admission must shape-check every covered bundle** against the aggregate's registered
   shape. The program's per-iteration header asserts already pin every proof to the shape at
   prove time, so a mixed-shape set cannot *prove*; the admission check is the cheap refusal
   that keeps such a transaction out of the mempool before any rVM work.

## What M5.3 hands to M5.4

- **The pinned aggregate program and its digest** — one N-generic program per inner shape, the
  registered artifact the fullnode pins by digest; M5.4's self-verifier program reads it the
  way the aggregate program reads the RV32 machine's shape.
- **The measured N-economics** — the tables above: production N=1 at tier 21 (48.6 GB oracle,
  ≥ 64 GB), N=2 at tier 22 (~95 GB, ≥ 128 GB), N=3 at tier 23 (~127 GB, ≥ 160 GB, a rung that
  exists nowhere), and the test-profile N=1..3 measured rows calibrating the linear scaling.
  The production proofs are written; their execution is scheduled for a ≥64 GB machine after
  chain-side aggregation lands (the 2026-09-15 ruling), and the GPU backend's first target is
  the production N=2/N=3 aggregate beyond that, with the tier-23 rung added when the GPU memory
  model is measured.
- **The chain-facing API, settled** — `aggregate` / `verify_aggregate` /
  `aggregate_program_digest`, with the startup key-build story measured (18.31 s at 2^19; the
  2^21 production build estimated at ~30–70 s).
- **The chain-side corrections** — sealed history carries each covered bundle's declared shape;
  admission shape-checks every covered bundle. Both stated above as requirements, not
  suggestions.
- **The `H_IN` answer** (R3) — no extra binding; `H_IN` is already bound through `pv::IN0..7`
  in the interface list.
- **The spec amendment to report, not silently edit** — §7's M5.4 line ("its end-to-end proof
  if it fits the laptop, else deferred with the measured requirement") now has the measured
  requirement for the self-recursion input: the N=1 production aggregate at tier 21, 48.6 GB
  oracle, ≥ 64 GB — the same class as M5.2's exit. The tier-23 rung exists nowhere until the
  GPU backend needs it for N=3 (R4).
