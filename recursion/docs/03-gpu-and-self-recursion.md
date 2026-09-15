# 03 — The GPU backend and self-recursion: the device model, N re-measured, the self-verifier

M5.4's record (plan: `docs/superpowers/plans/2026-09-15-zkvm-m5-4.md`; the machine:
`docs/01-rvm-machine.md`; the aggregate program and its per-N economics:
`docs/02-aggregate.md`). Seeded by Task 2's device-model measurement; the hardware numbers
join it as Tasks 3–6 land (the PTX bring-up, the production re-measurement, the
self-verifier's verdict).

## The backend split (Task 1, landed)

`recursion/src/machine.rs` mirrors `research/src/machine.rs`'s backend split exactly: a
`Backend` enum (`Cpu` / `Reference` / `Cuda`), `prove_with`, and a generic `prove_on` under
the postcard-retype discipline (the alternative configs commit with the same Poseidon2
permutation, the same salt stream and the same FRI parameters, so the wire encoding is a pure
retyping and the stock CPU `Machine::verify` accepts the proof). The feature trio in
`recursion/Cargo.toml` is research's verbatim: `reference-backend`, `mock-cuda` (=
`rand-zkvm-cuda/mock-driver`), `cuda` (= `rand-zkvm-cuda/cuda`; `cuda-core` and the CUDA 13
toolkit requirement live only behind the last). **Zero new kernels** — the rVM shares the
field, the `Poseidon2Goldilocks<8>` permutation (`PERM_SEED` = "RandZK", duplicated by value
in `recursion/src/machine/backend.rs` because research's constant is `pub(crate)`), the
twiddle tables and the hiding-FRI shape with the RV32 machine, so `rand-zkvm-cuda`'s ten
kernels cover the rVM's eight instances unchanged.

The equivalence suite (`recursion/tests/backend.rs`, the fullnode's discipline mirrored): the
table-covering toy program at the smallest tier proves on `Backend::Reference` and on
`Backend::Cuda`-with-mock-driver, verifies on the stock CPU verifier before and after
`to_bytes`, and nests identically with the CPU proof (same tier, same public values, same
commitment presence, every opened run's length, size within the salt factor). 3 tests per
feature, green on both.

## The device-memory model (Task 2, measured arithmetic)

No GPU on this box, so the model is the backend's own chunking arithmetic, pinned in
`recursion/tests/device_model.rs` with its code anchors exercised through the mock driver (the
real `CudaNttEngine::max_columns` at the mock's 1 GiB, and the real upload guard firing).
Two formulas, verbatim from `rand-zkvm-cuda`:

- **NTT chunk sizing:** `max_columns(n) = (free_bytes / 2) / (n · 8 · 4)`, clamped ≥ 1
  (`src/gpu/ntt.rs:21-24`).
- **The whole-matrix upload guard:** an upload of `values.len() · 8 > free_bytes` fails
  `CudaError::Alloc { bytes, free }` ("use a lower tier") before any copy
  (`src/gpu/ntt.rs:26-29`, `src/gpu/hash.rs:16-19`).

The NTT chunk table at the tier's cpu LDE height (2^(t+3), log_blowup 3), columns per pass and
passes over the cpu table's 66 columns:

| tier | cpu LDE height | max_columns at 24 GiB | at 40 GiB | at 80 GiB | passes at 80 GiB |
|---:|---:|---:|---:|---:|---:|
| 21 | 2^24 | 24 | 40 | 80 | 1 |
| 22 | 2^25 | 12 | 20 | 40 | 2 |
| 23 | 2^26 | 6 | 10 | 20 | 4 |

The whole-matrix upload sizes (the cpu LDE matrix at 70 salted columns — the rVM's 66 plus
the four hiding salts — dominating everything else the commit path uploads):

| tier | cpu LDE upload | guard verdict at 24 GiB | at 40 GiB | at 80 GiB |
|---:|---:|---|---|---|
| 21 | 9 395 240 960 B (9.4 GB) | passes | passes | passes |
| 22 | 18 790 481 920 B (18.8 GB) | passes | passes | passes |
| 23 | 37 580 963 840 B (37.6 GB) | **refused** | passes | passes |

Two honest corrections to the plan's R3, found by this task (measured arithmetic replaces
derived, the plan's own discipline):

1. **The guard does not force the 80 GB class at tier 23.** The plan read "a 40 GB card runs
   tier 23 only with the row-chunked stretch": at guard level the tier-23 cpu upload *passes*
   a 40 GiB card (37.58 GB < 42.95 GB). What the 80 GB class is really about is the full
   device working set — the matrix, its digest layers (~4.3 GB at tier 23), and the NTT
   working set, which the divisor caps at `free/2` (checked to close exactly: 4 buffers of
   `n × max_columns` u64 cost `free/2` to within one column). How those phases compose into a
   peak is **T3's hardware measurement**, not this document's claim.
2. **The plan's NTT column read ~74 columns per pass at 80 GB; the formula gives 20.** The
   table above is the corrected one.

What does not move: the host classes — the backend accelerates NTT and Merkle *compute* and
changes nothing about host memory (traces, salted matrices and digest layers live on the host
in `ProverData`), so tier 21 → ≥ 64 GB, 22 → ≥ 128 GB, 23 → ≥ 160 GB host stand.

## The tier-23 rung (Task 2, landed)

`TIERS` gains 23: the production N=3 aggregate rung, pinned by
`Tier::for_cycles(5 905 862) == Some(Tier(23))` (the M5.3 row model's production-N=3 value)
and by nothing else — a rung no CPU-only box in this fleet has, present because the backend
gives the fleet a machine class that can use it. `check_declared_heights`' out-of-`TIERS`
guard moved to 24.

## The self-verifier, measured (Tasks 5–6, landed)

Spec §4.5's self-verifier is built and green: `recursion/src/programs/rv32r.rs`'s `verify_rv32r`
— the shared phases 0–7 over the rVM's own batch shape, with `machine::chips`' AIRs driven
through the same constraint `Emit`, and the interface digest over
`[rvm_vk_digest ‖ 1 ‖ the proof's four public values]`. The sibling triple behind it:
`RvmShape`/`RvmKey` beside `InnerShape`/`InnerKey` (`src/shape.rs`'s `VerifierShape` trait),
the replay generic over the trait (`src/reference.rs`), and the tape generic with it
(`WitnessTape::build_for` / `build_n_for`). The RV32 path is behavior-identical throughout —
the Off-replay byte-for-byte pin and every differential re-ran green. `tests/self_verify.rs`:
acceptance with the exact interface digest, the wrong-shape refusal, digest determinism, and
M5.1's thirteen-segment tamper table refused at the same named steps, verbatim.

**The measured cost** (`the_self_verifiers_measured_cost_at_two_fixture_shapes`, pinned in the
test): two test-profile fixtures, 16 queries each —

| fixture | tier | cpu rows | permutations | mem accesses | program instrs | witness words | phase 5 |
|---|---:|---:|---:|---:|---:|---:|---:|
| toy (every table, 17 instrs) | 8 | 275 135 | 7 438 | 402 810 | 276 978 | 29 367 | 7 245 |
| busy (2 048 stores + 64 perms) | 13 | 367 260 | 9 088 | 478 728 | 369 363 | 35 199 | 7 525 |

Phase 5 is **not** height-independent (7 245 → 7 525): the constraint DAG is per-chip, but the
emitted selectors and the quotient recomposition square `log(degree_bits)` times per instance,
so the phase grows with the declared heights. The query phase dominates either way and scales
with `queries ×` (opened columns `×` per-column cost `+` Merkle levels `×` per-level cost).

**The production requirement, derived from measured anchors** (replacing the plan's R6
estimate with the same arithmetic made concrete): the M5.2-exit shape is tier 21, production
profile, 80 queries, declared heights `[reg 23, ram 22, poseidon2 16, reduce 18]`, eight
instances. The self-verifier's FRI phase over it scales against the RV32 verifier's measured
1 968 619 rows at ~640 opened columns per query; the rVM shape opens roughly 800–1 100 columns
per query (the poseidon2 chip alone is 341 of ~470 base trace columns, plus next-row,
quotient, random, and permutation extension runs). Scaled: **an estimated 2.9–3.9 M cpu rows
→ tier 22, oracle in the ~97–130 GB class → a ≥ 128 GB machine**, consistent with the plan's
R6 estimate of 2.6–3.5 M. At the test profile over the M5.2 twin's shape (tier 19, 16
queries): an estimated 1.0–1.5 M rows → tier 21, ~40–60 GB.

**The verdict:** the end-to-end self proof **does not fit the dev laptop** — even its lower
bound (~2.6 M rows, ~97 GB oracle) exceeds the box — so it is deferred with the measured
requirement, exactly the path spec §7 allows: the number above, the machine class, and a
runbook entry (Appendix A of the M5.4 plan, row 11) that produces the exact figure where the
other deferred proofs run. The end-to-end self proof is *written*: `verify_rv32r` plus a
tape is the whole artifact; only its execution is deferred.

## Still ahead

- **T3** — the PTX build and hardware bring-up on the fleet GPU node (blocked-on-provisioning;
  `rand-zkvm-cuda/ptx/PTX_BUILD.md`'s checklist, in order).
- **T4** — N re-measured at production on the GPU (the per-N table of `docs/02-aggregate.md`
  completed with GPU columns).
- **T5/T6** — the self-verifier program and its measured requirement (the verdict's number
  replaces the plan's derivation).
- **T7** — this document's completion and the big-machine runbook's final form.
