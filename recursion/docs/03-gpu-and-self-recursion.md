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

## The consolidated big-machine runbook (Appendix A, current)

Sequencing per the 2026-09-15 ruling: the production-profile proofs execute **after chain-side
aggregation lands**; the GPU measurement runs (T4) are not chain proofs and run when the GPU
node exists. Estimates marked *derived* are arithmetic from measured inputs, not measurements;
T5/T6 changed only the last row.

| # | run | command | class | est. time | memory (observed/derived) |
|---|---|---|---|---|---|
| 1 | M4.3's ERC-20 `transfer` proof (research e2e) | `cd research && cargo +1.98.1 test --release --test e2e -- --ignored --nocapture` | ≥ 64 GB CPU | *derived* ~30–60 min | SIGKILLed 3× at 28.5–28.9 GB on the 48 GB box; requirement above that |
| 2 | M4.4's SPL token proof (tier 20, 694 498 cycles) | same binary, the tier-20 ignore | ≥ 64 GB CPU | *derived* ~1 h | tier-18's ~4× rows |
| 3 | M5.2's rVM exit: the verifier program over one production bundle proof (tier 21) | `cd recursion && cargo +1.98.1 test --release --test exit -- --ignored --nocapture` | ≥ 64 GB CPU | ~20–40 min (its ignore note) | 48.6 GB oracle committed; est. 43–61 GB peak |
| 4 | M5.3's N=2 test-profile aggregate (tier 20) | `cargo test --release -p recursion --test aggregate two_test_profile -- --ignored --nocapture` | ≥ 64 GB CPU | *derived* ~50–60 min (2× the N=1 wall) | 33.7 GB sampled before jetsam; true peak above |
| 5 | M5.3's N=3 test-profile twin (tier 21) | `cargo test --release -p recursion --test aggregate twin -- --ignored --nocapture` | ≥ 64 GB CPU | *derived* ~45–90 min | ~38–42 GB derived from the tier-20 peak |
| 6 | Production N=1 aggregate (tier 21) | the M5.4 T4 vehicle on CPU, or a runbook binary | ≥ 64 GB CPU | *derived* ~1–2 h | 48.6 GB oracle (M5.2's derivation) |
| 7 | Production N=2 aggregate (tier 22) | the M5.4 T4 vehicle, `Some(Tier(22))` | ≥ 128 GB host | *derived* hours on CPU; T4's GPU number replaces it | ~95.3 GB oracle |
| 8 | Production N=3 aggregate (tier 23 — T2's rung) | the M5.4 T4 vehicle, `Some(Tier(23))` | ≥ 160 GB host + 80 GB device | T4's GPU number | ~127 GB host oracle; the device model above |
| 9 | The PTX first run + `cuda-hw` suite (T3) | `rand-zkvm-cuda/ptx/PTX_BUILD.md`'s checklist | GPU node (R8) | ~1 h bring-up | — |
| 10 | N re-measured on GPU (T4) | T4's `#[ignore]`d test | GPU node, ≥ 160 GB host | T4's numbers | per R3/R5 |
| 11 | The self-verifier end-to-end proof | T6's twin: `verify_rv32r` over the M5.2-exit-shape tape | ≥ 128 GB host (production input, *derived* 2.9–3.9 M rows → tier 22); ≥ 64 GB at the test-profile shape (*derived* 1.0–1.5 M → tier 21) | *derived* hours on CPU | ~97–130 GB host oracle |

Runs 1–6 clear on the ≥ 64 GB machine in one session (in order; ~4–6 h total); 7–8 want the
bigger host (or the GPU node for 8); 9–10 want the GPU node; 11 lands wherever its first
fixture proof exists — the M5.2 exit's production proof (row 3) is the production-input tape,
so 11 follows 3 on the same machine.

## What M5.4 hands to the chain-side phase (and M5.5)

- **The backend split, built and tested** — `Backend::{Cpu, Reference, Cuda}` with
  `prove_with`/`prove_on` under the postcard-retype discipline; the mock-driven equivalence
  suite green on both feature flags. The production runs in the runbook can start on the
  reference backend the day a big machine exists — the GPU only accelerates them (T3/T4).
- **The measured device model** — the corrected chunk table (20 columns per pass at 80 GiB for
  the tier-23 cpu LDE height) and the upload-guard boundaries (a 24 GiB card refuses tier 23's
  cpu matrix; 40 GiB passes at guard level); the phase-composed peak is T3's measurement.
- **The tier-23 rung** — in `TIERS`, with its machine class on record (≥ 160 GB host, 80 GB
  device class).
- **The self-verifier, built and measured** — `verify_rv32r` with its tamper differential, and
  its requirement measured at two fixtures and derived for the M5.2-exit shape: tier 22,
  ~97–130 GB, ≥ 128 GB host — the tree-of-aggregates question answered to a number, with the
  end-to-end proof written and scheduled in the runbook (row 11).
- **The consolidated runbook itself**, above: every deferred proof, its command, its class, its
  estimate — one ≥ 64 GB session clears runs 1–6 after chain-side aggregation lands, and the
  GPU node clears 9–10 (and accelerates 6–8, 11) when provisioned.

## Still ahead (blocked-on-provisioning)

- **T3** — the PTX build and hardware bring-up on the fleet GPU node
  (`rand-zkvm-cuda/ptx/PTX_BUILD.md`'s checklist, in order; Linux, R580+ driver, CUDA 13,
  LLVM 21, sm_80-class or newer, 80 GB device class, ≥ 160 GB host).
- **T4** — N re-measured at production on the GPU (the per-N table of `docs/02-aggregate.md`
  completed with GPU columns), on that node.

