# rVM phase 4 — the Merkle spans: one inner verification in tier 19

**Date:** 2026-10-09. **Scope:** `recursion/` (the rVM: DSL, programs, ISA, emulator, cpu AIR), then the fullnode
re-vendor. **Base:** circuits `main` 71e1a04 (rate ¼ merged). **Decided with the operator:** the software package
(cap select, allocator re-homing, no digest copies) **plus** immediate-address `SPONGE` and `COMPRESS`; not the
path-level precompile. The priced spike behind every number here:
`recursion/docs/measurements/2026-10-08-merkle-spike-findings.md` (each candidate built behind a flag and run through the emulator on the real
production fixture, honest proof accepted); this spec's §6 makes the measurement the record.

## 0. Why

`docs/06` ended phase 3 at **585 686 cpu rows (tier 20), 61 399 above the tier-19 gate** (`≤ 2^19 − 1 = 524 287`), and
named the next lever: the two Merkle spans, `input_root` (248 151 rows) and `commit_root` (120 640) — 63 % of the
program, 133 827 of them register reloads. Crossing the gate puts every aggregate one tier lower, which halves its
prover memory; the rate-¼ phase (`docs/07`) took the production N=1 aggregate to ≈ 64–75 GB projected, so tier 19
projects it to roughly half that.

### 0.1 Where the rows go (re-measured 2026-10-08, production, 80 queries)

The walk itself is two rows a level since phase 2 (`COMPRESS` + one `FADDI`). The spans are expensive because of what
feeds each operation:

- **Reloads never re-home** (`dsl/builder.rs`, `replay`'s `Mat` arm): a spilled handle is loaded into a scratch
  register for one use and stays spilled, so every later use pays another `LOAD`. The register file is full for the
  whole program (`live_max` 25 of `r1..r25`; `r26..r31` are scratch), because the tape for all 80 queries is read
  before any query runs.
- **Pointers are registers.** A `Ptr` is a holder register plus a compile-time delta; `SPONGE`, `COMPRESS` and
  `POSEIDON2` take register addresses only, so each use pays one `FADDI` — although every address is a compile-time
  constant.
- **The cap check selects a cap entry by a dot product** over four candidates: 88 rows a round, 14 rounds a query.
- **The walk copies the digest** leaf → running cell → out: 16 rows a round.

Per operation that is ≈ 3.9 rows for each bit-driven `COMPRESS` and each `SPONGE` block instead of 1.

## 1. The four cuts

All four are measured in the spike; the combined number is the design's target, re-measured in §6.

| cut | what | rows (alone, from 585 686) | consensus surface |
|---|---|---:|---|
| **D1 — cap select** | `off = 4·b0 + 8·b1`, then per lane `LOAD [cap0 + lane + off]` against the walk's digest | 513 994 (−71 692) | program digests |
| **A — re-homing** | a reload lands in a real register when its next use is nearer than the farthest resident's; a re-homed value keeps its spill cell | 439 432 (−146 254) | program digests |
| **D2 — no copies** | the walk compresses over the leaf digest in place and returns it; no copy in or out | 566 625 (−19 061) | program digests |
| **B — immediate addresses** | `SPONGE`'s source and `COMPRESS`'s sibling become absolute immediates in `b` | B (COMPRESS) −28 461; B′ (SPONGE) −69 278 | ISA meaning of opcodes 25/27, cpu AIR, emulator, decoder, program digests |

**Combined targets:** D1 + A + D2 = **367 339** rows; with B + B′ the spike's "everything" = **317 315** rows. The
phase's gate is the tier: one inner verification ≤ 524 287 (tier 19). The headroom is the margin for later cuts.

### 1.1 D1 — the cap select

`assert_cap_eq` in `programs/rv32.rs` today computes `Σ_k [index = k] · cap[k]` lane by lane. Replace it with an
address computed from the two cap-index bits: `off = 4·b0 + 8·b1` (`FMUL`/`FADD` of field elements that are known
boolean — `DslChallenger::sample_bits` constrains every bit where it is born), then for each of the four lanes a
register-offset `LOAD [cap0 + lane + off]` compared with the walk's digest lane by `assert_eq`.

**Soundness:** the bits are boolean, so `off ∈ {0, 4, 8, 12}`; the four caps are one contiguous 16-cell allocation
(asserted at build); the cpu AIR range-checks every `LOAD` address. This is the pattern `docs/06` Cut E1 already
ruled sound for the own-slot check. `Precompiles::Off` keeps the dot product as the differential reference.

### 1.2 A — re-homing reloads

On a reload (`Mat` of a spilled handle) the allocator asks `claim` for a real register instead of a scratch one when
the value's next use is nearer than the farthest-next-use resident's; the evicted resident is spilled as today. The
re-homed value keeps its spill cell, so evicting it again costs no `STORE`. Three rules, each with a unit test:

1. never evict a register the current instruction already reads (pin `mat_out` and the instruction's home operands);
2. no re-homing inside an `if_eq` body (the two arms must leave the register file in the same state);
3. inside a loop body, re-home only values defined in the body (a value from outside the loop would change the
   register state across iterations; the aggregate's loop body is the case that matters).

`NUM_REGS` and the scratch set do not change. Every program the DSL emits changes (all program digests), including
the aggregate programs and the self-verifier; `Precompiles::Off` builds get re-homing too (the Off replay is a
differential *arithmetic* reference; its digest moves and is re-pinned like the others).

### 1.3 D2 — no digest copies

`hash::merkle_walk` / `merkle_walk_with_injections` (Precompiles On) stop allocating `cur` and copying the leaf in and
the result out: the walk compresses over the caller's leaf digest in place and **returns** the digest it reached. The
caller (the round reader in `rv32.rs`) takes the returned digest. The leaf digest is a hash-scratch output the caller
does not reuse; that is asserted at build (the walk takes ownership). `tests/precompiles.rs`'s walk test reads the
returned digest instead of the old `out` argument.

### 1.4 B and B′ — immediate addresses

`SPONGE` (opcode 25) and `COMPRESS` (opcode 27) change meaning in their fourth word: `b` becomes the **absolute
address** of the source block (SPONGE) / the sibling digest (COMPRESS) instead of a register index.

- **ISA:** drop both from `Op::b_is_register`; the decoder takes `b` as an immediate field element, range-checked as
  an address like `LOAD`/`STORE`'s. `Op::COUNT` and the selector count do not change.
- **cpu AIR:** drop both from `Sels::B_REG`. The existing immediate-form constraint then binds `B0 = B`, `B1 = 0`; the
  `SPONGE` and `COMPRESS` bus keys and the address-limb range groups already read `B0`. **No new column, no degree
  change**, and one fewer register read per row (one fewer `REG` bus message).
- **Emulator:** read the address from the immediate; `bounded` checks unchanged.
- **DSL:** `sponge`/`compress_step` emit the absolute address (`addr_of` of the `Ptr`, a compile-time constant) and
  stop materialising the holder register.
- **An absolute, not relative, immediate:** a relative form (`A0 + b`) would need a new gated constraint; absolute
  reuses the immediate form already constrained.

**Soundness:** the address was previously a register value constrained by the `REG` bus; it is now a program word,
fixed by the preprocessed program table (the program is public and committed in the verifier key), and still
range-checked. A prover cannot choose it. The cheating suite gains forgeries that move the immediate (a different
block, an out-of-range address) and expect refusal.

## 2. What moves, what does not

**Moves:** every rVM program digest — `verify_rv32.digest`, both `aggregate_program_digest`s (production and test
fixture shapes), the self-verifier digest, the Off-replay digest; the rVM verifier keys (the cpu AIR's `B_REG` set
changes the constraint system); `tests/pins.json` rows, `N3_ROWS`, `LOOP_OVERHEAD` (274 → measured); the self-verifier
`CycleReport` pins; tier assertions in `tests/exit.rs` / `tests/aggregate.rs` / `tests/memprofile.rs` (test N=1
projects to tier 17); the REG table height (2^21 → 2^20 at production, projected). The fullnode re-pins
`aggregate_program_digest` and inherits the rVM key change at the next re-vendor; `admitted_tiers` may move (§4).

**Does not move:** the inner RV32 machine and every wallet proof; `inner_vk_digest`; the interface `[vk ‖ N ‖ B(8) ‖
35·N]`; the FRI profiles (inner 80/8/20, rVM 92/4/24); the quotient layout; the reduce chip; the poseidon2 table
(permutations unchanged, 54 515 a proof).

## 3. Order of work and gates

1. Baseline: the span profile (`tests/profile.rs`) and the exit twin's memprofile on this branch.
2. **D1** (the cap select) — measured; it alone must cross the gate (≤ 524 287), else stop and report.
3. **A** (re-homing) with its three rule tests, plus the allocator suite.
4. **D2** (no copies).
5. **B + B′** (the ISA/AIR change) with the cheating forgeries.
6. Re-pin, the full suite, measurement (profile, twin, the test N=2 and — if it fits this 48 GB box — N=3 aggregates),
   `docs/08`.
7. Fullnode re-vendor.

After each cut the profile is re-run and the row count recorded; each cut lands within ±15 % of its spike delta
(phase 2's band rule) or the report explains the difference.

## 4. The N-economics at the new tier

Projected from the spike (production, labelled): N=1 ≈ 368 k rows (tier 19, was 20), N=2 ≈ 735 k (tier 20, was 21),
N=3 ≈ 1.10 M → ≈ 0.95 M with B + B′ (tier 20, was 21). The node's `admitted_tiers` (production {20, 21, 22} today)
and the reduce chip's N ceiling (5) are re-derived from the measured rows in `docs/08`; the fullnode follow-through
moves `admitted_tiers` to what the measured rungs give.

## 5. Testing

- **D1:** `tests/self_verify.rs` and `tests/verifier.rs` round trips accept honest proofs; a tampered cap entry and a
  tampered cap-index bit are refused at the cap check's named step (new cases in the tamper tables).
- **A:** `tests/allocator.rs` gains one test per rule (§1.2) — each builds a program that would violate the rule and
  checks the emitted code does not; the emulator suite and every program's round trip are the integration evidence.
- **D2:** `tests/precompiles.rs`'s walk test against the returned digest; the On/Off differential still agrees.
- **B/B′:** `tests/isa.rs` (decode of the immediate form, range refusal); `tests/cpu.rs` (the immediate constraint
  binds `B1 = 0` for SPONGE/COMPRESS; the bus keys read the immediate); `tests/cheating.rs` forgeries (an immediate
  moved to another block; an immediate past the address range) refused by `Machine::verify`; the emulator refuses an
  out-of-range immediate by name.
- **Pins asserted unchanged:** `inner_vk_digest`, the interface digest vectors.
- **The suite:** `cargo test --release --no-fail-fast -- --skip a_one_proof_aggregate_round_trips` green; count
  recorded (298 at the rate-¼ end).

## 6. Measurement and documentation

- The span profile after each cut (`docs/measurements/2026-10-1x-span-profile-*.log`).
- The exit twin and the tier-16 synthetic under the heap profiler, before and after (same box, 16 threads).
- The test N=2 aggregate (proved here at rate ¼) and, if the twin's measurement supports it, the test N=3.
- `recursion/docs/08-phase4-spans.md`: the anatomy of §0.1 with the measured numbers, each cut's band, the pins that
  moved, the N-economics, the memory re-projection. Pointers in `docs/06` §7 item 1 and `docs/01`.

## 7. Out of scope (recorded)

- The path-level precompile (`docs/06` §7 item 1's third candidate): ≈ −50 to −56 k alone, less behind A and B, the
  largest AIR surface.
- Compressing injections straight from the hash scratch (≈ −16 k, not built in the spike) — a follow-up if the
  headroom is wanted.
- `POSEIDON2` immediate addresses (same pattern as B; small count in these spans).
- The inner FRI profile; the reduce N ceiling; device-resident LDEs.

## 8. Risks

| risk | closed by |
|---|---|
| re-homing changes register state across `if_eq` arms or loop iterations | the three rules (§1.2) with unit tests; the aggregate loop body's honest round trip and the cheating suite |
| a re-homed eviction picks a register the instruction reads | rule 1 + its test |
| the immediate form lets a prover choose an address | the address is a program word in the preprocessed table; forgeries in `tests/cheating.rs` |
| D2's in-place walk overwrites a digest the caller reuses | build-time ownership assertion; the self-verifier and verifier round trips |
| the spike's numbers do not reproduce on the real implementation | §3's per-cut band rule; the tier gate decides, not the spike |

## 9. Rulings

- Program and ISA cuts only; the inner machine never moves.
- B and B′ use absolute immediates, reusing the existing immediate constraint; no new column.
- `Precompiles::Off` builds take re-homing (their digest moves; their arithmetic reference role is unchanged).
- The tier gate decides; the spike's numbers are the plan's projection.
