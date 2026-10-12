# rVM phase 5 — the production N=2 aggregate in tier 19

**Date:** 2026-10-12. **Scope:** `recursion/` (the rVM's DSL, the verifier programs, the witness tape), then the
fullnode re-vendor. **Base:** circuits `main` f77ea14 (phase 4 + MODQ). **Decided with the operator:** build the
spike's program-only package, S6a → S2b → S4a → S1b. No ISA word and no AIR changes. The priced spike behind every
number here is `recursion/docs/measurements/2026-10-12-phase5-spike-findings.md` (commit 89c40fb on
`spike/rvm-phase5`). Each candidate there was built on the real program, run through the emulator on the real
production fixture, and accepted the honest proof. §6 below makes the measurement the record.

## 0. Why

Phase 4 (`docs/09`) took one production inner verification to **315 391 cpu rows (tier 19)**. The production
aggregate costs about N × inner + 300 rows, so N=2 is **631 053 rows (tier 20)**. The tier-19 gate is
`≤ 2^19 − 1 = 524 287`, so N=2 needs **inner ≤ ≈ 262 000**: a cut of at least ≈ 53 400 rows (−17 %) per inner
verification.

Crossing the gate puts the two-proof aggregate one tier lower, which halves its prover memory and its trace. N=2 is
the shape the node batches most.

### 0.1 Where the rows go (production, 80 queries; per query = /80)

- **`sample_bits` 53 013 (662/query).**
  - The program hints all 64 bits of each sampled element and checks each one boolean, in four rows a bit.
  - It runs two 32-bit Horners, the 31-multiplication all-ones product and the canonicality check.
  - About 159 rows a query are spill traffic: 64 bit handles stay live until the query phase.
  - Only `bits` = 19 of the 64 bits are ever used.
- **`input_root` 90 250 (1 128/query).**
  - 30 sponges a query (5 leaves + 25 injections), each paying 4 zeroing STOREs plus 4 LOAD + 4 STORE to copy its
    digest out of the shared hash scratch: 360 rows a query.
  - The 25 injection digests also cost an `alloc` (FADDI) each.
- **`commit_root` 34 960 (437/query):** 9 × (4 zero + 4 copy-out) STOREs and their LOADs.
- **Tape tails:** 2 321 hinted arrays end in an `n mod 8` tail, read one word at a time: 8 003 words, 16 006
  HINT + STORE rows.
- **`assert_eq` is two rows everywhere** (`FSUB t, a, b; JEQ t, r0`): 11 244 FSUBs. The cpu's equality gadget
  already compares `rd` with `ra`, so `JEQ a, b` alone makes the same check.

## 1. The four cuts

Each cut was measured alone and then all four together. The combined number is the design's target, re-measured in §6.

| cut | what | Δ alone (from 315 391) | consensus surface |
|---|---|---:|---|
| **S6a — one-row `assert_eq`** | `assert_eq(a, b)` emits `JEQ a, b`; the trap row is unchanged | −10 124 | program digests |
| **S2b — sponge in place** | each injection is compressed straight from the hash scratch's lanes (no tmp digest, no copy-out); each input and commit leaf is sponged in its own zeroed 8-cell state and walked in place | −27 120 (S2 alone −18 000) | program digests |
| **S4a — paired tails** | tape tails are hinted two words at a time with `HINTE` + `STOREE`: same tape, same cells | −7 522 | program digests |
| **S1b — low-bits `sample_bits`** | for query indices, decompose only the `bits` used bits; range-check the rest with LOAD addresses; canonicality by `L = (H − (2^32−1))·u`; booleanity as `b·b = b` | −38 486 | program digests **+ the `QueryBits` tape format** |

**Combined (measured in the spike):**

| | inner | N=1 | N=2 |
|---|---:|---|---|
| Target | **237 018 rows** (−78 373) | 237 344 rows, tier 18 | **474 305 rows, tier 19, 49 982 headroom** |

The alone-sum is −83 252. The 4.9 k overlap is S6a's FSUBs inside `sample_bits`, which S1b deletes. The phase's
gate is the tier: the production N=2 aggregate ≤ 524 287 rows, measured in emulation.

### 1.1 S6a — `assert_eq` as one `JEQ`

`Builder::assert_eq` (and every helper that lowers to it) emits `JEQ a, b`, which traps unless `a == b`, instead of
`FSUB t, a, b` followed by `JEQ t, r0`. The cpu's equality gadget constrains `D0 − A0` to be zero or invertible and
selects the branch on it. One row now computes what the FSUB + JEQ pair computed in two. The allocator no longer
reserves the scratch `t`. **Soundness:** unchanged; the check is the AIR's own equality gadget, and the trap row is
the same.

### 1.2 S2b — no copy-outs, leaves in their own state

- **Injections (S2):** the walk hashes an injected matrix row into the shared hash scratch. Today its 4-lane digest
  is copied out into a fresh `alloc`, then compressed. Instead, the walk's `COMPRESS` reads the digest straight from
  the scratch's lanes 0..4. This removes the copy-out and the alloc.
- **Leaves (S2b):** each input and commit leaf (14 a query) is sponged in its own 8-cell state. The state is zeroed
  exactly as the hash scratch is today, and the Merkle walk then runs over that state's lanes 0..4 in place (phase
  4's D2 walk). This removes the remaining copy-outs.
- **The zeroing is load-bearing:** `verify_rv32n` runs its body inside `counted_loop_mem`, so a leaf state is not
  fresh on the second proof. The spike's no-zeroing variant (S2b-fresh) was rejected for exactly this. A test that
  emulates an N=2 aggregate with **two distinct fixtures** pins it (§5).
- **Soundness:** the same cells are hashed into the same digests from the same starting state.

### 1.3 S4a — paired tape tails

The `n mod 8` tail of each hinted array is read by `HINTE` (two words) + `STOREE` (two cells) per pair, plus one
`HINT` + `STORE` for an odd last word. The tape and the cells written are unchanged, so this is a lowering change in
`hint_array` only. The `precompiles.rs` row pin for `hint_array_via_hintn_matches_the_compiled_pairs` moves; its
value and word-count assertions do not.

### 1.4 S1b — decompose only the used bits

For each query-index sample `x ∈ F_p` (`p = 2^64 − 2^32 + 1`) with `B = bits` (8 ≤ B ≤ 32; 19 at production), the
tape carries `b_0..b_{B−1}`, written into the existing 65-cell bits buffer, then `a, h0, h1, u`. The program
constrains:

1. **Booleanity:** `b_k · b_k = b_k` for each k (FMUL + one-row JEQ).
2. **Ranges:** each range is a `LOAD r0, [v + imm]` row. The cpu AIR already proves every LOAD address `< 2^24`
   with its three RANGE8 limbs, and `r0` discards the value.
   - `a` at `+0` and at `+(2^24 − 2^(32−B))`, so `a < 2^(32−B)`.
   - `h0` at `+0`, so `h0 < 2^24`.
   - `h1` at `+0` and at `+(2^24 − 2^8)`, so `h1 < 2^8`.

   Each bound needs the pair: `v + c < 2^24` alone admits `v ∈ [p − c, p)`.
3. **Halves:** `L := Σ b_k 2^k + 2^B·a` and `H := h0 + 2^24·h1`. So `L_int < 2^32` and `H_int < 2^32`, with no wrap.
4. **Decomposition and canonicality:** `L + 2^32·H = x`, and `L = (H − (2^32 − 1))·u`.

**Argument.** Let `X = L_int + 2^32·H_int`, so `X < 2^64 < 2p`. By (4), `X ≡ x`, so `X = x_c` or `X = x_c + p`.

- `X ≥ p` forces `H_int = 2^32 − 1` and `L_int ≥ 1`, because `H_int ≤ 2^32 − 2` gives `X < p`.
- But `H = 2^32 − 1` makes the canonicality constraint read `L = 0`, for every `u`. So the Goldilocks alias is
  refused.
- Hence `X = x_c`, and the index `Σ b_k 2^k = x_c mod 2^B` is unique. That is exactly p3's `sample_bits`.

**Completeness:** the honest `a, h0, h1` are the canonical limbs. `u = L / (H − (2^32 − 1))`, or `u = 0` when
`H = 2^32 − 1`; then `L = 0` for every canonical `x`, `x = p − 1` included.

**What is new.** The cpu's address range check is used as a *value* range check. The reads go up to cell
`2^24 − 1`, which is harmless because `r0` drops them. No AIR column or ISA word changes. The argument above is
restated in `docs/10` and checked by the tests in §5.

**What stays on the 64-bit path:** the PoW `check_witness` sample, one call a proof. Its tape entry stays 65 words.

**Tape format (consensus):** `Segment::QueryBits` goes from 65 words per sampled element to 65 for the PoW sample
plus `B + 4` per query index. The writer (`witness.rs`, `sampled_bits` and a new low-bits sibling) and the reference
decoder test move together. The tape is built host-side in this crate, and the fullnode vendors it. No wire format
outside the crate carries it.

**Not taken:** a cheaper `H ≠ 2^32 − 1` check by one INV would save 2 rows a query but fails completeness at
`x = p − 1` (probability 1/p).

**Fallback (operator's call at this spec's review):** if S1b's argument is not accepted, swap in S1a′ (stream the
64-bit checks, booleanity as `b·b = b`; digests only, tape unchanged). The spike measured that package at
254 698 inner and N=2 at 509 665 (tier 19, only 14 622 headroom).

## 2. What moves, what does not

**Moves:**

- Every rVM program digest: `verify_rv32.digest`, both `aggregate_program_digest`s (production and test fixture
  shapes), the self-verifier digest, the Off-replay digest, and the tree step programs' digests.
- `tests/pins.json` rows, `N3_ROWS` and `LOOP_OVERHEAD`; the self-verifier `CycleReport` pins.
- Tier assertions (production N=1 → 18; test N=1 → 17).
- The `QueryBits` segment length and its decoder test.
- The REG table at production N=2: ≈ 2 × 497 k accesses, so 2^20 instead of 2^21 (projection; traced in §6).

**Does not move:**

- The ISA: every opcode keeps its meaning. Unlike phase 4, no instruction word is reinterpreted.
- The cpu, memory, poseidon2 and reduce AIRs, and so the rVM verifier keys' constraint systems.
- The inner RV32 machine, every wallet proof and `inner_vk_digest`.
- The interface `[vk ‖ N ‖ B(8) ‖ 35·N]`, the FRI profiles (inner 80/8/20, rVM 92/4/24) and the permutation count
  (54 598 a proof).

**Re-vendor hazard:** a tape written by the pre-phase-5 writer does not decode under the new program, and the reverse
is also true. The program digest moves, so a mismatched pair is refused at the digest pin. The re-vendor still drops
every pre-phase-5 cached digest and tape fixture, as phase 4 did for its keys (`docs/09` §5).

## 3. Order of work and gates

1. **Baseline:** the span profile on this branch (315 391) and the production N=1/N=2 emulated aggregate.
2. **S6a**, the DSL lowering, with the allocator and dsl suites.
3. **S2b** (S2 first, then the leaf states), with the two-fixture N=2 emulation test.
4. **S4a**, the `hint_array` lowering.
5. **S1b**, the gadget, the tape writer and the soundness tests (§5). The PoW path is untouched.
6. Re-pin, the full suite, measurement (§6), and `docs/10`.
7. Fullnode re-vendor (separate repo, after the operator merges).

After each cut, the profile is re-run and the row count recorded. Each cut must land within ±15 % of its spike delta
(phase 2's band rule), measured against the cuts already landed, or the report must explain the difference. **Gate
after step 5:** the production N=2 aggregate (two distinct fixtures, emulated) is ≤ 524 287 rows. If it is not, stop
and report.

## 4. The N-economics at the new tier

Projected from the spike (production, labelled; rows ≈ N × 237 k + 300):

| N | rows | tier |
|---:|---:|---:|
| 1 | ≈ 237 k | 18 (was 19) |
| 2 | ≈ 474 k | 19 (was 20) |
| 3 | ≈ 711 k | 20 |
| 4 | ≈ 948 k | 20 (was 21) |
| 5 | ≈ 1.19 M | 21 |

`docs/10` re-derives the node's `admitted_tiers` ({19, 20, 21} after phase 4) from the measured rows; projected
{18, 19, 20, 21}. The fullnode follow-through moves it.

## 5. Testing

- **S6a:**
  - The dsl and allocator suites.
  - `tests/cheating.rs` unchanged and green. A forged unequal pair at an `assert_eq` site traps (one new case).
- **S2b:**
  - `tests/precompiles.rs`'s walk and sponge tests against the in-place digests; the On/Off differential agrees.
  - **New:** a production-shape N=2 aggregate emulated over two *distinct* fixtures, with each interface digest
    equal to the host's. A leaf state left dirty from proof 1 would fail this.
- **S4a:** the `hint_array` value and word-count tests; the moved row pin.
- **S1b** (the spike's `tests/spike_s1b.rs`, promoted to `tests/sample_bits.rs`):
  - Honest at B ∈ {8, 19, 20, 24, 27, 32} on random `x` and the edges `0, 1, 2, 2^32−2, 2^32−1, 2^32, p−2, p−1`.
  - Equal to `DuplexChallenger::sample_bits` on random transcripts.
  - Refuses: the alias `X = x + p` for every `u` tried; an index shifted into `a`; one shifted into `h0`; `h1`
    overflowing with `h0` compensating; a non-boolean bit.
  - On the rVM (Test profile): the gadget proves and verifies; a forged limb on its range-LOAD row is refused by
    `Machine::verify`.
- **Tape:** `the_query_bit_segment_decodes_to_the_sampled_query_indices` is rewritten for the new layout; the
  witness-tape layout pin moves.
- **Pins asserted unchanged:** `inner_vk_digest`, the rVM AIR constraint counts, the interface digest vectors and the
  perm count.
- **The suite:** `cargo test --release --no-fail-fast -- --skip a_one_proof_aggregate_round_trips` green, with the
  count recorded (344 at the phase-4 end).

## 6. Measurement and documentation

- The span profile after each cut (`docs/measurements/2026-10-1x-phase5-profile-*.log`).
- The production N=1 and N=2 aggregates in emulation, two distinct fixtures, with the REG and RAM heights traced.
- The exit twin and the tier-16 synthetic under the heap profiler, before and after, on this box. Anything over
  ≈ 20 GB runs from the operator's Terminal.
- The test N=2 aggregate proved at rate ¼ (test N=2 projected tier 17).
- The production proofs stay unmeasured until the ≥ 256 GB host is back; `docs/10` labels the production memory as a
  projection.
- `recursion/docs/10-phase5-n2-tier19.md` records:
  - §0.1's anatomy with measured numbers, and each cut's band;
  - S1b's argument;
  - the pins that moved, and the tape change;
  - the N-economics and `admitted_tiers`;
  - the re-vendor checklist.

  Pointers go in `docs/09` §7 and `docs/01`.

## 7. Out of scope (recorded)

- **S5, the path-level precompile:** ≈ −15 k, and the largest AIR surface; not needed.
- **S3, `POSEIDON2` immediates:** measured 0.
- **S4b, padding tape tails to whole `HINTN` blocks:** ≈ −6 k beyond S4a; a tape change. A follow-up if more
  headroom is wanted.
- **The allocator's lazily re-loaded index bits:** `reduce` +1 597 under S1b; an allocator follow-up.
- Device LDEs, the inner FRI profile and the reduce N ceiling.

## 8. Risks

| risk | closed by |
|---|---|
| S1b's range-by-address argument has a hole | §1.4's argument, the refusal tests, the forged-limb rVM proof; review of `docs/10`'s restatement; SW fallback measured |
| a leaf state is not zeroed on a later loop iteration | zeroing kept; the two-fixture N=2 emulation test |
| S6a's one-row `JEQ` differs from FSUB + JEQ at an edge (`a`, `b` in r0) | the equality gadget reads `D0 − A0`; a dsl test for `assert_eq(x, 0)` and `assert_eq(0, x)`; the cheating suite |
| the tape writer and program disagree on the new layout | one writer function per layout, the decoder test, every round trip |
| the spike's numbers do not reproduce | §3's per-cut band rule; the tier gate decides |

## 9. Rulings

- Program and tape cuts only: no ISA word, no AIR column, and no change to the inner machine.
- S1b applies to query-index samples only; the PoW sample keeps the 64-bit path.
- `Precompiles::Off` builds take S6a, S2b and S4a (their digests move). They keep the 64-bit `sample_bits` as the
  differential reference, so the Off tape keeps the 65-word `QueryBits` layout. The writer takes the layout from the
  program it targets.
- The tier gate decides; the spike's numbers are the plan's projection.
