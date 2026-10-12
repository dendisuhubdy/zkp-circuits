# 10 — Phase 5: the production N=2 aggregate in tier 19

Design: `docs/superpowers/specs/2026-10-12-rvm-phase5-design.md`. Plan:
`docs/superpowers/plans/2026-10-12-rvm-phase5.md`. Branch `spike/rvm-phase5`, on circuits `main`
`f77ea14` (phase 4 plus the MODQ chip). The priced spike behind every expected figure is
`docs/measurements/2026-10-12-phase5-spike-findings.md` (commit `89c40fb`). Every row count here
comes from the emulator's event log through `tests/profile.rs`
(`cargo test --release -p recursion --test profile -- --ignored --nocapture`), run after each cut
and copied to `docs/measurements/2026-10-12-phase5-profile-{baseline,s6a,s2b,s4a,s1b,final}.log`.
Every production aggregate figure is a B3 emulation from `tests/aggregate.rs`, logged as
`2026-10-12-phase5-n2-{baseline,s2b,s1b}.log` and `2026-10-12-phase5-prod-n{2,3}-emulate.log`.
Every pin is in `tests/pins.json` or a test literal. No production proof was run. Every memory and
proving figure is marked **pending operator run** (§8), and every other number that was not
measured is labelled a projection.

**Result:** one verified production inner proof dropped from **315 391 to 235 418 cpu rows**
(−25.4 %). The production N=2 aggregate dropped from **631 053 rows (tier 20) to 471 105 (tier
19)**, with 53 182 rows of headroom under the gate (`≤ 2^19 − 1 = 524 287`). The production N=1
aggregate is now **tier 18** (235 744 rows). Four cuts, each in its ±15 % band: S6a, `assert_eq`
as one `JEQ` (−10 124); S2b, sponges in their own state (−27 120); S4a, paired tape tails
(−7 522); S1b, query indices decomposed on their used low bits only (−35 207). No ISA word and no
AIR changed, so the rVM verifier keys did not move. Every program digest moved, and the
`QueryBits` tape segment changed layout (§4). Poseidon2 permutations are unchanged at 54 598 a
proof.

## 0. Why

Phase 4 (`docs/09`) and the MODQ re-pin left one production inner verification at **315 391 cpu
rows** (tier 19; `2026-10-12-phase5-profile-baseline.log`). The production aggregate costs N × inner
plus a loop overhead of a few hundred rows, so N=2 was **631 053 rows, tier 20**
(`2026-10-12-phase5-n2-baseline.log`, two distinct fixtures). The tier-19 gate is
`2^19 − 1 = 524 287`, so N=2 needed one inner verification at ≈ 262 000 rows or less: a cut of at
least ≈ 53 400 rows (−17 %).

Crossing the gate puts the two-proof aggregate one tier lower, which halves its cpu table and every
trace term sized by it. N=2 is the shape the node batches most.

## 1. The anatomy (the spec's §0.1, measured)

Production fixture, 80 queries, the `== profile Production` section of
`2026-10-12-phase5-profile-baseline.log` (per query = /80):

| span | cpu rows | /query | what the rows are |
|---|---:|---:|---|
| `sample_bits` | 53 013 | 662.7 | all 64 bits of each sampled element hinted and checked boolean; two 32-bit Horners; the all-ones product and the canonicality check. 7 553 reloads and 5 193 spills (≈ 159 rows a query) keep the 64 bit handles live into the query phase. Only `bits` = 19 of the 64 bits are used. |
| `input_root` | 90 250 | 1 128.1 | 30 sponges a query (5 leaves + 25 injections), each with 4 zeroing STOREs and a 4 LOAD + 4 STORE copy of its digest out of the shared hash scratch; one `alloc` (`FADDI`) per injection digest. `STORE` 21 454, `LOAD` 17 915, `FADDI` 2 401. |
| `commit_root` | 34 960 | 437.0 | 9 rounds a query, each with 4 zeroing and 4 copy-out STOREs and their LOADs. `LOAD` 10 880, `STORE` 5 760. |
| `(none)` (tape reads and the rest) | 98 127 | 1 226.6 | among them 2 321 hinted arrays ending in an `n mod 8` tail, read one word at a time: 8 003 tail words, 16 006 `HINT` + `STORE` rows (the spike's count). |
| everywhere | — | — | `assert_eq` is two rows (`FSUB t, a, b; JEQ t, r0`): 11 244 `FSUB` rows in the program. The cpu's equality gadget already compares `rd` with `ra`, so `JEQ a, b` alone makes the same check. |

The other spans were left alone: `reduce` 20 001, `select` 6 400, `bit_selected_power` 5 280,
`fold_round` 4 320, `roll_in` 3 040. Builder totals: 23 559 reloads, 9 114 spills, `live_max` 25.

## 2. The four cuts

Each Δ is measured against the cuts already landed. The bands are the plan's ±15 % of the spike's
expected Δ.

| after | cpu rows | expected Δ | measured Δ | band | verdict | `sample_bits` | `input_root` | `commit_root` | `(none)` | reloads | log |
|---|---:|---:|---:|---|---|---:|---:|---:|---:|---:|---|
| baseline | 315 391 | — | — | — | — | 53 013 | 90 250 | 34 960 | 98 127 | 23 559 | `-profile-baseline` |
| S6a | 305 267 | −10 124 | **−10 124** | −8 605 … −11 643 | in (0.0 %) | 47 586 | 88 650 | 32 080 | 97 910 | 23 559 | `-profile-s6a` |
| S2b | 278 147 | −27 120 | **−27 120** | −23 052 … −31 188 | in (0.0 %) | 47 586 | 67 529 | 26 080 | 97 911 | 23 399 | `-profile-s2b` |
| S4a | 270 625 | −7 522 | **−7 522** | −6 394 … −8 650 | in (0.0 %) | 47 586 | 67 529 | 26 080 | 90 389 | 23 399 | `-profile-s4a` |
| S1b | **235 418** | −35 127 | **−35 207** | −29 858 … −40 396 | in (+0.2 %) | 10 675 | 65 919 | 26 080 | 92 105 | 14 424 | `-profile-s1b` |

The final profile (`2026-10-12-phase5-profile-final.log`, re-run for this record on `f001206`)
reads the same 235 418 rows, 54 598 permutations, 1 679 138 mem accesses, 493 813 REG accesses,
209 175 witness words and 243 391 program instructions as the S1b log. The total is 1 600 rows
under the spike's combined 237 018, which is S1a′'s `b·b = b` booleanity the plan subtracted
(19 bits × 80 queries = 1 520) plus 80 rows. The test profile followed: 104 229 → **88 160** rows
(baseline and final logs, `== profile Test`).

The production N=2 aggregate after each cut, emulated over two distinct fixtures:

| after | N=2 cpu rows | tier | log |
|---|---:|---:|---|
| baseline | 631 053 | 20 | `2026-10-12-phase5-n2-baseline.log` |
| S2b (S6a + S2b) | 556 563 | 20 | `2026-10-12-phase5-n2-s2b.log` |
| S1b (all four) | **471 105** | **19** | `2026-10-12-phase5-n2-s1b.log`; re-run for this record in `2026-10-12-phase5-prod-n2-emulate.log` |

**S6a — `assert_eq` as one `JEQ`** (`Builder::assert_eq`, `dsl/builder.rs`). `assert_eq(a, b)`
emits `JEQ a, b` over the trap instead of `FSUB t, a, b; JEQ t, r0`. The cpu's equality gadget
constrains `D0 − A0` to be zero or invertible and selects the branch on it, so one row makes the
check two made. The trap row is unchanged. `FSUB` fell from 11 244 to 1 120 rows (the remaining
1 120 are `reduce`'s own subtractions). *Soundness:* unchanged; the check is the AIR's own
equality gadget. Test: `tests/dsl.rs::assert_eq_is_one_jeq_over_the_trap_in_either_order`.

**S2b — sponges in their own state** (`dsl/hash.rs` `sponge_state` and the walk's `On` branch;
`programs/rv32.rs` `emit_input_round_root`, `emit_commit_root`). Each injection is compressed
straight from the hash scratch's lanes 0..4, with no temporary digest and no copy-out. Each input
and commit leaf (14 a query) is sponged in its own 8-cell state, zeroed exactly as the hash
scratch is, and the Merkle walk runs over that state's lanes 0..4 in place (phase 4's D2 walk).
`input_root` fell 88 650 → 67 529 and `commit_root` 32 080 → 26 080. *Soundness:* the same cells
are hashed into the same digests from the same starting state. The zeroing is load-bearing:
`verify_rv32n` runs its body inside `counted_loop_mem`, so a leaf state is not fresh on the second
proof; the spike's no-zeroing variant was rejected for exactly that. Tests:
`tests/precompiles.rs::sponge_state_matches_padding_free_sponge_and_survives_reuse`,
`merkle_walk_via_compress_matches_the_compiled_walk` (a second injection leaves `max_addr` where
one injection left it, so no temporary digest is allocated per injection), and the production N=2
emulation over two distinct fixtures, which asserts each interface digest equals the host's.

**S4a — paired tape tails** (`Builder::hint_array_padded`). The `n mod 8` tail of each hinted array
is read by `HINTE` + `STOREE` two words at a time, plus one `HINT` + `STORE` for an odd last word.
The tape and the cells written are unchanged; only the lowering moved. `(none)` fell 97 911 →
90 389. The pair of scratch registers is taken after `s` from the sequential scratch bump, so it
cannot overlap it. Test: `tests/precompiles.rs::hint_array_via_hintn_matches_the_compiled_pairs`
(row pin moved; its value and word-count assertions did not).

**S1b — query indices on their used low bits** (`dsl/transcript.rs` `low_bits_gadget`,
`low_bits_tape`, `DslChallenger::sample_index_bits`; `Builder::range_load`; `witness.rs`
`Writer::low_bits`; `programs/rv32.rs`). For each query-index sample only the `bits` used bits are
decomposed, and the rest of the element is carried in three range-checked limbs and a canonicality
witness. `sample_bits` fell 47 586 → 10 675 rows, the reloads 23 399 → 14 424 and the spills
9 114 → 5 682. The PoW `check_witness` sample, one a proof, keeps the 64-bit path. §3 gives the
argument. `reduce` rose 20 001 → 21 598 (+1 597): the index bits are now loaded from their buffer
inside each query, and some spill there. That is the allocator follow-up in §7.

## 3. S1b's argument in full (the code's "`docs/10` §S1b")

Let `p = 2^64 − 2^32 + 1`, `x ∈ F_p` the sampled element, `x_c` its canonical representative, and
`B = bits` with 8 ≤ B ≤ 32 (19 at production). The tape carries `b_0 … b_{B−1}` (written into the
existing 65-cell bits buffer), then `a, h0, h1, u`: `B + 4` words. The program constrains:

1. **Booleanity:** `b_k · b_k = b_k` for each k (one `FMUL` and one `JEQ`).
2. **Ranges.** Each range check is a `LOAD r0, [v + imm]` row (`Builder::range_load`). The cpu AIR
   already proves every LOAD address `< 2^24` with its three RANGE8 limbs, and `r0` discards the
   value read. The checks are `a + 0` and `a + (2^24 − 2^(32−B))`, so `a < 2^(32−B)` (the second
   row is skipped when `32 − B = 24`, where the first already gives it); `h0 + 0`, so `h0 < 2^24`;
   `h1 + 0` and `h1 + (2^24 − 2^8)`, so `h1 < 2^8`. Each bound needs both rows of its pair:
   `v + c < 2^24` alone admits `v ∈ [p − c, p)`, and adding `v < 2^24` leaves `v ∈ [0, 2^24 − c)`.
3. **Halves:** `L := Σ b_k 2^k + 2^B·a` and `H := h0 + 2^24·h1`. By (1) and (2), `L_int < 2^32` and
   `H_int < 2^32` as integers, with no wrap.
4. **Decomposition and canonicality:** `L + 2^32·H = x`, and `L = (H − (2^32 − 1))·u`.

**Soundness.** Let `X = L_int + 2^32·H_int`, so `X < 2^64 < 2p`. By (4), `X ≡ x (mod p)`, so
`X = x_c` or `X = x_c + p`. If `X ≥ p`, then `H_int = 2^32 − 1` (because `H_int ≤ 2^32 − 2` gives
`X ≤ 2^64 − 2^32 − 1 < p`) and `L_int ≥ 1`. But `H = 2^32 − 1` makes the canonicality constraint
read `L = 0·u = 0`, for every `u`. So the Goldilocks alias — high half all ones, low half non-zero
— is refused, whatever `u` the prover chooses. Hence `X = x_c`, and the index `Σ b_k 2^k` equals
`x_c mod 2^B`, which is exactly p3's `DuplexChallenger::sample_bits(B)`.

**Completeness.** The honest `a, h0, h1` are the canonical limbs of `x_c`. The honest `u` is
`L / (H − (2^32 − 1))`, or `0` when `H = 2^32 − 1`; in that case `L = 0` for every canonical `x`,
`x = p − 1` included, so (4) holds. A cheaper check of `H ≠ 2^32 − 1` by one `INV` would save two
rows a query but fail completeness at `x = p − 1`; it was not taken.

**The one free witness word.** Every tape word except `u` is fixed by the constraints once `x` is
fixed. `u` is free only at `x_c = p − 1`, where `H − (2^32 − 1) = 0` and `L = 0`, so (4) holds for
every `u`. That freedom is harmless: `u` feeds nothing but the canonicality constraint, and the
index is already fixed by the bits.

**Cells past `bits` in the buffer.** `low_bits_gadget` writes cells `0 … B−1` of the 65-cell buffer
and only allocates the rest; cell 64 is the `POW` runs' output. A read of a cell past `B` is not a
prover choice: the memory AIR forces the first read of a fresh address to zero. And the build
refuses it anyway: `index_power` asserts that no `POW` run reads past the bits `sample_index_bits`
wrote.

**What is new.** The cpu's address range check is used as a *value* range check. The reads go up
to cell `2^24 − 1`, inside the address space, and `r0` drops them. No AIR column and no ISA word
changed. The argument covers 8 ≤ B ≤ 32 only (`a < 2^(32−B)` needs `32 − B ≤ 24`, and p3 requires
`2^B < |F|`); any other width is refused when the program is built.

**The tests that pin each step** (`tests/sample_bits.rs`, unless named otherwise):

| step | test |
|---|---|
| completeness, edges included | `honest_random_and_edges`: B ∈ {8, 19, 20, 24, 27, 32} on random `x` and `0, 1, 2, 2^32−2, 2^32−1, 2^32, p−2, p−1` |
| equal to p3 | `matches_native_challenger`: `sample_index_bits` against `DuplexChallenger::sample_bits` on random transcripts |
| (4), the alias refusal | `refuses_the_non_canonical_alias`: `X = x + p` with `u ∈ {0, 1, L}` at B ∈ {8, 19, 32} |
| (2) and (3), the ranges | `refuses_a_shifted_index_or_limb`: an index shifted into `a`; an index difference absorbed by `h0`; `h1` overflowing with `h0` compensating |
| (1), booleanity | `refuses_a_shifted_index_or_limb`, case 4: a non-boolean bit carrying the low half |
| the range LOAD is a real check | `the_gadget_proves_and_verifies_on_the_machine`: the gadget proves and verifies on the rVM (Test profile), and a forged RANGE8 limb on a range-LOAD row is refused |
| the width bound | `a_width_below_eight_is_refused_at_build`, `a_width_above_thirty_two_is_refused_at_build` |
| the tape | `the_tape_is_the_bits_then_four_limbs`; `tests/verifier.rs::the_query_bit_segment_decodes_to_the_sampled_query_indices` |
| no read past the written bits | `tests/precompiles.rs::a_pow_run_past_the_written_index_bits_is_refused_at_build` |

The `Precompiles::Off` replay reads the same tape (spec §9 ruling). Its acceptance half passed in
the Task 5 suite (124.66 s): both builds accepted a real Production proof with equal public values.

## 4. What moved

**No ISA or AIR change; the rVM verifier keys are unchanged.** Every opcode keeps its meaning (unlike
phase 4, no instruction word is reinterpreted). The cpu, memory, poseidon2 and reduce AIRs did not
change, and `tests/verifier_key.rs`, the `inner_vk_digest` pins and the interface digest vectors
passed with no edit. The inner RV32 machine, every wallet proof, the interface
`[vk ‖ N ‖ B(8) ‖ 35·N]`, the FRI profiles and the permutation count (54 598 a production proof)
did not move.

**Every program digest moved** (old from `f77ea14`, new from `f001206`):

| program | before | after | where |
|---|---|---|---|
| `verify_rv32.digest` | `79ebe02be4b90dfe13c26f42d00225995fd884c76984326b6a8147b8135d283b` | `c3065887a6a9885233d30cad9d09d864c72f0f2f0ea451d0c2e2f94595a01b24` | `src/programs/verify_rv32.digest` |
| production `aggregate_program_digest` (`verify_rv32n`) | `8bc2cecbd30b975ec15a5e11354434bd7e1c2814d46dd0acc1d92b3ff944d8c7` | `792a66d4a995c7b3874d38ecb8c971d5494b57b4cce13db11e08a4f9b2f9a982` | `tests/aggregate.rs` |
| test-shape aggregate digest | `e26f37e3682a42d2f9835dca49ac0ad7408ca27f24bc34867d5f2efb28a241a0` | `b4988faa0476692a20e285d920685110111d4a648d6687c6230bfceb055ea69b` | `tests/verifier.rs` |
| Off replay | `ac1f08cfc4aa66420718102d8b2eef9e157fb0a3aa94568c762e1313364fd406` | `40532641a13595decf6f131cfa8d5eeb7a0930ef9713c42a80da11bca20cd482` | `tests/verifier.rs` |
| self-verifier | `515fc2a1adaeabcdd4e186c9ba699199f284285f9f968c4ea07a279988bbd32c` | `890d66fc75b37ef4b49fbdcecd104c43ebd33a23a2fca1468397d5e1b401b6e5` | `tests/self_verify.rs` |
| `rv32t_leaf` (`T_LEAF_TEST`) | `d8d558eecb8fbdaaba7eaa93d7d04bae0a47808f31978ecea804f04f7e6e5d93` | `af535052d2df18b5e313a6f0c2e412456d059d5f602d569989ad1b2b69e90cac` | `tests/tree.rs` |
| `rv32t_int` (`T_INT_TEST`) | `a222637e1eb9333b16b820bbacceaac9ea0e5d4cebfc5379d170796a2ac6dc62` | **not re-recorded**: needs the regenerated test-tree fixtures (§5) | `tests/tree.rs` |

**The `QueryBits` tape layout changed** (consensus, between the tape writer and the program).
Before: 65 words per sampled element (64 bits and the canonicality hint) for the PoW sample and
for every query index. After: 65 words for the PoW sample, then `bits + 4` words per query index
(the `bits` low bits, then `a, h0, h1, u`), so the segment is `65 + num_queries·(bits + 4)` words.
`Writer::low_bits` writes it from `low_bits_tape`, the same function the tests drive. A tape
written by the pre-phase-5 writer does not decode under the new program, and the reverse is also
true. The digest pin refuses a mismatched pair, since the program digest moved with the layout.

**Row and tier pins** (`tests/pins.json`, `tests/aggregate.rs`, `tests/exit.rs`,
`tests/self_verify.rs`):

| pin | before | after |
|---|---|---|
| one inner verification (production) | 315 391 rows, tier 19 | **235 418, tier 18** (26 725 rows under `2^18 − 1`) |
| — mem accesses / REG accesses / witness words / program instrs | 1 721 705 / 662 040 / 212 455 / 326 964 | 1 679 138 / 493 813 / 209 175 / 243 391 |
| — permutations | 54 598 | 54 598 |
| `phase3_attribution` | reg 662 040; reduce 20 001; bit_selected_power 5 280; commit_root 34 960; sample_bits 53 013; reloads 23 559; spills 9 114 | 493 813; 21 598; 5 281; 26 080; 10 675; 14 424; 5 682 (select, fold_round unchanged) |
| production N=1 aggregate | 315 718, tier 19 | **235 744, tier 18** (measured; overhead 326) |
| production N=2 aggregate (B3) | 631 053, tier 20 | **471 105, tier 19** |
| production N=3 aggregate (B3) | ≈ 946 500 by arithmetic (3 × 315 391 + 327), tier 20 | 706 466, tier 20 |
| test aggregates N=1/2/3 (rows) | 104 556 / 208 729 / 312 902 | 88 486 / 176 589 / 264 692 (tiers 18 / 18 / 19 unchanged: there is no tier-17 rung) |
| `LOOP_OVERHEAD` | 327 | 326 |
| `N3_ROWS` | 312 902 | 264 692 |
| self-verifier toy `CycleReport` | (66 560, 6 008, 222 897, 68 568, 23 775) | (52 318, 6 008, 216 086, 53 462, 22 975) |
| self-verifier busy `CycleReport` | (77 285, 7 578, 256 092, 79 685, 29 479) | (61 300, 7 578, 248 006, 62 932, 28 775) |
| `tree_test` child / `rv32t_leaf` step | 91 034 / 182 444 rows | 74 605 / 149 586 rows (tier 18, overhead 376) |
| `tree_measure` (production, emulated) | leaf 632 175 (20); rv32r 347 673 (19), child 347 358; step 695 097 (20) | leaf 471 105 (19); rv32r 254 493 (18), child 254 177; step 508 735 (19); band 432 420 … 585 040 (tiers 19, 19, 20) |

**One move is measured but not traced to an instruction.** `LOOP_OVERHEAD` (N=1 aggregate rows
less one verification's) went 327 → 326 at both shapes (test 88 486 − 88 160; production
235 744 − 235 418). Bisection by single-site reverts put it at S2b's `emit_commit_root` leaf
sponge (the 8-cell `sponge_state` in place of the 4-cell digest copy); reverting that site alone
restores 327. The exact instruction, an interaction of the 8-cell allocation with the loop's cells,
was not traced. The self-verifier's phase-5 instruction counts moved (7 929, 8 209) → (7 915,
8 195), consistent with S6a but not attributed.

## 5. Re-vendor checklist

The fullnode follow-through (`deploy/sync-zkvm.sh`, `CIRCUITS_PIN`) applies these in one change:

- **Drop every pre-phase-5 cached program digest and tape fixture.** A pre-phase-5 tape does not
  decode under the new program (§4), and the reverse is also true. This covers the production
  `aggregate_program_digest` `8bc2cecb…` and any older value (phase 4's `e0eede8b…` and earlier,
  `docs/09` §5), `verify_rv32.digest` `79ebe02b…`, and every cached witness tape or tape fixture built by the pre-phase-5 writer. The rVM verifier keys did not change, so no key needs to be
  dropped for this phase's sake; the program digest pin is what refuses a stale program.
- **Re-pin `aggregate_program_digest`** to
  `792a66d4a995c7b3874d38ecb8c971d5494b57b4cce13db11e08a4f9b2f9a982`, and keep the startup (or
  pin-test) assertion that the admitted digest equals the circuits pin.
- **Move `admitted_tiers` from {19, 20, 21} to {18, 19, 20, 21}.** From the measured rungs: N=1 is
  tier 18 (235 744), N=2 tier 19 (471 105), N=3 tier 20 (706 466). From the projections in §6: N=4
  tier 20 and N=5 tier 21. The N ≤ 5 ceiling is unchanged (§6), so no valid production aggregate
  is tier 22, and tier 18 is now one.
- **The test-profile tree section waits on the fixture regeneration.** The 12 fixture-gated tests
  in `tests/tree.rs` are red until the operator regenerates the test-tree fixtures
  (`cargo test --release --test tree generate_test_tree_fixtures -- --ignored --nocapture`,
  ≈ 34 GB, then copy `tree/` into `$RECURSION_FIXTURES`). After that, these pins are still stale
  and must be re-recorded from its output: `T_INT_TEST`; `tree_test` `step_int_cpu_rows`,
  `step_int_tier`, `step_leaf_reduce_rows_per_child`, `step_int_reduce_rows_per_child` and
  `step_proof_bytes_max`; and the `vk_leaf`, `vk_t_leaf` and `vk_int` limbs (the step keys commit to
  the step programs, which moved). The fullnode's test-profile `aggregation_tree` section and
  `tests/tree-test-genesis.json` follow those values, not this record.
- The production tree's digests and its fixed-point level are still unmeasured (the 256 GB host,
  `docs/08` §4); the emulated production tree rows are in §4.

## 6. N-economics

Production cpu rows per aggregate. N=1 is the measured
`the_production_n1_aggregate_is_the_m52_pin_plus_loop_overhead` run (Task 5), N=2 and N=3 are the
B3 emulations (`2026-10-12-phase5-prod-n2-emulate.log`, `-prod-n3-emulate.log`):

| N | cpu rows | tier | headroom under the tier | before phase 5 | source |
|---:|---:|---:|---:|---|---|
| 1 | 235 744 | **18** | 26 399 | 315 718, tier 19 (spike baseline) | measured |
| 2 | 471 105 | **19** | 53 182 | 631 053, tier 20 | emulated |
| 3 | 706 466 | 20 | 342 109 | tier 20 (948 071 at phase 4, `docs/09` §5) | emulated |
| 4 | ≈ 941 827 | **20** | ≈ 106 748 | tier 21 | **projection** |
| 5 | ≈ 1 177 188 | 21 | ≈ 919 963 | tier 21 | **projection** |

Each further proof adds 235 361 rows (N=2 − N=1 = N=3 − N=2, exactly), so N=4 and N=5 are
arithmetic, not emulations. The N=3 emulation also reports 163 740 permutations, 5 036 642 mem
accesses and 627 534 witness words; N=2 reports 109 170, 3 357 986 and 418 359. Both stay inside
the `2^27` timestamp window (max ts 7 537 695 and 11 303 471).

**The reduce chip's N ceiling does not move.** The reduce rows are a compile-time function of the
program. Phase 5 changed no `REDUCE`, `FOLD` or `POW` dispatch (9 520, 720 and 1 280 in both the
baseline and the final log), and `the_production_reduce_heights_and_n_ceiling_are_pinned` still
passes at 196 960 reduce rows a proof. So `REDUCE_MAX_LOG_HEIGHT = 20` still caps production at
**N ≤ 5** (6 × 196 960 + 1 > 2^20). (The `reduce` *span*'s cpu rows rose by 1 597, §2; that is
allocator traffic around the dispatches, not reduce-chip rows.)

**Table heights (projection).** At N=2 the REG accesses are ≈ 2 × 493 813 ≈ 988 k, under `2^20`,
so the N=2 REG table is projected to halve with the cpu table. This is arithmetic on the
single-proof count; the N=2 emulation does not print REG accesses. The N=2 RAM table (3 357 986
accesses) stays `2^22`.

**Memory (projection).** No production proof was run. `docs/09` §5 projected the production N=1
aggregate between ≈ 32 and 75 GB at tier 19; at tier 18 the cpu table and every term sized by it
halve again, while the RAM table does not. Production memory stays a projection until a proof runs on a larger
host.

## 7. Out of scope, recorded

- **S5, the path-level precompile:** ≈ −15 k rows (spike, priced), and the largest AIR surface
  (ISA, cpu and poseidon2 AIR). Not needed for the gate.
- **S3, `POSEIDON2` immediate addresses:** measured 0 in the spike; every `POSEIDON2` pointer has
  delta 0 and a resident holder.
- **S4b, padding tape tails to whole `HINTN` blocks:** ≈ −6 k beyond S4a (spike, priced), and a
  tape change. A follow-up if more headroom is wanted.
- **The allocator's lazily re-loaded index bits:** `reduce` +1 597 under S1b (§2). An allocator
  follow-up.
- Device LDEs, the inner FRI profile and the reduce N ceiling.
- **The fullnode re-vendor** (§5): its own task after merge.

## 8. Testing and the runs for this record

- **The suite** (Task 5, after the re-pin): `cargo test --release --no-fail-fast -- --skip
  a_one_proof_aggregate_round_trips` — **344 passed, 12 failed, 31 ignored**. The 12 failures are
  exactly the fixture-gated `tests/tree.rs` tests, each panicking with "rvmproof is missing or
  stale" until the operator regenerates the test-tree fixtures (§5). `tests/backend.rs` passed 3
  each under `--features reference-backend` and `--features mock-cuda`.
- **New tests:** `tests/sample_bits.rs` (8, §3); `tests/dsl.rs::assert_eq_is_one_jeq_over_the_trap_in_either_order`;
  `tests/precompiles.rs::sponge_state_matches_padding_free_sponge_and_survives_reuse` and
  `a_pow_run_past_the_written_index_bits_is_refused_at_build`. Rewritten:
  `tests/verifier.rs::the_query_bit_segment_decodes_to_the_sampled_query_indices`,
  `tests/precompiles.rs::merkle_walk_via_compress_matches_the_compiled_walk` and
  `hint_array_via_hintn_matches_the_compiled_pairs`.
- **Emulations run for this record** (each 1 passed, 0 failed):
  `production_n2_aggregate_emulates_within_bounds` — 471 105 rows, tier 19
  (`2026-10-12-phase5-prod-n2-emulate.log`); `production_n3_aggregate_emulates_within_bounds` —
  706 466 rows, tier 20 (`-prod-n3-emulate.log`); the profile — 235 418 production rows
  (`-profile-final.log`). All three equal their pins.
- **Pending operator run.** The proved and heap-profiled runs can exceed 20 GB and were not run
  from the agent. Their numbers are **pending operator run**:

  | run | log | figures |
  |---|---|---|
  | exit twin (Test profile) under the heap profiler | `2026-10-12-phase5-twin.log` | peak live heap, prove wall, verify, proof bytes: pending operator run |
  | tier-16 synthetic under the heap profiler | `2026-10-12-phase5-tier16.log` | peak live heap, prove wall, proof bytes: pending operator run |
  | test N=2 aggregate (176 589 rows, tier 18), proved and verified natively | `2026-10-12-phase5-test-n2-prove.log` | proof bytes, wall: pending operator run |

  The commands, from `~/rand-worktrees/circuits-phase5/recursion`:

  ```bash
  RAYON_NUM_THREADS=16 cargo test --release --features parallel --test memprofile -- --ignored --nocapture tier19_exit_twin 2>&1 | tee docs/measurements/2026-10-12-phase5-twin.log
  RAYON_NUM_THREADS=16 cargo test --release --features parallel --test memprofile -- --ignored --nocapture tier16_synthetic_threads 2>&1 | tee docs/measurements/2026-10-12-phase5-tier16.log
  RAYON_NUM_THREADS=16 cargo test --release --features parallel --test aggregate -- --ignored --nocapture two_test_profile_bundle_proofs_aggregate_and_verify_natively 2>&1 | tee docs/measurements/2026-10-12-phase5-test-n2-prove.log
  ```

## Conclusion

Phase 5 put the production two-proof aggregate in **tier 19: 471 105 rows**, 53 182 under the gate,
by four program and tape cuts that each landed in their band — three to the row, S1b 0.2 % past its
estimate. One inner verification fell from 315 391 to 235 418 rows, so the production N=1 aggregate
is tier 18. Not one hash was added or removed, and no ISA word or AIR changed, so the rVM verifier
keys stayed put; every program digest and the `QueryBits` layout moved. The node's admitted tiers
become {18, 19, 20, 21} under the unchanged N ≤ 5 ceiling, once the re-vendor drops every
pre-phase-5 digest and tape. The proved runs on this box, the test-tree fixtures and every
production memory figure are pending.
