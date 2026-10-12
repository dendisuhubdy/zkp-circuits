# Phase 5 row cuts — priced (2026-10-12, circuits f77ea14 = phase 4 + MODQ, production, 80 queries)

Baseline (tests/profile.rs, unmodified): 315 391 cpu rows per production inner verification, 54 598 perms, 212 455 witness
words, 662 040 REG accesses; Test profile 104 229. Production aggregate, emulated over cached fixture 0 (twice for N=2, so
no new proving): N=1 315 718 (tier 19), N=2 631 053 (tier 20). Goal: N=2 in tier 19 (≤ 524 287) ⇒ inner ≤ ~262 000, a cut
of ≥ ~53 400 (−17 %).

## Baseline anatomy (production, per query = /80)
- `sample_bits` 53 013 (662/query): 64 hinted bits × (LOAD, FADDI, FMUL, FSUB+JEQ), two 32-bit Horners (124), the 31-mul
  all-ones product, canonicality, decomposition ≈ 490 rows of work + 159 rows of spill/reload (65 spills, 94 reloads/query):
  the 64 bit handles, and the ~19 returned index bits, live until the query phase.
- `input_root` 90 250 (1 128/query, 5 rounds): SPONGE 420, COMPRESS 115 (90 levels + 25 injections), STORE 268, LOAD 224,
  FADDI 30, FSUB/JEQ 20/20, POSEIDON2 16, FMULI/FADD 10/5. The LOAD/STOREs, exactly: 30 sponges/query (5 leaves + 25
  injections) × (4 zeroing STOREs + 4 LOAD + 4 STORE copying the digest out of the hash scratch) = 120 + 240; 16 partial
  tail blocks copied into the rate, 28 LOAD + 28 STORE; cap compare 40 LOADs; reloads 36. FADDI: one `alloc` per
  injection's tmp digest (25) and per leaf (5). So S2's copy-outs are 240 rows/query; zeroing is another 120.
- `commit_root` 34 960 (437/query, 9 rounds): COMPRESS 88, SPONGE 28, LOAD 136, STORE 72 (9 × (4 zero + 4 copy-out)),
  cap compare 9 × (2 FMULI, FADD, 4 × (LOAD, LOAD, FSUB, JEQ)).
- `(none)` 98 127: tape reads (HINTN 24 350; 2 321 arrays with an `n mod 8` tail, 8 003 tail words ⇒ 16 006 HINT+STORE rows),
  phase 5's extension arithmetic, the preamble's observations. Phase 6 preamble 82 151 = `sample_bits` 53 013 + 29 138.
- `reduce` 20 001, `fold_round` 4 320, `select` 6 400, `bit_selected_power` 5 280, `roll_in` 3 040 (left alone).
- `assert_eq` everywhere is `FSUB t, a, b; JEQ t, r0` — 11 244 FSUBs in all, though the cpu's equality gadget already
  compares `D0` (rd) with `A0` (ra), so `JEQ a, b` alone is the same check.

## Candidates (Δ rows from 315 391; each alone on f77ea14, built on the real program, run on the real production fixture, honest proof accepted)
| # | candidate | rows | Δ | alone crosses −53.4k? | consensus surface |
|---|---|---:|---:|---|---|
| S1a | `sample_bits` streamed: same 64-bit checks, each bit loaded, checked and folded into its Horner / all-ones product at once; index bits re-loaded from the bits buffer at each query's start | 299 385 | −16 006 | no | program digests only |
| S1a′ | S1a with booleanity as `b·b = b` (FMUL + JEQ under S6a; algebraically the same check) | — | −5 120 more (in combination) | no | digests only |
| S1b | decompose only the `bits` (= 19) used bits; remainder in range-checked limbs via `LOAD r0, [v + imm]`; canonicality by `L = (H − (2^32−1))·u` (§ soundness) | 276 905 | −38 486 | no | digests + QueryBits tape format (65 → bits + 4 words per index); no ISA, no AIR |
| S2 | each injection compressed straight from the hash scratch's lanes 0..4 (no tmp digest, no copy-out) | 297 391 | −18 000 | no | digests only |
| S2b | S2 + each leaf sponged in its own 8-cell state (zeroed) and walked in place (input and commit leaves, 14/query) | 288 271 | −27 120 | no | digests only |
| S2b-fresh | S2b without zeroing (fresh cells read zero) | 277 711 | −37 680 | no | **rejected**: `verify_rv32n` runs the body in `counted_loop_mem`, so the cells are not fresh for proof 2 |
| S3 | `POSEIDON2` state address as an immediate (emulator + builder; AIR unbuilt) | 315 391 | 0 | no | ISA + cpu AIR — not worth it: every POSEIDON2 pointer has delta 0 and a resident holder |
| S4a | hint tails two words at a time, `HINTE` + `STOREE` (same tape, same cells) | 307 869 | −7 522 | no | digests only |
| S4b | (priced) pad every tail to a whole `HINTN` block: 2 321 arrays, 16 006 → 2 321 rows | ≈301 706 | ≈ −13 685 | no | digests + tape (+10 565 unconstrained pad words, never absorbed: the sponge reads only `n` cells) |
| S5 | (priced) path-level precompile: 14 walks/query, 203 COMPRESS → 14 rows | ≈300 300 | ≈ −15 100 | no | ISA + cpu + poseidon2 AIR |
| S6a | `assert_eq(a, b)` as one `JEQ a, b` (the trap row is unchanged) | 305 267 | −10 124 | no | digests only |

No candidate crosses alone; the biggest, S1b, is 72 % of the cut.

## Combinations (measured together)
| package | inner rows | Δ | N=1 aggregate | N=2 aggregate | REG accesses |
|---|---:|---:|---|---|---:|
| SW = S1a′ + S2b + S6a + S4a (digests only, tape unchanged) | 254 698 | −60 693 | 255 024 (tier 18) | 509 665 (tier 19, 14 622 headroom) | 541 813 |
| ALL = S1b + S2b + S6a + S4a | 237 018 | −78 373 | 237 344 (tier 18) | 474 305 (tier 19, 49 982 headroom) | 497 013 |
SW without S1a′ (S1a): 259 818. ALL's alone-sum is −83 252; the 4.9k overlap is S6a's FSUBs inside `sample_bits`, which S1b removes.
Test profile: SW 92 016, ALL 88 480 (tier 17). Perms unchanged (54 598); RAM 1 721 705 → 1 679 138 (still 2^21). Projections
(rows = N × inner + ~300): ALL N=3 ≈ 711k, N=4 ≈ 948k (tier 20), N=5 ≈ 1.19M (tier 21); SW N=4 ≈ 1.019M (tier 20, thin).
N=2's REG accesses (≈ 2 × 497k) fall under 2^20 with ALL — the REG table halves too (projection; not traced at N=2).
Where ALL leaves it (production): `sample_bits` 12 275 (153/query), `input_root` 65 919, `commit_root` 26 080, `reduce` 21 598
(+1 597: the lazily re-loaded index bits now spill inside the query; an allocator follow-up).

## S1b soundness
Sampled `x ∈ F_p`, `p = 2^64 − 2^32 + 1`, `B = bits` (8 ≤ B ≤ 32; 19 here). Tape: `b_0..b_{B−1}` (into the 65-cell bits
buffer the POW runs read), then `a, h0, h1, u`. Constraints:
1. `b_k·(b_k − 1) = 0` for each k (one JEQ trap each).
2. Ranges, each a `LOAD r0, [v + imm]` row, whose address `v + imm` the cpu AIR proves `< 2^24` with its three RANGE8 limbs
   (the existing LOAD/STORE subject check; r0 drops the value): `a + 0`, `a + 2^24 − 2^(32−B)` ⇒ `a < 2^(32−B)`;
   `h0 + 0` ⇒ `h0 < 2^24`; `h1 + 0`, `h1 + 2^24 − 2^8` ⇒ `h1 < 2^8`. (The pair is needed: `v + c < 2^24` alone admits
   `v ∈ [p − c, p)`; with `v < 2^24` too, `v ∈ [0, 2^24 − c)`.)
3. `L := Σ b_k 2^k + 2^B·a`, `H := h0 + 2^24·h1`; then `L_int < 2^32` and `H_int < 2^32` with no wrap.
4. `L + 2^32·H = x` (decomposition) and `L = (H − (2^32 − 1))·u` (canonicality).

Let `X = L_int + 2^32·H_int < 2^64 < 2p`. By (4) `X ≡ x`, so `X = x_c` or `X = x_c + p`. If `X ≥ p` then `H_int = 2^32 − 1`
(`H_int ≤ 2^32 − 2` gives `X ≤ 2^64 − 2^32 − 1 < p`) and `L_int ≥ 1`; but `H = 2^32 − 1` makes the canonicality constraint read `L = 0` — the
Goldilocks alias (high half all ones, low half non-zero) is refused for every `u`. So `X = x_c` and the index
`Σ b_k 2^k = x_c mod 2^B` is unique — exactly p3's `sample_bits`. Completeness: the honest `a, h0, h1` are the canonical
limbs; `u = L/(H − (2^32 − 1))`, or 0 when `H = 2^32 − 1` (then `L = 0` for a canonical `x`, `x = p − 1` included).
Cost: 31 rows of hints (2 HINTN + 3 tail pairs + 4 HINT) + per bit LOAD/FADDI/FMUL/JEQ + Horner 2 + 5 range LOADs + 6
composition + 4 canonicality ≈ 150/query (measured 160 alone, 153 in ALL). New: the address range check is *used* as a value
range check (and reads up to cell 2^24 − 1, harmless reads); no AIR column or ISA word changes. The PoW `check_witness`
sample still takes the 64-bit path (one call). A cheaper `H ≠ 2^32 − 1` by one INV would save 2 rows/query but fail
completeness at `x = p − 1` (probability 1/p); not taken.

S1a, S1a′, S2, S2b, S4a and S6a change no check: S1a reorders the same constraints; `b·b = b` ⇔ `b(b−1) = 0`; S2/S2b hash the
same cells into the same digest (the leaf's 8-cell state is zeroed exactly as the hash scratch was); S4a writes the same words
to the same cells; S6a's `JEQ a, b` is the cpu equality gadget on `D0 − A0` that `FSUB` + `JEQ t, r0` computed in two rows.

## Validated
- Profile (emulation, honest production proof accepted) for every candidate and both packages: logs in the scratch dir
  `p5/*-profile.log` (`head-profile.log` the baseline).
- Production aggregate emulated at N=1 and N=2 (fixture 0 twice; the interface digest equals the host's) for baseline, SW and
  ALL: `p5/{baseline,combo-sw,combo-all}-n2.log`. This is what caught S2b-fresh (the second iteration's cells are not fresh).
- S1b: `tests/spike_s1b.rs` (in the S1b and ALL patches) — honest at B ∈ {8, 19, 20, 24, 27, 32} on 200 random `x` and the
  edges `0, 1, 2, 2^32−2, 2^32−1, 2^32, p−2, p−1`; equal to `DuplexChallenger::sample_bits` on random transcripts; refuses
  the alias `X = x + p` for every `u` tried, an index shifted into `a` (out of range), into `h0` (out of range), `h1`
  overflowing with `h0` compensating, and a non-boolean bit; and the gadget proves and verifies on the rVM (Test profile),
  with a forged limb on its range-LOAD row refused.
- Suites: S1b alone — dsl 21/21, cheating 102/102, transcript 14/14; S2b alone — dsl, cheating, precompiles 17/17, transcript;
  SW and ALL — allocator 11/11, cheating 102/102, dsl 21/21, emulator 25/25, transcript 14/14, spike_s1b 5/5 (ALL).
  Expected failures only: `verifier.rs` digest pins (aggregate digest, Off replay), `precompiles.rs`
  `hint_array_via_hintn_matches_the_compiled_pairs`'s row pin (S4a; values and words read match), and under S1b
  `the_query_bit_segment_decodes_to_the_sampled_query_indices` (the old 65-word QueryBits format) and the Off-precompile
  replay's acceptance (its 64-bit `sample_bits` reads the new tape).
- Not run: any rVM proof of the production program (spike rule); the N=2 aggregate over two distinct fixtures.

## Recommendation
Build phase 5 as one program-only package, in the order S6a → S2b → S4a → S1b (with S1a′'s `b·b = b`, ≈ −1.5k more):
237 018 rows per inner verification, production N=1 in tier 18 and **N=2 in tier 19 with ≈ 50k headroom** (N=4 projected
into tier 20). Nothing touches the ISA or an AIR; the consensus surface is program digests plus the QueryBits tape format.
If S1b's argument is not accepted, SW (S1a′ in its place) also reaches tier 19 at N=2, with only 14 622 rows (2.8 %) of
headroom. Do not build S3 (nothing to cut) or S5 (not needed; largest AIR surface). S4b (tape padding, ≈ −6k beyond S4a) and
an allocator fix for the lazily loaded index bits (≈ 1.6k) are follow-ups if more headroom is wanted.
Patches: `2026-10-12-phase5-{s1a-stream,s1b-lowbits,s2-inject-scratch,s2b-leaf-states,s3-poseidon2-imm,s4a-hinte-tails,
s6a-assert-jeq,combo-sw,combo-s1b-s2b-s6a-s4a}.patch` (each against f77ea14; s2b includes s2; the combos include the spike tests).
