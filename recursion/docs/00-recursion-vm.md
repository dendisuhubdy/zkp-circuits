# 00 — The recursion VM (rVM): ISA, emulator, and the measured cost of verifying one bundle proof

The rVM is the field-native machine whose programs verify Rand zkVM proofs (design spec:
`docs/superpowers/specs/2026-09-13-zkvm-m5-recursion-vm-design.md`; the M5.1 plan:
`docs/superpowers/plans/2026-09-13-zkvm-m5-1.md`). M5.1 builds its semantics and its first
program — the RV32-machine verifier — and measures what that program costs per verified inner
proof. The program is built against **constraint set 6** of the inner machine: the `public`
table is a mandatory ninth instance of every shape (last in `chips()` order), every proof
declares a sixth height (`public_log_height`), `pv::NUM` is 34 (`PUB0..7`, the unsalted
`H_PUB`, joins the inner public values), and `Machine::verifier_key` is a 6-tuple. The bundle
proofs the chain admits have an **empty** public segment (`verify_public(hc, &[], _)`) — the
rVM verifies `H_PUB` as ordinary public values (a prover-computed constant of the shape), and
no public-segment words enter the tape.

Every number in this document was measured on 2026-09-14 on this machine (macOS, 16 cores,
48 GB) with the crate's documented command, `cargo +1.98.1 test` run from `recursion/` (debug
profile: the crate itself at `opt-level = 1`, every dependency at `opt-level = 3`), and is pinned
by a test: `tests/pins.json` for the cycle numbers, `src/programs/verify_rv32.digest` for the
program digest.

## Instruction set (spec §3)

Twenty-four instructions; every instruction is one cpu row. Operands are register indices
(`r0..r31`; `r0` is the constant zero) or an immediate field element. `E` denotes an extension
operand: the pair `(r, r+1)`, value `c0 + c1·X`.

| mnemonic | operands | effect |
|---|---|---|
| `FADD FSUB FMUL` | `rd, ra, rb` | base-field arithmetic |
| `FADDI FMULI` | `rd, ra, imm` | base-field arithmetic with an immediate |
| `EADD ESUB EMUL` | `Ed, Ea, Eb` | extension-field arithmetic |
| `EMULF` | `Ed, Ea, rb` | extension × base |
| `INV` | `rd, ra` | `rd = ra⁻¹` as a prover hint; the row constrains `ra·rd = 1` |
| `EINV` | `Ed, Ea` | extension inverse, same hint-and-check shape |
| `MOV` | `rd, ra` | copy |
| `LOAD STORE` | `rd/rs, ra, imm` | memory cell at `ra + imm` |
| `LOADE STOREE` | `Ed/Es, ra, imm` | two consecutive cells |
| `JMP` | `imm` | `pc = imm` |
| `JEQ JNE` | `ra, rb, imm` | branch on base-field equality |
| `HINT` | `rd` | `rd = next witness word` |
| `HINTE` | `Ed` | two witness words |
| `PUBLIC` | `ra` | append `ra` to the public values |
| `POSEIDON2` | `ra` | permute the eight cells at `ra..ra+8` in place |
| `HALT` | — | end |

**Deliberately absent: `FRIFOLD`/`EXPBITS`/`MERKLE` precompiles** — see the decision below.

**Encoding.** One instruction = 4 field elements `[opcode | rd | ra | rb-or-imm]`. Opcode
numbering is the table's reading order, fixed by `Op as u8` (0 = `FADD` … 23 = `HALT`) and pinned
by `tests/isa.rs`; changing it changes every program digest. The program digest is a
padding-free-sponge-shaped Poseidon2 fold over the encoded words with the header in the capacity
lanes (`state = [0,0,0,0, RVM_PROGRAM_DOMAIN=15, n_instructions, 0,0]`, then one permutation per
instruction), exactly mirroring `rand_zkvm::hash::program_digest`.

**Field and memory.** `F = Goldilocks`, `EF = BinomialExtensionField<F, 2>` stored as `(c0, c1)`.
A digest is **4** field elements (spec §12 erratum 1); a commitment is a `MerkleCap` of 4 digests
(16 elements). Memory is a flat array of cells addressed by a field element below
`MEM_LIMIT = 2^24`; `pc` likewise. The DSL's spill arena occupies the first
`dsl::MEM_BASE = 2^22` cells.

## The witness tape (consumption order)

The rVM reads its witness with `HINT` in consumption order — not `Proof::to_bytes`' postcard
order — and commits to nothing about it (spec §2/§10). Fourteen pinned segments
(`src/witness.rs`, pinned by `tests/verifier.rs::the_witness_tape_layout_is_pinned`):

| # | segment | contents |
|---|---|---|
| 1 | `Header` | `tier`, the **six** declared log-heights (program, input, keccak, sha256, **public**, mem), `num_queries`, one word per FRI round's `log_arity` |
| 2 | `PublicValues` | the **34** inner public values (`PC_ENTRY`, `TIER`, `OUT0..7`, `HC0..7`, `IN0..7`, `PUB0..7`) |
| 3 | `Commitments` | `main`, `permutation`, `quotient_chunks`, `random` caps (16 words each) |
| 4 | `LookupTerminals` | one extension element per instance with lookups |
| 5 | `OpenedValues` | per instance: `trace_local`, `trace_next`, `preprocessed_local`, `preprocessed_next`, quotient chunks, `random`, `permutation_local`, `permutation_next` |
| 6 | `RandomOpenings` | the hiding wrapper's 4 hidden values per round / matrix / point (none for `preprocessed`) |
| 7 | `FriCommits` | per FRI round: the commit cap (16) and the commit-phase PoW witness (1, discarded — 0 bits) |
| 8 | `FinalPoly` | one extension coefficient (`log_final_poly_len = 0`) |
| 9 | `QueryPow` | the query grinding witness (1) |
| 10 | `QueryBits` | per sampled element: 64 bit words + 1 canonicality hint — the PoW sample first, then one per query |
| 11 | `InputOpenings` | per query, per round, per matrix: the opened row (public + hidden values) and its 4 salts |
| 12 | `InputPaths` | per query, per round: the restored path's siblings (4 words per Merkle level) |
| 13 | `CommitPhaseOpenings` | per query, per round: `arity − 1` sibling extension values, then the row's 4 salts |
| 14 | `CommitPhasePaths` | per query, per round: the restored path's siblings |

Segments 11–14 are **query-major per segment** (segment 11 holds every query's rows, then segment
12 every query's paths, and so on), so the program reads the four segments in full, in tape order,
before the unrolled per-query loop. Merkle multiproofs are expanded host-side into one full path
per query via `MerkleTreeMmcs::restore_and_recompute_paths` (the plan's ruling; it costs the host
no extra hashing and the program ~46 extra compressions per query against the amortised walk).
The public instance's openings flow through these segments exactly like every other instance's —
one more matrix in the `random`, `main`, `quotient_chunks` and `permutation` rounds.

## The measured number

Per verified inner proof (one RV32 bundle proof; **9 instances**, the public table last, no
keccak/sha256 tables; degree bits `[13,15,17,16,9,9,17,11,3]`,
`log_global_max_height = 20`, arity schedule `[1,1,2,2,2,3,3,3]`), from the emulator's own event
log:

| | `FriProfile::Test` (16 queries) | `FriProfile::Production` (80 queries) |
|---|---:|---:|
| cpu rows | 441 643 | **1 968 619** |
| Poseidon2 permutations | 11 205 | **51 605** |
| memory accesses | 597 021 | 2 705 197 |
| program instructions | 443 686 | 1 978 422 |
| witness words read | 43 344 | 199 760 |
| tape words | 43 344 | 199 760 |

The program is straight-line in the proof's data: every proof of the shape costs the same rows
(asserted by the exit test on 5 test-profile and 50 production-profile proofs). The production
row is pinned in `tests/pins.json`; the production program's digest
(`Checkpoints::Off`, `8901cec9c1681c9674f1e5582805d625c60b20d9f69be546da982622f36e0bda`) in
`src/programs/verify_rv32.digest`.

**M5.2 Task 4 re-pin (2026-09-14, ruling R5).** The table above is the *current* program's
measurement, re-taken after phase 8 changed from thirty-nine raw `PUBLIC` rows to the
four-element **interface digest**: the §4.4 list (vk digest, `N`, the 34 inner public values) is
stored, sponged with a capacity-seeded header (`RVM_PUB_DOMAIN = 17`, the `Program::digest`
construction — the proof's batch public values are always exactly those four elements, the cs6
`H_PUB` pattern; the node recomputes the list from the covered bundles and compares digests).
The measured delta against the M5.1 measurement: +174 cpu rows (5 682 847 → 5 683 021), +10
permutations (51 595 → 51 605, `ceil(39/4)`), +355 memory accesses; witness and tape unchanged.
The pre-R5 numbers remain the ones in the "Where the rows go" and "precompile decision" sections
below — their structure (the reduction and spill terms) is untouched by phase 8, and M5.2's Tasks
7–9 re-measure everything again anyway.

**M5.2 Task 7 re-pin (2026-09-15, liveness).** The table above is *re-measured again* after the
two-pass allocator landed: the replay frees a handle's register at its last use (clamped out of
loop bodies) and reuses spill cells by width, and the `Off` policy reproduces the pre-liveness
stream byte for byte (pinned by `tests/verifier.rs` against the pre-Task-7 digest). Measured
delta against the Task-4 row above: **cpu rows 5 683 021 → 4 052 455 (−28.7 %)** — 66 % of the
measured 2 454 511 spill/reload rows die, against the plan's ~3.6 M estimate (it guessed
85–90 %; the survivor is real register pressure in the reduction and the loop-carried
accumulators) — and **memory accesses 6 354 392 → 3 488 864 (−45 %)**; permutations and witness
unchanged. Test profile: 1 210 045 → 858 343 rows. The Task-8 gate (`rows > 2^21 · 0.75` =
1 572 864) **fires** at 4 052 455, exactly as the plan predicted, and the exit still needs tier 22
after this task alone.

**M5.2 Task 8 re-pin (2026-09-15, the `REDUCE` precompile).** The table above is *re-measured
again* with the batch-opening reduction in its chip (opcode 24, appended): one chip row per
column instead of the compiled loop, gated on Task 7's measurement, differentially pinned to
`run_reduce_sequence` (`tests/precompiles.rs`) which stays in the tree as the compiled reference.
Measured delta against the Task-7 row above: **cpu rows 4 052 455 → 2 240 988 (−44.7 %)** — the
compiled reduction was 1 811 467 rows post-liveness (~11.6 per column, more than the plan's ~7
estimate, so the cut beats the plan's ~2.5 M) — and **memory accesses 3 488 864 → 3 008 239**;
permutations and witness unchanged. Test profile: 858 343 → 496 028 rows. The exit is still 6.9 %
over tier 21's 2^21 = 2 097 152, and the Task-9 gate **fires** at 2 240 988 — as the plan
predicted.

**M5.2 Task 9 re-pin (2026-09-15, the `SPONGE` precompile).** The table above is *re-measured
again* with the leaf-sponge absorb loop in the poseidon2 chip's second row kind (opcode 25,
appended): one `SPONGE` per four-lane absorb block, gated on Task 8's measurement,
differentially pinned to `PaddingFreeSponge` (`tests/precompiles.rs`) with the compiled loop kept
as `dsl::hash::sponge_compiled`. Measured delta against the Task-8 row above: **cpu rows
2 240 988 → 1 968 619 (−12.1 %)** — 272 369 rows of absorb bookkeeping (~8.8 per absorb block;
the plan's ~0.55 M estimate guessed ~15–20) — and **memory accesses 3 008 239 → 2 705 197**;
permutations and witness unchanged. Test profile: 496 028 → 441 643 rows. **The exit now fits
tier 21: 1 968 619 < 2^21 = 2 097 152, with 6.1 % headroom** — the plan's target, landed.

### Where the rows go

Per-phase split of the program's instructions (the program is straight-line apart from assertion
traps, so these are also the cpu rows per phase), and the executed opcode histogram, both measured:

| phase | Test | Production |
|---|---:|---:|
| 0–4: header, transcript, commitments, terminal sum | 2 525 | 2 525 |
| 5: constraint evaluation at `zeta` | 38 983 | 38 983 |
| 6 preamble: claimed evals, betas, final poly, PoW, indices | 67 738 | 140 794 |
| query segments: tape reads | 79 936 | 399 680 |
| queries: Merkle walks, reduction, folds | 1 021 836 | 5 109 772 |
| 8: §4.4 public values | 895 | 895 |

| opcode | Test | Production | opcode | Test | Production |
|---|---:|---:|---|---:|---:|
| `FADD` | 15 663 | 78 063 | `MOV` | 68 996 | 328 836 |
| `FSUB` | 26 011 | 129 643 | `LOAD` | 256 889 | 1 194 393 |
| `FMUL` | 25 106 | 125 138 | `STORE` | 213 626 | 998 330 |
| `FADDI` | 14 594 | 62 402 | `LOADE` | 109 841 | 504 017 |
| `FMULI` | 1 839 | 8 943 | `STOREE` | 247 848 | 1 163 880 |
| `EADD` | 36 270 | 168 750 | `JEQ` | 2 043 | 9 803 |
| `ESUB` | 34 233 | 164 281 | `HINT` | 39 420 | 195 836 |
| `EMUL` | 101 270 | 482 262 | `HINTE` | 1 962 | 1 962 |
| `EMULF` | 2 006 | 9 686 | `PUBLIC` | 39 | 39 |
| `INV` | 128 | 640 | `POSEIDON2` | 11 195 | 51 595 |
| `EINV` | 891 | 4 347 | `HALT` | 1 | 1 |

The allocator spilled 1 525 260 handles and reloaded 929 251 of them at the production profile
(3 026 015 spill-arena cells; the arena is `2^22`, raised from `2^20` precisely for this phase —
the FRI reduction creates ~10 handle slots per opened column per query). The `LOAD`/`STORE` and
`LOADE`/`STOREE` rows are dominated by that spill traffic and by the memory-structured hashing and
tape reads.

Inside the query phase the dominant term is the batch-opening reduction,
`Σ α^k (p_at_z − p_at_x)(z − x)⁻¹` over every (round, matrix, point, column): the shape opens
**1 952** columns per query (main round 1 084, random 54, quotient chunks 408, preprocessed 42,
permutation 364 — the public instance's rounds and the cpu table's 51 new columns are the cs6
growth), so the reduction and its spill traffic are ≈ 2.8 M rows (~50% of the total). The Merkle
work (leaf sponges, walks, injections, commit-phase rows) is ≈ 1.3 M; `sample_bits`' 64-bit
canonical decompositions are ≈ 94 k; the fold rounds themselves are ≈ 100 k.

## The exit tests and their wall time

`tests/exit.rs`, against real bundle proofs produced by `Machine::prove` (disk-cached under
`recursion/target/recursion-fixtures`; the cs6 fixtures were regenerated — the cs5 files were
**deleted**, and would anyway have failed `load_cached`'s re-verification against the cs6
machine — at a cost of ~45–75 s per proof):

- `five_test_profile_bundle_proofs_are_accepted` — in-suite, ~11 s for the file.
- `thirteen_tampered_test_profile_proofs_are_refused_at_the_named_step` — in-suite, same run.
- `fifty_production_profile_bundle_proofs_are_accepted` — `#[ignore]`d; with a warm cache the
  whole ignored suite (this test, the 50-proof tamper test, and the budget test) runs in
  **under a minute** (measured 2026-09-14).
- `fifty_tampered_production_proofs_are_refused_at_the_same_step_as_the_native_verifier` —
  `#[ignore]`d; every tamper refused at its named checkpoint.
- `the_cycle_budget_per_inner_proof_is_pinned` — `#[ignore]`d; ~22 s alone; writes and then
  asserts `tests/pins.json` and `src/programs/verify_rv32.digest`.

Two test-level deviations from the plan's text, both forced and documented where they live: the
tamper table uses the *measured* refusal steps (a transcript-moving tamper is caught at the first
constraint binding the tape to the moved transcript — `"sample_bits decomposition"` or
`"quotient identity[0]"` — not at the plan's per-segment names; `Header` and
`CommitPhaseOpenings` are dynamic in `k`), and the `Checkpoints::On` subsequence check normalizes
branch targets to relative offsets (absolute `JEQ` immediates shift under inserted checkpoint
`PUBLIC`s, so literal instruction equality can never hold).

## The precompile decision

**Measured: 5 682 847 cpu rows per inner proof at the production profile — 10.8× over the 2^19
(524 288) decision point.** The spike's ~180 000-row model under-counted by ~31×: it carried no
term for the FRI batch-opening reduction (~2.8 M rows here, the single largest item) and none for
the allocator's spill/reload traffic (~50% of arithmetic rows). Spec §7 says that above 2^19,
Task 7 adds the `FRIFOLD`/`EXPBITS` precompiles and re-measures with the assertion that the count
then falls under 2^19. **Task 7 was not implemented, because that assertion is unreachable:** the
fold rounds `FRIFOLD` would replace are ≈ 100 k rows (1.8%) and the bit-selected exponentiations
`EXPBITS` would replace are ≈ 64 k rows (1.1%) of 5 682 847 — even at zero cost they land at
~5.5 M, still 10.5× over. Constraint set 6 grew the count by 8.2% (the public instance's rounds
and the cpu table's 51 new columns) and changes nothing of the structure. The decision point's
premise (a count near 2^18 that two precompiles might push under 2^19) does not hold; what
actually dominates is the reduction's per-column extension arithmetic and the spill traffic,
which neither precompile touches. If the 2^19 target is real, the options are a
batch-inversion/reduction precompile, liveness in the allocator, or a larger aggregate tier — a
protocol-level decision for M5.2, armed with the numbers above. The budget test pins the regime
this decision was made in (`cpu_rows > 2^19`) so a future optimization that changes it is forced
to revisit this paragraph.

## What M5.1 hands to M5.2

- A frozen 24-instruction ISA with a pinned encoding and a program digest, and an emulator that
  is the reference semantics for the five AIRs M5.2 writes.
- A verifier program for **constraint-set-6** proofs whose acceptance and refusal behaviour is
  pinned against the native verifier on 50 real production-profile proofs (50 accepted, 50
  tampered refused at named steps), plus in-suite twins at the test profile.
- Measured `cpu_rows`, `permutations`, `mem_accesses` and `witness_words` per inner proof
  (above), replacing spec §7's cost model: `TIERS`, `poseidon2_log_height` and the memory table's
  height are cut from these, and they say one inner proof wants ~2^23 cpu rows, not 2^19.
- The precompile question answered with a measurement: not `FRIFOLD`/`EXPBITS`.

**Superseded (M5.2 built, 2026-09-15).** The machine this section hands to exists now: the ISA
is at 26 instructions (`REDUCE` = 24, `SPONGE` = 25; 0–23 frozen), the program is three row cuts
smaller (5 682 847 → 1 968 619, tier 21), and the measured machine numbers — tables, buses,
tiers, widths, degrees, the three cuts' deltas and gates, the test-profile twin's times and proof
size, and the production exit's derived resource requirement — live in
`docs/01-rvm-machine.md`. This section remains as the record of what M5.1 actually handed over.
