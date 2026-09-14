# 00 — The recursion VM (rVM): ISA, emulator, and the measured cost of verifying one bundle proof

The rVM is the field-native machine whose programs verify Rand zkVM proofs (design spec:
`docs/superpowers/specs/2026-09-13-zkvm-m5-recursion-vm-design.md`; the M5.1 plan:
`docs/superpowers/plans/2026-09-13-zkvm-m5-1.md`). M5.1 builds its semantics and its first
program — the RV32-machine verifier — and measures what that program costs per verified inner
proof. Every number in this document was measured on 2026-09-14 on this machine (macOS, 16 cores,
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
| 1 | `Header` | `tier`, the five declared log-heights, `num_queries`, one word per FRI round's `log_arity` |
| 2 | `PublicValues` | the 26 inner public values |
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

## The measured number

Per verified inner proof (one RV32 bundle proof; 8 instances, no keccak/sha256 tables;
`log_global_max_height = 20`, arity schedule `[1,1,2,2,2,3,3,3]`), from the emulator's own event
log:

| | `FriProfile::Test` (16 queries) | `FriProfile::Production` (80 queries) |
|---|---:|---:|
| cpu rows | 1 116 783 | **5 250 623** |
| Poseidon2 permutations | 10 451 | **48 291** |
| memory accesses | 1 253 322 | 5 838 954 |
| program instructions | 1 118 823 | 5 260 423 |
| witness words read | 40 725 | 188 245 |
| tape words | 40 725 | 188 245 |

The program is straight-line in the proof's data: every proof of the shape costs the same rows
(asserted by the exit test on 5 test-profile and 50 production-profile proofs). The production
row is pinned in `tests/pins.json`; the production program's digest
(`Checkpoints::Off`, `89e4423067552e83dc12c6dadb9daadc7c02196422320c8bb599207180a354d6`) in
`src/programs/verify_rv32.digest`.

### Where the rows go

Per-phase split of the program's instructions (the program is straight-line apart from assertion
traps, so these are also the cpu rows per phase), and the executed opcode histogram, both measured:

| phase | Test | Production |
|---|---:|---:|
| 0–4: header, transcript, commitments, terminal sum | 2 287 | 2 287 |
| 5: constraint evaluation at `zeta` | 35 561 | 35 561 |
| 6 preamble: claimed evals, betas, final poly, PoW, indices | 63 169 | 136 225 |
| query segments: tape reads | 75 264 | 376 320 |
| queries: Merkle walks, reduction, folds | 941 740 | 4 709 228 |
| 8: §4.4 public values | 801 | 801 |

| opcode | Test | Production | opcode | Test | Production |
|---|---:|---:|---|---:|---:|
| `FADD` | 15 663 | 78 063 | `MOV` | 62 320 | 297 072 |
| `FSUB` | 25 976 | 129 480 | `LOAD` | 238 041 | 1 108 729 |
| `FMUL` | 24 914 | 124 178 | `STORE` | 200 321 | 938 241 |
| `FADDI` | 13 930 | 59 946 | `LOADE` | 99 378 | 455 858 |
| `FMULI` | 1 839 | 8 943 | `STOREE` | 224 494 | 1 053 806 |
| `EADD` | 32 948 | 153 076 | `JEQ` | 2 040 | 9 800 |
| `ESUB` | 30 990 | 148 750 | `HINT` | 37 187 | 184 707 |
| `EMUL` | 91 506 | 435 378 | `HINTE` | 1 769 | 1 769 |
| `EMULF` | 2 000 | 9 680 | `PUBLIC` | 31 | 31 |
| `INV` | 128 | 640 | `POSEIDON2` | 10 451 | 48 291 |
| `EINV` | 856 | 4 184 | `HALT` | 1 | 1 |

The allocator spilled 1 395 811 handles and reloaded 854 367 of them at the production profile
(2 763 817 spill-arena cells; the arena is `2^22`, raised from `2^20` precisely for this phase —
the FRI reduction creates ~10 handle slots per opened column per query). The `LOAD`/`STORE` and
`LOADE`/`STOREE` rows are dominated by that spill traffic and by the memory-structured hashing and
tape reads.

Inside the query phase the dominant term is the batch-opening reduction,
`Σ α^k (p_at_z − p_at_x)(z − x)⁻¹` over every (round, matrix, point, column): the shape opens
1 760 columns per query, so the reduction and its spill traffic are ≈ 2.6 M rows (~50% of the
total). The Merkle work (leaf sponges, walks, injections, commit-phase rows) is ≈ 1.3 M;
`sample_bits`' 64-bit canonical decompositions are ≈ 94 k; the fold rounds themselves are ≈ 100 k.

## The exit tests and their wall time

`tests/exit.rs`, against real bundle proofs produced by `Machine::prove` (disk-cached under
`recursion/target/recursion-fixtures`; producing the 13 test-profile and 50 production-profile
fixtures cost 6 581 s on this machine, ~95–130 s per production proof):

- `five_test_profile_bundle_proofs_are_accepted` — in-suite, ~11 s for the file.
- `thirteen_tampered_test_profile_proofs_are_refused_at_the_named_step` — in-suite, same run.
- `fifty_production_profile_bundle_proofs_are_accepted` — `#[ignore]`d; with a warm cache the
  whole ignored suite (this test, the 50-proof tamper test, and the budget test) ran in
  **43.3 s** (2026-09-14).
- `fifty_tampered_production_proofs_are_refused_at_the_same_step_as_the_native_verifier` —
  `#[ignore]`d; every tamper refused at its named checkpoint.
- `the_cycle_budget_per_inner_proof_is_pinned` — `#[ignore]`d; 16.9 s alone; writes and then
  asserts `tests/pins.json` and `src/programs/verify_rv32.digest`.

Two test-level deviations from the plan's text, both forced and documented where they live: the
tamper table uses the *measured* refusal steps (a transcript-moving tamper is caught at the first
constraint binding the tape to the moved transcript — `"sample_bits decomposition"` or
`"quotient identity[0]"` — not at the plan's per-segment names; `Header` and
`CommitPhaseOpenings` are dynamic in `k`), and the `Checkpoints::On` subsequence check normalizes
branch targets to relative offsets (absolute `JEQ` immediates shift under inserted checkpoint
`PUBLIC`s, so literal instruction equality can never hold).

## The precompile decision

**Measured: 5 250 623 cpu rows per inner proof at the production profile — 10× over the 2^19
(524 288) decision point.** The spike's ~180 000-row model under-counted by ~29×: it carried no
term for the FRI batch-opening reduction (~2.6 M rows here, the single largest item) and none for
the allocator's spill/reload traffic (~50% of arithmetic rows). Spec §7 says that above 2^19,
Task 7 adds the `FRIFOLD`/`EXPBITS` precompiles and re-measures with the assertion that the count
then falls under 2^19. **Task 7 was not implemented, because that assertion is unreachable:** the
fold rounds `FRIFOLD` would replace are ≈ 100 k rows (1.9%) and the bit-selected exponentiations
`EXPBITS` would replace are ≈ 64 k rows (1.2%) of 5 250 623 — even at zero cost they land at
~5.09 M, still 9.7× over. The decision point's premise (a count near 2^18 that two precompiles
might push under 2^19) does not hold; what actually dominates is the reduction's per-column
extension arithmetic and the spill traffic, which neither precompile touches. If the 2^19 target
is real, the options are a batch-inversion/reduction precompile, liveness in the allocator, or a
larger aggregate tier — a protocol-level decision for M5.2, armed with the numbers above. The
budget test pins the regime this decision was made in (`cpu_rows > 2^19`) so a future
optimization that changes it is forced to revisit this paragraph.

## What M5.1 hands to M5.2

- A frozen 24-instruction ISA with a pinned encoding and a program digest, and an emulator that
  is the reference semantics for the five AIRs M5.2 writes.
- A verifier program whose acceptance and refusal behaviour is pinned against the native verifier
  on 50 real production-profile proofs (50 accepted, 50 tampered refused at named steps), plus
  in-suite twins at the test profile.
- Measured `cpu_rows`, `permutations`, `mem_accesses` and `witness_words` per inner proof
  (above), replacing spec §7's cost model: `TIERS`, `poseidon2_log_height` and the memory table's
  height are cut from these, and they say one inner proof wants ~2^23 cpu rows, not 2^19.
- The precompile question answered with a measurement: not `FRIFOLD`/`EXPBITS`.
