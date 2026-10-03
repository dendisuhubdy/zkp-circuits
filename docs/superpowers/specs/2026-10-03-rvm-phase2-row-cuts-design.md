# rVM phase 2 — three measured row cuts to bring one verified inner proof under 2^20 rows, and the prover's memory re-measured

Status: design, 2026-10-03. Implements the recursion half of the fullnode's
`docs/compute-optimization.md` §4 ("Phase 2 — making recursion buyable"), corrected by
measurement: that page assumed the rVM ran Poseidon2 as ordinary instructions; it does not (the
chip has existed since M5.2), and the rows go elsewhere. This document is what the measurement
says and what to cut. Companion plan: `docs/superpowers/plans/2026-10-03-rvm-phase2-row-cuts.md`.

Base tree: `fix/cs6-2` at `6d2015d` (the commit the fullnode vendors, `CIRCUITS_PIN`) merged with
`org/feat/issue-45` (`d38d6cf`, the constraint-set-8 measurements; tests and docs only). Branch
`feat/rvm-phase2`, worktree `~/rand-worktrees/circuits-phase2`.

## 1. Where the rows go (measured, this tree, `tests/profile.rs`)

One verified RV32 bundle proof, constraint set 8, the shipped program (`Liveness::On`,
`Precompiles::On`), from the emulator's own event log:

| | Test (16 queries) | Production (80 queries) |
|---|---:|---:|
| cpu rows | 461 988 | **2 047 268** |
| Poseidon2 permutations (POSEIDON2 + SPONGE rows) | 11 875 | 54 515 |
| RAM accesses | 632 057 | 2 851 913 |
| witness words | 45 899 | 210 763 |
| program instructions | 464 105 | 2 057 401 |
| tier | 19 | 21 |

By phase (program instructions in emission order; the program is straight-line, so these are rows):

| phase | Test | Production | share (prod.) |
|---|---:|---:|---:|
| 0–4 header, transcript, commitments, terminal sum | 1 273 | 1 273 | 0.1 % |
| 5 constraint evaluation at ζ | 26 404 | 26 404 | 1.3 % |
| 6 preamble: claimed evals, betas, final poly, PoW, indices | 50 979 | 100 595 | 4.9 % |
| query segments: tape reads | 84 219 | 421 115 | 20.5 % |
| queries: Merkle walks, reduction, folds | 300 740 | 1 507 524 | 73.3 % |
| 8 interface digest | 489 | 489 | 0.0 % |

By opcode (production): STORE 564 607 (27.6 %), LOAD 539 964 (26.4 %), HINT 206 415 (10.1 %),
FADDI 136 027, FSUB 133 884, FMUL 130 098, FADD 79 823, LOADE 55 715, STOREE 50 756, SPONGE 35 797,
POSEIDON2 18 718, MOV 16 784, EMUL 13 664, EADD 12 295, JEQ 10 133, REDUCE 9 520, EMULF 9 206,
FMULI 8 863, ESUB 7 913, EINV 4 187, HINTE 2 174, INV 720, PUBLIC 4, HALT 1.

**54 % of all rows are LOAD/STORE and 10 % are HINT.** Field arithmetic is under 20 %. The query
phase decomposes, using the per-primitive costs `dsl/hash.rs` measures and pins in its doc
comments (33 rows per Merkle level, 25 per compress, 2 per copied cell, ~25 per REDUCE
descriptor):

| item inside the query phase (production) | rows | how |
|---|---:|---|
| Merkle levels (input-round walks + commit-phase roots) | ≈ 530 000 | ~16 500 levels × 32 rows of child select; the permutation itself is 1 row |
| copying opened rows into per-height sponge buffers (`emit_input_round_root`'s `concat`) | ≈ 336 000 | ~2 100 salted cells per query × 2 rows × 80 queries |
| REDUCE descriptors (11-cell build + 2 read-backs per dispatch) | ≈ 240 000 | 9 520 dispatches × ~25 rows |
| fold-chain sibling selection (arity ≤ 8) | ≈ 64 000 | ~800 rows per query |
| leaf/injection sponges, cap compares, bookkeeping | the rest (≈ 340 000) | |

Three of those are pure bookkeeping around work a chip already does. The plan cuts them, in the
order cheapest-to-prove first:

## 2. The cuts

### 2.1 Cut A — hint straight into the sponge buffer (program + tape; no AIR change)

Today `read_input_openings` hints each matrix's `row ‖ salt` into its own fresh array, and
`emit_input_round_root` then **copies** every array of a height group into one contiguous buffer
so the leaf sponge can run over it. The copy is 2 rows per cell. Instead: per round, allocate one
buffer per *height group* (distinct heights, tallest first — the reference's
`sorted_by_key(Reverse(height))`, stable within a height), hint the group's rows directly into it
in that order, and hand the reduction `Array` **views** into the buffer (`Builder::offset` is
compile-time, so a view costs nothing). The leaf sponge and the injections then run over the
buffer in place; `concat` is deleted.

The tape must agree: `WitnessTape::build`'s `Segment::InputOpenings` (`witness.rs`, step 11)
emits, per query, per round, the matrices **in height-group order** instead of committed order.
The tape is the aggregator's private witness, not a chain artefact; the only contract is that the
program and the tape agree, and the exit tests over real proofs are that contract's test.

Expected: −336 000 rows at production, RAM accesses −672 000. Program digest moves (every cut
moves it; see §4).

### 2.2 Cut B — `HINTN`: eight tape words into eight cells in one row (opcode 26)

`hint_array(n)` is `HINT scratch; STORE scratch` per word: 2 rows per word, 421 115 rows at
production. `HINTN rd=0, ra=ptr_reg, imm=0` reads the next **eight** witness words and writes them
to `mem[ra .. ra+8]`. The cpu row carries them in eight new columns `W0..W7` (free witness, exactly
as `HINT`'s `D0` is free today — the tape is prover-chosen; soundness never rested on hint
values, only on what later checks do with them) and sends eight `RAM` writes at timestamp slots
`16·clk + 0..7`. Both ends of the run are range-checked the way POSEIDON2's are: group 1's subject
is `A0 + 7`, group 3's base is `A0`. `rd` is unused (0), `b` is an immediate 0, `rb` is not a
register (`b_is_register` false). No `REG` write.

The DSL: `hint_array(n)` emits `⌊n/8⌋` `HINTN` rows then the plain `HINT; STORE` pairs for the
`n mod 8` tail — the tail stays compiled so the emulator never over-consumes the tape (a block
of eight always reads eight words). `hint_ext_array` is unchanged (used for the 2 174 extension
hints only). Under `Precompiles::Off` the old pairs are emitted — the differential reference.

Why a cpu row kind, not a chip: the words are free witness with no arithmetic, so a chip would be
eleven columns of nothing but RAM sends and one more instance for the self-verifier to open at
every query. The cost of the row kind is cpu width 72 → 82 (+2 selectors, +8 words): the cpu main
LDE grows ~14 %, about +2.7 GB on the tier-21 oracle, against the halving the three cuts bring.

Expected: −390 000 rows (tape reads 421 115 → ~27 000 dispatches + tails).

### 2.3 Cut C — `COMPRESS`: a Merkle level as one row (opcode 27, third row kind of the Poseidon2 chip)

`merkle_walk`'s level is `select_children` (32 rows: per lane two loads, `s − d`, `·bit`, two
`±`, two stores) plus one `POSEIDON2` row. `COMPRESS rd=bit_reg, ra=state_reg, rb=sib_reg` does
the level in one cpu row and one chip row:

- cpu row: reads `rd` (the index bit, `D0` — `Compress` joins `READ_RD`), `ra` (`A0`, the
  4-cell running digest's address) and `rb` (`B0`, the 4-cell sibling's address — `Compress` joins
  `B_REG`); range groups: 1 → `A0 + 3`, 2 → `B0 + 3`, 3 → `A0`, 4 → `B0`; sends
  `COMPRESS [clk, A0, B0, D0]` on a new lookup bus. No RAM access of its own.
- chip row (`IS_COMPRESS`, new columns `IS_COMPRESS`, `BIT`; `SRC_PTR` reused as the sibling
  pointer): `BIT` boolean; the permutation input is the ordered pair
  `IN[k] = d_k + BIT·(s_k − d_k)`, `IN[4+k] = s_k − BIT·(s_k − d_k)`, which is
  `TruncatedPermutation<Perm,2,4,8>` over `[digest ‖ sibling]` when `BIT = 0` and
  `[sibling ‖ digest]` when `BIT = 1` — `MerkleTreeMmcs::verify_batch`'s rule, bit-exact with
  `dsl::hash::select_children`. The RAM reads carry `d_k` and `s_k` **as expressions of `IN` and
  `BIT`** (`d_k = IN[k] + BIT·(IN[4+k] − IN[k])`, `s_k = IN[4+k] + BIT·(IN[k] − IN[4+k])`;
  degree 2, under the chip's degree-4 bound), so no raw-read columns are added: 4 reads at
  `PTR + k`, slot `k`; 4 reads at `SRC_PTR + k`, slot `4 + k`; 4 writes of `OUT[0..4]` to
  `PTR + k`, slot `8 + k`. Lanes `4..8` of the output are dropped (the compressor keeps lanes
  `0..4`, spec §12 erratum 1). `IS_PERM + IS_SPONGE + IS_COMPRESS = IS_REAL`; `SRC_PTR` and `BIT`
  are zero on every row kind that does not use them (AGENTS.md invariant 1).
- emulator: `Op::Compress` reads the bit from `rd` and **refuses a non-boolean bit**
  (`ExecError::NonBooleanBit { pc }`, a build-time mistake like `ReduceZeroLength`); `PermEvent`
  gains the kind (`src: None` perm, `Some(src)` sponge, and a third variant for compress with the
  sibling pointer and the bit — make `src` an enum, do not add a second `Option`).
- DSL: `Builder::compress_step(state: Ptr, sib: Ptr, bit: Felt)` emits one row.
  `merkle_walk_with_injections` under `Precompiles::On` keeps the running digest in four
  dedicated cells and emits one `compress_step` per level; an injection is `sponge` into a
  scratch digest then `compress_step(state, scratch, zero)`. `compress` (the standalone 25-row
  form, used by the cap compare and elsewhere — grep `hash::compress(` and
  `compress_into_state`) becomes `copy left → state; compress_step(state, right, zero)` when
  `out` must survive; under `Precompiles::Off` every compiled form stays as the differential
  reference.

Expected: −530 000 rows (one cpu row per level instead of 33), RAM accesses −260 000. Chip width
341 → 343.

### 2.4 The landing

| | today | after A | after A+B | after A+B+C |
|---|---:|---:|---:|---:|
| cpu rows, production | 2 047 268 | ≈ 1 711 000 | ≈ 1 321 000 | **≈ 790 000** |
| tier | 21 | 21 | 21 | **20** (2^20 = 1 048 576; ~25 % headroom) |
| RAM accesses | 2 851 913 | ≈ 2 180 000 | ≈ 2 180 000 | ≈ 1 920 000 (2^21, from 2^22) |

The production N=1 aggregate lands at tier 20, N=2 at tier 21 (2 × 790 k = 1.58 M < 2 097 152),
N=4 at tier 22 — every table one height shorter than today, which halves the prover's memory
and time at equal N before any hardware work. These are projections from measured per-primitive
costs; **each cut is re-measured by `tests/profile.rs` and re-pinned before the next starts**, the
M5.2 gate discipline. If a cut lands outside ±15 % of its projection, the plan stops and the
projection is corrected in this section before continuing.

Not in this phase, recorded for the next: the REDUCE descriptor (≈ 240 000 rows; a per-point
descriptor *table* the chip walks would make it ~160 dispatches a proof), the fold-chain select
(≈ 64 000), and the inner FRI profile (rate ¼ / ~40 queries halves everything in the query phase
at the wallet's expense — `compute-optimization.md` §4.4's measured decision).

## 3. The prover's memory, re-measured (hardware track)

`docs/02-aggregate.md` records 94.2–94.5 GB peak RSS for a tier-19 rVM proof and 376.9 GB for a
tier-21 production one on the 503 GB Linux box (2026-09-30, `/usr/bin/time -v`), 4–8× the
committed-oracle model of `docs/01`. Two earlier facts seemed not to fit: the same tier-19 proof
had completed on this 48 GB laptop (1 707.7 s, 2026-09-15, "~15 GB observed"), and the box's RSS
series climbs monotonically for two hours. The working hypothesis going in was allocator
retention. **The measurement refutes it.**

### 3.1 Tier-19 exit twin, live heap by phase (this box, 2026-10-03, `tests/memprofile.rs`)

A counting global allocator (live bytes and high-water mark, every allocation) and a `tracing`
subscriber printing both at every Plonky3 span boundary; single-threaded; the shape is
`tests/exit.rs`'s twin (one real test-profile bundle proof, 461 988 rows, tier 19, constraint
set 8). The run (`scratchpad/mem/tier19.log`):

| phase (Plonky3 span) | wall | Δ live | live after | note |
|---|---:|---:|---:|---|
| key build: preprocessed LDE + Merkle tree | 22 s | +2.0 GB | 2.05 GB | `with_zero_cols`, `coset_lde_batch`, `build merkle tree` |
| main trace commit: `randomize polys` + 8 × `coset_lde_batch_with_transform` | 24 s | +13.2 GB | 15.3 GB | the hiding doubling and the four salt columns included |
| main `build merkle tree` | 273 s | +4.3 GB | 19.6 GB | single-threaded Poseidon2 over the tallest LDE |
| `generate lookup permutation` × 8 | 1 s | +0.3 GB | 19.9 GB | |
| permutation trace commit (LDE) | 16 s | +7.0 GB | 27.0 GB | |
| permutation `build merkle tree` | 187 s | +4.3 GB | 31.3 GB | |
| `compute quotient` × 8 (program, cpu, reg, ram, poseidon2, public, range, reduce) | 245 s | +1.8, +6.5, **+13.7**, +6.8, +0.1, 0, 0, +0.8 GB | **61.0 GB** | the quotient-chunk LDEs are retained for the commit; the reg table (the tallest, degree 4 → 8 chunks under zk) is the largest single item |
| quotient `commit_ldes` (Merkle tree) | killed 20 s in | +17.7 GB and rising | **78.7 GB** | **SIGKILL by the kernel at 782 s** |

macOS's `maximum resident set size` for the run was 19.8 GB and its `rss` samples 7–17 GB
throughout: **on macOS, RSS excludes compressed and swapped pages**, so the September "15 GB /
30 GB observed" laptop figures measured the compressor's output, not the working set. The
September tier-19 proof that "completed on 48 GB" did so through ~50 GB of compressed swap. The
Linux `/usr/bin/time -v` figures are the honest ones.

**The live model, from this run** (tier 19, declared heights cpu 2^19, reg 2^21, ram 2^20,
poseidon2 2^14, reduce 2^15, program 2^19; `log_blowup 3`, hiding):

| term | GB | share of the 94 GB Linux peak |
|---|---:|---:|
| main LDE + salts + tree (the `docs/01` "committed oracle" term) | 17.6 | 19 % |
| permutation (LogUp) LDE + tree | 11.3 | 12 % |
| quotient LDEs (8 instances, 2–16 chunks each at blowup 2^(3+1)) | 29.7 | 32 % |
| quotient tree, random-polynomial commitment, FRI opening and commit phase | ≈ 33 (by difference) | 35 % |

The `docs/01` oracle model counted the first row only; the other three are 4× it, which is the
4–8× the box measured. Nothing is retained that the opening does not need: every committed LDE
is read again at the FRI query phase, so the batch prover's peak is inherent to committing
everything before opening anything.

### 3.2 What follows for the hardware plan

- **The ≥ 512 GB class for the production tier-21 proof stands today**; the ≥ 64 GB
  "committed oracle" requirement in `docs/01` is withdrawn (Task 4 rewrites it). RSS measured on
  macOS is never again a memory number in these docs.
- **The §2 cuts halve it directly**: every table one height shorter (tier 21 → 20) halves every
  term above, so the production N=1 aggregate lands near **≈ 190 GB** (a 256 GB host) and the
  tier-19 twin near 47 GB. Still not `compute-optimization.md` §4.4's ≤ 64 GB; the rest is
  structural and is the next phase's measured decision, candidates in order of leverage:
  1. the **quotient's share (32 %)**: the memory tables are 11 columns wide but their degree-4
     AIR makes 8 zk-chunks × 2 cells — a quotient as wide as the trace; a degree-2 memory AIR
     (one extra witness column for the product term) halves that term for the two tallest
     tables;
  2. the **register table's height** (4× the cpu table): ~2.1 `REG` messages per cpu row — the
     cuts shrink it with the rows, and a wider cpu row that reads fewer registers is the lever
     beyond that;
  3. `log_blowup 3 → 2` (rate ¼) halves every LDE at the price of ~1.5× the queries — the inner
     profile decision §4.4 of the fullnode page already names, applied to the rVM's own profile;
  4. the GPU backend as built changes none of this (traces live on the host); a device-resident
     LDE/tree would, and is the real reason to want the 80 GB device class.
- **Threads.** The recursion crate proves single-threaded (`p3-batch-stark` without `parallel`);
  the two Merkle trees above alone are 460 s of the 782. The RV32 prover's `parallel` build gave
  7.7× on 16 threads (`fullnode/docs/node-hardware.md` §6) and needs the fullnode's two-crate
  Plonky3 patch (`vendor/p3-fri`, `vendor/p3-merkle-tree`: the hiding RNG lock forked, never held
  across rayon work — upstream Plonky3 #2363). Task 6 brings both into `circuits/` behind a
  `parallel` feature and measures a tier-16 synthetic program on 1 and 16 threads (a tier-19 proof
  does not fit this box, as above); proofs are unchanged (same config, same transcript — the
  postcard-retype discipline of `docs/03`).
- The GPU items (PTX build, N on the device) stay hardware-blocked.

## 4. What moves, what does not

- **Moves:** the rVM verifier program digest (`src/programs/verify_rv32.digest`), the aggregate
  program digest (`tests/aggregate.rs`, `docs/02`'s admission vectors
  `aggregate_program_digest`), every pin in `tests/pins.json` and the row literals in
  `tests/exit.rs`/`tests/aggregate.rs`, the cpu and poseidon2 widths (`tests/tables.rs`), the
  rVM's own verifier keys (the self-verifier's `RvmShape` opens the wider tables), the tape layout
  of `Segment::InputOpenings`. The aggregate's **interface** (`[vk ‖ N ‖ B(8) ‖ 35·N]`, the
  binding, `verify_aggregate`'s API) does not move, so the fullnode's admission, selection,
  sealing and pruning code is untouched; the fullnode re-vendors and re-pins
  `admitted_shapes[].aggregate_program_digest` at the next chain cut (aggregation is enabled on
  no running chain).
- **Does not move:** the RV32 machine (constraint set 8), its proofs, the inner verifier key
  digest, the FRI profiles, the hashing (`permute_state`, the sponge, the compressor — the new
  row kind computes the same compressor), the chain's consensus rules.
- **Opcodes 0–25 never move** (`isa.rs`); 26 and 27 are appended. `Op::COUNT` 28,
  `NUM_SELECTORS` 28, every cpu column index after `SEL0` shifts by 2 — they are named constants,
  and `tests/cpu.rs`'s binding test iterates `Op::ALL`, so the two new opcodes are covered by it
  automatically; each still gets its own cheating tests (§5).

## 5. Testing (the repository's discipline, applied)

- **Differential, program level:** `tests/exit.rs`'s accept/refuse suites over real proofs, both
  profiles — the only proof that the program and the tape agree after Cut A, and that the
  precompiled walks and hints compute what the compiled ones did. `Precompiles::Off` must still
  build and accept (it is the reference); `tests/precompiles.rs` gains `hint_array` and
  `merkle_walk` Off-vs-On equivalence over random inputs (the pattern of
  `sponge_via_the_precompile_matches_padding_free_sponge`).
- **Differential, primitive level:** `tests/transcript.rs` checks `dsl::hash` against the p3
  crates on random input; the `COMPRESS` walk is checked against `MerkleTreeMmcs::verify_batch`
  the same way (random leaf, random siblings, random index bits, both bit values at every level).
- **Cheating (`tests/cheating.rs`), one per new invariant:** a `HINTN` whose base is above `2^24`
  with forged limbs; a `HINTN` whose top cell is out of range (base `2^24 − 4`); a `COMPRESS` chip
  row with a non-boolean `BIT`; a compress row claiming the plain kind (`IS_PERM` set, `BIT`
  nonzero); a compress row with `BIT` flipped against the dispatching cpu row's `D0`; a sibling
  read from the wrong address; an output lane written to the sibling instead of the state; a
  padding row with `IS_COMPRESS` set. Every one is built by editing the honest trace, proved,
  and refused by `Machine::verify`.
- **Table invariants:** `tests/tables.rs`'s width/degree pins updated (cpu 82, poseidon2 343,
  degrees unchanged); the table-driven "every written value bound, no padding sends" invariants
  (R6) extended to the new row kinds.
- **Measurement:** `tests/profile.rs` (new in this phase, `#[ignore]`d) is run after every cut
  and its output pasted into docs/04; `the_cycle_budget_per_inner_proof_is_pinned` re-pins
  `tests/pins.json`.
- **Memory:** `tests/memprofile.rs` (new, `#[ignore]`d) is the hardware track's instrument; its
  tier-19 run is recorded in docs/04 §3.

## 6. Rulings

1. A cut that lands outside ±15 % of §2.4's projection stops the plan until the projection is
   corrected here. (Measured, not assumed — spec §7's discipline.)
2. `HINTN` is a cpu row kind, not a chip (§2.2's reasoning). Revisit only if the cpu width
   becomes the binding memory term after the cuts.
3. `COMPRESS` is a row kind of the Poseidon2 chip, not a Merkle chip of its own: the permutation
   is the whole cost of a level once the select is free, and a second 341-column table would be
   opened at every query for nothing.
4. The compiled forms stay in the tree under `Precompiles::Off` as differential references.
   Nothing is deleted.
5. The tape layout is the program's to define; the fullnode never sees it.
6. No SNARK wrapper, no GPU requirement for validators, no change to the RV32 machine — the
   fullnode page's "what not to do" list holds.
