# rVM phase 3 — the REDUCE chip learns the descriptor layout, the fold and the index powers: one verified inner proof under 2^19 cpu rows with both memory tables at 2^21

Status: design, approved in conversation 2026-10-05. Base: circuits `main` 2899bdc (phase 2 merged at 75b7893).
Prior: `docs/superpowers/specs/2026-10-03-rvm-phase2-row-cuts-design.md`; measurements in `recursion/docs/04-phase2-row-cuts.md` (cited below as docs/04).

Phase 2 took one production inner-proof verification from 2 047 268 to 893 606 cpu rows (tier 21 → 20). The
fullnode's `docs/compute-optimization.md` §4.1 names "dedicated chips for Poseidon2 and FRI fold" as the next
step. The Poseidon2 chip already exists (PERM, SPONGE and COMPRESS row kinds; all 54 515 permutations run in
it; its cpu-side dispatch rows are under 12 % of the total), so that half of §4.1 is done. The rows that remain
are the query phase's bookkeeping: the REDUCE descriptor build, the fold chain with its sibling select and
bit-selected powers, and the register-allocator traffic those two keep alive. This phase moves the first two
into the REDUCE chip as preprocessed layout and two new row kinds, and lets the third fall with them.

**Gate (the milestone's definition of done):** production N = 1 verifies in fewer than 2^19 − 1 = 524 287 cpu rows
(tier 19), and the register and RAM tables both declare height 2^21. The inner RV32 proof, its FRI profile
(`log_blowup` 3, 80 queries, 20 PoW bits) and the wallet are not changed. Every cut lands inside a band fixed by
the Task-0 measurement, is re-measured on the production fixture, and re-pins its rows, heights and digests
before the next cut starts (phase 2 §6 ruling 1 applies: ±15 %).

## 1. Where the rows go (docs/04 measured; the attribution is derived and Task 0 re-measures it)

Production, 893 606 cpu rows (docs/04 §"Profile after the cuts"): queries 725 192 (80.2 %), preamble 100 325,
tape reads 50 235, constraint evaluation 26 404. By opcode: LOAD 245 950, FADDI 144 427, STORE 92 609, FMUL
73 138, LOADE 55 715, STOREE 50 756, SPONGE 35 797, HINTN 24 030, … REDUCE 9 520. Memory: 2 147 159 REG and
2 213 181 RAM accesses, both just over 2^21 (by 50 007 and 116 029), so both tables declare 2^22 and hold about
two thirds of the prover's main-plus-quotient memory.

Three sources, derived from `src/dsl/builder.rs::reduce`, `src/programs/rv32.rs::{emit_query,
emit_fold_round, bit_selected_power}` and the Production − Test opcode deltas (64 extra queries):

| source | cpu rows (derived) | REG | RAM | notes |
|---|---:|---:|---:|---|
| REDUCE descriptor build, 9 520 dispatches × ≥ 14 rows (1 FADDI alloc, 3 FADDI + 3 STORE constants, 4 STOREE, 1 REDUCE, 2 LOADE) | 133 280 code minimum; ≈ 238 000 with reloads (docs/04 §"Still ahead") | 314 160 | 285 600 (cpu 15 + chip 15 per dispatch) | 119 dispatches per query: one per (round, matrix, point); only `vals_base`, `row_base`, `len`, the inverse key and the chain differ, all compile-time |
| fold chain: sibling select (2 ESUB + 2 EMULF + 2 EADD per slot + indicator and prefix sums), fold (`[Π(β − x_k)]·Σ y_k w_k/(β − x_k)`: FSUB, EINV, EMUL, FMUL, EMUL, EMULF, EADD per slot), roll-ins | 73 840 op-count minimum (923 per query); up to ≈ 228 000 by the stale M5.1 figures that include reloads | proportional | small | the opcode deltas fit Σa = 38 over 9 rounds (3 × 2, 4 × 4, 2 × 8), not docs/00's `[1,1,2,2,2,3,3,3]`; Task 0 prints `shape.log_arities()` |
| `bit_selected_power`: 4 cpu rows per bit (FADDI, FMUL, FADDI, FMUL) over `log_folded` bits per round plus `h` bits per input height | ≈ 32 000–64 000 | 2–3 per row | 0 | the s = g^{rev(index)} ladder |
| allocator reloads (218 283 of the 245 950 LOADs; 14 906 spills) | — | 2 per row | 1 per row | mostly the extension handles the reduce and fold chains keep live across a query |

Needed for the gate: −369 319 cpu rows, −50 008 REG, −116 030 RAM. The descriptor table alone clears both
memory targets. The row target needs the descriptor table, the fold, and a measured share of the reloads; the
POW row kind is held in reserve for the gate.

### Task 0 — re-attribute before cutting

`tests/profile.rs` gains: `shape.log_arities()` and `degree_bits()`, the REG access count (today only RAM is
printed), and rows per call site (a `Builder` span stack keyed by the emitting function: `reduce`, `select`,
`fold_round`, `bit_selected_power`, `commit_root`, `sample_bits`, `reload`). Its output fixes the per-cut landing
bands in `tests/pins.json` (a `phase3_attribution` block) and the numbers in §1 are replaced by measured ones in
docs/06 before Cut D starts. No cut lands against the derived table above.

## 2. The cuts (in order; each is one task, one review, one re-pin)

### 2.1 Cut D — the descriptor layout is preprocessed; one REDUCE row per entry; chains carry in-chip

Today (`src/tables/reduce.rs`, width 39): the cpu builds an 11-cell descriptor `[vals_base, row_base, len,
inv(2), acc(2), alpha_pow(2), alpha(2)]` per dispatch, the chip reads it on its first row (11 RAM reads at
`16·clk + 0..10`), reads `pz`(2) and `px` per column, and writes `acc`/`alpha_pow` back on its last row (4 RAM
writes); the cpu reads them back (2 LOADE) to chain the next dispatch of the same height. Everything but
`inv`, `acc` and `alpha_pow` is a compile-time constant of the shape, because the program is unrolled per
query and the opened-value and row buffers are at `addr_of` constants.

After: the chip carries a **preprocessed trace**, committed in the verifier key as `ProgramAir`'s is, with
columns `ENTRY_ID`, `ADDR_V`, `ADDR_R`, `IS_FIRST`, `IS_LAST`, `CARRY` (1 when the next entry continues this
height chain), `KEY_SLOT` (which of the per-query inverse keys), and `QUERY` (0..79). The witness columns keep
`CLK`, `ACC`, `APOW`, `INV`, `ALPHA`, `PZ`, `PX`; `LEN`, `LEN1`, `LEN1_INV`, the 18 ZKQ-3 limb columns and the
first-row range lookups go, because the key binds every address (ZKQ-3's concern, a hinted address, cannot
arise). Soundness rule: **a descriptor is never a witness value**; the only way to name a buffer is the
preprocessed layout, which the verifier key commits to.

The cpu keeps one REDUCE row per entry (119 per query, 9 520 per proof, 1 REG read each), operand = `ENTRY_ID`
(immediate). One clock per entry keeps the memory table's strictly-increasing `(addr, ts)` rule exactly as
today, so no timestamp redesign is needed (the one-dispatch-per-query form would read a shared `px` cell twice
at one `16·clk + 13` and is rejected for that reason, §6 ruling 2). The bus key stays `[CLK, ENTRY_ID]` on
`IS_FIRST`.

Chaining: on a row with `CARRY = 1` and `IS_LAST = 1`, the transition constraint carries `ACC` and `APOW` into
the next entry's first row instead of resetting them, so no RAM write or read happens inside a chain. `INV`
and `ALPHA` are read on the first row of each chain from the per-query key buffer (`KEY_SLOT` selects the cell;
2 + 2 RAM reads) that the cpu fills once per query (14 STOREE of the `ext_inv_checked` keys, 1 STOREE of
alpha, all already computed today); the chain's last row writes `ACC` (2 RAM writes) into a per-query result
cell the cpu LOADEs (7 per query). The chip's degree stays where it is: the carry flag is preprocessed (degree
1) and the gated chain constraints remain degree ≤ 5 under the packed-lookup 8.

Per query the cpu pays about 1 FADDI + 15 STOREE + 119 REDUCE + 7 LOADE ≈ 142 rows, against ≥ 1 666 today.
Expected: −125 000 to −230 000 cpu rows, −300 000 REG, −250 000 RAM (band fixed by Task 0). The reduce chip's
own rows are unchanged (173 120, one per opened column) minus nothing; its width falls to about 25.

### 2.2 Cut E1 — the sibling select becomes a hinted vector and one equality (program + tape only)

Today each fold round assembles the a-vector of evaluations with an arithmetic select (6 extension ops per
slot, driven by the one-hot index) because the query's own folded value must land at position `idx` among the
`a − 1` hinted siblings. After: the tape hints the whole a-vector into the commit-root buffer (one HINTN per 4
cells), the cpu computes `idx = Σ bit_k·2^k` over the round's `la` index bits (`la` FMUL/FADD), loads
`msg[idx]` with a register-addressed LOADE, and asserts it equal to the folded value (2 FSUB, 1 JEQ to the
refusal exit). Soundness: the vector is only trusted through the commit-root sponge and Merkle walk that follow
(unchanged), and the equality binds the query's own value to its slot. About 10 rows per round in place of
18/46/120 at arity 2/4/8. Expected: −35 000 to −40 000 cpu rows (478 per query), and the `bit_indicator`
prefix-sum rows go with it.

### 2.3 Cut E2 — `FOLD`, a run of 2a rows in the REDUCE chip (second row kind)

The arity-a fold is a size-a inverse DFT on the bit-reversed coset values followed by Horner at `u = β / s`:
`out = Σ_m B_m·u^m` with `B_m = (1/a)·Σ_k y_k·c_k^{−m}`, `c_k = g_la^{rev(k)}`. The DFT weights are
constants of the arity; every constraint is degree 2 at every arity; no extension inverse remains. (Task 0's
first commit checks this identity against `fold_row` on random inputs at a = 2, 4, 8 before anything else is
built.)

Row kind `IS_FOLD`, dispatched by a new cpu opcode `FOLD` (opcode 28, `Op::COUNT` 29) whose bus key is
`[CLK, msg_ptr, u0, u1]` — the cpu computes `u = β·s⁻¹` (1 EMULF; `s⁻¹` by 1 INV, or by Cut F) and passes it in
registers, so the chip reads nothing it was not told. A run is 2a rows under one clock:

- rows 0..a−1 (phase 1): row k reads `y_k` (2 RAM reads at slots 2k, 2k+1; 16 slots at a = 8). A run shares
  one clock, so timestamps are `16·clk + slot`; the memory table needs `(addr, ts)` strictly increasing per
  address, and every cell a run touches is distinct (a y-cells, one result cell), so slot reuse between the
  reads and the last row's result write is sound — the emulator's slot numbering is a position, not a
  uniqueness domain. Row k accumulates `B_m += C[m][k]·y_k` for all m in 2a accumulator columns, with `C[·][k]` eight preprocessed
  base columns (zero beyond the arity);
- rows a..2a−1 (phase 2): Horner `ACC' = ACC·u + B_{a−1−m}`, the coefficient picked by a preprocessed one-hot;
  the last row writes `ACC` (2 RAM writes) to the round's result cell, which the cpu LOADEs.

Width added: 16 (B) + 2 (y) + 2 (u) + 2 (acc) + 8 + 8 preprocessed + 3 flags ≈ 41 columns, of which the
witness part (≈ 25) is opened at every query: about +2 000 reduce-chip rows per proof (one per opened column
per query), well inside the chip's 2^18. Rows per proof: Σ 2a over 9 rounds × 80 queries ≈ 6 080 chip rows.

The cpu per round: 1 INV, 1 EMULF, 1 FOLD, 1 LOADE, plus the roll-in (unchanged, `la + 2`). Expected: −30 000
to −50 000 cpu rows from the fold arithmetic (424 per query op-count minimum) and the reload share the
chains kept live. The `xs`/`ws` powers and `l_z` chain go entirely.

### 2.4 Cut F — `POW`, one row per index bit (third row kind; built only if D + E leave the gate short)

`s = base·Π_k (1 + bit_k·(g^{2^{L−1−k}} − 1))` as a run of L rows: row k reads `bit_k` (1 RAM read of the
hinted, already-booleanity-checked bit cell), carries `S' = S·(1 + bit·(G_k − 1))` with `G_k` preprocessed;
the last row writes `S`. Dispatch `POW [CLK, bits_ptr, base]`. Replaces 4 cpu rows per bit with 1 chip row and
about 3 cpu rows per call. Expected: −25 000 to −50 000 cpu rows. Opcode 29 if built.

### 2.5 The landing

| after | cpu rows (expected) | reg | ram | tier |
|---|---:|---:|---:|---:|
| phase 2 (measured) | 893 606 | 2 147 159 → 2^22 | 2 213 181 → 2^22 | 20 |
| D | 660 000–770 000 | ≈ 1 830 000 → 2^21 | ≈ 1 960 000 → 2^21 | 20 |
| D + E1 + E2 | 540 000–700 000 | | | 20 or 19 |
| D + E + F | 490 000–650 000 | | | 19 if ≤ 524 287 |

If D + E + F measured lands above 524 287, the phase stops at the measured point, the memory heights (already
met at D) are the delivered result, and the residual is reported with the next lever (the REDUCE chip reading
`px` once for a matrix's two points; the inner FRI profile) for a phase 4 decision. The gate is not widened.

### 2.6 Resolutions made while planning (binding; they correct §2.1 and §2.3 where the two differ)

The plan (`docs/superpowers/plans/2026-10-05-rvm-phase3-fold-reduce.md`, "Design resolutions" R1–R9) found that
§2.1 and §2.3 as written cannot be built, and resolved them as follows. Where this section and the earlier text
differ, this section governs.

- **R1 — the layout is looked up, not row-aligned.** The aggregate program runs every layout entry N times inside
  a tape-counted loop (`rv32n.rs`), so preprocessed columns aligned to the chip's rows would need a height that
  depends on N. The layout is a preprocessed *provider region* in `ProgramAir`'s pattern (rows plus a witness
  `MULT`), consumed by each run's first row over a `REDUCE_LAYOUT` bus. Ruling 3 holds: no field is a witness.
- **R2 — `KEY_SLOT` and `QUERY` are absolute addresses** (`KEY`, `ALPHA`, `RES` in the layout row).
- **R3 — `INV` is read once per entry**, because a height chain interleaves `zeta` and `zeta_next` entries with
  different keys; `ALPHA` is read once per chain and carried.
- **R4 — a chain carries across consecutive dispatches** (`n(CLK) = CLK + 1`, `n(ENTRY) = ENTRY + 1`); the builder
  emits a chain's REDUCE rows back to back and `replay` asserts it, which also keeps a chain inside one aggregate
  loop iteration.
- **R5 — `LEN`/`LEN1`/`LEN1_INV` become `ROW_END`/`END_INV`.**
- **R6 — the layout is part of the program digest** (absorbed only when non-empty) and the verifier-key cache is
  keyed by `(tier, digest, reduce_log_height)`.
- **R7 — the FOLD dispatch is `[CLK, msg, u0, u1, a]`** with the arity as the immediate, the result at
  `msg + 2a + 4`, and the DFT coefficients looked up from a 14-row preprocessed table on a `FOLD_COEFF` bus; phase 2
  uses a shift register, not a one-hot.
- **R8 — the POW dispatch is `[CLK, bits_ptr, off + 256·L, G, base]`** (Cut F only).
- **R9 — new buses `REDUCE_LAYOUT`, `FOLD`, `FOLD_COEFF`, `POW`**, every message degree 1; the reduce chip's
  packed-lookup degree is re-measured and pinned (≤ 8).
- **Boundary rule (controller review):** the first fold row after the last reduce row must carry `F_FIRST`, so no
  fold run exists without a dispatch; the same rule already holds for reduce runs and chain continuations.

## 3. Memory

Cut D's −300 000 REG and −250 000 RAM accesses take both memory tables from 2^22 to 2^21, which docs/04 §"Live
heap" prices at roughly half of the two largest main-plus-quotient terms (production N = 1 projection ≈ 240 GB
→ on the order of 150 GB; re-measured by `tests/memprofile.rs` at the tier-18 twin after D, where the laptop's
48 GB can hold it). The quotient-chunk lever (one matrix per instance, −20 % of peak) is a separate branch
(`feat/rvm-quotient-layout`) and is not part of this phase. The ≤ 64 GB host target of compute-optimization.md
§4.4 is not reached by this phase and is not claimed.

## 4. What moves, what does not

Moves: `Op` (`FOLD` = 28, `POW` = 29 if built; `Op::COUNT` 28 → 29 or 30), cpu selectors (width 82 → 83/84), `bus::REDUCE` key (FOLD/POW keys
are new entries on the same bus or a `FOLD` bus — decided in Cut E2's task by the lookup-degree pins), the
REDUCE chip's columns and its preprocessed trace, `machine.rs` (`verifier_key` cache key gains the preprocessed
layout — already keyed by `(tier, program digest, reduce)`, so the program digest covers it once the layout is a
function of the shape), `emulator.rs` (REDUCE semantics, FOLD, POW events), `dsl/builder.rs` (`reduce` signature
takes an entry id; `fold_run`, `pow_run`), `programs/rv32.rs` (every query), `verify_rv32.digest`, every pin in
`tests/pins.json`, the fixture-shape and production aggregate program digests, the self-verifier digest
(`rv32r` verifies an rVM proof whose chip widened), `docs/00/01/02/03` tables, and a new `docs/06`.

Does not move: the inner RV32 machine, the fixture proofs (`$RECURSION_FIXTURES` stays warm), `inner_vk_digest`,
the interface list, the Poseidon2 chip, the memory AIR, degree pins (`[2, 8, 4, 4, 4, 2, 2]`, reduce 8), the
aggregate program's structure and `LOOP_OVERHEAD`.

Collateral to correct in the same tree: `tests/exit.rs` asserts `cpu_rows > 1 << 19` ("the Task-7 decision
must be reconsidered") — it flips to the new pin; `isa.rs`'s "deliberately absent: FRIFOLD, EXPBITS" note and
docs/00's precompile-decision paragraph are rewritten with the measured reason they are present now; docs/01
lists the reduce chip's degree as 3 (it is 8, `tests/tables.rs:219`).

## 5. Testing (the repository's discipline, applied)

- Task 0 commits the fold identity test (`fold_row` vs DFT+Horner, a = 2, 4, 8, 256 random inputs each) and the
  attribution output; nothing else lands until it is green and the bands are pinned.
- Each cut: `tests/precompiles.rs` On-vs-Off equivalence stays the differential reference (the
  `Precompiles::Off` compiled form keeps the old arithmetic); `tests/cheating.rs` gains a forged-trace refusal
  per new constraint (a wrong `CARRY` carry, a descriptor row whose address differs from the preprocessed one,
  a FOLD run with a tampered `B_m`, a POW row with a non-boolean bit, a FOLD whose `u` differs from the cpu's);
  `tests/emulator.rs`, `tests/isa.rs`, `tests/cpu.rs` (operand binding for the new dispatches), `tests/tables.rs`
  (widths, degrees — the packed-lookup degree stays 8, asserted) move with the cut.
- Pins: `tests/pins.json` (rows, permutations, mem accesses, REG — a new field — witness words, instructions,
  per-cut attribution), `verify_rv32.digest`, `tests/{aggregate,verifier,self_verify,exit}.rs` literals, re-run
  through `the_cycle_budget_per_inner_proof_is_pinned` after each cut on the production fixture.
- The suite at each landing: `cargo test --release -p recursion` with the two tier-18+ aggregate round trips
  skipped as in phase 2, counts recorded in docs/06.
- Memory: `tests/memprofile.rs` tier-18 twin after Cut D, recorded in docs/06 §3.

## 6. Rulings

1. **Row kinds in the REDUCE chip, not a new instance** — a new instance touches `machine.rs`, `shape.rs`,
   `witness.rs` and the self-verifier for the same rows and adds a full opened-column set per query; a row kind
   adds only its witness width. Costs if wrong: a wider chip opened at every query (bounded above: ≈ +2 000
   reduce rows per proof).
2. **One REDUCE cpu row per entry, not one per query** — a single walking dispatch would need per-entry
   timestamps (16 slots per clock; shared `px` cells read twice at one timestamp), a memory-table redesign the
   savings (≈ 9 400 rows) do not pay for. Costs if wrong: 9 520 cpu rows kept.
3. **Descriptors are preprocessed, never hinted** — a hinted address lets the prover reduce arbitrary memory.
   No alternative was considered sound. Costs if wrong: nothing; it is the conservative choice.
4. **The fold is DFT + Horner, not the Lagrange form** — the direct single-row constraint is degree a + 1 (9 at
   arity 8, over the cap); DFT + Horner is degree 2 at every arity and needs no extension inverse. Costs if
   wrong: the identity test in Task 0 catches a wrong derivation before a row is built.
5. **The inner FRI profile does not change in this phase** — rate ¼ needs about 120 queries by the proven bound
   (not the "40" compute-optimization.md §4.4 states, which is a doc error to be corrected separately), changes
   the wallet's proof and every fixture, and raises the query count this phase is cutting. Costs if wrong: a
   lever left on the table for phase 4.
6. **The gate is not widened** — if D + E + F land above 524 287 rows, the phase reports the measured result and
   the next lever; tier 19 is the definition of done, not a stretch target.
