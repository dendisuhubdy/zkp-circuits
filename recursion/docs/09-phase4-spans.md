# 09 — Phase 4: the Merkle spans — one inner verification in tier 19

Design: `docs/superpowers/specs/2026-10-09-rvm-phase4-spans-design.md`. Plan:
`docs/superpowers/plans/2026-10-09-rvm-phase4-spans.md`. Branch `feat/rvm-phase4-spans`, planned
on `71e1a04` (rate ¼ merged) and rebased before the first cut onto `c83b1c7` (the tree-aggregation
merge, which owns `docs/08-tree-aggregation.md`; this record is docs/09 for that reason). The
priced spike behind every expected figure is `docs/measurements/2026-10-08-merkle-spike-findings.md`.
Every row count here comes from the emulator's event log through `tests/profile.rs`
(`cargo test --release -p recursion --test profile -- --ignored --nocapture`), run after each cut
and copied to `docs/measurements/2026-10-09-span-profile-{baseline,d1,a,d2,b}.log`; every pin is
in `tests/pins.json` or a test literal. Every memory and time figure is a run of
`tests/memprofile.rs` (its heap profiler's peak live heap) or `tests/aggregate.rs` on this 48 GB
box (16 cores, `--features parallel`, `RAYON_NUM_THREADS=16`), with its raw log under
`docs/measurements/2026-10-09-*.log` (the runs were made on 2026-10-11; the files carry the
phase's date). No figure here is a process RSS; every other number is labelled a projection, with
its derivation.

**Result:** one verified production inner proof dropped from **585 686 to 315 952 cpu rows**
(−46.1 %), and so from **tier 20 to tier 19**, with 208 335 rows of headroom under the gate
(`≤ 2^19 − 1 = 524 287`) that phase 3 missed by 61 399. Four cuts, each in its ±15 % band: D1,
the cap select (−71 692); A, re-homing reloads (−127 296); D2, the in-place Merkle walk
(−20 479); B and B′, immediate-address `SPONGE` and `COMPRESS` (−50 267). The two Merkle spans
went from 368 791 rows to 125 289 and the allocator's reloads from 176 283 to 23 500. Poseidon2
permutations (54 515) and witness words (212 203) are unchanged: the cuts removed bookkeeping
around the hashes, never a hash. Every production aggregate moves down one tier — N=1 19, N=2
and N=3 20 (emulated) — and the production REG table from `2^21` to `2^20` (662 492 accesses).
On this box the test-profile proofs did not get lighter where their tier did not move: the exit
twin (169 366 → 104 150 rows) is tier 18 on both sides, and its peak live heap read **16.75 GB
before and 17.19 GB after** — the peak is a transient inside `compute quotient`, within the
spread seen between two runs of the same twin program on two bases (15.64 GB on `2fbd45b`,
16.75 GB on `c83b1c7`), while the committed terms fell (§4). The test N=2 aggregate dropped to
tier 18 and **proved and verified here**. The memory win is the tier: one rung down for every
production aggregate, projected in §5, measured nowhere yet.

## 1. Why

`docs/06` ended phase 3 at **585 686 cpu rows (tier 20), 61 399 above the tier-19 gate**, and its
§7 item 1 named the next lever: the two Merkle spans, `input_root` (**248 151** rows, 42.4 %)
and `commit_root` (**120 640**, 20.6 %) — 368 791 rows, 63 % of the program, 133 827 of them the
allocator's reloads. Crossing the gate puts every aggregate one tier lower, which halves its cpu
table and every trace term that follows the cpu height; `docs/07` had taken the production N=1
aggregate to ≈ 64–75 GB projected at tier 20. The baseline was re-measured on this branch before
the first cut (`2026-10-09-span-profile-baseline.log`): the same 585 686 rows, the same two span
figures, so the rebase onto the tree-aggregation merge moved nothing in `rv32`.

## 2. Where the rows went (the spec's §0.1, measured)

Production fixture, 80 queries, the baseline log's `== profile Production` section:

- **Reloads never re-homed.** `replay`'s `Mat` arm loaded a spilled handle into a scratch
  register (`r26..r31`) for one use and left it spilled, so each later use paid another `LOAD`.
  The register file is full for the whole program — `live_max` **25** of `r1..r25` — because the
  tape for all 80 queries is read before any query runs. **176 283** reloads in all; **97 987** in
  `input_root` and **35 840** in `commit_root`.
- **Pointers were registers.** A `Ptr` is a holder register plus a compile-time delta, and
  `SPONGE`, `COMPRESS` and `POSEIDON2` took register addresses only (`POSEIDON2` still does,
  §9), so each use paid one `FADDI` although every address is a compile-time constant:
  `FADDI` **41 521** rows in `input_root`, **10 720** in `commit_root` (67 307 in the program).
- **The cap check selected a cap entry by a dot product** over the four candidates, 88 rows a
  round over 14 rounds a query (the spike's count): `commit_root`'s `FMUL` 14 400, `FADD` 8 640
  and `FSUB` 4 320, `input_root`'s `FMUL` 8 000, `FADD` 4 800 and `FSUB` 2 400.
- **The walk copied the digest** leaf → running cell → out, 16 rows a walk; 1 120 walks a proof
  (400 in `input_root`, 720 in `commit_root`).

So a bit-driven `COMPRESS` cost ≈ 3.94 rows and a `SPONGE` block ≈ 3.91 instead of one (the
spike's per-op count). Per query the spans were 3 101.9 rows (`input_root`) and 1 508.0
(`commit_root`).

## 3. The four cuts

| after | cpu rows | expected Δ (spike) | measured Δ | band (±15 % of expected) | verdict | `input_root` | `commit_root` | reloads | log |
|---|---:|---:|---:|---|---|---:|---:|---:|---|
| baseline | 585 686 | — | — | — | — | 248 151 | 120 640 | 176 283 | `-baseline` |
| D1 (cap select) | 513 994 | −71 692 | **−71 692** | −60 938 … −82 446 | in (0.0 %) | 222 551 | 74 560 | 153 884 | `-d1` |
| A (re-homing) | 386 698 | −127 296 | **−127 296** | −108 202 … −146 390 | in (0.0 %) | 137 201 | 56 560 | 26 056 | `-a` |
| D2 (no copies) | 366 219 | −19 359 | **−20 479** | −16 455 … −22 263 | in (+5.8 %) | 129 762 | 43 520 | 25 737 | `-d2` |
| B + B′ (immediates) | **315 952** | −50 024 | **−50 267** | −42 520 … −57 528 | in (+0.5 %) | 90 329 | 34 960 | 23 500 | `-b` |

The tier gate was met at the first cut (513 994 ≤ 524 287, 10 293 rows of headroom), as the plan
required. The final total is 1 363 rows under the spike's 317 315: D2 landed 1 120 rows past its
estimate (each walk saved ≈ 18.3 rows, the 16 copy rows plus ≈ 2 of store, load and reload
effects around them) and B/B′ 243 past. D1 and A reproduced the spike to the row. The test
profile followed: 169 366 → 155 018 → 118 320 → 114 225 → **104 150** rows.

**D1 — the cap select** (`hash::assert_cap_entry`, `Builder::load_offset`; `rv32::assert_cap_eq`
under `Precompiles::On`). From the cap-index bits it computes `off = 4·b0 + 8·b1` (two `FMULI`,
one `FADD`), then for each lane one register-offset `LOAD [cap0 + lane + off]` asserted equal to
the walk's digest under the check's name. *Soundness:* the bits are boolean — `sample_bits`
constrains every bit where it is born — so `off ∈ {0, 4, 8, 12}`; the four caps are one
contiguous 16-cell allocation, asserted at build time (`read_cap` and `constant_cap` allocate
them so); the cpu AIR range-checks every `LOAD` address. It is the pattern `docs/06` Cut E1 ruled
sound for the own-slot check. `Precompiles::Off` keeps the indicator dot product as the
differential reference.

**A — re-homing reloads** (`dsl/builder.rs`, `replay` and `claim`; `Liveness::On` builds, both
`Precompiles` settings). On a reload the allocator may claim a real register instead of a
scratch one, when the handle's next use is nearer than the farthest-next-use resident's; the
evicted resident is spilled as before, and the re-homed handle keeps its spill cell, so evicting
it again costs no `STORE` (it is evicted clean). The rules, each with a test in
`tests/allocator.rs`: (1) never evict a register the instruction being fed already reads — the
`Mat` outputs and the operand homes up to the next group are pinned; (2) never re-home inside an
`if_eq` body, so both arms leave the register file in the same state; (3) inside a loop, re-home
only values defined in the innermost body, never one from before the loop. Two guards complete
it. The **mutable guard**: a handle written in place after its definition (`counted_loop`'s
counter) is never re-homed — today rule 3 and the loop invariant already exclude it (the counter
is defined just before its own `LoopTop` and never spilled outside its loop), so the guard is
defence in depth and its test a regression guard against a relaxed rule 3. The **pre-loop
guard**: inside a loop, a re-home claim pins the residents defined before the innermost loop,
and a fresh handle's `Def` claim prefers any other victim over them, falling back to the old
choice only when none exists. The `Def` preference is output-neutral for every build that
succeeded before it (production and test `verify_rv32`, the self-verifier and the DSL sample
rebuilt to the same digests with it alone), because evicting a pre-loop resident inside a body
always tripped the `LoopEnd` invariant: it only turns such refusals into builds. A re-homed
handle that dies frees both its register and its cell (the cell bound is tested). `Liveness::Off`
stays the byte-for-byte pre-liveness reference: the spec's §1.2 line "`Precompiles::Off` builds
get re-homing too" was built as "both `Precompiles` settings under `Liveness::On`", and the
Off-replay digest did not move at A.

**D2 — no digest copies** (`hash::merkle_walk`, `merkle_walk_with_injections`). Under
`Precompiles::On` the walk compresses over the caller's leaf digest in place and returns it; no
copy in, no copy out. *Soundness:* the leaf is consumed by design, so it must alias nothing the
walk reads — a build-time assertion ("the walk consumes its leaf") refuses a leaf that overlaps
the siblings (4 × levels cells), any injection row or the 16-cell hash scratch; every caller reads
the returned digest. `Precompiles::Off` copies the result into the leaf and returns it. The
Off-replay digest moved here (`c580415b…` → `759b015d…`, `tests/verifier.rs`), with its
history clause.

**B and B′ — immediate-address `SPONGE` and `COMPRESS`** (`isa.rs`, `tables/cpu.rs`,
`emulator.rs`, `dsl/builder.rs`). The fourth word of `SPONGE` (opcode 25, the source block) and
`COMPRESS` (27, the sibling digest) is now the **absolute address**, not a register index: both
leave `Op::b_is_register` and `Sels::B_REG`. *Soundness:* the existing immediate-form
constraints `(1 − is_b_reg)·(B0 − B) = 0` and `(1 − is_b_reg)·B1 = 0` now bind `B0 = B` and
`B1 = 0` on both rows; `B` is a program word, fixed by the preprocessed program table the verifier
key commits, so a prover cannot choose it; the hash buses and both address-limb groups already
read `B0`, so the block stays range-checked — group 4 (the base limbs) refuses a base at `p − 2`,
group 2 (the top-cell limbs) refuses a top cell at `2^24`, each shown to be the sole refuser of
its case by neutralising the other. The emulator reads `b` from the word and refuses
`b + 3 ≥ 2^24` with `AddressOutOfRange` naming the pc. **No new column, no degree change**,
`Op::COUNT` stays 30, and each `SPONGE`/`COMPRESS` row sends one fewer `REG` message. The DSL
emits `addr_of(ptr)` and no longer materialises the holder: `input_root`'s `FADDI` 40 321 →
2 401, `commit_root`'s 8 560 → 720, and `reg_accesses` 815 063 → 662 492.

## 4. Measured

One run each, before and after, same box, 16 threads, `--features parallel`, Test profile, run
one at a time on 2026-10-11. **Before** is the base `c83b1c7` (the existing circuits checkout on
`main`, with its own tests); **after** is `d155616`. Logs: `2026-10-09-twin-before.log`,
`-twin-after.log`, `-tier16-before.log`, `-tier16-after.log`, `-aggregate-n2.log`. Every heap
figure is the heap profiler's `peak live heap`; the logs' `rss` columns are not used.

| | before (`c83b1c7`) | after (`d155616`) | ratio |
|---|---:|---:|---:|
| exit twin: cpu rows, tier | 169 366, tier 18 | **104 150**, tier 18 | ×0.61 |
| — peak live heap | 16.75 GB | 17.19 GB | ×1.03 |
| — prove wall | 120.3 s | 114.8 s | ×0.95 |
| — verify | 3.46 s | **2.19 s** | ×0.63 |
| — proof bytes | 264 682 B | 273 511 B | ×1.033 |
| tier-16 synthetic: cpu rows, tier | 63 762, tier 16 | 60 012, tier 16 | ×0.94 |
| — peak live heap | 3.84 GB | 3.99 GB | ×1.04 |
| — prove wall | 28.3 s | 28.0 s | ×0.99 |
| — proof bytes | 219 442 B | 219 154 B | ×0.999 |
| test N=2 aggregate | tier 19, 338 871 rows (proved at rate ¼, `docs/07` §3) | **tier 18**, 208 571 rows (`pins.json` `aggregate_test_n2_cpu_rows`; the test's own `RvmTier(18)` assertion held): proved, verified natively, eight outputs matched; 273 961 B, test wall 124.3 s (the log's two figures) | — |
| test N=3 aggregate | tier 19, 508 102 rows, not run | tier 19, 312 665 rows, **not run** (below) | — |

**The twin's peak did not fall, and that is expected at an unchanged tier.** The cpu table is
`2^18` either way; the REG table (411 319 → 263 336 accesses) and the RAM table (442 445 →
394 310) stay `2^19`; only the preprocessed program table halves (171 771 → 106 555
instructions, `2^18` → `2^17`). The committed terms show that: live heap after the third main
`build merkle tree` 7.38 → 6.97 GB, and at the end of the `FRI prover` 12.35 → 11.77 GB. The
peak is set later, by a transient in the parallel `compute quotient` spans: the span that
reaches it rose from Δlive +5.78 GB before to +8.61 GB after. Why is **not traced**; the likely
cause is how the nested parallel work is scheduled, since the same program read 15.64 GB on
2026-10-08 (`docs/07` §3, on `2fbd45b`) and 16.75 GB here on `c83b1c7`, so a 0.44 GB difference
between two single runs is inside the spread; the tree-aggregation merge between those two
bases is not traced as a cause either way. The verify drop (×0.63) follows the smaller program
table, whose LDE and tree the verifier builds; the proof's +8.8 kB is **not traced** (one run a
side).
The tier-16 synthetic is a DSL program too, so B′'s immediates and re-homing cut it 63 762 →
60 012 rows; its peak live heap moved +0.15 GB (+4 %), **not traced** (one run a side).

**The test N=3 aggregate was not run.** The brief's condition is the N=2 run's peak live heap
≤ 30 GB, and `two_test_profile_bundle_proofs_aggregate_and_verify_natively` is not under the heap
profiler and prints no heap figure, so the condition cannot be shown; the N=3 proof is tier 19
with the RAM table at `2^21` (1 182 161 accesses), and its ignore note still asks for a
≥ 64 GB host. The production N=1 proof is not run on this box.

**The production rows** (emulated; `2026-10-09-span-profile-b.log`, `pins.json`):

| | before (phase 3 / rate ¼) | after |
|---|---:|---:|
| one inner verification: cpu rows | 585 686 (tier 20) | **315 952 (tier 19)** |
| — `reg_accesses` (REG table) | 1 290 039 (`2^21`) | **662 492 (`2^20`)** |
| — mem accesses (RAM table) | 1 903 581 (`2^21`) | 1 718 640 (`2^21`) |
| — program instrs | 597 259 | 327 525 |
| — permutations / witness words | 54 515 / 212 203 | unchanged |
| — reloads / spills (builder) | 176 283 / 10 826 | 23 500 / 9 110 |
| production N=1 aggregate | tier 20 | **316 279 (tier 19)** |
| production N=2 aggregate (B3 emulation) | 1 171 511 (tier 21) | **632 175 (tier 20)** |
| production N=3 aggregate (B3 emulation) | 1 757 062 (tier 21) | **948 071 (tier 20)** |

The table heights follow the declared-height rule `docs/06` §3 uses (the next power of two over
the accesses): REG 662 492 is under `2^20`, so the production REG table halves; RAM 1 718 640
stays `2^21`. The spec projected the REG move (§2); it is measured here by the access count, not
by a production proof.

## 5. N-economics

Production rows per aggregate, emulated (N=1 is Task 5's emulation for the
`aggregate_program_digest` re-pin, 315 952 + 327; N=2 and N=3 are the B3 emulations above):

| N | cpu rows | tier | before phase 4 |
|---:|---:|---:|---|
| 1 | 316 279 | **19** | tier 20 |
| 2 | 632 175 | **20** | 1 171 511, tier 21 |
| 3 | 948 071 | **20** | 1 757 062, tier 21 |

Each further proof adds 315 896 rows (N=2 − N=1 = N=3 − N=2, exactly), so by arithmetic — a
projection, not an emulation — N=4 is ≈ 1 263 967 rows and N=5 ≈ 1 579 863, both tier 21
(`≤ 2^21 − 1`); tier 21 would hold cpu rows to N=6. **The reduce chip's N ceiling does not move:**
the reduce rows are a compile-time function of the program and phase 4 changed none of them
(196 480 a production proof, the `reduce` span still 20 001 cpu rows; pinned in
`tests/aggregate.rs`), so `REDUCE_MAX_LOG_HEIGHT = 20` still caps production at **N ≤ 5**.

**The recommendation the fullnode follow-through applies:** the production flat path's
`admitted_tiers` move from **{20, 21, 22}** to **{19, 20, 21}** — tier 19 for N=1, 20 for N=2–3,
21 for N=4–5 — with the N ≤ 5 ceiling unchanged; tier 22 admits nothing a valid production
aggregate can be. The test profile: N=1 104 477 (tier 18), N=2 208 571 (tier 18, was 19), N=3
312 665 (tier 19).

**Memory (projection).** Nothing at production has been measured. `docs/07` §4 projected the
production N=1 aggregate at ≈ 64–75 GB at tier 20; at tier 19 the cpu table and every term sized
by it halve, the REG table halves with it (`2^21` → `2^20`), and the RAM table does not
(`2^21`, 1 718 640 accesses). So the all-terms-halved figure, ≈ 32–38 GB, is a floor and
`docs/07`'s range a ceiling; the twin's measurement (§4) is a reminder that the peak is set by a
quotient transient, not by the committed terms alone. The host class for production N=1 is a
measurement for a larger host, not this record's claim. The production N=2 and N=3 emulations ran
again for this record (`2026-10-09-prod-n2-emulate.log`, `-prod-n3-emulate.log`): 632 175 rows,
109 004 permutations, 3 436 992 mem accesses; 948 071 rows, 163 491 permutations, 5 155 151
mem accesses; both inside the `2^27` timestamp window.

## 6. What moved, and what did not

| pin | before | after | where |
|---|---|---|---|
| one inner verification (production) | 585 686 rows, tier 20 | 315 952, tier 19 | `pins.json` `cpu_rows`; `exit::the_cycle_budget_per_inner_proof_is_pinned` (gate assertion now `≤ 2^19 − 1`) |
| mem accesses / program instrs | 1 903 581 / 597 259 | 1 718 640 / 327 525 | `pins.json` |
| `phase3_attribution` | reg 1 290 039; select 7 680; fold_round 5 040; bit_selected_power 7 680; commit_root 120 640; sample_bits 58 076; reloads 176 283; spills 10 826 | reg 662 492; 6 400; 4 320; 5 280; 34 960; 53 013; 23 500; 9 110 (reduce 20 001 unchanged) | `pins.json` |
| `verify_rv32.digest` | `cf5a350a…` | `6a70c377…` | `src/programs/verify_rv32.digest` |
| production `aggregate_program_digest` | `dc350ecf…` | `e0eede8b…` | `tests/aggregate.rs` |
| test-shape aggregate digest | `df3a18b8…` | `1bcbcec9…` | `tests/verifier.rs` |
| Off-replay digest | `c580415b…` | `759b015d…` (at D2) | `tests/verifier.rs` |
| test aggregates N=1/2/3 (rows) | 169 640 / 338 871 / 508 102 | 104 477 / 208 571 / 312 665 | `pins.json` |
| test aggregates N=1/2/3 (mem accesses) | 442 594 / 884 514 / 1 326 434 | 394 503 / 788 332 / 1 182 161 | `pins.json` |
| `LOOP_OVERHEAD` | 274 | 327 | `tests/aggregate.rs` |
| `N3_ROWS` | 508 102 | 312 665 | `tests/aggregate.rs` |
| B3 emulation N=2 / N=3 | 1 171 511 / 1 757 062 (tier 21) | 632 175 / 948 071 (tier 20) | `tests/aggregate.rs` |
| self-verifier digest | `b42ae772…` | `515fc2a1…` | `tests/self_verify.rs` |
| toy `CycleReport` | (101209, 6008, 247568, 103217, 23775) | (66560, 6008, 222897, 68568, 23775) | `tests/self_verify.rs` |
| busy `CycleReport` | (126541, 7578, 291961, 128941, 29479) | (77285, 7578, 256092, 79685, 29479) | `tests/self_verify.rs` |
| self-verifier phase 5 | (7933, 8213) | (7929, 8209) | `tests/self_verify.rs` |
| exit twin (test) | 169 366 rows, tier 18 | 104 150, tier 18 (no tier-17 rung) | `tests/exit.rs`, `tests/memprofile.rs` |
| tree, test profile | §7 | §7 | `pins.json` `tree_test`, `tests/tree.rs`, `tests/tree-test-genesis.json` |
| tree, production (emulated) | leaf 1 171 511 (21); rv32r 648 910 (20); child 648 518; step 1 294 577 (21); band [1 102 455, 1 491 559] | leaf 632 175 (20); rv32r 347 673 (19); child 347 358; step 695 097 (20); band [590 828, 799 356] | `pins.json` `tree_measure` |

**Two moves are measured but not attributed.** `LOOP_OVERHEAD` (the test N=1 aggregate's rows
less one verification's) rose 274 → 327 (104 477 − 104 150): the spike measured 318 for its
software package (D1 + A + D2, `2026-10-08-merkle-spike-findings.md`), so ≈ 44 of the 53 came
with the software cuts and the remaining ≈ 9 with B/B′ — by subtraction across two builds, not
traced to an instruction. The self-verifier's phase 5 lost 4 instructions (7933 → 7929); phase 5
is the constraint evaluation, which no cut targets, and the inner verifier's own phase 5 moved by
allocator effects of the same kind (26 404 → 26 402 at D1, → 25 609 at A, in the span logs) —
for the self-verifier this is **not traced**.

**The rVM verifier keys did not move (a correction to the spec).** Spec §2 lists "the rVM
verifier keys (the cpu AIR's `B_REG` set changes the constraint system)" under *moves*. That line
is wrong: `tests/verifier_key.rs`'s caps (`WANT`, `WANT_REDUCE`) pin the **preprocessed
commitment** — the program table and the range tables — and `B_REG` is an in-AIR selector sum
over the opcode columns, so it reaches the verifier through the chips' constraint code, not
through any committed matrix. The caps passed unchanged through B/B′ and the re-pin. That the
changed constraint bites is shown by the cheating suite (§8), not by a key move.

**Asserted unchanged** (the global constraints): the inner RV32 machine and every wallet proof;
`inner_vk_digest` and the admission-stub vectors (`346ee184…`); the interface
`[vk ‖ N ‖ B(8) ‖ 35·N]`; the FRI profiles (inner 80/8/20; `RvmFri` Production (2, 92, 24), Test
(2, 16, 4)); the quotient layout; the reduce chip and its rows; the poseidon2 table (54 515
permutations a proof); `NUM_REGS`, `ALLOCATABLE` (`r1..r25`) and `SCRATCH` (`r26..r31`);
`Op::COUNT` 30; `tests/security.rs`, `tests/quotient_layout.rs`, `tests/machine.rs`.

## 7. The test tree's fixed point moved from level 3 to level 2

`docs/08` §5 found the test-profile tree's fixed point at level 3: `rv32t_leaf` ran
2 × 32 272 = 64 544 reduce rows (under `2^16`) while `rv32t_int`, over tier-19 children, ran
2 × 33 296 = 66 592 (over it), so the root declared a different reduce height and arity schedule
and needed a third program. After phase 4 both steps are **tier 18** and **both** cross `2^16`
(2 × 32 912 = 65 824 and 2 × 33 328 = 66 656 reduce rows), so the root declares exactly S_T's
header words, `rv32t` at the root's shape is `rv32t_int` itself (the same digest), and
`rv32t_int` verifies its own proofs: **the fixed point is level 2**. The test profile's lists are
now **2 step programs** (`rv32t_leaf`, `rv32t_int`) and **3 keys** (`vk_leaf`, `vk_t_leaf`,
`vk_int`), the last of each repeating; `T_FIX_TEST`, `vk_fix` and `step_fix_cpu_rows` are dropped.
The spec binds the rule (the last entry repeats only at a fixed point), not the level.

| | tier, reg, ram, p2, **reduce**, program, queries | log arities |
|---|---|---|
| S_T (`rv32t_leaf` proof, proved) | 18, 19, 20, 15, **17**, 17, 16 | 1, 1, 1, 2, 3, 3, 1, 3, 2, 3, 1 |
| S_root (`rv32t_int` proof, proved) | 18, 19, 20, 15, **17**, 17, 16 | 1, 1, 1, 2, 3, 3, 1, 3, 2, 3, 1 |

| pin | value |
|---|---|
| C (`tree_test.child_cpu_rows`) | 91 034 (was 143 568) |
| `rv32t_leaf` over leaves 0, 1 | 182 444 rows, tier 18 (was 287 107, 19); O = +376 (was −29) |
| `rv32t_int` over step-0, step-1 | 185 267 rows, tier 18 (was 306 985, 19) |
| reduce rows per child, leaf / int | 32 912 / 33 328 (was 32 272 / 33 296) |
| `T_LEAF_TEST` | `d8d558eecb8fbdaaba7eaa93d7d04bae0a47808f31978ecea804f04f7e6e5d93` |
| `T_INT_TEST` (also `rv32t` at S_root) | `a222637e1eb9333b16b820bbacceaac9ea0e5d4cebfc5379d170796a2ac6dc62` |
| `vk_leaf` | `8fef0bda7fd95afc5e13f78313cd972994fa0fcb7cbce8cd0296cc1985e3377a` |
| `vk_t_leaf` | `0214ac3a79a57671a481c4ed519a9ae06eaaa76aaae75c0140f776fc8a48171c` |
| `vk_int` (children of every level ≥ 2's step at S_root) | `f97291efbacd55ada93b618cb9a58671aedc4d1ea8b390620d281ca0524ef767` |

(Key digests are the four `inner_vk_digest` limbs of `pins.json` as canonical u64, 16 hex digits
each; the header words are `tests/tree.rs`'s literal.) The test fixtures (four leaves, two
steps, the root, the foreign leaf) were re-proved on this box
(`docs/measurements/2026-10-11-tree-test-fixtures-phase4-laptop.log`: every step and the root
tier 18, reduce `2^17`; that log's process figures are not a memory measurement). Under S_T
itself — the same words, but `rv32t_leaf`'s program and so its key — the tape builder refuses the
root with `Replay(Constraints(0))`: the hinted cap is the child's own, and the restated
`the_interior_step_verifies_its_own_output_at_the_test_profile` asserts both halves.

Two things follow and are **not done here**: the fullnode's test-profile `aggregation_tree`
section (and `the_rebuilt_test_tree_keys_are_the_circuits_pins`) must change at the re-vendor —
3 → 2 steps, 4 → 3 keys, the regenerated `tests/tree-test-genesis.json`; and the **production**
tree's fixed-point level is still unmeasured — its list length comes from the production
emulation over a proved production depth-2 tree, which needs the 256 GB droplet (`docs/08` §4).

## 8. Testing

- **D1** (`tests/dsl.rs`): `assert_cap_entry_selects_each_of_the_four_digests_by_its_bits`,
  `assert_cap_entry_traps_at_its_name_on_the_wrong_digest`,
  `load_offset_adds_a_runtime_offset_to_a_compile_time_address`.
- **A** (`tests/allocator.rs`): `a_reload_rehomes_into_a_real_register_and_the_result_is_unchanged`,
  `a_rehome_never_evicts_an_operand_of_the_instruction_it_feeds` (rule 1),
  `no_reload_inside_an_if_eq_body_lands_in_an_allocatable_register` (rule 2),
  `a_loop_body_rehomes_only_its_own_values_and_never_moves_a_pre_loop_handle` (rule 3 and the
  pre-loop guard), `the_counted_loop_counter_is_never_rehomed` (the mutable guard's regression
  test), `rehomed_values_return_their_cells_when_they_die` (cells bounded by the non-re-homing
  arena). `tests/dsl.rs::a_loop_body_that_evicts_a_pre_existing_handle_is_refused` was reshaped
  (24 pre-loop constants read after the loop) so only pre-loop victims exist and the `LoopEnd`
  refusal still fires.
- **D2** (`tests/precompiles.rs`): `a_walk_whose_leaf_aliases_its_siblings_is_refused_at_build`,
  `a_walk_whose_leaf_aliases_an_injection_is_refused_at_build`; the walk tests read the returned
  digest. The hash-scratch clause of the aliasing assertion is untested (`hash_scratch` is
  `pub(super)`).
- **B/B′:** `tests/cheating.rs` — `honest_immediate_address_hash_traces_pass`,
  `a_sponge_source_moved_off_its_immediate_is_rejected`,
  `a_compress_sibling_moved_off_its_immediate_is_rejected`,
  `a_forged_second_pointer_limb_on_an_immediate_row_is_rejected`; `tests/cpu.rs` —
  `sponge_and_compress_rows_send_no_rb_register_read`, the extended binding test
  `every_operand_a_dispatch_carries_is_read_from_a_register` (a carried `B0` on a non-register
  fourth word passes only if a row constraint holds at `B0 = B` and fails at `B0 = B + 1`), and
  `a_multi_cell_access_whose_base_wraps_below_zero_is_refused` with `B` moved with `B0`, so each
  limb group is the sole refuser of its case; `tests/emulator.rs` —
  `sponge_and_compress_read_their_second_address_from_the_immediate`,
  `a_sponge_or_compress_immediate_past_the_address_space_is_refused_by_name`; `tests/isa.rs`.
- **Tree (ruling 10):** `the_interior_step_verifies_its_own_output_at_the_test_profile` and
  `the_step_program_at_the_roots_shape_is_rv32t_int_the_fixed_point` replace the two level-3
  tests; the shapes-rebuild and layout-refusal tests use `[S_T, S_root]` and `[S_T]`.
- **The suite:** `cargo test --release --no-fail-fast -- --skip a_one_proof_aggregate_round_trips`
  — **341 passed, 0 failed, 31 ignored** (298 passed, 20 ignored at the rate-¼ end; the rest is
  tree aggregation's tests from the base, `tree.rs` 22 + 1 ignored and `tree_measure` 3 + 10
  ignored, plus this phase's). `tests/tree.rs` alone: 22 passed over freshly proved fixtures.
  `tests/backend.rs` with `--features reference-backend` and with `--features mock-cuda`: 3
  passed each.
- **This record's runs** (§4): the twin and the tier-16 synthetic before and after, the test N=2
  aggregate, the production N=2 and N=3 emulations — each passed (1 passed, 0 failed).

## 9. Out of scope, recorded

- **The path-level precompile** (`docs/06` §7 item 1's third candidate): ≈ −50 to −56 k alone,
  less behind A and B, and the largest AIR surface.
- **Compressing injections straight from the hash scratch** (≈ −16 k, not built in the spike) — a
  follow-up if headroom is wanted.
- **`POSEIDON2` immediate addresses** (B's pattern; a small count in these spans).
- **The inner FRI profile; the reduce chip's N ceiling; device-resident LDEs.**
- **The production proofs:** the production N=1 aggregate at tier 19, the production tree and its
  fixed-point level — on a larger host.
- **The fullnode re-vendor** (`deploy/sync-zkvm.sh`, `CIRCUITS_PIN`, the `aggregate_program_digest`
  re-pin, `admitted_tiers` from §5, the test-tree section of §7) — its own task after merge.

## Conclusion

Phase 4 put one production inner verification in **tier 19: 315 952 rows**, 208 335 under the
gate phase 3 missed, by four program and ISA cuts that each landed in their band — the cap select
and re-homing to the row, the in-place walk 5.8 % past its estimate, the immediates 0.5 % past.
The two Merkle spans fell from 368 791 rows to 125 289 and the reloads from 176 283 to 23 500,
with not one hash added or removed. The inner machine, the interface, the FRI profiles, the
reduce chip and the rVM verifier keys did not move. Every production aggregate is one tier
lower — N=1 19, N=2 and N=3 20 — so the node's admitted tiers become {19, 20, 21} under the
unchanged N ≤ 5 ceiling. On this box the exit twin, still tier 18, keeps its peak (16.75 →
17.19 GB, within the spread) and verifies ×0.63 faster, and the test N=2 aggregate, now tier
18, proves and verifies. What the tier is worth in memory at production is projected, between
≈ 32 and 75 GB, until a production proof runs on a larger host.
