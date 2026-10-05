# 05 — Phase 3: the REDUCE chip takes the descriptor layout, the fold and the index powers

Design: `docs/superpowers/specs/2026-10-05-rvm-phase3-fold-reduce-design.md`. Plan: `docs/superpowers/plans/2026-10-05-rvm-phase3-fold-reduce.md`.

## 1. Where the rows go (Task 0, measured 2026-10-05, production fixture)

```
== profile Production: inner tier Tier(14), 893606 cpu rows, 54515 permutations, 2213181 mem accesses, 2147159 reg accesses, 210763 witness words, 903739 program instrs
-- shape: log_arities [1, 1, 2, 2, 2, 1, 3, 3, 2] (sum of arities 38), degree_bits [13, 15, 17, 16, 9, 9, 17, 11, 8], queries 80
-- rows per call site (executed; reloads and spills inside it; per query; top opcodes)
      116498   13.0%  (none)               reload   21160 spill   5429  /query   1456.2  [HINTN 24030, LOAD 21467, STORE 19302, LOADE 9555, HINT 8910, FADDI 7082]
       57276    6.4%  sample_bits          reload   12736 spill   4993  /query    716.0  [LOAD 12816, FMUL 7938, FSUB 5427, JEQ 5427, HINT 5265, FADDI 5184]
      248151   27.8%  input_root           reload   97987 spill      3  /query   3101.9  [LOAD 121107, FADDI 41521, SPONGE 33520, STORE 24723, COMPRESS 9200, FMUL 8000]
      163601   18.3%  reduce               reload   18480 spill   2881  /query   2045.0  [STOREE 40480, FADDI 40320, LOADE 37040, STORE 29041, REDUCE 9520, MOV 4480]
       87920    9.8%  bit_selected_power   reload   17280 spill    240  /query   1099.0  [FADDI 35840, FMUL 34560, LOAD 17280, STOREE 240]
       50960    5.7%  select               reload   12240 spill    480  /query    637.0  [LOAD 12240, EADD 6080, ESUB 6080, EMULF 6080, LOADE 5360, FADD 4320]
       36640    4.1%  fold_round           reload    1840 spill    880  /query    458.0  [MOV 7520, EMUL 6080, FMUL 4400, FMULI 3760, FSUB 3040, EMULF 3040]
      129600   14.5%  commit_root          reload   35280 spill      0  /query   1620.0  [LOAD 60240, FMUL 14400, STORE 14400, FADDI 11440, FADD 8640, COMPRESS 7040]
        2960    0.3%  roll_in              reload    1280 spill      0  /query     37.0  [LOADE 1280, EMUL 1200, EADD 480]
```

Spans nest and the innermost wins: `bit_selected_power` rows called from inside `reduce` and `fold_round` are
counted under `bit_selected_power`, not under their caller. Totals: reloads 218 283, spills 14 906, REDUCE
dispatches 9 520. Inside `reduce`, beyond the top six: FSUB 1 120, EINV 1 120, LOAD 480 (MOV 4 480 is in the list).

Q = 80, R = 9, E = 119 (9 520 / 80), H = 7 (the global height 20 plus the six roll-ins at 19, 18, 16, 14, 12, 11),
K = 14 (1 120 EINV in `reduce` / 80 = inverse keys per query). Spec §1's derived table, against this one:

- REDUCE descriptor build: 133 280 code minimum, ≈ 238 000 with reloads → `reduce` 163 601 (17.2 rows per
  dispatch; 18 480 reloads, 2 881 spills inside it).
- Fold chain (select + fold + roll-ins): 73 840 op-count minimum, up to ≈ 228 000 → `select` 50 960 + `fold_round`
  36 640 + `roll_in` 2 960 = 90 560 (1 132 per query).
- Arity schedule: Σa = 38 over 9 rounds (3 × 2, 4 × 4, 2 × 8) → measured `[1, 1, 2, 2, 2, 1, 3, 3, 2]`, as derived.
- `bit_selected_power`: ≈ 32 000–64 000 → 87 920 (1 099 per query, ≈ 274 bits per query at 4 rows per bit), 37 %
  above the derived ceiling.
- Allocator reloads 218 283 / spills 14 906 → 218 283 / 14 906, as derived; by site: `input_root` 97 987,
  `commit_root` 35 280, `(none)` 21 160, `reduce` 18 480, `bit_selected_power` 17 280, `sample_bits` 12 736,
  `select` 12 240, `fold_round` 1 840, `roll_in` 1 280.
- Memory: REG 2 147 159, RAM 2 213 181, as spec §1.

## 2. The landing bands (±15 % of each cut's projected delta; phase 2 §6 ruling 1)

T₀ = 893 606. Each band is [T_prev − 1.15·Δ, T_prev − 0.85·Δ], with T_prev the previous cut's *measured* rows.

| cut | Δ (projected rows removed) | formula | band (Task 0) | measured | in band |
|---|---:|---|---|---:|---|
| D | 145 441 | rows(reduce) − [EINV+MOV+FSUB in reduce] − Q·(E + H + K + 3) | 726 349–769 981 | 749 846 (Δ −143 760) | yes |
| E1 | 35 120 (ruled; was 54 160) | rows(select) − Q·Σ_r(2·la_r + 5) − Q·Σ_r(a_r + 9) | 709 458–719 994 | 703 766 (Δ −46 080) | **no** (below; accepted) |
| E2 | 40 800 (re-read after E1; was 33 760) | rows(fold_round, re-read after E1) − 4·Q·R | 656 846–669 086 (from E1's measured 703 766) | | |
| F | 82 800 | rows(bit_selected_power) − 4·Q·(H + R) | relative to E2's measured | | |

Inputs: D = 163 601 − (1 120 + 4 480 + 1 120) − 80·(119 + 7 + 14 + 3); E1 = 50 960 − 80·79 − 80·119 (Σla = 17,
Σa = 38); E2 = 43 680 − 4·80·9, with `fold_round` re-read after E1 (36 720 → 43 680: the row loads moved into it);
F = 87 920 − 4·80·16.

**E1's sign (controller ruling, Task 2).** The plan wrote E1's last term with a `+`, which gave Δ_E1 = 54 160, more
than the whole `select` span (50 960). The ruled formula subtracts it: Δ_E1 = 35 120 (spec §2.2's "−35 000 to
−40 000"), band [749 846 − 1.15·35 120, 749 846 − 0.85·35 120] = 709 458–719 994.

**E1 measured below its band (Task 2).** Production lands at 703 766 rows (Δ −46 080, 10 958 rows past the
projection). The miss is `commit_root`, which the formula prices as unchanged: the leaf is now sponged in place, so
each round no longer stores the `arity` row values into a fresh buffer (Σa = 38 STOREE a query) or copies its four
salts (2 rows a cell, 72 a query). `commit_root` 129 600 → 120 640 (−8 960). The other spans: `select`
50 960 → 7 680 (−43 280; Q·Σ(2·la + 5) = 6 320 derived, 96 a query measured, with 17 reloads a query), `fold_round`
36 720 → 43 680 (+6 960; the formula's Q·Σ(a + 9) = 9 520 credit), `(none)` 116 498 → 115 778 (−720: the
tape reads, HINTN +240, HINT −480, STORE −480), `roll_in` 2 960 → 2 880 (−80). Sum −46 080.
**Ruling (controller, 2026-10-05): accepted.** 703 766 is E1's landing point. The band's model kept the per-round
row store and salt copy that sponging the leaf in place removes. That is an omission in the band's model, not an
anomaly in the cut. The correctness evidence is the On/Off differential, the tamper tables and the own-slot refusal.
The miss is recorded in spec §2.5. E2's band above (Δ 40 800, 656 846–669 086) stands.

Memory targets: REG 2 147 159 → under 2 097 152 (needs −50 008); RAM 2 213 181 → under 2 097 152.

## 3. Memory (Task 1b, measured 2026-10-05)

**The declared memory tables.** Both rVM memory tables are sized `pad_height(accesses + 1)` (`machine::build_traces`).
Production, before → after Cut D: REG 2 147 159 → **1 785 559** accesses, RAM 2 213 181 → **1 913 981**. Both are now
under 2 097 152, so both tables declare **2^21** (they were 2^22). The cpu table stays at 2^20 (749 846 rows, tier 20).
Test profile (the twin's shape): REG **510 423** → 2^19, RAM **444 525** → 2^19, cpu 202 198 rows → tier 18. The twin's
pre-cut REG count was never measured; its main-tree Δ halving (+1.07 → +0.54 GB below) is consistent with the tallest
table, the reg table, going 2^20 → 2^19 (derived, not measured).

**The exit twin at tier 18** (`tests/memprofile.rs::tier19_exit_twin`, run alone, `--features parallel`, 16 threads,
this 48 GB box). The before column is docs/05 §"The exit twin at tier 18" (230 950 rows,
`docs/measurements/2026-10-05-tier18-twin-memprofile.log`).

| phase (Plonky3 span) | before: live after (ends at) | after Cut D: live after (ends at) |
|---|---:|---:|
| main trace `build merkle tree` | 10.78 GB (40.2 s), Δ +1.07 | **8.81 GB** (31.5 s), Δ +0.54 |
| permutation `build merkle tree` | 16.95 GB (62.0 s), Δ +1.07 | **13.30 GB** (46.3 s), Δ +0.54 |
| `compute quotient` (outermost close) | 23.65 GB (134.8 s), peak 30.09 | **18.27 GB** (107.3 s), peak **24.86** |
| quotient `build merkle tree` | 25.84 GB (147.8 s) | **19.65 GB** (114.9 s) |
| the next commit round's `build merkle tree` | 29.70 GB (162.7 s) | **22.31 GB** (124.4 s) |
| `FRI prover` (commit phase) | 31.35 GB (184.8 s) | **23.09 GB** (133.1 s) |
| **run peak** | **33.27 GB**, in the FRI commit phase | **24.86 GB** (−25 %), inside `compute quotient` (≈ 100–104 s) |
| prove / verify / proof | 185.4 s / 5.46 s / 268 417 B | **133.2 s / 6.59 s / 259 720 B** |
| outcome | proved | **proved** (`== exit twin (tier 18): 202198 rows, tier 18, proof 259720 B, prove 133.2 s; peak live heap 24.86 GB`) |

macOS `maximum resident set size` for the run: 29.4 GB. As docs/04 says, that is not a memory number. The peak moved
back into the quotient phase because every committed tree after it is now smaller.

**Projection to production N = 1 (labelled; not measured).** docs/05 projected the production N = 1 aggregate (tier 20)
at ≈ 170–175 GB with REG and RAM at 2^22. Cut D halves both memory tables at production, the same change the twin
measures here (its tallest table halved, peak ×0.75). Applying ×0.75 gives **≈ 130 GB**. This is a projection until the
tier-20 production proof runs on a large host.


## 4. The cuts, measured (each cut task appends its row and its `== profile` line)

### Cut D (Task 1a machine side, Task 1b program side)

| cut | measured cpu rows | Δ | band | in band | REG (≤ 2 097 151) | RAM (≤ 2 097 151) | `reduce` span | REDUCE dispatches |
|---|---:|---:|---|---|---:|---:|---:|---:|
| D | 749 846 | −143 760 (projected −145 441) | 726 349–769 981 | **yes** | 1 785 559, met | 1 913 981, met | 163 601 → **20 001** | 9 520 |

```
== profile Production: inner tier Tier(14), 749846 cpu rows, 54515 permutations, 1913981 mem accesses, 1785559 reg accesses, 210763 witness words, 759979 program instrs
== profile Test: inner tier Tier(14), 202198 cpu rows, 11875 permutations, 444525 mem accesses, 510423 reg accesses, 45899 witness words, 204315 program instrs
-- rows per call site (production)
      116498   15.5%  (none)               reload   21160 spill   5429  /query   1456.2
       57276    7.6%  sample_bits          reload   12736 spill   4993  /query    716.0
      248151   33.1%  input_root           reload   97987 spill      3  /query   3101.9
       20001    2.7%  reduce               reload    1520 spill    321  /query    250.0  [REDUCE 9520, MOV 4480, LOADE 2080, STOREE 1520, FSUB 1120, EINV 1120]
       87680   11.7%  bit_selected_power   reload   17280 spill      0  /query   1096.0
       50960    6.8%  select               reload   12240 spill    480  /query    637.0
       36720    4.9%  fold_round           reload    1840 spill    960  /query    459.0
      129600   17.3%  commit_root          reload   35280 spill      0  /query   1620.0
        2960    0.4%  roll_in              reload    1280 spill      0  /query     37.0
-- reloads 201323, spills 12186; reduce dispatches 9520
```

Per query: 119 REDUCE rows (one per layout entry), 7 chains (one per opened height), 14 inverse keys (14 EINV), one
key buffer and one result buffer. `reduce` is 250 rows a query (was 2 045). Outside `reduce`, two spans moved
slightly because the allocator's schedule changed: `bit_selected_power` 87 920 → 87 680 and `fold_round`
36 640 → 36 720.

Pins and literals re-measured (the Re-pin Procedure):
- `tests/pins.json`: cpu rows 893 606 → 749 846; mem accesses 2 213 181 → 1 913 981; program instrs 903 739 → 759 979;
  REG 2 147 159 → 1 785 559; aggregate Test N = 1/2/3 cpu rows 231 224 / 462 039 / 692 854 → 202 472 / 404 535 /
  606 598 (mem 504 514 / 1 008 354 / 1 512 194 → 444 674 / 888 674 / 1 332 674). Permutations and witness words did not move.
- `LOOP_OVERHEAD` 274, unchanged. `N3_ROWS` 692 854 → 606 598. Aggregate tiers 18 / 19 / 20, unchanged.
- The production `verify_rv32` digest (`src/programs/verify_rv32.digest`): `723218da…d0d1` → `ef9b5b38…a388`.
- The aggregate digest at the Test shape: `5f1f6901…12df` → `8a2d166f…8509`. At the production shape:
  `c90b3f0a…74d8` → `a183de6e…6637`.
- The Off replay (`39bb6b8d…3352`) did not move: `Precompiles::Off` still compiles the reduction.
- Self-verifier digest `91e50e14…bd13` → `40eb7077…8487`. Toy CycleReport (131 739, 6 130, 276 847, 133 587, 24 135) →
  (120 955, 6 130, 254 575, 122 803, 24 135). Busy (167 746, 7 780, 320 075, 169 858, 29 967) → (156 466, 7 780,
  297 259, 158 578, 29 967). Phase 5 7 845 / 8 125, unchanged.
- The exit twin is 230 950 → 202 198 rows at tier 18. The production exit is 893 606 → 749 846 rows at tier 20.

### Cut E1 (Task 2)

| cut | measured cpu rows | Δ | band | in band | REG (≤ 2 097 151) | RAM (≤ 2 097 151) | `select` span | `fold_round` span | `commit_root` span |
|---|---:|---:|---|---|---:|---:|---:|---:|---:|
| E1 | 703 766 | −46 080 (projected −35 120) | 709 458–719 994 | **no** (below by 5 692; accepted) | 1 612 439, met | 1 891 821, met | 50 960 → **7 680** | 36 720 → 43 680 | 129 600 → 120 640 |

```
== profile Production: inner tier Tier(14), 703766 cpu rows, 54515 permutations, 1891821 mem accesses, 1612439 reg accesses, 212203 witness words, 715339 program instrs
== profile Test: inner tier Tier(14), 192982 cpu rows, 11875 permutations, 440093 mem accesses, 475799 reg accesses, 46187 witness words, 195387 program instrs
-- rows per call site (production)
      115778   16.5%  (none)               reload   21160 spill   5429  /query   1447.2
       57276    8.1%  sample_bits          reload   12736 spill   4993  /query    716.0
      248151   35.3%  input_root           reload   97987 spill      3  /query   3101.9
       20001    2.8%  reduce               reload    1520 spill    321  /query    250.0
       87680   12.5%  bit_selected_power   reload   17280 spill      0  /query   1096.0
        7680    1.1%  select               reload    1360 spill      0  /query     96.0  [MOV 1440, JEQ 1440, FMULI 1360, LOAD 1360, ESUB 720, LOADE 720]
       43680    6.2%  fold_round           reload    5360 spill   1360  /query    546.0
      120640   17.1%  commit_root          reload   35840 spill      0  /query   1508.0
        2880    0.4%  roll_in              reload   1200 spill      0  /query     36.0
-- reloads 194443, spills 12106; reduce dispatches 9520
```

The tape: `CommitPhaseOpenings` carries the whole row (2·a words a round, was 2·(a − 1)), so witness words
210 763 → 212 203 (+2 words × 9 rounds × 80 queries). `select` is one `LOADE` at a register offset (720 = 9 × 80),
the offset arithmetic (`FMULI` 1 360 = Σla × 80, `FADD`) and the two-lane equality (`ESUB` 720, `JEQ`
1 440 = 2 a round). Per query: 18 MOV + 18 JEQ + 17 FMULI + 17 LOAD + 9 ESUB + 9 LOADE = 88, and 8 more outside the top six (Σ(la − 1) = 8 offset `FADD`s, derived) = 96.

Re-pinned (the Re-pin Procedure, after the controller accepted the landing point):
- `tests/pins.json`: cpu rows 749 846 → 703 766; mem accesses 1 913 981 → 1 891 821; witness words 210 763 → 212 203;
  program instrs 759 979 → 715 339; REG 1 785 559 → 1 612 439; spans select 50 960 → 7 680, fold_round 36 720 →
  43 680, commit_root 129 600 → 120 640; reloads 201 323 → 194 443, spills 12 186 → 12 106. Permutations unchanged.
  Aggregate Test N = 1/2/3 cpu rows 202 472 / 404 535 / 606 598 → 193 256 / 386 103 / 578 950 (mem 444 674 /
  888 674 / 1 332 674 → 440 242 / 879 810 / 1 319 378; witness words 45 908 / 91 807 / 137 706 → 46 196 / 92 383 /
  138 570).
- `LOOP_OVERHEAD` 274, unchanged (193 256 = 192 982 + 274). `N3_ROWS` 606 598 → 578 950. Aggregate tiers 18 / 19 / 20,
  unchanged.
- The production `verify_rv32` digest: `ef9b5b38…a388` → `75576ad7…c8ba`.
- The aggregate digest at the Test shape: `8a2d166f…8509` → `9a43596f…4aa9`. At the production shape:
  `a183de6e…6637` → `9a619401…e649`.
- The Off replay moves this time, because the tape and the Off pipeline changed: `39bb6b8d…3352` → `af0c16e8…6c7b`.
- Self-verifier digest `40eb7077…8487` → `f60f0f5c…579b`. Toy CycleReport (120 955, 6 130, 254 575, 122 803, 24 135) →
  (114 955, 6 130, 251 855, 116 963, 24 295). Busy (156 466, 7 780, 297 259, 158 578, 29 967) → (146 626, 7 780,
  292 843, 149 026, 30 255). Phase 5 7 845 / 8 125, unchanged.
- The exit twin is 202 198 → 192 982 rows at tier 18. The production exit is 749 846 → 703 766 rows at tier 20.
- The reduce key (`WANT_REDUCE`) is unchanged: E1 does not touch the reduce chip's preprocessed region.

## 5. What moved (Task 5)

## 6. The suite (Task 5)
