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
| D | 145 441 | rows(reduce) − [EINV+MOV+FSUB in reduce] − Q·(E + H + K + 3) | 726 349–769 981 | | |
| E1 | 54 160 | rows(select) − Q·Σ_r(2·la_r + 5) + Q·Σ_r(a_r + 9) | relative to D's measured | | |
| E2 | 33 760 | rows(fold_round, re-read after E1) − 4·Q·R | relative to E1's measured | | |
| F | 82 800 | rows(bit_selected_power) − 4·Q·(H + R) | relative to E2's measured | | |

Inputs: D = 163 601 − (1 120 + 4 480 + 1 120) − 80·(119 + 7 + 14 + 3); E1 = 50 960 − 80·79 + 80·119 (Σla = 17,
Σa = 38); E2 = 36 640 − 4·80·9, provisional until `fold_round` is re-read after E1; F = 87 920 − 4·80·16.
E1 is computed with the formula as the plan writes it. With the last term subtracted instead, Δ_E1 = 35 120,
which is spec §2.2's "−35 000 to −40 000"; as written, Δ_E1 exceeds the whole `select` span (50 960). The E1
task should confirm the sign before it lands against this band.

Memory targets: REG 2 147 159 → under 2 097 152 (needs −50 008); RAM 2 213 181 → under 2 097 152.

## 3. Memory (Task 1b fills this)

## 4. The cuts, measured (each cut task appends its row and its `== profile` line)

## 5. What moved (Task 5)

## 6. The suite (Task 5)
