# Gas: what one unit buys

Gas is meant to track what a proof costs its prover, and that cost is the committed trace: rows
times columns, over every table a row touches. This document fixes how that is counted, gives the
count for every priced row kind, and records the weights constraint set 11 adopted from it
(ZKVM-202, fullnode #167).

**The weights are the count.** Through constraint set 10 they were not: `DOT4` and `MSUB4` bought
1.57 and 1.81 times a plain cycle's cells per gas, `KECCAK` and `SHA256` 0.70 and 0.77. The
weights are enforced by the cpu AIR (`tables/cpu.rs`, `w_next`), so moving one changes every
verifier key — a constraint-set bump and a chain cut — and the owner's October ruling was not to
cut a chain for that alone. The ruling of November 2026 is to adopt the counted weights at the
next constraint set, the two hash weights lowered with the rest. Constraint set 11 is that set:
every priced row is now within 7 % of a plain cycle, every one but the absorb row within 0.3 %,
and `tests/gas_cells.rs` fails on any that leaves ±15 % or whose weight is not the rounded count.

## The method

**One unit: the slot.** A cpu row is one gas. Behind every cpu row the tier provisions a fixed
share of two other tables whatever the row does: `Tier::alu_height` is `2^(t+1)`, two ALU rows per
cycle, and `Tier::min_mem_log_height` is `t + 2`, four memory rows per cycle (the cpu row's four
access slots). Those tables are committed at that height whether or not the rows are used, so the
cost of a plain cycle is the whole slot: **1 cpu row + 2 alu rows + 4 memory rows**.

**What a syscall row adds.** A `KECCAK`, `SHA256` or `MODQ` row pulls one block into its chip's
table, and the chip sends its own reads and writes on `MEMORY`, each one a memory-table row beyond
the slot's four. A `POSEIDON2` absorb row and a digest-prefix row each pull one 32-row permutation
into the poseidon2 table. So an operation's cells are

```
cells(op) = slot + chip_rows × width(chip) + chip_memory_rows × width(memory)
```

and its price is right when `cells(op) / gas(op)` equals the slot. The **ratio** below is
`cells(op) / gas(op) / slot`: above 1 the operation is under-priced (a gas buys more prover work
than a plain cycle's), below 1 it is over-priced.

**What a column is.** Every committed trace cell, in base-field elements per row:

- **main** — the table's own columns (`Chip::table_width`);
- **blind** — the five LogUp-terminal blind columns `machine::Chip` appends to every table
  (`tables::blind`); committed at full height though only row 0 is non-zero;
- **preprocessed** — committed once per verifier key, but opened and evaluated by every proof;
- **LogUp** — the permutation trace. `p3-lookup` 0.7's `LogUpGadget::generate_permutation` builds
  one accumulator column plus one fraction column per *packed* lookup context
  (`Lookups::pack_same_bus` folds a table's interactions on one bus into as few columns as the
  quotient degree allows), each an element of the challenge field `F_{p²}`, committed flattened:
  `(contexts + 1) × 2` cells per row.

None of the widths is a literal in the test. Main and preprocessed come from the `Chip`'s `BaseAir`;
the blind is the chip's width minus its table's; the LogUp width is read from a real verifier key's
packed contexts (`Machine::verifier_key_with_modq(..).lookups`, tier 10 with all three optional
tables declared — a chip's columns and its packing do not depend on the tier or on any height).

| table | main | blind | preprocessed | LogUp (contexts) | **trace** | quotient |
|---|---:|---:|---:|---:|---:|---:|
| cpu | 284 | 5 | 0 | 74 (36) | **363** | 16 |
| alu | 64 | 5 | 0 | 36 (17) | **105** | 16 |
| memory | 12 | 5 | 0 | 10 (4) | **27** | 8 |
| poseidon2 | 34 | 5 | 13 | 6 (2) | **58** | 8 |
| keccak | 2 612 | 5 | 99 | 24 (11) | **2 740** | 8 |
| sha256 | 466 | 5 | 10 | 18 (8) | **499** | 8 |
| modq | 59 | 5 | 16 | 34 (16) | **114** | 8 |

The slot is `363 + 2·105 + 4·27 = 681` cells. (Through constraint set 10 the cpu table was one
column narrower and the slot 680: set 11's `MODQ_W`, the column that carries a `MODQ` row's per-op
weight, is itself in the count.)

**Rows per operation** are measured, not restated: the test runs a probe guest that makes one call
of every priced syscall on the emulator and reads each event's chip traffic
(`CycleEvent::keccak_accesses`, `sha256_accesses`, `modq.accesses`), takes the block sizes from the
chips' `BLOCK` constants and the gas from `gas::row_gas`, then builds the probe's traces
(`build_traces_salted`, no proof) and checks that every table holds exactly the real rows the
per-operation counts add up to. The modq chip's memory rows are as its module documents: a
transform reads 256 words and writes 256 (512); `DOT4` reads two four-poly spans and writes one
poly (2 304); `MSUB4` reads two spans and the broadcast poly and writes four (3 328).

## The count

| operation | chip rows | chip memory rows | cells | gas | cells / gas | ratio | gas, sets ≤ 10 | ratio then |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| plain cycle | — | — | 681 | 1 | 681.0 | 1.000 | 1 | 1.000 |
| `POSEIDON2` absorb row | 32 poseidon2 | 0 | 2 537 | 4 | 634.2 | 0.931 | 3 | 1.243 |
| digest-prefix row | 32 poseidon2 | 0 | 2 537 | 4 | 634.2 | 0.931 | 3 | 1.243 |
| `KECCAK` | 32 keccak | 100 | 91 061 | 134 | 679.6 | 0.998 | 192 | 0.697 |
| `SHA256` | 64 sha256 | 32 | 33 481 | 49 | 683.3 | 1.003 | 64 | 0.769 |
| `MODQ` `NTT` | 1 024 modq | 512 | 131 241 | 193 | 680.0 | 0.999 | 168 | 1.149 |
| `MODQ` `INTT` | 1 024 modq | 512 | 131 241 | 193 | 680.0 | 0.999 | 168 | 1.149 |
| `MODQ` `DOT4` | 1 024 modq | 2 304 | 179 625 | 264 | 680.4 | 0.999 | 168 | 1.572 |
| `MODQ` `MSUB4` | 1 024 modq | 3 328 | 207 273 | 304 | 681.8 | 1.001 | 168 | 1.814 |

Every row also carries its slot (1 cpu, 2 alu, 4 memory rows). Each weight is
`round(cells / 681)`, and the band the test enforces is ±15 % of a plain cycle. The absorb row is
the one that cannot sit at 1.0: its fair weight is 3.73, and 4 is the nearest integer (0.931; at 3
it was 1.243, outside the band).

The last two columns are the weights of constraint sets ≤ 10 and the ratios set 10's count gave
them (on its 680-cell slot; the test reproduces them). `DOT4` and `MSUB4` were under-priced because the flat `MODQ_GAS = 168` was
derived from the chip's block alone and their memory traffic is as large again as the block
(`MSUB4`: 89 856 memory cells against the block's 116 736). `KECCAK` and `SHA256` were over-priced
because their weights were set at about 460 cells per gas, a slot counted without blind or LogUp
columns; those columns add 48 % to the slot and only 1–5 % to a 2 612- or 466-column hash row.

Under-pricing was the direction that mattered for safety: a guest made of `MSUB4` calls bought 1.8
times the prover work its gas paid for. Over-pricing only overcharged.

## Why the two earlier counts differ

This section is the record of constraint set 10: its weights, its 283-column cpu table, and the
two reviews that counted them differently. Both are reproduced by `the_earlier_counts_are_reproduced` from the same widths and rows.

**The 17 November review** counted main and preprocessed columns only, and an operation's cells
were its chip block plus the chip's memory rows, without the cpu row's own slot. Its slot is
`283 + 2·64 + 4·12 = 459`; it gives Keccak 87 952 cells, SHA-256 30 848, `NTT` 82 944, `DOT4`
104 448 (1.35×) and `MSUB4` 116 736 (1.51×), and finds Keccak (1.00) and SHA-256 (1.05) fair. It
leaves out the columns that weigh most on narrow tables: blind and LogUp take a memory row from 12
cells to 27 and a modq row from 75 to 114, while a keccak row barely moves.

**The October audit** counted what a proof commits itself: main, blind and LogUp columns plus the
quotient chunks, and no preprocessed columns, with the slot in the numerator. Its slot is
`(288 + 74 + 16) + 2·(69 + 36 + 16) + 4·(17 + 10 + 8) = 760`; it gives `DOT4` 1.49×, `MSUB4`
1.77×, Keccak 0.61 and SHA-256 0.69.

So the two differed in three choices — blind and LogUp columns, preprocessed columns, quotient
chunks — and in whether the syscall's own cpu row is counted. The method of record here takes
every committed *trace* cell and the cpu row; it agrees with October on which operations are off
and in which direction, and differs from it by a few percent in size.

| ratio, set 10 | **trace (record)** | 17 Nov (main + pre) | trace − preprocessed | trace + quotient | October (per proof) |
|---|---:|---:|---:|---:|---:|
| `POSEIDON2` absorb, digest prefix | **1.243** | 1.092 | 1.039 | 1.260 | 1.077 |
| `KECCAK` | **0.697** | 0.998 | 0.673 | 0.632 | 0.610 |
| `SHA256` | **0.769** | 1.050 | 0.755 | 0.706 | 0.693 |
| `NTT`, `INTT` | **1.149** | 1.076 | 1.005 | 1.125 | 0.996 |
| `DOT4` | **1.572** | 1.354 | 1.429 | 1.616 | 1.488 |
| `MSUB4` | **1.814** | 1.514 | 1.671 | 1.897 | 1.768 |

`DOT4` and `MSUB4` were under-priced under every method, and `KECCAK` and `SHA256` over-priced
under every method that counts blind and LogUp columns. The absorb row was the one verdict that
depended on the method (13 of a poseidon2 row's 58 cells are preprocessed).

The same sensitivities at constraint set 11's weights, which were fitted to the method of record:

| ratio, set 11 | **trace (record)** | trace − preprocessed | trace + quotient | October (per proof) |
|---|---:|---:|---:|---:|
| `POSEIDON2` absorb, digest prefix | **0.931** | 0.779 | 0.944 | 0.807 |
| `KECCAK` | **0.998** | 0.963 | 0.904 | 0.873 |
| `SHA256` | **1.003** | 0.984 | 0.921 | 0.903 |
| `NTT`, `INTT` | **0.999** | 0.874 | 0.978 | 0.866 |
| `DOT4` | **0.999** | 0.908 | 1.027 | 0.945 |
| `MSUB4` | **1.001** | 0.922 | 1.047 | 0.976 |

No operation is under-priced by more than 5 % under any of them. A method that leaves the
preprocessed columns out finds the narrow chips (poseidon2 13 of 58 cells, modq 16 of 114)
over-priced by up to 22 %, which is the direction that only overcharges.

## What the count leaves out

- **Quotient chunks.** Committed by every proof, but not trace: `2^log_chunks × 2` cells per row,
  16 for cpu and alu, 8 for the rest. They are the "trace + quotient" column above.
- **Preprocessed columns are cheaper than main ones.** Their commitment is part of the key and is
  not recomputed per proof. Counting them at full weight slightly overstates the hash chips and
  poseidon2; "trace − preprocessed" bounds the effect.
- **Powers of two.** A table's cost moves only when its height doubles. The memory table's floor
  of four rows per cycle is rarely full (`msauth` at `M = 3` sends 3.1 per cycle), so a chip's
  memory rows first fill slack: `msauth`'s 837 k rows fit the tier-18 floor of 2^20 and its `MODQ`
  traffic costs nothing at the margin. The count is the average cost of a row, which is what a
  per-row weight can express.
- **The poseidon2 table's height is the tier's** (`2^(t+2)`, `2^(t−3)` permutations), not the
  run's. An absorb row consumes one of those slots rather than adding rows; the count charges it
  the slot's 32 rows.
- **Per-proof fixed tables** (program, range, nibble, input, public) and each optional table's
  `2^7` floor belong to no row and are not in the count.
- **The hiding PCS** doubles every committed column alike and changes no ratio.

## The weights of constraint set 11

Each is `round(cells / slot)` on the count above, taken after the meter's own column was added
(the proposal made on set 10's 680-cell slot gave `MSUB4` 305; with `MODQ_W` in the cpu table the
slot is 681 and the count gives 304 — every other weight came out as proposed).

| operation | sets ≤ 10 | set 11 | fee per call | ratio |
|---|---:|---:|---:|---:|
| plain cycle | 1 | 1 | — | 1.000 |
| `POSEIDON2` absorb row, digest-prefix row | 3 | 4 | +33 % | 0.931 |
| `KECCAK` | 192 | 134 | −30 % | 0.998 |
| `SHA256` | 64 | 49 | −23 % | 1.003 |
| `MODQ` `NTT`, `INTT` | 168 | 193 | +15 % | 0.999 |
| `MODQ` `DOT4` | 168 | 264 | +57 % | 0.999 |
| `MODQ` `MSUB4` | 168 | 304 | +81 % | 1.001 |

### How the meter prices a `MODQ` call by op

- **`gas.rs`**: `MODQ_GAS` is four constants (`MODQ_NTT_GAS`, `MODQ_INTT_GAS`, `MODQ_DOT4_GAS`,
  `MODQ_MSUB4_GAS`) behind `modq_gas(op)`; `row_gas` reads the op from the call's `a1`
  (`modq_op`: its low two bits, as the chip's `A1` identity reads them). `gas_max_with_modq`'s
  modq term takes the heaviest op, `(MODQ_MAX_GAS − 1) · 2^mlh / 1024 = 303 · 2^mlh / 1024`, since
  a ceiling must cover a table full of `MSUB4`; the absorb term is `(4 − 1) · 2^(t−3)`.
- **The cpu row does not know the op.** It holds `a1` whole in `MEM_VAL`, and only the modq chip
  decomposes it: its one-hot `IS_NTT`/`IS_INTT`/`IS_DOT`/`IS_MSUB`, boolean, summing to `IS_REAL`
  and tied to `A1`'s low bits by the chip's rule 1. So the chip prices the call. Its `MODQ` table
  entry gained a fourth field, the linear form

  ```
  192·IS_NTT + 192·IS_INTT + 263·IS_DOT + 303·IS_MSUB        (each weight less the row's own 1)
  ```

  on the block's first row, and the cpu row looks up `(CLK, HASH_PTR, MEM_VAL, MODQ_W)` with
  `MODQ_W` a new cpu column (the 284th). `w_next`'s modq term is `n(MODQ_W)`: linear, so the
  transition stays degree 2. One cpu column, one bus field, no new range check.
- **Why a prover cannot pay one op's price for another's work.** (1) A `SYS_MODQ` row's lookup has
  count 1, so `(CLK, HASH_PTR, a1, MODQ_W)` must be an entry of the modq table; `CLK` is unique
  per cpu row and one real block answers it, and that block's fourth field is fixed by its op
  flags, which the chip ties to the same `a1` — the `a1` the cpu read from the register file. So
  `MODQ_W` is the weight of the op the chip performs, or the bus does not balance. (2) The gas
  chain adds `MODQ_W` as it stands, so the row is charged exactly that. (3) Off a `SYS_MODQ` row
  nothing looks `MODQ_W` up, so `(1 − SYS_MODQ) · MODQ_W = 0` pins it to zero there: a free value
  would be a free credit on the chain. `tests/gas.rs` (`modq::a_modq_op_claimed_at_another_weight_
  is_refused`) forges each of the three against a real proof, per op, with the chain and the
  public gas word made consistent with the lie; `tests/modq.rs` asks the chip standalone at every
  wrong price.
- **The hash weights** are constants in the same expression; the absorb weight also appears in the
  first-row rule `GAS = POSEIDON2_ABSORB_GAS`.

## What the re-weighting does to a fee (for governance)

The fee is charged per gas, and the price of a gas is governance's. At an unchanged price:

- **a plain cycle costs what it did**, so a guest that only computes pays the same;
- **hashing through the chips is cheaper**: a `KECCAK` permutation −30 % (192 → 134), a `SHA256`
  compression −23 % (64 → 49);
- **`MODQ` is dearer**: `NTT`/`INTT` +15 % (168 → 193), `DOT4` +57 % (168 → 264), `MSUB4` +81 %
  (168 → 304);
- **a Poseidon2 permutation is dearer**: an absorb row and a digest-prefix row +33 % (3 → 4). Every
  proof pays the digest prefix once — one row per four program words, per four private inputs
  (plus the salt row) and per four public words — so every call's floor rises by its prefix rows:
  `msauth`'s 1 620 prefix rows are 1 620 gas more;
- **header ceilings move** (what a proof with `gas_limit = None` declares, and what a fee keyed on
  the public gas word charges): `gas_max` at tier `t` with no hash table rises from
  `2^t − 1 + 2^(t−2)` to `2^t − 1 + 3·2^(t−3)` (+10 %); a declared keccak block adds 133 instead
  of 191, a sha256 block 48 instead of 63, a modq block 303 instead of 167.

What a deployed guest pays therefore moves with its mix. A Keccak-heavy guest (the EVM
interpreter's `KECCAK256`, Solidity mappings; `msauth`'s SHAKE) pays less; a guest dominated by
`MODQ` or by Poseidon2 absorbs pays more. If governance wants the *revenue* per unit of prover
work unchanged, no price change is needed: that is what the re-weighting restores. If it wants a
particular guest's fee unchanged, the price of gas is the only lever and moves every guest.

## `msauth` at the weights

`msauth` (Dilithium2 verification, the private-multisig guest) is the one deployed caller of
`MODQ`. Per signature it makes 9 `NTT`, 4 `INTT`, 4 `DOT4` and 1 `MSUB4` calls and 99 Keccak
permutations — counted on the emulator by `msauth_at_the_weights`, on the seeded fixture of
`tests/msauth.rs`; no proof is made.

| `M` | cycles (with prefix) | Keccak | `NTT` / `INTT` / `DOT4` / `MSUB4` | gas, sets ≤ 10 | gas, set 11 |
|---:|---:|---:|---|---:|---:|
| 1 | 85 830 | 99 | 9 / 4 / 4 / 1 | 111 217 | 108 056 (−2.8 %) |
| 2 | 169 068 | 198 | 18 / 8 / 8 / 2 | 216 576 | 208 621 (−3.7 %) |
| 3 | 251 946 | 297 | 27 / 12 / 12 / 3 | 321 575 | 308 826 (−4.0 %) |

Per signature the `MODQ` re-weighting adds 845 gas (9 + 4 transforms at +25, 4 `DOT4` at +96, one
`MSUB4` at +136) and the Keccak correction takes 5 742 back (99 at −58); the prefix rows and the
absorb rows add one each (1 633 once, then 103 per signature). **Its shape does not move**: a tier is
chosen by cycles and Poseidon2 permutations and a table's height by its rows, and a weight touches
neither, so tier 18 and the pinned heights (keccak 14, modq 16, memory 20) are as they were — the
test asserts the run fits them at every `M`.

What does move is the pinned gas word. `msauth` proves with `gas_limit = None`, so its public gas
word is the header ceiling `gas_max_with_modq(18, 14, 0, 16)`, and admission pins it exactly:

```
2^18 − 1  +  3 · 2^15  +  133 · 2^14/32  +  303 · 2^16/1024
 262 143  +   98 304   +     68 096      +      19 392        =  447 935        (436 159 through set 10)
```

The admission constant and the fee charged on that word move in the same cut: a fee keyed on the
word rises 2.7 % at an unchanged price, though the work `msauth` meters fell. (The proposal's
hand-derived 447 999 was at `MSUB4` = 305.) The fullnode's own gas tiers and fee arithmetic were
not read for this document.

## The test

`cargo test --release --test gas_cells -- --nocapture` prints the tables above.

- `cells_per_gas_is_within_the_band_or_on_the_list` fails if an operation's ratio is outside
  ±15 %, if its weight is not `round(cells / slot)`, or if `KNOWN_MISPRICED` — the list of
  exceptions sets ≤ 10 needed, now empty — has an entry; it pins the slot (681), every operation's
  cells and every weight. A column added to any table moves these numbers, which is the point: the
  weights are re-read whenever a width changes.
- `the_row_counts_are_what_the_trace_generator_lays_down` checks the row model against real traces.
- `the_earlier_counts_are_reproduced` pins set 10's record: the 680-, 459- and 760-cell methods at
  that set's weights and cpu width.
- `msauth_at_the_weights` pins the table of the last section, and that the run fits the pinned
  tier and heights.
