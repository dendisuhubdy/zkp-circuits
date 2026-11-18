# Gas: what one unit buys

Gas is meant to track what a proof costs its prover, and that cost is the committed trace: rows
times columns, over every table a row touches. This document fixes how that is counted, gives the
count for every priced row kind, says where the weights in `gas.rs` are off, and proposes the
weights for the next constraint set (ZKVM-202, fullnode #167).

**Nothing here changes a weight.** The weights are enforced by the cpu AIR (`tables/cpu.rs`,
`w_next`), so moving one changes every verifier key: a constraint-set bump and a chain cut. The
owner's October ruling was not to cut a chain for this, and it stands. What changes now is that the
count is a test (`tests/gas_cells.rs`) instead of a comment, so the next set starts from numbers.

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
| cpu | 283 | 5 | 0 | 74 (36) | **362** | 16 |
| alu | 64 | 5 | 0 | 36 (17) | **105** | 16 |
| memory | 12 | 5 | 0 | 10 (4) | **27** | 8 |
| poseidon2 | 34 | 5 | 13 | 6 (2) | **58** | 8 |
| keccak | 2 612 | 5 | 99 | 24 (11) | **2 740** | 8 |
| sha256 | 466 | 5 | 10 | 18 (8) | **499** | 8 |
| modq | 59 | 5 | 16 | 34 (16) | **114** | 8 |

The slot is `362 + 2·105 + 4·27 = 680` cells.

**Rows per operation** are measured, not restated: the test runs a probe guest that makes one call
of every priced syscall on the emulator and reads each event's chip traffic
(`CycleEvent::keccak_accesses`, `sha256_accesses`, `modq.accesses`), takes the block sizes from the
chips' `BLOCK` constants and the gas from `gas::row_gas`, then builds the probe's traces
(`build_traces_salted`, no proof) and checks that every table holds exactly the real rows the
per-operation counts add up to. The modq chip's memory rows are as its module documents: a
transform reads 256 words and writes 256 (512); `DOT4` reads two four-poly spans and writes one
poly (2 304); `MSUB4` reads two spans and the broadcast poly and writes four (3 328).

## The count

| operation | chip rows | chip memory rows | cells | gas | cells / gas | ratio |
|---|---:|---:|---:|---:|---:|---:|
| plain cycle | — | — | 680 | 1 | 680.0 | 1.000 |
| `POSEIDON2` absorb row | 32 poseidon2 | 0 | 2 536 | 3 | 845.3 | **1.243** |
| digest-prefix row | 32 poseidon2 | 0 | 2 536 | 3 | 845.3 | **1.243** |
| `KECCAK` | 32 keccak | 100 | 91 060 | 192 | 474.3 | **0.697** |
| `SHA256` | 64 sha256 | 32 | 33 480 | 64 | 523.1 | **0.769** |
| `MODQ` `NTT` | 1 024 modq | 512 | 131 240 | 168 | 781.2 | 1.149 |
| `MODQ` `INTT` | 1 024 modq | 512 | 131 240 | 168 | 781.2 | 1.149 |
| `MODQ` `DOT4` | 1 024 modq | 2 304 | 179 624 | 168 | 1 069.2 | **1.572** |
| `MODQ` `MSUB4` | 1 024 modq | 3 328 | 207 272 | 168 | 1 233.8 | **1.814** |

Every row also carries its slot (1 cpu, 2 alu, 4 memory rows). The band the test enforces is
±15 % of a plain cycle; the bold ratios are outside it and sit on the test's `KNOWN_MISPRICED`
list. `DOT4` and `MSUB4` are under-priced because the flat `MODQ_GAS` was derived from the chip's
block alone and their memory traffic is as large again as the block (`MSUB4`: 89 856 memory cells
against the block's 116 736). `KECCAK` and `SHA256` are over-priced because their weights were set
at about 460 cells per gas, a slot counted without blind or LogUp columns; those columns add 48 %
to the slot and only 1–5 % to a 2 612- or 466-column hash row. The absorb row's 3 is the nearest
integer below its fair 3.73. `NTT`/`INTT` are inside the band by one part in a thousand.

Under-pricing is the direction that matters for safety: a guest made of `MSUB4` calls buys 1.8
times the prover work its gas pays for. Over-pricing only overcharges.

## Why the two earlier counts differ

Both are reproduced by `the_earlier_counts_are_reproduced` from the same widths and rows.

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

So the two differ in three choices — blind and LogUp columns, preprocessed columns, quotient
chunks — and in whether the syscall's own cpu row is counted. The method of record here takes
every committed *trace* cell and the cpu row; it agrees with October on which operations are off
and in which direction, and differs from it by a few percent in size.

| ratio | **trace (record)** | 17 Nov (main + pre) | trace − preprocessed | trace + quotient | October (per proof) |
|---|---:|---:|---:|---:|---:|
| `POSEIDON2` absorb, digest prefix | **1.243** | 1.092 | 1.039 | 1.260 | 1.077 |
| `KECCAK` | **0.697** | 0.998 | 0.673 | 0.632 | 0.610 |
| `SHA256` | **0.769** | 1.050 | 0.755 | 0.706 | 0.693 |
| `NTT`, `INTT` | **1.149** | 1.076 | 1.005 | 1.125 | 0.996 |
| `DOT4` | **1.572** | 1.354 | 1.429 | 1.616 | 1.488 |
| `MSUB4` | **1.814** | 1.514 | 1.671 | 1.897 | 1.768 |

`DOT4` and `MSUB4` are under-priced under every method, and `KECCAK` and `SHA256` over-priced
under every method that counts blind and LogUp columns. The absorb row is the one verdict that
depends on the method: outside the band under the method of record and with quotient chunks
added, inside under the other three (13 of a poseidon2 row's 58 cells are preprocessed).

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

## Proposed weights for the next constraint set

The weight that brings each operation to ratio 1.0 is `round(cells / 680)`:

| operation | today | proposed | ratio at the proposed weight |
|---|---:|---:|---:|
| `POSEIDON2` absorb row, digest-prefix row | 3 | 4 | 0.932 |
| `KECCAK` | 192 | 134 | 0.999 |
| `SHA256` | 64 | 49 | 1.005 |
| `MODQ` `NTT`, `INTT` | 168 | 193 | 1.000 |
| `MODQ` `DOT4` | 168 | 264 | 1.001 |
| `MODQ` `MSUB4` | 168 | 305 | 0.999 |

The `MODQ` split is the part that closes an under-pricing and is the minimum to carry; the three
hash weights are corrections in the user's favour (Keccak, SHA-256) or a rounding step (absorb)
and can ride the same cut. `NTT`/`INTT` are inside the band today and move only because the split
gives them their own weight anyway.

What has to change, described and not implemented:

- **`gas.rs`**: `MODQ_GAS` becomes four constants; `row_gas` reads the op from the call's `a1`
  (`modq::Args::decode`); `gas_max_with_modq`'s modq term takes the heaviest op,
  `(MODQ_MSUB4_GAS − 1) · 2^mlh / 1024`, since a ceiling must cover a table full of `MSUB4`. If the
  absorb weight moves, `gas_max`'s `2^(t−2)` term becomes `(W − 1) · 2^(t−3)`.
- **`tables/cpu.rs`, `w_next`**: today the modq term is one selector at one constant,
  `(MODQ_GAS − 1) · n(SYS_MODQ)`. The cpu row does not know the op: it holds `a1` whole in
  `MEM_VAL`, and only the modq chip decomposes it (its one-hot `IS_NTT`/`IS_INTT`/`IS_DOT`/
  `IS_MSUB`, already tied to `A1`). The cheapest per-op meter keeps the decomposition there: the
  chip adds a fourth field to its `MODQ` table entry, the linear form
  `Σ (W_op − 1) · IS_op` on the block's first row, and the cpu row looks up
  `(CLK, HASH_PTR, MEM_VAL, MODQ_W)` with `MODQ_W` a new cpu column pinned to zero off
  `SYS_MODQ` rows. The meter's term becomes `n(MODQ_W)`, and the transition stays degree 2. One cpu
  column, one bus field, no new range check. The alternative — two op-bit columns on the cpu row
  and four selector products in `w_next` — needs `a1`'s low bits split off in the cpu table, which
  costs a range check the chip already pays for.
- **The hash weights** are constants in the same expression; the absorb weight also appears in the
  first-row rule `GAS = POSEIDON2_ABSORB_GAS`.
- **Outside this crate**: the fullnode's fee schedule mirrors these constants, and `msauth`'s
  admission pins the gas word (below).

## `msauth` under the proposed weights

`msauth` (Dilithium2 verification, the private-multisig guest) is the one deployed caller of
`MODQ`. Per signature it makes 9 `NTT`, 4 `INTT`, 4 `DOT4` and 1 `MSUB4` calls and 99 Keccak
permutations — counted on the emulator by `msauth_under_the_proposed_weights`, on the seeded
fixture of `tests/msauth.rs`; no proof is made.

| `M` | cycles (with prefix) | Keccak | `NTT` / `INTT` / `DOT4` / `MSUB4` | gas today | `MODQ` re-weighted | every op re-weighted |
|---:|---:|---:|---|---:|---:|---:|
| 1 | 85 830 | 99 | 9 / 4 / 4 / 1 | 111 217 | 112 063 (+0.8 %) | 108 057 (−2.8 %) |
| 2 | 169 068 | 198 | 18 / 8 / 8 / 2 | 216 576 | 218 268 (+0.8 %) | 208 623 (−3.7 %) |
| 3 | 251 946 | 297 | 27 / 12 / 12 / 3 | 321 575 | 324 113 (+0.8 %) | 308 829 (−4.0 %) |

A re-weighting adds 846 gas per signature for `MODQ` alone, and the Keccak correction more than
pays it back. **It still fits, and nothing about its shape moves**: a tier is chosen by cycles and
Poseidon2 permutations and a table's height by its rows, and a weight touches neither, so tier 18
and the pinned heights (keccak 14, modq 16, memory 20) are unchanged.

What does move is the pinned gas word. `msauth` proves with `gas_limit = None`, so its public gas
word is the header ceiling `gas_max_with_modq(18, 14, 0, 16)`, and admission pins it exactly:
**436 159 today, 444 927 with `MODQ` re-weighted, 447 999 with every op re-weighted** (the modq
term at `MSUB4`'s weight over 64 blocks, the Keccak term over 512). The admission constant and the
fee charged on that word have to move in the same cut. The fullnode's own gas tiers and fee
arithmetic were not read for this document.

## The test

`cargo test --release --test gas_cells -- --nocapture` prints the tables above.

- `cells_per_gas_is_within_the_band_or_on_the_list` fails if an operation's ratio is outside
  ±15 % and it is not on `KNOWN_MISPRICED`; if a listed operation is inside the band; or if a
  listed ratio or fair weight has drifted from its pin (±0.005). A column added to any table moves
  these numbers, which is the point: the list is re-read whenever a width changes, and emptied in
  the commit that re-weights.
- `the_row_counts_are_what_the_trace_generator_lays_down` checks the row model against real traces.
- `the_earlier_counts_are_reproduced` pins the 459- and 760-cell methods.
- `msauth_under_the_proposed_weights` pins the table of the last section.
