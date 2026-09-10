# The tables and their buses

The relation is proved as one batch of six AIR tables under one commitment
and one FRI opening (`p3-batch-stark`). Tables never call each other
directly; they exchange facts through named LogUp buses, and the batch
verifier checks that every bus balances globally.

```
                                  ┌───────────┐
                                  │  PROGRAM  │ preprocessed; commitment = hc
                                  └───────────┘
                                        │ PROGRAM bus (lookup: cpu fetches, program provides)
                  MEMORY bus            ▼             ALU bus
                            ◄─────┌───────────┐─────►
                 (permutation)    │    CPU    │    (lookup)
                                  └───────────┘
                                        │
                    ┌───────────────────┴───────────────────┐
                    ▼                                       ▼
               ┌───────────┐                           ┌───────────┐
               │  MEMORY   │                           │    ALU    │
               └───────────┘                           └───────────┘
                     │ RANGE8                                │ RANGE8 AND4 OR4 XOR4 POW2
                     └──────────────────┬────────────────────┘
                              ┌──────────┴──────────┐
                              ▼                     ▼
                        ┌───────────┐         ┌───────────┐
                        │   RANGE   │         │  NIBBLE   │
                        └───────────┘         └───────────┘
                    preprocessed, 256 rows   preprocessed, 256 rows
                    every byte a; pow2(a)    every nibble pair (a,b)
```

Eight buses in total: `PROGRAM`, `MEMORY`, `ALU`, `RANGE8` and `POW2`
(carried by the range table), and `AND4`, `OR4`, `XOR4` (carried by the
nibble table). `PROGRAM`, `ALU`, `RANGE8`, `AND4`, `OR4`, `XOR4`, `POW2` are
`LookupBus`es (a subset check: every value a consumer sends must appear,
with enough multiplicity, in the provider's table). `MEMORY` is a
`PermutationCheckBus` — both sides are prover-supplied main-trace rows, and
the argument proved is multiset equality, not a lookup into a fixed table.

## `program` — preprocessed, `pre::WIDTH = 25` + `col::WIDTH = 1`

Preprocessed columns: `pc`, then the 23 `Decoded` fields in the fixed
`to_fields` order (`rd rs1 rs2 imm is_alu alu_op is_imm is_branch br_op
br_neg is_lb is_lh is_lw is_sb is_sh is_sw signed is_jal is_jalr is_lui
is_auipc is_ecall writes_rd`), then `valid` (1 on real instruction rows, 0
on padding). One main column, `mult`: how many times this row was fetched.
Constraint: a row with `valid = 0` must have `mult = 0` — padding can never
be fetched. Provides `(pc, 23 fields…)` on `PROGRAM` with count `mult`.

## `cpu` — main, `col::WIDTH = 76`

Columns: `clk pc next_pc is_real`, the same 23 decoded fields (fetched, not
recomputed — `is_load`/`is_store` are *expressions* the AIR computes from
the one-hot `is_lb/is_lh/is_lw`/`is_sb/is_sh/is_sw` fields, not columns of
their own), `a b c alu_out tgt` (operands and results), `mem_addr mem_val`,
three syscall flags `sys_halt sys_write sys_read`, eight one-hot output
selectors `out_sel0..7`, eight cumulative counters `written0..7`, four byte
limbs `ma0..3` of `mem_addr` (the WORD address) and `ma3_hi` (`ma0+3`'s high
nibble, unchanged in role since M2.3/M2.4), then the M2.5 sub-word columns:
`off0 off1` (the byte offset within the word, two booleans), `w0..3` (byte
limbs of `mem_val` — the word actually in memory), `byte half` (the
selected byte/halfword), `hi sgn` (the sign-relevant byte's high nibble and
sign bit), `rb0..3` (byte limbs of `b`, rs2's value, on store rows), and
`merged0..3` (the word a store writes back). This is the only table with
public values: `pc_entry`, the tier index, and the eight output words.

Constraints, in words: `is_real` is boolean and monotone (once 0, stays 0);
`clk` starts at 0 and increments by 1 on real rows; the first row's `pc`
equals the public `pc_entry`; the *last real row* is a `HALT`, and nothing
runs after it — every row past it is padding. Every real row looks up its
own `(pc, 23 fields)` on `PROGRAM` — the
CPU never decodes an opcode bit itself, only trusts what the lookup
returned. The second ALU operand is `imm` or `b` depending on `is_imm`; an
ALU-using row (`is_alu`, branch, load, store, `jalr`) looks up `(op, a,
b_eff, alu_out)` on `ALU`, and a second, independent ALU slot computes
`pc + imm` for `branch`/`jal`/`auipc`. `c` (the value written to `rd`) is
pinned by kind: `alu_out` for ALU ops, the sign/zero-extended loaded value
for `lb`/`lh`/`lw` (below), `pc+4` for `jal`/`jalr`, `imm` for `lui`, `tgt`
for `auipc`. On every row whose kind does *not* define `c` (branches,
stores, `HALT`/`WRITE_OUTPUT`), `c` is forced to 0 — the constraint that
stops a cheating witness from smuggling a value through an unused column
(`defines_c` in `cpu.rs`). `next_pc` is `pc+4` unless the row is a taken
branch, `jal`, or `jalr`. Register reads/writes and the memory access(es)
go out on `MEMORY` below. `ECALL` rows pre-decode `rs1=17 (a7)`, `rs2=10
(a0)`, so the syscall number and first argument arrive through the ordinary
register-read slots; the second argument (`a1`) is read through the
memory-access slot. `WRITE_OUTPUT` constrains `public_values[2+slot] =
word` via eight one-hot selectors on `slot`. The eight `written_i` columns
accumulate `out_sel_i` down the table and are boolean on every row, which
caps each slot at a single write (matching the emulator's `DoubleWrite`
error) and lets the last row assert `(1 − written_i)·public_values[2+i] =
0`: a slot no `WRITE_OUTPUT` ever selected is zero, as the spec requires,
instead of being a free public value.

### M2.5: sub-word loads and stores

Memory stays word-addressed. `mem_addr` (the word address) and `off0/off1`
(the byte offset within the word, `off = off0 + 2·off1`) are ALU_OUT's
quotient and remainder by 4, both *stated*, not just implied by
`mem_addr·4 + off = alu_out` alone — that identity is a field relation only,
satisfiable by `mem_addr = (alu_out − off)·4⁻¹ mod p` for any `off` a
cheating witness likes. What rules that out, exactly as it did pre-M2.5:
`mem_addr` is decomposed into the four byte limbs `ma0..3`, each
range-checked on `RANGE8`, bounded below 2^30 by a nibble bound on the top
limb (`ma3_hi` is `ma0+3`'s high nibble — an *isolated* extraction, so its
low-nibble companion gets its own dummy `AND4[lo, 0, 0]` range check before
`ma3_hi` can be trusted, see the `alu` section below — and `AND4[ma3_hi,
0xC, 0]` masks the top two bits, the M2.3 replacement for the old
`AND8[ma3, 0xC0, 0]` byte-table check). With `alu_out` already 32-bit (the
ALU table's own limb checks) and `off` a sum of two booleans (`< 4`),
`mem_addr·4 + off < 2^32` cannot wrap, so the identity holds over the
integers, not just mod `p`. Width imposes its own alignment on top of that:
`is_lw*(off0+off1) = 0`, `is_lh*off0 = 0` (and the `sw`/`sh` equivalents) —
a full word must sit on a word boundary, a halfword on a 2-byte boundary, a
byte is never misaligned.

`mem_val` is the word actually in memory at `mem_addr` — the read value for
a load, the *pre-store* value for a store (`emulator::execute` pushes
exactly this as the row's `SLOT_MEM` read either way) — decomposed into
`w0..3`, each `RANGE8`-checked, with `mem_val = word(w0..3)` pinned
directly. `byte`/`half` select the addressed byte/halfword out of `w0..3`
by `off0/off1`, pinned on `lb`/`sb` and `lh`/`sh` rows respectively. Sign
extension for `lb`/`lh` runs through `hi`/`sgn`: the sign-relevant byte is
`byte` itself for `lb`, and the top byte of whichever half `off1` selected
for `lh` (reusing the already-committed `w1`/`w3` rather than dividing
`half` back apart) — an isolated nibble extraction (`hi_lo`, that byte's
low nibble, gets its own dummy `AND4[lo, 0, 0]` lookup, exactly the M2.4
sign-bit pattern in `alu.rs`), then `AND4[hi, 8, sgn*8]` extracts the true
top bit. The loaded value is `c = lb·(byte + sgn·signed·(2^32−2^8)) +
lh·(half + sgn·signed·(2^32−2^16)) + lw·mem_val`, pinned when `is_load`
(`defines_c` gains `is_lb+is_lh+is_lw` in place of the old single
`is_load`).

Stores decompose `b` (rs2's value, already read every row) into `rb0..3`,
each `RANGE8`-checked on store rows, with `is_store·(b − word(rb0..3)) = 0`
— exactly the M1 store-forgery invariant (`2c8a39d`), generalized: a
store's written bytes must trace back to a value that was actually in a
register. `merged0..3` is the read-modify-write result, spelled out per
byte: `merged_k = w_k + selp(k)·(bp(k) − w_k)`, where `selp(k)` is 1 (`sw`),
`off1`-selected (`sh`), or `off0/off1`-selected (`sb`) — which byte(s) this
store overwrites — and `bp(k)` is the corresponding byte of `rb0..3`. This
is the pin that replaces `2c8a39d`'s "a store's `mem_val` is the rs2
value": now "the written value is `merged`, and `merged = b` when `is_sw`"
— provable structurally from the formula above (when `is_sw=1`, `selp(k)=1`
for every `k` and `bp(k)=rb_k`, so `merged_k = rb_k`, i.e. `merged =
word(rb0..3) = b`).

Sends: 2 `MEMORY` register-read messages every row; a `SLOT_MEM` message on
load/store/ecall rows that is *always a read* (`is_write = 0`) — a load's
or a store's own access reads the word (or, for `ecall`, `a1`) that was
there, carrying `mem_val`; a `SLOT_W` message on `writes_rd`/`sys_read`/
`is_store` rows that is either a register writeback (space 0, addr `rd`,
value `c`) or a store's word write (space 1/RAM, addr `mem_addr`, value
`merged`) — the two never coincide on one row, since a store never sets
`writes_rd` or `sys_read`. 2 `ALU` lookups. On load/store rows: 4 `RANGE8`
for `ma0..3`, 2 `AND4` for the address's top-nibble bound, 4 `RANGE8` for
`w0..3`; additionally on store rows, 4 `RANGE8` for `rb0..3`; additionally
on `lb`/`lh` rows, 2 `AND4` for the sign extraction. Receives: 1 `PROGRAM`
lookup.

## `memory` — main, `col::WIDTH = 12`

Columns: `space addr ts value is_write is_real addr_changed diff_inv`, then
four limbs `d0..d3` of the gap to the next row. Rows are sorted by
`(space, addr, ts)`; `space` 0 is the register file (`addr` = register index
0–31), `space` 1 is RAM (`addr` = word address) — this is how registers ride
in the same table as RAM instead of costing the CPU 32 dedicated columns.

The **timestamp rule**: `ts = 4·clk + slot`, with `slot ∈ {0,1,2,3}` for the
register-1 read, register-2 read, the RAM/`a1` access, and the register
write respectively (`SLOT_R1..SLOT_W` in `emulator.rs`). This bounds every
cycle to at most four memory accesses and gives every access in the whole
execution a distinct, orderable key.

Constraints: `addr_changed` is `(space,addr)` differing from the next row,
checked with an inverse column; when the address is unchanged, `ts` must
strictly increase (proved via the byte-limbed gap on `RANGE8`) and a read
must return the same value as the previous access; when the address changes,
the new `(space,addr)` must be strictly greater (same gap technique) and a
first read of a fresh address must return 0. Receives `(space, addr, ts,
value, is_write)` on `MEMORY` with count `is_real`. Sends four `RANGE8`
lookups per row (the gap limbs).

## `alu` — main, `col::WIDTH = 52`

Columns: 11 one-hot op flags (`add sub and or xor sll srl sra slt sltu eq`),
`a b c`, three 4-limb decompositions `a0..3 b0..3 c0..3`, scratch limbs
`q0..3` (shift quotient / `sll` high word / bitwise `a`'s low nibbles),
`s0..3` (compare difference / right-shift remainder / bitwise `b`'s low
nibbles), `t0..3` (`pow2 − 1 − remainder` / bitwise `c`'s low nibbles), sign
bits `sa sb`, `shh` (the shift amount's bit 4), `pow2 = 2^sh`, four adder
carries, an inverse column for `eq`, `is_real`, `mult` (how many times the
CPU hit this exact tuple), and three more isolated-extraction scratch
columns: `ah3` (`a0+3`'s high nibble, `slt`/`sra`), `bh_n` (`b0+3`'s high
nibble on `slt` rows for `sb`, or `b0`'s high nibble on shift rows for
`shh` — the two never collide since `slt` and shift never co-occur), and
`qh3` (`sll`'s `q0+3`'s high nibble, its overflow check).

Constraints: exactly one op flag set per real row; every limb decomposition
recomposes to its word, and `a0..3`/`b0..3` are range-checked on `RANGE8`
under `g_ab = is_real − and − or − xor`, `c0..3` under the further-narrowed
`g_c = g_ab − slt − sltu − eq` (M2.4: dropped wherever a stronger constraint
already binds the limb — see below); `add`/`sub`/`slt`/`sltu` share one
limb-wise adder with boolean carries; `slt`/`sltu` reduce to a
subtract-with-borrow, `slt`/`sra` sign-correct using the top-limb's sign
bit. Every sign/shift/overflow bit below M2.3 came from a byte-table `AND8`
lookup against a single-bit mask; each is now a **nibble isolated
extraction**: given a byte column `x` and a *derived* high-nibble witness
`hi`, the low nibble `x − 16·hi` gets its own dummy `AND4[lo, 0, 0]` range
check (proving `lo ∈ [0,16)`), and a second, real `AND4[hi, mask, hi & mask]`
lookup both proves `hi ∈ [0,16)` and extracts the bit(s) the mask selects —
between them, `lo + 16·hi = x` with both parts in `[0,16)` forces `hi` to be
`x`'s true high nibble, the *unique* such decomposition of a byte `< 256`.
`slt`'s sign bits `sa`/`sb` and `sra`'s `sa` use this on `a0+3`/`b0+3`
(`AND4[hi, 8, sa·8]`); the shift amount's high bit `shh` uses it on `b0`
(`AND4[hi, 1, shh]`, so `sh = (b0 − 16·hi) + 16·shh`); `sll`'s overflow check
uses it on `q0+3` (`AND4[hi, 8, 0]`, forcing that nibble's top bit clear).
`and`/`or`/`xor` are different: each limb's low nibble is a *stored* scratch
column (reusing `q0..3`/`s0..3`/`t0..3`, free on bitwise rows since no other
op uses them there) with its own real `AND4`/`OR4`/`XOR4` lookup, so the high
nibble can be a *derived pure expression*, `(byte − lo)·16⁻¹`, with **no**
extra dummy range check — the low nibble's own lookup already anchors it,
and the map `byte ↦ (byte − lo)·16⁻¹` only lands in `[0,16)` for `byte < 256`
(see `bitwise_high_nibble`'s doc comment in `alu.rs` for the bijection
argument). That is two lookups per limb, eight per bitwise row.

**M2.4 — collapsing the RANGE8 limb checks.** Before M2.4, `a0..3`/`b0..3`/
`c0..3` were unconditionally `RANGE8`-checked on every real row (`is_real`),
twelve lookups regardless of op — on top of the eight nibble lookups a
bitwise row already pays, a pure redundancy: the nibble lookups above
already bind every bitwise limb (both nibbles of each byte get a real
lookup, so the byte itself is forced into `[0,256)` — see
`bitwise_high_nibble`'s doc comment). `g_ab` (`a0..3`/`b0..3`) and `g_c`
(`c0..3`) drop the RANGE8 lookup for a limb wherever a stronger constraint
already binds it: `g_ab` is 0 on `and`/`or`/`xor` rows (nibble-bound
instead); `g_c` is additionally 0 on `slt`/`sltu`/`eq` rows, where
`(cmp+eq)·c·(c−1) = 0` already forces `c ∈ {0,1}` — stronger than a
byte-range check. Both gates are sums of boolean row-selector flags (never a
product), so `Count::bounded(gate, 1)` still holds. Exact per-op lookup
counts (RANGE8 + `POW2`/`AND4`/`OR4`/`XOR4`, all bus lookups this table
performs per row; excludes the one `ALU` `table_entry` it always provides),
counted directly from `fill_row`/`alu_trace`'s `RangeCounts`/`NibbleCounts`
calls (see `tests/tables.rs::cmp_and_eq_rows_do_not_range_check_their_c_limb`
and `::bitwise_rows_no_longer_range_check_their_byte_limbs`, which assert
these totals against the honest witness the fill functions actually build):

| Op | `a0..3` RANGE8 | `b0..3` RANGE8 | `c0..3` RANGE8 | `s0..3`/`t0..3`/`q0..3` RANGE8 | sign/shift/overflow nibble lookups | `POW2` | Total/row |
|---|---|---|---|---|---|---|---|
| `add`/`sub` | 4 (`g_ab`) | 4 (`g_ab`) | 4 (`g_ab` — stays: a wrong carry could pass the field identity with an out-of-range limb) | 0 | 0 | 0 | **12** |
| `eq` | 4 (`g_ab`) | 4 (`g_ab`) | 0 (`g_c`, dropped) | 0 | 0 | 0 | **8** |
| `sltu` | 4 (`g_ab`) | 4 (`g_ab`) | 0 (`g_c`, dropped) | 4 (`s0..3`, `cmp` gate, unchanged) | 0 | 0 | **12** |
| `slt` | 4 (`g_ab`) | 4 (`g_ab`) | 0 (`g_c`, dropped) | 4 (`s0..3`, `cmp` gate, unchanged) | 4 (`sa`: dummy+extract, `sb`: dummy+extract) | 0 | **16** |
| `and`/`or`/`xor` | 0 (`g_ab`, dropped) | 0 (`g_ab`, dropped) | 0 (`g_ab`, dropped) | 0 | 8 (4 limbs × {lo, hi} on the active op's bus) | 0 | **8** |
| `sll` | 4 (`g_ab`) | 4 (`g_ab`) | 4 (`g_ab` — the shift result needs its own range proof) | 4 (`q0..3`, `shift` gate, unchanged) | 4 (shift-amount: dummy+extract; overflow `qh3`: dummy+extract) | 1 | **21** |
| `srl` | 4 (`g_ab`) | 4 (`g_ab`) | 4 (`g_ab`) | 12 (`q0..3` + `s0..3` + `t0..3`, `shift`/`rshift` gates, unchanged) | 2 (shift-amount: dummy+extract) | 1 | **27** |
| `sra` | 4 (`g_ab`) | 4 (`g_ab`) | 4 (`g_ab`) | 12 (`q0..3` + `s0..3` + `t0..3`) | 4 (shift-amount: dummy+extract; `sa`: dummy+extract) | 1 | **29** |

`and`/`or`/`xor` (the M2.3 motivating case, 20 lookups before this task —
12 RANGE8 + 8 nibble) drop to 8; `add`/`sub`/`eq`/`sltu` land at or under 12.
The Global Constraints' ≤14-lookups/row target is met by every op except
`slt` (16) and the shift family (`sll`/`srl`/`sra`, 21–29) — this is a
resolved scope note, not a miss: `slt` needs two independent isolated sign
extractions (`sa` on `a`, `sb` on `b`), each costing a dummy range-check
plus the real extraction, since nothing else on a `slt` row looks up either
companion low nibble the way the bitwise case's own op lookup does; and
`q0..3`/`s0..3`/`t0..3` (the shift/compare scratch limbs) were explicitly
scoped **unchanged** for this task ("Q, S, T lookups stay op-gated as
today"), so the shift family's pre-existing per-row cost carries forward
untouched. `sll` proves
`a·2^sh = c + hi·2^32` with `hi` and `c` range-checked and `(sh, 2^sh)` on
`POW2`; `srl`/`sra` prove the integer division `a = q·2^sh + r`, `r < 2^sh`,
with `sra` working on the two's-complement magnitude and re-flipping the
sign after. Provides `(op, a, b, c)` on `ALU` with count `mult`, and
`(1 − is_real)·mult = 0` forces that count to zero on padding rows. That last
one is load-bearing: on a padding row every op flag is zero (so `op` reads as
`Add`), the limb range checks are gated by `is_real` (directly, or via
`g_ab`/`g_c`, which are themselves `is_real` minus some of those same zero
flags — so still zero on a padding row), every arithmetic
constraint carries a flag factor, and the recomposition `a = Σ a_i·2^{8i}` is
satisfied by parking a whole field element in limb 0 — so without it a
padding row provided an arbitrary `Add` tuple with arbitrary multiplicity,
and the CPU consumes `Add` for every `ADD`/`ADDI`, every load/store address,
every `JALR` target and the whole slot-2 `(0, pc, imm, tgt)` lookup. The
general rule, applied to every `table_entry` in the crate: **the count must
be forced to zero wherever the message columns are unconstrained.**
`program` already does this (`mult·(1 − valid) = 0`); `range` and `nibble`
are preprocessed with no padding rows at all — every one of their rows is a
genuine table entry, so their `table_entry` counts are never structurally
"unconstrained" the way a consumer's padding row is.

## `range` — preprocessed, `pre::WIDTH = 3` + `col::WIDTH = 2`

Preprocessed: 256 rows, one per byte `a`, holding — on the 32 rows with
`a < 32` — `pow2 = 2^a` and a flag `is_pow2`. Main: two multiplicities,
`m_range` and `m_pow2`. Constraint: a `POW2` lookup can only land on an
`is_pow2` row (`m_pow2·(1 − is_pow2) = 0`). Provides `RANGE8` (`[a]`) and
`POW2` (`[a, 2^a]`), each with its own multiplicity column. Its buses are
consumed by `memory` (`RANGE8` only), `alu` (both), and `cpu` (`RANGE8`, for
the load/store address limbs); `program` never looks it up.

## `nibble` — preprocessed, `pre::WIDTH = 5` + `col::WIDTH = 3`

Preprocessed: 256 rows, one per nibble pair `(a, b)` with `a, b ∈ [0,16)`
(`row_of(a,b) = 16a + b`), holding `a&b`, `a|b`, `a^b`. Main: three
multiplicities, `m_and`, `m_or`, `m_xor`. No row-level constraint beyond the
`table_entry`s themselves — every one of the 256 rows is a genuine,
in-range AND/OR/XOR entry, so unlike `range`'s `is_pow2` split there is no
"invalid" row for a multiplicity to land on. That also means a successful
lookup against this table is itself a range check: any key that isn't a
valid `(a,b) ∈ [0,16)²` pair simply has no matching row. Provides `AND4`
(`[a, b, a & b]`), `OR4` (`[a, b, a | b]`), and `XOR4` (`[a, b, a ^ b]`),
each with its own multiplicity column. Consumed only by `alu` (bitwise
operands and every isolated nibble extraction) and `cpu` (the memory
alignment check, and — since M2.5 — `lb`/`lh`'s sign-bit extraction).

## Why the program is preprocessed, and what that means for `hc`

Plonky3 commits a preprocessed trace once, independent of any witness, and
the verifier holds that commitment permanently in its `CommonData`. Because
`program`'s decoded columns are preprocessed, **that commitment is `hc`**:
registering a confidential program on-chain means publishing this one
Merkle root, and the constraint system and verifier code stay identical for
every program. `Machine::code_hash` recomputes it directly from the program
via `verifier_key`, so any verifier — not just the original prover — can
derive `hc` standalone. That recomputation always includes the range and
nibble tables too, since they are also preprocessed and fold into the same
`CommonData`; `Machine::verifier_key` caches this per `(program digest, tier)`
(64-entry, FIFO-evicted) — `tests/e2e.rs::verifier_key_is_cached_after_first_verify`
measures the cached hit at under 40% of the first, uncached recomputation
(retuned in M2.3: splitting the 2^16-row byte table into two 256-row tables
made the uncached build cheap enough that the old 10% bound no longer held —
see the test's own comment for the measured numbers).

Recomputability depends on one deliberate choice in `machine.rs::key_config`:
the hiding MMCS's per-commit salt (and the PCS's own random codewords) are
seeded not from OS entropy but from a deterministic 64-bit digest of the
program (`program_digest`, which folds `base_pc`, the word count, and every
word). Every actual `prove_batch` call still runs against `make_config`'s
fresh-entropy config for the main-trace, quotient, and permutation
commitments — that is what keeps zero knowledge intact, and is why two proofs
of the same run are still different bytes (`docs/03-privacy.md`). Only the
*preprocessed* commitment — `program`, `range`, and `nibble` — is
deterministic, and that determinism is exactly what lets `hc` be recomputed
by any verifier without having witnessed the original proving session.

The reason this is safe is **not** that "the program table is public, so no
privacy is lost." A commitment whose randomness is a function of the message
is binding but not hiding: it is brute-forceable over any guessable program
space, and two deployments of the same program yield the same `hc` and are
therefore linkable. It is harmless in milestone 1 for a more basic reason —
program confidentiality is not a milestone-1 property at all. `verify` takes
the whole `Program` in the clear, so the verifier already holds every word and
there is nothing left for a salt to hide. See `docs/03-privacy.md`; a hiding
program commitment is a milestone-3 question, alongside the in-circuit digest
that stops the verifier from holding the code.
