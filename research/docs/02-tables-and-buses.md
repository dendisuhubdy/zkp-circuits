# The tables and their buses

The relation is proved as one batch of five AIR tables under one commitment
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
                     │ RANGE8                                │ RANGE8 AND8 OR8 XOR8 POW2
                     └───────────────────┴───────────────────┘
                                         ▼
                                    ┌───────────┐
                                    │   BYTE    │ preprocessed, 2^16 rows: every (a,b) byte pair
                                    └───────────┘
```

Eight buses in total: `PROGRAM`, `MEMORY`, `ALU`, and five carried by the
byte table — `RANGE8`, `AND8`, `OR8`, `XOR8`, `POW2`. `PROGRAM`, `ALU`,
`RANGE8`, `AND8`, `OR8`, `XOR8`, `POW2` are `LookupBus`es (a subset check:
every value a consumer sends must appear, with enough multiplicity, in the
provider's table). `MEMORY` is a `PermutationCheckBus` — both sides are
prover-supplied main-trace rows, and the argument proved is multiset
equality, not a lookup into a fixed table.

## `program` — preprocessed, `pre::WIDTH = 20` + `col::WIDTH = 1`

Preprocessed columns: `pc`, then the 18 `Decoded` fields in the fixed
`to_fields` order (`rd rs1 rs2 imm is_alu alu_op is_imm is_branch br_op
br_neg is_load is_store is_jal is_jalr is_lui is_auipc is_ecall writes_rd`),
then `valid` (1 on real instruction rows, 0 on padding). One main column,
`mult`: how many times this row was fetched. Constraint: a row with
`valid = 0` must have `mult = 0` — padding can never be fetched. Provides
`(pc, 18 fields…)` on `PROGRAM` with count `mult`.

## `cpu` — main, `col::WIDTH = 52`

Columns: `clk pc next_pc is_real`, the same 18 decoded fields (fetched, not
recomputed), `a b c alu_out tgt` (operands and results), `mem_addr mem_val`,
three syscall flags `sys_halt sys_write sys_read`, eight one-hot output
selectors `out_sel0..7` (indices 32–39), eight cumulative counters
`written0..7` (40–47), and four byte limbs `ma0..3` of `mem_addr` (48–51).
This is the only table with public values: `pc_entry`, the tier index, and the
eight output words.

Constraints, in words: `is_real` is boolean and monotone (once 0, stays 0);
`clk` starts at 0 and increments by 1 on real rows; the first row's `pc`
equals the public `pc_entry`; the *last real row* is a `HALT`, and nothing
runs after it — every row past it is padding. Every real row looks up its
own `(pc, 18 fields)` on `PROGRAM` — the
CPU never decodes an opcode bit itself, only trusts what the lookup
returned. The second ALU operand is `imm` or `b` depending on `is_imm`; an
ALU-using row (`is_alu`, branch, load, store, `jalr`) looks up `(op, a,
b_eff, alu_out)` on `ALU`, and a second, independent ALU slot computes
`pc + imm` for `branch`/`jal`/`auipc`. `c` (the value written to `rd`) is
pinned by kind: `alu_out` for ALU ops, `mem_val` for loads, `pc+4` for
`jal`/`jalr`, `imm` for `lui`, `tgt` for `auipc`. On every row whose kind
does *not* define `c` (branches, stores, `HALT`/`WRITE_OUTPUT`), `c` is
forced to 0 — the constraint that stops a cheating witness from smuggling a
value through an unused column (`defines_c` in `cpu.rs`). A store's `mem_val` is pinned to `b`, the value
just read from `rs2` — the one `MEMORY` message field the bus would otherwise accept
unstated, letting a cheating witness store a value no register ever held and read it back
through a later load as genuine memory contents. `next_pc` is
`pc+4` unless the row is a taken branch, `jal`, or `jalr`. Register
reads/writes and the one optional memory access go out on `MEMORY` below.
`ECALL` rows pre-decode `rs1=17 (a7)`, `rs2=10 (a0)`, so the syscall number
and first argument arrive through the ordinary register-read slots; the
second argument (`a1`) is read through the memory-access slot.
`WRITE_OUTPUT` constrains `public_values[2+slot] = word` via eight one-hot
selectors on `slot`. The eight `written_i` columns accumulate `out_sel_i` down
the table and are boolean on every row, which caps each slot at a single write
(matching the emulator's `DoubleWrite` error) and lets the last row assert
`(1 − written_i)·public_values[2+i] = 0`: a slot no `WRITE_OUTPUT` ever
selected is zero, as the spec requires, instead of being a free public value.

Word alignment of `LW`/`SW` is a stated constraint, not an accident.
`mem_addr·4 = alu_out` on its own is a field identity — a misaligned `alu_out`
would just give `mem_addr = alu_out·4⁻¹ mod p` — so `mem_addr` is additionally
decomposed into the four byte limbs `ma0..3`, each range-checked on `RANGE8`,
with one `AND8` lookup `(ma3, 0xC0) → 0` bounding `mem_addr` below 2^30. Since
`alu_out` is already 32-bit (the ALU table's own limb range checks),
`mem_addr·4 < 2^32` cannot wrap and the identity holds over the integers.

Sends: 4 `MEMORY` messages per row (two register reads, one optional
RAM/`a1` access, one optional register write), 2 `ALU` lookups, and on
load/store rows 4 `RANGE8` plus 1 `AND8` for the address limbs. Receives:
1 `PROGRAM` lookup.

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

## `alu` — main, `col::WIDTH = 49`

Columns: 11 one-hot op flags (`add sub and or xor sll srl sra slt sltu eq`),
`a b c`, three 4-limb decompositions `a0..3 b0..3 c0..3`, scratch limbs
`q0..3` (shift quotient / `sll` high word), `s0..3` (compare difference /
right-shift remainder), `t0..3` (`pow2 − 1 − remainder`), sign bits `sa sb`,
shift amount `sh`, `pow2 = 2^sh`, four adder carries, an inverse column for
`eq`, `is_real`, and `mult` (how many times the CPU hit this exact tuple).

Constraints: exactly one op flag set per real row; every limb decomposition
recomposes to its word and is range-checked on `RANGE8`; `add`/`sub`/`slt`/
`sltu` share one limb-wise adder with boolean carries; `slt`/`sltu` reduce to
a subtract-with-borrow, `slt` sign-corrects using the top-limb sign bits
(an `AND8` lookup against `0x80`); `eq` uses an inverse column to prove
`a ≠ b ⇒ c = 0` and `a = b ⇒ c = 1`; `and`/`or`/`xor` look up each limb
triple on `AND8`/`OR8`/`XOR8`; `sll` proves `a·2^sh = c + hi·2^32` with `hi`
and `c` range-checked and `(sh, 2^sh)` on `POW2`; `srl`/`sra` prove the
integer division `a = q·2^sh + r`, `r < 2^sh`, with `sra` working on the
two's-complement magnitude and re-flipping the sign after. Provides
`(op, a, b, c)` on `ALU` with count `mult`, and `(1 − is_real)·mult = 0`
forces that count to zero on padding rows. That last one is load-bearing: on a
padding row every op flag is zero (so `op` reads as `Add`), the limb range
checks are counted by `is_real`, every arithmetic constraint carries a flag
factor, and the recomposition `a = Σ a_i·2^{8i}` is satisfied by parking a
whole field element in limb 0 — so without it a padding row provided an
arbitrary `Add` tuple with arbitrary multiplicity, and the CPU consumes `Add`
for every `ADD`/`ADDI`, every load/store address, every `JALR` target and the
whole slot-2 `(0, pc, imm, tgt)` lookup. The general rule, applied to every
`table_entry` in the crate: **the count must be forced to zero wherever the
message columns are unconstrained.** `program` already does this
(`mult·(1 − valid) = 0`); `byte` is preprocessed with no padding rows at all.

## `byte` — preprocessed, `pre::WIDTH = 7` + `col::WIDTH = 5`

Preprocessed: 2^16 rows, one per byte pair `(a, b)`, holding `a&b`, `a|b`,
`a^b`, and — on the 32 rows with `b = 0, a < 32` — `pow2 = 2^a` and a flag
`is_pow2`. Main: five multiplicities, one per bus. Constraint: a `POW2`
lookup can only land on an `is_pow2` row. Provides `RANGE8` (`[a]`), `AND8`
(`[a, b, a & b]`), `OR8` (`[a, b, a | b]`), `XOR8` (`[a, b, a ^ b]`), and
`POW2` (`[a, 2^a]`), each with its own multiplicity column. It is the only
table besides `program` that is preprocessed. Its buses are consumed by
`memory` (`RANGE8` only), `alu` (all five), and `cpu` (`RANGE8` and `AND8`,
for the load/store address limbs); `program` never looks it up.

## Why the program is preprocessed, and what that means for `hc`

Plonky3 commits a preprocessed trace once, independent of any witness, and
the verifier holds that commitment permanently in its `CommonData`. Because
`program`'s decoded columns are preprocessed, **that commitment is `hc`**:
registering a confidential program on-chain means publishing this one
Merkle root, and the constraint system and verifier code stay identical for
every program. `Machine::code_hash` recomputes it directly from the program
via `verifier_key`, so any verifier — not just the original prover — can
derive `hc` standalone. That recomputation always includes the 2^16-row byte
table too, since it is also preprocessed and folds into the same
`CommonData`; `Machine::verifier_key` caches this per `(program digest, tier)`
(64-entry, FIFO-evicted) — `tests/e2e.rs::verifier_key_is_cached_after_first_verify`
measures the cached hit at under 10% of the first, uncached recomputation.

Recomputability depends on one deliberate choice in `machine.rs::key_config`:
the hiding MMCS's per-commit salt (and the PCS's own random codewords) are
seeded not from OS entropy but from a deterministic 64-bit digest of the
program (`program_digest`, which folds `base_pc`, the word count, and every
word). Every actual `prove_batch` call still runs against `make_config`'s
fresh-entropy config for the main-trace, quotient, and permutation
commitments — that is what keeps zero knowledge intact, and is why two proofs
of the same run are still different bytes (`docs/03-privacy.md`). Only the
*preprocessed* commitment — `program` and `byte` — is deterministic, and that
determinism is exactly what lets `hc` be recomputed by any verifier without
having witnessed the original proving session.

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
