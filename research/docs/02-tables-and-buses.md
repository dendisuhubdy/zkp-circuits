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

## `cpu` — main, `col::WIDTH = 40`

Columns: `clk pc next_pc is_real`, the same 18 decoded fields (fetched, not
recomputed), `a b c alu_out tgt` (operands and results), `mem_addr mem_val`,
three syscall flags `sys_halt sys_write sys_read`, and eight one-hot output
selectors `out_sel0..7`. This is the only table with public values: `pc_entry`,
the tier index, and the eight output words.

Constraints, in words: `is_real` is boolean and monotone (once 0, stays 0);
`clk` starts at 0 and increments by 1 on real rows; the first row's `pc`
equals the public `pc_entry`; the row after the last real row must be a
`HALT`. Every real row looks up its own `(pc, 18 fields)` on `PROGRAM` — the
CPU never decodes an opcode bit itself, only trusts what the lookup
returned. The second ALU operand is `imm` or `b` depending on `is_imm`; an
ALU-using row (`is_alu`, branch, load, store, `jalr`) looks up `(op, a,
b_eff, alu_out)` on `ALU`, and a second, independent ALU slot computes
`pc + imm` for `branch`/`jal`/`auipc`. `c` (the value written to `rd`) is
pinned by kind: `alu_out` for ALU ops, `mem_val` for loads, `pc+4` for
`jal`/`jalr`, `imm` for `lui`, `tgt` for `auipc`. On every row whose kind
does *not* define `c` (branches, stores, `HALT`/`WRITE_OUTPUT`), `c` is
forced to 0 — the constraint that stops a cheating witness from smuggling a
value through an unused column (`defines_c` in `cpu.rs`). `next_pc` is
`pc+4` unless the row is a taken branch, `jal`, or `jalr`. Register
reads/writes and the one optional memory access go out on `MEMORY` below.
`ECALL` rows pre-decode `rs1=17 (a7)`, `rs2=10 (a0)`, so the syscall number
and first argument arrive through the ordinary register-read slots; the
second argument (`a1`) is read through the memory-access slot.
`WRITE_OUTPUT` constrains `public_values[2+slot] = word` via eight one-hot
selectors on `slot`.

Sends: 4 `MEMORY` messages per row (two register reads, one optional
RAM/`a1` access, one optional register write), 2 `ALU` lookups. Receives:
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
`(op, a, b, c)` on `ALU` with count `mult`.

## `byte` — preprocessed, `pre::WIDTH = 7` + `col::WIDTH = 5`

Preprocessed: 2^16 rows, one per byte pair `(a, b)`, holding `a&b`, `a|b`,
`a^b`, and — on the 32 rows with `b = 0, a < 32` — `pow2 = 2^a` and a flag
`is_pow2`. Main: five multiplicities, one per bus. Constraint: a `POW2`
lookup can only land on an `is_pow2` row. Provides `RANGE8` (`[a]`), `AND8`/
`OR8`/`XOR8` (`[a,b,a·b]`), and `POW2` (`[a,pow2]`), each with its own
multiplicity column. It is the only table besides `program` that is
preprocessed, and its buses are consumed by `memory` (`RANGE8` only) and
`alu` (all five) — `cpu` and `program` never look it up directly; every byte
check the CPU or the program table needs is delegated through `alu` or
`memory` first.

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
`CommonData`; this is a known, fixed cost per verification in this
milestone, to be cached later.

Recomputability depends on one deliberate choice in `machine.rs::key_config`:
the hiding MMCS's per-commit salt (and the PCS's own random codewords) are
seeded not from OS entropy but from a deterministic 64-bit digest of the
program (`program_digest`). Every actual `prove_batch` call still runs
against `make_config`'s fresh-entropy config for the main-trace, quotient,
and permutation commitments — that is what keeps zero knowledge intact, and
is why two proofs of the same run are still different bytes (`docs/03-privacy.md`).
Only the *preprocessed* commitment — `program` and `byte`, both of them
public data with nothing to hide — is deterministic, and that determinism is
exactly what lets `hc` be recomputed by any verifier without having
witnessed the original proving session.
