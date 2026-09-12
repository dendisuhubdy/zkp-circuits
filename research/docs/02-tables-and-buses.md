# The tables and their buses

The relation is proved as one batch of nine AIR tables under one commitment
and one FRI opening (`p3-batch-stark`). Tables never call each other
directly; they exchange facts through named LogUp buses, and the batch
verifier checks that every bus balances globally.

```
                                  ┌───────────┐
                                  │  PROGRAM  │ main; in-circuit decoder; hc is proved, not preprocessed
                                  └───────────┘
                                   │ PROGRAM (instruction fetch)  │ PROGRAM_WORD (M3.4 digest rows)
                                   ▼                              ▼
                  MEMORY bus            ┌───────────┐             ALU bus
                            ◄─────      │    CPU    │      ─────►
                 (permutation)          └───────────┘            (lookup)
                                        │   │    │
                    ┌───────────────────┘   │    └───────────────┐
                    ▼                       │                    ▼
               ┌───────────┐                │               ┌───────────┐
               │  MEMORY   │                │               │    ALU    │
               └───────────┘                │               └───────────┘
                     │ RANGE8                │ INPUT_DIGEST /      │ RANGE8 AND4 OR4 XOR4 POW2
                     │                       │ INPUT_READ (M4.1)   │
                     │                       ▼                     │
                     │                 ┌───────────┐               │
                     │                 │   INPUT   │  main; one row per
                     │                 └───────────┘  committed input word
                     │                       │ (no further buses)  │
                     └──────────────────┬────┴──────────────────────┘
                              ┌──────────┴──────────┐
                              ▼                     ▼
                        ┌───────────┐         ┌───────────┐
                        │   RANGE   │         │  NIBBLE   │
                        └───────────┘         └───────────┘
                    preprocessed, 256 rows   preprocessed, 256 rows
                    every byte a; pow2(a)    every nibble pair (a,b)

                        ┌─────────────┐
                        │  POSEIDON2  │  main; height = tier.poseidon2_height()
                        └─────────────┘
                    provides POSEIDON2 (lookup); consumed by cpu's hash rows
                    (a POSEIDON2 syscall), its digest rows (M3.4, hc),
                    *and* its indigest rows (M4.1, H_IN)

                        ┌─────────────┐
                        │   KECCAK    │  main; height = 1 << Proof::keccak_log_height
                        └─────────────┘
                    provides KECCAK (clk, ptr) (lookup); consumed by cpu's
                    SYS_KECCAK rows. Unlike every other chip it also *sends*
                    on MEMORY — its own 50 reads and 50 writes per block, so
                    the cpu row that asks for a permutation never carries the
                    permuted words at all (M4.2)
```

Thirteen buses in total: `PROGRAM`, `PROGRAM_WORD` (M3.4), `INPUT_DIGEST`,
`INPUT_READ` (M4.1, carried by the new `input` table), `MEMORY`, `ALU`,
`RANGE8` and `POW2` (carried by the range table), `AND4`, `OR4`, `XOR4`
(carried by the nibble table), `POSEIDON2` (carried by the poseidon2
table), and `KECCAK` (M4.2, carried by the keccak table). Every one of these
except `MEMORY` is a `LookupBus` (a subset
check: every value a consumer sends must appear, with enough multiplicity,
in the provider's table). `MEMORY` is a `PermutationCheckBus` — both sides
are prover-supplied main-trace rows, and the argument proved is multiset
equality, not a lookup into a fixed table. Since M4.2 the memory table is
not the only *receiver* on it and the cpu table not the only sender: the
keccak chip sends its own traffic, and `memory_trace` records it
(`CycleEvent::keccak_accesses`) alongside the cpu's own.

## `input` — main, `col::WIDTH = 4` (M4.1)

One row per committed private-input word: `IDX` (the row's own index, 0 at
row 0, `+1` every row including through padding — input indices always
start at 0 by definition, so unlike `program`'s `PC` there is no external
`base_pc` anchor to worry about), `WORD` (the input value), `IS_REAL`, and
`MULT_READ` (how many times `READ_INPUT` actually reads this index — a
free witness value, pinned to reality only by its own bus's balance).
`IS_REAL` is a boolean, monotone prefix exactly like every other main
table's real/padding split; `IDX`'s `+1`-per-row chain needs no separate
"no aliasing" argument the way `program`'s `PC` does, since starting at 0
already makes every row's index unique.

**Two buses, not one — review round 1 (C1).** An earlier design put both
consumers of `(IDX, WORD)` — the digest's mandatory absorption and a
`SYS_READ`'s optional one — on a single `INPUT_WORD` bus with count
`IS_REAL * (1 + MULT_READ)`. That is unsound: LogUp balances per
`(idx, word)` key only, not per *consumer class*, so a prover could shrink
the digest's demand at some index (excluding a word from `H_IN`) while a
genuine `READ_INPUT` at that same index still succeeded, consuming the
row's now-sole remaining unit of supply — `H_IN` would then commit to
*fewer* words than the guest actually read, with every constraint
satisfied. The table now provides on **two separate buses** instead:

- `INPUT_DIGEST`, count `IS_REAL` — the `cpu` table's `IS_INDIGEST` rows'
  *only* source of `(idx, word)`, one unit per real row, completely
  independent of how many times (if any) that index is read.
- `INPUT_READ`, count `IS_REAL * MULT_READ` — `SYS_READ`'s only source,
  `MULT_READ` unrelated to `INPUT_DIGEST`'s own count.

With the two separated, `INPUT_DIGEST` alone carries exactly `program`'s
`MULT_WORD = VALID` argument (the "`hc` binds the whole executable
program" section, above): the cpu table's real (non-salt) `IS_INDIGEST`
rows demand exactly the drained absorption chain's index set — `{0, ..,
n_in-1}` with the words they actually absorbed, fixed independently of
this table. For `INPUT_DIGEST` to balance, this table's real rows must
supply *exactly* that set: a real row at `idx >= n_in` is an unclaimed
supply (rejected — `LOOKUP_BALANCE_PANIC`), and an index the digest
demands but this table doesn't supply as real is an unclaimed demand
(also rejected) — either way, `real_count == n_in` is forced, and the
absorbed words must equal this table's `WORD` values exactly.
`INPUT_READ` then separately, and independently, ties `MULT_READ` to the
true `SYS_READ` count per index, with no way for either bus to borrow
slack from the other. `MULT_READ` needs no range check of its own: `IDX`
is already pinned one row per committed index, never revisited, so a
too-large `MULT_READ` only ever inflates *that one row's* `INPUT_READ`
supply — it can't be spread across rows to hide an over-count, and any
excess is caught by `INPUT_READ`'s own balance against the true
`SYS_READ` demand regardless of magnitude.

**Padding.** `WORD` and `MULT_READ` are both pinned to 0 wherever
`IS_REAL = 0` (AGENTS.md invariant 1/2) — a stray nonzero `MULT_READ` on a
padding row is exactly the "unconstrained column nothing currently reads"
class of bug AGENTS.md's ALU lesson warns about, and pinning it is what
makes `tests/cheating.rs`'s padding-row `MULT_READ` regression a real
rejection rather than a no-op tamper.

**Height.** `input_log_height(n)` follows `program_log_height`'s own
"declare `n+1`, floor at `MIN_HEIGHT`" rule (`MIN_HEIGHT = 4`,
`MIN_LOG_HEIGHT = 2`, `MAX_LOG_HEIGHT = 20` — a million private-input
words, comfortably past any guest this crate runs, one size smaller than
`program`'s ceiling since inputs are typically far shorter than programs).
`Proof` carries the declared height as `input_log_height: u8`, exactly
mirroring `program_log_height`; `Machine::verify` bounds it to
`[MIN_LOG_HEIGHT, MAX_LOG_HEIGHT]` before using it to size anything.
`MAX_LOG_HEIGHT = 20` is only the table-shape ceiling, though: `cpu`'s
shared absorb machinery range-checks `HASH_LEFT` via two `RANGE8` limbs on
every indigest row, bounding it to 16 bits — so the effective cap on
`n_in` is 65535, well below what `MAX_LOG_HEIGHT` alone would allow.

## `program` — main, `col::WIDTH = 108`

M3.4: the program table is a **witness** trace with an in-circuit decoder,
not a preprocessed ROM the verifier holds in the clear. Each row carries a
raw 32-bit instruction `WORD`, its 32-bit decomposition (`bit0..31`, each
boolean, `WORD = Σ bit_i·2^i`), the same 23 `Decoded` fields the old
preprocessed table carried (`rd rs1 rs2 imm is_alu alu_op is_imm is_branch
br_op br_neg is_lb is_lh is_lw is_sb is_sh is_sw signed is_jal is_jalr
is_lui is_auipc is_ecall writes_rd`), `valid`, and two multiplicities:
`mult` (ordinary instruction-fetch count, `PROGRAM` bus) and `mult_word`
(digest-row fetch count, the new `PROGRAM_WORD` bus, M3.4). Plus decoder
scratch: an is-zero gadget on the final `rd` field (`rd_is_zero`/`rd_inv`,
for `writes_rd`) and 46 one-hot legality/decode flags (`flags` module in
`tables/program.rs`), one per `(opcode, funct3, funct7)` case
`isa::Instr::decode` recognizes.

**The decoder.** Every `Decoded` field is a flag-weighted sum of raw bit
sums (rd/rs1/rs2, the six immediate-format formulas — U/I/S/B/J-type plus
the raw 5-bit shamt for ALUI shifts, each a *linear* expression in the bit
columns, sign-extended by adding `sign_bit·(2^32 − 2^width)`) or fixed
overrides (`Ecall` sets `rd = REG_A0`, `rs1 = REG_A7`, `rs2 = REG_A0`, the
same values `Instr::decoded()` hard-codes). Each of the 46 flags is pinned
by an opcode-match constraint (`flag·(op − code) = 0`) and, where needed, a
funct3/funct7-match constraint — so a flag can only be forced nonzero when
its exact bit pattern actually appears in `WORD`. `valid` is the sum of all
46 flags (at most one can ever be forced nonzero on a real row, since the
patterns are pairwise disjoint); a word matching none of them forces
`valid = 0`. The M-extension ops (`Mul..Remu`) are reachable **only**
through the `OP_ALU, funct7 = 1` flags — no `OP_ALUI` flag ever maps to
one, mirroring `isa::Instr::decode`'s own `funct7 = 1` gate exactly (an
`OP_ALUI` word can never be legally read as an M op, regardless of its
`funct7` bits, which are just part of its sign-extended immediate there).
Every constraint here is at most degree 2 in the columns (a flag times a
linear bit-sum, or a flag times a fixed constant).

**No address aliasing without a host-trusted `pc`.** Since `PC` is now a
witness column, every row's `PC` is pinned to be exactly 4 more than the
row before it (unconditional, including across the padding boundary) —
over any realistic table height this makes every row's `PC` distinct
regardless of what absolute value the sequence starts at, so `PROGRAM`/
`PROGRAM_WORD` lookups can never land on the "wrong" row. The starting
value needs no separate check: the cpu table's own digest-row and
ordinary-fetch `pc` values only balance against *some* base the two tables
agree on, and the ordinary lookup-balance mechanism rejects any mismatch.

**Padding.** `mult` is forced to 0 wherever `valid = 0` (a padding row,
all-zero, whose `WORD = 0` decodes as no known opcode, can never be
fetched), and `program_trace` panics if any real word is undecodable (the
same invariant the old preprocessed builder enforced). `mult_word` is
pinned harder still — see "`hc` binds the whole executable program" below.

**`hc` binds the whole executable program.** `mult_word` is constrained to
*equal* `valid` (`mult_word = valid`), not merely zeroed on invalid rows —
the weaker `mult_word · (1 − valid) = 0` was this table's actual constraint
through the first cut of M3.4, and it was a real gap: it left `mult_word`
free on valid rows, so a real, decodable `valid = 1` row could supply zero
copies of its own `(pc, word)` and simply never be digested while staying
fully fetchable (and executable, e.g. as a `JALR` target) via `PROGRAM` —
`hc` would then bind a strict prefix of the executable program, not all of
it. With `mult_word = valid`, `PROGRAM_WORD`'s LogUp balance is a
set-equality argument: the digest rows demand exactly `len` distinct
messages, one per `base_pc + 4·j` for `j < len`; every valid row supplies
exactly one message, at its own (unique — see "No address aliasing" above)
`pc`. Balancing forces the two sets equal — `len` comes out equal to the
number of valid rows, and a valid row honestly placed outside the digested
window (`mult_word = 1`, matching its own `valid`) has a supplied message
nothing demands, so the bus fails to balance (`LOOKUP_BALANCE_PANIC`) and
the proof is rejected. The simpler witness — the original gap verbatim, a
valid row left at `mult_word = 0` — never reaches that global check at
all: it trips the local `mult_word = valid` equation on its own row first
(`CONSTRAINT_PANIC`). Either way, there is no way to be `valid = 1` and
excluded from `hc`. See `src/tables/program.rs`'s module doc and
`tests/cheating.rs::an_undigested_reachable_program_tail_is_rejected`
(which reproduces the simpler, local case).

**Height (review fix): proof-declared, not tier-derived.** The table's
height is `1 << Proof::program_log_height` — a value the *prover* declares
per proof (`tables::program::program_log_height(len) = pad_height(len + 1,
MIN_HEIGHT).trailing_zeros()`, floored at `MIN_HEIGHT = 16` rows, ceilinged
at `MAX_LOG_HEIGHT = 22`), not a function of the tier. An early version of
this milestone set it to `cpu_height()` (the same height as `cpu`) — unsafe:
a digest row absorbs up to 4 `PROGRAM_WORD`s per *cycle*, so a program with
`len` up to `4·(cpu_height − 1)` words fits the cycle budget while needing
far more than `cpu_height` program-table rows to hold its own words, and
`program_trace`'s `assert!(len <= height)` would panic rather than error.
`Machine::verify` bounds the proof-carried `program_log_height` itself
(`[MIN_LOG_HEIGHT, MAX_LOG_HEIGHT]`, `VerifyError::ProgramHeight` if it
isn't) before using it to size anything, exactly as it already bounds
`proof.tier`. `Machine::verifier_key`'s cache key grows to `(tier,
program_log_height)` accordingly (still program-*content*-independent —
computable from the tier and the declared height alone).

Soundness does not depend on the verifier checking the declared height
against the program in any other way, because `hc` already does: it binds
`(base_pc, len, words)` via the capacity-lane header
(`hash::program_digest`), and `mult_word = valid` (above) makes the
`PROGRAM_WORD` set-equality argument do the rest — the digested set and
the valid-row set coincide, so `len` and the valid-row count are forced
equal. A prover who declares a table too small to hold `len` real rows
simply cannot build a witness that balances (some word `hc` commits to has
nowhere to live); one who declares a table larger than necessary only
spends more of their own proving time and a slightly bigger verifier-side
degree-bits check. The declared height
only *sizes* the table — it can never let a prover shrink or pad the
program the digest is already bound to. See `docs/03-privacy.md`.

`program_trace` (the witness builder) counts an ordinary-fetch `mult` per
`CycleEvent` whose `pc` matches — except, since M3.2, a `POSEIDON2` call's
absorb/write-back rows, which share their ecall row's `pc` without being
separate fetches (`cpu`'s `PROGRAM` lookup is gated off on them below).
`mult_word` is unconditionally 1 for every real row: every proof includes
exactly one traversal of the whole program for `hc`, regardless of how the
program actually ran.

## `cpu` — main, `col::WIDTH = 222`

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
`merged0..3` (the word a store writes back), then the M3.2 hash-row columns
(their own subsection below): four selectors `sys_hash is_hash is_hash_out
hash_fin`, `hash_ptr hash_n hash_left hash_idx`, eight state lanes
`hs0..7`, four per-row words `hv0..3`, four absorb-row lane-activity
booleans `act0..3`, byte limbs `left0..1`/`idx0..1` of `hash_left`/
`hash_idx`, 16 byte limbs `hvl0..15` of `hv0..3` (write-back rows only),
five byte limbs `hp0..3`/`hp3_hi` of `hash_ptr` (ecall row only — the
`ma0..3`/`ma3_hi` pattern, bounding `hash_ptr < 2^30`), and the
canonical-digest-encoding gadget's four columns `himax0..1`/`inv0..1`
(write-back rows only), then the M3.4 digest-row columns (their own
subsection below): `is_digest`, `digest_last`, 32 byte limbs `dhvl0..31` of
the 8 output words, `dhimax0..3`/`dinv0..3` (the canonical-encoding
gadget, last digest row only), and (M4.1, freeing the physical `hs0..7`
cell at the digest-to-indigest transition for `H_IN`'s header seed) eight
dedicated columns `dpout0..7` holding the last digest row's own real
permutation output. Then the M4.1 indigest-row columns (their own
subsection below, mirroring the digest-row prefix): `is_indigest`,
`indigest_last`, `is_salt`, 32 byte limbs `ihvl0..31` of the 8 `H_IN`
output words, and the canonical-encoding gadget's `ihimax0..3`/`iinv0..3`
(last indigest row only). This is the only table with public
values: `pc_entry`, the tier index, the eight output words, (M3.4) the
eight `hc` words `pv::HC0..HC7`, and (M4.1) the eight `H_IN` words
`pv::IN0..IN7` — `pv::NUM` grows from 18 to 26.

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
lookup. (M3.2 repurposes all four `MEMORY` slots on hash rows — see below;
every formula above still applies unchanged on every *non*-hash row.)

### M3.2: the `POSEIDON2` syscall — absorb and write-back hash rows

One `POSEIDON2` call (syscall 3, `docs/01-isa.md`) is a *row-group*: the
ecall row itself (`sys_hash`), one absorb row per 4-word (or final partial)
block (`is_hash`), and exactly two digest write-back rows (`is_hash_out`,
the second also marked `hash_fin`). All four count as ordinary cycles
(`is_real = 1`, `exec.cycles()`/tier selection see every one of them); `pc`
does not advance until the group's very last row. `hash_ptr`/`hash_n` are
read off the ecall row (`a0`/`a1`, the usual ecall argument slots) and held
constant across the whole group; `hash_left`/`hash_idx` track words not yet
absorbed and the current block index. Absorb/write-back rows are *not* new
`PROGRAM` fetches (the lookup is gated by `is_real - is_hash - is_hash_out`)
and carry none of the ordinary per-instruction columns — every decoded
field and the other two syscall flags are pinned to zero on them, which is
also what stops a cheating witness from smuggling an extra ALU/branch/
`WRITE_OUTPUT` claim through a row that looks, to the `PROGRAM`/`ALU`
buses, like it isn't fetching anything (the same AGENTS.md invariant-1
bug class, generalized to a new row kind).

**Slot story.** `hs0..7` is the sponge state as of the end of the
*previous* block (all-zero for the first); `hv0..3` is this row's four
machine words. On an absorb row the four `MEMORY` slots (`SLOT_R1 SLOT_R2
SLOT_MEM SLOT_W`, reused 1:1 with `act0..3`/`hv0..3`) each read one word at
`hash_ptr + 4·hash_idx + k`, gated by that lane's own `act_k` — a lane past
the block's real word count sends count 0 and its `hv_k` is pinned to the
*previous* state's own lane instead of a memory value (the sponge's
overwrite never touches it). On a write-back row all four slots write
`hash_ptr + k + 4·hash_fin`, unconditionally (count 1), from `hv0..3`. The
`POSEIDON2` lookup itself fires once per absorb row, keyed
`[hv0..3, hs4..7, next-row hs0..7]` — the overwritten rate lanes plus the
untouched capacity lanes as input, and the *next* row's `hs0..7` (whichever
row that is) as the claimed output; since the poseidon2 table only ever
provides genuine permutation pairs, this is what proves the state chain a
genuine Poseidon2 permutation, one block at a time, all the way to the
digest. The final absorb row's output becomes the first write-back row's
`hs0..7` (the digest, in lanes 0..3); the second write-back row copies it
forward unchanged (nothing else propagates `hs` across a write-back-to-
write-back transition). Each write-back row's `hv0..3` is pinned as the
honest lo/hi split (`hv_2j + hv_2j+1·2^32 = hs_lane_j`, byte-decomposed via
`hvl0..15` and `RANGE8`-checked) of two `hs` lanes — 0/1 on the first row,
2/3 on the second.

**Address bound.** `hash_ptr` is otherwise just the raw `a0` register
value — an unbounded field element. Since it feeds directly into every
hash-row `MEMORY` message's `addr`, and `memory.rs`'s own consistency
check only range-checks the *delta* between consecutive sorted
`(space, addr)` keys (never an address's absolute magnitude), an
unbounded `hash_ptr` would let a witness pick it so that `SPACE_RAM`'s
sort key (`1·2^30 + hash_ptr`, `memory.rs::KEY_SHIFT`) wraps, mod the
Goldilocks prime, into any other key — a register cell, or an
out-of-bounds RAM word — redirecting a hash row's reads/writes away from
the `n` words it claims to hash. `hp0..3`/`hp3_hi` close this exactly the
way `ma0..3`/`ma3_hi` close it for `MEM_ADDR`: `RANGE8` on each byte plus
`AND4[hp3_hi, 0xC, 0]` masking the top two bits, bounding `hash_ptr <
2^30`. Checked once, on the ecall row only — `hash_ptr` is copied
unchanged across the rest of the row-group (below), so bounding it there
bounds it (and every derived hash address, at most `hash_ptr + 4099`)
everywhere it is used.

**The `n = 0` escape.** The `final_absorb` drain rule (previous
paragraph) only ever fires on an `is_hash` transition — with zero absorb
rows in the group (the honest `n = 0` case), it never fires at all. Two
more rules close the gap it would otherwise leave open (a witness routing
straight from the ecall row to a write-back row for *any* `hash_n`,
publishing the empty-input digest regardless): the row right after the
ecall row must be either an absorb row or a write-back row, never
anything else (`sys_hash·(n(is_hash) + n(is_hash_out) - 1) = 0`), and it
can only be a write-back row when `hash_n = 0`
(`sys_hash·n(is_hash_out)·hash_n = 0`). A witness that instead nests an
absorb row somewhere but never actually absorbs anything is separately
caught by the first write-back row's own `hash_left = 0` requirement
(below) — the routing rules alone don't yet pin *that* row's `hash_left`
to match, since nothing but the `sys_hash -> next` copy otherwise touches
it, and a witness is free to set the copied value to whatever it likes.

**The "skip the first write-back row" escape.** A narrower version of the
same idea survives even with all of the above: nothing stopped a witness
routing straight into a `hash_fin = 1` row — the *second* write-back
row — without ever visiting the first, whether coming from the ecall row
directly (`n = 0`) or from the last absorb row (`n > 0`). Digest words
0..3 are then never written at all, so a guest reading `ptr..ptr+3` back
would see whatever RAM already held instead of the honest zeros — a valid
proof of a non-honest execution. Three rules, one per way into a
`hash_fin = 1` row, close it: `sys_hash·n(is_hash_out)·n(hash_fin) = 0`
(ecall row), `is_hash·n(is_hash_out)·n(hash_fin) = 0` (last absorb row),
and — the case neither of those two reaches, a witness parking at the
first write-back row and then routing *its own* next row somewhere other
than the second write-back row —
`is_hash_out·(1-hash_fin)·(1 - n(is_hash_out)·n(hash_fin)) = 0` (degree 4,
still under the degree-8 ceiling). Together the three cover every
transition that could land on `hash_fin = 1`, so a `POSEIDON2` call now
always writes both digest rows.

**Canonical digest encoding.** `hv_lo + hv_hi·2^32 = hs_lane` is only a
*field* identity — for any lane value `v < 2^32 - 1` the non-canonical
pair `(v + 1, 2^32 - 1)` satisfies it too (`(v+1) + (2^32-1)·2^32 = v + p
≡ v mod p`), and both words are still individually `< 2^32`, so `hvl0..15`
does not catch it either. The only *canonical* (base-`2^32`) pair with
`hi = 2^32 - 1` is `lo = 0` (the field's single largest element, `p - 1`)
— every other value with that `hi` is some smaller lane's non-canonical
alternate. `himax_j` (a zero-check flag on `d = hi - (2^32-1)`, `inv_j`
its inverse witness) forces exactly that: `d·inv_j = 1 - himax_j` forces
`himax_j = 1` whenever `d = 0`, regardless of `inv_j` (its term vanishes);
`himax_j·lo = 0` then forces `lo = 0` whenever `himax_j = 1` — closing the
non-canonical case while leaving every ordinary lane (`inv_j = d⁻¹`,
`himax_j = 0`) and the one legitimate `hi = 2^32-1` case (`lo = 0`)
satisfiable.

**Per-row-kind invariant argument** (AGENTS.md: every bus message column
constrained on every row kind that sends it; every count forced to zero
wherever its message is unconstrained):
- *ecall row*: `sys_hash·(a - POSEIDON2)`, `hash_ptr = b`, `hash_n = mem_val`,
  `hash_left = hash_n`, `hash_idx = 0`, `hs0..7 = 0` are all pinned
  directly; its own `MEMORY`/`ALU`/`PROGRAM` sends are the ordinary-ecall
  formulas, untouched; `hp0..3`/`hp3_hi` bound `hash_ptr < 2^30` (above);
  the three routing rules above bind the next row's kind to `hash_n` and
  rule out landing on `hash_fin = 1` directly.
- *absorb, non-final*: `act3 = 1` is forced (a witness cannot split one
  block into two smaller ones — a different, non-standard hash of the same
  message), so the row always absorbs a full 4-word block; `hash_left`/
  `hash_idx` chain to the next absorb row (`hash_idx` bounded `< 1024`,
  `= POSEIDON2_MAX_WORDS / 4`, via `idx0`'s plain `RANGE8` plus `idx0+1`'s
  tightened `AND4[idx1, 3, idx1]`, matching only `idx1 < 4`); the
  `POSEIDON2` lookup pins the chain to a genuine permutation.
- *absorb, final (partial)*: `act3` may be 0, but `hash_left` is forced to
  drain to exactly 0 on the *next* row — no early stop leaving words
  unabsorbed, no over-absorption (which would otherwise only be caught by
  a `RANGE8`-rejected field wraparound); inactive lanes' `hv_k = hs_k`;
  the next row cannot land on `hash_fin = 1` either (above).
- *write-back 1*: `hash_fin = 0`; `hash_left = 0` is required directly
  (not just via propagation — the `n = 0` escape above); `hs0..7` is
  whatever the last absorb's `POSEIDON2` lookup pinned it to (the digest,
  lanes 0..3); `hv0..3` splits `hs0..1`, canonically (`himax0..1`/
  `inv0..1` above); all four `MEMORY` slots write unconditionally; its own
  next row must be the second write-back row (above).
- *write-back 2*: `hash_fin = 1`, ending the row-group (`next_pc = pc + 4`
  here, nowhere else in the group); `hs0..7` is copied forward from
  write-back 1 unchanged; `hv0..3` splits `hs2..3`, canonically. `is_hash`
  and `is_hash_out` are also mutually exclusive on every row
  (`is_hash·is_hash_out = 0`) — nothing else stops a row claiming to be
  both an absorb and a write-back row at once.
- *padding*: `sys_hash is_hash is_hash_out hash_fin` are `SELECTORS`
  entries, so `(1 - is_real)·v = 0` forces all four to 0 — no lookup on
  either bus fires with a nonzero count there.

### M3.4: the digest-row prefix — `hc` in-circuit

`Program::digest_rows()` (`⌈len/4⌉`, at least 1) rows precede the first
instruction row: row 0 of the cpu table is always a digest row, never an
instruction. They reuse hash rows' absorb machinery wholesale — `hs0..7`
(sponge state), `hv0..3` (this row's up to 4 absorbed words), `act0..3`
(lane activity), `hash_left`/`hash_idx` and their byte limbs — gated by a
new selector `is_digest` instead of `is_hash`; the two are mutually
exclusive (they never occur on the same row) and share every generic
"this row absorbs something" constraint (`act0..3` well-formed, the
`POSEIDON2` bus lookup, inactive-lane carry-forward). The differences from
a hash row:

- **No memory sends at all.** A digest row's four words come from the new
  `PROGRAM_WORD` bus (`program_word_lookup(pc_k, hv_k)` for each active
  lane `k`, `pc_k = pc + 4·(4·hash_idx + k)` — `pc` here is `base_pc`,
  constant across the whole group), not a memory read — `is_digest` is
  folded into the same `off_cpu` exclusion hash rows already use for the
  four `MEMORY`-slot sends, the `DEC0..22` zeroing, and the ordinary
  `PROGRAM`-fetch count.
- **No preceding ecall row.** A `POSEIDON2` syscall's absorb rows inherit
  `hash_ptr`/`hash_n` and the all-zero starting state from their ecall row;
  a digest group has none, so `pc` (= `base_pc`) and `hash_n` (reused to
  carry `len`) are free witness values pinned only on `when_first_row`,
  and the starting sponge state is seeded there too — **not** all-zero:
  `hs4..6 = [HC_DOMAIN, base_pc, len]`, `hs0..3 = hs7 = 0`. This is what
  makes `hc` length- and base-bound without spending a rate slot (and
  hence a row) on a header block — see `hash::program_digest`'s doc
  comment for the exact construction and why it costs exactly
  `digest_rows()` permutations, not `⌈(len+3)/4⌉`.
- **`pc` is carried forward one row further than `hash_ptr` would be.**
  Every digest row pins `next_pc = pc` (constant across the group,
  including its own last row) — combined with the ordinary `n(pc) =
  next_pc` transition rule (already true on every real-row-to-real-row
  transition), this is what makes the *first instruction row's* `pc`
  equal to the digest group's `base_pc`, with no separate "boundary"
  constraint needed. `pv::PC_ENTRY` is bound to row 0's `pc` on
  `when_first_row`, exactly as it always was — it just now names the
  first *digest* row instead of the first instruction row.
- **`hash_idx`'s bound is looser.** A `POSEIDON2` syscall is capped at
  `POSEIDON2_MAX_WORDS = 4096` words (1024 blocks), so hash rows tighten
  `idx1` (the top byte of `hash_idx`) to `< 4` via an `AND4` lookup
  (`docs` above). A program can run to many thousands of words, so digest
  rows use only the plain `RANGE8[idx1]` bound instead (`hash_idx <
  65536`) — gated by `is_digest` alone, not reusing the hash-only AND4
  check.
- **`hash_n` (`len`) does not survive into the first instruction row.**
  Its copy-forward constraint is gated by `is_digest · n(is_digest)` (not
  bare `is_digest`), so it only has to persist digest-row-to-digest-row;
  the first instruction row's own `hash_n` column stays at its unrelated
  `zero_vec` default. (`pc` and `hash_left` do not need this distinction —
  `pc`'s constant-carry is meant to continue one row further, and
  `hash_left` naturally lands on 0 at the boundary, matching that row's
  own default.)
- **The last digest row (`digest_last = 1`, a dedicated witness column —
  see its doc comment for why not the degree-2 expression
  `is_digest·(1 − n(is_digest))`) publishes `hc`.** `n(hs0..3)` — the
  state after this row's own `POSEIDON2` permutation, i.e. the state
  entering the first instruction row — is encoded into 8 lo/hi machine
  words (`dhvl0..31`, `RANGE8`-checked; `dhimax0..3`/`dinv0..3` the same
  canonical-encoding gadget hash write-back rows use, one pair per lane
  here instead of two rows of two) and pinned equal to `pv::HC0..HC7`.
- **Digest rows count as cycles** (`Machine::build_traces`'s cycle check,
  `Tier::for_cycles`): a program's `digest_rows()` is added to its
  `Execution::cycles()` before comparing against `Tier::max_cycles()`.

`IS_DIGEST` is a contiguous prefix, enforced the same way `is_real`'s own
padding suffix is: 1 on row 0 (`when_first_row`), and once it drops to 0 it
never returns to 1. Skipping a digest row (ending the group early) is
rejected the same way M3.2's absorb-row `n`-binding is: `hash_left` cannot
reach exactly 0 early without absorbing a full 4-word block every row but
the last, and `digest_last`'s own pin desyncs the moment the group ends
somewhere the witness didn't mark.

### M4.1: the indigest-row region — `H_IN` in-circuit

Right after the program-digest prefix ends comes a second, structurally
identical digest region: `IS_INDIGEST` rows absorb the guest's committed
private-input vector into `H_IN` (`pv::IN0..IN7`), reusing the same shared
absorb machinery `IS_DIGEST`/`IS_HASH` already share (`HS0..7`, `HV0..3`,
`ACT0..3`, `HASH_LEFT`, `HASH_IDX`, their byte limbs — all three selectors
are pairwise mutually exclusive, so sharing is safe). This is a *mirror*
of the digest-row prefix (`IS_DIGEST`/`DIGEST_LAST`/`DHVL0..31`/
`DHIMAX0..3`/`DINV0..3`), not a generalization of it: `IS_INDIGEST` gets
its own final-encoding columns (`IHVL0..31`/`IHIMAX0..3`/`IINV0..3`)
rather than reusing `DHVL0..31`, since folding the two together would mean
re-deriving every `DHVL`-gated constraint to branch on which selector fired
and which `pv` slice to write, for a column-count saving this table's
degree/height budget does not need.

**The one real difference from the digest-row prefix: where the region is
seeded.** The program digest is row 0 of the table, so it seeds its own
header (`[HC_DOMAIN, base_pc, len]`) on `when_first_row` — there is no
"row before it" to transition from. The indigest region has no such luxury
(it isn't row 0, and — unlike a `POSEIDON2` syscall's absorb rows — there
is no preceding ecall row to inherit from either), so its header
(`[IN_DOMAIN, n_in, 0]`, one fewer real word than `hc`'s — no `base_pc`
analogue for a flat input vector) is instead seeded on the *transition out
of the program-digest prefix*, gated by `DIGEST_LAST` rather than
`when_first_row`. This forced a second change: the program digest's last
row's own real permutation output — needed by the honest trace one row
later as `n(HS0..7)` before M4.1 — collided with the indigest header now
wanting that same physical cell, so the last digest row's output moved to
dedicated `DPOUT0..7` columns instead (see that column's doc comment); the
`POSEIDON2` bus lookup and the `DHVL` canonical-encoding check both read
`DPOUT0..7` on that one row instead of `n(HS0..7)`, with zero change
everywhere else.

**Salted, so `H_IN` is hiding as well as binding.** The **first** absorbed
block of the indigest region is not a real input word at all — it is a
128-bit salt (four fresh witness words drawn per proof from OS entropy,
`Machine::prove`/`prove_on`), marked by a dedicated `IS_SALT` column (1 on
exactly that one row, the mirror image of `INDIGEST_LAST`'s "exactly one
row" pattern, at the opposite boundary). The salt row absorbs a full,
unconditionally-active 4-word block (`IS_SALT * (1 - ACT3) = 0`) and is
excluded from `INPUT_DIGEST`'s consume (`is_real_indigest = is_indigest -
IS_SALT` gates it) and from the `HASH_LEFT` drain (the salt isn't one of
the `n_in` committed words) — an unsalted `H_IN` would let a verifier who
can enumerate candidate private-input vectors test them directly against
`pv::IN0..7` (`docs/03-privacy.md`). `n_in == 0` needs no special case
post-salt: the salt row alone already guarantees at least one permutation,
so every real indigest row (unlike a digest-row-style "at least one row"
convention) is legitimately non-empty by construction, and lane 0 must
always be active there (`is_real_indigest * (1 - ACT0) = 0`) exactly like
`is_hash`/`is_digest`.

`INDIGEST_LAST`'s own row publishes `H_IN` to `pv::IN0..IN7`, the same
canonical byte-decomposition-and-non-canonical-rejection gadget
`DIGEST_LAST` uses for `pv::HC0..HC7`. Unlike `hc`, `H_IN` is **not**
checked by `Machine::verify` against a caller-supplied value — it is a
guest-visible commitment the guest itself opens (with the salt) if it
chooses to, not a verifier-side identity check.

### M4.2: the `KECCAK` ecall row

One row, never a row group — the shortest syscall shape in the table, and the
only one whose work happens entirely in another chip. It adds exactly one
column, `SYS_KECCAK` (appended at the end of the column list rather than
slotted next to the other selectors, so no existing index moves), which joins
the ecall one-hot (`SYS_HALT + SYS_WRITE + SYS_READ + SYS_HASH + SYS_KECCAK`)
and the padding-row `SELECTORS` gate.

What the row constrains:

- `A = SYS_KECCAK`'s syscall number (4) and `HASH_PTR = B` — `a0`, read the
  ordinary way through the register-2 slot, is the state's word address. The
  row **reuses** the `SYS_HASH` group's `HASH_PTR`/`HP0..3`/`HP3_HI` columns
  rather than adding its own; the "CRITICAL 1" limb decomposition
  (`HASH_PTR = Σ HP_i·2^(8i)`, four `RANGE8` lookups, `AND4[hp3_lo, 0, 0]`
  and `AND4[HP3_HI, 0xC, 0]`) is gated on `SYS_HASH + SYS_KECCAK`, which are
  mutually exclusive, so the count stays ≤ 1 and the bound costs nothing new.
- The rest of the hash group's shared columns are pinned to zero here
  (`HASH_N`, `HASH_LEFT`, `HASH_IDX`, `HS0..7`), so a keccak row cannot
  smuggle a half-formed hash claim through a row no hash rule gates on. It
  also does not route: `continues` keys off `SYS_HASH` alone, so a keccak row
  falls through to the ordinary `NEXT_PC = PC + 4` rule.
- **The cubic pointer rule.** `AND4[HP3_HI, 0xC, 0]` alone gives
  `HP3_HI ∈ {0,1,2,3}`, i.e. `ptr < 2^30`. The keccak chip addresses
  `PTR .. PTR + 49` by plain field addition and has nothing of its own that
  bounds `PTR`, so the top nibble is tightened one step further —
  `SYS_KECCAK · HP3_HI · (HP3_HI − 1) · (HP3_HI − 2) = 0`, hence
  `ptr ≤ 0x2fff_ffff` and `ptr + 49 < 2^30` with room to spare. Degree 4 on a
  selector-gated product of one column, well under this table's degree-8
  ceiling. The emulator enforces the same bound as reference semantics
  (`ExecError::KeccakPtrOutOfRange`, `KECCAK_PTR_LIMIT = 0x3000_0000 − 50`),
  so no honest execution exists that this rule could not prove.
  `tests/cheating.rs`'s `a_keccak_pointer_with_hp3_hi_equal_to_three_is_
  rejected` is the regression, with `a_relocated_keccak_pointer_inside_the_
  bound_still_proves` as its control.
- `bus::KECCAK.lookup_key([CLK, HASH_PTR], count = SYS_KECCAK)` — the whole
  handshake. `CLK` is this table's own digest-prefix-shifted clock, which is
  also what the chip's `4·CLK`/`4·CLK + 1` memory timestamps are built from,
  so the pair identifies the cpu row and the chip's block as one event.

Note what is **not** here: the 50 input words, the 50 output words, and the
100 memory messages that move them. Those belong to the `keccak` table, which
is why a permutation costs one cpu row and four memory slots instead of 100.

## `memory` — main, `col::WIDTH = 12`

Columns: `space addr ts value is_write is_real addr_changed diff_inv`, then
four limbs `d0..d3` of the gap to the next row. Rows are sorted by
`(space, addr, ts)`; `space` 0 is the register file (`addr` = register index
0–31), `space` 1 is RAM (`addr` = word address) — this is how registers ride
in the same table as RAM instead of costing the CPU 32 dedicated columns.

The **timestamp rule**: `ts = 4·clk + slot`, with `slot ∈ {0,1,2,3}` for the
register-1 read, register-2 read, the RAM/`a1` access, and the register
write respectively (`SLOT_R1..SLOT_W` in `emulator.rs`). This bounds every
*cpu-issued* access to at most four per cycle and gives every access in the
whole execution a distinct, orderable key. M4.2 adds one sender that is not
the cpu table: a `KECCAK` row's 100 accesses (50 reads at slot 0, 50 writes
at slot 1) are sent by the **keccak** chip off its own columns, and land here
like any other — the slot numbering still separates them from the ecall row's
own register reads, which live in `SPACE_REG`.

### Height (M4.2, controller ruling 1)

Through M4.1 this table's height was flatly `2^(ℓ+2)` — four accesses per
cycle times `2^ℓ` cycles. A `KECCAK` row breaks that assumption by two orders
of magnitude, so M4.2's first cut sized the table
`log2_ceil(2^(ℓ+2) + 100·2^(klh−5))`, a function of the tier and the declared
keccak height. That is verifier-computable but wrong in practice: `klh` floors
at 5 (every proof carries one keccak block, real or padding), so the `+100`
term is never zero and *every* proof — a guest that never calls `KECCAK`
included — paid for a doubled memory table (at tier 10, `4 096 + 100 → 2^13`).

The height is a **proof-declared** parameter instead, `Proof::mem_log_height`,
the same treatment `program`, `input` and `keccak` already get. The prover
declares `max(ℓ + 2, log2_ceil(accesses + 1))` — counting every `accesses` and
`keccak_accesses` entry the trace will hold, plus the one padding row the
table's own invariant requires — and `verify` checks only
`ℓ + 2 ≤ mem_log_height ≤ MAX_MEM_LOG_HEIGHT` (24).

**Why that one-sided check is enough.** The table's size is not a resource a
prover can win by misdeclaring. Too large only costs the prover: extra rows
are `is_real = 0` padding, already pinned to send nothing on any bus. Too
small is not an attack but an impossibility: every message the cpu and keccak
tables send on `MEMORY` has to be received by a real row here, so the table
cannot be shorter than the traffic it answers. The `ℓ + 2` floor is kept for
*privacy*, not soundness — without it a proof would advertise its guest's
memory-access count at finer resolution than the tier already publishes; with
it, a tier-10 guest making 12 accesses and one making 4 000 both declare 12.
`MAX_MEM_LOG_HEIGHT` is the usual defensive ceiling on an untrusted shift.
`tests/e2e.rs`'s three height tests pin all of this: the floor for a
keccak-free guest, the floor still winning at three permutations (300
accesses), and the count taking over at forty (4 000).

Constraints: `addr_changed` is `(space,addr)` differing from the next row,
checked with an inverse column; when the address is unchanged, `ts` must
strictly increase (proved via the byte-limbed gap on `RANGE8`) and a read
must return the same value as the previous access; when the address changes,
the new `(space,addr)` must be strictly greater (same gap technique) and a
first read of a fresh address must return 0. Receives `(space, addr, ts,
value, is_write)` on `MEMORY` with count `is_real`. Sends four `RANGE8`
lookups per row (the gap limbs).

## `alu` — main, `col::WIDTH = 64`

Columns: 19 one-hot op flags (`add sub and or xor sll srl sra slt sltu eq`
plus, since M2.6, `mul mulh mulhu mulhsu div divu rem remu`), `a b c`, three
4-limb decompositions `a0..3 b0..3 c0..3`, scratch limbs `q0..3` (shift
quotient / `sll` high word / bitwise `a`'s low nibbles / M2.6 `mul`'s three
cross-term products + carry, as whole field values, not byte limbs / M2.6
`div`'s quotient-magnitude limbs), `s0..3` (compare difference / right-shift
remainder / bitwise `b`'s low nibbles / M2.6 `mul`'s sign-correction borrow
(`s0`) plus its carry's own three byte limbs (`s1..3`) / M2.6 `div`'s
remainder-magnitude limbs), `t0..3` (`pow2 − 1 − remainder` / bitwise `c`'s
low nibbles / M2.6 `mul`'s `LO` byte limbs, populated on *every* mul-family
row regardless of which op is selected — see the per-op reuse table below),
sign bits `sa sb` (M2.6: also used by `mulh`/`mulhsu`/`div`/`rem`), `shh`
(the shift amount's bit 4 / M2.6 `div`'s `R < |B|` diff-byte 0), `pow2 =
2^sh` (M2.6 `div`'s diff-byte 1), four adder carries, an inverse column for
`eq` (M2.6: also `div`'s magnitude-zero-check inverse), `is_real`, `mult`
(how many times the CPU hit this exact tuple), three more isolated-extraction
scratch columns — `ah3` (`a0+3`'s high nibble, `slt`/`sra`/M2.6
`mulh`/`mulhsu`/`div`/`rem`), `bh_n` (`b0+3`'s high nibble on `slt`/M2.6
`mulh`/`div`/`rem` rows for `sb`, or `b0`'s high nibble on shift rows for
`shh` — the roles never collide, since `slt`/shift/`mul`-family/`div`-family
never co-occur), `qh3` (`sll`'s `q0+3`'s high nibble, its overflow check /
M2.6 `div`'s magnitude-zero flag, reusing the same is-zero-gadget pattern as
`eq`'s `inv`) — and, new in M2.6, `divz` (`[b = 0]`, a two-constraint
is-zero gadget on `b`/`invb`), `invb` (`b`'s inverse when `b != 0`), and
`db2`/`db3` (the third and fourth byte of `div`'s `R < |B|` diff, alongside
the reused `shh`/`pw` for the first two).

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

### M2.6 — the RV32M extension

`AluOp` grows from 11 to 19 variants (`Mul Mulh Mulhu Mulhsu Div Divu Rem
Remu`, codes 11–18); every later column index in the table above shifts by
+8 from the M2.3/M2.4 layout. `g_ab`/`g_c` are unchanged — `is_mul`/`is_div`
are not excluded, so `a0..3`/`b0..3`/`c0..3` keep their ordinary `RANGE8`
checks on mul/div rows exactly like `add`/`sub`, since `c` there is a
genuine 32-bit arithmetic result, not a compare bit or a bitwise byte the
nibble table already binds.

**Multiplication** (`mul mulh mulhu mulhsu`). Split `a = al + 2^16·ah`,
`b = bl + 2^16·bh` (16-bit halves, sums of the existing byte limbs). The
schoolbook identity `a·b = t0 + 2^16·t1 + 2^32·t2` (`t0=al·bl, t1=al·bh+
ah·bl, t2=ah·bh`) is exact over the integers, and since `a·b ≤ (2^32-1)² <
p`, it is an exact field equation too. Writing the true 64-bit product as
`lo + 2^32·hi`, algebra gives `lo = t0 + 2^16·t1 - 2^32·carry` and
`hi = t2 + carry` for `carry := hi - t2` (honestly `< 2^17`). `t0,t1,t2` are
*forced* — not free — by the identity, given `al,ah,bl,bh < 2^16`; `carry`
is the one free witness, bounded to `< 2^24` by its own 3-byte `RANGE8`
decomposition (looser than the honest `< 2^17`, but sufficient — see the
uniqueness argument below). The spec's own attack — claim `hi = 2^32-1`
for a small product — is exactly what the 3-limb bound forecloses: a
4-byte value has no valid 3-limb encoding
(`tests/cheating.rs::mulhu_cannot_claim_hi_equals_2_32_minus_1_for_a_small_
product`).

That alone only pins `carry` on rows where the `mul` flag's own `c = lo`
check actually fires — a `mulhu`-only row's `c = hi` check is *additive* in
`carry` (not the `2^32`-amplified map `lo` gets), so a small forged `carry`
gives a small, still-plausible, still-wrong `hi`
(`tests/cheating.rs::a_small_in_range_forged_carry_on_a_mulhu_row_is_still_
rejected` demonstrates exactly this against the naive design). The fix:
`lo`'s own byte limbs (`t0..3`) are `RANGE8`-checked and pinned
*unconditionally* on every mul-family row, not just `mul` rows — every op
inherits the uniqueness argument regardless of which output it selects.
Sign correction for `mulh`/`mulhsu`: `hi_signed = hi - sa·b - [mulh]·sb·a`
(mod `2^32`, `mulhsu` uses only `sa`), with a single boolean `borrow`
column reintroducing `2^32` on underflow — sufficient by a case analysis
over `(sa,sb)` (`src/tables/alu.rs`'s module doc comment has the full
argument). No dedicated `mul`/`div` overflow tracking beyond that: every
term stays inside the field's `< p` bound throughout.

**Division** (`div divu rem remu`). `|a|`, `|b|` are *expressions*
(`a + sa·(2^32-2a)`, similarly for `b`), not separately byte-decomposed —
deliberately: `t0..3` is `mul`'s `lo` limbs and `carry0..3` is the
add/sub/cmp adder's own unconditionally-boolean carries, so neither is free
for this purpose, and neither is needed, since `a`/`b`'s existing `RANGE8`
checks plus `sa`/`sb` being genuine sign bits already bound `|a|`,`|b| <
2^32`. `q` (quotient magnitude) and `r` (remainder magnitude) are their own
`RANGE8`-decomposed limbs, satisfying `|a| = q·|b| + r` and `r < |b|`
(checked via a direct `RANGE8` decomposition of `|b| - r - 1`, not a
per-limb borrow chain — the same "small values can't wrap the field"
argument as everywhere else in this table) whenever `b != 0`.
`divz := [b = 0]` via a two-constraint is-zero gadget on `b`/`invb`
(`b·invb = 1-divz` *and* `divz·b = 0` — the first equation alone is
bypassable with `invb = 0`, which is exactly what
`tests/cheating.rs::a_wrong_divz_on_a_nonzero_divisor_is_rejected` forges).
Final sign fix-up selects `mag` (`q` for div/divu, `r` for rem/remu) and
negates it when the op-appropriate sign flag calls for it, gated by
`1 - qh3` where `qh3 := [mag = 0]` (another is-zero gadget, reusing
`qh3`/`inv`): without that gate the naive `mag + (2^32 - 2·mag)` formula
gives exactly `2^32` (unrepresentable) whenever `mag = 0` and negation is
called for — an ordinary case (`REM(-4, 2) = 0`), not just `i32::MIN / -1`.
That MIN/-1 overflow case needs no dedicated selector at all: `|MIN| =
2^31`, `|-1| = 1`, so the unsigned core already gives `q = 2^31, r = 0`,
and leaving `2^31` unnegated (same-sign quotient) *is* `0x8000_0000` in
32-bit arithmetic — representing `+2^31` is impossible in two's complement,
so "don't negate" and "wrap to MIN" coincide by construction.

Per-op lookup counts (`RANGE8` + `AND4`, counted directly from `fill_row`'s
`RangeCounts`/`NibbleCounts` calls — see `tests/tables.rs::mul_family_
lookup_counts_per_op` and `::div_family_lookup_counts_per_op`, which assert
these totals against the honest witness `fill_row` actually builds):

| Op | Standard `a0..3`/`b0..3`/`c0..3` | Op-specific `RANGE8` | Sign-bit `AND4` | Total/row |
|---|---|---|---|---|
| `mul`/`mulhu` | 12 | 7 (`t0..3` + `carry`'s `s1..3`) | 0 | **19** |
| `mulhsu` | 12 | 7 | 2 (`sa` only) | **21** |
| `mulh` | 12 | 7 | 4 (`sa` and `sb`) | **23** |
| `divu`/`remu` | 12 | 8 (`q0..3`/`s0..3`) + 4 if `b != 0` (`r < \|b\|` diff) | 0 | **24** (**20** if `b = 0`) |
| `div`/`rem` | 12 | 8 + 4 if `b != 0` | 4 (`sa` and `sb`) | **28** (**24** if `b = 0`) |

Well past the M2.4 ≤14-lookups/row target — an explicitly out-of-scope
note for this task, not a miss: M2.6 is not held to the 56-column-width or
14-lookup budgets that scoped M2.3/M2.4, since the RV32M flag growth alone
(11→19 one-hot columns) exceeds them regardless of any lookup accounting.

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

## `poseidon2` — main, `col::WIDTH = 34` + preprocessed, `pre::WIDTH = 13`

M3.1 (approach A from the M3 design spec): a width-8 Goldilocks Poseidon2
permutation, **one row per round**, in fixed 32-row blocks — 30 round rows
(4 initial full rounds, 22 partial rounds, 4 terminal full rounds —
`p3_goldilocks`'s own `GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS`/
`GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8`) plus 2 idle rows. Height is
`tier.poseidon2_height()`, decoupled from `tier.cpu_height()` since M3.3.
M3.3 measured the `transfer` guest at 190 permutations at tier 12 — more
than the `2^t` = 128 slots `poseidon2_height` gave through M3.2, so it
gained a bit of height, to `2^(t+1)`. M3.4 added the program digest's own
`⌈len/4⌉` permutations to every proof (`transfer`'s program is 4 554 words,
1 139 digest-row permutations on top of its 190 execution ones, 1 329
total) and made digest rows count as cycles too, forcing `transfer` to
tier 14 regardless — where even `2^(t+1)` (1 024 slots) falls short of
1 329, so `poseidon2_height` gained one more bit, to `2^(t+2)` (2 048
slots at tier 14; a tier-10 proof now has 128 slots, tier-12 has 512).
See `machine::Tier::poseidon2_height`'s doc comment and
`docs/06-viewing-keys.md`'s cost table for the full numbers.

Preprocessed columns (period 32, `pre::WIDTH = 13`): `rc0..7` (this round's
constants — only lane 0 is nonzero on a partial round), `is_full`,
`is_partial`, `is_first` (row 0 of the block), `is_last` (row 29, the last
round row), `is_idle` (rows 30/31). These are generated once from
`round_constants()`, which reproduces — by redrawing from the same
`machine::PERM_SEED`-seeded RNG, in the exact order `Poseidon2::
new_from_rng_128` draws them — the same round constants `machine::
permutation()` uses for the proof system's own hashing; there are no new
constants for this table (per the M3.1 design ruling).

Main columns (`col::WIDTH = 34`): `is_real`, `mult`, `s0..7` (the state
entering this row), `x3_0..7`/`x7_0..7` (S-box intermediates — see below),
`in0..7` (this block's absorbed input, copied down every row of the block).

**S-box degree split.** The Goldilocks S-box is `x^7`; splitting it
`x3 = (s+rc)^3` then `x7 = x3·x3·(s+rc)` keeps every constraint that uses it
at degree ≤ 3 in the columns, gated to degree 4 by the (degree-1,
preprocessed) row-kind selector. The linear-layer output constraints
(`s_next = mds_light(x7)` on full rounds, `internal_matmul(x7)` on partial
rounds) are degree 1 in the columns, degree 2 gated. Measured (see below):
**4**, the same number the M3.1 design's own degree note predicted.

**Round arithmetic.** `mds_light` (the external/MDS-light linear layer:
`mat4` on each half of the state, then add the cross-half column sums) and
`internal_matmul` (the internal linear layer, `state[i] = sum +
diag[i]·state[i]` for `diag = MATRIX_DIAG_8_GOLDILOCKS`) are generic helpers
over any `PrimeCharacteristicRing`, used both in the AIR (`E = AB::Expr`)
and in a plain-`Goldilocks` scalar replay (`permute_scalar`) that
`tests/tables.rs::poseidon2_scalar_helpers_match_plonky3` checks against
`Poseidon2Goldilocks::<8>::permute` on 10,000 random states — the anchor
that the round-constant reproduction and the linear-layer arithmetic both
match Plonky3 bit-for-bit. The same operation order is proven correct
independently at `rand-zkvm-cuda/src/device/poseidon2.rs`.

**Row semantics.** Row 0 of a block: `in = s` (the raw absorbed input). Full
rounds: the S-box runs on all 8 lanes; row 0 additionally applies the
initial MDS-light layer before its own round constant (Plonky3's
`external_initial_permute_state`, fused into row 0 rather than costing a
separate row). Partial rounds: the S-box runs on lane 0 only (`rc` on lanes
1–7 is pinned to 0 in the preprocessed trace; `x7` on those lanes is `s`
unchanged), matching `p3_poseidon2::internal_permute_state`. Idle rows
constrain nothing beyond `mult = 0`. `in` and `is_real` persist across a
block's rows (a transition constraint keyed off the *next* row's
preprocessed `is_first`, not off `is_real` — see "Padding" below); once
`is_real` drops to 0 across a block boundary it must stay 0, so real blocks
are always a prefix and padding blocks a block-aligned suffix.

**Bus.** On the last round row of a real block (`is_last · is_real`),
provides `[in0..7, next-s0..7]` (`next-s` being the terminal round's output,
read off the following idle row) on `POSEIDON2` with count `mult`; `mult` is
forced to 0 everywhere else (`mult·(1-is_last) = 0` and `mult·(1-is_real) =
0` — both invariants from `AGENTS.md`'s per-table checklist).

**Padding.** `is_full`/`is_partial`/`is_idle` are *preprocessed* selectors
with a fixed period, not gated by `is_real` — so the round-transition
constraints they carry run on literally every block in the trace, real or
not. A block with no real event still needs a genuine, self-consistent
permutation trace (of a canonical all-zero input) to satisfy them; the trace
builder (`poseidon2_trace`) fills every block this way, leaving only
`is_real`/`mult` at zero to mark a block as padding. Before M3.2 wired the
emulator's own hash events in, `build_traces` produced a valid all-padding
poseidon2 trace for every guest (none of them called `POSEIDON2` yet); a
guest that still doesn't call it (every guest but `poseidon2_demo`) gets
exactly that same all-padding trace today.

## `keccak` — main, `col::WIDTH = 2612` + preprocessed, `pre::WIDTH = 99` (M4.2)

Keccak-f[1600] as a hand-written AIR, **one row per round**, in fixed 32-row
blocks (24 round rows + 8 idle rows) — the `poseidon2` chip's shape, with
Plonky3's own `keccak-air` *column layout* (the vendored 0.7 set ships
`p3-keccak`, the scalar permutation, but no `p3-keccak-air`, so the AIR
itself is written here; `docs/04-guests.md` has that correction). Height is
`1 << Proof::keccak_log_height`, proof-declared like `program`'s and
`input`'s: one block per permutation, floored at a single (padding) block so
the table exists in every proof, and ceilinged by the *tier* —
`klh ≤ ℓ + 5`, since a permutation costs a cpu row and therefore a cycle
(`machine::Tier::max_keccak_log_height`). That tier relation is the table's
only upper bound; an earlier flat `MAX_LOG_HEIGHT = 20` was removed because
it disagreed with it in both directions (at tier 10 it would have admitted
32 768 permutation slots for at most 1 023 possible calls).

The design spec estimated ~2,650 main columns; the built table is exactly
**2,612**, pinned by `tests/tables.rs`'s shape test.

**Preprocessed columns** (period 32, `pre::WIDTH = 99`): `IS_ROUND0 + r` (a
24-wide one-hot over the round rows), `IS_FIRST` (row 0), `IS_LAST_ROUND`
(row 23), `IS_IDLE` (rows 24..31), `IS_IDLE0 + i` (an 8-wide one-hot over the
idle rows), and `RC0 + z` (bit `z` of this round's iota constant, zero on
idle rows). `24 + 1 + 1 + 1 + 8 + 64 = 99`. All of it depends only on the
height, which is why it is generated by the height-carrying
`KeccakAir::preprocessed_trace_at` rather than the `BaseAir` trait method
(the same split `poseidon2` makes).

**Main columns** (`col::WIDTH = 2612`): `IS_REAL`, `MULT`, `CLK`, `PTR`; `IN`
(100 16-bit limbs — the permutation's input, copied down every row of the
block); `A` (100 limbs — the state *entering* this round, and on the idle
rows the permutation's output); `C`/`C'` (2 x 5 x 64 bits — the column
parities and `C' = C XOR D`); `A'` (25 x 64 bits, the post-theta state
`A XOR D`); `A''` (100 limbs, post-rho-pi-chi); the 64 bits of `A''[0,0]`;
and the 4 limbs of `A'''[0,0]` (post-iota).
`4 + 100 + 100 + 320 + 320 + 1600 + 100 + 64 + 4 = 2612`. A lane is addressed
`lane(x, y) = x + 5y`, a limb `l` covers bits `16l..16l+15`, and a 32-bit
word `w` is limbs `4*(w/2) + 2*(w%2)` (low) and `+1` (high) — exactly
`keccak::state_to_words`' packing.

**The round arithmetic**, as rules 4–10 (the numbering in `eval`):

4. `C'[x][z] = C[x][z] XOR D[x][z]` with `D[x] = C[x-1] XOR rotl(C[x+1], 1)`
   — a three-way XOR, degree 3.
5. `A` reconstructed limb by limb from bits: `A = A' XOR C XOR C'` (since
   `A' = A XOR D` and `C' = C XOR D`), each limb a sum
   `Σ_{i<16} 2^i · xor3(…)`.
6. `C[x]` is the true column parity of `A[x, ·]` — the degree-3 parity triple
   product.
7. chi over the rho-pi-permuted `A'`: `p XOR (NOT q AND r)`, degree 3,
   producing `A''`.
8. iota on lane (0,0): bind `A''[0,0]`'s bits to its limbs, then XOR the
   preprocessed round constant into them to get `A'''[0,0]`.
9. Round transition: the next row's `A` is this round's output.
10. Idle-row copy: every idle row of the block holds that same output.

Rules 4, 6, 7 and 8 are written **ungated**: on an idle row every bit column
in them is zero and each reads `0 = 0`, so gating them with `is_round` would
only cost a degree. Rule 5 genuinely must be switched off on idle rows (there
`A` holds the output while the bits are zero) and is — but spelled
`is_round · A_limb = Σ …` rather than `is_round · (A_limb − Σ …)`, the same
statement on round rows at degree 3 instead of 4.

**Why there are no `RANGE8` lookups here.** Every limb this table exposes is
derived from `assert_bool`'d bits (rules 5, 7, 8), so a limb is a sum of 16
booleans times powers of two: a genuine 16-bit integer in a field far larger
than `2^16`, with no wraparound available. `IN` inherits it through rules 2
and 1, the idle rows' `A` through rules 9 and 10. So the 32-bit words this
chip puts on `MEMORY` (`lo + 2^16 · hi`) are true 32-bit words without a
single range lookup — the one table in the machine that needs none.

**Row semantics.** Row 0: `IN = A` (rule 2), the raw permutation input.
`IS_REAL`, `CLK`, `PTR` and all 100 `IN` limbs are block-constant (rule 1).
Round row `r` holds the state entering round `r`; the first idle row (24)
holds round 23's output, and rows 25–31 copy it.

**Bus.** On the last round row, provides `[CLK, PTR]` on `KECCAK` with count
`MULT`, and `MULT` is constrained **equal** to `IS_REAL` there — not merely
bounded by it, which is where this AIR is deliberately stricter than
`poseidon2`'s. A real-but-unpaid `poseidon2` block is inert. A real-but-unpaid
keccak block is not: this chip sends its own memory traffic gated on `IS_REAL`
alone, so a prover could flip a padding block to `IS_REAL = 1`, point `PTR` at
live guest RAM and pick any `CLK`, and it would honestly read 50 words and
honestly write their permutation back for a later `lw` to pick up — a
Keccak-f the guest never asked for, with a perfectly consistent memory table.
`MULT = IS_REAL` makes the `KECCAK` bus balance a one-to-one pairing of real
blocks with cpu `SYS_KECCAK` rows (the key carries the cpu's unique `clk`), so
a block no syscall issued cannot exist. `tests/keccak.rs`'s `unpaid` module
has both directions.

The **`MEMORY` schedule** spreads the 100 accesses over the block so no row
carries more than a handful of interactions: 2 reads on each of rows 0..=24
(row `r` takes words `2r`, `2r+1`) at `ts = 4·CLK`, and 7 writes on each idle
row (idle row `i` takes words `7i .. 7i+6`, clipped at word 49) at
`ts = 4·CLK + 1`. The message columns are selector-weighted sums over the rows
that can carry that slot — the selectors are preprocessed one-hots, so at most
one is 1 per row, each slot is a single well-defined access, and on a row that
carries none the count is zero. Counted as the AIR writes them (which is what
the packed-lookup budget sees), that is 9 `MEMORY` interactions on *every* row
plus the single `KECCAK` entry: 10 per row.

**Padding.** The round selectors are preprocessed and periodic, so every block
in the trace — real or not — must carry a genuine, self-consistent permutation
trace to satisfy them. `keccak_trace` fills every padding block with the honest
permutation of the all-zero state and marks it only by `IS_REAL = MULT = 0`
(AGENTS.md invariant 2: with `IS_REAL` zero every bus count on the row is zero
too, so a padding block sends no memory traffic and provides no `KECCAK`
entry). `tests/keccak.rs` checks the filler's arithmetic against `p3_keccak`
on 1,000 random states, and runs the chip alone under the real batch STARK
with throwaway consumers on both of its buses.

**What the padding block costs.** It is not free. Measured at
`FriProfile::Production` on `guests::fib` (`tests/e2e.rs::
measure_production_profile_at_tier_10_and_12`, the same command
`docs/03-privacy.md` records): adding this table took a tier-10 proof from
437 599 to 1 142 262 bytes and a tier-12 proof from 460 242 to 1 161 162 —
about 705 KB either way, for a guest that never calls `KECCAK`. Prove time
barely moves (5.996 s → 6.154 s at tier 10; 23.40 s → 23.91 s at tier 12),
which locates the cost: not in committing a 32-row trace, but in *opening* a
2 612-wide main-trace leaf at each of the profile's 27 FRI queries. The
table's width, not its height, is what a proof pays for — the one M4.2 number
worth carrying into M4.3's own chip design.

## Constraint degree budget

Measured (`p3_batch_stark::symbolic::get_max_constraint_degree`, pinned by
`tests/tables.rs::alu_max_constraint_degree_is_pinned`) against the real,
same-bus-packed lookup contexts (M4.1, `machine::chips()` order): `program`
2, `cpu` 8, `memory` 4, `alu` 8, `range` 2, `nibble` 2, `poseidon2` 4,
`input` 2, `keccak` 3 (M4.2) — `alu`'s comes from the M2.6 `div`
sign-fix identity, `cpu`'s from its packed lookup fraction-pins rather than
its own row logic (whose costliest single constraint is only degree 6),
`poseidon2`'s from its S-box split (see that table's own section). M3.2's
hash-row columns and constraints (below), including the address bound,
`n = 0` escape, "skip the first write-back row" escape, and
canonical-digest-encoding fixes, keep every individual product at or under
what the existing worst case already spent — the biggest single new term
is the write-back "must be followed by `hash_fin = 1`" rule at degree 4
(`is_hash_out·(1-hash_fin)·(1 - n(is_hash_out)·n(hash_fin))`); every other
new term is degree 3 or lower (the `not_final`/`final_absorb` absorb-chain
gates, the write-back `hs` copy-forward pin, the three `n(hash_fin) = 0`/
routing rules, the write-back `hash_left = 0` rule, and the `himax`/`inv`
canonical-encoding equations) — so `cpu`'s measured degree is unchanged at
8, not raised past it.

M3.4's additions land the same way. `program`'s in-circuit decoder is
entirely degree ≤ 2 (a one-hot flag column, degree 1, times a linear
bit-sum or a fixed constant) — the table's own measured max stays 2,
unchanged from the old preprocessed-only padding invariant. `cpu`'s digest
rows reuse hash rows' machinery at the same or lower degree throughout,
with one deliberate exception called out in the column doc comment:
`digest_last` is a **dedicated witness column**, not the degree-2
expression `is_digest·(1 - n(is_digest))` it's defined equal to — every
downstream use (32 `RANGE8` gates, the 8 `pv::HC` pins, the 4 canonical-
encoding lane checks) reads that column directly instead, so none of them
inherits an extra degree from redefining "last digest row" inline
everywhere it's needed. `cpu`'s measured degree stays 8, not raised past it,
by the same margin argument M3.2's additions already relied on.

**M4.1's additions land the same way, measured, not assumed.** The
indigest region mirrors the digest-row prefix's degree profile exactly
(same absorb machinery, same canonical-encoding gadget, one deliberate
degree-4 exception already covered above); the two-bus split
(`INPUT_DIGEST`/`INPUT_READ`, review round 1) and the `is_real_indigest *
(1 - ACT0) = 0` lane rule add nothing past what the existing worst case
already spends. `cpu`'s measured degree stayed at 8 across both the
initial M4.1 build and the review-round fixes (`tests/tables.rs::
alu_max_constraint_degree_is_pinned`, re-run after each). `input`'s own
degree is 2: `IS_REAL` alone (degree 1) provides `INPUT_DIGEST`, and
`IS_REAL * MULT_READ` (degree 2) provides `INPUT_READ` — the same ceiling
the earlier, since-replaced single-bus `IS_REAL * (1 + MULT_READ)` formula
had.

**M4.2's keccak chip measures 3 — including its packed lookups, which is the
number that was actually in doubt.** The AIR's own row logic is 3 by
construction: the three rules that must be cubic (`xor3`, the parity triple
product, chi's `p XOR (NOT q AND r)`) and every other rule written to stay at
or under them — rule 5 deliberately spelled `is_round · A = Σ …` rather than
`is_round · (A − Σ …)` precisely to avoid a fourth degree. The open
engineering risk going into the task was the *lookup* side: this chip writes
10 bus interactions on every row (9 `MEMORY` slots plus the `KECCAK` entry),
all but one of them on the same bus, and `p3-batch-stark` packs same-bus
lookups together up to the largest fraction-pin degree that keeps the quotient
chunk count fixed — so a chip with that many same-bus messages could plausibly
have been pushed past its row logic's own degree by the packing alone. It is
not: the selector-weighted message columns times a degree-2 `IS_REAL · sel_sum`
count keep the packed fractions at 3 as well, and
`tests/tables.rs::alu_max_constraint_degree_is_pinned` pins the measurement
(`degrees[8] == 3`). The named fallback — spreading the sends over more rows
if packing had cost a degree — was not needed.

Because no table here declares periodic columns, every one of these numbers
is invariant to trace height: `get_max_constraint_degree` short-circuits on
`layout.num_periodic_columns == 0` and returns the cached degree multiple.
That is also the argument (M4.2, controller ruling 1) for `mem_log_height`
not being part of the `KeyCache` key — the memory table's packed `Lookups`,
and hence the `CommonData` the key caches, are the same at every declared
memory height.

This config's ceiling is degree 8 (`generic_config`'s `log_blowup = 3` plus this
machine's `is_zk = 1` hiding: `constraint_degree = max_degree + 1 ≤ 9` ⇒
`log2_ceil(8) = 3` quotient chunks, `p3-batch-stark`'s cap), so `alu` and
`cpu` are both already at the edge — any new constraint with a higher degree
needs `log_blowup` raised (and the FRI soundness/cost tradeoff that comes
with it) alongside it.

## Why the program digest is in-circuit, and what that means for `hc`

Through M3.3, `program` was a *preprocessed* trace: Plonky3 commits it once,
independent of any witness, and the verifier holds that commitment
permanently in its `CommonData` — so `hc` was literally that Merkle root,
and `verify` had to take the whole `Program` in the clear to reproduce it
(`docs/03-privacy.md`'s "not a milestone-1 property" framing). M3.4 replaces
that with an **in-circuit digest**: `program` is now a witness trace (the
in-circuit decoder above), and `hc` is a sponge computed row by row over
`cpu`'s digest-row prefix and pinned to public values `pv::HC0..HC7` —
`Machine::verify(hc, proof)` checks those against a caller-supplied `hc` it
never has to derive from a program at all.

This makes the verifier key — `Machine::verifier_key(tier)` — **program-
independent**. The only preprocessed columns left are the range and nibble
tables (fixed, 256 rows each) and the Poseidon2 chip's round-constant table
(a pure function of `PERM_SEED` and the tier's height) — none of which
depend on any specific program, so `CommonData` is now a pure function of
the tier alone. `Machine::verifier_key`'s cache collapses from "one entry
per `(program digest, tier)`" (a 64-entry, FIFO-evicted `KeyCache`) to "one
entry per tier" (`TIERS.len() == 6`, so it never actually evicts anything)
— `tests/e2e.rs::verifier_key_is_cached_after_first_verify` still measures
the cached hit at under 40% of the first, uncached recomputation.

`key_config`'s hiding MMCS salt (and the PCS's random codewords) no longer
need to be seeded from the program either — they are seeded from a fixed
constant (`machine::KEY_SEED`, documented alongside `PERM_SEED`), since the
preprocessed trace they salt no longer varies by program, only by tier.
Every actual `prove_batch` call still runs against `make_config`'s
fresh-entropy config for the main-trace, quotient, and permutation
commitments — that is what keeps zero knowledge intact, and is why two
proofs of the same run are still different bytes (`docs/03-privacy.md`).

`hc` itself: `Program::digest()` (host-side, `isa.rs`) and `hash::
program_digest` compute exactly what the digest rows compute in-circuit —
a Poseidon2 sponge whose capacity lanes are seeded with `[HC_DOMAIN,
base_pc, len]` before any word is absorbed (rather than spending a rate
slot on that header), then `⌈len/4⌉` blocks of up to 4 program words each.
`Program::code_hash()` formats it as hex — the M3.4 replacement for the old
`Machine::code_hash`, which hashed the (now program-independent)
preprocessed commitment and can no longer serve as a program identity at
all.

The privacy question this reopens — the verifier no longer holds the
program, so what does `hc` leak, and is it still just "binding, not
hiding"? — is answered in `docs/03-privacy.md`, not here.
