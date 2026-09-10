# The ISA

`rand_zkvm` executes a staged subset of RV32I/M. `src/isa.rs` defines the
`Instr` enum, its encoder/decoder, and the `Decoded` selector set the program
table commits. This document lists what runs today, how it is encoded, the
selector fields the CPU trusts, and the syscall ABI.

## Instructions, by milestone

| Milestone | Instructions |
|---|---|
| M1+M2 (implemented) | `LUI AUIPC JAL JALR` · `BEQ BNE BLT BGE BLTU BGEU` · `LW SW` · `LB LH LBU LHU SB SH` · `ADDI SLTI SLTIU XORI ORI ANDI SLLI SRLI SRAI` · `ADD SUB SLL SLT SLTU XOR SRL SRA OR AND` · `MUL MULH MULHU MULHSU DIV DIVU REM REMU` (M2.6) · `ECALL` |
| never | `FENCE`, CSR instructions, `EBREAK` (traps) |

Memory stays word-addressed (M2.5): `Instr::Load { rd, rs1, imm, width, signed }` and
`Instr::Store { rs1, rs2, imm, width }` carry a `Width ∈ {Byte, Half, Word}` that selects
how many bytes of the addressed word a load/store touches, and — for loads — whether the
result is sign- or zero-extended. `LW`/`SW` compute the byte address through the ALU;
`off = alu_out & 3` is the byte offset within its word. Alignment is a *constraint*, not
only an emulator error: the underlying identity `mem_addr·4 + off = alu_out` alone would be
satisfiable over the field by `mem_addr = (alu_out − off)·4⁻¹ mod p` for any `off` a
cheating witness likes, so the CPU table also decomposes `mem_addr` into four
range-checked byte limbs and bounds it below 2^30 with a nibble extraction against the top
limb (`AND4` lookups, since M2.3). With `alu_out` already 32-bit and `off` a sum of two
booleans (hence `< 4`), `mem_addr·4 + off < 2^32` cannot wrap, so the identity holds over
the integers, not just mod `p`. On top of that, width imposes its own alignment: a full
word must sit on a word boundary (`off = 0`), a halfword on a 2-byte boundary (`off ∈ {0,
2}`), and a byte is never misaligned — `IS_LW*(OFF0+OFF1) = 0` and `IS_LH*OFF0 = 0` (and the
`SW`/`SH` equivalents) state this directly in the AIR, not just in the emulator. The
emulator (`emulator.rs`) returns `ExecError::Misaligned` for the same cases, carrying the
byte address (`alu_out`) that failed. A store is a read-modify-write of the addressed word:
the emulator reads the pre-store word, merges in the stored bytes at `off`, and writes the
merged word back; `LB`/`LBU`/`LH`/`LHU` extract the selected byte/half and, for the signed
forms, sign-extend it. Data memory (the RAM half of the `memory` table) starts entirely
zeroed — a guest that
wants an initialised array has to write it itself before reading it. `x0` is
hard-wired to zero: the program table's `writes_rd` selector is already
`(rd ≠ 0)`, so a write to `x0` is never sent on the register-write side of
the `MEMORY` bus, and the emulator forces `regs[0] = 0` after every cycle to
match.

`JALR` does not clear bit 0 of its target the way the RISC-V spec's C-extension
convention expects. `next_pc = a + imm` is used exactly as computed; if that
value is odd, the next fetch looks up an odd `pc` in the `program` table, the
`PROGRAM` lookup fails, and the run simply cannot be proved. There is no
implicit alignment fixup.

## Encoding

Encoding follows the standard RV32I bit layout (`isa.rs::Instr::encode` /
`::decode`): R-type for register-register ALU ops, I-type for immediates,
loads, and `JALR`, S-type for stores, B-type for branches, U-type for `LUI`/
`AUIPC`, J-type for `JAL`. `AluOp::Eq` is a table-only opcode: the ALU trace
and bus can express it (`BEQ`/`BNE` compile to it), but no RISC-V instruction
encodes it directly, and `alu_funct` panics if asked to. Branch conditions
map onto two ALU comparisons plus a `br_neg` flag: `BLT`/`BGE` and
`BLTU`/`BGEU` share `Slt`/`Sltu`, `BEQ`/`BNE` share `Eq`, and `br_neg` flips
the result for `BNE`/`BGE`/`BGEU`.

**M2.6 — the RV32M extension.** `MUL MULH MULHU MULHSU DIV DIVU REM REMU`
decode from the R-type `OP_ALU` opcode (`0x33`) with `funct7 = 1` exclusively
— standard RV32M `funct3` order (`MUL=0 MULH=1 MULHSU=2 MULHU=3 DIV=4
DIVU=5 REM=6 REMU=7`). There is no RV32M immediate form: `OP_ALUI`'s decode
path never even inspects `funct7` for non-shift ops (those bits are part of
the 12-bit immediate), and for the shift-immediate family it only accepts
`funct7 in {0, 0x20}` — `funct7 = 1` is simply not a producible `AluImm`
encoding, checked directly by
`tests/isa.rs::m_extension_is_register_register_only_alu_imm_rejects_reserved_shift_funct7`.
Emulator semantics (`AluOp::eval`) follow the RISC-V spec's defined
edge cases exactly: `DIV` by a zero divisor returns `0xffff_ffff`, `DIVU` by
zero likewise; `REM`/`REMU` by zero return the original dividend unchanged;
signed overflow (`i32::MIN / -1`) returns quotient `i32::MIN`, remainder
`0`. See `docs/02-tables-and-buses.md`'s `alu` section and `src/tables/
alu.rs`'s module doc comment for how the ALU table proves this — an exact
integer identity over 16-bit halves for multiplication, and an
unsigned-magnitude quotient/remainder identity with a final sign fix-up for
division, including the soundness argument for the spec's own `HI =
2^32-1` product-attack rejection.

## Why RV32, not RV64

A 32-bit word is exactly four 8-bit limbs in Goldilocks, and every 32×32
product fits without overflow: `(2^32 − 1)·2^31 < 2^63 < p` where
`p = 2^64 − 2^32 + 1`. RV64 would roughly double the limb columns in `alu`
and `memory`. sBPF (the Solana target) is natively 64-bit; interpreting it
here costs about two RV32 operations per sBPF instruction — an acceptable
tax for a guest, not a reason to widen the machine.

## The `Decoded` selector set

The program table is preprocessed: it holds every instruction word's decode
already worked out, and the CPU table only ever reads these fields off the
`PROGRAM` bus — it never inspects opcode bits itself. `Decoded::to_fields`
fixes the order (`isa.rs`), 23 fields in total (M2.5 replaced the single
`is_load`/`is_store` booleans with a one-hot per load/store mnemonic, plus a
`signed` flag):

| Field | Meaning |
|---|---|
| `rd` | destination register index |
| `rs1` | first source register index |
| `rs2` | second source register index |
| `imm` | immediate, already sign-extended to a `u32` |
| `is_alu` | set for `AluImm`/`AluReg` |
| `alu_op` | the `AluOp` code the ALU bus should use |
| `is_imm` | set whenever the second operand is `imm`, not `rs2`'s value (`AluImm`, `Load`, `Store`, `Jalr`) |
| `is_branch` | set for all six branch mnemonics |
| `br_op` | the ALU comparison (`Slt`, `Sltu`, or `Eq`) the branch reduces to |
| `br_neg` | flips the comparison result for `BNE`/`BGE`/`BGEU` |
| `is_lb`, `is_lh`, `is_lw` | one-hot: which load width (`is_load = is_lb+is_lh+is_lw`) |
| `is_sb`, `is_sh`, `is_sw` | one-hot: which store width (`is_store = is_sb+is_sh+is_sw`) |
| `signed` | set for `LB`/`LH` (the sign-extending loads); meaningless elsewhere |
| `is_jal` | set for `JAL` |
| `is_jalr` | set for `JALR` |
| `is_lui` | set for `LUI` |
| `is_auipc` | set for `AUIPC` |
| `is_ecall` | set for `ECALL` |
| `writes_rd` | `1` iff this instruction writes a register and that register is not `x0` |

This is a deliberate refinement beyond the design spec's original wording:
rather than one boolean flag per mnemonic, the table pre-decodes these 23
semantic fields once. The trust model is identical (the CPU still never
decodes a bit; every selector arrives already proved correct by the `PROGRAM`
lookup), but there are fewer columns than one-per-mnemonic and the CPU's
constraints read as "if `is_lb+is_lh+is_lw` then …" instead of long sums over
every individual instruction's own flag. `is_load`/`is_store` are themselves
now *expressions* the CPU AIR computes from the one-hot fields, not columns.

## Syscall ABI

`ECALL` reads its syscall number from `a7` (register 17) and its first
argument from `a0` (register 10) — the program table pre-decodes every
`ECALL` row with `rs1 = 17, rs2 = 10, rd = 10`, so those two values arrive
through the ordinary register-read slots. A second argument, when a syscall
needs one, is read through the row's memory-access slot as register `a1`
(register 11); the result of a value-returning syscall is written back to
`a0`.

| # | Name | Milestone | Effect |
|---|---|---|---|
| 0 | `HALT` | M1 | ends execution; every remaining row in the table is padding |
| 1 | `WRITE_OUTPUT slot word` | M1 | `out[slot] = word`, `slot < 8`; constrained directly against the public values, at most once per slot, and any slot never written is pinned to zero |
| 2 | `READ_INPUT idx` | M1 | returns private input word `idx` in `a0` — a prover-chosen witness value, and two reads of the same `idx` are not constrained to agree; see `docs/03-privacy.md` |
| 3 | `POSEIDON2 ptr n` | M3.2 | hashes the `n` words at word address `ptr` (`0 <= n <= POSEIDON2_MAX_WORDS = 4096`) with the Poseidon2 sponge (rate 4, overwrite mode, no padding — `hash::sponge_hash`, the exact `PaddingFreeSponge<_, 8, 4, 4>` semantics) and overwrites `ptr..ptr+8` with the 8-word (lo/hi) digest in place |

`NOTE_COMMIT`, `NULLIFY` and `MERKLE_VERIFY` (M3.3) are **not** separate
syscalls: they are guest-level library routines built entirely on
`POSEIDON2` (`asm::emit_note_commit`/`emit_nullify`/`emit_merkle_verify`),
staging a domain-tagged message into RAM and calling `POSEIDON2` over it —
`NOTE_COMMIT`/`NULLIFY` once, `MERKLE_VERIFY` once per tree level (32 calls
for this crate's depth). No new syscall numbers were needed; see
`docs/06-viewing-keys.md`.

`POSEIDON2` does not follow the "second argument through the memory slot,
result in `a0`" shape the syscall preamble above describes for a
*single*-row syscall: it spans several cpu rows (the ecall row, one absorb
row per 4-word block, and two digest write-back rows — `docs/02-tables-and-
buses.md`'s `cpu` section has the full row-kind account), and its "return
value" is written to RAM in place at `ptr` rather than into `a0`. `a0`
(`ptr`) and `a1` (`n`, read through the memory slot exactly like any other
ecall's second argument) are still read the ordinary way, on the ecall row
only.

There is no RISC-V cross toolchain on the development machine, so every guest
here is written directly against `asm.rs`'s mnemonic helpers (`src/asm.rs::ops`)
rather than compiled from C or Rust `no_std`. A later milestone's `loader.rs`
will load a flat binary (`objcopy -O binary`) built externally at `pc_entry`
instead.
