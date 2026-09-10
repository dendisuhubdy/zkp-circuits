# The ISA

`rand_zkvm` executes a staged subset of RV32I/M. `src/isa.rs` defines the
`Instr` enum, its encoder/decoder, and the `Decoded` selector set the program
table commits. This document lists what runs today, how it is encoded, the
selector fields the CPU trusts, and the syscall ABI.

## Instructions, by milestone

| Milestone | Instructions |
|---|---|
| M1 (implemented) | `LUI AUIPC JAL JALR` · `BEQ BNE BLT BGE BLTU BGEU` · `LW SW` · `ADDI SLTI SLTIU XORI ORI ANDI SLLI SRLI SRAI` · `ADD SUB SLL SLT SLTU XOR SRL SRA OR AND` · `ECALL` |
| M2 (not yet implemented) | `LB LH LBU LHU SB SH` · `MUL MULH MULHU MULHSU DIV DIVU REM REMU` |
| never | `FENCE`, CSR instructions, `EBREAK` (traps) |

Only word-aligned loads and stores exist today. `LW`/`SW` compute the byte
address through the ALU and then divide by 4 in the CPU's memory constraint.
Alignment is a *constraint*, not only an emulator error: `mem_addr·4 = alu_out`
alone would be satisfied over the field by `mem_addr = alu_out·4⁻¹ mod p`, so
the CPU table also decomposes `mem_addr` into four range-checked byte limbs and
bounds it below 2^30 with a nibble extraction against the top limb (`AND4`
lookups, since M2.3). With `alu_out` already 32-bit, `mem_addr·4 < 2^32`
cannot wrap, the identity holds over the integers, and a misaligned address
is unprovable. The emulator (`emulator.rs`)
returns `ExecError::Misaligned` for any address that is not a multiple of 4,
so the two agree; there is no sub-word path yet. Data memory (the RAM half of
the `memory` table) starts entirely zeroed — a guest that
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
fixes the order (`isa.rs`), 18 fields in total:

| Field | Meaning |
|---|---|
| `rd` | destination register index |
| `rs1` | first source register index |
| `rs2` | second source register index |
| `imm` | immediate, already sign-extended to a `u32` |
| `is_alu` | set for `AluImm`/`AluReg` |
| `alu_op` | the `AluOp` code the ALU bus should use |
| `is_imm` | set whenever the second operand is `imm`, not `rs2`'s value (`AluImm`, `Lw`, `Sw`, `Jalr`) |
| `is_branch` | set for all six branch mnemonics |
| `br_op` | the ALU comparison (`Slt`, `Sltu`, or `Eq`) the branch reduces to |
| `br_neg` | flips the comparison result for `BNE`/`BGE`/`BGEU` |
| `is_load` | set for `LW` |
| `is_store` | set for `SW` |
| `is_jal` | set for `JAL` |
| `is_jalr` | set for `JALR` |
| `is_lui` | set for `LUI` |
| `is_auipc` | set for `AUIPC` |
| `is_ecall` | set for `ECALL` |
| `writes_rd` | `1` iff this instruction writes a register and that register is not `x0` |

This is a deliberate refinement beyond the design spec's original wording:
rather than one boolean flag per mnemonic, the table pre-decodes these 18
semantic fields once. The trust model is identical (the CPU still never
decodes a bit; every selector arrives already proved correct by the `PROGRAM`
lookup), but there are fewer columns and the CPU's constraints read as "if
`is_load` then …" instead of long sums over one-hot mnemonic flags.

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
| 10 | `POSEIDON2 ptr_in ptr_out` | M3 (not implemented) | hashes 8 words at `ptr_in`, writes 4 at `ptr_out` |
| 11 | `NOTE_COMMIT` | M3 (not implemented) | commitment of `(value, ρ, pk)` |
| 12 | `NULLIFY` | M3 (not implemented) | `nf = H(nk ‖ cm)` — bound to the commitment, not to a sender-chosen nonce |
| 13 | `MERKLE_VERIFY` | M3 (not implemented) | membership against a public root |

There is no RISC-V cross toolchain on the development machine, so every guest
here is written directly against `asm.rs`'s mnemonic helpers (`src/asm.rs::ops`)
rather than compiled from C or Rust `no_std`. A later milestone's `loader.rs`
will load a flat binary (`objcopy -O binary`) built externally at `pc_entry`
instead.
