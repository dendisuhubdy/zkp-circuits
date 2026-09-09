# `circuits/research` — the Rand reference zkVM

Date: 2026-09-09
Status: approved design, pre-implementation
Owner: circuits repo

## 1. Purpose

`circuits/research/` holds the reference zero-knowledge circuit for Rand
Protocol. It is the concrete form of the whitepaper's universal execution
relation R_exec (whitepaper §"Confidential Arbitrary Computation"): one
constraint system, one verifier, every program bound only by its code
commitment. Everything else in the protocol that touches proofs — the node's
`zkp` module, the SVM precompiles, the EVM and Solana guest story — is expected
to converge on what this crate does.

It is not a teaching demo like zkp1–zkp6, though it follows their conventions
(narrated `cargo run --release`, cheating-prover tests, a measured summary
table). It is the thing those demos were leading up to.

## 2. Decisions already fixed

These were settled by the whitepaper or in the design session and are inputs
to this spec, not open questions.

| Decision | Value | Source |
|---|---|---|
| Architecture | One RISC-V zkVM. EVM and sBPF run as interpreter guests inside it. | whitepaper §zkVM comparison (a); approved 2026-09-09 |
| ISA | RV32IM subset, staged (see §4) | this spec |
| Proof system | FRI-STARK, transparent, no pairing wrapper | whitepaper §STARK Proof System |
| Library | Plonky3 0.7 (`p3-batch-stark` + `p3-lookup` + `p3-uni-stark`) | approved 2026-09-09 |
| Base field | Goldilocks, p = 2^64 − 2^32 + 1 | whitepaper |
| Challenge field | degree-2 binomial extension, ≈2^128 | whitepaper |
| Hash (Merkle, transcript) | Poseidon2 over Goldilocks | this spec; whitepaper lists SHA3-384/BLAKE3-384 for the production transcript, Poseidon2 is used here because it is what recursion will need and Plonky3 ships it natively |
| Blowup | 8 (rate 1/8) | whitepaper |
| Zero knowledge | on, from milestone 1 (hiding FRI PCS) | approved 2026-09-09 |
| Trace height | padded to the gas tier, never the actual cycle count | whitepaper Def. gastier; approved for milestone 1 |
| Memory argument | LogUp permutation between a CPU table and a sorted memory table | whitepaper §Composition, Lookups |

## 3. Architecture: a machine of tables on buses

The relation is proved as a *batch* of AIR tables under one commitment and
one FRI opening. Tables exchange facts through named LogUp buses; the batch
verifier checks that every bus balances. This is the SP1 / OpenVM "machine of
chips" shape, and it is what `p3-batch-stark` 0.7 provides directly.

### 3.1 Tables

| Table | Rows | Preprocessed? | Sends | Receives |
|---|---|---|---|---|
| `program` | one per instruction word, pre-decoded | yes (decoded fields) + one main column (`mult`) | `PROGRAM` entries | — |
| `cpu` | one per cycle | no | `MEMORY` accesses, `ALU` ops, `BYTE` checks | `PROGRAM` fetch |
| `memory` | one per access, sorted by (space, addr, clk) | no | `BYTE` checks (ordering) | `MEMORY` accesses |
| `alu` | one per arithmetic/logic/compare/shift op | no | `BYTE` checks (limbs, bitwise) | `ALU` ops |
| `byte` | 2^16 rows: every (a, b) byte pair with a&b, a\|b, a^b; first 32 rows also carry 2^a | yes | `BYTE` and `POW2` entries | — |

### 3.2 Buses

| Bus | Kind | Message | Provider | Consumer |
|---|---|---|---|---|
| `PROGRAM` | lookup (table) | (pc, flags…, rd, rs1, rs2, imm, rd_is_zero) | program | cpu |
| `MEMORY` | permutation (multiset equality) | (space, addr, clk, value, is_write) | cpu | memory |
| `ALU` | lookup | (op, a, b, c) | alu | cpu |
| `BYTE` | lookup | (a, b, a&b, a\|b, a^b) | byte | alu, memory, cpu |
| `POW2` | lookup | (s, 2^s), s < 32 | byte (first 32 rows) | alu |

`space` distinguishes the register file (space 0, addr = register index 0–31)
from RAM (space 1, addr = word address). Registers therefore live in the
memory table, which is how SP1 does it and removes 32 columns from the CPU.

### 3.3 Program commitment

The `program` table's decoded columns are a *preprocessed* trace. Plonky3
commits preprocessed columns once and the verifier holds that commitment in
its `CommonData`. For this crate, **hc is that preprocessed commitment**.
Registering a confidential program on-chain means publishing this 32-byte
value; the constraint system and verifier code are identical for every
program.

Deviation from the whitepaper, stated plainly: the whitepaper wants hc to be
a *public input* to a single verifier key. Here the verifier key is
per-program (it contains hc) while the verifier *code* is universal.
Milestone 3 closes the gap by moving the program into the main trace and
hashing it in-circuit with the Poseidon2 chip, exposing the digest as a
public value.

### 3.4 Public values

Fixed layout, so nothing leaks through length:

```
[ pc_entry, tier_index, out_0, out_1, …, out_7 ]
```

- `pc_entry` — where execution starts.
- `tier_index` — the gas tier ℓ. Public *per proof* because a STARK's size
  reveals its trace height anyway; the whitepaper's claim that only a batch
  histogram is public holds at the aggregation layer (milestone 4+), not per
  transaction. Documented in §7.
- `out_0..out_7` — eight output words written by the `WRITE_OUTPUT` syscall,
  zero if unused. Later milestones append nullifiers, commitments and the
  Merkle root here.

## 4. ISA and guest ABI

### 4.1 Instructions

RV32I integer base plus the M extension, staged:

| Milestone | Instructions |
|---|---|
| M1 | `LUI AUIPC JAL JALR` · `BEQ BNE BLT BGE BLTU BGEU` · `LW SW` · `ADDI SLTI SLTIU XORI ORI ANDI SLLI SRLI SRAI` · `ADD SUB SLL SLT SLTU XOR SRL SRA OR AND` · `ECALL` |
| M2 | `LB LH LBU LHU SB SH` · `MUL MULH MULHU MULHSU DIV DIVU REM REMU` |
| never | `FENCE`, CSR instructions, `EBREAK` (traps) |

Word-aligned loads and stores only in M1. `x0` is hard-wired to zero via the
`rd_is_zero` flag pre-decoded in the program table.

Why RV32 and not RV64: 32-bit words are four 8-bit limbs in Goldilocks and
every 32×32 product fits in the field without overflow (max
(2^32−1)·2^31 < 2^63 < p). RV64 roughly doubles limb columns in `alu` and
`memory`. sBPF's 64-bit registers cost about two RV32 operations each when
interpreted, which is an acceptable tax for a guest.

### 4.2 Syscalls (`ECALL`, number in `a7`, args in `a0`, `a1`; result in `a0`)

| # | Name | Milestone | Effect |
|---|---|---|---|
| 0 | `HALT` | M1 | ends execution; remaining rows are padding |
| 1 | `WRITE_OUTPUT slot word` | M1 | `out[slot] = word`, slot < 8 |
| 2 | `READ_INPUT idx` | M2 | returns private input word `idx` (witness only) |
| 10 | `POSEIDON2 ptr_in ptr_out` | M3 | hashes 8 words at `ptr_in`, writes 4 at `ptr_out` |
| 11 | `NOTE_COMMIT` | M3 | commitment of (value, ρ, pk) |
| 12 | `NULLIFY` | M3 | nf = H(sk ‖ ρ) |
| 13 | `MERKLE_VERIFY` | M3 | membership against public root |

### 4.3 Guest programs

There is no RISC-V cross toolchain on the development machine. The crate
ships:

- `asm.rs` — a small assembler (mnemonic + operands → `u32`), enough to write
  every test and demo guest in Rust source.
- `loader.rs` (M2) — loads a flat binary (`objcopy -O binary`) at `pc_entry`
  for guests built with an external toolchain.

## 5. Trace layouts and constraints

Values are single Goldilocks elements holding a `u32`. Limb decomposition
happens only where a constraint needs it (the ALU and the ordering checks in
memory). A value is guaranteed 32-bit if every path that *writes* it is
range-checked: ALU results (limbs), immediates (preprocessed, trusted), `pc+4`
(bounded by the program table).

### 5.1 `program` (preprocessed + 1 main column)

Preprocessed: `pc`, one boolean flag per mnemonic in §4.1, `rd`, `rs1`,
`rs2`, `imm` (as a `u32` value, sign already applied), `rd_is_zero`.
Main: `mult` — how many times this row was fetched. Provides
`(pc, flags…, rd, rs1, rs2, imm, rd_is_zero)` on `PROGRAM` with count `mult`.

### 5.2 `cpu` (main)

Columns: `clk`, `pc`, `next_pc`, `is_real`, the same flag set as `program`,
`rd`, `rs1`, `rs2`, `imm`, `rd_is_zero`, `a` (rs1 value), `b` (rs2 value),
`c` (value written to rd), `mem_addr`, `mem_val`, `alu_out`, `is_halted`.

Constraints:

- `is_real` boolean; once zero it stays zero; `clk` increments by 1 on real
  rows; first row has `clk = 0` and `pc = pc_entry`.
- Fetch: on real rows, look up `(pc, flags…, rd, rs1, rs2, imm, rd_is_zero)`
  on `PROGRAM` with count 1. Flags are therefore trusted-decoded; the CPU
  does not decode bits.
- Register reads: send `(0, rs1, clk, a, 0)` and `(0, rs2, clk, b, 0)` on
  `MEMORY`. Register write: send `(0, rd, clk, c, 1)` unless `rd_is_zero`,
  in which case `c` is constrained to 0 and the message count is 0.
- Operand select: `b_eff = is_imm ? imm : b` where `is_imm` is the sum of the
  I-type flags.
- ALU ops: when an ALU flag is set, look up `(op_code, a, b_eff, alu_out)` on
  `ALU` and constrain `c = alu_out`. Branches look up the compare op and use
  `alu_out` (0/1) to select `next_pc ∈ {pc+4, pc+imm}`.
- `LUI`: `c = imm`. `AUIPC`: `c = pc + imm` via the ALU add op (keeps the
  range check). `JAL`/`JALR`: `c = pc + 4`, `next_pc = pc + imm` or
  `(a + imm) & ~1` via ALU.
- `LW`: send `(1, (a + imm)/4, clk, mem_val, 0)` on `MEMORY`, `c = mem_val`;
  the address add goes through the ALU. `SW`: same with `is_write = 1` and
  `mem_val = b`.
- `ECALL`: the program table pre-decodes `rs1 = 17 (a7)` and `rs2 = 10 (a0)`
  for every `ECALL`, so the syscall number and first argument arrive through
  the ordinary `a` and `b` reads. The second argument `a1` is read through
  the memory-access slot as `(0, 11, clk, mem_val, 0)`. An `ECALL` row
  therefore makes at most three `MEMORY` reads and one write, keeping the
  four-accesses-per-cycle bound of §7. `HALT` sets `is_halted` and forces
  `is_real = 0` on the next row. `WRITE_OUTPUT` constrains
  `public_values[2 + slot] = word` with `slot = a0`, `word = a1`, via eight
  one-hot selector columns on `slot`.
- Transition: `next.pc = next_pc` on real→real rows.

### 5.3 `memory` (main)

Columns: `space`, `addr`, `clk`, `value`, `is_write`, `is_real`, plus
`addr_changed` (boolean) and four limb columns for the difference
`Δ = next.clk − clk − 1` (or `next.addr − addr − 1` when the address changes).

Constraints, on transitions between real rows:

- `addr_changed = (next.space, next.addr) ≠ (space, addr)`, enforced with an
  inverse column.
- If not `addr_changed`: `next.clk > clk` (Δ limbs looked up on `BYTE`); if
  `next.is_write = 0` then `next.value = value`.
- If `addr_changed`: `(next.space, next.addr) > (space, addr)` (Δ limbs on
  `BYTE`); and `next.is_write = 1 ∨ next.value = 0` — fresh memory reads
  zero.
- First real row: `is_write = 1 ∨ value = 0`.
- Receive `(space, addr, clk, value, is_write)` on `MEMORY` with count
  `is_real`.

Because both sides of `MEMORY` are prover-supplied, the argument is a
multiset equality, not a subset lookup; `PermutationCheckBus` in `p3-lookup`.

### 5.4 `alu` (main)

Columns: op flags (`add sub and or xor sll srl sra slt sltu eq`), `a`, `b`,
`c`, limbs `a0..a3`, `b0..b3`, `c0..c3`, carry/borrow columns, shift
scratch (`pow2`, `hi`, `rem`), `is_real`.

Constraints:

- Limb recomposition: `a = Σ a_i·2^{8i}`, same for `b`, `c`; every limb
  looked up on `BYTE` (with a zero partner, using the `a` column of the pair
  table).
- `add`/`sub`: limb-wise with carries, carries boolean.
- `and`/`or`/`xor`: each limb triple looked up on `BYTE`.
- `slt`/`sltu`: `a − b` mod 2^32 with a final borrow bit; `c` = borrow (for
  `slt`, sign-adjusted using the top-limb sign bits, which are extracted via
  one more `BYTE` lookup of `a3 & 0x80`).
- `eq`: `c = (a − b == 0)` via inverse column.
- `sll`: `c + hi·2^32 = a · pow2` with `pow2 = 2^(b mod 32)`, `hi` and `c`
  range-checked; `(b mod 32, pow2)` is looked up on `POW2`, and `b mod 32`
  is `b0 & 31` via one `BYTE` lookup.
- `srl`: `a = c · pow2 + rem`, `rem < pow2` enforced as
  `rem · 2^(32−s) < 2^32`.
- `sra`: `srl` on the magnitude with sign fill from the top bit.
- Provide `(op, a, b, c)` on `ALU` with count `mult` (a main column; the CPU
  may hit the same tuple more than once).

### 5.5 `byte` (preprocessed)

2^16 preprocessed rows `(a, b, a&b, a|b, a^b, pow2, is_pow2_row)`, where
`pow2 = 2^a` and `is_pow2_row = 1` on the first 32 rows (those with `b = 0`
and `a < 32`) and both are 0 elsewhere. Provides `(a, b, a&b, a|b, a^b)` on
`BYTE` with count `mult_byte` and `(a, pow2)` on `POW2` with count
`mult_pow2 · is_pow2_row` (both `mult_*` are main columns).

## 6. Witness generation

```
guest source ──asm──▶ u32 words ──▶ Program (decoded rows, preprocessed)
                                      │
Emulator::run(program, tier) ─────────┘ ──▶ Vec<CycleEvent>
                                              │
   cpu::trace   memory::trace   alu::trace ◀──┘   (each pads to its tier height)
                                              │
   StarkInstance × 5 ──▶ prove_batch ──▶ BatchProof
   verify_batch(airs, proof, public_values, common)
```

- `emulator.rs` executes natively and records, per cycle, the decoded
  instruction, register reads/writes, memory access, ALU op, and syscall.
  It is also the reference semantics for tests.
- Each table's `trace(&[CycleEvent], tier) -> RowMajorMatrix` is independent
  and unit-testable.
- `machine.rs` owns the Plonky3 config (Goldilocks, degree-2 extension,
  Poseidon2 sponge/compress, `MerkleTreeHidingMmcs`, `HidingFriPcs`, blowup 8,
  query count from `FriParameters`), builds `ProverData` once per program,
  and exposes `prove(program, tier) -> Proof` and `verify(hc, proof, pv)`.

## 7. Privacy

- **Zero knowledge.** `HidingFriPcs` randomises the trace low-degree
  extension and the FRI batch polynomial. Plonky3 documents this as
  *statistically* zero-knowledge (its own TODO in `p3-uni-stark/prover.rs`);
  the crate says so too and measures the overhead in the demo table.
- **Tier padding.** Tiers are `G = {2^10, 2^12, 2^14, 2^16, 2^18, 2^20}`
  cycles. The prover picks the smallest tier ≥ actual cycles; `cpu` and `alu`
  pad to `G_ℓ` rows, `memory` to `4·G_ℓ` (four accesses per cycle upper
  bound), `program` and `byte` to their fixed sizes. Padding rows are
  `is_real = 0` and emit nothing on any bus.
- **What leaks.** The proof reveals the tier (height), `pc_entry`, and the
  eight output words. It does not reveal the exact cycle count, any
  register or memory value, any branch taken, or which syscalls ran beyond
  what the outputs imply. The whitepaper's per-batch histogram is a property
  of the aggregation layer, not of one proof; this crate documents that in
  `docs/03-privacy.md`.
- **Delegated proving.** Out of scope for the circuit; the witness is a
  `Vec<CycleEvent>` and whoever holds it sees everything, as the whitepaper's
  Remark on the delegation boundary says.

## 8. The three targets

Only RISC-V executes natively. The other two are software running under the
same relation. Milestone 1 *documents* both in `docs/04-guests.md` with an
opcode-to-cost table; milestone 4 builds them.

| Target | Path into R_exec | Coprocessor tables it will want |
|---|---|---|
| Solidity | `solc` → EVM bytecode → a `no_std` EVM interpreter compiled to RV32IM, bytecode as private input | Keccak-256 (`p3-keccak-air` exists), 256-bit add/mul/mod, ecrecover (secp256k1) |
| Solana / SVM | sBPF ELF → an sBPF interpreter compiled to RV32IM | SHA-256, Ed25519 verify, 64-bit mul; sBPF is itself an 11-register load/store ISA, so a direct sBPF→RV32 translator is the natural later optimisation |
| RISC-V | native | none |

The interpreter approach is what the whitepaper chose: publishing a contract
is registering a hash, never generating a circuit.

## 9. Testing

- **Constraint tests** per table: build a trace from a known event list and
  run `p3-batch-stark`'s debug `check_constraints`; then mutate one cell and
  assert it fails.
- **End-to-end**: guests `fib` (loop, ALU, branches), `memcpy` (LW/SW
  consistency), `bubble_sort` (all of the above with data-dependent
  control flow); each proves and verifies at its natural tier.
- **Cheating prover**: (a) tamper one cpu cell after tracing → verify fails;
  (b) prove program A, verify against program B's `CommonData` → fails;
  (c) claim a wrong output word → fails; (d) claim a smaller tier than the
  run needs → the trace builder refuses, and a hand-built oversized trace
  fails to verify.
- **Zero knowledge**: two proofs of the same run are different bytes and
  both verify; the same guest at two tiers yields proofs whose only
  observable difference is height.
- **Emulator vs. spec**: instruction-level tests for every mnemonic against
  hand-computed results, including sign edge cases for `SRA`, `SLT`, `BGE`.
- **Demo**: `cargo run --release` narrates one guest end-to-end and prints
  the zkp2/zkp3-style table (constraints per table, rows, prove ms, verify
  ms, proof bytes, ZK on/off overhead).

## 10. Milestones

| # | Scope | Exit criterion |
|---|---|---|
| M1 | Tables §5, ISA row M1, syscalls 0–1, ZK on, tier padding, assembler, emulator, tests §9, guidance README + `docs/01–05` | `fib`, `memcpy`, `bubble_sort` prove and verify with ZK at their tiers; all cheating tests reject |
| M2 | Sub-word loads/stores, M extension, flat-binary loader, `READ_INPUT` | a guest compiled with an external RISC-V toolchain runs and proves |
| M3 | Poseidon2 chip, syscalls 10–13, program digest in-circuit as a public value | the zkp6/zkp4 transfer relation re-expressed as a guest proves under R_exec |
| M4 | EVM and sBPF guest interpreters, Keccak/SHA coprocessors | an ERC-20 `transfer` and an SPL `Transfer` each prove under R_exec |

## 11. Crate layout

```
circuits/research/
  Cargo.toml                 crate `rand_zkvm`; bin `demo`
  README.md                  the guidance document (why, what, how to read)
  docs/
    01-isa.md                instruction table, encoding, syscall ABI
    02-tables-and-buses.md   §3 and §5 with column diagrams
    03-privacy.md            §7, what leaks, tiers, ZK caveat
    04-guests.md             §8, Solidity and Solana paths, coprocessor map
    05-roadmap.md            §10 and the whitepaper deviations
  src/
    lib.rs
    isa.rs                   Instr enum, encode/decode, flag ordering
    asm.rs                   mini assembler
    emulator.rs              executor + CycleEvent recorder
    tables/
      mod.rs                 shared column helpers, bus names
      program.rs             AIR + trace
      cpu.rs
      memory.rs
      alu.rs
      byte.rs
    machine.rs               Plonky3 config, tiers, prove/verify
    main.rs                  narrated demo
  tests/
    e2e.rs  cheating.rs  zk.rs  emulator.rs
```

Naming: the folder is `research` as requested; the crate is `rand_zkvm` so
that the name survives when it moves out of research.

## 12. Known deviations and open items

1. hc is a verifier-side commitment in M1, a public value from M3 (§3.3).
2. Tier index is public per proof (§3.4, §7).
3. Zero knowledge is statistical in Plonky3 0.7 (§7).
4. Transcript hash is Poseidon2, not SHA3-384/BLAKE3-384 (§2). Changing it
   is a config swap; the whitepaper's crypto-agility registry covers it.
5. Recursion and per-batch aggregation are outside this crate until M4+.
