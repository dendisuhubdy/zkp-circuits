# Rand zkVM milestone 5 — the recursion VM (rVM)

Status: **design approved in conversation 2026-09-13, spec for user review, not built.**
Decided by the user on 2026-09-13 after the feasibility spike in `spike-recursive-verifier`:
block-level proof aggregation needs a recursion coprocessor, and the coprocessor is a second
machine with a native Goldilocks instruction set ("recursion VM"), not a hardwired verifier AIR.

Related: `fullnode/docs/aggregation.md` (the chain-side design this serves), `docs/superpowers/specs/2026-09-11-zkvm-m4-design.md`
(the RV32 machine as it stands after M4.4), `research/docs/02-tables-and-buses.md`,
`research/docs/03-privacy.md`.

## 1. Why a second machine

The fullnode's block cap admits about three shielded transfers per block because each carries a
~1.3 MB 80-query STARK proof. The chain-side remedy (`aggregation.md`) is one recursive proof per
sealing block that verifies N bundle proofs. That needs a proof system that can verify its own kind
of proof cheaply enough to prove.

The spike measured what it costs to run the existing verifier (`rand_zkvm::machine::verify`,
Plonky3 0.7 batch STARK, Goldilocks, Poseidon2) as an RV32IM guest of the current machine, on one
real production-profile bundle proof (tier 14, 8 table instances, 80 queries, blowup 8, 20 PoW
bits; proof 330 620 words):

| phase | cycles | share |
|---|---|---|
| software Poseidon2 (43 562 permutations: 31 314 leaf sponge, 11 262 path compression, 986 challenger) | 1 194 479 867 | 88.9 % |
| FRI / Merkle reduction loops (extension arithmetic in software) | 88 468 511 | 6.6 % |
| proof deserialisation and input reading | 21 400 000 | 1.6 % |
| out-of-domain constraint evaluation, eight tables (extrapolated) | ~139 000 | 0.01 % |
| **total** | **1 343 834 826** | 1 281 × tier 20 |

With every syscall the RV32 machine could gain (field-lane Poseidon2, extension-field ALU, a
public memory-mapped input) the estimate is ~30 M cycles per inner proof: tier 25 for one, tier 28
for eight. The machine's maximum tier is 20 and a tier-25 prover needs terabytes. **A verifier as
an RV32 guest cannot work.** Two facts from the spike also bind this design: the RV32 machine's
`POSEIDON2` syscall absorbs u32 words and cannot hash a Goldilocks digest, and there is no
Merkle-verify syscall.

What does work is what SP1 and RISC Zero do: a second, small machine whose native word is the
field element, whose instructions are exactly the verifier's operations, proven with the same STARK
stack. In that machine the 1.34 G cycles above become a few hundred thousand rows.

## 2. Architecture

A new crate `recursion/` in this repo (own workspace member, `std` on the host; nothing runs on a
RISC-V target). It contains:

- `isa.rs` — the instruction set (§3), the encoded program form, the program digest.
- `emulator.rs` — executes a program over Goldilocks with a private witness tape, records the
  trace events the tables need, counts cycles and permutations.
- `dsl/` — the builder that programs are written against (§4).
- `programs/` — the verifier program for RV32-machine proofs (§4.2) and, in M5.4, the verifier
  program for rVM proofs.
- `tables/` — the five AIRs (§5); `machine.rs` — batch prover/verifier, tiers, verifier-key cache,
  mirroring `research/src/machine.rs`.
- `aggregate.rs` — the chain-facing API (§6).

The rVM reuses from `research/`: the Goldilocks field and its degree-2 extension
(`BinomialExtensionField<Goldilocks, 2>`), the Poseidon2 parameters and reference permutation, the
FRI profile (`log_blowup 3`, 80 queries, 20 PoW bits at production), the batch-STARK configuration,
and the lookup-bus machinery (`p3-lookup`). It does not touch the RV32 machine's tables.

**Field-native state.** Registers and memory cells hold one Goldilocks element each. An extension
element occupies two consecutive registers or cells (`(c0, c1)` with `c0 + c1·X`). There are no
bytes, no u32 range checks, no signedness. Memory is a flat array of cells indexed by a field
element interpreted as an address below `2^24`.

**Witness, not input.** A program reads its private witness with `HINT` in the order it consumes
it. The rVM has **no salted input commitment**: nothing about its witness needs hiding (the inner
proofs are public objects), and the program's public values are its entire interface. This is what
lets the aggregate proof be small and its admission cheap. The RV32 machine's public-input segment
(M4.4 spec §5.1 item 8) is a separate constraint-set item and is not part of M5.

**Program binding.** A program is a list of encoded instructions; its digest is the Poseidon2 hash
of the words, committed in the `program` table exactly as the RV32 machine's `hc` binds a guest.
The verifier key of an rVM proof therefore binds the verifier program; the fullnode registers the
digest of the aggregate program the way it registers a guest's `hc`.

## 3. Instruction set

Every instruction is one cpu row. Operands are register indices (`r0..r31`; `r0` is the constant
zero) or an immediate field element. `E` denotes an extension operand: the pair `(r, r+1)`.

| mnemonic | operands | effect |
|---|---|---|
| `FADD FSUB FMUL` | `rd, ra, rb` | base-field arithmetic |
| `FADDI FMULI` | `rd, ra, imm` | base-field arithmetic with an immediate |
| `EADD ESUB EMUL` | `Ed, Ea, Eb` | extension-field arithmetic (two rows' worth of work in one row: 2 adds, or 3 muls + 2 adds) |
| `EMULF` | `Ed, Ea, rb` | extension × base |
| `INV` | `rd, ra` | `rd = ra⁻¹` supplied by the prover as a hint; the row constrains `ra·rd = 1` (and `ra ≠ 0`) |
| `EINV` | `Ed, Ea` | extension inverse, same hint-and-check shape |
| `MOV` | `rd, ra` | copy |
| `LOAD STORE` | `rd/rs, ra, imm` | memory cell at `ra + imm` |
| `LOADE STOREE` | `Ed/Es, ra, imm` | two consecutive cells |
| `JMP` | `imm` | `pc = imm` |
| `JEQ JNE` | `ra, rb, imm` | branch on base-field equality |
| `HINT` | `rd` | `rd = next witness word` |
| `HINTE` | `Ed` | two witness words |
| `PUBLIC` | `ra` | append `ra` to the public values |
| `POSEIDON2` | `ra` | permute the eight cells at `ra..ra+8` in place (one row; the work is in the `poseidon2` chip) |
| `HALT` | — | end |

Twenty-four instructions. Deliberately absent: `FRIFOLD`, `EXPBITS`, `MERKLE` precompiles.
The verifier's FRI fold step and Merkle path step are compiled sequences of the above. M5.1 counts
what they cost; a precompile is added only if the measured count puts an 8-proof aggregate above
tier 21 (§7).

**Encoding.** One instruction = 4 field elements `[opcode | rd | ra | rb-or-imm]`; the program
table commits the four columns per row. Addresses and immediates are field elements; the cpu AIR
constrains `pc` and memory addresses below `2^24` with a 3-limb 8-bit decomposition against the
existing `RANGE8` lookup (the only range check in the machine).

## 4. Programs

### 4.1 The DSL

`recursion/src/dsl` is a Rust builder with typed handles `Felt`, `Ext`, `Digest` (`[Felt; 8]`),
`Ptr`, and `Array<T>`, and methods that emit instructions while allocating registers and memory
(a simple linear allocator with spills to memory; programs are straight-line except for loops over
queries and Merkle levels, which the builder unrolls or emits as counted loops). A program is built
once on the host, its instruction list encoded and digested, and the digest committed to the repo
beside the program source as `programs/<name>.digest`, with a test that rebuilding reproduces it.

### 4.2 The verifier program for RV32-machine proofs

Written against the DSL by porting `rand_zkvm::machine::verify` and the Plonky3 verifiers it calls
(`p3-batch-stark::verify`, `p3-fri::verifier`, the MMCS `verify_batch`, the `DuplexChallenger`)
step for step, in the same order the native code runs:

1. absorb the verifier key digest, the instance heights and the public values into the challenger;
2. read the trace commitments (`HINT`), absorb, draw the lookup challenges;
3. read the permutation and quotient commitments, absorb, draw `alpha`, `zeta`;
4. read the opened values at `zeta` and `zeta·g` for every table (`HINT`), absorb;
5. evaluate every table's constraints at `zeta` (§4.3) and check the quotient identity;
6. draw the FRI betas, read the fold commitments, then for each of the 80 queries: draw the index,
   read the openings and Merkle paths (`HINT`), verify each path (`POSEIDON2` per level), and fold
   through the rounds with `EMUL`/`EADD`, checking the final polynomial;
7. check the proof-of-work witness against the PoW bits;
8. `PUBLIC` the inner verifier key digest and the inner public values.

Every step has a differential test (§8): the DSL program and the native verifier, run on the same
proof, must produce identical challenges, identical fold values and identical acceptance, and must
refuse a tampered proof at the same step.

### 4.3 Generated constraint evaluation

Each RV32 table's AIR is walked once, at build time, with Plonky3's symbolic builder
(`SymbolicAirBuilder`) to obtain its constraint expression DAG; the DSL emits the DAG as
`FADD`/`FMUL`/`EMUL` instructions over the opened values, folding by `alpha`. The spike measured
about 2 800 nodes for the cpu table and far fewer for the others; ten tables are well under 100 k
instructions. When a constraint set changes, the program is regenerated and its digest changes;
nothing in the rVM changes.

### 4.4 Public values

Exactly, in order: the inner verifier key digest (8 elements), `N`, then `N × 8` inner public
values (for a bundle proof, its eight output words as field elements). A node verifying an rVM
proof learns "these N proofs verify under this key and published these outputs" and nothing else.
The fullnode's aggregate admission recomputes this list from the covered bundles' public fields and
compares.

### 4.5 The self-verifier (M5.4)

The rVM's own verifier is a second program written in the same DSL against the rVM's tables. It
exists to show the machine can aggregate aggregates (a tree); its end-to-end proof may be deferred
if it exceeds the laptop (§7).

## 5. Tables and proof shape

| table | rows | width (estimate) | role |
|---|---|---|---|
| `cpu` | one per instruction | ~50 | fetch (from `program`), decode selectors, base and extension ALU, `INV` hint check, control, the `MEMORY` and `POSEIDON2` bus sends, address range limbs |
| `memory` | one per access | ~10 | timestamp-ordered permutation over `[addr, ts, value]`; the RV32 machine's pattern, one field value per cell |
| `poseidon2` | **one per permutation** | ~300 | the eight input lanes, the intermediate state of every round as columns, the eight output lanes; the round constants preprocessed; sends 8 reads and 8 writes on `MEMORY` |
| `program` | one per instruction | 4 + digest columns | the encoded program and its Poseidon2 digest, exposed in the verifier key |
| `public` | one per `PUBLIC` | 2 | index, value; exposed as the proof's public values |

**Poseidon2 chip ruling.** The RV32 machine's `poseidon2` table is round-per-row (period 32,
34 columns). At 43 562 permutations per inner proof that is 1.4 M rows per proof and 2^24 rows for
eight, which does not fit a laptop's prover. The rVM builds a permutation-per-row chip instead
(~300 columns, 44 k rows per proof, 2^19 for eight): 3.6× fewer cells and sane heights. The RV32
machine's table is untouched; the reference permutation and constants are shared.

**Buses:** `MEMORY` (`[addr, ts, value, is_write]`), `POSEIDON2` (`[clk, ptr]`), `PROGRAM`
(`[pc, word0..3]`), `RANGE8`. Invariants 1 and 2 of `AGENTS.md` apply unchanged.

**Proof shape:** the same batch STARK, field, hash and FRI profile as the RV32 machine; tiers are
powers of two in cpu rows, `TIERS = [14, 16, 18, 20, 22]` (the rVM's tier 22 is a cpu height, not
an RV32 one; the fullnode's proof cap applies unchanged since proof size scales with the number of
tables and queries, not rows). A verifier key is cached per `(tier, poseidon2_log_height)`.

**Verification on the node:** `recursion::verify(vk, proof) -> Result<PublicValues>`, native, one
call per sealing block, comparable to a bundle proof's verification today (~0.8 s cold, ~16 ms
warm) regardless of N.

## 6. Chain-facing interface

```rust
pub struct AggregateProof { pub proof: Proof, pub public: Vec<Goldilocks> }   // §4.4 layout
pub fn aggregate(inner_vk: &VerifierKey, proofs: &[InnerProof]) -> Result<AggregateProof>;
pub fn verify_aggregate(rvm_vk: &VerifierKey, a: &AggregateProof) -> Result<Vec<[u32; 8]>>;
pub fn aggregate_program_digest() -> Digest;   // what the fullnode registers
```

`InnerProof` is the RV32 machine's `Proof` plus its public values. `aggregate` builds the witness
tape (the proofs' postcard bytes decoded to field elements in consumption order), runs the
emulator, proves, and returns the proof with its public values. The fullnode side (`Action::Aggregate`,
the sealing pipeline, subsidy, pruning) is `fullnode/docs/aggregation.md` and its spec; nothing of
it lives here.

## 7. Cost model and milestones

**Cost model** (from the spike's exact counts; to be replaced by M5.1's measurement):

| per inner 80-query bundle proof | rows |
|---|---|
| Poseidon2 permutations | 43 562 (chip) + 43 562 cpu rows to dispatch |
| Merkle path bookkeeping and FRI folds (80 queries × 8 instances × ~15 levels, extension ops) | ~100 000 cpu rows |
| constraint evaluation, ten tables | ~25 000 cpu rows |
| transcript, hints, control | ~10 000 cpu rows |
| **cpu rows** | **~180 000 → 2^18** |

Eight inner proofs: ~1.4 M cpu rows (tier 21 → rounded to 22 in `TIERS`), 350 k Poseidon2 rows
(2^19). Prover memory at those heights with the widths above is single-digit GB per table; the
laptop proves an aggregate of 8, a GPU far more.

**Milestones and exit tests** (each milestone gets its own implementation plan, as M4.1–M4.4 did;
M5.1 is planned first and M5.2's plan is written after M5.1's measurement)

- **M5.1 — ISA, emulator, DSL, the number.** `recursion/` with §3, the emulator, the DSL, the
  verifier program (§4.2–4.4). Exit: the program accepts 50 real production-profile bundle proofs
  and refuses 50 tampered ones at the same step as the native verifier; the emulator reports cpu
  rows and permutations per inner proof. Decision point: if the count exceeds 2^19 cpu rows per
  proof, add `FRIFOLD`/`EXPBITS` precompiles in M5.1 and re-measure.
- **M5.2 — the machine.** The five AIRs, traces, prover, verifier, tiers, key cache, cheating tests
  (a wrong Merkle sibling, a wrong fold value, a forged public value, a skipped or extra
  permutation, a bad program digest, a bad `INV` hint, an address above `2^24` — each refused), the
  equality contract that the chip's permutation equals the reference on 1 000 random states. Exit:
  an rVM proof of the verifier program over one real bundle proof verifies natively.
- **M5.3 — the aggregate program and the chain interface.** §6's API; N measured at the production
  profile on the laptop and recorded. Exit: an aggregate of 3 real bundle proofs verifies natively,
  and a fullnode-side stub recomputes the public values from the bundles' public fields and
  matches. A tampered inner proof inside the aggregate makes `aggregate` fail, and a tampered
  aggregate fails `verify_aggregate`.
- **M5.4 — GPU and self-recursion.** CUDA backend for the rVM tables following the RV32 backend's
  pattern; N re-measured; the self-verifier program (§4.5) with its emulator differential; its
  end-to-end proof if it fits the laptop, else deferred with the measured requirement.

## 8. Testing

- **Differential, per step** (M5.1): the DSL program is instrumented with `PUBLIC` checkpoints
  (challenges, fold values) that a host test compares with the native verifier's intermediate
  values on the same proof; tampering tests flip one proof byte at a time in each phase.
- **Cycle budget** (M5.1): the instruction count and permutation count per inner proof are pinned
  by a test, so a regression in the compiled program is visible.
- **Cheating** (M5.2): every table's soundness argument gets a tamper test, as `research/tests/cheating.rs`
  does for the RV32 machine.
- **End to end** (M5.2–M5.4): real proofs only; no stubs on the proving path.
- **Docs carry measured numbers** (`AGENTS.md` rule): widths, degrees, rows per inner proof, N,
  proof size, prove/verify time, test counts.

## 9. Out of scope

- The fullnode: `Action::Aggregate`, the register, subsidy, sealing, pruning, sync in sealed form
  (`fullnode/docs/aggregation.md` and its spec).
- The RV32 machine's public unsalted input segment (M4.4 spec §5.1 item 8; needed by the SPL guest,
  not by the rVM).
- Any change to the RV32 machine's tables, buses or syscalls.
- The forward path in which bundles go to aggregators before block inclusion.
- Verifying proofs from other proof systems.

## 10. Rulings made in this design

| ruling | why | cost if wrong |
|---|---|---|
| a recursion VM, not a hardwired verifier AIR | a constraint-set change is a program change, not a circuit change; it can verify itself | a second machine to maintain (five tables, one ISA) |
| one level of recursion first, self-recursion as an M5.4 program | the sealing pipeline needs N bundles → 1 proof; a tree is the same ISA with another program | if an aggregate of the target N does not fit a tier, the tree arrives one milestone later |
| no salted input commitment on the rVM | its witness is public proofs; the public values are the interface | none; the RV32 machine keeps its own commitment |
| permutation-per-row Poseidon2 chip (~300 columns) instead of reusing the round-per-row table | 32× fewer rows; heights that fit a laptop | a second Poseidon2 AIR to keep equal to the reference (equality test) |
| precompiles (`FRIFOLD`, `EXPBITS`) only after M5.1 measures | the spike's breakdown says hashing dominates; folds may be cheap enough as sequences | one extra M5.1 iteration if they are needed |
| `INV`/`EINV` as hint-and-check | the standard way to make inversion one row | the prover must supply the hint (the emulator computes it) |
| addresses below `2^24` with an 8-bit-limb range check | one lookup already exists; memory of 16 M cells is ample for 8 proofs | a program needing more memory needs a wider limb decomposition |
| `TIERS = [14, 16, 18, 20, 22]` | cpu heights sized to 1–8 inner proofs by the cost model | re-cut after M5.1's measurement |

## 11. Open items

- The exact N the laptop and the GPU reach at the production profile (M5.3/M5.4 measurements).
- Whether the aggregate program should also bind the inner proofs' `H_IN` values (it does not need
  to: the bundle digest already binds the bundle; recorded here so the aggregation spec can decide).
- The rVM's own verifier key arity and how the fullnode pins it (the vendoring task).
