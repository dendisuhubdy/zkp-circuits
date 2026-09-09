# Rand reference zkVM — Milestone 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A single crate `circuits/research` (`rand_zkvm`) whose one binary narrates, proves and verifies RV32I guest programs under a zero-knowledge, tier-padded batch STARK made of five tables on LogUp buses.

**Architecture:** An emulator executes a guest and records per-cycle events. Five AIR tables (program, cpu, memory, alu, byte) each build a trace from those events and are proved together by `p3-batch-stark`; they exchange facts over named LogUp buses (`PROGRAM`, `MEMORY`, `ALU`, `RANGE8`, `AND8`, `OR8`, `XOR8`, `POW2`). The program is a preprocessed table whose commitment is the code hash. A hiding FRI commitment gives zero knowledge, and every table is padded to a gas-tier height.

**Tech Stack:** Rust 1.98.1 (pinned via `rust-toolchain.toml`), Plonky3 0.7.0 (`p3-air`, `p3-uni-stark`, `p3-batch-stark`, `p3-lookup`, `p3-goldilocks`, `p3-field`, `p3-matrix`, `p3-challenger`, `p3-commit`, `p3-fri`, `p3-dft`, `p3-merkle-tree`, `p3-symmetric`), `rand 0.10` (`std_rng`), `serde`, `postcard`.

**Spec:** `docs/superpowers/specs/2026-09-09-research-zkvm-design.md` (read it first; this plan refines §5.1 by pre-decoding *selectors* instead of one flag per mnemonic, and adds `READ_INPUT` to milestone 1 so the demo has a real private input).

## Global Constraints

- Folder `circuits/research/`, crate name `rand_zkvm`, edition 2021, one binary (`src/main.rs`), library in `src/lib.rs`.
- Toolchain pinned: `rust-toolchain.toml` with `channel = "1.98.1"`. Plonky3 0.7 does not compile on 1.91.
- Plonky3 crates all at `=0.7.0`. `rand = { version = "0.10", features = ["std_rng"] }` (Plonky3's version; 0.9 will not link).
- Field: Goldilocks. Challenge: `BinomialExtensionField<Goldilocks, 2>`. Hash: `Poseidon2Goldilocks<8>`, sponge `PaddingFreeSponge<Perm, 8, 4, 4>`, compress `TruncatedPermutation<Perm, 2, 4, 8>`, challenger `DuplexChallenger<Goldilocks, Perm, 8, 4>`.
- Zero knowledge always on: `MerkleTreeHidingMmcs<…, StdRng, 2, 4, 4>` + `HidingFriPcs<…, StdRng>` with 4 random codewords.
- FRI: `log_blowup = 3`. Production profile: `num_queries = 80`, `query_proof_of_work_bits = 20`. Test profile: `num_queries = 16`, `query_proof_of_work_bits = 4`. Both: `log_final_poly_len = 0`, `max_log_arity = 1`, `commit_proof_of_work_bits = 0`.
- Tiers (log2 of CPU height): `[10, 12, 14, 16, 18, 20]`. CPU and program-fetch rows = 2^k, ALU rows = 2^(k+1), memory rows = 2^(k+2), byte table = 2^16 rows, program table = next power of two ≥ len+1, minimum 16. A run needs `cycles + 1 ≤ 2^k` so every table keeps at least one padding row.
- Public values, exactly 10: `[pc_entry, tier_log2, out0..out7]`.
- Every table has an `is_real` column; padding rows have every selector/flag equal to 0 and emit nothing on any bus. Constraints between two rows are wrapped in `when_transition()`.
- Tests run in debug mode (`cargo test`) so `p3-batch-stark`'s `check_constraints` runs inside `prove_batch` and panics on the first violated constraint with the row index. Set `[profile.dev.package."*"] opt-level = 3` and `[profile.test] opt-level = 1` so this is fast enough.
- Commit after every task with a message describing the task; all commits in the `circuits` repo.

---

## File map

| File | Responsibility |
|---|---|
| `research/Cargo.toml`, `rust-toolchain.toml`, `.gitignore` | crate + toolchain |
| `research/src/lib.rs` | module list and re-exports |
| `research/src/isa.rs` | `AluOp`, `BranchCond`, `Instr`, `Decoded`, `Program`, RV32I encode/decode |
| `research/src/asm.rs` | `Assembler` with labels; mnemonic helper functions |
| `research/src/guests.rs` | the guest programs used by tests and the demo |
| `research/src/emulator.rs` | `execute()` → `Execution { events, outputs }` |
| `research/src/tables/mod.rs` | bus names, `F` alias, small helpers |
| `research/src/tables/byte.rs` | 2^16 byte table AIR, `ByteCounts` |
| `research/src/tables/program.rs` | preprocessed program AIR + fetch multiplicities |
| `research/src/tables/memory.rs` | sorted memory AIR + trace |
| `research/src/tables/alu.rs` | ALU AIR + trace |
| `research/src/tables/cpu.rs` | CPU AIR + trace, public value layout |
| `research/src/machine.rs` | Plonky3 config, `Chip` enum, tiers, `build_traces`, `prove`, `verify` |
| `research/src/main.rs` | the narrated demo |
| `research/tests/{isa,emulator,tables,e2e,cheating,zk}.rs` | tests |
| `research/README.md`, `research/docs/0{1..5}-*.md` | guidance docs |

---

### Task 1: Crate scaffold, toolchain pin, Plonky3 config, byte table

**Files:**
- Create: `research/Cargo.toml`, `research/rust-toolchain.toml`, `research/.gitignore`, `research/src/lib.rs`, `research/src/tables/mod.rs`, `research/src/tables/byte.rs`, `research/src/machine.rs` (config part only)
- Test: `research/tests/tables.rs`

**Interfaces:**
- Produces: `machine::{Val, Challenge, Config, FriProfile, make_config}`; `tables::{F, bus::{RANGE8, AND8, OR8, XOR8, POW2, PROGRAM, MEMORY, ALU}}`; `tables::byte::{ByteAir, ByteCounts, byte_trace, col}`.

- [ ] **Step 1: Scaffold the crate**

```toml
# research/Cargo.toml
[package]
name = "rand_zkvm"
version = "0.1.0"
edition = "2021"
description = "Rand Protocol reference zkVM: RV32I under a zero-knowledge batch STARK (Plonky3, Goldilocks)"

[lib]
path = "src/lib.rs"

[[bin]]
name = "rand_zkvm"
path = "src/main.rs"

[dependencies]
p3-air = "=0.7.0"
p3-uni-stark = "=0.7.0"
p3-batch-stark = "=0.7.0"
p3-lookup = "=0.7.0"
p3-goldilocks = "=0.7.0"
p3-field = "=0.7.0"
p3-matrix = "=0.7.0"
p3-challenger = "=0.7.0"
p3-commit = "=0.7.0"
p3-fri = "=0.7.0"
p3-dft = "=0.7.0"
p3-merkle-tree = "=0.7.0"
p3-symmetric = "=0.7.0"
rand = { version = "0.10", features = ["std_rng"] }
serde = { version = "1", features = ["derive"] }
postcard = { version = "1", features = ["alloc"] }

[profile.release]
opt-level = 3

[profile.dev.package."*"]
opt-level = 3

[profile.test]
opt-level = 1
```

```toml
# research/rust-toolchain.toml
[toolchain]
channel = "1.98.1"
```

`.gitignore`: `/target` and `Cargo.lock`? No — commit `Cargo.lock` (the zkp crates do). `.gitignore` contains only `/target`.

```rust
// research/src/lib.rs
pub mod isa;
pub mod asm;
pub mod guests;
pub mod emulator;
pub mod tables;
pub mod machine;
```

For this task create empty `isa.rs`, `asm.rs`, `guests.rs`, `emulator.rs` files containing only `//! filled in by a later task` so the crate compiles.

- [ ] **Step 2: Bus names and field alias**

```rust
// research/src/tables/mod.rs
//! The five tables of the machine and the buses that connect them.
pub mod byte;
pub mod program;
pub mod memory;
pub mod alu;
pub mod cpu;

pub type F = p3_goldilocks::Goldilocks;

/// Bus catalogue. A bus is a name; the batch verifier checks every bus balances.
pub mod bus {
    use p3_lookup::{LookupBus, PermutationCheckBus};
    /// cpu → program: (pc, 18 decoded fields). Program provides.
    pub const PROGRAM: LookupBus<'static> = LookupBus::new("PROGRAM");
    /// cpu ↔ memory: (space, addr, ts, value, is_write). Multiset equality.
    pub const MEMORY: PermutationCheckBus<'static> = PermutationCheckBus::new("MEMORY");
    /// cpu → alu: (op, a, b, c). Alu provides.
    pub const ALU: LookupBus<'static> = LookupBus::new("ALU");
    /// x in [0,256). Byte provides.
    pub const RANGE8: LookupBus<'static> = LookupBus::new("RANGE8");
    /// (a, b, a&b). Byte provides.
    pub const AND8: LookupBus<'static> = LookupBus::new("AND8");
    pub const OR8: LookupBus<'static> = LookupBus::new("OR8");
    pub const XOR8: LookupBus<'static> = LookupBus::new("XOR8");
    /// (s, 2^s) for s < 32. Byte provides.
    pub const POW2: LookupBus<'static> = LookupBus::new("POW2");
}

/// Split a u32 into four little-endian bytes as field elements.
pub fn limbs(x: u32) -> [F; 4] {
    use p3_field::PrimeCharacteristicRing;
    core::array::from_fn(|i| F::from_u32((x >> (8 * i)) & 0xff))
}

/// Next power of two ≥ n, at least `min`.
pub fn pad_height(n: usize, min: usize) -> usize {
    n.max(min).next_power_of_two()
}
```

For this task, `program`, `memory`, `alu`, `cpu` modules are empty files with a doc comment so the crate compiles.

- [ ] **Step 3: Write the failing byte-table test**

```rust
// research/tests/tables.rs
use rand_zkvm::machine::{make_config, FriProfile, Chip};
use rand_zkvm::tables::byte::{byte_trace, ByteAir, ByteCounts};
use rand_zkvm::tables::bus;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_batch_stark::{prove_batch, verify_batch, ProverData, StarkInstance};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use rand_zkvm::tables::F;

/// A throwaway table that asks the byte table questions. main: [x, y, z, is_real]
#[derive(Clone)]
struct Asker;
impl<Fld> BaseAir<Fld> for Asker { fn width(&self) -> usize { 4 } }
impl<AB: AirBuilder + InteractionBuilder> Air<AB> for Asker where AB::F: p3_field::Field {
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let (x, y, z, r) = (m.current(0).unwrap(), m.current(1).unwrap(), m.current(2).unwrap(), m.current(3).unwrap());
        b.assert_bool(r);
        bus::RANGE8.lookup_key(b, [x.into()], Count::bounded(r.into(), 1));
        bus::AND8.lookup_key(b, [x.into(), y.into(), z.into()], Count::bounded(r.into(), 1));
    }
}

#[test]
fn byte_table_answers_range_and_and_lookups() {
    let config = make_config(FriProfile::Test);
    let mut counts = ByteCounts::default();
    let rows: Vec<(u32, u32)> = vec![(0xf0, 0x3c), (7, 7), (255, 0), (1, 2)];
    let mut asker = vec![F::ZERO; 16 * 4];
    for (i, (x, y)) in rows.iter().enumerate() {
        counts.range8(*x);
        counts.and8(*x, *y);
        asker[4 * i] = F::from_u32(*x);
        asker[4 * i + 1] = F::from_u32(*y);
        asker[4 * i + 2] = F::from_u32(x & y);
        asker[4 * i + 3] = F::ONE;
    }
    let asker_trace = RowMajorMatrix::new(asker, 4);
    let byte = byte_trace(&counts);
    // prove with a two-AIR enum local to the test
    #[derive(Clone)]
    enum T { Byte(ByteAir), Ask(Asker) }
    impl<Fld: p3_field::Field> BaseAir<Fld> for T {
        fn width(&self) -> usize { match self { T::Byte(a) => <ByteAir as BaseAir<Fld>>::width(a), T::Ask(a) => <Asker as BaseAir<Fld>>::width(a) } }
        fn preprocessed_width(&self) -> usize { match self { T::Byte(a) => <ByteAir as BaseAir<Fld>>::preprocessed_width(a), _ => 0 } }
        fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> { match self { T::Byte(a) => <ByteAir as BaseAir<Fld>>::preprocessed_trace(a), _ => None } }
    }
    impl<AB: AirBuilder + p3_air::PermutationAirBuilder + InteractionBuilder> Air<AB> for T where AB::F: p3_field::Field {
        fn eval(&self, b: &mut AB) { match self { T::Byte(a) => a.eval(b), T::Ask(a) => a.eval(b) } }
    }
    let airs = vec![T::Byte(ByteAir), T::Ask(Asker)];
    let instances = vec![
        StarkInstance { air: &airs[0], trace: &byte, public_values: vec![] },
        StarkInstance { air: &airs[1], trace: &asker_trace, public_values: vec![] },
    ];
    let pd = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &pd);
    verify_batch(&config, &airs, &proof, &[vec![], vec![]], &pd.common).unwrap();
}
```

- [ ] **Step 4: Run to verify it fails**

Run: `cd research && cargo test --test tables`
Expected: compile error, `machine::make_config` and `tables::byte` missing.

- [ ] **Step 5: Implement the config**

```rust
// research/src/machine.rs  (config half; the prove/verify half is Task 8)
//! Plonky3 configuration, the `Chip` enum, gas tiers, prove and verify.
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;
use rand::rngs::StdRng;
use rand::SeedableRng;

pub type Val = Goldilocks;
pub type Challenge = BinomialExtensionField<Val, 2>;
pub type Perm = Poseidon2Goldilocks<8>;
type Hash = PaddingFreeSponge<Perm, 8, 4, 4>;
type Compress = TruncatedPermutation<Perm, 2, 4, 8>;
type Packing = <Val as Field>::Packing;
pub type ValMmcs = MerkleTreeHidingMmcs<Packing, Packing, Hash, Compress, StdRng, 2, 4, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Challenger = DuplexChallenger<Val, Perm, 8, 4>;
type Dft = Radix2DitParallel<Val>;
pub type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, StdRng>;
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

/// Fixed seed for the Poseidon2 round constants. Prover and verifier derive the
/// same permutation from it. Production swaps this for the published
/// `GOLDILOCKS_POSEIDON2_RC_8_*` constants; the circuit does not change.
const PERM_SEED: u64 = 0x5261_6e64_5a4b; // "RandZK"

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FriProfile {
    /// 16 queries, 4 PoW bits — for `cargo test`.
    Test,
    /// 80 queries, 20 PoW bits, blowup 8 — the whitepaper table.
    Production,
}

impl FriProfile {
    pub fn num_queries(self) -> usize { match self { Self::Test => 16, Self::Production => 80 } }
    pub fn pow_bits(self) -> usize { match self { Self::Test => 4, Self::Production => 20 } }
}

pub fn permutation() -> Perm {
    Perm::new_from_rng_128(&mut StdRng::seed_from_u64(PERM_SEED))
}

pub fn make_config(profile: FriProfile) -> Config {
    let perm = permutation();
    let hash = Hash::new(perm.clone());
    let compress = Compress::new(perm.clone());
    // The RNGs below only feed the zero-knowledge masks; fresh entropy per proof is
    // taken from the OS.
    let val_mmcs = ValMmcs::new(hash, compress, 2, StdRng::from_rng(&mut rand::rng()));
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri = FriParameters {
        log_blowup: 3,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: profile.num_queries(),
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: profile.pow_bits(),
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri, 4, StdRng::from_rng(&mut rand::rng()));
    StarkConfig::new(pcs, Challenger::new(perm))
}
```

- [ ] **Step 6: Implement the byte table**

```rust
// research/src/tables/byte.rs
//! 2^16-row preprocessed table of every byte pair, serving five buses.
use super::{bus, F};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

pub const HEIGHT: usize = 1 << 16;

/// Preprocessed columns.
pub mod pre {
    pub const A: usize = 0;
    pub const B: usize = 1;
    pub const AND: usize = 2;
    pub const OR: usize = 3;
    pub const XOR: usize = 4;
    pub const POW2: usize = 5;      // 2^A on rows with B == 0 and A < 32, else 0
    pub const IS_POW2: usize = 6;   // 1 on those rows
    pub const WIDTH: usize = 7;
}
/// Main columns: one multiplicity per bus.
pub mod col {
    pub const M_RANGE: usize = 0;
    pub const M_AND: usize = 1;
    pub const M_OR: usize = 2;
    pub const M_XOR: usize = 3;
    pub const M_POW2: usize = 4;
    pub const WIDTH: usize = 5;
}

#[inline] pub fn row_of(a: u32, b: u32) -> usize { (a as usize) * 256 + b as usize }

#[derive(Clone, Copy, Debug, Default)]
pub struct ByteAir;

impl<Fld: Field> BaseAir<Fld> for ByteAir {
    fn width(&self) -> usize { col::WIDTH }
    fn preprocessed_width(&self) -> usize { pre::WIDTH }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> {
        let mut v = Fld::zero_vec(HEIGHT * pre::WIDTH);
        for a in 0..256u32 {
            for b in 0..256u32 {
                let r = row_of(a, b) * pre::WIDTH;
                v[r + pre::A] = Fld::from_u32(a);
                v[r + pre::B] = Fld::from_u32(b);
                v[r + pre::AND] = Fld::from_u32(a & b);
                v[r + pre::OR] = Fld::from_u32(a | b);
                v[r + pre::XOR] = Fld::from_u32(a ^ b);
                if b == 0 && a < 32 {
                    v[r + pre::POW2] = Fld::from_u32(1 << a);
                    v[r + pre::IS_POW2] = Fld::ONE;
                }
            }
        }
        Some(RowMajorMatrix::new(v, pre::WIDTH))
    }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for ByteAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let p = b.preprocessed().clone();
        let m = b.main();
        let (a, bb, and, or, xor, pow2, is_pow2) = (
            p.current(pre::A).unwrap(), p.current(pre::B).unwrap(), p.current(pre::AND).unwrap(),
            p.current(pre::OR).unwrap(), p.current(pre::XOR).unwrap(), p.current(pre::POW2).unwrap(),
            p.current(pre::IS_POW2).unwrap(),
        );
        let (mr, ma, mo, mx, mp) = (
            m.current(col::M_RANGE).unwrap(), m.current(col::M_AND).unwrap(), m.current(col::M_OR).unwrap(),
            m.current(col::M_XOR).unwrap(), m.current(col::M_POW2).unwrap(),
        );
        // POW2 entries may only be consumed on pow2 rows.
        b.assert_zero(mp.into() * (AB::Expr::ONE - is_pow2.into()));
        bus::RANGE8.table_entry(b, [a.into()], mr.into());
        bus::AND8.table_entry(b, [a.into(), bb.into(), and.into()], ma.into());
        bus::OR8.table_entry(b, [a.into(), bb.into(), or.into()], mo.into());
        bus::XOR8.table_entry(b, [a.into(), bb.into(), xor.into()], mx.into());
        bus::POW2.table_entry(b, [a.into(), pow2.into()], mp.into());
    }
}

/// Counts every lookup the other tables perform. Trace builders call these in
/// lock-step with the interactions their AIRs declare.
#[derive(Clone, Debug, Default)]
pub struct ByteCounts {
    pub range: Vec<u64>, pub and: Vec<u64>, pub or: Vec<u64>, pub xor: Vec<u64>, pub pow2: Vec<u64>,
}
impl ByteCounts {
    fn ensure(&mut self) { if self.range.is_empty() { for v in [&mut self.range, &mut self.and, &mut self.or, &mut self.xor, &mut self.pow2] { *v = vec![0; HEIGHT]; } } }
    pub fn range8(&mut self, x: u32) { self.ensure(); assert!(x < 256); self.range[row_of(x, 0)] += 1; }
    pub fn and8(&mut self, a: u32, b: u32) { self.ensure(); self.and[row_of(a, b)] += 1; }
    pub fn or8(&mut self, a: u32, b: u32) { self.ensure(); self.or[row_of(a, b)] += 1; }
    pub fn xor8(&mut self, a: u32, b: u32) { self.ensure(); self.xor[row_of(a, b)] += 1; }
    pub fn pow2(&mut self, s: u32) { self.ensure(); assert!(s < 32); self.pow2[row_of(s, 0)] += 1; }
}

pub fn byte_trace(c: &ByteCounts) -> RowMajorMatrix<F> {
    let mut c = c.clone();
    c.ensure();
    let mut v = F::zero_vec(HEIGHT * col::WIDTH);
    for r in 0..HEIGHT {
        v[r * col::WIDTH + col::M_RANGE] = F::from_u64(c.range[r]);
        v[r * col::WIDTH + col::M_AND] = F::from_u64(c.and[r]);
        v[r * col::WIDTH + col::M_OR] = F::from_u64(c.or[r]);
        v[r * col::WIDTH + col::M_XOR] = F::from_u64(c.xor[r]);
        v[r * col::WIDTH + col::M_POW2] = F::from_u64(c.pow2[r]);
    }
    RowMajorMatrix::new(v, col::WIDTH)
}
```

Add to `machine.rs` a placeholder-free `Chip` enum later (Task 8); the test above defines its own enum, so nothing else is needed now.

- [ ] **Step 7: Run the test**

Run: `cd research && cargo test --test tables`
Expected: PASS (the first run compiles Plonky3, ~2 minutes).

- [ ] **Step 8: Commit**

```bash
cd /Users/dendisuhubdy/Github/randprotocol/circuits
git add research
git commit -m "research: crate scaffold, Goldilocks hiding-FRI config, byte table"
```

---

### Task 2: ISA — instructions, RV32I encoding, pre-decoded selectors

**Files:**
- Create: `research/src/isa.rs`
- Test: `research/tests/isa.rs`

**Interfaces:**
- Produces:
  - `AluOp { Add=0, Sub=1, And=2, Or=3, Xor=4, Sll=5, Srl=6, Sra=7, Slt=8, Sltu=9, Eq=10 }`, `AluOp::eval(self, a: u32, b: u32) -> u32`, `AluOp::COUNT = 11`, `AluOp::from_code(u32) -> AluOp`
  - `BranchCond { Eq, Ne, Lt, Ge, Ltu, Geu }`, `BranchCond::alu_op(self) -> AluOp`, `BranchCond::negate(self) -> bool`
  - `Instr` enum with variants `Lui{rd,imm}`, `Auipc{rd,imm}`, `Jal{rd,imm}`, `Jalr{rd,rs1,imm}`, `Branch{cond,rs1,rs2,imm}`, `Lw{rd,rs1,imm}`, `Sw{rs1,rs2,imm}`, `AluImm{op,rd,rs1,imm}`, `AluReg{op,rd,rs1,rs2}`, `Ecall` (all fields `u32`; `imm` is the *sign-extended value as u32*, i.e. what `pc + imm` or `rs1 + imm` adds mod 2^32)
  - `Instr::encode(&self) -> u32`, `Instr::decode(u32) -> Result<Instr, DecodeError>`, `Instr::decoded(&self) -> Decoded`
  - `Decoded` (18 `u32` fields, see spec §5.1 refinement) with `Decoded::to_fields(&self) -> [u32; 18]` and `Decoded::NUM_FIELDS = 18`, field order: `rd, rs1, rs2, imm, is_alu, alu_op, is_imm, is_branch, br_op, br_neg, is_load, is_store, is_jal, is_jalr, is_lui, is_auipc, is_ecall, writes_rd`
  - `Program { base_pc: u32, words: Vec<u32> }` with `Program::new(base_pc, words)`, `Program::len()`, `Program::instr_at(pc) -> Option<Instr>`
  - Register constants `REG_ZERO=0, REG_RA=1, REG_SP=2, REG_A0=10, REG_A1=11, REG_A2=12, REG_A7=17`, syscall numbers `SYS_HALT=0, SYS_WRITE_OUTPUT=1, SYS_READ_INPUT=2`, `NUM_OUTPUTS=8`

- [ ] **Step 1: Write the failing tests**

```rust
// research/tests/isa.rs
use rand_zkvm::isa::*;

#[test]
fn alu_ops_match_reference_semantics() {
    assert_eq!(AluOp::Add.eval(0xffff_ffff, 1), 0);
    assert_eq!(AluOp::Sub.eval(0, 1), 0xffff_ffff);
    assert_eq!(AluOp::Sll.eval(1, 31), 0x8000_0000);
    assert_eq!(AluOp::Sll.eval(1, 32), 1);              // shift amount masked to 5 bits
    assert_eq!(AluOp::Srl.eval(0x8000_0000, 31), 1);
    assert_eq!(AluOp::Sra.eval(0x8000_0000, 31), 0xffff_ffff);
    assert_eq!(AluOp::Sra.eval(0x7fff_ffff, 4), 0x07ff_ffff);
    assert_eq!(AluOp::Slt.eval(0xffff_ffff, 0), 1);     // -1 < 0
    assert_eq!(AluOp::Slt.eval(0, 0xffff_ffff), 0);
    assert_eq!(AluOp::Sltu.eval(0xffff_ffff, 0), 0);
    assert_eq!(AluOp::Sltu.eval(0, 1), 1);
    assert_eq!(AluOp::Eq.eval(5, 5), 1);
    assert_eq!(AluOp::Eq.eval(5, 6), 0);
    assert_eq!(AluOp::Xor.eval(0xf0f0, 0x0ff0), 0xff00);
}

#[test]
fn encode_decode_roundtrip_every_variant() {
    let cases = vec![
        Instr::Lui { rd: 5, imm: 0xdead_b000 },
        Instr::Auipc { rd: 6, imm: 0x0000_1000 },
        Instr::Jal { rd: 1, imm: (-8i32) as u32 },
        Instr::Jalr { rd: 0, rs1: 1, imm: 0 },
        Instr::Branch { cond: BranchCond::Ne, rs1: 3, rs2: 4, imm: (-12i32) as u32 },
        Instr::Branch { cond: BranchCond::Geu, rs1: 3, rs2: 4, imm: 4094 },
        Instr::Lw { rd: 7, rs1: 2, imm: (-4i32) as u32 },
        Instr::Sw { rs1: 2, rs2: 7, imm: 2047 },
        Instr::AluImm { op: AluOp::Add, rd: 1, rs1: 1, imm: (-1i32) as u32 },
        Instr::AluImm { op: AluOp::Sra, rd: 1, rs1: 1, imm: 7 },
        Instr::AluImm { op: AluOp::Srl, rd: 1, rs1: 1, imm: 31 },
        Instr::AluImm { op: AluOp::Sltu, rd: 1, rs1: 1, imm: 1 },
        Instr::AluReg { op: AluOp::Sub, rd: 9, rs1: 10, rs2: 11 },
        Instr::AluReg { op: AluOp::Sra, rd: 9, rs1: 10, rs2: 11 },
        Instr::Ecall,
    ];
    for i in cases {
        let w = i.encode();
        assert_eq!(Instr::decode(w).unwrap(), i, "word {w:#010x}");
    }
}

#[test]
fn known_encodings_match_the_riscv_spec() {
    // addi x1, x0, 5  = 0x00500093
    assert_eq!(Instr::AluImm { op: AluOp::Add, rd: 1, rs1: 0, imm: 5 }.encode(), 0x0050_0093);
    // add x3, x1, x2 = 0x002081b3
    assert_eq!(Instr::AluReg { op: AluOp::Add, rd: 3, rs1: 1, rs2: 2 }.encode(), 0x0020_81b3);
    // ecall = 0x00000073
    assert_eq!(Instr::Ecall.encode(), 0x0000_0073);
    // beq x1, x2, +8 = 0x00208463
    assert_eq!(Instr::Branch { cond: BranchCond::Eq, rs1: 1, rs2: 2, imm: 8 }.encode(), 0x0020_8463);
    // lw x5, 4(x2) = 0x00412283
    assert_eq!(Instr::Lw { rd: 5, rs1: 2, imm: 4 }.encode(), 0x0041_2283);
    // sw x5, 4(x2) = 0x00512223
    assert_eq!(Instr::Sw { rs1: 2, rs2: 5, imm: 4 }.encode(), 0x0051_2223);
}

#[test]
fn decoded_selectors() {
    let d = Instr::AluImm { op: AluOp::Xor, rd: 3, rs1: 4, imm: 9 }.decoded();
    assert_eq!((d.is_alu, d.alu_op, d.is_imm, d.writes_rd, d.rd, d.rs1, d.imm), (1, 4, 1, 1, 3, 4, 9));
    let d = Instr::AluReg { op: AluOp::Add, rd: 0, rs1: 4, rs2: 5 }.decoded();
    assert_eq!(d.writes_rd, 0, "x0 is never written");
    let d = Instr::Branch { cond: BranchCond::Ge, rs1: 1, rs2: 2, imm: 8 }.decoded();
    assert_eq!((d.is_branch, d.br_op, d.br_neg, d.is_imm), (1, 8, 1, 0));
    let d = Instr::Ecall.decoded();
    assert_eq!((d.is_ecall, d.rs1, d.rs2, d.rd, d.writes_rd), (1, 17, 10, 10, 0));
    let d = Instr::Lw { rd: 2, rs1: 3, imm: 4 }.decoded();
    assert_eq!((d.is_load, d.is_imm, d.writes_rd), (1, 1, 1));
    assert_eq!(Decoded::NUM_FIELDS, 18);
    assert_eq!(d.to_fields()[0], 2);
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd research && cargo test --test isa`
Expected: compile error, `isa` items missing.

- [ ] **Step 3: Implement `isa.rs`**

```rust
// research/src/isa.rs
//! The RV32I subset of milestone 1, its encoding, and the pre-decoded selector
//! set that the program table commits and the CPU table consumes.

pub const REG_ZERO: u32 = 0;
pub const REG_RA: u32 = 1;
pub const REG_SP: u32 = 2;
pub const REG_A0: u32 = 10;
pub const REG_A1: u32 = 11;
pub const REG_A2: u32 = 12;
pub const REG_A7: u32 = 17;

pub const SYS_HALT: u32 = 0;
pub const SYS_WRITE_OUTPUT: u32 = 1;
pub const SYS_READ_INPUT: u32 = 2;
pub const NUM_OUTPUTS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum AluOp { Add = 0, Sub = 1, And = 2, Or = 3, Xor = 4, Sll = 5, Srl = 6, Sra = 7, Slt = 8, Sltu = 9, Eq = 10 }

impl AluOp {
    pub const COUNT: usize = 11;
    pub const ALL: [AluOp; 11] = [AluOp::Add, AluOp::Sub, AluOp::And, AluOp::Or, AluOp::Xor, AluOp::Sll, AluOp::Srl, AluOp::Sra, AluOp::Slt, AluOp::Sltu, AluOp::Eq];
    pub fn code(self) -> u32 { self as u32 }
    pub fn from_code(c: u32) -> AluOp { Self::ALL[c as usize] }
    /// Reference semantics. The ALU table proves exactly this function.
    pub fn eval(self, a: u32, b: u32) -> u32 {
        let s = b & 31;
        match self {
            AluOp::Add => a.wrapping_add(b),
            AluOp::Sub => a.wrapping_sub(b),
            AluOp::And => a & b,
            AluOp::Or => a | b,
            AluOp::Xor => a ^ b,
            AluOp::Sll => a << s,
            AluOp::Srl => a >> s,
            AluOp::Sra => ((a as i32) >> s) as u32,
            AluOp::Slt => ((a as i32) < (b as i32)) as u32,
            AluOp::Sltu => (a < b) as u32,
            AluOp::Eq => (a == b) as u32,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BranchCond { Eq, Ne, Lt, Ge, Ltu, Geu }

impl BranchCond {
    /// The compare the ALU performs; `negate` flips its result.
    pub fn alu_op(self) -> AluOp { match self { Self::Eq | Self::Ne => AluOp::Eq, Self::Lt | Self::Ge => AluOp::Slt, Self::Ltu | Self::Geu => AluOp::Sltu } }
    pub fn negate(self) -> bool { matches!(self, Self::Ne | Self::Ge | Self::Geu) }
    pub fn taken(self, a: u32, b: u32) -> bool { (self.alu_op().eval(a, b) == 1) != self.negate() }
    fn funct3(self) -> u32 { match self { Self::Eq => 0, Self::Ne => 1, Self::Lt => 4, Self::Ge => 5, Self::Ltu => 6, Self::Geu => 7 } }
    fn from_funct3(f: u32) -> Option<Self> { Some(match f { 0 => Self::Eq, 1 => Self::Ne, 4 => Self::Lt, 5 => Self::Ge, 6 => Self::Ltu, 7 => Self::Geu, _ => return None }) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Instr {
    Lui { rd: u32, imm: u32 },
    Auipc { rd: u32, imm: u32 },
    Jal { rd: u32, imm: u32 },
    Jalr { rd: u32, rs1: u32, imm: u32 },
    Branch { cond: BranchCond, rs1: u32, rs2: u32, imm: u32 },
    Lw { rd: u32, rs1: u32, imm: u32 },
    Sw { rs1: u32, rs2: u32, imm: u32 },
    AluImm { op: AluOp, rd: u32, rs1: u32, imm: u32 },
    AluReg { op: AluOp, rd: u32, rs1: u32, rs2: u32 },
    Ecall,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError { Opcode(u32), Funct(u32), Shamt(u32) }

const OP_LUI: u32 = 0x37; const OP_AUIPC: u32 = 0x17; const OP_JAL: u32 = 0x6f; const OP_JALR: u32 = 0x67;
const OP_BRANCH: u32 = 0x63; const OP_LOAD: u32 = 0x03; const OP_STORE: u32 = 0x23;
const OP_ALUI: u32 = 0x13; const OP_ALU: u32 = 0x33; const OP_SYSTEM: u32 = 0x73;

fn alu_funct(op: AluOp) -> (u32, u32) {
    // (funct3, funct7)
    match op {
        AluOp::Add => (0, 0), AluOp::Sub => (0, 0x20), AluOp::Sll => (1, 0), AluOp::Slt => (2, 0), AluOp::Sltu => (3, 0),
        AluOp::Xor => (4, 0), AluOp::Srl => (5, 0), AluOp::Sra => (5, 0x20), AluOp::Or => (6, 0), AluOp::And => (7, 0),
        AluOp::Eq => unreachable!("EQ is not an encodable instruction"),
    }
}
fn alu_from_funct(f3: u32, f7: u32, imm_form: bool) -> Result<AluOp, DecodeError> {
    Ok(match (f3, f7) {
        (0, 0) => AluOp::Add,
        (0, 0x20) if !imm_form => AluOp::Sub,
        (0, _) if imm_form => AluOp::Add,
        (1, 0) => AluOp::Sll,
        (2, _) if imm_form => AluOp::Slt, (2, 0) => AluOp::Slt,
        (3, _) if imm_form => AluOp::Sltu, (3, 0) => AluOp::Sltu,
        (4, _) if imm_form => AluOp::Xor, (4, 0) => AluOp::Xor,
        (5, 0) => AluOp::Srl, (5, 0x20) => AluOp::Sra,
        (6, _) if imm_form => AluOp::Or, (6, 0) => AluOp::Or,
        (7, _) if imm_form => AluOp::And, (7, 0) => AluOp::And,
        _ => return Err(DecodeError::Funct((f7 << 3) | f3)),
    })
}
fn sext(x: u32, bits: u32) -> u32 { ((x << (32 - bits)) as i32 >> (32 - bits)) as u32 }
fn bits(w: u32, hi: u32, lo: u32) -> u32 { (w >> lo) & ((1u32 << (hi - lo + 1)) - 1) }

impl Instr {
    pub fn encode(&self) -> u32 {
        let i_type = |imm: u32, rs1: u32, f3: u32, rd: u32, op: u32| (imm & 0xfff) << 20 | rs1 << 15 | f3 << 12 | rd << 7 | op;
        match *self {
            Instr::Lui { rd, imm } => (imm & 0xffff_f000) | rd << 7 | OP_LUI,
            Instr::Auipc { rd, imm } => (imm & 0xffff_f000) | rd << 7 | OP_AUIPC,
            Instr::Jal { rd, imm } => bits(imm, 20, 20) << 31 | bits(imm, 10, 1) << 21 | bits(imm, 11, 11) << 20 | bits(imm, 19, 12) << 12 | rd << 7 | OP_JAL,
            Instr::Jalr { rd, rs1, imm } => i_type(imm, rs1, 0, rd, OP_JALR),
            Instr::Branch { cond, rs1, rs2, imm } => bits(imm, 12, 12) << 31 | bits(imm, 10, 5) << 25 | rs2 << 20 | rs1 << 15 | cond.funct3() << 12 | bits(imm, 4, 1) << 8 | bits(imm, 11, 11) << 7 | OP_BRANCH,
            Instr::Lw { rd, rs1, imm } => i_type(imm, rs1, 2, rd, OP_LOAD),
            Instr::Sw { rs1, rs2, imm } => bits(imm, 11, 5) << 25 | rs2 << 20 | rs1 << 15 | 2 << 12 | bits(imm, 4, 0) << 7 | OP_STORE,
            Instr::AluImm { op, rd, rs1, imm } => {
                let (f3, f7) = alu_funct(op);
                let imm = if matches!(op, AluOp::Sll | AluOp::Srl | AluOp::Sra) { (imm & 31) | f7 << 5 } else { imm };
                i_type(imm, rs1, f3, rd, OP_ALUI)
            }
            Instr::AluReg { op, rd, rs1, rs2 } => { let (f3, f7) = alu_funct(op); f7 << 25 | rs2 << 20 | rs1 << 15 | f3 << 12 | rd << 7 | OP_ALU }
            Instr::Ecall => OP_SYSTEM,
        }
    }

    pub fn decode(w: u32) -> Result<Instr, DecodeError> {
        let op = w & 0x7f; let rd = bits(w, 11, 7); let f3 = bits(w, 14, 12); let rs1 = bits(w, 19, 15); let rs2 = bits(w, 24, 20); let f7 = bits(w, 31, 25);
        let imm_i = sext(bits(w, 31, 20), 12);
        Ok(match op {
            OP_LUI => Instr::Lui { rd, imm: w & 0xffff_f000 },
            OP_AUIPC => Instr::Auipc { rd, imm: w & 0xffff_f000 },
            OP_JAL => { let imm = bits(w, 31, 31) << 20 | bits(w, 19, 12) << 12 | bits(w, 20, 20) << 11 | bits(w, 30, 21) << 1; Instr::Jal { rd, imm: sext(imm, 21) } }
            OP_JALR => Instr::Jalr { rd, rs1, imm: imm_i },
            OP_BRANCH => { let imm = bits(w, 31, 31) << 12 | bits(w, 7, 7) << 11 | bits(w, 30, 25) << 5 | bits(w, 11, 8) << 1; Instr::Branch { cond: BranchCond::from_funct3(f3).ok_or(DecodeError::Funct(f3))?, rs1, rs2, imm: sext(imm, 13) } }
            OP_LOAD => { if f3 != 2 { return Err(DecodeError::Funct(f3)); } Instr::Lw { rd, rs1, imm: imm_i } }
            OP_STORE => { if f3 != 2 { return Err(DecodeError::Funct(f3)); } Instr::Sw { rs1, rs2, imm: sext(bits(w, 31, 25) << 5 | bits(w, 11, 7), 12) } }
            OP_ALUI => {
                let shift = matches!(f3, 1 | 5);
                let op = alu_from_funct(f3, if shift { f7 } else { 0 }, true)?;
                let imm = if shift { if f7 != 0 && f7 != 0x20 { return Err(DecodeError::Shamt(f7)); } rs2 } else { imm_i };
                Instr::AluImm { op, rd, rs1, imm }
            }
            OP_ALU => Instr::AluReg { op: alu_from_funct(f3, f7, false)?, rd, rs1, rs2 },
            OP_SYSTEM if w == OP_SYSTEM => Instr::Ecall,
            _ => return Err(DecodeError::Opcode(op)),
        })
    }

    pub fn decoded(&self) -> Decoded {
        let mut d = Decoded::default();
        let wr = |rd: u32| (rd != 0) as u32;
        match *self {
            Instr::Lui { rd, imm } => { d.rd = rd; d.imm = imm; d.is_lui = 1; d.writes_rd = wr(rd); }
            Instr::Auipc { rd, imm } => { d.rd = rd; d.imm = imm; d.is_auipc = 1; d.writes_rd = wr(rd); }
            Instr::Jal { rd, imm } => { d.rd = rd; d.imm = imm; d.is_jal = 1; d.writes_rd = wr(rd); }
            Instr::Jalr { rd, rs1, imm } => { d.rd = rd; d.rs1 = rs1; d.imm = imm; d.is_jalr = 1; d.is_imm = 1; d.writes_rd = wr(rd); }
            Instr::Branch { cond, rs1, rs2, imm } => { d.rs1 = rs1; d.rs2 = rs2; d.imm = imm; d.is_branch = 1; d.br_op = cond.alu_op().code(); d.br_neg = cond.negate() as u32; }
            Instr::Lw { rd, rs1, imm } => { d.rd = rd; d.rs1 = rs1; d.imm = imm; d.is_load = 1; d.is_imm = 1; d.writes_rd = wr(rd); }
            Instr::Sw { rs1, rs2, imm } => { d.rs1 = rs1; d.rs2 = rs2; d.imm = imm; d.is_store = 1; d.is_imm = 1; }
            Instr::AluImm { op, rd, rs1, imm } => { d.rd = rd; d.rs1 = rs1; d.imm = imm; d.is_alu = 1; d.alu_op = op.code(); d.is_imm = 1; d.writes_rd = wr(rd); }
            Instr::AluReg { op, rd, rs1, rs2 } => { d.rd = rd; d.rs1 = rs1; d.rs2 = rs2; d.is_alu = 1; d.alu_op = op.code(); d.writes_rd = wr(rd); }
            Instr::Ecall => { d.rs1 = REG_A7; d.rs2 = REG_A0; d.rd = REG_A0; d.is_ecall = 1; }
        }
        d
    }
}

/// The PROGRAM bus message minus `pc`. Every field is a small non-negative
/// integer; booleans are 0/1.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Decoded {
    pub rd: u32, pub rs1: u32, pub rs2: u32, pub imm: u32,
    pub is_alu: u32, pub alu_op: u32, pub is_imm: u32,
    pub is_branch: u32, pub br_op: u32, pub br_neg: u32,
    pub is_load: u32, pub is_store: u32, pub is_jal: u32, pub is_jalr: u32,
    pub is_lui: u32, pub is_auipc: u32, pub is_ecall: u32, pub writes_rd: u32,
}
impl Decoded {
    pub const NUM_FIELDS: usize = 18;
    pub fn to_fields(&self) -> [u32; 18] {
        [self.rd, self.rs1, self.rs2, self.imm, self.is_alu, self.alu_op, self.is_imm, self.is_branch, self.br_op, self.br_neg,
         self.is_load, self.is_store, self.is_jal, self.is_jalr, self.is_lui, self.is_auipc, self.is_ecall, self.writes_rd]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program { pub base_pc: u32, pub words: Vec<u32> }
impl Program {
    pub fn new(base_pc: u32, words: Vec<u32>) -> Self { assert_eq!(base_pc % 4, 0); Self { base_pc, words } }
    pub fn len(&self) -> usize { self.words.len() }
    pub fn is_empty(&self) -> bool { self.words.is_empty() }
    pub fn pc_of(&self, index: usize) -> u32 { self.base_pc + 4 * index as u32 }
    pub fn instr_at(&self, pc: u32) -> Option<Instr> {
        if pc < self.base_pc || pc % 4 != 0 { return None; }
        self.words.get(((pc - self.base_pc) / 4) as usize).and_then(|w| Instr::decode(*w).ok())
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cd research && cargo test --test isa`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add research/src/isa.rs research/tests/isa.rs
git commit -m "research: RV32I subset, encoding, pre-decoded selectors"
```

---

### Task 3: Assembler and guest programs

**Files:**
- Create: `research/src/asm.rs`, `research/src/guests.rs`
- Test: `research/tests/asm.rs`

**Interfaces:**
- Consumes: `isa::{Instr, AluOp, BranchCond, Program, REG_*, SYS_*}`
- Produces:
  - `asm::Assembler` with `new(base_pc: u32)`, `label(&mut self, name: &str)`, `push(&mut self, i: Instr)`, `branch(&mut self, cond, rs1, rs2, label: &str)`, `jal(&mut self, rd, label: &str)`, `assemble(self) -> Program`
  - `asm::ops` module of helpers returning `Instr`: `addi(rd, rs1, imm: i32)`, `li(rd, imm: i32) -> Vec<Instr>` (LUI+ADDI), `add, sub, and, or, xor, sll, srl, sra, slt, sltu(rd, rs1, rs2)`, `andi, ori, xori, slli, srli, srai, slti, sltiu(rd, rs1, imm: i32)`, `lw(rd, rs1, off: i32)`, `sw(rs1, rs2, off: i32)`, `lui(rd, imm)`, `auipc(rd, imm)`, `jalr(rd, rs1, off: i32)`, `ecall()`, `halt() -> Vec<Instr>` (`li a7, 0; ecall`), `write_output(slot: u32, reg: u32) -> Vec<Instr>` (`li a7,1; li a0,slot; mv a1,reg; ecall`), `read_input(idx: u32) -> Vec<Instr>` (`li a7,2; li a0,idx; ecall` → result in a0)
  - `guests::{fib(n: u32) -> Program, memcpy(n: u32) -> Program, bubble_sort(values: &[u32]) -> Program, balance_check(threshold: u32) -> Program, all() -> Vec<(&'static str, Program, Vec<u32>)>`

- [ ] **Step 1: Write the failing tests**

```rust
// research/tests/asm.rs
use rand_zkvm::asm::{ops::*, Assembler};
use rand_zkvm::guests;
use rand_zkvm::isa::*;

#[test]
fn labels_resolve_to_relative_offsets() {
    let mut a = Assembler::new(0);
    a.push(addi(1, 0, 3));          // 0x00
    a.label("loop");                // 0x04
    a.push(addi(1, 1, -1));         // 0x04
    a.branch(BranchCond::Ne, 1, 0, "loop"); // 0x08 -> -4
    a.jal(0, "end");                // 0x0c -> +8
    a.push(addi(2, 0, 99));         // 0x10 (skipped)
    a.label("end");                 // 0x14
    for i in halt() { a.push(i); }
    let p = a.assemble();
    assert_eq!(p.instr_at(8), Some(Instr::Branch { cond: BranchCond::Ne, rs1: 1, rs2: 0, imm: (-4i32) as u32 }));
    assert_eq!(p.instr_at(12), Some(Instr::Jal { rd: 0, imm: 8 }));
}

#[test]
fn li_handles_negative_and_large_values() {
    // li expands to lui+addi; check by decoding and simulating the two steps
    for v in [0i32, 1, -1, 2047, 2048, -2048, -2049, 0x7fff_ffff, i32::MIN, 0x1234_5678] {
        let seq = li(5, v);
        let mut acc: u32 = 0;
        for i in seq {
            match i {
                Instr::Lui { imm, .. } => acc = imm,
                Instr::AluImm { op: AluOp::Add, imm, rs1, .. } => { if rs1 == 0 { acc = imm } else { acc = acc.wrapping_add(imm) } }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(acc, v as u32, "li {v}");
    }
}

#[test]
fn every_guest_decodes() {
    for (name, p, _inputs) in guests::all() {
        for (i, w) in p.words.iter().enumerate() {
            Instr::decode(*w).unwrap_or_else(|e| panic!("{name} word {i}: {e:?}"));
        }
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd research && cargo test --test asm`
Expected: compile error, `asm`/`guests` items missing.

- [ ] **Step 3: Implement the assembler**

```rust
// research/src/asm.rs
//! A small assembler so guests can be written in Rust source without a RISC-V toolchain.
use crate::isa::*;
use std::collections::HashMap;

enum Item { Instr(Instr), Branch { cond: BranchCond, rs1: u32, rs2: u32, label: String }, Jal { rd: u32, label: String } }

pub struct Assembler { base_pc: u32, items: Vec<Item>, labels: HashMap<String, usize> }

impl Assembler {
    pub fn new(base_pc: u32) -> Self { Self { base_pc, items: Vec::new(), labels: HashMap::new() } }
    pub fn label(&mut self, name: &str) { assert!(self.labels.insert(name.to_string(), self.items.len()).is_none(), "duplicate label {name}"); }
    pub fn push(&mut self, i: Instr) { self.items.push(Item::Instr(i)); }
    pub fn extend(&mut self, is: impl IntoIterator<Item = Instr>) { for i in is { self.push(i); } }
    pub fn branch(&mut self, cond: BranchCond, rs1: u32, rs2: u32, label: &str) { self.items.push(Item::Branch { cond, rs1, rs2, label: label.into() }); }
    pub fn jal(&mut self, rd: u32, label: &str) { self.items.push(Item::Jal { rd, label: label.into() }); }
    pub fn assemble(self) -> Program {
        let target = |label: &str, from: usize| -> u32 {
            let to = *self.labels.get(label).unwrap_or_else(|| panic!("unknown label {label}"));
            ((to as i64 - from as i64) * 4) as i32 as u32
        };
        let words = self.items.iter().enumerate().map(|(i, it)| match it {
            Item::Instr(x) => x.encode(),
            Item::Branch { cond, rs1, rs2, label } => Instr::Branch { cond: *cond, rs1: *rs1, rs2: *rs2, imm: target(label, i) }.encode(),
            Item::Jal { rd, label } => Instr::Jal { rd: *rd, imm: target(label, i) }.encode(),
        }).collect();
        Program::new(self.base_pc, words)
    }
}

/// Mnemonic helpers. Immediates are `i32` for readability and stored sign-extended.
pub mod ops {
    use crate::isa::*;
    fn imm(i: i32) -> u32 { i as u32 }
    pub fn addi(rd: u32, rs1: u32, i: i32) -> Instr { Instr::AluImm { op: AluOp::Add, rd, rs1, imm: imm(i) } }
    pub fn andi(rd: u32, rs1: u32, i: i32) -> Instr { Instr::AluImm { op: AluOp::And, rd, rs1, imm: imm(i) } }
    pub fn ori(rd: u32, rs1: u32, i: i32) -> Instr { Instr::AluImm { op: AluOp::Or, rd, rs1, imm: imm(i) } }
    pub fn xori(rd: u32, rs1: u32, i: i32) -> Instr { Instr::AluImm { op: AluOp::Xor, rd, rs1, imm: imm(i) } }
    pub fn slti(rd: u32, rs1: u32, i: i32) -> Instr { Instr::AluImm { op: AluOp::Slt, rd, rs1, imm: imm(i) } }
    pub fn sltiu(rd: u32, rs1: u32, i: i32) -> Instr { Instr::AluImm { op: AluOp::Sltu, rd, rs1, imm: imm(i) } }
    pub fn slli(rd: u32, rs1: u32, sh: u32) -> Instr { Instr::AluImm { op: AluOp::Sll, rd, rs1, imm: sh & 31 } }
    pub fn srli(rd: u32, rs1: u32, sh: u32) -> Instr { Instr::AluImm { op: AluOp::Srl, rd, rs1, imm: sh & 31 } }
    pub fn srai(rd: u32, rs1: u32, sh: u32) -> Instr { Instr::AluImm { op: AluOp::Sra, rd, rs1, imm: sh & 31 } }
    macro_rules! rrr { ($($name:ident => $op:ident),*) => { $( pub fn $name(rd: u32, rs1: u32, rs2: u32) -> Instr { Instr::AluReg { op: AluOp::$op, rd, rs1, rs2 } } )* } }
    rrr!(add => Add, sub => Sub, and => And, or => Or, xor => Xor, sll => Sll, srl => Srl, sra => Sra, slt => Slt, sltu => Sltu);
    pub fn lw(rd: u32, rs1: u32, off: i32) -> Instr { Instr::Lw { rd, rs1, imm: imm(off) } }
    pub fn sw(rs1: u32, rs2: u32, off: i32) -> Instr { Instr::Sw { rs1, rs2, imm: imm(off) } }
    pub fn lui(rd: u32, upper: u32) -> Instr { Instr::Lui { rd, imm: upper & 0xffff_f000 } }
    pub fn auipc(rd: u32, upper: u32) -> Instr { Instr::Auipc { rd, imm: upper & 0xffff_f000 } }
    pub fn jalr(rd: u32, rs1: u32, off: i32) -> Instr { Instr::Jalr { rd, rs1, imm: imm(off) } }
    pub fn ecall() -> Instr { Instr::Ecall }
    pub fn mv(rd: u32, rs: u32) -> Instr { addi(rd, rs, 0) }
    /// Load a 32-bit constant: `lui` + `addi` when needed.
    pub fn li(rd: u32, v: i32) -> Vec<Instr> {
        if (-2048..=2047).contains(&v) { return vec![addi(rd, 0, v)]; }
        let v = v as u32;
        let lo = ((v & 0xfff) as i32) << 20 >> 20;           // sign-extended low 12
        let hi = v.wrapping_sub(lo as u32) & 0xffff_f000;     // upper 20 compensating for negative lo
        if lo == 0 { vec![lui(rd, hi)] } else { vec![lui(rd, hi), addi(rd, rd, lo)] }
    }
    pub fn halt() -> Vec<Instr> { let mut v = li(REG_A7, SYS_HALT as i32); v.push(ecall()); v }
    pub fn write_output(slot: u32, reg: u32) -> Vec<Instr> {
        let mut v = li(REG_A7, SYS_WRITE_OUTPUT as i32); v.extend(li(REG_A0, slot as i32)); v.push(mv(REG_A1, reg)); v.push(ecall()); v
    }
    /// Result lands in a0.
    pub fn read_input(idx: u32) -> Vec<Instr> { let mut v = li(REG_A7, SYS_READ_INPUT as i32); v.extend(li(REG_A0, idx as i32)); v.push(ecall()); v }
}
```

- [ ] **Step 4: Implement the guests**

```rust
// research/src/guests.rs
//! Guest programs shared by tests and the demo. Registers: t0..t6 = x5..x7,x28..x31; s0.. = x8..
use crate::asm::{ops::*, Assembler};
use crate::isa::*;

const T0: u32 = 5; const T1: u32 = 6; const T2: u32 = 7; const T3: u32 = 28; const T4: u32 = 29; const T5: u32 = 30;
const HEAP: i32 = 0x1000; // data lives above the code

/// out0 = fib(n) mod 2^32, computed with a counted loop.
pub fn fib(n: u32) -> Program {
    let mut a = Assembler::new(0);
    a.extend(li(T0, 0));            // f0
    a.extend(li(T1, 1));            // f1
    a.extend(li(T2, n as i32));     // counter
    a.label("loop");
    a.branch(BranchCond::Eq, T2, 0, "done");
    a.push(add(T3, T0, T1));
    a.push(mv(T0, T1));
    a.push(mv(T1, T3));
    a.push(addi(T2, T2, -1));
    a.jal(0, "loop");
    a.label("done");
    a.extend(write_output(0, T0));
    a.extend(halt());
    a.assemble()
}

/// Writes 1..=n to HEAP, copies to HEAP+4n, outputs the sum of the copy.
pub fn memcpy(n: u32) -> Program {
    let mut a = Assembler::new(0);
    a.extend(li(T0, HEAP)); a.extend(li(T1, HEAP + 4 * n as i32)); a.extend(li(T2, n as i32)); a.extend(li(T3, 1));
    a.label("fill");
    a.branch(BranchCond::Eq, T2, 0, "copy_setup");
    a.push(sw(T0, T3, 0)); a.push(addi(T0, T0, 4)); a.push(addi(T3, T3, 1)); a.push(addi(T2, T2, -1));
    a.jal(0, "fill");
    a.label("copy_setup");
    a.extend(li(T0, HEAP)); a.extend(li(T2, n as i32)); a.extend(li(T5, 0));
    a.label("copy");
    a.branch(BranchCond::Eq, T2, 0, "done");
    a.push(lw(T4, T0, 0)); a.push(sw(T1, T4, 0)); a.push(lw(T4, T1, 0)); a.push(add(T5, T5, T4));
    a.push(addi(T0, T0, 4)); a.push(addi(T1, T1, 4)); a.push(addi(T2, T2, -1));
    a.jal(0, "copy");
    a.label("done");
    a.extend(write_output(0, T5));
    a.extend(halt());
    a.assemble()
}

/// Stores `values` at HEAP, bubble-sorts them in place (unsigned), outputs min and max.
pub fn bubble_sort(values: &[u32]) -> Program {
    let n = values.len() as i32;
    let mut a = Assembler::new(0);
    for (i, v) in values.iter().enumerate() {
        a.extend(li(T0, *v as i32)); a.extend(li(T1, HEAP + 4 * i as i32)); a.push(sw(T1, T0, 0));
    }
    a.extend(li(T4, n - 1));                       // outer count
    a.label("outer");
    a.branch(BranchCond::Eq, T4, 0, "done");
    a.extend(li(T0, HEAP)); a.push(mv(T5, T4));    // inner count
    a.label("inner");
    a.branch(BranchCond::Eq, T5, 0, "outer_next");
    a.push(lw(T1, T0, 0)); a.push(lw(T2, T0, 4));
    a.push(sltu(T3, T2, T1));                      // T3 = a[i+1] < a[i]
    a.branch(BranchCond::Eq, T3, 0, "no_swap");
    a.push(sw(T0, T2, 0)); a.push(sw(T0, T1, 4));
    a.label("no_swap");
    a.push(addi(T0, T0, 4)); a.push(addi(T5, T5, -1));
    a.jal(0, "inner");
    a.label("outer_next");
    a.push(addi(T4, T4, -1));
    a.jal(0, "outer");
    a.label("done");
    a.extend(li(T0, HEAP)); a.push(lw(T1, T0, 0)); a.push(lw(T2, T0, 4 * (n - 1)));
    a.extend(write_output(0, T1)); a.extend(write_output(1, T2));
    a.extend(halt());
    a.assemble()
}

/// The confidential-computation demo: reads private inputs 0..3 (balances),
/// sums them, and outputs only whether the sum ≥ `threshold` (1) or not (0).
pub fn balance_check(threshold: u32) -> Program {
    let mut a = Assembler::new(0);
    a.extend(li(T5, 0));
    for idx in 0..4 {
        a.extend(read_input(idx));
        a.push(add(T5, T5, REG_A0));
    }
    a.extend(li(T0, threshold as i32));
    a.push(sltu(T1, T5, T0));       // T1 = sum < threshold
    a.push(xori(T1, T1, 1));        // T1 = sum >= threshold
    a.extend(write_output(0, T1));
    a.extend(halt());
    a.assemble()
}

/// (name, program, private inputs)
pub fn all() -> Vec<(&'static str, Program, Vec<u32>)> {
    vec![
        ("fib(20)", fib(20), vec![]),
        ("memcpy(8)", memcpy(8), vec![]),
        ("bubble_sort", bubble_sort(&[9, 3, 0xffff_fff0, 1, 7, 3]), vec![]),
        ("balance_check", balance_check(1000), vec![400, 250, 300, 75]),
    ]
}
```

- [ ] **Step 5: Run tests**

Run: `cd research && cargo test --test asm`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add research/src/asm.rs research/src/guests.rs research/tests/asm.rs
git commit -m "research: assembler with labels and the four guest programs"
```

---

### Task 4: Emulator and event recorder

**Files:**
- Create: `research/src/emulator.rs`
- Test: `research/tests/emulator.rs`

**Interfaces:**
- Consumes: `isa::*`
- Produces:
  ```rust
  pub struct MemAccess { pub space: u32, pub addr: u32, pub slot: u32, pub value: u32, pub is_write: bool }
  pub struct AluEvent { pub op: AluOp, pub a: u32, pub b: u32, pub c: u32 }
  pub enum Syscall { Halt, WriteOutput { slot: u32, word: u32 }, ReadInput { idx: u32, word: u32 } }
  pub struct CycleEvent {
      pub clk: u32, pub pc: u32, pub next_pc: u32, pub instr: Instr, pub dec: Decoded,
      pub a: u32, pub b: u32, pub c: u32, pub alu_out: u32, pub tgt: u32, pub mem_addr: u32, pub mem_val: u32,
      pub sys: Option<Syscall>, pub accesses: Vec<MemAccess>, pub alu: Vec<AluEvent>,
  }
  pub struct Execution { pub events: Vec<CycleEvent>, pub outputs: [u32; NUM_OUTPUTS], pub halted: bool }
  pub enum ExecError { OutOfCycles(usize), BadPc(u32), Misaligned(u32), BadSyscall(u32), OutputSlot(u32), DoubleWrite(u32), InputIndex(u32) }
  pub fn execute(program: &Program, inputs: &[u32], max_cycles: usize) -> Result<Execution, ExecError>
  pub const SLOT_R1: u32 = 0; SLOT_R2 = 1; SLOT_MEM = 2; SLOT_W = 3;   // ts = 4*clk + slot
  pub const SPACE_REG: u32 = 0; SPACE_RAM = 1;
  impl MemAccess { pub fn ts(&self, clk: u32) -> u32 }
  ```
  Semantics that the CPU AIR relies on, per cycle: `a` = value of `rs1`, `b` = value of `rs2` (both always read, slots 0 and 1), `alu_out` = slot-1 ALU result (`op1` on `a`, `b_eff`), `tgt` = `pc + imm` mod 2^32 (slot-2 ALU add) on branch/jal/auipc rows and 0 otherwise, `mem_addr` = word address (`(a+imm)/4`) on load/store, `11` on ecall, `mem_val` = loaded/stored word or the value of `a1` on ecall, `c` = value written to `rd` (defined even when nothing is written). Every access is appended in slot order. ALU events are appended in slot order (slot 1 first).

- [ ] **Step 1: Write the failing tests**

```rust
// research/tests/emulator.rs
use rand_zkvm::emulator::*;
use rand_zkvm::guests;
use rand_zkvm::asm::{ops::*, Assembler};
use rand_zkvm::isa::*;

fn run(p: &Program, inputs: &[u32]) -> Execution { execute(p, inputs, 1 << 16).unwrap() }

#[test]
fn fib_outputs_the_right_number() {
    let e = run(&guests::fib(20), &[]);
    assert!(e.halted);
    assert_eq!(e.outputs[0], 6765);
    assert_eq!(e.outputs[1..], [0; 7]);
}

#[test]
fn memcpy_and_sort() {
    assert_eq!(run(&guests::memcpy(8), &[]).outputs[0], 36);
    let e = run(&guests::bubble_sort(&[9, 3, 0xffff_fff0, 1, 7, 3]), &[]);
    assert_eq!((e.outputs[0], e.outputs[1]), (1, 0xffff_fff0));
}

#[test]
fn balance_check_reads_private_inputs() {
    assert_eq!(run(&guests::balance_check(1000), &[400, 250, 300, 75]).outputs[0], 1);
    assert_eq!(run(&guests::balance_check(1000), &[1, 2, 3, 4]).outputs[0], 0);
}

#[test]
fn events_carry_what_the_cpu_table_needs() {
    // addi t0, x0, 7 ; sw x0(0x100) <- t0 ; lw t1, 0x100(x0) ; halt
    let mut a = Assembler::new(0);
    a.push(addi(5, 0, 7)); a.push(sw(0, 5, 0x100)); a.push(lw(6, 0, 0x100)); a.extend(halt());
    let e = run(&a.assemble(), &[]);
    let ev = &e.events[0];
    assert_eq!((ev.pc, ev.next_pc, ev.a, ev.c, ev.alu_out), (0, 4, 0, 7, 7));
    assert_eq!(ev.accesses.len(), 3, "rs1 read, rs2 read, rd write");
    assert_eq!(ev.accesses[2], MemAccess { space: SPACE_REG, addr: 5, slot: SLOT_W, value: 7, is_write: true });
    assert_eq!(ev.alu, vec![AluEvent { op: AluOp::Add, a: 0, b: 7, c: 7 }]);
    let ev = &e.events[1];
    assert_eq!((ev.mem_addr, ev.mem_val), (0x40, 7));
    assert_eq!(ev.accesses[2], MemAccess { space: SPACE_RAM, addr: 0x40, slot: SLOT_MEM, value: 7, is_write: true });
    assert_eq!(ev.accesses.len(), 3, "no rd write for sw");
    let ev = &e.events[2];
    assert_eq!((ev.mem_addr, ev.mem_val, ev.c), (0x40, 7, 7));
    let last = e.events.last().unwrap();
    assert_eq!(last.sys, Some(Syscall::Halt));
    assert_eq!(last.mem_addr, 11);
    assert_eq!(last.accesses.len(), 3, "a7 read, a0 read, a1 read via mem slot");
}

#[test]
fn errors_are_reported() {
    let mut a = Assembler::new(0); a.push(lw(6, 0, 2)); a.extend(halt());
    assert_eq!(execute(&a.assemble(), &[], 100).unwrap_err(), ExecError::Misaligned(2));
    let mut a = Assembler::new(0); a.push(addi(0, 0, 0));
    assert_eq!(execute(&a.assemble(), &[], 100).unwrap_err(), ExecError::BadPc(4));
    let mut a = Assembler::new(0); a.label("l"); a.jal(0, "l");
    assert_eq!(execute(&a.assemble(), &[], 10).unwrap_err(), ExecError::OutOfCycles(10));
    let mut a = Assembler::new(0); a.extend(write_output(0, 5)); a.extend(write_output(0, 5)); a.extend(halt());
    assert_eq!(execute(&a.assemble(), &[], 100).unwrap_err(), ExecError::DoubleWrite(0));
}

#[test]
fn branch_and_shift_sign_edge_cases() {
    // t0 = -1; t1 = 1; bge t0,t1 -> not taken (signed); bgeu t0,t1 -> taken; sra t2 = t0 >> 4 = -1
    let mut a = Assembler::new(0);
    a.extend(li(5, -1)); a.extend(li(6, 1));
    a.branch(BranchCond::Ge, 5, 6, "wrong");
    a.branch(BranchCond::Geu, 5, 6, "ok");
    a.label("wrong"); a.extend(li(7, 99)); a.jal(0, "end");
    a.label("ok"); a.push(srai(7, 5, 4));
    a.label("end"); a.extend(write_output(0, 7)); a.extend(halt());
    assert_eq!(run(&a.assemble(), &[]).outputs[0], 0xffff_ffff);
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd research && cargo test --test emulator`
Expected: compile error, `emulator` items missing.

- [ ] **Step 3: Implement the emulator**

```rust
// research/src/emulator.rs
//! Native executor that records exactly the events the tables need. Also the
//! reference semantics: if the emulator and the AIR disagree, the AIR is wrong.
use crate::isa::*;
use std::collections::HashMap;

pub const SLOT_R1: u32 = 0; pub const SLOT_R2: u32 = 1; pub const SLOT_MEM: u32 = 2; pub const SLOT_W: u32 = 3;
pub const SPACE_REG: u32 = 0; pub const SPACE_RAM: u32 = 1;
/// Register `a1` is read through the memory slot on ecall rows.
pub const ECALL_MEM_REG: u32 = REG_A1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemAccess { pub space: u32, pub addr: u32, pub slot: u32, pub value: u32, pub is_write: bool }
impl MemAccess { pub fn ts(&self, clk: u32) -> u32 { 4 * clk + self.slot } }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AluEvent { pub op: AluOp, pub a: u32, pub b: u32, pub c: u32 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Syscall { Halt, WriteOutput { slot: u32, word: u32 }, ReadInput { idx: u32, word: u32 } }

#[derive(Clone, Debug)]
pub struct CycleEvent {
    pub clk: u32, pub pc: u32, pub next_pc: u32, pub instr: Instr, pub dec: Decoded,
    pub a: u32, pub b: u32, pub c: u32, pub alu_out: u32, pub tgt: u32, pub mem_addr: u32, pub mem_val: u32,
    pub sys: Option<Syscall>, pub accesses: Vec<MemAccess>, pub alu: Vec<AluEvent>,
}

#[derive(Clone, Debug)]
pub struct Execution { pub events: Vec<CycleEvent>, pub outputs: [u32; NUM_OUTPUTS], pub halted: bool }
impl Execution { pub fn cycles(&self) -> usize { self.events.len() } }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecError { OutOfCycles(usize), BadPc(u32), Misaligned(u32), BadSyscall(u32), OutputSlot(u32), DoubleWrite(u32), InputIndex(u32) }

pub fn execute(program: &Program, inputs: &[u32], max_cycles: usize) -> Result<Execution, ExecError> {
    let mut regs = [0u32; 32];
    let mut ram: HashMap<u32, u32> = HashMap::new(); // word address -> value; unwritten reads are 0
    let mut outputs = [0u32; NUM_OUTPUTS];
    let mut written = [false; NUM_OUTPUTS];
    let mut events = Vec::new();
    let mut pc = program.base_pc;
    for clk in 0..max_cycles as u32 {
        let instr = program.instr_at(pc).ok_or(ExecError::BadPc(pc))?;
        let dec = instr.decoded();
        let a = regs[dec.rs1 as usize];
        let b = regs[dec.rs2 as usize];
        let mut acc = vec![
            MemAccess { space: SPACE_REG, addr: dec.rs1, slot: SLOT_R1, value: a, is_write: false },
            MemAccess { space: SPACE_REG, addr: dec.rs2, slot: SLOT_R2, value: b, is_write: false },
        ];
        let mut alu = Vec::new();
        let (mut c, mut alu_out, mut tgt, mut mem_addr, mut mem_val, mut sys) = (0u32, 0u32, 0u32, 0u32, 0u32, None);
        let mut next_pc = pc.wrapping_add(4);
        let b_eff = if dec.is_imm == 1 { dec.imm } else { b };
        // slot-1 ALU
        let op1 = if dec.is_alu == 1 { Some(AluOp::from_code(dec.alu_op)) } else if dec.is_branch == 1 { Some(AluOp::from_code(dec.br_op)) } else if dec.is_load + dec.is_store + dec.is_jalr == 1 { Some(AluOp::Add) } else { None };
        if let Some(op) = op1 { alu_out = op.eval(a, b_eff); alu.push(AluEvent { op, a, b: b_eff, c: alu_out }); }
        // slot-2 ALU: pc + imm
        if dec.is_branch + dec.is_jal + dec.is_auipc == 1 { tgt = pc.wrapping_add(dec.imm); alu.push(AluEvent { op: AluOp::Add, a: pc, b: dec.imm, c: tgt }); }
        match instr {
            Instr::AluImm { .. } | Instr::AluReg { .. } => c = alu_out,
            Instr::Lui { imm, .. } => c = imm,
            Instr::Auipc { .. } => c = tgt,
            Instr::Jal { .. } => { c = pc.wrapping_add(4); next_pc = tgt; }
            Instr::Jalr { .. } => { c = pc.wrapping_add(4); next_pc = alu_out; }
            Instr::Branch { .. } => { let taken = (alu_out == 1) != (dec.br_neg == 1); if taken { next_pc = tgt; } }
            Instr::Lw { .. } => {
                if alu_out % 4 != 0 { return Err(ExecError::Misaligned(alu_out)); }
                mem_addr = alu_out / 4; mem_val = *ram.get(&mem_addr).unwrap_or(&0); c = mem_val;
                acc.push(MemAccess { space: SPACE_RAM, addr: mem_addr, slot: SLOT_MEM, value: mem_val, is_write: false });
            }
            Instr::Sw { .. } => {
                if alu_out % 4 != 0 { return Err(ExecError::Misaligned(alu_out)); }
                mem_addr = alu_out / 4; mem_val = b; ram.insert(mem_addr, b);
                acc.push(MemAccess { space: SPACE_RAM, addr: mem_addr, slot: SLOT_MEM, value: b, is_write: true });
            }
            Instr::Ecall => {
                mem_addr = ECALL_MEM_REG; mem_val = regs[ECALL_MEM_REG as usize];
                acc.push(MemAccess { space: SPACE_REG, addr: ECALL_MEM_REG, slot: SLOT_MEM, value: mem_val, is_write: false });
                let (num, arg0, arg1) = (a, b, mem_val);
                sys = Some(match num {
                    SYS_HALT => Syscall::Halt,
                    SYS_WRITE_OUTPUT => {
                        let slot = arg0 as usize;
                        if slot >= NUM_OUTPUTS { return Err(ExecError::OutputSlot(arg0)); }
                        if written[slot] { return Err(ExecError::DoubleWrite(arg0)); }
                        written[slot] = true; outputs[slot] = arg1;
                        Syscall::WriteOutput { slot: arg0, word: arg1 }
                    }
                    SYS_READ_INPUT => {
                        let word = *inputs.get(arg0 as usize).ok_or(ExecError::InputIndex(arg0))?;
                        c = word;
                        Syscall::ReadInput { idx: arg0, word }
                    }
                    other => return Err(ExecError::BadSyscall(other)),
                });
            }
        }
        let writes = dec.writes_rd == 1 || matches!(sys, Some(Syscall::ReadInput { .. }));
        if writes {
            regs[dec.rd as usize] = c;
            acc.push(MemAccess { space: SPACE_REG, addr: dec.rd, slot: SLOT_W, value: c, is_write: true });
        }
        regs[0] = 0;
        let halted = matches!(sys, Some(Syscall::Halt));
        events.push(CycleEvent { clk, pc, next_pc, instr, dec, a, b, c, alu_out, tgt, mem_addr, mem_val, sys, accesses: acc, alu });
        if halted { return Ok(Execution { events, outputs, halted: true }); }
        pc = next_pc;
    }
    Err(ExecError::OutOfCycles(max_cycles))
}
```

- [ ] **Step 4: Run tests**

Run: `cd research && cargo test --test emulator`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add research/src/emulator.rs research/tests/emulator.rs
git commit -m "research: emulator with per-cycle event recording"
```

---

### Task 5: Program table

**Files:**
- Create: `research/src/tables/program.rs`
- Test: add to `research/tests/tables.rs`

**Interfaces:**
- Consumes: `isa::{Program, Decoded}`, `emulator::CycleEvent`, `tables::{bus::PROGRAM, F, pad_height}`
- Produces:
  ```rust
  pub mod pre { pub const PC: usize = 0; pub const FIELDS: usize = 1; /* 1..=18 */ pub const VALID: usize = 19; pub const WIDTH: usize = 20; }
  pub mod col { pub const MULT: usize = 0; pub const WIDTH: usize = 1; }
  pub const MIN_HEIGHT: usize = 16;
  #[derive(Clone)] pub struct ProgramAir { pub program: Program }
  impl ProgramAir { pub fn height(&self) -> usize }            // pad_height(len + 1, MIN_HEIGHT)
  pub fn program_trace(program: &Program, events: &[CycleEvent]) -> RowMajorMatrix<F>
  pub const MESSAGE_LEN: usize = 19;                             // pc + 18 fields
  ```

- [ ] **Step 1: Write the failing test** (append to `tests/tables.rs`)

```rust
use rand_zkvm::isa::Instr;
use rand_zkvm::tables::program::{self, program_trace, ProgramAir};
use rand_zkvm::emulator::execute;
use rand_zkvm::guests;

#[test]
fn program_table_rows_are_decoded_instructions_and_fetch_counts() {
    let p = guests::fib(5);
    let air = ProgramAir { program: p.clone() };
    let pre: RowMajorMatrix<F> = <ProgramAir as BaseAir<F>>::preprocessed_trace(&air).unwrap();
    assert_eq!(pre.height(), 32);
    // row 2 is the third instruction
    let d = Instr::decode(p.words[2]).unwrap().decoded().to_fields();
    let row: Vec<F> = pre.values[2 * program::pre::WIDTH..3 * program::pre::WIDTH].to_vec();
    assert_eq!(row[program::pre::PC], F::from_u32(8));
    for (i, f) in d.iter().enumerate() { assert_eq!(row[program::pre::FIELDS + i], F::from_u32(*f), "field {i}"); }
    assert_eq!(row[program::pre::VALID], F::ONE);
    let last = pre.height() - 1;
    assert_eq!(pre.values[last * program::pre::WIDTH + program::pre::VALID], F::ZERO);
    let e = execute(&p, &[], 10_000).unwrap();
    let t = program_trace(&p, &e.events);
    let total: u64 = t.values.iter().map(|x| x.as_canonical_u64()).sum();
    assert_eq!(total as usize, e.events.len(), "every cycle fetched exactly one row");
}
```
Add `use p3_field::PrimeField64; use p3_matrix::Matrix;` at the top of the test file.

- [ ] **Step 2: Run to verify failure**

Run: `cd research && cargo test --test tables program_table`
Expected: compile error, `tables::program` missing.

- [ ] **Step 3: Implement**

```rust
// research/src/tables/program.rs
//! Preprocessed, pre-decoded program ROM. Its commitment is the code hash hc.
use super::{bus, pad_height, F};
use crate::emulator::CycleEvent;
use crate::isa::{Decoded, Instr, Program};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;
use std::collections::HashMap;

pub mod pre {
    pub const PC: usize = 0;
    pub const FIELDS: usize = 1;
    pub const VALID: usize = 1 + crate::isa::Decoded::NUM_FIELDS; // 19
    pub const WIDTH: usize = VALID + 1;                            // 20
}
pub mod col { pub const MULT: usize = 0; pub const WIDTH: usize = 1; }
pub const MIN_HEIGHT: usize = 16;
pub const MESSAGE_LEN: usize = 1 + Decoded::NUM_FIELDS;

#[derive(Clone, Debug)]
pub struct ProgramAir { pub program: Program }

impl ProgramAir {
    pub fn height(&self) -> usize { pad_height(self.program.len() + 1, MIN_HEIGHT) }
}

impl<Fld: Field> BaseAir<Fld> for ProgramAir {
    fn width(&self) -> usize { col::WIDTH }
    fn preprocessed_width(&self) -> usize { pre::WIDTH }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> {
        let h = self.height();
        let mut v = Fld::zero_vec(h * pre::WIDTH);
        for (i, w) in self.program.words.iter().enumerate() {
            let d = Instr::decode(*w).expect("program contains an undecodable word").decoded().to_fields();
            let r = i * pre::WIDTH;
            v[r + pre::PC] = Fld::from_u32(self.program.pc_of(i));
            for (j, f) in d.iter().enumerate() { v[r + pre::FIELDS + j] = Fld::from_u32(*f); }
            v[r + pre::VALID] = Fld::ONE;
        }
        Some(RowMajorMatrix::new(v, pre::WIDTH))
    }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for ProgramAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let p = b.preprocessed().clone();
        let mult = b.main().current(col::MULT).unwrap();
        let valid = p.current(pre::VALID).unwrap();
        // Padding rows can never be fetched.
        b.assert_zero(mult.into() * (AB::Expr::ONE - valid.into()));
        let msg: Vec<AB::Expr> = (0..MESSAGE_LEN).map(|i| p.current(i).unwrap().into()).collect();
        bus::PROGRAM.table_entry(b, msg, mult.into());
    }
}

/// Main column: how many times each instruction was fetched.
pub fn program_trace(program: &Program, events: &[CycleEvent]) -> RowMajorMatrix<F> {
    let air = ProgramAir { program: program.clone() };
    let h = air.height();
    let mut counts: HashMap<u32, u64> = HashMap::new();
    for e in events { *counts.entry(e.pc).or_default() += 1; }
    let mut v = F::zero_vec(h * col::WIDTH);
    for i in 0..program.len() {
        v[i * col::WIDTH + col::MULT] = F::from_u64(*counts.get(&program.pc_of(i)).unwrap_or(&0));
    }
    RowMajorMatrix::new(v, col::WIDTH)
}
```

- [ ] **Step 4: Run the test**

Run: `cd research && cargo test --test tables program_table`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add research/src/tables/program.rs research/tests/tables.rs
git commit -m "research: preprocessed program table"
```

---

### Task 6: Memory table

**Files:**
- Create: `research/src/tables/memory.rs`
- Test: add to `research/tests/tables.rs`

**Interfaces:**
- Consumes: `emulator::{CycleEvent, MemAccess}`, `tables::{bus::{MEMORY, RANGE8}, byte::ByteCounts, limbs, F}`
- Produces:
  ```rust
  pub mod col { SPACE=0, ADDR=1, TS=2, VALUE=3, IS_WRITE=4, IS_REAL=5, ADDR_CHANGED=6, DIFF_INV=7, D0=8, D1=9, D2=10, D3=11, WIDTH=12 }
  pub const KEY_SHIFT: u32 = 30;                 // key = space << 30 | addr
  #[derive(Clone, Copy, Default)] pub struct MemoryAir;
  pub fn memory_trace(events: &[CycleEvent], height: usize, counts: &mut ByteCounts) -> RowMajorMatrix<F>
  ```

- [ ] **Step 1: Write the failing tests** (append to `tests/tables.rs`)

```rust
use rand_zkvm::tables::memory::{self, memory_trace, MemoryAir};
use rand_zkvm::tables::byte::ByteCounts;

#[test]
fn memory_trace_is_sorted_and_consistent() {
    let p = guests::memcpy(4);
    let e = execute(&p, &[], 10_000).unwrap();
    let mut counts = ByteCounts::default();
    let t = memory_trace(&e.events, 1 << 12, &mut counts);
    let w = memory::col::WIDTH;
    let accesses: usize = e.events.iter().map(|c| c.accesses.len()).sum();
    let real: usize = (0..t.height()).filter(|r| t.values[r * w + memory::col::IS_REAL] == F::ONE).count();
    assert_eq!(real, accesses);
    let key = |r: usize| t.values[r * w + memory::col::SPACE].as_canonical_u64() << 30 | t.values[r * w + memory::col::ADDR].as_canonical_u64();
    let ts = |r: usize| t.values[r * w + memory::col::TS].as_canonical_u64();
    for r in 0..real - 1 {
        assert!((key(r), ts(r)) < (key(r + 1), ts(r + 1)), "row {r} not sorted");
        if key(r) == key(r + 1) && t.values[(r + 1) * w + memory::col::IS_WRITE] == F::ZERO {
            assert_eq!(t.values[r * w + memory::col::VALUE], t.values[(r + 1) * w + memory::col::VALUE], "read at row {} must see previous value", r + 1);
        }
    }
    // Δ limbs were counted: 4 range checks per real transition
    let total: u64 = counts.range.iter().sum();
    assert_eq!(total as usize, 4 * (real - 1));
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd research && cargo test --test tables memory_trace`
Expected: compile error.

- [ ] **Step 3: Implement**

```rust
// research/src/tables/memory.rs
//! Registers and RAM in one table, sorted by (space, addr, ts). Read-after-write
//! consistency is a transition constraint; the CPU's accesses reach here through
//! the MEMORY multiset bus.
use super::{bus, byte::ByteCounts, limbs, F};
use crate::emulator::CycleEvent;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

pub mod col {
    pub const SPACE: usize = 0; pub const ADDR: usize = 1; pub const TS: usize = 2; pub const VALUE: usize = 3;
    pub const IS_WRITE: usize = 4; pub const IS_REAL: usize = 5; pub const ADDR_CHANGED: usize = 6; pub const DIFF_INV: usize = 7;
    pub const D0: usize = 8; pub const D1: usize = 9; pub const D2: usize = 10; pub const D3: usize = 11;
    pub const WIDTH: usize = 12;
}
pub const KEY_SHIFT: u32 = 30;

#[derive(Clone, Copy, Debug, Default)]
pub struct MemoryAir;

impl<Fld> BaseAir<Fld> for MemoryAir { fn width(&self) -> usize { col::WIDTH } }

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for MemoryAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        use col::*;
        let m = b.main();
        let l = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let n = |i: usize| -> AB::Expr { m.next(i).unwrap().into() };
        let one = AB::Expr::ONE;
        let shift = AB::Expr::from_u64(1 << KEY_SHIFT);

        b.assert_bool(l(IS_REAL));
        b.assert_bool(l(IS_WRITE));
        b.assert_bool(l(ADDR_CHANGED));
        // A read of never-written memory returns zero.
        b.when_first_row().assert_zero(l(IS_REAL) * (one.clone() - l(IS_WRITE)) * l(VALUE));

        let key_l = l(SPACE) * shift.clone() + l(ADDR);
        let key_n = n(SPACE) * shift + n(ADDR);
        let dk = key_n - key_l;
        let both = l(IS_REAL) * n(IS_REAL);
        let delta = l(ADDR_CHANGED) * (dk.clone() - one.clone())
            + (one.clone() - l(ADDR_CHANGED)) * (n(TS) - l(TS) - one.clone());
        let delta_limbs = l(D0) + l(D1) * AB::Expr::from_u32(1 << 8) + l(D2) * AB::Expr::from_u32(1 << 16) + l(D3) * AB::Expr::from_u32(1 << 24);

        let mut t = b.when_transition();
        // padding is a suffix
        t.assert_zero((one.clone() - l(IS_REAL)) * n(IS_REAL));
        // addr_changed == (key_n != key_l)
        t.assert_zero(both.clone() * (l(ADDR_CHANGED) - dk.clone() * l(DIFF_INV)));
        t.assert_zero(both.clone() * (one.clone() - l(ADDR_CHANGED)) * dk);
        // strictly increasing (key, ts): delta ≥ 0 is enforced by the byte lookups below
        t.assert_zero(both.clone() * (delta - delta_limbs));
        // read-after-write: same address, next is a read → same value
        t.assert_zero(n(IS_REAL) * (one.clone() - l(ADDR_CHANGED)) * (one.clone() - n(IS_WRITE)) * (n(VALUE) - l(VALUE)));
        // first touch of a fresh address as a read → zero
        t.assert_zero(n(IS_REAL) * l(ADDR_CHANGED) * (one.clone() - n(IS_WRITE)) * n(VALUE));
        drop(t);

        for d in [D0, D1, D2, D3] {
            bus::RANGE8.lookup_key(b, [l(d)], Count::bounded(both.clone(), 1));
        }
        bus::MEMORY.receive(b, [l(SPACE), l(ADDR), l(TS), l(VALUE), l(IS_WRITE)], Count::bounded(l(IS_REAL), 1));
    }
}

pub fn memory_trace(events: &[CycleEvent], height: usize, counts: &mut ByteCounts) -> RowMajorMatrix<F> {
    // (key, ts, space, addr, value, is_write)
    let mut rows: Vec<(u64, u64, u32, u32, u32, bool)> = Vec::new();
    for e in events {
        for a in &e.accesses {
            rows.push((((a.space as u64) << KEY_SHIFT) | a.addr as u64, a.ts(e.clk) as u64, a.space, a.addr, a.value, a.is_write));
        }
    }
    rows.sort_by_key(|r| (r.0, r.1));
    assert!(rows.len() < height, "memory table needs at least one padding row: {} accesses, height {height}", rows.len());
    let mut v = F::zero_vec(height * col::WIDTH);
    for (i, r) in rows.iter().enumerate() {
        let base = i * col::WIDTH;
        v[base + col::SPACE] = F::from_u32(r.2);
        v[base + col::ADDR] = F::from_u32(r.3);
        v[base + col::TS] = F::from_u64(r.1);
        v[base + col::VALUE] = F::from_u32(r.4);
        v[base + col::IS_WRITE] = F::from_bool(r.5);
        v[base + col::IS_REAL] = F::ONE;
        if let Some(nx) = rows.get(i + 1) {
            let changed = nx.0 != r.0;
            let delta: u64 = if changed { nx.0 - r.0 - 1 } else {
                assert!(nx.1 > r.1, "two accesses to the same address at the same timestamp");
                if !nx.5 { assert_eq!(nx.4, r.4, "read does not match last write at key {:#x}", r.0); }
                nx.1 - r.1 - 1
            };
            if changed && !nx.5 { assert_eq!(nx.4, 0, "first read of a fresh address must be zero"); }
            v[base + col::ADDR_CHANGED] = F::from_bool(changed);
            v[base + col::DIFF_INV] = if changed { F::from_u64(nx.0 - r.0).inverse() } else { F::ZERO };
            assert!(delta < 1 << 32);
            let dl = limbs(delta as u32);
            for (j, c) in [col::D0, col::D1, col::D2, col::D3].iter().enumerate() {
                v[base + c] = dl[j];
                counts.range8((delta >> (8 * j)) as u32 & 0xff);
            }
        }
    }
    if let Some(first) = rows.first() { if !first.5 { assert_eq!(first.4, 0); } }
    RowMajorMatrix::new(v, col::WIDTH)
}
```

- [ ] **Step 4: Run the test**

Run: `cd research && cargo test --test tables memory_trace`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add research/src/tables/memory.rs research/tests/tables.rs
git commit -m "research: sorted memory table with LogUp bus"
```

---

### Task 7: ALU table

**Files:**
- Create: `research/src/tables/alu.rs`
- Test: add to `research/tests/tables.rs`

**Interfaces:**
- Consumes: `isa::AluOp`, `emulator::{CycleEvent, AluEvent}`, `tables::{bus::*, byte::ByteCounts, limbs, F}`
- Produces:
  ```rust
  pub mod col {
      // flags 0..=10 in AluOp code order
      pub const FLAG0: usize = 0; pub const A: usize = 11; pub const B: usize = 12; pub const C: usize = 13;
      pub const A0: usize = 14; pub const B0: usize = 18; pub const C0: usize = 22; pub const Q0: usize = 26; pub const S0: usize = 30; pub const T0: usize = 34;
      pub const SA: usize = 38; pub const SB: usize = 39; pub const SH: usize = 40; pub const PW: usize = 41;
      pub const CARRY0: usize = 42; pub const INV: usize = 46; pub const IS_REAL: usize = 47; pub const MULT: usize = 48; pub const WIDTH: usize = 49;
  }
  #[derive(Clone, Copy, Default)] pub struct AluAir;
  pub fn alu_trace(events: &[CycleEvent], height: usize, counts: &mut ByteCounts) -> RowMajorMatrix<F>
  pub fn fill_row(row: &mut [F], ev: &AluEvent, counts: &mut ByteCounts)   // one row, used by tests
  ```

- [ ] **Step 1: Write the failing tests** (append to `tests/tables.rs`)

```rust
use rand_zkvm::tables::alu::{self, fill_row};
use rand_zkvm::emulator::AluEvent;
use rand_zkvm::isa::AluOp;

#[test]
fn alu_rows_recompose_and_carry() {
    let mut counts = ByteCounts::default();
    let mut row = vec![F::ZERO; alu::col::WIDTH];
    fill_row(&mut row, &AluEvent { op: AluOp::Add, a: 0xffff_ffff, b: 1, c: 0 }, &mut counts);
    assert_eq!(row[alu::col::FLAG0 + AluOp::Add.code() as usize], F::ONE);
    assert_eq!(row[alu::col::C], F::ZERO);
    for i in 0..4 { assert_eq!(row[alu::col::CARRY0 + i], F::ONE, "carry {i}"); }
    let mut row = vec![F::ZERO; alu::col::WIDTH];
    fill_row(&mut row, &AluEvent { op: AluOp::Sra, a: 0x8000_0000, b: 4, c: 0xf800_0000 }, &mut counts);
    assert_eq!(row[alu::col::SA], F::ONE);
    assert_eq!(row[alu::col::SH], F::from_u32(4));
    assert_eq!(row[alu::col::PW], F::from_u32(16));
    // q = (~a) >> 4 = 0x07ff_ffff ; c = ~q
    assert_eq!(row[alu::col::Q0], F::from_u32(0xff));
    assert_eq!(row[alu::col::C0 + 3], F::from_u32(0xf8));
    let mut row = vec![F::ZERO; alu::col::WIDTH];
    fill_row(&mut row, &AluEvent { op: AluOp::Slt, a: 0xffff_ffff, b: 0, c: 1 }, &mut counts);
    assert_eq!((row[alu::col::SA], row[alu::col::SB], row[alu::col::CARRY0 + 3]), (F::ONE, F::ZERO, F::ZERO));
}

#[test]
#[should_panic(expected = "does not match")]
fn alu_fill_rejects_wrong_result() {
    let mut counts = ByteCounts::default();
    let mut row = vec![F::ZERO; alu::col::WIDTH];
    fill_row(&mut row, &AluEvent { op: AluOp::Add, a: 1, b: 1, c: 3 }, &mut counts);
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd research && cargo test --test tables alu_`
Expected: compile error.

- [ ] **Step 3: Implement**

```rust
// research/src/tables/alu.rs
//! 32-bit ALU as four byte limbs. Add/sub/compare share one adder; bitwise ops
//! and shifts go through the byte table; shifts are proved as exact integer
//! identities that cannot wrap in Goldilocks.
use super::{bus, byte::ByteCounts, limbs, F};
use crate::emulator::{AluEvent, CycleEvent};
use crate::isa::AluOp;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

pub mod col {
    pub const FLAG0: usize = 0;   // 11 flags, AluOp code order
    pub const A: usize = 11; pub const B: usize = 12; pub const C: usize = 13;
    pub const A0: usize = 14; pub const B0: usize = 18; pub const C0: usize = 22;
    pub const Q0: usize = 26;     // shift quotient / sll high word limbs
    pub const S0: usize = 30;     // compare difference / right-shift remainder limbs
    pub const T0: usize = 34;     // pw - 1 - r limbs
    pub const SA: usize = 38; pub const SB: usize = 39; pub const SH: usize = 40; pub const PW: usize = 41;
    pub const CARRY0: usize = 42; pub const INV: usize = 46; pub const IS_REAL: usize = 47; pub const MULT: usize = 48;
    pub const WIDTH: usize = 49;
}
use col::*;

#[derive(Clone, Copy, Debug, Default)]
pub struct AluAir;

impl<Fld> BaseAir<Fld> for AluAir { fn width(&self) -> usize { WIDTH } }

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for AluAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let one = AB::Expr::ONE;
        let c8 = |k: u32| AB::Expr::from_u32(1u32 << (8 * k));
        let f = |op: AluOp| v(FLAG0 + op.code() as usize);
        let (add, sub, and, or, xor, sll, srl, sra, slt, sltu, eq) = (
            f(AluOp::Add), f(AluOp::Sub), f(AluOp::And), f(AluOp::Or), f(AluOp::Xor), f(AluOp::Sll),
            f(AluOp::Srl), f(AluOp::Sra), f(AluOp::Slt), f(AluOp::Sltu), f(AluOp::Eq),
        );
        let is_real = v(IS_REAL);
        b.assert_bool(is_real.clone());
        let mut sum = AB::Expr::ZERO;
        for i in 0..AluOp::COUNT { b.assert_bool(v(FLAG0 + i)); sum += v(FLAG0 + i); }
        b.assert_eq(sum, is_real.clone());

        // limb recomposition and range checks
        let word = |base: usize| v(base) + v(base + 1) * c8(1) + v(base + 2) * c8(2) + v(base + 3) * c8(3);
        b.assert_eq(word(A0), v(A));
        b.assert_eq(word(B0), v(B));
        b.assert_eq(word(C0), v(C));
        for i in 0..4 {
            for base in [A0, B0, C0] { bus::RANGE8.lookup_key(b, [v(base + i)], Count::bounded(is_real.clone(), 1)); }
        }
        let cmp = slt.clone() + sltu.clone();
        let rshift = srl.clone() + sra.clone();
        let shift = sll.clone() + rshift.clone();
        for i in 0..4 {
            bus::RANGE8.lookup_key(b, [v(S0 + i)], Count::bounded(cmp.clone() + rshift.clone(), 1));
            bus::RANGE8.lookup_key(b, [v(T0 + i)], Count::bounded(rshift.clone(), 1));
            bus::RANGE8.lookup_key(b, [v(Q0 + i)], Count::bounded(shift.clone(), 1));
        }

        // shared adder: x + y = z (mod 2^32) with limb carries
        let adder = add.clone() + sub.clone() + cmp.clone();
        for i in 0..4 {
            let x = add.clone() * v(A0 + i) + sub.clone() * v(B0 + i) + cmp.clone() * v(B0 + i);
            let y = add.clone() * v(B0 + i) + sub.clone() * v(C0 + i) + cmp.clone() * v(S0 + i);
            let z = add.clone() * v(C0 + i) + (sub.clone() + cmp.clone()) * v(A0 + i);
            let cin = if i == 0 { AB::Expr::ZERO } else { v(CARRY0 + i - 1) };
            b.assert_bool(v(CARRY0 + i));
            b.assert_zero((one.clone() - adder.clone()) * v(CARRY0 + i));
            b.assert_zero(x + y + cin - z - v(CARRY0 + i) * AB::Expr::from_u32(256));
        }
        let borrow = v(CARRY0 + 3);
        // sign bits
        b.assert_bool(v(SA));
        b.assert_bool(v(SB));
        let c128 = AB::Expr::from_u32(128);
        bus::AND8.lookup_key(b, [v(A0 + 3), c128.clone(), v(SA) * c128.clone()], Count::bounded(slt.clone() + sra.clone(), 1));
        bus::AND8.lookup_key(b, [v(B0 + 3), c128.clone(), v(SB) * c128.clone()], Count::bounded(slt.clone(), 1));
        b.assert_zero(srl.clone() * v(SA));
        // compares
        b.assert_zero((cmp.clone() + eq.clone()) * v(C) * (v(C) - one.clone()));
        b.assert_zero(sltu.clone() * (v(C) - borrow.clone()));
        let sx = v(SA) + v(SB) - v(SA) * v(SB) * AB::Expr::TWO;
        b.assert_zero(slt.clone() * (v(C) - (one.clone() - sx.clone()) * borrow.clone() - sx * v(SA)));
        let diff = v(A) - v(B);
        b.assert_zero(eq.clone() * (diff.clone() * v(INV) + v(C) - one.clone()));
        b.assert_zero(eq.clone() * v(C) * diff);
        // bitwise
        for i in 0..4 {
            bus::AND8.lookup_key(b, [v(A0 + i), v(B0 + i), v(C0 + i)], Count::bounded(and.clone(), 1));
            bus::OR8.lookup_key(b, [v(A0 + i), v(B0 + i), v(C0 + i)], Count::bounded(or.clone(), 1));
            bus::XOR8.lookup_key(b, [v(A0 + i), v(B0 + i), v(C0 + i)], Count::bounded(xor.clone(), 1));
        }
        // shifts
        bus::AND8.lookup_key(b, [v(B0), AB::Expr::from_u32(31), v(SH)], Count::bounded(shift.clone(), 1));
        bus::POW2.lookup_key(b, [v(SH), v(PW)], Count::bounded(shift.clone(), 1));
        let q = word(Q0);
        let r = word(S0);
        let t = word(T0);
        let two32 = AB::Expr::from_u64(1 << 32);
        b.assert_zero(sll.clone() * (v(A) * v(PW) - q.clone() * two32 - v(C)));
        bus::AND8.lookup_key(b, [v(Q0 + 3), c128, AB::Expr::ZERO], Count::bounded(sll.clone(), 1));
        // right shifts: complement when negative (sra), shift, complement back
        let flip = |x: AB::Expr| x.clone() + v(SA) * (AB::Expr::from_u32(255) - x * AB::Expr::TWO);
        let a_prime = flip(v(A0)) + flip(v(A0 + 1)) * c8(1) + flip(v(A0 + 2)) * c8(2) + flip(v(A0 + 3)) * c8(3);
        b.assert_zero(rshift.clone() * (a_prime - q * v(PW) - r.clone()));
        b.assert_zero(rshift.clone() * (v(PW) - one.clone() - r - t));
        for i in 0..4 { b.assert_zero(rshift.clone() * (v(C0 + i) - flip(v(Q0 + i)))); }

        // provide (op, a, b, c)
        let mut op = AB::Expr::ZERO;
        for i in 0..AluOp::COUNT { op += v(FLAG0 + i) * AB::Expr::from_u32(i as u32); }
        bus::ALU.table_entry(b, [op, v(A), v(B), v(C)], v(MULT));
    }
}

fn set_limbs(row: &mut [F], base: usize, x: u32, counts: &mut ByteCounts, count: bool) {
    let l = limbs(x);
    for i in 0..4 { row[base + i] = l[i]; if count { counts.range8((x >> (8 * i)) & 0xff); } }
}

/// Fill one ALU row from an event and count its byte-table lookups.
pub fn fill_row(row: &mut [F], ev: &AluEvent, counts: &mut ByteCounts) {
    let AluEvent { op, a, b, c } = *ev;
    assert_eq!(c, op.eval(a, b), "ALU event {op:?}({a:#x}, {b:#x}) = {c:#x} does not match reference semantics");
    row[FLAG0 + op.code() as usize] = F::ONE;
    row[A] = F::from_u32(a); row[B] = F::from_u32(b); row[C] = F::from_u32(c);
    row[IS_REAL] = F::ONE; row[MULT] = F::ONE;
    set_limbs(row, A0, a, counts, true); set_limbs(row, B0, b, counts, true); set_limbs(row, C0, c, counts, true);
    let (a3, b3, b0) = ((a >> 24) & 0xff, (b >> 24) & 0xff, b & 0xff);
    let adder = |row: &mut [F], x: u32, y: u32| {
        // carries of x + y limb-wise
        let mut carry = 0u32;
        for i in 0..4 {
            let s = ((x >> (8 * i)) & 0xff) + ((y >> (8 * i)) & 0xff) + carry;
            carry = s >> 8;
            row[CARRY0 + i] = F::from_u32(carry);
        }
    };
    match op {
        AluOp::Add => adder(row, a, b),
        AluOp::Sub => adder(row, b, c),
        AluOp::Slt | AluOp::Sltu => {
            let d = a.wrapping_sub(b);
            set_limbs(row, S0, d, counts, true);
            adder(row, b, d);
            if op == AluOp::Slt {
                row[SA] = F::from_u32(a3 >> 7); row[SB] = F::from_u32(b3 >> 7);
                counts.and8(a3, 128); counts.and8(b3, 128);
            }
        }
        AluOp::Eq => { if a != b { row[INV] = (F::from_u32(a) - F::from_u32(b)).inverse(); } }
        AluOp::And => for i in 0..4 { counts.and8((a >> (8 * i)) & 0xff, (b >> (8 * i)) & 0xff) },
        AluOp::Or => for i in 0..4 { counts.or8((a >> (8 * i)) & 0xff, (b >> (8 * i)) & 0xff) },
        AluOp::Xor => for i in 0..4 { counts.xor8((a >> (8 * i)) & 0xff, (b >> (8 * i)) & 0xff) },
        AluOp::Sll | AluOp::Srl | AluOp::Sra => {
            let sh = b & 31; let pw = 1u32 << sh;
            row[SH] = F::from_u32(sh); row[PW] = F::from_u32(pw);
            counts.and8(b0, 31); counts.pow2(sh);
            if op == AluOp::Sll {
                let hi = ((a as u64 * pw as u64) >> 32) as u32;
                set_limbs(row, Q0, hi, counts, true);
                counts.and8((hi >> 24) & 0xff, 128);
            } else {
                let sa = if op == AluOp::Sra { a >> 31 } else { 0 };
                if op == AluOp::Sra { row[SA] = F::from_u32(sa); counts.and8(a3, 128); }
                let ap = if sa == 1 { !a } else { a };
                let q = ap >> sh; let r = ap - q * pw; let t = pw - 1 - r;
                set_limbs(row, Q0, q, counts, true); set_limbs(row, S0, r, counts, true); set_limbs(row, T0, t, counts, true);
            }
        }
    }
}

pub fn alu_trace(events: &[CycleEvent], height: usize, counts: &mut ByteCounts) -> RowMajorMatrix<F> {
    let evs: Vec<&AluEvent> = events.iter().flat_map(|e| e.alu.iter()).collect();
    assert!(evs.len() < height, "alu table needs a padding row: {} ops, height {height}", evs.len());
    let mut v = F::zero_vec(height * WIDTH);
    for (i, ev) in evs.iter().enumerate() { fill_row(&mut v[i * WIDTH..(i + 1) * WIDTH], ev, counts); }
    RowMajorMatrix::new(v, WIDTH)
}
```

- [ ] **Step 4: Run the tests**

Run: `cd research && cargo test --test tables alu_`
Expected: PASS (2 tests, one `should_panic`).

- [ ] **Step 5: Commit**

```bash
git add research/src/tables/alu.rs research/tests/tables.rs
git commit -m "research: ALU table with limb adder, byte-table bitwise ops and exact shifts"
```

---

### Task 8: CPU table

**Files:**
- Create: `research/src/tables/cpu.rs`
- Test: add to `research/tests/tables.rs`

**Interfaces:**
- Consumes: `emulator::{CycleEvent, Syscall, SLOT_*, SPACE_*, ECALL_MEM_REG}`, `isa::{Decoded, SYS_*, NUM_OUTPUTS}`, `tables::{bus::{PROGRAM, MEMORY, ALU}, F}`, `tables::program::MESSAGE_LEN`
- Produces:
  ```rust
  pub mod col {
      pub const CLK: usize = 0; pub const PC: usize = 1; pub const NEXT_PC: usize = 2; pub const IS_REAL: usize = 3;
      pub const DEC0: usize = 4;   // 18 decoded fields, Decoded::to_fields order; DEC0 + k
      pub const RD: usize = 4; pub const RS1: usize = 5; pub const RS2: usize = 6; pub const IMM: usize = 7;
      pub const IS_ALU: usize = 8; pub const ALU_OP: usize = 9; pub const IS_IMM: usize = 10; pub const IS_BRANCH: usize = 11;
      pub const BR_OP: usize = 12; pub const BR_NEG: usize = 13; pub const IS_LOAD: usize = 14; pub const IS_STORE: usize = 15;
      pub const IS_JAL: usize = 16; pub const IS_JALR: usize = 17; pub const IS_LUI: usize = 18; pub const IS_AUIPC: usize = 19;
      pub const IS_ECALL: usize = 20; pub const WRITES_RD: usize = 21;
      pub const A: usize = 22; pub const B: usize = 23; pub const C: usize = 24; pub const ALU_OUT: usize = 25; pub const TGT: usize = 26;
      pub const MEM_ADDR: usize = 27; pub const MEM_VAL: usize = 28;
      pub const SYS_HALT: usize = 29; pub const SYS_WRITE: usize = 30; pub const SYS_READ: usize = 31;
      pub const OUT_SEL0: usize = 32; pub const WIDTH: usize = 40;
  }
  pub mod pv { pub const PC_ENTRY: usize = 0; pub const TIER: usize = 1; pub const OUT0: usize = 2; pub const NUM: usize = 10; }
  #[derive(Clone, Copy, Default)] pub struct CpuAir;
  pub fn public_values(pc_entry: u32, tier_log2: usize, outputs: &[u32; 8]) -> Vec<F>
  pub fn cpu_trace(events: &[CycleEvent], height: usize) -> RowMajorMatrix<F>
  ```

- [ ] **Step 1: Write the failing test** (append to `tests/tables.rs`)

```rust
use rand_zkvm::tables::cpu::{self, cpu_trace, public_values};

#[test]
fn cpu_trace_mirrors_events_and_pads() {
    let p = guests::fib(3);
    let e = execute(&p, &[], 10_000).unwrap();
    let t = cpu_trace(&e.events, 64);
    let w = cpu::col::WIDTH;
    assert_eq!(t.height(), 64);
    for (i, ev) in e.events.iter().enumerate() {
        let r = &t.values[i * w..(i + 1) * w];
        assert_eq!(r[cpu::col::CLK], F::from_u32(ev.clk));
        assert_eq!(r[cpu::col::PC], F::from_u32(ev.pc));
        assert_eq!(r[cpu::col::NEXT_PC], F::from_u32(ev.next_pc));
        assert_eq!(r[cpu::col::IS_REAL], F::ONE);
        let d = ev.dec.to_fields();
        for k in 0..18 { assert_eq!(r[cpu::col::DEC0 + k], F::from_u32(d[k])); }
        assert_eq!((r[cpu::col::A], r[cpu::col::B], r[cpu::col::C]), (F::from_u32(ev.a), F::from_u32(ev.b), F::from_u32(ev.c)));
    }
    let last_real = e.events.len() - 1;
    assert_eq!(t.values[last_real * w + cpu::col::SYS_HALT], F::ONE);
    let write_row = e.events.iter().position(|ev| matches!(ev.sys, Some(rand_zkvm::emulator::Syscall::WriteOutput { .. }))).unwrap();
    assert_eq!(t.values[write_row * w + cpu::col::OUT_SEL0], F::ONE);
    let pad = &t.values[(last_real + 1) * w..(last_real + 2) * w];
    assert!(pad.iter().all(|x| *x == F::ZERO));
    let pv = public_values(0, 10, &e.outputs);
    assert_eq!(pv.len(), cpu::pv::NUM);
    assert_eq!(pv[cpu::pv::OUT0], F::from_u32(2));
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd research && cargo test --test tables cpu_trace`
Expected: compile error.

- [ ] **Step 3: Implement**

```rust
// research/src/tables/cpu.rs
//! One row per cycle. Fetches from PROGRAM, reads and writes through MEMORY,
//! delegates arithmetic to ALU. The only table with public values.
use super::{bus, program::MESSAGE_LEN, F};
use crate::emulator::{CycleEvent, Syscall, ECALL_MEM_REG, SLOT_MEM, SLOT_R1, SLOT_R2, SLOT_W};
use crate::isa::{NUM_OUTPUTS, SYS_HALT, SYS_READ_INPUT, SYS_WRITE_OUTPUT};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

pub mod col {
    pub const CLK: usize = 0; pub const PC: usize = 1; pub const NEXT_PC: usize = 2; pub const IS_REAL: usize = 3;
    pub const DEC0: usize = 4;
    pub const RD: usize = 4; pub const RS1: usize = 5; pub const RS2: usize = 6; pub const IMM: usize = 7;
    pub const IS_ALU: usize = 8; pub const ALU_OP: usize = 9; pub const IS_IMM: usize = 10; pub const IS_BRANCH: usize = 11;
    pub const BR_OP: usize = 12; pub const BR_NEG: usize = 13; pub const IS_LOAD: usize = 14; pub const IS_STORE: usize = 15;
    pub const IS_JAL: usize = 16; pub const IS_JALR: usize = 17; pub const IS_LUI: usize = 18; pub const IS_AUIPC: usize = 19;
    pub const IS_ECALL: usize = 20; pub const WRITES_RD: usize = 21;
    pub const A: usize = 22; pub const B: usize = 23; pub const C: usize = 24; pub const ALU_OUT: usize = 25; pub const TGT: usize = 26;
    pub const MEM_ADDR: usize = 27; pub const MEM_VAL: usize = 28;
    pub const SYS_HALT: usize = 29; pub const SYS_WRITE: usize = 30; pub const SYS_READ: usize = 31;
    pub const OUT_SEL0: usize = 32;
    pub const WIDTH: usize = OUT_SEL0 + crate::isa::NUM_OUTPUTS; // 40
    /// Columns that must be zero on padding rows.
    pub const SELECTORS: [usize; 15] = [IS_ALU, IS_IMM, IS_BRANCH, IS_LOAD, IS_STORE, IS_JAL, IS_JALR, IS_LUI, IS_AUIPC, IS_ECALL, WRITES_RD, SYS_HALT, SYS_WRITE, SYS_READ, BR_NEG];
}
pub mod pv { pub const PC_ENTRY: usize = 0; pub const TIER: usize = 1; pub const OUT0: usize = 2; pub const NUM: usize = 2 + crate::isa::NUM_OUTPUTS; }
use col::*;

#[derive(Clone, Copy, Debug, Default)]
pub struct CpuAir;

impl<Fld> BaseAir<Fld> for CpuAir {
    fn width(&self) -> usize { WIDTH }
    fn num_public_values(&self) -> usize { pv::NUM }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for CpuAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let pvs: Vec<AB::Expr> = b.public_values().iter().map(|p| (*p).into()).collect();
        let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let n = |i: usize| -> AB::Expr { m.next(i).unwrap().into() };
        let one = AB::Expr::ONE;
        let four = AB::Expr::from_u32(4);
        let is_real = v(IS_REAL);

        b.assert_bool(is_real.clone());
        for s in SELECTORS { b.assert_bool(v(s)); b.assert_zero((one.clone() - is_real.clone()) * v(s)); }
        {
            let mut f = b.when_first_row();
            f.assert_one(v(IS_REAL));
            f.assert_zero(v(CLK));
            f.assert_eq(v(PC), pvs[pv::PC_ENTRY].clone());
        }
        b.when_last_row().assert_zero(v(IS_REAL));
        {
            let mut t = b.when_transition();
            t.assert_zero((one.clone() - is_real.clone()) * n(IS_REAL));
            t.assert_zero(n(IS_REAL) * (n(CLK) - v(CLK) - one.clone()));
            t.assert_zero(n(IS_REAL) * (n(PC) - v(NEXT_PC)));
            // the last real row is a HALT, and nothing runs after a HALT
            t.assert_zero(is_real.clone() * (one.clone() - n(IS_REAL)) * (one.clone() - v(SYS_HALT)));
            t.assert_zero(v(SYS_HALT) * n(IS_REAL));
        }

        // fetch
        let msg: Vec<AB::Expr> = std::iter::once(v(PC)).chain((0..MESSAGE_LEN - 1).map(|k| v(DEC0 + k))).collect();
        bus::PROGRAM.lookup_key(b, msg, Count::bounded(is_real.clone(), 1));

        // operand select and ALU delegation
        let b_eff = v(IS_IMM) * v(IMM) + (one.clone() - v(IS_IMM)) * v(B);
        let op1 = v(IS_ALU) * v(ALU_OP) + v(IS_BRANCH) * v(BR_OP);
        let uses_slot1 = v(IS_ALU) + v(IS_BRANCH) + v(IS_LOAD) + v(IS_STORE) + v(IS_JALR);
        bus::ALU.lookup_key(b, [op1, v(A), b_eff, v(ALU_OUT)], Count::bounded(uses_slot1, 1));
        let uses_slot2 = v(IS_BRANCH) + v(IS_JAL) + v(IS_AUIPC);
        bus::ALU.lookup_key(b, [AB::Expr::ZERO, v(PC), v(IMM), v(TGT)], Count::bounded(uses_slot2, 1));

        // rd value
        b.assert_zero(v(IS_ALU) * (v(C) - v(ALU_OUT)));
        b.assert_zero(v(IS_LOAD) * (v(C) - v(MEM_VAL)));
        b.assert_zero((v(IS_JAL) + v(IS_JALR)) * (v(C) - v(PC) - four.clone()));
        b.assert_zero(v(IS_LUI) * (v(C) - v(IMM)));
        b.assert_zero(v(IS_AUIPC) * (v(C) - v(TGT)));

        // next pc
        let taken = v(ALU_OUT) + v(BR_NEG) - v(ALU_OUT) * v(BR_NEG) * AB::Expr::TWO;
        let fallthrough = v(PC) + four.clone();
        b.assert_zero(v(IS_BRANCH) * (v(NEXT_PC) - fallthrough.clone() - taken * (v(TGT) - fallthrough.clone())));
        b.assert_zero(v(IS_JAL) * (v(NEXT_PC) - v(TGT)));
        b.assert_zero(v(IS_JALR) * (v(NEXT_PC) - v(ALU_OUT)));
        b.assert_zero(is_real.clone() * (one.clone() - v(IS_BRANCH) - v(IS_JAL) - v(IS_JALR)) * (v(NEXT_PC) - fallthrough));

        // memory
        let is_mem = v(IS_LOAD) + v(IS_STORE);
        b.assert_zero(is_mem.clone() * (v(MEM_ADDR) * four.clone() - v(ALU_OUT)));
        b.assert_zero(v(IS_ECALL) * (v(MEM_ADDR) - AB::Expr::from_u32(ECALL_MEM_REG)));
        let ts = |slot: u32| v(CLK) * four.clone() + AB::Expr::from_u32(slot);
        let zero = AB::Expr::ZERO;
        bus::MEMORY.send(b, [zero.clone(), v(RS1), ts(SLOT_R1), v(A), zero.clone()], Count::bounded(is_real.clone(), 1));
        bus::MEMORY.send(b, [zero.clone(), v(RS2), ts(SLOT_R2), v(B), zero.clone()], Count::bounded(is_real.clone(), 1));
        bus::MEMORY.send(b, [is_mem.clone(), v(MEM_ADDR), ts(SLOT_MEM), v(MEM_VAL), v(IS_STORE)], Count::bounded(is_mem + v(IS_ECALL), 1));
        bus::MEMORY.send(b, [zero.clone(), v(RD), ts(SLOT_W), v(C), one.clone()], Count::bounded(v(WRITES_RD) + v(SYS_READ), 1));

        // syscalls: a = number, b = arg0, mem_val = arg1
        let sys_sum = v(SYS_HALT) + v(SYS_WRITE) + v(SYS_READ);
        b.assert_zero(v(IS_ECALL) * (sys_sum.clone() - one.clone()));
        b.assert_zero((one.clone() - v(IS_ECALL)) * sys_sum);
        b.assert_zero(v(SYS_HALT) * (v(A) - AB::Expr::from_u32(SYS_HALT)));
        b.assert_zero(v(SYS_WRITE) * (v(A) - AB::Expr::from_u32(SYS_WRITE_OUTPUT)));
        b.assert_zero(v(SYS_READ) * (v(A) - AB::Expr::from_u32(SYS_READ_INPUT)));
        let mut sel_sum = AB::Expr::ZERO;
        for i in 0..NUM_OUTPUTS {
            let s = v(OUT_SEL0 + i);
            b.assert_bool(s.clone());
            b.assert_zero(s.clone() * (v(B) - AB::Expr::from_u32(i as u32)));
            b.assert_zero(s.clone() * (v(MEM_VAL) - pvs[pv::OUT0 + i].clone()));
            sel_sum += s;
        }
        b.assert_eq(sel_sum, v(SYS_WRITE));
    }
}

pub fn public_values(pc_entry: u32, tier_log2: usize, outputs: &[u32; NUM_OUTPUTS]) -> Vec<F> {
    let mut v = vec![F::from_u32(pc_entry), F::from_u64(tier_log2 as u64)];
    v.extend(outputs.iter().map(|o| F::from_u32(*o)));
    v
}

pub fn cpu_trace(events: &[CycleEvent], height: usize) -> RowMajorMatrix<F> {
    assert!(events.len() < height, "cpu table needs a padding row: {} cycles, height {height}", events.len());
    let mut v = F::zero_vec(height * WIDTH);
    for (i, e) in events.iter().enumerate() {
        let r = &mut v[i * WIDTH..(i + 1) * WIDTH];
        r[CLK] = F::from_u32(e.clk); r[PC] = F::from_u32(e.pc); r[NEXT_PC] = F::from_u32(e.next_pc); r[IS_REAL] = F::ONE;
        for (k, f) in e.dec.to_fields().iter().enumerate() { r[DEC0 + k] = F::from_u32(*f); }
        r[A] = F::from_u32(e.a); r[B] = F::from_u32(e.b); r[C] = F::from_u32(e.c);
        r[ALU_OUT] = F::from_u32(e.alu_out); r[TGT] = F::from_u32(e.tgt);
        r[MEM_ADDR] = F::from_u32(e.mem_addr); r[MEM_VAL] = F::from_u32(e.mem_val);
        match e.sys {
            Some(Syscall::Halt) => r[SYS_HALT] = F::ONE,
            Some(Syscall::WriteOutput { slot, .. }) => { r[SYS_WRITE] = F::ONE; r[OUT_SEL0 + slot as usize] = F::ONE; }
            Some(Syscall::ReadInput { .. }) => r[SYS_READ] = F::ONE,
            None => {}
        }
    }
    RowMajorMatrix::new(v, WIDTH)
}
```

- [ ] **Step 4: Run the test**

Run: `cd research && cargo test --test tables cpu_trace`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add research/src/tables/cpu.rs research/tests/tables.rs
git commit -m "research: CPU table"
```

---

### Task 9: Machine — tiers, chip enum, prove, verify, end-to-end and adversarial tests

**Files:**
- Modify: `research/src/machine.rs` (append to the config half from Task 1)
- Test: `research/tests/e2e.rs`, `research/tests/cheating.rs`, `research/tests/zk.rs`

**Interfaces:**
- Consumes: everything above.
- Produces:
  ```rust
  pub const TIERS: [usize; 6] = [10, 12, 14, 16, 18, 20];
  #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)] pub struct Tier(pub usize);
  impl Tier { pub fn for_cycles(cycles: usize) -> Option<Tier>; pub fn cpu_height(self) -> usize; pub fn alu_height(self) -> usize; pub fn mem_height(self) -> usize; pub fn max_cycles(self) -> usize }
  #[derive(Clone)] pub enum Chip { Program(ProgramAir), Cpu(CpuAir), Memory(MemoryAir), Alu(AluAir), Byte(ByteAir) }
  pub fn chips(program: &Program) -> Vec<Chip>          // order: Program, Cpu, Memory, Alu, Byte
  pub struct Traces { pub program: RowMajorMatrix<Val>, pub cpu: .., pub memory: .., pub alu: .., pub byte: .., pub public_values: Vec<Val> }
  impl Traces { pub fn as_slice(&self) -> [&RowMajorMatrix<Val>; 5]; pub fn heights(&self) -> [usize; 5] }
  pub fn build_traces(program: &Program, exec: &Execution, tier: Tier) -> Result<Traces, ProveError>
  #[derive(Serialize, Deserialize)] pub struct Proof { pub tier: Tier, pub public_values: Vec<u64>, pub batch: BatchProof<Config> }
  impl Proof { pub fn to_bytes(&self) -> Vec<u8>; pub fn size(&self) -> usize }
  #[derive(Debug)] pub enum ProveError { Exec(ExecError), NoTier(usize), TooManyCycles { cycles: usize, tier: Tier } }
  #[derive(Debug)] pub enum VerifyError { PublicValues, Tier, Batch(String) }
  pub struct Machine { pub config: Config, pub profile: FriProfile }
  impl Machine {
      pub fn new(profile: FriProfile) -> Self
      pub fn prove(&self, program: &Program, inputs: &[u32], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError>
      pub fn prove_traces(&self, program: &Program, traces: &Traces, tier: Tier) -> Proof
      pub fn verifier_key(&self, program: &Program, tier: Tier) -> CommonData<Config>
      pub fn code_hash(&self, program: &Program, tier: Tier) -> String     // hex of the preprocessed commitment
      pub fn verify(&self, program: &Program, proof: &Proof) -> Result<(), VerifyError>
  }
  ```

- [ ] **Step 1: Write the end-to-end test**

```rust
// research/tests/e2e.rs
use rand_zkvm::guests;
use rand_zkvm::machine::{FriProfile, Machine, Tier};

#[test]
fn every_guest_proves_and_verifies() {
    let m = Machine::new(FriProfile::Test);
    for (name, program, inputs) in guests::all() {
        let (proof, exec) = m.prove(&program, &inputs, None).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(proof.tier, Tier(10), "{name} should fit the smallest tier");
        assert_eq!(proof.public_values[2], exec.outputs[0] as u64);
        m.verify(&program, &proof).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert!(proof.size() > 0);
    }
}

#[test]
fn tier_padding_hides_cycle_count() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(5);
    let (p10, e) = m.prove(&p, &[], Some(Tier(10))).unwrap();
    let (p12, _) = m.prove(&p, &[], Some(Tier(12))).unwrap();
    assert!(e.cycles() < 100);
    m.verify(&p, &p10).unwrap();
    m.verify(&p, &p12).unwrap();
    assert_ne!(p10.batch.degree_bits, p12.batch.degree_bits);
    assert_eq!(p10.public_values[1], 10);
    assert_eq!(p12.public_values[1], 12);
}
```

- [ ] **Step 2: Write the cheating tests**

```rust
// research/tests/cheating.rs
//! Every test here builds a wrong witness and checks the verifier rejects it.
//! In debug builds Plonky3 panics inside `prove_batch` on the first violated
//! constraint; in release builds it produces a proof that fails to verify.
//! `rejects` accepts either.
use p3_field::PrimeCharacteristicRing;
use rand_zkvm::emulator::execute;
use rand_zkvm::guests;
use rand_zkvm::machine::{build_traces, FriProfile, Machine, Tier, Traces};
use rand_zkvm::tables::{cpu, F};
use std::panic::{catch_unwind, AssertUnwindSafe};

fn rejects(f: impl FnOnce() -> Result<(), rand_zkvm::machine::VerifyError>) -> bool {
    match catch_unwind(AssertUnwindSafe(f)) { Ok(Ok(())) => false, _ => true }
}

fn setup() -> (Machine, rand_zkvm::isa::Program, Traces) {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let e = execute(&p, &[], 10_000).unwrap();
    let t = build_traces(&p, &e, Tier(10)).unwrap();
    (m, p, t)
}

#[test]
fn honest_traces_pass() {
    let (m, p, t) = setup();
    let proof = m.prove_traces(&p, &t, Tier(10));
    m.verify(&p, &proof).unwrap();
}

#[test]
fn claiming_a_wrong_output_is_rejected() {
    let (m, p, mut t) = setup();
    t.public_values[cpu::pv::OUT0] = F::from_u32(56);   // fib(10) is 55
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

#[test]
fn tampering_a_register_value_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    t.cpu.values[3 * w + cpu::col::C] += F::ONE;         // row 3 writes a wrong rd
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

#[test]
fn skipping_a_cycle_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    let last = (0..t.cpu.height()).rev().find(|r| t.cpu.values[r * w + cpu::col::IS_REAL] == F::ONE).unwrap();
    // mark the row before HALT as padding: the chain of pcs breaks
    t.cpu.values[(last - 1) * w + cpu::col::IS_REAL] = F::ZERO;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

#[test]
fn proof_for_one_program_does_not_verify_another() {
    let m = Machine::new(FriProfile::Test);
    let (proof, _) = m.prove(&guests::fib(10), &[], None).unwrap();
    assert!(rejects(|| m.verify(&guests::fib(11), &proof)));
}

#[test]
fn wrong_tier_claim_is_rejected() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (mut proof, _) = m.prove(&p, &[], None).unwrap();
    proof.tier = Tier(12);
    assert!(rejects(|| m.verify(&p, &proof)));
}

#[test]
fn a_run_that_does_not_fit_the_tier_is_refused() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(300);   // ~1800 cycles > 2^10 - 1
    assert!(matches!(m.prove(&p, &[], Some(Tier(10))), Err(rand_zkvm::machine::ProveError::TooManyCycles { .. })));
    let (proof, _) = m.prove(&p, &[], None).unwrap();
    assert_eq!(proof.tier, Tier(12));
}
```

Add `use p3_matrix::Matrix;` at the top for `.height()`.

- [ ] **Step 3: Write the zero-knowledge test**

```rust
// research/tests/zk.rs
use rand_zkvm::guests;
use rand_zkvm::machine::{FriProfile, Machine};

#[test]
fn two_proofs_of_the_same_run_differ_and_both_verify() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::balance_check(1000);
    let inputs = [400, 250, 300, 75];
    let (a, _) = m.prove(&p, &inputs, None).unwrap();
    let (b, _) = m.prove(&p, &inputs, None).unwrap();
    assert_eq!(a.public_values, b.public_values);
    assert_ne!(a.to_bytes(), b.to_bytes(), "hiding commitments must randomise the proof");
    m.verify(&p, &a).unwrap();
    m.verify(&p, &b).unwrap();
}

#[test]
fn different_private_inputs_same_output_are_indistinguishable_in_public_values() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::balance_check(1000);
    let (a, _) = m.prove(&p, &[400, 250, 300, 75], None).unwrap();
    let (b, _) = m.prove(&p, &[1000, 0, 0, 0], None).unwrap();
    assert_eq!(a.public_values, b.public_values);
    assert_eq!(a.batch.degree_bits, b.batch.degree_bits);
}
```

- [ ] **Step 4: Run to verify failure**

Run: `cd research && cargo test --test e2e`
Expected: compile error, `Machine` missing.

- [ ] **Step 5: Implement the rest of `machine.rs`**

Append below the config code from Task 1:

```rust
use crate::emulator::{execute, ExecError, Execution};
use crate::isa::Program;
use crate::tables::alu::{alu_trace, AluAir};
use crate::tables::byte::{byte_trace, ByteAir, ByteCounts};
use crate::tables::cpu::{cpu_trace, public_values, CpuAir};
use crate::tables::memory::{memory_trace, MemoryAir};
use crate::tables::program::{program_trace, ProgramAir};
use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder};
use p3_batch_stark::{prove_batch, verify_batch, BatchProof, CommonData, ProverData, StarkInstance};
use p3_field::PrimeField64;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::StarkGenericConfig;
use serde::{Deserialize, Serialize};

pub const TIERS: [usize; 6] = [10, 12, 14, 16, 18, 20];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Tier(pub usize);
impl Tier {
    pub fn for_cycles(cycles: usize) -> Option<Tier> { TIERS.iter().copied().map(Tier).find(|t| cycles <= t.max_cycles()) }
    pub fn cpu_height(self) -> usize { 1 << self.0 }
    pub fn alu_height(self) -> usize { 1 << (self.0 + 1) }
    pub fn mem_height(self) -> usize { 1 << (self.0 + 2) }
    /// One padding row is always kept.
    pub fn max_cycles(self) -> usize { self.cpu_height() - 1 }
}

#[derive(Clone)]
pub enum Chip { Program(ProgramAir), Cpu(CpuAir), Memory(MemoryAir), Alu(AluAir), Byte(ByteAir) }

impl BaseAir<Val> for Chip {
    fn width(&self) -> usize {
        match self { Chip::Program(a) => BaseAir::<Val>::width(a), Chip::Cpu(a) => BaseAir::<Val>::width(a), Chip::Memory(a) => BaseAir::<Val>::width(a), Chip::Alu(a) => BaseAir::<Val>::width(a), Chip::Byte(a) => BaseAir::<Val>::width(a) }
    }
    fn preprocessed_width(&self) -> usize {
        match self { Chip::Program(a) => BaseAir::<Val>::preprocessed_width(a), Chip::Byte(a) => BaseAir::<Val>::preprocessed_width(a), _ => 0 }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        match self { Chip::Program(a) => BaseAir::<Val>::preprocessed_trace(a), Chip::Byte(a) => BaseAir::<Val>::preprocessed_trace(a), _ => None }
    }
    fn num_public_values(&self) -> usize { match self { Chip::Cpu(a) => BaseAir::<Val>::num_public_values(a), _ => 0 } }
}

impl<AB> Air<AB> for Chip
where
    AB: AirBuilder<F = Val> + PermutationAirBuilder + InteractionBuilder,
{
    fn eval(&self, b: &mut AB) {
        match self { Chip::Program(a) => a.eval(b), Chip::Cpu(a) => a.eval(b), Chip::Memory(a) => a.eval(b), Chip::Alu(a) => a.eval(b), Chip::Byte(a) => a.eval(b) }
    }
}

pub fn chips(program: &Program) -> Vec<Chip> {
    vec![Chip::Program(ProgramAir { program: program.clone() }), Chip::Cpu(CpuAir), Chip::Memory(MemoryAir), Chip::Alu(AluAir), Chip::Byte(ByteAir)]
}

pub struct Traces {
    pub program: RowMajorMatrix<Val>, pub cpu: RowMajorMatrix<Val>, pub memory: RowMajorMatrix<Val>,
    pub alu: RowMajorMatrix<Val>, pub byte: RowMajorMatrix<Val>, pub public_values: Vec<Val>,
}
impl Traces {
    pub fn as_slice(&self) -> [&RowMajorMatrix<Val>; 5] { [&self.program, &self.cpu, &self.memory, &self.alu, &self.byte] }
    pub fn heights(&self) -> [usize; 5] { self.as_slice().map(|m| m.height()) }
}

#[derive(Debug)]
pub enum ProveError { Exec(ExecError), NoTier(usize), TooManyCycles { cycles: usize, tier: Tier } }
#[derive(Debug)]
pub enum VerifyError { PublicValues, Tier, Batch(String) }

pub fn build_traces(program: &Program, exec: &Execution, tier: Tier) -> Result<Traces, ProveError> {
    let cycles = exec.cycles();
    if cycles > tier.max_cycles() { return Err(ProveError::TooManyCycles { cycles, tier }); }
    let mut counts = ByteCounts::default();
    let cpu = cpu_trace(&exec.events, tier.cpu_height());
    let memory = memory_trace(&exec.events, tier.mem_height(), &mut counts);
    let alu = alu_trace(&exec.events, tier.alu_height(), &mut counts);
    let byte = byte_trace(&counts);
    let program_t = program_trace(program, &exec.events);
    Ok(Traces { program: program_t, cpu, memory, alu, byte, public_values: public_values(program.base_pc, tier.0, &exec.outputs) })
}

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Proof { pub tier: Tier, pub public_values: Vec<u64>, pub batch: BatchProof<Config> }
impl Proof {
    pub fn to_bytes(&self) -> Vec<u8> { postcard::to_allocvec(self).expect("proof serialises") }
    pub fn size(&self) -> usize { self.to_bytes().len() }
}

pub struct Machine { pub config: Config, pub profile: FriProfile }

impl Machine {
    pub fn new(profile: FriProfile) -> Self { Self { config: make_config(profile), profile } }

    fn log_ext_degrees(&self, program: &Program, tier: Tier) -> Vec<usize> {
        let zk = self.config.is_zk();
        let prog_h = ProgramAir { program: program.clone() }.height();
        [prog_h, tier.cpu_height(), tier.mem_height(), tier.alu_height(), crate::tables::byte::HEIGHT]
            .iter().map(|h| h.trailing_zeros() as usize + zk).collect()
    }

    pub fn verifier_key(&self, program: &Program, tier: Tier) -> CommonData<Config> {
        ProverData::from_airs_and_degrees(&self.config, &chips(program), &self.log_ext_degrees(program, tier)).common
    }

    /// The code hash hc: the Merkle root of the preprocessed columns (program + byte table).
    pub fn code_hash(&self, program: &Program, tier: Tier) -> String {
        let key = self.verifier_key(program, tier);
        let com = key.preprocessed.as_ref().expect("program table is preprocessed");
        postcard::to_allocvec(&com.commitment).unwrap().iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn prove(&self, program: &Program, inputs: &[u32], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError> {
        let exec = execute(program, inputs, 1 << 20).map_err(ProveError::Exec)?;
        let tier = match tier { Some(t) => t, None => Tier::for_cycles(exec.cycles()).ok_or(ProveError::NoTier(exec.cycles()))? };
        let traces = build_traces(program, &exec, tier)?;
        Ok((self.prove_traces(program, &traces, tier), exec))
    }

    pub fn prove_traces(&self, program: &Program, traces: &Traces, tier: Tier) -> Proof {
        let airs = chips(program);
        let mats = traces.as_slice();
        let instances: Vec<StarkInstance<'_, Config, Chip>> = airs.iter().zip(mats.iter()).enumerate().map(|(i, (air, trace))| StarkInstance {
            air, trace, public_values: if i == 1 { traces.public_values.clone() } else { vec![] },
        }).collect();
        let prover_data = ProverData::from_instances(&self.config, &instances);
        let batch = prove_batch(&self.config, &instances, &prover_data);
        Proof { tier, public_values: traces.public_values.iter().map(|x| x.as_canonical_u64()).collect(), batch }
    }

    pub fn verify(&self, program: &Program, proof: &Proof) -> Result<(), VerifyError> {
        if proof.public_values.len() != crate::tables::cpu::pv::NUM { return Err(VerifyError::PublicValues); }
        if proof.public_values[crate::tables::cpu::pv::TIER] != proof.tier.0 as u64 { return Err(VerifyError::Tier); }
        if proof.batch.degree_bits != self.log_ext_degrees(program, proof.tier) { return Err(VerifyError::Tier); }
        let airs = chips(program);
        let pv: Vec<Val> = proof.public_values.iter().map(|x| Val::from_u64(*x)).collect();
        let pvs: Vec<Vec<Val>> = (0..5).map(|i| if i == 1 { pv.clone() } else { vec![] }).collect();
        let common = self.verifier_key(program, proof.tier);
        verify_batch(&self.config, &airs, &proof.batch, &pvs, &common).map_err(|e| VerifyError::Batch(format!("{e:?}")))
    }
}
```

`proof.batch.degree_bits` holds *extended* degree bits (`log2(height) + is_zk`), which is exactly what `log_ext_degrees` computes. Import `p3_field::PrimeCharacteristicRing` for `Val::from_u64`.

- [ ] **Step 6: Run all tests**

Run: `cd research && cargo test`
Expected: PASS. The first run of the batch prover in debug mode may reveal a constraint that the emulator satisfies but the AIR states wrongly; Plonky3 panics with the instance index and row. Use the file map to find the table (instance order: program, cpu, memory, alu, byte) and fix the constraint or the trace builder, whichever disagrees with the spec. Do not weaken a constraint to make a test pass without recording why in a code comment.

- [ ] **Step 7: Commit**

```bash
git add research/src/machine.rs research/tests/e2e.rs research/tests/cheating.rs research/tests/zk.rs
git commit -m "research: batch machine with tiers, ZK, prove/verify, adversarial tests"
```

---

### Task 10: The narrated binary, README, and docs

**Files:**
- Create: `research/src/main.rs`, `research/README.md`, `research/docs/01-isa.md`, `research/docs/02-tables-and-buses.md`, `research/docs/03-privacy.md`, `research/docs/04-guests.md`, `research/docs/05-roadmap.md`
- Modify: `circuits/README.md` (add a `research` row)

**Interfaces:**
- Consumes: `machine::{Machine, FriProfile, Tier}`, `guests`, `emulator`, `tables::*::col::WIDTH`

- [ ] **Step 1: Write the demo**

The binary takes no arguments and prints eight parts. Timing uses `std::time::Instant`. Use `FriProfile::Production` for the headline numbers, then re-run one proof with `FriProfile::Test` to show the parameter effect.

```rust
// research/src/main.rs
//! `cargo run --release` — the Rand reference zkVM, narrated end to end.
use rand_zkvm::emulator::execute;
use rand_zkvm::guests;
use rand_zkvm::isa::Instr;
use rand_zkvm::machine::{build_traces, FriProfile, Machine, Tier, TIERS};
use rand_zkvm::tables::{alu, cpu, memory, program, byte};
use std::time::Instant;

fn hr(title: &str) { println!("\n══ {title} {}", "═".repeat(70usize.saturating_sub(title.len()))); }

fn main() {
    hr("Part 1 · What R_exec proves");
    println!("A confidential call is: code hash hc (public), private inputs and state (witness),");
    println!("public outputs (8 words). The verifier learns only hc, the gas tier, and the outputs.");
    println!("Everything else — registers, memory, branches, the number of cycles — stays hidden.");

    hr("Part 2 · The guest: a confidential balance check");
    let threshold = 1000;
    let program = guests::balance_check(threshold);
    let inputs = [400u32, 250, 300, 75];
    println!("{} instructions at pc 0. It reads four private balances, sums them, and outputs", program.len());
    println!("1 if the sum ≥ {threshold}, else 0. Listing:");
    for (i, w) in program.words.iter().enumerate() {
        println!("  {:>4x}: {:08x}  {:?}", program.pc_of(i), w, Instr::decode(*w).unwrap());
    }

    hr("Part 3 · Execute (prover side; nothing here is visible to the chain)");
    let t = Instant::now();
    let exec = execute(&program, &inputs, 1 << 20).unwrap();
    println!("inputs {:?} → outputs {:?} in {} cycles ({:?})", inputs, &exec.outputs[..2], exec.cycles(), t.elapsed());

    hr("Part 4 · Arithmetize: five tables on eight buses");
    let tier = Tier::for_cycles(exec.cycles()).unwrap();
    let traces = build_traces(&program, &exec, tier).unwrap();
    println!("tier {} → cpu 2^{} rows (actual {} cycles), padding hides the rest", tier.0, tier.0, exec.cycles());
    println!("{:<10}{:>10}{:>8}   {}", "table", "rows", "cols", "role");
    for (name, h, w, role) in [
        ("program", traces.program.height(), program::col::WIDTH + program::pre::WIDTH, "preprocessed ROM; its commitment is hc"),
        ("cpu", traces.cpu.height(), cpu::col::WIDTH, "one row per cycle; fetch, decode selectors, pc"),
        ("memory", traces.memory.height(), memory::col::WIDTH, "registers + RAM sorted by (addr, ts)"),
        ("alu", traces.alu.height(), alu::col::WIDTH, "byte-limb arithmetic, shifts, compares"),
        ("byte", traces.byte.height(), byte::col::WIDTH + byte::pre::WIDTH, "2^16 byte pairs: range, and/or/xor, pow2"),
    ] { println!("{name:<10}{h:>10}{w:>8}   {role}"); }
    println!("buses: PROGRAM MEMORY ALU RANGE8 AND8 OR8 XOR8 POW2 (LogUp, verified globally)");

    hr("Part 5 · Prove and verify (production FRI: blowup 8, 80 queries, 20 PoW bits, ZK on)");
    let m = Machine::new(FriProfile::Production);
    let hc = m.code_hash(&program, tier);
    println!("hc = {hc}");
    let t = Instant::now();
    let proof = m.prove_traces(&program, &traces, tier);
    let prove_ms = t.elapsed().as_millis();
    println!("proof: {} bytes in {} ms", proof.size(), prove_ms);
    let t = Instant::now();
    m.verify(&program, &proof).unwrap();
    let verify_ms = t.elapsed().as_micros() as f64 / 1000.0;
    println!("verified in {verify_ms:.1} ms with public values {:?}", proof.public_values);

    hr("Part 6 · Cheating provers");
    let mut bad = build_traces(&program, &exec, tier).unwrap();
    bad.public_values[cpu::pv::OUT0] = p3_field::PrimeCharacteristicRing::from_u32(0);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { let p = m.prove_traces(&program, &bad, tier); m.verify(&program, &p) }));
    println!("claim output 0 instead of 1        → {}", if matches!(r, Ok(Ok(()))) { "ACCEPTED (bug)" } else { "rejected" });
    let other = guests::balance_check(threshold + 1);
    println!("verify against a different program → {}", if m.verify(&other, &proof).is_ok() { "ACCEPTED (bug)" } else { "rejected" });

    hr("Part 7 · Zero knowledge and tier padding");
    let (p1, _) = m.prove(&program, &inputs, None).unwrap();
    let (p2, _) = m.prove(&program, &[1000, 0, 0, 0], None).unwrap();
    println!("same output, different private inputs: public values equal = {}, proof bytes equal = {}", p1.public_values == p2.public_values, p1.to_bytes() == p2.to_bytes());
    let (p3, _) = m.prove(&program, &inputs, Some(Tier(12))).unwrap();
    println!("same run at tier 12: {} bytes (tier 10: {} bytes) — size reveals the tier, never the cycle count", p3.size(), p1.size());

    hr("Part 8 · Summary");
    let mt = Machine::new(FriProfile::Test);
    let t = Instant::now(); let pt = mt.prove_traces(&program, &traces, tier); let test_ms = t.elapsed().as_millis();
    println!("{:<28}{:>14}{:>14}", "", "production", "test profile");
    println!("{:<28}{:>14}{:>14}", "FRI queries / PoW bits", "80 / 20", "16 / 4");
    println!("{:<28}{:>14}{:>14}", "prove (ms)", prove_ms, test_ms);
    println!("{:<28}{:>14}{:>14}", "proof size (bytes)", proof.size(), pt.size());
    println!("{:<28}{:>14.1}", "verify (ms)", verify_ms);
    println!("field Goldilocks · challenge F_p² · hash Poseidon2 · blowup 8 · ZK hiding FRI · tiers {TIERS:?}");
    println!("\nRead docs/02-tables-and-buses.md for the constraint list, docs/03-privacy.md for what leaks.");
    for (name, p, inp) in guests::all() {
        let (pr, ex) = m.prove(&p, &inp, None).unwrap();
        m.verify(&p, &pr).unwrap();
        println!("{name:<16} cycles {:>6} tier {:>2} proof {:>7} B", ex.cycles(), pr.tier.0, pr.size());
    }
}
```

Add `use p3_matrix::Matrix;` for `.height()`.

- [ ] **Step 2: Run it**

Run: `cd research && cargo run --release`
Expected: eight parts print; every "→" line says `rejected`; "public values equal = true, proof bytes equal = false"; the final table lists four guests.

- [ ] **Step 3: Write `README.md`** — the guidance document. Sections, in this order, each a few paragraphs, no placeholders:

1. **What this is** — the reference for R_exec; one relation, one verifier, program bound by hc; where it sits relative to zkp1–zkp6 and to the node.
2. **Run it** — `cargo run --release`, `cargo test`; note the toolchain pin.
3. **The machine in one picture** — an ASCII diagram of the five tables and eight buses (copy from `docs/02`).
4. **How confidential arbitrary computation works** — walk through Parts 1–7 of the demo in prose: hc, private inputs via `READ_INPUT`, public outputs via `WRITE_OUTPUT`, tier padding, hiding commitments; then the whitepaper mapping: R_transfer is a guest; nullifiers, commitments and Merkle paths arrive as syscalls in milestone 3.
5. **The three targets** — RISC-V native; Solidity via an EVM interpreter guest; Solana via an sBPF interpreter guest; the coprocessor tables each needs (link `docs/04`).
6. **What leaks and what does not** — the table from `docs/03`.
7. **Deviations from the whitepaper** — the five items from the spec §12 plus the selector refinement.
8. **Reading order** — `isa.rs` → `emulator.rs` → `tables/cpu.rs` → `tables/memory.rs` → `tables/alu.rs` → `machine.rs`.

- [ ] **Step 4: Write the five docs**

- `docs/01-isa.md`: the instruction table (M1 / M2 / never), encoding notes, the `Decoded` selector table with one line per selector, the syscall ABI table, why RV32.
- `docs/02-tables-and-buses.md`: the ASCII diagram; for each table its column list (copy the `col` modules) and its constraints in words matching the code, and its bus sends/receives; the timestamp rule `ts = 4·clk + slot`; why the program is preprocessed and what that means for hc.
- `docs/03-privacy.md`: ZK via hiding FRI (statistical, cite the Plonky3 comment), tier table with heights per table, the leak table (tier, pc_entry, outputs, code commitment: public; everything else: hidden), delegated proving boundary.
- `docs/04-guests.md`: Solidity path (solc → bytecode → no_std EVM interpreter compiled to RV32IM; opcodes → coprocessor tables: KECCAK256, ADDMOD/MULMOD/EXP, ECRECOVER, SLOAD/SSTORE via Merkle witness syscalls), Solana path (sBPF ELF → interpreter; SHA-256, Ed25519, 64-bit mul; sBPF→RV32 translator later), estimated cycle multipliers, what milestone 4 builds first.
- `docs/05-roadmap.md`: milestones 1–4 from the spec with exit criteria, the deviation list, and the intended relationship to `../../fullnode` (the node embeds `rand_zkvm::machine::Machine::verify` as consensus code; provers run `prove`).

- [ ] **Step 5: Add the row to `circuits/README.md`**

Insert into the crate table:

```
| `research` | **Rand reference zkVM** | Plonky3 (Goldilocks, LogUp, hiding FRI) | RV32I guest programs proved under one universal relation; the guidance circuit for the whole protocol |
```

and a sentence under "Reading order": `4. research/README.md — the real thing: a zkVM, and what "confidential arbitrary computation" means concretely.`

- [ ] **Step 6: Run everything once more**

Run: `cd research && cargo test && cargo run --release`
Expected: all tests pass; demo completes.

- [ ] **Step 7: Commit**

```bash
git add research circuits/README.md
git commit -m "research: narrated demo binary, guidance README and docs"
```
