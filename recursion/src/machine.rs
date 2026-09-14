//! The rVM's batch-STARK machine: Plonky3 configuration, tiers, proof shape, the program-keyed
//! verifier-key cache (plan Task 1; the chip set and `prove`/`verify` grow per task through
//! Task 6, mirroring `research/src/machine.rs`'s structure).
//!
//! The rVM reuses the RV32 machine's exact proof-system configuration (spec §5's reuse ruling):
//! same field, extension, Poseidon2 permutation, hiding FRI profile and batch machinery. What is
//! new is the chip set and that the verifier key is **program-dependent** (plan R1/R6): the
//! program table is preprocessed, so the preprocessed cap binds every program word and there is
//! no in-circuit `hc` digest.
use p3_batch_stark::{BatchProof, CommonData, ProverData};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::PrimeField64;
use p3_fri::HidingFriPcs;
use p3_lookup::InteractionBuilder;
use p3_uni_stark::StarkConfig;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

pub use rand_zkvm::machine::{
    Challenge, Challenger, Compress, FriProfile, Hash, Perm, ValMmcs, permutation,
};

/// The rVM's field and proof-system types are the RV32 machine's own aliases.
pub type Val = rand_zkvm::machine::Val;
type Dft = Radix2DitParallel<Val>;
pub type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, StdRng>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

use crate::emulator::ExecError;
use crate::isa::{DecodeError, Instr, Op, Program, NUM_REGS};
use crate::tables::pad_height;
use crate::tables::program::ProgramAir;
use crate::tables::range::RangeAir;

/// Fixed seed for the rVM's `key_config` RNGs — the role of `research`'s `machine::KEY_SEED`
/// (a deterministic preprocessed commitment any verifier can recompute standalone), over a
/// different artifact family, so a different arbitrary constant: "RVM_M5_2".
const KEY_SEED: u64 = 0x5256_4d5f_4d35_5f32;

fn build_config(profile: FriProfile, mmcs_rng: StdRng, pcs_rng: StdRng) -> Config {
    let perm = permutation();
    let hash = Hash::new(perm.clone());
    let compress = Compress::new(perm);
    let val_mmcs = ValMmcs::new(hash, compress, 2, mmcs_rng);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri = p3_fri::FriParameters {
        log_blowup: 3,
        log_final_poly_len: 0,
        max_log_arity: 3,
        num_queries: profile.num_queries(),
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: profile.pow_bits(),
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri, 4, pcs_rng);
    StarkConfig::new(pcs, Challenger::new(permutation()))
}

/// The deterministic config behind `verifier_key`: any verifier recomputes the same preprocessed
/// commitment from `(program, tier, reduce)` alone — `research`'s `key_config`, verbatim in role.
fn key_config(profile: FriProfile) -> Config {
    let (mmcs_rng, pcs_rng) = key_rngs();
    build_config(profile, mmcs_rng, pcs_rng)
}

fn key_rngs() -> (StdRng, StdRng) {
    (StdRng::seed_from_u64(KEY_SEED), StdRng::seed_from_u64(KEY_SEED ^ 0x9E37_79B9_7F4A_7C15))
}

pub fn make_config(profile: FriProfile) -> Config {
    build_config(profile, StdRng::from_rng(&mut rand::rng()), StdRng::from_rng(&mut rand::rng()))
}

/// The rVM tier ladder (plan R2): stride 2 through the cheap-test sizes, then every rung near the
/// exit — 19 (the post-cut test-profile verifier program), 21 (the production exit), 22 (the
/// safety rung). No 23: the uncut program needs ~165 GB peak, a machine this fleet does not have.
pub const TIERS: [usize; 10] = [8, 10, 12, 14, 16, 18, 19, 20, 21, 22];

/// Floor on every proof-declared table log-height: one padding row's worth, mirroring the RV32
/// machine's per-table `MIN_LOG_HEIGHT`s.
pub const MIN_LOG_HEIGHT: u8 = 4;
/// The public table's fixed log-height: 4 real rows (the interface digest, R5) plus the padding
/// rule, `pad_height(4 + 1, 4) = 8`.
pub const PUBLIC_LOG_HEIGHT: u8 = 3;
/// Defensive ceiling on the two memory tables' declared log-heights — the RV32
/// `MAX_MEM_LOG_HEIGHT`'s role, one rung wider because the register table carries per-row
/// register traffic the RV32 machine does not.
pub const MAX_MEM_LOG_HEIGHT: u8 = 26;
pub const POSEIDON2_MAX_LOG_HEIGHT: u8 = 20;
pub const REDUCE_MAX_LOG_HEIGHT: u8 = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Tier(pub usize);
impl Tier {
    pub fn for_cycles(cycles: usize) -> Option<Tier> { TIERS.iter().copied().map(Tier).find(|t| cycles <= t.max_cycles()) }
    pub fn cpu_height(self) -> usize { 1 << self.0 }
    /// One padding row is always kept.
    pub fn max_cycles(self) -> usize { self.cpu_height() - 1 }
}

/// The program table's own floor: 4 rows (the plan's `pad_height(len + 1, 4)` rule) — smaller
/// than `MIN_LOG_HEIGHT`, which floors the *declared* tables' log-heights at 16 rows.
pub const PROGRAM_MIN_HEIGHT: usize = 4;

/// The program table's height rule: one row per instruction plus one padding row, floored — the
/// canonical definition (`tables::program`, Task 2, re-exports it).
pub fn program_log_height(len: usize) -> u8 {
    pad_height(len + 1, PROGRAM_MIN_HEIGHT).trailing_zeros() as u8
}

/// Each instance's extended trace degree bits, in the final `chips()` order — a pure function of
/// the program, the tier and the declared heights, which is why it can be a free function: the
/// batch verifier checks `proof.batch.degree_bits` against it rather than trusting the proof
/// (the RV32 `Machine::log_ext_degrees`'s role).
///
/// Order: `program, cpu, reg_memory, ram_memory, poseidon2, public, range`, plus `reduce` last
/// when the proof declares one (`reduce_log_height != 0`). The `+ 1` per entry is the ZK doubling
/// (`is_zk() == true` for every config this crate builds — they are all `HidingFriPcs`; Task 6's
/// `verify` reads the same fact off the config it uses).
pub fn log_ext_degrees(program: &Program, tier: Tier, reg_log_height: u8, ram_log_height: u8, poseidon2_log_height: u8, reduce_log_height: u8) -> Vec<usize> {
    let zk = 1usize;
    let mut v = vec![
        program_log_height(program.instrs.len()) as usize + zk,
        tier.0 + zk,
        reg_log_height as usize + zk,
        ram_log_height as usize + zk,
        poseidon2_log_height as usize + zk,
        PUBLIC_LOG_HEIGHT as usize + zk,
        crate::tables::range::HEIGHT.trailing_zeros() as usize + zk,
    ];
    if reduce_log_height != 0 {
        v.push(reduce_log_height as usize + zk);
    }
    v
}

/// Every range check on the proof's declared shape, in one place and before anything is sized
/// from it — the RV32 `check_declared_heights`'s role (cheap-before-expensive): an untrusted
/// tier outside `TIERS` or an absurd declared height must be rejected before `1usize << h` is
/// ever evaluated.
pub fn check_declared_heights(tier: Tier, reg_log_height: u8, ram_log_height: u8, poseidon2_log_height: u8, reduce_log_height: u8) -> Result<(), VerifyError> {
    if !TIERS.contains(&tier.0) { return Err(VerifyError::Tier); }
    if !(MIN_LOG_HEIGHT..=MAX_MEM_LOG_HEIGHT).contains(&reg_log_height) { return Err(VerifyError::RegHeight); }
    if !(MIN_LOG_HEIGHT..=MAX_MEM_LOG_HEIGHT).contains(&ram_log_height) { return Err(VerifyError::RamHeight); }
    if !(MIN_LOG_HEIGHT..=POSEIDON2_MAX_LOG_HEIGHT).contains(&poseidon2_log_height) { return Err(VerifyError::Poseidon2Height); }
    // The keccak pattern: 0 is the distinguished "no reduce table" value; any other value is a
    // declared height in range.
    if reduce_log_height != 0 && !(MIN_LOG_HEIGHT..=REDUCE_MAX_LOG_HEIGHT).contains(&reduce_log_height) { return Err(VerifyError::ReduceHeight); }
    Ok(())
}

#[derive(Debug)]
pub enum ProveError {
    Exec(ExecError),
    NoTier(usize),
    TooManyCycles { cycles: usize, tier: Tier },
    /// An explicit `Some(tier)` outside `TIERS` — the prove-side mirror of
    /// `check_declared_heights`' `TIERS.contains` guard (research audit ZH3).
    BadTier(usize),
    /// `check_program` found a word the emulator could never execute (R1: registration-time
    /// legality — the preprocessed table commits to the program, so its words are checked at the
    /// one place they enter the machine).
    Decode(DecodeError),
}

#[derive(Debug)]
pub enum VerifyError {
    PublicValues,
    Tier,
    Batch(String),
    RegHeight,
    RamHeight,
    Poseidon2Height,
    ReduceHeight,
}

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Proof {
    pub tier: Tier,
    pub reg_log_height: u8,
    pub ram_log_height: u8,
    pub poseidon2_log_height: u8,
    /// 0 is "no reduce instance in this batch" (the keccak pattern), not a height.
    pub reduce_log_height: u8,
    /// Always exactly 4: the program's interface digest (R5).
    pub public_values: Vec<u64>,
    pub batch: BatchProof<Config>,
}
impl Proof {
    pub fn to_bytes(&self) -> Vec<u8> { postcard::to_allocvec(self).expect("proof serialises") }
    pub fn size(&self) -> usize { self.to_bytes().len() }
}

/// Bound on the number of `(program, tier, reduce)` verifier keys kept in memory at once — the
/// RV32 cache's FIFO policy, over a program-keyed space instead (R6).
const KEY_CACHE_CAPACITY: usize = 64;

#[derive(Default)]
struct KeyCache {
    map: HashMap<(usize, [u64; 4], bool), Arc<CommonData<Config>>>,
    order: VecDeque<(usize, [u64; 4], bool)>,
}
impl KeyCache {
    fn get(&self, key: &(usize, [u64; 4], bool)) -> Option<Arc<CommonData<Config>>> {
        self.map.get(key).cloned()
    }
    fn insert(&mut self, key: (usize, [u64; 4], bool), value: Arc<CommonData<Config>>) {
        if self.map.contains_key(&key) { return; }
        if self.map.len() >= KEY_CACHE_CAPACITY {
            if let Some(oldest) = self.order.pop_front() { self.map.remove(&oldest); }
        }
        self.order.push_back(key);
        self.map.insert(key, value);
    }
}

pub struct Machine { pub config: Config, pub profile: FriProfile, keys: Mutex<KeyCache> }

impl Machine {
    pub fn new(profile: FriProfile) -> Self {
        Self { config: make_config(profile), profile, keys: Mutex::new(KeyCache::default()) }
    }

    /// The preprocessed commitment for `(program, tier, reduce)` (R6), cached. The chip set
    /// grows per task toward the final eight-instance batch (Task 6); the cache key is already
    /// the final one, so no caller changes.
    pub fn verifier_key(&self, program: &Program, tier: Tier, reduce: bool) -> Arc<CommonData<Config>> {
        let digest = program.digest();
        let key = (tier.0, std::array::from_fn(|i| digest[i].as_canonical_u64()), reduce);
        if let Some(hit) = self.keys.lock().unwrap().get(&key) { return hit; }
        let arc = Arc::new(program.clone());
        let airs = chips(&arc, tier, if reduce { MIN_LOG_HEIGHT } else { 0 });
        let degrees = current_degree_bits(program, tier);
        let common = Arc::new(ProverData::from_airs_and_degrees(&key_config(self.profile), &airs, &degrees).common);
        self.keys.lock().unwrap().insert(key, common.clone());
        common
    }

    /// Number of `(program, tier, reduce)` verifier keys currently cached.
    pub fn cached_keys(&self) -> usize { self.keys.lock().unwrap().map.len() }

    /// Registration-time legality (R1): the preprocessed program table commits to every word, so
    /// every word must be something the emulator could execute — the M3.4 invariant
    /// (`research/src/tables/program.rs`'s panic-on-undecodable), moved to the one place the
    /// words enter the machine. The same checks `emulator::execute` makes per row: register
    /// indices in range, and extension pairs not starting at `r31`.
    pub fn check_program(program: &Program) -> Result<(), DecodeError> {
        for instr in &program.instrs {
            check_instr(instr)?;
        }
        Ok(())
    }
}

fn check_instr(instr: &Instr) -> Result<(), DecodeError> {
    let reg = |idx: u8, slot: &'static str| -> Result<(), DecodeError> {
        if idx as usize >= NUM_REGS { return Err(DecodeError::Register { slot, value: idx as u64 }); }
        Ok(())
    };
    let pair = |idx: u8, slot: &'static str| -> Result<(), DecodeError> {
        if idx as usize + 1 >= NUM_REGS { return Err(DecodeError::Register { slot, value: idx as u64 + 1 }); }
        Ok(())
    };
    reg(instr.rd, "rd")?;
    reg(instr.ra, "ra")?;
    if instr.op.b_is_register() {
        reg(instr.rb(), "rb")?;
    }
    match instr.op {
        Op::Eadd | Op::Esub | Op::Emul => { pair(instr.rd, "rd")?; pair(instr.ra, "ra")?; pair(instr.rb(), "rb")?; }
        Op::Emulf | Op::Einv => { pair(instr.rd, "rd")?; pair(instr.ra, "ra")?; }
        Op::Loade | Op::Storee | Op::Hinte => { pair(instr.rd, "rd")?; }
        _ => {}
    }
    Ok(())
}

/// The machine's chips, in the final `chips()` order's relative positions: `program, cpu,
/// reg_memory, ram_memory, poseidon2, public, range`, `reduce` last when declared. The set grows
/// per task (Task 2: `program` + `range`) — the order is load-bearing: the public table owns the
/// batch's public values at instance index 5, and `prove`/`verify` (Task 6) hard-code it.
pub fn chips(program: &Arc<Program>, _tier: Tier, _reduce_log_height: u8) -> Vec<Chip> {
    vec![
        Chip::Program(ProgramAir::new(program.clone())),
        Chip::Range(RangeAir),
    ]
}

/// The degree bits matching the *current* `chips()` set, ZK-doubled. Converges on
/// [`log_ext_degrees`] as the chip set completes (Task 6); until then it is the per-task
/// intermediate — the key is cached per task's set, and nothing cross-checks keys across tasks.
fn current_degree_bits(program: &Program, _tier: Tier) -> Vec<usize> {
    let zk = 1usize;
    vec![
        program_log_height(program.instrs.len()) as usize + zk,
        crate::tables::range::HEIGHT.trailing_zeros() as usize + zk,
    ]
}

/// The machine's chips. Later tables append their variants in the final `chips()` order.
#[derive(Clone, Debug)]
pub enum Chip {
    Program(ProgramAir),
    Range(RangeAir),
}

impl p3_air::BaseAir<Val> for Chip {
    fn width(&self) -> usize {
        match self {
            Chip::Program(a) => p3_air::BaseAir::<Val>::width(a),
            Chip::Range(a) => p3_air::BaseAir::<Val>::width(a),
        }
    }
    fn preprocessed_width(&self) -> usize {
        match self {
            Chip::Program(a) => p3_air::BaseAir::<Val>::preprocessed_width(a),
            Chip::Range(a) => p3_air::BaseAir::<Val>::preprocessed_width(a),
        }
    }
    fn preprocessed_trace(&self) -> Option<p3_matrix::dense::RowMajorMatrix<Val>> {
        match self {
            Chip::Program(a) => p3_air::BaseAir::<Val>::preprocessed_trace(a),
            Chip::Range(a) => p3_air::BaseAir::<Val>::preprocessed_trace(a),
        }
    }
}

impl<AB> p3_air::Air<AB> for Chip
where
    AB: p3_air::AirBuilder<F = Val> + p3_air::PermutationAirBuilder + InteractionBuilder,
{
    fn eval(&self, b: &mut AB) {
        match self {
            Chip::Program(a) => p3_air::Air::eval(a, b),
            Chip::Range(a) => p3_air::Air::eval(a, b),
        }
    }
}
