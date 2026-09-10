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
///
/// `pub(crate)`, not private: `tables::poseidon2::round_constants` reproduces the exact same
/// `ExternalLayerConstants::new_from_rng`/internal-constants RNG draw that `permutation()`
/// below makes, so the M3 Poseidon2 *chip*'s round constants are byte-identical to this
/// machine's own hashing permutation — see that module's doc comment for why (`p3_poseidon2`
/// consumes its constants into opaque `external_layer`/`internal_layer` fields with no
/// accessor, so the only way to recover them is to redraw them from the same seed).
pub(crate) const PERM_SEED: u64 = 0x5261_6e64_5a4b; // "RandZK"

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FriProfile {
    /// 16 queries, 4 PoW bits — for `cargo test`. 3·16+4 = 52 conjectured bits; not a
    /// production target, only fast enough for the suite.
    Test,
    /// 27 queries, 20 PoW bits, blowup 8. Chosen so the ethSTARK conjectured bound
    /// `log_blowup·num_queries + query_pow_bits ≥ 100`: 3·27+20 = 101.
    Production,
}

impl FriProfile {
    pub fn num_queries(self) -> usize {
        match self {
            Self::Test => 16,
            Self::Production => 27,
        }
    }
    pub fn pow_bits(self) -> usize {
        match self {
            Self::Test => 4,
            Self::Production => 20,
        }
    }
}

pub fn permutation() -> Perm {
    Perm::new_from_rng_128(&mut StdRng::seed_from_u64(PERM_SEED))
}

/// Builds a `Config` from two explicit RNGs: `mmcs_rng` seeds the value MMCS's per-commit
/// hiding salts (used for *every* commit through it, preprocessed traces included — see
/// `p3_merkle_tree::hiding_mmcs::MerkleTreeHidingMmcs::commit`), `pcs_rng` seeds the PCS's own
/// random codewords/quotient blinding. Kept private: callers pick a seeding strategy through
/// `make_config` (fresh OS entropy, for proving) or `key_config` (deterministic, for a
/// preprocessed commitment any verifier can recompute).
fn build_config(profile: FriProfile, mmcs_rng: StdRng, pcs_rng: StdRng) -> Config {
    let perm = permutation();
    let hash = Hash::new(perm.clone());
    let compress = Compress::new(perm);
    let val_mmcs = ValMmcs::new(hash, compress, 2, mmcs_rng);
    generic_config(profile, Dft::default(), val_mmcs, pcs_rng)
}

/// The FRI/PCS setup, written once over any value-MMCS and DFT. Every backend goes through
/// here, so "the reference backend uses the same FRI parameters as the CPU one" is not a
/// comment that can drift — `build_config` is literally this function with the Plonky3
/// `ValMmcs`/`Radix2DitParallel` pair, and `reference_cfg`/`cuda_cfg` call it with theirs.
fn generic_config<D, M>(
    profile: FriProfile,
    dft: D,
    val_mmcs: M,
    pcs_rng: StdRng,
) -> StarkConfig<HidingFriPcs<Val, D, M, ExtensionMmcs<Val, Challenge, M>, StdRng>, Challenge, Challenger>
where
    D: p3_dft::TwoAdicSubgroupDft<Val>,
    M: p3_commit::Mmcs<Val, MultiProof: Sync, Error: Sync> + Clone,
{
    let challenge_mmcs = ExtensionMmcs::new(val_mmcs.clone());
    let fri = FriParameters {
        log_blowup: 3,
        log_final_poly_len: 0,
        max_log_arity: 3,
        num_queries: profile.num_queries(),
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: profile.pow_bits(),
        mmcs: challenge_mmcs,
    };
    let pcs = HidingFriPcs::new(dft, val_mmcs, fri, 4, pcs_rng);
    StarkConfig::new(pcs, Challenger::new(permutation()))
}

/// The reference (CPU-twin) backend: `rand-zkvm-cuda`'s own Merkle tree and NTT, running on
/// the host. Structurally identical to `Config` — same Poseidon2 permutation, same salt
/// stream, same FRI parameters — so its proofs decode as CPU proofs (see `prove_on`).
#[cfg(feature = "reference-backend")]
mod reference_cfg {
    use super::*;
    pub type Mmcs = rand_zkvm_cuda::merkle::mmcs::HidingMmcs<rand_zkvm_cuda::merkle::cpu::CpuHashEngine>;
    pub type Dft = rand_zkvm_cuda::dft::Dft<rand_zkvm_cuda::ntt::cpu::CpuNttEngine>;
    pub type Pcs = HidingFriPcs<Val, Dft, Mmcs, ExtensionMmcs<Val, Challenge, Mmcs>, StdRng>;
    pub type Config = StarkConfig<Pcs, Challenge, Challenger>;
    pub fn config(profile: FriProfile, mmcs_rng: StdRng, pcs_rng: StdRng) -> Config {
        let engine = std::sync::Arc::new(rand_zkvm_cuda::merkle::cpu::CpuHashEngine::new(PERM_SEED));
        let mmcs = Mmcs::new(engine, PERM_SEED, 2, mmcs_rng);
        super::generic_config(profile, Dft::default(), mmcs, pcs_rng)
    }
}

/// The CUDA backend. With `mock-cuda` the same code runs against the mock driver, so the
/// whole `Backend::Cuda` path is exercised on a machine with no GPU.
#[cfg(any(feature = "cuda", feature = "mock-cuda"))]
mod cuda_cfg {
    use super::*;
    pub type Mmcs = rand_zkvm_cuda::merkle::mmcs::HidingMmcs<rand_zkvm_cuda::gpu::hash::CudaHashEngine>;
    pub type Dft = rand_zkvm_cuda::dft::Dft<rand_zkvm_cuda::gpu::ntt::CudaNttEngine>;
    pub type Pcs = HidingFriPcs<Val, Dft, Mmcs, ExtensionMmcs<Val, Challenge, Mmcs>, StdRng>;
    pub type Config = StarkConfig<Pcs, Challenge, Challenger>;
    pub fn config(
        profile: FriProfile,
        gpu: std::sync::Arc<rand_zkvm_cuda::gpu::GpuProver>,
        mmcs_rng: StdRng,
        pcs_rng: StdRng,
    ) -> Config {
        let engine = std::sync::Arc::new(rand_zkvm_cuda::gpu::hash::CudaHashEngine { gpu: gpu.clone() });
        let mmcs = Mmcs::new(engine, PERM_SEED, 2, mmcs_rng);
        // The tuple-struct constructor, not the alias: `Dft` here is a `type`, and a type
        // alias cannot be called.
        let dft = rand_zkvm_cuda::dft::Dft(std::sync::Arc::new(rand_zkvm_cuda::gpu::ntt::CudaNttEngine { gpu }));
        super::generic_config(profile, dft, mmcs, pcs_rng)
    }
}

pub fn make_config(profile: FriProfile) -> Config {
    // Fresh entropy per proof, taken from the OS: this is the config actually used to prove,
    // so main-trace and quotient commitments stay hiding.
    build_config(profile, StdRng::from_rng(&mut rand::rng()), StdRng::from_rng(&mut rand::rng()))
}

use crate::emulator::{execute, ExecError, Execution};
use crate::isa::Program;
use crate::tables::alu::{alu_trace, AluAir};
use crate::tables::cpu::{cpu_trace, public_values, CpuAir};
use crate::tables::memory::{memory_trace, MemoryAir};
use crate::tables::nibble::{nibble_trace, NibbleAir, NibbleCounts};
use crate::tables::poseidon2::{poseidon2_trace, Poseidon2Air};
use crate::tables::program::{program_trace, ProgramAir};
use crate::tables::range::{range_trace, RangeAir, RangeCounts};
use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder};
use p3_batch_stark::{prove_batch, verify_batch, BatchProof, CommonData, ProverData, StarkInstance};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::StarkGenericConfig;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

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
    /// `2^t`, i.e. `2^(t-5)` Poseidon2 permutation slots (each block is 32 rows). The M3 plan's
    /// own estimate is that the transfer guest may need `2^(t+1)` at tier 12 (~165
    /// permutations vs. 128 slots here) — M3.3 measures the real count; if it doesn't fit,
    /// this is the one line that changes.
    pub fn poseidon2_height(self) -> usize { self.cpu_height() }
}

#[derive(Clone)]
pub enum Chip { Program(ProgramAir), Cpu(CpuAir), Memory(MemoryAir), Alu(AluAir), Range(RangeAir), Nibble(NibbleAir), Poseidon2(Poseidon2Air, usize) }

impl BaseAir<Val> for Chip {
    fn width(&self) -> usize {
        match self { Chip::Program(a) => BaseAir::<Val>::width(a), Chip::Cpu(a) => BaseAir::<Val>::width(a), Chip::Memory(a) => BaseAir::<Val>::width(a), Chip::Alu(a) => BaseAir::<Val>::width(a), Chip::Range(a) => BaseAir::<Val>::width(a), Chip::Nibble(a) => BaseAir::<Val>::width(a), Chip::Poseidon2(a, _) => BaseAir::<Val>::width(a) }
    }
    fn preprocessed_width(&self) -> usize {
        match self { Chip::Program(a) => BaseAir::<Val>::preprocessed_width(a), Chip::Range(a) => BaseAir::<Val>::preprocessed_width(a), Chip::Nibble(a) => BaseAir::<Val>::preprocessed_width(a), Chip::Poseidon2(a, _) => BaseAir::<Val>::preprocessed_width(a), _ => 0 }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        match self {
            Chip::Program(a) => BaseAir::<Val>::preprocessed_trace(a),
            Chip::Range(a) => BaseAir::<Val>::preprocessed_trace(a),
            Chip::Nibble(a) => BaseAir::<Val>::preprocessed_trace(a),
            // `Poseidon2Air`'s own `BaseAir::preprocessed_trace` deliberately panics (its
            // preprocessed trace depends on the tier's height, which isn't available through
            // that trait method) — go through the height-carrying inherent method instead.
            Chip::Poseidon2(_, height) => Some(Poseidon2Air::preprocessed_trace_at(*height)),
            _ => None,
        }
    }
    fn num_public_values(&self) -> usize { match self { Chip::Cpu(a) => BaseAir::<Val>::num_public_values(a), _ => 0 } }
}

impl<AB> Air<AB> for Chip
where
    AB: AirBuilder<F = Val> + PermutationAirBuilder + InteractionBuilder,
{
    fn eval(&self, b: &mut AB) {
        match self { Chip::Program(a) => a.eval(b), Chip::Cpu(a) => a.eval(b), Chip::Memory(a) => a.eval(b), Chip::Alu(a) => a.eval(b), Chip::Range(a) => a.eval(b), Chip::Nibble(a) => a.eval(b), Chip::Poseidon2(a, _) => a.eval(b) }
    }
}

/// `Poseidon2` is appended last: `i == 1` (`Cpu`) must stay the public-values slot that
/// `prove_traces`/`verify` hard-code, so every new chip since M2 has gone at the end rather
/// than disturbing that index.
pub fn chips(program: &Program, tier: Tier) -> Vec<Chip> {
    vec![
        Chip::Program(ProgramAir { program: program.clone() }),
        Chip::Cpu(CpuAir),
        Chip::Memory(MemoryAir),
        Chip::Alu(AluAir),
        Chip::Range(RangeAir),
        Chip::Nibble(NibbleAir),
        Chip::Poseidon2(Poseidon2Air, tier.poseidon2_height()),
    ]
}

pub struct Traces {
    pub program: RowMajorMatrix<Val>, pub cpu: RowMajorMatrix<Val>, pub memory: RowMajorMatrix<Val>,
    pub alu: RowMajorMatrix<Val>, pub range: RowMajorMatrix<Val>, pub nibble: RowMajorMatrix<Val>,
    pub poseidon2: RowMajorMatrix<Val>, pub public_values: Vec<Val>,
}
impl Traces {
    pub fn as_slice(&self) -> [&RowMajorMatrix<Val>; 7] { [&self.program, &self.cpu, &self.memory, &self.alu, &self.range, &self.nibble, &self.poseidon2] }
    pub fn heights(&self) -> [usize; 7] { self.as_slice().map(|m| m.height()) }
}

#[derive(Debug)]
pub enum ProveError { Exec(ExecError), NoTier(usize), TooManyCycles { cycles: usize, tier: Tier }, Backend(String) }
#[derive(Debug)]
pub enum VerifyError { PublicValues, Tier, Batch(String) }

pub fn build_traces(program: &Program, exec: &Execution, tier: Tier) -> Result<Traces, ProveError> {
    let cycles = exec.cycles();
    if cycles > tier.max_cycles() { return Err(ProveError::TooManyCycles { cycles, tier }); }
    let mut range = RangeCounts::default();
    let mut nibble = NibbleCounts::default();
    let cpu = cpu_trace(&exec.events, tier.cpu_height(), &mut range, &mut nibble);
    let memory = memory_trace(&exec.events, tier.mem_height(), &mut range);
    let alu = alu_trace(&exec.events, tier.alu_height(), &mut range, &mut nibble);
    let range_t = range_trace(&range);
    let nibble_t = nibble_trace(&nibble);
    let program_t = program_trace(program, &exec.events);
    // M3.2 wires the emulator's own hash events in; until then the table is all padding
    // (`IS_REAL = 0` throughout) but still a genuine, AIR-satisfying permutation trace — see
    // `tables::poseidon2`'s module doc comment.
    let poseidon2_t = poseidon2_trace(&[], tier.poseidon2_height());
    Ok(Traces { program: program_t, cpu, memory, alu, range: range_t, nibble: nibble_t, poseidon2: poseidon2_t, public_values: public_values(program.base_pc, tier.0, &exec.outputs) })
}

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Proof { pub tier: Tier, pub public_values: Vec<u64>, pub batch: BatchProof<Config> }
impl Proof {
    pub fn to_bytes(&self) -> Vec<u8> { postcard::to_allocvec(self).expect("proof serialises") }
    pub fn size(&self) -> usize { self.to_bytes().len() }
}

/// Deterministic 64-bit digest of a program: an FNV-1a-style fold over `base_pc` and every
/// word. Used only to seed `key_config`'s RNGs, never for anything cryptographic in its own
/// right — it just needs to be a pure function of the program.
fn program_digest(program: &Program) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ (program.base_pc as u64);
    // Length first, so the fold cannot collide two programs that differ only in how many
    // words they have. (`hc` itself is the preprocessed Merkle root, which already commits
    // to the padded height; this digest only seeds that commitment's salt, but there is no
    // reason to leave it length-extendable.)
    h ^= program.words.len() as u64;
    h = h.wrapping_mul(0x0000_0001_0000_01b3);
    for &w in &program.words {
        h ^= w as u64;
        h = h.wrapping_mul(0x0000_0001_0000_01b3);
    }
    h
}

/// A `Config` whose value-MMCS salts and PCS random codewords are both seeded deterministically
/// from `program` (and nothing else) instead of OS entropy, so that the resulting preprocessed
/// commitment (`Machine::verifier_key`/`code_hash`) is a pure function of the program: any
/// verifier can recompute it standalone, without having witnessed the proving session.
///
/// A salt that is a function of the message is *binding but not hiding*: it is brute-forceable
/// over any guessable program space, and two deployments of the same program produce the same
/// `hc` and are therefore linkable. That is acceptable here only because milestone 1 is not
/// trying to hide the program at all — `verify` takes the whole `Program` in the clear, so the
/// verifier already holds every word (`docs/03-privacy.md`). It is *not* a claim that a
/// program-derived salt costs nothing in general. A hiding program commitment belongs with
/// milestone 3's in-circuit digest, where the verifier stops holding the code. Never
/// used for the actual `prove_batch` call, whose main-trace/quotient/permutation commitments
/// must keep fresh entropy (see `make_config`) or two proofs of the same run would be
/// distinguishable, breaking zero-knowledge.
fn key_config(profile: FriProfile, program: &Program) -> Config {
    let (mmcs_rng, pcs_rng) = key_rngs(program);
    build_config(profile, mmcs_rng, pcs_rng)
}

/// The deterministic `(mmcs_rng, pcs_rng)` pair behind `key_config`, factored out so every
/// backend seeds its own key config identically and therefore produces a preprocessed
/// commitment byte-identical to the one `verifier_key` recomputes on the CPU.
fn key_rngs(program: &Program) -> (StdRng, StdRng) {
    let seed = program_digest(program);
    // XOR with an arbitrary odd constant so the two RNG streams don't start identically.
    (StdRng::seed_from_u64(seed), StdRng::seed_from_u64(seed ^ 0x9E37_79B9_7F4A_7C15))
}

/// Which prover implementation `Machine::prove_with` runs the batch STARK on. Every variant
/// produces a `Proof` the ordinary CPU `Machine::verify` accepts; they differ only in who
/// computes the NTTs and Poseidon2 hashes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// Plonky3's own `Radix2DitParallel` + `MerkleTreeHidingMmcs`.
    Cpu,
    /// `rand-zkvm-cuda`'s engines running on the host: the CPU twin of the GPU path.
    #[cfg(feature = "reference-backend")]
    Reference,
    /// `rand-zkvm-cuda`'s CUDA engines (or the mock driver under `mock-cuda`).
    #[cfg(any(feature = "cuda", feature = "mock-cuda"))]
    Cuda,
}

/// Best-effort text of a caught panic payload: `panic!("{e}")` and `panic!("literal")` cover
/// every panic the backend engines raise.
#[cfg(any(feature = "reference-backend", feature = "cuda", feature = "mock-cuda"))]
fn panic_message(p: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = p.downcast_ref::<String>() { return format!("backend panicked: {s}"); }
    if let Some(s) = p.downcast_ref::<&str>() { return format!("backend panicked: {s}"); }
    "backend panicked".to_string()
}

/// Bound on the number of `(program digest, tier)` verifier keys `Machine::verifier_key`
/// keeps in memory at once. Past this, the oldest entry is evicted (FIFO) to make room for the
/// new one — a preprocessed commitment is cheap enough to recompute that a fancier (e.g. LRU)
/// policy is not worth the complexity here.
const KEY_CACHE_CAPACITY: usize = 64;

/// A bounded, FIFO-evicted cache of `Machine::verifier_key` results, keyed by
/// `(program_digest(program), tier.0)`.
#[derive(Default)]
struct KeyCache {
    map: HashMap<(u64, usize), Arc<CommonData<Config>>>,
    order: VecDeque<(u64, usize)>,
}
impl KeyCache {
    fn get(&self, key: &(u64, usize)) -> Option<Arc<CommonData<Config>>> {
        self.map.get(key).cloned()
    }
    fn insert(&mut self, key: (u64, usize), value: Arc<CommonData<Config>>) {
        if self.map.contains_key(&key) {
            return;
        }
        if self.map.len() >= KEY_CACHE_CAPACITY {
            if let Some(oldest) = self.order.pop_front() {
                self.map.remove(&oldest);
            }
        }
        self.order.push_back(key);
        self.map.insert(key, value);
    }
}

pub struct Machine { pub config: Config, pub profile: FriProfile, keys: Mutex<KeyCache> }

impl Machine {
    pub fn new(profile: FriProfile) -> Self { Self { config: make_config(profile), profile, keys: Mutex::new(KeyCache::default()) } }

    fn log_ext_degrees(&self, program: &Program, tier: Tier) -> Vec<usize> {
        let zk = self.config.is_zk();
        let prog_h = ProgramAir { program: program.clone() }.height();
        // Order matches `chips()`: program, cpu, memory, alu, range, nibble, poseidon2.
        [prog_h, tier.cpu_height(), tier.mem_height(), tier.alu_height(), crate::tables::range::HEIGHT, crate::tables::nibble::HEIGHT, tier.poseidon2_height()]
            .iter().map(|h| h.trailing_zeros() as usize + zk).collect()
    }

    /// The preprocessed commitment (program + range + nibble tables) for `(program, tier)`,
    /// cached by `program_digest(program)` and `tier.0` — see `KeyCache`. Recomputing it from
    /// scratch runs the full `ProverData::from_airs_and_degrees` preprocessing pass (in
    /// particular building the range and nibble tables' Merkle trees every time), which is
    /// the cost this cache exists to amortize across repeated `verify`/`code_hash` calls for
    /// the same `(program, tier)`.
    pub fn verifier_key(&self, program: &Program, tier: Tier) -> Arc<CommonData<Config>> {
        let key = (program_digest(program), tier.0);
        if let Some(hit) = self.keys.lock().unwrap().get(&key) {
            return hit;
        }
        let common = Arc::new(
            ProverData::from_airs_and_degrees(&key_config(self.profile, program), &chips(program, tier), &self.log_ext_degrees(program, tier)).common,
        );
        self.keys.lock().unwrap().insert(key, common.clone());
        common
    }

    /// Number of `(program, tier)` verifier keys currently cached.
    pub fn cached_keys(&self) -> usize { self.keys.lock().unwrap().map.len() }

    /// The code hash hc: the Merkle root of the preprocessed columns (program + range + nibble tables).
    pub fn code_hash(&self, program: &Program, tier: Tier) -> String {
        let key = self.verifier_key(program, tier);
        let com = key.preprocessed.as_ref().expect("program table is preprocessed");
        postcard::to_allocvec(&com.commitment).unwrap().iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn prove(&self, program: &Program, inputs: &[u32], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError> {
        // Run up to the largest tier's cycle budget; a program that has not halted by then
        // can never be proved, so `OutOfCycles` and `TooManyCycles` agree on the limit.
        let exec = execute(program, inputs, Tier(*TIERS.last().unwrap()).max_cycles()).map_err(ProveError::Exec)?;
        let tier = match tier { Some(t) => t, None => Tier::for_cycles(exec.cycles()).ok_or(ProveError::NoTier(exec.cycles()))? };
        let traces = build_traces(program, &exec, tier)?;
        Ok((self.prove_traces(program, &traces, tier), exec))
    }

    /// NOTE: the body below is duplicated, deliberately, by `prove_on` (the generic-over-config
    /// twin used by `Backend::Reference`/`Backend::Cuda`). The two must stay identical in every
    /// proof-shaping respect — instance construction, the `i == 1` public-values placement, and
    /// the `key_config`/`self.config` split between the key's prover data and `prove_batch` —
    /// or a backend proof stops matching what the CPU verifier recomputes. Change one, change
    /// the other.
    pub fn prove_traces(&self, program: &Program, traces: &Traces, tier: Tier) -> Proof {
        let airs = chips(program, tier);
        let mats = traces.as_slice();
        let instances: Vec<StarkInstance<'_, Config, Chip>> = airs.iter().zip(mats.iter()).enumerate().map(|(i, (air, trace))| StarkInstance {
            air, trace, public_values: if i == 1 { traces.public_values.clone() } else { vec![] },
        }).collect();
        // Built with `key_config` so the preprocessed tree's commitment (and the leaf data
        // `prove_batch` opens it against) matches exactly what a verifier will recompute via
        // `verifier_key`. `prove_batch` itself still runs against `self.config` (fresh entropy)
        // for the main trace, quotient, and permutation commitments: see the doc comment on
        // `key_config` and the confirmation below that `prove_batch` never re-derives the
        // preprocessed commitment from its `config` argument.
        //
        // Confirmed in `p3-batch-stark-0.7.0/src/prover.rs`: `prove_batch` reads the
        // preprocessed commitment and metadata from `prover_data.common.preprocessed`, and
        // opens it using `prover_data.prover_only.preprocessed_prover_data` directly (see the
        // "Round 3" block that builds `rounds` for `pcs.open_with_preprocessing`). It only
        // calls `config.pcs()` for the PCS's structural operations (domains, the main/quotient/
        // permutation commits, and the actual opening machinery) — never to recompute or
        // re-commit the preprocessed trace. So `config` and the config used to build
        // `prover_data` only need to be *structurally* compatible (same hash/compress/Dft/FRI
        // parameters, which `key_config` and `make_config` share via `build_config`); their
        // RNG state can differ freely.
        let key_cfg = key_config(self.profile, program);
        let prover_data = ProverData::from_airs_and_degrees(&key_cfg, &airs, &self.log_ext_degrees(program, tier));
        let batch = prove_batch(&self.config, &instances, &prover_data);
        Proof { tier, public_values: traces.public_values.iter().map(|x| x.as_canonical_u64()).collect(), batch }
    }

    /// Prove on `backend`. `Backend::Cpu` is exactly `prove`; the other backends run the same
    /// batch STARK with `rand-zkvm-cuda`'s engines and hand back a `Proof` that this
    /// `Machine`'s own `verify` accepts.
    pub fn prove_with(&self, backend: Backend, program: &Program, inputs: &[u32], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError> {
        match backend {
            Backend::Cpu => self.prove(program, inputs, tier),
            #[cfg(feature = "reference-backend")]
            Backend::Reference => {
                // Fresh entropy for the proving config (hiding), deterministic for the key
                // config — the same split `make_config`/`key_config` make on the CPU.
                let cfg = reference_cfg::config(self.profile, StdRng::from_rng(&mut rand::rng()), StdRng::from_rng(&mut rand::rng()));
                let (mmcs_rng, pcs_rng) = key_rngs(program);
                let key = reference_cfg::config(self.profile, mmcs_rng, pcs_rng);
                self.prove_on(&cfg, &key, program, inputs, tier)
            }
            #[cfg(any(feature = "cuda", feature = "mock-cuda"))]
            Backend::Cuda => {
                let gpu = rand_zkvm_cuda::gpu::GpuProver::probe(PERM_SEED).map_err(|e| ProveError::Backend(e.to_string()))?;
                let cfg = cuda_cfg::config(self.profile, gpu.clone(), StdRng::from_rng(&mut rand::rng()), StdRng::from_rng(&mut rand::rng()));
                let (mmcs_rng, pcs_rng) = key_rngs(program);
                let key = cuda_cfg::config(self.profile, gpu, mmcs_rng, pcs_rng);
                self.prove_on(&cfg, &key, program, inputs, tier)
            }
        }
    }

    /// The body of `prove`/`prove_traces` over any structurally compatible config. The proof
    /// is converted to the CPU `Config` by a postcard round trip: the alternative configs
    /// commit with the same Poseidon2 permutation, the same salt stream and the same FRI
    /// parameters, so the wire encodings of their commitments and opening proofs are
    /// byte-identical to the CPU ones and the decode is a pure retyping.
    ///
    /// `key_cfg` must be seeded from `key_rngs`: the preprocessed commitment is what the
    /// verifier recomputes on the CPU via `verifier_key`, and the backend has to reproduce it
    /// exactly or verification fails at the first check.
    ///
    /// NOTE: this body is a deliberate duplicate of `prove_traces`'s (which cannot be generic
    /// over `SC` because `Proof` names the CPU `Config`). Instance construction, the `i == 1`
    /// public-values placement, and the `key_cfg`/`cfg` split must stay identical in both, or a
    /// backend proof stops matching what the CPU verifier recomputes. Change one, change the
    /// other.
    #[cfg(any(feature = "reference-backend", feature = "cuda", feature = "mock-cuda"))]
    fn prove_on<SC>(&self, cfg: &SC, key_cfg: &SC, program: &Program, inputs: &[u32], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError>
    where
        SC: StarkGenericConfig<Challenge = Challenge, Challenger = Challenger>,
        // Bounds copied from `p3_batch_stark::prove_batch`'s signature, plus the pin that
        // makes this config's base field our `Val` so `Chip`'s `Air` impls apply.
        SC::Pcs: p3_commit::Pcs<Challenge, Challenger, Domain: p3_commit::PolynomialSpace<Val = Val>> + Sync,
        p3_batch_stark::Domain<SC>: Send + Sync,
        <SC::Pcs as p3_commit::Pcs<Challenge, Challenger>>::ProverData: Sync,
        <SC::Pcs as p3_commit::Pcs<Challenge, Challenger>>::Commitment: Sync,
    {
        // Mirrors `prove`: run up to the largest tier's cycle budget, so `OutOfCycles` and
        // `TooManyCycles` agree on the limit here exactly as they do on the CPU path.
        let exec = execute(program, inputs, Tier(*TIERS.last().unwrap()).max_cycles()).map_err(ProveError::Exec)?;
        let tier = match tier { Some(t) => t, None => Tier::for_cycles(exec.cycles()).ok_or(ProveError::NoTier(exec.cycles()))? };
        let traces = build_traces(program, &exec, tier)?;
        let airs = chips(program, tier);
        let mats = traces.as_slice();
        let instances: Vec<StarkInstance<'_, SC, Chip>> = airs.iter().zip(mats.iter()).enumerate().map(|(i, (air, trace))| StarkInstance {
            air, trace, public_values: if i == 1 { traces.public_values.clone() } else { vec![] },
        }).collect();
        // `log_ext_degrees` reads `self.config.is_zk()` — the *CPU* config — not `key_cfg`'s.
        // That is invariant, not a leak: every backend config (`reference_cfg`, `cuda_cfg`) is
        // built on `HidingFriPcs` just as `make_config` is, so `is_zk()` is `true` for all of
        // them and the degree bits agree with what `verify` recomputes.
        let prover_data = ProverData::from_airs_and_degrees(key_cfg, &airs, &self.log_ext_degrees(program, tier));
        // The engines panic (rather than return) on a device failure — `CudaHashEngine::ok`
        // and friends — so a backend fault must not take the caller's process down with it.
        let batch = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prove_batch(cfg, &instances, &prover_data)))
            .map_err(|p| ProveError::Backend(panic_message(p)))?;
        let bytes = postcard::to_allocvec(&batch).map_err(|e| ProveError::Backend(format!("proof serialise: {e}")))?;
        let batch: BatchProof<Config> = postcard::from_bytes(&bytes).map_err(|e| ProveError::Backend(format!("proof convert: {e}")))?;
        Ok((Proof { tier, public_values: traces.public_values.iter().map(|x| x.as_canonical_u64()).collect(), batch }, exec))
    }

    pub fn verify(&self, program: &Program, proof: &Proof) -> Result<(), VerifyError> {
        if proof.public_values.len() != crate::tables::cpu::pv::NUM { return Err(VerifyError::PublicValues); }
        // `public_values` is deserialized from untrusted bytes as raw `u64`s, and
        // `Val::from_u64` does not reduce: `out0` and `out0 + p` are the same field element
        // and both verify, but they are different `to_bytes()` and different numbers to
        // anyone reading the proof. Insist on the canonical representative so a proof has
        // exactly one encoding of its outputs.
        if proof.public_values.iter().any(|x| *x >= Val::ORDER_U64) { return Err(VerifyError::PublicValues); }
        if proof.public_values[crate::tables::cpu::pv::PC_ENTRY] != program.base_pc as u64 { return Err(VerifyError::PublicValues); }
        if proof.public_values[crate::tables::cpu::pv::TIER] != proof.tier.0 as u64 { return Err(VerifyError::Tier); }
        // `proof.tier` is deserialized from untrusted bytes: an attacker-supplied out-of-range
        // tier (anything not in TIERS) must be rejected here, before `log_ext_degrees` calls
        // `Tier::cpu_height`/`alu_height`/`mem_height`, which shift by `self.0` and panic in
        // debug builds for a large enough tier (e.g. `1usize << 99`).
        if !TIERS.contains(&proof.tier.0) { return Err(VerifyError::Tier); }
        if proof.batch.degree_bits != self.log_ext_degrees(program, proof.tier) { return Err(VerifyError::Tier); }
        let airs = chips(program, proof.tier);
        let pv: Vec<Val> = proof.public_values.iter().map(|x| Val::from_u64(*x)).collect();
        let pvs: Vec<Vec<Val>> = (0..7).map(|i| if i == 1 { pv.clone() } else { vec![] }).collect();
        let common = self.verifier_key(program, proof.tier);
        verify_batch(&self.config, &airs, &proof.batch, &pvs, &common).map_err(|e| VerifyError::Batch(format!("{e:?}")))
    }
}

/// Symbolic max constraint degree of each chip, in `chips()` order — computed the same way
/// `ProverData::from_airs_and_degrees` (i.e. `verifier_key`) derives each instance's quotient
/// chunk count: against the real, same-bus-packed lookup contexts for `(program, tier)`, not
/// a hand-counted estimate. No proving happens here — only the symbolic constraint walk
/// (`p3_batch_stark::symbolic::get_max_constraint_degree`) plus the one preprocessed-column
/// commitment `from_airs_and_degrees` always does, so this stays fast.
///
/// Exists to back `tests/tables.rs`'s per-table constraint-degree regression tests: each
/// table's degree is pinned to a specific number there, with a comment on *why*; a change
/// here should come with a matching update to those assertions and to
/// `docs/02-tables-and-buses.md`.
pub fn max_constraint_degrees(program: &Program, tier: Tier) -> Vec<usize> {
    let machine = Machine::new(FriProfile::Test);
    let key_cfg = key_config(machine.profile, program);
    let airs = chips(program, tier);
    let is_zk = machine.config.is_zk();
    let ext_degrees = machine.log_ext_degrees(program, tier);
    let prover_data = ProverData::from_airs_and_degrees(&key_cfg, &airs, &ext_degrees);
    let lookup_gadget = p3_lookup::LogUpGadget::new();
    airs.iter()
        .zip(prover_data.common.lookups.iter())
        .zip(ext_degrees.iter())
        .map(|((air, lookups), &ext_db)| {
            let trace_len = 1usize << (ext_db - is_zk);
            p3_batch_stark::symbolic::get_max_constraint_degree::<Val, Challenge, Chip, _>(
                air,
                p3_air::symbolic::AirLayout::from_air(air),
                trace_len,
                lookups,
                &lookup_gadget,
            )
        })
        .collect()
}

#[cfg(test)]
mod fri_soundness_tests {
    use super::*;
    use p3_fri::FriParameters;

    /// `log_blowup` here mirrors the literal in `generic_config` — if that literal ever
    /// changes, this test's own `log_blowup` must change with it. `mmcs: ()` is valid
    /// because `conjectured_soundness_bits` has no bound on `M`.
    #[test]
    fn production_profile_meets_the_100_bit_conjectured_target() {
        let fri: FriParameters<()> = FriParameters {
            log_blowup: 3,
            log_final_poly_len: 0,
            max_log_arity: 3,
            num_queries: FriProfile::Production.num_queries(),
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: FriProfile::Production.pow_bits(),
            mmcs: (),
        };
        assert_eq!(FriProfile::Production.num_queries(), 27);
        assert_eq!(FriProfile::Production.pow_bits(), 20);
        assert!(fri.conjectured_soundness_bits() >= 100, "got {}", fri.conjectured_soundness_bits());
    }
}
