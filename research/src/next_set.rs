//! The next constraint set, opt-in (`--features next-set`). **Nothing here is the live
//! machine**: `machine::Machine`, its proof format, its verifier keys and `CONSTRAINT_SET` are
//! untouched by this module and by the feature, and a full node that vendors this crate
//! without the feature compiles none of it.
//!
//! What it carries today is one change (monorepo issue 65, ZKVM-112): **the poseidon2 table's
//! height is declared by the proof** instead of fixed at `2^(t+2)` by the tier. A proof's
//! header gains `poseidon2_log_height`, the verifier range-checks it against a small admitted
//! set before it builds anything, and the height is one more component of the verifier-key
//! tuple — the same treatment the keccak, sha256 and modq tables already have. The AIR of the
//! poseidon2 chip does not change: it is periodic in 32-row blocks at any height, and the
//! table at height `2^(t+2)` is exactly the current set's (`tests/next_set.rs` checks that the
//! key for that height is the current key).
//!
//! ## The admitted heights
//!
//! `{ t + 2, t, t − 2, … }` down to the private-data floor (`2^7` rows): the tier's present
//! height and every fourth of it. At the tiers in `TIERS` (all even) that is `8, 10, …, t + 2`
//! — `(t − 4) / 2` shapes per tier, 3 at tier 10 and 8 at tier 20 — where admitting every
//! height from 7 would be `t − 4`. The price of the coarser set is a table at most four times
//! taller than the workload needs. Each admitted height is a distinct verifier key, which is
//! why the set is kept small and why [`check_poseidon2_log_height`] runs before any key build
//! (the CON-60 / CON-701 findings were junk proofs forcing key builds).
//!
//! ## What is and is not done
//!
//! Done and tested at tiers 10 to 14: proving and verifying at a declared height, the range
//! check, the refusals, the key-build counts. Not done: the rVM's verifier of this machine
//! (`../recursion`'s `shape.rs` reads a seven-component tuple), the gas ceiling
//! (`gas::gas_max` still charges the tier's full permutation budget; it could fall with the
//! declared height the way it does for keccak), the key blob (`VerifierKeyBlob`), and the GPU
//! backends. `docs/05-roadmap.md`, "ZKVM-112", lists them.
use crate::emulator::{execute, Execution};
use crate::isa::Program;
use crate::machine::{self, chips_at, key_config, Config, FriProfile, ProveError, ProveOptions, Tier, Val, TIERS};
use crate::tables::poseidon2::BLOCK;
use crate::tables::MIN_PRIVATE_TABLE_LOG_HEIGHT;
use p3_batch_stark::{prove_batch, verify_batch, CommonData, ProverData};
use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// The number this set would carry: one past the live `machine::CONSTRAINT_SET`.
pub const CONSTRAINT_SET: u32 = machine::CONSTRAINT_SET + 1;

/// Admitted heights are this many doublings apart, counted down from the tier's maximum.
pub const POSEIDON2_HEIGHT_STEP: u8 = 2;

/// The tallest poseidon2 table a tier admits — the current set's fixed height, `t + 2`.
pub fn max_poseidon2_log_height(tier: Tier) -> u8 {
    tier.poseidon2_height().trailing_zeros() as u8
}

/// The admitted heights of a tier, smallest first.
pub fn admitted_poseidon2_log_heights(tier: Tier) -> Vec<u8> {
    let max = max_poseidon2_log_height(tier);
    let mut v: Vec<u8> = (0..).map(|k| max as i32 - (k * POSEIDON2_HEIGHT_STEP as i32)).take_while(|h| *h >= MIN_PRIVATE_TABLE_LOG_HEIGHT as i32).map(|h| h as u8).collect();
    v.reverse();
    v
}

/// The height a prover declares for `permutations` permutations at `tier`: the smallest
/// admitted one whose table holds them (one 32-row block each). `None` if even the tier's
/// maximum does not.
pub fn poseidon2_log_height(tier: Tier, permutations: usize) -> Option<u8> {
    admitted_poseidon2_log_heights(tier).into_iter().find(|h| permutations * BLOCK <= 1usize << h)
}

/// Why a next-set proof was refused.
#[derive(Debug, PartialEq)]
pub enum VerifyError {
    /// `poseidon2_log_height` is under the private-data floor.
    Poseidon2HeightBelowFloor { declared: u8 },
    /// `poseidon2_log_height` exceeds the tier's maximum, `t + 2`.
    Poseidon2HeightExceedsTier { declared: u8, max: u8 },
    /// `poseidon2_log_height` is inside the range but not one of the tier's admitted heights.
    Poseidon2HeightNotAdmitted { declared: u8 },
    /// Any refusal the current set's verifier also makes.
    Machine(machine::VerifyError),
}

/// The range check on a declared poseidon2 height. `tier` must already be known to be in
/// `TIERS` (`machine::check_declared_heights_with_modq` is what establishes that, and
/// [`Machine::verify`] calls it first); an unknown tier is refused here too rather than
/// trusted.
pub fn check_poseidon2_log_height(tier: Tier, declared: u8) -> Result<(), VerifyError> {
    if !TIERS.contains(&tier.0) {
        return Err(VerifyError::Machine(machine::VerifyError::Tier));
    }
    if declared < MIN_PRIVATE_TABLE_LOG_HEIGHT {
        return Err(VerifyError::Poseidon2HeightBelowFloor { declared });
    }
    let max = max_poseidon2_log_height(tier);
    if declared > max {
        return Err(VerifyError::Poseidon2HeightExceedsTier { declared, max });
    }
    if (max - declared) % POSEIDON2_HEIGHT_STEP != 0 {
        return Err(VerifyError::Poseidon2HeightNotAdmitted { declared });
    }
    Ok(())
}

/// A next-set proof: the current set's proof with the poseidon2 table's declared height in the
/// header. (At the cut the field moves into `machine::Proof`; a wrapper keeps the live struct's
/// encoding untouched meanwhile.)
#[derive(Serialize, Deserialize)]
pub struct Proof {
    /// The poseidon2 table's height, as a base-2 log. Public: it bounds the number of Poseidon2
    /// permutations the run made (program, input and public digests included) to within the
    /// admitted set's factor of four — one more structural fact of the kind
    /// `keccak_log_height` already is (`docs/03-privacy.md`, "What a proof leaks").
    pub poseidon2_log_height: u8,
    pub inner: machine::Proof,
}

/// The verifier-key tuple: the current set's seven components and the poseidon2 height.
pub type KeyTuple = (usize, u8, u8, u8, u8, u8, u8, u8);

fn key_tuple(p: &Proof) -> KeyTuple {
    (p.inner.tier.0, p.inner.program_log_height, p.inner.input_log_height, p.inner.keccak_log_height, p.inner.sha256_log_height, p.inner.modq_log_height, p.inner.public_log_height, p.poseidon2_log_height)
}

/// The number of Poseidon2 permutations a run makes, counted the way
/// `machine::build_traces_salted` counts them: one per program-digest, input-digest and
/// public-digest row and one per syscall absorb row.
pub fn permutations(program: &Program, inputs: &[u32], public: &[u32], exec: &Execution) -> usize {
    let absorb_rows = exec.events.iter().filter(|e| matches!(e.hash_row, Some(crate::emulator::HashRow::Absorb { .. }))).count();
    program.digest_rows() + crate::hash::input_digest_row_count(inputs.len()) + crate::hash::public_digest_row_count(public.len()) + absorb_rows
}

/// The next-set machine: the current machine's configuration and trace builder, with the
/// poseidon2 table at the declared height. Keys are cached without eviction — a test
/// instrument, not the full node's cache.
pub struct Machine {
    inner: machine::Machine,
    keys: Mutex<HashMap<KeyTuple, Arc<CommonData<Config>>>>,
    key_builds: AtomicUsize,
}

impl Machine {
    pub fn new(profile: FriProfile) -> Self {
        Self { inner: machine::Machine::new(profile), keys: Mutex::new(HashMap::new()), key_builds: AtomicUsize::new(0) }
    }

    /// Verifier keys built so far (never evicted), for tests that show a refusal built none.
    pub fn key_builds(&self) -> usize {
        self.key_builds.load(Ordering::SeqCst)
    }

    /// Prove, declaring the smallest admitted poseidon2 height that holds the run.
    pub fn prove(&self, program: &Program, inputs: &[u32], public: &[u32], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError> {
        self.prove_declaring(program, inputs, public, tier, None)
    }

    /// [`Self::prove`] with the declared height chosen by the caller (`None`: the smallest that
    /// fits). A height that is not admitted, or too small for the run, is an error — the
    /// prover refuses what the verifier would.
    pub fn prove_declaring(&self, program: &Program, inputs: &[u32], public: &[u32], tier: Option<Tier>, poseidon2_log_height: Option<u8>) -> Result<(Proof, Execution), ProveError> {
        use rand::RngExt;
        let exec = execute(program, inputs, public, Tier(*TIERS.last().unwrap()).max_cycles()).map_err(ProveError::Exec)?;
        let perms = permutations(program, inputs, public, &exec);
        let tier = match tier {
            Some(t) if TIERS.contains(&t.0) => t,
            Some(t) => return Err(ProveError::BadTier(t.0)),
            None => {
                let cycles = exec.cycles() + program.digest_rows() + crate::hash::input_digest_row_count(inputs.len()) + crate::hash::public_digest_row_count(public.len());
                Tier::for_workload(cycles, perms).ok_or(ProveError::NoTier(cycles))?
            }
        };
        let too_many = ProveError::TooManyPoseidon2Permutations { perms, tier };
        let declared = match poseidon2_log_height {
            None => match self::poseidon2_log_height(tier, perms) {
                Some(h) => h,
                None => return Err(too_many),
            },
            Some(h) => {
                if check_poseidon2_log_height(tier, h).is_err() || perms * BLOCK > 1usize << h {
                    return Err(too_many);
                }
                h
            }
        };
        let salt: [u32; 4] = rand::rng().random();
        // The current set's builder lays the poseidon2 table out as the run's blocks in order,
        // then identical padding blocks up to the tier's height. The first `2^declared` rows
        // are therefore exactly the table at the declared height.
        let mut traces = machine::build_traces_salted_with(program, inputs, public, salt, &exec, tier, ProveOptions::default())?;
        let width = p3_matrix::Matrix::width(&traces.poseidon2);
        traces.poseidon2.values.truncate((1usize << declared) * width);
        let blinds = crate::tables::blind::fresh(traces.as_slice().len());
        let inner = self.inner.prove_traces_at(&traces, tier, &blinds, 1usize << declared, |cfg, instances, prover_data| prove_batch(cfg, instances, prover_data));
        Ok((Proof { poseidon2_log_height: declared, inner }, exec))
    }

    /// The key for a tuple, built on first use. The caller has range-checked every component.
    fn key(&self, k: KeyTuple) -> Arc<CommonData<Config>> {
        if let Some(c) = self.keys.lock().unwrap().get(&k) {
            return c.clone();
        }
        let (tier, plh, ilh, klh, slh, mlh, publh, p2lh) = (Tier(k.0), k.1, k.2, k.3, k.4, k.5, k.6, k.7);
        self.key_builds.fetch_add(1, Ordering::SeqCst);
        let airs = chips_at(tier, klh, slh, mlh, 1usize << p2lh);
        let degrees = self.inner.log_ext_degrees_at(tier, plh, ilh, klh, slh, mlh, publh, tier.min_mem_log_height(), 1usize << p2lh);
        let common = Arc::new(ProverData::from_airs_and_degrees(&key_config(self.inner.profile), &airs, &degrees).common);
        self.keys.lock().unwrap().insert(k, common.clone());
        common
    }

    /// The verifier key's preprocessed commitment for a tuple, as the current machine exposes
    /// its own through `verifier_key`: for comparing the two at the tier's maximum height.
    pub fn verifier_key(&self, k: KeyTuple) -> Arc<CommonData<Config>> {
        self.key(k)
    }

    /// `machine::Machine::verify`, step for step, with the declared poseidon2 height
    /// range-checked alongside the other declared heights — before the degree-bits comparison
    /// and before any key is built — and used wherever the current set uses the tier's.
    pub fn verify(&self, hc: &[u32; 8], proof: &Proof) -> Result<(), VerifyError> {
        let p = &proof.inner;
        machine::check_public_values(hc, p).map_err(VerifyError::Machine)?;
        machine::check_declared_heights_with_modq(p.tier, p.program_log_height, p.input_log_height, p.keccak_log_height, p.sha256_log_height, p.modq_log_height, p.public_log_height, p.mem_log_height)
            .map_err(VerifyError::Machine)?;
        check_poseidon2_log_height(p.tier, proof.poseidon2_log_height)?;
        let entry_pc = p.public_values[crate::tables::cpu::pv::PC_ENTRY];
        if !crate::tables::program::pc_window_fits(entry_pc, p.program_log_height) {
            return Err(VerifyError::Machine(machine::VerifyError::PcWindow { entry_pc, program_log_height: p.program_log_height }));
        }
        machine::check_commit_pow_witnesses(p).map_err(VerifyError::Machine)?;
        let height = 1usize << proof.poseidon2_log_height;
        let degrees = self.inner.log_ext_degrees_at(p.tier, p.program_log_height, p.input_log_height, p.keccak_log_height, p.sha256_log_height, p.modq_log_height, p.public_log_height, p.mem_log_height, height);
        if p.batch.degree_bits != degrees {
            return Err(VerifyError::Machine(machine::VerifyError::Tier));
        }
        let airs = chips_at(p.tier, p.keccak_log_height, p.sha256_log_height, p.modq_log_height, height);
        let pv_vals: Vec<Val> = p.public_values.iter().map(|x| Val::from_u64(*x)).collect();
        let pvs: Vec<Vec<Val>> = (0..airs.len()).map(|i| if i == 1 { pv_vals.clone() } else { vec![] }).collect();
        let common = self.key(key_tuple(proof));
        verify_batch(&self.inner.config, &airs, &p.batch, &pvs, &common).map_err(|e| VerifyError::Machine(machine::VerifyError::Batch(format!("{e:?}"))))
    }
}
