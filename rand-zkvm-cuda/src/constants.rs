//! The Poseidon2 round constants the engines hash with. For the zkVM's own seed
//! (`table::PERM_SEED`, "RandZK") they come from the committed table in
//! `research/src/poseidon2_constants.rs` (audit finding ZKV-2), compiled into this crate by
//! `#[path]` below — the one table `rand_zkvm` builds its permutation and its poseidon2 chip
//! from, not a copy of it. Any other seed (this crate's own tests only) still regenerates the
//! constants exactly as `Poseidon2Goldilocks::<8>::new_from_rng_128(&mut StdRng::
//! seed_from_u64(seed))` draws them: 4 initial rows, 4 terminal rows (via
//! `ExternalLayerConstants::new_from_rng(8, rng)`), then 22 internal.
use p3_field::PrimeField64;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_poseidon2::ExternalLayerConstants;
use rand::distr::StandardUniform;
use rand::{RngExt, SeedableRng, rngs::StdRng};

/// `research`'s committed round-constant table, by path: `rand-zkvm-cuda` cannot depend on
/// `rand_zkvm` (the dependency runs the other way), so the file is compiled in here too.
#[path = "../../research/src/poseidon2_constants.rs"]
pub mod table;

pub const N_INITIAL: usize = 4;
pub const N_INTERNAL: usize = 22;
pub const N_TERMINAL: usize = 4;

pub fn permutation(seed: u64) -> Poseidon2Goldilocks<8> {
    if seed == table::PERM_SEED {
        return table::permutation();
    }
    Poseidon2Goldilocks::<8>::new_from_rng_128(&mut StdRng::seed_from_u64(seed))
}

/// The device layout: initial rows, then the internal scalars, then terminal rows.
pub fn poseidon2_constants(seed: u64) -> [u64; crate::device::poseidon2::N_CONSTS] {
    let (initial, internal, terminal): (Vec<[u64; 8]>, Vec<u64>, Vec<[u64; 8]>) = if seed == table::PERM_SEED {
        (table::INITIAL.to_vec(), table::INTERNAL.to_vec(), table::TERMINAL.to_vec())
    } else {
        let mut rng = StdRng::seed_from_u64(seed);
        let ext = ExternalLayerConstants::<Goldilocks, 8>::new_from_rng(N_INITIAL + N_TERMINAL, &mut rng);
        let internal: Vec<Goldilocks> = (&mut rng).sample_iter(StandardUniform).take(N_INTERNAL).collect();
        let rows = |r: &[[Goldilocks; 8]]| r.iter().map(|row| row.map(|x| x.as_canonical_u64())).collect();
        (rows(ext.get_initial_constants()), internal.iter().map(|x| x.as_canonical_u64()).collect(), rows(ext.get_terminal_constants()))
    };
    let mut k = [0u64; crate::device::poseidon2::N_CONSTS];
    let mut i = 0;
    for row in &initial { for x in row { k[i] = *x; i += 1; } }
    for x in &internal { k[i] = *x; i += 1; }
    for row in &terminal { for x in row { k[i] = *x; i += 1; } }
    debug_assert_eq!(i, crate::device::poseidon2::N_CONSTS);
    k
}
