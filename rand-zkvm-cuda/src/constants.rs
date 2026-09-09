//! Regenerates the Poseidon2 round constants exactly as `Poseidon2Goldilocks::<8>::
//! new_from_rng_128(&mut StdRng::seed_from_u64(seed))` draws them: 4 initial rows, 4
//! terminal rows (via `ExternalLayerConstants::new_from_rng(8, rng)`), then 22 internal.
use p3_field::PrimeField64;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_poseidon2::ExternalLayerConstants;
use rand::distr::StandardUniform;
use rand::{RngExt, SeedableRng, rngs::StdRng};

pub const N_INITIAL: usize = 4;
pub const N_INTERNAL: usize = 22;
pub const N_TERMINAL: usize = 4;

pub fn permutation(seed: u64) -> Poseidon2Goldilocks<8> {
    Poseidon2Goldilocks::<8>::new_from_rng_128(&mut StdRng::seed_from_u64(seed))
}

pub fn poseidon2_constants(seed: u64) -> [u64; crate::device::poseidon2::N_CONSTS] {
    let mut rng = StdRng::seed_from_u64(seed);
    let ext = ExternalLayerConstants::<Goldilocks, 8>::new_from_rng(N_INITIAL + N_TERMINAL, &mut rng);
    let internal: Vec<Goldilocks> = (&mut rng).sample_iter(StandardUniform).take(N_INTERNAL).collect();
    let mut k = [0u64; crate::device::poseidon2::N_CONSTS];
    let mut i = 0;
    for row in ext.get_initial_constants() { for x in row { k[i] = x.as_canonical_u64(); i += 1; } }
    for x in &internal { k[i] = x.as_canonical_u64(); i += 1; }
    for row in ext.get_terminal_constants() { for x in row { k[i] = x.as_canonical_u64(); i += 1; } }
    debug_assert_eq!(i, crate::device::poseidon2::N_CONSTS);
    k
}
