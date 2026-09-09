use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge, Permutation, PseudoCompressionFunction, TruncatedPermutation};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use rand_zkvm_cuda::constants::{permutation, poseidon2_constants};
use rand_zkvm_cuda::device::poseidon2;

const SEED: u64 = 0x5261_6e64_5a4b; // the zkVM's PERM_SEED ("RandZK")

fn to_u64(v: &[Goldilocks]) -> Vec<u64> { v.iter().map(|x| x.as_canonical_u64()).collect() }

#[test]
fn regenerated_permutation_matches_new_from_rng_128() {
    let ours = permutation(SEED);
    let theirs = Poseidon2Goldilocks::<8>::new_from_rng_128(&mut StdRng::seed_from_u64(SEED));
    let mut rng = StdRng::seed_from_u64(9);
    for _ in 0..100 {
        let s: [Goldilocks; 8] = core::array::from_fn(|_| Goldilocks::from_u64(rng.random::<u64>() % 0xFFFF_FFFF_0000_0001));
        assert_eq!(ours.permute(s), theirs.permute(s));
    }
}

#[test]
fn u64_permutation_matches_plonky3_for_many_seeds() {
    for seed in [SEED, 0, 1, 42, u64::MAX] {
        let perm = Poseidon2Goldilocks::<8>::new_from_rng_128(&mut StdRng::seed_from_u64(seed));
        let k = poseidon2_constants(seed);
        let mut rng = StdRng::seed_from_u64(seed ^ 7);
        for _ in 0..2000 {
            let raw: [u64; 8] = core::array::from_fn(|_| rng.random::<u64>() % 0xFFFF_FFFF_0000_0001);
            let expected = to_u64(&perm.permute(raw.map(Goldilocks::from_u64)));
            let mut st = raw;
            poseidon2::permute(&mut st, &k);
            assert_eq!(st.to_vec(), expected, "seed {seed}");
        }
    }
}

#[test]
fn hash_row_matches_padding_free_sponge() {
    let perm = Poseidon2Goldilocks::<8>::new_from_rng_128(&mut StdRng::seed_from_u64(SEED));
    let sponge = PaddingFreeSponge::<_, 8, 4, 4>::new(perm.clone());
    let k = poseidon2_constants(SEED);
    let mut rng = StdRng::seed_from_u64(3);
    for len in [0usize, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 52, 56, 60, 100] {
        let row: Vec<u64> = (0..len).map(|_| rng.random::<u64>() % 0xFFFF_FFFF_0000_0001).collect();
        let expected = to_u64(&sponge.hash_iter(row.iter().map(|&x| Goldilocks::from_u64(x))));
        assert_eq!(poseidon2::hash_row(&row, &k).to_vec(), expected, "len {len}");
    }
}

#[test]
fn compress_matches_truncated_permutation() {
    let perm = Poseidon2Goldilocks::<8>::new_from_rng_128(&mut StdRng::seed_from_u64(SEED));
    let tp = TruncatedPermutation::<_, 2, 4, 8>::new(perm);
    let k = poseidon2_constants(SEED);
    let mut rng = StdRng::seed_from_u64(4);
    for _ in 0..1000 {
        let a: [u64; 4] = core::array::from_fn(|_| rng.random::<u64>() % 0xFFFF_FFFF_0000_0001);
        let b: [u64; 4] = core::array::from_fn(|_| rng.random::<u64>() % 0xFFFF_FFFF_0000_0001);
        let expected = to_u64(&tp.compress([a.map(Goldilocks::from_u64), b.map(Goldilocks::from_u64)]));
        assert_eq!(poseidon2::compress(&a, &b, &k).to_vec(), expected);
    }
}
