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

/// HCS-2 (the 2026-09-27 zkVM review, with INT-3): the constants every live hash on this crate's
/// engines uses are the committed table, not a seeded draw. `research` and `recursion` hand the
/// engines exactly one seed — `PERM_SEED`, through `CpuHashEngine::new`, `GpuProver::probe` and
/// `HidingMmcs::new` — and for that seed `constants::{permutation, poseidon2_constants}` return the
/// `#[path]`-included `research/src/poseidon2_constants.rs` table without constructing a `StdRng`
/// (the seeded branch exists for this file's other-seed differential tests only). Checked here with
/// no `rand` in the loop: the device-layout constants are the table's rows in the device order, and
/// both the host permutation and the device kernel answer the table's own known vectors (the ones
/// `poseidon2_constants::tests` pins, captured before the table existed). If this crate ever drifted
/// back to a seeded draw — or a `rand` upgrade changed `StdRng` under the other tests here — this
/// test would still hold for the chain's constants, which is the point: it is the one that must.
#[test]
fn the_chain_seed_reads_the_committed_table_not_an_rng() {
    use rand_zkvm_cuda::constants::table;
    assert_eq!(SEED, table::PERM_SEED);
    let k = poseidon2_constants(table::PERM_SEED);
    let layout: Vec<u64> = table::INITIAL.iter().flatten().chain(table::INTERNAL.iter()).chain(table::TERMINAL.iter().flatten()).copied().collect();
    assert_eq!(k.to_vec(), layout, "device constants = initial rows, internal scalars, terminal rows");
    let vectors: [([u64; 8], [u64; 8]); 3] = [
        ([0; 8], [0x1e4b2c9eebb442b0, 0x2fbb0154ab9d22da, 0x9c397e8d1b856b3d, 0x3900699f4fe93a6e, 0xcb37891674d3ad6b, 0x9b530f7ac1ef1f56, 0x0510bc15edfecf33, 0xf9caffe23a93cd28]),
        ([0, 1, 2, 3, 4, 5, 6, 7], [0x682c703ce406cd60, 0x35fe4cacd5147b44, 0xf0b819068ae2838e, 0xde5f0a9ba791a8f4, 0xcf8ee9826729b322, 0x38e89ce1e7fcb535, 0xf58f43c0801e00db, 0x694ec48edbb331fa]),
        ([0xffff_ffff_0000_0000; 8], [0xdfebf956a8205183, 0xbacca056a5ba1b75, 0xdc24d665e3f9864b, 0x1ad86aab4b3e131a, 0xc68f628d6f8833e6, 0x0b913e0aa0757959, 0x248d88435c62b658, 0x7bc6fc5500a81dbc]),
    ];
    let host = permutation(table::PERM_SEED);
    for (input, want) in vectors {
        assert_eq!(to_u64(&host.permute(input.map(Goldilocks::from_u64))), want.to_vec(), "host permute({input:x?})");
        let mut st = input;
        poseidon2::permute(&mut st, &k);
        assert_eq!(st, want, "device permute({input:x?})");
    }
}
