use std::sync::Arc;
use p3_commit::{BatchOpeningRef, Mmcs};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::{Dimensions, Matrix};
use p3_matrix::dense::RowMajorMatrix;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use rand_zkvm_cuda::merkle::cpu::CpuHashEngine;
use rand_zkvm_cuda::merkle::mmcs::{HidingMmcs, P3Hiding, Compress, Hash, Perm};

const SEED: u64 = 0x5261_6e64_5a4b;

fn p3(rng_seed: u64) -> P3Hiding { let p = Perm::new_from_rng_128(&mut StdRng::seed_from_u64(SEED)); P3Hiding::new(Hash::new(p.clone()), Compress::new(p), 2, StdRng::seed_from_u64(rng_seed)) }
fn ours(rng_seed: u64) -> HidingMmcs<CpuHashEngine> { HidingMmcs::new(Arc::new(CpuHashEngine::new(SEED)), SEED, 2, StdRng::seed_from_u64(rng_seed)) }
fn mats(rng: &mut StdRng, shape: &[(usize, usize)]) -> Vec<RowMajorMatrix<Goldilocks>> {
    shape.iter().map(|&(h, w)| RowMajorMatrix::new((0..h * w).map(|_| Goldilocks::from_u64(rng.random::<u64>() % 0xFFFF_FFFF_0000_0001)).collect(), w)).collect()
}
const SHAPES: [&[(usize, usize)]; 3] = [&[(64, 5), (64, 2), (16, 3), (8, 1)], &[(1 << 12, 56), (1 << 13, 20), (1 << 14, 12), (1 << 14, 1)], &[(2, 1)]];

#[test]
fn commit_equals_plonky3_with_same_salt_rng() {
    let mut rng = StdRng::seed_from_u64(31);
    for shape in SHAPES {
        let m = mats(&mut rng, shape);
        let (c1, _) = p3(77).commit(m.clone());
        let (c2, _) = ours(77).commit(m);
        assert_eq!(c1, c2, "{shape:?}");
    }
}

#[test]
fn plonky3_verifies_our_single_openings_and_rejects_tampering() {
    let mut rng = StdRng::seed_from_u64(32);
    for shape in SHAPES {
        let m = mats(&mut rng, shape);
        let dims: Vec<Dimensions> = m.iter().map(|x| x.dimensions()).collect();
        let o = ours(5);
        let (commit, pd) = o.commit(m);
        let max_h = dims.iter().map(|d| d.height).max().unwrap();
        for index in [0usize, 1, max_h / 2, max_h - 1] {
            let opening = o.open_batch(index, &pd);
            p3(0).verify_batch(&commit, &dims, index, BatchOpeningRef::new(&opening.opened_values, &opening.opening_proof)).unwrap();
            o.verify_batch(&commit, &dims, index, BatchOpeningRef::new(&opening.opened_values, &opening.opening_proof)).unwrap();
            let mut bad = opening.opened_values.clone();
            bad[0][0] += Goldilocks::ONE;
            assert!(p3(0).verify_batch(&commit, &dims, index, BatchOpeningRef::new(&bad, &opening.opening_proof)).is_err());
        }
    }
}

#[test]
fn plonky3_verifies_our_pruned_multi_openings() {
    let mut rng = StdRng::seed_from_u64(33);
    for shape in SHAPES {
        let m = mats(&mut rng, shape);
        let dims: Vec<Dimensions> = m.iter().map(|x| x.dimensions()).collect();
        let o = ours(6);
        let (commit, pd) = o.commit(m.clone());
        let max_h = dims.iter().map(|d| d.height).max().unwrap();
        let indices: Vec<usize> = (0..80).map(|_| rng.random::<u64>() as usize % max_h).collect();
        let (opened, proof) = o.open_multi_batch(&indices, &pd);
        p3(0).verify_multi_batch(&commit, &dims, &indices, &opened, &proof).unwrap();
        o.verify_multi_batch(&commit, &dims, &indices, &opened, &proof).unwrap();
        // Same salts ⇒ byte-identical multi proof to Plonky3's own.
        let (_, pd3) = p3(6).commit(m);
        let (opened3, proof3) = p3(6).open_multi_batch(&indices, &pd3);
        assert_eq!(postcard::to_allocvec(&(opened3, proof3)).unwrap(), postcard::to_allocvec(&(opened, proof)).unwrap());
    }
}

#[test]
fn get_matrices_returns_unsalted_originals() {
    let mut rng = StdRng::seed_from_u64(34);
    let m = mats(&mut rng, SHAPES[0]);
    let o = ours(1);
    let (_, pd) = o.commit(m.clone());
    let got = o.get_matrices(&pd);
    assert_eq!(got.len(), m.len());
    for (a, b) in got.iter().zip(&m) { assert_eq!(a.width(), b.width()); assert_eq!(**a, *b); }
    assert_eq!(o.get_max_height(&pd), 64);
}
