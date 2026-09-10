use p3_commit::Mmcs;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use rand_zkvm_cuda::merkle::{build_tree, cap, cpu::CpuHashEngine, plan, HashEngine};

const SEED: u64 = 0x5261_6e64_5a4b;
type Perm = Poseidon2Goldilocks<8>;
type Hash = PaddingFreeSponge<Perm, 8, 4, 4>;
type Compress = TruncatedPermutation<Perm, 2, 4, 8>;
type Packing = <Goldilocks as Field>::Packing;
type Mmcs3 = MerkleTreeMmcs<Packing, Packing, Hash, Compress, 2, 4>;

fn mmcs() -> Mmcs3 { let p = Perm::new_from_rng_128(&mut StdRng::seed_from_u64(SEED)); Mmcs3::new(Hash::new(p.clone()), Compress::new(p), 2) }
fn rand_mat(rng: &mut StdRng, h: usize, w: usize) -> Vec<u64> { (0..h * w).map(|_| rng.random::<u64>() % 0xFFFF_FFFF_0000_0001).collect() }
fn to_p3(v: &[u64], w: usize) -> RowMajorMatrix<Goldilocks> { RowMajorMatrix::new(v.iter().map(|&x| Goldilocks::from_u64(x)).collect(), w) }

#[test]
fn plan_orders_tallest_first_stably_and_injects_at_matching_layers() {
    let p = plan(&[16, 64, 16, 8, 64]);
    assert_eq!(p.order, vec![1, 4, 0, 2, 3]);
    // layer 0 = leaves of the 64-high matrices; next layers 32, 16 (inject 0,2), 8 (inject 3), 4, 2, 1
    assert_eq!(p.layers, vec![vec![], vec![0, 2], vec![3], vec![], vec![], vec![]]);
}

#[test]
fn caps_equal_plonky3_for_every_tier_shape() {
    let e = CpuHashEngine::new(SEED);
    let m = mmcs();
    let mut rng = StdRng::seed_from_u64(21);
    // (heights, widths) shaped like the batch STARK at tier 10 after a ×16 hiding blowup: cpu, alu, mem, byte, program, random
    let shapes: Vec<Vec<(usize, usize)>> = vec![
        vec![(1 << 14, 56), (1 << 15, 24), (1 << 16, 16), (1 << 16, 8), (1 << 10, 6), (1 << 16, 1)],
        vec![(1 << 4, 3)],
        vec![(1 << 5, 2), (1 << 5, 7), (1 << 3, 1)],
        vec![(1 << 6, 1), (1 << 2, 4)],
    ];
    for shape in shapes {
        let mats: Vec<(Vec<u64>, usize, usize)> = shape.iter().map(|&(h, w)| (rand_mat(&mut rng, h, w), w, h)).collect();
        let (theirs_cap, _) = m.commit(mats.iter().map(|(v, w, _)| to_p3(v, *w)).collect());
        let up: Vec<_> = mats.iter().map(|(v, w, _)| e.upload(v, *w)).collect();
        let refs: Vec<_> = up.iter().zip(&mats).map(|(u, (_, w, h))| (u, *w, *h)).collect();
        let tree = build_tree(&e, &refs);
        let ours = cap(&tree, 2);
        let theirs: Vec<[u64; 4]> = theirs_cap.roots().iter().map(|d| d.map(|x| x.as_canonical_u64())).collect();
        assert_eq!(ours, theirs, "shape {shape:?}");
    }
}

/// The commit geometry gate: `plan` only injects a matrix at the layer whose length is
/// `height.next_power_of_two()`, so a height off Plonky3's `validate_commit_reachable_heights`
/// ladder has no layer to land on. 48 is not reachable from 64 (the ladder there is 64, 32, ...).
#[test]
#[should_panic(expected = "not reachable on the commit ladder")]
fn build_tree_rejects_a_height_off_the_commit_ladder() {
    let e = CpuHashEngine::new(SEED);
    let mut rng = StdRng::seed_from_u64(48);
    let mats: Vec<(Vec<u64>, usize, usize)> = [64usize, 48].iter().map(|&h| (rand_mat(&mut rng, h, 2), 2, h)).collect();
    let up: Vec<_> = mats.iter().map(|(v, w, _)| e.upload(v, *w)).collect();
    let refs: Vec<_> = up.iter().zip(&mats).map(|(u, (_, w, h))| (u, *w, *h)).collect();
    let _ = build_tree(&e, &refs);
}
