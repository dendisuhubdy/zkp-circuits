use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use rand_zkvm_cuda::dft::Dft;
use rand_zkvm_cuda::ntt::cpu::CpuNttEngine;

fn mat(rng: &mut StdRng, n: usize, w: usize) -> RowMajorMatrix<Goldilocks> {
    RowMajorMatrix::new((0..n * w).map(|_| Goldilocks::from_u64(rng.random::<u64>() % 0xFFFF_FFFF_0000_0001)).collect(), w)
}

#[test]
fn every_entry_point_matches_radix2dit_parallel() {
    let ours = Dft::<CpuNttEngine>::default();
    let theirs = Radix2DitParallel::<Goldilocks>::default();
    let mut rng = StdRng::seed_from_u64(11);
    let shift = Goldilocks::GENERATOR;
    for log_n in [1usize, 2, 5, 10, 11, 14] {
        let n = 1 << log_n;
        for w in [1usize, 5, 56] {
            let m = mat(&mut rng, n, w);
            assert_eq!(ours.dft_batch(m.clone()).to_row_major_matrix(), theirs.dft_batch(m.clone()).to_row_major_matrix(), "dft n={n} w={w}");
            assert_eq!(ours.idft_batch(m.clone()), theirs.idft_batch(m.clone()), "idft n={n} w={w}");
            for added in [1usize, 3, 4] {
                assert_eq!(ours.coset_lde_batch(m.clone(), added, shift).to_row_major_matrix(),
                           theirs.coset_lde_batch(m.clone(), added, shift).to_row_major_matrix(), "lde n={n} w={w} added={added}");
            }
            assert_eq!(ours.coset_idft_batch(m.clone(), shift), theirs.coset_idft_batch(m.clone(), shift), "coset_idft n={n} w={w}");
        }
    }
}

#[test]
fn column_chunking_gives_identical_results() {
    // A chunking engine that admits 3 columns at a time must give the same answer.
    #[derive(Clone, Default)] struct Narrow(CpuNttEngine);
    impl rand_zkvm_cuda::ntt::NttEngine for Narrow {
        type Buf = Vec<u64>;
        fn max_columns(&self, _n: usize) -> usize { 3 }
        fn upload_row_major(&self, v: &[u64], n: usize, w: usize) -> Vec<u64> { self.0.upload_row_major(v, n, w) }
        fn download_row_major(&self, b: &Vec<u64>, n: usize, w: usize) -> Vec<u64> { self.0.download_row_major(b, n, w) }
        fn dif(&self, b: &mut Vec<u64>, n: usize, w: usize, inv: bool) { self.0.dif(b, n, w, inv) }
        fn bit_reverse(&self, b: &Vec<u64>, n: usize, w: usize) -> Vec<u64> { self.0.bit_reverse(b, n, w) }
        fn scale_pow(&self, b: &mut Vec<u64>, n: usize, w: usize, base: u64, u: u64) { self.0.scale_pow(b, n, w, base, u) }
        fn zero_extend(&self, b: &Vec<u64>, n: usize, w: usize, k: usize) -> Vec<u64> { self.0.zero_extend(b, n, w, k) }
    }
    let narrow = Dft::<Narrow>::default();
    let wide = Dft::<CpuNttEngine>::default();
    let mut rng = StdRng::seed_from_u64(12);
    let m = mat(&mut rng, 64, 10);
    assert_eq!(narrow.coset_lde_batch(m.clone(), 2, Goldilocks::GENERATOR).to_row_major_matrix(),
               wide.coset_lde_batch(m, 2, Goldilocks::GENERATOR).to_row_major_matrix());
}
