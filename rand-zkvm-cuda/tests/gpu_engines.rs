#![cfg(feature = "mock-driver")]
use std::sync::Arc;
use p3_commit::Mmcs;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use rand_zkvm_cuda::dft::Dft;
use rand_zkvm_cuda::gpu::{hash::CudaHashEngine, ntt::CudaNttEngine, GpuProver};
use rand_zkvm_cuda::merkle::{cpu::CpuHashEngine, mmcs::HidingMmcs};
use rand_zkvm_cuda::ntt::cpu::CpuNttEngine;

const SEED: u64 = 0x5261_6e64_5a4b;
fn gpu() -> Arc<GpuProver> {
    let dir = std::env::temp_dir().join("rand-zkvm-cuda-mock"); std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("k.ptx"); std::fs::write(&p, "// mock").unwrap(); std::env::set_var("RAND_ZKVM_PTX", &p);
    GpuProver::probe(SEED).unwrap()
}
fn mat(rng: &mut StdRng, n: usize, w: usize) -> RowMajorMatrix<Goldilocks> { RowMajorMatrix::new((0..n * w).map(|_| Goldilocks::from_u64(rng.random::<u64>() % 0xFFFF_FFFF_0000_0001)).collect(), w) }

#[test]
fn cuda_dft_equals_cpu_dft_under_mock() {
    let g = gpu();
    let cuda = Dft(Arc::new(CudaNttEngine { gpu: g }));
    let cpu = Dft::<CpuNttEngine>::default();
    let mut rng = StdRng::seed_from_u64(41);
    for log_n in [1usize, 4, 10, 11, 13] { for w in [1usize, 6] {
        let m = mat(&mut rng, 1 << log_n, w);
        assert_eq!(cuda.coset_lde_batch(m.clone(), 3, Goldilocks::GENERATOR).to_row_major_matrix(), cpu.coset_lde_batch(m.clone(), 3, Goldilocks::GENERATOR).to_row_major_matrix());
        assert_eq!(cuda.coset_idft_batch(m.clone(), Goldilocks::GENERATOR), cpu.coset_idft_batch(m, Goldilocks::GENERATOR));
    } }
}

#[test]
fn cuda_mmcs_equals_cpu_mmcs_under_mock() {
    let g = gpu();
    let cuda = HidingMmcs::new(Arc::new(CudaHashEngine { gpu: g }), SEED, 2, StdRng::seed_from_u64(9));
    let cpu = HidingMmcs::new(Arc::new(CpuHashEngine::new(SEED)), SEED, 2, StdRng::seed_from_u64(9));
    let mut rng = StdRng::seed_from_u64(42);
    let ms: Vec<_> = [(1usize << 10, 56), (1 << 11, 20), (1 << 12, 12), (1 << 6, 3), (1 << 12, 1)].iter().map(|&(h, w)| mat(&mut rng, h, w)).collect();
    let (c1, pd1) = cuda.commit(ms.clone());
    let (c2, pd2) = cpu.commit(ms);
    assert_eq!(c1, c2);
    let idx: Vec<usize> = (0..50).map(|_| rng.random::<u64>() as usize % (1 << 12)).collect();
    let a = cuda.open_multi_batch(&idx, &pd1); let b = cpu.open_multi_batch(&idx, &pd2);
    assert_eq!(postcard::to_allocvec(&a).unwrap(), postcard::to_allocvec(&b).unwrap());
}
