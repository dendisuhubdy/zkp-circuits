//! Hardware tests: the real CUDA driver (`--features cuda-hw`) against the CPU reference twins
//! and Plonky3's own DFT. Needs a GPU and the PTX at `GpuProver::ptx_path()` (see
//! `ptx/PTX_BUILD.md`); `gpu_engines.rs`/`gpu_driver.rs` are the same checks under the host mock.
#![cfg(feature = "cuda-hw")]
use std::sync::Arc;
use p3_commit::Mmcs;
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use rand_zkvm_cuda::dft::Dft;
use rand_zkvm_cuda::gpu::driver::{Arg, Device};
use rand_zkvm_cuda::gpu::{hash::CudaHashEngine, ntt::CudaNttEngine, GpuProver};
use rand_zkvm_cuda::merkle::{cpu::CpuHashEngine, mmcs::HidingMmcs};
use rand_zkvm_cuda::ntt::cpu::CpuNttEngine;

const SEED: u64 = 0x5261_6e64_5a4b;

fn gpu() -> Arc<GpuProver> {
    GpuProver::probe(SEED).unwrap_or_else(|e| panic!("GpuProver::probe: {e}"))
}
fn mat(rng: &mut StdRng, n: usize, w: usize) -> RowMajorMatrix<Goldilocks> {
    RowMajorMatrix::new((0..n * w).map(|_| Goldilocks::from_u64(rng.random::<u64>() % 0xFFFF_FFFF_0000_0001)).collect(), w)
}

/// The kernel parameter ABI (PTX_BUILD.md step 1): a slice is (ptr, len), a scalar one word.
/// A mismatch reads garbage, so a known permutation must come back exactly.
#[test]
fn hw_launch_matches_the_packed_abi() {
    let g = gpu();
    let d = &g.dev;
    let src = d.upload(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap(); // row-major 4×2
    let dst = d.alloc(8).unwrap();
    d.launch(&g.module, "to_col_major", 1, 256, &[Arg::Buf(&src), Arg::Buf(&dst), Arg::U32(4), Arg::U32(2)]).unwrap();
    assert_eq!(d.download(&dst).unwrap(), vec![1, 3, 5, 7, 2, 4, 6, 8]);
    let back = d.alloc(8).unwrap();
    d.launch(&g.module, "to_row_major", 1, 256, &[Arg::Buf(&dst), Arg::Buf(&back), Arg::U32(4), Arg::U32(2)]).unwrap();
    assert_eq!(d.download(&back).unwrap(), vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let _ = Device::open(0).unwrap();
}

/// Every DFT entry point, GPU vs the CPU twin vs Plonky3, across the tile boundary
/// (log_n ≤ 10 runs only `dif_tiles`, above it `dif_stage` then `dif_tiles`).
#[test]
fn hw_dft_equals_cpu_and_plonky3() {
    let cuda = Dft(Arc::new(CudaNttEngine { gpu: gpu() }));
    let cpu = Dft::<CpuNttEngine>::default();
    let p3 = Radix2DitParallel::<Goldilocks>::default();
    let shift = Goldilocks::GENERATOR;
    let mut rng = StdRng::seed_from_u64(41);
    for log_n in [1usize, 2, 4, 9, 10, 11, 13, 16] {
        for w in [1usize, 6, 56] {
            let m = mat(&mut rng, 1 << log_n, w);
            let want = p3.dft_batch(m.clone()).to_row_major_matrix();
            assert_eq!(cuda.dft_batch(m.clone()).to_row_major_matrix(), want, "dft log_n={log_n} w={w}");
            assert_eq!(cpu.dft_batch(m.clone()).to_row_major_matrix(), want, "cpu dft log_n={log_n} w={w}");
            assert_eq!(cuda.idft_batch(m.clone()), p3.idft_batch(m.clone()), "idft log_n={log_n} w={w}");
            for added in [1usize, 3] {
                let want = p3.coset_lde_batch(m.clone(), added, shift).to_row_major_matrix();
                assert_eq!(cuda.coset_lde_batch(m.clone(), added, shift).to_row_major_matrix(), want, "lde log_n={log_n} w={w} added={added}");
                assert_eq!(cpu.coset_lde_batch(m.clone(), added, shift).to_row_major_matrix(), want, "cpu lde log_n={log_n} w={w} added={added}");
            }
            assert_eq!(cuda.coset_idft_batch(m.clone(), shift), p3.coset_idft_batch(m, shift), "coset_idft log_n={log_n} w={w}");
        }
    }
}

/// PTX_BUILD.md step 3: `dif_tiles` (shared memory, block barriers) at a large n, where a
/// miscompiled barrier would show as a wrong transform.
#[test]
fn hw_large_dft_equals_plonky3() {
    let cuda = Dft(Arc::new(CudaNttEngine { gpu: gpu() }));
    let p3 = Radix2DitParallel::<Goldilocks>::default();
    let shift = Goldilocks::GENERATOR;
    let mut rng = StdRng::seed_from_u64(43);
    for (log_n, w) in [(20usize, 1usize), (20, 4), (22, 2)] {
        let m = mat(&mut rng, 1 << log_n, w);
        assert_eq!(cuda.dft_batch(m.clone()).to_row_major_matrix(), p3.dft_batch(m.clone()).to_row_major_matrix(), "dft log_n={log_n} w={w}");
        assert_eq!(cuda.coset_lde_batch(m.clone(), 2, shift).to_row_major_matrix(), p3.coset_lde_batch(m, 2, shift).to_row_major_matrix(), "lde log_n={log_n} w={w}");
    }
}

/// The Poseidon2 Merkle kernels (`copy_columns`, `poseidon2_rows`, `_compress`, `_inject`):
/// GPU commitments and openings equal the CPU twin's, byte for byte.
#[test]
fn hw_mmcs_equals_cpu_mmcs() {
    let cuda = HidingMmcs::new(Arc::new(CudaHashEngine { gpu: gpu() }), SEED, 2, StdRng::seed_from_u64(9));
    let cpu = HidingMmcs::new(Arc::new(CpuHashEngine::new(SEED)), SEED, 2, StdRng::seed_from_u64(9));
    let mut rng = StdRng::seed_from_u64(42);
    for shapes in [
        vec![(1usize << 10, 56usize), (1 << 11, 20), (1 << 12, 12), (1 << 6, 3), (1 << 12, 1)],
        vec![(1 << 16, 8), (1 << 14, 30), (1 << 16, 1)],
        vec![(1 << 18, 5)],
    ] {
        let max_h = shapes.iter().map(|s| s.0).max().unwrap();
        let ms: Vec<_> = shapes.iter().map(|&(h, w)| mat(&mut rng, h, w)).collect();
        let (c1, pd1) = cuda.commit(ms.clone());
        let (c2, pd2) = cpu.commit(ms);
        assert_eq!(c1, c2, "commitment {shapes:?}");
        let idx: Vec<usize> = (0..50).map(|_| rng.random::<u64>() as usize % max_h).collect();
        let a = cuda.open_multi_batch(&idx, &pd1);
        let b = cpu.open_multi_batch(&idx, &pd2);
        assert_eq!(postcard::to_allocvec(&a).unwrap(), postcard::to_allocvec(&b).unwrap(), "openings {shapes:?}");
    }
}
