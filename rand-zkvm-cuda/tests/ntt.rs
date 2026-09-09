use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_util::reverse_bits_len;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use rand_zkvm_cuda::ntt::{cpu::CpuNttEngine, twiddles, NttEngine, LOG_MAX, LO_BITS};
use rand_zkvm_cuda::device::gl;

fn rand_mat(rng: &mut StdRng, n: usize, w: usize) -> Vec<u64> { (0..n * w).map(|_| rng.random::<u64>() % gl::P).collect() }

#[test]
fn twiddle_tables_reconstruct_powers() {
    let t = twiddles();
    let omega = Goldilocks::two_adic_generator(LOG_MAX).as_canonical_u64();
    for j in [0usize, 1, 2, 8191, 8192, 8193, 1 << 20, (1 << 25) - 1] {
        let expect = gl::pow(omega, j as u64);
        assert_eq!(gl::mul(t.lo[j & ((1 << LO_BITS) - 1)], t.hi[j >> LO_BITS]), expect, "j={j}");
        assert_eq!(gl::mul(t.inv_lo[j & ((1 << LO_BITS) - 1)], t.inv_hi[j >> LO_BITS]), gl::inv(expect));
    }
}

#[test]
fn dif_matches_plonky3_dft_bit_reversed() {
    let e = CpuNttEngine::default();
    let cpu = Radix2DitParallel::<Goldilocks>::default();
    let mut rng = StdRng::seed_from_u64(5);
    for log_n in [1usize, 2, 3, 9, 10, 11, 12, 15] {
        let n = 1 << log_n;
        for w in [1usize, 3, 7] {
            let vals = rand_mat(&mut rng, n, w);
            let mut buf = e.upload_row_major(&vals, n, w);
            e.dif(&mut buf, n, w, false);
            let ours = e.download_row_major(&buf, n, w);
            let expected = cpu.dft_batch(RowMajorMatrix::new(vals.iter().map(|&x| Goldilocks::from_u64(x)).collect(), w)).to_row_major_matrix();
            for r in 0..n { for c in 0..w {
                assert_eq!(ours[r * w + c], expected.get(reverse_bits_len(r, log_n), c).unwrap().as_canonical_u64(), "n={n} w={w} r={r} c={c}");
            } }
        }
    }
}

#[test]
fn inverse_dif_then_bit_reverse_recovers_coefficients() {
    let e = CpuNttEngine::default();
    let mut rng = StdRng::seed_from_u64(6);
    for log_n in [3usize, 10, 13] {
        let n = 1 << log_n; let w = 2;
        let coeffs = rand_mat(&mut rng, n, w);
        let mut buf = e.upload_row_major(&coeffs, n, w);
        e.dif(&mut buf, n, w, false);
        let evals = e.bit_reverse(&buf, n, w);            // natural-order evaluations
        let mut back = evals;
        e.dif(&mut back, n, w, true);
        let mut nat = e.bit_reverse(&back, n, w);
        e.scale_pow(&mut nat, n, w, 1, gl::inv(n as u64));
        assert_eq!(e.download_row_major(&nat, n, w), coeffs);
    }
}

#[test]
fn zero_extend_and_scale_pow() {
    let e = CpuNttEngine::default();
    let vals: Vec<u64> = (1..=8).collect(); // n=4, w=2 row-major: rows [1,2],[3,4],[5,6],[7,8]
    let buf = e.upload_row_major(&vals, 4, 2);
    let ext = e.zero_extend(&buf, 4, 2, 1);
    assert_eq!(e.download_row_major(&ext, 8, 2), vec![1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0]);
    let mut b2 = e.upload_row_major(&vals, 4, 2);
    e.scale_pow(&mut b2, 4, 2, 2, 3); // row r scaled by 3·2^r
    assert_eq!(e.download_row_major(&b2, 4, 2), vec![3, 6, 18, 24, 60, 72, 168, 192]);
}
