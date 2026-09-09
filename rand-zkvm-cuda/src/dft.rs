//! `Dft<E>`: a `TwoAdicSubgroupDft<Goldilocks>` built on top of any `NttEngine`.
//!
//! Every entry point is expressed in terms of the engine's `dif` (natural → bit-reversed
//! forward, or inverse-twiddle unscaled backward), `bit_reverse`, `scale_pow`, and
//! `zero_extend` primitives, chunked over columns to respect `max_columns`.
use crate::device::gl;
use crate::ntt::NttEngine;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::bitrev::{BitReversalPerm, BitReversedMatrixView};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use std::sync::Arc;

pub struct Dft<E: NttEngine>(pub Arc<E>);
impl<E: NttEngine> Clone for Dft<E> {
    fn clone(&self) -> Self {
        Dft(self.0.clone())
    }
}
impl<E: NttEngine + Default> Default for Dft<E> {
    fn default() -> Self {
        Dft(Arc::new(E::default()))
    }
}

fn raw(m: &RowMajorMatrix<Goldilocks>) -> Vec<u64> {
    m.values.iter().map(|x| x.as_canonical_u64()).collect()
}
fn wrap(v: Vec<u64>, w: usize) -> RowMajorMatrix<Goldilocks> {
    RowMajorMatrix::new(v.into_iter().map(Goldilocks::from_u64).collect(), w)
}

/// Extract columns [c0, c1) of a row-major n×w matrix as a row-major n×(c1-c0) matrix.
fn columns(values: &[u64], w: usize, c0: usize, c1: usize) -> Vec<u64> {
    let n = values.len() / w;
    let mut out = Vec::with_capacity(n * (c1 - c0));
    for r in 0..n {
        out.extend_from_slice(&values[r * w + c0..r * w + c1]);
    }
    out
}
/// Write a row-major n×(c1-c0) block into columns [c0, c1) of a row-major n×w matrix.
fn place(dst: &mut [u64], w: usize, c0: usize, c1: usize, block: &[u64]) {
    let n = dst.len() / w;
    let bw = c1 - c0;
    for r in 0..n {
        dst[r * w + c0..r * w + c1].copy_from_slice(&block[r * bw..(r + 1) * bw]);
    }
}

impl<E: NttEngine> Dft<E> {
    /// Run `f` over column chunks that fit the engine; `f` maps an n_in×wc block to an n_out×wc block.
    fn chunked(&self, values: &[u64], w: usize, n_in: usize, n_out: usize, f: impl Fn(&[u64], usize) -> Vec<u64>) -> Vec<u64> {
        let max = self.0.max_columns(n_out.max(n_in)).max(1);
        if w <= max {
            return f(values, w);
        }
        let mut out = vec![0u64; n_out * w];
        let mut c0 = 0;
        while c0 < w {
            let c1 = (c0 + max).min(w);
            let block = f(&columns(values, w, c0, c1), c1 - c0);
            place(&mut out, w, c0, c1, &block);
            c0 = c1;
        }
        out
    }
    /// natural coefficients (row-major) ← natural evaluations (row-major), scaled by n⁻¹ and shift⁻ⁱ
    fn inverse_block(&self, block: &[u64], n: usize, wc: usize, shift_inv: u64) -> Vec<u64> {
        let e = &self.0;
        let mut buf = e.upload_row_major(block, n, wc);
        e.dif(&mut buf, n, wc, true);
        let mut nat = e.bit_reverse(&buf, n, wc);
        e.scale_pow(&mut nat, n, wc, shift_inv, gl::inv(n as u64));
        e.download_row_major(&nat, n, wc)
    }
}

impl<E: NttEngine + Default> TwoAdicSubgroupDft<Goldilocks> for Dft<E> {
    type Evaluations = BitReversedMatrixView<RowMajorMatrix<Goldilocks>>;

    fn dft_batch(&self, mat: RowMajorMatrix<Goldilocks>) -> Self::Evaluations {
        let (n, w) = (mat.height(), mat.width());
        let out = self.chunked(&raw(&mat), w, n, n, |block, wc| {
            let mut buf = self.0.upload_row_major(block, n, wc);
            self.0.dif(&mut buf, n, wc, false);
            self.0.download_row_major(&buf, n, wc)
        });
        BitReversalPerm::new_view(wrap(out, w))
    }

    fn idft_batch(&self, mat: RowMajorMatrix<Goldilocks>) -> RowMajorMatrix<Goldilocks> {
        let (n, w) = (mat.height(), mat.width());
        wrap(self.chunked(&raw(&mat), w, n, n, |b, wc| self.inverse_block(b, n, wc, 1)), w)
    }

    fn coset_idft_batch(&self, mat: RowMajorMatrix<Goldilocks>, shift: Goldilocks) -> RowMajorMatrix<Goldilocks> {
        let (n, w) = (mat.height(), mat.width());
        let s_inv = shift.inverse().as_canonical_u64();
        wrap(self.chunked(&raw(&mat), w, n, n, |b, wc| self.inverse_block(b, n, wc, s_inv)), w)
    }

    fn coset_lde_batch(&self, mat: RowMajorMatrix<Goldilocks>, added_bits: usize, shift: Goldilocks) -> Self::Evaluations {
        let (n, w) = (mat.height(), mat.width());
        let n_ext = n << added_bits;
        let s = shift.as_canonical_u64();
        let out = self.chunked(&raw(&mat), w, n, n_ext, |block, wc| {
            let e = &self.0;
            let mut buf = e.upload_row_major(block, n, wc);
            e.dif(&mut buf, n, wc, true);
            let mut coeffs = e.bit_reverse(&buf, n, wc);
            e.scale_pow(&mut coeffs, n, wc, 1, gl::inv(n as u64));
            let mut ext = e.zero_extend(&coeffs, n, wc, added_bits);
            e.scale_pow(&mut ext, n_ext, wc, s, 1);
            e.dif(&mut ext, n_ext, wc, false);
            e.download_row_major(&ext, n_ext, wc)
        });
        BitReversalPerm::new_view(wrap(out, w))
    }
}
