//! NTT engine trait and the twiddle-table math shared by every implementation.
pub mod cpu;
use crate::device::gl;
use p3_field::{PrimeField64, TwoAdicField};
use p3_goldilocks::Goldilocks;

pub use crate::device::kernels::{LOG_MAX, LOG_TILE, LO_BITS};

pub struct Twiddles {
    pub lo: Vec<u64>,
    pub hi: Vec<u64>,
    pub inv_lo: Vec<u64>,
    pub inv_hi: Vec<u64>,
}

fn table(base: u64, len: usize) -> Vec<u64> {
    let mut v = Vec::with_capacity(len);
    let mut acc = 1u64;
    for _ in 0..len {
        v.push(acc);
        acc = gl::mul(acc, base);
    }
    v
}

/// ω = Goldilocks::two_adic_generator(LOG_MAX)
pub fn twiddles() -> Twiddles {
    let omega = Goldilocks::two_adic_generator(LOG_MAX).as_canonical_u64();
    let omega_inv = gl::inv(omega);
    let lo_len = 1 << LO_BITS;
    let hi_len = 1 << (LOG_MAX - LO_BITS);
    Twiddles {
        lo: table(omega, lo_len),
        hi: table(gl::pow(omega, lo_len as u64), hi_len),
        inv_lo: table(omega_inv, lo_len),
        inv_hi: table(gl::pow(omega_inv, lo_len as u64), hi_len),
    }
}

pub trait NttEngine: Clone + Send + Sync + 'static {
    type Buf;
    /// how many columns of height n fit at once
    fn max_columns(&self, n: usize) -> usize;
    /// → column-major on device
    fn upload_row_major(&self, values: &[u64], n: usize, w: usize) -> Self::Buf;
    fn download_row_major(&self, buf: &Self::Buf, n: usize, w: usize) -> Vec<u64>;
    /// natural in → bit-reversed out
    fn dif(&self, buf: &mut Self::Buf, n: usize, w: usize, inverse: bool);
    /// new buffer, rows permuted
    fn bit_reverse(&self, buf: &Self::Buf, n: usize, w: usize) -> Self::Buf;
    /// x[r] *= uniform·base^r
    fn scale_pow(&self, buf: &mut Self::Buf, n: usize, w: usize, base: u64, uniform: u64);
    fn zero_extend(&self, buf: &Self::Buf, n: usize, w: usize, added_bits: usize) -> Self::Buf;
}
