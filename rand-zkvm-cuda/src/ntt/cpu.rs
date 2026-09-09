//! Sequential CPU reference implementation of `NttEngine`, run through the same
//! per-thread kernel bodies device engines use.
use super::{twiddles, NttEngine, Twiddles, LOG_TILE};
use crate::device::kernels as k;
use p3_util::log2_strict_usize;
use std::sync::Arc;

#[derive(Clone)]
pub struct CpuNttEngine {
    tw: Arc<Twiddles>,
}

impl Default for CpuNttEngine {
    fn default() -> Self {
        Self { tw: Arc::new(twiddles()) }
    }
}

impl NttEngine for CpuNttEngine {
    type Buf = Vec<u64>;

    fn max_columns(&self, _n: usize) -> usize {
        usize::MAX
    }

    fn upload_row_major(&self, values: &[u64], n: usize, w: usize) -> Vec<u64> {
        let mut dst = vec![0u64; n * w];
        for t in 0..n * w {
            k::to_col_major(t, values, &mut dst, n, w);
        }
        dst
    }

    fn download_row_major(&self, buf: &Vec<u64>, n: usize, w: usize) -> Vec<u64> {
        let mut dst = vec![0u64; n * w];
        for t in 0..n * w {
            k::to_row_major(t, buf, &mut dst, n, w);
        }
        dst
    }

    fn dif(&self, buf: &mut Vec<u64>, n: usize, w: usize, inverse: bool) {
        if n < 2 {
            return;
        }
        let log_n = log2_strict_usize(n);
        let (lo, hi) = if inverse { (&self.tw.inv_lo, &self.tw.inv_hi) } else { (&self.tw.lo, &self.tw.hi) };
        let log_tile = LOG_TILE.min(log_n);
        for s in ((log_tile + 1)..=log_n).rev() {
            for t in 0..w * n / 2 {
                k::dif_stage(t, buf, n, log_n, s, lo, hi);
            }
        }
        let tile = 1 << log_tile;
        for tile_start in (0..w * n).step_by(tile) {
            let chunk = &mut buf[tile_start..tile_start + tile];
            for s in (1..=log_tile).rev() {
                for t in 0..tile / 2 {
                    k::dif_tile_stage(t, chunk, log_n, s, lo, hi);
                }
            }
        }
    }

    fn bit_reverse(&self, buf: &Vec<u64>, n: usize, w: usize) -> Vec<u64> {
        let mut dst = vec![0u64; n * w];
        for t in 0..n * w {
            k::bit_reverse(t, buf, &mut dst, n, log2_strict_usize(n));
        }
        dst
    }

    fn scale_pow(&self, buf: &mut Vec<u64>, n: usize, _w: usize, base: u64, uniform: u64) {
        for t in 0..buf.len() {
            k::scale_pow(t, buf, n, base, uniform);
        }
    }

    fn zero_extend(&self, buf: &Vec<u64>, n: usize, w: usize, added_bits: usize) -> Vec<u64> {
        let n_ext = n << added_bits;
        let mut dst = vec![0u64; n_ext * w];
        for t in 0..n_ext * w {
            k::zero_extend(t, buf, &mut dst, n, n_ext);
        }
        dst
    }
}
