//! `CudaNttEngine`: `NttEngine` backed by a `GpuProver` (real CUDA, or the mock driver).
use std::sync::Arc;
use p3_util::log2_strict_usize;
use super::driver::{Arg, Buffer};
use super::GpuProver;
use crate::ntt::{NttEngine, LOG_TILE};

pub const DEFAULT_PERM_SEED: u64 = 0x5261_6e64_5a4b;
const BLOCK: u32 = 256;

#[derive(Clone)]
pub struct CudaNttEngine { pub gpu: Arc<GpuProver> }
impl Default for CudaNttEngine { fn default() -> Self { Self { gpu: GpuProver::probe(DEFAULT_PERM_SEED).unwrap_or_else(|e| panic!("{e}")) } } }

impl CudaNttEngine {
    fn ok<T>(r: Result<T, super::CudaError>) -> T { r.unwrap_or_else(|e| panic!("{e}")) }
}

impl NttEngine for CudaNttEngine {
    type Buf = Buffer;
    fn max_columns(&self, n: usize) -> usize {
        // LDE keeps ~4 buffers of n×wc u64 alive; leave headroom.
        ((self.gpu.free_bytes / 2) / (n * 8 * 4)).max(1)
    }
    fn upload_row_major(&self, values: &[u64], n: usize, w: usize) -> Buffer {
        // Report an oversized upload as an allocation failure (which carries the "use a lower
        // tier" hint) rather than letting the driver fail the copy with a bare `Copy` error.
        let bytes = values.len() * 8;
        if bytes > self.gpu.free_bytes { Self::ok::<()>(Err(super::CudaError::Alloc { bytes, free: self.gpu.free_bytes })); }
        let src = Self::ok(self.gpu.dev.upload(values).map_err(super::CudaError::Copy));
        let dst = Self::ok(self.gpu.alloc(n * w));
        Self::ok(self.gpu.launch("to_col_major", n * w, BLOCK, &[Arg::Buf(&src), Arg::Buf(&dst), Arg::U32(n as u32), Arg::U32(w as u32)]));
        dst
    }
    fn download_row_major(&self, buf: &Buffer, n: usize, w: usize) -> Vec<u64> {
        let dst = Self::ok(self.gpu.alloc(n * w));
        Self::ok(self.gpu.launch("to_row_major", n * w, BLOCK, &[Arg::Buf(buf), Arg::Buf(&dst), Arg::U32(n as u32), Arg::U32(w as u32)]));
        Self::ok(self.gpu.dev.download(&dst).map_err(super::CudaError::Copy))
    }
    // `dif_stage`/`dif_tiles` operate in place on `buf`; it is passed once, never
    // aliased against another argument in the same launch.
    fn dif(&self, buf: &mut Buffer, n: usize, w: usize, inverse: bool) {
        if n < 2 { return; }
        let log_n = log2_strict_usize(n);
        let (lo, hi) = if inverse { (&self.gpu.tw_inv_lo, &self.gpu.tw_inv_hi) } else { (&self.gpu.tw_lo, &self.gpu.tw_hi) };
        let log_tile = LOG_TILE.min(log_n);
        for s in ((log_tile + 1)..=log_n).rev() {
            Self::ok(self.gpu.launch("dif_stage", w * n / 2, BLOCK, &[Arg::Buf(buf), Arg::U32(n as u32), Arg::U32(log_n as u32), Arg::U32(s as u32), Arg::Buf(lo), Arg::Buf(hi)]));
        }
        let tile = 1usize << log_tile;
        let blocks = w * n / tile;
        Self::ok(self.gpu.launch("dif_tiles", blocks * (tile / 2), (tile / 2) as u32, &[Arg::Buf(buf), Arg::U32(n as u32), Arg::U32(log_n as u32), Arg::U32(log_tile as u32), Arg::Buf(lo), Arg::Buf(hi)]));
    }
    fn bit_reverse(&self, buf: &Buffer, n: usize, w: usize) -> Buffer {
        let dst = Self::ok(self.gpu.alloc(n * w));
        Self::ok(self.gpu.launch("bit_reverse", n * w, BLOCK, &[Arg::Buf(buf), Arg::Buf(&dst), Arg::U32(n as u32), Arg::U32(log2_strict_usize(n) as u32)]));
        dst
    }
    // `scale_pow` operates in place on `buf`; it is passed once.
    fn scale_pow(&self, buf: &mut Buffer, n: usize, w: usize, base: u64, uniform: u64) {
        Self::ok(self.gpu.launch("scale_pow", n * w, BLOCK, &[Arg::Buf(buf), Arg::U32(n as u32), Arg::U64(base), Arg::U64(uniform)]));
    }
    fn zero_extend(&self, buf: &Buffer, n: usize, w: usize, added_bits: usize) -> Buffer {
        let n_ext = n << added_bits;
        let dst = Self::ok(self.gpu.alloc(n_ext * w));
        Self::ok(self.gpu.launch("zero_extend", n_ext * w, BLOCK, &[Arg::Buf(buf), Arg::Buf(&dst), Arg::U32(n as u32), Arg::U32(n_ext as u32)]));
        dst
    }
}
