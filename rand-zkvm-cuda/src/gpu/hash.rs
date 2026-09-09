//! `CudaHashEngine`: `HashEngine` backed by a `GpuProver` (real CUDA, or the mock driver).
use std::sync::Arc;
use super::driver::{Arg, Buffer};
use super::GpuProver;
use crate::merkle::{Digest, HashEngine};

const BLOCK: u32 = 256;

#[derive(Clone)]
pub struct CudaHashEngine { pub gpu: Arc<GpuProver> }
impl CudaHashEngine { fn ok<T>(r: Result<T, super::CudaError>) -> T { r.unwrap_or_else(|e| panic!("{e}")) } }

impl HashEngine for CudaHashEngine {
    type Mat = Buffer; type Dig = Buffer;
    fn upload(&self, values: &[u64], _width: usize) -> Buffer { Self::ok(self.gpu.dev.upload(values).map_err(super::CudaError::Copy)) }
    fn concat(&self, parts: &[(&Buffer, usize)], n: usize) -> (Buffer, usize) {
        let total: usize = parts.iter().map(|p| p.1).sum();
        let dst = Self::ok(self.gpu.alloc(n * total));
        let mut off = 0;
        for (src, w) in parts {
            Self::ok(self.gpu.launch("copy_columns", n * w, BLOCK, &[Arg::Buf(src), Arg::U32(*w as u32), Arg::Buf(&dst), Arg::U32(total as u32), Arg::U32(off as u32)]));
            off += w;
        }
        (dst, total)
    }
    fn hash_rows(&self, rows: &Buffer, width: usize, n: usize, out_len: usize) -> Buffer {
        let out = Self::ok(self.gpu.alloc(4 * out_len));
        Self::ok(self.gpu.launch("poseidon2_rows", n, BLOCK, &[Arg::Buf(rows), Arg::U32(width as u32), Arg::U32(n as u32), Arg::Buf(&self.gpu.consts), Arg::Buf(&out)]));
        out
    }
    fn compress(&self, prev: &Buffer, next_len: usize, out_len: usize) -> Buffer {
        let out = Self::ok(self.gpu.alloc(4 * out_len));
        Self::ok(self.gpu.launch("poseidon2_compress", next_len, BLOCK, &[Arg::Buf(prev), Arg::U32(next_len as u32), Arg::Buf(&self.gpu.consts), Arg::Buf(&out)]));
        out
    }
    fn inject(&self, prev: &Buffer, raw_next: usize, rows: &Buffer, width: usize, n_rows: usize, out_len: usize) -> Buffer {
        let out = Self::ok(self.gpu.alloc(4 * out_len));
        Self::ok(self.gpu.launch("poseidon2_inject", raw_next, BLOCK, &[Arg::Buf(prev), Arg::U32(raw_next as u32), Arg::Buf(rows), Arg::U32(width as u32), Arg::U32(n_rows as u32), Arg::Buf(&self.gpu.consts), Arg::Buf(&out)]));
        out
    }
    fn download(&self, dig: &Buffer) -> Vec<Digest> {
        Self::ok(self.gpu.dev.download(dig).map_err(super::CudaError::Copy)).chunks_exact(4).map(|c| [c[0], c[1], c[2], c[3]]).collect()
    }
}
