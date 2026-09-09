use std::sync::Arc;
use super::{Digest, HashEngine};
use crate::device::kernels as k;

#[derive(Clone)]
pub struct CpuHashEngine { k: Arc<[u64; crate::device::poseidon2::N_CONSTS]> }
impl CpuHashEngine { pub fn new(perm_seed: u64) -> Self { Self { k: Arc::new(crate::constants::poseidon2_constants(perm_seed)) } } }

impl HashEngine for CpuHashEngine {
    type Mat = Vec<u64>;
    type Dig = Vec<u64>;
    fn upload(&self, values: &[u64], _width: usize) -> Vec<u64> { values.to_vec() }
    fn concat(&self, parts: &[(&Vec<u64>, usize)], n: usize) -> (Vec<u64>, usize) {
        if parts.len() == 1 { return (parts[0].0.clone(), parts[0].1); }
        let total: usize = parts.iter().map(|p| p.1).sum();
        let mut dst = vec![0u64; n * total];
        let mut off = 0;
        for (src, w) in parts { for t in 0..src.len() { k::copy_columns(t, src, *w, &mut dst, total, off); } off += w; }
        (dst, total)
    }
    fn hash_rows(&self, rows: &Vec<u64>, width: usize, n: usize, out_len: usize) -> Vec<u64> {
        let mut out = vec![0u64; 4 * out_len];
        for t in 0..n { k::poseidon2_rows(t, rows, width, n, &self.k[..], &mut out); }
        out
    }
    fn compress(&self, prev: &Vec<u64>, next_len: usize, out_len: usize) -> Vec<u64> {
        let mut out = vec![0u64; 4 * out_len];
        for t in 0..next_len { k::poseidon2_compress(t, prev, next_len, &self.k[..], &mut out); }
        out
    }
    fn inject(&self, prev: &Vec<u64>, raw_next: usize, rows: &Vec<u64>, width: usize, n_rows: usize, out_len: usize) -> Vec<u64> {
        let mut out = vec![0u64; 4 * out_len];
        for t in 0..raw_next { k::poseidon2_inject(t, prev, raw_next, rows, width, n_rows, &self.k[..], &mut out); }
        out
    }
    fn download(&self, dig: &Vec<u64>) -> Vec<Digest> { dig.chunks_exact(4).map(|c| [c[0], c[1], c[2], c[3]]).collect() }
}
