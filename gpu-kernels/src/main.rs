//! cuda-oxide entry points for the Rand zkVM GPU prover. Every kernel is a thin wrapper
//! over the per-thread bodies in `rand-zkvm-cuda/src/device/kernels.rs`, shared by `#[path]`
//! so the CPU reference, the mock driver and the GPU execute identical code.
#[path = "../../rand-zkvm-cuda/src/device/gl.rs"]
mod gl;
#[path = "../../rand-zkvm-cuda/src/device/kernels.rs"]
mod kernels;
#[path = "../../rand-zkvm-cuda/src/device/poseidon2.rs"]
mod poseidon2;
// `kernels.rs` says `use super::gl` / `use super::poseidon2`; with the modules mounted at the
// crate root those paths resolve because `main.rs` is their parent.

use cuda_device::{cuda_module, kernel, thread, DisjointSlice, SharedArray};

#[cuda_module]
mod k {
    use super::*;
    #[inline(always)]
    unsafe fn all<'a>(d: &'a mut DisjointSlice<u64>) -> &'a mut [u64] {
        core::slice::from_raw_parts_mut(d.as_mut_ptr(), d.len())
    }

    #[kernel]
    pub fn scale_pow(mut data: DisjointSlice<u64>, n: u32, base: u64, uniform: u64) {
        let t = thread::index_1d().get();
        let d = unsafe { all(&mut data) };
        kernels::scale_pow(t, d, n as usize, base, uniform);
    }
    #[kernel]
    pub fn bit_reverse(src: &[u64], mut dst: DisjointSlice<u64>, n: u32, log_n: u32) {
        let t = thread::index_1d().get();
        let d = unsafe { all(&mut dst) };
        kernels::bit_reverse(t, src, d, n as usize, log_n as usize);
    }
    #[kernel]
    pub fn zero_extend(src: &[u64], mut dst: DisjointSlice<u64>, n: u32, n_ext: u32) {
        let t = thread::index_1d().get();
        let d = unsafe { all(&mut dst) };
        kernels::zero_extend(t, src, d, n as usize, n_ext as usize);
    }
    #[kernel]
    pub fn to_col_major(src: &[u64], mut dst: DisjointSlice<u64>, rows: u32, cols: u32) {
        let t = thread::index_1d().get();
        let d = unsafe { all(&mut dst) };
        kernels::to_col_major(t, src, d, rows as usize, cols as usize);
    }
    #[kernel]
    pub fn to_row_major(src: &[u64], mut dst: DisjointSlice<u64>, rows: u32, cols: u32) {
        let t = thread::index_1d().get();
        let d = unsafe { all(&mut dst) };
        kernels::to_row_major(t, src, d, rows as usize, cols as usize);
    }
    #[kernel]
    pub fn dif_stage(
        mut data: DisjointSlice<u64>,
        n: u32,
        log_n: u32,
        s: u32,
        lo: &[u64],
        hi: &[u64],
    ) {
        let t = thread::index_1d().get();
        let d = unsafe { all(&mut data) };
        kernels::dif_stage(t, d, n as usize, log_n as usize, s as usize, lo, hi);
    }
    /// One block per 2^log_tile-element tile; blockDim.x = tile/2. Stages log_tile..=1 in shared memory.
    #[kernel]
    pub fn dif_tiles(
        mut data: DisjointSlice<u64>,
        n: u32,
        log_n: u32,
        log_tile: u32,
        lo: &[u64],
        hi: &[u64],
    ) {
        static mut TILE: SharedArray<u64, 1024> = SharedArray::UNINIT;
        let tile = 1usize << log_tile;
        let base = thread::blockIdx_x() as usize * tile;
        let tx = thread::threadIdx_x() as usize;
        let d = unsafe { all(&mut data) };
        let _ = n;
        unsafe {
            TILE[tx] = d[base + tx];
            TILE[tx + tile / 2] = d[base + tx + tile / 2];
        }
        thread::sync_threads();
        let mut s = log_tile as usize;
        while s >= 1 {
            let tl = unsafe { core::slice::from_raw_parts_mut(TILE.as_mut_ptr(), tile) };
            kernels::dif_tile_stage(tx, tl, log_n as usize, s, lo, hi);
            thread::sync_threads();
            s -= 1;
        }
        unsafe {
            d[base + tx] = TILE[tx];
            d[base + tx + tile / 2] = TILE[tx + tile / 2];
        }
    }
    #[kernel]
    pub fn copy_columns(
        src: &[u64],
        src_w: u32,
        mut dst: DisjointSlice<u64>,
        dst_w: u32,
        col_off: u32,
    ) {
        let t = thread::index_1d().get();
        let d = unsafe { all(&mut dst) };
        kernels::copy_columns(t, src, src_w as usize, d, dst_w as usize, col_off as usize);
    }
    #[kernel]
    pub fn poseidon2_rows(
        rows: &[u64],
        width: u32,
        n: u32,
        k: &[u64],
        mut out: DisjointSlice<u64>,
    ) {
        let t = thread::index_1d().get();
        let o = unsafe { all(&mut out) };
        kernels::poseidon2_rows(t, rows, width as usize, n as usize, k, o);
    }
    #[kernel]
    pub fn poseidon2_compress(prev: &[u64], next_len: u32, k: &[u64], mut out: DisjointSlice<u64>) {
        let t = thread::index_1d().get();
        let o = unsafe { all(&mut out) };
        kernels::poseidon2_compress(t, prev, next_len as usize, k, o);
    }
    #[kernel]
    pub fn poseidon2_inject(
        prev: &[u64],
        raw_next: u32,
        rows: &[u64],
        width: u32,
        n_rows: u32,
        k: &[u64],
        mut out: DisjointSlice<u64>,
    ) {
        let t = thread::index_1d().get();
        let o = unsafe { all(&mut out) };
        kernels::poseidon2_inject(
            t,
            prev,
            raw_next as usize,
            rows,
            width as usize,
            n_rows as usize,
            k,
            o,
        );
    }
}

fn main() {}
