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
    use kernels::Cells;

    /// This thread's view of the device buffer behind `d`: a `Cells` over all of it, which
    /// reads and writes one element at a time through a raw pointer and never forms a
    /// reference into the buffer.
    ///
    /// # Safety
    /// `d.as_mut_ptr()` is valid for `d.len()` `u64`s (the launch's `(ptr, len)` pair from
    /// `rand-zkvm-cuda/src/gpu/driver/real.rs`, one live `DeviceBuffer`). Every thread of the
    /// launch makes the same `Cells` from its own copy of `d`, so the caller must:
    /// - write only the elements its own thread index owns in this launch, a set disjoint from
    ///   every other thread's (the per-kernel maps in `rand-zkvm-cuda/src/device/kernels.rs`);
    /// - read no element another thread writes in the same launch (a thread reads back only what
    ///   it owns — `dif_stage`'s butterfly reads its own pair `i0`, `i1`);
    /// - not pass the same buffer as another argument of the same launch (`gpu/ntt.rs` and
    ///   `gpu/hash.rs` pass an in-place buffer once, and every `src` is a separate allocation from
    ///   its `dst`), so no `&[u64]` parameter covers memory a `Cells` writes.
    ///
    /// Those are `Cells::from_raw`'s conditions. No thread holds a `&mut` to the buffer or to
    /// any element of it, so Rust's aliasing rules see only raw-pointer accesses, and under the
    /// maps above no two of them race: the launch is sound, not merely race-free.
    #[inline(always)]
    unsafe fn cells<'a>(d: &'a mut DisjointSlice<u64>) -> Cells<'a> {
        Cells::from_raw(d.as_mut_ptr(), d.len())
    }

    #[kernel]
    pub fn scale_pow(mut data: DisjointSlice<u64>, n: u32, base: u64, uniform: u64) {
        let t = thread::index_1d().get();
        // SAFETY: `cells`'s rules hold: `kernels::scale_pow` reads and writes only `data[t]`.
        let d = unsafe { cells(&mut data) };
        kernels::scale_pow(t, d, n as usize, base, uniform);
    }
    #[kernel]
    pub fn bit_reverse(src: &[u64], mut dst: DisjointSlice<u64>, n: u32, log_n: u32) {
        let t = thread::index_1d().get();
        // SAFETY: `cells`'s rules hold: `kernels::bit_reverse` writes only `dst[col*n + rev(row)]`
        // for `t = col*n + row`, a bijection on `0..n*w` (`rev` permutes `0..n`); `src` is a
        // separate allocation.
        let d = unsafe { cells(&mut dst) };
        kernels::bit_reverse(t, src, d, n as usize, log_n as usize);
    }
    #[kernel]
    pub fn zero_extend(src: &[u64], mut dst: DisjointSlice<u64>, n: u32, n_ext: u32) {
        let t = thread::index_1d().get();
        // SAFETY: `cells`'s rules hold: `kernels::zero_extend` writes only `dst[t]`; `src` is a
        // separate allocation.
        let d = unsafe { cells(&mut dst) };
        kernels::zero_extend(t, src, d, n as usize, n_ext as usize);
    }
    #[kernel]
    pub fn to_col_major(src: &[u64], mut dst: DisjointSlice<u64>, rows: u32, cols: u32) {
        let t = thread::index_1d().get();
        // SAFETY: `cells`'s rules hold: `kernels::to_col_major` writes only `dst[c*rows + r]` for
        // `t = r*cols + c`, a bijection on `0..rows*cols`; `src` is a separate allocation.
        let d = unsafe { cells(&mut dst) };
        kernels::to_col_major(t, src, d, rows as usize, cols as usize);
    }
    #[kernel]
    pub fn to_row_major(src: &[u64], mut dst: DisjointSlice<u64>, rows: u32, cols: u32) {
        let t = thread::index_1d().get();
        // SAFETY: `cells`'s rules hold: `kernels::to_row_major` writes only `dst[r*cols + c]` for
        // `t = c*rows + r`, a bijection on `0..rows*cols`; `src` is a separate allocation.
        let d = unsafe { cells(&mut dst) };
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
        // SAFETY: `cells`'s rules hold: `kernels::dif_stage` reads and writes only butterfly `t`'s
        // pair `(i0, i0 + m/2)`; within one stage `s` the butterflies partition the buffer.
        let d = unsafe { cells(&mut data) };
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
        // SAFETY: `cells`'s rules hold: thread `tx` of block `b` reads and writes only
        // `d[b*tile + tx]` and `d[b*tile + tx + tile/2]` (the launch is `w*n/tile` blocks of
        // `tile/2` threads, `gpu/ntt.rs::dif`), disjoint across the grid.
        let d = unsafe { cells(&mut data) };
        let _ = n;
        // SAFETY: `&raw mut TILE` names this block's shared memory without forming a reference
        // to it, and `as_raw_mut_ptr` turns it into an element pointer without one either (no
        // thread holds a `&mut SharedArray`). `Cells::from_raw`'s conditions for the `tile`
        // elements: they lie inside `TILE` (`tile <= 1024`: `log_tile <= LOG_TILE = 10`); the
        // tile is touched only through this block's `tl`; and between barriers the threads'
        // accesses are disjoint — the load below and the store at the end touch only slots `tx`
        // and `tx + tile/2` (together every slot, so no stage reads an unwritten one), and in
        // stage `s` thread `tx` reads and writes only its butterfly pair `(i0, i0 + 2^(s-1))`
        // (`kernels::dif_tile_stage`), the pairs partitioning the tile, with a `sync_threads`
        // after the load and after every stage.
        let tl = unsafe { Cells::from_raw(SharedArray::as_raw_mut_ptr(&raw mut TILE), tile) };
        tl.set(tx, d.get(base + tx));
        tl.set(tx + tile / 2, d.get(base + tx + tile / 2));
        thread::sync_threads();
        let mut s = log_tile as usize;
        while s >= 1 {
            kernels::dif_tile_stage(tx, tl, log_n as usize, s, lo, hi);
            thread::sync_threads();
            s -= 1;
        }
        // After the last stage's barrier each thread copies back only its own two slots, to the
        // two elements of `d` it read at the start.
        d.set(base + tx, tl.get(tx));
        d.set(base + tx + tile / 2, tl.get(tx + tile / 2));
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
        // SAFETY: `cells`'s rules hold: `kernels::copy_columns` writes only
        // `dst[r*dst_w + col_off + c]` for `t = r*src_w + c`, injective while
        // `col_off + src_w <= dst_w` (`gpu/hash.rs::concat` lays the parts side by side, one launch
        // per part); `src` is a separate allocation.
        let d = unsafe { cells(&mut dst) };
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
        // SAFETY: `cells`'s rules hold: `kernels::poseidon2_rows` writes only `out[4t..4t+4]`.
        let o = unsafe { cells(&mut out) };
        kernels::poseidon2_rows(t, rows, width as usize, n as usize, k, o);
    }
    #[kernel]
    pub fn poseidon2_compress(prev: &[u64], next_len: u32, k: &[u64], mut out: DisjointSlice<u64>) {
        let t = thread::index_1d().get();
        // SAFETY: `cells`'s rules hold: `kernels::poseidon2_compress` writes only `out[4t..4t+4]`;
        // `prev` is a separate allocation.
        let o = unsafe { cells(&mut out) };
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
        // SAFETY: `cells`'s rules hold: `kernels::poseidon2_inject` writes only `out[4t..4t+4]`;
        // `prev` and `rows` are separate allocations.
        let o = unsafe { cells(&mut out) };
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
