//! R4-a (randprotocol/fullnode#49): a GPU launch simulated on host threads, for Miri.
//!
//! Each simulated GPU thread makes its own `Cells::from_raw` over the one shared output buffer
//! and runs the kernel body for its index, exactly as `gpu-kernels/src/main.rs`'s `cells` does,
//! several host threads at once. `cargo +nightly miri test --test cells_launch` (Stacked or Tree
//! Borrows) accepts it. The pre-fix pattern (`core::slice::from_raw_parts_mut` over the whole
//! buffer per thread, a `&mut [u64]` each) run the same way is reported by Miri as a data race
//! between the threads' retags, under both models. Sizes are tiny so Miri finishes in seconds;
//! outside Miri the results are also checked against the sequential `Cells::new` run.
use rand_zkvm_cuda::device::{gl, kernels::{self, Cells}, poseidon2};

#[derive(Clone, Copy)]
struct Ptr(*mut u64, usize);
// SAFETY: test-only carrier of a buffer pointer into scoped threads, which `launch` joins before
// the buffer's borrow ends; every access through it goes through `Cells::from_raw` under the
// per-kernel disjointness the kernel bodies document.
unsafe impl Send for Ptr {}
unsafe impl Sync for Ptr {}

const THREADS: usize = 3;

/// Runs `body(t, cells)` for every `t < total`, striped over `THREADS` host threads at once,
/// each `t` with its own `Cells` over the whole buffer (one GPU thread's view).
fn launch(total: usize, buf: &mut [u64], body: impl Fn(usize, Cells<'_>) + Sync) {
    let p = Ptr(buf.as_mut_ptr(), buf.len());
    std::thread::scope(|s| {
        for h in 0..THREADS {
            let body = &body;
            s.spawn(move || {
                let p = p;
                let mut t = h;
                while t < total {
                    // SAFETY: `p` is `buf`, valid and exclusively lent to this launch until the
                    // scope joins; it is reached only through these `Cells`; and the kernel
                    // bodies below write disjoint elements per `t` and read only their own.
                    body(t, unsafe { Cells::from_raw(p.0, p.1) });
                    t += THREADS;
                }
            });
        }
    });
}

/// The same bodies run one `t` at a time through one `Cells::new` (the CPU reference's path).
fn sequential(total: usize, buf: &mut [u64], body: impl Fn(usize, Cells<'_>)) {
    let c = Cells::new(buf);
    for t in 0..total { body(t, c); }
}

fn data(n: usize) -> Vec<u64> {
    (0..n as u64).map(|i| i.wrapping_mul(0x9E37_79B9_7F4A_7C15) % gl::P).collect()
}

fn both(total: usize, init: Vec<u64>, body: impl Fn(usize, Cells<'_>) + Sync) {
    let mut par = init.clone();
    launch(total, &mut par, &body);
    let mut seq = init;
    sequential(total, &mut seq, &body);
    assert_eq!(par, seq);
}

#[test]
fn a_parallel_launch_through_cells_is_sound_and_matches_the_sequential_run() {
    let (n, w, log_n) = (8usize, 2usize, 3usize);
    let lo = data(1 << kernels::LO_BITS);
    let hi = data(1 << (kernels::LOG_MAX - kernels::LO_BITS));
    let src = data(n * w);
    let k = data(poseidon2::N_CONSTS);

    both(n * w, data(n * w), |t, d| kernels::scale_pow(t, d, n, 7, 3));
    both(n * w, vec![0; n * w], |t, d| kernels::bit_reverse(t, &src, d, n, log_n));
    both(n * w, vec![0; n * w], |t, d| kernels::to_col_major(t, &src, d, n, w));
    both(n * w, vec![0; n * w], |t, d| kernels::to_row_major(t, &src, d, n, w));
    both(2 * n * w, vec![0; 2 * n * w], |t, d| kernels::zero_extend(t, &src, d, n, 2 * n));
    both(n * w, vec![0; n * (w + 1)], |t, d| kernels::copy_columns(t, &src, w, d, w + 1, 1));
    both(2, vec![0; 8], |t, d| kernels::poseidon2_rows(t, &src, w, 2, &k, d));
    both(2, vec![0; 8], |t, d| kernels::poseidon2_compress(t, &src, 2, &k, d));
    both(2, vec![0; 8], |t, d| kernels::poseidon2_inject(t, &src, 2, &src, w, 1, &k, d));
    let (mut par, mut seq) = (data(n * w), data(n * w));
    for s in (1..=log_n).rev() {
        launch(w * n / 2, &mut par, |t, d| kernels::dif_stage(t, d, n, log_n, s, &lo, &hi));
        sequential(w * n / 2, &mut seq, |t, d| kernels::dif_stage(t, d, n, log_n, s, &lo, &hi));
    }
    assert_eq!(par, seq);
}

/// `dif_tiles`'s block: `tile/2` threads share one tile, each through its own `Cells::from_raw`,
/// with a barrier after every stage.
#[test]
fn a_tile_block_through_cells_is_sound_and_matches_the_sequential_run() {
    let log_tile = 3usize;
    let tile = 1usize << log_tile;
    let lo = data(1 << kernels::LO_BITS);
    let hi = data(1 << (kernels::LOG_MAX - kernels::LO_BITS));
    let mut par = data(tile);
    let p = Ptr(par.as_mut_ptr(), tile);
    let bar = std::sync::Barrier::new(tile / 2);
    std::thread::scope(|sc| {
        for tx in 0..tile / 2 {
            let (bar, lo, hi) = (&bar, &lo, &hi);
            sc.spawn(move || {
                let p = p;
                for s in (1..=log_tile).rev() {
                    // SAFETY: `p` is `par`, lent to this block until the scope joins; between two
                    // barriers thread `tx` touches only its butterfly pair in stage `s`.
                    let tl = unsafe { Cells::from_raw(p.0, p.1) };
                    kernels::dif_tile_stage(tx, tl, log_tile, s, lo, hi);
                    bar.wait();
                }
            });
        }
    });
    let mut seq = data(tile);
    let c = Cells::new(&mut seq);
    for s in (1..=log_tile).rev() {
        for tx in 0..tile / 2 { kernels::dif_tile_stage(tx, c, log_tile, s, &lo, &hi); }
    }
    assert_eq!(par, seq);
}
