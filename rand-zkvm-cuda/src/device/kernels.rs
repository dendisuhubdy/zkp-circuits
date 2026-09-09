//! Per-thread bodies of every GPU kernel. `t` is the global thread index. Each body
//! writes only the element(s) owned by `t`, so running bodies for all `t` in any order
//! or in parallel gives the same result. The cuda-oxide crate wraps each in a
//! `#[kernel]`; the mock driver runs them in a loop.
use super::gl::{add, mul, pow, sub};
use super::poseidon2::{compress, hash_row};

pub const LO_BITS: usize = 13;
pub const LOG_MAX: usize = 26;
pub const LOG_TILE: usize = 10;

#[inline(always)]
fn rev(x: usize, bits: usize) -> usize { if bits == 0 { 0 } else { x.reverse_bits() >> (usize::BITS as usize - bits) } }

/// ω_n^j for the size-n NTT, n = 2^log_n, from the two-level ω_{2^26} tables.
#[inline(always)]
pub fn twiddle(lo: &[u64], hi: &[u64], j: usize, log_n: usize) -> u64 {
    let idx = j << (LOG_MAX - log_n);
    mul(lo[idx & ((1 << LO_BITS) - 1)], hi[idx >> LO_BITS])
}

/// data[t] *= uniform · base^(t mod n)   (column-major, so t mod n is the row)
pub fn scale_pow(t: usize, data: &mut [u64], n: usize, base: u64, uniform: u64) {
    if t >= data.len() { return; }
    let r = (t % n) as u64;
    data[t] = mul(data[t], mul(uniform, pow(base, r)));
}

/// dst[col*n + rev(row)] = src[col*n + row]
pub fn bit_reverse(t: usize, src: &[u64], dst: &mut [u64], n: usize, log_n: usize) {
    if t >= src.len() { return; }
    let col = t / n; let row = t % n;
    dst[col * n + rev(row, log_n)] = src[t];
}

/// dst (n_ext rows) = src (n rows) padded with zero rows, column-major.
pub fn zero_extend(t: usize, src: &[u64], dst: &mut [u64], n: usize, n_ext: usize) {
    if t >= dst.len() { return; }
    let col = t / n_ext; let row = t % n_ext;
    dst[t] = if row < n { src[col * n + row] } else { 0 };
}

/// row-major (rows × cols) → column-major
pub fn to_col_major(t: usize, src: &[u64], dst: &mut [u64], rows: usize, cols: usize) {
    if t >= src.len() { return; }
    let r = t / cols; let c = t % cols;
    dst[c * rows + r] = src[t];
}

/// column-major → row-major (rows × cols)
pub fn to_row_major(t: usize, src: &[u64], dst: &mut [u64], rows: usize, cols: usize) {
    if t >= src.len() { return; }
    let c = t / rows; let r = t % rows;
    dst[r * cols + c] = src[t];
}

/// One radix-2 DIF (Gentleman–Sande) stage with m = 2^s over `w` columns of height n.
/// Thread t handles butterfly t of the w·n/2 butterflies.
pub fn dif_stage(t: usize, data: &mut [u64], n: usize, log_n: usize, s: usize, lo: &[u64], hi: &[u64]) {
    let half_n = n / 2;
    if t >= (data.len() / n) * half_n { return; }
    let col = t / half_n; let b = t % half_n;
    let m = 1usize << s; let half = m / 2;
    let k = (b / half) * m; let j = b % half;
    let i0 = col * n + k + j; let i1 = i0 + half;
    let w = twiddle(lo, hi, j << (log_n - s), log_n); // ω_m^j = ω_n^{j·n/m}
    let u = data[i0]; let v = data[i1];
    data[i0] = add(u, v);
    data[i1] = mul(sub(u, v), w);
}

/// The stages s = log_tile..=1 of a DIF over one contiguous tile of 2^log_tile elements.
/// `t` is the thread within the tile (0..tile/2); call once per stage, with a barrier
/// between stages on the GPU.
pub fn dif_tile_stage(t: usize, tile: &mut [u64], log_n: usize, s: usize, lo: &[u64], hi: &[u64]) {
    let m = 1usize << s; let half = m / 2;
    if t >= tile.len() / 2 { return; }
    let k = (t / half) * m; let j = t % half;
    let i0 = k + j; let i1 = i0 + half;
    let w = twiddle(lo, hi, j << (log_n - s), log_n);
    let u = tile[i0]; let v = tile[i1];
    tile[i0] = add(u, v);
    tile[i1] = mul(sub(u, v), w);
}

/// Copy `n` rows of a `src_w`-wide row-major matrix into columns [col_off, col_off+src_w)
/// of a `dst_w`-wide row-major matrix.
pub fn copy_columns(t: usize, src: &[u64], src_w: usize, dst: &mut [u64], dst_w: usize, col_off: usize) {
    if t >= src.len() { return; }
    let r = t / src_w; let c = t % src_w;
    dst[r * dst_w + col_off + c] = src[t];
}

/// out[4t..4t+4] = sponge(row t of a `width`-wide row-major matrix)
pub fn poseidon2_rows(t: usize, rows: &[u64], width: usize, n: usize, k: &[u64], out: &mut [u64]) {
    if t >= n { return; }
    let d = hash_row(&rows[t * width..(t + 1) * width], k);
    out[4 * t..4 * t + 4].copy_from_slice(&d);
}

/// out[t] = compress(prev[2t], prev[2t+1]) for t < next_len (digests are 4 u64 each)
pub fn poseidon2_compress(t: usize, prev: &[u64], next_len: usize, k: &[u64], out: &mut [u64]) {
    if t >= next_len { return; }
    let a: [u64; 4] = prev[8 * t..8 * t + 4].try_into().unwrap();
    let b: [u64; 4] = prev[8 * t + 4..8 * t + 8].try_into().unwrap();
    out[4 * t..4 * t + 4].copy_from_slice(&compress(&a, &b, k));
}

/// Plonky3 `compress_and_inject` for arity 2: for t < raw_next, d = compress(prev pair);
/// r = hash(row t) if t < n_rows else zero digest; out[t] = compress(d, r).
pub fn poseidon2_inject(t: usize, prev: &[u64], raw_next: usize, rows: &[u64], width: usize, n_rows: usize, k: &[u64], out: &mut [u64]) {
    if t >= raw_next { return; }
    let a: [u64; 4] = prev[8 * t..8 * t + 4].try_into().unwrap();
    let b: [u64; 4] = prev[8 * t + 4..8 * t + 8].try_into().unwrap();
    let d = compress(&a, &b, k);
    let r = if t < n_rows { hash_row(&rows[t * width..(t + 1) * width], k) } else { [0u64; 4] };
    out[4 * t..4 * t + 4].copy_from_slice(&compress(&d, &r, k));
}
