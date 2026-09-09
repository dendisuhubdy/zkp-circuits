//! Poseidon2, width 8, over Goldilocks u64. Mirrors p3-poseidon2 0.7 exactly:
//! initial MDS-light, 4 external rounds, 22 internal rounds, 4 external rounds.
use super::gl::{add, mul, sub};

pub const WIDTH: usize = 8;
pub const RATE: usize = 4;
pub const OUT: usize = 4;
pub const IDX_INITIAL: usize = 0;    // 4 rows × 8
pub const IDX_INTERNAL: usize = 32;  // 22 scalars
pub const IDX_TERMINAL: usize = 54;  // 4 rows × 8
pub const N_CONSTS: usize = 86;

#[inline(always)]
fn sbox(x: u64) -> u64 { let x2 = mul(x, x); let x4 = mul(x2, x2); mul(mul(x4, x2), x) }

#[inline(always)]
fn double(x: u64) -> u64 { add(x, x) }

/// [2 3 1 1; 1 2 3 1; 1 1 2 3; 3 1 1 2] · x, same operation order as p3 `apply_mat4`.
#[inline(always)]
fn mat4(x: &mut [u64], o: usize) {
    let t01 = add(x[o], x[o + 1]);
    let t23 = add(x[o + 2], x[o + 3]);
    let t0123 = add(t01, t23);
    let t01123 = add(t0123, x[o + 1]);
    let t01233 = add(t0123, x[o + 3]);
    x[o + 3] = add(t01233, double(x[o]));
    x[o + 1] = add(t01123, double(x[o + 2]));
    x[o] = add(t01123, t01);
    x[o + 2] = add(t01233, t23);
}

#[inline(always)]
fn mds_light(s: &mut [u64; WIDTH]) {
    mat4(s, 0);
    mat4(s, 4);
    let sums = [add(s[0], s[4]), add(s[1], s[5]), add(s[2], s[6]), add(s[3], s[7])];
    for i in 0..WIDTH { s[i] = add(s[i], sums[i % 4]); }
}

/// diag = [-2, 1, 2, 1/2, 3, -1/2, -3, -4]; state[i] = sum + diag[i]·state[i].
#[inline(always)]
fn internal_matmul(s: &mut [u64; WIDTH]) {
    let mut sum = 0u64;
    for i in 0..WIDTH { sum = add(sum, s[i]); }
    let half = |x: u64| -> u64 { if x & 1 == 0 { x >> 1 } else { (x >> 1) + 0x7FFF_FFFF_8000_0001 } }; // x/2 mod p
    s[0] = sub(sum, double(s[0]));
    s[1] = add(sum, s[1]);
    s[2] = add(sum, double(s[2]));
    s[3] = add(sum, half(s[3]));
    let three4 = add(double(s[4]), s[4]);
    s[4] = add(sum, three4);
    s[5] = sub(sum, half(s[5]));
    let three6 = add(double(s[6]), s[6]);
    s[6] = sub(sum, three6);
    let two7 = double(s[7]);
    s[7] = sub(sum, add(two7, two7));
}

pub fn permute(s: &mut [u64; WIDTH], k: &[u64]) {
    mds_light(s);
    for r in 0..4 {
        for i in 0..WIDTH { s[i] = sbox(add(s[i], k[IDX_INITIAL + r * WIDTH + i])); }
        mds_light(s);
    }
    for r in 0..22 {
        s[0] = sbox(add(s[0], k[IDX_INTERNAL + r]));
        internal_matmul(s);
    }
    for r in 0..4 {
        for i in 0..WIDTH { s[i] = sbox(add(s[i], k[IDX_TERMINAL + r * WIDTH + i])); }
        mds_light(s);
    }
}

/// `PaddingFreeSponge<_, 8, 4, 4>::hash_iter` over `row`.
pub fn hash_row(row: &[u64], k: &[u64]) -> [u64; OUT] {
    let mut s = [0u64; WIDTH];
    let mut i = 0;
    while i + RATE <= row.len() {
        s[0] = row[i]; s[1] = row[i + 1]; s[2] = row[i + 2]; s[3] = row[i + 3];
        permute(&mut s, k);
        i += RATE;
    }
    let rem = row.len() - i;
    if rem != 0 {
        for j in 0..rem { s[j] = row[i + j]; }
        permute(&mut s, k);
    }
    [s[0], s[1], s[2], s[3]]
}

/// `TruncatedPermutation<_, 2, 4, 8>::compress([a, b])`.
pub fn compress(a: &[u64; 4], b: &[u64; 4], k: &[u64]) -> [u64; 4] {
    let mut s = [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]];
    permute(&mut s, k);
    [s[0], s[1], s[2], s[3]]
}
