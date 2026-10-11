//! Port of `crystals-dilithium` 2.0.0 `rounding/lvl2.rs` (the verify half: `decompose`,
//! `use_hint`).
use crate::params::{self, Q};
const GAMMA2: i32 = params::GAMMA2 as i32;

/// For finite field element a, compute high and low bits a0, a1 such that
/// a mod^+ Q = a1*ALPHA + a0 with -ALPHA/2 < a0 <= ALPHA/2, except if a1 = (Q-1)/ALPHA where we
/// set a1 = 0 and -ALPHA/2 <= a0 = a mod^+ Q - Q < 0. Assumes a to be standard representative.
///
/// Returns a tuple (a0, a1).
pub fn decompose(a: i32) -> (i32, i32) {
    let mut a1: i32 = (a + 127) >> 7;
    a1 = (a1 * 11275 + (1 << 23)) >> 24;
    a1 ^= ((43 - a1) >> 31) & a1;
    let mut a0: i32 = a - a1 * 2 * GAMMA2;
    a0 -= (((Q - 1) / 2 - a0) >> 31) & Q;
    (a0, a1)
}

/// Correct high bits according to hint.
///
/// Returns corrected high bits.
pub fn use_hint(a: i32, hint: i32) -> i32 {
    let (a0, a1) = decompose(a);
    if hint == 0 {
        return a1;
    }
    if a0 > 0 {
        if a1 == 43 {
            0
        } else {
            a1 + 1
        }
    } else if a1 == 0 {
        43
    } else {
        a1 - 1
    }
}
