//! Goldilocks field, p = 2^64 - 2^32 + 1, over plain `u64`. Every function takes and
//! returns canonical values (`< P`). Written so the same source compiles to PTX.
pub const P: u64 = 0xFFFF_FFFF_0000_0001;
/// 2^64 mod p = 2^32 - 1.
pub const EPSILON: u64 = 0xFFFF_FFFF;

#[inline(always)]
pub fn reduce(x: u64) -> u64 { if x >= P { x - P } else { x } }

#[inline(always)]
pub fn add(a: u64, b: u64) -> u64 {
    let (s, carry) = a.overflowing_add(b);
    // carry means the true sum is s + 2^64 ≡ s + EPSILON; that add cannot overflow again
    // because s < 2p - 2^64 = 2^64 - 2^33 + 2.
    let s = if carry { s.wrapping_add(EPSILON) } else { s };
    reduce(s)
}

#[inline(always)]
pub fn sub(a: u64, b: u64) -> u64 {
    let (d, borrow) = a.overflowing_sub(b);
    // borrow means the true value is d - 2^64 ≡ d - EPSILON; d ≥ 2^32 so no underflow.
    if borrow { d.wrapping_sub(EPSILON) } else { d }
}

#[inline(always)]
pub fn neg(a: u64) -> u64 { if a == 0 { 0 } else { P - a } }

/// Reduce a 128-bit product. With x = lo + hi_lo·2^64 + hi_hi·2^96 and 2^64 ≡ EPSILON,
/// 2^96 ≡ -1: x ≡ lo - hi_hi + hi_lo·EPSILON.
#[inline(always)]
pub fn reduce128(x: u128) -> u64 {
    let lo = x as u64;
    let hi = (x >> 64) as u64;
    let hi_hi = hi >> 32;
    let hi_lo = hi & EPSILON;
    let (t0, borrow) = lo.overflowing_sub(hi_hi);
    let t0 = if borrow { t0.wrapping_sub(EPSILON) } else { t0 };
    let t1 = hi_lo * EPSILON; // < 2^64
    let (r, carry) = t0.overflowing_add(t1);
    let r = if carry { r.wrapping_add(EPSILON) } else { r };
    reduce(r)
}

#[inline(always)]
pub fn mul(a: u64, b: u64) -> u64 { reduce128((a as u128) * (b as u128)) }

pub fn pow(mut base: u64, mut e: u64) -> u64 {
    let mut acc = 1u64;
    while e != 0 {
        if e & 1 == 1 { acc = mul(acc, base); }
        base = mul(base, base);
        e >>= 1;
    }
    acc
}

/// Fermat inverse; host-side use only (~64 squarings).
pub fn inv(a: u64) -> u64 { pow(a, P - 2) }
