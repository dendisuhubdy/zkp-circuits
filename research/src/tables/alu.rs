//! 32-bit ALU as four byte limbs. Add/sub/compare share one adder; bitwise ops
//! go through the nibble table (two lookups per limb — low then derived high
//! nibble); shifts are proved as exact integer identities that cannot wrap in
//! Goldilocks, with the shift amount and a handful of isolated sign/overflow
//! bits extracted through the nibble table too.
use super::{bus, limbs, nibble::NibbleCounts, range::RangeCounts, F};
use crate::emulator::{AluEvent, CycleEvent};
use crate::isa::AluOp;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

pub mod col {
    pub const FLAG0: usize = 0;   // 11 flags, AluOp code order
    pub const A: usize = 11; pub const B: usize = 12; pub const C: usize = 13;
    pub const A0: usize = 14; pub const B0: usize = 18; pub const C0: usize = 22;
    pub const Q0: usize = 26;     // shift quotient / sll high word limbs / bitwise AL0..3
    pub const S0: usize = 30;     // compare difference / right-shift remainder limbs / bitwise BL0..3
    pub const T0: usize = 34;     // pw - 1 - r limbs / bitwise CL0..3
    pub const SA: usize = 38; pub const SB: usize = 39; pub const SHH: usize = 40; pub const PW: usize = 41;
    pub const CARRY0: usize = 42; pub const INV: usize = 46; pub const IS_REAL: usize = 47; pub const MULT: usize = 48;
    /// A's top-limb (A0+3) low nibble's high-nibble companion, used only on `slt`/`sra`
    /// rows to extract A's sign bit.
    pub const AH3: usize = 49;
    /// B's relevant limb's high nibble: B's top limb (limb 3) on `slt` rows (for SB),
    /// B's limb 0 on shift rows (for the shift-amount high bit).
    pub const BH_N: usize = 50;
    /// `sll`'s overflow check: Q's top limb (Q0+3)'s high nibble.
    pub const QH3: usize = 51;
    pub const WIDTH: usize = 52;
}
use col::*;

#[derive(Clone, Copy, Debug, Default)]
pub struct AluAir;

impl<Fld> BaseAir<Fld> for AluAir { fn width(&self) -> usize { WIDTH } }

// A fixed Goldilocks constant: 16⁻¹ mod (2^64 - 2^32 + 1) = 17293822565076172801.
// Used only to derive a nibble-pair's HIGH half from its LOW half as a pure
// expression (never a witness column) in cases where BOTH nibbles already get an
// independent, real lookup elsewhere on the same row (the bitwise case below) — see
// the doc comment on `bitwise_high_nibble`.
const INV16: u64 = 17_293_822_565_076_172_801;

/// For bitwise rows only: given a byte limb `byte` and its already-looked-up low
/// nibble `lo` (bound to [0,16) by the row's own low-nibble AND4/OR4/XOR4 lookup),
/// the high nibble is `(byte - lo) * 16⁻¹` as a pure expression — no extra column,
/// no extra lookup. This is sound *only* because `lo` already has an independent,
/// non-dummy lookup on this row (the low-nibble AND4/OR4/XOR4 call): the map
/// `byte ↦ (byte - lo) * 16⁻¹` is a field bijection, and only byte values in [0,256)
/// map to a high-nibble result in [0,16) (the bijection's unique preimage for any
/// target in [0,16) is exactly `lo + 16*target`, which is <256). So constraining the
/// *derived* high nibble to a valid AND4/OR4/XOR4 row (its second, real lookup) is
/// enough to force `byte < 256` with zero extra columns. This does NOT generalize to
/// an isolated nibble extraction (sign bits, shift amount, memory alignment) where
/// the low nibble has no other lookup of its own — those need an explicit dummy
/// range-check lookup in addition (see `nibble_lo_dummy_range` below).
fn bitwise_high_nibble<AB: AirBuilder>(byte: AB::Expr, lo: AB::Expr) -> AB::Expr {
    (byte - lo) * AB::Expr::from_u64(INV16)
}

/// Isolated nibble extraction: the companion low nibble has no other lookup on this
/// row, so it needs its own dummy range-check lookup (weight 0 used as an arbitrary
/// in-range mask; the output slot is pinned to 0 — since the companion range check's
/// own output value is unused, any consistent fixed constant works as long as the
/// row exists in the table for every nibble; we key against 0 for simplicity, i.e.
/// AND4[x, 0, 0] holds for every x in [0,16)).
fn nibble_lo_dummy_range<AB: AirBuilder + InteractionBuilder>(b: &mut AB, lo: AB::Expr, gate: AB::Expr) {
    bus::AND4.lookup_key(b, [lo, AB::Expr::ZERO, AB::Expr::ZERO], Count::bounded(gate, 1));
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for AluAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let one = AB::Expr::ONE;
        let c8 = |k: u32| AB::Expr::from_u32(1u32 << (8 * k));
        let f = |op: AluOp| v(FLAG0 + op.code() as usize);
        let (add, sub, and, or, xor, sll, srl, sra, slt, sltu, eq) = (
            f(AluOp::Add), f(AluOp::Sub), f(AluOp::And), f(AluOp::Or), f(AluOp::Xor), f(AluOp::Sll),
            f(AluOp::Srl), f(AluOp::Sra), f(AluOp::Slt), f(AluOp::Sltu), f(AluOp::Eq),
        );
        let is_real = v(IS_REAL);
        b.assert_bool(is_real.clone());
        // INVARIANT — for every `table_entry` in this crate, the count must be forced to
        // zero wherever the message columns are unconstrained. On a padding row every op
        // flag is zero (so the provided `op` decodes as `Add`), the limb range checks are
        // gated on `is_real`, and every arithmetic constraint carries a flag factor — so
        // `A`, `B` and `C` are free field elements there. Without this line `MULT` was the
        // last free column, and a padding row provided an arbitrary `(Add, a, b, c)` tuple
        // with arbitrary multiplicity: the CPU consumes `Add` for every ADD/ADDI, every
        // load/store address, every JALR target and the whole slot-2 `(0, pc, imm, tgt)`
        // lookup, so `fib(10) = 999` was provable (`tests/cheating.rs`).
        b.assert_zero((one.clone() - is_real.clone()) * v(MULT));
        let mut sum = AB::Expr::ZERO;
        for i in 0..AluOp::COUNT { b.assert_bool(v(FLAG0 + i)); sum += v(FLAG0 + i); }
        b.assert_eq(sum, is_real.clone());

        // limb recomposition and range checks
        let word = |base: usize| v(base) + v(base + 1) * c8(1) + v(base + 2) * c8(2) + v(base + 3) * c8(3);
        b.assert_eq(word(A0), v(A));
        b.assert_eq(word(B0), v(B));
        b.assert_eq(word(C0), v(C));
        for i in 0..4 {
            for base in [A0, B0, C0] { bus::RANGE8.lookup_key(b, [v(base + i)], Count::bounded(is_real.clone(), 1)); }
        }
        let cmp = slt.clone() + sltu.clone();
        let rshift = srl.clone() + sra.clone();
        let shift = sll.clone() + rshift.clone();
        for i in 0..4 {
            bus::RANGE8.lookup_key(b, [v(S0 + i)], Count::bounded(cmp.clone() + rshift.clone(), 1));
            bus::RANGE8.lookup_key(b, [v(T0 + i)], Count::bounded(rshift.clone(), 1));
            bus::RANGE8.lookup_key(b, [v(Q0 + i)], Count::bounded(shift.clone(), 1));
        }

        // shared adder: x + y = z (mod 2^32) with limb carries
        let adder = add.clone() + sub.clone() + cmp.clone();
        for i in 0..4 {
            let x = add.clone() * v(A0 + i) + sub.clone() * v(B0 + i) + cmp.clone() * v(B0 + i);
            let y = add.clone() * v(B0 + i) + sub.clone() * v(C0 + i) + cmp.clone() * v(S0 + i);
            let z = add.clone() * v(C0 + i) + (sub.clone() + cmp.clone()) * v(A0 + i);
            let cin = if i == 0 { AB::Expr::ZERO } else { v(CARRY0 + i - 1) };
            b.assert_bool(v(CARRY0 + i));
            b.assert_zero((one.clone() - adder.clone()) * v(CARRY0 + i));
            b.assert_zero(x + y + cin - z - v(CARRY0 + i) * AB::Expr::from_u32(256));
        }
        let borrow = v(CARRY0 + 3);

        // sign bits: A's sign on slt/sra rows (AH3, from A0+3's high nibble), B's sign on
        // slt rows only (BH_N, from B0+3's high nibble). Each isolated low-nibble
        // companion (a3_lo/b3_lo) gets its own dummy range-check lookup since nothing else
        // on these rows looks it up; see `nibble_lo_dummy_range`'s doc comment.
        b.assert_bool(v(SA));
        b.assert_bool(v(SB));
        let a3_lo = v(A0 + 3) - AB::Expr::from_u32(16) * v(AH3);
        nibble_lo_dummy_range(b, a3_lo, slt.clone() + sra.clone());
        bus::AND4.lookup_key(b, [v(AH3), AB::Expr::from_u32(8), v(SA) * AB::Expr::from_u32(8)], Count::bounded(slt.clone() + sra.clone(), 1));
        let b3_lo = v(B0 + 3) - AB::Expr::from_u32(16) * v(BH_N);
        nibble_lo_dummy_range(b, b3_lo, slt.clone());
        bus::AND4.lookup_key(b, [v(BH_N), AB::Expr::from_u32(8), v(SB) * AB::Expr::from_u32(8)], Count::bounded(slt.clone(), 1));
        b.assert_zero(srl.clone() * v(SA));

        // compares
        b.assert_zero((cmp.clone() + eq.clone()) * v(C) * (v(C) - one.clone()));
        b.assert_zero(sltu.clone() * (v(C) - borrow.clone()));
        let sx = v(SA) + v(SB) - v(SA) * v(SB) * AB::Expr::TWO;
        b.assert_zero(slt.clone() * (v(C) - (one.clone() - sx.clone()) * borrow.clone() - sx * v(SA)));
        let diff = v(A) - v(B);
        b.assert_zero(eq.clone() * (diff.clone() * v(INV) + v(C) - one.clone()));
        b.assert_zero(eq.clone() * v(C) * diff);

        // bitwise: low nibbles are stored scratch (Q0..3/S0..3/T0..3, meaningful only on
        // bitwise rows — every other op either gates its own use of these columns to zero
        // or leaves them unused), high nibbles are derived expressions bound by the row's
        // own second lookup (`bitwise_high_nibble`). Two lookups per limb, eight per row.
        for i in 0..4 {
            let (al, bl, cl) = (v(Q0 + i), v(S0 + i), v(T0 + i));
            let ah = bitwise_high_nibble::<AB>(v(A0 + i), al.clone());
            let bh = bitwise_high_nibble::<AB>(v(B0 + i), bl.clone());
            let ch = bitwise_high_nibble::<AB>(v(C0 + i), cl.clone());
            bus::AND4.lookup_key(b, [al.clone(), bl.clone(), cl.clone()], Count::bounded(and.clone(), 1));
            bus::AND4.lookup_key(b, [ah.clone(), bh.clone(), ch.clone()], Count::bounded(and.clone(), 1));
            bus::OR4.lookup_key(b, [al.clone(), bl.clone(), cl.clone()], Count::bounded(or.clone(), 1));
            bus::OR4.lookup_key(b, [ah.clone(), bh.clone(), ch.clone()], Count::bounded(or.clone(), 1));
            bus::XOR4.lookup_key(b, [al, bl, cl], Count::bounded(xor.clone(), 1));
            bus::XOR4.lookup_key(b, [ah, bh, ch], Count::bounded(xor.clone(), 1));
        }

        // shifts. The shift amount `sh = b & 31` is decomposed as B0's low nibble
        // (`b0_lo`, derived — not stored — from B0 and BH_N, exactly like the sign-bit
        // extraction above; BH_N is reused here for B's limb-0 high nibble, safe because
        // shift and slt never co-occur) plus 16 times SHH, B0's high nibble's bit 0.
        let b0_lo = v(B0) - AB::Expr::from_u32(16) * v(BH_N);
        nibble_lo_dummy_range(b, b0_lo.clone(), shift.clone());
        bus::AND4.lookup_key(b, [v(BH_N), AB::Expr::ONE, v(SHH)], Count::bounded(shift.clone(), 1));
        let sh = b0_lo + AB::Expr::from_u32(16) * v(SHH);
        bus::POW2.lookup_key(b, [sh, v(PW)], Count::bounded(shift.clone(), 1));
        let q = word(Q0);
        let r = word(S0);
        let t = word(T0);
        let two32 = AB::Expr::from_u64(1 << 32);
        b.assert_zero(sll.clone() * (v(A) * v(PW) - q.clone() * two32 - v(C)));
        // sll's overflow check: Q's top limb's high nibble (QH3) must have its top bit
        // clear, via the same isolated-extraction pattern as the sign bits above.
        let q3_lo = v(Q0 + 3) - AB::Expr::from_u32(16) * v(QH3);
        nibble_lo_dummy_range(b, q3_lo, sll.clone());
        bus::AND4.lookup_key(b, [v(QH3), AB::Expr::from_u32(8), AB::Expr::ZERO], Count::bounded(sll.clone(), 1));
        // right shifts: complement when negative (sra), shift, complement back
        let flip = |x: AB::Expr| x.clone() + v(SA) * (AB::Expr::from_u32(255) - x * AB::Expr::TWO);
        let a_prime = flip(v(A0)) + flip(v(A0 + 1)) * c8(1) + flip(v(A0 + 2)) * c8(2) + flip(v(A0 + 3)) * c8(3);
        b.assert_zero(rshift.clone() * (a_prime - q * v(PW) - r.clone()));
        b.assert_zero(rshift.clone() * (v(PW) - one.clone() - r - t));
        for i in 0..4 { b.assert_zero(rshift.clone() * (v(C0 + i) - flip(v(Q0 + i)))); }

        // provide (op, a, b, c)
        let mut op = AB::Expr::ZERO;
        for i in 0..AluOp::COUNT { op += v(FLAG0 + i) * AB::Expr::from_u32(i as u32); }
        bus::ALU.table_entry(b, [op, v(A), v(B), v(C)], v(MULT));
    }
}

fn set_limbs(row: &mut [F], base: usize, x: u32, range: &mut RangeCounts, count: bool) {
    let l = limbs(x);
    for i in 0..4 { row[base + i] = l[i]; if count { range.range8((x >> (8 * i)) & 0xff); } }
}

/// Sets `hi_col` to `byte`'s high nibble and `sa_col` to its top bit, counting the
/// dummy low-nibble range check and the real `AND4[hi,8,sa*8]` extraction lookup.
fn sign_bit(row: &mut [F], byte: u32, hi_col: usize, sa_col: usize, nibble: &mut NibbleCounts) {
    let lo = byte & 0xf;
    let hi = byte >> 4;
    row[hi_col] = F::from_u32(hi);
    row[sa_col] = F::from_u32(hi >> 3); // top bit of the nibble == top bit of the byte
    nibble.and4(lo, 0);
    nibble.and4(hi, 8);
}

/// Fill one ALU row from an event and count its RANGE8/AND4/OR4/XOR4/POW2 lookups.
pub fn fill_row(row: &mut [F], ev: &AluEvent, range: &mut RangeCounts, nibble: &mut NibbleCounts) {
    let AluEvent { op, a, b, c } = *ev;
    assert_eq!(c, op.eval(a, b), "ALU event {op:?}({a:#x}, {b:#x}) = {c:#x} does not match reference semantics");
    row[FLAG0 + op.code() as usize] = F::ONE;
    row[A] = F::from_u32(a); row[B] = F::from_u32(b); row[C] = F::from_u32(c);
    row[IS_REAL] = F::ONE; row[MULT] = F::ONE;
    set_limbs(row, A0, a, range, true); set_limbs(row, B0, b, range, true); set_limbs(row, C0, c, range, true);
    let (a3, b3, b0) = ((a >> 24) & 0xff, (b >> 24) & 0xff, b & 0xff);
    let adder = |row: &mut [F], x: u32, y: u32| {
        // carries of x + y limb-wise
        let mut carry = 0u32;
        for i in 0..4 {
            let s = ((x >> (8 * i)) & 0xff) + ((y >> (8 * i)) & 0xff) + carry;
            carry = s >> 8;
            row[CARRY0 + i] = F::from_u32(carry);
        }
    };
    match op {
        AluOp::Add => adder(row, a, b),
        AluOp::Sub => adder(row, b, c),
        AluOp::Slt | AluOp::Sltu => {
            let d = a.wrapping_sub(b);
            set_limbs(row, S0, d, range, true);
            adder(row, b, d);
            if op == AluOp::Slt {
                sign_bit(row, a3, AH3, SA, nibble);
                sign_bit(row, b3, BH_N, SB, nibble);
            }
        }
        AluOp::Eq => { if a != b { row[INV] = (F::from_u32(a) - F::from_u32(b)).inverse(); } }
        AluOp::And | AluOp::Or | AluOp::Xor => {
            for i in 0..4 {
                let (ab, bb, cb) = ((a >> (8 * i)) & 0xff, (b >> (8 * i)) & 0xff, (c >> (8 * i)) & 0xff);
                let (al, ah) = (ab & 0xf, ab >> 4);
                let (bl, bh) = (bb & 0xf, bb >> 4);
                let cl = cb & 0xf;
                row[Q0 + i] = F::from_u32(al);
                row[S0 + i] = F::from_u32(bl);
                row[T0 + i] = F::from_u32(cl);
                match op {
                    AluOp::And => { nibble.and4(al, bl); nibble.and4(ah, bh); }
                    AluOp::Or => { nibble.or4(al, bl); nibble.or4(ah, bh); }
                    AluOp::Xor => { nibble.xor4(al, bl); nibble.xor4(ah, bh); }
                    _ => unreachable!(),
                }
            }
        }
        AluOp::Sll | AluOp::Srl | AluOp::Sra => {
            let sh = b & 31; let pw = 1u32 << sh;
            row[PW] = F::from_u32(pw);
            // shift-amount decomposition: b0's low nibble (implied, not stored — see the
            // eval comment) plus BH_N (b0's high nibble) and SHH = BH_N's bottom bit.
            let bh_n = b0 >> 4;
            row[BH_N] = F::from_u32(bh_n);
            row[SHH] = F::from_u32(bh_n & 1);
            nibble.and4(b0 & 0xf, 0);
            nibble.and4(bh_n, 1);
            range.pow2(sh);
            if op == AluOp::Sll {
                let hi = ((a as u64 * pw as u64) >> 32) as u32;
                set_limbs(row, Q0, hi, range, true);
                let hi3 = (hi >> 24) & 0xff;
                let qh3 = hi3 >> 4;
                row[QH3] = F::from_u32(qh3);
                nibble.and4(hi3 & 0xf, 0);
                nibble.and4(qh3, 8);
            } else {
                let sa = if op == AluOp::Sra { a >> 31 } else { 0 };
                if op == AluOp::Sra { sign_bit(row, a3, AH3, SA, nibble); }
                let ap = if sa == 1 { !a } else { a };
                let q = ap >> sh; let r = ap - q * pw; let t = pw - 1 - r;
                set_limbs(row, Q0, q, range, true); set_limbs(row, S0, r, range, true); set_limbs(row, T0, t, range, true);
            }
        }
    }
}

pub fn alu_trace(events: &[CycleEvent], height: usize, range: &mut RangeCounts, nibble: &mut NibbleCounts) -> RowMajorMatrix<F> {
    let evs: Vec<&AluEvent> = events.iter().flat_map(|e| e.alu.iter()).collect();
    assert!(evs.len() < height, "alu table needs a padding row: {} ops, height {height}", evs.len());
    let mut v = F::zero_vec(height * WIDTH);
    for (i, ev) in evs.iter().enumerate() { fill_row(&mut v[i * WIDTH..(i + 1) * WIDTH], ev, range, nibble); }
    RowMajorMatrix::new(v, WIDTH)
}
