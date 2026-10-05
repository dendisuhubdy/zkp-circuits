//! The reduction chip (Task 8; phase 3 Cut D, 2026-10-05): one chip row per reduction column.
//!
//! **The layout is preprocessed.** Every run's addresses — its opened values, its row, its
//! inverse key, the chain's alpha and result cells — are compile-time constants of the program,
//! listed in `Program::reduce_layout`. The chip's preprocessed region holds one row per entry,
//! with a witness `MULT` (the `ProgramAir` pattern), and is committed by the verifier key. Each
//! run looks up its entry on its first row (`REDUCE_LAYOUT`), so a descriptor is never a witness
//! value. The aggregate program runs every entry N times; `MULT` is N.
//!
//! **Chains carry in the chip.** A run's rows step `acc += apow·(pz − px)·inv`,
//! `apow ·= alpha`; a run whose entry carries hands both to the next row, the next entry's first
//! row, dispatched by the very next cpu row (`n(CLK) = CLK + 1`, `n(ENTRY) = ENTRY + 1`). A chain
//! starts at `acc = 0`, `apow = 1`, reads alpha once, and writes its result once.
//!
//! Every message is degree 1: its counts are columns (`WRITES`, `READ_ALPHA` are constrained
//! products) and its values are columns (`OUT` is constrained to the step's output).
use super::{bus, F};
use crate::emulator::{Event, TS_ALPHA0, TS_ALPHA1, TS_KEY0, TS_KEY1, TS_RES0, TS_RES1, TS_RUN_PX, TS_RUN_PZ0, TS_RUN_PZ1};
use crate::isa::ReduceEntry;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use std::sync::Arc;

pub mod col {
    pub const IS_REAL: usize = 0;
    pub const IS_FIRST: usize = 1;
    pub const IS_LAST: usize = 2;
    pub const CLK: usize = 3;
    pub const ENTRY: usize = 4;
    pub const ADDR_V: usize = 5;
    pub const ADDR_R: usize = 6;
    /// The entry's last row cell, from the layout: `IS_LAST ⟺ ADDR_R = ROW_END` (R5).
    pub const ROW_END: usize = 7;
    pub const END_INV: usize = 8;
    pub const KEY: usize = 9;
    pub const ALPHA_ADDR: usize = 10;
    pub const RES: usize = 11;
    pub const CHAIN_START: usize = 12;
    pub const CARRY: usize = 13;
    pub const ACC0: usize = 14;
    pub const ACC1: usize = 15;
    pub const APOW0: usize = 16;
    pub const APOW1: usize = 17;
    pub const INV0: usize = 18;
    pub const INV1: usize = 19;
    pub const ALPHA0: usize = 20;
    pub const ALPHA1: usize = 21;
    pub const PZ0: usize = 22;
    pub const PZ1: usize = 23;
    pub const PX: usize = 24;
    /// The step's output accumulator on a last row: the result written when the chain closes.
    pub const OUT0: usize = 25;
    pub const OUT1: usize = 26;
    /// `IS_LAST·(1 − CARRY)` and `IS_FIRST·CHAIN_START`, as columns so every count is degree 1.
    pub const WRITES: usize = 27;
    pub const READ_ALPHA: usize = 28;
    /// The provider region's multiplicity: how many runs of this row's layout entry executed.
    pub const MULT: usize = 29;
    pub const WIDTH: usize = 30;
}
pub mod pre {
    pub const L_IS_ENTRY: usize = 0;
    pub const L_ENTRY: usize = 1;
    pub const L_ADDR_V: usize = 2;
    pub const L_ADDR_R: usize = 3;
    pub const L_ROW_END: usize = 4;
    pub const L_KEY: usize = 5;
    pub const L_ALPHA: usize = 6;
    pub const L_RES: usize = 7;
    /// `chain_start + 2·carry`.
    pub const L_FLAGS: usize = 8;
    pub const WIDTH: usize = 9;
}
use col::*;

pub const MIN_LOG_HEIGHT: u8 = 4;

/// The chip carries its program's layout (the preprocessed region is built from it) and the
/// declared height that region is committed at.
#[derive(Clone, Debug)]
pub struct ReduceAir {
    pub layout: Arc<Vec<ReduceEntry>>,
    pub height: usize,
}

impl ReduceAir {
    pub fn new(layout: Arc<Vec<ReduceEntry>>, height: usize) -> Self {
        assert!(height >= provider_rows(&layout), "the reduce table must hold its provider region");
        ReduceAir { layout, height }
    }
}

/// Rows the preprocessed provider region occupies.
pub fn provider_rows(layout: &[ReduceEntry]) -> usize {
    layout.len()
}

impl<Fld: Field> BaseAir<Fld> for ReduceAir {
    fn width(&self) -> usize { col::WIDTH }
    fn preprocessed_width(&self) -> usize { pre::WIDTH }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> {
        let mut v = Fld::zero_vec(self.height * pre::WIDTH);
        for (i, e) in self.layout.iter().enumerate() {
            let r = &mut v[i * pre::WIDTH..(i + 1) * pre::WIDTH];
            r[pre::L_IS_ENTRY] = Fld::ONE;
            r[pre::L_ENTRY] = Fld::from_u64(i as u64);
            r[pre::L_ADDR_V] = Fld::from_u64(e.vals);
            r[pre::L_ADDR_R] = Fld::from_u64(e.row);
            r[pre::L_ROW_END] = Fld::from_u64(e.row + e.len as u64 - 1);
            r[pre::L_KEY] = Fld::from_u64(e.key);
            r[pre::L_ALPHA] = Fld::from_u64(e.alpha);
            r[pre::L_RES] = Fld::from_u64(e.res);
            r[pre::L_FLAGS] = Fld::from_u64(e.chain_start as u64 + 2 * e.carry as u64);
        }
        Some(RowMajorMatrix::new(v, pre::WIDTH))
    }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for ReduceAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let p = b.preprocessed().clone();
        let m = b.main();
        let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let n = |i: usize| -> AB::Expr { m.next(i).unwrap().into() };
        let l = |i: usize| -> AB::Expr { p.current(i).unwrap().into() };
        let one = AB::Expr::ONE;
        let seven = AB::Expr::from_u64(7);
        let sixteen = AB::Expr::from_u32(16);

        let (is_real, is_first, is_last) = (v(IS_REAL), v(IS_FIRST), v(IS_LAST));
        for c in [IS_REAL, IS_FIRST, IS_LAST, CHAIN_START, CARRY] {
            b.assert_bool(v(c));
        }
        // V-OPCODES-1: both run-boundary kinds exist only on real rows.
        b.assert_zero(is_first.clone() * (one.clone() - is_real.clone()));
        b.assert_zero(is_last.clone() * (one.clone() - is_real.clone()));
        // R5: IS_LAST ⟺ ADDR_R = ROW_END on a real row (a last row sits there; a real non-last
        // row does not, witnessed by the inverse).
        let d = v(ADDR_R) - v(ROW_END);
        b.assert_zero(is_last.clone() * d.clone());
        b.assert_zero(is_real.clone() * (one.clone() - is_last.clone()) * (one.clone() - d * v(END_INV)));
        // The two count columns.
        b.assert_zero(v(WRITES) - is_last.clone() * (one.clone() - v(CARRY)));
        b.assert_zero(v(READ_ALPHA) - is_first.clone() * v(CHAIN_START));
        // A chain starts at acc = 0, apow = 1.
        b.assert_zero(v(READ_ALPHA) * v(ACC0));
        b.assert_zero(v(READ_ALPHA) * v(ACC1));
        b.assert_zero(v(READ_ALPHA) * (v(APOW0) - one.clone()));
        b.assert_zero(v(READ_ALPHA) * v(APOW1));
        // AGENTS.md invariant 2 on the provider: a multiplicity only on a layout row.
        b.assert_zero(v(MULT) * (one.clone() - l(pre::L_IS_ENTRY)));

        // ── boundaries and the run structure (ZKR-4) ──
        b.when_first_row().assert_zero(is_real.clone() * (one.clone() - is_first.clone()));
        b.when_first_row().assert_zero(is_first.clone() * (one.clone() - v(CHAIN_START)));
        b.when_last_row().assert_zero(is_real.clone());
        {
            let mut t = b.when_transition();
            t.assert_zero((one.clone() - is_real.clone()) * n(IS_REAL));
            t.assert_zero(is_last.clone() * n(IS_REAL) * (one.clone() - n(IS_FIRST)));
            t.assert_zero(is_real.clone() * (one.clone() - is_last.clone()) * (one.clone() - n(IS_REAL)));
            t.assert_zero(is_real.clone() * (one.clone() - is_last.clone()) * n(IS_FIRST));
        }

        // ── the column step: diff = pz − px; t = apow·diff; t2 = t·inv; acc += t2; apow ·= alpha ──
        let (diff0, diff1) = (v(PZ0) - v(PX), v(PZ1));
        let t0 = v(APOW0) * diff0.clone() + seven.clone() * v(APOW1) * diff1.clone();
        let t1 = v(APOW0) * diff1 + v(APOW1) * diff0;
        let t2_0 = t0.clone() * v(INV0) + seven.clone() * t1.clone() * v(INV1);
        let t2_1 = t0 * v(INV1) + t1 * v(INV0);
        let acc_next0 = v(ACC0) + t2_0;
        let acc_next1 = v(ACC1) + t2_1;
        let apow_next0 = v(APOW0) * v(ALPHA0) + seven.clone() * v(APOW1) * v(ALPHA1);
        let apow_next1 = v(APOW0) * v(ALPHA1) + v(APOW1) * v(ALPHA0);
        b.assert_zero(is_last.clone() * (v(OUT0) - acc_next0.clone()));
        b.assert_zero(is_last.clone() * (v(OUT1) - acc_next1.clone()));

        // ── within an entry: the step chains, every per-entry column is carried ──
        let in_run_next = n(IS_REAL) * (one.clone() - n(IS_FIRST));
        {
            let mut t = b.when_transition();
            t.assert_zero(in_run_next.clone() * (n(ACC0) - acc_next0.clone()));
            t.assert_zero(in_run_next.clone() * (n(ACC1) - acc_next1.clone()));
            t.assert_zero(in_run_next.clone() * (n(APOW0) - apow_next0.clone()));
            t.assert_zero(in_run_next.clone() * (n(APOW1) - apow_next1.clone()));
            for c in [INV0, INV1, ALPHA0, ALPHA1, CLK, ENTRY, ROW_END, KEY, ALPHA_ADDR, RES, CHAIN_START, CARRY] {
                t.assert_zero(in_run_next.clone() * (n(c) - v(c)));
            }
            t.assert_zero(in_run_next.clone() * (n(ADDR_V) - v(ADDR_V) - AB::Expr::from_u32(2)));
            t.assert_zero(in_run_next.clone() * (n(ADDR_R) - v(ADDR_R) - one.clone()));
        }
        // ── across entries (R4): a carrying last row hands acc, apow and alpha to the next row,
        // which is the next entry's first row at the next clock; a continuation entry is entered
        // only that way ──
        let carry = is_last.clone() * v(CARRY);
        {
            let mut t = b.when_transition();
            t.assert_zero(carry.clone() * (one.clone() - n(IS_FIRST)));
            t.assert_zero(carry.clone() * n(CHAIN_START));
            t.assert_zero(carry.clone() * (n(ENTRY) - v(ENTRY) - one.clone()));
            t.assert_zero(carry.clone() * (n(CLK) - v(CLK) - one.clone()));
            t.assert_zero(carry.clone() * (n(ACC0) - acc_next0));
            t.assert_zero(carry.clone() * (n(ACC1) - acc_next1));
            t.assert_zero(carry.clone() * (n(APOW0) - apow_next0));
            t.assert_zero(carry.clone() * (n(APOW1) - apow_next1));
            t.assert_zero(carry.clone() * (n(ALPHA0) - v(ALPHA0)));
            t.assert_zero(carry.clone() * (n(ALPHA1) - v(ALPHA1)));
            t.assert_zero(n(IS_FIRST) * (one.clone() - n(CHAIN_START)) * (one.clone() - carry));
        }

        // ── buses ──
        bus::REDUCE.table_entry(b, [v(CLK), v(ENTRY)], is_first.clone());
        let flags = v(CHAIN_START) + AB::Expr::from_u32(2) * v(CARRY);
        bus::REDUCE_LAYOUT.lookup_key(
            b,
            [v(ENTRY), v(ADDR_V), v(ADDR_R), v(ROW_END), v(KEY), v(ALPHA_ADDR), v(RES), flags],
            Count::bounded(is_first.clone(), 1),
        );
        bus::REDUCE_LAYOUT.table_entry(
            b,
            [l(pre::L_ENTRY), l(pre::L_ADDR_V), l(pre::L_ADDR_R), l(pre::L_ROW_END), l(pre::L_KEY), l(pre::L_ALPHA), l(pre::L_RES), l(pre::L_FLAGS)],
            v(MULT),
        );
        let clk = v(CLK);
        let ts = |slot: u32| sixteen.clone() * clk.clone() + AB::Expr::from_u32(slot);
        let zero = AB::Expr::ZERO;
        bus::RAM.send(b, [v(KEY), ts(TS_KEY0), v(INV0), zero.clone()], Count::bounded(is_first.clone(), 1));
        bus::RAM.send(b, [v(KEY) + one.clone(), ts(TS_KEY1), v(INV1), zero.clone()], Count::bounded(is_first.clone(), 1));
        bus::RAM.send(b, [v(ALPHA_ADDR), ts(TS_ALPHA0), v(ALPHA0), zero.clone()], Count::bounded(v(READ_ALPHA), 1));
        bus::RAM.send(b, [v(ALPHA_ADDR) + one.clone(), ts(TS_ALPHA1), v(ALPHA1), zero.clone()], Count::bounded(v(READ_ALPHA), 1));
        bus::RAM.send(b, [v(ADDR_V), ts(TS_RUN_PZ0), v(PZ0), zero.clone()], Count::bounded(is_real.clone(), 1));
        bus::RAM.send(b, [v(ADDR_V) + one.clone(), ts(TS_RUN_PZ1), v(PZ1), zero.clone()], Count::bounded(is_real.clone(), 1));
        bus::RAM.send(b, [v(ADDR_R), ts(TS_RUN_PX), v(PX), zero], Count::bounded(is_real, 1));
        bus::RAM.send(b, [v(RES), ts(TS_RES0), v(OUT0), one.clone()], Count::bounded(v(WRITES), 1));
        bus::RAM.send(b, [v(RES) + one.clone(), ts(TS_RES1), v(OUT1), one], Count::bounded(v(WRITES), 1));
    }
}

/// The declared log-height: the runs plus one padding row, and at least the provider region,
/// floored — with `0` the "no reduce table" value (the keccak pattern, `machine::chips`).
pub fn reduce_log_height(rows: usize, provider: usize) -> u8 {
    if rows == 0 {
        return 0;
    }
    super::pad_height((rows + 1).max(provider), 1 << MIN_LOG_HEIGHT).trailing_zeros() as u8
}

/// The `REDUCE` events, in execution order.
pub fn reduce_events(events: &[Event]) -> Vec<&Event> {
    events.iter().filter(|e| e.reduce.is_some()).collect()
}

/// One chip row per reduced column.
pub fn reduce_rows(events: &[&Event]) -> usize {
    events.iter().map(|e| e.reduce.unwrap().len as usize).sum()
}

/// The runs in execution order (a chain's entries are consecutive dispatches, so adjacent), the
/// provider region's multiplicities, and all-zero padding.
pub fn reduce_trace(layout: &[ReduceEntry], events: &[&Event], height: usize) -> RowMajorMatrix<F> {
    let n_rows = reduce_rows(events);
    assert!(n_rows < height && layout.len() <= height, "reduce table: {n_rows} rows, {} layout entries, height {height}", layout.len());
    let mut v = F::zero_vec(height * WIDTH);
    let mut row = 0usize;
    for e in events {
        let ev = e.reduce.unwrap();
        let le = layout[ev.entry as usize];
        let (mut acc, mut apow) = (ev.acc_in, ev.apow_in);
        // The event's log: the key's two reads, the alpha's two at a chain start, then three per column.
        let mut reads = e.mem.iter().skip(if le.chain_start { 4 } else { 2 });
        let row_end = le.row + le.len as u64 - 1;
        for k in 0..le.len as u64 {
            let r = &mut v[row * WIDTH..(row + 1) * WIDTH];
            let (first, last) = (k == 0, k == le.len as u64 - 1);
            r[IS_REAL] = F::ONE;
            r[IS_FIRST] = F::from_bool(first);
            r[IS_LAST] = F::from_bool(last);
            r[CLK] = F::from_u64(e.clk as u64);
            r[ENTRY] = F::from_u64(ev.entry as u64);
            r[ADDR_V] = F::from_u64(le.vals + 2 * k);
            r[ADDR_R] = F::from_u64(le.row + k);
            r[ROW_END] = F::from_u64(row_end);
            if !last {
                r[END_INV] = (F::from_u64(le.row + k) - F::from_u64(row_end)).inverse();
            }
            r[KEY] = F::from_u64(le.key);
            r[ALPHA_ADDR] = F::from_u64(le.alpha);
            r[RES] = F::from_u64(le.res);
            r[CHAIN_START] = F::from_bool(le.chain_start);
            r[CARRY] = F::from_bool(le.carry);
            r[ACC0] = acc[0];
            r[ACC1] = acc[1];
            r[APOW0] = apow[0];
            r[APOW1] = apow[1];
            r[INV0] = ev.inv[0];
            r[INV1] = ev.inv[1];
            r[ALPHA0] = ev.alpha[0];
            r[ALPHA1] = ev.alpha[1];
            let pz = [reads.next().expect("pz0").value, reads.next().expect("pz1").value];
            let px = reads.next().expect("px").value;
            r[PZ0] = pz[0];
            r[PZ1] = pz[1];
            r[PX] = px;
            let (t0, t1) = ext_mul(apow, [pz[0] - px, pz[1]]);
            let (t2_0, t2_1) = ext_mul([t0, t1], ev.inv);
            acc = [acc[0] + t2_0, acc[1] + t2_1];
            apow = ext_mul(apow, ev.alpha).into();
            if last {
                r[OUT0] = acc[0];
                r[OUT1] = acc[1];
                r[WRITES] = F::from_bool(!le.carry);
            }
            r[READ_ALPHA] = F::from_bool(first && le.chain_start);
            row += 1;
        }
        debug_assert_eq!((acc, apow), (ev.acc_out, ev.apow_out), "the trace recomputes the emulator's chain");
    }
    for e in events {
        v[e.reduce.unwrap().entry as usize * WIDTH + MULT] += F::ONE;
    }
    RowMajorMatrix::new(v, WIDTH)
}

/// `(a0 + a1·X)·(b0 + b1·X)`, `X² = 7` — the same extension multiplication the cpu uses.
fn ext_mul(a: [F; 2], b: [F; 2]) -> (F, F) {
    let seven = F::from_u64(7);
    (a[0] * b[0] + seven * a[1] * b[1], a[0] * b[1] + a[1] * b[0])
}
