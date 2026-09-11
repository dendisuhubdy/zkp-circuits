//! M4.1: the `input` witness table — one row per committed private-input word, providing
//! `(IDX, WORD)` on `INPUT_WORD`. Mirrors `tables::program`'s `(PC, WORD)`/`PROGRAM_WORD`
//! shape exactly, with one difference `PROGRAM_WORD` never needed: `INPUT_WORD` has *two*
//! consumers (the cpu table's `IS_INDIGEST` digest rows, and its `SYS_READ` rows), so a row's
//! provided count is `IS_REAL * (1 + MULT_READ)` — the mandatory 1 the digest always claims,
//! plus however many times the guest actually reads that index (`MULT_READ`, a free but
//! LogUp-balance-checked witness value). Any real row the digest does not cover (an honest
//! table always has real rows exactly `{0, .., n_in-1}`, matching what the digest demands —
//! see below) supplies an unclaimable extra "1" that can never balance, which is what forces
//! the real-row count to equal `n_in` exactly, the same set-equality argument
//! `docs/02-tables-and-buses.md`'s "`hc` binds the whole executable program" section makes
//! for `program`'s `MULT_WORD = VALID`.
use super::{bus, F};
use crate::emulator::{CycleEvent, Syscall};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

pub mod col {
    pub const IDX: usize = 0;
    pub const WORD: usize = 1;
    pub const IS_REAL: usize = 2;
    /// How many times `SYS_READ` actually consumes this row's `(IDX, WORD)`, beyond the one
    /// mandatory copy the `IS_INDIGEST` digest rows always claim. A free witness value, but
    /// pinned to reality by the `INPUT_WORD` bus balance: if it disagrees with the true read
    /// count, the SYS_READ side's demand and this row's supply stop matching.
    pub const MULT_READ: usize = 3;
    pub const WIDTH: usize = 4;
}
use col::*;

pub const MIN_HEIGHT: usize = 4;
pub const MIN_LOG_HEIGHT: u8 = 2; // 1 << 2 == MIN_HEIGHT
/// Ceiling on the declared (proof-carried) input-table log-height — 2^20 rows is a million
/// private-input words, comfortably past any guest this crate runs; mirrors
/// `tables::program::MAX_LOG_HEIGHT`'s role exactly, one size smaller since private inputs
/// are typically far shorter than programs.
pub const MAX_LOG_HEIGHT: u8 = 20;

/// Same "+1 padding row, floor at MIN_HEIGHT" rule as `tables::program::program_log_height`.
pub fn input_log_height(n: usize) -> u8 {
    super::pad_height(n + 1, MIN_HEIGHT).trailing_zeros() as u8
}

#[derive(Clone, Copy, Debug, Default)]
pub struct InputAir;

impl<Fld> BaseAir<Fld> for InputAir {
    fn width(&self) -> usize { WIDTH }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for InputAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let n = |i: usize| -> AB::Expr { m.next(i).unwrap().into() };
        let one = AB::Expr::ONE;

        b.assert_bool(v(IS_REAL));
        // Real rows form a prefix — once IS_REAL drops to 0 it never returns, so the real-row
        // set is always exactly {0, .., realCount-1} for some realCount, never a scattered set.
        b.when_transition().assert_zero((one.clone() - v(IS_REAL)) * n(IS_REAL));
        // IDX = row index: 0 at row 0, +1 every row (including through padding — harmless,
        // nothing reads a padding row's IDX since its count is forced to 0 below). Unlike
        // `program`'s PC (which needs an external `base_pc` anchor), input indices always
        // start at 0 by definition, so no separate "no aliasing without a trusted base" check
        // is needed beyond this.
        b.when_first_row().assert_zero(v(IDX));
        b.when_transition().assert_zero(n(IDX) - v(IDX) - one.clone());
        // AGENTS.md invariant 1: pin the message columns on padding rows too.
        b.assert_zero((one.clone() - v(IS_REAL)) * v(WORD));
        // AGENTS.md invariant 2: MULT_READ forced to 0 on padding rows explicitly — the total
        // provided count below already zeroes out via the IS_REAL factor regardless of
        // MULT_READ's value, but a stray MULT_READ on a padding row is exactly the kind of
        // "unconstrained column nothing currently reads" AGENTS.md's ALU lesson warns about;
        // this local pin is also what makes cheating test (e) (below) a real rejection rather
        // than a no-op tamper.
        b.assert_zero((one.clone() - v(IS_REAL)) * v(MULT_READ));

        let count = v(IS_REAL) * (one + v(MULT_READ));
        bus::INPUT_WORD.table_entry(b, [v(IDX), v(WORD)], count);
    }
}

/// How many times each committed index is actually consumed by a `READ_INPUT` — the honest
/// `MULT_READ` values `input_trace` needs. `idx` is always `< n` for an honest execution
/// (`emulator::execute` already errors `ExecError::InputIndex` otherwise), so this never
/// indexes out of bounds on a witness that got this far.
pub fn read_counts(n: usize, events: &[CycleEvent]) -> Vec<u32> {
    let mut counts = vec![0u32; n];
    for e in events {
        if let Some(Syscall::ReadInput { idx, .. }) = e.sys {
            counts[idx as usize] += 1;
        }
    }
    counts
}

pub fn input_trace(inputs: &[u32], read_counts: &[u32], height: usize) -> RowMajorMatrix<F> {
    assert!(inputs.len() <= height, "input table needs {} rows, height {height}", inputs.len());
    assert_eq!(inputs.len(), read_counts.len());
    let mut v = F::zero_vec(height * WIDTH);
    for (i, (&w, &rc)) in inputs.iter().zip(read_counts).enumerate() {
        let r = &mut v[i * WIDTH..(i + 1) * WIDTH];
        r[IDX] = F::from_u32(i as u32);
        r[WORD] = F::from_u32(w);
        r[IS_REAL] = F::ONE;
        r[MULT_READ] = F::from_u32(rc);
    }
    for i in inputs.len()..height {
        v[i * WIDTH + IDX] = F::from_u32(i as u32);
    }
    RowMajorMatrix::new(v, WIDTH)
}
