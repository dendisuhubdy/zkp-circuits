use rand_zkvm::machine::{make_config, FriProfile};
use rand_zkvm::tables::range::{self, range_trace, RangeAir, RangeCounts};
use rand_zkvm::tables::nibble::{self, nibble_trace, NibbleCounts};
use rand_zkvm::tables::bus;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_batch_stark::{prove_batch, verify_batch, ProverData, StarkInstance};
use p3_field::PrimeCharacteristicRing;
use p3_field::PrimeField64;
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use rand_zkvm::tables::F;
use rand_zkvm::isa::Instr;
use rand_zkvm::tables::program::{self, program_trace, ProgramAir};
use rand_zkvm::emulator::execute;
use rand_zkvm::guests;
use rand_zkvm::tables::memory::{self, memory_trace};
use rand_zkvm::tables::alu::{self, fill_row};
use rand_zkvm::emulator::AluEvent;
use rand_zkvm::isa::AluOp;

/// A throwaway table that asks both of the range table's questions. main: [x, r_range, s,
/// pw, r_pow2]. Two separate weighted lookups per row (rather than one column each for
/// RANGE8 and POW2) so a row can exercise either, both, or neither independently — the
/// fourth row here exercises RANGE8 only, since there are 4 range checks but only 3 pow2
/// checks to answer.
#[derive(Clone)]
struct RangeAsker;
impl<Fld> BaseAir<Fld> for RangeAsker { fn width(&self) -> usize { 5 } }
impl<AB: AirBuilder + InteractionBuilder> Air<AB> for RangeAsker where AB::F: p3_field::Field {
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let (x, rr, s, pw, rp) = (
            m.current(0).unwrap(), m.current(1).unwrap(), m.current(2).unwrap(), m.current(3).unwrap(), m.current(4).unwrap(),
        );
        b.assert_bool(rr);
        b.assert_bool(rp);
        bus::RANGE8.lookup_key(b, [x.into()], Count::bounded(rr.into(), 1));
        bus::POW2.lookup_key(b, [s.into(), pw.into()], Count::bounded(rp.into(), 1));
    }
}

#[test]
fn range_table_answers_range8_and_pow2_lookups() {
    let config = make_config(FriProfile::Test);
    let mut counts = RangeCounts::default();
    let xs = [0u32, 7, 255, 31];
    let pow2s = [(0u32, 1u32), (5, 32), (31, 1u32 << 31)];
    for x in xs { counts.range8(x); }
    for (s, _) in pow2s { counts.pow2(s); }
    let mut asker = vec![F::ZERO; 16 * 5];
    for (i, x) in xs.iter().enumerate() {
        asker[5 * i] = F::from_u32(*x);
        asker[5 * i + 1] = F::ONE;
        if let Some((s, pw)) = pow2s.get(i) {
            asker[5 * i + 2] = F::from_u32(*s);
            asker[5 * i + 3] = F::from_u32(*pw);
            asker[5 * i + 4] = F::ONE;
        }
    }
    let asker_trace = RowMajorMatrix::new(asker, 5);
    let range = range_trace(&counts);
    #[derive(Clone)]
    enum T { Range(RangeAir), Ask(RangeAsker) }
    impl<Fld: p3_field::Field> BaseAir<Fld> for T {
        fn width(&self) -> usize { match self { T::Range(a) => <RangeAir as BaseAir<Fld>>::width(a), T::Ask(a) => <RangeAsker as BaseAir<Fld>>::width(a) } }
        fn preprocessed_width(&self) -> usize { match self { T::Range(a) => <RangeAir as BaseAir<Fld>>::preprocessed_width(a), _ => 0 } }
        fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> { match self { T::Range(a) => <RangeAir as BaseAir<Fld>>::preprocessed_trace(a), _ => None } }
    }
    impl<AB: AirBuilder + p3_air::PermutationAirBuilder + InteractionBuilder> Air<AB> for T where AB::F: p3_field::Field {
        fn eval(&self, b: &mut AB) { match self { T::Range(a) => a.eval(b), T::Ask(a) => a.eval(b) } }
    }
    let airs = vec![T::Range(RangeAir), T::Ask(RangeAsker)];
    let instances = vec![
        StarkInstance { air: &airs[0], trace: &range, public_values: vec![] },
        StarkInstance { air: &airs[1], trace: &asker_trace, public_values: vec![] },
    ];
    let pd = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &pd);
    verify_batch(&config, &airs, &proof, &[vec![], vec![]], &pd.common).unwrap();
}

#[test]
fn bumping_a_range_pow2_multiplicity_on_a_non_pow2_row_is_rejected_directly() {
    // row_of(200,0) has a=200 ≥ 32, so is_pow2 is 0 there
    let counts = RangeCounts::default();
    let t = range_trace(&counts);
    assert_eq!(t.values[200 * range::col::WIDTH + range::col::M_POW2], F::ZERO);
}

#[test]
fn nibble_table_answers_and4_or4_xor4_lookups() {
    let mut counts = NibbleCounts::default();
    counts.and4(0xf, 0x3); counts.or4(0x5, 0xa); counts.xor4(0x1, 0x1);
    let t = nibble_trace(&counts);
    assert_eq!(t.values[nibble::row_of(0xf,0x3) * nibble::col::WIDTH + nibble::col::M_AND], F::ONE);
    assert_eq!(t.values[nibble::row_of(0x5,0xa) * nibble::col::WIDTH + nibble::col::M_OR], F::ONE);
    assert_eq!(t.values[nibble::row_of(0x1,0x1) * nibble::col::WIDTH + nibble::col::M_XOR], F::ONE);
}

#[test]
fn program_table_rows_are_decoded_instructions_and_fetch_counts() {
    let p = guests::fib(5);
    let air = ProgramAir { program: p.clone() };
    let pre: RowMajorMatrix<F> = <ProgramAir as BaseAir<F>>::preprocessed_trace(&air).unwrap();
    assert_eq!(pre.height(), air.height());
    assert_eq!(pre.height(), 16);
    // row 2 is the third instruction
    let d = Instr::decode(p.words[2]).unwrap().decoded().to_fields();
    let row: Vec<F> = pre.values[2 * program::pre::WIDTH..3 * program::pre::WIDTH].to_vec();
    assert_eq!(row[program::pre::PC], F::from_u32(8));
    for (i, f) in d.iter().enumerate() { assert_eq!(row[program::pre::FIELDS + i], F::from_u32(*f), "field {i}"); }
    assert_eq!(row[program::pre::VALID], F::ONE);
    let last = pre.height() - 1;
    assert_eq!(pre.values[last * program::pre::WIDTH + program::pre::VALID], F::ZERO);
    let e = execute(&p, &[], 10_000).unwrap();
    let t = program_trace(&p, &e.events);
    let total: u64 = t.values.iter().map(|x| x.as_canonical_u64()).sum();
    assert_eq!(total as usize, e.events.len(), "every cycle fetched exactly one row");
}

#[test]
fn memory_trace_is_sorted_and_consistent() {
    let p = guests::memcpy(4);
    let e = execute(&p, &[], 10_000).unwrap();
    let mut counts = RangeCounts::default();
    let t = memory_trace(&e.events, 1 << 12, &mut counts);
    let w = memory::col::WIDTH;
    let accesses: usize = e.events.iter().map(|c| c.accesses.len()).sum();
    let real: usize = (0..t.height()).filter(|r| t.values[r * w + memory::col::IS_REAL] == F::ONE).count();
    assert_eq!(real, accesses);
    let key = |r: usize| t.values[r * w + memory::col::SPACE].as_canonical_u64() << 30 | t.values[r * w + memory::col::ADDR].as_canonical_u64();
    let ts = |r: usize| t.values[r * w + memory::col::TS].as_canonical_u64();
    for r in 0..real - 1 {
        assert!((key(r), ts(r)) < (key(r + 1), ts(r + 1)), "row {r} not sorted");
        if key(r) == key(r + 1) && t.values[(r + 1) * w + memory::col::IS_WRITE] == F::ZERO {
            assert_eq!(t.values[r * w + memory::col::VALUE], t.values[(r + 1) * w + memory::col::VALUE], "read at row {} must see previous value", r + 1);
        }
    }
    // Δ limbs were counted: 4 range checks per real transition
    let total: u64 = counts.range.iter().sum();
    assert_eq!(total as usize, 4 * (real - 1));
}

#[test]
fn alu_rows_recompose_and_carry() {
    let mut range = RangeCounts::default();
    let mut nibble = NibbleCounts::default();
    let mut row = vec![F::ZERO; alu::col::WIDTH];
    fill_row(&mut row, &AluEvent { op: AluOp::Add, a: 0xffff_ffff, b: 1, c: 0 }, &mut range, &mut nibble);
    assert_eq!(row[alu::col::FLAG0 + AluOp::Add.code() as usize], F::ONE);
    assert_eq!(row[alu::col::C], F::ZERO);
    for i in 0..4 { assert_eq!(row[alu::col::CARRY0 + i], F::ONE, "carry {i}"); }
    let mut row = vec![F::ZERO; alu::col::WIDTH];
    fill_row(&mut row, &AluEvent { op: AluOp::Sra, a: 0x8000_0000, b: 4, c: 0xf800_0000 }, &mut range, &mut nibble);
    assert_eq!(row[alu::col::SA], F::ONE);
    assert_eq!(row[alu::col::SHH], F::ZERO); // b=4 < 16, so bit4 of b is 0
    assert_eq!(row[alu::col::PW], F::from_u32(16));
    // q = (~a) >> 4 = 0x07ff_ffff ; c = ~q
    assert_eq!(row[alu::col::Q0], F::from_u32(0xff));
    assert_eq!(row[alu::col::C0 + 3], F::from_u32(0xf8));
    let mut row = vec![F::ZERO; alu::col::WIDTH];
    fill_row(&mut row, &AluEvent { op: AluOp::Slt, a: 0xffff_ffff, b: 0, c: 1 }, &mut range, &mut nibble);
    assert_eq!((row[alu::col::SA], row[alu::col::SB], row[alu::col::CARRY0 + 3]), (F::ONE, F::ZERO, F::ZERO));
}

/// M2.4: `slt`/`sltu`/`eq` rows no longer RANGE8-check their `C0..3` limb, since
/// `(cmp+eq)*C*(C-1)=0` already forces `C ∈ {0,1}` directly — a stronger constraint
/// than a byte-range check, so the RANGE8 lookup on `C0..3` was redundant there.
/// Method: call `fill_row` directly (the exact code path that decides whether to
/// call `range.range8()` per limb) and sum the resulting `RangeCounts`.
#[test]
fn cmp_and_eq_rows_do_not_range_check_their_c_limb() {
    let mut range = RangeCounts::default();
    let mut nibble = NibbleCounts::default();
    // slt: A(4) + B(4) + S(4, cmp gate, unchanged) = 12, not 4(A)+4(B)+4(C)+4(S)=16.
    let mut row = vec![F::ZERO; alu::col::WIDTH];
    fill_row(&mut row, &AluEvent { op: AluOp::Slt, a: 3, b: 9, c: 1 }, &mut range, &mut nibble);
    assert_eq!(range.range.iter().sum::<u64>(), 12);

    // eq: A(4) + B(4) = 8, not 4(A)+4(B)+4(C)=12 (eq has no S/T/Q scratch limbs at all).
    let mut range = RangeCounts::default();
    let mut row = vec![F::ZERO; alu::col::WIDTH];
    fill_row(&mut row, &AluEvent { op: AluOp::Eq, a: 3, b: 3, c: 1 }, &mut range, &mut nibble);
    assert_eq!(range.range.iter().sum::<u64>(), 8);

    // sltu: A(4) + B(4) + S(4, cmp gate) = 12, C dropped same as slt.
    let mut range = RangeCounts::default();
    let mut row = vec![F::ZERO; alu::col::WIDTH];
    fill_row(&mut row, &AluEvent { op: AluOp::Sltu, a: 3, b: 9, c: 1 }, &mut range, &mut nibble);
    assert_eq!(range.range.iter().sum::<u64>(), 12);
}

/// M2.4: bitwise rows no longer RANGE8-check ANY of `A0..3`/`B0..3`/`C0..3` — the
/// nibble lookups (`bitwise_high_nibble`) already bind all twelve limbs on these
/// rows (verified: each limb's low nibble gets a real AND4/OR4/XOR4 lookup, and its
/// derived high nibble gets a second one, so both halves — hence the whole byte —
/// are forced into range by the nibble table alone). Before M2.4 these rows paid
/// RANGE8 (12) *and* nibble (8) for the same bytes; after, only the nibble lookups
/// remain: `add/sub`'s 12 RANGE8 lookups collapse to 0, leaving just the 8 nibble
/// lookups already present since Task 3.
#[test]
fn bitwise_rows_no_longer_range_check_their_byte_limbs() {
    let mut range = RangeCounts::default();
    let mut nibble = NibbleCounts::default();
    let mut row = vec![F::ZERO; alu::col::WIDTH];
    fill_row(&mut row, &AluEvent { op: AluOp::And, a: 0x12, b: 0x34, c: 0x12 & 0x34 }, &mut range, &mut nibble);
    assert_eq!(range.range.iter().sum::<u64>(), 0, "no RANGE8 lookups on a bitwise row");
    let total_nibble: u64 = nibble.and.iter().sum::<u64>() + nibble.or.iter().sum::<u64>() + nibble.xor.iter().sum::<u64>();
    assert_eq!(total_nibble, 8, "4 limbs x {{lo, hi}} = 8 nibble lookups, unchanged from Task 3");
}

#[test]
#[should_panic(expected = "does not match")]
fn alu_fill_rejects_wrong_result() {
    let mut range = RangeCounts::default();
    let mut nibble = NibbleCounts::default();
    let mut row = vec![F::ZERO; alu::col::WIDTH];
    fill_row(&mut row, &AluEvent { op: AluOp::Add, a: 1, b: 1, c: 3 }, &mut range, &mut nibble);
}

use rand_zkvm::tables::cpu::{self, cpu_trace, public_values};

#[test]
fn cpu_trace_mirrors_events_and_pads() {
    let p = guests::fib(3);
    let e = execute(&p, &[], 10_000).unwrap();
    let mut range = RangeCounts::default();
    let mut nibble = NibbleCounts::default();
    let t = cpu_trace(&e.events, 64, &mut range, &mut nibble);
    let w = cpu::col::WIDTH;
    assert_eq!(t.height(), 64);
    for (i, ev) in e.events.iter().enumerate() {
        let r = &t.values[i * w..(i + 1) * w];
        assert_eq!(r[cpu::col::CLK], F::from_u32(ev.clk));
        assert_eq!(r[cpu::col::PC], F::from_u32(ev.pc));
        assert_eq!(r[cpu::col::NEXT_PC], F::from_u32(ev.next_pc));
        assert_eq!(r[cpu::col::IS_REAL], F::ONE);
        let d = ev.dec.to_fields();
        for k in 0..23 { assert_eq!(r[cpu::col::DEC0 + k], F::from_u32(d[k])); }
        assert_eq!((r[cpu::col::A], r[cpu::col::B], r[cpu::col::C]), (F::from_u32(ev.a), F::from_u32(ev.b), F::from_u32(ev.c)));
    }
    let last_real = e.events.len() - 1;
    assert_eq!(t.values[last_real * w + cpu::col::SYS_HALT], F::ONE);
    let write_row = e.events.iter().position(|ev| matches!(ev.sys, Some(rand_zkvm::emulator::Syscall::WriteOutput { .. }))).unwrap();
    assert_eq!(t.values[write_row * w + cpu::col::OUT_SEL0], F::ONE);
    // Padding rows are all-zero except the `written` accumulators, which must carry the
    // final per-slot write counts through to the last row for the unwritten-slot constraint.
    let pad = &t.values[(last_real + 1) * w..(last_real + 2) * w];
    for (i, x) in pad.iter().enumerate() {
        let expected = if i == cpu::col::WRITTEN0 { F::ONE } else { F::ZERO };
        assert_eq!(*x, expected, "padding column {i}");
    }
    let last = &t.values[(t.height() - 1) * w..t.height() * w];
    assert_eq!(last[cpu::col::WRITTEN0], F::ONE, "slot 0 was written");
    for k in 1..8 { assert_eq!(last[cpu::col::WRITTEN0 + k], F::ZERO, "slot {k} was not"); }
    let pv = public_values(0, 10, &e.outputs);
    assert_eq!(pv.len(), cpu::pv::NUM);
    assert_eq!(pv[cpu::pv::OUT0], F::from_u32(2));
}

#[test]
fn cpu_trace_limbs_and_counts_every_load_store_address() {
    let p = guests::memcpy(4);
    let e = execute(&p, &[], 10_000).unwrap();
    let mut range = RangeCounts::default();
    let mut nibble = NibbleCounts::default();
    let t = cpu_trace(&e.events, 1 << 10, &mut range, &mut nibble);
    let w = cpu::col::WIDTH;
    let is_mem = |i: usize| { let d = &e.events[i].dec; d.is_lb + d.is_lh + d.is_lw + d.is_sb + d.is_sh + d.is_sw == 1 };
    let is_store = |i: usize| { let d = &e.events[i].dec; d.is_sb + d.is_sh + d.is_sw == 1 };
    let mem_rows: Vec<usize> = (0..e.events.len()).filter(|i| is_mem(*i)).collect();
    let n_stores = mem_rows.iter().filter(|i| is_store(**i)).count();
    assert!(!mem_rows.is_empty(), "memcpy loads and stores");
    for i in &mem_rows {
        let addr = e.events[*i].mem_addr;
        assert!(addr < 1 << 30, "row {i}: mem_addr must fit the AND4 bound");
        for k in 0..4 {
            assert_eq!(t.values[i * w + cpu::col::MA0 + k], F::from_u32((addr >> (8 * k)) & 0xff), "row {i} limb {k}");
        }
    }
    // Every load/store row RANGE8-checks its MA0..3 address limbs and its W0..3 word limbs
    // (8), plus the store's own RB0..3 rs2 limbs (4 more) on store rows only; memcpy uses
    // only LW/SW, so every load/store row also pays the same two AND4 lookups (the
    // low-nibble dummy range check and the MA3_HI-against-0xC extraction) — sign-extraction
    // AND4 lookups only fire on LB/LH rows, which memcpy never uses.
    assert_eq!(range.range.iter().sum::<u64>() as usize, 8 * mem_rows.len() + 4 * n_stores);
    let nibble_total: u64 = nibble.and.iter().sum();
    assert_eq!(nibble_total as usize, 2 * mem_rows.len());
}

/// M2.6 mul family: `mul`/`mulhu` pay the standard 12 (A0..3/B0..3/C0..3, `g_ab`/`g_c` both
/// include `is_mul`) plus 4 (`T0..3`, LO's own limbs, unconditional on every mul-family row
/// — this is the fix that pins `CARRY` even when the row doesn't select `LO` as its output,
/// see the `alu` module doc comment) plus 3 (`S1..3`, `CARRY`'s own limbs) = 19, no AND4
/// (neither needs a sign bit). `mulh` additionally extracts both `SA` and `SB` (dummy +
/// real each = 4 AND4); `mulhsu` extracts only `SA` (2 AND4, since it treats `B` as
/// unsigned) — this is the exact per-op lookup-gate accounting the M2.4 table established
/// for the RV32I ops, extended to M2.6.
#[test]
fn mul_family_lookup_counts_per_op() {
    let cases = [
        (AluOp::Mul, 0xdead_beefu32, 0x1234_5678u32, 19usize, 0usize),
        (AluOp::Mulhu, 0xffff_ffffu32, 0xffff_ffffu32, 19, 0),
        (AluOp::Mulh, (-2i32) as u32, (-3i32) as u32, 19, 4),
        (AluOp::Mulhsu, (-1i32) as u32, 7u32, 19, 2),
    ];
    for (op, a, b, want_range, want_nibble) in cases {
        let mut range = RangeCounts::default();
        let mut nibble = NibbleCounts::default();
        let c = op.eval(a, b);
        let mut row = vec![F::ZERO; alu::col::WIDTH];
        fill_row(&mut row, &AluEvent { op, a, b, c }, &mut range, &mut nibble);
        assert_eq!(range.range.iter().sum::<u64>() as usize, want_range, "{op:?} RANGE8 count");
        let nibble_total: u64 = nibble.and.iter().sum::<u64>() + nibble.or.iter().sum::<u64>() + nibble.xor.iter().sum::<u64>();
        assert_eq!(nibble_total as usize, want_nibble, "{op:?} AND4/OR4/XOR4 count");
    }
}

/// M2.6 div family: every op pays the standard 12 (A0..3/B0..3/C0..3) plus 8 (`Q0..3`/
/// `S0..3`, the quotient/remainder core limbs, unconditional on every `is_div` row
/// regardless of `DIVZ`) = 20, plus (only when `B != 0`, `normal` gated) 4 more for the
/// `R < |B|` diff limbs = 24. `div`/`rem` additionally extract both `SA` and `SB` (4 AND4);
/// `divu`/`remu` extract neither.
#[test]
fn div_family_lookup_counts_per_op() {
    // B != 0: the R < |B| diff-limb check fires.
    let cases = [
        (AluOp::Divu, 10u32, 3u32, 24usize, 0usize),
        (AluOp::Remu, 10u32, 3u32, 24, 0),
        (AluOp::Div, (-7i32) as u32, 2u32, 24, 4),
        (AluOp::Rem, (-7i32) as u32, 2u32, 24, 4),
    ];
    for (op, a, b, want_range, want_nibble) in cases {
        let mut range = RangeCounts::default();
        let mut nibble = NibbleCounts::default();
        let c = op.eval(a, b);
        let mut row = vec![F::ZERO; alu::col::WIDTH];
        fill_row(&mut row, &AluEvent { op, a, b, c }, &mut range, &mut nibble);
        assert_eq!(range.range.iter().sum::<u64>() as usize, want_range, "{op:?} RANGE8 count (B != 0)");
        let nibble_total: u64 = nibble.and.iter().sum::<u64>() + nibble.or.iter().sum::<u64>() + nibble.xor.iter().sum::<u64>();
        assert_eq!(nibble_total as usize, want_nibble, "{op:?} AND4 count (B != 0)");
    }
    // B == 0 (DIVZ): the R < |B| diff-limb check does not fire (nothing to compare
    // against), dropping 4 RANGE8 lookups relative to the B != 0 case above.
    let divz_cases = [
        (AluOp::Divu, 10u32, 0u32, 20usize, 0usize),
        (AluOp::Remu, 10u32, 0u32, 20, 0),
        (AluOp::Div, (-7i32) as u32, 0u32, 20, 4),
        (AluOp::Rem, (-7i32) as u32, 0u32, 20, 4),
    ];
    for (op, a, b, want_range, want_nibble) in divz_cases {
        let mut range = RangeCounts::default();
        let mut nibble = NibbleCounts::default();
        let c = op.eval(a, b);
        let mut row = vec![F::ZERO; alu::col::WIDTH];
        fill_row(&mut row, &AluEvent { op, a, b, c }, &mut range, &mut nibble);
        assert_eq!(range.range.iter().sum::<u64>() as usize, want_range, "{op:?} RANGE8 count (B == 0)");
        let nibble_total: u64 = nibble.and.iter().sum::<u64>() + nibble.or.iter().sum::<u64>() + nibble.xor.iter().sum::<u64>();
        assert_eq!(nibble_total as usize, want_nibble, "{op:?} AND4 count (B == 0)");
    }
}

/// Pins each table's *symbolic* max constraint degree — the number that determines how many
/// FRI quotient chunks its instance needs (`log2_ceil(max_degree + 1 - 1)` under this
/// machine's `is_zk = 1` hiding PCS), against `p3_batch_stark`'s ceiling of `1 << log_blowup =
/// 8` chunks (`generic_config`'s `log_blowup: 3`, i.e. `log2_ceil(constraint_degree - 1) <=
/// 3`, i.e. `max_degree <= 8`).
///
/// `rand_zkvm::machine::max_constraint_degrees` runs the *exact* computation
/// `ProverData::from_airs_and_degrees` (hence `Machine::verifier_key`) performs to size each
/// instance's quotient — `p3_batch_stark::symbolic::get_max_constraint_degree` against the
/// real, same-bus-packed lookup contexts for that `(program, tier)` — so this test is pinning
/// what actually ships, not a hand-recount. No proving: `ProverData::from_airs_and_degrees`
/// only commits the preprocessed columns and walks the symbolic constraint tree: sub-second.
///
/// Chip order is `machine::chips()`'s: program, cpu, memory, alu, range, nibble.
///
/// If any of these numbers moves, re-measure (this test will fail with the new number) and:
/// - update the assertion and its comment below,
/// - update `docs/02-tables-and-buses.md`'s "max constraint degree" line,
/// - if a degree now exceeds 8, `log_blowup` (or the AIR) must change — 8 is this config's
///   hard ceiling, not a soft target.
#[test]
fn alu_max_constraint_degree_is_pinned() {
    use rand_zkvm::machine::{max_constraint_degrees, Tier};
    let p = guests::fib(5);
    // Tier-invariant: no table here uses periodic columns, so the symbolic degree doesn't
    // depend on trace height — any tier gives the same numbers. `Tier(10)` (the smallest) is
    // used only because `max_constraint_degrees` needs one to size the ALU/CPU/memory traces.
    let degrees = max_constraint_degrees(&p, Tier(10));
    assert_eq!(degrees.len(), 6, "one degree per chip in machine::chips() order");

    // program: preprocessed-only chip. Its one main-AIR constraint is the padding invariant
    // `(1 - valid) * mult == 0` (AGENTS.md's invariant 2) — degree 2. The packed PROGRAM-bus
    // lookup fraction-pin doesn't exceed that either.
    assert_eq!(degrees[0], 2, "program table max constraint degree");

    // cpu: measured max is 8 — but (checked via get_symbolic_constraints directly) it comes
    // from the *packed* lookup fraction-pins (the batch-stark same-bus folding that groups
    // several of CPU's outgoing bus messages together up to the quotient-chunk-preserving
    // budget), not from CPU's own row logic: CPU's most complex single AIR constraint is only
    // degree 6. Still exactly at this config's degree-8 ceiling, same as ALU.
    assert_eq!(degrees[1], 8, "cpu table max constraint degree");

    // memory: measured max is 4, on both the main-AIR side and the packed lookups — comfortably
    // under the degree-8 ceiling (log_chunks = 2, half the budget ALU/CPU spend).
    assert_eq!(degrees[2], 4, "memory table max constraint degree");

    // alu: measured max is 8 — the M2.6 `div` sign-fix identity (reconstructing the true
    // remainder sign from the flipped/unflipped RANGE8-checked byte limbs and the divisor's
    // sign bit) is this AIR's single degree-8 constraint, one shy of this config's degree-9
    // ceiling (`log_blowup = 3` => `constraint_degree <= 9` with `is_zk = 1` => `max_degree <=
    // 8`). See `src/tables/alu.rs`'s div comments for the identity itself.
    assert_eq!(degrees[3], 8, "alu table max constraint degree");

    // range: single preprocessed-answering chip; its one main-AIR constraint and its packed
    // RANGE8/POW2 lookup fraction-pins all sit at degree 2.
    assert_eq!(degrees[4], 2, "range table max constraint degree");

    // nibble: no main-AIR constraints at all (it has no row-level validity marker of its own —
    // AGENTS.md's cheating-tests note; `LOOKUP_BALANCE_PANIC` is what catches an unpaid
    // multiplicity here). Its packed AND4/OR4/XOR4 lookup fraction-pins are degree 2.
    assert_eq!(degrees[5], 2, "nibble table max constraint degree");
}
