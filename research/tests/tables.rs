use rand_zkvm::machine::{make_config, FriProfile};
use rand_zkvm::tables::byte::{byte_trace, ByteAir, ByteCounts};
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

/// A throwaway table that asks the byte table questions. main: [x, y, z, is_real]
#[derive(Clone)]
struct Asker;
impl<Fld> BaseAir<Fld> for Asker { fn width(&self) -> usize { 4 } }
impl<AB: AirBuilder + InteractionBuilder> Air<AB> for Asker where AB::F: p3_field::Field {
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let (x, y, z, r) = (m.current(0).unwrap(), m.current(1).unwrap(), m.current(2).unwrap(), m.current(3).unwrap());
        b.assert_bool(r);
        bus::RANGE8.lookup_key(b, [x.into()], Count::bounded(r.into(), 1));
        bus::AND8.lookup_key(b, [x.into(), y.into(), z.into()], Count::bounded(r.into(), 1));
    }
}

#[test]
fn byte_table_answers_range_and_and_lookups() {
    let config = make_config(FriProfile::Test);
    let mut counts = ByteCounts::default();
    let rows: Vec<(u32, u32)> = vec![(0xf0, 0x3c), (7, 7), (255, 0), (1, 2)];
    let mut asker = vec![F::ZERO; 16 * 4];
    for (i, (x, y)) in rows.iter().enumerate() {
        counts.range8(*x);
        counts.and8(*x, *y);
        asker[4 * i] = F::from_u32(*x);
        asker[4 * i + 1] = F::from_u32(*y);
        asker[4 * i + 2] = F::from_u32(x & y);
        asker[4 * i + 3] = F::ONE;
    }
    let asker_trace = RowMajorMatrix::new(asker, 4);
    let byte = byte_trace(&counts);
    // prove with a two-AIR enum local to the test
    #[derive(Clone)]
    enum T { Byte(ByteAir), Ask(Asker) }
    impl<Fld: p3_field::Field> BaseAir<Fld> for T {
        fn width(&self) -> usize { match self { T::Byte(a) => <ByteAir as BaseAir<Fld>>::width(a), T::Ask(a) => <Asker as BaseAir<Fld>>::width(a) } }
        fn preprocessed_width(&self) -> usize { match self { T::Byte(a) => <ByteAir as BaseAir<Fld>>::preprocessed_width(a), _ => 0 } }
        fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> { match self { T::Byte(a) => <ByteAir as BaseAir<Fld>>::preprocessed_trace(a), _ => None } }
    }
    impl<AB: AirBuilder + p3_air::PermutationAirBuilder + InteractionBuilder> Air<AB> for T where AB::F: p3_field::Field {
        fn eval(&self, b: &mut AB) { match self { T::Byte(a) => a.eval(b), T::Ask(a) => a.eval(b) } }
    }
    let airs = vec![T::Byte(ByteAir), T::Ask(Asker)];
    let instances = vec![
        StarkInstance { air: &airs[0], trace: &byte, public_values: vec![] },
        StarkInstance { air: &airs[1], trace: &asker_trace, public_values: vec![] },
    ];
    let pd = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &pd);
    verify_batch(&config, &airs, &proof, &[vec![], vec![]], &pd.common).unwrap();
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
