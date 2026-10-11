//! MODQ (private multisig phase 3): the chip standalone — the modq table, a `MODQ` asker in place
//! of the cpu, a permissive `MEMORY` twin in place of the memory table (it receives whatever it is
//! given, with no order or read-after-write rule) and the range table. Task 3's harness, moved
//! here and generalised so `tests/cheating.rs` can switch one `Defence` off
//! (`ModqAirWithout(off)`); `tests/modq.rs` uses `modq_run::run_raw` (real `ModqAir`). Compiled only with `cheating`.
use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder};
use p3_batch_stark::{prove_batch, verify_batch, ProverData, StarkInstance};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;
use rand_zkvm::machine::{make_config, FriProfile, VerifyError};
use rand_zkvm::tables::modq::{col, range_counts_without, Defence, Forged, ModqAir, ModqAirWithout, ModqEvent};
use rand_zkvm::tables::range::{range_trace, RangeAir, RangeCounts};
use rand_zkvm::tables::F;

#[allow(unused_imports)]
pub use super::modq_run::{events, twin_of, Asker, MemoryTwin};

#[derive(Clone)]
pub enum T { S(ModqAirWithout, usize), A(Asker), M(MemoryTwin), R(RangeAir) }
impl<Fld: Field> BaseAir<Fld> for T {
    fn width(&self) -> usize {
        match self {
            T::S(a, _) => <ModqAirWithout as BaseAir<Fld>>::width(a),
            T::A(a) => <Asker as BaseAir<Fld>>::width(a),
            T::M(a) => <MemoryTwin as BaseAir<Fld>>::width(a),
            T::R(a) => <RangeAir as BaseAir<Fld>>::width(a),
        }
    }
    fn preprocessed_width(&self) -> usize {
        match self {
            T::S(a, _) => <ModqAirWithout as BaseAir<Fld>>::preprocessed_width(a),
            T::R(a) => <RangeAir as BaseAir<Fld>>::preprocessed_width(a),
            _ => 0,
        }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> {
        match self {
            T::S(_, h) => Some(ModqAir::preprocessed_trace_at(*h)),
            T::R(a) => <RangeAir as BaseAir<Fld>>::preprocessed_trace(a),
            _ => None,
        }
    }
}
impl<AB: AirBuilder + PermutationAirBuilder + InteractionBuilder> Air<AB> for T where AB::F: Field {
    fn eval(&self, b: &mut AB) {
        match self { T::S(a, _) => a.eval(b), T::A(a) => a.eval(b), T::M(a) => a.eval(b), T::R(a) => a.eval(b) }
    }
}

/// Prove and verify the four-table batch: the modq `trace` under `ModqAirWithout(off)`, an asker
/// row per `(clk, base, a1)` in `asks`, the memory `twin` and the range table of `range`.
pub fn run_raw(trace: &RowMajorMatrix<F>, range: &RangeCounts, asks: &[(u32, u32, u32)], twin: &RowMajorMatrix<F>, off: Option<Defence>) -> Result<(), VerifyError> {
    let mut asker = F::zero_vec(asks.len().next_power_of_two().max(4) * 4);
    for (i, &(clk, base, a1)) in asks.iter().enumerate() {
        asker[i * 4..i * 4 + 4].copy_from_slice(&[F::ONE, F::from_u32(clk), F::from_u32(base), F::from_u32(a1)]);
    }
    let asker = RowMajorMatrix::new(asker, 4);
    let range_t = range_trace(range);
    let airs = vec![T::S(ModqAirWithout(off), trace.values.len() / col::WIDTH), T::A(Asker), T::M(MemoryTwin), T::R(RangeAir)];
    let instances = vec![
        StarkInstance { air: &airs[0], trace, public_values: vec![] },
        StarkInstance { air: &airs[1], trace: &asker, public_values: vec![] },
        StarkInstance { air: &airs[2], trace: twin, public_values: vec![] },
        StarkInstance { air: &airs[3], trace: &range_t, public_values: vec![] },
    ];
    let config = make_config(FriProfile::Test);
    let pd = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &pd);
    verify_batch(&config, &airs, &proof, &[vec![], vec![], vec![], vec![]], &pd.common).map_err(|e| VerifyError::Batch(format!("{e:?}")))
}

/// A forged block standalone with `off` switched off: the cpu asks for each of `events`, the
/// twin holds exactly the forged block's accesses, and the range table holds the limbs rule 8
/// looks up under `off` (`range_counts_without`).
pub fn run(forged: &Forged, events: &[ModqEvent], off: Option<Defence>) -> Result<(), VerifyError> {
    let asks: Vec<(u32, u32, u32)> = events.iter().map(|e| (e.clk, e.base, e.a1)).collect();
    run_raw(&forged.trace, &range_counts_without(&forged.trace, off), &asks, &twin_of(&forged.accesses), off)
}
