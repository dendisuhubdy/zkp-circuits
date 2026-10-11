//! The MODQ forgery suite (private multisig phase 3): each forgery accepted with only its defence
//! off. Needs the `cheating` feature (forge hooks); split out of `cheating.rs`, which the fullnode
//! vendors and must build without that feature.
use rand_zkvm::emulator::execute;
use rand_zkvm::machine::{build_traces_salted, FriProfile, Machine, Tier};

mod common;
use common::rejects;

// ---- MODQ (private multisig phase 3): each forgery accepted with only its defence off ----------
// Pre-flight ruling 1 (phase 4's `d95aa5e` method). Each AIR-level forgery is built by
// `tables::modq::forge_block`, consistent everywhere but its lie: `K`/`D` recomputed, a
// transform's later stages and the block's memory writes re-derived, the range counts and memory
// accesses read back off the forged trace (`machine::build_traces_forged` rebuilds the machine's
// range and memory tables from them). `ModqAirWithout(Some(d))` switches exactly one constraint
// group off; it is a `#[doc(hidden)]` type `chips()` never builds.

use rand_zkvm::modq::Op;
use rand_zkvm::tables::modq::{forge_block, modq_log_height, Defence, Lie};

const NTT0: u32 = 0;
const INTT1: u32 = 1 | 1 << 8;
const DOT_8_0_4: u32 = 2 | 8 << 8 | 4 << 24;
const MSUB_0_8_4: u32 = 3 | 8 << 16 | 4 << 24;

/// Each MODQ cheating test peaks at ~5.4–5.9 GB RSS (tier-14 machine proof plus the standalone
/// harness; `/usr/bin/time -l`, one thread). Under libtest's default parallelism (one thread per
/// core) the file would hold ~16 of them at once and exhaust a 48 GB host, so every MODQ test
/// first takes one of `MODQ_SLOTS` permits: at most three run together, whatever `--test-threads`.
const MODQ_SLOTS: usize = 3;
static MODQ_PERMITS: std::sync::Mutex<usize> = std::sync::Mutex::new(0);
static MODQ_FREED: std::sync::Condvar = std::sync::Condvar::new();

struct ModqPermit;
impl Drop for ModqPermit {
    fn drop(&mut self) {
        *MODQ_PERMITS.lock().unwrap_or_else(|e| e.into_inner()) -= 1;
        MODQ_FREED.notify_one();
    }
}
fn modq_permit() -> ModqPermit {
    let mut held = MODQ_PERMITS.lock().unwrap_or_else(|e| e.into_inner());
    while *held >= MODQ_SLOTS { held = MODQ_FREED.wait(held).unwrap_or_else(|e| e.into_inner()); }
    *held += 1;
    ModqPermit
}

fn modq_run(calls: &[u32], unchecked: bool) -> (rand_zkvm::isa::Program, rand_zkvm::emulator::Execution) {
    let p = common::modq_program(calls);
    let e = if unchecked { rand_zkvm::emulator::execute_unchecked_modq(&p, &[], &[], 1 << 16) } else { execute(&p, &[], &[], 1 << 16) };
    (p, e.unwrap())
}

fn machine_rejects(p: &rand_zkvm::isa::Program, e: &rand_zkvm::emulator::Execution, n_calls: usize, lie: Lie) -> bool {
    machine_outcome(p, e, n_calls, lie).0
}

/// `(rejected, outcome)`: whether the machine rejects the forged traces, and what it said.
fn machine_outcome(p: &rand_zkvm::isa::Program, e: &rand_zkvm::emulator::Execution, n_calls: usize, lie: Lie) -> (bool, String) {
    let m = Machine::new(FriProfile::Test);
    let limit = rand_zkvm::gas::gas_max_with_modq(Tier(14), 0, 0, modq_log_height(n_calls));
    let t = rand_zkvm::machine::build_traces_forged(p, &[], &[], [0u32; 4], e, Tier(14), limit, lie).unwrap();
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { let pr = m.prove_traces(p, &t, Tier(14)); m.verify(&p.digest(), &pr) }));
    let said = outcome(&r);
    eprintln!("{lie:?} in the machine: {said}");
    (rejects(|| r.unwrap_or_else(|e| std::panic::resume_unwind(e))), said)
}

/// Pre-flight ruling 1: accepted standalone with only `off` switched off, rejected with it on, and rejected by the machine.
fn off_accepts_on_rejects(calls: &[u32], unchecked: bool, lie: Lie, off: Defence) {
    let (p, e) = modq_run(calls, unchecked);
    let evs = common::modq_harness::events(&e);
    let forged = forge_block(&evs, modq_log_height(evs.len()), lie);
    let accepted = common::modq_harness::run(&forged, &evs, Some(off));
    eprintln!("{lie:?} with {off:?} off: {accepted:?}");
    assert!(accepted.is_ok(), "{lie:?} must be accepted with only {off:?} off");
    let on = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| common::modq_harness::run(&forged, &evs, None)));
    eprintln!("{lie:?} with {off:?} on: {}", outcome(&on));
    assert!(rejects(|| common::modq_harness::run(&forged, &evs, None)), "{lie:?} must be rejected with {off:?} on");
    assert!(machine_rejects(&p, &e, calls.len(), lie), "{lie:?} must be rejected by the machine");
}

/// Defences outside the modq AIR: the forgery passes the modq AIR with every defence on, and dies in the machine.
fn passes_the_chip_dies_in_the_machine(calls: &[u32], unchecked: bool, lie: Lie) {
    let (p, e) = modq_run(calls, unchecked);
    let evs = common::modq_harness::events(&e);
    let forged = forge_block(&evs, modq_log_height(evs.len()), lie);
    assert!(common::modq_harness::run(&forged, &evs, None).is_ok(), "{lie:?} passes the modq AIR alone");
    assert!(machine_rejects(&p, &e, calls.len(), lie), "{lie:?} must be rejected by the machine");
}

/// The report's "rejected, with the error" column: a verify error, or the constraint panic's head.
fn outcome(r: &std::thread::Result<Result<(), rand_zkvm::machine::VerifyError>>) -> String {
    match r {
        Ok(Ok(())) => "ACCEPTED".into(),
        Ok(Err(e)) => format!("{e:?}").chars().take(160).collect(),
        Err(p) => p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default().chars().take(160).collect(),
    }
}

#[test]
fn modq_honest_traces_pass_and_every_lie_changes_the_witness() {
    let _permit = modq_permit();
    let (p, e) = modq_run(&[NTT0, INTT1, DOT_8_0_4, MSUB_0_8_4], false);
    assert!(!machine_rejects(&p, &e, 4, Lie::None), "honest");
    let evs = common::modq_harness::events(&e);
    let honest = forge_block(&evs, 12, Lie::None).trace;
    for lie in [Lie::NonCanonicalO0 { block: 0, stage: 7 }, Lie::SwapUV { block: 0, stage: 3 }, Lie::ButterflyOutput { block: 0, stage: 3, delta: 1 },
                Lie::InputLimbCarry { block: 0 }, Lie::DotCarry { block: 2, coefficient: 17, k: 1, delta: 1 }, Lie::MsubBroadcast { block: 3, coefficient: 17, k: 2, delta: 1 },
                Lie::OpAs { block: 1, op: Op::Ntt }, Lie::NonCanonicalO1 { block: 0, stage: 7 }, Lie::ButterflyOutputO1 { block: 0, stage: 3, delta: 1 },
                Lie::InputLimbCarryV { block: 0 }, Lie::InputLimbCarryW { block: 2 }, Lie::DotStart { block: 2, coefficient: 17, delta: 1 }] {
        assert_ne!(forge_block(&evs, 12, lie).trace.values, honest.values, "{lie:?} must change the witness");
    }
}

#[test] fn modq_non_canonical_output_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT0], false, Lie::NonCanonicalO0 { block: 0, stage: 7 }, Defence::CanonicalO0); }
#[test] fn modq_non_canonical_o1_output_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT0], false, Lie::NonCanonicalO1 { block: 0, stage: 7 }, Defence::CanonicalO1); }
#[test] fn modq_wire_value_swap_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT0], false, Lie::SwapUV { block: 0, stage: 3 }, Defence::Wire); }
#[test] fn modq_forged_butterfly_output_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT0], false, Lie::ButterflyOutput { block: 0, stage: 3, delta: 1 }, Defence::OutputIdentityO0); }
#[test] fn modq_forged_butterfly_o1_output_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT0], false, Lie::ButterflyOutputO1 { block: 0, stage: 3, delta: 1 }, Defence::OutputIdentityO1); }
#[test] fn modq_input_limb_out_of_range_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT0], false, Lie::InputLimbCarry { block: 0 }, Defence::InputRangeU); }
#[test] fn modq_v_limb_out_of_range_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT0], false, Lie::InputLimbCarryV { block: 0 }, Defence::InputRangeV); }
#[test] fn modq_w_limb_out_of_range_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[DOT_8_0_4], false, Lie::InputLimbCarryW { block: 0 }, Defence::InputRangeW); }
#[test] fn modq_dot_start_tamper_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[DOT_8_0_4], false, Lie::DotStart { block: 0, coefficient: 17, delta: 1 }, Defence::DotStart); }
#[test] fn modq_dot_carry_tamper_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[DOT_8_0_4], false, Lie::DotCarry { block: 0, coefficient: 17, k: 1, delta: 1 }, Defence::DotCarry); }
#[test] fn modq_msub_broadcast_tamper_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[MSUB_0_8_4], false, Lie::MsubBroadcast { block: 0, coefficient: 17, k: 2, delta: 1 }, Defence::MsubCarry); }
#[test] fn modq_op_bit_flip_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[INTT1], false, Lie::OpAs { block: 0, op: Op::Ntt }, Defence::A1Decomposition); }
#[test] fn modq_reserved_a1_bit_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT0 | 1 << 5], true, Lie::None, Defence::A1Decomposition); }
#[test] fn modq_ntt_with_nonzero_a_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT0 | 1 << 16], true, Lie::None, Defence::CanonicalArgsA); }
#[test] fn modq_ntt_with_nonzero_b_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT0 | 1 << 24], true, Lie::None, Defence::CanonicalArgsB); }

#[test] fn modq_overlapping_dot_operands_die_on_strict_order() { let _permit = modq_permit(); passes_the_chip_dies_in_the_machine(&[2 | 8 << 8 | 2 << 24], true, Lie::None); }
#[test] fn modq_memory_read_mismatch_is_rejected() { let _permit = modq_permit(); passes_the_chip_dies_in_the_machine(&[NTT0], false, Lie::ReadValue { block: 0, delta: 1 }); }
/// The modq instance (index 8 in the batch) is the one whose constraints fail.
#[test]
fn modq_wrong_zeta_block_is_rejected() {
    let _permit = modq_permit();
    let (p, e) = modq_run(&[NTT0], false);
    let (rejected, said) = machine_outcome(&p, &e, 1, Lie::ShiftedZetas);
    assert!(rejected, "ZF is preprocessed, bound by the verifier key");
    assert!(said.contains("OodEvaluationMismatch { index: Some(8) }"), "the modq table rejects it: {said}");
}

/// Every table's constraints hold; only a bus fails to balance (`MODQ`: an entry no cpu row asks for).
#[test]
fn modq_padding_block_made_real_is_rejected() {
    let _permit = modq_permit();
    let (p, e) = modq_run(&[NTT0, INTT1, NTT0], false);
    let (rejected, said) = machine_outcome(&p, &e, 3, Lie::RealPadding { block: 3 });
    assert!(rejected, "a MODQ entry no cpu row asks for");
    assert!(said.contains("Lookup(TerminalSumNonZero)"), "a lookup imbalance rejects it: {said}");
}

/// The `MODQ` bus has no provider without a modq table. `Lie::NoModqTable` drops the table *and*
/// its memory traffic and range counts, so the memory and range tables balance without it; the
/// gas limit is the run's own gas, so the header's gas ceiling (which drops with the table) is not
/// what refuses it. What is left is the cpu row's unanswered `MODQ` lookup.
#[test]
fn modq_row_without_a_modq_table_is_rejected() {
    let _permit = modq_permit();
    let (p, e) = modq_run(&[NTT0], false);
    let m = Machine::new(FriProfile::Test);
    let gas = rand_zkvm::gas::gas_of(&p, &[], &[], &e.events);
    let honest = build_traces_salted(&p, &[], &[], [0u32; 4], &e, Tier(14), gas).unwrap();
    m.verify(&p.digest(), &m.prove_traces(&p, &honest, Tier(14))).expect("the honest traces verify");
    let t = rand_zkvm::machine::build_traces_forged(&p, &[], &[], [0u32; 4], &e, Tier(14), gas, Lie::NoModqTable).unwrap();
    assert!(t.modq.is_none() && t.modq_log_height == 0);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { let pr = m.prove_traces(&p, &t, Tier(14)); m.verify(&p.digest(), &pr) }));
    let said = outcome(&r);
    eprintln!("NoModqTable in the machine: {said}");
    assert!(said.contains("Lookup(TerminalSumNonZero)"), "the unanswered MODQ lookup rejects it: {said}");
    assert!(rejects(|| r.unwrap_or_else(|e| std::panic::resume_unwind(e))));
}

#[test]
fn modq_heights_outside_the_flat_range_are_rejected_before_any_key() {
    let _permit = modq_permit();
    use rand_zkvm::machine::VerifyError;
    let prover = Machine::new(FriProfile::Test);
    let p = common::modq_program(&[NTT0]);
    // The run's own gas as the declared limit: the header's ceiling at height 10 would exceed
    // `gas_max_with_modq` at height 9, and `GasLimit` would answer before the height check.
    let gas = rand_zkvm::gas::gas_of(&p, &[], &[], &execute(&p, &[], &[], 1 << 16).unwrap().events);
    let opts = rand_zkvm::machine::ProveOptions { gas_limit: Some(gas), ..Default::default() };
    let (proof, _) = prover.prove_with_options(&p, &[], &[], Some(Tier(14)), opts).unwrap();
    let idx = proof.batch.degree_bits.len() - 2;
    for bad in [9u8, 21] {
        let mut pr: rand_zkvm::machine::Proof = postcard::from_bytes(&proof.to_bytes()).unwrap();
        pr.modq_log_height = bad;
        pr.batch.degree_bits[idx] = bad as usize + 1;
        let verifier = Machine::new(FriProfile::Test);
        assert!(matches!(verifier.verify(&p.digest(), &pr), Err(VerifyError::ModqHeight)), "height {bad}");
        assert_eq!(verifier.cached_keys(), 0, "the range check precedes the verifier key");
    }
}
