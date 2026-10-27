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
//
// Forged traces are proved in the machine with `Machine::prove_traces_without_self_check` (audit
// CS9-2): under plain `cargo test` the batch prover's `debug_assertions` self-check would otherwise
// panic on the lie before any proof exists, and the tests that assert on the *verifier's* typed error
// (`OodEvaluationMismatch`, `Lookup(TerminalSumNonZero)`) could only pass with `--release`. Honest
// traces still go through `prove_traces`, self-check on.

use rand_zkvm::modq::Op;
use rand_zkvm::tables::modq::{forge_block, modq_log_height, Defence, Lie, MIN_LOG_HEIGHT};

const NTT0: u32 = 0;
const INTT1: u32 = 1 | 1 << 8;
const DOT_8_0_4: u32 = 2 | 8 << 8 | 4 << 24;
const MSUB_0_8_4: u32 = 3 | 8 << 16 | 4 << 24;
/// An `NTT` into poly 2: `out` has bits `(0, 1) = (0, 1)`, the shape `Lie::NonBooleanBit` carries.
const NTT_OUT2: u32 = 2 << 8;
/// Op byte `2 + 3 = 5`: the `a1` of a block that claims to be a `DOT4` and an `MSUB4` at once
/// (`Lie::TwoOps`); bit 2 is reserved, so only `execute_unchecked_modq` runs it (as an `INTT`).
const DOT_AND_MSUB: u32 = 5 | 8 << 8 | 4 << 24;

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
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { let pr = m.prove_traces_without_self_check(p, &t, Tier(14)); m.verify(&p.digest(), &pr) }));
    let said = outcome(&r);
    eprintln!("{lie:?} in the machine: {said}");
    (rejects(|| r.unwrap_or_else(|e| std::panic::resume_unwind(e))), said)
}

/// Pre-flight ruling 1: accepted standalone with only `off` switched off, rejected with it on, and rejected by the machine.
fn off_accepts_on_rejects(calls: &[u32], unchecked: bool, lie: Lie, off: Defence) {
    let (p, e) = modq_run(calls, unchecked);
    let evs = common::modq_harness::events(&e);
    // A run with no call has no table; `Lie::RealPadding` on it needs the one-block floor.
    let forged = forge_block(&evs, modq_log_height(evs.len()).max(MIN_LOG_HEIGHT), lie);
    let accepted = common::modq_harness::run(&forged, Some(off));
    eprintln!("{lie:?} with {off:?} off: {accepted:?}");
    assert!(accepted.is_ok(), "{lie:?} must be accepted with only {off:?} off");
    let on = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| common::modq_harness::run(&forged, None)));
    eprintln!("{lie:?} with {off:?} on: {}", outcome(&on));
    assert!(rejects(|| common::modq_harness::run(&forged, None)), "{lie:?} must be rejected with {off:?} on");
    assert!(machine_rejects(&p, &e, calls.len(), lie), "{lie:?} must be rejected by the machine");
}

/// Defences outside the modq AIR: the forgery passes the modq AIR with every defence on, and dies in the machine.
fn passes_the_chip_dies_in_the_machine(calls: &[u32], unchecked: bool, lie: Lie) {
    let (p, e) = modq_run(calls, unchecked);
    let evs = common::modq_harness::events(&e);
    let forged = forge_block(&evs, modq_log_height(evs.len()), lie);
    assert!(common::modq_harness::run(&forged, None).is_ok(), "{lie:?} passes the modq AIR alone");
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
                Lie::InputLimbCarryV { block: 0 }, Lie::InputLimbCarryW { block: 2 }, Lie::DotStart { block: 2, coefficient: 17, delta: 1 },
                // Audit CS9-1's lies (`TwoOps` needs its own `a1`; `UnwrittenO0`/`O1` lie in the story, not the witness).
                Lie::NonBooleanBit { block: 2 }, Lie::OpLess { block: 0 }, Lie::HalfReal { block: 2 }, Lie::TransformW { block: 0 },
                Lie::CrossedU { block: 0, stage: 3 }, Lie::CrossedV { block: 0, stage: 3 }, Lie::WrongAddress { block: 0, slot: 0, delta: 1 },
                Lie::ReadValue { block: 0, delta: 1 }, Lie::ReadValueV { block: 0, delta: 1 }, Lie::ReadValueW { block: 2, delta: 1 },
                Lie::LimbCarryO0 { block: 0 }, Lie::LimbCarryO1 { block: 0 }, Lie::LimbCarryK0 { block: 0 }, Lie::LimbCarryK1 { block: 0 }] {
        assert_ne!(forge_block(&evs, 12, lie).trace.values, honest.values, "{lie:?} must change the witness");
    }
    for lie in [Lie::UnwrittenO0 { block: 0 }, Lie::UnwrittenO1 { block: 0 }] {
        let f = forge_block(&evs, 12, lie);
        assert_eq!(f.trace.values, honest.values, "{lie:?} leaves the witness honest");
        assert_ne!(f.accesses, forge_block(&evs, 12, Lie::None).accesses, "{lie:?} must change the memory story");
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

// ---- Audit CS9-1 (2026-10-15): the lines that had no switch, each with the one lie only it tells. ----
// Rule 1. `TwoOps` is accepted with only `RealBoolean` off because every bound rules 5–8 declare
// (`Count::bounded(.., 1)`) is the AIR's promise, not the lookup's check: the block claims itself twice
// on `MODQ`, reads `V` twice, counts every limb twice, and the story (asks, twin, range) pays twice.
#[test] fn modq_two_op_block_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[DOT_AND_MSUB], true, Lie::TwoOps { block: 0 }, Defence::RealBoolean); }
#[test] fn modq_non_boolean_offset_bit_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT_OUT2], false, Lie::NonBooleanBit { block: 0 }, Defence::FlagsBoolean); }
#[test] fn modq_op_less_real_block_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT0], false, Lie::OpLess { block: 0 }, Defence::OneHot); }
#[test] fn modq_half_real_block_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[DOT_8_0_4], false, Lie::HalfReal { block: 0 }, Defence::BlockConstant); }
// Rule 2.
#[test] fn modq_transform_with_a_multiplier_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT0], false, Lie::TransformW { block: 0 }, Defence::TransformNoW); }
// Rule 3.
#[test] fn modq_crossed_u_wire_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT0], false, Lie::CrossedU { block: 0, stage: 3 }, Defence::IdxU); }
#[test] fn modq_crossed_v_wire_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT0], false, Lie::CrossedV { block: 0, stage: 3 }, Defence::IdxV); }
#[test] fn modq_wrong_u_address_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT0], false, Lie::WrongAddress { block: 0, slot: 0, delta: 1 }, Defence::AddrU); }
#[test] fn modq_wrong_v_address_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT0], false, Lie::WrongAddress { block: 0, slot: 1, delta: 1 }, Defence::AddrV); }
#[test] fn modq_wrong_w_address_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[DOT_8_0_4], false, Lie::WrongAddress { block: 0, slot: 2, delta: 1 }, Defence::AddrW); }
#[test] fn modq_wrong_o0_address_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT0], false, Lie::WrongAddress { block: 0, slot: 3, delta: 1 }, Defence::AddrO0); }
#[test] fn modq_wrong_o1_address_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT0], false, Lie::WrongAddress { block: 0, slot: 4, delta: 1 }, Defence::AddrO1); }
// Rule 6: the memory story is memory's own (the read values the emulator saw; no writes for the
// `Unwritten*` lies), so the chip's send is what disagrees with it — standalone now, not only in the
// machine (the audit's "ReadValue only exercises at machine level"). A `ReadValue*` lie cannot use
// `off_accepts_on_rejects`: with its `Memory*` defence off the chip sends no read at all, so the
// twin's (honest) read is left unpaid and the batch is refused for that, not accepted. The
// isolation is instead that the same call with `Lie::None` passes standalone, and the lied value
// is the only difference.
fn read_lie_rejected(calls: &[u32], lie: Lie) {
    let (p, e) = modq_run(calls, false);
    let evs = common::modq_harness::events(&e);
    let honest = forge_block(&evs, modq_log_height(evs.len()), Lie::None);
    assert!(common::modq_harness::run(&honest, None).is_ok(), "the honest block passes standalone");
    let forged = forge_block(&evs, modq_log_height(evs.len()), lie);
    assert!(rejects(|| common::modq_harness::run(&forged, None)), "{lie:?} must be rejected standalone (the MEMORY balance)");
    assert!(machine_rejects(&p, &e, calls.len(), lie), "{lie:?} must be rejected by the machine");
}
#[test] fn modq_memory_read_mismatch_is_rejected() { let _permit = modq_permit(); read_lie_rejected(&[NTT0], Lie::ReadValue { block: 0, delta: 1 }); }
#[test] fn modq_v_read_mismatch_is_rejected() { let _permit = modq_permit(); read_lie_rejected(&[NTT0], Lie::ReadValueV { block: 0, delta: 1 }); }
#[test] fn modq_w_read_mismatch_is_rejected() { let _permit = modq_permit(); read_lie_rejected(&[DOT_8_0_4], Lie::ReadValueW { block: 0, delta: 1 }); }
#[test] fn modq_unwritten_o0_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT0], false, Lie::UnwrittenO0 { block: 0 }, Defence::MemoryO0); }
#[test] fn modq_unwritten_o1_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT0], false, Lie::UnwrittenO1 { block: 0 }, Defence::MemoryO1); }
// Rule 7: a real block on a run with no `SYS_MODQ` row at all — the table claims an entry no cpu row
// asks for; without the entry the chip can carry any block unseen.
#[test] fn modq_unasked_block_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[], false, Lie::RealPadding { block: 0 }, Defence::Handshake); }
// Rule 8: the output and quotient limb groups, as `InputLimbCarry` for the inputs.
#[test] fn modq_output_limb_out_of_range_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT0], false, Lie::LimbCarryO0 { block: 0 }, Defence::OutputRangeO0); }
#[test] fn modq_o1_limb_out_of_range_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT0], false, Lie::LimbCarryO1 { block: 0 }, Defence::OutputRangeO1); }
#[test] fn modq_k0_limb_out_of_range_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT0], false, Lie::LimbCarryK0 { block: 0 }, Defence::QuotientRangeK0); }
#[test] fn modq_k1_limb_out_of_range_is_rejected() { let _permit = modq_permit(); off_accepts_on_rejects(&[NTT0], false, Lie::LimbCarryK1 { block: 0 }, Defence::QuotientRangeK1); }

#[test] fn modq_overlapping_dot_operands_die_on_strict_order() { let _permit = modq_permit(); passes_the_chip_dies_in_the_machine(&[2 | 8 << 8 | 2 << 24], true, Lie::None); }
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
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { let pr = m.prove_traces_without_self_check(&p, &t, Tier(14)); m.verify(&p.digest(), &pr) }));
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
