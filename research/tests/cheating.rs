//! Every test here builds a wrong witness and checks the verifier rejects it.
//! In debug builds Plonky3 panics inside `prove_batch` on the first violated
//! constraint; in release builds it produces a proof that fails to verify.
//! `rejects` accepts either.
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;
use rand_zkvm::emulator::{execute, SLOT_W};
use rand_zkvm::guests;
use rand_zkvm::isa::REG_A1;
use rand_zkvm::machine::{build_traces, FriProfile, Machine, Tier, Traces};
use rand_zkvm::tables::{alu, cpu, memory, F};
use std::panic::{catch_unwind, AssertUnwindSafe};

fn rejects(f: impl FnOnce() -> Result<(), rand_zkvm::machine::VerifyError>) -> bool {
    match catch_unwind(AssertUnwindSafe(f)) { Ok(Ok(())) => false, _ => true }
}

fn setup() -> (Machine, rand_zkvm::isa::Program, Traces) {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let e = execute(&p, &[], 10_000).unwrap();
    let t = build_traces(&p, &e, Tier(10)).unwrap();
    (m, p, t)
}

#[test]
fn honest_traces_pass() {
    let (m, p, t) = setup();
    let proof = m.prove_traces(&p, &t, Tier(10));
    m.verify(&p, &proof).unwrap();
}

#[test]
fn claiming_a_wrong_output_is_rejected() {
    let (m, p, mut t) = setup();
    t.public_values[cpu::pv::OUT0] = F::from_u32(56);   // fib(10) is 55
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

#[test]
fn tampering_a_register_value_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    t.cpu.values[3 * w + cpu::col::C] += F::ONE;         // row 3 writes a wrong rd
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

#[test]
fn skipping_a_cycle_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    let last = (0..t.cpu.height()).rev().find(|r| t.cpu.values[r * w + cpu::col::IS_REAL] == F::ONE).unwrap();
    // mark the row before HALT as padding: the chain of pcs breaks
    t.cpu.values[(last - 1) * w + cpu::col::IS_REAL] = F::ZERO;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

#[test]
fn proof_for_one_program_does_not_verify_another() {
    let m = Machine::new(FriProfile::Test);
    let (proof, _) = m.prove(&guests::fib(10), &[], None).unwrap();
    assert!(rejects(|| m.verify(&guests::fib(11), &proof)));
}

#[test]
fn wrong_tier_claim_is_rejected() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (mut proof, _) = m.prove(&p, &[], None).unwrap();
    proof.tier = Tier(12);
    assert!(rejects(|| m.verify(&p, &proof)));
}

#[test]
fn a_run_that_does_not_fit_the_tier_is_refused() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(300);   // ~1800 cycles > 2^10 - 1
    assert!(matches!(m.prove(&p, &[], Some(Tier(10))), Err(rand_zkvm::machine::ProveError::TooManyCycles { .. })));
    let (proof, _) = m.prove(&p, &[], None).unwrap();
    assert_eq!(proof.tier, Tier(12));
}

#[test]
fn out_of_range_tier_is_an_error_not_a_panic() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (mut proof, _) = m.prove(&p, &[], None).unwrap();
    proof.tier = Tier(99);
    proof.public_values[cpu::pv::TIER] = 99;
    assert!(matches!(m.verify(&p, &proof), Err(rand_zkvm::machine::VerifyError::Tier)));
}

#[test]
fn wrong_entry_point_claim_is_rejected() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (mut proof, _) = m.prove(&p, &[], None).unwrap();
    proof.public_values[cpu::pv::PC_ENTRY] = 4;
    assert!(matches!(m.verify(&p, &proof), Err(rand_zkvm::machine::VerifyError::PublicValues)));
}

/// Rewrite an honest `fib(10)` witness so that it claims `out0 = forged`, using nothing
/// but a *padding* row of the ALU table as the source of the arithmetic that justifies it.
///
/// The ALU table provides `(op, a, b, c)` on the ALU bus with count `MULT`. On a padding
/// row every op flag is zero — so the provided `op` decodes as `Add` — the limb range
/// checks and every arithmetic constraint are gated on a flag or on `is_real`, and (before
/// the `(1 − is_real)·MULT = 0` constraint) `MULT` itself was unconstrained. A padding row
/// could therefore hand the CPU an arbitrary `Add` tuple with arbitrary multiplicity.
///
/// The rewrite is a closed edit: `mv a1, t0` (the instruction that stages the output word)
/// is made to produce `forged` instead of `fib(10)`; the register file, every later `a1`
/// read, the `WRITE_OUTPUT` row's `mem_val` and the public output word follow; the honest
/// ALU row that provided the real tuple is retired to `MULT = 0` so the bus still balances,
/// and the forged tuple is planted on the last (padding) ALU row. Nothing else moves.
fn forge_fib_output_through_an_alu_padding_row(t: &mut Traces, forged: u32) {
    let (wc, wm, wa) = (cpu::col::WIDTH, memory::col::WIDTH, alu::col::WIDTH);
    let new = F::from_u32(forged);

    // The `WRITE_OUTPUT` ecall, and the `mv a1, t0` immediately before it that stages a1.
    let ecall_row = (0..t.cpu.height()).find(|r| t.cpu.values[r * wc + cpu::col::SYS_WRITE] == F::ONE).expect("fib writes an output");
    let mv_row = ecall_row - 1;
    assert_eq!(t.cpu.values[mv_row * wc + cpu::col::IS_ALU], F::ONE, "row before the ecall is `mv a1, t0`");
    assert_eq!(t.cpu.values[mv_row * wc + cpu::col::RD], F::from_u32(REG_A1));
    let a_in = t.cpu.values[mv_row * wc + cpu::col::A];
    let honest = t.cpu.values[mv_row * wc + cpu::col::C];
    let write_ts = 4 * t.cpu.values[mv_row * wc + cpu::col::CLK].as_canonical_u64() + SLOT_W as u64;

    // cpu: the `mv` now yields `forged`, and every later ecall reads the new a1.
    t.cpu.values[mv_row * wc + cpu::col::ALU_OUT] = new;
    t.cpu.values[mv_row * wc + cpu::col::C] = new;
    for r in mv_row + 1..t.cpu.height() {
        if t.cpu.values[r * wc + cpu::col::IS_ECALL] == F::ONE { t.cpu.values[r * wc + cpu::col::MEM_VAL] = new; }
    }
    t.public_values[cpu::pv::OUT0] = new;

    // memory: a1's write and every read of it afterwards.
    for r in 0..t.memory.height() {
        let row = &mut t.memory.values[r * wm..(r + 1) * wm];
        if row[memory::col::IS_REAL] == F::ONE
            && row[memory::col::SPACE] == F::ZERO
            && row[memory::col::ADDR] == F::from_u32(REG_A1)
            && row[memory::col::TS].as_canonical_u64() >= write_ts
        {
            row[memory::col::VALUE] = new;
        }
    }

    // alu: retire one honest provider of the real tuple, plant the forged one on padding.
    let honest_row = (0..t.alu.height())
        .find(|r| {
            let row = &t.alu.values[r * wa..(r + 1) * wa];
            row[alu::col::FLAG0] == F::ONE && row[alu::col::A] == a_in && row[alu::col::B] == F::ZERO && row[alu::col::C] == honest && row[alu::col::MULT] != F::ZERO
        })
        .expect("the honest (Add, a, 0, c) tuple is provided somewhere");
    t.alu.values[honest_row * wa + alu::col::MULT] = F::ZERO;
    let pad = t.alu.height() - 1;
    assert_eq!(t.alu.values[pad * wa + alu::col::IS_REAL], F::ZERO, "last alu row is padding");
    t.alu.values[pad * wa + alu::col::A] = a_in;
    t.alu.values[pad * wa + alu::col::B] = F::ZERO;
    t.alu.values[pad * wa + alu::col::C] = new;
    // `word(A0) = A` and `word(C0) = C` are the only ungated constraints that touch these
    // columns, and the limbs' `RANGE8` lookups are counted by `is_real` — so parking the
    // whole word in limb 0 satisfies the recomposition with no range check to answer to.
    t.alu.values[pad * wa + alu::col::A0] = a_in;
    t.alu.values[pad * wa + alu::col::C0] = new;
    t.alu.values[pad * wa + alu::col::MULT] = F::ONE;
}

#[test]
fn a_tuple_forged_on_an_alu_padding_row_is_rejected() {
    let (m, p, mut t) = setup();
    forge_fib_output_through_an_alu_padding_row(&mut t, 999); // fib(10) is 55
    assert_eq!(t.public_values[cpu::pv::OUT0], F::from_u32(999));
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}


#[test]
fn claiming_a_word_in_an_unwritten_output_slot_is_rejected() {
    let (m, p, mut t) = setup();
    // `fib` writes slot 0 only; spec §3.4 says every slot no WRITE_OUTPUT selected is zero.
    assert_eq!(t.public_values[cpu::pv::OUT0 + 1], F::ZERO);
    t.public_values[cpu::pv::OUT0 + 1] = F::from_u32(7);
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}
