//! The soundness suite (plan Tasks 6, 8, 10): every test builds a wrong witness and checks the
//! machine rejects it, through `rejects()` and nothing else — a per-instance constraint-checker
//! panic (`CONSTRAINT_PANIC`), a global lookup-balance panic (`LOOKUP_BALANCE_PANIC`), or a
//! verify error counts; anything else means the test tripped on something it did not mean to.
mod common;

use common::rejects;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;
use recursion::emulator::execute;
use recursion::isa::{F, Instr, Op, Program};
use recursion::machine::{build_traces, FriProfile, Machine, Tier, Traces};
use recursion::tables::{cpu, memory, poseidon2, program as program_table, public as public_table};

fn i(op: Op, rd: u8, ra: u8, b: u64) -> Instr {
    Instr { op, rd, ra, b: F::from_u64(b) }
}
fn ir(op: Op, rd: u8, ra: u8, rb: u8) -> Instr {
    i(op, rd, ra, rb as u64)
}

/// The honest setup: one program touching every table — base and extension arithmetic, an `INV`,
/// a store/load round trip, a permutation, and the four published words R5 requires.
fn setup() -> (Machine, Program, Traces) {
    let p = Program {
        instrs: vec![
            i(Op::Faddi, 1, 0, 7),          // 0
            i(Op::Faddi, 2, 0, 5),          // 1
            ir(Op::Fadd, 3, 1, 2),          // 2: r3 = 12
            i(Op::Inv, 4, 3, 0),            // 3: r4 = 12^-1
            i(Op::Faddi, 5, 0, 100),        // 4
            i(Op::Store, 2, 5, 3),          // 5: mem[103] = 5
            i(Op::Load, 6, 5, 3),           // 6: r6 = 5
            i(Op::Faddi, 7, 0, 64),         // 7: ptr
            i(Op::Store, 1, 7, 0),          // 8: mem[64] = 7
            i(Op::Store, 2, 7, 1),          // 9: mem[65] = 5
            i(Op::Poseidon2, 0, 7, 0),      // 10: permute cells 64..71
            i(Op::Load, 8, 7, 0),           // 11
            i(Op::Public, 0, 3, 0),         // 12
            i(Op::Public, 0, 6, 0),         // 13
            i(Op::Public, 0, 8, 0),         // 14
            i(Op::Public, 0, 4, 0),         // 15
            i(Op::Halt, 0, 0, 0),           // 16
        ],
        checkpoints: vec![],
    };
    let m = Machine::new(FriProfile::Test);
    let exec = execute(&p, &[], 10_000).unwrap();
    let t = build_traces(&p, &exec, Tier(8)).unwrap();
    (m, p, t)
}

fn prove_and_verify(m: &Machine, p: &Program, t: &Traces) -> Result<(), recursion::machine::VerifyError> {
    let proof = m.prove_traces(p, t, Tier(8));
    m.verify(p, &proof)
}

#[test]
fn honest_traces_pass() {
    let (m, p, t) = setup();
    prove_and_verify(&m, &p, &t).unwrap();
}

#[test]
fn a_wrong_arithmetic_result_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    // Row 2 is the FADD: claim the sum is 13, not 12.
    t.cpu.values[2 * w + cpu::col::D0] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_skipped_row_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    // Mark the LOAD row as padding: the pc chain and the CLK chain break.
    t.cpu.values[6 * w + cpu::col::IS_REAL] = F::ZERO;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_bad_inv_hint_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    // Row 3 is the INV: any value but the true inverse fails `ra·rd = 1`.
    t.cpu.values[3 * w + cpu::col::D0] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn an_address_above_two_to_the_twentyfour_with_forged_limbs_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    // The LOAD row's limb columns are what pins its address below 2^24; shifting one limb is a
    // forged range proof. (The honest machine refuses the address outright at the emulator —
    // `tests/cpu.rs` — this is the row-level range check that makes the AIR agree.)
    t.cpu.values[6 * w + cpu::col::LIMB0] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_register_write_to_r0_surfacing_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    // Rewrite the FADD to target r0, and claim the write is not dropped (RD_IS_ZERO = 0 while
    // RD = 0): the is-zero gadget itself fails first.
    t.cpu.values[2 * w + cpu::col::RD] = F::ZERO;
    t.cpu.values[2 * w + cpu::col::RD_IS_ZERO] = F::ZERO;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_fetch_count_short_by_one_is_rejected() {
    let (m, p, mut t) = setup();
    let w = program_table::col::WIDTH;
    // The FADD lives at program row 2; drop its fetch count and the cpu's fetch is unclaimed.
    let mult = t.program.values[2 * w + program_table::col::MULT];
    assert_eq!(mult, F::ONE);
    t.program.values[2 * w + program_table::col::MULT] = F::ZERO;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_skipped_permutation_is_rejected() {
    let (m, p, mut t) = setup();
    let w = poseidon2::col::WIDTH;
    // The one real permutation row vanishes (its bus claims go with it): the cpu's dispatch has
    // no provider — and the memory table's reads and writes have no sender either.
    let row = (0..t.poseidon2.height()).find(|r| t.poseidon2.values[r * w + poseidon2::col::IS_REAL] == F::ONE).unwrap();
    t.poseidon2.values[row * w + poseidon2::col::IS_REAL] = F::ZERO;
    t.poseidon2.values[row * w + poseidon2::col::MULT] = F::ZERO;
    t.poseidon2.values[row * w + poseidon2::col::IS_PERM] = F::ZERO;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn an_extra_permutation_is_rejected() {
    let (m, p, mut t) = setup();
    let w = poseidon2::col::WIDTH;
    let row = (0..t.poseidon2.height()).find(|r| t.poseidon2.values[r * w + poseidon2::col::IS_REAL] == F::ONE).unwrap();
    // Clone the real row into the padding row after it: a permutation nothing dispatched.
    for c in 0..w {
        t.poseidon2.values[(row + 1) * w + c] = t.poseidon2.values[row * w + c];
    }
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_tampered_memory_value_is_rejected() {
    let (m, p, mut t) = setup();
    let w = memory::col::WIDTH;
    // The "wrong Merkle sibling" shape: the value the RAM table claims a read returned is not
    // the value last written — read-after-write is the transition constraint that catches it.
    let row = (0..t.ram.height()).find(|r| {
        t.ram.values[r * w + memory::col::IS_REAL] == F::ONE
            && t.ram.values[r * w + memory::col::IS_WRITE] == F::ZERO
    }).unwrap();
    t.ram.values[row * w + memory::col::VALUE] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_forged_public_value_is_rejected() {
    let (m, p, t) = setup();
    // (a) The batch public values, tampered after the fact: the transcript binds them.
    let mut proof = m.prove_traces(&p, &t, Tier(8));
    proof.public_values[0] += 1;
    assert!(rejects(|| m.verify(&p, &proof)));
    // (b) The public table's own VALUE column: the selector tie `VALUE = pv[i]` fails on the row.
    let (_, _, mut t2) = setup();
    let w = public_table::col::WIDTH;
    t2.public.values[w + public_table::col::VALUE] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t2)));
}

#[test]
fn a_proof_of_one_program_does_not_verify_against_another() {
    let (m, p, t) = setup();
    let proof = m.prove_traces(&p, &t, Tier(8));
    let mut other = p.clone();
    other.instrs[2] = ir(Op::Fsub, 3, 1, 2);
    // R1: the preprocessed cap binds the program — a different program is a different key.
    assert!(rejects(|| m.verify(&other, &proof)));
}

#[test]
fn a_proof_at_the_wrong_tier_is_rejected() {
    let (m, p, t) = setup();
    let mut proof = m.prove_traces(&p, &t, Tier(8));
    proof.tier = Tier(10);
    assert!(rejects(|| m.verify(&p, &proof)));
}

#[test]
fn an_out_of_range_tier_is_an_error_not_a_panic() {
    let (m, p, t) = setup();
    let mut proof = m.prove_traces(&p, &t, Tier(8));
    proof.tier = Tier(99);
    assert!(matches!(m.verify(&p, &proof), Err(recursion::machine::VerifyError::Tier)));
}
