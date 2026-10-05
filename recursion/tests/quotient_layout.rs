//! The quotient-layout fork (`docs/05-quotient-layout.md`): the rVM commits each instance's
//! quotient chunks as one matrix. What this file pins: the machine's layout constant, the proof's
//! quotient-round structure, the proof's survival of serialisation, and the refusals — a flipped
//! chunk value, a flipped random hint, and a proof made under upstream's layout.
mod common;

use p3_batch_stark::QuotientLayout;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use recursion::isa::{Instr, Op, Program, F};
use recursion::machine::{Machine, Tier, VerifyError, QUOTIENT_LAYOUT};
use rand_zkvm::machine::FriProfile;

fn instr(op: Op, rd: u8, ra: u8, b: u64) -> Instr {
    Instr { op, rd, ra, b: F::from_u64(b) }
}

/// `tests/machine.rs`'s toy with the four-word interface digest.
fn toy_program() -> Program {
    Program {
        instrs: vec![
            instr(Op::Faddi, 1, 0, 7),
            instr(Op::Faddi, 2, 0, 5),
            instr(Op::Fadd, 3, 1, 2),
            instr(Op::Public, 0, 3, 0),
            instr(Op::Public, 0, 1, 0),
            instr(Op::Public, 0, 2, 0),
            instr(Op::Public, 0, 3, 0),
            instr(Op::Halt, 0, 0, 0),
        ],
        checkpoints: vec![],
    }
}

/// The quotient round's index in `opening_proof`: `random` (0), `main` (1), `quotient_chunks` (2),
/// then `preprocessed` and `permutation` (`p3-batch-stark/src/prover.rs`, "Round 2").
const QUOTIENT_ROUND: usize = 2;
const NUM_RANDOM_CODEWORDS: usize = 4;
const DIMENSION: usize = <recursion::machine::Challenge as BasedVectorSpace<recursion::machine::Val>>::DIMENSION;

#[test]
fn the_machine_pins_the_per_instance_layout() {
    assert_eq!(QUOTIENT_LAYOUT, QuotientLayout::PerInstance, "the rVM's own proofs take the fork's layout");
}

#[test]
fn a_per_instance_proof_has_one_quotient_matrix_per_instance_and_verifies() {
    let p = toy_program();
    let m = Machine::new(FriProfile::Test);
    let (proof, _) = m.prove(&p, &[], None).unwrap();
    m.verify(&p, &proof).unwrap();

    let n = proof.batch.degree_bits.len();
    let (rand_openings, fri) = &proof.batch.opening_proof;
    // The hiding PCS's hidden halves: one set of four per instance, not one per chunk.
    assert_eq!(rand_openings[QUOTIENT_ROUND].len(), n, "one quotient matrix per instance");
    for mat in &rand_openings[QUOTIENT_ROUND] {
        assert_eq!(mat.len(), 1, "opened at zeta only");
        assert_eq!(mat[0].len(), NUM_RANDOM_CODEWORDS);
    }
    // The committed rows: `chunks · DIMENSION + 4` base columns, chunks as the proof's per-chunk
    // opened values count them (16 for the cpu table, 2 for the program table).
    for q in 0..fri.input_openings[QUOTIENT_ROUND].opened_values.len() {
        let rows = &fri.input_openings[QUOTIENT_ROUND].opened_values[q];
        assert_eq!(rows.len(), n);
        for (i, row) in rows.iter().enumerate() {
            let chunks = proof.batch.opened_values.instances[i].base_opened_values.quotient_chunks.len();
            assert!(chunks >= 2, "ZK doubles every chunk count");
            assert_eq!(row.len(), chunks * DIMENSION + NUM_RANDOM_CODEWORDS, "instance {i}");
        }
    }
    // The per-chunk opened values keep upstream's shape, so recomposition is untouched.
    for inst in &proof.batch.opened_values.instances {
        for chunk in &inst.base_opened_values.quotient_chunks {
            assert_eq!(chunk.len(), DIMENSION);
        }
    }
}

#[test]
fn a_per_instance_proof_survives_postcard() {
    let p = toy_program();
    let m = Machine::new(FriProfile::Test);
    let (proof, _) = m.prove(&p, &[], None).unwrap();
    let bytes = proof.to_bytes();
    let back: recursion::machine::Proof = postcard::from_bytes(&bytes).unwrap();
    m.verify(&p, &back).unwrap();
}

#[test]
fn a_flipped_quotient_chunk_value_is_refused() {
    let p = toy_program();
    let m = Machine::new(FriProfile::Test);
    let (mut proof, _) = m.prove(&p, &[], None).unwrap();
    // Instance 1 is the cpu table (16 chunks); flip one lane of chunk 3 inside the wide row.
    let v = &mut proof.batch.opened_values.instances[1].base_opened_values.quotient_chunks[3][0];
    *v += recursion::machine::Challenge::ONE;
    match m.verify(&p, &proof) {
        Err(VerifyError::Batch(_)) => {}
        other => panic!("a flipped quotient value must be refused by the batch verifier, got {other:?}"),
    }
}

#[test]
fn a_flipped_quotient_random_hint_is_refused() {
    let p = toy_program();
    let m = Machine::new(FriProfile::Test);
    let (mut proof, _) = m.prove(&p, &[], None).unwrap();
    // The wide row's four hidden values are the instance's one salt set now; flip one.
    let v = &mut proof.batch.opening_proof.0[QUOTIENT_ROUND][1][0][0];
    *v += recursion::machine::Challenge::ONE;
    match m.verify(&p, &proof) {
        Err(VerifyError::Batch(_)) => {}
        other => panic!("a flipped random hint must fail the Merkle row, got {other:?}"),
    }
}

#[test]
fn a_proof_made_under_upstreams_layout_is_refused_not_panicked() {
    let p = toy_program();
    let m = Machine::new(FriProfile::Test);
    let exec = recursion::emulator::execute(&p, &[], Tier(8).max_cycles()).unwrap();
    let tier = Tier::for_cycles(exec.cpu_rows()).unwrap();
    let traces = recursion::machine::build_traces(&p, &exec, tier).unwrap();
    let honest = m.prove_traces_with_layout(&p, &traces, tier, QUOTIENT_LAYOUT);
    m.verify(&p, &honest).unwrap();
    let per_chunk = m.prove_traces_with_layout(&p, &traces, tier, QuotientLayout::PerChunk);
    match m.verify(&p, &per_chunk) {
        Err(VerifyError::Batch(msg)) => {
            assert!(
                msg.contains("Mismatch") || msg.contains("InvalidOpeningArgument"),
                "the refusal names the layout disagreement: {msg}"
            );
        }
        other => panic!("a PerChunk proof must be refused by a PerInstance verifier, got {other:?}"),
    }
}
