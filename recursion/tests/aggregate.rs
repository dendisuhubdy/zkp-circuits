//! The N-generic aggregate program (M5.3): one counted loop over the tape's N, each iteration
//! the per-proof pipeline with a fresh challenger, then the interface digest over
//! `[inner_vk_digest ‖ N ‖ 34·N]`. The differentials: N=1 is the single-proof program plus a
//! pinned loop overhead, and the thirteen segment tampers are refused at the M5.1 table's named
//! steps, verbatim, at `(proof, segment)`.

mod common;

use p3_field::PrimeCharacteristicRing;
use rand_zkvm::machine::{FriProfile, Proof};
use recursion::dsl::Checkpoints;
use recursion::emulator::{execute, ExecError};
use recursion::isa::F;
use recursion::programs::{aggregate_program_digest, verify_rv32, verify_rv32n};
use recursion::shape::{InnerKey, InnerShape};
use recursion::witness::{Segment, WitnessTape};

const MAX_CYCLES: usize = 1 << 24;

/// The rows the counted loop and the runtime-length interface sponge cost over the single-proof
/// program at N=1, measured on this tree: the count word and its guard, the sponge state and
/// cursor, the per-proof 34-word staged absorb (with its eight rate-fill permutations), the
/// final partial-block permutation, and the loop scaffolding — against the single-proof phase
/// 8's list build and one-shot `sponge_seeded` it replaces.
const LOOP_OVERHEAD: usize = 139;

/// The N=3 total, measured on this tree. The per-N total is *not* a clean multiple of the
/// per-proof rows: the staged absorb permutes when the rate fills, and the fill phase advances
/// by two lanes per proof (34 mod 4), so an odd-numbered iteration permutes nine times where an
/// even one permutes eight — the per-N rows are `pre + Σ body_j + post` with the parity term,
/// pinned per N rather than modelled.
const N3_ROWS: usize = 1_324_694;

fn shape_and_key(p: &Proof) -> (InnerShape, InnerKey) {
    let shape = InnerShape::of(
        FriProfile::Test,
        p.tier,
        p.program_log_height,
        p.input_log_height,
        p.keccak_log_height,
        p.sha256_log_height,
        p.public_log_height,
        p.mem_log_height,
    );
    let key = InnerKey::of(FriProfile::Test, &shape);
    (shape, key)
}

/// The N=1 differential: the looped program over one fixture proof accepts, publishes exactly
/// the single-proof program's interface digest, and costs the single-proof rows plus the pinned
/// loop overhead.
#[test]
fn n1_aggregate_publishes_the_single_proof_digest_at_a_pinned_overhead() {
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let (shape, key) = shape_and_key(&p.proof);

    let single_vp = verify_rv32(&shape, &key, Checkpoints::Off);
    let single_tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let single_exec = execute(&single_vp.program, &single_tape.words, MAX_CYCLES).unwrap();

    let vp = verify_rv32n(&shape, &key, Checkpoints::Off);
    let tape =
        WitnessTape::build_n(FriProfile::Test, &shape, &key, std::slice::from_ref(&p.proof))
            .unwrap();
    let exec = execute(&vp.program, &tape.words, MAX_CYCLES)
        .expect("the looped program accepts one real proof");

    assert_eq!(
        exec.public, single_exec.public,
        "N=1 publishes exactly the single-proof program's interface digest"
    );
    let words =
        recursion::public_values::interface_words(&shape, &key, &[p.proof.public_values.clone()]);
    assert_eq!(
        exec.public,
        recursion::public_values::public_digest(&words).to_vec(),
        "and that digest is the host's §4.4 construction, exactly"
    );
    assert_eq!(
        exec.cpu_rows(),
        single_exec.cpu_rows() + LOOP_OVERHEAD,
        "the loop costs the single-proof rows plus the pinned overhead"
    );
}

/// Three real proofs, one looped run: accepted, and the published digest is the host's
/// `[vk ‖ 3 ‖ 34·3]` list — the staged absorb's two rate-fill parities both exercised.
#[test]
fn n3_aggregate_publishes_the_host_interface_digest() {
    let proofs: Vec<Proof> =
        common::bundle_proofs(FriProfile::Test, 3).into_iter().map(|p| p.proof).collect();
    let (shape, key) = shape_and_key(&proofs[0]);
    let vp = verify_rv32n(&shape, &key, Checkpoints::Off);
    let tape = WitnessTape::build_n(FriProfile::Test, &shape, &key, &proofs).unwrap();
    let exec = execute(&vp.program, &tape.words, MAX_CYCLES)
        .expect("the looped program accepts three real proofs");

    let pvs: Vec<Vec<u64>> = proofs.iter().map(|p| p.public_values.clone()).collect();
    let words = recursion::public_values::interface_words(&shape, &key, &pvs);
    assert_eq!(
        exec.public,
        recursion::public_values::public_digest(&words).to_vec(),
        "the looped program's digest is the host's §4.4 list over three proofs"
    );
    assert_eq!(exec.cpu_rows(), N3_ROWS, "the N=3 row count is pinned");
}

/// The loop-invariant test: the replay's `LoopEnd` check — every handle that existed before the
/// loop must end it with the allocation it started with — does not fire for the looped program.
/// Building is the test: a violation panics here, at build time, naming the handle.
#[test]
fn the_looped_program_builds_under_the_replays_loop_invariant() {
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let (shape, key) = shape_and_key(&p.proof);
    let _ = verify_rv32n(&shape, &key, Checkpoints::Off);
}

/// What the fullnode registers: one digest per inner shape, deterministic, and not the
/// single-proof program's.
#[test]
fn the_aggregate_program_digest_is_deterministic_and_distinct() {
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let (shape, key) = shape_and_key(&p.proof);
    let d1 = aggregate_program_digest(&shape, &key);
    let d2 = aggregate_program_digest(&shape, &key);
    assert_eq!(d1, d2, "rebuilding the program reproduces its digest");
    let single = verify_rv32(&shape, &key, Checkpoints::Off).program.digest();
    assert_ne!(d1, single, "the aggregate program is not the single-proof program");
}

/// A tape whose count word is zero is refused at a named step — the counted loop's `n >= 1`
/// precondition enforced in-program, before any proof is read.
#[test]
fn an_empty_aggregate_is_refused_at_the_count_word() {
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let (shape, key) = shape_and_key(&p.proof);
    let vp = verify_rv32n(&shape, &key, Checkpoints::Off);
    let tape = WitnessTape::build_n(FriProfile::Test, &shape, &key, &[]).unwrap();
    match execute(&vp.program, &tape.words, MAX_CYCLES) {
        Err(ExecError::InverseOfZero { pc }) => assert_eq!(
            vp.program.checkpoint_at(pc),
            Some("aggregate count"),
            "the empty aggregate is refused at the count word's guard"
        ),
        other => panic!("expected the count-word refusal, got {other:?}"),
    }
}

/// A count word that overstates the proofs on the tape runs the loop off the tape's end.
#[test]
fn an_overstated_count_runs_off_the_tape() {
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let (shape, key) = shape_and_key(&p.proof);
    let vp = verify_rv32n(&shape, &key, Checkpoints::Off);
    let mut tape =
        WitnessTape::build_n(FriProfile::Test, &shape, &key, std::slice::from_ref(&p.proof))
            .unwrap();
    tape.words[0] += F::ONE;
    match execute(&vp.program, &tape.words, MAX_CYCLES) {
        Err(ExecError::HintExhausted { .. }) => {}
        other => panic!("an overstated count must run off the tape, got {other:?}"),
    }
}

// ── the tamper differential ──────────────────────────────────────────────────────────────────
// M5.1's table, verbatim (`tests/exit.rs`'s, with its measured deviations), reused at
// `(proof, segment)`: the looped program must refuse the same word at the same named step.

fn tamper_table() -> Vec<(Segment, &'static str)> {
    vec![
        (Segment::Header, "header word 0"),                 // see expected_step: dynamic suffix
        (Segment::PublicValues, "quotient identity[0]"),
        (Segment::Commitments, "quotient identity[0]"),
        (Segment::LookupTerminals, "lookup terminal sum"),
        (Segment::OpenedValues, "quotient identity[0]"),
        (Segment::RandomOpenings, "sample_bits decomposition"),
        (Segment::FriCommits, "sample_bits decomposition"),
        (Segment::FinalPoly, "sample_bits decomposition"),
        (Segment::QueryPow, "sample_bits decomposition"),
        (Segment::InputOpenings, "input opening root[random]"),
        (Segment::InputPaths, "input opening root[random]"),
        (Segment::CommitPhaseOpenings, "commit phase root[0]"), // see expected_step: dynamic round
        (Segment::CommitPhasePaths, "commit phase root[0]"),
    ]
}

/// The refusal step expected for a tamper of `seg` at segment offset `off`, given the shape —
/// `tests/exit.rs`'s, verbatim.
fn expected_step(seg: Segment, off: usize, shape: &InnerShape) -> String {
    match seg {
        Segment::Header => format!("header word {off}"),
        Segment::CommitPhaseOpenings => {
            let strides: Vec<usize> = shape
                .log_arities
                .iter()
                .map(|&la| ((1usize << la) - 1) * 2 + recursion::witness::SALT_ELEMS)
                .collect();
            let query_stride: usize = strides.iter().sum();
            let mut at = off % query_stride;
            for (r, &s) in strides.iter().enumerate() {
                if at < s {
                    return format!("commit phase root[{r}]");
                }
                at -= s;
            }
            unreachable!("the offset is inside a query's run");
        }
        _ => tamper_table().into_iter().find(|(s, _)| *s == seg).unwrap().1.to_string(),
    }
}

/// One word corrupted in proof `j`'s region of an N-proof tape must be refused at the named
/// step — the loop gives every proof the single-proof program's checks, iteration `j` included.
fn refuse_at(profile: FriProfile, proofs: &[Proof], j: usize, seg: Segment, off_seed: usize) {
    let (shape, key) = shape_and_key(&proofs[0]);
    let vp = verify_rv32n(&shape, &key, Checkpoints::Off);
    let mut tape = WitnessTape::build_n(profile, &shape, &key, proofs).unwrap();
    let r = *tape
        .segment_refs()
        .iter()
        .find(|r| r.proof == j && r.segment == seg)
        .unwrap_or_else(|| panic!("proof {j} has a {seg:?} segment"));
    assert!(r.len > 0, "{seg:?} is empty");
    let off = off_seed % r.len;
    let want_step = expected_step(seg, off, &shape);
    tape.words[r.start + off] += F::ONE;
    match execute(&vp.program, &tape.words, MAX_CYCLES) {
        Err(ExecError::InverseOfZero { pc }) => assert_eq!(
            vp.program.checkpoint_at(pc),
            Some(want_step.as_str()),
            "proof {j}, tampered {seg:?}: refused at the wrong step"
        ),
        other => panic!("proof {j}, tampered {seg:?}: expected a refusal, got {other:?}"),
    }
}

/// The thirteen segment tampers, each on its own fixture's N=1 tape — `(0, segment)`, the
/// single-proof table exactly.
#[test]
fn thirteen_tampered_proofs_are_refused_at_the_named_steps() {
    let table = tamper_table();
    let proofs: Vec<Proof> = common::bundle_proofs(FriProfile::Test, table.len())
        .into_iter()
        .map(|p| p.proof)
        .collect();
    for (k, (seg, _)) in table.iter().enumerate() {
        refuse_at(FriProfile::Test, std::slice::from_ref(&proofs[k]), 0, *seg, k);
    }
}

/// The same table's killers land in later iterations too: iteration 0 completing first changes
/// nothing about how iteration `j` refuses its own tampered proof.
#[test]
fn tampers_in_later_iterations_are_refused_at_the_named_steps() {
    let proofs: Vec<Proof> =
        common::bundle_proofs(FriProfile::Test, 3).into_iter().map(|p| p.proof).collect();
    refuse_at(FriProfile::Test, &proofs, 1, Segment::OpenedValues, 0);
    refuse_at(FriProfile::Test, &proofs, 2, Segment::Commitments, 1);
    refuse_at(FriProfile::Test, &proofs, 2, Segment::Header, 3);
    refuse_at(FriProfile::Test, &proofs, 1, Segment::LookupTerminals, 0);
}
