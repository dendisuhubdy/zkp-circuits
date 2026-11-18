//! The opt-in next constraint set (`src/next_set.rs`, feature `next-set`): the poseidon2
//! table's height is declared by the proof (monorepo issue 65, ZKVM-112). Tiers 10 to 14 only.
//! The live machine is not under test here except to show it is unaffected; its own pins
//! (`verifier_key.rs`, `key_blob.rs`) are what show the current set did not move.
use p3_matrix::Matrix;
use rand_zkvm::emulator::execute;
use rand_zkvm::guests;
use rand_zkvm::isa::Program;
use rand_zkvm::machine::{self, build_traces, FriProfile, ProveError, Tier};
use rand_zkvm::next_set::{self, admitted_poseidon2_log_heights, check_poseidon2_log_height, max_poseidon2_log_height, poseidon2_log_height, VerifyError};

fn hashing_guest() -> Program {
    // 64 words through POSEIDON2: 16 absorb rows, on top of the digest rows of a program that
    // stores those 64 words one by one.
    let msg: Vec<u32> = (0..64).collect();
    guests::poseidon2_demo(&msg)
}

/// Committed main-trace cells of a run at the current set's shape and with the poseidon2 table
/// at a declared height: `(total now, poseidon2 now, total declared, poseidon2 declared)`.
/// Main columns only — no blind, LogUp or preprocessed columns.
fn main_cells(program: &Program, tier: Tier, declared: u8) -> (usize, usize, usize, usize) {
    let exec = execute(program, &[], &[], tier.max_cycles()).unwrap();
    let t = build_traces(program, &[], &[], &exec, tier).unwrap();
    let total: usize = t.as_slice().iter().map(|m| m.width() * m.height()).sum();
    let p2 = t.poseidon2.width() * t.poseidon2.height();
    let p2_declared = t.poseidon2.width() << declared;
    (total, p2, total - p2 + p2_declared, p2_declared)
}

// ─────────────────────────── the admitted set ───────────────────────────

#[test]
fn the_admitted_heights_are_the_tiers_maximum_and_every_fourth_of_it() {
    assert_eq!(admitted_poseidon2_log_heights(Tier(10)), vec![8, 10, 12]);
    assert_eq!(admitted_poseidon2_log_heights(Tier(14)), vec![8, 10, 12, 14, 16]);
    assert_eq!(admitted_poseidon2_log_heights(Tier(20)), vec![8, 10, 12, 14, 16, 18, 20, 22]);
    for t in machine::TIERS {
        let tier = Tier(t);
        let admitted = admitted_poseidon2_log_heights(tier);
        assert_eq!(*admitted.last().unwrap(), max_poseidon2_log_height(tier), "the current set's height is admitted");
        assert_eq!(1usize << max_poseidon2_log_height(tier), tier.poseidon2_height());
        assert_eq!(admitted.len(), (t - 4) / 2, "tier {t}");
        for h in 0..=40u8 {
            assert_eq!(check_poseidon2_log_height(tier, h).is_ok(), admitted.contains(&h), "tier {t}, height {h}");
        }
    }
}

#[test]
fn each_refusal_has_its_own_error() {
    let tier = Tier(12);
    assert_eq!(check_poseidon2_log_height(tier, 6), Err(VerifyError::Poseidon2HeightBelowFloor { declared: 6 }));
    assert_eq!(check_poseidon2_log_height(tier, 0), Err(VerifyError::Poseidon2HeightBelowFloor { declared: 0 }));
    assert_eq!(check_poseidon2_log_height(tier, 7), Err(VerifyError::Poseidon2HeightNotAdmitted { declared: 7 }));
    assert_eq!(check_poseidon2_log_height(tier, 11), Err(VerifyError::Poseidon2HeightNotAdmitted { declared: 11 }));
    assert_eq!(check_poseidon2_log_height(tier, 15), Err(VerifyError::Poseidon2HeightExceedsTier { declared: 15, max: 14 }));
    assert_eq!(check_poseidon2_log_height(tier, 255), Err(VerifyError::Poseidon2HeightExceedsTier { declared: 255, max: 14 }));
    assert_eq!(check_poseidon2_log_height(Tier(11), 10), Err(VerifyError::Machine(machine::VerifyError::Tier)));
    assert_eq!(check_poseidon2_log_height(Tier(99), 10), Err(VerifyError::Machine(machine::VerifyError::Tier)));
}

#[test]
fn the_declared_height_is_the_smallest_admitted_one_that_holds_the_run() {
    let tier = Tier(12);
    assert_eq!(poseidon2_log_height(tier, 0), Some(8));
    assert_eq!(poseidon2_log_height(tier, 8), Some(8), "eight blocks fill 2^8 rows");
    assert_eq!(poseidon2_log_height(tier, 9), Some(10));
    assert_eq!(poseidon2_log_height(tier, 32), Some(10));
    assert_eq!(poseidon2_log_height(tier, 33), Some(12));
    assert_eq!(poseidon2_log_height(tier, 512), Some(14));
    assert_eq!(poseidon2_log_height(tier, 513), None, "more than the tier holds");
}

// ─────────────────────────── proving and verifying ───────────────────────────

/// The issue's first acceptance line: a guest with no POSEIDON2 call proves with the poseidon2
/// table at the floor height, and the proof verifies.
#[test]
fn a_guest_that_does_not_hash_proves_at_the_floor() {
    let m = next_set::Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (proof, exec) = m.prove(&p, &[], &[], None).unwrap();
    let tier = proof.inner.tier;
    assert_eq!(next_set::permutations(&p, &[], &[], &exec), p.digest_rows() + 2, "the program digest, the input salt row and the public header row");
    assert_eq!(proof.poseidon2_log_height, 8, "the smallest admitted height");
    // The poseidon2 instance is the seventh (index 6); +1 is the hiding PCS's extra bit.
    assert_eq!(proof.inner.batch.degree_bits[6], 8 + 1);
    m.verify(&p.digest(), &proof).unwrap();
    assert_eq!(m.key_builds(), 1);
    // The same program on the live machine carries the table at 2^(t+2).
    let live = machine::Machine::new(FriProfile::Test);
    let (current, _) = live.prove(&p, &[], &[], Some(tier)).unwrap();
    assert_eq!(current.batch.degree_bits[6], tier.0 + 2 + 1);
    live.verify(&p.digest(), &current).unwrap();
    let (total, p2, total_declared, p2_declared) = main_cells(&p, tier, proof.poseidon2_log_height);
    eprintln!(
        "fib(10), tier {}: main-trace cells {total} -> {total_declared} ({:.1} % fewer); poseidon2 table {p2} -> {p2_declared}",
        tier.0,
        100.0 * (total - total_declared) as f64 / total as f64
    );
}

/// A guest that does hash declares what it needs, and one that fills the tier declares the
/// tier's height — the current set's shape.
#[test]
fn a_hashing_guest_declares_what_it_needs() {
    let m = next_set::Machine::new(FriProfile::Test);
    let p = hashing_guest();
    let (proof, exec) = m.prove(&p, &[], &[], Some(Tier(12))).unwrap();
    let perms = next_set::permutations(&p, &[], &[], &exec);
    let tier = proof.inner.tier;
    assert_eq!(Some(proof.poseidon2_log_height), poseidon2_log_height(tier, perms));
    assert!(perms * 32 <= 1 << proof.poseidon2_log_height);
    assert!(proof.poseidon2_log_height > 8 && proof.poseidon2_log_height < max_poseidon2_log_height(tier), "between the floor and the tier's height");
    m.verify(&p.digest(), &proof).unwrap();
    let (total, p2, total_declared, p2_declared) = main_cells(&p, tier, proof.poseidon2_log_height);
    eprintln!(
        "poseidon2_demo(64 words), tier {}, {perms} permutations, declared 2^{}: main-trace cells {total} -> {total_declared} ({:.1} % fewer); poseidon2 table {p2} -> {p2_declared}",
        tier.0,
        proof.poseidon2_log_height,
        100.0 * (total - total_declared) as f64 / total as f64
    );
}

/// At the tier's maximum the next set's table is the current set's: the same key.
#[test]
fn the_key_at_the_tiers_maximum_is_the_current_key() {
    let m = next_set::Machine::new(FriProfile::Test);
    let live = machine::Machine::new(FriProfile::Test);
    let tier = Tier(10);
    let next = m.verifier_key((10, 7, 7, 0, 0, 0, 7, max_poseidon2_log_height(tier)));
    let current = live.verifier_key(tier, 7, 7, 0, 0, 7);
    let bytes = |c: &p3_batch_stark::CommonData<machine::Config>| postcard::to_allocvec(&c.preprocessed.as_ref().unwrap().commitment).unwrap();
    assert_eq!(bytes(&next), bytes(&current));
    // And a lower height is a different key.
    let lower = m.verifier_key((10, 7, 7, 0, 0, 0, 7, 8));
    assert_ne!(bytes(&lower), bytes(&current));
}

/// A proof made at the tier's maximum height is a current-set proof: the live verifier accepts
/// its inner proof unchanged.
#[test]
fn a_proof_at_the_tiers_maximum_is_a_current_set_proof() {
    let m = next_set::Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (proof, _) = m.prove_declaring(&p, &[], &[], Some(Tier(10)), Some(12)).unwrap();
    m.verify(&p.digest(), &proof).unwrap();
    machine::Machine::new(FriProfile::Test).verify(&p.digest(), &proof.inner).unwrap();
    // A proof at a lower height is not: the live verifier's degree-bits check refuses it.
    let (low, _) = m.prove_declaring(&p, &[], &[], Some(Tier(10)), Some(8)).unwrap();
    assert_eq!(machine::Machine::new(FriProfile::Test).verify(&p.digest(), &low.inner), Err(machine::VerifyError::Tier));
}

// ─────────────────────────── refusals ───────────────────────────

/// The issue's second acceptance line: a declared height outside the admitted set is refused
/// before any key is built.
#[test]
fn a_height_outside_the_admitted_set_is_refused_before_any_key_is_built() {
    let prover = next_set::Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (mut proof, _) = prover.prove(&p, &[], &[], None).unwrap();
    let tier = proof.inner.tier;
    let honest = proof.poseidon2_log_height;
    // A fresh verifier, so its build count starts at zero.
    let v = next_set::Machine::new(FriProfile::Test);
    for h in (0..=64u8).chain([127, 128, 200, 255]) {
        if admitted_poseidon2_log_heights(tier).contains(&h) {
            continue;
        }
        proof.poseidon2_log_height = h;
        // What a forger would also edit, so the degree-bits comparison could not be what stops it.
        proof.inner.batch.degree_bits[6] = h as usize + 1;
        let err = v.verify(&p.digest(), &proof).unwrap_err();
        assert!(
            matches!(err, VerifyError::Poseidon2HeightBelowFloor { .. } | VerifyError::Poseidon2HeightExceedsTier { .. } | VerifyError::Poseidon2HeightNotAdmitted { .. }),
            "height {h}: {err:?}"
        );
    }
    assert_eq!(v.key_builds(), 0, "no refusal above built a key");
    // An admitted height that is not the proof's: refused by the degree-bits comparison, again
    // with no key built.
    proof.inner.batch.degree_bits[6] = honest as usize + 1;
    for h in admitted_poseidon2_log_heights(tier).into_iter().filter(|h| *h != honest) {
        proof.poseidon2_log_height = h;
        assert_eq!(v.verify(&p.digest(), &proof), Err(VerifyError::Machine(machine::VerifyError::Tier)), "height {h}");
    }
    assert_eq!(v.key_builds(), 0);
    proof.poseidon2_log_height = honest;
    v.verify(&p.digest(), &proof).unwrap();
    assert_eq!(v.key_builds(), 1);
}

/// A header and degree bits both rewritten to another admitted height get as far as the batch
/// verifier — one key build, for an admitted shape — and fail there: the proof's openings are
/// for a table of another height.
#[test]
fn a_proof_relabelled_to_another_admitted_height_fails_in_the_batch_verifier() {
    let m = next_set::Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (mut proof, _) = m.prove(&p, &[], &[], None).unwrap();
    m.verify(&p.digest(), &proof).unwrap();
    let honest = proof.poseidon2_log_height;
    let other = admitted_poseidon2_log_heights(proof.inner.tier).into_iter().find(|h| *h != honest).unwrap();
    proof.poseidon2_log_height = other;
    proof.inner.batch.degree_bits[6] = other as usize + 1;
    let err = m.verify(&p.digest(), &proof).unwrap_err();
    assert!(matches!(err, VerifyError::Machine(machine::VerifyError::Batch(_))), "{err:?}");
}

/// The prover refuses a declared height its run does not fit, or that the verifier would not
/// admit.
#[test]
fn the_prover_refuses_a_height_that_does_not_hold_the_run() {
    let m = next_set::Machine::new(FriProfile::Test);
    let p = hashing_guest();
    let (proof, _) = m.prove(&p, &[], &[], Some(Tier(12))).unwrap();
    let (tier, needed) = (proof.inner.tier, proof.poseidon2_log_height);
    assert!(needed > 8, "the guest needs more than the floor");
    for h in [needed - 2, needed - 1, 7, 0, max_poseidon2_log_height(tier) + 2] {
        assert!(
            matches!(m.prove_declaring(&p, &[], &[], Some(tier), Some(h)), Err(ProveError::TooManyPoseidon2Permutations { .. })),
            "height {h}"
        );
    }
}

/// The declared height is one byte of header; the proof round-trips.
#[test]
fn the_header_adds_one_byte() {
    let m = next_set::Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (proof, _) = m.prove(&p, &[], &[], None).unwrap();
    let next = postcard::to_allocvec(&proof).unwrap();
    let inner = postcard::to_allocvec(&proof.inner).unwrap();
    assert_eq!(next.len(), inner.len() + 1);
    let back: next_set::Proof = postcard::from_bytes(&next).unwrap();
    m.verify(&p.digest(), &back).unwrap();
    assert_eq!(next_set::CONSTRAINT_SET, machine::CONSTRAINT_SET + 1);
}

// ─────────────────────────── measurement ───────────────────────────

/// The ERC-20 transfer (the compiled EVM guest, tier 18): committed main-trace cells at the
/// current shape and with the poseidon2 table at the height this run would declare. Traces
/// only — nothing is proved (a tier-18 proof does not fit this machine; ZKVM-111), so this is
/// a cell count, not a prove-time or peak-heap figure.
///
/// ```sh
/// cargo test --release --test next_set erc20 -- --nocapture
/// ```
#[test]
fn erc20_transfer_cells_with_a_declared_poseidon2_height() {
    use evm_core::u256::U256;
    use rand_zkvm::evm::{erc20_transfer, ALICE, BOB};
    let p = guests::compiled::evm();
    let call = erc20_transfer(ALICE, BOB, U256::from_u32(250), &[(ALICE, U256::from_u32(1000))]);
    let inputs = call.input_words();
    let exec = execute(&p, &inputs, &[], Tier(20).max_cycles()).unwrap();
    let perms = next_set::permutations(&p, &inputs, &[], &exec);
    let cycles = exec.cycles() + p.digest_rows() + rand_zkvm::hash::input_digest_row_count(inputs.len()) + rand_zkvm::hash::public_digest_row_count(0);
    let tier = Tier::for_workload(cycles, perms).unwrap();
    let declared = poseidon2_log_height(tier, perms).unwrap();
    let t = build_traces(&p, &inputs, &[], &exec, tier).unwrap();
    let total: usize = t.as_slice().iter().map(|m| m.width() * m.height()).sum();
    let p2 = t.poseidon2.width() * t.poseidon2.height();
    let p2_declared = t.poseidon2.width() << declared;
    eprintln!(
        "erc20 transfer: tier {}, {cycles} cycles, {perms} poseidon2 permutations ({} of them the program digest); poseidon2 table 2^{} -> 2^{declared}; \
         main-trace cells {total} -> {} ({:.1} % fewer); poseidon2 share of main cells now {:.1} %",
        tier.0,
        p.digest_rows(),
        tier.0 + 2,
        total - p2 + p2_declared,
        100.0 * (p2 - p2_declared) as f64 / total as f64,
        100.0 * p2 as f64 / total as f64,
    );
    assert!(declared <= max_poseidon2_log_height(tier));
}
