//! The bundle guest end to end: a standalone probe for `emit_add64_carry`, honest 2-in-2-out
//! and 1-in-1-out-with-dummies proofs, and every cheating scenario the design spec calls out.
//! Follows `tests/viewing.rs`'s idiom: a logically-dishonest-but-internally-consistent witness
//! is rejected structurally (the guest's own digest disagrees with
//! `notes::expected_bundle_outputs` for the claimed plaintext — the taint-and-corrupt `bad`
//! flag has folded a nonzero word into the preimage); a trace-level tamper is rejected via
//! `rejects()`. See `docs/06-viewing-keys.md`'s "The `bundle` relation" section for the
//! soundness argument this file exercises.
use rand_zkvm::emulator::execute;
use rand_zkvm::guests;
use rand_zkvm::ledger::CommitmentTree;
use rand_zkvm::machine::{FriProfile, Machine, Tier};
use rand_zkvm::notes::{self, expected_bundle_outputs, Note, SpendKey, ViewingKey, Word8, DEPTH};

struct Party { sk: SpendKey, vk: ViewingKey }
impl Party { fn new() -> Party { let sk = SpendKey::random(); Party { sk, vk: sk.viewing_key() } } }

/// A tree with two real notes owned by `owner`, ready to spend as a bundle's two inputs.
fn two_real_inputs(owner: &Party, amounts: [u64; 2], asset: u32, time: u32) -> (CommitmentTree, [(Note, [Word8; DEPTH], u32); 2]) {
    let mut tree = CommitmentTree::new();
    let notes: Vec<Note> = amounts.iter().map(|&amt| Note::new(owner.vk.pk(), Party::new().vk.pk(), amt, asset, time)).collect();
    for n in &notes { tree.append(n.commitment()); }
    let ins = std::array::from_fn(|i| { let (p, idx) = tree.path_for(&notes[i].commitment()).unwrap(); (notes[i], p, idx) });
    (tree, ins)
}

fn dummy_input(asset: u32, time: u32) -> (Note, [Word8; DEPTH], u32) {
    (Note::new([0; 8], [0; 8], 0, asset, time), [[0; 8]; DEPTH], 0)
}

// ───────────────────────── Step 4: emit_add64_carry standalone probe ─────────────────────────

/// Runs `emit_add64_carry` through a tiny probe program: `sum := a`, then `sum += b`, publish
/// `(sum_lo, sum_hi, carry_out)`. Compared against `u128` addition (`sum_lo`/`sum_hi` are the
/// low 64 bits of `a as u128 + b as u128`, wrapped exactly like a native `u64::wrapping_add`;
/// `carry_out` is whether that widened sum's bit 64 is set).
fn add64_probe(a: u64, b: u64) -> (u32, u32, u32) {
    use rand_zkvm::asm::{emit_add64_carry, ops::*, Assembler};
    const SUM_LO: u32 = 5; // t0
    const SUM_HI: u32 = 6; // t1
    const LO: u32 = 7;     // t2
    const HI: u32 = 28;    // t3
    const TMP: u32 = 29;   // t4
    const CARRY: u32 = 30; // t5
    let mut asm = Assembler::new(0);
    asm.extend(li(SUM_LO, a as u32 as i32));
    asm.extend(li(SUM_HI, (a >> 32) as u32 as i32));
    asm.extend(li(LO, b as u32 as i32));
    asm.extend(li(HI, (b >> 32) as u32 as i32));
    emit_add64_carry(&mut asm, SUM_LO, SUM_HI, LO, HI, TMP, CARRY);
    asm.extend(write_output(0, SUM_LO));
    asm.extend(write_output(1, SUM_HI));
    asm.extend(write_output(2, CARRY));
    asm.extend(halt());
    let program = asm.assemble();
    let e = execute(&program, &[], 1 << 16).unwrap();
    assert!(e.halted);
    (e.outputs[0], e.outputs[1], e.outputs[2])
}

#[test]
fn add64_carry_matches_u128_addition() {
    let cases: [(u64, u64); 6] = [
        (0, 0),
        (1_000, 2_000),
        (u32::MAX as u64, 1),                      // low-word carry only, no high overflow
        ((1u64 << 63) - 1, (1u64 << 63) - 1),      // both < 2^63, sum just under 2^64
        (u64::MAX, 1),                             // wraps exactly at 2^64
        (u64::MAX, u64::MAX),                      // wraps well past 2^64
    ];
    for (a, b) in cases {
        let (sum_lo, sum_hi, carry_out) = add64_probe(a, b);
        let wide = a as u128 + b as u128;
        let expected_lo = wide as u32;
        let expected_hi = (wide >> 32) as u32;
        let expected_carry = if (wide >> 64) != 0 { 1u32 } else { 0 };
        assert_eq!((sum_lo, sum_hi, carry_out), (expected_lo, expected_hi, expected_carry), "a={a:#x} b={b:#x}");
    }
}

// ───────────────────────── Step 6: honest bundles ─────────────────────────

#[test]
fn honest_two_in_two_out_proves_and_verifies() {
    let m = Machine::new(FriProfile::Test);
    let (alice, bob) = (Party::new(), Party::new());
    let (asset, time) = (0u32, 1_700_000_000u32);
    let (tree, inputs) = two_real_inputs(&alice, [1_000, 2_000], asset, time);
    let anchor = tree.root();
    // Conservation (design spec §4): in1 + in2 == out1 + out2 + fee + burn, i.e.
    // 1_000 + 2_000 == 2_400 + 500 + 100 + 0.
    let outputs = [
        Note::new(bob.vk.pk(), alice.vk.pk(), 2_400, asset, time),
        Note::new(alice.vk.pk(), alice.vk.pk(), 500, asset, time),
    ];
    let fee = 100u64;
    let burn = 0u64;
    let program = guests::bundle();
    let inputs_vec = notes::bundle_inputs(&alice.sk, &inputs, &outputs, anchor, fee, burn, asset, time);
    let e = execute(&program, &inputs_vec, 1 << 22).unwrap();
    assert!(e.halted);
    assert_eq!(e.outputs, expected_bundle_outputs(&alice.sk, &inputs, &outputs, anchor, fee, burn, asset, time));
    let permutations = e.events.iter().filter(|ev| matches!(ev.hash_row, Some(rand_zkvm::emulator::HashRow::Absorb { .. }))).count();
    let hash_calls = e.events.iter().filter(|ev| matches!(ev.hash_row, Some(rand_zkvm::emulator::HashRow::Ecall { .. }))).count();
    let (proof, exec) = m.prove(&program, &inputs_vec, None).unwrap();
    let total_permutations = permutations + program.digest_rows();
    eprintln!("bundle 2-in-2-out: {} words, {} exec cycles, {} hash calls, {} exec permutations, {} digest rows, {} total permutations, tier {:?}",
        program.len(), exec.cycles(), hash_calls, permutations, program.digest_rows(), total_permutations, proof.tier);
    m.verify(&program.digest(), &proof).unwrap();
}

#[test]
fn honest_one_in_one_out_with_dummies_proves() {
    let m = Machine::new(FriProfile::Test);
    let alice = Party::new();
    let (asset, time) = (0u32, 1_700_000_000u32);
    let (tree, real) = two_real_inputs(&alice, [1_000, 0 /* unused */], asset, time);
    let inputs = [real[0], dummy_input(asset, time)];
    let anchor = tree.root();
    let outputs = [
        Note::new(alice.vk.pk(), alice.vk.pk(), 900, asset, time),
        Note { pk: [0; 8], from: alice.vk.pk(), amount: 0, asset, time, r: [0; 8] },
    ];
    let (fee, burn) = (100u64, 0u64);
    let program = guests::bundle();
    let inputs_vec = notes::bundle_inputs(&alice.sk, &inputs, &outputs, anchor, fee, burn, asset, time);
    let e = execute(&program, &inputs_vec, 1 << 22).unwrap();
    assert!(e.halted);
    assert_eq!(e.outputs, expected_bundle_outputs(&alice.sk, &inputs, &outputs, anchor, fee, burn, asset, time));
    let permutations = e.events.iter().filter(|ev| matches!(ev.hash_row, Some(rand_zkvm::emulator::HashRow::Absorb { .. }))).count();
    let hash_calls = e.events.iter().filter(|ev| matches!(ev.hash_row, Some(rand_zkvm::emulator::HashRow::Ecall { .. }))).count();
    let (proof, exec) = m.prove(&program, &inputs_vec, None).unwrap();
    let total_permutations = permutations + program.digest_rows();
    eprintln!("bundle 1-in-1-out-with-dummies: {} words, {} exec cycles, {} hash calls, {} exec permutations, {} digest rows, {} total permutations, tier {:?}",
        program.len(), exec.cycles(), hash_calls, permutations, program.digest_rows(), total_permutations, proof.tier);
    m.verify(&program.digest(), &proof).unwrap();
}

// ───────────────────────── Step 7: structural cheats ─────────────────────────

/// Outputs (+ fee + burn) exceed inputs: the `bad` flag's balance check catches it, corrupting
/// the digest. The STARK verifies (the guest ran faithfully on a dishonest input vector); the
/// digest the honest fixture *would* expect for the claimed (anchor, fee, burn, asset, time)
/// does not match what the guest actually published.
#[test]
fn over_spend_is_rejected() {
    let m = Machine::new(FriProfile::Test);
    let alice = Party::new();
    let (asset, time) = (0u32, 1_700_000_000u32);
    let (tree, real) = two_real_inputs(&alice, [1_000, 0], asset, time);
    let inputs = [real[0], dummy_input(asset, time)];
    let anchor = tree.root();
    // Claim 1_000 out of a note worth only 1_000, plus a 100-unit fee: 1_100 > 1_000.
    let outputs = [
        Note::new(alice.vk.pk(), alice.vk.pk(), 1_000, asset, time),
        Note { pk: [0; 8], from: alice.vk.pk(), amount: 0, asset, time, r: [0; 8] },
    ];
    let (fee, burn) = (100u64, 0u64);
    let program = guests::bundle();
    let inputs_vec = notes::bundle_inputs(&alice.sk, &inputs, &outputs, anchor, fee, burn, asset, time);
    let e = execute(&program, &inputs_vec, 1 << 22).unwrap();
    assert!(e.halted, "the guest runs to completion on any well-typed input vector");
    let expected_if_honest = expected_bundle_outputs(&alice.sk, &inputs, &outputs, anchor, fee, burn, asset, time);
    assert_ne!(e.outputs, expected_if_honest, "the bad flag corrupts the digest an honest run would have produced");
    let (proof, _) = m.prove(&program, &inputs_vec, None).unwrap();
    assert!(m.verify(&program.digest(), &proof).is_ok(), "the STARK verifies: the guest faithfully computed ITS OWN (corrupted) digest");
}

/// A real input (amount > 0) with a wrong Merkle path: the corrupted root fails `emit_eq8`
/// against `anchor`, setting `bad` — same corrupted-digest pattern as over-spend.
#[test]
fn a_real_input_with_a_wrong_path_is_rejected() {
    let alice = Party::new();
    let (asset, time) = (0u32, 1_700_000_000u32);
    let (tree, mut real) = two_real_inputs(&alice, [1_000, 500], asset, time);
    real[0].1[0][0] ^= 1; // tamper input 1's immediate sibling
    let anchor = tree.root();
    let outputs = [
        Note::new(alice.vk.pk(), alice.vk.pk(), 1_000, asset, time),
        Note::new(alice.vk.pk(), alice.vk.pk(), 500, asset, time),
    ];
    let (fee, burn) = (0u64, 0u64);
    let program = guests::bundle();
    let inputs_vec = notes::bundle_inputs(&alice.sk, &real, &outputs, anchor, fee, burn, asset, time);
    let e = execute(&program, &inputs_vec, 1 << 22).unwrap();
    assert!(e.halted);
    assert_ne!(e.outputs, expected_bundle_outputs(&alice.sk, &real, &outputs, anchor, fee, burn, asset, time));
}

/// A dummy input (amount == 0) with a wrong path is FINE — membership is skipped, the path is
/// never read. This is the mirror image of the previous test and documents the boundary: it is
/// amount, not path validity, that gates the skip.
#[test]
fn a_dummy_input_with_a_garbage_path_still_proves() {
    let m = Machine::new(FriProfile::Test);
    let alice = Party::new();
    let (asset, time) = (0u32, 1_700_000_000u32);
    let (tree, real) = two_real_inputs(&alice, [1_000, 0], asset, time);
    let mut dummy = dummy_input(asset, time);
    dummy.1[0] = [0xffff_ffff; 8]; // garbage path — irrelevant since amount == 0
    let inputs = [real[0], dummy];
    let anchor = tree.root();
    let outputs = [
        Note::new(alice.vk.pk(), alice.vk.pk(), 1_000, asset, time),
        Note { pk: [0; 8], from: alice.vk.pk(), amount: 0, asset, time, r: [0; 8] },
    ];
    let program = guests::bundle();
    let inputs_vec = notes::bundle_inputs(&alice.sk, &inputs, &outputs, anchor, 0, 0, asset, time);
    let e = execute(&program, &inputs_vec, 1 << 22).unwrap();
    assert!(e.halted);
    assert_eq!(e.outputs, expected_bundle_outputs(&alice.sk, &inputs, &outputs, anchor, 0, 0, asset, time), "a dummy's path is never read, garbage or not");
    let (proof, _) = m.prove(&program, &inputs_vec, None).unwrap();
    m.verify(&program.digest(), &proof).unwrap();
}

/// The exact scenario the design task calls out by name: try to claim amount > 0 on an input
/// while *hoping* to skip membership by handing it no valid path. It is UNCONSTRUCTIBLE, not
/// merely rejected — the skip branch's own condition (`amount_lo | amount_hi == 0`) reads the
/// same words that make the amount nonzero, so a nonzero amount deterministically takes the
/// membership-check branch instead, using whatever garbage path was supplied — this test shows
/// that path, ending in the same corrupted-digest rejection as
/// `a_real_input_with_a_wrong_path_is_rejected` (because that IS what happens: there is no
/// separate "skip was fooled" code path to exercise).
#[test]
fn a_nonzero_amount_cannot_skip_membership() {
    let alice = Party::new();
    let (asset, time) = (0u32, 1_700_000_000u32);
    let (tree, real) = two_real_inputs(&alice, [1_000, 0], asset, time);
    let mut fake_dummy = dummy_input(asset, time); // amount == 0, garbage path, as a real dummy would have
    fake_dummy.0.amount = 500; // attacker tries to sneak in value while keeping the garbage path
    let inputs = [real[0], fake_dummy];
    let anchor = tree.root();
    let outputs = [
        Note::new(alice.vk.pk(), alice.vk.pk(), 1_000, asset, time),
        Note::new(alice.vk.pk(), alice.vk.pk(), 500, asset, time),
    ];
    let program = guests::bundle();
    let inputs_vec = notes::bundle_inputs(&alice.sk, &inputs, &outputs, anchor, 0, 0, asset, time);
    let e = execute(&program, &inputs_vec, 1 << 22).unwrap();
    assert!(e.halted, "the branch condition reads amount, not a separate 'is dummy' flag — there is nothing to crash on");
    assert_ne!(e.outputs, expected_bundle_outputs(&alice.sk, &inputs, &outputs, anchor, 0, 0, asset, time), "input 2's garbage path was used for real, since amount != 0 forced the membership branch");
}

/// A real note whose committed asset differs from the bundle's declared public asset. Resolved
/// per the plan's "Ambiguities resolved": the guest checks each real input's own `asset` field
/// against the bundle's public `asset`, gated on that input's `amount != 0` branch (mirroring
/// the anchor-agreement check) — so a note actually created under a different asset, spent into
/// a bundle labelled with a different asset, sets `bad` and corrupts the digest, exactly like
/// every other structural-rejection test in this file.
#[test]
fn asset_mismatch_is_rejected() {
    let alice = Party::new();
    let (real_asset, claimed_asset, time) = (1u32, 2u32, 1_700_000_000u32);
    let (tree, real) = two_real_inputs(&alice, [1_000, 0], real_asset, time);
    let inputs = [real[0], dummy_input(claimed_asset, time)];
    let anchor = tree.root();
    let outputs = [
        Note::new(alice.vk.pk(), alice.vk.pk(), 1_000, claimed_asset, time),
        Note { pk: [0; 8], from: alice.vk.pk(), amount: 0, asset: claimed_asset, time, r: [0; 8] },
    ];
    let program = guests::bundle();
    // Declares asset = claimed_asset (2), but input 1's real note (and tree leaf) was created
    // under real_asset (1) — bundle_inputs still writes IN1_ASSET from the note's own field
    // (1), so cm_in/nullifier/MERKLE_VERIFY all succeed (the tree leaf really was hashed with
    // asset=1); the guest's separate per-input asset check (IN1_ASSET vs the bundle's public
    // ASSET field) is what catches the mismatch and sets `bad`.
    let inputs_vec = notes::bundle_inputs(&alice.sk, &inputs, &outputs, anchor, 0, 0, claimed_asset, time);
    let e = execute(&program, &inputs_vec, 1 << 22).unwrap();
    assert!(e.halted);
    assert_ne!(e.outputs, expected_bundle_outputs(&alice.sk, &inputs, &outputs, anchor, 0, 0, claimed_asset, time));
}

// ───────────────────────── Step 8: fee/digest binding, 64-bit wrap, one true rejects() ─────────────────────────

/// Not a guest-level cheat at all: the digest is a pure function of the plaintext it was built
/// from, so a caller who tries to present a DIFFERENT fee than the one actually folded into the
/// proof's digest simply gets a different expected value — this is what makes
/// `Ledger::apply_bundle` (Task 4) able to catch it with a plain equality check, no STARK
/// involved.
#[test]
fn fee_not_matching_the_digest_is_detectable() {
    let alice = Party::new();
    let bob = Party::new();
    let (asset, time) = (0u32, 1_700_000_000u32);
    let (tree, real) = two_real_inputs(&alice, [1_000, 0], asset, time);
    let inputs = [real[0], dummy_input(asset, time)];
    let anchor = tree.root();
    let outputs = [
        Note::new(bob.vk.pk(), alice.vk.pk(), 900, asset, time),
        Note { pk: [0; 8], from: alice.vk.pk(), amount: 0, asset, time, r: [0; 8] },
    ];
    let honest_fee = 100u64;
    let d_honest = expected_bundle_outputs(&alice.sk, &inputs, &outputs, anchor, honest_fee, 0, asset, time);
    let d_wrong_fee = expected_bundle_outputs(&alice.sk, &inputs, &outputs, anchor, honest_fee + 1, 0, asset, time);
    assert_ne!(d_honest, d_wrong_fee, "the digest is bound to fee; a caller cannot substitute a different one after the fact");
}

/// A 64-bit wrap on the output+fee+burn side: three amounts individually under 2^63 whose sum
/// exceeds 2^64 (their combined true value is far more than the inputs actually hold) — the
/// final add64 carry-out sets `bad`.
#[test]
fn a_64_bit_wrap_in_the_balance_is_rejected() {
    let alice = Party::new();
    let (asset, time) = (0u32, 1_700_000_000u32);
    let (tree, real) = two_real_inputs(&alice, [1, 0], asset, time); // trivial real input value
    let inputs = [real[0], dummy_input(asset, time)];
    let anchor = tree.root();
    let near_2_63 = (1u64 << 63) - 1;
    let outputs = [
        Note::new(alice.vk.pk(), alice.vk.pk(), near_2_63, asset, time),
        Note::new(alice.vk.pk(), alice.vk.pk(), near_2_63, asset, time),
    ];
    let (fee, burn) = (near_2_63, 0u64); // out1+out2+fee alone already exceeds 2^64
    let program = guests::bundle();
    let inputs_vec = notes::bundle_inputs(&alice.sk, &inputs, &outputs, anchor, fee, burn, asset, time);
    let e = execute(&program, &inputs_vec, 1 << 22).unwrap();
    assert!(e.halted);
    assert_ne!(e.outputs, expected_bundle_outputs(&alice.sk, &inputs, &outputs, anchor, fee, burn, asset, time));
}

/// The one genuine STARK-level rejection in this file, mirroring
/// `tests/viewing.rs::a_viewing_key_cannot_spend`'s tail: directly overwrite the honestly-
/// computed public digest in the built `Traces` with a hand-picked "nicer looking" value. The
/// write-back rows pin the public-value columns to what the emulator actually put in RAM, so
/// this is a real constraint violation, not a logic-level cheat.
#[test]
fn tampering_the_published_digest_directly_is_a_constraint_violation() {
    use p3_field::PrimeCharacteristicRing;
    use rand_zkvm::machine::build_traces_salted;
    use rand_zkvm::tables::{cpu, F};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    fn rejects(f: impl FnOnce() -> Result<(), rand_zkvm::machine::VerifyError>) -> bool {
        match catch_unwind(AssertUnwindSafe(f)) {
            Ok(Ok(())) => false,
            Ok(Err(_)) => true,
            Err(p) => p.downcast_ref::<&str>().map(|s| s.contains("constraints not satisfied on row")).unwrap_or(false)
                || p.downcast_ref::<String>().map(|s| s.contains("constraints not satisfied on row")).unwrap_or(false),
        }
    }
    let m = Machine::new(FriProfile::Test);
    let alice = Party::new();
    let (asset, time) = (0u32, 1_700_000_000u32);
    let (tree, real) = two_real_inputs(&alice, [1_000, 0], asset, time);
    let inputs = [real[0], dummy_input(asset, time)];
    let anchor = tree.root();
    let outputs = [
        Note::new(alice.vk.pk(), alice.vk.pk(), 1_000, asset, time),
        Note { pk: [0; 8], from: alice.vk.pk(), amount: 0, asset, time, r: [0; 8] },
    ];
    let program = guests::bundle();
    let inputs_vec = notes::bundle_inputs(&alice.sk, &inputs, &outputs, anchor, 0, 0, asset, time);
    let e = execute(&program, &inputs_vec, 1 << 22).unwrap();
    // Use the honest 2-in-2-out proof's measured tier (Step 6's eprintln!) so the salted trace
    // is built at the same height `prove_traces` expects.
    let tier = Tier(14);
    let mut t = build_traces_salted(&program, &inputs_vec, [0u32; 4], &e, tier).unwrap();
    t.public_values[cpu::pv::OUT0] += F::ONE;
    assert!(rejects(|| { let p = m.prove_traces(&program, &t, tier); m.verify(&program.digest(), &p) }));
}
