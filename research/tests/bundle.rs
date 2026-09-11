//! The bundle guest end to end: a standalone probe for `emit_add64_carry`, honest 2-in-2-out
//! and 1-in-1-out-with-dummies proofs, and every cheating scenario the design spec calls out.
//! Follows `tests/viewing.rs`'s idiom: a logically-dishonest-but-internally-consistent witness
//! is rejected structurally (the guest's own digest disagrees with
//! `notes::expected_bundle_outputs` for the claimed plaintext — the taint-and-corrupt `bad`
//! flag has folded a nonzero word into the preimage); a trace-level tamper is rejected via
//! `rejects()`. See `docs/06-viewing-keys.md`'s "The `bundle` relation" section for the
//! soundness argument this file exercises.
//!
//! The second half of the file (Task 4) is ledger-level: `Ledger::apply_bundle`'s admission
//! order, one test per way a bundle can be refused, and the viewing layer over a bundle's two
//! output slots.
use rand_zkvm::emulator::execute;
use rand_zkvm::guests;
use rand_zkvm::ledger::{Bundle, CommitmentTree, Ledger, LedgerError};
use rand_zkvm::machine::{FriProfile, Machine, Proof, Tier, VerifyError};
use rand_zkvm::notes::{self, expected_bundle_outputs, Note, SpendKey, ViewingKey, Word8, DEPTH};
use rand_zkvm::tables::cpu;
use rand_zkvm::viewing::{scan, verify_row, Disclosure, Envelope, Role, RowError, RowSource, TxKey};
use std::sync::{Mutex, OnceLock};

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

/// A zero-amount input whose membership the guest skips (design spec §3). Built through
/// `Note::new`, never a literal `Note { .., r: [0; 8] }`: `r` is what makes two dummies in one
/// bundle distinct. With a zero `r` both dummies would hash to the same `cm_in`, hence the same
/// nullifier, and `guests::bundle`'s duplicate-input check would taint the proof. The same
/// applies to dummy *outputs*, which is why every placeholder output below is `Note::new` too.
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
        Note::new([0; 8], alice.vk.pk(), 0, asset, time),
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
        Note::new([0; 8], alice.vk.pk(), 0, asset, time),
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
        Note::new([0; 8], alice.vk.pk(), 0, asset, time),
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
        Note::new([0; 8], alice.vk.pk(), 0, claimed_asset, time),
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

/// Review round 1, finding I1: the same note spent as both inputs doubles its value — nothing
/// before the new duplicate check compares input 1 against input 2, so two copies of one real
/// note pass membership, anchor agreement and asset agreement individually (it IS the tree's
/// one real leaf, checked against the SAME anchor, twice) and the balance sum simply sees
/// `amount + amount`. `nf1 == nf2` (a nullifier is a deterministic function of `cm_in`, and
/// both inputs share the identical note/path/index here) is what the new check catches.
#[test]
fn the_same_note_spent_as_both_inputs_is_rejected() {
    let alice = Party::new();
    let (asset, time) = (0u32, 1_700_000_000u32);
    let (tree, real) = two_real_inputs(&alice, [1_000, 0 /* unused: input 2 reuses input 1 below */], asset, time);
    let inputs = [real[0], real[0]]; // the exact same (note, path, index) in both slots
    let anchor = tree.root();
    // Balances as if the guest's balance sum (which does not know the two inputs are the
    // same note) saw 1_000 + 1_000 = 2_000 in.
    let outputs = [
        Note::new(alice.vk.pk(), alice.vk.pk(), 1_500, asset, time),
        Note::new(alice.vk.pk(), alice.vk.pk(), 500, asset, time),
    ];
    let program = guests::bundle();
    let inputs_vec = notes::bundle_inputs(&alice.sk, &inputs, &outputs, anchor, 0, 0, asset, time);
    let e = execute(&program, &inputs_vec, 1 << 22).unwrap();
    assert!(e.halted);
    assert_ne!(e.outputs, expected_bundle_outputs(&alice.sk, &inputs, &outputs, anchor, 0, 0, asset, time));
}

/// Review round 1, finding I1's other half: two byte-for-byte identical output notes mint the
/// same commitment twice. Built from an otherwise-honest one-real-input-plus-dummy bundle
/// (`honest_one_in_one_out_with_dummies_proves`'s shape) with output 2 replaced by a literal
/// copy of output 1 (same `pk`, `r`, everything — `Note` is `Copy`) instead of a genuine
/// second note; the balance still conserves (`500 + 500 == 1_000`), so only the new
/// `cm_out1 == cm_out2` check can be what rejects it.
#[test]
fn identical_output_notes_are_rejected() {
    let alice = Party::new();
    let (asset, time) = (0u32, 1_700_000_000u32);
    let (tree, real) = two_real_inputs(&alice, [1_000, 0], asset, time);
    let inputs = [real[0], dummy_input(asset, time)];
    let anchor = tree.root();
    let out = Note::new(alice.vk.pk(), alice.vk.pk(), 500, asset, time);
    let outputs = [out, out]; // the exact same note, twice
    let program = guests::bundle();
    let inputs_vec = notes::bundle_inputs(&alice.sk, &inputs, &outputs, anchor, 0, 0, asset, time);
    let e = execute(&program, &inputs_vec, 1 << 22).unwrap();
    assert!(e.halted);
    assert_ne!(e.outputs, expected_bundle_outputs(&alice.sk, &inputs, &outputs, anchor, 0, 0, asset, time));
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
        Note::new([0; 8], alice.vk.pk(), 0, asset, time),
    ];
    let honest_fee = 100u64;
    let d_honest = expected_bundle_outputs(&alice.sk, &inputs, &outputs, anchor, honest_fee, 0, asset, time);
    let d_wrong_fee = expected_bundle_outputs(&alice.sk, &inputs, &outputs, anchor, honest_fee + 1, 0, asset, time);
    assert_ne!(d_honest, d_wrong_fee, "the digest is bound to fee; a caller cannot substitute a different one after the fact");
}

/// A 64-bit wrap on the output+fee+burn side, isolated from the final equality compare
/// (controller ruling, review round 1: the original version of this test — `out1 = out2 =
/// near_2_63`, `fee = near_2_63` — also fails the plain `sum_in != sum_out` equality check
/// (`0x1 != 0xffff_ffff_ffff_fffe`), so deleting the carry-fold `emit_or_into(&mut a, BAD,
/// T5)` calls would leave this test green for the wrong reason). This witness makes the
/// *wrapped* sums compare EQUAL, so only a carry fold (not the equality compare) can catch
/// it: both inputs are dummies (`amount == 0`, so `sum_in = (0, 0)` trivially and neither
/// input's membership/anchor/asset checks run at all), and `out1 = out2 = 2^63 - 1`,
/// `fee = 2`, `burn = 0` — each individually `< 2^63` (passes every range check) — sum to
/// exactly `2*(2^63-1) + 2 = 2^64`, which wraps to `sum_out = (0, 0)`, bit-for-bit equal to
/// `sum_in`. The duplicate-input/duplicate-output folds DO run here (they are outside the
/// dummy skip, and nullifiers are computed for dummies too) and are silent by construction:
/// `dummy_input` builds each dummy through `Note::new`, whose `r` is fresh OS randomness, so
/// the two dummies' `cm_in`/`nf` differ, as do the two outputs'. Verified by running (review
/// round 1) that this test discriminates: with every
/// carry-fold `emit_or_into(&mut a, BAD, T5)` call in `guests::bundle`'s conservation block
/// temporarily commented out, this exact witness is accepted (`e.outputs ==
/// expected_bundle_outputs(..)`) — see the task report for both runs.
#[test]
fn a_64_bit_wrap_in_the_balance_is_rejected() {
    let alice = Party::new();
    let (asset, time) = (0u32, 1_700_000_000u32);
    let inputs = [dummy_input(asset, time), dummy_input(asset, time)];
    let anchor = [0u32; 8]; // never read: both inputs are dummies, membership is skipped entirely
    let near_2_63 = (1u64 << 63) - 1;
    let outputs = [
        Note::new(alice.vk.pk(), alice.vk.pk(), near_2_63, asset, time),
        Note::new(alice.vk.pk(), alice.vk.pk(), near_2_63, asset, time),
    ];
    let (fee, burn) = (2u64, 0u64); // out1 + out2 + fee == 2^64 exactly, wraps to 0 == sum_in
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
        Note::new([0; 8], alice.vk.pk(), 0, asset, time),
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

// ───────────────────────── Task 4: ledger admission and viewing ─────────────────────────
//
// Everything below is ledger-level, and every test shares ONE proof: `apply_bundle` rejects
// each admission failure *before* `Machine::verify` is reached, so a rejection test needs a
// well-formed proof, not a bespoke one, and proving a 2-in-2-out bundle costs ~25 s. The
// fixture is the same consolidation bundle throughout — Alice spends two notes she was minted
// and pays Bob, keeping change — which is also exactly the shape the viewing test at the end
// needs (design spec §3's motivating case for a 2-in-2-out bundle).

/// The one honest bundle every test below starts from: Alice spends her 1 000 and 2 000 notes,
/// pays Bob 2 400, keeps 500 as change, pays a 100 fee and burns nothing
/// (`2_400 + 500 + 100 + 0 == 1_000 + 2_000`).
struct Fixture {
    alice: Party,
    bob: Party,
    bridge: Party,
    /// The two notes minted to Alice — the bundle's real inputs, and the tree's only leaves.
    in_notes: [Note; 2],
    outputs: [Note; 2],
    envelopes: [Envelope; 2],
    keys: [TxKey; 2],
    anchor: Word8,
    nullifiers: [Word8; 2],
    commitments: [Word8; 2],
    fee: u64,
    burn: u64,
    asset: u32,
    /// When the two input notes were minted, and the bundle's own `time` (60 s later).
    mint_time: u32,
    time: u32,
    /// Behind a `Mutex` only because one test (`a_malformed_proof_is_rejected_as_a_proof_error`)
    /// has to corrupt `public_values` and put them back: `Proof` is not `Clone` and a second
    /// proof would cost another ~25 s. Every other test locks it purely to read.
    proof: Mutex<Proof>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let m = Machine::new(FriProfile::Test);
        let (alice, bob, bridge) = (Party::new(), Party::new(), Party::new());
        let (asset, mint_time) = (1u32, 1_700_000_000u32);
        let mut ledger = Ledger::new(mint_time);
        let in_notes: [Note; 2] = [1_000u64, 2_000].map(|amount| {
            let n = Note::new(alice.vk.pk(), bridge.vk.pk(), amount, asset, mint_time);
            let env = Envelope::seal(&bridge.vk, &alice.vk.address(), &n, &TxKey::random());
            ledger.mint(&n, env).unwrap();
            n
        });
        ledger.advance(60);
        let (time, anchor) = (ledger.now, ledger.root());
        let inputs: [(Note, [Word8; DEPTH], u32); 2] = std::array::from_fn(|i| {
            let (path, index) = ledger.path_for(&in_notes[i].commitment()).unwrap();
            (in_notes[i], path, index)
        });
        let outputs = [
            Note::new(bob.vk.pk(), alice.vk.pk(), 2_400, asset, time),
            Note::new(alice.vk.pk(), alice.vk.pk(), 500, asset, time),
        ];
        let (fee, burn) = (100u64, 0u64);
        let keys = [TxKey::random(), TxKey::random()];
        let envelopes = [
            Envelope::seal(&alice.vk, &bob.vk.address(), &outputs[0], &keys[0]),
            Envelope::seal(&alice.vk, &alice.vk.address(), &outputs[1], &keys[1]),
        ];
        let inputs_vec = notes::bundle_inputs(&alice.sk, &inputs, &outputs, anchor, fee, burn, asset, time);
        let (proof, _) = m.prove(&ledger.bundle_program, &inputs_vec, None).unwrap();
        m.verify(&ledger.bundle_program.digest(), &proof).unwrap();
        let nullifiers = [alice.vk.nullifier(&in_notes[0].commitment()), alice.vk.nullifier(&in_notes[1].commitment())];
        let commitments = [outputs[0].commitment(), outputs[1].commitment()];
        // The proof really does publish the digest the ledger will recompute from plaintext —
        // asserted here so a fixture drift shows up as a fixture failure, not as six confusing
        // `BadDigest`s in tests that are about something else entirely.
        let published: Word8 = std::array::from_fn(|i| proof.public_values[cpu::pv::OUT0 + i] as u32);
        assert_eq!(published, notes::bundle_digest(&anchor, &nullifiers[0], &nullifiers[1], &commitments[0], &commitments[1], fee, burn, asset, time));
        Fixture { alice, bob, bridge, in_notes, outputs, envelopes, keys, anchor, nullifiers, commitments, fee, burn, asset, mint_time, time, proof: Mutex::new(proof) }
    })
}

/// A chain in exactly the state the fixture's proof was built against: the two input notes
/// minted (so the tree holds them and `root() == anchor`), the clock at the bundle's `time`.
fn fresh_ledger(f: &Fixture) -> Ledger {
    let mut ledger = Ledger::new(f.mint_time);
    for n in &f.in_notes {
        let env = Envelope::seal(&f.bridge.vk, &f.alice.vk.address(), n, &TxKey::random());
        ledger.mint(n, env).unwrap();
    }
    ledger.advance(f.time - f.mint_time);
    assert_eq!(ledger.root(), f.anchor, "the rebuilt chain must be the one the proof was made against");
    ledger
}

fn honest_bundle(f: &Fixture) -> Bundle {
    Bundle {
        anchor: f.anchor,
        nullifiers: f.nullifiers,
        commitments: f.commitments,
        fee: f.fee,
        burn: f.burn,
        asset: f.asset,
        time: f.time,
        envelopes: f.envelopes.clone(),
    }
}

/// The shared proof. Poisoning is ignored deliberately: a panic in one rejection test must not
/// turn every other test in this file into a confusing mutex error.
fn shared_proof(f: &'static Fixture) -> std::sync::MutexGuard<'static, Proof> {
    f.proof.lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn an_honest_bundle_is_admitted_and_accounted() {
    let f = fixture();
    let m = Machine::new(FriProfile::Test);
    let mut l = fresh_ledger(f);
    let b = honest_bundle(f);
    let proof = shared_proof(f);
    assert_eq!(l.apply_bundle(&m, &proof, &b).unwrap(), 0);
    assert_eq!(l.bundles.len(), 1);
    assert_eq!((l.fees_collected, l.burned), (100, 0), "fee and burn are totalled, not routed (S2/S3)");
    for nf in b.nullifiers { assert!(l.has_nullifier(&nf), "both nullifiers, dummy or not, are inserted"); }
    for cm in b.commitments { assert!(l.has_commitment(&cm), "both commitments are appended"); }
    assert_ne!(l.root(), f.anchor, "the tree grew, and the new root was recorded");
    // A replay is refused at the nullifier check, long before the proof is verified again.
    assert!(matches!(l.apply_bundle(&m, &proof, &b), Err(LedgerError::Spent(nf)) if nf == b.nullifiers[0]));
}

/// §7's "the two differ", input side. Neither nullifier is in the spent set yet, so the set
/// alone cannot see this; `guests::bundle` taints it in-circuit too, and this check is what
/// catches it without paying for a verification.
#[test]
fn a_bundle_whose_two_nullifiers_are_equal_is_rejected() {
    let f = fixture();
    let m = Machine::new(FriProfile::Test);
    let mut l = fresh_ledger(f);
    let mut b = honest_bundle(f);
    b.nullifiers[1] = b.nullifiers[0];
    assert!(matches!(l.apply_bundle(&m, &shared_proof(f), &b), Err(LedgerError::DuplicateNullifierInBundle)));
    assert!(l.bundles.is_empty());
}

/// The output-side mirror: the same commitment in both slots would be appended to the tree
/// twice, making the second leaf unreachable through `CommitmentTree::index`.
#[test]
fn a_bundle_whose_two_commitments_are_equal_is_rejected() {
    let f = fixture();
    let m = Machine::new(FriProfile::Test);
    let mut l = fresh_ledger(f);
    let mut b = honest_bundle(f);
    b.commitments[1] = b.commitments[0];
    assert!(matches!(l.apply_bundle(&m, &shared_proof(f), &b), Err(LedgerError::DuplicateCommitmentInBundle)));
    assert!(l.bundles.is_empty());
}

/// The cross-bundle case the within-bundle check cannot see: a *later* bundle reusing a
/// nullifier an earlier one already published — double-spending the same note through two
/// separate bundles.
#[test]
fn a_nullifier_spent_by_an_earlier_bundle_is_rejected() {
    let f = fixture();
    let m = Machine::new(FriProfile::Test);
    let mut l = fresh_ledger(f);
    let proof = shared_proof(f);
    l.apply_bundle(&m, &proof, &honest_bundle(f)).unwrap();
    // A second, otherwise-unrelated bundle (fresh commitments, a fresh first nullifier) whose
    // second slot re-spends the note the first bundle already consumed.
    let (other1, other2) = (
        Note::new(f.alice.vk.pk(), f.alice.vk.pk(), 7, f.asset, f.time),
        Note::new(f.alice.vk.pk(), f.alice.vk.pk(), 8, f.asset, f.time),
    );
    let mut b = honest_bundle(f);
    b.commitments = [other1.commitment(), other2.commitment()];
    b.nullifiers = [f.alice.vk.nullifier(&other1.commitment()), f.nullifiers[1]];
    assert!(matches!(l.apply_bundle(&m, &proof, &b), Err(LedgerError::Spent(nf)) if nf == f.nullifiers[1]));
    assert_eq!(l.bundles.len(), 1);
}

/// A commitment that already exists as a tree leaf — here, one of the bundle's own input
/// notes, minted long before. Appending it again would leave the original leaf in the tree but
/// unreachable through `index`/`path_for` (`CommitmentTree::append`'s documented hazard).
#[test]
fn a_commitment_already_in_the_tree_is_rejected() {
    let f = fixture();
    let m = Machine::new(FriProfile::Test);
    let mut l = fresh_ledger(f);
    let mut b = honest_bundle(f);
    b.commitments[0] = f.in_notes[0].commitment();
    let cm = b.commitments[0];
    assert!(matches!(l.apply_bundle(&m, &shared_proof(f), &b), Err(LedgerError::Duplicate(d)) if d == cm));
    assert!(l.bundles.is_empty());
}

/// The digest binds every published plaintext field, so presenting a different `fee` alongside
/// an honest proof is caught by a plain hash recomputation — no STARK involved. This is the
/// ledger-level half of `fee_not_matching_the_digest_is_detectable` above: the same tamper the
/// guest-level test shows is *detectable* is shown here to be *rejected*.
#[test]
fn a_bundle_whose_plaintext_does_not_match_the_published_digest_is_rejected() {
    let f = fixture();
    let m = Machine::new(FriProfile::Test);
    let mut l = fresh_ledger(f);
    let proof = shared_proof(f);
    let mut b = honest_bundle(f);
    b.fee += 1;
    assert!(matches!(l.apply_bundle(&m, &proof, &b), Err(LedgerError::BadDigest)));
    // The same for `burn` and `asset`, the two other bundle-level fields no other check reads.
    let mut b = honest_bundle(f);
    b.burn += 1;
    assert!(matches!(l.apply_bundle(&m, &proof, &b), Err(LedgerError::BadDigest)));
    let mut b = honest_bundle(f);
    b.asset += 1;
    assert!(matches!(l.apply_bundle(&m, &proof, &b), Err(LedgerError::BadDigest)));
    assert_eq!((l.fees_collected, l.burned), (0, 0), "a rejected bundle accumulates nothing");
    assert!(l.bundles.is_empty());
}

/// An anchor that is not a recorded root at all (one bit flipped). The anchor check runs before
/// the digest recomputation, so this is `UnknownAnchor`, not `BadDigest`, even though a
/// tampered anchor also breaks the digest.
#[test]
fn a_bundle_with_an_unknown_anchor_is_rejected() {
    let f = fixture();
    let m = Machine::new(FriProfile::Test);
    let mut l = fresh_ledger(f);
    let mut b = honest_bundle(f);
    b.anchor[0] ^= 1;
    let a = b.anchor;
    assert!(matches!(l.apply_bundle(&m, &shared_proof(f), &b), Err(LedgerError::UnknownAnchor(u)) if u == a));
}

/// The `ANCHOR_WINDOW` itself, from the bundle side: a genuine, once-current root stays valid
/// for 64 further roots and no longer. Each filler mint records exactly one root, and the
/// bundle's anchor is the newest entry when the window starts scrolling, so 63 fillers leave it
/// inside the window and 65 push it out.
#[test]
fn a_bundles_anchor_expires_after_the_anchor_window() {
    let f = fixture();
    let m = Machine::new(FriProfile::Test);
    let proof = shared_proof(f);
    let filler = |l: &mut Ledger, i: u32| {
        let to = Party::new();
        let n = Note::new(to.vk.pk(), f.bridge.vk.pk(), u64::from(i) + 1, 9, l.now);
        let env = Envelope::seal(&f.bridge.vk, &to.vk.address(), &n, &TxKey::random());
        l.mint(&n, env).unwrap();
    };
    let mut l = fresh_ledger(f);
    for i in 0..(Ledger::ANCHOR_WINDOW as u32 - 1) { filler(&mut l, i); }
    assert_ne!(l.root(), f.anchor);
    l.apply_bundle(&m, &proof, &honest_bundle(f)).expect("still inside the window");

    let mut l = fresh_ledger(f);
    for i in 0..(Ledger::ANCHOR_WINDOW as u32 + 1) { filler(&mut l, i); }
    assert!(matches!(l.apply_bundle(&m, &proof, &honest_bundle(f)), Err(LedgerError::UnknownAnchor(a)) if a == f.anchor));
}

/// §7's "`time` within 64 of the height", checked here against `now` (this crate has no block
/// height). The window exists so a prover has the same minute the `ANCHOR_WINDOW` gives it;
/// a `time` in the future is never accepted, however close.
#[test]
fn a_bundles_time_must_be_inside_the_time_window() {
    let f = fixture();
    let m = Machine::new(FriProfile::Test);
    let proof = shared_proof(f);
    let mut l = fresh_ledger(f);
    l.advance(Ledger::TIME_WINDOW);
    l.apply_bundle(&m, &proof, &honest_bundle(f)).expect("exactly TIME_WINDOW seconds old is still admissible");

    let mut l = fresh_ledger(f);
    l.advance(Ledger::TIME_WINDOW + 1);
    let now = l.now;
    assert!(matches!(l.apply_bundle(&m, &proof, &honest_bundle(f)), Err(LedgerError::Time { claimed, now: n }) if claimed == f.time && n == now));

    let mut l = fresh_ledger(f);
    let mut b = honest_bundle(f);
    b.time = l.now + 1;
    assert!(matches!(l.apply_bundle(&m, &proof, &b), Err(LedgerError::Time { .. })), "a bundle cannot claim a future time");
}

/// The two shape checks that run before anything else — a proof carrying the wrong number of
/// public values is a *proof* error (not a misleading digest mismatch), and a digest word
/// outside 32 bits, which no honest trace can produce since an output is a register word, is
/// `BadDigest` rather than a silent truncation — and the last check of all, which only a proof
/// that has passed every plaintext check ever reaches.
#[test]
fn a_malformed_proof_is_rejected_as_a_proof_error() {
    let f = fixture();
    let m = Machine::new(FriProfile::Test);
    let mut l = fresh_ledger(f);
    let b = honest_bundle(f);
    let mut proof = shared_proof(f);
    let honest_pvs = proof.public_values.clone();

    proof.public_values.pop();
    assert!(matches!(l.apply_bundle(&m, &proof, &b), Err(LedgerError::Proof(VerifyError::PublicValues))));

    proof.public_values = honest_pvs.clone();
    proof.public_values[cpu::pv::OUT0] = u64::from(u32::MAX) + 1;
    assert!(matches!(l.apply_bundle(&m, &proof, &b), Err(LedgerError::BadDigest)));

    // Step 7, the only check a proof reaches once every plaintext check has passed: the proof
    // must verify under `bundle_program`'s OWN `hc`. Corrupting `pv::HC0` leaves the published
    // digest (`OUT0..8`) untouched, so admission gets all the way to `Machine::verify` and is
    // refused there — which is also why a proof of some *other* program, a `transfer` included,
    // can never be submitted as a bundle.
    proof.public_values = honest_pvs.clone();
    proof.public_values[cpu::pv::HC0] ^= 1;
    assert!(matches!(l.apply_bundle(&m, &proof, &b), Err(LedgerError::Proof(VerifyError::PublicValues))));
    assert!(l.bundles.is_empty(), "nothing was applied by any of the three");

    proof.public_values = honest_pvs;
    l.apply_bundle(&m, &proof, &b).expect("the restored proof is the honest one again");
}

// ───────────────────────── Step 7: viewing over a bundle ─────────────────────────

/// The bundle-shaped analogue of `tests/viewing.rs::disclosure_scopes_and_row_verification`,
/// over the fixture's consolidation bundle: Alice spends both of her own notes, pays Bob and
/// keeps change, so she is the sender of both output slots and the receiver of one of them.
#[test]
fn disclosure_scopes_over_a_bundle() {
    let f = fixture();
    let m = Machine::new(FriProfile::Test);
    let mut l = fresh_ledger(f);
    l.apply_bundle(&m, &shared_proof(f), &honest_bundle(f)).unwrap();

    // Alice: the two mints she received, then the bundle — slot 0 sent (to Bob), slot 1 both
    // received (her change) and sent (she created it).
    let alice = Disclosure::Party(f.alice.vk);
    let rows = scan(&l, &alice);
    assert_eq!(
        rows.iter().map(|r| (r.source, r.tx, r.slot, r.role)).collect::<Vec<_>>(),
        vec![
            (RowSource::Transfer, 0, 0, Role::Received),
            (RowSource::Transfer, 1, 0, Role::Received),
            (RowSource::Bundle, 0, 0, Role::Sent),
            (RowSource::Bundle, 0, 1, Role::Received),
            (RowSource::Bundle, 0, 1, Role::Sent),
        ]
    );
    let bundle_rows: Vec<_> = rows.iter().filter(|r| r.source == RowSource::Bundle).collect();
    assert_eq!(bundle_rows.iter().filter(|r| r.role == Role::Sent).count(), 2, "one Sent row per output slot");
    assert_eq!(bundle_rows.iter().filter(|r| r.role == Role::Received).count(), 1, "her change output only");
    // Each Sent row names the note behind ITS OWN slot's nullifier — the consolidation's two
    // spent inputs, recovered from Alice's own history, which is the only way to recover them
    // (the spent commitments are never public).
    assert_eq!(rows[2].spent, Some(f.in_notes[0]));
    assert_eq!(rows[4].spent, Some(f.in_notes[1]));
    assert_eq!((rows[2].receiver, rows[2].amount), (f.bob.vk.pk(), 2_400));
    assert_eq!((rows[3].sender, rows[3].receiver, rows[3].amount, rows[3].asset, rows[3].time), (f.alice.vk.pk(), f.alice.vk.pk(), 500, f.asset, f.time));
    assert_eq!(rows[2].nf, Some(f.nullifiers[0]));
    assert_eq!(rows[4].nf, Some(f.nullifiers[1]));
    for r in &rows { verify_row(&l, &alice, r).unwrap(); }

    // Bob: the one output he was paid, and nothing else — not the change, not the mints.
    let bob = Disclosure::Party(f.bob.vk);
    let rows_bob = scan(&l, &bob);
    assert_eq!(rows_bob.iter().map(|r| (r.source, r.tx, r.slot, r.role, r.amount)).collect::<Vec<_>>(), vec![(RowSource::Bundle, 0, 0, Role::Received, 2_400)]);
    assert_eq!(rows_bob[0].sender, f.alice.vk.pk());
    for r in &rows_bob { verify_row(&l, &bob, r).unwrap(); }

    // The bridge minted, and has no part in the bundle at all.
    let bridge = Disclosure::Party(f.bridge.vk);
    let rows_bridge = scan(&l, &bridge);
    assert_eq!(rows_bridge.iter().map(|r| (r.source, r.role, r.spent)).collect::<Vec<_>>(), vec![(RowSource::Transfer, Role::Sent, None), (RowSource::Transfer, Role::Sent, None)]);
    for r in &rows_bridge { verify_row(&l, &bridge, r).unwrap(); }
    assert!(scan(&l, &Disclosure::Party(Party::new().vk)).is_empty(), "a stranger's key opens nothing");

    // One transaction key opens exactly its own output slot of the bundle — and nothing of the
    // mint that happens to share its index in the other sequence.
    for slot in 0..2usize {
        let one = Disclosure::Transaction { tx: 0, key: f.keys[slot] };
        let rows_one = scan(&l, &one);
        assert_eq!(rows_one.iter().map(|r| (r.source, r.slot, r.role)).collect::<Vec<_>>(), vec![(RowSource::Bundle, slot as u8, Role::Transaction)]);
        assert_eq!(rows_one[0].note, f.outputs[slot]);
        assert_eq!(rows_one[0].nf, Some(f.nullifiers[slot]));
        verify_row(&l, &one, &rows_one[0]).unwrap();
    }

    // Tampered bundle rows fail against the chain, whichever way they are bent.
    let honest = rows[2].clone();
    let mut r = honest.clone(); r.slot = 1;
    assert_eq!(verify_row(&l, &alice, &r), Err(RowError::Commitment), "slot 1's commitment is not this note's");
    let mut r = honest.clone(); r.slot = 2;
    assert_eq!(verify_row(&l, &alice, &r), Err(RowError::Slot));
    let mut r = honest.clone(); r.tx = 1;
    assert_eq!(verify_row(&l, &alice, &r), Err(RowError::UnknownTx), "there is only one bundle");
    let mut r = honest.clone(); r.source = RowSource::Transfer;
    assert_eq!(verify_row(&l, &alice, &r), Err(RowError::Commitment), "the bundle's row is not tx 0 of the transfer sequence");
    let mut r = honest.clone(); r.amount = 2_399;
    assert_eq!(verify_row(&l, &alice, &r), Err(RowError::Fields));
    let mut r = honest.clone(); r.spent = Some(f.in_notes[1]);
    assert_eq!(verify_row(&l, &alice, &r), Err(RowError::Nullifier), "slot 0's row must name slot 0's spent note");
    assert_eq!(verify_row(&l, &bob, &honest), Err(RowError::Party), "a row from one party's scope does not verify under another's");
    assert_eq!(verify_row(&l, &Disclosure::Transaction { tx: 0, key: f.keys[0] }, &honest), Err(RowError::Scope));
}
