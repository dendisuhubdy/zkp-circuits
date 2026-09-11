use rand_zkvm::guests;
use rand_zkvm::machine::{FriProfile, Machine};

/// H_IN (`pv::IN0..IN0+8`) is salted (M4.1, controller ruling) precisely so it varies between
/// two proofs of the *same* run: public values are equal everywhere else (hiding of the
/// witness/cycle-count/tier padding this test always checked), but must now *differ* inside
/// the salted commitment window, since each `prove` call draws a fresh salt from OS entropy.
#[test]
fn two_proofs_of_the_same_run_differ_and_both_verify() {
    use rand_zkvm::tables::cpu::pv;
    let m = Machine::new(FriProfile::Test);
    let p = guests::balance_check(1000);
    let inputs = [400, 250, 300, 75];
    let (a, _) = m.prove(&p, &inputs, None).unwrap();
    let (b, _) = m.prove(&p, &inputs, None).unwrap();
    assert_eq!(&a.public_values[..pv::IN0], &b.public_values[..pv::IN0], "public values outside H_IN must still agree");
    assert_eq!(&a.public_values[pv::IN0 + 8..], &b.public_values[pv::IN0 + 8..], "public values after H_IN must still agree");
    assert_ne!(&a.public_values[pv::IN0..pv::IN0 + 8], &b.public_values[pv::IN0..pv::IN0 + 8], "H_IN must be salted (hiding)");
    assert_ne!(a.to_bytes(), b.to_bytes(), "hiding commitments must randomise the proof");
    m.verify(&p.digest(), &a).unwrap();
    m.verify(&p.digest(), &b).unwrap();
}

#[test]
fn different_private_inputs_same_output_are_indistinguishable_in_public_values() {
    use rand_zkvm::tables::cpu::pv;
    let m = Machine::new(FriProfile::Test);
    let p = guests::balance_check(1000);
    let (a, _) = m.prove(&p, &[400, 250, 300, 75], None).unwrap();
    let (b, _) = m.prove(&p, &[1000, 0, 0, 0], None).unwrap();
    assert_eq!(&a.public_values[..pv::IN0], &b.public_values[..pv::IN0], "public values outside H_IN must agree");
    assert_eq!(&a.public_values[pv::IN0 + 8..], &b.public_values[pv::IN0 + 8..], "public values after H_IN must agree");
    assert_eq!(a.batch.degree_bits, b.batch.degree_bits);
}

/// H_IN is a genuine commitment to *both* the salt and the input words: fixing the salt makes
/// `pv::IN0..7` reproducible and equal to `hash::input_digest(salt, inputs)`, and changing
/// only the salt (same inputs) changes the digest.
#[test]
fn input_commitment_is_binding_to_salt_and_inputs() {
    use rand_zkvm::tables::cpu::pv;
    let m = Machine::new(FriProfile::Test);
    let p = guests::balance_check(1000);
    let inputs = [400u32, 250, 300, 75];
    let salt = [1u32, 2, 3, 4];
    let (proof, _) = m.prove_salted(&p, &inputs, salt, None).unwrap();
    let expected = rand_zkvm::hash::input_digest(salt, &inputs);
    for k in 0..8 {
        assert_eq!(proof.public_values[pv::IN0 + k], expected[k] as u64, "H_IN word {k}");
    }
    let other_salt = [5u32, 6, 7, 8];
    let other_expected = rand_zkvm::hash::input_digest(other_salt, &inputs);
    assert_ne!(expected, other_expected, "a different salt must change H_IN for the same inputs");
}
