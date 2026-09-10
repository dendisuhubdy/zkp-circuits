use rand_zkvm::guests;
use rand_zkvm::machine::{FriProfile, Machine, Tier};

#[test]
fn every_guest_proves_and_verifies() {
    let m = Machine::new(FriProfile::Test);
    for (name, program, inputs) in guests::all() {
        let (proof, exec) = m.prove(&program, &inputs, None).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(proof.tier, Tier(10), "{name} should fit the smallest tier");
        assert_eq!(proof.public_values[2], exec.outputs[0] as u64);
        m.verify(&program, &proof).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert!(proof.size() > 0);
    }
}

#[test]
fn tier_padding_hides_cycle_count() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(5);
    let (p10, e) = m.prove(&p, &[], Some(Tier(10))).unwrap();
    let (p12, _) = m.prove(&p, &[], Some(Tier(12))).unwrap();
    assert!(e.cycles() < 100);
    m.verify(&p, &p10).unwrap();
    m.verify(&p, &p12).unwrap();
    assert_ne!(p10.batch.degree_bits, p12.batch.degree_bits);
    assert_eq!(p10.public_values[1], 10);
    assert_eq!(p12.public_values[1], 12);
}

#[test]
fn a_fresh_verifier_accepts_the_proof() {
    let prover = Machine::new(FriProfile::Test);
    let verifier = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (proof, _) = prover.prove(&p, &[], None).unwrap();
    verifier.verify(&p, &proof).unwrap();
    assert_eq!(prover.code_hash(&p, proof.tier), verifier.code_hash(&p, proof.tier));
    assert_ne!(prover.code_hash(&p, proof.tier), verifier.code_hash(&guests::fib(11), proof.tier));
}

#[test]
fn verifier_key_is_cached_after_first_verify() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (proof, _) = m.prove(&p, &[], None).unwrap();
    let t0 = std::time::Instant::now();
    m.verify(&p, &proof).unwrap();
    let first = t0.elapsed();
    let t1 = std::time::Instant::now();
    m.verify(&p, &proof).unwrap();
    let second = t1.elapsed();
    assert!(
        second < first / 10,
        "cached verify should be under 10% of the first: first={first:?} second={second:?}"
    );
    assert_eq!(m.cached_keys(), 1);
}

#[test]
#[ignore]
fn measure_production_profile_at_tier_10_and_12() {
    let m = Machine::new(FriProfile::Production);
    // `fib(650)` runs 3910 cycles: past tier 10's max (1023) and within tier 12's max
    // (4095), so `prove(.., Some(Tier(12)))` actually exercises tier 12's padded height
    // rather than erroring `TooManyCycles` (as `fib(900)`, 5410 cycles, does).
    for (label, tier, n) in [("tier 10", Tier(10), 10u32), ("tier 12", Tier(12), 650u32)] {
        let p = guests::fib(n);
        let t0 = std::time::Instant::now();
        let (proof, _) = m.prove(&p, &[], Some(tier)).unwrap();
        let prove_time = t0.elapsed();
        let t1 = std::time::Instant::now();
        m.verify(&p, &proof).unwrap();
        let verify_time = t1.elapsed();
        println!("{label}: proof size = {} bytes, prove = {:?}, verify = {:?}", proof.size(), prove_time, verify_time);
    }
}
