//! The per-instance quotient layout on the RV32 machine, opt-in (feature `next-set`; monorepo
//! issue 64, ZKVM-111). The live machine commits one matrix per quotient chunk
//! (`machine::QUOTIENT_LAYOUT = PerChunk`) and that is not changed here: these tests show the
//! other layout proves and verifies through `Machine::{prove_traces_with_layout,
//! verify_with_layout}`, that neither verifier accepts the other's proofs, and what the
//! layout does to the proof. `tests/quotient_layout_heap.rs` measures the heap.
use p3_batch_stark::QuotientLayout::{self, PerChunk, PerInstance};
use rand_zkvm::emulator::execute;
use rand_zkvm::guests;
use rand_zkvm::isa::Program;
use rand_zkvm::machine::{build_traces, FriProfile, Machine, Proof, Tier, VerifyError, QUOTIENT_LAYOUT};

fn prove(m: &Machine, p: &Program, tier: Tier, layout: QuotientLayout) -> Proof {
    let exec = execute(p, &[], &[], tier.max_cycles()).unwrap();
    let traces = build_traces(p, &[], &[], &exec, tier).unwrap();
    m.prove_traces_with_layout(&traces, tier, layout)
}

#[test]
fn the_live_layout_is_per_chunk() {
    assert_eq!(QUOTIENT_LAYOUT, PerChunk);
}

/// A proof under either layout verifies under that layout and is refused under the other —
/// by the live `verify` too, which is `PerChunk`.
#[test]
fn each_layout_verifies_its_own_proofs_and_refuses_the_others() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let hc = p.digest();
    let per_chunk = prove(&m, &p, Tier(10), PerChunk);
    let per_instance = prove(&m, &p, Tier(10), PerInstance);

    m.verify(&hc, &per_chunk).expect("a PerChunk proof is a live proof");
    m.verify_with_layout(&hc, &per_chunk, PerChunk).unwrap();
    m.verify_with_layout(&hc, &per_instance, PerInstance).unwrap();

    let refused = |r: Result<(), VerifyError>| matches!(r, Err(VerifyError::Batch(_)));
    assert!(refused(m.verify(&hc, &per_instance)), "the live verifier refuses a PerInstance proof");
    assert!(refused(m.verify_with_layout(&hc, &per_instance, PerChunk)));
    assert!(refused(m.verify_with_layout(&hc, &per_chunk, PerInstance)));

    // A live proof (the ordinary `prove`) verifies under `verify_with_layout(PerChunk)`.
    let (live, _) = m.prove(&p, &[], &[], Some(Tier(10))).unwrap();
    m.verify_with_layout(&hc, &live, PerChunk).unwrap();
    assert!(refused(m.verify_with_layout(&hc, &live, PerInstance)));
}

/// The layout does not weaken what the quotient opening binds: one opened quotient value
/// changed, in any instance, and the PerInstance proof is refused. Likewise a public value.
#[test]
fn a_tampered_per_instance_proof_is_refused() {
    use p3_field::PrimeCharacteristicRing;
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let hc = p.digest();
    let proof = prove(&m, &p, Tier(10), PerInstance);
    m.verify_with_layout(&hc, &proof, PerInstance).unwrap();
    let bytes = postcard::to_allocvec(&proof).unwrap();
    let n = proof.batch.opened_values.instances.len();
    for i in 0..n {
        let mut bad: Proof = postcard::from_bytes(&bytes).unwrap();
        let chunks = &mut bad.batch.opened_values.instances[i].base_opened_values.quotient_chunks;
        let last = chunks.len() - 1;
        chunks[last][0] += rand_zkvm::machine::Challenge::ONE;
        assert!(m.verify_with_layout(&hc, &bad, PerInstance).is_err(), "instance {i}");
    }
    let mut bad: Proof = postcard::from_bytes(&bytes).unwrap();
    bad.public_values[rand_zkvm::tables::cpu::pv::OUT0] ^= 1;
    assert!(m.verify_with_layout(&hc, &bad, PerInstance).is_err());
}

/// What the layout changes in the proof: the same opened values, fewer bytes (one set of
/// random-codeword openings and one Merkle path per instance for the quotient round, not one
/// per chunk). Sizes are printed; the assertion is only the direction.
#[test]
fn the_per_instance_proof_is_smaller_and_opens_the_same_shape() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    for tier in [Tier(10), Tier(12)] {
        let a = prove(&m, &p, tier, PerChunk);
        let b = prove(&m, &p, tier, PerInstance);
        let (la, lb) = (postcard::to_allocvec(&a).unwrap().len(), postcard::to_allocvec(&b).unwrap().len());
        let chunks = |pr: &Proof| -> Vec<usize> { pr.batch.opened_values.instances.iter().map(|i| i.base_opened_values.quotient_chunks.len()).collect() };
        assert_eq!(chunks(&a), chunks(&b), "the opened values keep upstream's per-chunk shape");
        assert_eq!(a.batch.degree_bits, b.batch.degree_bits);
        eprintln!(
            "tier {}: proof bytes PerChunk {la}, PerInstance {lb} ({:.1} % smaller); quotient chunks per instance {:?} (total {})",
            tier.0,
            100.0 * (la - lb) as f64 / la as f64,
            chunks(&a),
            chunks(&a).iter().sum::<usize>()
        );
        assert!(lb < la);
    }
}

/// The constraint degree of every table, which is what stands between this machine and rate
/// 1/4: blowup 4 needs every table at degree ≤ 5 (4 quotient chunks or fewer), and the cpu and
/// alu tables are at 8. Printed for `docs/05-roadmap.md`; pinned so a change is deliberate.
#[test]
fn the_tables_that_block_blowup_4_are_cpu_and_alu() {
    use rand_zkvm::machine::max_constraint_degrees_with_modq;
    // Every chip: keccak, sha256 and modq declared at their floors.
    let degrees = max_constraint_degrees_with_modq(Tier(10), 7, 7, 7, 7, 10, 7, 12);
    let names = ["program", "cpu", "memory", "alu", "range", "nibble", "poseidon2", "input", "keccak", "sha256", "modq", "public"];
    assert_eq!(degrees.len(), names.len());
    let table: Vec<(&str, usize)> = names.iter().copied().zip(degrees.iter().copied()).collect();
    eprintln!("max constraint degree per table: {table:?}");
    let over: Vec<&str> = table.iter().filter(|(_, d)| *d > 5).map(|(n, _)| *n).collect();
    assert_eq!(over, vec!["cpu", "alu"], "the tables whose degree needs more than 4 quotient chunks");
    assert_eq!(*degrees.iter().max().unwrap(), 8);
}

// ─────────────────────────── rate 1/4 (opt-in profiles) ───────────────────────────

/// The live profiles are rate 1/8 and unchanged; the two opt-in profiles are rate 1/4 with the
/// rVM's query and grinding numbers.
#[test]
fn the_live_profiles_keep_blowup_8() {
    assert_eq!((FriProfile::Test.log_blowup(), FriProfile::Test.num_queries(), FriProfile::Test.pow_bits()), (3, 16, 4));
    assert_eq!((FriProfile::Production.log_blowup(), FriProfile::Production.num_queries(), FriProfile::Production.pow_bits()), (3, 80, 20));
    assert_eq!((FriProfile::QuarterTest.log_blowup(), FriProfile::QuarterTest.num_queries(), FriProfile::QuarterTest.pow_bits()), (2, 16, 4));
    assert_eq!((FriProfile::Quarter.log_blowup(), FriProfile::Quarter.num_queries(), FriProfile::Quarter.pow_bits()), (2, 92, 24));
    // The live profiles' postcard encodings did not move.
    assert_eq!(postcard::to_allocvec(&FriProfile::Test).unwrap(), vec![0]);
    assert_eq!(postcard::to_allocvec(&FriProfile::Production).unwrap(), vec![1]);
}

/// Does this machine prove at blowup 4 with its degree-8 cpu and alu tables as they are? The
/// rVM does (its degree-8 chips have 8 quotient chunks against blowup 4, and the PCS
/// re-extrapolates). This is the experiment for the RV32 machine, at tier 10, under both
/// layouts, with every guest in `guests::all()` that fits the tier.
#[test]
fn the_machine_proves_and_verifies_at_rate_one_quarter() {
    let m = Machine::new(FriProfile::QuarterTest);
    let live = Machine::new(FriProfile::Test);
    let mut proved = 0;
    for (name, p, inputs) in guests::all() {
        let Ok(exec) = execute(&p, &inputs, &[], Tier(10).max_cycles()) else { continue };
        let Ok(traces) = build_traces(&p, &inputs, &[], &exec, Tier(10)) else { continue };
        for layout in [PerChunk, PerInstance] {
            let proof = m.prove_traces_with_layout(&traces, Tier(10), layout);
            m.verify_with_layout(&p.digest(), &proof, layout).unwrap_or_else(|e| panic!("{name} under {layout:?}: {e:?}"));
            // A rate-1/4 proof is not a live proof.
            assert!(live.verify_with_layout(&p.digest(), &proof, layout).is_err(), "{name}: the rate-1/8 verifier accepted a rate-1/4 proof");
        }
        proved += 1;
    }
    eprintln!("rate 1/4, tier 10: {proved} guests proved and verified under both layouts");
    assert!(proved >= 5, "only {proved} guests fit tier 10");
    // And a rate-1/8 proof is refused by the rate-1/4 verifier.
    let p = guests::fib(10);
    let (proof, _) = live.prove(&p, &[], &[], Some(Tier(10))).unwrap();
    assert!(m.verify(&p.digest(), &proof).is_err());
}

/// One constraint violated, at rate 1/4: the cheating suite's simplest forgery (an output the
/// trace did not compute) is refused, so the larger quotient domain did not stop the quotient
/// from binding the constraints.
#[test]
fn a_rate_one_quarter_proof_with_a_forged_output_is_refused() {
    let m = Machine::new(FriProfile::QuarterTest);
    let p = guests::fib(10);
    let exec = execute(&p, &[], &[], Tier(10).max_cycles()).unwrap();
    let traces = build_traces(&p, &[], &[], &exec, Tier(10)).unwrap();
    let mut proof = m.prove_traces_with_layout(&traces, Tier(10), PerInstance);
    m.verify_with_layout(&p.digest(), &proof, PerInstance).unwrap();
    proof.public_values[rand_zkvm::tables::cpu::pv::OUT0] += 1;
    assert!(m.verify_with_layout(&p.digest(), &proof, PerInstance).is_err());
}
