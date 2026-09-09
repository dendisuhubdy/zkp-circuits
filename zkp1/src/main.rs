//! Narrated demo. Run with `cargo run --release`.

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use std::time::Instant;

use zkp1::cubic::CubicCircuit;
use zkp1::mimc::{mimc, short_hex, MimcPreimageCircuit, ROUNDS};
use zkp1::snark;
use zkp1::Fr;

fn banner(s: &str) {
    println!("\n══════════════════════════════════════════════════════════════");
    println!("  {s}");
    println!("══════════════════════════════════════════════════════════════");
}

fn main() {
    let mut rng = rand::rngs::OsRng;

    banner("PART 1  ·  x³ + x + 5 = 35  (raw R1CS)");
    println!(
        "Statement : \"I know x such that x³ + x + 5 = 35\"\n\
         Witness   : x = 3   (kept secret)\n\
         Public    : out = 35"
    );

    // Inspect the constraint system on its own, before any cryptography.
    let x = Fr::from(3u64);
    let out = CubicCircuit::eval(x);
    let cs = ConstraintSystem::<Fr>::new_ref();
    CubicCircuit { x: Some(x), out: Some(out) }.generate_constraints(cs.clone()).unwrap();
    println!("\nConstraint system:");
    println!("  constraints        : {}", cs.num_constraints());
    println!("  public input wires : {}  (+1 for the constant wire '1')", cs.num_instance_variables() - 1);
    println!("  private wires      : {}  (x, x², x³)", cs.num_witness_variables());
    println!("  satisfied by x=3?  : {}", cs.is_satisfied().unwrap());

    let cs_bad = ConstraintSystem::<Fr>::new_ref();
    CubicCircuit { x: Some(Fr::from(4u64)), out: Some(out) }.generate_constraints(cs_bad.clone()).unwrap();
    println!("  satisfied by x=4?  : {}", cs_bad.is_satisfied().unwrap());

    // 1. Setup
    println!("\n[1] Trusted setup — depends only on the circuit's shape, not on x");
    let t = Instant::now();
    let (pk, vk) = snark::setup(CubicCircuit { x: None, out: None }, &mut rng);
    println!("    proving key  : {:>7} bytes", snark::size_of(&pk));
    println!("    verifying key: {:>7} bytes", snark::size_of(&vk));
    println!("    took {:?}", t.elapsed());

    // 2. Prove
    println!("\n[2] Prove — uses the proving key + the secret witness");
    let t = Instant::now();
    let proof = snark::prove(&pk, CubicCircuit { x: Some(x), out: Some(out) }, &mut rng).unwrap();
    println!("    proof        : {:>7} bytes  (3 curve points: A, B, C)", snark::size_of(&proof));
    println!("    took {:?}", t.elapsed());

    // 3. Verify
    println!("\n[3] Verify — uses ONLY the verifying key, the public input, the proof");
    let t = Instant::now();
    let ok = snark::verify(&vk, &[out], &proof);
    println!("    public input out=35  → accepted = {ok}   ({:?})", t.elapsed());
    let ok_wrong = snark::verify(&vk, &[Fr::from(36u64)], &proof);
    println!("    public input out=36  → accepted = {ok_wrong}   (same proof, different claim)");

    // A dishonest prover.
    // Groth16's prover does not return an error for a bad witness: in debug builds
    // it hits a `debug_assert!(cs.is_satisfied())` and panics, and in release builds
    // it happily emits a proof that the verifier rejects. A real prover checks its
    // own witness first, so we do that here and only call `prove` on a good one.
    println!("\n[4] A cheating prover tries x=4 for out=35");
    let cheat = CubicCircuit { x: Some(Fr::from(4u64)), out: Some(out) };
    let cs_cheat = ConstraintSystem::<Fr>::new_ref();
    cheat.clone().generate_constraints(cs_cheat.clone()).unwrap();
    if cs_cheat.is_satisfied().unwrap() {
        let bad = snark::prove(&pk, cheat, &mut rng).unwrap();
        println!("    produced a proof; verifier accepts = {}", snark::verify(&vk, &[out], &bad));
    } else {
        println!("    prover refused: witness x=4 does not satisfy the constraints (4³+4+5 = 73 ≠ 35)");
        println!("    (Groth16 itself doesn't check; a proof forged from a bad witness simply fails to verify.)");
    }

    // Zero-knowledge, visibly
    println!("\n[5] Zero-knowledge: two proofs of the same statement");
    let p1 = snark::prove(&pk, CubicCircuit { x: Some(x), out: Some(out) }, &mut rng).unwrap();
    let p2 = snark::prove(&pk, CubicCircuit { x: Some(x), out: Some(out) }, &mut rng).unwrap();
    let (mut b1, mut b2) = (Vec::new(), Vec::new());
    p1.serialize_compressed(&mut b1).unwrap();
    p2.serialize_compressed(&mut b2).unwrap();
    println!("    proof #1 : {}…", hex(&b1[..16]));
    println!("    proof #2 : {}…", hex(&b2[..16]));
    println!("    identical bytes? {}   both verify? {}", b1 == b2, snark::verify(&vk, &[out], &p1) && snark::verify(&vk, &[out], &p2));
    println!("    The prover adds fresh randomness each time; the witness is never in the bytes.");

    banner("PART 2  ·  hash preimage  MiMC(x) = h  (gadgets)");
    let secret = Fr::from(0xDEAD_BEEF_u64);
    let key = Fr::from(0u64);
    let h = mimc(secret, key);
    println!(
        "Statement : \"I know x such that MiMC(x) = h\"\n\
         Witness   : x = 0xdeadbeef  (kept secret)\n\
         Public    : h = {}\n\
         Rounds    : {}",
        short_hex(&h),
        ROUNDS
    );

    let cs = ConstraintSystem::<Fr>::new_ref();
    MimcPreimageCircuit::with_secret(secret, key).generate_constraints(cs.clone()).unwrap();
    println!("\nConstraint system:");
    println!("  constraints : {}  (4 per round × {} rounds + 1 equality)", cs.num_constraints(), ROUNDS);

    println!("\n[1] Setup");
    let t = Instant::now();
    let (pk, vk) = snark::setup(MimcPreimageCircuit::blank(), &mut rng);
    println!("    proving key  : {:>7} bytes   ({:?})", snark::size_of(&pk), t.elapsed());
    println!("    verifying key: {:>7} bytes", snark::size_of(&vk));

    println!("\n[2] Prove");
    let t = Instant::now();
    let circuit = MimcPreimageCircuit::with_secret(secret, key);
    let public = circuit.public_inputs();
    let proof = snark::prove(&pk, circuit, &mut rng).unwrap();
    println!("    proof        : {:>7} bytes   ({:?})  ← same size as Part 1", snark::size_of(&proof), t.elapsed());

    println!("\n[3] Verify");
    let t = Instant::now();
    println!("    correct h    → accepted = {}   ({:?})", snark::verify(&vk, &public, &proof), t.elapsed());
    let wrong_h = mimc(Fr::from(1u64), key);
    println!("    different h  → accepted = {}", snark::verify(&vk, &[key, wrong_h], &proof));

    banner("TAKEAWAYS");
    println!(
        "• A circuit is a list of  A·B = C  equations over a prime field.\n\
         • Setup fixes the circuit; prove needs the witness; verify never sees it.\n\
         • Proof size and verify time are constant — 41 vs 3 constraints, same 128-byte proof.\n\
         • Zero-knowledge: proofs are randomized; the witness stays in the exponent.\n\
         • Soundness: a proof built from a non-satisfying witness is always rejected."
    );
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
