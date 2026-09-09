//! Narrated SNARK demo. Run `cargo run --release` here, then in ../zkp3,
//! and compare the size / time tables.

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use std::time::Instant;

use zkp2::chain::{chain, ChainCircuit};
use zkp2::snark;
use zkp2::{Fr, K, N_STEPS};

fn main() {
    let mut rng = rand::rngs::OsRng;
    println!("zkp2 · zk-SNARK (Groth16 / BN254)");
    println!("statement: I know x₀ with  x ← x³ + {K}  applied {N_STEPS}× giving public y");

    let x0 = Fr::from(3u64);
    let y = chain(x0);
    println!("witness x₀ = 3 (secret)      public y = {}", short(&y));

    // ---- arithmetization ---------------------------------------------------
    let cs = ConstraintSystem::<Fr>::new_ref();
    ChainCircuit::with_secret(x0).generate_constraints(cs.clone()).unwrap();
    println!("\n[arithmetize]  R1CS circuit");
    println!("    constraints : {}   (2 per step + 1 output check)", cs.num_constraints());
    println!("    wires       : {} witness + {} public", cs.num_witness_variables(), cs.num_instance_variables() - 1);
    println!("    The whole loop is unrolled into gates. N is frozen into the circuit.");

    // ---- setup (SNARK-only phase) ------------------------------------------
    println!("\n[setup]        TRUSTED SETUP — the phase a STARK does not have");
    let t = Instant::now();
    let (pk, vk) = snark::setup(ChainCircuit::blank(), &mut rng);
    let t_setup = t.elapsed();
    println!("    proving key   : {:>8} bytes", snark::size_of(&pk));
    println!("    verifying key : {:>8} bytes", snark::size_of(&vk));
    println!("    time          : {t_setup:?}");
    println!("    Toxic waste τ lives in this process's RNG state and is now gone.");

    // ---- prove --------------------------------------------------------------
    println!("\n[prove]");
    let t = Instant::now();
    let proof = snark::prove(&pk, ChainCircuit::with_secret(x0), &mut rng).expect("honest witness");
    let t_prove = t.elapsed();
    let mut bytes = Vec::new();
    proof.serialize_compressed(&mut bytes).unwrap();
    println!("    proof size    : {:>8} bytes   (3 curve points A, B, C — always)", bytes.len());
    println!("    time          : {t_prove:?}");

    // ---- verify -------------------------------------------------------------
    println!("\n[verify]       3 pairings, no dependence on N");
    let t = Instant::now();
    let ok = snark::verify(&vk, &[y], &proof);
    let t_verify = t.elapsed();
    println!("    correct y     : accepted = {ok}   ({t_verify:?})");
    println!("    wrong y       : accepted = {}", snark::verify(&vk, &[y + Fr::from(1u64)], &proof));
    // A cheating prover with the wrong secret. Our `prove` checks the witness
    // before calling Groth16, so it refuses rather than forging a proof that
    // the verifier would reject anyway (see the note on `snark::prove`).
    match snark::prove(&pk, ChainCircuit { x0: Some(Fr::from(4u64)), y: Some(y) }, &mut rng) {
        Ok(bad) => println!("    wrong x₀      : accepted = {}", snark::verify(&vk, &[y], &bad)),
        Err(e) => println!("    wrong x₀      : prover refused ({e:?}) — x₀=4 does not reach y"),
    }

    // ---- zero-knowledge -----------------------------------------------------
    let p2 = snark::prove(&pk, ChainCircuit::with_secret(x0), &mut rng).expect("honest witness");
    let mut b2 = Vec::new();
    p2.serialize_compressed(&mut b2).unwrap();
    println!("\n[zero-knowledge]  second proof of same statement identical? {}  (blinded by r, s)", bytes == b2);

    println!("\n┌─────────────── SNARK summary ───────────────┐");
    println!("│ setup      {:>10?}  trusted, per-circuit  │", t_setup);
    println!("│ prove      {:>10?}                        │", t_prove);
    println!("│ verify     {:>10?}                        │", t_verify);
    println!("│ proof      {:>7} B   constant              │", bytes.len());
    println!("│ vk         {:>7} B                         │", snark::size_of(&vk));
    println!("│ assumption  pairing-friendly curve, not PQ  │");
    println!("└─────────────────────────────────────────────┘");
    println!("Now run ../zkp3 and compare.");
}

fn short(f: &Fr) -> String {
    use ark_ff::{BigInteger, PrimeField};
    let hex: String = f.into_bigint().to_bytes_be().iter().map(|b| format!("{b:02x}")).collect();
    format!("0x{}…{}", &hex[..10], &hex[hex.len() - 6..])
}
