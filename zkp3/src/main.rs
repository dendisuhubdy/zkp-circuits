//! Narrated STARK demo. Run `cargo run --release` here and in ../zkp2.

use std::time::Instant;
use winterfell::math::FieldElement;
use winterfell::Trace;
use zkp3::stark::{self, build_trace, options, Hash};
use zkp3::{Felt, K, N_STEPS};

fn main() {
    println!("zkp3 · zk-STARK (winterfell / f128 / Blake3 / FRI)");
    println!("statement: I know x₀ with  x ← x³ + {K}  applied {N_STEPS}× giving public y");

    let x0 = Felt::new(3);
    let y = stark::chain(x0);
    println!("witness x₀ = 3 (secret)      public y = {y}");
    println!("(different number from zkp2's y: same computation, 128-bit field instead of 254-bit)");

    // ---- arithmetization ---------------------------------------------------
    let trace = build_trace(x0);
    println!("\n[arithmetize]  AIR = execution trace + transition constraint");
    println!("    trace       : {} column × {} rows  ⇒ {} transitions", trace.width(), trace.length(), trace.length() - 1);
    println!("    constraints : 1 transition (degree 3) + 1 boundary assertion");
    println!("    The step is written once; N only sets the table height.");
    println!("    first rows  : {}, {}, {}, …", trace.get(0, 0), trace.get(0, 1), trace.get(0, 2));

    // ---- setup --------------------------------------------------------------
    println!("\n[setup]        (none)  — transparent: no keys, no ceremony, no toxic waste");
    let o = options();
    println!("    security knobs: {} queries, blowup ×{}, grinding {} bits", o.num_queries(), o.blowup_factor(), o.grinding_factor());

    // ---- prove --------------------------------------------------------------
    println!("\n[prove]        FFT → Merkle commit → Fiat-Shamir → FRI");
    let t = Instant::now();
    let proof = stark::prove(x0);
    let t_prove = t.elapsed();
    let bytes = proof.to_bytes();
    let sec = proof.conjectured_security::<Hash>().bits();
    println!("    proof size    : {:>8} bytes   (Merkle roots + {} query openings + FRI layers)", bytes.len(), o.num_queries());
    println!("    security      : {sec} bits conjectured");
    println!("    time          : {t_prove:?}");

    // ---- verify -------------------------------------------------------------
    println!("\n[verify]       hash Merkle paths, check FRI folds, evaluate AIR at random z");
    let t = Instant::now();
    let res = stark::verify_proof(proof.clone(), y);
    let t_verify = t.elapsed();
    match &res {
        Ok(()) => println!("    correct y     : accepted = true   ({t_verify:?})"),
        Err(e) => println!("    correct y     : accepted = false  ({t_verify:?})  error: {e}"),
    }
    println!("    wrong y       : accepted = {}", stark::verify_proof(proof.clone(), y + Felt::ONE).is_ok());

    // ---- zero-knowledge -----------------------------------------------------
    let p2 = stark::prove(x0);
    println!(
        "\n[zero-knowledge]  second proof identical? {}  — deterministic: winterfell 0.13 adds no trace",
        p2.to_bytes() == bytes
    );
    println!("    masking, so this is a transparent succinct argument, not a *zero-knowledge* one.");
    println!("    (Groth16 in zkp2 blinds every proof for free.)");

    println!("\n┌─────────────── STARK summary ───────────────┐");
    println!("│ setup             none   transparent         │");
    println!("│ prove      {:>10?}                        │", t_prove);
    println!("│ verify     {:>10?}                        │", t_verify);
    println!("│ proof      {:>7} B   grows ~log²(N)        │", bytes.len());
    println!("│ vk               0 B   (the AIR source code) │");
    println!("│ assumption  collision-resistant hash, PQ-safe│");
    println!("└─────────────────────────────────────────────┘");
    println!("Compare with ../zkp2.");
}
