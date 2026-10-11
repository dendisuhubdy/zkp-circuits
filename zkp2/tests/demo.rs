//! Runs the narrated demo binary and checks the claims it prints: honest proofs are accepted, forgeries are refused.

fn run() -> String {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_zkp2"))
        .output()
        .expect("spawn demo");
    assert!(
        out.status.success(),
        "demo exited with {:?}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf-8 stdout")
}

#[test]
fn the_demo_accepts_the_right_y_and_refuses_the_wrong_witness() {
    let o = run();
    assert!(o.contains("correct y     : accepted = true"));
    assert!(o.contains("wrong y       : accepted = false"));
    assert!(o.contains("wrong x₀      : prover refused (Unsatisfiable)"));
    assert!(o.contains("identical? false"), "Groth16 proofs are blinded");
}
