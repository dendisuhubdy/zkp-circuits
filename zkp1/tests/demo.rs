//! Runs the narrated demo binary and checks the claims it prints: honest proofs are accepted, forgeries are refused.

fn run() -> String {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_zkp1"))
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
fn the_demo_accepts_the_honest_proof_and_rejects_every_forgery() {
    let o = run();
    assert!(o.contains("satisfied by x=3?  : true"));
    assert!(o.contains("satisfied by x=4?  : false"));
    assert!(o.contains("public input out=35  → accepted = true"));
    assert!(o.contains("public input out=36  → accepted = false"));
    assert!(o.contains("prover refused: witness x=4"));
    assert!(o.contains("identical bytes? false   both verify? true"));
    assert!(o.contains("correct h    → accepted = true"));
    assert!(o.contains("different h  → accepted = false"));
}
