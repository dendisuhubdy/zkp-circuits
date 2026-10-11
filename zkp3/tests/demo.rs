//! Runs the narrated demo binary and checks the claims it prints: honest proofs are accepted, forgeries are refused.

fn run() -> String {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_zkp3"))
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
fn the_demo_verifies_the_stark_and_is_deterministic() {
    let o = run();
    assert!(o.contains("correct y     : accepted = true"));
    assert!(o.contains("wrong y       : accepted = false"));
    assert!(o.contains("second proof identical? true"));
}
