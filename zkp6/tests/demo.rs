//! Runs the narrated demo binary and checks the claims it prints: honest proofs are accepted, forgeries are refused.

fn run() -> String {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_zkp6"))
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
fn the_demo_rejects_a_double_spend_a_forged_note_and_a_swapped_recipient() {
    let o = run();
    assert!(o.contains("✗ rejected: NoteAlreadySpent"));
    assert!(o.contains("InvalidProof"));
    assert!(o.contains("parse error:"));
    assert!(o.contains("original lands: Ok"));
    assert!(o.contains("An observer sees 3 deposits and 3 withdrawals"));
}
