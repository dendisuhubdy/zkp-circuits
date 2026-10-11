//! Runs the narrated demo binary and checks the claims it prints: honest proofs are accepted, forgeries are refused.

fn run() -> String {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_zkp4"))
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
fn the_demo_scenario_ends_with_every_attack_refused() {
    let o = run();
    let attacks = o.split("── Attacks").nth(1).expect("attacks section");
    assert!(attacks.contains("replay Bob's tx           → NullifierSeen"));
    assert!(attacks.contains("(inflate)   → wallet refused: Unsatisfiable"));
    assert!(attacks.contains("Bob spends Alice's change → wallet refused: Unsatisfiable"));
    assert!(attacks.contains("Alice re-spends note 0    → NullifierSeen"));
    assert!(o.contains("v_pub=2 → bob-t"));
}
