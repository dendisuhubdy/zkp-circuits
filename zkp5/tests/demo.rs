//! Runs the narrated demo binary and checks the claims it prints: honest proofs are accepted, forgeries are refused.

fn run() -> String {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_zkp5"))
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
fn the_demo_refuses_replays_and_forged_ring_signatures() {
    let o = run();
    let attacks = o.split("── Attacks").nth(1).expect("attacks section");
    assert!(attacks.contains("replay tx                     → KeyImageSeen(0)"));
    assert!(attacks.contains("spend same output, new ring   → KeyImageSeen(0)"));
    assert!(attacks.contains("claim 8-output is worth 100   → RingSignature(0)"));
    assert!(attacks.contains("sign without the one-time key → RingSignature(0)"));
    assert!(attacks.contains("edit fee after signing        → RingSignature(0)"));
    assert!(o.contains("bob       total      10"));
}
