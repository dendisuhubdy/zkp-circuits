//! The C path's guest proves: spec §7's "a fifth guest in C … proves under the research prover's
//! test profile".

use rand_zkvm::isa::Program;
use rand_zkvm::machine::{FriProfile, Machine};
use std::path::PathBuf;
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// `c-fib`, built by `rand-guest build --lang c`, proves `fib(20) = 6765` under
/// `FriProfile::Test` and the proof verifies against the image's own `hc`. `#[ignore]`d for its
/// time, not its memory (a tier-10 proof); needs a RISC-V clang (`build::find_clang`). Run it with:
///
/// ```text
/// cd rand-guest && cargo +1.98.1 test --test prove -- --ignored --nocapture
/// ```
#[test]
#[ignore]
fn c_fib_proves_and_verifies_under_the_test_profile() {
    assert!(rand_guest::build::find_clang().is_some(), "needs a clang with a riscv32 target (brew install llvm, or set CLANG)");
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("c-fib.bin");
    let o = Command::new(env!("CARGO_BIN_EXE_rand-guest"))
        .args(["build", "--lang", "c"])
        .arg(root().join("guests-compiled/c-fib"))
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let program = Program::from_flat_image(&std::fs::read(&out).unwrap()).unwrap();

    let m = Machine::new(FriProfile::Test);
    let t0 = std::time::Instant::now();
    let (proof, exec) = m.prove(&program, &[20], &[], None).unwrap();
    let prove_time = t0.elapsed();
    assert_eq!(exec.outputs[0], 6765);
    let t1 = std::time::Instant::now();
    m.verify(&program.digest(), &proof).unwrap();
    eprintln!(
        "c-fib(20): {} words, {} cycles, tier {}, proof {} bytes, prove {:?}, verify {:?}",
        program.words.len(),
        exec.cycles(),
        proof.tier.0,
        proof.size(),
        prove_time,
        t1.elapsed()
    );
}
