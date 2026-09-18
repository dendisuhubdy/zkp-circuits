//! `run` executes the committed images on the emulator and reports what the research crate's
//! own tests report.

use std::path::PathBuf;
use std::process::Command;

fn root() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..") }
fn bin() -> PathBuf { PathBuf::from(env!("CARGO_BIN_EXE_rand-guest")) }

#[test]
fn fib_20_runs_to_6765_with_a_tier() {
    let o = Command::new(bin()).args(["run"]).arg(root().join("guests-compiled/bin/fib.bin")).args(["--input", "20"]).output().unwrap();
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{s}");
    assert!(s.contains("out[0] = 6765"), "{s}");
    assert!(s.contains("cycles "), "{s}");
    assert!(s.contains("tier 10"), "{s}");
}

#[test]
fn a_trap_is_reported_with_its_pc_and_exit_code_2() {
    // fib with no input: READ_INPUT 0 past an empty vector is an input-index trap.
    let o = Command::new(bin()).args(["run"]).arg(root().join("guests-compiled/bin/fib.bin")).output().unwrap();
    assert_eq!(o.status.code(), Some(2));
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(s.contains("trap at pc"), "{s}");
}

/// `run`'s tier pick must agree with what `Machine::prove` would pick, not just fit the cycle
/// budget: `Tier::for_workload`'s Poseidon2-permutation term (the digest/indigest/public-digest
/// rows plus any in-guest `POSEIDON2` absorb rows) is a second, independent constraint
/// (`research/src/machine.rs`'s `Machine::prove_salted`, the `None =>` arm; audit ZH1). This test
/// pins the *agreement*, not a number: it recomputes the same `Tier::for_workload(cycles,
/// permutations)` call host-side, from a plain `emulator::execute` of the same guest and input,
/// and checks `run`'s printed tier equals whatever that comes out to.
#[test]
fn keccak256_picks_the_tier_prove_would_pick() {
    use rand_zkvm::emulator::{self, HashRow};
    use rand_zkvm::isa::Program;
    use rand_zkvm::machine::{Tier, TIERS};

    let image = std::fs::read(root().join("guests-compiled/bin/keccak256.bin")).unwrap();
    let program = Program::from_flat_binary(0x1000, &image).unwrap();

    // `research/src/guests.rs`'s `compiled::keccak256` doc comment: input[0] is the message's
    // byte length, input[1..] the message four bytes per word little-endian. A short message is
    // enough — the test only needs a real execution to pull real digest/absorb-row counts from.
    let msg: Vec<u8> = (0..16u8).map(|i| i.wrapping_mul(31)).collect();
    let mut inputs = vec![msg.len() as u32];
    for c in msg.chunks(4) {
        let mut w = [0u8; 4];
        w[..c.len()].copy_from_slice(c);
        inputs.push(u32::from_le_bytes(w));
    }

    let max = Tier(*TIERS.last().unwrap()).max_cycles();
    let exec = emulator::execute(&program, &inputs, &[], max).unwrap();
    // Term by term, `Machine::prove_salted`'s `None =>` arm.
    let digest_rows = program.digest_rows() + rand_zkvm::hash::input_digest_row_count(inputs.len()) + rand_zkvm::hash::public_digest_row_count(0);
    let cycles = exec.cycles() + digest_rows;
    let absorb_rows = exec.events.iter().filter(|e| matches!(e.hash_row, Some(HashRow::Absorb { .. }))).count();
    let permutations = digest_rows + absorb_rows;
    let want = Tier::for_workload(cycles, permutations).expect("some tier fits this small workload");

    let mut args = vec!["run".to_string(), root().join("guests-compiled/bin/keccak256.bin").to_string_lossy().into_owned(), "--input".to_string()];
    args.extend(inputs.iter().map(|w| w.to_string()));
    let o = Command::new(bin()).args(&args).output().unwrap();
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{s}");
    assert!(s.contains(&format!("tier {}", want.0)), "wanted tier {}: {s}", want.0);
}
