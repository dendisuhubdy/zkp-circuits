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
