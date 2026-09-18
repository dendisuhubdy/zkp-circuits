//! `sbpf-rt` (sbpf2rv's C runtime) on the machine itself: `sbpf-rt/test/rv32` is a C guest that
//! includes the runtime's sources and drives what the host suite cannot reach — the hand-written
//! RV32 `sbpf_setjmp`/`sbpf_longjmp` unwinding from six frames down with every callee-saved
//! register dirtied, and `sol_sha256` on the SHA-256 coprocessor — then writes eight words (derived
//! in that file's header comment). Gated, like the c-fib test, on a clang with a `riscv32` target.
//!
//! The software Ed25519 verify and secp256k1 recover run in their own modes. Neither fits the
//! machine's largest tier, which `run` caps execution at, so the default test checks that and the
//! `#[ignore]`d one measures them with the emulator's cap raised. It holds every cycle's trace row in
//! memory — measured 2026-09-18 at about 25 GB resident, 14 s — and printed: secp256k1 recover
//! 15 730 633 cycles, two Ed25519 verifies (one valid, one invalid) 28 581 563:
//!
//!     cargo test --release --test sbpf_rt -- --ignored --nocapture

use std::path::{Path, PathBuf};
use std::process::Command;

use rand_zkvm::emulator::{execute, ExecError};
use rand_zkvm::isa::Program;
use rand_zkvm::machine::{Tier, TIERS};

fn root() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..") }
fn bin() -> PathBuf { PathBuf::from(env!("CARGO_BIN_EXE_rand-guest")) }

fn build(dir: &Path) -> PathBuf {
    let out = dir.join("sbpf-rt.bin");
    let o = Command::new(bin())
        .args(["build", "--lang", "c"])
        .arg(root().join("sbpf-rt/test/rv32"))
        .arg("--out")
        .arg(&out)
        .args(["--max-words", "65535"])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    out
}

fn program(image: &Path) -> Program {
    Program::from_flat_image(&std::fs::read(image).unwrap()).unwrap()
}

#[test]
fn the_sbpf_runtime_traps_unwinds_and_hashes_on_the_machine() {
    let Ok(_) = rand_guest::build::find_clang() else { eprintln!("no RISC-V clang; skipping"); return; };
    let tmp = tempfile::tempdir().unwrap();
    let image = build(tmp.path());
    let r = Command::new(bin()).args(["run"]).arg(&image).args(["--input", "0"]).output().unwrap();
    let s = String::from_utf8_lossy(&r.stdout);
    assert!(r.status.success(), "{s}");
    let want: [u32; 8] =
        [0x0004_a13, 121, 0x5a5a_1234, 0xba78_16bf, 0x248d_6a61, 0x863, 0xffff_fffc, 0xa22b_9c85];
    for (i, w) in want.iter().enumerate() {
        assert!(s.contains(&format!("out[{i}] = {w}\n")), "out[{i}] should be {w}:\n{s}");
    }

    // The signature checks do not fit the largest tier.
    let max = Tier(*TIERS.last().unwrap()).max_cycles();
    let p = program(&image);
    for mode in [1u32, 2] {
        assert_eq!(execute(&p, &[mode], &[], max).err(), Some(ExecError::OutOfCycles(max)), "mode {mode}");
    }
}

#[test]
#[ignore = "measures the software signature checks: millions of cycles, each a trace row in memory"]
fn the_software_signature_checks_cost() {
    let Ok(_) = rand_guest::build::find_clang() else { eprintln!("no RISC-V clang; skipping"); return; };
    let tmp = tempfile::tempdir().unwrap();
    let p = program(&build(tmp.path()));
    let cap = 1 << 25;
    let base = execute(&p, &[3], &[], cap).unwrap().cycles();
    let secp = execute(&p, &[1], &[], cap).unwrap();
    assert_eq!(secp.outputs[0], 0xe32d_f428, "go-ethereum's key");
    let ed = execute(&p, &[2], &[], cap).unwrap();
    assert_eq!((ed.outputs[0], ed.outputs[1]), (0, 1), "RFC 8032 TEST 1, and one flipped S bit");
    println!("baseline {base} cycles");
    println!("secp256k1 recover: {} cycles", secp.cycles() - base);
    println!("ed25519 verify x2 (one valid, one invalid): {} cycles", ed.cycles() - base);
}
