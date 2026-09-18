//! `evm-rt` (evm2rv's C runtime) on the machine itself: `evm-rt/test/rv32` is a C guest that
//! includes the runtime's sources and drives its halt path — the hand-written RV32
//! `evm_rt_setjmp`/`evm_rt_longjmp` the host suite cannot reach — plus the u256 library, then
//! writes eight words (the expected values are derived in that file's header comment). Gated,
//! like the c-fib test, on a clang with a `riscv32` target.

use std::path::PathBuf;
use std::process::Command;

fn root() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..") }
fn bin() -> PathBuf { PathBuf::from(env!("CARGO_BIN_EXE_rand-guest")) }

#[test]
fn the_evm_runtime_halts_and_unwinds_on_the_machine() {
    let Ok(_) = rand_guest::build::find_clang() else { eprintln!("no RISC-V clang; skipping"); return; };
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("evm-rt.bin");
    let o = Command::new(bin())
        .args(["build", "--lang", "c"])
        .arg(root().join("evm-rt/test/rv32"))
        .arg("--out")
        .arg(&out)
        .args(["--max-words", "65535"])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    let r = Command::new(bin()).args(["run"]).arg(&out).output().unwrap();
    let s = String::from_utf8_lossy(&r.stdout);
    assert!(r.status.success(), "{s}");
    let want: [u32; 8] = [0x000a_421c, 1_000_000, 3, 20_003, 0x407, 0x5a5a_1234, 0xaaaa_aaaa, 958_899];
    for (i, w) in want.iter().enumerate() {
        assert!(s.contains(&format!("out[{i}] = {w}\n")), "out[{i}] should be {w}:\n{s}");
    }
}
