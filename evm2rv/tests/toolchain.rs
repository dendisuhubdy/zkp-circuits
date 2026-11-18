//! The clang pin in the generated `build.rs` (Task 9): `hc` depends on the C compiler, so the
//! shim builds only with rand-guest's clang, 23.1.1, and refuses any other unless
//! `RAND_GUEST_CLANG_UNPINNED=1`, which builds with a loud warning. The "other" clang here is the
//! real one behind a wrapper that reports another version, so the unpinned build still produces
//! the pinned build's image.

mod common;

use std::os::unix::fs::PermissionsExt;

use common::{build_shim, rand_guest, root, scrubbed};
use evm2rv::emit::Stage;

#[test]
fn the_shim_refuses_a_clang_other_than_the_pin() {
    let dir = root().join("evm2rv/target/toolchain");
    std::fs::create_dir_all(&dir).unwrap();
    // PUSH1 1, PUSH0, MSTORE, PUSH1 32, PUSH0, RETURN.
    let code = dir.join("one.hex");
    std::fs::write(&code, "60015f5260205ff3").unwrap();
    let (_, pinned_hc) = build_shim(&code, &dir.join("pinned"), "pin-test", false, Stage::Two);

    // The real compiler behind the wrapper is the one the pinned build above used — `$CLANG`, else
    // Homebrew's, the build's own rule (`rand-guest`'s `find_clang`) — so that "the same image"
    // below compares one compiler with itself. (Until ZKVM-101 this was Homebrew's path spelled
    // out, which does not exist on a Linux runner: the wrapper could not `exec` it, and build.rs
    // reported the wrapper as a clang that "does not run or has no riscv32 target".)
    let real = std::env::var_os("CLANG").map_or_else(
        || std::path::PathBuf::from("/opt/homebrew/opt/llvm/bin/clang"),
        std::path::PathBuf::from,
    );
    let real = real.canonicalize().unwrap_or_else(|e| panic!("no clang at {}: {e}", real.display()));
    let quoted = real.to_str().expect("a UTF-8 clang path");
    assert!(!quoted.contains('\''), "a clang path with a single quote: {quoted}");
    let fake = dir.join("clang-22");
    std::fs::write(
        &fake,
        format!("#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  echo \"Homebrew clang version 22.1.0\"\n  exit 0\nfi\nexec '{quoted}' \"$@\"\n"),
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    // build.rs takes the `llvm-ar` and `llvm-ranlib` beside the clang (else the ones on PATH).
    for tool in ["llvm-ar", "llvm-ranlib"] {
        let link = dir.join(tool);
        let _ = std::fs::remove_file(&link);
        let beside = real.with_file_name(tool);
        if beside.exists() {
            std::os::unix::fs::symlink(&beside, &link).unwrap();
        }
    }

    let crate_dir = dir.join("other");
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_evm2rv"))
        .arg(&code)
        .arg("--out")
        .arg(&crate_dir)
        .args(["--name", "pin-test"])
        .output()
        .unwrap();
    assert!(o.status.success());
    let build = |unpinned: bool| {
        let mut c = scrubbed(rand_guest());
        c.arg("build")
            .arg(&crate_dir)
            .arg("--out")
            .arg(crate_dir.join("image.bin"))
            .args(["--max-words", "65535"])
            .env("CLANG", &fake);
        if unpinned {
            c.env("RAND_GUEST_CLANG_UNPINNED", "1");
        } else {
            c.env_remove("RAND_GUEST_CLANG_UNPINNED");
        }
        let o = c.output().unwrap();
        (
            o.status.success(),
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        )
    };

    let (ok, _, err) = build(false);
    assert!(!ok, "a clang reporting 22.1.0 was accepted: {err}");
    assert!(
        err.contains("is clang 22.1.0, but rand-guest is pinned to clang 23.1.1"),
        "{err}"
    );

    let (ok, out, err) = build(true);
    assert!(ok, "{out}{err}");
    assert!(
        err.contains("WARNING: ") && err.contains("is clang 22.1.0, not the pinned 23.1.1; building anyway because RAND_GUEST_CLANG_UNPINNED=1. hc will not match published images."),
        "{err}"
    );
    // The same compiler behind the wrapper: the same image.
    assert!(out.contains(&format!("hc {pinned_hc},")), "{out}");
}
