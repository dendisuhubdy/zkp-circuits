//! `rand-guest build` is a function of the guest's source and the pinned toolchain alone: nothing in
//! the builder's environment can change `hc`. A verifier rebuilds a deployed guest to check `hc`, so
//! a builder whose shell exports a profile override, a target `RUSTFLAGS` or a `CARGO_TARGET_DIR`
//! must get the same image as one whose shell does not — or be refused, as a `.cargo/config.toml`
//! (which cargo merges into the build, and which `build` cannot scrub) is.
//!
//! The Rust tests build a copy of `guests-compiled/fib` (small and quick) in its own directory, so
//! they never race another test's build of the committed guest; they need the pinned toolchain with
//! the guest target, as `tests/build.rs` does.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .unwrap()
}

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rand-guest"))
}

/// `guests-compiled/fib`, copied beside it (the same depth, so its relative `guest-sdk` path holds).
fn fib_copy() -> tempfile::TempDir {
    let guest = tempfile::tempdir_in(root().join("guests-compiled")).unwrap();
    let src = root().join("guests-compiled/fib");
    std::fs::create_dir_all(guest.path().join("src")).unwrap();
    for f in ["Cargo.toml", "Cargo.lock", "src/main.rs"] {
        std::fs::copy(src.join(f), guest.path().join(f)).unwrap();
    }
    guest
}

fn build(guest: &Path, out: &Path, env: &[(&str, &str)]) -> Output {
    let mut c = Command::new(bin());
    c.arg("build").arg(guest).arg("--out").arg(out);
    for (k, v) in env {
        c.env(k, v);
    }
    c.output().unwrap()
}

/// The `hc` a successful `build` prints.
fn hc(o: &Output) -> String {
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(
        o.status.success(),
        "{out}\n{}",
        String::from_utf8_lossy(&o.stderr)
    );
    out.split(", hc ")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap_or_else(|| panic!("no hc in {out}"))
        .to_string()
}

#[test]
fn the_builders_environment_cannot_change_hc() {
    let guest = fib_copy();
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("fib.bin");
    let clean = hc(&build(guest.path(), &out, &[]));
    // Each of these changes the image when cargo sees it: LTO off and 16 codegen units reshape the
    // code, and overflow checks add branches (and panic locations) to `fib`'s additions.
    let overrides: [&[(&str, &str)]; 4] = [
        &[("CARGO_PROFILE_RELEASE_LTO", "false")],
        &[("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "16")],
        &[(
            "CARGO_TARGET_RISCV32IM_UNKNOWN_NONE_ELF_RUSTFLAGS",
            "-Coverflow-checks=on",
        )],
        &[
            ("CARGO_PROFILE_RELEASE_LTO", "false"),
            ("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "16"),
            ("CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS", "true"),
            (
                "CARGO_TARGET_RISCV32IM_UNKNOWN_NONE_ELF_RUSTFLAGS",
                "-Coverflow-checks=on",
            ),
            ("RUSTFLAGS", "-Copt-level=0"),
            ("CARGO_ENCODED_RUSTFLAGS", "-Copt-level=0"),
            ("CARGO_INCREMENTAL", "1"),
        ],
    ];
    for env in overrides {
        assert_eq!(
            hc(&build(guest.path(), &out, env)),
            clean,
            "{env:?} changed hc"
        );
    }
    // And the committed guest's own pin: the copy is the committed source.
    let pinned = std::fs::read(root().join("guests-compiled/bin/fib.bin")).unwrap();
    let p = rand_zkvm::isa::Program::from_flat_binary(0x1000, &pinned).unwrap();
    let want: String = p.digest().iter().map(|w| format!("{w:08x}")).collect();
    assert_eq!(
        clean, want,
        "the copy of fib builds to fib's pinned program"
    );
}

#[test]
fn a_target_dir_elsewhere_still_packs_the_fresh_elf() {
    let guest = fib_copy();
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("fib.bin");
    let old = hc(&build(guest.path(), &out, &[]));
    // A different program in the same directory: its `hc` must be the one packed, not the stale
    // ELF the first build left in `<guest>/target`, wherever `CARGO_TARGET_DIR` points cargo.
    let main = guest.path().join("src/main.rs");
    let text = std::fs::read_to_string(&main).unwrap();
    std::fs::write(
        &main,
        text.replace("write_output(0, fib(n));", "write_output(0, fib(n) ^ 1);"),
    )
    .unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let moved = hc(&build(
        guest.path(),
        &out,
        &[
            ("CARGO_TARGET_DIR", elsewhere.path().to_str().unwrap()),
            ("CARGO_BUILD_TARGET_DIR", elsewhere.path().to_str().unwrap()),
        ],
    ));
    assert_ne!(moved, old, "the stale ELF was packed");
    std::fs::remove_dir_all(guest.path().join("target")).unwrap();
    assert_eq!(
        hc(&build(guest.path(), &out, &[])),
        moved,
        "a clean build of the new source gives the same hc"
    );
}

/// A guest with a `Cargo.toml` and nothing else: enough for the refusal, which comes before any
/// compiler runs (and before the walk up to the checkout, so the guest need not be in one).
fn bare_guest(parent: &Path) -> PathBuf {
    let g = parent.join("guest");
    std::fs::create_dir_all(g.join("src")).unwrap();
    std::fs::write(
        g.join("Cargo.toml"),
        "[package]\nname = \"g\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[workspace]\n",
    )
    .unwrap();
    std::fs::write(g.join("src/main.rs"), "fn main() {}\n").unwrap();
    g
}

#[test]
fn a_cargo_config_in_an_ancestor_is_refused() {
    for name in ["config.toml", "config"] {
        let tmp = tempfile::tempdir().unwrap();
        let guest = bare_guest(tmp.path());
        let cfg = tmp.path().join(".cargo").join(name);
        std::fs::create_dir_all(cfg.parent().unwrap()).unwrap();
        std::fs::write(&cfg, "[profile.release]\nlto = false\n").unwrap();
        let o = build(&guest, &tmp.path().join("out.bin"), &[]);
        let err = String::from_utf8_lossy(&o.stderr);
        assert!(!o.status.success(), "{name}: built anyway");
        let cfg = cfg.canonicalize().unwrap();
        assert!(
            err.contains(&cfg.display().to_string()),
            "{name}: the refusal names the file: {err}"
        );
        assert!(!tmp.path().join("out.bin").exists());
    }
}

#[test]
fn a_cargo_config_in_cargo_home_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let guest = bare_guest(tmp.path());
    let home = tempfile::tempdir().unwrap();
    std::fs::write(
        home.path().join("config.toml"),
        "[build]\nrustflags = [\"-Copt-level=0\"]\n",
    )
    .unwrap();
    let o = build(
        &guest,
        &tmp.path().join("out.bin"),
        &[("CARGO_HOME", home.path().to_str().unwrap())],
    );
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(!o.status.success());
    assert!(
        err.contains("config.toml") && err.contains("CARGO_HOME"),
        "{err}"
    );
}

/// A stand-in clang with a riscv32 target but the wrong version: refused unless the builder says
/// `RAND_GUEST_CLANG_UNPINNED=1`, and then only with a warning that `hc` will not match.
#[test]
fn a_clang_other_than_the_pinned_one_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let fake = tmp.path().join("clang");
    std::fs::write(
        &fake,
        "#!/bin/sh\ncase \"$1\" in\n  --print-targets) echo '    riscv32     - 32-bit RISC-V' ;;\n  --version) echo 'clang version 99.0.1' ;;\n  *) exit 1 ;;\nesac\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let guest = tmp.path().join("g");
    std::fs::create_dir_all(&guest).unwrap();
    std::fs::write(guest.join("main.c"), "void main(void) {}\n").unwrap();
    let run = |unpinned: bool| {
        let mut c = Command::new(bin());
        c.args(["build", "--lang", "c"])
            .arg(&guest)
            .arg("--out")
            .arg(tmp.path().join("out.bin"))
            .env("CLANG", &fake);
        if unpinned {
            c.env("RAND_GUEST_CLANG_UNPINNED", "1");
        } else {
            c.env_remove("RAND_GUEST_CLANG_UNPINNED");
        }
        c.output().unwrap()
    };
    let o = run(false);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(!o.status.success());
    assert!(
        err.contains("99.0.1") && err.contains(rand_guest::build::CLANG_VERSION),
        "{err}"
    );
    assert!(
        err.contains("RAND_GUEST_CLANG_UNPINNED"),
        "the refusal names the override: {err}"
    );
    // With the override the clang is accepted, loudly (the stand-in then fails to compile, which is
    // past the point this checks).
    let o = run(true);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("WARNING") && err.contains("will not match"),
        "{err}"
    );
    assert!(!err.contains("refus"), "{err}");
}
