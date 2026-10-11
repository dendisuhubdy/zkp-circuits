//! The build driver's refusals and helpers that need no compiler: linker-script discovery, the
//! checkout-root walk, the legacy-pin guard, the `clang --version` parser (against fake clangs
//! written to a temp dir), and `$CLANG` being an instruction rather than a hint.
#![cfg(unix)]

use rand_guest::build::{checkout_root, clang_version, find_ld, refuse_legacy_out};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// An executable shell script standing in for clang.
fn fake_clang(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

#[test]
fn find_ld_takes_the_guests_own_script_else_the_sdks() {
    let tmp = tempfile::tempdir().unwrap();
    let fake_root = Path::new("/checkout");
    assert_eq!(find_ld(tmp.path(), fake_root).unwrap(), fake_root.join("guest-sdk/guest.ld"), "no .ld: the SDK's");
    std::fs::write(tmp.path().join("mine.ld"), "").unwrap();
    std::fs::write(tmp.path().join("notes.txt"), "").unwrap();
    assert_eq!(find_ld(tmp.path(), fake_root).unwrap(), tmp.path().join("mine.ld"), "exactly one .ld: it");
}

#[test]
fn find_ld_refuses_two_scripts_and_names_the_count() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("a.ld"), "").unwrap();
    std::fs::write(tmp.path().join("b.ld"), "").unwrap();
    let e = find_ld(tmp.path(), Path::new("/checkout")).unwrap_err().to_string();
    assert!(e.contains("2 linker scripts") && e.contains("--ld"), "{e}");
}

#[test]
fn find_ld_on_a_missing_directory_is_an_error_naming_it() {
    let e = find_ld(Path::new("/no/such/guest/dir"), Path::new("/checkout")).unwrap_err();
    assert!(format!("{e:#}").contains("/no/such/guest/dir"), "{e:#}");
}

#[test]
fn checkout_root_walks_up_to_the_directory_holding_guest_sdk() {
    let r = checkout_root(&root().join("guests-compiled/fib")).unwrap();
    assert_eq!(r.canonicalize().unwrap(), root().canonicalize().unwrap());
    // a directory outside any checkout is refused by name
    let tmp = tempfile::tempdir().unwrap();
    let e = checkout_root(tmp.path()).unwrap_err().to_string();
    assert!(e.contains("not inside a circuits checkout"), "{e}");
    let e = checkout_root(Path::new("/no/such/dir")).unwrap_err().to_string();
    assert!(e.contains("no such guest directory"), "{e}");
}

#[test]
fn refuse_legacy_out_allows_a_missing_file_a_container_and_refuses_a_flat_pin() {
    let tmp = tempfile::tempdir().unwrap();
    // nothing there yet: fine
    refuse_legacy_out(&tmp.path().join("new.bin")).unwrap();
    // an existing flat binary (first word is not the image magic): refused
    let flat = tmp.path().join("flat.bin");
    std::fs::write(&flat, 0x0000_0013u32.to_le_bytes().repeat(8)).unwrap();
    assert!(refuse_legacy_out(&flat).is_err());
    // a file shorter than one word has no magic either
    let short = tmp.path().join("short.bin");
    std::fs::write(&short, [1u8, 2]).unwrap();
    assert!(refuse_legacy_out(&short).is_err());
}

#[test]
fn clang_version_parses_vendor_prefixed_and_plain_banners() {
    let tmp = tempfile::tempdir().unwrap();
    let plain = fake_clang(tmp.path(), "plain", "echo 'clang version 23.1.1 (https://example/llvm 0abc)'; echo second line");
    assert_eq!(clang_version(&plain).unwrap(), "23.1.1");
    let vendor = fake_clang(tmp.path(), "vendor", "echo 'Homebrew clang version 23.1.2'");
    assert_eq!(clang_version(&vendor).unwrap(), "23.1.2");
}

#[test]
fn clang_version_refuses_a_banner_without_a_version_and_a_missing_binary() {
    let tmp = tempfile::tempdir().unwrap();
    let junk = fake_clang(tmp.path(), "junk", "echo 'gcc (GCC) 14.2.0'");
    let e = clang_version(&junk).unwrap_err().to_string();
    assert!(e.contains("printed no `clang version`") && e.contains("gcc (GCC) 14.2.0"), "{e}");
    let silent = fake_clang(tmp.path(), "silent", "exit 0");
    assert!(clang_version(&silent).is_err());
    let e = clang_version(&tmp.path().join("absent")).unwrap_err();
    assert!(format!("{e:#}").contains("--version"), "{e:#}");
}

/// `$CLANG` is an instruction: when it names a binary with no riscv32 target the build stops and
/// names it, instead of quietly using another clang. Run through the binary so the environment
/// variable is the child's alone.
#[test]
fn a_clang_env_var_without_a_riscv32_target_is_refused_by_name() {
    let tmp = tempfile::tempdir().unwrap();
    let no_riscv = fake_clang(tmp.path(), "no-riscv", "echo '    x86-64 - 64-bit X86'");
    let guest = tempfile::tempdir().unwrap();
    std::fs::write(guest.path().join("g.c"), "void main(void) {}\n").unwrap();
    let out = tmp.path().join("out.bin");
    let o = Command::new(env!("CARGO_BIN_EXE_rand-guest"))
        .args(["build", "--lang", "c"])
        .arg(guest.path())
        .arg("--out")
        .arg(&out)
        .env("CLANG", &no_riscv)
        .output()
        .unwrap();
    assert!(!o.status.success());
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(stderr.contains("has no riscv32 target") && stderr.contains("no-riscv"), "{stderr}");
    assert!(!out.exists(), "nothing is written when the toolchain is refused");
}

/// A fake clang that claims riscv32 but a different version is refused unless the escape hatch is
/// set to exactly `1`; the refusal names both versions.
#[test]
fn a_clang_of_the_wrong_version_is_refused_without_the_unpinned_switch() {
    let tmp = tempfile::tempdir().unwrap();
    let wrong = fake_clang(
        tmp.path(),
        "wrong",
        "case \"$1\" in --print-targets) echo '    riscv32 - 32-bit RISC-V';; --version) echo 'clang version 1.2.3';; esac",
    );
    let guest = tempfile::tempdir().unwrap();
    std::fs::write(guest.path().join("g.c"), "void main(void) {}\n").unwrap();
    let out = tmp.path().join("out.bin");
    let run = |unpinned: Option<&str>| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_rand-guest"));
        c.args(["build", "--lang", "c"]).arg(guest.path()).arg("--out").arg(&out).env("CLANG", &wrong);
        c.env_remove("RAND_GUEST_CLANG_UNPINNED");
        if let Some(v) = unpinned {
            c.env("RAND_GUEST_CLANG_UNPINNED", v);
        }
        c.output().unwrap()
    };
    let o = run(None);
    assert!(!o.status.success());
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(stderr.contains("is clang 1.2.3") && stderr.contains("pinned to clang"), "{stderr}");
    // "0" is not the switch: only the exact value 1 accepts another version (the fake then fails
    // to compile, which is a later and different error)
    let o = run(Some("0"));
    assert!(String::from_utf8_lossy(&o.stderr).contains("pinned to clang"));
    let o = run(Some("1"));
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(stderr.contains("WARNING") && stderr.contains("building anyway"), "{stderr}");
}
