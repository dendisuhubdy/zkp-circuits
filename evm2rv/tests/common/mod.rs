//! What the translation tests share: the pinned toolchain, `rand-guest` built from this checkout,
//! a shim built from a contract, and `rand-guest run` over it.

#![allow(dead_code)]

pub mod host;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use evm2rv::emit::Stage;
use evm_core::ffi::halt_code;
use evm_core::interp::{Halt, Outcome};

pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .unwrap()
}

/// `cargo` with the pinned toolchain.
pub fn cargo() -> Command {
    let mut c = scrubbed("cargo");
    c.arg("+1.98.1");
    c
}

/// A command without the variables the outer `cargo test` sets for *this* crate (`rand-guest
/// build` runs cargo itself, for the shim).
pub fn scrubbed(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut c = Command::new(program);
    for (k, _) in std::env::vars() {
        if k.starts_with("CARGO_") && k != "CARGO_HOME" {
            c.env_remove(&k);
        }
    }
    c.env_remove("RUSTC");
    c.env_remove("RUSTDOC");
    c.env_remove("RUSTC_WRAPPER");
    c.env_remove("RUSTC_WORKSPACE_WRAPPER");
    c
}

/// The `rand-guest` binary, built once from this checkout.
pub fn rand_guest() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let manifest = root().join("rand-guest/Cargo.toml");
        let o = cargo()
            .args(["build", "--bin", "rand-guest", "--manifest-path"])
            .arg(&manifest)
            .output()
            .unwrap();
        assert!(
            o.status.success(),
            "building rand-guest: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        root().join("rand-guest/target/debug/rand-guest")
    })
}

/// Both stages, for the tests that run under each.
pub const STAGES: [Stage; 2] = [Stage::One, Stage::Two];

/// The CLI's `--stage` value.
pub fn stage_arg(stage: Stage) -> &'static str {
    match stage {
        Stage::One => "1",
        Stage::Two => "2",
    }
}

/// Translate `contract` at `stage` into `dir` (inside the checkout, as `rand-guest build`
/// requires) as crate `name` and build it; returns the image and its `hc`. `outcome` turns the
/// shim's `emit-outcome` feature on for this build.
pub fn build_shim(
    contract: &Path,
    dir: &Path,
    name: &str,
    outcome: bool,
    stage: Stage,
) -> (PathBuf, String) {
    let _ = std::fs::remove_dir_all(dir.join("src"));
    let o = Command::new(env!("CARGO_BIN_EXE_evm2rv"))
        .arg(contract)
        .arg("--out")
        .arg(dir)
        .args(["--name", name, "--stage", stage_arg(stage)])
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "evm2rv: {}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    if outcome {
        let toml = dir.join("Cargo.toml");
        let text = std::fs::read_to_string(&toml).unwrap();
        let patched = text.replace("default = []", "default = [\"emit-outcome\"]");
        assert_ne!(
            text, patched,
            "the shim's Cargo.toml has no `default = []` to patch"
        );
        std::fs::write(&toml, patched).unwrap();
    }
    // The generated crate carries its own Cargo.lock (cc and its dependencies pinned exactly);
    // the build must use it as written, never re-resolve it.
    let lock_before =
        std::fs::read_to_string(dir.join("Cargo.lock")).expect("a generated Cargo.lock");
    let image = dir.join("image.bin");
    let o = scrubbed(rand_guest())
        .arg("build")
        .arg(dir)
        .arg("--out")
        .arg(&image)
        .args(["--max-words", "65535"])
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "rand-guest build {}: {}{}",
        dir.display(),
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    let stdout = String::from_utf8_lossy(&o.stdout);
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert_eq!(
        std::fs::read_to_string(dir.join("Cargo.lock")).unwrap(),
        lock_before,
        "the build rewrote the generated Cargo.lock"
    );
    assert!(
        !stderr.contains("Locking") && !stderr.contains("Updating crates.io index"),
        "the build re-resolved the lock: {stderr}"
    );
    // build.rs names the compiler that produced the image.
    assert!(
        stderr.contains("evm2rv: clang "),
        "no clang version line: {stderr}"
    );
    let wrote = stdout
        .lines()
        .find(|l| l.starts_with("wrote"))
        .unwrap_or_else(|| panic!("no `wrote` line: {stdout}"));
    eprintln!("{}: {wrote}", dir.display());
    let hc = wrote
        .split("hc ")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .expect("an hc in the `wrote` line")
        .to_string();
    (image, hc)
}

/// `rand-guest run`'s stdout when the run went past the largest tier's cycle budget, else `None`.
pub fn run_out_of_cycles(image: &Path, inputs: &[u32]) -> Option<String> {
    let o = scrubbed(rand_guest())
        .arg("run")
        .arg(image)
        .arg("--input")
        .args(inputs.iter().map(u32::to_string))
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&o.stdout).into_owned();
    s.contains("trap: OutOfCycles").then_some(s)
}

/// `rand-guest run image --input words…`: the eight output words and the executed cycles.
pub fn run(image: &Path, inputs: &[u32]) -> ([u32; 8], usize) {
    let o = scrubbed(rand_guest())
        .arg("run")
        .arg(image)
        .arg("--input")
        .args(inputs.iter().map(u32::to_string))
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(
        o.status.success(),
        "rand-guest run {}: {s}{}",
        image.display(),
        String::from_utf8_lossy(&o.stderr)
    );
    let mut out = [0u32; 8];
    for (i, w) in out.iter_mut().enumerate() {
        let prefix = format!("out[{i}] = ");
        *w = s
            .lines()
            .find_map(|l| l.strip_prefix(&prefix))
            .unwrap_or_else(|| panic!("no out[{i}] line: {s}"))
            .parse()
            .unwrap();
    }
    let cycles = s
        .lines()
        .find_map(|l| l.strip_prefix("cycles "))
        .expect("a cycles line")
        .parse()
        .unwrap();
    (out, cycles)
}

/// The halt as the `emit-outcome` build encodes it: the `ffi.rs` code, a trap's opcode above it.
pub fn encoded_halt(o: &Outcome) -> u32 {
    let arg = match o.halt {
        Halt::Trap(op) => op as u32,
        _ => 0,
    };
    halt_code(o.halt) | (arg << 8)
}
