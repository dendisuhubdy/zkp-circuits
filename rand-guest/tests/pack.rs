//! The packer reproduces the committed images from the guests' ELFs. The ELFs are built here with
//! the same cargo invocation the Makefiles use, so this test needs the riscv32im target and
//! llvm-tools installed (`rustup +1.98.1 target add …`). Cargo merges `--config` rustflags with a
//! guest's `.cargo/config.toml` rather than replacing them, which is why the harness below invokes
//! cargo differently per guest (see `build_guest_elf`); Task 3 removes `fib`'s and `keccak256`'s
//! `.cargo/config.toml` so this tool is the single source of flags and that split goes away.

use std::path::PathBuf;
use std::process::Command;
use rand_zkvm::isa::Program;

fn root() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..") }

/// Builds a guest exactly as its Makefile does and returns the ELF path.
///
/// `fib` and `keccak256` already carry their rustflags (`-T` + `target-feature`) in
/// `.cargo/config.toml`, exactly as their Makefile's plain `cargo build` relies on: passing
/// `--config` here too would *merge* with, not replace, that file's `rustflags` array — cargo
/// joins array-valued config from different sources rather than letting the higher-priority one
/// win — duplicating `-T` and breaking the link ("region 'RAM' already defined"). `evm` and `sbpf`
/// carry no `rustflags` in their `.cargo/config.toml`; their Makefile supplies the whole set,
/// including the checkout-relative `--remap-path-prefix`, through `--config`, which is what the
/// branch below mirrors.
fn build_guest_elf(name: &str, crate_name: &str, ld: &str) -> PathBuf {
    let dir = root().join("guests-compiled").join(name);
    let mut cmd = Command::new("cargo");
    cmd.args(["+1.98.1", "build", "--release", "--target", "riscv32im-unknown-none-elf"]);
    if name == "evm" || name == "sbpf" {
        let flags = format!(
            "[\"-C\",\"link-arg=-T{ld}\",\"-C\",\"target-feature=-unaligned-scalar-mem\",\"--remap-path-prefix={}=/rand-circuits\"]",
            root().canonicalize().unwrap().display()
        );
        cmd.arg("--config").arg(format!("target.riscv32im-unknown-none-elf.rustflags={flags}"));
    }
    let status = cmd.current_dir(&dir).status().expect("cargo runs");
    assert!(status.success(), "building {name}");
    dir.join("target/riscv32im-unknown-none-elf/release").join(crate_name)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}

fn pinned(name: &str) -> String {
    let text = std::fs::read_to_string(root().join("guests-compiled/bin").join(format!("{name}.bin.sha256"))).unwrap();
    text.split_whitespace().next().unwrap().to_string()
}

fn pinned_bytes(name: &str) -> Vec<u8> {
    std::fs::read(root().join("guests-compiled/bin").join(format!("{name}.bin"))).unwrap()
}

#[test]
fn the_packer_reproduces_every_committed_image() {
    // Two gates, because the four pins are two different formats. `evm` and `sbpf` have a data
    // segment, so their Makefiles run the ELF through `mkimage.py` (`pack`'s Rust port); those two
    // are gated byte for byte against the committed `.bin.sha256`. `fib` and `keccak256` have no
    // data segment at all, so their Makefiles just `objcopy -O binary` the ELF — a headerless flat
    // binary loaded by `Program::from_flat_binary(0x1000, …)` (`research/src/guests.rs`, pinned
    // again by `research/tests/isa.rs`) — and that pin is a shared fixture this task does not
    // touch. `pack()` still emits the one container format the spec gives it, even with no data
    // segment, but `Program::from_flat_image`'s `n_data = 0` case is defined to decode to the
    // word-for-word same `Program` as `from_flat_binary` on the same text — so `fib`/`keccak256`
    // are gated at the program level instead: same `base_pc`, same `words`, same `digest()`.
    for (name, elf, ld) in [
        ("fib", "fib-guest", "../../guest-sdk/guest.ld"),
        ("keccak256", "keccak256-guest", "../../guest-sdk/guest.ld"),
        ("evm", "evm-guest", "evm.ld"),
        ("sbpf", "sbpf-guest", "sbpf.ld"),
    ] {
        let elf_bytes = std::fs::read(build_guest_elf(name, elf, ld)).unwrap();
        let image = rand_guest::pack::pack(&elf_bytes).unwrap();
        if name == "fib" || name == "keccak256" {
            let from_image = Program::from_flat_image(&image).unwrap();
            let from_flat = Program::from_flat_binary(0x1000, &pinned_bytes(name)).unwrap();
            assert_eq!(from_image, from_flat, "{name}: Program");
            assert_eq!(from_image.digest(), from_flat.digest(), "{name}: digest");
        } else {
            assert_eq!(sha256_hex(&image), pinned(name), "{name}.bin");
        }
        let info = rand_guest::pack::describe(&image).unwrap();
        assert!(info.n_text > 0);
    }
}

#[test]
fn a_non_elf_is_refused_by_name() {
    let err = rand_guest::pack::pack(b"not an elf at all").unwrap_err().to_string();
    assert!(err.contains("ELF32"), "{err}");
}
