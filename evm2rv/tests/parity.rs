//! Task 4's exit test: the translated ERC-20 against the interpreter, on the machine.
//!
//! `evm2rv` translates the interpreter's own ERC-20 runtime bytecode
//! (`guests-compiled/evm/contracts/erc20.runtime.hex`) into a shim crate, `rand-guest build` turns
//! that into an image, and `rand-guest run` executes it on the emulator with each vector's input
//! words — the interpreter's exact input vector, no extra words. For every vector the translated
//! program must publish the same eight words as
//!
//! * the interpreter run natively on the host (`EvmCall::expected`, the oracle), and
//! * the interpreter's committed guest, `guests-compiled/bin/evm.bin`, run on the same emulator,
//!
//! and report the same status, `gas_used` and halt. `gas_used` and the halt are not public words
//! (only the status and the `EVM_OUT` digest are), so they come from a **second build of the same
//! shim with its `emit-outcome` cargo feature on**: that build writes the status and digest words
//! 0..4 as usual, the halt code (the trap's opcode in bits 8..15) to `out[6]` and `gas_used` to
//! `out[7]`. Only this test enables the feature; the image a chain would deploy is the default
//! build, and its eight words are the ones compared against `evm.bin`.
//!
//! The vectors are research's (`rand_zkvm::evm`): the transfer of 250 from a balance of 1 000
//! (`tests/e2e.rs`'s exit test and `rand-guest/tests/run.rs`'s cycle pin), `approve`,
//! `transferFrom` (built here from the same fixtures: the spender is the caller, with an allowance
//! witnessed), the transfer of 5 000 against 1 000 that reverts with Solidity's `Error(string)`,
//! and out-of-gas at three limits — inside the first block, at an `SSTORE`, and one short of the
//! transfer's own gas — plus that transfer at exactly its gas.
//!
//! No RISC-V clang is a failure here, not a skip: the shim's `build.rs` panics naming the clang it
//! could not find, and `rand-guest build` fails with it.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use evm_core::ffi::halt_code;
use evm_core::interp::{Halt, Outcome};
use evm_core::u256::U256;
use rand_zkvm::evm::{
    abi_call, erc20_transfer, mapping_slot, mapping_slot2, EvmCall, ALICE, BOB, SLOT_ALLOWANCES,
    SLOT_BALANCES,
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .unwrap()
}

/// `cargo` with the pinned toolchain.
fn cargo() -> Command {
    let mut c = scrubbed("cargo");
    c.arg("+1.98.1");
    c
}

/// A command without the variables the outer `cargo test` sets for *this* crate (`rand-guest
/// build` runs cargo itself, for the shim).
fn scrubbed(program: impl AsRef<std::ffi::OsStr>) -> Command {
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
fn rand_guest() -> &'static Path {
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

fn erc20_hex() -> PathBuf {
    root().join("guests-compiled/evm/contracts/erc20.runtime.hex")
}

/// Translate the ERC-20 into `dir` (inside the checkout, as `rand-guest build` requires) and build
/// it; returns the image. `outcome` turns the shim's `emit-outcome` feature on for this build.
fn build_shim(dir: &Path, outcome: bool) -> PathBuf {
    let _ = std::fs::remove_dir_all(dir.join("src"));
    let o = Command::new(env!("CARGO_BIN_EXE_evm2rv"))
        .arg(erc20_hex())
        .arg("--out")
        .arg(dir)
        .args(["--name", "erc20-evm2rv"])
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
    eprintln!(
        "{}: {}",
        dir.display(),
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter(|l| l.starts_with("wrote"))
            .collect::<Vec<_>>()
            .join(" ")
    );
    image
}

/// The two images: the default build (what a chain deploys) and the `emit-outcome` build.
fn images() -> &'static (PathBuf, PathBuf) {
    static IMAGES: OnceLock<(PathBuf, PathBuf)> = OnceLock::new();
    IMAGES.get_or_init(|| {
        let base = root().join("evm2rv/target/parity");
        let plain = build_shim(&base.join("erc20"), false);
        let outcome = build_shim(&base.join("erc20-outcome"), true);
        (plain, outcome)
    })
}

/// `rand-guest run image --input words…`: the eight output words and the executed cycles.
fn run(image: &Path, inputs: &[u32]) -> ([u32; 8], usize) {
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
fn encoded_halt(o: &Outcome) -> u32 {
    let arg = match o.halt {
        Halt::Trap(op) => op as u32,
        _ => 0,
    };
    halt_code(o.halt) | (arg << 8)
}

/// Runs `call` through the interpreter natively, `evm.bin` and both translated images; asserts
/// the parity the module doc lists, and returns `(interpreter cycles, translated cycles)`.
fn check(name: &str, call: &EvmCall, want_status: u32) -> (usize, usize) {
    let (plain, outcome) = images();
    let words = call.input_words();
    let (want, o, _post) = call.expected();
    assert_eq!(want[0], want_status, "{name}: the oracle's own status");

    let (interp, interp_cycles) = run(&root().join("guests-compiled/bin/evm.bin"), &words);
    assert_eq!(
        interp, want,
        "{name}: evm.bin disagrees with the native interpreter"
    );

    let (got, cycles) = run(plain, &words);
    assert_eq!(
        got, want,
        "{name}: the translated program's eight public words"
    );

    let (dbg, _) = run(outcome, &words);
    assert_eq!(
        dbg[..6],
        want[..6],
        "{name}: the emit-outcome build's status and digest words 0..4"
    );
    assert_eq!(
        dbg[6],
        encoded_halt(&o),
        "{name}: the halt ({:?} in the interpreter)",
        o.halt
    );
    assert_eq!(dbg[7] as u64, o.gas_used, "{name}: gas_used");

    eprintln!(
        "{name}: status {} halt {:?} gas_used {} — cycles: interpreter {interp_cycles}, translated {cycles}",
        want[0], o.halt, o.gas_used
    );
    (interp_cycles, cycles)
}

fn transfer_250() -> EvmCall {
    erc20_transfer(
        ALICE,
        BOB,
        U256::from_u32(250),
        &[(ALICE, U256::from_u32(1000))],
    )
}

#[test]
fn transfer_matches_the_interpreter() {
    check("transfer", &transfer_250(), 1);
}

/// `approve(BOB, 5)` from ALICE: the nested `_allowances` mapping and one `Approval` log with three
/// topics (e2e.rs's vector).
#[test]
fn approve_matches_the_interpreter() {
    let mut ap = erc20_transfer(ALICE, BOB, U256::ZERO, &[]);
    ap.calldata = abi_call("approve(address,uint256)", &[BOB, U256::from_u32(5)]);
    ap.touched = vec![mapping_slot2(&ALICE, &BOB, SLOT_ALLOWANCES)];
    check("approve", &ap, 1);
}

/// `transferFrom(ALICE, BOB, 100)` called by BOB against an allowance of 300 and a balance of
/// 1 000: `_spendAllowance` reads and rewrites the allowance (an `Approval` log), `_transfer`
/// moves the balance (a `Transfer` log).
#[test]
fn transfer_from_matches_the_interpreter() {
    let mut tf = erc20_transfer(ALICE, BOB, U256::ZERO, &[(ALICE, U256::from_u32(1000))]);
    let allowance = mapping_slot2(&ALICE, &BOB, SLOT_ALLOWANCES);
    tf.tree.insert(allowance, U256::from_u32(300));
    tf.caller = BOB;
    tf.calldata = abi_call(
        "transferFrom(address,address,uint256)",
        &[ALICE, BOB, U256::from_u32(100)],
    );
    tf.touched = vec![
        allowance,
        mapping_slot(&ALICE, SLOT_BALANCES),
        mapping_slot(&BOB, SLOT_BALANCES),
    ];
    check("transferFrom", &tf, 1);
}

/// A transfer of 5 000 against a balance of 1 000 reverts with `Error(string)` return data, which
/// the digest binds.
#[test]
fn a_revert_matches_the_interpreter() {
    let over = erc20_transfer(
        ALICE,
        BOB,
        U256::from_u32(5000),
        &[(ALICE, U256::from_u32(1000))],
    );
    check("revert", &over, 0);
}

/// Out of gas at three limits: inside the first block (100), at the transfer's 20 000 `SSTORE`
/// onto BOB's empty balance (20 000), and one short of what the transfer uses (29 955, the last
/// charge fails). Each is an exceptional halt that reports `gas_used = gas_limit`. The exact
/// limit (29 956) succeeds with nothing to spare, in both.
#[test]
fn out_of_gas_matches_the_interpreter() {
    let used = transfer_250().expected().1.gas_used;
    assert_eq!(
        used, 29_956,
        "the transfer's gas, which the limits below are chosen around"
    );
    for gas in [100u64, 20_000, used - 1] {
        let mut call = transfer_250();
        call.gas_limit = gas;
        let (_, o, _) = call.expected();
        assert_eq!(o.halt, Halt::OutOfGas, "gas {gas}: the oracle runs out");
        check(&format!("out-of-gas {gas}"), &call, 2);
    }
    let mut exact = transfer_250();
    exact.gas_limit = used;
    check(&format!("exact gas {used}"), &exact, 1);
}
