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

mod common;

use std::path::PathBuf;
use std::sync::OnceLock;

use common::{build_shim, encoded_halt, root, run};
use evm_core::interp::Halt;
use evm_core::u256::U256;
use rand_zkvm::evm::{
    abi_call, erc20_transfer, mapping_slot, mapping_slot2, EvmCall, ALICE, BOB, SLOT_ALLOWANCES,
    SLOT_BALANCES,
};

fn erc20_hex() -> PathBuf {
    root().join("guests-compiled/evm/contracts/erc20.runtime.hex")
}

/// Translate and build the ERC-20 into `dir`.
fn build_erc20(dir: &std::path::Path, outcome: bool) -> (PathBuf, String) {
    build_shim(&erc20_hex(), dir, "erc20-evm2rv", outcome)
}

/// The two images, the default build (what a chain deploys) and the `emit-outcome` build, and
/// the default build's `hc`.
struct Images {
    plain: PathBuf,
    outcome: PathBuf,
    plain_hc: String,
}

fn images() -> &'static Images {
    static IMAGES: OnceLock<Images> = OnceLock::new();
    IMAGES.get_or_init(|| {
        let base = root().join("evm2rv/target/parity");
        let (plain, plain_hc) = build_erc20(&base.join("erc20"), false);
        let (outcome, _) = build_erc20(&base.join("erc20-outcome"), true);
        Images {
            plain,
            outcome,
            plain_hc,
        }
    })
}

/// The default ERC-20 translation's program digest. It binds the translator's output, evm-rt,
/// evm-core, guest-sdk, the pinned cc and the clang that compiled the C (build.rs prints its
/// version), so a change to any of them moves it — deliberately: re-derive it and say why.
const ERC20_HC: &str = "3307bfc4aaf87e4021941d18a9e813441354bb6fa19b357c5b604839e516579d";

/// `hc` of the default ERC-20 translation, pinned (fix round 1, item 7). Uses the parity build.
#[test]
fn the_default_erc20_translation_hc_is_pinned() {
    assert_eq!(images().plain_hc, ERC20_HC);
}

/// Runs `call` through the interpreter natively, `evm.bin` and both translated images; asserts
/// the parity the module doc lists, and returns `(interpreter cycles, translated cycles)`.
fn check(name: &str, call: &EvmCall, want_status: u32) -> (usize, usize) {
    let Images { plain, outcome, .. } = images();
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
