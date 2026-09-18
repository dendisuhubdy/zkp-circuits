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
//! Every vector runs under both stages (Task 8): the stage-one and the stage-two translation each
//! build their two images, and each is held to the same oracle. Each stage's default image has its
//! own pinned `hc`.
//!
//! No RISC-V clang is a failure here, not a skip: the shim's `build.rs` panics naming the clang it
//! could not find, and `rand-guest build` fails with it.

mod common;

use std::path::PathBuf;
use std::sync::OnceLock;

use common::{build_shim, encoded_halt, root, run, run_tier, STAGES};
use evm2rv::emit::Stage;
use evm_core::abi::public_output;
use evm_core::interp::{Halt, Log, Outcome, MAX_LOGS, MAX_RETURN_BYTES};
use evm_core::u256::U256;
use rand_zkvm::evm::{
    abi_call, erc20_transfer, mapping_slot, mapping_slot2, EvmCall, HostRef, ALICE, BOB,
    SLOT_ALLOWANCES, SLOT_BALANCES,
};

fn erc20_hex() -> PathBuf {
    root().join("guests-compiled/evm/contracts/erc20.runtime.hex")
}

/// Translate and build the ERC-20 into `dir`.
fn build_erc20(dir: &std::path::Path, outcome: bool, stage: Stage) -> (PathBuf, String) {
    build_shim(&erc20_hex(), dir, "erc20-evm2rv", outcome, stage)
}

/// The two images, the default build (what a chain deploys) and the `emit-outcome` build, and
/// the default build's `hc`.
struct Images {
    plain: PathBuf,
    outcome: PathBuf,
    plain_hc: String,
}

fn images(stage: Stage) -> &'static Images {
    static ONE: OnceLock<Images> = OnceLock::new();
    static TWO: OnceLock<Images> = OnceLock::new();
    let (cell, dir) = match stage {
        Stage::One => (&ONE, "erc20"),
        Stage::Two => (&TWO, "erc20-stage2"),
    };
    cell.get_or_init(|| {
        let base = root().join("evm2rv/target/parity");
        let (plain, plain_hc) = build_erc20(&base.join(dir), false, stage);
        let (outcome, _) = build_erc20(&base.join(format!("{dir}-outcome")), true, stage);
        Images {
            plain,
            outcome,
            plain_hc,
        }
    })
}

/// The stage-one ERC-20 translation's program digest. It binds the translator's output, evm-rt,
/// evm-core, guest-sdk, the pinned cc and the clang that compiled the C (build.rs prints its
/// version), so a change to any of them moves it — deliberately: re-derive it and say why.
///
/// Re-derived in Task 9 for the code guard (the digest of the source bytecode in `contract.c`, and
/// the check in `main.rs`); it was `3307bfc4…579d`. `--no-default-config` alone does not move it.
const ERC20_HC: &str = "9cdb79e7f05d53f6503f0eb777bb0c2356d29cab516a0378864802e42fd048c8";

/// The same for the stage-two translation (Task 8): a different program, so a different digest.
/// Re-derived in Task 9 for the code guard; it was `87aba574…0ccad`.
const ERC20_HC_STAGE2: &str = "a0feae92a7311c9562495717100eb7aea71270a38ed435d06dc31387e0ea8ff6";

/// `hc` of the stage-one ERC-20 translation (`--stage 1`), pinned (fix round 1, item 7). Uses
/// the parity build.
#[test]
fn the_stage_one_erc20_translation_hc_is_pinned() {
    assert_eq!(images(Stage::One).plain_hc, ERC20_HC);
}

/// `hc` of the stage-two ERC-20 translation (`--stage 2`), pinned.
#[test]
fn the_stage_two_erc20_translation_hc_is_pinned() {
    assert_eq!(images(Stage::Two).plain_hc, ERC20_HC_STAGE2);
}

/// Runs `call` through the interpreter natively, `evm.bin` and both translated images of each
/// stage; asserts the parity the module doc lists, and returns `(interpreter cycles, stage-one
/// cycles, stage-two cycles)`.
fn check(name: &str, call: &EvmCall, want_status: u32) -> (usize, usize, usize) {
    let words = call.input_words();
    let (want, o, _post) = call.expected();
    assert_eq!(want[0], want_status, "{name}: the oracle's own status");

    let (interp, interp_cycles, interp_tier) =
        run_tier(&root().join("guests-compiled/bin/evm.bin"), &words);
    assert_eq!(
        interp, want,
        "{name}: evm.bin disagrees with the native interpreter"
    );

    let mut cycles = [0usize; 2];
    let mut tiers = [None; 2];
    for (k, stage) in STAGES.into_iter().enumerate() {
        let Images { plain, outcome, .. } = images(stage);
        let (got, c, tier) = run_tier(plain, &words);
        tiers[k] = tier;
        assert_eq!(
            got, want,
            "{name} ({stage:?}): the translated program's eight public words"
        );

        let (dbg, _) = run(outcome, &words);
        assert_eq!(
            dbg[..6],
            want[..6],
            "{name} ({stage:?}): the emit-outcome build's status and digest words 0..4"
        );
        assert_eq!(
            dbg[6],
            encoded_halt(&o),
            "{name} ({stage:?}): the halt ({:?} in the interpreter)",
            o.halt
        );
        assert_eq!(dbg[7] as u64, o.gas_used, "{name} ({stage:?}): gas_used");
        cycles[k] = c;
    }

    eprintln!(
        "{name}: status {} halt {:?} gas_used {} — cycles (tier): interpreter {interp_cycles} ({interp_tier:?}), stage one {} ({:?}), stage two {} ({:?})",
        want[0], o.halt, o.gas_used, cycles[0], tiers[0], cycles[1], tiers[1]
    );
    (interp_cycles, cycles[0], cycles[1])
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

/// The code guard (Task 9): the transfer with its code one byte different — the last byte, inside
/// solc's metadata trailer, which no path executes. The interpreter runs it exactly as the real
/// code (status 1). Both translations refuse it before any translated code runs: status 2,
/// `gas_used` 0, `OutOfBounds` — the interpreter's `pre_halt` — and publish exactly the `pre_halt`
/// output for that code. This is accepted divergence #3.
#[test]
fn a_code_one_byte_different_is_refused_by_the_guard() {
    let mut call = transfer_250();
    *call.code.last_mut().unwrap() ^= 1;
    let words = call.input_words();
    let (interp, o, _) = call.expected();
    assert_eq!(
        (interp[0], o.halt),
        (1, Halt::Return),
        "the interpreter runs the other code"
    );
    let (evm_bin, _) = run(&root().join("guests-compiled/bin/evm.bin"), &words);
    assert_eq!(evm_bin, interp, "evm.bin runs the other code too");

    let pre = Outcome {
        halt: Halt::OutOfBounds,
        gas_used: 0,
        ret: [0; MAX_RETURN_BYTES],
        ret_len: 0,
        logs: [Log::EMPTY; MAX_LOGS],
        n_logs: 0,
    };
    let root_before = call.tree.root();
    let want = public_output(&mut HostRef, &call.code, &root_before, &root_before, &pre);
    for stage in STAGES {
        let Images { plain, outcome, .. } = images(stage);
        let (got, cycles, tier) = run_tier(plain, &words);
        assert_eq!(
            got, want,
            "{stage:?}: the pre_halt output for the other code"
        );
        let (dbg, _) = run(outcome, &words);
        assert_eq!(
            (dbg[0], dbg[6], dbg[7]),
            (2, encoded_halt(&pre), 0),
            "{stage:?}: status 2, OutOfBounds, gas_used 0"
        );
        eprintln!("guard ({stage:?}): refused in {cycles} cycles (tier {tier:?})");
    }
}
