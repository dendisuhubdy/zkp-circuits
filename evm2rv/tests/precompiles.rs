//! Task 5's end-to-end test: a translated contract that calls two precompiles, sha256 (2) and
//! ecrecover (1), by STATICCALL. solc is not installed here, so the contract is hand-assembled
//! (below, opcode by opcode); the expected words are the known answers (FIPS 180-2's
//! sha256("abc"), go-ethereum's ecRecover.json `ValidKey`), and the gas is Shanghai's, worked by
//! hand in [`CONTRACT`]'s table. The interpreter traps on every call, so it is no oracle here
//! (controller ruling 1).
//!
//! evm2rv translates it, `rand-guest build` builds the shim twice (the default image and the
//! `emit-outcome` one, as in `parity.rs`), and each vector's eight public words are compared with
//! `evm_core::abi::run_call_with_executor` over the expected `Outcome` — the same decoding, the
//! same digest — so the words bind the return data. The `emit-outcome` build adds the halt and
//! `gas_used`.
//!
//! The ecrecover call itself runs ~14.5 million cycles (the report's table: past the largest
//! tier, 2^20, so unprovable today and in the coprocessor backlog). `rand-guest run` stops at that
//! tier's budget, so the vectors in which it runs are executed by the shared cycle counter
//! (`rand-guest/tests/support/count.rs`: the emulator's semantics without its per-cycle log), and
//! `rand-guest run` is shown to run out on them. The vector whose ecrecover call fails for want
//! of gas (2 999 of the 3 000 it costs) runs on `rand-guest run` itself.

mod common;
#[path = "../../rand-guest/tests/support/count.rs"]
mod count;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use common::{build_shim, encoded_halt, root, run, run_out_of_cycles};
use evm_core::abi::{run_call_with_executor, Workspace};
use evm_core::interp::{Halt, Log, Outcome, MAX_LOGS, MAX_RETURN_BYTES};
use evm_core::u256::U256;
use rand_zkvm::evm::{EvmCall, HostRef, SparseTree, ALICE, TOKEN};
use rand_zkvm::isa::Program;

/// go-ethereum's ecRecover.json `ValidKey`: hash, v = 28, r, s — and the address it recovers.
const ECRECOVER_IN: &str = "18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c\
                            000000000000000000000000000000000000000000000000000000000000001c\
                            73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f\
                            eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549";
const ECRECOVER_OUT: &str = "000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b";
/// FIPS 180-2 B.1: sha256("abc").
const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

/// The contract, with each op's Shanghai static gas and what the runtime charges (the memory
/// expansion is 3w + w^2/512 for w words, so each step here is 3 per new word):
///
/// | ops | static | dynamic |
/// |---|---|---|
/// | PUSH3 "abc", PUSH1 0, MSTORE                       | 9  | memory to 1 word: 3 |
/// | PUSH1 128, PUSH2 data, PUSH1 32, CODECOPY           | 12 | 4 words copied: 12; memory to 5 words: 12 |
/// | STATICCALL(GAS, 2, 29, 3, 0xa0, 32)                 | 5 PUSH1 + GAS = 17 | 100 + memory to 6 words: 3 + sha256 60 + 12 = 175 |
/// | STATICCALL(CALLDATALOAD(0), 1, 32, 128, 0xc0, 32)   | 5 PUSH1 + PUSH1 + CALLDATALOAD = 21 | 100 + memory to 7 words: 3 + ecrecover 3 000 (or the 2 999 a failing call is passed) |
/// | PUSH1 2, MUL, ADD                                   | 11 | |
/// | RETURNDATASIZE, PUSH2 256, MUL, ADD                 | 13 | |
/// | PUSH1 0xe0, MSTORE                                  | 6  | memory to 8 words: 3 |
/// | RETURNDATACOPY(0x100, 0, RETURNDATASIZE)            | 11 | 32 bytes: 3 + memory to 9 words: 3 (none when it copies nothing) |
/// | RETURN(0xa0, 128)                                   | 6  | memory to 9 words: 3 when RETURNDATACOPY did not get there |
/// | INVALID, then the 128 bytes of ecrecover's input    |    | |
///
/// Static 106. Both calls succeeding: 106 + 3 + 24 + 175 + 3 103 + 3 + 6 = 3 420. The ecrecover
/// call passed 2 999: 106 + 3 + 24 + 175 + 3 102 + 3 + 0 + 3 = 3 416. The words returned are
/// mem[0xa0..0x120): the sha256 digest, ecrecover's output (the ret region), the flags
/// s_sha + 2 s_ecrecover + 256 RETURNDATASIZE, and ecrecover's output again (RETURNDATACOPY).
fn contract() -> Vec<u8> {
    let mut c: Vec<u8> = vec![
        0x62, 0x61, 0x62, 0x63, // PUSH3 "abc"
        0x60, 0x00, 0x52, // PUSH1 0, MSTORE: "abc" at 29..32
        0x60, 0x80, // PUSH1 128 (size)
        0x61, 0x00, 0x00, // PUSH2 data (patched below)
        0x60, 0x20, 0x39, // PUSH1 32 (dest), CODECOPY
        0x60, 0x20, 0x60, 0xa0, 0x60, 0x03, 0x60, 0x1d, 0x60,
        0x02, // retLen, retOff, argsLen, argsOff, 2
        0x5a, 0xfa, // GAS, STATICCALL
        0x60, 0x20, 0x60, 0xc0, 0x60, 0x80, 0x60, 0x20, 0x60,
        0x01, // retLen, retOff, argsLen, argsOff, 1
        0x60, 0x00, 0x35, 0xfa, // CALLDATALOAD(0), STATICCALL
        0x60, 0x02, 0x02, 0x01, // PUSH1 2, MUL, ADD
        0x3d, 0x61, 0x01, 0x00, 0x02, 0x01, // RETURNDATASIZE, PUSH2 256, MUL, ADD
        0x60, 0xe0, 0x52, // PUSH1 0xe0, MSTORE
        0x3d, 0x60, 0x00, 0x61, 0x01, 0x00, 0x3e, // RETURNDATACOPY(0x100, 0, RETURNDATASIZE)
        0x60, 0x80, 0x60, 0xa0, 0xf3, // RETURN(0xa0, 128)
        0xfe, // INVALID: the data follows
    ];
    let data = c.len() as u16;
    c[10..12].copy_from_slice(&data.to_be_bytes());
    c.extend(hex::decode(ECRECOVER_IN).unwrap());
    c
}

fn word(v: u32) -> Vec<u8> {
    let mut w = vec![0u8; 32];
    w[28..].copy_from_slice(&v.to_be_bytes());
    w
}

/// A call of the contract with `requested` as ecrecover's gas, under `gas_limit`.
fn call(requested: u32, gas_limit: u64) -> EvmCall {
    EvmCall {
        code: contract(),
        calldata: word(requested),
        address: TOKEN,
        caller: ALICE,
        callvalue: U256::ZERO,
        gas_limit,
        tree: SparseTree::new(),
        touched: Vec::new(),
    }
}

/// The eight public words for `call` finishing with `halt`, `ret` and `gas_used`: the harness's
/// own decoding and digest over that outcome.
fn expected(call: &EvmCall, halt: Halt, ret: &[u8], gas_used: u64) -> [u32; 8] {
    let words = call.input_words();
    let mut ws = Box::new(Workspace::ZERO);
    let mut exec = |_: &mut HostRef, _: &[u8], _: &[u8], _, _: &mut _, _: &mut _| {
        let mut o = Outcome {
            halt,
            gas_used,
            ret: [0; MAX_RETURN_BYTES],
            ret_len: ret.len(),
            logs: [Log::EMPTY; MAX_LOGS],
            n_logs: 0,
        };
        o.ret[..ret.len()].copy_from_slice(ret);
        o
    };
    run_call_with_executor(
        &mut HostRef,
        &mut ws,
        |i| words[i as usize],
        words.len() as u32,
        &mut exec,
    )
    .0
}

struct Images {
    plain: PathBuf,
    outcome: PathBuf,
}

fn images() -> &'static Images {
    static IMAGES: OnceLock<Images> = OnceLock::new();
    IMAGES.get_or_init(|| {
        let base = root().join("evm2rv/target/precompiles");
        std::fs::create_dir_all(&base).unwrap();
        let hex_path = base.join("calls.hex");
        std::fs::write(&hex_path, hex::encode(contract())).unwrap();
        let (plain, _) = build_shim(&hex_path, &base.join("calls"), "calls-evm2rv", false);
        let (outcome, _) = build_shim(&hex_path, &base.join("calls-outcome"), "calls-evm2rv", true);
        Images { plain, outcome }
    })
}

/// The eight words of `image` on `call`: `rand-guest run` when it fits the largest tier, else the
/// cycle counter (after checking that `rand-guest run` does run out).
fn words(image: &Path, call: &EvmCall, fits: bool) -> [u32; 8] {
    let input = call.input_words();
    let program = Program::from_flat_image(&std::fs::read(image).unwrap()).unwrap();
    let (out, n) = count::count(&program, &input, 100_000_000).expect("the counter");
    if fits {
        // Where the run fits, the counter is the emulator: the same words, the same cycles.
        let (got, cycles) = run(image, &input);
        assert_eq!(
            (got, cycles as u64),
            (out, n),
            "the counter against rand-guest run"
        );
        eprintln!("{}: {n} cycles (rand-guest run)", image.display());
        return got;
    }
    assert!(
        run_out_of_cycles(image, &input).is_some(),
        "expected to pass 2^20 cycles"
    );
    eprintln!("{}: {n} cycles (counted)", image.display());
    out
}

fn check(name: &str, call: &EvmCall, fits: bool, halt: Halt, ret: &[u8], gas_used: u64) {
    let Images { plain, outcome } = images();
    let want = expected(call, halt, ret, gas_used);
    assert_eq!(
        words(plain, call, fits),
        want,
        "{name}: the eight public words"
    );
    let dbg = words(outcome, call, fits);
    assert_eq!(
        dbg[..6],
        want[..6],
        "{name}: the emit-outcome build's status and digest"
    );
    let o = Outcome {
        halt,
        gas_used,
        ret: [0; MAX_RETURN_BYTES],
        ret_len: 0,
        logs: [Log::EMPTY; MAX_LOGS],
        n_logs: 0,
    };
    assert_eq!(dbg[6], encoded_halt(&o), "{name}: the halt");
    assert_eq!(dbg[7] as u64, gas_used, "{name}: gas_used");
}

fn returned(ec_ok: bool) -> Vec<u8> {
    let ec = if ec_ok {
        hex::decode(ECRECOVER_OUT).unwrap()
    } else {
        vec![0; 32]
    };
    let flags = if ec_ok { 1 + 2 + 256 * 32 } else { 1 };
    [
        hex::decode(SHA256_ABC).unwrap(),
        ec.clone(),
        word(flags),
        ec,
    ]
    .concat()
}

/// Both calls succeed: the sha256 digest, the recovered address twice (through the ret region
/// and through RETURNDATACOPY), and the flags 0x2003.
#[test]
fn sha256_and_ecrecover_by_staticcall() {
    check(
        "both",
        &call(3000, 100_000),
        false,
        Halt::Return,
        &returned(true),
        3420,
    );
}

/// ecrecover passed 2 999 gas of the 3 000 it costs: the call fails (0), its gas is gone, the
/// return data is empty (RETURNDATASIZE 0, a zero-length RETURNDATACOPY) and its ret region is
/// untouched. Nothing past 2^20 cycles runs, so this is `rand-guest run` itself.
#[test]
fn an_ecrecover_call_without_the_gas_fails_and_the_contract_goes_on() {
    check(
        "underfunded",
        &call(2999, 100_000),
        true,
        Halt::Return,
        &returned(false),
        3416,
    );
}

/// The exact gas succeeds; one less is an exceptional halt that consumes the limit.
#[test]
fn the_exact_gas_and_one_less() {
    check(
        "exact",
        &call(3000, 3420),
        false,
        Halt::Return,
        &returned(true),
        3420,
    );
    check(
        "one short",
        &call(3000, 3419),
        false,
        Halt::OutOfGas,
        &[],
        3419,
    );
}

/// The CLI names the two calls as trapping unless their target is a precompile.
#[test]
fn the_cli_warns_on_each_call() {
    let dir = root().join("evm2rv/target/precompiles");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("warn.hex");
    std::fs::write(&path, hex::encode(contract())).unwrap();
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_evm2rv"))
        .arg(&path)
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{s}");
    assert_eq!(
        s.matches("STATICCALL (0xfa) traps (status 2) unless the target is a precompile")
            .count(),
        2,
        "{s}"
    );
}
