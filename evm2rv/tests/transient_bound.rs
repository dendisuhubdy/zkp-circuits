//! OPCODES-701: one bound on transient storage across every execution path that runs without the
//! RISC-V toolchain. A contract that `TSTORE`s 16 distinct non-zero keys stops; one with 17 halts
//! `OutOfBounds`. Each runs through
//!
//! * the interpreter (`evm-core`'s `interp.rs`, `MAX_TRANSIENT_SLOTS` and `transient.rs`), and
//! * `evm2rv`'s translation at both stages, built with the host `cc` against `evm-rt`
//!   (`evm_cancun.c`'s table, sized by `evm_rt.h`'s `MAX_TRANSIENT_SLOTS`) through the host
//!   harness (`common/host.rs`),
//!
//! and every path is held to the literal 16, not only to each other: a table of 15 on any one
//! side turns this red. `evm2rv` has no limit of its own — its translations call `evm_tstore`, so
//! its bound is `evm_rt.h`'s — and that define is checked against `interp.rs`'s constant here too
//! (as research's `the_c_gas_constants_and_limits_are_interp_rs` does), so the three agree by
//! construction and by behaviour.

mod common;

use std::sync::OnceLock;

use common::{host, root, STAGES};
use evm2rv::emit::{translate, Options};
use evm_core::interp::{Halt, MAX_TRANSIENT_SLOTS};
use evm_core::u256::U256;
use rand_zkvm::evm::{EvmCall, HostRef, SparseTree, ALICE, TOKEN};

/// The bound the audit pins (commit 9063e8e).
const BOUND: usize = 16;

/// `TSTORE(k, 1)` for k = 1..=n, then `STOP`.
fn tstores(n: usize) -> Vec<u8> {
    let mut code = Vec::new();
    for k in 1..=n {
        code.extend_from_slice(&[0x60, 0x01, 0x60, k as u8, 0x5d]);
    }
    code.push(0x00);
    code
}

fn call(n: usize) -> EvmCall {
    EvmCall {
        code: tstores(n),
        calldata: Vec::new(),
        address: TOKEN,
        caller: ALICE,
        callvalue: U256::ZERO,
        gas_limit: 1_000_000,
        tree: SparseTree::new(),
        touched: Vec::new(),
    }
}

/// Library contract index `2 * (n - BOUND) + stage`.
fn lib() -> &'static host::Lib {
    static L: OnceLock<host::Lib> = OnceLock::new();
    L.get_or_init(|| {
        let mut cs = Vec::new();
        for n in [BOUND, BOUND + 1] {
            for &stage in STAGES.iter() {
                cs.push(translate(&tstores(n), &Options { chain_id: None, stage }).unwrap().c);
            }
        }
        host::build("transient-bound", &cs)
    })
}

#[test]
fn the_transient_limit_constants_are_one_bound() {
    assert_eq!(MAX_TRANSIENT_SLOTS, BOUND, "interp.rs's MAX_TRANSIENT_SLOTS");
    let h = std::fs::read_to_string(root().join("evm-rt/evm_rt.h")).unwrap();
    let line = h
        .lines()
        .find(|l| l.starts_with("#define MAX_TRANSIENT_SLOTS "))
        .expect("MAX_TRANSIENT_SLOTS in evm_rt.h");
    let c: usize = line.split_whitespace().nth(2).unwrap().parse().unwrap();
    assert_eq!(c, MAX_TRANSIENT_SLOTS, "evm_rt.h (evm2rv's runtime) against interp.rs");
}

#[test]
fn sixteen_transient_keys_fit_and_a_seventeenth_halts_on_every_path() {
    let l = lib();
    for (i, n) in [BOUND, BOUND + 1].into_iter().enumerate() {
        let c = call(n);
        let (want, o, _) = c.expected();
        let (halt, status) =
            if n <= BOUND { (Halt::Stop, 1) } else { (Halt::OutOfBounds, 2) };
        assert_eq!(o.halt, halt, "interpreter, {n} keys");
        assert_eq!(want[0], status, "interpreter's status, {n} keys");
        let words = c.input_words();
        for (k, stage) in STAGES.iter().enumerate() {
            let (got, t, _) = l.run_words(&mut HostRef, 2 * i + k, &words);
            assert_eq!(got[0], status, "evm2rv {stage:?} + evm-rt, {n} keys: status");
            assert_eq!(got, want, "evm2rv {stage:?} + evm-rt, {n} keys: the eight words");
            assert_eq!(t.halt, o.halt, "evm2rv {stage:?} + evm-rt, {n} keys: the halt");
            assert_eq!(t.gas_used, o.gas_used, "evm2rv {stage:?} + evm-rt, {n} keys: gas_used");
        }
    }
}
