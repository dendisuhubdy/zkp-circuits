//! The ERC-20's vectors through the host harness (`common/host.rs`): the same calls
//! `tests/parity.rs` runs on the emulator — `transfer`, `approve`, `transferFrom`, the revert,
//! out-of-gas at three limits and the exact limit — plus the reads (`balanceOf`, `totalSupply`,
//! `allowance`), a transfer to self, a transfer of zero, a `transferFrom` over its allowance, an
//! unknown selector and empty calldata (the dispatcher reverts), and the code guard on a metadata
//! byte. Each runs at both stages against the native interpreter: the eight words, `gas_used`, the
//! return data and the logs; and each pins what it can (the status, `transfer`'s 29 956 gas, the
//! values the reads return, the revert's `Error(string)`).
//!
//! `tests/parity.rs` needs the pinned guest clang; this file needs only the host `cc`, so the
//! ERC-20's parity is checked on any machine.

mod common;

use std::sync::{Mutex, OnceLock};

use common::{host, STAGES};
use evm2rv::emit::{translate, Options};
use evm_core::abi::public_output;
use evm_core::interp::{Halt, Log, Outcome, MAX_LOGS, MAX_RETURN_BYTES};
use evm_core::u256::U256;
use rand_zkvm::evm::{
    abi_call, erc20_transfer, mapping_slot, mapping_slot2, EvmCall, HostRef, ALICE, BOB,
    SLOT_ALLOWANCES, SLOT_BALANCES, SLOT_TOTAL_SUPPLY,
};

/// The two translations of the ERC-20, built once; the runtime's state is global, so runs are
/// serialized.
fn lib() -> &'static (host::Lib, Mutex<()>) {
    static L: OnceLock<(host::Lib, Mutex<()>)> = OnceLock::new();
    L.get_or_init(|| {
        let code = rand_zkvm::evm::erc20_code();
        let cs: Vec<String> = STAGES
            .iter()
            .map(|&stage| {
                translate(
                    &code,
                    &Options {
                        chain_id: None,
                        stage,
                    },
                )
                .unwrap()
                .c
            })
            .collect();
        (host::build("erc20-host", &cs), Mutex::new(()))
    })
}

/// `call` through the interpreter and both stages; returns the interpreter's outcome.
fn check(name: &str, call: &EvmCall, status: u32) -> Outcome {
    let (l, m) = lib();
    let _g = m.lock().unwrap();
    let words = call.input_words();
    let (want, o, _) = call.expected();
    assert_eq!(want[0], status, "{name}: the oracle's status ({:?})", o.halt);
    for (k, stage) in STAGES.iter().enumerate() {
        let (got, t, _) = l.run_words(&mut HostRef, k, &words);
        assert_eq!(got, want, "{name} ({stage:?}): the eight words");
        assert_eq!(t.gas_used, o.gas_used, "{name} ({stage:?}): gas_used");
        assert_eq!(&t.ret[..t.ret_len], &o.ret[..o.ret_len], "{name} ({stage:?}): return data");
        assert_eq!(t.n_logs, o.n_logs, "{name} ({stage:?}): logs");
        if status != 2 {
            assert_eq!(t.halt, o.halt, "{name} ({stage:?}): the halt");
        }
    }
    eprintln!(
        "{name}: status {} halt {:?} gas_used {} logs {} ret {}",
        want[0],
        o.halt,
        o.gas_used,
        o.n_logs,
        hex::encode(&o.ret[..o.ret_len])
    );
    o
}

fn transfer_250() -> EvmCall {
    erc20_transfer(ALICE, BOB, U256::from_u32(250), &[(ALICE, U256::from_u32(1000))])
}

/// A read-only call on the transfer's pre-state: `sig(args)`, with witnesses for `touched`.
fn read(sig: &str, args: &[U256], touched: Vec<U256>) -> EvmCall {
    let mut c = transfer_250();
    c.calldata = abi_call(sig, args);
    c.touched = touched;
    c
}

/// Solidity's `Error(string)`: the selector, the offset 32, the length, the padded string.
fn error_string(msg: &str) -> Vec<u8> {
    let mut v = vec![0x08, 0xc3, 0x79, 0xa0];
    v.extend_from_slice(&U256::from_u32(32).to_be_bytes());
    v.extend_from_slice(&U256::from_u32(msg.len() as u32).to_be_bytes());
    let mut s = msg.as_bytes().to_vec();
    s.resize(s.len().div_ceil(32) * 32, 0);
    v.extend_from_slice(&s);
    v
}

#[test]
fn transfer_250_of_1000() {
    let o = check("transfer", &transfer_250(), 1);
    assert_eq!(o.gas_used, 29_956, "the README's figure");
    assert_eq!(o.n_logs, 1, "one Transfer event");
    assert_eq!(o.logs[0].n_topics, 3);
    assert_eq!(o.logs[0].topics[1], ALICE);
    assert_eq!(o.logs[0].topics[2], BOB);
    assert_eq!(o.ret[..32], U256::ONE.to_be_bytes(), "transfer returns true");
}

#[test]
fn transfer_to_self_and_of_zero() {
    let mut to_self = transfer_250();
    to_self.calldata = abi_call("transfer(address,uint256)", &[ALICE, U256::from_u32(250)]);
    to_self.touched = vec![mapping_slot(&ALICE, SLOT_BALANCES)];
    let o = check("transfer to self", &to_self, 1);
    assert_eq!(o.n_logs, 1);
    assert_eq!(o.ret[..32], U256::ONE.to_be_bytes());

    let mut zero = transfer_250();
    zero.calldata = abi_call("transfer(address,uint256)", &[BOB, U256::ZERO]);
    let o = check("transfer of zero", &zero, 1);
    assert_eq!(o.n_logs, 1);
    // All of it: ALICE's balance goes to zero (a reset) and BOB's from zero (a set).
    let mut all = transfer_250();
    all.calldata = abi_call("transfer(address,uint256)", &[BOB, U256::from_u32(1000)]);
    let o = check("transfer of the whole balance", &all, 1);
    assert_eq!(o.n_logs, 1);
}

#[test]
fn approve_and_transfer_from() {
    let mut ap = erc20_transfer(ALICE, BOB, U256::ZERO, &[]);
    ap.calldata = abi_call("approve(address,uint256)", &[BOB, U256::from_u32(5)]);
    ap.touched = vec![mapping_slot2(&ALICE, &BOB, SLOT_ALLOWANCES)];
    let o = check("approve", &ap, 1);
    assert_eq!(o.n_logs, 1, "one Approval event");
    assert_eq!(o.logs[0].n_topics, 3);
    assert_eq!(o.ret[..32], U256::ONE.to_be_bytes());

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
    let o = check("transferFrom", &tf, 1);
    assert_eq!(o.n_logs, 1, "this ERC-20's _spendAllowance emits no Approval: one Transfer");
    assert_eq!(o.logs[0].n_topics, 3);
    assert_eq!((o.logs[0].topics[1], o.logs[0].topics[2]), (ALICE, BOB));
    assert_eq!(o.ret[..32], U256::ONE.to_be_bytes());

    // Over the allowance: the revert names it.
    let mut over = EvmCall {
        code: tf.code.clone(),
        calldata: abi_call(
            "transferFrom(address,address,uint256)",
            &[ALICE, BOB, U256::from_u32(301)],
        ),
        address: tf.address,
        caller: BOB,
        callvalue: U256::ZERO,
        gas_limit: tf.gas_limit,
        tree: tf.tree.clone(),
        touched: tf.touched.clone(),
    };
    let o = check("transferFrom over the allowance", &over, 0);
    assert_eq!(&o.ret[..o.ret_len], &error_string("ERC20: insufficient allowance")[..]);
    assert_eq!(o.ret_len, 100, "selector, offset, length, the 29-byte string padded to 32");
    assert_eq!(o.n_logs, 0);
    // Exactly the allowance: fine.
    over.calldata = abi_call(
        "transferFrom(address,address,uint256)",
        &[ALICE, BOB, U256::from_u32(300)],
    );
    check("transferFrom of exactly the allowance", &over, 1);
}

#[test]
fn a_transfer_over_the_balance_reverts_with_error_string() {
    let over = erc20_transfer(ALICE, BOB, U256::from_u32(5000), &[(ALICE, U256::from_u32(1000))]);
    let o = check("revert", &over, 0);
    assert_eq!(
        &o.ret[..o.ret_len],
        &error_string("ERC20: transfer amount exceeds balance")[..]
    );
    assert_eq!(o.ret_len, 132);
    assert_eq!(o.n_logs, 0);
    // One over the balance, too.
    let over = erc20_transfer(ALICE, BOB, U256::from_u32(1001), &[(ALICE, U256::from_u32(1000))]);
    check("revert by one", &over, 0);
    // From an account with no balance at all.
    let none = erc20_transfer(BOB, ALICE, U256::ONE, &[(ALICE, U256::from_u32(1000))]);
    check("revert from an empty balance", &none, 0);
}

#[test]
fn out_of_gas_at_three_limits_and_the_exact_one() {
    let used = check("transfer", &transfer_250(), 1).gas_used;
    assert_eq!(used, 29_956);
    for gas in [100u64, 20_000, used - 1] {
        let mut call = transfer_250();
        call.gas_limit = gas;
        let o = check(&format!("out of gas at {gas}"), &call, 2);
        assert_eq!(o.gas_used, gas, "the limit spent");
        assert_eq!(o.halt, Halt::OutOfGas);
    }
    let mut exact = transfer_250();
    exact.gas_limit = used;
    let o = check("exact gas", &exact, 1);
    assert_eq!(o.gas_used, used);
    // Zero gas: the first block's head fails.
    let mut none = transfer_250();
    none.gas_limit = 0;
    let o = check("no gas at all", &none, 2);
    assert_eq!(o.gas_used, 0);
}

#[test]
fn the_reads_balance_of_total_supply_and_allowance() {
    let o = check(
        "balanceOf(ALICE)",
        &read("balanceOf(address)", &[ALICE], vec![mapping_slot(&ALICE, SLOT_BALANCES)]),
        1,
    );
    assert_eq!(o.ret[..32], U256::from_u32(1000).to_be_bytes());
    let o = check(
        "balanceOf(BOB)",
        &read("balanceOf(address)", &[BOB], vec![mapping_slot(&BOB, SLOT_BALANCES)]),
        1,
    );
    assert_eq!(o.ret[..32], U256::ZERO.to_be_bytes());
    let o = check(
        "totalSupply()",
        &read("totalSupply()", &[], vec![U256::from_u32(SLOT_TOTAL_SUPPLY)]),
        1,
    );
    assert_eq!(o.ret[..32], U256::from_u32(1000).to_be_bytes());
    let o = check(
        "allowance(ALICE, BOB) unset",
        &read(
            "allowance(address,address)",
            &[ALICE, BOB],
            vec![mapping_slot2(&ALICE, &BOB, SLOT_ALLOWANCES)],
        ),
        1,
    );
    assert_eq!(o.ret[..32], U256::ZERO.to_be_bytes());
    // A read without its witness is an exceptional halt.
    check("balanceOf(ALICE) without a witness", &read("balanceOf(address)", &[ALICE], vec![]), 2);
    // The reads make no state change and no log.
    assert_eq!(o.n_logs, 0);
}

#[test]
fn an_unknown_selector_and_empty_calldata_revert() {
    let mut c = transfer_250();
    c.calldata = vec![0xde, 0xad, 0xbe, 0xef];
    c.touched = vec![];
    let o = check("unknown selector", &c, 0);
    assert_eq!(o.ret_len, 0, "the fallback reverts with nothing");
    c.calldata = vec![];
    let o = check("empty calldata", &c, 0);
    assert_eq!(o.ret_len, 0);
    // A selector with its arguments cut short: Solidity's ABI decoder reverts.
    c.calldata = abi_call("transfer(address,uint256)", &[BOB]);
    let o = check("short calldata", &c, 0);
    assert_eq!(o.ret_len, 0);
}

/// The code guard on the host: the transfer with the last byte of solc's metadata changed runs
/// in the interpreter (status 1) and is refused by both translations with the `pre_halt` output.
#[test]
fn a_metadata_byte_changed_is_refused_on_the_host() {
    let (l, m) = lib();
    let _g = m.lock().unwrap();
    let mut call = transfer_250();
    *call.code.last_mut().unwrap() ^= 1;
    let words = call.input_words();
    let (interp, o, _) = call.expected();
    assert_eq!((interp[0], o.halt), (1, Halt::Return));
    let pre = Outcome {
        halt: Halt::OutOfBounds,
        gas_used: 0,
        ret: [0; MAX_RETURN_BYTES],
        ret_len: 0,
        logs: [Log::EMPTY; MAX_LOGS],
        n_logs: 0,
    };
    let root = call.tree.root();
    let want = public_output(&mut HostRef, &call.code, &root, &root, &pre);
    assert_ne!(want, interp);
    for (k, stage) in STAGES.iter().enumerate() {
        let (got, t, _) = l.run_words(&mut HostRef, k, &words);
        assert_eq!(got, want, "{stage:?}: the pre_halt output");
        assert_eq!((t.halt, t.gas_used), (Halt::OutOfBounds, 0), "{stage:?}");
    }
}
