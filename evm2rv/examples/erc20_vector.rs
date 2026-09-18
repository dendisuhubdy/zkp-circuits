//! The ERC-20 input vectors the parity test runs, printed for `rand-guest run --input`.
//!
//! ```text
//! cargo +1.98.1 run --release --example erc20_vector -- transfer > transfer.words
//! rand-guest run image.bin --input $(cat transfer.words)
//! ```
//!
//! `<vector>` is `transfer` (ALICE sends BOB 250 of her 1 000), `approve` (ALICE lets BOB spend
//! 5) or `transferFrom` (BOB moves 100 of ALICE's 1 000 against an allowance of 300). They are
//! `tests/parity.rs`'s vectors, built from research's fixtures (`rand_zkvm::evm`). The words are
//! the interpreter's exact input vector: the code, the calldata, the environment, the gas limit,
//! the pre-state root and one storage witness per slot the call touches.
//!
//! With `--expected`, it prints instead what the interpreter publishes for that vector, run
//! natively on the host, as `rand-guest run` prints its outputs (`out[i] = w`).

use evm_core::u256::U256;
use rand_zkvm::evm::{
    abi_call, erc20_transfer, mapping_slot, mapping_slot2, EvmCall, ALICE, BOB, SLOT_ALLOWANCES,
    SLOT_BALANCES,
};

fn vector(name: &str) -> Option<EvmCall> {
    Some(match name {
        "transfer" => erc20_transfer(
            ALICE,
            BOB,
            U256::from_u32(250),
            &[(ALICE, U256::from_u32(1000))],
        ),
        "approve" => {
            let mut ap = erc20_transfer(ALICE, BOB, U256::ZERO, &[]);
            ap.calldata = abi_call("approve(address,uint256)", &[BOB, U256::from_u32(5)]);
            ap.touched = vec![mapping_slot2(&ALICE, &BOB, SLOT_ALLOWANCES)];
            ap
        }
        "transferFrom" => {
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
            tf
        }
        _ => return None,
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let expected = args.iter().any(|a| a == "--expected");
    let names: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let (Some(name), 1) = (names.first(), names.len()) else {
        eprintln!("usage: erc20_vector <transfer|approve|transferFrom> [--expected]");
        std::process::exit(2);
    };
    let Some(call) = vector(name) else {
        eprintln!("unknown vector {name}: the vectors are transfer, approve and transferFrom");
        std::process::exit(2);
    };
    if expected {
        let (out, o, _) = call.expected();
        for (i, w) in out.iter().enumerate() {
            println!("out[{i}] = {w}");
        }
        eprintln!(
            "interpreter (native): status {}, {:?}, gas_used {}",
            out[0], o.halt, o.gas_used
        );
    } else {
        let words: Vec<String> = call.input_words().iter().map(u32::to_string).collect();
        println!("{}", words.join(" "));
        eprintln!("{} input words", words.len());
    }
}
