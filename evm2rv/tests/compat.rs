//! The compatibility table against the code (ZKVM-121's acceptance: "a published compatibility
//! table that matches the code, with a test that walks every opcode byte and checks the table").
//!
//! `evm2rv::compat` is a description; nothing in the translator reads it. These tests are what
//! hold it to the two things it describes:
//!
//! - **the walk**: each of the 256 opcode bytes, as a one-opcode program, through the interpreter
//!   (`evm_core`, natively — the code `evm.bin` is built from) and through a translation at both
//!   stages (built for the host, `common/host.rs`). The halt each path reports must be the one
//!   the table's `Behaviour` says. Change what an opcode does on either path without changing the
//!   table and this fails.
//! - **the conditional rows** (`RunsIf`): `RETURNDATACOPY` with a non-zero length, and the call
//!   family against a precompile, a non-precompile and a non-zero value.
//! - **the precompile rows**: a `STATICCALL` to every listed address, and to some unlisted ones.
//! - **the gas rows**: the static figure against `interp.rs`'s on every byte, and each rule the
//!   table states in words (`SLOAD`, `SSTORE`, the dynamic costs), run on both paths.
//! - **the caps**: a range past the memory, return data past its cap and a ninth log halt
//!   `OutOfBounds`, not out-of-gas.
//! - **the published file**: `COMPATIBILITY.md` is `compat::markdown()`.
//! - **`evm2rv check`**: over the committed contracts and a hand-made one.

mod common;

use std::path::PathBuf;
use std::process::Command;

use common::{host, root, STAGES};
use evm2rv::blocks;
use evm2rv::compat::{self, Behaviour, Gas, Severity};
use evm2rv::emit::{translate, Options, Stage};
use evm_core::interp::{Halt, Outcome};
use evm_core::u256::U256;
use rand_zkvm::evm::{erc20_transfer, EvmCall, HostRef, ALICE, BOB};

/// Far more than any probe spends, so no probe halts for want of gas.
const GAS: u64 = 10_000_000;
/// The constant the translations' `CHAINID` pushes.
const CHAIN_ID: u64 = 0x1234;

/// A call of `code` with no calldata and a witness for slot 0 (so `SLOAD`/`SSTORE` of slot 0
/// run). Built from the ERC-20 fixture rather than as a struct literal, so a field added to
/// `EvmCall` does not break this file.
fn call(code: &[u8]) -> EvmCall {
    let mut c = erc20_transfer(ALICE, BOB, U256::ZERO, &[]);
    c.code = code.to_vec();
    c.calldata = Vec::new();
    c.touched = vec![U256::ZERO];
    c.gas_limit = GAS;
    c
}

/// Both stages' translations of every code, stage one's first: contract `k * codes.len() + i` is
/// code `i` at `STAGES[k]`.
fn translations(codes: &[Vec<u8>]) -> Vec<String> {
    STAGES
        .iter()
        .flat_map(|&stage| {
            codes.iter().map(move |c| {
                translate(
                    c,
                    &Options {
                        chain_id: Some(CHAIN_ID),
                        stage,
                    },
                )
                .unwrap()
                .c
            })
        })
        .collect()
}

/// The translation of code `i` (of `n`) at each stage, run over `call`.
fn translated(lib: &host::Lib, n: usize, i: usize, call: &EvmCall) -> Vec<(Stage, [u32; 8], Outcome)> {
    let words = call.input_words();
    STAGES
        .iter()
        .enumerate()
        .map(|(k, &stage)| {
            let (out, o, _) = lib.run_words(&mut HostRef, k * n + i, &words);
            (stage, out, o)
        })
        .collect()
}

/// Seventeen `PUSH0`s — the deepest any opcode reaches (`SWAP16`) — then `op`. Every operand is
/// zero, so an opcode that runs halts for no reason of its own: the run falls off the end
/// (`Stop`), except the three in [`running_halt`].
fn probe(op: u8) -> Vec<u8> {
    let mut c = vec![0x5f; 17];
    c.push(op);
    c
}

/// What a probe halts with when its opcode runs: `JUMP` to 0 (a `PUSH0`, not a `JUMPDEST`) is a
/// bad jump, `RETURN` and `REVERT` are themselves, and everything else falls off the end.
fn running_halt(op: u8) -> Halt {
    match op {
        0x56 => Halt::BadJump,
        0xf3 => Halt::Return,
        0xfd => Halt::Revert,
        _ => Halt::Stop,
    }
}

/// The halt the table predicts for `op`'s probe on a path with behaviour `b`. `RunsIf` is
/// resolved for the probe's all-zero operands: `RETURNDATACOPY` of length zero runs; a call to
/// address zero is not a call to a precompile, so it traps.
fn predicted(op: u8, b: Behaviour) -> Halt {
    match b {
        Behaviour::Runs => running_halt(op),
        Behaviour::RunsIf if op == 0x3e => Halt::Stop,
        Behaviour::RunsIf => {
            assert!(
                blocks::CALL_FAMILY.contains(&op),
                "{op:#04x} is RunsIf and this test has no rule for it"
            );
            Halt::Trap(op)
        }
        Behaviour::Traps | Behaviour::Undefined => Halt::Trap(op),
        Behaviour::Invalid => Halt::Invalid,
    }
}

#[test]
fn every_opcode_byte_does_what_the_table_says_on_both_paths() {
    let codes: Vec<Vec<u8>> = (0..=255u8).map(probe).collect();
    let lib = host::build("compat-walk", &translations(&codes));
    let mut seen = [0usize; 5];
    for op in 0..=255u8 {
        let row = compat::opcode(op);
        let name = row.name.clone().unwrap_or_else(|| format!("{op:#04x}"));
        let c = call(&codes[op as usize]);

        // The interpreter, natively.
        let (want_words, o, _) = c.expected();
        assert_eq!(
            o.halt,
            predicted(op, row.interp),
            "{name} ({op:#04x}): the table says the interpreter {:?}, and it halted {:?}",
            row.interp,
            o.halt
        );
        // "Undefined" and "traps" are the same halt; what tells them apart is the name.
        assert_eq!(
            row.interp == Behaviour::Undefined,
            compat::name(op).starts_with("UNDEFINED"),
            "{op:#04x}: undefined in the table iff it has no mnemonic"
        );
        assert_eq!(
            row.xlat == Behaviour::Undefined,
            row.interp == Behaviour::Undefined,
            "{op:#04x}: undefined on one path only"
        );

        // A translation, at both stages.
        for (stage, words, t) in translated(&lib, codes.len(), op as usize, &c) {
            assert_eq!(
                t.halt,
                predicted(op, row.xlat),
                "{name} ({op:#04x}, {stage:?}): the table says a translation {:?}, and it halted {:?}",
                row.xlat,
                t.halt
            );
            // Where the table gives both paths the same behaviour, the public words and the gas
            // are the same too.
            if row.interp == row.xlat {
                assert_eq!(words, want_words, "{name} ({stage:?}): the eight words");
                assert_eq!(t.gas_used, o.gas_used, "{name} ({stage:?}): gas_used");
            }
            // An opcode that runs and falls off the end spent the seventeen PUSH0s, its static
            // gas and, for the few with a dynamic part, that part at zero operands.
            if t.halt == Halt::Stop && row.xlat != Behaviour::RunsIf {
                let dynamic = match op {
                    0x0a => compat::EXP_BASE,
                    0x20 => compat::KECCAK_BASE,
                    0x55 => compat::SSTORE_RESET,
                    0x51 | 0x52 | 0x53 => compat::memory_cost(1),
                    0xa0..=0xa4 => {
                        compat::LOG_BASE + compat::LOG_PER_TOPIC * (op - 0xa0) as u64
                    }
                    _ => 0,
                };
                assert_eq!(
                    t.gas_used,
                    17 * 2 + row.static_gas + dynamic,
                    "{name} ({stage:?}): the gas of its probe"
                );
            }
        }
        seen[match row.interp {
            Behaviour::Runs => 0,
            Behaviour::RunsIf => 1,
            Behaviour::Traps => 2,
            Behaviour::Invalid => 3,
            Behaviour::Undefined => 4,
        }] += 1;
    }
    eprintln!(
        "interpreter: {} run, {} run for some operands, {} trap, {} invalid, {} undefined",
        seen[0], seen[1], seen[2], seen[3], seen[4]
    );
    assert_eq!(seen.iter().sum::<usize>(), 256);
}

/// `PUSH1 v`.
fn p1(v: u8) -> [u8; 2] {
    [0x60, v]
}

/// The call-family opcode `op` to `address` with `gas` requested, no input, no output and (for
/// `CALL`/`CALLCODE`) `value`; then the success flag returned as one word.
fn call_code(op: u8, address: u16, value: u8, gas: u32) -> Vec<u8> {
    let mut c = vec![0x5f, 0x5f, 0x5f, 0x5f]; // retLen, retOff, argsLen, argsOff
    if op == 0xf1 || op == 0xf2 {
        c.extend(p1(value));
    }
    c.push(0x61); // PUSH2 address
    c.extend(address.to_be_bytes());
    c.push(0x62); // PUSH3 gas
    c.extend(&gas.to_be_bytes()[1..]);
    c.push(op);
    c.extend([0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]); // PUSH0 MSTORE, PUSH1 32 PUSH0 RETURN
    c
}

/// The gas [`call_code`] spends around the call itself: its pushes, and returning the flag.
fn call_overhead(op: u8) -> u64 {
    let value = if op == 0xf1 || op == 0xf2 { 3 } else { 0 };
    4 * 2 + value + 3 + 3 + (2 + 3 + compat::memory_cost(1)) + (3 + 2)
}

/// The word a run returned.
fn returned_word(o: &Outcome) -> U256 {
    assert_eq!(o.ret_len, 32, "one word returned");
    U256::from_be_bytes(o.ret[..32].try_into().unwrap())
}

#[test]
fn the_conditional_rows_trap_exactly_where_the_table_says() {
    // RETURNDATACOPY of one byte, in a contract that makes no call.
    let rdc: Vec<u8> = [&p1(1)[..], &[0x5f, 0x5f, 0x3e]].concat();
    // Each call opcode: to identity (4), to address 10 (no such precompile here), to address 0,
    // and to identity with a value.
    let mut codes = vec![rdc];
    for &op in &blocks::CALL_FAMILY {
        codes.push(call_code(op, 4, 0, 100_000));
        codes.push(call_code(op, 0x0a, 0, 100_000));
        codes.push(call_code(op, 0, 0, 100_000));
        codes.push(call_code(op, 4, 1, 100_000));
    }
    let lib = host::build("compat-conditional", &translations(&codes));

    let row = compat::opcode(0x3e);
    assert_eq!((row.interp, row.xlat), (Behaviour::RunsIf, Behaviour::RunsIf));
    let c = call(&codes[0]);
    assert_eq!(c.expected().1.halt, Halt::Trap(0x3e));
    for (stage, _, t) in translated(&lib, codes.len(), 0, &c) {
        assert_eq!(t.halt, Halt::Trap(0x3e), "RETURNDATACOPY of one byte ({stage:?})");
    }

    for (k, &op) in blocks::CALL_FAMILY.iter().enumerate() {
        let row = compat::opcode(op);
        assert_eq!(
            (row.interp, row.xlat),
            (Behaviour::Traps, Behaviour::RunsIf),
            "{op:#04x}: the call family's row"
        );
        let has_value = op == 0xf1 || op == 0xf2;
        for (j, what) in ["identity", "address 10", "address 0", "identity with a value"]
            .iter()
            .enumerate()
        {
            let i = 1 + 4 * k + j;
            let c = call(&codes[i]);
            // The interpreter traps on every call.
            assert_eq!(c.expected().1.halt, Halt::Trap(op), "{op:#04x} to {what}: interpreter");
            // A translation runs the call to a precompile with no value, and traps otherwise.
            // DELEGATECALL and STATICCALL carry no value, so their fourth case is the first.
            let runs = j == 0 || (j == 3 && !has_value);
            for (stage, _, t) in translated(&lib, codes.len(), i, &c) {
                if runs {
                    assert_eq!(t.halt, Halt::Return, "{op:#04x} to {what} ({stage:?})");
                    assert_eq!(returned_word(&t), U256::ONE, "{op:#04x} to {what}: success");
                    // identity over nothing: 15.
                    assert_eq!(
                        t.gas_used,
                        call_overhead(op) + compat::CALL_ACCESS + 15,
                        "{op:#04x} to {what} ({stage:?}): gas"
                    );
                } else {
                    assert_eq!(t.halt, Halt::Trap(op), "{op:#04x} to {what} ({stage:?})");
                }
            }
        }
    }
}

#[test]
fn every_precompile_address_does_what_the_table_says() {
    // Every listed address, and four the table does not list (other contracts: a call traps).
    const UNLISTED: [u32; 4] = [0, 0x12, 0xff, 0x101];
    const REQUESTED: u32 = 1_000_000;
    let addresses: Vec<u32> = compat::PRECOMPILE_ADDRESSES
        .iter()
        .chain(UNLISTED.iter())
        .copied()
        .collect();
    let codes: Vec<Vec<u8>> = addresses
        .iter()
        .map(|&a| call_code(0xfa, a as u16, 0, REQUESTED))
        .collect();
    let lib = host::build("compat-precompiles", &translations(&codes));
    for (i, &a) in addresses.iter().enumerate() {
        let c = call(&codes[i]);
        assert_eq!(
            c.expected().1.halt,
            Halt::Trap(0xfa),
            "address {a:#x}: the interpreter traps on every call"
        );
        let row = compat::precompile(a);
        assert_eq!(row.is_none(), UNLISTED.contains(&a), "address {a:#x}: listed");
        for (stage, _, t) in translated(&lib, codes.len(), i, &c) {
            match &row {
                Some(p) if p.xlat == Behaviour::Runs => {
                    assert_eq!(t.halt, Halt::Return, "{} ({stage:?}): it runs", p.name);
                    match p.empty_input_gas {
                        // The call succeeds on an empty input and costs the row's figure.
                        Some(gas) => {
                            assert_eq!(returned_word(&t), U256::ONE, "{}: success", p.name);
                            assert_eq!(
                                t.gas_used,
                                call_overhead(0xfa) + compat::CALL_ACCESS + gas,
                                "{} ({stage:?}): gas on an empty input",
                                p.name
                            );
                        }
                        // It fails on an empty input: the flag is 0 and the gas passed is gone.
                        None => {
                            assert_eq!(returned_word(&t), U256::ZERO, "{}: failure", p.name);
                            assert_eq!(
                                t.gas_used,
                                call_overhead(0xfa) + compat::CALL_ACCESS + REQUESTED as u64,
                                "{} ({stage:?}): a failed call consumes the gas passed",
                                p.name
                            );
                        }
                    }
                }
                Some(p) => {
                    assert_eq!(p.xlat, Behaviour::Traps, "{}: runs or traps", p.name);
                    assert_eq!(p.gas, Gas::None, "{}: a trap has no gas rule", p.name);
                    assert_eq!(t.halt, Halt::Trap(0xfa), "{} ({stage:?}): it traps", p.name);
                }
                None => assert_eq!(t.halt, Halt::Trap(0xfa), "address {a:#x} ({stage:?})"),
            }
        }
    }
    // The addresses that run are exactly `precompiles.h`'s PC_FIRST..=PC_LAST.
    let header = std::fs::read_to_string(root().join("evm-rt/precompiles.h")).unwrap();
    let define = |name: &str| -> u32 {
        header
            .lines()
            .find_map(|l| l.strip_prefix(&format!("#define {name} ")))
            .unwrap_or_else(|| panic!("no {name} in precompiles.h"))
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap()
    };
    let running: Vec<u32> = compat::precompiles()
        .iter()
        .filter(|p| p.xlat == Behaviour::Runs)
        .map(|p| p.address)
        .collect();
    assert_eq!(
        running,
        (define("PC_FIRST")..=define("PC_LAST")).collect::<Vec<_>>()
    );
}

#[test]
fn the_static_gas_and_the_trap_sets_are_the_codes() {
    for op in 0..=255u8 {
        let row = compat::opcode(op);
        // The interpreter's own table, on every byte it runs; ORIGIN and CHAINID are the
        // translation's alone (README, "Environment opcodes").
        if matches!(row.interp, Behaviour::Runs | Behaviour::RunsIf) {
            assert_eq!(row.static_gas, evm_core::interp::static_gas(op), "{op:#04x}");
        } else {
            assert_eq!(evm_core::interp::static_gas(op), 0, "{op:#04x}: nothing runs");
        }
        if op == 0x32 || op == 0x46 {
            assert_eq!(row.static_gas, 2, "{op:#04x}: G_BASE in a translation");
        }
        // A row with no gas is a row where nothing runs on either path, and the reverse.
        let nothing_runs = !matches!(row.interp, Behaviour::Runs | Behaviour::RunsIf)
            && !matches!(row.xlat, Behaviour::Runs | Behaviour::RunsIf);
        assert_eq!(row.gas == Gas::None, nothing_runs, "{op:#04x}: Gas::None");
        assert_eq!(row.gas_rule.is_empty(), nothing_runs, "{op:#04x}: a gas rule");
        // `blocks.rs`'s sets.
        assert_eq!(
            blocks::TRAP_TERM.contains(&op),
            row.xlat == Behaviour::Traps,
            "{op:#04x}: in TRAP_TERM iff the table says a translation traps"
        );
        assert_eq!(
            blocks::CALL_FAMILY.contains(&op),
            row.interp == Behaviour::Traps && row.xlat == Behaviour::RunsIf,
            "{op:#04x}: in CALL_FAMILY iff it runs to a precompile only"
        );
        // A trap or a conditional row says why.
        if row.interp == Behaviour::Traps || row.xlat == Behaviour::RunsIf {
            assert!(!row.note.is_empty(), "{op:#04x}: a reason");
        }
    }
    // Exactly the opcodes with storage gas differ from mainnet.
    let differs: Vec<u8> = compat::opcodes()
        .iter()
        .filter(|o| o.gas == Gas::Differs)
        .map(|o| o.byte)
        .collect();
    assert_eq!(differs, [0x54, 0x55]);
}

/// One gas case: the code, the pre-state value of slot 0, the gas limit, and the expected halt
/// and gas used.
struct GasCase {
    name: &'static str,
    code: Vec<u8>,
    slot0: u32,
    limit: u64,
    halt: Halt,
    gas: u64,
}

fn gas_cases() -> Vec<GasCase> {
    use compat::*;
    let case = |name, code: &[&[u8]], slot0, gas| GasCase {
        name,
        code: code.concat(),
        slot0,
        limit: GAS,
        halt: Halt::Stop,
        gas,
    };
    const PUSH0: &[u8] = &[0x5f];
    const POP: &[u8] = &[0x50];
    let sstore = |v: u8| [&p1(v)[..], PUSH0, &[0x55]].concat();
    let mut cases = vec![
        // No access list: the second SLOAD of a slot costs what the first did.
        case(
            "SLOAD twice",
            &[PUSH0, &[0x54], POP, PUSH0, &[0x54], POP],
            5,
            2 * (2 + SLOAD + 2),
        ),
        case("SSTORE zero to non-zero", &[&sstore(1)], 0, 5 + SSTORE_SET),
        case("SSTORE non-zero to non-zero", &[&sstore(7)], 5, 5 + SSTORE_RESET),
        // No refund: clearing a slot costs the reset and nothing comes back.
        case("SSTORE non-zero to zero", &[&sstore(0)], 5, 5 + SSTORE_RESET),
        // Mainnet's 100-gas no-op is the reset here.
        case("SSTORE of the value already there", &[&sstore(5)], 5, 5 + SSTORE_RESET),
        case("SSTORE zero to zero", &[&sstore(0)], 0, 5 + SSTORE_RESET),
        // Decided on the current value alone: a slot set in this call is then a reset, and one
        // cleared in this call is a set again.
        case(
            "SSTORE set, then written again",
            &[&sstore(1), &sstore(2)],
            0,
            2 * 5 + SSTORE_SET + SSTORE_RESET,
        ),
        case(
            "SSTORE cleared, then set",
            &[&sstore(0), &sstore(2)],
            5,
            2 * 5 + SSTORE_RESET + SSTORE_SET,
        ),
        case("TLOAD", &[PUSH0, &[0x5c]], 0, 2 + TRANSIENT),
        case("TSTORE", &[&p1(1), PUSH0, &[0x5d]], 0, 5 + TRANSIENT),
        case(
            "EXP, a one-byte exponent",
            &[&p1(0xff), &p1(2), &[0x0a]],
            0,
            6 + EXP_BASE + EXP_PER_BYTE,
        ),
        case(
            "EXP, a two-byte exponent",
            &[&[0x61, 0x01, 0x00], &p1(2), &[0x0a]],
            0,
            6 + EXP_BASE + 2 * EXP_PER_BYTE,
        ),
        case(
            "KECCAK256 of 33 bytes",
            &[&p1(33), PUSH0, &[0x20]],
            0,
            5 + KECCAK_BASE + 2 * KECCAK_PER_WORD + memory_cost(2),
        ),
        case(
            "LOG2 with 32 bytes of data",
            &[PUSH0, PUSH0, &p1(32), PUSH0, &[0xa2]],
            0,
            9 + LOG_BASE + 2 * LOG_PER_TOPIC + 32 * LOG_PER_BYTE + memory_cost(1),
        ),
        case(
            "CALLDATACOPY of 64 bytes",
            &[&p1(64), PUSH0, PUSH0, &[0x37]],
            0,
            7 + 3 + 2 * COPY_PER_WORD + memory_cost(2),
        ),
        case(
            "CODECOPY of 33 bytes",
            &[&p1(33), PUSH0, PUSH0, &[0x39]],
            0,
            7 + 3 + 2 * COPY_PER_WORD + memory_cost(2),
        ),
        case(
            "MCOPY of 33 bytes from 0 to 32",
            &[&p1(33), PUSH0, &p1(32), &[0x5e]],
            0,
            8 + 3 + 2 * COPY_PER_WORD + memory_cost(3),
        ),
        // The quadratic term: 1 024 words is 3 * 1 024 + 1 024^2 / 512 = 5 120.
        case(
            "MSTORE ending at 32 768",
            &[PUSH0, &[0x61, 0x7f, 0xe0], &[0x52]],
            0,
            2 + 3 + 3 + 5_120,
        ),
    ];
    assert_eq!(memory_cost(1_024), 5_120);
    // No 2 300-gas check: an SSTORE runs with exactly its cost left and nothing after.
    cases.push(GasCase {
        name: "SSTORE with exactly its gas",
        code: sstore(7),
        slot0: 5,
        limit: 5 + SSTORE_RESET,
        halt: Halt::Stop,
        gas: 5 + SSTORE_RESET,
    });
    // The caps: OutOfBounds with gas to spare (an exceptional halt, so the whole limit).
    let cap = |name, code: Vec<u8>| GasCase {
        name,
        code,
        slot0: 0,
        limit: GAS,
        halt: Halt::OutOfBounds,
        gas: GAS,
    };
    // MSTORE at 65 505: the word ends at 65 537.
    cases.push(cap("memory past 64 KiB", vec![0x5f, 0x62, 0x00, 0xff, 0xe1, 0x52]));
    // RETURN(0, 1 025).
    cases.push(cap("return data past 1 KiB", vec![0x61, 0x04, 0x01, 0x5f, 0xf3]));
    // Nine LOG0s.
    cases.push(cap("a ninth log", [0x5f, 0x5f, 0xa0].repeat(9)));
    cases
}

#[test]
fn the_gas_rules_and_the_caps_are_what_the_table_says() {
    let cases = gas_cases();
    let codes: Vec<Vec<u8>> = cases.iter().map(|c| c.code.clone()).collect();
    let lib = host::build("compat-gas", &translations(&codes));
    for (i, case) in cases.iter().enumerate() {
        let mut c = call(&case.code);
        c.tree.insert(U256::ZERO, U256::from_u32(case.slot0));
        c.gas_limit = case.limit;
        let (want, o, _) = c.expected();
        assert_eq!(o.halt, case.halt, "{}: interpreter halt", case.name);
        assert_eq!(o.gas_used, case.gas, "{}: interpreter gas", case.name);
        for (stage, words, t) in translated(&lib, codes.len(), i, &c) {
            assert_eq!(t.halt, case.halt, "{} ({stage:?}): halt", case.name);
            assert_eq!(t.gas_used, case.gas, "{} ({stage:?}): gas", case.name);
            assert_eq!(words, want, "{} ({stage:?}): the eight words", case.name);
        }
    }
    // The caps table is `evm-core`'s constants, and an exceptional halt is status 2.
    let limit = |what: &str| compat::CAPS.iter().find(|c| c.what.starts_with(what)).unwrap().limit;
    assert_eq!(limit("memory"), 65_536);
    assert_eq!(limit("calldata"), 4_096);
    assert_eq!(limit("return data"), 1_024);
    assert_eq!(limit("logs"), 8);
    assert_eq!(limit("transient"), 16);
    assert_eq!(limit("storage witnesses"), 32);
    assert_eq!(limit("code"), 24_576);
    assert_eq!(limit("stack"), 1_024);
}

fn compat_md() -> PathBuf {
    root().join("evm2rv/COMPATIBILITY.md")
}

#[test]
fn the_committed_compatibility_table_is_what_the_module_generates() {
    let want = compat::markdown();
    if std::env::var_os("EVM2RV_COMPAT_REGEN").is_some() {
        std::fs::write(compat_md(), &want).unwrap();
    }
    let have = std::fs::read_to_string(compat_md()).unwrap_or_default();
    assert!(
        have == want,
        "{} is stale; regenerate with EVM2RV_COMPAT_REGEN=1 cargo +1.98.1 test --test compat",
        compat_md().display()
    );
    // Every byte is in the rendered table, alone or inside a folded range.
    let mut covered = [false; 256];
    for line in want.lines().filter(|l| l.starts_with("| `0x")) {
        let cell = line.split('|').nth(1).unwrap();
        let bytes: Vec<u32> = cell
            .split('`')
            .filter_map(|t| t.strip_prefix("0x"))
            .map(|h| u32::from_str_radix(h, 16).unwrap())
            .collect();
        // The precompile rows start the same way; the opcode rows are the ones before them.
        if line.split('|').count() != 8 || bytes.is_empty() {
            continue;
        }
        let (a, b) = (bytes[0], *bytes.last().unwrap());
        if want[..want.find("## Precompiles").unwrap()].contains(line) {
            for x in a..=b {
                covered[x as usize] = true;
            }
        }
    }
    assert!(covered.iter().all(|&c| c), "a byte is missing from the table");
    // The docs that used to carry their own lists link here.
    for doc in ["evm2rv/README.md", "research/docs/04-guests.md"] {
        let text = std::fs::read_to_string(root().join(doc)).unwrap();
        assert!(text.contains("COMPATIBILITY.md"), "{doc} does not link the table");
    }
}

fn committed(name: &str) -> Vec<u8> {
    let text = std::fs::read_to_string(root().join("guests-compiled/evm/contracts").join(name))
        .unwrap();
    let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    hex::decode(digits.strip_prefix("0x").unwrap_or(&digits)).unwrap()
}

/// A contract with one of each kind: TIMESTAMP (always traps), a STATICCALL (may trap), CHAINID
/// (the interpreter only), and a `PUSH2` whose data is two trapping opcodes' bytes.
const HAND_MADE: [u8; 9] = [0x61, 0x42, 0xf0, 0x42, 0x46, 0xfa, 0x54, 0x0c, 0x00];

#[test]
fn check_lists_every_trapping_opcode_with_its_offset() {
    let r = compat::check(&HAND_MADE);
    let got: Vec<(usize, u8, Severity)> =
        r.findings.iter().map(|f| (f.pc, f.opcode, f.severity)).collect();
    assert_eq!(
        got,
        [
            (3, 0x42, Severity::Traps),
            (4, 0x46, Severity::InterpreterOnly),
            (5, 0xfa, Severity::MayTrap),
        ],
        "the PUSH2's data is not read as opcodes"
    );
    assert_eq!(r.findings[0].name, "TIMESTAMP");
    assert_eq!(r.findings[0].reason, compat::opcode(0x42).note);
    assert_eq!((r.undefined, r.gas_differs), (1, 1));
    assert!(r.traps() && r.may_trap() && r.interpreter_traps());

    // The committed contracts. The ERC-20 is clean on both paths.
    let erc20 = compat::check(&committed("erc20.runtime.hex"));
    assert_eq!(erc20.findings, [], "the ERC-20 has nothing that traps");
    assert!(!erc20.traps() && !erc20.may_trap() && !erc20.interpreter_traps());
    assert!(erc20.gas_differs > 0, "it reads and writes storage");
    // On every committed contract, the scan and `blocks::warnings` name the same opcodes at the
    // same offsets (the warnings know nothing of CHAINID, ORIGIN or RETURNDATACOPY).
    for name in ["erc20.runtime.hex", "cancun.runtime.hex", "osaka.runtime.hex"] {
        let code = committed(name);
        let r = compat::check(&code);
        let scan: Vec<(usize, u8)> = r
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Traps || blocks::CALL_FAMILY.contains(&f.opcode))
            .map(|f| (f.pc, f.opcode))
            .collect();
        let warned: Vec<(usize, u8)> = blocks::warnings(&code)
            .iter()
            .map(|w| match *w {
                blocks::Warning::Trap { pc, opcode } | blocks::Warning::Call { pc, opcode } => {
                    (pc, opcode)
                }
                blocks::Warning::CodeTooLarge { .. } => panic!("{name} is over the code cap"),
            })
            .collect();
        assert_eq!(scan, warned, "{name}");
        eprintln!(
            "{name}: {} findings, {} undefined bytes, {} storage opcodes",
            r.findings.len(),
            r.undefined,
            r.gas_differs
        );
    }

    // Over the cap: one fact, no findings.
    let big = compat::check(&vec![0x42; evm_core::interp::MAX_CODE_BYTES + 1]);
    assert_eq!(big.code_too_large, Some(evm_core::interp::MAX_CODE_BYTES + 1));
    assert!(big.findings.is_empty() && big.traps());
}

/// `evm2rv check <file> [--interpreter]`: its exit status and stdout.
fn run_check(file: &std::path::Path, interpreter: bool) -> (i32, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_evm2rv"));
    c.arg("check").arg(file);
    if interpreter {
        c.arg("--interpreter");
    }
    let o = c.output().unwrap();
    (
        o.status.code().expect("an exit status"),
        String::from_utf8(o.stdout).unwrap(),
    )
}

#[test]
fn the_check_subcommand_reports_and_sets_its_exit_status() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("compat-check");
    std::fs::create_dir_all(&dir).unwrap();
    let write = |name: &str, code: &[u8]| {
        let p = dir.join(name);
        std::fs::write(&p, code).unwrap();
        p
    };

    // The ERC-20: clean on both paths.
    let erc20 = root().join("guests-compiled/evm/contracts/erc20.runtime.hex");
    for interpreter in [false, true] {
        let (status, out) = run_check(&erc20, interpreter);
        assert_eq!(status, 0, "{out}");
        assert!(out.contains("clean: nothing in this code traps"), "{out}");
        assert!(out.contains("0 always trap, 0 may trap, 0 trap in the interpreter only"), "{out}");
    }

    // The hand-made contract: TIMESTAMP always traps.
    let (status, out) = run_check(&write("hand.bin", &HAND_MADE), false);
    assert_eq!(status, 1, "{out}");
    assert!(out.contains("pc 0x0003: TIMESTAMP (0x42) TRAPS"), "{out}");
    assert!(out.contains("pc 0x0004: CHAINID (0x46) interpreter only"), "{out}");
    assert!(out.contains("pc 0x0005: STATICCALL (0xfa) MAY TRAP"), "{out}");
    assert!(out.contains(compat::opcode(0x42).note), "{out}");
    assert!(out.contains("1 always trap, 1 may trap, 1 trap in the interpreter only"), "{out}");
    assert!(!out.contains("CREATE"), "push data read as an opcode: {out}");

    // Only a call: conditional in a translation, a trap in the interpreter.
    let only_call = write("call.bin", &call_code(0xfa, 2, 0, 1_000));
    assert_eq!(run_check(&only_call, false).0, 2);
    assert_eq!(run_check(&only_call, true).0, 1);

    // Only CHAINID: clean in a translation, a trap in the interpreter.
    let only_chainid = write("chainid.bin", &[0x46, 0x50, 0x00]);
    assert_eq!(run_check(&only_chainid, false).0, 0);
    assert_eq!(run_check(&only_chainid, true).0, 1);

    // The translating form of the CLI still takes a bare contract path.
    let o = Command::new(env!("CARGO_BIN_EXE_evm2rv")).arg(&erc20).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stdout).contains("no trapping opcodes present"));
}
