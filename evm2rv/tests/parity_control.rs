//! Directed parity for control flow and the environment: static and dynamic `JUMP`/`JUMPI` to a
//! `JUMPDEST`, to a non-`JUMPDEST`, into push data and past the code, `JUMPI` with a zero, a
//! one and a high-limb condition, a counted loop, `PC` and `GAS` at several points, `STOP` and
//! dead code, `INVALID`, every one of the sixteen trapping opcodes and an undefined byte, empty
//! code, `ADDRESS`/`CALLER`/`CALLVALUE`, and a few gas-limit edges. Pins: `(status, gas_used,
//! returned word)`; both stages must agree with the interpreter, and the laundered twin sends
//! every jump through the dispatch (`common/directed.rs`).

mod common;

use common::directed::{run_directed, Directed, TAIL};
use evm2rv::blocks::TRAP_TERM;
use evm2rv::emit::mnemonic;

#[test]
fn jumps_static_dynamic_and_bad() {
    let cases = vec![
        // PUSH1 4, JUMP, INVALID, 4: JUMPDEST, STOP: 3 + 8 + 1.
        Directed::new("jump over an INVALID", "600456fe5b00", 1, 12),
        // The destination is the STOP at 5, not a JUMPDEST.
        Directed::new("jump to a non-jumpdest", "600556fe5b00", 2, 100_000),
        // pc 3 is the 0x5b inside PUSH1's immediate.
        Directed::new("jump into push data", "600356605b00", 2, 100_000),
        // pc 3 is the code's length.
        Directed::new("jump to the end of the code", "60035600", 2, 100_000),
        Directed::new("jump past the code", "61ffff5600", 2, 100_000),
        Directed::new("jump to 2^32", "64010000000056 5b00", 2, 100_000),
        // A JUMPDEST as the last byte is a fine destination: 3 + 8 + 1.
        Directed::new("jump to the last byte", "6003565b", 1, 12),
        // The destination from calldata (dynamic in both stages): word 0 = 4. Laundering moves
        // the JUMPDEST but not the calldata, so these three run without the twin.
        Directed::new("dynamic jump from calldata", &format!("5f3556 fe 5b6007{TAIL}"), 1, 30)
            .calldata(&format!("{}04", "00".repeat(31)))
            .ret_word(7)
            .no_launder(),
        Directed::new("dynamic jump from calldata to push data", "5f3556 fe 605b00", 2, 100_000)
            .calldata(&format!("{}05", "00".repeat(31)))
            .no_launder(),
        Directed::new("dynamic jump from calldata past the code", "5f3556 fe 5b00", 2, 100_000)
            .calldata(&format!("{}ff", "00".repeat(31)))
            .no_launder(),
        // Jump back to 0 forever: out of gas at the limit.
        Directed::new("a jump loop runs out of gas", "5b5f56", 2, 100_000),
        // Jump to a JUMPDEST whose block then falls off the end: STOP.
        Directed::new("jump then fall off the end", "6003565b6001", 1, 15),
        // Two jumps in a row through two JUMPDESTs: 3 + 8 + 1 + 3 + 8 + 1.
        Directed::new("two chained jumps", "600356 5b600756 5b00", 1, 24),
        // A jump whose destination was pushed earlier, under an unrelated word (stage one sends it
        // through the switch, stage two resolves it): PUSH1 7, PUSH1 9, POP, JUMP, STOP, 7: JUMPDEST:
        // 3 + 3 + 2 + 8 + 1.
        Directed::new("destination pushed two ops before the jump", "60076009505600 5b00", 1, 17),
    ];
    run_directed("control-jumps", &cases);
}

#[test]
fn jumpi_taken_not_taken_and_the_condition_width() {
    let cases = vec![
        // PUSH0 (cond), PUSH1 12, JUMPI, PUSH1 1, TAIL, 12: JUMPDEST, INVALID. Not taken:
        // 2 + 3 + 10 + 3 + 13.
        Directed::new("jumpi with a zero condition falls through", &format!("5f600c57 6001{TAIL} 5bfe"), 1, 31).ret_word(1),
        // PUSH1 1, PUSH1 13, JUMPI, PUSH1 1, TAIL, 13: JUMPDEST, PUSH1 2, TAIL. Taken:
        // 3 + 3 + 10 + 1 + 3 + 13.
        Directed::new("jumpi with a one condition is taken", &format!("6001600d57 6001{TAIL} 5b6002{TAIL}"), 1, 33).ret_word(2),
        // The condition 2^255: nonzero only in the high limb. 9 + 3 + 10 + 1 + 3 + 13.
        Directed::new("jumpi with a high-limb condition is taken", &format!("600160ff1b 601057 6001{TAIL} 5b6002{TAIL}"), 1, 39).ret_word(2),
        // The condition 2^32: nonzero only in the second limb.
        Directed::new("jumpi with a second-limb condition is taken", &format!("640100000000 601157 6001{TAIL} 5b6002{TAIL}"), 1, 33).ret_word(2),
        // Not taken to a bogus destination: fine. Taken to one: bad jump.
        Directed::new("jumpi not taken to a non-jumpdest", "5f60ff5700", 1, 15),
        Directed::new("jumpi taken to a non-jumpdest", "600160ff5700", 2, 100_000),
        Directed::new("jumpi taken into push data", "6001600657 605b00", 2, 100_000),
        Directed::new("jumpi taken to 2^32", "60016401000000005700", 2, 100_000),
        // Both operands from calldata: word 0 the destination, word 1 the condition (no twin:
        // laundering would move the JUMPDEST the calldata names).
        Directed::new(
            "dynamic jumpi taken",
            &format!("6020355f3557 6001{TAIL} 5b6002{TAIL}"),
            1,
            38,
        )
        .calldata(&format!("{}0e{}01", "00".repeat(31), "00".repeat(31)))
        .ret_word(2)
        .no_launder(),
        Directed::new(
            "dynamic jumpi not taken",
            &format!("6020355f3557 6001{TAIL} 5b6002{TAIL}"),
            1,
            37,
        )
        .calldata(&format!("{}0e{}", "00".repeat(31), "00".repeat(32)))
        .ret_word(1)
        .no_launder(),
        Directed::new("dynamic jumpi taken to a non-jumpdest", "6020355f3557 00", 2, 100_000)
            .calldata(&format!("{}05{}01", "00".repeat(31), "00".repeat(31)))
            .no_launder(),
    ];
    run_directed("control-jumpi", &cases);
}

/// A counted loop: acc = 0, i = 10; while i != 0 { acc += i; i -= 1 }; return acc.
///
/// ```text
/// 0  PUSH0          acc
/// 1  PUSH1 10       i
/// 3  JUMPDEST                 [acc, i]
/// 4  DUP1, ISZERO, PUSH1 20, JUMPI
/// 9  DUP1, SWAP2, ADD, SWAP1 [acc + i, i]
/// 13 PUSH1 1, SWAP1, SUB     [acc', i - 1]
/// 17 PUSH1 3, JUMP
/// 20 JUMPDEST, POP, TAIL
/// ```
///
/// 5 to start; per iteration 1 + 3 + 3 + 3 + 10 (not taken) + 3 + 3 + 3 + 3 + 3 + 3 + 3 + 3 + 8
/// = 52, ten times; the exit 1 + 3 + 3 + 3 + 10 + 1 + 2 = 23; then the tail 13: 561.
#[test]
fn a_counted_loop_sums_one_to_ten() {
    let loop_code = |n: u8| format!("5f60{n:02x} 5b 8015601457 80910190 60019003 600356 5b50{TAIL}");
    let cases = vec![
        Directed::new("loop to 10", &loop_code(10), 1, 561).ret_word(55),
        Directed::new("loop to 1", &loop_code(1), 1, 5 + 52 + 23 + 13).ret_word(1),
        Directed::new("loop to 0 runs no iteration", &loop_code(0), 1, 5 + 23 + 13).ret_word(0),
        Directed::new("loop to 100", &loop_code(100), 1, 5 + 52 * 100 + 23 + 13).ret_word(5050),
        // The loop at exactly its gas, and one short of it.
        Directed::new("loop to 10 at exactly its gas", &loop_code(10), 1, 561).gas_limit(561).ret_word(55),
        Directed::new("loop to 10 one short of its gas", &loop_code(10), 2, 560).gas_limit(560),
        // Out of gas mid-loop: the head of some iteration's block fails; the whole limit is spent.
        Directed::new("loop to 100 out of gas", &loop_code(100), 2, 2000).gas_limit(2000),
    ];
    run_directed("control-loop", &cases);
}

#[test]
fn pc_gas_stop_and_dead_code() {
    let cases = vec![
        Directed::new("pc at 0", &format!("58{TAIL}"), 1, 15).ret_word(0).ret_moves(),
        // PUSH1 0, POP, PC: the pc counts the immediate.
        Directed::new("pc after a push", &format!("60005058{TAIL}"), 1, 20).ret_word(3).ret_moves(),
        Directed::new("pc after a jump", &format!("600356 5b58{TAIL}"), 1, 27).ret_word(4).ret_moves(),
        // GAS: 100 000 - 2.
        Directed::new("gas at the start", &format!("5a{TAIL}"), 1, 15).ret_word(99_998).ret_moves(),
        Directed::new("gas twice", &format!("5a505a{TAIL}"), 1, 19).ret_word(99_994).ret_moves(),
        // GAS after a 20 000 SSTORE: 100 000 - 3 - 3 - 20 000 - 2.
        Directed::new("gas after an sstore", &format!("602a600555 5a{TAIL}"), 1, 20021)
            .touched(5)
            .ret_word(79_992)
            .ret_moves(),
        // GAS at a lower limit.
        Directed::new("gas at a limit of 1000", &format!("5a{TAIL}"), 1, 15).gas_limit(1000).ret_word(998),
        Directed::new("stop then dead code", "00fe", 1, 0),
        Directed::new("stop with words on the stack", "6001600200", 1, 6),
        Directed::new("dead code after a return is not run", "5f5ff3 fe 6001", 1, 4).ret_hex(""),
        Directed::new("empty code", "", 1, 0),
        Directed::new("a single JUMPDEST", "5b", 1, 1),
        Directed::new("a single PUSH0", "5f", 1, 2),
        Directed::new("INVALID", "fe", 2, 100_000),
        Directed::new("INVALID after a push", "6001fe", 2, 100_000),
        // Undefined bytes trap; so does a Cancun opcode (TLOAD) and MCOPY.
        Directed::new("undefined 0x0c traps", "0c", 2, 100_000),
        Directed::new("undefined 0x21 traps", "6001 21", 2, 100_000),
        Directed::new("TLOAD traps", "5f5c", 2, 100_000),
        Directed::new("MCOPY traps", "5f5f5f5e", 2, 100_000),
        Directed::new("PUSH0-then-0xef traps", "5fef", 2, 100_000),
    ];
    run_directed("control-pc-gas", &cases);
}

/// Every one of the sixteen `TRAP_TERM` opcodes halts the call (status 2, the limit spent), bare
/// and after enough pushes for its operands, as the interpreter traps on it before touching the
/// stack.
#[test]
fn every_trapping_opcode_halts() {
    let mut cases = Vec::new();
    for op in TRAP_TERM {
        cases.push(Directed::new(format!("{} bare", mnemonic(op)), &format!("{op:02x}"), 2, 100_000));
        cases.push(Directed::new(
            format!("{} after seven pushes", mnemonic(op)),
            &format!("{}{op:02x}00", "6001".repeat(7)),
            2,
            100_000,
        ));
    }
    // ... and a trap reached only on one branch: the other returns.
    cases.push(
        Directed::new("TIMESTAMP on the untaken branch", &format!("5f600c57 6001{TAIL} 5b4200"), 1, 31).ret_word(1),
    );
    cases.push(Directed::new("TIMESTAMP on the taken branch", &format!("6001600d57 6001{TAIL} 5b4200"), 2, 100_000));
    run_directed("control-traps", &cases);
}

#[test]
fn address_caller_and_callvalue() {
    let cases = vec![
        Directed::new("address", &format!("30{TAIL}"), 1, 15).ret_word(0xc0de),
        Directed::new("caller", &format!("33{TAIL}"), 1, 15).ret_word(0xca11),
        Directed::new("callvalue of 0", &format!("34{TAIL}"), 1, 15).ret_word(0),
        Directed::new("callvalue of 7", &format!("34{TAIL}"), 1, 15).callvalue(7).ret_word(7),
        Directed::new("callvalue of 2^40", &format!("34{TAIL}"), 1, 15).callvalue(1 << 40).ret_word(1 << 40),
        // ADDRESS and CALLER are distinct words: EQ is 0.
        Directed::new("address != caller", &format!("303314{TAIL}"), 1, 20).ret_word(0),
        // Arithmetic over an environment word: CALLVALUE + 1.
        Directed::new("callvalue + 1", &format!("6001 34 01{TAIL}"), 1, 21).callvalue(41).ret_word(42),
        // ISZERO over the environment, as a branch condition: CALLVALUE 0 falls through.
        Directed::new(
            "branch on callvalue",
            &format!("34600c57 6001{TAIL} 5b6002{TAIL}"),
            1,
            31,
        )
        .ret_word(1),
        Directed::new(
            "branch on a nonzero callvalue",
            &format!("34600c57 6001{TAIL} 5b6002{TAIL}"),
            1,
            32,
        )
        .callvalue(9)
        .ret_word(2),
    ];
    run_directed("control-env", &cases);
}
