//! Directed parity for the stack opcodes: every `DUPn` and `SWAPn` (1 to 16) over seventeen
//! distinct words, each one short of its operands (an underflow at the block head), `POP` on an
//! empty stack, the 1 024-word limit from both sides, every `PUSHn` round-tripped through the
//! returned word, and a `PUSHn` whose immediate runs past the end of the code (zero-padded, as the
//! interpreter reads it). Pins: `(status, gas_used, returned word)`; the translation at both
//! stages must agree with the interpreter (`common/directed.rs`).

mod common;

use common::directed::{bytes, run_directed, Directed, TAIL};

/// PUSH1 1 … PUSH1 17: seventeen distinct words, 17 on top. 51 gas.
fn seventeen() -> String {
    (1..=17u8).map(|v| format!("60{v:02x}")).collect()
}

/// Every DUPn copies the n-th word from the top, 18 - n here: 51 + 3 + 13.
#[test]
fn every_dup_copies_the_nth_word_from_the_top() {
    let cases: Vec<Directed> = (1..=16u8)
        .map(|n| {
            Directed::new(
                format!("dup{n}"),
                &format!("{}{:02x}{TAIL}", seventeen(), 0x7f + n),
                1,
                67,
            )
            .ret_word(18 - n as u64)
        })
        .collect();
    run_directed("stack-dup", &cases);
}

/// Every SWAPn trades the top with the (n+1)-th word, 17 - n here: 51 + 3 + 13.
#[test]
fn every_swap_trades_the_top_with_the_nth_below() {
    let cases: Vec<Directed> = (1..=16u8)
        .map(|n| {
            Directed::new(
                format!("swap{n}"),
                &format!("{}{:02x}{TAIL}", seventeen(), 0x8f + n),
                1,
                67,
            )
            .ret_word(17 - n as u64)
        })
        .collect();
    run_directed("stack-swap", &cases);
}

/// DUPn over n - 1 words and SWAPn over n words underflow: status 2, the limit spent. The
/// interpreter underflows at the opcode; the translation at the block head (the same status and
/// gas, a different halt kind — accepted divergence #1).
#[test]
fn a_dup_or_swap_one_word_short_underflows() {
    let mut cases = Vec::new();
    for n in 1..=16u8 {
        let pushes: String = (1..n).map(|v| format!("60{v:02x}")).collect();
        cases.push(Directed::new(
            format!("dup{n} over {} words", n - 1),
            &format!("{pushes}{:02x}00", 0x7f + n),
            2,
            100_000,
        ));
        let pushes: String = (1..=n).map(|v| format!("60{v:02x}")).collect();
        cases.push(Directed::new(
            format!("swap{n} over {n} words"),
            &format!("{pushes}{:02x}00", 0x8f + n),
            2,
            100_000,
        ));
    }
    run_directed("stack-underflow", &cases);
}

#[test]
fn pop_and_the_binary_ops_on_too_few_words() {
    let cases = vec![
        Directed::new("pop on an empty stack", "50", 2, 100_000),
        Directed::new("pop after a push", "60015000", 1, 5),
        Directed::new("two pops after one push", "6001505000", 2, 100_000),
        Directed::new("add with one operand", "600101", 2, 100_000),
        Directed::new("addmod with two operands", "6001600108", 2, 100_000),
        Directed::new("mstore with one operand", "600152", 2, 100_000),
        Directed::new("return with one operand", "6001f3", 2, 100_000),
        Directed::new("log1 with two operands", "5f5fa1", 2, 100_000),
        Directed::new("jumpi with one operand", "600157", 2, 100_000),
        // A push, then an op needing two in the next block: the second block's head underflows.
        Directed::new("underflow in a second block", "60015b0100", 2, 100_000),
        // Deep enough after a jump: the first block leaves two words for the second.
        // PUSH1 3, PUSH1 4, PUSH1 7, JUMP, 7: JUMPDEST, ADD: 3 + 3 + 3 + 8 + 1 + 3.
        Directed::new("two words across a jump", &format!("60036004600756 5b01{TAIL}"), 1, 34).ret_word(7),
    ];
    run_directed("stack-pop", &cases);
}

/// 1 024 words fit; the 1 025th push overflows (status 2, the limit spent). Laundering would add
/// its own words, so the twins are skipped.
#[test]
fn the_stack_limit_from_both_sides() {
    let push0 = |n: usize| "5f".repeat(n);
    let cases = vec![
        Directed::new("1024 pushes then STOP", &format!("{}00", push0(1024)), 1, 2048).no_launder(),
        Directed::new("1025 pushes", &push0(1025), 2, 100_000).no_launder(),
        Directed::new("1024 pushes then DUP1", &format!("{}80", push0(1024)), 2, 100_000).no_launder(),
        // Pop one, then there is room for one more.
        Directed::new(
            "1024 pushes, POP, PUSH0, STOP",
            &format!("{}505f00", push0(1024)),
            1,
            2052,
        )
        .no_launder(),
        // The limit is per stack, not per block: 1 023 words from one block and two more in the
        // next overflow at the second block's head.
        Directed::new(
            "1023 words then a block pushing two",
            &format!("{}5b5f5f00", push0(1023)),
            2,
            100_000,
        )
        .no_launder(),
        Directed::new(
            "1023 words then a block pushing one",
            &format!("{}5b5f00", push0(1023)),
            1,
            2049,
        )
        .no_launder(),
    ];
    run_directed("stack-limit", &cases);
}

/// PUSH0 and every PUSHn with a distinct immediate come back as the returned word, right-aligned.
#[test]
fn every_push_round_trips() {
    let mut cases = vec![Directed::new("push0", &format!("5f{TAIL}"), 1, 15).ret_word(0)];
    for n in 1..=32u8 {
        let imm: Vec<u8> = (1..=n).map(|k| k.wrapping_mul(0x37).wrapping_add(k)).collect();
        let mut ret = vec![0u8; 32 - n as usize];
        ret.extend_from_slice(&imm);
        cases.push(
            Directed::new(
                format!("push{n}"),
                &format!("{:02x}{}{TAIL}", 0x5f + n, hex::encode(&imm)),
                1,
                16,
            )
            .ret_bytes(ret),
        );
    }
    // A full-width immediate with every byte set.
    cases.push(
        Directed::new("push32 of MAX", &format!("7f{}{TAIL}", "ff".repeat(32)), 1, 16)
            .ret_hex(&"ff".repeat(32)),
    );
    run_directed("stack-push", &cases);
}

/// A `PUSHn` at the end of the code with fewer than n bytes left reads zeros for the rest, then
/// the code ends — `STOP`. The word is observable through the halt only (nothing can follow the
/// push), so the status, the gas and the digest are the parity; `tests/blocks_edges.rs` pins the
/// decoded immediate. Laundering would complete the immediate, so the twins are skipped.
#[test]
fn a_truncated_push_at_the_end_of_the_code() {
    let cases = vec![
        Directed::new("PUSH2 with one byte", "6101", 1, 3).no_launder(),
        Directed::new("PUSH32 with no bytes", "7f", 1, 3).no_launder(),
        Directed::new("PUSH1 with no bytes", "60", 1, 3).no_launder(),
        Directed::new("PUSH32 with 31 bytes", &format!("7f{}", "ab".repeat(31)), 1, 3).no_launder(),
        // The truncated push's word is on the stack: a DUP1 cannot follow it, but a push after a
        // complete one can be checked — PUSH1 7, then PUSH3 with one byte 0x01 pushes 0x010000.
        Directed::new("a complete push then a truncated one", "60076201", 1, 6).no_launder(),
        // Truncated push data that would be a JUMPDEST byte is still push data: PUSH2 0x5b then
        // the end. Nothing to jump to, nothing to run.
        Directed::new("truncated push data is not code", "615b", 1, 3).no_launder(),
    ];
    // The decoded immediates, for the record: zero-padded on the right.
    let b = evm2rv::blocks::blocks(&bytes("6101"));
    assert_eq!(b[0].ops[0].push.unwrap()[30..], [0x01, 0x00]);
    run_directed("stack-truncated", &cases);
}
