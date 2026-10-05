//! The block analysis at its edges (`src/blocks.rs`): dead code after a terminator is still a
//! block, a `JUMPDEST` byte inside push data starts nothing, a terminator byte inside push data
//! ends nothing, a truncated `PUSHn` at the end of the code decodes zero-padded with the block's
//! end clamped, consecutive `JUMPDEST`s, every terminator kind, the stack bounds of the deep
//! stack ops and the n-ary ones, the static-gas table over the push/dup/swap ranges, `warnings`
//! at every pc shape, and the partition and `gas_after` invariants over the fuzz corpus — not
//! only the ERC-20.

use evm2rv::blocks::{
    blocks, jumpdests, stack_bounds, stack_effect, static_gas, warnings, Block, Op, Term,
    Warning, CALL_FAMILY, TRAP_TERM, WARN_SET,
};
use evm2rv::emit::mnemonic;
use evm_core::interp::MAX_CODE_BYTES;

fn spans(bs: &[Block]) -> Vec<(usize, usize)> {
    bs.iter().map(|b| (b.start, b.end)).collect()
}

fn terms(bs: &[Block]) -> Vec<Term> {
    bs.iter().map(|b| b.term).collect()
}

#[test]
fn dead_code_after_a_terminator_is_still_a_block() {
    // STOP, PUSH1 1, STOP: nothing reaches the second block, but it is decoded like any other.
    let bs = blocks(&[0x00, 0x60, 0x01, 0x00]);
    assert_eq!(spans(&bs), vec![(0, 1), (1, 4)]);
    assert_eq!(terms(&bs), vec![Term::Stop, Term::Stop]);
    assert_eq!(bs[1].ops.len(), 2);
    assert_eq!(bs[1].static_gas, 3);
    // RETURN then INVALID then a JUMPDEST: three blocks.
    let bs = blocks(&[0x5f, 0x5f, 0xf3, 0xfe, 0x5b, 0x00]);
    assert_eq!(spans(&bs), vec![(0, 3), (3, 4), (4, 6)]);
    assert_eq!(terms(&bs), vec![Term::Return, Term::Invalid, Term::Stop]);
}

#[test]
fn a_jumpdest_byte_inside_push_data_starts_no_block() {
    // PUSH1 0x5b, STOP: one block, no jumpdest.
    let bs = blocks(&[0x60, 0x5b, 0x00]);
    assert_eq!(spans(&bs), vec![(0, 3)]);
    assert_eq!(jumpdests(&[0x60, 0x5b, 0x00]), Vec::<usize>::new());
    // PUSH2 0x5b5b, JUMPDEST, STOP: the real one at 3 splits, the two inside the immediate do not.
    let code = [0x61, 0x5b, 0x5b, 0x5b, 0x00];
    let bs = blocks(&code);
    assert_eq!(spans(&bs), vec![(0, 3), (3, 5)]);
    assert_eq!(terms(&bs), vec![Term::Fallthrough(3), Term::Stop]);
    assert_eq!(jumpdests(&code), vec![3]);
    // PUSH32 whose 32 immediate bytes are all 0x5b, then a JUMPDEST at 33.
    let mut code = vec![0x7f];
    code.extend([0x5b; 32]);
    code.push(0x5b);
    assert_eq!(jumpdests(&code), vec![33]);
    assert_eq!(spans(&blocks(&code)), vec![(0, 33), (33, 34)]);
    // A truncated PUSH32 swallows the rest: no jumpdest at all.
    assert_eq!(jumpdests(&[0x7f, 0x5b, 0x5b]), Vec::<usize>::new());
    assert_eq!(spans(&blocks(&[0x7f, 0x5b, 0x5b])), vec![(0, 3)]);
}

#[test]
fn a_terminator_byte_inside_push_data_ends_no_block() {
    // PUSH1 0x00 (STOP's byte), PUSH1 0xfe (INVALID's), PUSH1 0x56 (JUMP's), PUSH1 0xf3, ADD, STOP.
    let code = [0x60, 0x00, 0x60, 0xfe, 0x60, 0x56, 0x60, 0xf3, 0x01, 0x00];
    let bs = blocks(&code);
    assert_eq!(spans(&bs), vec![(0, 10)]);
    assert_eq!(bs[0].ops.len(), 6);
    assert_eq!(bs[0].term, Term::Stop);
    assert_eq!(bs[0].static_gas, 4 * 3 + 3);
    // A trapping byte inside push data neither ends the block nor warns.
    let code = [0x60, 0x42, 0x60, 0xff, 0x00];
    assert_eq!(spans(&blocks(&code)), vec![(0, 5)]);
    assert!(warnings(&code).is_empty());
}

#[test]
fn a_truncated_push_at_the_end_decodes_zero_padded_with_the_end_clamped() {
    // PUSH2 with one byte: the immediate is 0x01 then a zero, the block ends at the code's end.
    let bs = blocks(&[0x61, 0x01]);
    assert_eq!(spans(&bs), vec![(0, 2)]);
    assert_eq!(bs[0].term, Term::Stop);
    let op = &bs[0].ops[0];
    assert_eq!(op.opcode, 0x61);
    let mut want = [0u8; 32];
    want[30] = 0x01;
    assert_eq!(op.push, Some(want));
    // PUSH32 alone: all zeros, end 1.
    let bs = blocks(&[0x7f]);
    assert_eq!(spans(&bs), vec![(0, 1)]);
    assert_eq!(bs[0].ops[0].push, Some([0u8; 32]));
    // PUSH1 alone.
    let bs = blocks(&[0x60]);
    assert_eq!(spans(&bs), vec![(0, 1)]);
    assert_eq!(bs[0].ops[0].push, Some([0u8; 32]));
    assert_eq!(bs[0].static_gas, 3);
    // After a jumpdest: the second block is the truncated push alone.
    let bs = blocks(&[0x5b, 0x63, 0xaa, 0xbb]);
    assert_eq!(spans(&bs), vec![(0, 4)]);
    let mut want = [0u8; 32];
    want[28] = 0xaa;
    want[29] = 0xbb;
    assert_eq!(bs[0].ops[1].push, Some(want));
    // Exactly at the cap with a truncated PUSH32 as its last byte: the last block ends at the cap.
    let mut code = vec![0x5b; MAX_CODE_BYTES - 1];
    code.push(0x7f);
    let bs = blocks(&code);
    assert_eq!(bs.last().unwrap().end, MAX_CODE_BYTES);
    assert_eq!(bs.len(), MAX_CODE_BYTES - 1);
    assert_eq!(bs.last().unwrap().ops.len(), 2, "the last JUMPDEST and the PUSH32");
}

#[test]
fn consecutive_jumpdests_are_one_block_each() {
    let bs = blocks(&[0x5b, 0x5b, 0x5b]);
    assert_eq!(spans(&bs), vec![(0, 1), (1, 2), (2, 3)]);
    assert_eq!(
        terms(&bs),
        vec![Term::Fallthrough(1), Term::Fallthrough(2), Term::Stop]
    );
    for b in &bs {
        assert_eq!(b.static_gas, 1);
        assert_eq!((b.min_depth, b.max_growth), (0, 0));
        assert_eq!(b.ops.len(), 1);
        assert_eq!(b.ops[0].gas_after, 0);
    }
    // A JUMPDEST as the first byte is a block start, not a split.
    let bs = blocks(&[0x5b, 0x00]);
    assert_eq!(spans(&bs), vec![(0, 2)]);
}

#[test]
fn every_terminator_kind_ends_its_block() {
    let one = |code: &[u8]| {
        let bs = blocks(code);
        (bs.len(), bs[0].term, bs[0].end)
    };
    assert_eq!(one(&[0x00, 0x00]), (2, Term::Stop, 1));
    assert_eq!(one(&[0x56, 0x00]), (2, Term::Jump, 1));
    assert_eq!(one(&[0x57, 0x00]), (2, Term::JumpI(1), 1));
    assert_eq!(one(&[0x60, 0x01, 0x57, 0x00]), (2, Term::JumpI(3), 3));
    assert_eq!(one(&[0xf3, 0x00]), (2, Term::Return, 1));
    assert_eq!(one(&[0xfd, 0x00]), (2, Term::Revert, 1));
    assert_eq!(one(&[0xfe, 0x00]), (2, Term::Invalid, 1));
    for op in TRAP_TERM {
        assert_eq!(one(&[op, 0x00]), (2, Term::TrapOp(op), 1), "{op:#04x}");
    }
    // Undefined bytes and the Cancun opcodes trap the same way.
    for op in [0x0c, 0x0e, 0x21, 0x2f, 0x49, 0x4f, 0x5c, 0x5d, 0x5e, 0xa5, 0xef, 0xfb, 0xfc] {
        assert_eq!(one(&[op, 0x00]), (2, Term::TrapOp(op), 1), "{op:#04x}");
        assert!(mnemonic(op).starts_with("UNDEFINED_") || matches!(op, 0x5c | 0x5d | 0x5e), "{op:#04x}");
    }
    // The call family does not end a block; JUMPDEST does not either.
    for op in CALL_FAMILY {
        assert_eq!(one(&[op, 0x00]), (1, Term::Stop, 2), "{op:#04x}");
    }
    assert_eq!(one(&[0x5b, 0x00]), (1, Term::Stop, 2));
    // Running off the end with no terminator at all.
    assert_eq!(one(&[0x60, 0x01, 0x01]), (1, Term::Stop, 3));
}

#[test]
fn stack_bounds_of_the_deep_and_n_ary_ops() {
    let bounds = |code: &[u8]| {
        let b = &blocks(code)[0];
        (b.min_depth, b.max_growth)
    };
    assert_eq!(bounds(&[0x9f]), (17, 0), "SWAP16 needs 17");
    assert_eq!(bounds(&[0x90]), (2, 0), "SWAP1 needs 2");
    assert_eq!(bounds(&[0x8f]), (16, 1), "DUP16 needs 16, pushes 1");
    assert_eq!(bounds(&[0x80]), (1, 1));
    assert_eq!(bounds(&[0xa4]), (6, 0), "LOG4: offset, size, four topics");
    assert_eq!(bounds(&[0xa0]), (2, 0));
    assert_eq!(bounds(&[0xf1]), (7, 0), "CALL: seven in, the flag out");
    assert_eq!(bounds(&[0xf2]), (7, 0));
    assert_eq!(bounds(&[0xf4]), (6, 0));
    assert_eq!(bounds(&[0xfa]), (6, 0));
    assert_eq!(bounds(&[0x08]), (3, 0), "ADDMOD");
    assert_eq!(bounds(&[0x09]), (3, 0));
    assert_eq!(bounds(&[0x37]), (3, 0), "CALLDATACOPY");
    assert_eq!(bounds(&[0x39]), (3, 0));
    assert_eq!(bounds(&[0x3e]), (3, 0));
    assert_eq!(bounds(&[0x50, 0x50, 0x50]), (3, 0), "three POPs");
    assert_eq!(bounds(&[0x5f, 0x5f, 0x5f, 0x5f, 0x5f]), (0, 5));
    assert_eq!(bounds(&[0x5f, 0x50, 0x5f, 0x50]), (0, 1));
    // ADD, ADD, ADD: each needs two over what is left: 2, then 3, then 4.
    assert_eq!(bounds(&[0x01, 0x01, 0x01]), (4, 0));
    // PUSH then ADD: one pushed, one more needed.
    assert_eq!(bounds(&[0x60, 0x01, 0x01]), (1, 1));
    // The trapping opcodes touch nothing.
    for op in TRAP_TERM {
        assert_eq!(bounds(&[op]), (0, 0), "{op:#04x}");
    }
    assert_eq!(bounds(&[0x00]), (0, 0));
    assert_eq!(bounds(&[0xfe]), (0, 0));
    // A deep op after pushes: fifteen pushes then DUP16 still needs one from the entry.
    let mut code = vec![0x5f; 15];
    code.push(0x8f);
    assert_eq!(bounds(&code), (1, 16));
    // The growth is the peak, not the end: five pushes, then LOG3 consumes five.
    let mut code = vec![0x5f; 5];
    code.push(0xa3);
    assert_eq!(bounds(&code), (0, 5));
    // `stack_bounds` over an empty sequence.
    assert_eq!(stack_bounds(&[]), (0, 0));
}

#[test]
fn stack_effect_agrees_with_a_hand_table() {
    let table: &[(u8, (usize, i32))] = &[
        (0x00, (0, 0)),
        (0x01, (2, -1)),
        (0x08, (3, -2)),
        (0x0a, (2, -1)),
        (0x15, (1, 0)),
        (0x19, (1, 0)),
        (0x20, (2, -1)),
        (0x30, (0, 1)),
        (0x32, (0, 1)),
        (0x35, (1, 0)),
        (0x37, (3, -3)),
        (0x3d, (0, 1)),
        (0x46, (0, 1)),
        (0x50, (1, -1)),
        (0x51, (1, 0)),
        (0x52, (2, -2)),
        (0x53, (2, -2)),
        (0x54, (1, 0)),
        (0x55, (2, -2)),
        (0x56, (1, -1)),
        (0x57, (2, -2)),
        (0x58, (0, 1)),
        (0x5b, (0, 0)),
        (0x5f, (0, 1)),
        (0x60, (0, 1)),
        (0x7f, (0, 1)),
        (0x80, (1, 1)),
        (0x8f, (16, 1)),
        (0x90, (2, 0)),
        (0x9f, (17, 0)),
        (0xa0, (2, -2)),
        (0xa4, (6, -6)),
        (0xf1, (7, -6)),
        (0xf4, (6, -5)),
        (0xf3, (2, -2)),
        (0xfd, (2, -2)),
        (0xfe, (0, 0)),
        (0x31, (0, 0)),
        (0xff, (0, 0)),
        (0x0c, (0, 0)),
    ];
    for &(op, want) in table {
        assert_eq!(stack_effect(op), want, "{op:#04x} {}", mnemonic(op));
    }
    // No opcode pops more than it needs.
    for op in 0..=255u8 {
        let (need, net) = stack_effect(op);
        assert!(net >= -(need as i32), "{op:#04x}: pops more than it needs");
        assert!(net <= 1, "{op:#04x}: pushes more than one");
    }
    // Every mnemonic is distinct.
    let names: std::collections::BTreeSet<String> = (0..=255u8).map(mnemonic).collect();
    assert_eq!(names.len(), 256);
}

#[test]
fn static_gas_over_the_push_dup_swap_and_dynamic_ranges() {
    assert_eq!(static_gas(0x5f), 2, "PUSH0 is base");
    for op in 0x60..=0x7f {
        assert_eq!(static_gas(op), 3, "PUSH{}", op - 0x5f);
    }
    for op in 0x80..=0x9f {
        assert_eq!(static_gas(op), 3, "{}", mnemonic(op));
    }
    assert_eq!(static_gas(0x5b), 1);
    assert_eq!(static_gas(0x54), 2100);
    assert_eq!(static_gas(0x56), 8);
    assert_eq!(static_gas(0x57), 10);
    assert_eq!(static_gas(0x0a), 0, "EXP is dynamic");
    assert_eq!(static_gas(0x20), 0, "KECCAK256 is dynamic");
    assert_eq!(static_gas(0x55), 0, "SSTORE is dynamic");
    for op in 0xa0..=0xa4 {
        assert_eq!(static_gas(op), 0, "LOGn is dynamic");
    }
    for op in [0x00, 0xf3, 0xfd, 0xfe] {
        assert_eq!(static_gas(op), 0, "{op:#04x} is free");
    }
    for op in TRAP_TERM.iter().chain(CALL_FAMILY.iter()) {
        assert_eq!(static_gas(*op), 0, "{op:#04x}");
    }
    // The sum of a block of every PUSHn with its immediate: 32 × 3.
    let mut code = Vec::new();
    for n in 1..=32u8 {
        code.push(0x5f + n);
        code.extend(std::iter::repeat_n(0, n as usize));
    }
    let bs = blocks(&code);
    assert_eq!(bs.len(), 1);
    assert_eq!(bs[0].static_gas, 96);
    assert_eq!(bs[0].ops.len(), 32);
    assert_eq!(bs[0].ops[0].gas_after, 93);
    assert_eq!((bs[0].min_depth, bs[0].max_growth), (0, 32));
}

#[test]
fn warnings_at_every_pc_shape() {
    // Each warned byte, at pc 0.
    for op in WARN_SET {
        let w = warnings(&[op]);
        let want = if CALL_FAMILY.contains(&op) {
            Warning::Call { pc: 0, opcode: op }
        } else {
            Warning::Trap { pc: 0, opcode: op }
        };
        assert_eq!(w, vec![want], "{op:#04x}");
    }
    // After a PUSH32, the pc is 33.
    let mut code = vec![0x7f];
    code.extend([0u8; 32]);
    code.push(0x42);
    assert_eq!(warnings(&code), vec![Warning::Trap { pc: 33, opcode: 0x42 }]);
    // In dead code after a STOP: still reported (the CLI warns about it).
    assert_eq!(
        warnings(&[0x00, 0xf0]),
        vec![Warning::Trap { pc: 1, opcode: 0xf0 }]
    );
    // Two in a row, and a trap after a call.
    assert_eq!(
        warnings(&[0xfa, 0xf1, 0x31]),
        vec![
            Warning::Call { pc: 0, opcode: 0xfa },
            Warning::Call { pc: 1, opcode: 0xf1 },
            Warning::Trap { pc: 2, opcode: 0x31 },
        ]
    );
    // A truncated push at the end hides nothing after it.
    assert!(warnings(&[0x61, 0x42]).is_empty());
    // Undefined bytes are not warned: they trap, but they are not in the set.
    assert!(warnings(&[0x0c, 0x5c, 0xef]).is_empty());
    assert!(warnings(&[]).is_empty());
}

/// What every block list must satisfy, whatever the code.
fn assert_partition(code: &[u8]) {
    let bs = blocks(code);
    let jd = jumpdests(code);
    assert_eq!(bs.first().unwrap().start, 0);
    assert_eq!(bs.last().unwrap().end, code.len());
    for w in bs.windows(2) {
        assert_eq!(w[0].end, w[1].start, "contiguous");
    }
    for b in &bs {
        // The ops decode the block's bytes exactly (the last op may run past the end: a
        // truncated push).
        let mut pc = b.start;
        for op in &b.ops {
            assert_eq!(op.pc, pc);
            pc += if op.push.is_some() {
                1 + (op.opcode - 0x5f) as usize
            } else {
                1
            };
            assert_eq!(op.push.is_some(), (0x60..=0x7f).contains(&op.opcode));
        }
        assert_eq!(pc.min(code.len()), b.end);
        // A JUMPDEST only ever starts a block.
        for op in b.ops.iter().skip(1) {
            assert_ne!(op.opcode, 0x5b, "a JUMPDEST inside block [{:#x}, {:#x})", b.start, b.end);
        }
        // The terminator is the last op, and the fall-through pc is the end.
        match b.term {
            Term::Fallthrough(p) => {
                assert_eq!(p, b.end);
                assert!(jd.binary_search(&p).is_ok(), "a fall-through into a non-jumpdest");
            }
            Term::JumpI(p) => {
                assert_eq!(p, b.end);
                assert_eq!(b.ops.last().unwrap().opcode, 0x57);
            }
            Term::Jump => assert_eq!(b.ops.last().unwrap().opcode, 0x56),
            Term::Return => assert_eq!(b.ops.last().unwrap().opcode, 0xf3),
            Term::Revert => assert_eq!(b.ops.last().unwrap().opcode, 0xfd),
            Term::Invalid => assert_eq!(b.ops.last().unwrap().opcode, 0xfe),
            Term::TrapOp(op) => assert_eq!(b.ops.last().unwrap().opcode, op),
            Term::Stop => {
                if b.end < code.len() {
                    assert_eq!(b.ops.last().unwrap().opcode, 0x00);
                }
            }
            Term::OutOfBounds => unreachable!(),
        }
        // The static gas is the sum, the bounds are `stack_bounds`, and `gas_after` chains.
        assert_eq!(
            b.static_gas,
            b.ops.iter().map(|o| static_gas(o.opcode)).sum::<u64>()
        );
        assert_eq!((b.min_depth, b.max_growth), stack_bounds(&b.ops));
        let mut suffix = 0;
        for op in b.ops.iter().rev() {
            assert_eq!(op.gas_after, suffix);
            suffix += static_gas(op.opcode);
        }
    }
    // Every jumpdest starts a block, and every block start is 0, a jumpdest, or the byte after
    // a terminator.
    let starts: Vec<usize> = bs.iter().map(|b| b.start).collect();
    for &j in &jd {
        assert!(starts.binary_search(&j).is_ok(), "jumpdest {j} starts no block");
    }
    for w in bs.windows(2) {
        let s = w[1].start;
        assert!(
            jd.binary_search(&s).is_ok() || !matches!(w[0].term, Term::Fallthrough(_)),
            "block at {s} starts at neither a jumpdest nor after a terminator"
        );
    }
}

#[test]
fn the_partition_invariants_hold_on_the_corpus_and_on_random_bytes() {
    for seed in 0..300 {
        assert_partition(&evm2rv::gen::case(seed).code);
        assert_partition(&evm2rv::gen::case_opaque(seed).code);
    }
    // Arbitrary bytes: every byte value appears, pushes run past the end, nothing is valid.
    let mut r = evm2rv::gen::Rng::new(7);
    for _ in 0..300 {
        let n = r.range(0, 200) as usize;
        assert_partition(&r.bytes(n));
    }
    assert_partition(&[]);
    assert_partition(&(0..=255u8).collect::<Vec<u8>>());
}

#[test]
fn an_op_carries_its_pc_opcode_and_immediate() {
    // PUSH3 0x0a0b0c at 0, ADD at 4, PUSH0 at 5.
    let bs = blocks(&[0x62, 0x0a, 0x0b, 0x0c, 0x01, 0x5f]);
    let mut imm = [0u8; 32];
    imm[29..].copy_from_slice(&[0x0a, 0x0b, 0x0c]);
    assert_eq!(
        bs[0].ops,
        vec![
            Op { pc: 0, opcode: 0x62, push: Some(imm), gas_after: 5 },
            Op { pc: 4, opcode: 0x01, push: None, gas_after: 2 },
            Op { pc: 5, opcode: 0x5f, push: None, gas_after: 0 },
        ]
    );
}

/// `jumpdests` is the interpreter's own scan, on the corpus and on arbitrary bytes: the one
/// thing this crate must never drift from.
#[test]
fn jumpdests_match_the_interpreters_scan_on_the_corpus_and_random_bytes() {
    let oracle = |code: &[u8]| -> Vec<usize> {
        let capped = &code[..code.len().min(MAX_CODE_BYTES)];
        let mut bits = [0u32; MAX_CODE_BYTES / 32];
        evm_core::interp::scan_jumpdests(capped, &mut bits);
        (0..capped.len())
            .filter(|&i| (bits[i / 32] >> (i % 32)) & 1 == 1)
            .collect()
    };
    let mut total = 0;
    for seed in 0..300 {
        for code in [evm2rv::gen::case(seed).code, evm2rv::gen::case_opaque(seed).code] {
            let jd = jumpdests(&code);
            assert_eq!(jd, oracle(&code), "seed {seed}");
            total += jd.len();
        }
    }
    assert!(total > 1000, "the corpus has jump targets: {total}");
    let mut r = evm2rv::gen::Rng::new(11);
    for _ in 0..500 {
        let n = r.range(0, 300) as usize;
        let code = r.bytes(n);
        assert_eq!(jumpdests(&code), oracle(&code));
    }
}
