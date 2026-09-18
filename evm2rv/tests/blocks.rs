//! Task 3's tests: `jumpdests` against the interpreter's own scan on the ERC-20 bytecode, block
//! splitting at jumpdests and after terminators, the static-gas table against the interpreter's
//! for every opcode byte, a hand-built static-gas sum, stack bounds on a hand-built sequence, and
//! `warnings` over the cross-contract family (both the statically-trapping sixteen and the
//! runtime-resolved call family).

use evm2rv::blocks::{blocks, jumpdests, static_gas, warnings, Term};
use evm_core::interp::MAX_CODE_BYTES;

/// The ERC-20 runtime bytecode the interpreter's own tests use (`evm-core`'s parity vector).
fn erc20_code() -> Vec<u8> {
    let hex_text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../guests-compiled/evm/contracts/erc20.runtime.hex"
    ))
    .expect("reading erc20.runtime.hex");
    hex::decode(
        hex_text
            .trim()
            .strip_prefix("0x")
            .unwrap_or(hex_text.trim()),
    )
    .expect("decoding erc20.runtime.hex")
}

/// The interpreter's own scan, called directly (not `evm2rv`'s wrapper), as the oracle.
fn interpreter_jumpdests(code: &[u8]) -> Vec<usize> {
    let capped = &code[..code.len().min(MAX_CODE_BYTES)];
    let mut bits = [0u32; MAX_CODE_BYTES / 32];
    evm_core::interp::scan_jumpdests(capped, &mut bits);
    (0..capped.len())
        .filter(|&i| (bits[i / 32] >> (i % 32)) & 1 == 1)
        .collect()
}

#[test]
fn jumpdests_matches_interpreter_on_erc20() {
    let code = erc20_code();
    assert_eq!(jumpdests(&code), interpreter_jumpdests(&code));
    // Not a vacuous check: the ERC-20 has real jump targets.
    assert!(!jumpdests(&code).is_empty());
}

#[test]
fn jumpdests_excludes_push_immediates() {
    // PUSH1 0x5b (JUMPDEST's byte value, as push data) ; JUMPDEST
    let code = [0x60, 0x5b, 0x5b];
    // Byte 1 is push data (not a jumpdest, despite its value); byte 2 is a real JUMPDEST.
    assert_eq!(jumpdests(&code), vec![2]);
}

#[test]
fn static_gas_matches_interpreter_for_every_opcode_byte() {
    for op in 0u16..=255 {
        let op = op as u8;
        assert_eq!(
            static_gas(op),
            evm_core::interp::static_gas(op),
            "static_gas({op:#04x}) diverges from the interpreter's table"
        );
    }
}

#[test]
#[allow(clippy::identity_op)] // written out per the brief: "3+3+3+0", STOP's 0 included on purpose
fn static_gas_sum_on_hand_built_sequence() {
    // PUSH1 1, PUSH1 2, ADD, STOP — the brief's own example: 3 + 3 + 3 + 0.
    let code = [0x60, 0x01, 0x60, 0x02, 0x01, 0x00];
    let bs = blocks(&code);
    assert_eq!(bs.len(), 1);
    assert_eq!(bs[0].ops.len(), 4);
    assert_eq!(bs[0].static_gas, 3 + 3 + 3 + 0);
    assert_eq!(bs[0].term, Term::Stop);
}

#[test]
fn stack_bounds_on_dup1_swap1_pop() {
    // DUP1, SWAP1, POP, STOP
    let code = [0x80, 0x90, 0x50, 0x00];
    let bs = blocks(&code);
    assert_eq!(bs.len(), 1);
    // DUP1 needs 1 item present (min_depth); the stack never grows more than 1 above that entry
    // depth (after DUP1 pushes the duplicate, before POP removes it).
    assert_eq!(bs[0].min_depth, 1);
    assert_eq!(bs[0].max_growth, 1);
}

#[test]
fn blocks_split_at_every_jumpdest() {
    // JUMPDEST, STOP, JUMPDEST, STOP
    let code = [0x5b, 0x00, 0x5b, 0x00];
    let bs = blocks(&code);
    assert_eq!(bs.len(), 2);
    assert_eq!((bs[0].start, bs[0].end), (0, 2));
    assert_eq!(bs[0].term, Term::Stop);
    assert_eq!((bs[1].start, bs[1].end), (2, 4));
    assert_eq!(bs[1].term, Term::Stop);
}

#[test]
fn blocks_split_after_jump() {
    // PUSH1 3, JUMP, JUMPDEST, STOP
    let code = [0x60, 0x03, 0x56, 0x5b, 0x00];
    let bs = blocks(&code);
    assert_eq!(bs.len(), 2);
    assert_eq!((bs[0].start, bs[0].end), (0, 3));
    assert_eq!(bs[0].term, Term::Jump);
    assert_eq!((bs[1].start, bs[1].end), (3, 5));
    assert_eq!(bs[1].term, Term::Stop);
}

#[test]
fn blocks_split_after_jumpi_with_fallthrough_term() {
    // PUSH1 6, PUSH1 1, JUMPI, ADD, JUMPDEST, STOP
    let code = [0x60, 0x06, 0x60, 0x01, 0x57, 0x01, 0x5b, 0x00];
    let bs = blocks(&code);
    // block 0: [0,5) ends in JUMPI whose fallthrough is pc 5
    assert_eq!((bs[0].start, bs[0].end), (0, 5));
    assert_eq!(bs[0].term, Term::JumpI(5));
    // block 1: [5,6) — a single ADD — falls into the JUMPDEST at 6 without its own terminator
    assert_eq!((bs[1].start, bs[1].end), (5, 6));
    assert_eq!(bs[1].term, Term::Fallthrough(6));
    // block 2: [6,8) — the JUMPDEST itself is an ordinary op starting this block, then STOP
    assert_eq!((bs[2].start, bs[2].end), (6, 8));
    assert_eq!(bs[2].term, Term::Stop);
}

#[test]
fn blocks_split_after_trapping_opcode_and_fall_off_end_is_stop() {
    // BALANCE (a statically-trapping opcode, ends the block); no trailing STOP — falling off
    // the end of the code is STOP, per the interpreter's rule.
    let code = [0x60, 0x00, 0x31];
    let bs = blocks(&code);
    assert_eq!(bs.len(), 1);
    assert_eq!(bs[0].term, Term::TrapOp(0x31));
    assert_eq!(bs[0].end, 3);
}

#[test]
fn call_family_is_not_a_block_terminator() {
    // PUSH1 0 x6, PUSH1 0, CALL, PUSH1 1, STOP — CALL does not split the block: the runtime
    // resolves it by address, so it is ordinary here.
    let mut code = vec![];
    for _ in 0..7 {
        code.extend_from_slice(&[0x60, 0x00]); // 7 args
    }
    code.push(0xf1); // CALL
    code.push(0x00); // STOP
    let bs = blocks(&code);
    assert_eq!(bs.len(), 1, "CALL must not end the block");
    assert_eq!(bs[0].term, Term::Stop);
    assert!(bs[0].ops.iter().any(|o| o.opcode == 0xf1));
}

#[test]
fn empty_code_is_one_stop_block() {
    let bs = blocks(&[]);
    assert_eq!(bs.len(), 1);
    assert_eq!(bs[0].term, Term::Stop);
    assert_eq!((bs[0].start, bs[0].end), (0, 0));
}

#[test]
fn warnings_reports_statically_trapping_opcodes_with_pc() {
    // PUSH1 0, BALANCE, PUSH1 0, TIMESTAMP
    let code = [0x60, 0x00, 0x31, 0x60, 0x00, 0x42];
    let w = warnings(&code);
    assert_eq!(w, vec![(2, 0x31), (5, 0x42)]);
}

#[test]
fn warnings_reports_call_family_even_though_it_is_not_a_terminator() {
    let mut code = vec![];
    for _ in 0..6 {
        code.extend_from_slice(&[0x60, 0x00]);
    }
    code.push(0xfa); // STATICCALL, at pc 12
    code.push(0x00); // STOP
    let w = warnings(&code);
    assert_eq!(w, vec![(12, 0xfa)]);
}

#[test]
fn warnings_skips_push_immediates() {
    // PUSH1 0x31 — the immediate byte happens to equal BALANCE's opcode, and must not be
    // reported.
    let code = [0x60, 0x31, 0x00];
    assert!(warnings(&code).is_empty());
}

#[test]
fn erc20_blocks_and_warnings_are_stable() {
    let code = erc20_code();
    let bs = blocks(&code);
    assert!(!bs.is_empty());
    // Every block's ops decode exactly the bytes between its own start and end, except that a
    // trailing block's last `PUSHn` may declare an immediate that runs past the actual code (the
    // ERC-20's solc metadata trailer, linearly disassembled, does this) — legal, and zero-padded
    // exactly as the interpreter reads it — so `end` is the code-clamped boundary `blocks` itself
    // reports, not necessarily the literal `pc + immediate length`.
    for b in &bs {
        let mut pc = b.start;
        for op in &b.ops {
            assert_eq!(op.pc, pc);
            pc += if op.push.is_some() {
                1 + (op.opcode - 0x5f) as usize
            } else {
                1
            };
        }
        assert_eq!(pc.min(code.len()), b.end);
    }
    // Blocks partition the code with no gaps and no overlap.
    for w in bs.windows(2) {
        assert_eq!(w[0].end, w[1].start);
    }
    assert_eq!(bs.first().unwrap().start, 0);
    assert_eq!(bs.last().unwrap().end, code.len());

    // The ERC-20 subset (transfer/approve/transferFrom/balanceOf/totalSupply) does not touch the
    // cross-contract family.
    assert!(warnings(&code).is_empty());
}
