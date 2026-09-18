//! Task 4's emitter tests (Task 8: the structural ones run under both stages — the block head, the
//! jumps' shape, the call family's arity, the return-data buffer, `CHAINID`, compiling clean for
//! rv32im — while the per-opcode strings are stage one's, `op_c`): each opcode's C against the spec's table (the operand order the
//! interpreter pops in, offsets and lengths saturated, the runtime's names), the block head, the
//! jump switch and the statically resolved jumps, `GAS`/`PC`, the traps (the sixteen and undefined
//! bytes), the call family (a runtime dispatch to the precompiles, Task 5) and the return-data
//! buffer, the environment (`ORIGIN` = `CALLER`,
//! `CHAINID` a required constant), code over the cap, and the generated shim crate. The emitted
//! ERC-20 must compile clean under `-Wall -Wextra -Werror` for rv32im.

use std::path::PathBuf;
use std::process::Command;

use evm2rv::blocks::{Op, TRAP_TERM};
use evm2rv::emit::{op_c, translate, EmitError, Options, Stage};
use evm2rv::shim::{crate_name, files, C_FLAGS};
use evm_core::interp::MAX_CODE_BYTES;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .unwrap()
}

fn erc20_code() -> Vec<u8> {
    let text =
        std::fs::read_to_string(root().join("guests-compiled/evm/contracts/erc20.runtime.hex"))
            .unwrap();
    hex::decode(text.trim()).unwrap()
}

const STAGES: [Stage; 2] = [Stage::One, Stage::Two];

/// No `CHAINID` constant, at `stage`.
fn at(stage: Stage) -> Options {
    Options {
        chain_id: None,
        stage,
    }
}

/// Stage one, whose C the string tests pin.
fn one() -> Options {
    at(Stage::One)
}

fn op(opcode: u8) -> Op {
    Op {
        pc: 0x2a,
        opcode,
        push: None,
        gas_after: 0,
    }
}

/// The C for `opcode` in a contract with no call-family opcode.
fn c_of(opcode: u8) -> String {
    op_c(&op(opcode), 0, &one(), false).unwrap()
}

/// ... and in one with a call-family opcode (the return-data buffer is live).
fn c_of_calls(opcode: u8) -> String {
    op_c(&op(opcode), 0, &one(), true).unwrap()
}

const S1: &str = "&evm_stack[evm_sp-1]";
const S2: &str = "&evm_stack[evm_sp-2]";
const S3: &str = "&evm_stack[evm_sp-3]";

fn sat(s: &str) -> String {
    format!("u256_sat_u32({s})")
}

/// Two-operand ops: `a` is the top (`evm_sp-1`), `b` the second, the result over the second —
/// `a op b`, as the interpreter's `binary` pops them.
#[test]
fn binary_ops_take_the_top_as_their_first_operand() {
    for (opcode, f) in [
        (0x01, "u256_add"),
        (0x02, "u256_mul"),
        (0x03, "u256_sub"),
        (0x04, "u256_div"),
        (0x05, "u256_sdiv"),
        (0x06, "u256_mod"),
        (0x07, "u256_smod"),
        (0x10, "u256_lt"),
        (0x11, "u256_gt"),
        (0x12, "u256_slt"),
        (0x13, "u256_sgt"),
        (0x14, "u256_eq"),
        (0x16, "u256_and"),
        (0x17, "u256_or"),
        (0x18, "u256_xor"),
    ] {
        assert_eq!(
            c_of(opcode),
            format!("{f}({S2}, {S1}, {S2}); evm_sp--;"),
            "{opcode:#04x}"
        );
    }
    // The spec's example, ADD, spelled out.
    assert_eq!(
        c_of(0x01),
        "u256_add(&evm_stack[evm_sp-2], &evm_stack[evm_sp-1], &evm_stack[evm_sp-2]); evm_sp--;"
    );
}

/// The ops whose runtime call takes the value first: SIGNEXTEND, BYTE and the shifts pop the
/// index/shift first (the top) and the value second; EXP pops the base first.
#[test]
fn value_first_ops_and_the_three_operand_ones() {
    for (opcode, f) in [
        (0x0b, "u256_signextend"),
        (0x1a, "u256_byte"),
        (0x1b, "u256_shl"),
        (0x1c, "u256_shr"),
        (0x1d, "u256_sar"),
    ] {
        assert_eq!(
            c_of(opcode),
            format!("{f}({S2}, {S2}, {S1}); evm_sp--;"),
            "{opcode:#04x}"
        );
    }
    assert_eq!(c_of(0x0a), format!("evm_exp({S2}, {S1}, {S2}); evm_sp--;"));
    assert_eq!(
        c_of(0x08),
        format!("u256_addmod({S3}, {S1}, {S2}, {S3}); evm_sp -= 2;")
    );
    assert_eq!(
        c_of(0x09),
        format!("u256_mulmod({S3}, {S1}, {S2}, {S3}); evm_sp -= 2;")
    );
    assert_eq!(c_of(0x15), format!("u256_iszero({S1}, {S1});"));
    assert_eq!(c_of(0x19), format!("u256_not({S1}, {S1});"));
}

/// Memory, calldata, code, storage, logs and the halts: offsets and lengths saturated, MSTORE8's
/// value the bare low limb, the operands in the interpreter's pop order.
#[test]
fn memory_storage_logs_and_halts() {
    assert_eq!(
        c_of(0x20),
        format!("evm_keccak({}, {}, {S2}); evm_sp--;", sat(S1), sat(S2))
    );
    assert_eq!(c_of(0x35), format!("evm_calldataload({}, {S1});", sat(S1)));
    for (opcode, f) in [
        (0x37, "evm_copy_calldata"),
        (0x39, "evm_copy_code"),
        (0x3e, "evm_copy_returndata"),
    ] {
        assert_eq!(
            c_of(opcode),
            format!("{f}({}, {}, {}); evm_sp -= 3;", sat(S1), sat(S2), sat(S3))
        );
    }
    assert_eq!(c_of(0x51), format!("evm_mload({}, {S1});", sat(S1)));
    assert_eq!(
        c_of(0x52),
        format!("evm_mstore({}, {S2}); evm_sp -= 2;", sat(S1))
    );
    assert_eq!(
        c_of(0x53),
        format!("evm_mstore8({}, u256_low_u32({S2})); evm_sp -= 2;", sat(S1))
    );
    assert_eq!(c_of(0x54), format!("evm_storage_load({S1}, {S1});"));
    assert_eq!(
        c_of(0x55),
        format!("evm_storage_store({S1}, {S2}); evm_sp -= 2;")
    );
    assert_eq!(
        c_of(0xa0),
        format!(
            "evm_log(0, {}, {}, &evm_stack[evm_sp-2]); evm_sp -= 2;",
            sat(S1),
            sat(S2)
        )
    );
    assert_eq!(
        c_of(0xa3),
        format!(
            "evm_log(3, {}, {}, &evm_stack[evm_sp-5]); evm_sp -= 5;",
            sat(S1),
            sat(S2)
        )
    );
    assert_eq!(c_of(0xf3), format!("evm_return({}, {});", sat(S1), sat(S2)));
    assert_eq!(c_of(0xfd), format!("evm_revert({}, {});", sat(S1), sat(S2)));
    assert_eq!(c_of(0x00), "evm_halt(EVM_HALT_STOP, 0);");
    assert_eq!(c_of(0xfe), "evm_halt(EVM_HALT_INVALID, 0);");
}

#[test]
fn stack_ops_pushes_and_constants() {
    assert_eq!(c_of(0x50), "evm_sp--;");
    assert_eq!(
        c_of(0x80),
        "evm_stack[evm_sp] = evm_stack[evm_sp-1]; evm_sp++;"
    );
    assert_eq!(
        c_of(0x8f),
        "evm_stack[evm_sp] = evm_stack[evm_sp-16]; evm_sp++;"
    );
    assert_eq!(
        c_of(0x90),
        "{ u256 t_ = evm_stack[evm_sp-1]; evm_stack[evm_sp-1] = evm_stack[evm_sp-2]; evm_stack[evm_sp-2] = t_; }"
    );
    assert_eq!(
        c_of(0x9f),
        "{ u256 t_ = evm_stack[evm_sp-1]; evm_stack[evm_sp-1] = evm_stack[evm_sp-17]; evm_stack[evm_sp-17] = t_; }"
    );
    assert_eq!(c_of(0x5f), "u256_from_u32(&evm_stack[evm_sp++], 0u);");
    // PC is the op's own pc, a constant.
    assert_eq!(c_of(0x58), "u256_from_u32(&evm_stack[evm_sp++], 0x2au);");
    assert_eq!(
        c_of(0x59),
        "u256_from_u32(&evm_stack[evm_sp++], evm_msize);"
    );
    assert_eq!(
        c_of(0x36),
        "u256_from_u32(&evm_stack[evm_sp++], evm_calldata_len);"
    );
    assert_eq!(
        c_of(0x38),
        "u256_from_u32(&evm_stack[evm_sp++], evm_code_len);"
    );
    assert_eq!(c_of(0x3d), "u256_from_u32(&evm_stack[evm_sp++], 0u);");
    assert_eq!(c_of(0x5b), "", "JUMPDEST: its gas is in the head's charge");

    // PUSHn immediates: a u32, a u64, and a full word as a .rodata constant.
    let push = |n: usize, bytes: &[u8]| {
        let mut v = [0u8; 32];
        v[32 - bytes.len()..].copy_from_slice(bytes);
        let o = Op {
            pc: 0,
            opcode: 0x5f + n as u8,
            push: Some(v),
            gas_after: 0,
        };
        op_c(&o, 0, &one(), false).unwrap()
    };
    assert_eq!(
        push(1, &[0x80]),
        "u256_from_u32(&evm_stack[evm_sp++], 0x80u);"
    );
    assert_eq!(
        push(8, &[1, 2, 3, 4, 5, 6, 7, 8]),
        "u256_from_u64(&evm_stack[evm_sp++], 0x102030405060708ull);"
    );
    let full: Vec<u8> = (1..=32).collect();
    assert_eq!(
        push(32, &full),
        "{ static const u256 k_ = {{0x1d1e1f20u, 0x191a1b1cu, 0x15161718u, 0x11121314u, 0xd0e0f10u, 0x90a0b0cu, 0x5060708u, 0x1020304u}}; evm_stack[evm_sp++] = k_; }"
    );
}

/// GAS pushes the live counter plus the static gas of the rest of its block, which the head has
/// already taken (ruling 4); `translate` feeds it the block's own suffix sum.
#[test]
fn gas_adds_back_the_rest_of_the_block() {
    let o = Op {
        pc: 0,
        opcode: 0x5a,
        push: None,
        gas_after: 0,
    };
    assert_eq!(
        op_c(&o, 17, &one(), false).unwrap(),
        "u256_from_u64(&evm_stack[evm_sp++], evm_gas + 17ull);"
    );
    // GAS, PUSH1 1, ADD, POP, STOP: after GAS come 3 + 3 + 2 + 0 = 8.
    for stage in STAGES {
        let c = translate(&[0x5a, 0x60, 0x01, 0x01, 0x50, 0x00], &at(stage))
            .unwrap()
            .c;
        assert!(c.contains("evm_gas + 8ull"), "{c}");
        assert!(c.contains("evm_charge(10);"), "{c}"); // 2 + 3 + 3 + 2
    }
}

#[test]
fn environment_opcodes() {
    assert_eq!(c_of(0x30), "evm_stack[evm_sp++] = evm_address;");
    assert_eq!(c_of(0x33), "evm_stack[evm_sp++] = evm_caller;");
    assert_eq!(c_of(0x32), c_of(0x33), "ORIGIN reads CALLER");
    assert_eq!(c_of(0x34), "evm_stack[evm_sp++] = evm_callvalue;");
    // CHAINID is the translation's constant, and there is no default.
    let chain = |id| {
        op_c(
            &op(0x46),
            0,
            &Options {
                chain_id: id,
                stage: Stage::One,
            },
            false,
        )
    };
    assert_eq!(
        chain(Some(0x2a)).unwrap(),
        "u256_from_u64(&evm_stack[evm_sp++], 0x2aull);"
    );
    assert_eq!(chain(None), Err(EmitError::ChainIdRequired { pc: 0x2a }));
    // PUSH1 1, CHAINID, STOP — at either stage.
    let code = [0x60, 0x01, 0x46, 0x00];
    for stage in STAGES {
        assert_eq!(
            translate(&code, &at(stage)).unwrap_err(),
            EmitError::ChainIdRequired { pc: 2 }
        );
        let c = translate(
            &code,
            &Options {
                chain_id: Some(7),
                stage,
            },
        )
        .unwrap()
        .c;
        assert!(c.contains("CHAINID 7"), "the header names the constant");
        if stage == Stage::One {
            assert!(c.contains("u256_from_u64(&evm_stack[evm_sp++], 0x7ull);"));
        }
        // A 0x46 byte inside push data is not CHAINID.
        assert!(translate(&[0x60, 0x46, 0x00], &at(stage)).is_ok());
    }
}

/// ORIGIN and CHAINID cost G_BASE = 2 each in the translation (fix round 1 of Task 4, item 6): the
/// head's charge includes them, and GAS's add-back counts them.
#[test]
fn origin_and_chainid_are_charged_g_base() {
    for stage in STAGES {
        let opts = Options {
            chain_id: Some(1),
            stage,
        };
        // ORIGIN, CHAINID, POP, POP, STOP: 2 + 2 + 2 + 2 + 0.
        let c = translate(&[0x32, 0x46, 0x50, 0x50, 0x00], &opts).unwrap().c;
        assert!(c.contains("evm_charge(8);"), "{c}");
        // GAS, ORIGIN, CHAINID, STOP: after GAS come 2 + 2.
        let c = translate(&[0x5a, 0x32, 0x46, 0x00], &opts).unwrap().c;
        assert!(c.contains("evm_gas + 4ull"), "{c}");
        assert!(c.contains("evm_charge(6);"), "{c}");
    }
    let b = &evm2rv::blocks::blocks(&[0x32, 0x46, 0x00])[0];
    assert_eq!(b.static_gas, 4);
    assert_eq!(b.ops[0].gas_after, 2);
}

/// The sixteen `TRAP_TERM` opcodes (the nine block-context ones among them) and any byte the
/// interpreter does not implement halt `Trap(op)`.
#[test]
fn trapping_opcodes_halt_with_their_opcode() {
    for opcode in TRAP_TERM
        .iter()
        .copied()
        .chain([0x0c, 0x21, 0x5c, 0x5e, 0xef])
    {
        assert_eq!(
            c_of(opcode),
            format!("evm_halt(EVM_HALT_TRAP, {opcode:#04x});"),
            "{opcode:#04x}"
        );
    }
}

/// The call family (Task 5, ruling 6) is a runtime dispatch: `evm_call` gets the op, its operands
/// (`&evm_stack[evm_sp-7]` for CALL/CALLCODE, `-6` for DELEGATECALL/STATICCALL, so the top is the
/// gas) and the static gas of the rest of its block, and the success flag replaces the deepest
/// operand. Its own static gas is 0 (everything is charged in the runtime), the block continues
/// past it, and the head counts its real arity. A contract with a call starts `evm_entry` with
/// `evm_calls_begin()`.
#[test]
fn the_call_family_dispatches_at_runtime_and_the_block_continues() {
    for (call, n) in [(0xf1u8, 7usize), (0xf2, 7), (0xf4, 6), (0xfa, 6)] {
        // PUSH1 0 (n times), CALL, PUSH1 1, ADD, POP, STOP: after the call, 3 + 3 + 2 + 0 = 8.
        let mut code = [0x60u8, 0x00].repeat(n);
        code.extend_from_slice(&[call, 0x60, 0x01, 0x01, 0x50, 0x00]);
        // Stage two spills the n operands first and hands the runtime the same contiguous words.
        let c = translate(&code, &at(Stage::Two)).unwrap().c;
        let line = c.lines().find(|l| l.contains("evm_call(")).expect(&c);
        assert!(
            line.contains(&format!("u256_from_u32(&sp_[{}], 0x0u);", n - 1))
                && line.contains(&format!("evm_call({call:#04x}, &sp_[0], 8ull);")),
            "{c}"
        );
        let c = translate(&code, &one()).unwrap().c;
        assert!(
            c.contains(&format!(
                "evm_call({call:#04x}, &evm_stack[evm_sp-{n}], 8ull); evm_sp -= {};",
                n - 1
            )),
            "{c}"
        );
        assert!(c.contains("u256_add"), "the block continues: {c}");
        assert!(
            c.contains(&format!("evm_charge({});", 3 * n + 8)),
            "the pushes and the tail; the call is 0: {c}"
        );
        assert!(!c.contains("EVM_HALT_TRAP"), "{c}");
        assert!(!c.contains("EVM_HALT_STACK_UNDERFLOW"), "{c}");
        let entry = c.find("void evm_entry(void) {").unwrap();
        assert!(
            c[entry..].starts_with("void evm_entry(void) {\n    evm_calls_begin();\n"),
            "{c}"
        );
        assert_eq!(c.matches("evm_calls_begin").count(), 1, "{c}");
        let b = &evm2rv::blocks::blocks(&code)[0];
        assert_eq!(
            (b.min_depth, b.max_growth),
            (0, n),
            "{call:#04x}: n pushed, n popped, the flag pushed"
        );
    }
}

/// With the call's real arity, a call on a shallow stack underflows at the block head, where the
/// interpreter halted Trap(op) without touching the stack. Both are status 2 with gas_used =
/// gas_limit, which the observable contract (Task 4's ruling) accepts; the kind of the halt is
/// not public (Task 5, ruling 6).
#[test]
fn a_call_on_a_shallow_stack_underflows_at_the_block_head() {
    // PUSH1 1, CALL, STOP: the call needs 7, one is pushed: entry needs 6.
    let c = translate(&[0x60, 0x01, 0xf1, 0x00], &one()).unwrap().c;
    assert!(
        c.contains("if (evm_sp < 6u) { evm_halt(EVM_HALT_STACK_UNDERFLOW, 0); }"),
        "{c}"
    );
    assert!(
        c.contains("evm_call(0xf1, &evm_stack[evm_sp-7], 0ull);"),
        "{c}"
    );
    let c = translate(&[0x60, 0x01, 0xf1, 0x00], &at(Stage::Two))
        .unwrap()
        .c;
    assert!(
        c.contains("if (evm_sp < 6u) { evm_halt(EVM_HALT_STACK_UNDERFLOW, 0); }"),
        "{c}"
    );
    assert!(c.contains("evm_call(0xf1, &sp_[-6], 0ull);"), "{c}");
}

/// RETURNDATASIZE/RETURNDATACOPY: in a contract with no call-family opcode, which can never have
/// made a call, the interpreter's rule exactly (a constant 0, `evm_copy_returndata`), and no
/// `evm_calls_begin`; in one with a call, the buffer (`evm_rdata_len`,
/// `evm_copy_returndata_buf`).
#[test]
fn the_return_data_buffer_only_in_a_contract_that_calls() {
    assert_eq!(c_of(0x3d), "u256_from_u32(&evm_stack[evm_sp++], 0u);");
    assert_eq!(
        c_of_calls(0x3d),
        "u256_from_u32(&evm_stack[evm_sp++], evm_rdata_len);"
    );
    assert_eq!(
        c_of_calls(0x3e),
        format!(
            "evm_copy_returndata_buf({}, {}, {}); evm_sp -= 3;",
            sat(S1),
            sat(S2),
            sat(S3)
        )
    );
    for stage in STAGES {
        // RETURNDATASIZE, POP, STOP: no call, no buffer.
        let c = translate(&[0x3d, 0x50, 0x00], &at(stage)).unwrap().c;
        assert!(
            !c.contains("evm_rdata") && !c.contains("evm_calls_begin"),
            "{c}"
        );
        // ... and with a STATICCALL anywhere in the code, the buffer.
        let c = translate(&[0x3d, 0x50, 0x00, 0xfa], &at(stage)).unwrap().c;
        assert!(
            c.contains("evm_rdata_len") && c.contains("evm_calls_begin();"),
            "{c}"
        );
        // The ERC-20 makes no call: its C has none of it.
        let c = translate(&erc20_code(), &at(stage)).unwrap().c;
        assert!(
            !c.contains("evm_call(") && !c.contains("evm_calls_begin") && !c.contains("evm_rdata"),
            "{c}"
        );
    }
}

/// The block head: underflow, then overflow, then the static charge, each omitted when it cannot
/// fire.
#[test]
fn the_block_head_checks_the_stack_then_charges() {
    for stage in STAGES {
        // ADD, POP, STOP: needs 2, never grows.
        let c = translate(&[0x01, 0x50, 0x00], &at(stage)).unwrap().c;
        let under = c
            .find("if (evm_sp < 2u) { evm_halt(EVM_HALT_STACK_UNDERFLOW, 0); }")
            .expect(&c);
        let charge = c.find("evm_charge(5);").expect(&c);
        assert!(under < charge);
        assert!(!c.contains("EVM_HALT_STACK_OVERFLOW"), "{c}");
        // PUSH1 1, PUSH1 2, POP, POP, STOP: grows by 2 from any depth.
        let c = translate(&[0x60, 1, 0x60, 2, 0x50, 0x50, 0x00], &at(stage))
            .unwrap()
            .c;
        assert!(
            c.contains("if (evm_sp + 2u > STACK_LIMIT) { evm_halt(EVM_HALT_STACK_OVERFLOW, 0); }"),
            "{c}"
        );
        assert!(!c.contains("EVM_HALT_STACK_UNDERFLOW"), "{c}");
        // STOP alone: no checks, no charge.
        let c = translate(&[0x00], &at(stage)).unwrap().c;
        assert!(!c.contains("evm_charge"), "{c}");
    }
}

/// A dynamic JUMP/JUMPI goes through the one switch over the jumpdest set, after checking the
/// high limbs; a PUSHn-then-jump is resolved to a direct goto, or to a bad jump when the constant
/// is not a jumpdest.
#[test]
fn jumps_dynamic_and_static() {
    // 0: PUSH1 4, JUMP, INVALID, 4: JUMPDEST, STOP — a static jump; no switch is emitted.
    let c = translate(&[0x60, 0x04, 0x56, 0xfe, 0x5b, 0x00], &one())
        .unwrap()
        .c;
    assert!(c.contains("goto L_4;"), "{c}");
    assert!(c.contains("folded into the jump"), "{c}");
    assert!(!c.contains("switch"), "{c}");
    assert!(c.contains("L_4: "), "{c}");

    // A constant that is not a jumpdest (5 is STOP) or does not fit a u32.
    let c = translate(&[0x60, 0x05, 0x56, 0xfe, 0x5b, 0x00], &one())
        .unwrap()
        .c;
    assert!(c.contains("evm_halt(EVM_HALT_BAD_JUMP, 0);"), "{c}");
    let wide = [0x64, 0x01, 0, 0, 0, 0x06, 0x56, 0x5b, 0x00]; // PUSH5 0x0100000006
    let c = translate(&wide, &one()).unwrap().c;
    assert!(c.contains("evm_halt(EVM_HALT_BAD_JUMP, 0);"), "{c}");
    assert!(!c.contains("goto L_7;"), "{c}");
    // PUSH1 3, JUMP, 3: JUMPDEST, STOP resolves.
    let c = translate(&[0x60, 0x03, 0x56, 0x5b, 0x00], &one())
        .unwrap()
        .c;
    assert!(c.contains("goto L_3;"), "{c}");

    // A static JUMPI: the condition is the top word once the destination is folded away.
    let c = translate(&[0x60, 1, 0x60, 0x06, 0x57, 0x00, 0x5b, 0x00], &one())
        .unwrap()
        .c;
    assert!(
        c.contains("{ int c_ = !u256_is_zero(&evm_stack[evm_sp-1]); evm_sp--; if (c_) goto L_6; }"),
        "{c}"
    );

    // A dynamic JUMP (the destination from calldata): the switch, every jumpdest a case.
    // PUSH0, CALLDATALOAD, JUMP, 3: JUMPDEST, STOP, 5: JUMPDEST, STOP
    let c = translate(&[0x5f, 0x35, 0x56, 0x5b, 0x00, 0x5b, 0x00], &one())
        .unwrap()
        .c;
    assert!(c.contains("switch (jd) {"), "{c}");
    assert!(c.contains("case 3u: goto L_3;"), "{c}");
    assert!(c.contains("case 5u: goto L_5;"), "{c}");
    assert!(
        c.contains("default: evm_halt(EVM_HALT_BAD_JUMP, 0);"),
        "{c}"
    );
    assert_eq!(
        c_of(0x56),
        "{ const u256 *d_ = &evm_stack[evm_sp-1]; evm_sp--; if (!u256_hi_zero(d_)) evm_halt(EVM_HALT_BAD_JUMP, 0); jd = d_->l[0]; goto dispatch; }"
    );
    assert_eq!(
        c_of(0x57),
        "{ const u256 *d_ = &evm_stack[evm_sp-1]; int c_ = !u256_is_zero(&evm_stack[evm_sp-2]); evm_sp -= 2; if (c_) { if (!u256_hi_zero(d_)) evm_halt(EVM_HALT_BAD_JUMP, 0); jd = d_->l[0]; goto dispatch; } }"
    );

    // Stage two: every constant destination resolves (not only a push right before the jump),
    // and a dynamic one goes through the same switch with the same checks.
    let two = |code: &[u8]| translate(code, &at(Stage::Two)).unwrap().c;
    let c = two(&[0x60, 0x04, 0x56, 0xfe, 0x5b, 0x00]);
    assert!(c.contains("goto L_4;") && c.contains("L_4: "), "{c}");
    assert!(!c.contains("switch"), "{c}");
    let c = two(&[0x60, 0x05, 0x56, 0xfe, 0x5b, 0x00]);
    assert!(c.contains("evm_halt(EVM_HALT_BAD_JUMP, 0);"), "{c}");
    let c = two(&wide);
    assert!(
        c.contains("evm_halt(EVM_HALT_BAD_JUMP, 0);") && !c.contains("goto L_7;"),
        "{c}"
    );
    // PUSH1 6, PUSH1 1, POP, JUMP, 6: JUMPDEST, STOP — the destination was pushed two ops before
    // the jump, which stage one sends through the switch.
    let code = [0x60, 0x06, 0x60, 0x01, 0x50, 0x56, 0x5b, 0x00];
    let c = two(&code);
    assert!(c.contains("goto L_6;") && !c.contains("switch"), "{c}");
    assert!(translate(&code, &one()).unwrap().c.contains("switch"));
    // A constant condition and destination: no spill (nothing is left), a direct branch.
    let c = two(&[0x60, 1, 0x60, 0x06, 0x57, 0x00, 0x5b, 0x00]);
    assert!(c.contains("{ int c_ = 1; if (c_) goto L_6; }"), "{c}");
    let c = two(&[0x5f, 0x35, 0x56, 0x5b, 0x00, 0x5b, 0x00]);
    assert!(c.contains("switch (jd) {"), "{c}");
    assert!(
        c.contains("case 3u: goto L_3;") && c.contains("case 5u: goto L_5;"),
        "{c}"
    );
    assert!(
        c.contains("default: evm_halt(EVM_HALT_BAD_JUMP, 0);"),
        "{c}"
    );
    assert!(
        c.contains("const u256 *d_ = &r0; if (!u256_hi_zero(d_)) evm_halt(EVM_HALT_BAD_JUMP, 0); jd = d_->l[0]; goto dispatch; }"),
        "{c}"
    );
}

/// Running off the end is STOP; code over the cap halts OutOfBounds without burning the limit
/// (the interpreter's pre_halt reports gas_used 0).
#[test]
fn the_end_of_the_code_and_code_over_the_cap() {
    for stage in STAGES {
        let c = translate(&[0x60, 0x01], &at(stage)).unwrap().c;
        // `evm_entry` ends with the STOP; the code guard's constant follows it.
        assert!(
            c.contains("evm_halt(EVM_HALT_STOP, 0);\n}\n\n/* The code guard"),
            "{c}"
        );

        let big = vec![0x5b; MAX_CODE_BYTES + 1];
        let e = translate(&big, &at(stage)).unwrap();
        assert_eq!(e.blocks, 1);
        assert!(
            e.c.contains(
                "evm_halt_code = EVM_HALT_OUT_OF_BOUNDS; evm_halt_arg = 0; evm_rt_unwind();"
            ),
            "{}",
            e.c
        );
        assert!(!e.c.contains("evm_charge"), "{}", e.c);
    }
}

/// The ERC-20's C compiles clean for rv32im under -Wall -Wextra -Werror against evm-rt's headers,
/// and every label it defines is used (only jump targets and the entry are labelled).
#[test]
fn the_erc20_compiles_clean_for_rv32im() {
    for stage in STAGES {
        erc20_compiles_clean(stage);
    }
}

fn erc20_compiles_clean(stage: Stage) {
    let e = translate(&erc20_code(), &at(stage)).unwrap();
    assert_eq!(e.blocks, 74);
    let dir = root().join("evm2rv/target/emit-test");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join(format!("erc20-{stage:?}.c"));
    std::fs::write(&file, &e.c).unwrap();
    let clang = ["/opt/homebrew/opt/llvm/bin/clang", "clang"]
        .into_iter()
        .map(PathBuf::from)
        .chain(std::env::var_os("CLANG").map(PathBuf::from))
        .find(|c| {
            Command::new(c)
                .arg("--print-targets")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("riscv32"))
                .unwrap_or(false)
        })
        .expect("a clang with a riscv32 target (brew install llvm, or set CLANG)");
    let o = Command::new(clang)
        .args(C_FLAGS)
        .args(["-fsyntax-only", "-Wall", "-Wextra", "-Werror", "-I"])
        .arg(root().join("evm-rt"))
        .arg(&file)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}

/// Every one-opcode contract compiles clean for rv32im under -Wall -Wextra -Werror (Task 6: the
/// fuzzer's host build found a block head whose unbraced `if` was followed, on the next line, by
/// an op comment and its statement — clang's -Wmisleading-indentation — in a block with no static
/// charge, such as a lone `EXP`). Each byte, a PUSHn with its immediate, in one file.
#[test]
fn every_one_opcode_contract_compiles_clean_for_rv32im() {
    for stage in STAGES {
        one_opcode_contracts_compile_clean(stage);
    }
}

fn one_opcode_contracts_compile_clean(stage: Stage) {
    let mut all = String::new();
    for op in 0..=255u8 {
        let mut code = vec![op];
        if (0x60..=0x7f).contains(&op) {
            code.extend(std::iter::repeat_n(0x11, (op - 0x5f) as usize));
        }
        let c = translate(
            &code,
            &Options {
                chain_id: Some(1),
                stage,
            },
        )
        .unwrap()
        .c;
        let c = c
            .replace(
                "void evm_entry(void)",
                &format!("void evm_entry_{op}(void)"),
            )
            .replace(
                "*evm_code_digest(void)",
                &format!("*evm_code_digest_{op}(void)"),
            );
        if op == 0 {
            all.push_str(&c);
        } else {
            all.push_str(&c.replace("#include <stdint.h>\n#include \"evm_rt.h\"\n", ""));
        }
    }
    let dir = root().join("evm2rv/target/emit-test");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join(format!("one-opcode-{stage:?}.c"));
    std::fs::write(&file, &all).unwrap();
    let o = Command::new(riscv_clang())
        .args(C_FLAGS)
        .args(["-fsyntax-only", "-Wall", "-Wextra", "-Werror", "-I"])
        .arg(root().join("evm-rt"))
        .arg(&file)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}

/// A clang with a riscv32 target: Homebrew's, `clang`, or `$CLANG`.
fn riscv_clang() -> PathBuf {
    ["/opt/homebrew/opt/llvm/bin/clang", "clang"]
        .into_iter()
        .map(PathBuf::from)
        .chain(std::env::var_os("CLANG").map(PathBuf::from))
        .find(|c| {
            Command::new(c)
                .arg("--print-targets")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("riscv32"))
                .unwrap_or(false)
        })
        .expect("a clang with a riscv32 target (brew install llvm, or set CLANG)")
}

/// The shim's C flags are rand-guest's, flag for flag: `clang_flags` in rand-guest/src/build.rs
/// lists exactly these, in this order, then the path remap.
#[test]
fn the_shim_uses_rand_guests_c_flags() {
    let src = std::fs::read_to_string(root().join("rand-guest/src/build.rs")).unwrap();
    let body = &src[src
        .find("fn clang_flags")
        .expect("rand-guest's clang_flags")..];
    let body = &body[..body.find("\n}\n").unwrap()];
    let listed: Vec<&str> = body
        .lines()
        .filter_map(|l| l.trim().strip_prefix('"'))
        .filter_map(|l| l.strip_suffix("\".into(),"))
        .collect();
    // The generated build.rs passes `--no-default-config` itself, ahead of C_FLAGS
    // (evm2rv/src/shim.rs), so the command line is rand-guest's list flag for flag.
    let shim: Vec<&str> = std::iter::once("--no-default-config")
        .chain(C_FLAGS.iter().copied())
        .collect();
    assert_eq!(
        listed, shim,
        "rand-guest's clang_flags and the shim's command line"
    );
    // One clang pin: the shim's CLANG_VERSION is rand-guest's.
    assert!(
        src.contains(&format!(
            "pub const CLANG_VERSION: &str = \"{}\";",
            evm2rv::shim::CLANG_VERSION
        )),
        "evm2rv::shim::CLANG_VERSION must equal rand-guest's CLANG_VERSION"
    );
    assert!(body.contains("-ffile-prefix-map={}=/rand-circuits"));
    assert!(!C_FLAGS.iter().any(|f| f.contains("rv32imc")));
    let b = files("x", "../..").build_rs;
    for f in C_FLAGS {
        assert!(b.contains(&format!("{f:?},")), "build.rs lacks {f}");
    }
    assert!(b.contains("-ffile-prefix-map={}=/rand-circuits"));
    assert!(b.contains("const ROOT: &str = \"../..\";"));
}

#[test]
fn the_shim_crate() {
    let f = files("erc20-evm2rv", "../..");
    assert!(f.cargo_toml.contains("name = \"erc20-evm2rv\""));
    assert!(f.cargo_toml.contains(
        "evm-core = { path = \"../../guests-compiled/evm-core\", features = [\"ffi\"] }"
    ));
    assert!(f
        .cargo_toml
        .contains("guest-sdk = { path = \"../../guest-sdk\" }"));
    assert!(f.cargo_toml.contains("default = []\n"));
    assert!(f.cargo_toml.contains("emit-outcome = []"));
    // cc pinned exactly, with a lock carrying its exact dependencies; the build script neither
    // inherits rustflags into the C flags nor hides which clang it used.
    assert!(f.cargo_toml.contains("cc = \"=1.4.6\""), "{}", f.cargo_toml);
    for (name, version) in [
        ("cc", "1.4.6"),
        ("find-msvc-tools", "0.1.12"),
        ("shlex", "2.0.1"),
    ] {
        assert!(
            f.cargo_lock
                .contains(&format!("name = \"{name}\"\nversion = \"{version}\"\n")),
            "{}",
            f.cargo_lock
        );
    }
    assert!(f.cargo_lock.contains("name = \"erc20-evm2rv\""));
    assert!(f
        .cargo_lock
        .starts_with("# This file is automatically @generated by Cargo."));
    assert!(f.build_rs.contains(".inherit_rustflags(false)"));
    // The whole runtime, the precompiles included (the linker keeps only what a contract calls),
    // and rand-guest's guest.h for the SHA-256 coprocessor.
    for src in [
        "\"evm_rt.c\"",
        "\"u256.c\"",
        "\"evm_call.c\"",
        "\"precompiles.c\"",
        "\"evm_bn.c\"",
        "\"evm_secp256k1.c\"",
        "\"evm_bn254.c\"",
    ] {
        assert!(f.build_rs.contains(src), "{src}: {}", f.build_rs);
    }
    assert!(f.build_rs.contains(".include(root.join(\"rand-guest\"))"));
    assert!(f.build_rs.contains("cargo:warning=evm2rv: clang {first}"));
    // rand-guest's clang pin, with its override, and no clang configuration file.
    assert!(f
        .build_rs
        .contains("const CLANG_VERSION: &str = \"23.1.1\";"));
    assert_eq!(evm2rv::shim::CLANG_VERSION, "23.1.1");
    assert!(f.build_rs.contains("assert_pinned(&clang);"));
    assert!(f.build_rs.contains("RAND_GUEST_CLANG_UNPINNED"));
    assert!(f.build_rs.contains(".flag(\"--no-default-config\")"));
    // The code guard runs before the translated code.
    assert!(f.main_rs.contains("fn evm_code_digest() -> *const u32;"));
    assert!(f
        .main_rs
        .contains("if pre != 0 || !is_the_translated_code(code) {"));
    // The globals C writes are `static mut` on the Rust side.
    for g in [
        "evm_ret:",
        "evm_ret_len:",
        "evm_logs:",
        "evm_n_logs:",
        "evm_halt_arg:",
    ] {
        assert!(f.main_rs.contains(&format!("static mut {g}")), "{g}");
    }
    assert!(
        !f.main_rs.contains("\n    static evm_"),
        "every runtime static is mut"
    );
    assert!(f.main_rs.contains("run_call_with_executor"));
    assert!(f.main_rs.contains("evm_rt_enter(evm_entry)"));
    assert!(f.ld.contains("ORIGIN = 0x10000"));
    assert_eq!(crate_name("erc20.runtime"), "erc20-runtime");
    assert_eq!(crate_name("20x"), "evm2rv-20x");

    // Outside a checkout the crate is refused (rand-guest could not build it there).
    let tmp = std::env::temp_dir().join(format!("evm2rv-outside-{}", std::process::id()));
    let err = evm2rv::shim::write_crate(&tmp, "x", "").unwrap_err();
    assert!(
        err.to_string().contains("not inside a circuits checkout"),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// The CLI: writes the five files, takes stages 1 and 2 (and refuses any other), and refuses
/// CHAINID without --chain-id.
#[test]
fn the_cli() {
    let bin = env!("CARGO_BIN_EXE_evm2rv");
    let dir = root().join("evm2rv/target/emit-test/cli");
    let o = Command::new(bin)
        .arg(root().join("guests-compiled/evm/contracts/erc20.runtime.hex"))
        .arg("--out")
        .arg(&dir)
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(
        o.status.success(),
        "{s}{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(s.contains("1296 code bytes: 74 blocks"), "{s}");
    // Stage two is the default.
    assert!(s.contains("(stage 2)"), "{s}");
    assert!(std::fs::read_to_string(dir.join("contract.c"))
        .unwrap()
        .contains("(stage two)"));
    assert!(s.contains("no trapping opcodes present"), "{s}");
    for f in [
        "contract.c",
        "Cargo.toml",
        "Cargo.lock",
        "build.rs",
        "src/main.rs",
        "shim.ld",
    ] {
        assert!(dir.join(f).exists(), "{f}");
    }
    let toml = std::fs::read_to_string(dir.join("Cargo.toml")).unwrap();
    assert!(toml.contains("name = \"erc20-runtime\""), "{toml}");
    assert!(toml.contains("path = \"../../../../guest-sdk\""), "{toml}");

    for (stage, header) in [("1", "(stage one)"), ("2", "(stage two)")] {
        let o = Command::new(bin)
            .arg(root().join("guests-compiled/evm/contracts/erc20.runtime.hex"))
            .args(["--stage", stage, "--out"])
            .arg(&dir)
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let c = std::fs::read_to_string(dir.join("contract.c")).unwrap();
        assert!(c.contains(header), "--stage {stage}");
    }
    let o = Command::new(bin)
        .arg(root().join("guests-compiled/evm/contracts/erc20.runtime.hex"))
        .args(["--stage", "3"])
        .output()
        .unwrap();
    assert!(!o.status.success());

    let chainid = dir.join("chainid.hex");
    std::fs::write(&chainid, "4600").unwrap(); // CHAINID, STOP
    let o = Command::new(bin).arg(&chainid).output().unwrap();
    assert!(!o.status.success());
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("no --chain-id"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let o = Command::new(bin)
        .arg(&chainid)
        .args(["--chain-id", "5"])
        .output()
        .unwrap();
    assert!(o.status.success());

    // A trapping opcode is named in a warning: TIMESTAMP, STOP.
    let ts = dir.join("timestamp.hex");
    std::fs::write(&ts, "4200").unwrap();
    let o = Command::new(bin).arg(&ts).output().unwrap();
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(s.contains("pc 0x0000: TIMESTAMP (0x42) traps"), "{s}");
}

/// The input format is chosen by extension (fix round 1, item 5): `.hex` is hex text — all
/// whitespace stripped, an optional `0x`, anything else an error — and every other extension is
/// raw bytes, even when those bytes happen to be ASCII hex digits.
#[test]
fn the_cli_reads_hex_by_extension_and_raw_bytes_otherwise() {
    let bin = env!("CARGO_BIN_EXE_evm2rv");
    let dir = root().join("evm2rv/target/emit-test/input");
    std::fs::create_dir_all(&dir).unwrap();
    let run = |name: &str, content: &[u8]| {
        let f = dir.join(name);
        std::fs::write(&f, content).unwrap();
        let o = Command::new(bin).arg(&f).output().unwrap();
        (
            o.status.success(),
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        )
    };
    // Hex with a 0x prefix, spaces, tabs and newlines inside: PUSH1 1, POP, STOP.
    let (ok, out, err) = run("spaced.hex", b"0x60 01\n\t50\r\n00\n");
    assert!(ok, "{out}{err}");
    assert!(out.contains("4 code bytes"), "{out}");
    let (ok, out, _) = run("plain.hex", b"60015000");
    assert!(ok && out.contains("4 code bytes"), "{out}");
    // Not hex: an error, never a fallback to raw bytes.
    for (name, bad) in [
        ("letters.hex", &b"60zz00"[..]),
        ("odd.hex", b"600"),
        ("twoprefix.hex", b"0x0x6000"),
    ] {
        let (ok, out, err) = run(name, bad);
        assert!(!ok, "{name} should be refused: {out}");
        assert!(err.contains("hex"), "{name}: {err}");
    }
    // Any other extension is raw bytes: the text "6000" is four bytes of code, not two.
    let (ok, out, err) = run("ascii.bin", b"6000");
    assert!(ok, "{out}{err}");
    assert!(out.contains("4 code bytes"), "{out}");
    let (ok, out, _) = run("raw.bin", &[0x60, 0x01, 0x50, 0x00, 0x0a]);
    assert!(ok && out.contains("5 code bytes"), "{out}");
    let (ok, out, _) = run("noext", &[0x00]);
    assert!(ok && out.contains("1 code bytes"), "{out}");
}
