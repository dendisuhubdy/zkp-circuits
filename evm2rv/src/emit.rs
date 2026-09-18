//! Stage one: each basic block to C over `evm-rt`'s memory stack (the spec's §3).
//!
//! The whole contract becomes one function, `void evm_entry(void)`, with a label per block
//! (`L_<pc>`, the block's start pc in decimal) and one `switch` over the jumpdest set that every
//! dynamic `JUMP`/`JUMPI` reaches through `goto dispatch` — no computed gotos, no function
//! pointers (controller ruling 1). `evm_entry` never returns a value: every halt is `evm_halt`,
//! which unwinds to `evm_rt_enter`, and running off the end of the code is `STOP`.
//!
//! **The block head** (ruling 2) checks the stack once — `evm_sp < min_depth` is
//! `StackUnderflow`, `evm_sp + max_growth > 1024` is `StackOverflow` — and then charges the
//! block's static gas once (`OutOfGas`). The interpreter charges each opcode's gas before that
//! opcode's own stack check, so the *kind* of an exceptional halt can differ when a block would
//! fail two ways; nothing observable does, since every exceptional halt is status 2 with
//! `gas_used = gas_limit` (`evm_halt` zeroes the counter), and a status-2 digest binds no return
//! data, no logs and the pre-state root.
//!
//! **Offsets and lengths** go to the runtime as `u256_sat_u32` (ruling 6); `MSTORE8`'s value is
//! the unsaturated low limb. `GAS` pushes `evm_gas + gas_after` (ruling 4): the rest of the
//! block's static gas was taken at the head and has not been "spent" yet in the interpreter's
//! per-opcode accounting.
//!
//! **Traps.** The sixteen [`crate::blocks::TRAP_TERM`] opcodes and every byte the interpreter does
//! not implement are `evm_halt(EVM_HALT_TRAP, op)`.
//!
//! **The call family** (Task 5): `CALL`/`CALLCODE`/`DELEGATECALL`/`STATICCALL` are
//! `evm_call(op, &evm_stack[evm_sp-n], gas_after)`, n = 7 or 6, then `evm_sp -= n - 1`: the
//! runtime runs a precompile (addresses 1-9) and writes the success flag over the deepest operand,
//! and traps `Trap(op)` on any other target, as the interpreter traps on the whole family. Its
//! static gas is 0 (the runtime charges everything, and takes the rest of the block's static gas,
//! `gas_after`, into its all-but-one-64th); the block continues past it, and the head counts its
//! real arity — so a call on a shallow stack now underflows at the head where the interpreter
//! trapped, both status 2 with `gas_used = gas_limit` (ruling 6). The interpreter traps on every
//! call, so a translated contract that calls a precompile is a strict superset of it; one that
//! makes no call is emitted exactly as before. A contract with a call-family opcode starts with
//! `evm_calls_begin()` and reads `RETURNDATASIZE`/`RETURNDATACOPY` from the runtime's buffer; one
//! without keeps the interpreter's constant 0 and `evm_copy_returndata`.
//!
//! **Environment** (ruling 8): `ADDRESS`, `CALLER`, `CALLVALUE` read `evm_address`, `evm_caller`,
//! `evm_callvalue`, which the shim fills from the decoded `Env`; `ORIGIN` reads `evm_caller`;
//! `CHAINID` is the `--chain-id` constant, baked in here so the image hash binds it — and
//! translating code that contains `CHAINID` without one is an error ([`EmitError`]), never a
//! silent default. The nine block-context opcodes trap (they are in `TRAP_TERM`).
//!
//! **Code over `MAX_CODE_BYTES`** is one `Term::OutOfBounds` block, which halts `OutOfBounds`
//! with `gas_used = 0` — the interpreter's `pre_halt` spends nothing (ruling 3) — so it sets the
//! halt code and unwinds directly instead of calling `evm_halt`, which would burn the limit.

use std::fmt::Write as _;

use crate::blocks::{blocks, jumpdests, Block, Op, Term, CALL_FAMILY};

/// Which translation: stage one (this module, the memory stack) or stage two (register lifting,
/// [`crate::lift`]). Both run the same runtime calls with the same gas and produce the same
/// observable results; stage two keeps a block's intermediate words in C locals, and is the
/// default (Task 8, ruling 1: it passes every test stage one does, in fewer cycles).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Stage {
    One,
    #[default]
    Two,
}

/// What the emitter needs besides the code.
#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    /// The value `CHAINID` pushes. Required when the code contains `CHAINID`.
    pub chain_id: Option<u64>,
    /// The translation stage.
    pub stage: Stage,
}

/// Why a contract cannot be translated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmitError {
    /// The code contains `CHAINID` (first at `pc`) and no `--chain-id` was given. The constant is
    /// part of the translation — the image hash binds it — so there is no default.
    ChainIdRequired { pc: usize },
}

impl std::fmt::Display for EmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmitError::ChainIdRequired { pc } => write!(
                f,
                "the code contains CHAINID (pc {pc:#06x}) and no --chain-id was given; the chain id is baked into the translation, so there is no default"
            ),
        }
    }
}

impl std::error::Error for EmitError {}

/// A translated contract: the C, and the counts the CLI prints.
#[derive(Clone, Debug)]
pub struct Emitted {
    pub c: String,
    pub blocks: usize,
    /// Opcodes emitted.
    pub opcodes: usize,
    /// Stage two: the `u256` locals `evm_entry` declares (the most any block holds at once, and
    /// never more than [`crate::lift::MAX_LOCALS`]). 0 for stage one.
    pub locals: usize,
}

/// `&evm_stack[evm_sp-n]`, the n-th word from the top (1 is the top).
fn s(n: usize) -> String {
    format!("&evm_stack[evm_sp-{n}]")
}

/// `u256_sat_u32(&evm_stack[evm_sp-n])`: an offset or length operand.
fn sat(n: usize) -> String {
    format!("u256_sat_u32({})", s(n))
}

/// A `PUSHn` immediate as C that pushes it.
fn push_c(v: &[u8; 32]) -> String {
    let limbs: [u32; 8] = std::array::from_fn(|i| {
        let o = 32 - 4 * (i + 1);
        u32::from_be_bytes([v[o], v[o + 1], v[o + 2], v[o + 3]])
    });
    if limbs[1..].iter().all(|&l| l == 0) {
        format!("u256_from_u32(&evm_stack[evm_sp++], {:#x}u);", limbs[0])
    } else if limbs[2..].iter().all(|&l| l == 0) {
        let v = (limbs[1] as u64) << 32 | limbs[0] as u64;
        format!("u256_from_u64(&evm_stack[evm_sp++], {v:#x}ull);")
    } else {
        let l: Vec<String> = limbs.iter().map(|l| format!("{l:#x}u")).collect();
        format!(
            "{{ static const u256 k_ = {{{{{}}}}}; evm_stack[evm_sp++] = k_; }}",
            l.join(", ")
        )
    }
}

/// The C for one opcode, given the static gas of the ops after it in its block (`GAS` and the
/// call family need it) and whether the contract has a call-family opcode anywhere (`calls`: the
/// return-data opcodes read the runtime's buffer). Terminators halt or jump; `JUMP`/`JUMPI` here
/// are the dynamic form (`goto dispatch`) — the emitter resolves a `PUSHn`-then-jump pair
/// statically in [`translate`] instead.
///
/// An opcode this crate traps on (the sixteen [`crate::blocks::TRAP_TERM`] opcodes and every byte
/// the interpreter does not implement) is `evm_halt(EVM_HALT_TRAP, op)`.
pub fn op_c(op: &Op, gas_after: u64, opts: &Options, calls: bool) -> Result<String, EmitError> {
    let bin = |f: &str| format!("{f}({}, {}, {}); evm_sp--;", s(2), s(1), s(2));
    let o = op.opcode;
    Ok(match o {
        0x00 => "evm_halt(EVM_HALT_STOP, 0);".into(),
        // Two operands: `a` is the top, the result replaces the second word (the runtime's
        // result may alias any operand), `a op b` as the interpreter's `binary`.
        0x01 => bin("u256_add"),
        0x02 => bin("u256_mul"),
        0x03 => bin("u256_sub"),
        0x04 => bin("u256_div"),
        0x05 => bin("u256_sdiv"),
        0x06 => bin("u256_mod"),
        0x07 => bin("u256_smod"),
        0x08 | 0x09 => format!(
            "{}({}, {}, {}, {}); evm_sp -= 2;",
            if o == 0x08 { "u256_addmod" } else { "u256_mulmod" },
            s(3),
            s(1),
            s(2),
            s(3)
        ),
        // EXP: base is the top, the exponent second; the runtime charges 10 + 50/byte first.
        0x0a => format!("evm_exp({}, {}, {}); evm_sp--;", s(2), s(1), s(2)),
        // SIGNEXTEND, BYTE, SHL, SHR, SAR: the top is the index/shift, the value second, and the
        // runtime takes the value first.
        0x0b => format!("u256_signextend({}, {}, {}); evm_sp--;", s(2), s(2), s(1)),
        0x10 => bin("u256_lt"),
        0x11 => bin("u256_gt"),
        0x12 => bin("u256_slt"),
        0x13 => bin("u256_sgt"),
        0x14 => bin("u256_eq"),
        0x15 => format!("u256_iszero({}, {});", s(1), s(1)),
        0x16 => bin("u256_and"),
        0x17 => bin("u256_or"),
        0x18 => bin("u256_xor"),
        0x19 => format!("u256_not({}, {});", s(1), s(1)),
        0x1a => format!("u256_byte({}, {}, {}); evm_sp--;", s(2), s(2), s(1)),
        0x1b => format!("u256_shl({}, {}, {}); evm_sp--;", s(2), s(2), s(1)),
        0x1c => format!("u256_shr({}, {}, {}); evm_sp--;", s(2), s(2), s(1)),
        0x1d => format!("u256_sar({}, {}, {}); evm_sp--;", s(2), s(2), s(1)),
        // KECCAK256: offset on top, size second.
        0x20 => format!("evm_keccak({}, {}, {}); evm_sp--;", sat(1), sat(2), s(2)),
        0x30 => "evm_stack[evm_sp++] = evm_address;".into(),
        // ORIGIN is CALLER: one call, no relayer.
        0x32 | 0x33 => "evm_stack[evm_sp++] = evm_caller;".into(),
        0x34 => "evm_stack[evm_sp++] = evm_callvalue;".into(),
        0x35 => format!("evm_calldataload({}, {});", sat(1), s(1)),
        0x36 => "u256_from_u32(&evm_stack[evm_sp++], evm_calldata_len);".into(),
        // The copies: destination on top, then the source offset, then the length.
        0x37 => format!(
            "evm_copy_calldata({}, {}, {}); evm_sp -= 3;",
            sat(1),
            sat(2),
            sat(3)
        ),
        0x38 => "u256_from_u32(&evm_stack[evm_sp++], evm_code_len);".into(),
        0x39 => format!(
            "evm_copy_code({}, {}, {}); evm_sp -= 3;",
            sat(1),
            sat(2),
            sat(3)
        ),
        // Without a call-family opcode no call is ever made: the return data is always empty,
        // the interpreter's rule. With one, the runtime's buffer.
        0x3d if calls => "u256_from_u32(&evm_stack[evm_sp++], evm_rdata_len);".into(),
        0x3d => "u256_from_u32(&evm_stack[evm_sp++], 0u);".into(),
        0x3e => format!(
            "{}({}, {}, {}); evm_sp -= 3;",
            if calls {
                "evm_copy_returndata_buf"
            } else {
                "evm_copy_returndata"
            },
            sat(1),
            sat(2),
            sat(3)
        ),
        0x46 => match opts.chain_id {
            Some(id) => format!("u256_from_u64(&evm_stack[evm_sp++], {id:#x}ull);"),
            None => return Err(EmitError::ChainIdRequired { pc: op.pc }),
        },
        0x50 => "evm_sp--;".into(),
        0x51 => format!("evm_mload({}, {});", sat(1), s(1)),
        // MSTORE: offset on top, value second.
        0x52 => format!("evm_mstore({}, {}); evm_sp -= 2;", sat(1), s(2)),
        // MSTORE8's value is the unsaturated low limb: only its low byte is stored.
        0x53 => format!(
            "evm_mstore8({}, u256_low_u32({})); evm_sp -= 2;",
            sat(1),
            s(2)
        ),
        0x54 => format!("evm_storage_load({}, {});", s(1), s(1)),
        // SSTORE: slot on top, value second.
        0x55 => format!("evm_storage_store({}, {}); evm_sp -= 2;", s(1), s(2)),
        0x56 => "{ const u256 *d_ = &evm_stack[evm_sp-1]; evm_sp--; if (!u256_hi_zero(d_)) evm_halt(EVM_HALT_BAD_JUMP, 0); jd = d_->l[0]; goto dispatch; }".into(),
        // JUMPI: destination on top, condition second; the destination is checked only when the
        // branch is taken, as the interpreter checks it.
        0x57 => "{ const u256 *d_ = &evm_stack[evm_sp-1]; int c_ = !u256_is_zero(&evm_stack[evm_sp-2]); evm_sp -= 2; if (c_) { if (!u256_hi_zero(d_)) evm_halt(EVM_HALT_BAD_JUMP, 0); jd = d_->l[0]; goto dispatch; } }".into(),
        0x58 => format!("u256_from_u32(&evm_stack[evm_sp++], {:#x}u);", op.pc),
        0x59 => "u256_from_u32(&evm_stack[evm_sp++], evm_msize);".into(),
        0x5a => format!("u256_from_u64(&evm_stack[evm_sp++], evm_gas + {gas_after}ull);"),
        0x5b => String::new(),
        0x5f => "u256_from_u32(&evm_stack[evm_sp++], 0u);".into(),
        0x60..=0x7f => push_c(op.push.as_ref().expect("a PUSHn op carries its immediate")),
        0x80..=0x8f => {
            let n = (o - 0x7f) as usize;
            format!("evm_stack[evm_sp] = evm_stack[evm_sp-{n}]; evm_sp++;")
        }
        0x90..=0x9f => {
            let n = (o - 0x8f) as usize + 1;
            format!(
                "{{ u256 t_ = evm_stack[evm_sp-1]; evm_stack[evm_sp-1] = evm_stack[evm_sp-{n}]; evm_stack[evm_sp-{n}] = t_; }}"
            )
        }
        // LOGn: offset on top, size second, then the n topics, the deepest last-popped.
        0xa0..=0xa4 => {
            let n = (o - 0xa0) as usize;
            format!(
                "evm_log({n}, {}, {}, &evm_stack[evm_sp-{}]); evm_sp -= {};",
                sat(1),
                sat(2),
                2 + n,
                2 + n
            )
        }
        // The call family: the operands from the top down are gas, address, [value,] argsOffset,
        // argsLength, retOffset, retLength; the flag lands on the deepest.
        0xf1 | 0xf2 | 0xf4 | 0xfa => {
            let n = if matches!(o, 0xf1 | 0xf2) { 7 } else { 6 };
            format!(
                "evm_call({o:#04x}, &evm_stack[evm_sp-{n}], {gas_after}ull); evm_sp -= {};",
                n - 1
            )
        }
        0xf3 => format!("evm_return({}, {});", sat(1), sat(2)),
        0xfd => format!("evm_revert({}, {});", sat(1), sat(2)),
        0xfe => "evm_halt(EVM_HALT_INVALID, 0);".into(),
        _ => format!("evm_halt(EVM_HALT_TRAP, {o:#04x});"),
    })
}

/// The opcode's name, for the comment beside its C.
pub fn mnemonic(op: u8) -> String {
    let name = match op {
        0x00 => "STOP",
        0x01 => "ADD",
        0x02 => "MUL",
        0x03 => "SUB",
        0x04 => "DIV",
        0x05 => "SDIV",
        0x06 => "MOD",
        0x07 => "SMOD",
        0x08 => "ADDMOD",
        0x09 => "MULMOD",
        0x0a => "EXP",
        0x0b => "SIGNEXTEND",
        0x10 => "LT",
        0x11 => "GT",
        0x12 => "SLT",
        0x13 => "SGT",
        0x14 => "EQ",
        0x15 => "ISZERO",
        0x16 => "AND",
        0x17 => "OR",
        0x18 => "XOR",
        0x19 => "NOT",
        0x1a => "BYTE",
        0x1b => "SHL",
        0x1c => "SHR",
        0x1d => "SAR",
        0x20 => "KECCAK256",
        0x30 => "ADDRESS",
        0x31 => "BALANCE",
        0x32 => "ORIGIN",
        0x33 => "CALLER",
        0x34 => "CALLVALUE",
        0x35 => "CALLDATALOAD",
        0x36 => "CALLDATASIZE",
        0x37 => "CALLDATACOPY",
        0x38 => "CODESIZE",
        0x39 => "CODECOPY",
        0x3a => "GASPRICE",
        0x3b => "EXTCODESIZE",
        0x3c => "EXTCODECOPY",
        0x3d => "RETURNDATASIZE",
        0x3e => "RETURNDATACOPY",
        0x3f => "EXTCODEHASH",
        0x40 => "BLOCKHASH",
        0x41 => "COINBASE",
        0x42 => "TIMESTAMP",
        0x43 => "NUMBER",
        0x44 => "PREVRANDAO",
        0x45 => "GASLIMIT",
        0x46 => "CHAINID",
        0x47 => "SELFBALANCE",
        0x48 => "BASEFEE",
        0x50 => "POP",
        0x51 => "MLOAD",
        0x52 => "MSTORE",
        0x53 => "MSTORE8",
        0x54 => "SLOAD",
        0x55 => "SSTORE",
        0x56 => "JUMP",
        0x57 => "JUMPI",
        0x58 => "PC",
        0x59 => "MSIZE",
        0x5a => "GAS",
        0x5b => "JUMPDEST",
        0x5f => "PUSH0",
        0x60..=0x7f => return format!("PUSH{}", op - 0x5f),
        0x80..=0x8f => return format!("DUP{}", op - 0x7f),
        0x90..=0x9f => return format!("SWAP{}", op - 0x8f),
        0xa0..=0xa4 => return format!("LOG{}", op - 0xa0),
        0xf0 => "CREATE",
        0xf1 => "CALL",
        0xf2 => "CALLCODE",
        0xf3 => "RETURN",
        0xf4 => "DELEGATECALL",
        0xf5 => "CREATE2",
        0xfa => "STATICCALL",
        0xfd => "REVERT",
        0xfe => "INVALID",
        0xff => "SELFDESTRUCT",
        _ => return format!("UNDEFINED_{op:#04x}"),
    };
    name.into()
}

/// The comment beside an op: its pc and name, and a push's immediate.
pub(crate) fn comment(op: &Op) -> String {
    match &op.push {
        Some(v) => {
            let n = (op.opcode - 0x5f) as usize;
            format!(
                "/* {:#06x} {} 0x{} */",
                op.pc,
                mnemonic(op.opcode),
                hex::encode(&v[32 - n..])
            )
        }
        None => format!("/* {:#06x} {} */", op.pc, mnemonic(op.opcode)),
    }
}

/// A `PUSHn` immediate as a jump target: `Some(t)` when it fits a u32 (the only form the
/// interpreter can jump to), else `None` — a static bad jump.
fn static_target(v: &[u8; 32]) -> Option<usize> {
    if v[..28].iter().any(|&b| b != 0) {
        return None;
    }
    Some(u32::from_be_bytes([v[28], v[29], v[30], v[31]]) as usize)
}

/// The block head: the stack check and the static charge (`blocks.rs`'s numbers, the call
/// family at its real arity). The checks are braced: the next line starts with an op's comment,
/// which an unbraced `if` would make -Wmisleading-indentation's case. `after_checks` (stage two's
/// base pointer, or nothing) goes between the checks and the charge.
pub(crate) fn head_c(b: &Block, after_checks: &str) -> String {
    let mut h = format!(
        "/* [{:#06x}, {:#06x}) min_depth {}, max_growth {}, static gas {} */\n",
        b.start, b.end, b.min_depth, b.max_growth, b.static_gas,
    );
    if b.min_depth > 0 {
        let _ = writeln!(
            h,
            "    if (evm_sp < {}u) {{ evm_halt(EVM_HALT_STACK_UNDERFLOW, 0); }}",
            b.min_depth
        );
    }
    if b.max_growth > 0 {
        let _ = writeln!(
            h,
            "    if (evm_sp + {}u > STACK_LIMIT) {{ evm_halt(EVM_HALT_STACK_OVERFLOW, 0); }}",
            b.max_growth
        );
    }
    h.push_str(after_checks);
    if b.static_gas > 0 {
        let _ = writeln!(h, "    evm_charge({});", b.static_gas);
    }
    h
}

/// Translate `code` to the C of one `evm_entry`, at `opts.stage`.
pub fn translate(code: &[u8], opts: &Options) -> Result<Emitted, EmitError> {
    match opts.stage {
        Stage::One => translate_one(code, opts),
        Stage::Two => crate::lift::translate(code, opts),
    }
}

/// Stage one.
fn translate_one(code: &[u8], opts: &Options) -> Result<Emitted, EmitError> {
    let bs = blocks(code);
    let jd = jumpdests(code);
    let is_jd = |t: usize| jd.binary_search(&t).is_ok();

    // Each block's C without its label; a block is labelled only if something jumps to it, so the
    // C compiles clean under -Wall (an unreferenced label is a warning).
    let mut pieces: Vec<(usize, String)> = Vec::with_capacity(bs.len());
    let mut targets: Vec<usize> = vec![bs[0].start];
    let mut opcodes = 0usize;
    let mut dynamic_jumps = false;
    // A call-family opcode anywhere in the code (a data byte inside a push is not one).
    let calls = bs
        .iter()
        .any(|b| b.ops.iter().any(|o| CALL_FAMILY.contains(&o.opcode)));
    for b in &bs {
        let mut body = String::new();
        if b.term == Term::OutOfBounds {
            // The interpreter's pre_halt: nothing runs and nothing is spent (gas_used 0), so
            // the halt is recorded and unwound without `evm_halt`'s burn of the limit.
            body.push_str(
                "/* code over MAX_CODE_BYTES: the interpreter runs nothing */\n    evm_halt_code = EVM_HALT_OUT_OF_BOUNDS; evm_halt_arg = 0; evm_rt_unwind();\n",
            );
            pieces.push((b.start, body));
            continue;
        }
        body.push_str(&head_c(b, ""));
        for (i, op) in b.ops.iter().enumerate() {
            opcodes += 1;
            // `PUSHn t; JUMP` / `PUSHn t; JUMPI`: the destination is a constant, resolved here.
            // The push is folded into the jump — the word it would write is popped by the very
            // next op and never read — while the head's bounds still count it, so a push onto a
            // full stack overflows exactly as in the interpreter.
            let next_is_jump = b
                .ops
                .get(i + 1)
                .is_some_and(|n| matches!(n.opcode, 0x56 | 0x57));
            if op.push.is_some() && next_is_jump {
                let _ = writeln!(body, "    {} /* folded into the jump */", comment(op));
                continue;
            }
            let folded = i
                .checked_sub(1)
                .and_then(|j| b.ops[j].push.as_ref())
                .map(static_target);
            let c = match (op.opcode, folded) {
                (0x56, Some(t)) => match t.filter(|&t| is_jd(t)) {
                    Some(t) => {
                        targets.push(t);
                        format!("goto L_{t};")
                    }
                    None => "evm_halt(EVM_HALT_BAD_JUMP, 0);".into(),
                },
                // The condition is the top word now that the destination was never pushed.
                (0x57, Some(t)) => {
                    let taken = match t.filter(|&t| is_jd(t)) {
                        Some(t) => {
                            targets.push(t);
                            format!("goto L_{t};")
                        }
                        None => "evm_halt(EVM_HALT_BAD_JUMP, 0);".into(),
                    };
                    format!(
                        "{{ int c_ = !u256_is_zero(&evm_stack[evm_sp-1]); evm_sp--; if (c_) {taken} }}"
                    )
                }
                _ => {
                    if matches!(op.opcode, 0x56 | 0x57) {
                        dynamic_jumps = true;
                    }
                    op_c(op, op.gas_after, opts, calls)?
                }
            };
            if c.is_empty() {
                let _ = writeln!(body, "    {}", comment(op));
            } else {
                let _ = writeln!(body, "    {} {}", comment(op), c);
            }
        }
        pieces.push((b.start, body));
    }
    if dynamic_jumps {
        targets.extend_from_slice(&jd);
    }
    targets.sort_unstable();
    targets.dedup();

    let mut out = String::new();
    let _ = writeln!(
        out,
        "/* Generated by evm2rv (stage one) from {} bytes of EVM runtime bytecode: {} blocks, {} jumpdests{}.\n * Do not edit — re-run evm2rv. Built with evm-rt by the shim's build.rs. */",
        code.len(),
        bs.len(),
        jd.len(),
        match opts.chain_id {
            Some(id) => format!(", CHAINID {id}"),
            None => String::new(),
        }
    );
    out.push_str("#include <stdint.h>\n#include \"evm_rt.h\"\n\n");
    out.push_str("void evm_entry(void);\n\n");
    out.push_str("void evm_entry(void) {\n");
    if calls {
        out.push_str("    evm_calls_begin();\n");
    }
    if dynamic_jumps {
        out.push_str("    uint32_t jd = 0;\n");
    }
    let _ = writeln!(out, "    goto L_{};", bs[0].start);
    if dynamic_jumps {
        out.push_str("dispatch:\n    switch (jd) {\n");
        for t in &jd {
            let _ = writeln!(out, "    case {t}u: goto L_{t};");
        }
        out.push_str("    default: evm_halt(EVM_HALT_BAD_JUMP, 0);\n    }\n");
    }
    for (start, body) in &pieces {
        if targets.binary_search(start).is_ok() {
            let _ = write!(out, "L_{start}: {body}");
        } else {
            let _ = write!(out, "    {body}");
        }
    }
    out.push_str("    /* running off the end of the code */\n    evm_halt(EVM_HALT_STOP, 0);\n}\n");
    Ok(Emitted {
        c: out,
        blocks: bs.len(),
        opcodes,
        locals: 0,
    })
}
