//! Basic-block analysis: the interpreter's jumpdest rule, block splitting at every `JUMPDEST` and
//! after every terminator, per-block static gas (mirroring the interpreter's own `static_gas`
//! table byte for byte) and the stack bounds (`min_depth`/`max_growth`) a single comparison at
//! the block head checks instead of a check per opcode.
//!
//! **The trapping-opcode boundary** (binding ruling, amending the task brief). The interpreter
//! halts `Halt::Trap(op)` on every opcode outside its subset, unconditionally and without
//! touching the stack (`evm_core::interp::Interpreter::step`'s catch-all arm pops nothing before
//! returning the halt). `evm2rv` deliberately keeps trapping on:
//!
//! - the nine block-context opcodes ([`BLOCK_CTX_TRAPS`]) the interpreter has no public-segment
//!   binding for yet, and
//! - seven more of the cross-contract family ([`STORAGE_CREATE_TRAPS`]): `BALANCE`,
//!   `EXTCODESIZE`, `EXTCODECOPY`, `EXTCODEHASH`, `CREATE`, `CREATE2`, `SELFDESTRUCT`.
//!
//! Together these sixteen ([`TRAP_TERM`]) become [`Term::TrapOp`] and end the block.
//!
//! `CALL`/`CALLCODE`/`DELEGATECALL`/`STATICCALL` ([`CALL_FAMILY`]) are **not** block terminators
//! here: a precompile target is resolved by address at runtime (the runtime traps only on a
//! non-precompile target), so they are ordinary [`Op`]s with the standard EVM stack effect, and
//! the block continues past them.
//!
//! `CHAINID` and `ORIGIN` are likewise ordinary ops — a translation-time constant and `CALLER`,
//! respectively — even though the interpreter itself does not implement either (its static-gas
//! table charges both zero, which this crate's table mirrors exactly, byte for byte).
//!
//! [`warnings`] reports every occurrence (in code order, immediates correctly skipped) of any
//! opcode in [`WARN_SET`] — [`TRAP_TERM`]'s sixteen plus [`CALL_FAMILY`]'s four — as a
//! [`Warning::Trap`].
//!
//! **Code longer than [`MAX_CODE_BYTES`]** (EIP-170's cap) is a separate case from every opcode
//! above: `Interpreter::new` refuses it outright (`pre_halt = Halt::OutOfBounds`) before a single
//! opcode runs, so none of it is ever reachable. [`jumpdests`] returns the empty set, [`blocks`]
//! returns exactly one empty block terminated by [`Term::OutOfBounds`], and [`warnings`] returns
//! exactly one [`Warning::CodeTooLarge`] and nothing else for such an input.
//!
//! Each [`Op`] also carries [`Op::gas_after`]: the sum of [`static_gas`] over every op strictly
//! after it in its block, which `GAS` (Task 4's emitter) adds to the live gas counter to correct
//! for static gas being charged once, up front, at the block head rather than per opcode.

use evm_core::interp::MAX_CODE_BYTES;

/// One decoded instruction. `push` is `Some` only for `PUSH1..PUSH32` (`0x60..=0x7f`); `PUSH0`
/// carries no immediate, so — like every other opcode — it is `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Op {
    pub pc: usize,
    pub opcode: u8,
    pub push: Option<[u8; 32]>,
    /// The sum of [`static_gas`] over every op strictly after this one in the same block —
    /// what is still "owed" from the block's up-front charge, from this op's point of view.
    /// Static gas is never charged per opcode; it is charged once, at the block head, as
    /// `block.static_gas` (Task 4's emitted C decrements the whole block's charge from `evm_gas`
    /// before any of the block's ops run). So by the time a mid-block `GAS` executes, `gas_after`
    /// worth of gas has been deducted up front for ops that have not run yet. `GAS` (Task 4) must
    /// therefore push `evm_gas + gas_after`, not the raw counter, so the value it returns is the
    /// gas actually remaining *at this point in the original per-opcode accounting* rather than
    /// gas already debited for instructions still to come.
    pub gas_after: u64,
}

/// How a block ends. The terminating opcode, when one physically occupies a byte (everything but
/// [`Term::Fallthrough`]), is also the last entry of the block's `ops`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Term {
    /// The block did not end in a terminator opcode; it simply ran into the next block's
    /// `JUMPDEST` at this pc. Execution always falls straight through — the split exists only
    /// because a jump may land here, not because control flow does anything unusual.
    Fallthrough(usize),
    /// `JUMP`: the destination is a runtime value, resolved by the emitted jump switch.
    Jump,
    /// `JUMPI`: the fallthrough pc taken when the condition is false (the pc right after the
    /// `JUMPI` byte).
    JumpI(usize),
    /// `STOP`, or the block ran off the end of the code (the interpreter's rule: that is `STOP`
    /// too).
    Stop,
    Return,
    Revert,
    /// The `0xfe` opcode — the interpreter's one distinguished halt outside `Trap`.
    Invalid,
    /// One of [`TRAP_TERM`]'s sixteen opcodes: the interpreter halts on it unconditionally,
    /// before touching the stack, and so does the translation (`evm_halt(HALT_TRAP, op)`, Task
    /// 4). Also covers any opcode byte the interpreter does not implement at all and this crate
    /// has no other classification for (undefined bytes, the Cancun opcodes, …) — those trap
    /// exactly the same way, just without a name in [`WARN_SET`].
    TrapOp(u8),
    /// `code` is longer than [`MAX_CODE_BYTES`] (EIP-170's cap). The interpreter's
    /// `Interpreter::new` sets `pre_halt = Halt::OutOfBounds` for such code, and `run` executes
    /// nothing — none of the code is reachable. [`blocks`] mirrors that with exactly one block,
    /// at pc 0, containing no ops, terminated by this variant; Task 4's emitter turns it straight
    /// into `evm_halt` with the `OutOfBounds` halt code from `evm-rt`'s / `evm-core`'s `ffi.rs`
    /// halt table (`HALT_OUT_OF_BOUNDS`), the same code `Interpreter::run` itself would report.
    OutOfBounds,
}

/// One basic block: `[start, end)` of the code, its decoded ops, the sum of the interpreter's
/// static gas for those ops, and the stack bounds a single check at the block head enforces
/// (`entry_depth >= min_depth && entry_depth + max_growth <= 1024`, per the spec's §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub start: usize,
    pub end: usize,
    pub ops: Vec<Op>,
    pub static_gas: u64,
    /// The minimum stack depth the block may be entered with, or some path through it underflows.
    pub min_depth: usize,
    /// The most the stack grows above `min_depth` at any point in the block; `min_depth +
    /// max_growth` must not exceed 1024, or some path through it overflows.
    pub max_growth: usize,
    pub term: Term,
}

/// A translation-time warning [`warnings`] reports; something worth flagging to the caller
/// without refusing to translate the contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Warning {
    /// A [`WARN_SET`] opcode — one of [`TRAP_TERM`]'s sixteen or [`CALL_FAMILY`]'s four — present
    /// at `pc`.
    Trap { pc: usize, opcode: u8 },
    /// `code` is `len` bytes, longer than [`MAX_CODE_BYTES`] (EIP-170's cap). This is the *only*
    /// warning [`warnings`] reports for such an input: the interpreter's `Interpreter::new` sets
    /// `pre_halt = Halt::OutOfBounds` and runs nothing, so none of the code is ever reachable and
    /// a per-opcode [`Trap`](Warning::Trap) warning for bytes inside it would be misleading.
    CodeTooLarge { len: usize },
}

/// The nine block-context opcodes: no public-segment binding exists yet (plan's Global
/// Constraints), so the translator traps on them exactly as the interpreter does.
pub const BLOCK_CTX_TRAPS: [u8; 9] = [0x3a, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x47, 0x48];

/// `BALANCE`, `EXTCODESIZE`, `EXTCODECOPY`, `EXTCODEHASH`, `CREATE`, `CREATE2`, `SELFDESTRUCT` —
/// the rest of the cross-contract family that traps unconditionally, unlike [`CALL_FAMILY`],
/// which has an address to resolve at runtime.
pub const STORAGE_CREATE_TRAPS: [u8; 7] = [0x31, 0x3b, 0x3c, 0x3f, 0xf0, 0xf5, 0xff];

/// `CALL`, `CALLCODE`, `DELEGATECALL`, `STATICCALL` — resolved by address at runtime (a
/// precompile call succeeds; anything else is the runtime's own trap). Not block terminators:
/// ordinary [`Op`]s with the standard EVM stack effect.
pub const CALL_FAMILY: [u8; 4] = [0xf1, 0xf2, 0xf4, 0xfa];

/// The sixteen opcodes [`blocks`] turns into a [`Term::TrapOp`] block terminator:
/// [`BLOCK_CTX_TRAPS`] followed by [`STORAGE_CREATE_TRAPS`].
pub const TRAP_TERM: [u8; 16] = [
    0x3a, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x47, 0x48, // BLOCK_CTX_TRAPS
    0x31, 0x3b, 0x3c, 0x3f, 0xf0, 0xf5, 0xff, // STORAGE_CREATE_TRAPS
];

/// The twenty opcodes [`warnings`] reports: [`TRAP_TERM`] plus [`CALL_FAMILY`].
pub const WARN_SET: [u8; 20] = [
    0x3a, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x47, 0x48, // BLOCK_CTX_TRAPS
    0x31, 0x3b, 0x3c, 0x3f, 0xf0, 0xf5, 0xff, // STORAGE_CREATE_TRAPS
    0xf1, 0xf2, 0xf4, 0xfa, // CALL_FAMILY
];

/// The Shanghai static gas of `op`, mirroring `evm_core::interp::static_gas`'s table exactly —
/// same match, same arms, same constants — so this crate is not tied to the interpreter's `pub`
/// visibility for its own translation logic. `tests/blocks.rs`'s `static_gas_matches_interpreter`
/// asserts the two agree for every opcode byte, so any future drift in either table fails CI
/// rather than double- or under-charging a translated contract.
///
/// Opcodes whose cost is wholly dynamic (`EXP`, `KECCAK256`, `SSTORE`, `LOGn`) are charged inside
/// the runtime calls Task 4 emits and are zero here, as are the free ones (`STOP`, `RETURN`,
/// `REVERT`, `INVALID`), `CHAINID`/`ORIGIN` (the interpreter's table has no entry for either,
/// even though this translator implements both as ordinary ops), and every opcode this crate
/// traps on.
pub const fn static_gas(op: u8) -> u64 {
    const G_BASE: u64 = 2;
    const G_VERYLOW: u64 = 3;
    const G_LOW: u64 = 5;
    const G_MID: u64 = 8;
    const G_HIGH: u64 = 10;
    const G_JUMPDEST: u64 = 1;
    const G_SLOAD: u64 = 2_100;
    match op {
        0x5b => G_JUMPDEST,
        // base
        0x30 | 0x33 | 0x34 | 0x36 | 0x38 | 0x3d | 0x50 | 0x58 | 0x59 | 0x5a | 0x5f => G_BASE,
        // verylow: ADD/SUB, every comparison and bitwise opcode, CALLDATALOAD, MLOAD/MSTORE/
        // MSTORE8, the copies' base, PUSHn, DUPn, SWAPn
        0x01 | 0x03 | 0x10..=0x1d | 0x35 | 0x37 | 0x39 | 0x3e | 0x51..=0x53 | 0x60..=0x9f => {
            G_VERYLOW
        }
        // low
        0x02 | 0x04..=0x07 | 0x0b => G_LOW,
        // mid
        0x08 | 0x09 | 0x56 => G_MID,
        // high
        0x57 => G_HIGH,
        0x54 => G_SLOAD,
        _ => 0,
    }
}

/// The interpreter's rule (`evm_core::interp::scan_jumpdests`, reused rather than reimplemented —
/// the one thing this crate must never drift from): every `JUMPDEST` byte that is not inside a
/// `PUSHn`'s immediate, as a sorted list of positions. Code longer than [`MAX_CODE_BYTES`] is
/// **not** capped and rescanned: `Interpreter::new` refuses such code outright (`pre_halt =
/// Halt::OutOfBounds`, nothing executes), so none of it is ever reachable and this returns the
/// empty set — never a jumpdest list computed over a truncated prefix, which would misreport
/// positions that can never actually be jumped to.
pub fn jumpdests(code: &[u8]) -> Vec<usize> {
    if code.len() > MAX_CODE_BYTES {
        return Vec::new();
    }
    let mut bits = [0u32; MAX_CODE_BYTES / 32];
    evm_core::interp::scan_jumpdests(code, &mut bits);
    (0..code.len())
        .filter(|&i| (bits[i / 32] >> (i % 32)) & 1 == 1)
        .collect()
}

/// One decoded instruction at `pc`, and the pc of the next one. `PUSH1..PUSH32`'s immediate reads
/// past the end of `code` as zero, exactly as the interpreter reads it. `gas_after` is left `0`
/// here — it depends on the op's position within its whole block, which `decode` does not know —
/// and is filled in by [`blocks`] once a block's full `ops` vector exists.
fn decode(code: &[u8], pc: usize) -> (Op, usize) {
    let opcode = code[pc];
    if (0x60..=0x7f).contains(&opcode) {
        let n = (opcode - 0x5f) as usize;
        let mut b = [0u8; 32];
        for i in 0..n {
            b[32 - n + i] = code.get(pc + 1 + i).copied().unwrap_or(0);
        }
        (
            Op {
                pc,
                opcode,
                push: Some(b),
                gas_after: 0,
            },
            pc + 1 + n,
        )
    } else {
        (
            Op {
                pc,
                opcode,
                push: None,
                gas_after: 0,
            },
            pc + 1,
        )
    }
}

/// What an opcode does to control flow: whether [`blocks`] keeps decoding straight through it or
/// ends the block there.
enum Classify {
    Ordinary,
    Stop,
    Jump,
    JumpI,
    Return,
    Revert,
    Invalid,
    /// [`TRAP_TERM`]'s sixteen, or any opcode byte this crate does not otherwise classify — both
    /// become [`Term::TrapOp`], matching the interpreter's unconditional, stack-untouched halt.
    Trap,
}

fn classify(opcode: u8) -> Classify {
    match opcode {
        0x00 => Classify::Stop,
        0x56 => Classify::Jump,
        0x57 => Classify::JumpI,
        0xf3 => Classify::Return,
        0xfd => Classify::Revert,
        0xfe => Classify::Invalid,
        // arithmetic, comparison, bitwise, KECCAK256
        0x01..=0x0b | 0x10..=0x1d | 0x20 => Classify::Ordinary,
        // environment, including ORIGIN (= CALLER) and CHAINID (a translation-time constant) —
        // both ordinary here though the interpreter itself does not implement either
        0x30 | 0x32 | 0x33 | 0x34 | 0x35 | 0x36 | 0x37 | 0x38 | 0x39 | 0x3d | 0x3e | 0x46 => {
            Classify::Ordinary
        }
        // stack, memory, storage, PC/MSIZE/GAS/JUMPDEST (0x56/0x57 already matched above)
        0x50..=0x55 | 0x58 | 0x59 | 0x5a | 0x5b | 0x5f => Classify::Ordinary,
        // PUSH0..32 (0x5f already matched above), DUPn, SWAPn
        0x60..=0x9f => Classify::Ordinary,
        // LOG0..4
        0xa0..=0xa4 => Classify::Ordinary,
        // the call family — resolved by address at runtime, not a block terminator
        0xf1 | 0xf2 | 0xf4 | 0xfa => Classify::Ordinary,
        _ => Classify::Trap,
    }
}

/// The standard EVM stack effect of `op`: `(need, net)` — the minimum items that must already be
/// present, and the net change to the depth once the op has run. Every opcode this crate traps on
/// unconditionally (see [`Classify::Trap`]) is `(0, 0)`, matching the interpreter's catch-all,
/// which halts before touching the stack at all.
pub fn stack_effect(op: u8) -> (usize, i32) {
    match op {
        0x00 => (0, 0),                               // STOP
        0x01..=0x07 => (2, -1),                       // ADD..SMOD
        0x08 | 0x09 => (3, -2),                       // ADDMOD, MULMOD
        0x0a | 0x0b => (2, -1),                       // EXP, SIGNEXTEND
        0x10..=0x14 => (2, -1),                       // LT..EQ
        0x15 => (1, 0),                               // ISZERO
        0x16..=0x18 => (2, -1),                       // AND, OR, XOR
        0x19 => (1, 0),                               // NOT
        0x1a..=0x1d => (2, -1),                       // BYTE, SHL, SHR, SAR
        0x20 => (2, -1),                              // KECCAK256
        0x30 => (0, 1),                               // ADDRESS
        0x32 => (0, 1),                               // ORIGIN
        0x33 => (0, 1),                               // CALLER
        0x34 => (0, 1),                               // CALLVALUE
        0x35 => (1, 0),                               // CALLDATALOAD
        0x36 => (0, 1),                               // CALLDATASIZE
        0x37 => (3, -3),                              // CALLDATACOPY
        0x38 => (0, 1),                               // CODESIZE
        0x39 => (3, -3),                              // CODECOPY
        0x3d => (0, 1),                               // RETURNDATASIZE
        0x3e => (3, -3),                              // RETURNDATACOPY
        0x46 => (0, 1),                               // CHAINID
        0x50 => (1, -1),                              // POP
        0x51 => (1, 0),                               // MLOAD
        0x52 => (2, -2),                              // MSTORE
        0x53 => (2, -2),                              // MSTORE8
        0x54 => (1, 0),                               // SLOAD
        0x55 => (2, -2),                              // SSTORE
        0x56 => (1, -1),                              // JUMP
        0x57 => (2, -2),                              // JUMPI
        0x58 => (0, 1),                               // PC
        0x59 => (0, 1),                               // MSIZE
        0x5a => (0, 1),                               // GAS
        0x5b => (0, 0),                               // JUMPDEST
        0x5f => (0, 1),                               // PUSH0
        0x60..=0x7f => (0, 1),                        // PUSH1..32
        0x80..=0x8f => ((op - 0x7f) as usize, 1),     // DUPn: needs n, pushes a copy
        0x90..=0x9f => ((op - 0x8f) as usize + 1, 0), // SWAPn: needs n+1, no net change
        0xa0..=0xa4 => {
            let n = (op - 0xa0) as usize;
            (2 + n, -((2 + n) as i32)) // LOGn: offset, size, n topics — all consumed
        }
        0xf1 | 0xf2 => (7, -6), // CALL, CALLCODE: gas,addr,value,argsOff,argsLen,retOff,retLen -> ok
        0xf3 => (2, -2),        // RETURN
        0xf4 | 0xfa => (6, -5), // DELEGATECALL, STATICCALL: gas,addr,argsOff,argsLen,retOff,retLen -> ok
        0xfd => (2, -2),        // REVERT
        0xfe => (0, 0),         // INVALID
        _ => (0, 0),            // every trap
    }
}

/// `(min_depth, max_growth)` for a straight-line sequence of ops: the entry depth below which
/// some op in the sequence underflows, and the most the stack grows above that entry depth at any
/// point. `depth` tracks the running stack height relative to an assumed-zero entry; `min_depth`
/// is the largest shortfall any op's `need` would hit at that point, and `max_growth` is the
/// highest `depth` climbs.
pub fn stack_bounds(ops: &[Op]) -> (usize, usize) {
    let mut depth: i64 = 0;
    let mut min_depth: i64 = 0;
    let mut max_growth: i64 = 0;
    for op in ops {
        let (need, net) = stack_effect(op.opcode);
        let shortfall = need as i64 - depth;
        if shortfall > min_depth {
            min_depth = shortfall;
        }
        depth += net as i64;
        if depth > max_growth {
            max_growth = depth;
        }
    }
    (min_depth.max(0) as usize, max_growth.max(0) as usize)
}

/// Split `code` into basic blocks at every `JUMPDEST` and after every terminator (`JUMP`,
/// `JUMPI`, `STOP`, `RETURN`, `REVERT`, `INVALID`, or one of [`TRAP_TERM`]'s sixteen opcodes, or
/// any other opcode byte this crate does not implement). Falling off the end of the code is
/// `STOP`, as in the interpreter.
///
/// Code longer than [`MAX_CODE_BYTES`] is **not** capped and analysed as a truncated prefix:
/// `Interpreter::new` refuses it outright (`pre_halt = Halt::OutOfBounds`), so none of it ever
/// runs. This returns exactly one block — `[0, 0)`, no ops, `static_gas` 0, `min_depth` 0,
/// `max_growth` 0 — terminated by [`Term::OutOfBounds`], the closest analogue to "nothing
/// executes" a block list has.
pub fn blocks(code: &[u8]) -> Vec<Block> {
    if code.len() > MAX_CODE_BYTES {
        return vec![Block {
            start: 0,
            end: 0,
            ops: Vec::new(),
            static_gas: 0,
            min_depth: 0,
            max_growth: 0,
            term: Term::OutOfBounds,
        }];
    }

    if code.is_empty() {
        // An empty contract still needs somewhere for the emitter to enter and immediately
        // `STOP` — the interpreter's own rule for running off the end of the code.
        return vec![Block {
            start: 0,
            end: 0,
            ops: Vec::new(),
            static_gas: 0,
            min_depth: 0,
            max_growth: 0,
            term: Term::Stop,
        }];
    }

    let mut is_jumpdest = vec![false; code.len()];
    for i in jumpdests(code) {
        is_jumpdest[i] = true;
    }

    let mut out = Vec::new();
    let mut pc = 0usize;
    while pc < code.len() {
        let start = pc;
        let mut ops: Vec<Op> = Vec::new();
        let term = loop {
            if pc >= code.len() {
                break Term::Stop;
            }
            if pc != start && is_jumpdest[pc] {
                break Term::Fallthrough(pc);
            }
            let (op, next_pc) = decode(code, pc);
            let opcode = op.opcode;
            match classify(opcode) {
                Classify::Ordinary => {
                    ops.push(op);
                    pc = next_pc;
                    // straight-line: keep decoding within this block
                }
                Classify::Stop => {
                    ops.push(op);
                    pc = next_pc;
                    break Term::Stop;
                }
                Classify::Jump => {
                    ops.push(op);
                    pc = next_pc;
                    break Term::Jump;
                }
                Classify::JumpI => {
                    ops.push(op);
                    pc = next_pc;
                    break Term::JumpI(next_pc);
                }
                Classify::Return => {
                    ops.push(op);
                    pc = next_pc;
                    break Term::Return;
                }
                Classify::Revert => {
                    ops.push(op);
                    pc = next_pc;
                    break Term::Revert;
                }
                Classify::Invalid => {
                    ops.push(op);
                    pc = next_pc;
                    break Term::Invalid;
                }
                Classify::Trap => {
                    ops.push(op);
                    pc = next_pc;
                    break Term::TrapOp(opcode);
                }
            }
        };
        // A trailing `PUSHn` whose declared immediate runs past the actual code (legal — it
        // reads as zero-padded, exactly as the interpreter reads it) can leave `pc` past
        // `code.len()`; the block's `end` is clamped back to the code, same as every other
        // boundary this analysis reports.
        let end = pc.min(code.len());
        let static_gas_sum: u64 = ops.iter().map(|o| static_gas(o.opcode)).sum();
        let (min_depth, max_growth) = stack_bounds(&ops);
        // `gas_after`: walking the block backwards, each op's `gas_after` is the running suffix
        // sum *before* that op's own cost is folded in — i.e. the sum of `static_gas` over every
        // op strictly after it. The last op sees `gas_after == 0` (nothing after it); each op
        // before it accumulates the next op's `gas_after` plus that next op's own static gas,
        // which is exactly the invariant `tests/blocks.rs` checks.
        {
            let mut suffix = 0u64;
            for op in ops.iter_mut().rev() {
                op.gas_after = suffix;
                suffix += static_gas(op.opcode);
            }
        }
        out.push(Block {
            start,
            end,
            ops,
            static_gas: static_gas_sum,
            min_depth,
            max_growth,
            term,
        });
    }
    out
}

/// Every [`Warning`] `code` raises, in code order, with `PUSHn` immediates correctly skipped so a
/// push's data bytes are never misread as an opcode.
///
/// Code longer than [`MAX_CODE_BYTES`] is **not** capped and scanned for per-opcode warnings:
/// `Interpreter::new` refuses it outright and nothing in it ever runs, so this reports exactly one
/// [`Warning::CodeTooLarge`] and nothing else — never a [`Warning::Trap`] for bytes that can never
/// be reached.
pub fn warnings(code: &[u8]) -> Vec<Warning> {
    if code.len() > MAX_CODE_BYTES {
        return vec![Warning::CodeTooLarge { len: code.len() }];
    }
    let mut out = Vec::new();
    let mut pc = 0usize;
    while pc < code.len() {
        let (op, next_pc) = decode(code, pc);
        if WARN_SET.contains(&op.opcode) {
            out.push(Warning::Trap {
                pc: op.pc,
                opcode: op.opcode,
            });
        }
        pc = next_pc;
    }
    out
}
