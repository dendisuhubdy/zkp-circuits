//! **Test-only**: random EVM programs for the differential fuzzing (`tests/fuzz.rs`) — not part of
//! the translator. Every case is a function of its seed alone ([`case`]), so a failing case is
//! re-created from its seed and printed as bytecode hex.
//!
//! A program is a run of *segments* over a simulated stack, then an epilogue:
//!
//! * **straight** runs of random opcodes, each with its operands set up just before it — a fresh
//!   push of a value picked for the operand's role (an "interesting" 256-bit word, a memory offset
//!   near 0 or near `MAX_MEMORY_BYTES`, a length, a witnessed storage slot, a shift or byte index,
//!   a call target, …) or a `DUPn` of a result already on the stack, so results feed later ops;
//! * **loops** (a counter in memory or in a witnessed storage slot, 1–12 iterations, a
//!   stack-neutral body, the back edge static or dynamic);
//! * **forward branches** (`JUMPI` over a stack-neutral run), **dynamic forward jumps over dead
//!   bytes** (random bytes, call-family and `JUMPDEST` bytes included — which switches a contract
//!   into return-data buffer mode without ever executing a call), **guarded early exits**, and
//!   rare **stack-depth stress** (a loop that overflows the 1024-entry stack, an op on too shallow
//!   a stack);
//! * an **epilogue** that stores the top of the stack to memory and ends in `RETURN`, `REVERT`,
//!   `STOP`, running off the end (sometimes inside a truncated `PUSHn`), `INVALID`, a trapping
//!   byte, a static or dynamic bad jump, or a call to a non-precompile.
//!
//! The opcode of each straight-run step is drawn uniformly from [`OPS`] — every opcode the
//! translation implements, so each is executed many times over a corpus. Faults (out-of-bounds
//! memory, a missing witness, a trap) are rare per step, so most programs run to their epilogue.
//!
//! `CHAINID` and `ORIGIN` are generated like any other opcode. The interpreter traps on both, so
//! [`Case::interp_code`] is the same program with each replaced by `CALLER` (same gas, same stack
//! effect); when the code contains `CHAINID`, the caller is a u64 and the translation's
//! `--chain-id` is that value, so the two programs compute the same words (`tests/fuzz.rs` runs
//! the translation of [`Case::code`] over an input vector carrying `interp_code`, so `CODECOPY`
//! and the code hash agree too).

use evm_core::u256::U256;

use crate::blocks::stack_effect;

/// splitmix64: small, fast, and good enough to spread a seed over a program.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed ^ 0x9e37_79b9_7f4a_7c15)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    /// Uniform in `0..n` (n > 0).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
    /// Uniform in `lo..=hi`.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.below(hi - lo + 1)
    }
    /// True with probability `permille` / 1000.
    pub fn chance(&mut self, permille: u64) -> bool {
        self.below(1000) < permille
    }
    pub fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[self.below(xs.len() as u64) as usize]
    }
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u64() as u8).collect()
    }
    pub fn word(&mut self) -> U256 {
        U256(std::array::from_fn(|_| self.next_u64() as u32))
    }
}

/// How the fuzz harness sets the gas limit: the full limit, or a cut below what the full run used
/// (resolved after running the interpreter once at the full limit).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gas {
    Full,
    /// `used * n / 65536`.
    Fraction(u32),
    /// `used - k` (saturating): one short of the exact gas, and the exact gas itself.
    Minus(u64),
}

/// One fuzz case: the program and everything its input vector carries.
#[derive(Clone, Debug)]
pub struct Case {
    pub seed: u64,
    /// The code the translation is made from.
    pub code: Vec<u8>,
    pub calldata: Vec<u8>,
    pub address: U256,
    pub caller: U256,
    pub callvalue: U256,
    /// The pre-state: `(slot, value)`, value nonzero.
    pub storage: Vec<(U256, U256)>,
    /// The slots a witness is supplied for.
    pub touched: Vec<U256>,
    /// The generous limit the case runs under first.
    pub gas_limit: u64,
    pub gas: Gas,
    /// `--chain-id`: `Some(caller)` when the code contains `CHAINID`.
    pub chain_id: Option<u64>,
    /// What the generator put in, for the report's tallies.
    pub tags: Tags,
}

/// What a case contains, as the generator built it.
#[derive(Clone, Copy, Debug, Default)]
pub struct Tags {
    pub loops: u32,
    /// A call-family opcode somewhere (executed or dead).
    pub call_byte: bool,
    /// A call-family opcode in dead code only.
    pub dead_call_byte: bool,
    /// A call-family step (the harness learns whether one reached a precompile).
    pub call_step: bool,
    /// The epilogue is a dynamic jump to a non-jumpdest.
    pub dynamic_bad_jump: bool,
}

impl Case {
    /// The code the interpreter runs: [`Case::code`] with every `CHAINID` and `ORIGIN` opcode
    /// (not a push's data) replaced by `CALLER`, which the interpreter implements at the same
    /// gas and stack effect. With `chain_id == caller` the two push the same word.
    pub fn interp_code(&self) -> Vec<u8> {
        let mut c = self.code.clone();
        let mut i = 0;
        while i < c.len() {
            let op = c[i];
            if op == 0x46 || op == 0x32 {
                c[i] = 0x33;
            }
            i += if (0x60..=0x7f).contains(&op) {
                1 + (op - 0x5f) as usize
            } else {
                1
            };
        }
        c
    }
}

/// Every opcode byte the translation implements (none of these is `Trap(op)` in the
/// translation): what the straight runs draw from, and what the fuzz report requires to be
/// executed at least 100 times. `JUMP`/`JUMPI` are generated by the control-flow segments, the
/// halts (`STOP`, `RETURN`, `REVERT`, `INVALID`) by the epilogue and the early exits.
pub const OPS: &[u8] = &[
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, // arithmetic
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
    0x1d, // cmp, bits
    0x20, // KECCAK256
    0x30, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3d, 0x3e, 0x46, // environment
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x58, 0x59, 0x5a, 0x5b,
    0x5f, // stack, memory, storage
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, // LOGn
    0xf1, 0xf2, 0xf4, 0xfa, // the call family
];

/// The whole set the report counts: [`OPS`] plus the control flow and the halts.
pub fn non_trapping() -> Vec<u8> {
    let mut v: Vec<u8> = OPS.to_vec();
    v.extend_from_slice(&[0x00, 0x56, 0x57, 0xf3, 0xfd, 0xfe]);
    v.sort_unstable();
    v
}

/// What an operand is for, which decides the values it gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Val,
    /// A memory offset.
    Off,
    /// A memory length.
    Len,
    /// An offset into calldata or code.
    Src,
    Slot,
    /// SIGNEXTEND's and BYTE's index.
    Idx,
    Shift,
    Exp,
    CallGas,
    Target,
    CallValue,
    /// RETURNDATACOPY's source offset and length.
    RdSrc,
    RdLen,
    /// RETURN/REVERT's length.
    RetLen,
}

/// The roles of `op`'s operands, the top first.
fn roles(op: u8) -> Vec<Role> {
    use Role::*;
    match op {
        0x0a => vec![Val, Exp],
        0x0b | 0x1a => vec![Idx, Val],
        0x1b..=0x1d => vec![Shift, Val],
        0x20 => vec![Off, Len],
        0x35 => vec![Src],
        0x37 | 0x39 => vec![Off, Src, Len],
        0x3e => vec![Off, RdSrc, RdLen],
        0x51 => vec![Off],
        0x52 | 0x53 => vec![Off, Val],
        0x54 => vec![Slot],
        0x55 => vec![Slot, Val],
        0xa0..=0xa4 => {
            let mut r = vec![Off, Len];
            r.extend(std::iter::repeat_n(Val, (op - 0xa0) as usize));
            r
        }
        0xf1 | 0xf2 => vec![CallGas, Target, CallValue, Off, Len, Off, Len],
        0xf4 | 0xfa => vec![CallGas, Target, Off, Len, Off, Len],
        0xf3 | 0xfd => vec![Off, RetLen],
        _ => {
            let (need, _) = stack_effect(op);
            vec![Val; need]
        }
    }
}

fn pow2(k: u32) -> U256 {
    let mut v = U256::ZERO;
    if k < 256 {
        v.0[(k / 32) as usize] = 1 << (k % 32);
    }
    v
}

fn neg(v: &U256) -> U256 {
    U256::ZERO.sub(v)
}

/// A 256-bit word from the edges of every operation: zero, one, small numbers, the powers of two
/// and their neighbours at every limb boundary, the signed extremes, all-ones, and random words
/// of random byte width.
fn interesting(r: &mut Rng) -> U256 {
    match r.below(12) {
        0 => U256::ZERO,
        1 => U256::from_u32(r.range(1, 3) as u32),
        2 => U256::from_u32(r.below(300) as u32),
        3 => {
            let k = r.pick(&[
                7u32, 8, 15, 16, 31, 32, 63, 64, 127, 128, 159, 160, 191, 192, 223, 224, 254, 255,
            ]);
            match r.below(3) {
                0 => pow2(k),
                1 => pow2(k).sub(&U256::ONE),
                _ => pow2(k).add(&U256::ONE),
            }
        }
        4 => neg(&U256::from_u32(r.range(1, 3) as u32)),
        5 => pow2(255),
        6 => pow2(255).sub(&U256::ONE),
        7 => U256::MAX,
        8 => neg(&U256::from_u32(r.below(300) as u32)),
        _ => {
            // Random, of a random byte width (so EXP's gas and SIGNEXTEND's sign vary).
            let w = r.range(1, 32) as usize;
            let b = r.bytes(w);
            U256::from_be_slice(&b)
        }
    }
}

const MEM: u64 = 65_536;

/// One program under construction: the bytes, the labels, and the simulated stack depth.
struct Gen<'a> {
    r: &'a mut Rng,
    code: Vec<u8>,
    labels: Vec<Option<usize>>,
    fixups: Vec<(usize, usize)>,
    depth: usize,
    slots: Vec<U256>,
    loop_slot: Option<U256>,
    tags: Tags,
    calldata_len: usize,
    /// A fault-prone program: edge operands that halt (memory past the end, a missing witness, a
    /// nonzero RETURNDATACOPY before any call), mid-run calls, stack stress and the halting
    /// epilogues. The rest (most of the corpus) keep to operands that do not halt, so their
    /// results reach the output.
    faulty: bool,
    /// Inside a loop body, and the LOGs emitted so far: a clean program stays under the
    /// interpreter's eight logs.
    in_loop: bool,
    logs: u32,
}

/// Where the running accumulator of observed results lives in memory (see [`Gen::observe`]).
const ACC: u64 = 0x100;

impl Gen<'_> {
    fn op(&mut self, b: u8) {
        self.code.push(b);
    }
    /// The shortest `PUSHn` of `v` (`PUSH0` for zero half the time), or a random wider one.
    fn push(&mut self, v: &U256) {
        let be = v.to_be_bytes();
        let lead = be.iter().take_while(|&&b| b == 0).count();
        let mut n = 32 - lead;
        if n == 0 && self.r.chance(500) {
            self.op(0x5f);
            self.depth += 1;
            return;
        }
        n = n.max(1);
        if n < 32 && self.r.chance(150) {
            n = self.r.range(n as u64, 32) as usize;
        }
        self.op(0x5f + n as u8);
        self.code.extend_from_slice(&be[32 - n..]);
        self.depth += 1;
    }
    fn push_u(&mut self, v: u64) {
        self.push(&U256::from_u64(v));
    }
    fn label(&mut self) -> usize {
        self.labels.push(None);
        self.labels.len() - 1
    }
    /// `JUMPDEST` here, and `l` names it.
    fn bind(&mut self, l: usize) {
        self.labels[l] = Some(self.code.len());
        self.op(0x5b);
    }
    /// `PUSH2 l` (patched once every label is bound).
    fn push_label(&mut self, l: usize) {
        self.op(0x61);
        self.fixups.push((self.code.len(), l));
        self.code.extend_from_slice(&[0, 0]);
        self.depth += 1;
    }
    fn pop_to(&mut self, d: usize) {
        while self.depth > d {
            self.op(0x50);
            self.depth -= 1;
        }
        while self.depth < d {
            let v = interesting(self.r);
            self.push(&v);
        }
    }

    /// A value for an operand in `role`.
    fn value(&mut self, role: Role) -> U256 {
        if !self.faulty {
            // In bounds for any length below: offsets under 8 KiB, lengths up to 4 KiB.
            let r = &mut *self.r;
            match role {
                Role::Off => {
                    return U256::from_u32(if r.chance(900) {
                        r.below(512)
                    } else {
                        r.below(8192)
                    } as u32)
                }
                Role::Len => {
                    return U256::from_u32(match r.below(10) {
                        0..=3 => 0,
                        4..=8 => r.range(1, 64),
                        _ => r.range(65, 4096),
                    } as u32)
                }
                Role::RetLen => return U256::from_u32(r.range(0, 1024) as u32),
                Role::Slot if !self.slots.is_empty() => return r.pick(&self.slots),
                Role::RdLen => return U256::ZERO,
                _ => {}
            }
        }
        let r = &mut *self.r;
        match role {
            Role::Val | Role::Exp => interesting(r),
            Role::Off => match r.below(1000) {
                0..=879 => U256::from_u32(r.below(512) as u32),
                880..=969 => U256::from_u32(r.below(8192) as u32),
                970..=991 => U256::from_u64(MEM - r.range(0, 1200)),
                992..=996 => U256::from_u64(MEM + r.below(40)),
                _ => r.pick(&[
                    pow2(32),
                    U256::MAX,
                    pow2(64).sub(&U256::ONE),
                    pow2(32).sub(&U256::ONE),
                ]),
            },
            Role::Len => match r.below(1000) {
                0..=399 => U256::ZERO,
                400..=799 => U256::from_u32(r.range(1, 64) as u32),
                800..=949 => U256::from_u32(r.range(65, 1100) as u32),
                950..=997 => U256::from_u32(r.range(1100, 4096) as u32),
                _ => r.pick(&[
                    U256::from_u64(MEM),
                    U256::from_u64(MEM + 1),
                    pow2(32),
                    U256::MAX,
                ]),
            },
            Role::RetLen => match r.below(1000) {
                0..=199 => U256::ZERO,
                200..=899 => U256::from_u32(r.range(1, 256) as u32),
                900..=989 => U256::from_u32(r.range(257, 1024) as u32),
                _ => U256::from_u32(r.range(1025, 1100) as u32),
            },
            Role::Src => match r.below(10) {
                0..=5 => U256::from_u32(r.below(64) as u32),
                6 | 7 => {
                    U256::from_u64((self.calldata_len as u64 + 32).saturating_sub(r.below(64)))
                }
                8 => U256::from_u32(r.below(30_000) as u32),
                _ => r.pick(&[pow2(32), U256::MAX, pow2(32).sub(&U256::ONE), pow2(64)]),
            },
            Role::Slot => {
                if !self.slots.is_empty() && !r.chance(8) {
                    r.pick(&self.slots)
                } else {
                    // A slot with no witness: NoWitness (the harness never witnesses these).
                    U256::from_u64(0xdead_0000 + r.below(16))
                }
            }
            Role::Idx => match r.below(10) {
                0..=7 => U256::from_u32(r.below(34) as u32),
                _ => interesting(r),
            },
            Role::Shift => match r.below(10) {
                0..=6 => U256::from_u32(r.below(260) as u32),
                7 => U256::from_u32(r.pick(&[0u32, 1, 255, 256, 257])),
                _ => interesting(r),
            },
            Role::CallGas => match r.below(6) {
                0 => U256::ZERO,
                1 => U256::from_u32(r.below(200) as u32),
                2 => U256::from_u32(r.below(100_000) as u32),
                3 => U256::MAX,
                4 => pow2(64),
                _ => interesting(r),
            },
            Role::Target => match r.below(20) {
                // A non-precompile: the interpreter's trap, which the translation keeps.
                0..=4 => U256::ZERO,
                5..=7 => U256::from_u32(r.range(10, 300) as u32),
                8..=10 => {
                    let mut a = r.word();
                    for l in &mut a.0[5..] {
                        *l = 0;
                    }
                    a
                }
                // 2^160 + k: the bits above 160 are ignored, so k in 1..9 is a precompile.
                11 => pow2(160).add(&U256::from_u32(r.range(1, 9) as u32)),
                // A precompile.
                _ => U256::from_u32(r.range(1, 9) as u32),
            },
            Role::CallValue => {
                if r.chance(850) {
                    U256::ZERO
                } else {
                    interesting(r)
                }
            }
            Role::RdSrc => match r.below(4) {
                0 => U256::ZERO,
                1 => U256::from_u32(r.below(100) as u32),
                2 => U256::from_u64(0xffff_ffff),
                _ => U256::MAX,
            },
            Role::RdLen => {
                if r.chance(970) {
                    U256::ZERO
                } else {
                    U256::from_u32(r.range(1, 64) as u32)
                }
            }
        }
    }

    /// Set up `op`'s operands (the deepest pushed first) and emit it.
    fn step(&mut self, op: u8) {
        let rs = roles(op);
        let (need, net) = stack_effect(op);
        // DUPn/SWAPn read deep: fill the stack so they do not underflow (a rare deliberate
        // underflow is stress's job).
        if rs.is_empty() || matches!(op, 0x80..=0x9f) {
            while self.depth < need {
                let v = interesting(self.r);
                self.push(&v);
            }
        } else {
            for &role in rs.iter().rev() {
                // A `Val` operand is sometimes a result already on the stack.
                if role == Role::Val && self.depth > 0 && self.r.chance(350) {
                    let k = self.r.range(1, self.depth.min(16) as u64) as u8;
                    self.op(0x7f + k);
                    self.depth += 1;
                } else {
                    let v = self.value(role);
                    self.push(&v);
                }
            }
        }
        if (0x60..=0x7f).contains(&op) {
            let n = (op - 0x5f) as usize;
            let b = if self.r.chance(100) {
                // A JUMPDEST byte inside the push data: not a jump target.
                vec![0x5b; n]
            } else {
                self.r.bytes(n)
            };
            self.op(op);
            self.code.extend_from_slice(&b);
        } else {
            self.op(op);
        }
        if matches!(op, 0xf1 | 0xf2 | 0xf4 | 0xfa) {
            self.tags.call_byte = true;
            self.tags.call_step = true;
        }
        self.depth = (self.depth as i64 + net as i64).max(0) as usize;
    }

    /// `n` straight-run steps.
    fn straight(&mut self, n: usize) {
        for _ in 0..n {
            let mut op = self.r.pick(OPS);
            // The call family is terminal more often than not (a non-precompile traps): keep it
            // rare enough that most programs reach their epilogue.
            if matches!(op, 0xf1 | 0xf2 | 0xf4 | 0xfa) && !(self.faulty && self.r.chance(150)) {
                op = self.r.pick(&[0x01u8, 0x16, 0x52, 0x80]);
            }
            if matches!(op, 0xa0..=0xa4) && !self.faulty {
                if self.in_loop || self.logs >= 6 {
                    op = 0x59;
                } else {
                    self.logs += 1;
                }
            }
            // Clean programs keep SLOAD/SSTORE only where a witness exists.
            if !self.faulty && self.slots.is_empty() && matches!(op, 0x54 | 0x55) {
                op = 0x5a;
            }
            self.step(op);
            let (_, net) = stack_effect(op);
            if net >= 0 && self.depth > 0 && !matches!(op, 0x5b | 0x90..=0x9f) && self.r.chance(700)
            {
                self.observe();
            }
            if self.depth > 48 {
                let keep = self.r.range(4, 16) as usize;
                self.pop_to(keep);
            }
        }
    }

    /// A stack-neutral straight run.
    fn neutral(&mut self, n: usize) {
        let d = self.depth;
        self.straight(n);
        self.pop_to(d);
    }

    /// A loop of `iters` iterations over a neutral body, the counter in memory or in storage.
    fn looped(&mut self) {
        self.tags.loops += 1;
        let iters = self.r.range(1, 12);
        let body = self.r.range(2, 10) as usize;
        let in_storage = self.loop_slot.is_some() && self.r.chance(300);
        let cnt = self.r.range(0x3000, 0x3100) & !31;
        // counter = iters
        self.push_u(iters);
        if in_storage {
            let s = self.loop_slot.unwrap();
            self.push(&s);
            self.op(0x55);
        } else {
            self.push_u(cnt);
            self.op(0x52);
        }
        self.depth -= 2;
        let top = self.label();
        self.bind(top);
        self.in_loop = true;
        self.neutral(body);
        self.in_loop = false;
        // counter - 1, stored, and the copy tested by JUMPI
        self.push_u(1);
        if in_storage {
            let s = self.loop_slot.unwrap();
            self.push(&s);
            self.op(0x54);
        } else {
            self.push_u(cnt);
            self.op(0x51);
        }
        self.op(0x03); // SUB: counter - 1
        self.depth -= 1;
        self.op(0x80); // DUP1
        self.depth += 1;
        if in_storage {
            let s = self.loop_slot.unwrap();
            self.push(&s);
            self.op(0x55);
        } else {
            self.push_u(cnt);
            self.op(0x52);
        }
        self.depth -= 2;
        self.push_label(top);
        if self.r.chance(300) {
            // A dynamic back edge: the push is not folded into the JUMPI.
            self.push_u(0);
            self.op(0x01);
            self.depth -= 1;
        }
        self.op(0x57);
        self.depth -= 2;
    }

    /// `JUMPI` forward over a neutral run.
    fn branch(&mut self) {
        if self.r.chance(120) {
            // A JUMPI not taken never checks its destination: zero, then a bogus target (past the
            // code, above 32 bits, or a data byte), static or dynamic.
            self.push_u(0);
            let t = self.r.pick(&[
                U256::from_u32(0xfff0),
                pow2(40),
                U256::MAX,
                U256::from_u32(1),
            ]);
            self.push(&t);
            if self.r.chance(500) {
                self.push_u(0);
                self.op(0x01);
                self.depth -= 1;
            }
            self.op(0x57);
            self.depth -= 2;
            return;
        }
        let skip = self.label();
        let cond = if self.depth > 0 && self.r.chance(500) {
            // A computed condition: a copy of a result.
            let k = self.r.range(1, self.depth.min(16) as u64) as u8;
            self.op(0x7f + k);
            self.depth += 1;
            None
        } else {
            Some(if self.r.chance(500) {
                U256::ONE
            } else {
                U256::ZERO
            })
        };
        if let Some(c) = cond {
            self.push(&c);
        }
        self.push_label(skip);
        self.op(0x57);
        self.depth -= 2;
        let n = self.r.range(1, 8) as usize;
        self.neutral(n);
        self.bind(skip);
    }

    /// A dynamic `JUMP` forward over dead bytes.
    fn dead(&mut self) {
        let to = self.label();
        self.push_label(to);
        self.push_u(0);
        self.op(0x17); // OR: not a PUSH immediately before the JUMP
        self.depth -= 1;
        self.op(0x56);
        self.depth -= 1;
        let n = self.r.range(1, 24) as usize;
        for _ in 0..n {
            let b = match self.r.below(10) {
                0 => self.r.pick(&[0xf1u8, 0xf2, 0xf4, 0xfa]),
                1 => 0x5b,
                2 => self.r.pick(&[0x46u8, 0x32, 0x3d, 0x3e]),
                _ => self.r.next_u64() as u8,
            };
            if matches!(b, 0xf1 | 0xf2 | 0xf4 | 0xfa) {
                self.tags.call_byte = true;
                self.tags.dead_call_byte = true;
            }
            self.op(b);
        }
        // A PUSHn among the dead bytes may swallow the label's JUMPDEST: pad with enough STOPs
        // that any immediate ends before it.
        self.code.extend_from_slice(&[0u8; 32]);
        self.bind(to);
    }

    /// A guarded early exit: `JUMPI` over a halt, usually taken.
    fn early_exit(&mut self) {
        let skip = self.label();
        let c = if self.r.chance(900) {
            U256::ONE
        } else {
            U256::ZERO
        };
        self.push(&c);
        self.push_label(skip);
        self.op(0x57);
        self.depth -= 2;
        let d = self.depth;
        self.terminal(true);
        self.depth = d;
        self.bind(skip);
    }

    /// Rare stack stress: an overflowing loop, or an op on too shallow a stack.
    fn stress(&mut self) {
        if self.r.chance(500) {
            // PUSH1 1 forever (the counter in memory, as `looped`, with 1100 iterations): the
            // 1025th push overflows.
            let cnt = 0x3200;
            self.push_u(1100);
            self.push_u(cnt);
            self.op(0x52);
            self.depth -= 2;
            let top = self.label();
            self.bind(top);
            self.push_u(1);
            self.push_u(1);
            self.push_u(cnt);
            self.op(0x51);
            self.op(0x03);
            self.op(0x80);
            self.push_u(cnt);
            self.op(0x52);
            self.push_label(top);
            self.op(0x57);
            self.depth = 0; // never reached
        } else {
            let op = self.r.pick(&[0x01u8, 0x08, 0x52, 0x8f, 0x9f, 0x55, 0xa4]);
            self.pop_to(0);
            let v = interesting(self.r);
            self.push(&v);
            self.op(op);
            self.depth = 0;
        }
    }

    /// A halt: the epilogue's, or an early exit's.
    /// `mid`: not at the end of the code, so it must really halt — no running off the end, and no
    /// truncated `PUSHn`, which would swallow what follows.
    fn terminal(&mut self, mid: bool) {
        let pick = if self.faulty {
            match self.r.below(100) {
                89.. if mid => 0,
                p => p,
            }
        } else {
            // RETURN, REVERT, STOP, a truncated PUSHn, running off the end.
            self.r.pick(&[0u64, 1, 2, 3, 35, 40, 47, 50, 89, 98])
        };
        match pick {
            0..=34 => {
                // RETURN the region the dump wrote, or a random one.
                self.dump();
                let (off, len) = if self.r.chance(700) {
                    (U256::ZERO, U256::from_u32(32 * self.r.range(1, 8) as u32))
                } else {
                    (self.value(Role::Off), self.value(Role::RetLen))
                };
                self.push(&len);
                self.push(&off);
                self.op(0xf3);
            }
            35..=46 => {
                self.dump();
                let len = self.value(Role::RetLen);
                let off = self.value(Role::Off);
                self.push(&len);
                self.push(&off);
                self.op(0xfd);
            }
            47..=54 => {
                self.dump();
                self.op(0x00);
            }
            55..=61 => self.op(0xfe),
            62..=67 => {
                let b = self.r.pick(&[
                    0x31u8, 0x3a, 0x3b, 0x3c, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x47, 0x48,
                    0xf0, 0xf5, 0xff, 0x0c, 0x21, 0x49, 0x4a, 0x5c, 0x5d, 0x5e, 0xa5, 0xef, 0xfb,
                ]);
                self.op(b);
            }
            68..=72 => {
                // A static bad jump: past the code, or onto a JUMPDEST byte inside push data.
                if self.r.chance(500) {
                    self.push_u(0xfff0);
                } else {
                    // PUSH2 at its own first data byte (a JUMPDEST byte there would not count).
                    let at = self.code.len() + 1;
                    self.op(0x61);
                    self.code.extend_from_slice(&[(at >> 8) as u8, at as u8]);
                    self.depth += 1;
                }
                self.op(0x56);
            }
            73..=82 => {
                // A dynamic bad jump.
                self.tags.dynamic_bad_jump = true;
                let t = match self.r.below(4) {
                    0 => U256::from_u32(0xfff0),
                    1 => pow2(40),
                    2 => U256::from_u32(1), // inside the first push's data or an op, never a JUMPDEST
                    _ => U256::MAX,
                };
                self.push(&t);
                // `t + 0`: half the time a constant zero, which stage two folds into a static bad
                // jump; the other half a zero known only at run time (`CALLDATASIZE DUP1 XOR`), so
                // stage two's jump stays dynamic and its dispatch's bad-jump exits are exercised
                // too (Task 8). The choice reads no randomness, so no other case changes.
                if self.code.len().is_multiple_of(2) {
                    self.push_u(0);
                } else {
                    self.op(0x36);
                    self.op(0x80);
                    self.op(0x18);
                    self.depth += 1;
                }
                self.op(0x01);
                self.op(0x56);
            }
            83..=88 => {
                // A call to a non-precompile: the interpreter's trap, kept.
                let op = self.r.pick(&[0xf1u8, 0xf2, 0xf4, 0xfa]);
                let n = if matches!(op, 0xf1 | 0xf2) { 7 } else { 6 };
                for i in 0..n {
                    let v = if i == n - 2 {
                        U256::from_u32(0x1234)
                    } else {
                        U256::ZERO
                    };
                    self.push(&v);
                }
                self.op(op);
                self.tags.call_byte = true;
                self.tags.call_step = true;
            }
            89..=92 => {
                // Off the end inside a truncated PUSHn: its missing bytes read as zeros.
                let n = self.r.range(2, 32) as u8;
                self.op(0x5f + n);
                let k = self.r.below(n as u64 - 1) as usize;
                let b = self.r.bytes(k);
                self.code.extend_from_slice(&b);
            }
            _ => {
                self.dump(); // and run off the end: STOP
            }
        }
    }

    /// A sweep: 32 value-computing opcodes, each on fresh operands, each result stored at its own
    /// word of memory, and all 1024 bytes returned — every result is observed.
    fn sweep(&mut self) {
        const PURE: &[u8] = &[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x10, 0x11, 0x12,
            0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x05, 0x07, 0x0b,
            0x1a, 0x1d, 0x0a, 0x08, 0x09, 0x20, 0x35, 0x51, 0x58, 0x59, 0x5a, 0x46, 0x32,
        ];
        for i in 0..32u64 {
            let op = self.r.pick(PURE);
            self.step(op);
            self.push_u(32 * i);
            self.op(0x52);
            self.depth -= 2;
        }
        self.push_u(1024);
        self.push_u(0);
        self.op(0xf3);
    }

    /// Fold the top word into the accumulator at [`ACC`] (`acc ^= top`), keeping the top: what
    /// an op computed then reaches the output even when the stack drops it later.
    fn observe(&mut self) {
        self.op(0x80); // DUP1
        self.push_u(ACC);
        self.op(0x51); // MLOAD
        self.op(0x18); // XOR
        self.push_u(ACC);
        self.op(0x52); // MSTORE
        self.depth -= 2; // the two pushes: DUP1 +1, XOR -1, MSTORE -2 net to nothing
    }

    /// Store up to eight words from the top of the stack at 0, 32, …, the accumulator first.
    fn dump(&mut self) {
        self.push_u(ACC);
        self.op(0x51);
        if !self.faulty && self.r.chance(300) {
            if let Some(&s) = self.slots.first() {
                // Into storage too, so a STOP's post-state root binds it.
                self.op(0x80);
                self.depth += 1;
                self.push(&s);
                self.op(0x55);
                self.depth -= 2;
            }
        }
        let n = self.depth.min(self.r.range(1, 8) as usize);
        for i in 0..n {
            self.push_u(32 * i as u64);
            self.op(0x52);
            self.depth -= 2;
        }
    }
}

/// The case for `seed`.
pub fn case(seed: u64) -> Case {
    let mut r = Rng::new(seed);
    let calldata_len = match r.below(10) {
        0 => 0,
        1..=7 => r.range(1, 200) as usize,
        8 => r.range(200, 1500) as usize,
        _ => 4 + 32 * r.range(0, 6) as usize,
    };
    let calldata = r.bytes(calldata_len);
    // Storage: up to five witnessed slots, one of which may be the loop counter's.
    let n_slots = r.range(0, 5) as usize;
    let mut slots = Vec::new();
    let mut storage = Vec::new();
    for _ in 0..n_slots {
        let s = if r.chance(500) {
            U256::from_u32(r.below(8) as u32)
        } else {
            r.word()
        };
        if slots.contains(&s) {
            continue;
        }
        slots.push(s);
        if r.chance(600) {
            let v = if r.chance(500) {
                U256::from_u32(r.range(1, 1000) as u32)
            } else {
                r.word()
            };
            if !v.is_zero() {
                storage.push((s, v));
            }
        }
    }
    let loop_slot = if r.chance(400) {
        let s = U256::from_u64(0x10_0000 + r.below(1000));
        slots.push(s);
        Some(s)
    } else {
        None
    };
    let touched = slots.clone();
    let faulty = r.chance(350);
    let mut g = Gen {
        r: &mut r,
        code: Vec::new(),
        labels: Vec::new(),
        fixups: Vec::new(),
        depth: 0,
        slots,
        loop_slot,
        tags: Tags::default(),
        calldata_len,
        faulty,
        in_loop: false,
        logs: 0,
    };
    let sweep = !faulty && g.r.chance(300);
    let n_seg = if sweep { 0 } else { g.r.range(2, 9) };
    if sweep {
        g.sweep();
    }
    for _ in 0..n_seg {
        match g.r.below(100) {
            0..=51 => {
                let n = g.r.range(3, 24) as usize;
                g.straight(n);
            }
            52..=69 => g.looped(),
            70..=81 => g.branch(),
            82..=88 => g.dead(),
            89..=95 if g.faulty => g.early_exit(),
            96..=97 => {
                // A lone JUMPDEST mid-run: a block boundary nothing jumps to.
                g.bind_anon();
            }
            _ => {
                if g.faulty && g.r.chance(300) {
                    g.stress();
                    break;
                }
                let n = g.r.range(3, 10) as usize;
                g.straight(n);
            }
        }
    }
    if !sweep {
        g.terminal(false);
    }
    // Patch the labels.
    let Gen {
        code,
        labels,
        fixups,
        tags,
        ..
    } = g;
    let mut code = code;
    for (at, l) in fixups {
        let t = labels[l].expect("every label is bound");
        code[at] = (t >> 8) as u8;
        code[at + 1] = t as u8;
    }
    let has_chainid = {
        let mut i = 0;
        let mut found = false;
        while i < code.len() {
            let op = code[i];
            found |= op == 0x46;
            i += if (0x60..=0x7f).contains(&op) {
                1 + (op - 0x5f) as usize
            } else {
                1
            };
        }
        found
    };
    let mut address = r.word();
    for l in &mut address.0[5..] {
        *l = 0;
    }
    let (caller, chain_id) = if has_chainid {
        let c = match r.below(4) {
            0 => 1,
            1 => r.below(1 << 32),
            2 => u64::MAX,
            _ => r.next_u64(),
        };
        (U256::from_u64(c), Some(c))
    } else {
        let mut c = r.word();
        for l in &mut c.0[5..] {
            *l = 0;
        }
        (c, None)
    };
    let callvalue = if r.chance(700) {
        U256::ZERO
    } else {
        interesting(&mut r)
    };
    let gas = match r.below(20) {
        0..=16 => Gas::Full,
        17 | 18 => Gas::Fraction(r.below(65_536) as u32),
        _ => Gas::Minus(r.below(2)),
    };
    Case {
        seed,
        code,
        calldata,
        address,
        caller,
        callvalue,
        storage,
        touched,
        gas_limit: 5_000_000,
        gas,
        chain_id,
        tags,
    }
}

impl Gen<'_> {
    fn bind_anon(&mut self) {
        let l = self.label();
        self.bind(l);
    }
}
