//! Stage two: register lifting per block (the spec's §4). The same runtime calls, the same block
//! heads and the same gas as stage one ([`crate::emit`]); what changes is where a block keeps its
//! words.
//!
//! **The analysis.** Each block is simulated symbolically from its entry depth. A stack position
//! is named relative to the depth the block was entered with (`-1` is the entry top, `0` the first
//! word pushed), and every position holds a [`Val`]:
//!
//! * `Arr(q)` — the word the memory stack holds at position `q`, unchanged since the block began or
//!   since its last spill. A block's entry words stay `Arr` until something replaces them, so
//!   reading one is a load through the block's base pointer `sp_ = &evm_stack[evm_sp]` (taken once
//!   at the head); `DUPn` and `SWAPn` of them only rename, and emit nothing.
//! * `Local(i)` — the C local `r<i>` (a `u256`, 32 bytes on the C stack): every result a block
//!   computes. Locals are reference-counted (a `DUP` of a local shares it), and a runtime call's
//!   result is written over an operand local nobody else holds (every `u256_*` and runtime routine
//!   allows its result to alias its operands — the rule stage one's in-place stack already uses).
//! * `Const` — a push, `PC`, `CHAINID`, or an arithmetic/comparison/bitwise result over constants
//!   folded at translation with the interpreter's own `evm_core::u256::U256` (never `EXP`, whose gas
//!   depends on its operand, nor anything that touches memory, storage or gas). An offset or length
//!   operand that is a constant becomes a literal — saturated at translation exactly as
//!   `u256_sat_u32` saturates — a constant jump destination a direct `goto` (or a static bad jump),
//!   and a constant word a runtime call reads is a function-scope `static const u256` (one per
//!   distinct value): the loader's data prologue writes its non-zero limbs once per run, where
//!   building it at each use would cost a call every time.
//! * `Env` — `ADDRESS`, `CALLER` (and `ORIGIN`), `CALLVALUE`: the runtime globals the shim fills
//!   before the run and nothing writes during it, read in place.
//!
//! The memory stack is written only by a **spill**, never by an operation: that is the invariant
//! that keeps every `Arr(q)` valid until the next spill. A spill writes each position below a
//! height whose value is not already `Arr` of itself — a parallel move, since a block's `SWAP`s
//! can leave its entry words permuted: moves whose destination no pending move still reads go
//! first, and what is left is then a set of disjoint cycles, each rotated through the one
//! temporary `t_`. Words above the spilled height that read a slot the spill writes (a jump's
//! destination, `LOG`'s offset and size) are first copied into locals.
//!
//! **Where the stack must be true.** At every exit into another block — the fall-through, a
//! `JUMP`, and a `JUMPI` (before it branches, so both successors see the same stack) — the block
//! spills everything and moves `evm_sp` to its exit depth once: each block's head (unchanged from
//! stage one: underflow, overflow, then the static charge) then sees exactly the depth stage one
//! would have. Inside a block, `evm_sp` stays at the entry depth. No runtime routine reads
//! `evm_stack` or `evm_sp` itself (the audit is in Task 8's report); two take a pointer to
//! contiguous stack words, and both are handed a spilled stack: the call family
//! (`evm_call(op, &sp_[h-n], gas_after)`, which writes its flag over the deepest operand, so the
//! whole stack is spilled first and that slot is `Arr` again after) and `LOGn` (its topics).
//! Halting paths need nothing: every exceptional halt discards the state, and `STOP`, `RETURN`
//! and `REVERT` read memory, not the stack.
//!
//! **The frame.** `evm_entry` declares one pool of locals, `r0 … r<n-1>`, shared by every block:
//! no local is live across a block boundary, so the pool is as large as the most any one block
//! holds at once. A block never holds more than [`MAX_LOCALS`] (3 KiB of words): before any
//! operation that would leave less than `OP_ROOM` free, the block spills everything and goes on
//! from the memory stack.

use std::fmt::Write as _;

use evm_core::u256::U256;

use crate::blocks::{blocks, jumpdests, Op, Term, CALL_FAMILY};
use crate::emit::{comment, head_c, EmitError, Emitted, Options};

/// The most `u256` locals any block holds at once: 96 × 32 bytes = 3 KiB of `evm_entry`'s frame,
/// under the 4 KiB budget with room for the compiler's own spills (the shim's C stack is 64 KiB,
/// shared with the precompiles `evm_call` runs).
pub const MAX_LOCALS: usize = 96;

/// What the cap keeps free at the start of every operation: its result, and the locals a spill's
/// protection may take (a jump's destination, or `LOG`'s offset and size), with one to spare.
const OP_ROOM: usize = 4;

/// What one stack position holds (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Val {
    Arr(i64),
    Local(usize),
    Const([u32; 8]),
    Env(&'static str),
}

/// How a runtime call takes an operand.
#[derive(Clone, Copy)]
enum Use {
    /// `const u256 *`.
    Ptr,
    /// An offset or length: `u256_sat_u32`.
    Sat,
    /// `MSTORE8`'s value: `u256_low_u32`, unsaturated.
    Low,
}

/// What the whole of `evm_entry` shares.
#[derive(Default)]
struct Func {
    /// The pool's size: one more than the highest local any block used.
    locals: usize,
    /// The `static const u256 K<i>` table: every constant a runtime call reads through a pointer.
    consts: Vec<[u32; 8]>,
    /// A spill rotated a cycle through `t_`.
    temp: bool,
    /// Some block uses `sp_`.
    sp: bool,
}

impl Func {
    fn konst(&mut self, l: [u32; 8]) -> usize {
        match self.consts.iter().position(|c| *c == l) {
            Some(i) => i,
            None => {
                self.consts.push(l);
                self.consts.len() - 1
            }
        }
    }
}

/// The jumps a block resolved: static targets (labelled) and whether any is dynamic.
struct Jumps<'a> {
    targets: Vec<usize>,
    dynamic: bool,
    jd: &'a [usize],
}

impl Jumps<'_> {
    /// A constant destination: `Some(t)` when it is a jumpdest (the interpreter's rule: the high
    /// limbs zero, the low one in the set), else `None`, a bad jump.
    fn target(&self, l: &[u32; 8]) -> Option<usize> {
        let t = l[0] as usize;
        (l[1..].iter().all(|&x| x == 0) && self.jd.binary_search(&t).is_ok()).then_some(t)
    }
}

/// One block's symbolic stack.
struct Lift<'f> {
    f: &'f mut Func,
    /// The lowest position the block may touch: `-min_depth` (the head guarantees it exists).
    lo: i64,
    /// Positions `lo..h`.
    stack: Vec<Val>,
    refs: [u32; MAX_LOCALS],
    /// Locals the current operation reads or has allocated: not free for another allocation.
    busy: Vec<usize>,
    /// The block reads or writes the memory stack through `sp_`.
    sp: bool,
}

fn small(l: &[u32; 8]) -> Option<u64> {
    l[2..]
        .iter()
        .all(|&x| x == 0)
        .then_some((l[1] as u64) << 32 | l[0] as u64)
}

/// `op` over constant operands (`v[0]` the top), with the interpreter's own arithmetic; `None`
/// for anything that is not a pure function of its operands.
fn fold(op: u8, v: &[[u32; 8]]) -> Option<[u32; 8]> {
    let u = |i: usize| U256(v[i]);
    let b = |x: bool| if x { U256::ONE } else { U256::ZERO };
    Some(
        match op {
            0x01 => u(0).add(&u(1)),
            0x02 => u(0).mul(&u(1)),
            0x03 => u(0).sub(&u(1)),
            0x04 => u(0).div(&u(1)),
            0x05 => u(0).sdiv(&u(1)),
            0x06 => u(0).rem(&u(1)),
            0x07 => u(0).smod(&u(1)),
            0x08 => u(0).addmod(&u(1), &u(2)),
            0x09 => u(0).mulmod(&u(1), &u(2)),
            0x0b => u(1).signextend(&u(0)),
            0x10 => b(u(0).lt(&u(1))),
            0x11 => b(u(1).lt(&u(0))),
            0x12 => b(u(0).slt(&u(1))),
            0x13 => b(u(1).slt(&u(0))),
            0x14 => b(u(0) == u(1)),
            0x15 => b(u(0).is_zero()),
            0x16 => u(0).and(&u(1)),
            0x17 => u(0).or(&u(1)),
            0x18 => u(0).xor(&u(1)),
            0x19 => u(0).not(),
            0x1a => u(1).byte(&u(0)),
            0x1b => u(1).shl(&u(0)),
            0x1c => u(1).shr(&u(0)),
            0x1d => u(1).sar(&u(0)),
            _ => return None,
        }
        .0,
    )
}

/// A `PUSHn` immediate (big-endian bytes) as limbs.
fn limbs(v: &[u8; 32]) -> [u32; 8] {
    std::array::from_fn(|i| {
        let o = 32 - 4 * (i + 1);
        u32::from_be_bytes([v[o], v[o + 1], v[o + 2], v[o + 3]])
    })
}

fn from_u64(v: u64) -> [u32; 8] {
    U256::from_u64(v).0
}

impl<'f> Lift<'f> {
    fn new(f: &'f mut Func, min_depth: usize) -> Lift<'f> {
        let lo = -(min_depth as i64);
        Lift {
            f,
            lo,
            stack: (lo..0).map(Val::Arr).collect(),
            refs: [0; MAX_LOCALS],
            busy: Vec::new(),
            sp: false,
        }
    }

    fn h(&self) -> i64 {
        self.lo + self.stack.len() as i64
    }

    fn at(&self, p: i64) -> Val {
        self.stack[(p - self.lo) as usize]
    }

    fn set(&mut self, p: i64, v: Val) {
        if let Val::Local(i) = self.at(p) {
            self.refs[i] -= 1;
        }
        if let Val::Local(i) = v {
            self.refs[i] += 1;
        }
        let k = (p - self.lo) as usize;
        self.stack[k] = v;
    }

    fn push(&mut self, v: Val) {
        if let Val::Local(i) = v {
            self.refs[i] += 1;
        }
        self.stack.push(v);
    }

    fn pop(&mut self) -> Val {
        let v = self
            .stack
            .pop()
            .expect("the block head's min_depth covers every pop");
        if let Val::Local(i) = v {
            self.refs[i] -= 1;
        }
        v
    }

    fn live(&self) -> usize {
        self.refs.iter().filter(|&&r| r > 0).count()
    }

    /// A local no position holds and the current operation does not use.
    fn alloc(&mut self) -> usize {
        let i = (0..MAX_LOCALS)
            .find(|&i| self.refs[i] == 0 && !self.busy.contains(&i))
            .expect("the cap leaves OP_ROOM locals free");
        self.busy.push(i);
        self.f.locals = self.f.locals.max(i + 1);
        i
    }

    /// The result's local: an operand local the operation has made dead, else a fresh one.
    fn dst(&mut self) -> usize {
        match self.busy.iter().copied().find(|&i| self.refs[i] == 0) {
            Some(i) => i,
            None => self.alloc(),
        }
    }

    fn arr(&mut self, q: i64) -> String {
        self.sp = true;
        self.f.sp = true;
        format!("sp_[{q}]")
    }

    /// C that writes the constant `l` to the lvalue `dst`.
    fn materialize(&mut self, dst: &str, l: [u32; 8]) -> String {
        match small(&l) {
            Some(v) if v <= u32::MAX as u64 => format!("u256_from_u32(&{dst}, {v:#x}u); "),
            Some(v) => format!("u256_from_u64(&{dst}, {v:#x}ull); "),
            None => format!("{dst} = K{}; ", self.f.konst(l)),
        }
    }

    /// `v` as a `const u256 *`.
    fn ptr(&mut self, v: Val) -> String {
        match v {
            Val::Arr(q) => format!("&{}", self.arr(q)),
            Val::Local(i) => {
                self.busy.push(i);
                format!("&r{i}")
            }
            Val::Env(n) => format!("&{n}"),
            Val::Const(l) => format!("&K{}", self.f.konst(l)),
        }
    }

    /// `v` as an offset or length: a constant saturates here, as `u256_sat_u32` would.
    fn sat(&mut self, v: Val) -> String {
        match v {
            Val::Const(l) if l[1..].iter().all(|&x| x == 0) => format!("{:#x}u", l[0]),
            Val::Const(_) => format!("{:#x}u", u32::MAX),
            v => format!("u256_sat_u32({})", self.ptr(v)),
        }
    }

    /// `v`'s low limb, unsaturated.
    fn low(&mut self, v: Val) -> String {
        match v {
            Val::Const(l) => format!("{:#x}u", l[0]),
            v => format!("u256_low_u32({})", self.ptr(v)),
        }
    }

    /// A runtime call over the top `uses.len()` words (the top first), with a result pushed when
    /// `result`: `render(args, dst)`.
    fn call(
        &mut self,
        uses: &[Use],
        result: bool,
        render: impl FnOnce(&[String], &str) -> String,
    ) -> String {
        let vals: Vec<Val> = uses.iter().map(|_| self.pop()).collect();
        // Every operand local is in use until the call has read it — including one this pop left
        // unreferenced, which nothing else may be allocated over before the call (the result may
        // be: every runtime routine lets its result alias its operands).
        for v in &vals {
            if let Val::Local(i) = v {
                self.busy.push(*i);
            }
        }
        let mut args = Vec::with_capacity(uses.len());
        for (u, v) in uses.iter().zip(vals) {
            args.push(match u {
                Use::Ptr => self.ptr(v),
                Use::Sat => self.sat(v),
                Use::Low => self.low(v),
            });
        }
        let d = result.then(|| self.dst());
        let name = d.map(|d| format!("r{d}")).unwrap_or_default();
        let code = render(&args, &name);
        if let Some(d) = d {
            self.push(Val::Local(d));
        }
        self.busy.clear();
        code
    }

    /// A pure operation over the top `n` words: folded when they are all constants, else the
    /// runtime call `render(args, dst)`.
    fn pure(&mut self, op: u8, n: usize, render: impl FnOnce(&[String], &str) -> String) -> String {
        let h = self.h();
        let consts: Option<Vec<[u32; 8]>> = (0..n as i64)
            .map(|i| match self.at(h - 1 - i) {
                Val::Const(l) => Some(l),
                _ => None,
            })
            .collect();
        if let Some(r) = consts.and_then(|c| fold(op, &c)) {
            for _ in 0..n {
                self.pop();
            }
            self.push(Val::Const(r));
            return String::new();
        }
        self.call(&vec![Use::Ptr; n], true, render)
    }

    /// A word computed from nothing on the stack, into a fresh local.
    fn fresh(&mut self, render: impl FnOnce(&str) -> String) -> String {
        let d = self.alloc();
        let code = render(&format!("r{d}"));
        self.push(Val::Local(d));
        self.busy.clear();
        code
    }

    /// C that writes `v` to the memory stack at position `d`.
    fn store(&mut self, d: i64, v: Val) -> String {
        let at = self.arr(d);
        match v {
            Val::Arr(q) => format!("{at} = {}; ", self.arr(q)),
            Val::Local(i) => format!("{at} = r{i}; "),
            Val::Env(n) => format!("{at} = {n}; "),
            Val::Const(l) => self.materialize(&at, l),
        }
    }

    /// Spill: make the memory stack true below position `k` (see the module docs). Words at `k`
    /// and above keep their values, copied into locals first if the spill overwrites their slot.
    fn flush(&mut self, k: i64) -> String {
        debug_assert!(self.busy.is_empty());
        let mut s = String::new();
        let dirty: Vec<i64> = (self.lo..k)
            .filter(|&p| self.at(p) != Val::Arr(p))
            .collect();
        if dirty.is_empty() {
            return s;
        }
        for p in k..self.h() {
            if let Val::Arr(q) = self.at(p) {
                if dirty.contains(&q) {
                    let t = self.alloc();
                    let from = self.arr(q);
                    let _ = write!(s, "r{t} = {from}; ");
                    self.set(p, Val::Local(t));
                }
            }
        }
        self.busy.clear();
        let mut pending: Vec<(i64, Val)> = dirty.iter().map(|&p| (p, self.at(p))).collect();
        while !pending.is_empty() {
            // A move whose destination no pending move still reads.
            let ready = (0..pending.len())
                .find(|&i| !pending.iter().any(|&(_, v)| v == Val::Arr(pending[i].0)));
            if let Some(i) = ready {
                let (d, v) = pending.remove(i);
                s.push_str(&self.store(d, v));
                continue;
            }
            // Every pending move now reads a slot another one writes, and each slot is read
            // once: disjoint cycles of `Arr` moves. Rotate one through `t_`.
            self.f.temp = true;
            let d0 = pending[0].0;
            let _ = write!(s, "t_ = {}; ", self.arr(d0));
            let mut d = d0;
            loop {
                let i = pending.iter().position(|&(x, _)| x == d).expect("a cycle");
                let (_, v) = pending.remove(i);
                let Val::Arr(q) = v else {
                    unreachable!("only Arr moves are left in a cycle")
                };
                let at = self.arr(d);
                if q == d0 {
                    let _ = write!(s, "{at} = t_; ");
                    break;
                }
                let _ = write!(s, "{at} = {}; ", self.arr(q));
                d = q;
            }
        }
        for p in dirty {
            self.set(p, Val::Arr(p));
        }
        s
    }

    /// Leave the block at depth `k` (relative to the entry): spill below it, and move `evm_sp`.
    fn exit(&mut self, k: i64) -> String {
        let mut s = self.flush(k);
        match k {
            0 => {}
            k if k > 0 => {
                let _ = write!(s, "evm_sp += {k}; ");
            }
            k => {
                let _ = write!(s, "evm_sp -= {}; ", -k);
            }
        }
        s
    }

    /// The C for one op.
    fn op(
        &mut self,
        op: &Op,
        opts: &Options,
        calls: bool,
        j: &mut Jumps<'_>,
    ) -> Result<String, EmitError> {
        let o = op.opcode;
        let mut s = String::new();
        if self.live() + OP_ROOM > MAX_LOCALS {
            let h = self.h();
            s.push_str(&self.flush(h));
        }
        let bin = |f: &'static str| {
            move |a: &[String], d: &str| format!("{f}(&{d}, {}, {});", a[0], a[1])
        };
        // The value first, then the index/shift (the top): SIGNEXTEND, BYTE, SHL, SHR, SAR.
        let vfirst = |f: &'static str| {
            move |a: &[String], d: &str| format!("{f}(&{d}, {}, {});", a[1], a[0])
        };
        let code = match o {
            0x00 => "evm_halt(EVM_HALT_STOP, 0);".into(),
            0x01 => self.pure(o, 2, bin("u256_add")),
            0x02 => self.pure(o, 2, bin("u256_mul")),
            0x03 => self.pure(o, 2, bin("u256_sub")),
            0x04 => self.pure(o, 2, bin("u256_div")),
            0x05 => self.pure(o, 2, bin("u256_sdiv")),
            0x06 => self.pure(o, 2, bin("u256_mod")),
            0x07 => self.pure(o, 2, bin("u256_smod")),
            0x08 | 0x09 => {
                let f = if o == 0x08 {
                    "u256_addmod"
                } else {
                    "u256_mulmod"
                };
                self.pure(o, 3, |a, d| {
                    format!("{f}(&{d}, {}, {}, {});", a[0], a[1], a[2])
                })
            }
            // EXP: the base is the top; its gas depends on the exponent, so it is never folded.
            0x0a => self.call(&[Use::Ptr, Use::Ptr], true, |a, d| {
                format!("evm_exp(&{d}, {}, {});", a[0], a[1])
            }),
            0x0b => self.pure(o, 2, vfirst("u256_signextend")),
            0x10 => self.pure(o, 2, bin("u256_lt")),
            0x11 => self.pure(o, 2, bin("u256_gt")),
            0x12 => self.pure(o, 2, bin("u256_slt")),
            0x13 => self.pure(o, 2, bin("u256_sgt")),
            0x14 => self.pure(o, 2, bin("u256_eq")),
            0x15 => self.pure(o, 1, |a, d| format!("u256_iszero(&{d}, {});", a[0])),
            0x16 => self.pure(o, 2, bin("u256_and")),
            0x17 => self.pure(o, 2, bin("u256_or")),
            0x18 => self.pure(o, 2, bin("u256_xor")),
            0x19 => self.pure(o, 1, |a, d| format!("u256_not(&{d}, {});", a[0])),
            0x1a => self.pure(o, 2, vfirst("u256_byte")),
            0x1b => self.pure(o, 2, vfirst("u256_shl")),
            0x1c => self.pure(o, 2, vfirst("u256_shr")),
            0x1d => self.pure(o, 2, vfirst("u256_sar")),
            // KECCAK256: offset on top, size second.
            0x20 => self.call(&[Use::Sat, Use::Sat], true, |a, d| {
                format!("evm_keccak({}, {}, &{d});", a[0], a[1])
            }),
            0x30 => {
                self.push(Val::Env("evm_address"));
                String::new()
            }
            // ORIGIN is CALLER: one call, no relayer.
            0x32 | 0x33 => {
                self.push(Val::Env("evm_caller"));
                String::new()
            }
            0x34 => {
                self.push(Val::Env("evm_callvalue"));
                String::new()
            }
            0x35 => self.call(&[Use::Sat], true, |a, d| {
                format!("evm_calldataload({}, &{d});", a[0])
            }),
            0x36 => self.fresh(|d| format!("u256_from_u32(&{d}, evm_calldata_len);")),
            // The copies: destination on top, then the source offset, then the length.
            0x37 | 0x39 | 0x3e => {
                let f = match o {
                    0x37 => "evm_copy_calldata",
                    0x39 => "evm_copy_code",
                    _ if calls => "evm_copy_returndata_buf",
                    _ => "evm_copy_returndata",
                };
                self.call(&[Use::Sat, Use::Sat, Use::Sat], false, |a, _| {
                    format!("{f}({}, {}, {});", a[0], a[1], a[2])
                })
            }
            0x38 => self.fresh(|d| format!("u256_from_u32(&{d}, evm_code_len);")),
            // Without a call-family opcode the return data is always empty (the interpreter's
            // rule); with one, the runtime's buffer, read now.
            0x3d if calls => self.fresh(|d| format!("u256_from_u32(&{d}, evm_rdata_len);")),
            0x3d => {
                self.push(Val::Const([0; 8]));
                String::new()
            }
            0x46 => match opts.chain_id {
                Some(id) => {
                    self.push(Val::Const(from_u64(id)));
                    String::new()
                }
                None => return Err(EmitError::ChainIdRequired { pc: op.pc }),
            },
            0x50 => {
                self.pop();
                String::new()
            }
            0x51 => self.call(&[Use::Sat], true, |a, d| {
                format!("evm_mload({}, &{d});", a[0])
            }),
            // MSTORE: offset on top, value second.
            0x52 => self.call(&[Use::Sat, Use::Ptr], false, |a, _| {
                format!("evm_mstore({}, {});", a[0], a[1])
            }),
            // MSTORE8's value is the unsaturated low limb: only its low byte is stored.
            0x53 => self.call(&[Use::Sat, Use::Low], false, |a, _| {
                format!("evm_mstore8({}, {});", a[0], a[1])
            }),
            0x54 => self.call(&[Use::Ptr], true, |a, d| {
                format!("evm_storage_load({}, &{d});", a[0])
            }),
            // SSTORE: slot on top, value second.
            0x55 => self.call(&[Use::Ptr, Use::Ptr], false, |a, _| {
                format!("evm_storage_store({}, {});", a[0], a[1])
            }),
            0x56 => self.jump(j),
            0x57 => self.jumpi(j),
            0x58 => {
                self.push(Val::Const(from_u64(op.pc as u64)));
                String::new()
            }
            0x59 => self.fresh(|d| format!("u256_from_u32(&{d}, evm_msize);")),
            // GAS: the rest of the block's static gas was taken at the head (ruling 4).
            0x5a => {
                let g = op.gas_after;
                self.fresh(|d| format!("u256_from_u64(&{d}, evm_gas + {g}ull);"))
            }
            0x5b => String::new(),
            0x5f => {
                self.push(Val::Const([0; 8]));
                String::new()
            }
            0x60..=0x7f => {
                let v = op.push.as_ref().expect("a PUSHn op carries its immediate");
                self.push(Val::Const(limbs(v)));
                String::new()
            }
            0x80..=0x8f => {
                let n = (o - 0x7f) as i64;
                let v = self.at(self.h() - n);
                self.push(v);
                String::new()
            }
            0x90..=0x9f => {
                let n = (o - 0x8f) as usize;
                let top = self.stack.len() - 1;
                self.stack.swap(top, top - n);
                String::new()
            }
            // LOGn: offset on top, size second, then the n topics, which the runtime reads in
            // place — so everything below the offset and size is spilled first.
            0xa0..=0xa4 => {
                let n = (o - 0xa0) as i64;
                let h = self.h();
                let ex = self.flush(h - 2);
                let (off, size) = (self.pop(), self.pop());
                let (off, size) = (self.sat(off), self.sat(size));
                for _ in 0..n {
                    self.pop();
                }
                self.busy.clear();
                let topics = self.arr(h - 2 - n);
                format!("{ex}evm_log({n}, {off}, {size}, &{topics});")
            }
            // The call family reads its operands in place and writes the flag over the deepest:
            // the whole stack is spilled first, and that slot is the array's again after.
            0xf1 | 0xf2 | 0xf4 | 0xfa => {
                let n: i64 = if matches!(o, 0xf1 | 0xf2) { 7 } else { 6 };
                let h = self.h();
                let ex = self.flush(h);
                for _ in 0..n {
                    self.pop();
                }
                self.push(Val::Arr(h - n));
                let a = self.arr(h - n);
                format!("{ex}evm_call({o:#04x}, &{a}, {}ull);", op.gas_after)
            }
            0xf3 => self.call(&[Use::Sat, Use::Sat], false, |a, _| {
                format!("evm_return({}, {});", a[0], a[1])
            }),
            0xfd => self.call(&[Use::Sat, Use::Sat], false, |a, _| {
                format!("evm_revert({}, {});", a[0], a[1])
            }),
            0xfe => "evm_halt(EVM_HALT_INVALID, 0);".into(),
            _ => format!("evm_halt(EVM_HALT_TRAP, {o:#04x});"),
        };
        s.push_str(&code);
        Ok(s)
    }

    /// `JUMP`: a constant destination is a direct `goto` (or a static bad jump, which needs no
    /// spill); any other goes through the dispatch, read after the spill (protected by it).
    fn jump(&mut self, j: &mut Jumps<'_>) -> String {
        let h = self.h();
        if let Val::Const(l) = self.at(h - 1) {
            return match j.target(&l) {
                Some(t) => {
                    let ex = self.exit(h - 1);
                    self.pop();
                    j.targets.push(t);
                    format!("{ex}goto L_{t};")
                }
                None => {
                    self.pop();
                    "evm_halt(EVM_HALT_BAD_JUMP, 0);".into()
                }
            };
        }
        j.dynamic = true;
        let ex = self.exit(h - 1);
        let d = self.pop();
        let p = self.ptr(d);
        self.busy.clear();
        format!("{{ {ex}const u256 *d_ = {p}; if (!u256_hi_zero(d_)) evm_halt(EVM_HALT_BAD_JUMP, 0); jd = d_->l[0]; goto dispatch; }}")
    }

    /// `JUMPI`: destination on top, condition second. The condition is read first, then the
    /// block spills (both successors need the stack), then the branch; the destination is
    /// checked only when the branch is taken, as the interpreter checks it.
    fn jumpi(&mut self, j: &mut Jumps<'_>) -> String {
        let h = self.h();
        let dest = self.pop();
        let cond = self.pop();
        let c = match cond {
            Val::Const(l) => (if l == [0; 8] { "0" } else { "1" }).to_string(),
            v => format!("!u256_is_zero({})", self.ptr(v)),
        };
        self.busy.clear();
        // The destination sits just above the exit depth while the block spills, so the spill
        // protects it.
        self.push(dest);
        let ex = self.exit(h - 2);
        let dest = self.pop();
        match dest {
            Val::Const(l) => {
                let taken = match j.target(&l) {
                    Some(t) => {
                        j.targets.push(t);
                        format!("goto L_{t};")
                    }
                    None => "evm_halt(EVM_HALT_BAD_JUMP, 0);".into(),
                };
                format!("{{ int c_ = {c}; {ex}if (c_) {taken} }}")
            }
            v => {
                j.dynamic = true;
                let p = self.ptr(v);
                self.busy.clear();
                format!("{{ int c_ = {c}; {ex}const u256 *d_ = {p}; if (c_) {{ if (!u256_hi_zero(d_)) evm_halt(EVM_HALT_BAD_JUMP, 0); jd = d_->l[0]; goto dispatch; }} }}")
            }
        }
    }
}

/// Translate `code` to the C of one `evm_entry`, stage two.
pub fn translate(code: &[u8], opts: &Options) -> Result<Emitted, EmitError> {
    let bs = blocks(code);
    let jd = jumpdests(code);
    let calls = bs
        .iter()
        .any(|b| b.ops.iter().any(|o| CALL_FAMILY.contains(&o.opcode)));
    let mut f = Func::default();
    let mut j = Jumps {
        targets: vec![bs[0].start],
        dynamic: false,
        jd: &jd,
    };
    let mut pieces: Vec<(usize, String)> = Vec::with_capacity(bs.len());
    let mut opcodes = 0usize;
    for b in &bs {
        if b.term == Term::OutOfBounds {
            // The interpreter's pre_halt, exactly as stage one emits it.
            pieces.push((
                b.start,
                "/* code over MAX_CODE_BYTES: the interpreter runs nothing */\n    evm_halt_code = EVM_HALT_OUT_OF_BOUNDS; evm_halt_arg = 0; evm_rt_unwind();\n".into(),
            ));
            continue;
        }
        let mut l = Lift::new(&mut f, b.min_depth);
        let mut body = String::new();
        for op in &b.ops {
            opcodes += 1;
            let c = l.op(op, opts, calls, &mut j)?;
            let c = c.trim_end();
            if c.is_empty() {
                let _ = writeln!(body, "    {}", comment(op));
            } else {
                let _ = writeln!(body, "    {} {}", comment(op), c);
            }
        }
        // Falling into the next block (a jumpdest) is an exit like a jump.
        if matches!(b.term, Term::Fallthrough(_)) {
            let h = l.h();
            let ex = l.exit(h);
            if !ex.is_empty() {
                let _ = writeln!(body, "    /* spill */ {}", ex.trim_end());
            }
        }
        let base = if l.sp {
            "    sp_ = &evm_stack[evm_sp];\n"
        } else {
            ""
        };
        pieces.push((b.start, head_c(b, base) + &body));
    }
    let mut targets = j.targets;
    if j.dynamic {
        targets.extend_from_slice(&jd);
    }
    targets.sort_unstable();
    targets.dedup();

    let mut out = String::new();
    let _ = writeln!(
        out,
        "/* Generated by evm2rv (stage two) from {} bytes of EVM runtime bytecode: {} blocks, {} jumpdests{}.\n * Do not edit — re-run evm2rv. Built with evm-rt by the shim's build.rs. */",
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
    for (i, k) in f.consts.iter().enumerate() {
        let l: Vec<String> = k.iter().map(|l| format!("{l:#x}u")).collect();
        let _ = writeln!(
            out,
            "    static const u256 K{i} = {{{{{}}}}};",
            l.join(", ")
        );
    }
    if f.sp {
        out.push_str("    u256 *sp_;\n");
    }
    if f.locals > 0 {
        let names: Vec<String> = (0..f.locals).map(|i| format!("r{i}")).collect();
        let _ = writeln!(out, "    u256 {};", names.join(", "));
    }
    if f.temp {
        out.push_str("    u256 t_;\n");
    }
    if j.dynamic {
        out.push_str("    uint32_t jd = 0;\n");
    }
    let _ = writeln!(out, "    goto L_{};", bs[0].start);
    if j.dynamic {
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
        locals: f.locals,
    })
}
