//! Random well-formed sBPF programs for the differential fuzzing in `tests/fuzz.rs` (Task 5). Test
//! only: this file is not a module of the library; the test includes it with `#[path]`.
//!
//! A case is a program as a list of assembler items with labels ([`It`]), plus the instruction data
//! its input region carries (`[selector][p0..p7][64 raw bytes]`, a region with no accounts, so the
//! data starts at `r1 + 16` and parameter `k` sits at [`param`]`(k)`). The same case runs on the
//! host (`Program::from_text`, text at [`sbpf_core::memory::REGION_PROGRAM`]) and inside a real ELF
//! (text wherever the loader puts it), so every address a program forms from its own text goes
//! through the assembler ([`It::Addr`], [`It::AddrEnd`]) with the text's virtual address.
//!
//! # Shape
//!
//! `main` (the entry) loads `r9` with the coverage base and runs a random body, then folds its
//! scratch frame, the heap and the instruction data into `r0` and exits. Up to four callees follow,
//! each a random body of its own (a callee calls only callees after it, so plain calls always end),
//! some with a *member*: a label inside the body that is itself called — a function whose entry lies
//! inside another's code. Then a recursive function, a *pad* (code no call or constant names as an
//! entry: a `callx` to it is the accepted divergence, see [`MAGIC`]) and a dead table of `lddw`s
//! naming every entry, which is what makes each of them a `callx`-plausible constant to the scanner.
//!
//! Bodies mix every opcode class at both ALU widths; loads and stores of every width into a scratch
//! frame, the heap, the instruction data and the text; guarded and unguarded division; `le`/`be`;
//! `lddw`; forward conditional jumps (if, if/else); bounded loops counting down a register in
//! `r6..r8` that the body never writes; internal calls, member calls, `callx` to entries, members,
//! unaligned entry addresses, non-code and the pad; recursion to a depth from the input; the twelve
//! supported syscalls with sensible arguments; writes to `r10`. A case may also carry one planned
//! *terminal* event — an access outside every region or straddling a region's end, a division by
//! zero, an invalid `le`/`be` width, a v2 or unassigned opcode, a register above `r10`, an unknown
//! syscall, `abort`/`sol_panic_`, an overlapping `sol_memcpy_`, a jump or call out of the text.
//!
//! # Coverage
//!
//! Each generated instruction of interest is followed (a jump: preceded) by a one-byte store of 1 at
//! `r9 + id` — `r9` is [`MARK_BASE`] in the heap, set by `main`, so every callee reads it before
//! writing it (a live-in across every call). `id` below 256 is the opcode byte that ran; from 256 up
//! it is [`NAMED`]'s index + 256. A class was *executed* in a run exactly when its byte is set in the
//! heap afterwards; the heap is part of what the fuzzer compares, so the two sides agree on it.
//!
//! A body may still write `r9` like any other register: [`Gen::dst`] hands it out, and
//! [`Gen::settle`] stores what it holds to the frame and loads the base back before the next mark,
//! jump, call or `exit` can see it. A callee may also clobber `r9` just before its final `exit`,
//! after its last mark: the caller's own marks then land only if `r9` came back as the frame's.
//!
//! The marks page is out of reach of everything else by construction. `main` first allocates it
//! (the first block a bump allocator hands out on an empty heap is the heap's first bytes, and it
//! never hands them out again), ordinary heap traffic starts right above it ([`HEAP_TRAFFIC`]), and
//! no syscall is given a heap destination. The fuzzer asserts, for every case, that the
//! reservation happened (the allocator's cursor is at least [`MARK_BYTES`]) and that every mark
//! byte is 0 or 1.

use sbpf_core::isa::{self, opc, Insn};
use sbpf_core::memory::{HEAP_BYTES, REGION_HEAP, REGION_INPUT, REGION_STACK, STACK_BYTES};
use sbpf_core::syscalls;
use std::collections::HashMap;

/// An assembler label.
pub type Label = u64;

/// One assembler item.
#[derive(Clone, Debug)]
pub enum It {
    /// One instruction slot.
    I(Insn),
    /// `lddw dst, imm64`.
    Lddw(u8, u64),
    /// `ja` or a conditional jump (immediate or register form) to a label.
    J {
        opc: u8,
        dst: u8,
        src: u8,
        imm: i32,
        to: Label,
    },
    /// An internal `call` to a label.
    Call(Label),
    /// `lddw dst, text_va + 8 * pc(label) + delta`.
    Addr(u8, Label, i64),
    /// `lddw dst, text_va + text_len + delta`: an address relative to the text's end.
    AddrEnd(u8, i64),
    /// A label.
    L(Label),
    /// `lddw dst, (hi.imm << 32) | lo` whose second slot is the whole instruction `hi` (the
    /// interpreter decodes it as one if a jump lands there), with `label` on that second slot.
    LddwSplit {
        dst: u8,
        lo: i32,
        hi: Insn,
        label: Label,
    },
}

/// The coverage bytes: `r9 + id`, [`MARK_BYTES`] of them at the bottom of the heap — the block
/// `main`'s first call to `sol_alloc_free_` is handed on an empty heap, so the allocator never
/// hands any of them out again.
pub const MARK_BASE: u64 = REGION_HEAP;
/// The coverage page's size: 256 opcode bytes, then the named classes.
pub const MARK_BYTES: u64 = 512;
/// Where ordinary heap traffic starts: right above the coverage page.
const HEAP_TRAFFIC: u64 = MARK_BASE + MARK_BYTES;
/// How far ordinary heap traffic reaches from [`HEAP_TRAFFIC`].
const HEAP_SPAN: u64 = 0x4000;

/// What a `callx` to the pad ends in: a load from this address, which no region contains. The
/// interpreter runs the pad and halts `AccessViolation(MAGIC)`; the translation knows no function
/// there and halts `BadJump` at the `callx` — the one accepted divergence (Task 5 ruling 3).
pub const MAGIC: u64 = 0x5_0bad_ca11;

/// The pad's label in every case (see [`with_pad_named`]).
pub const PAD: Label = 2;

/// `c` with the pad added to the dead table, so the scanner takes it for a function entry: a
/// `callx` to it is then an ordinary call, and a case that ended in the accepted divergence must
/// run the same on both sides. The pad is followed by its three items (`lddw`, the load, `exit`);
/// the name goes right after them.
pub fn with_pad_named(c: &Case) -> Case {
    let mut c = c.clone();
    let at = c
        .items
        .iter()
        .position(|it| matches!(it, It::L(PAD)))
        .expect("every case has a pad");
    c.items.insert(at + 4, It::Addr(0, PAD, 0));
    c
}

/// The named coverage classes; mark id = 256 + index.
pub const NAMED: &[&str] = &[
    "mem:stack",
    "mem:heap",
    "mem:input",
    "mem:program",
    "mem:alloc",
    "le16",
    "le32",
    "le64",
    "be16",
    "be32",
    "be64",
    "call",
    "call:member",
    "callx:entry",
    "callx:member",
    "callx:unaligned",
    "exit:callee",
    "recursion:returned",
    "recursion:depth>=5",
    "sys:sol_log_",
    "sys:sol_log_64_",
    "sys:sol_log_compute_units_",
    "sys:sol_log_pubkey",
    "sys:sol_memcpy_",
    "sys:sol_memmove_",
    "sys:sol_memset_",
    "sys:sol_memcmp_",
    "sys:sol_alloc_free_",
    "sys:sol_sha256",
    "r10:write-balanced",
    "r10:write-callee-unrestored",
    "arg-through:stxb",
    "arg-through:stxh",
    "arg-through:stxw",
    "arg-through:stxdw",
    "callee:reads-r0-r6-r9-first",
    "callee:writes-some-of-r0-r5",
    "loop",
    "loop:trip-from-input",
    "if",
    "if-else",
    "exit:early",
    "div:guarded-reg",
    "lddw:jump-into-second-slot",
    "call:own-member",
    "fallthrough-into-next-function",
    "call:member-inside-a-loop",
    "call:into-lddw-second-slot",
    "r9:written",
    "callee:clobbers-r9-before-exit",
    "div32:divisor-0x80000000",
    "budget:call-in-loop",
    "budget:fault-in-callee",
];

/// The mark id of a named class.
pub fn named(name: &str) -> u16 {
    256 + NAMED
        .iter()
        .position(|n| *n == name)
        .unwrap_or_else(|| panic!("no class {name}")) as u16
}

/// The address of instruction-data parameter `k` (`0..8`): after the region's 8-byte account count,
/// the 8-byte data length and the 8-byte selector.
pub fn param(k: u64) -> u64 {
    REGION_INPUT + 24 + 8 * k
}
/// The 64 raw bytes after the parameters.
const RAW: u64 = REGION_INPUT + 24 + 64;
/// The instruction data: selector, eight parameters, 64 raw bytes.
pub const DATA_LEN: usize = 8 + 64 + 64;

/// The input region a case runs over: `serialize_aligned(&[], data, &[7; 32])`.
pub fn input_region(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(&[7u8; 32]);
    out
}
/// Its length for a case's data.
pub const INPUT_LEN: u64 = 16 + DATA_LEN as u64 + 32;

/// SplitMix64: a fixed stream, so a seed is a program forever.
#[derive(Clone)]
pub struct Mix(pub u64);
impl Mix {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    pub fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }
    pub fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[self.below(xs.len() as u64) as usize]
    }
}

/// One generated case.
#[derive(Clone, Debug)]
pub struct Case {
    pub seed: u64,
    pub items: Vec<It>,
    /// The instruction data ([`DATA_LEN`] bytes; the selector is 0).
    pub data: Vec<u8>,
    /// A budget case: parameter 0 is the trip count of a loop the fuzzer sizes so the run lands
    /// near the instruction limit.
    pub budget: bool,
}

pub fn ins(opc: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
    Insn {
        opc,
        dst,
        src,
        off,
        imm,
    }
}

/// Assembles `items` for a text at `text_va`: the text, and where each label landed.
pub fn assemble(items: &[It], text_va: u64) -> (Vec<u8>, HashMap<Label, usize>) {
    let mut at: HashMap<Label, usize> = HashMap::new();
    let mut pc = 0;
    for it in items {
        match it {
            It::L(l) => assert!(at.insert(*l, pc).is_none(), "label {l} twice"),
            It::LddwSplit { label, .. } => {
                assert!(at.insert(*label, pc + 1).is_none(), "label {label} twice");
                pc += 2
            }
            It::Lddw(..) | It::Addr(..) | It::AddrEnd(..) => pc += 2,
            _ => pc += 1,
        }
    }
    let n_slots = pc;
    let rel = |to: Label, pc: usize| at[&to] as i64 - (pc as i64 + 1);
    let lddw = |d: u8, v: u64| {
        [
            ins(opc::LD_DW_IMM, d, 0, 0, v as u32 as i32),
            ins(0, 0, 0, 0, (v >> 32) as u32 as i32),
        ]
    };
    let mut out: Vec<Insn> = Vec::with_capacity(n_slots);
    for it in items {
        let pc = out.len();
        match it {
            It::I(i) => out.push(*i),
            It::Lddw(d, v) => out.extend(lddw(*d, *v)),
            It::J {
                opc,
                dst,
                src,
                imm,
                to,
            } => out.push(ins(*opc, *dst, *src, rel(*to, pc) as i16, *imm)),
            It::Call(to) => out.push(ins(opc::CALL_IMM, 0, 0, 0, rel(*to, pc) as i32)),
            It::Addr(d, to, delta) => out.extend(lddw(
                *d,
                (text_va + 8 * at[to] as u64).wrapping_add(*delta as u64),
            )),
            It::AddrEnd(d, delta) => out.extend(lddw(
                *d,
                (text_va + 8 * n_slots as u64).wrapping_add(*delta as u64),
            )),
            It::LddwSplit { dst, lo, hi, .. } => {
                out.push(ins(opc::LD_DW_IMM, *dst, 0, 0, *lo));
                out.push(*hi);
            }
            It::L(_) => {}
        }
    }
    let text = out
        .iter()
        .flat_map(|i| isa::encode(*i).to_le_bytes())
        .collect();
    (text, at)
}

/// Every labelled item's labels shifted into `ns << 32`, so several cases' items can share one text.
/// Label 0 (the text's first slot) stays the *shared* text's first slot, and the case's own `L(0)`
/// is dropped.
pub fn relabel(items: &[It], ns: u64) -> Vec<It> {
    let f = |l: Label| if l == 0 { 0 } else { l | (ns << 32) };
    items
        .iter()
        .filter(|it| !matches!(it, It::L(0)))
        .map(|it| match it.clone() {
            It::J {
                opc,
                dst,
                src,
                imm,
                to,
            } => It::J {
                opc,
                dst,
                src,
                imm,
                to: f(to),
            },
            It::Call(to) => It::Call(f(to)),
            It::Addr(d, to, delta) => It::Addr(d, f(to), delta),
            It::L(l) => It::L(f(l)),
            It::LddwSplit { dst, lo, hi, label } => It::LddwSplit {
                dst,
                lo,
                hi,
                label: f(label),
            },
            other => other,
        })
        .collect()
}

// ---- the opcode tables ----------------------------------------------------------------------------

/// Every ALU opcode but `le`/`be` and division, which [`Gen::alu`] generates itself.
#[rustfmt::skip]
const ALU: &[u8] = &[
    opc::ADD32_IMM, opc::ADD32_REG, opc::SUB32_IMM, opc::SUB32_REG,
    opc::MUL32_IMM, opc::MUL32_REG, opc::OR32_IMM, opc::OR32_REG,
    opc::AND32_IMM, opc::AND32_REG, opc::LSH32_IMM, opc::LSH32_REG,
    opc::RSH32_IMM, opc::RSH32_REG, opc::NEG32, opc::XOR32_IMM,
    opc::XOR32_REG, opc::MOV32_IMM, opc::MOV32_REG, opc::ARSH32_IMM,
    opc::ARSH32_REG, opc::ADD64_IMM, opc::ADD64_REG, opc::SUB64_IMM,
    opc::SUB64_REG, opc::MUL64_IMM, opc::MUL64_REG, opc::OR64_IMM,
    opc::OR64_REG, opc::AND64_IMM, opc::AND64_REG, opc::LSH64_IMM,
    opc::LSH64_REG, opc::RSH64_IMM, opc::RSH64_REG, opc::NEG64,
    opc::XOR64_IMM, opc::XOR64_REG, opc::MOV64_IMM, opc::MOV64_REG,
    opc::ARSH64_IMM, opc::ARSH64_REG,
];
#[rustfmt::skip]
const DIV: &[u8] = &[
    opc::DIV32_IMM, opc::DIV32_REG, opc::MOD32_IMM, opc::MOD32_REG,
    opc::DIV64_IMM, opc::DIV64_REG, opc::MOD64_IMM, opc::MOD64_REG,
];
#[rustfmt::skip]
const JCC: &[u8] = &[
    opc::JEQ_IMM, opc::JEQ_REG, opc::JGT_IMM, opc::JGT_REG,
    opc::JGE_IMM, opc::JGE_REG, opc::JLT_IMM, opc::JLT_REG,
    opc::JLE_IMM, opc::JLE_REG, opc::JSET_IMM, opc::JSET_REG,
    opc::JNE_IMM, opc::JNE_REG, opc::JSGT_IMM, opc::JSGT_REG,
    opc::JSGE_IMM, opc::JSGE_REG, opc::JSLT_IMM, opc::JSLT_REG,
    opc::JSLE_IMM, opc::JSLE_REG,
];
/// `(ldx, st imm, stx, width)`.
const MEM: [(u8, u8, u8, i64); 4] = [
    (opc::LD_B_REG, opc::ST_B_IMM, opc::ST_B_REG, 1),
    (opc::LD_H_REG, opc::ST_H_IMM, opc::ST_H_REG, 2),
    (opc::LD_W_REG, opc::ST_W_IMM, opc::ST_W_REG, 4),
    (opc::LD_DW_REG, opc::ST_DW_IMM, opc::ST_DW_REG, 8),
];
/// SBPF v2's product/quotient/remainder class, `hor64`, and a few other bytes v1 does not assign.
const NOT_V1: &[u8] = &[
    0x36, 0x3e, 0x46, 0x4e, 0x56, 0x5e, 0x66, 0x6e, 0x76, 0x7e, 0x86, 0x8e, 0x96, 0x9e, 0xb6, 0xbe,
    0xc6, 0xce, 0xd6, 0xde, 0xe6, 0xee, 0xf6, 0xfe, 0xf7, 0x8c, 0x00, 0xff, 0x06, 0x0e,
];

#[rustfmt::skip]
const IMMS: &[i32] = &[
    0, 1, -1, 2, 3, 7, 8, 15,
    16, 31, 32, 33, 63, 64, 65, 127,
    255, 0x7fff, -0x8000, 0x1234_5678, i32::MAX, i32::MIN, -2,
];

// ---- the generator ------------------------------------------------------------------------------

/// A planned terminal event.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Terminal {
    AvOutOfRegion,
    AvStraddleStack,
    AvStraddleHeap,
    AvStraddleInput,
    AvStraddleText,
    AvBelowStack,
    AvStoreProgram,
    AvSyscall,
    DivRegZero,
    DivImmZero,
    BadLeBe,
    NotV1,
    BadRegister,
    CallxBadRegister,
    UnknownSyscall,
    Abort,
    Panic,
    MemcpyOverlap,
    CallDepth,
    CallxNonCode,
    CallxPad,
    JumpOutOfText,
    CallOutOfText,
    CallImmBadSrc,
    /// A `call` in the text's last slot: the callee's `exit` cannot fetch the return slot.
    EndCall,
    /// An `lddw` whose first slot is the text's last.
    EndLddw,
    /// Running off the end of the text.
    EndFallOff,
    /// A jump into an `lddw`'s second slot, which holds an unassigned opcode.
    IntoLddwBad,
}

const TERMINALS: &[Terminal] = &[
    Terminal::AvOutOfRegion,
    Terminal::AvStraddleStack,
    Terminal::AvStraddleHeap,
    Terminal::AvStraddleInput,
    Terminal::AvStraddleText,
    Terminal::AvBelowStack,
    Terminal::AvStoreProgram,
    Terminal::AvSyscall,
    Terminal::DivRegZero,
    Terminal::DivImmZero,
    Terminal::BadLeBe,
    Terminal::NotV1,
    Terminal::BadRegister,
    Terminal::CallxBadRegister,
    Terminal::UnknownSyscall,
    Terminal::Abort,
    Terminal::Panic,
    Terminal::MemcpyOverlap,
    Terminal::CallDepth,
    Terminal::CallxNonCode,
    Terminal::CallxPad,
    Terminal::JumpOutOfText,
    Terminal::CallOutOfText,
    Terminal::CallImmBadSrc,
    Terminal::EndCall,
    Terminal::EndLddw,
    Terminal::EndFallOff,
    Terminal::IntoLddwBad,
];

struct Func {
    entry: Label,
    member: Option<Label>,
    /// The register a callee's arg-through-store prologue reads (its caller may set it first).
    arg: Option<u8>,
    /// A member placed inside a loop: the loop's counter, which its caller sets (small) first.
    counter: Option<u8>,
}

struct Gen {
    r: Mix,
    out: Vec<It>,
    next: Label,
    /// Registers a body must not write: the loop counters of every enclosing loop.
    locked: u16,
    /// Control nesting (ifs and loops).
    depth: usize,
    /// How many enclosing loops.
    loops: usize,
    /// Which function is being generated: 0 is main.
    cur: usize,
    funcs: Vec<Func>,
    rec: Label,
    pad: Label,
    /// `main`'s frame: whether `r10` may be moved here (balanced moves only in main).
    in_main: bool,
    /// The text's last item, reached by a jump from a terminal: its label and what it is.
    end: Option<(Label, Terminal)>,
    /// Extra functions a budget case calls: label, and whether the planned fault is in it.
    helpers: Vec<(Label, bool)>,
    /// A member still to be placed inside the next top-level loop of the current function.
    member_in_loop: Option<Label>,
    /// A function that is one `lddw` and an `exit`, and the label of that `lddw`'s second slot.
    split: (Label, Label),
    /// [`Gen::dst`] handed out `r9`, the coverage base, since the last [`Gen::settle`].
    r9_dirty: bool,
}

impl Gen {
    fn label(&mut self) -> Label {
        self.next += 1;
        self.next
    }
    fn i(&mut self, opc: u8, dst: u8, src: u8, off: i16, imm: i32) {
        self.out.push(It::I(ins(opc, dst, src, off, imm)));
    }
    fn mark(&mut self, id: u16) {
        self.settle();
        // `stb [r9 + id], 1`.
        self.i(opc::ST_B_IMM, 9, 0, id as i16, 1);
    }
    /// If a body may have written `r9` since the last call: store what it holds to the scratch
    /// frame (so the write is observable — `main` folds its frame into `r0`), then load the
    /// coverage base back. Emitted before every mark, at the start of every chunk and terminal and
    /// after an `lddw` pair a jump may land inside, so no jump, call, `exit` or mark is ever
    /// emitted while `r9` may be something else: every path into a mark passes through a settle.
    fn settle(&mut self) {
        if self.r9_dirty {
            self.r9_dirty = false;
            self.i(opc::ST_DW_REG, 10, 9, -496, 0);
            self.out.push(It::Lddw(9, MARK_BASE));
            self.mark(named("r9:written"));
        }
    }
    fn mark_named(&mut self, name: &str) {
        self.mark(named(name));
    }
    fn imm(&mut self) -> i32 {
        if self.r.chance(1, 4) {
            self.r.next() as i32
        } else {
            self.r.pick(IMMS)
        }
    }
    /// A register a body may write: `r0..r9`, minus the locked ones (the loop counters; a budget
    /// case also locks `r9`). `r9` is the coverage base, so handing it out leaves it to be
    /// [`Gen::settle`]d before the next mark.
    fn dst(&mut self) -> u8 {
        loop {
            let d = self.r.below(10) as u8;
            if self.locked & (1 << d) == 0 {
                self.r9_dirty |= d == 9;
                return d;
            }
        }
    }
    /// [`Gen::dst`] without `r9`: a `callx` register, whose callee reads `r9` as its coverage
    /// base before anything could settle it.
    fn dst_below9(&mut self) -> u8 {
        loop {
            let d = self.r.below(9) as u8;
            if self.locked & (1 << d) == 0 {
                return d;
            }
        }
    }
    /// Any register, `r0..r10`.
    fn src(&mut self) -> u8 {
        self.r.below(11) as u8
    }

    fn alu(&mut self) {
        let roll = self.r.below(20);
        if roll < 2 {
            // Division: by a non-zero immediate, or by a register behind a zero guard.
            let o = self.r.pick(DIV);
            let d = self.dst();
            if o & 0x08 == 0 {
                let mut k = self.imm();
                if k == 0 {
                    k = 3;
                }
                self.i(o, d, 0, 0, k);
            } else if o & 0x07 == 0x04 && self.r.chance(1, 3) {
                // A 32-bit divisor whose low half is exactly bit 31 — the value the guard below
                // skips — set right here, so it runs unguarded.
                let s = self.dst();
                let v = self.r.pick(&[
                    0x8000_0000u64,
                    0xffff_ffff_8000_0000,
                    0x1_8000_0000,
                    0x8000_0000_8000_0000,
                ]);
                self.out.push(It::Lddw(s, v));
                self.i(o, d, s, 0, 0);
                self.mark(o as u16);
                self.mark_named("div32:divisor-0x80000000");
                return;
            } else {
                let s = self.src();
                let skip = self.label();
                // A 32-bit divisor is its low half: divide only when one of its low 31 bits is set
                // (a divisor with only bit 31 set is skipped here; the branch above runs it).
                if o & 0x07 == 0x04 {
                    let go = self.label();
                    self.out.push(It::J {
                        opc: opc::JSET_IMM,
                        dst: s,
                        src: 0,
                        imm: 0x7fff_ffff,
                        to: go,
                    });
                    self.out.push(It::J {
                        opc: opc::JA,
                        dst: 0,
                        src: 0,
                        imm: 0,
                        to: skip,
                    });
                    self.out.push(It::L(go));
                } else {
                    self.out.push(It::J {
                        opc: opc::JEQ_IMM,
                        dst: s,
                        src: 0,
                        imm: 0,
                        to: skip,
                    });
                }
                self.i(o, d, s, 0, 0);
                self.mark(o as u16);
                self.mark_named("div:guarded-reg");
                self.out.push(It::L(skip));
                return;
            }
            self.mark(o as u16);
        } else if roll < 4 {
            let (o, w) = if self.r.chance(1, 2) {
                (opc::LE, "le")
            } else {
                (opc::BE, "be")
            };
            let k = self.r.pick(&[16, 32, 64]);
            let d = self.dst();
            self.i(o, d, 0, 0, k);
            self.mark(o as u16);
            self.mark_named(&format!("{w}{k}"));
        } else if roll < 5 {
            let d = self.dst();
            let v = if self.r.chance(1, 2) {
                self.r.next()
            } else {
                self.r.pick(&[
                    0,
                    u64::MAX,
                    1 << 63,
                    0xffff_ffff,
                    0x1_0000_0000,
                    REGION_STACK,
                    REGION_HEAP + 8,
                ])
            };
            self.out.push(It::Lddw(d, v));
            self.mark(opc::LD_DW_IMM as u16);
        } else {
            let o = self.r.pick(ALU);
            let d = self.dst();
            let is_reg = o & 0x08 != 0;
            let s = if is_reg { self.src() } else { 0 };
            let k = if is_reg || matches!(o, opc::NEG32 | opc::NEG64) {
                0
            } else {
                self.imm()
            };
            self.i(o, d, s, 0, k);
            self.mark(o as u16);
        }
    }

    /// A load or store of every width into one of the regions, always in bounds.
    fn mem(&mut self) {
        let (ld, st, stx, w) = self.r.pick(&MEM);
        let kind = self.r.below(10);
        // (base register, offset, may store, class)
        let (base, off, store_ok, class) = if kind < 5 {
            // The scratch frame: r10 - 512 .. r10.
            let off = -(self.r.below(512 - w as u64 + 1) as i64) - w;
            (10u8, off, true, "mem:stack")
        } else {
            let t = self.dst();
            let (addr, span, store_ok, class) = match kind {
                5 | 6 => (HEAP_TRAFFIC, HEAP_SPAN, true, "mem:heap"),
                7 | 8 => (RAW - 64, 128, true, "mem:input"),
                _ => (0, 64, false, "mem:program"),
            };
            let at = self.r.below(span - w as u64 + 1);
            // Split the address between the base and the offset, either way round.
            let off = self.r.below(at + 1).min(0x7fff) as i64;
            if class == "mem:program" {
                self.out.push(It::Addr(t, 0, (at as i64) - off));
            } else {
                self.out.push(It::Lddw(t, addr + at - off as u64));
            }
            (t, off, store_ok, class)
        };
        let o = match self.r.below(3) {
            0 if store_ok => {
                let v = self.imm();
                self.i(st, base, 0, off as i16, v);
                st
            }
            1 if store_ok => {
                let s = self.src();
                self.i(stx, base, s, off as i16, 0);
                stx
            }
            _ => {
                let d = self.dst();
                self.i(ld, d, base, off as i16, 0);
                ld
            }
        };
        self.mark(o as u16);
        self.mark_named(class);
    }

    fn cond(&mut self) -> (u8, u8, u8, i32) {
        let o = self.r.pick(JCC);
        let d = self.src();
        if o & 0x08 != 0 {
            (o, d, self.src(), 0)
        } else {
            (o, d, 0, self.imm())
        }
    }

    fn if_(&mut self, budget: &mut usize) {
        let (o, d, s, k) = self.cond();
        self.mark(o as u16);
        let else_ = self.label();
        self.out.push(It::J {
            opc: o,
            dst: d,
            src: s,
            imm: k,
            to: else_,
        });
        self.depth += 1;
        let n = 1 + self.r.below(4) as usize;
        self.body(n, budget);
        if self.r.chance(1, 2) {
            let end = self.label();
            self.mark(opc::JA as u16);
            self.out.push(It::J {
                opc: opc::JA,
                dst: 0,
                src: 0,
                imm: 0,
                to: end,
            });
            self.out.push(It::L(else_));
            let n = 1 + self.r.below(3) as usize;
            self.body(n, budget);
            self.out.push(It::L(end));
            self.mark_named("if-else");
        } else {
            self.out.push(It::L(else_));
            self.mark_named("if");
        }
        self.depth -= 1;
    }

    fn loop_(&mut self, budget: &mut usize) {
        let free: Vec<u8> = [6u8, 7, 8]
            .into_iter()
            .filter(|r| self.locked & (1 << r) == 0)
            .collect();
        if free.is_empty() {
            return self.alu();
        }
        let c = match (self.depth, self.member_in_loop) {
            (0, Some(_)) => self.funcs[self.cur].counter.unwrap(),
            _ => self.r.pick(&free),
        };
        let from_input = self.r.chance(1, 2);
        if from_input {
            let k = self.r.below(8);
            self.out.push(It::Lddw(c, param(k)));
            self.i(opc::LD_DW_REG, c, c, 0, 0);
            self.i(opc::AND64_IMM, c, 0, 0, 3);
            self.i(opc::ADD64_IMM, c, 0, 0, 1);
        } else {
            let n = 1 + self.r.below(if self.loops > 0 { 3 } else { 5 }) as i32;
            self.i(opc::MOV64_IMM, c, 0, 0, n);
        }
        let head = self.label();
        self.out.push(It::L(head));
        if self.depth == 0 {
            if let Some(m) = self.member_in_loop.take() {
                self.out.push(It::L(m));
            }
        }
        self.locked |= 1 << c;
        self.depth += 1;
        self.loops += 1;
        let n = 1 + self.r.below(4) as usize;
        self.body(n, budget);
        self.loops -= 1;
        self.depth -= 1;
        self.locked &= !(1 << c);
        self.mark_named(if from_input {
            "loop:trip-from-input"
        } else {
            "loop"
        });
        match self.r.below(3) {
            0 => {
                self.i(opc::SUB64_IMM, c, 0, 0, 1);
                self.mark(opc::JNE_IMM as u16);
                self.out.push(It::J {
                    opc: opc::JNE_IMM,
                    dst: c,
                    src: 0,
                    imm: 0,
                    to: head,
                });
            }
            1 => {
                self.i(opc::ADD64_IMM, c, 0, 0, -1);
                self.mark(opc::JSGT_IMM as u16);
                self.out.push(It::J {
                    opc: opc::JSGT_IMM,
                    dst: c,
                    src: 0,
                    imm: 0,
                    to: head,
                });
            }
            _ => {
                self.i(opc::SUB32_IMM, c, 0, 0, 1);
                self.mark(opc::JGT_IMM as u16);
                self.out.push(It::J {
                    opc: opc::JGT_IMM,
                    dst: c,
                    src: 0,
                    imm: 0,
                    to: head,
                });
            }
        }
    }

    /// Sets a callee's argument register first (sometimes) so its arg-through-store prologue reads a
    /// value the caller chose.
    fn set_arg(&mut self, f: usize) {
        if let Some(a) = self.funcs[f].arg {
            if self.r.chance(2, 3) && self.locked & (1 << a) == 0 {
                let v = self.r.next();
                self.out.push(It::Lddw(a, v));
            }
        }
    }

    /// After a call: store some of r0..r5 to the scratch frame, so what came back is observable.
    fn after_call(&mut self) {
        if self.r.chance(1, 2) {
            for r in 0..6u8 {
                if self.r.chance(1, 2) {
                    self.i(opc::ST_DW_REG, 10, r, -8 * (1 + r as i16) - 256, 0);
                }
            }
        }
    }

    fn call(&mut self) {
        let callees: Vec<usize> = (self.cur + 1..self.funcs.len()).collect();
        if callees.is_empty() {
            return self.alu();
        }
        if self.r.chance(1, 12) {
            // Into the one-`lddw` function, at the pair or at its second slot.
            let (whole, hi) = self.split;
            let into = self.r.chance(1, 2);
            if self.r.chance(1, 2) {
                self.out.push(It::Call(if into { hi } else { whole }));
            } else {
                let t = self.dst_below9();
                self.out.push(It::Addr(t, if into { hi } else { whole }, 0));
                self.i(opc::CALL_REG, 0, 0, 0, t as i32);
            }
            if into {
                self.mark_named("call:into-lddw-second-slot");
            }
            self.after_call();
            return;
        }
        let f = self.r.pick(&callees);
        self.set_arg(f);
        let mut to_member = self.funcs[f].member.is_some() && self.r.chance(1, 3);
        if to_member {
            if let Some(c) = self.funcs[f].counter {
                // The member is a loop's head: the caller hands it a small count, which it can
                // only do outside a loop of its own (the counter may be one of its own).
                if self.loops == 0 {
                    let n = 1 + self.r.below(3) as i32;
                    self.i(opc::MOV64_IMM, c, 0, 0, n);
                    self.mark_named("call:member-inside-a-loop");
                } else {
                    to_member = false;
                }
            }
        }
        match self.r.below(5) {
            0..=2 => {
                let to = if to_member {
                    self.funcs[f].member.unwrap()
                } else {
                    self.funcs[f].entry
                };
                self.out.push(It::Call(to));
                self.mark(opc::CALL_IMM as u16);
                self.mark_named(if to_member { "call:member" } else { "call" });
            }
            _ => {
                let t = self.dst_below9();
                let to = if to_member {
                    self.funcs[f].member.unwrap()
                } else {
                    self.funcs[f].entry
                };
                let unaligned = !to_member && self.r.chance(1, 3);
                let delta = if unaligned {
                    1 + self.r.below(7) as i64
                } else {
                    0
                };
                self.out.push(It::Addr(t, to, delta));
                self.i(opc::CALL_REG, 0, 0, 0, t as i32);
                self.mark(opc::CALL_REG as u16);
                self.mark_named(if to_member {
                    "callx:member"
                } else if unaligned {
                    "callx:unaligned"
                } else {
                    "callx:entry"
                });
            }
        }
        self.after_call();
    }

    fn recursion(&mut self) {
        // r1 = depth below this call: small, or from the input.
        let n = self.r.below(6) as i32;
        self.i(opc::MOV64_IMM, 1, 0, 0, n);
        self.out.push(It::Call(self.rec));
        self.mark_named("recursion:returned");
        if n >= 4 {
            self.mark_named("recursion:depth>=5");
        }
        self.after_call();
    }

    /// `mov rd, r10; add rd, -off`.
    fn frame_ptr(&mut self, d: u8, off: i32) {
        self.i(opc::MOV64_REG, d, 10, 0, 0);
        self.i(opc::ADD64_IMM, d, 0, 0, -off);
    }

    fn syscall(&mut self) {
        use syscalls::*;
        let pick = self.r.below(10);
        let (hash, name) = match pick {
            0 => {
                let off = 32 + self.r.below(400) as i32;
                self.frame_ptr(1, off);
                let n = self.r.below(off as u64 + 1) as i32;
                self.i(opc::MOV64_IMM, 2, 0, 0, n);
                (SOL_LOG, "sol_log_")
            }
            1 => {
                for r in 1..6 {
                    let v = self.imm();
                    self.i(opc::MOV64_IMM, r, 0, 0, v);
                }
                if self.r.chance(1, 2) {
                    (SOL_LOG_64, "sol_log_64_")
                } else {
                    (SOL_LOG_COMPUTE_UNITS, "sol_log_compute_units_")
                }
            }
            2 => {
                let off = 32 + self.r.below(400) as i32;
                self.frame_ptr(1, off);
                (SOL_LOG_PUBKEY, "sol_log_pubkey")
            }
            3 | 4 => {
                // dst and src 64 bytes apart in the frame (memmove: anywhere, overlapping or not),
                // or src in the heap / instruction data / text.
                let n = self.r.below(65) as i32;
                let a = 64 + self.r.below(192) as i32;
                self.frame_ptr(1, a);
                let memmove = pick == 4;
                match self.r.below(4) {
                    0 => self
                        .out
                        .push(It::Lddw(2, HEAP_TRAFFIC + self.r.below(1024))),
                    1 => self.out.push(It::Lddw(2, RAW - 64)),
                    2 => self.out.push(It::Addr(2, 0, self.r.below(32) as i64)),
                    _ => {
                        let b = if memmove {
                            a + self.r.below(80) as i32 - 40
                        } else if self.r.chance(1, 2) {
                            a + 64
                        } else {
                            a - 64
                        };
                        self.frame_ptr(2, b.max(0));
                    }
                }
                self.i(opc::MOV64_IMM, 3, 0, 0, n);
                if memmove {
                    (SOL_MEMMOVE, "sol_memmove_")
                } else {
                    (SOL_MEMCPY, "sol_memcpy_")
                }
            }
            5 => {
                let a = 64 + self.r.below(400) as i32;
                self.frame_ptr(1, a);
                let v = self.imm();
                self.i(opc::MOV64_IMM, 2, 0, 0, v);
                let n = self.r.below(65) as i32;
                self.i(opc::MOV64_IMM, 3, 0, 0, n);
                (SOL_MEMSET, "sol_memset_")
            }
            6 => {
                let a = 64 + self.r.below(300) as i32;
                let b = 64 + self.r.below(300) as i32;
                self.frame_ptr(1, a);
                if self.r.chance(1, 3) {
                    self.out.push(It::Lddw(2, RAW - 64));
                } else {
                    self.frame_ptr(2, b);
                }
                let n = self.r.below(65) as i32;
                self.i(opc::MOV64_IMM, 3, 0, 0, n);
                let o = 8 + 4 * self.r.below(8) as i32;
                self.frame_ptr(4, o);
                (SOL_MEMCMP, "sol_memcmp_")
            }
            7 => {
                let size = self.r.below(257) as i32;
                self.i(opc::MOV64_IMM, 1, 0, 0, size);
                let free = self.r.chance(1, 5);
                self.i(opc::MOV64_IMM, 2, 0, 0, free as i32);
                self.out
                    .push(It::I(ins(opc::CALL_IMM, 0, 1, 0, SOL_ALLOC_FREE as i32)));
                self.mark(opc::CALL_IMM as u16);
                self.mark_named("sys:sol_alloc_free_");
                // Use the block (a null pointer faults, as it should).
                if !free && size >= 8 && self.r.chance(2, 3) {
                    let (ld, _, stx, w) = self.r.pick(&MEM);
                    let off = self.r.below(size as u64 - w as u64 + 1) as i16;
                    let s = self.src();
                    let d = self.r.below(5) as u8 + 1;
                    self.i(opc::MOV64_REG, d, 0, 0, 0);
                    self.i(stx, d, s, off, 0);
                    let d2 = self.dst();
                    self.i(ld, d2, d, off, 0);
                    self.mark_named("mem:alloc");
                }
                return;
            }
            8 => {
                // Two (ptr, len) pairs at r10-200: the frame's r10-128.. and the instruction data.
                self.frame_ptr(1, 128);
                self.i(opc::ST_DW_REG, 10, 1, -200, 0);
                let n0 = self.r.below(65) as i32;
                self.i(opc::ST_DW_IMM, 10, 0, -192, n0);
                self.out.push(It::Lddw(1, RAW - 64));
                self.i(opc::ST_DW_REG, 10, 1, -184, 0);
                let n1 = self.r.below(129) as i32;
                self.i(opc::ST_DW_IMM, 10, 0, -176, n1);
                self.frame_ptr(1, 200);
                let pairs = self.r.below(3) as i32;
                self.i(opc::MOV64_IMM, 2, 0, 0, pairs);
                let o = 40 + self.r.below(32) as i32;
                self.frame_ptr(3, o);
                (SOL_SHA256, "sol_sha256")
            }
            _ => {
                for r in 1..6 {
                    let v = self.imm();
                    self.i(opc::MOV64_IMM, r, 0, 0, v);
                }
                (SOL_LOG_64, "sol_log_64_")
            }
        };
        self.out
            .push(It::I(ins(opc::CALL_IMM, 0, 1, 0, hash as i32)));
        self.mark(opc::CALL_IMM as u16);
        self.mark_named(&format!("sys:{name}"));
    }

    fn r10_write(&mut self, budget: &mut usize) {
        if self.in_main {
            // Balanced: move the frame pointer, run a little, move it back.
            let k = 8 * (1 + self.r.below(32) as i32) * if self.r.chance(1, 2) { 1 } else { -1 };
            self.i(opc::ADD64_IMM, 10, 0, 0, k);
            self.mark_named("r10:write-balanced");
            let n = 1 + self.r.below(3) as usize;
            self.body(n, budget);
            self.i(opc::ADD64_IMM, 10, 0, 0, -k);
        } else {
            // A callee moves its frame and returns without restoring it: `exit` must.
            if self.r.chance(1, 2) {
                let k = 8 * (1 + self.r.below(64) as i32);
                self.i(opc::ADD64_IMM, 10, 0, 0, -k);
            } else {
                let s = self.src();
                self.i(opc::MOV64_REG, 10, s, 0, 0);
            }
            self.mark_named("r10:write-callee-unrestored");
            self.mark_named("exit:callee");
            self.mark_named("exit:early");
            self.i(opc::EXIT, 0, 0, 0, 0);
        }
    }

    /// `n` chunks. `budget` is how many more nested control structures this function may open.
    fn body(&mut self, n: usize, budget: &mut usize) {
        for _ in 0..n {
            self.settle();
            let roll = self.r.below(100);
            let control_ok = self.depth < 3 && *budget > 0;
            match roll {
                0..=34 => self.alu(),
                35..=56 => self.mem(),
                57..=64 if control_ok => {
                    *budget -= 1;
                    self.if_(budget)
                }
                65..=69 if control_ok && self.loops < 2 => {
                    *budget -= 1;
                    self.loop_(budget)
                }
                70..=78 => self.call(),
                79..=80 if self.loops == 0 => self.recursion(),
                81..=89 => self.syscall(),
                // In main a balanced move anywhere; in a callee an unrestored one, then `exit`, inside
                // an `if` (so the rest of the callee still runs on the other path).
                90..=91 if self.in_main || self.depth > 0 => self.r10_write(budget),
                92..=93 if self.depth > 0 => {
                    if !self.in_main {
                        self.mark_named("exit:callee");
                    }
                    self.mark_named("exit:early");
                    self.i(opc::EXIT, 0, 0, 0, 0);
                }
                94..=95 => self.jump_into_lddw(),
                96..=98
                    if self.loops == 0
                        && self.cur > 0
                        && self.funcs[self.cur].member.is_some()
                        && self.funcs[self.cur].counter.is_none()
                        && self.member_in_loop.is_none() =>
                {
                    // Into this function's own member: recursion through a merged entry, which ends
                    // at CallDepth at the latest.
                    let m = self.funcs[self.cur].member.unwrap();
                    self.out.push(It::Call(m));
                    self.mark_named("call:own-member");
                    self.after_call();
                }
                _ => self.alu(),
            }
        }
    }

    /// The one planned terminal event, where it stands.
    fn terminal(&mut self, t: Terminal) {
        use Terminal::*;
        self.settle();
        let d = self.dst();
        match t {
            AvOutOfRegion => {
                let a = self
                    .r
                    .pick(&[0u64, 8, 0x5_0000_0000, 0xffff_ffff_ffff_fff8, MAGIC + 8]);
                self.out.push(It::Lddw(d, a));
                let (ld, st, _, _) = self.r.pick(&MEM);
                if self.r.chance(1, 2) {
                    self.i(ld, 0, d, 0, 0)
                } else {
                    self.i(st, d, 0, 0, 1)
                }
            }
            AvStraddleStack | AvStraddleHeap | AvStraddleInput | AvStraddleText => {
                let (ld, st, stx, w) = self.r.pick(&MEM[1..]);
                let over = 1 + self.r.below(w as u64 - 1) as i64; // bytes past the end
                let split = self.r.below(64) as i64;
                match t {
                    AvStraddleText => {
                        // A load (the text is read-only).
                        self.out.push(It::AddrEnd(d, over - w - split));
                        self.i(ld, 0, d, split as i16, 0);
                        return;
                    }
                    _ => {
                        let end = match t {
                            AvStraddleStack => REGION_STACK + STACK_BYTES as u64,
                            AvStraddleHeap => REGION_HEAP + HEAP_BYTES as u64,
                            _ => REGION_INPUT + INPUT_LEN,
                        };
                        let at = end - (w - over) as u64;
                        self.out.push(It::Lddw(d, at - split as u64));
                    }
                }
                match self.r.below(3) {
                    0 => self.i(ld, 0, d, split as i16, 0),
                    1 => self.i(st, d, 0, split as i16, 7),
                    _ => self.i(stx, d, 1, split as i16, 0),
                }
            }
            AvBelowStack => {
                // Width 1 half the time: a byte cannot straddle, so this is where most one-byte
                // faults come from.
                let (ld, _, _, w) = if self.r.chance(1, 2) {
                    MEM[0]
                } else {
                    self.r.pick(&MEM)
                };
                self.out.push(It::Lddw(d, REGION_STACK));
                let off = -(w as i16) + self.r.below(w as u64) as i16;
                self.i(ld, 0, d, off, 0);
            }
            AvStoreProgram => {
                let (_, st, _, _) = if self.r.chance(1, 2) {
                    MEM[0]
                } else {
                    self.r.pick(&MEM)
                };
                // text_va + 9: not 8-aligned, so not a function root.
                self.out.push(It::Addr(d, 0, 1));
                self.i(st, d, 0, 8, 1);
            }
            AvSyscall => {
                // A pointer argument no region holds.
                self.i(opc::MOV64_IMM, 1, 0, 0, 16);
                self.i(opc::MOV64_IMM, 2, 0, 0, 8);
                self.i(opc::MOV64_IMM, 3, 0, 0, 8);
                self.out.push(It::I(ins(
                    opc::CALL_IMM,
                    0,
                    1,
                    0,
                    syscalls::SOL_MEMCMP as i32,
                )));
            }
            DivRegZero => {
                let o = self.r.pick(&[
                    opc::DIV32_REG,
                    opc::MOD32_REG,
                    opc::DIV64_REG,
                    opc::MOD64_REG,
                ]);
                let s = self.dst();
                if o & 0x07 == 0x04 {
                    // A 32-bit divisor: zero in its low half only.
                    self.out.push(It::Lddw(s, 0x7_0000_0000));
                } else {
                    self.i(opc::MOV64_IMM, s, 0, 0, 0);
                }
                self.i(o, d, s, 0, 0);
            }
            DivImmZero => {
                let o = self.r.pick(&[
                    opc::DIV32_IMM,
                    opc::MOD32_IMM,
                    opc::DIV64_IMM,
                    opc::MOD64_IMM,
                ]);
                self.i(o, d, 0, 0, 0);
            }
            BadLeBe => {
                let o = self.r.pick(&[opc::LE, opc::BE]);
                let k = self.r.pick(&[0, 1, 8, 24, 48, 63, 65, 128, -16]);
                self.i(o, d, 0, 0, k);
            }
            NotV1 => {
                let o = self.r.pick(NOT_V1);
                let s = self.src();
                let k = self.imm();
                self.i(o, d, s, 0, k);
            }
            BadRegister => {
                // A nibble above r10, as dst or as src, on an otherwise good instruction.
                let o = self
                    .r
                    .pick(&[opc::MOV64_REG, opc::ADD32_IMM, opc::LD_DW_REG, opc::EXIT]);
                let bad = 11 + self.r.below(5) as u8;
                if self.r.chance(1, 2) {
                    self.i(o, bad, 1, 0, 0)
                } else {
                    self.i(o, 1, bad, 0, 0)
                }
            }
            CallxBadRegister => {
                let k = 11 + self.r.below(20) as i32;
                self.i(opc::CALL_REG, 0, 0, 0, k);
            }
            UnknownSyscall => {
                let mut h = self.r.next() as u32;
                while syscalls::SUPPORTED.iter().any(|(s, _)| *s == h) {
                    h = h.wrapping_add(1);
                }
                self.out.push(It::I(ins(opc::CALL_IMM, 0, 1, 0, h as i32)));
            }
            Abort => self
                .out
                .push(It::I(ins(opc::CALL_IMM, 0, 1, 0, syscalls::ABORT as i32))),
            Panic => self.out.push(It::I(ins(
                opc::CALL_IMM,
                0,
                1,
                0,
                syscalls::SOL_PANIC as i32,
            ))),
            MemcpyOverlap => {
                self.frame_ptr(1, 128);
                let o = 120 + self.r.below(16) as i32;
                self.frame_ptr(2, o);
                self.i(opc::MOV64_IMM, 3, 0, 0, 16);
                self.out.push(It::I(ins(
                    opc::CALL_IMM,
                    0,
                    1,
                    0,
                    syscalls::SOL_MEMCPY as i32,
                )));
            }
            CallDepth => {
                let n = 7 + self.r.below(4) as i32;
                self.i(opc::MOV64_IMM, 1, 0, 0, n);
                self.out.push(It::Call(self.rec));
            }
            CallxNonCode => {
                match self.r.below(4) {
                    0 => {
                        let v = self.imm();
                        self.i(opc::MOV64_IMM, d, 0, 0, v)
                    }
                    1 => self.out.push(It::AddrEnd(d, 8 * self.r.below(4) as i64)),
                    2 => self.out.push(It::Addr(d, 0, -8)),
                    _ => {
                        self.i(opc::CALL_REG, 0, 0, 0, 10);
                        return;
                    }
                }
                self.i(opc::CALL_REG, 0, 0, 0, d as i32);
            }
            CallxPad => {
                // Not an 8-aligned constant, so the scanner cannot take it for a function.
                self.out.push(It::Addr(d, self.pad, -5));
                self.i(opc::ADD64_IMM, d, 0, 0, 5);
                self.i(opc::CALL_REG, 0, 0, 0, d as i32);
            }
            JumpOutOfText => {
                let o = self.r.pick(&[opc::JA, opc::JEQ_REG, opc::JGE_IMM]);
                let off = self.r.pick(&[i16::MAX, i16::MIN, -30000]);
                self.i(o, d, d, off, 0);
            }
            CallOutOfText => {
                let k = self.r.pick(&[i32::MAX, i32::MIN, 1 << 20, -(1 << 20)]);
                self.i(opc::CALL_IMM, 0, 0, 0, k);
            }
            CallImmBadSrc => {
                let s = 2 + self.r.below(9) as u8;
                self.i(opc::CALL_IMM, 0, s, 0, 1);
            }
            EndCall | EndLddw | EndFallOff => {
                let l = self.label();
                self.end = Some((l, t));
                // `call rec` with r1 = 0 returns at once, to a slot past the text.
                self.i(opc::MOV64_IMM, 1, 0, 0, 0);
                self.out.push(It::J {
                    opc: opc::JA,
                    dst: 0,
                    src: 0,
                    imm: 0,
                    to: l,
                });
            }
            IntoLddwBad => {
                let l = self.label();
                self.out.push(It::J {
                    opc: opc::JA,
                    dst: 0,
                    src: 0,
                    imm: 0,
                    to: l,
                });
                let o = self.r.pick(NOT_V1);
                let lo = self.imm();
                let k = self.imm();
                self.out.push(It::LddwSplit {
                    dst: d,
                    lo,
                    hi: ins(o, 0, 0, 0, k),
                    label: l,
                });
            }
        }
    }

    /// A jump into an `lddw`'s second slot, which here holds a real instruction (its immediate is
    /// the constant's high half): run as one, then on past the pair. Sometimes the jump is
    /// conditional, so the pair also runs as an `lddw`.
    fn jump_into_lddw(&mut self) {
        let l = self.label();
        let always = self.r.chance(1, 2);
        if always {
            self.out.push(It::J {
                opc: opc::JA,
                dst: 0,
                src: 0,
                imm: 0,
                to: l,
            });
        } else {
            let (o, d, s, k) = self.cond();
            self.out.push(It::J {
                opc: o,
                dst: d,
                src: s,
                imm: k,
                to: l,
            });
        }
        let d = self.dst();
        let lo = self.imm();
        let o = self.r.pick(ALU);
        let hd = self.dst();
        let hs = if o & 0x08 != 0 { self.src() } else { 0 };
        let k = self.imm();
        self.out.push(It::LddwSplit {
            dst: d,
            lo,
            hi: ins(o, hd, hs, 0, k),
            label: l,
        });
        // Both ways through the pair meet here.
        self.settle();
        if always {
            self.mark_named("lddw:jump-into-second-slot");
        }
    }

    /// A callee's prologue patterns, each with its mark.
    fn prologue(&mut self, f: usize) {
        if self.r.chance(1, 2) {
            // r0 and r6..r9, read before anything writes them.
            for (k, r) in [0u8, 6, 7, 8, 9].into_iter().enumerate() {
                self.i(opc::ST_DW_REG, 10, r, -16 - 8 * k as i16, 0);
            }
            self.mark_named("callee:reads-r0-r6-r9-first");
        }
        if let Some(a) = self.funcs[f].arg {
            // The argument is read only through a store of one width (then cleared).
            let k = self.r.below(4) as usize;
            let (ld, _, stx, _) = MEM[k];
            self.i(stx, 10, a, -8, 0);
            self.i(opc::MOV64_IMM, a, 0, 0, 0);
            self.i(ld, 0, 10, -8, 0);
            self.mark_named(
                [
                    "arg-through:stxb",
                    "arg-through:stxh",
                    "arg-through:stxw",
                    "arg-through:stxdw",
                ][k],
            );
        }
        if self.r.chance(1, 2) {
            // Write r3 on one path only, r2 on both.
            let (o, d, s, k) = self.cond();
            let skip = self.label();
            self.out.push(It::J {
                opc: o,
                dst: d,
                src: s,
                imm: k,
                to: skip,
            });
            let v = self.imm();
            self.i(opc::MOV64_IMM, 3, 0, 0, v);
            self.out.push(It::L(skip));
            let v = self.imm();
            self.i(opc::MOV64_IMM, 2, 0, 0, v);
            self.mark_named("callee:writes-some-of-r0-r5");
        }
    }

    /// `main`'s epilogue: fold the scratch frame, the first 512 bytes of heap traffic and the
    /// instruction data into r0 (the real pipeline publishes only r0 of all this), then exit.
    fn fold_and_exit(&mut self) {
        self.settle();
        for (base, words) in [(None, 64), (Some(HEAP_TRAFFIC), 64), (Some(RAW - 64), 16)] {
            match base {
                None => self.frame_ptr(2, 512),
                Some(a) => self.out.push(It::Lddw(2, a)),
            }
            self.i(opc::MOV64_IMM, 3, 0, 0, words);
            let head = self.label();
            self.out.push(It::L(head));
            self.i(opc::LD_DW_REG, 4, 2, 0, 0);
            self.i(opc::XOR64_REG, 0, 4, 0, 0);
            self.i(opc::MUL64_IMM, 0, 0, 0, 0x0100_01b3);
            self.i(opc::ADD64_IMM, 2, 0, 0, 8);
            self.i(opc::SUB64_IMM, 3, 0, 0, 1);
            self.out.push(It::J {
                opc: opc::JNE_IMM,
                dst: 3,
                src: 0,
                imm: 0,
                to: head,
            });
        }
        self.i(opc::EXIT, 0, 0, 0, 0);
    }
}

/// The case for `seed`.
pub fn case(seed: u64) -> Case {
    let mut r = Mix(seed ^ 0x5bf0_3635_d1a2_2c47);
    // About 1.6% budget cases (a mean of 156 in any 10 000 seeds, so the class clears 100 in every
    // range, not just the default one).
    let budget = r.below(64) == 0;
    let mut g = Gen {
        r,
        out: Vec::new(),
        next: 0,
        locked: 0,
        depth: 0,
        loops: 0,
        cur: 0,
        funcs: Vec::new(),
        rec: 0,
        pad: 0,
        in_main: true,
        end: None,
        helpers: Vec::new(),
        member_in_loop: None,
        split: (0, 0),
        r9_dirty: false,
    };
    // Label 0 is the text's first slot (main's entry): `It::Addr(_, 0, k)` is text_va + k.
    g.out.push(It::L(0));
    g.rec = g.label();
    g.pad = g.label();
    assert_eq!(g.pad, PAD);
    g.split = (g.label(), g.label());
    let n_callees = g.r.below(5) as usize;
    let main = g.label();
    g.funcs.push(Func {
        entry: main,
        member: None,
        arg: None,
        counter: None,
    });
    for _ in 0..n_callees {
        let entry = g.label();
        let member = if g.r.chance(1, 2) {
            Some(g.label())
        } else {
            None
        };
        let arg = if g.r.chance(1, 2) {
            Some(1 + g.r.below(5) as u8)
        } else {
            None
        };
        // A member may be a loop's head, entered with a count its caller sets: which counter
        // register is decided here, before any caller is generated.
        let counter = if member.is_some() && g.r.chance(1, 3) {
            Some(6 + g.r.below(3) as u8)
        } else {
            None
        };
        g.funcs.push(Func {
            entry,
            member,
            arg,
            counter,
        });
    }
    // Two cases in three carry a terminal: each of the 28 is then planned about 235 times in 10 000
    // seeds, and the rarest halt class (a terminal that is sometimes not reached) keeps a margin
    // over 100 in any seed range (`FUZZ_SEED_BASE`).
    let terminal = if !budget && g.r.chance(2, 3) {
        Some(g.r.pick(TERMINALS))
    } else {
        None
    };
    // Where the terminal goes: main's top level (0) or a callee's (k).
    let term_in = match terminal {
        Some(_) => Some(g.r.below(1 + n_callees as u64) as usize),
        None => None,
    };

    // ---- main ----
    g.out.push(It::L(main));
    // Reserve the coverage page: the first allocation on an empty heap is its first bytes, and a
    // bump allocator never hands them out again. (Four instructions, none of which can fault.)
    g.i(opc::MOV64_IMM, 1, 0, 0, MARK_BYTES as i32);
    g.i(opc::MOV64_IMM, 2, 0, 0, 0);
    g.out.push(It::I(ins(
        opc::CALL_IMM,
        0,
        1,
        0,
        syscalls::SOL_ALLOC_FREE as i32,
    )));
    g.out.push(It::Lddw(9, MARK_BASE));
    if budget {
        budget_body(&mut g);
    } else {
        let n = 4 + g.r.below(20) as usize;
        let at = g.r.below(n as u64 + 1) as usize;
        let mut nest = 6;
        for k in 0..n {
            if k == at && term_in == Some(0) {
                g.terminal(terminal.unwrap());
            }
            g.body(1, &mut nest);
        }
        if n == at && term_in == Some(0) {
            g.terminal(terminal.unwrap());
        }
    }
    g.fold_and_exit();

    // ---- the callees ----
    g.in_main = false;
    for f in 1..g.funcs.len() {
        g.cur = f;
        let entry = g.funcs[f].entry;
        g.out.push(It::L(entry));
        g.prologue(f);
        let n = 2 + g.r.below(8) as usize;
        let in_loop = g.funcs[f].counter.is_some();
        if in_loop {
            g.member_in_loop = g.funcs[f].member;
        }
        let member_at = if g.funcs[f].member.is_some() && !in_loop {
            Some(1 + g.r.below(n as u64 - 1) as usize)
        } else {
            None
        };
        let term_at = g.r.below(n as u64) as usize;
        let mut nest = 3;
        for k in 0..n {
            if Some(k) == member_at {
                let m = g.funcs[f].member.unwrap();
                g.out.push(It::L(m));
            }
            if k == term_at && term_in == Some(f) {
                g.terminal(terminal.unwrap());
            }
            g.body(1, &mut nest);
        }
        if let Some(m) = g.member_in_loop.take() {
            // No top-level loop came up: the member goes here instead.
            g.out.push(It::L(m));
        }
        if f + 1 < g.funcs.len() && g.r.chance(1, 5) {
            // No `exit`: fall into the next function, whose entry is then inside this one.
            g.mark_named("fallthrough-into-next-function");
        } else {
            g.mark_named("exit:callee");
            if g.r.chance(1, 3) {
                // The caller's r9 (the coverage base) must come back as it was: r6..r9 are the
                // frame's, not the callee's.
                g.mark_named("callee:clobbers-r9-before-exit");
                match g.r.below(3) {
                    0 => {
                        let v = g.r.next();
                        g.out.push(It::Lddw(9, v));
                    }
                    1 => {
                        let s = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10][g.r.below(10) as usize];
                        g.i(opc::MOV64_REG, 9, s, 0, 0);
                    }
                    _ => {
                        let k = g.imm();
                        g.i(opc::XOR64_IMM, 9, 0, 0, k | 1);
                    }
                }
            }
            g.i(opc::EXIT, 0, 0, 0, 0);
        }
    }

    // ---- a budget case's helpers: straight-line, the planned fault in one of them ----
    let helpers = std::mem::take(&mut g.helpers);
    for (l, fault) in helpers {
        g.out.push(It::L(l));
        g.locked = 0x3c0;
        for _ in 0..g.r.below(8) {
            safe_op(&mut g);
        }
        if fault {
            g.mark_named("budget:fault-in-callee");
            budget_fault(&mut g);
        }
        g.locked = 0;
        g.i(opc::EXIT, 0, 0, 0, 0);
    }

    // ---- the recursive function: r1 more levels below it ----
    g.cur = g.funcs.len();
    let rec = g.rec;
    g.out.push(It::L(rec));
    let done = g.label();
    g.out.push(It::J {
        opc: opc::JEQ_IMM,
        dst: 1,
        src: 0,
        imm: 0,
        to: done,
    });
    g.i(opc::SUB64_IMM, 1, 0, 0, 1);
    g.i(opc::ST_DW_REG, 10, 1, -8, 0);
    g.out.push(It::Call(rec));
    g.i(opc::ADD64_IMM, 0, 0, 0, 1);
    g.out.push(It::L(done));
    g.i(opc::EXIT, 0, 0, 0, 0);

    // ---- one `lddw` and an `exit`; a call may land on the pair's second slot ----
    let (whole, hi) = g.split;
    g.out.push(It::L(whole));
    let o = g.r.pick(&[
        opc::MOV64_IMM,
        opc::ADD64_IMM,
        opc::XOR32_IMM,
        opc::LSH64_IMM,
    ]);
    let lo = g.imm();
    let k = g.imm();
    g.out.push(It::LddwSplit {
        dst: 0,
        lo,
        hi: ins(o, 0, 0, 0, k),
        label: hi,
    });
    g.i(opc::EXIT, 0, 0, 0, 0);

    // ---- the pad: code nothing names as an entry ----
    let pad = g.pad;
    g.i(opc::MOV64_IMM, 0, 0, 0, 0x7ad);
    g.i(opc::EXIT, 0, 0, 0, 0);
    g.out.push(It::L(pad));
    g.out.push(It::Lddw(1, MAGIC));
    g.i(opc::LD_B_REG, 0, 1, 0, 0);
    g.i(opc::EXIT, 0, 0, 0, 0);

    // ---- the dead table: every entry as an 8-aligned lddw constant ----
    let names: Vec<Label> = g
        .funcs
        .iter()
        .flat_map(|f| [Some(f.entry), f.member].into_iter().flatten())
        .chain([rec, whole, hi])
        .collect();
    for l in names {
        g.out.push(It::Addr(0, l, 0));
    }

    // ---- the text's last slot, if a terminal jumps there ----
    if let Some((l, t)) = g.end {
        g.out.push(It::L(l));
        match t {
            Terminal::EndCall => g.out.push(It::Call(rec)),
            Terminal::EndLddw => g.i(opc::LD_DW_IMM, 0, 0, 0, 7),
            _ => g.i(opc::MOV64_IMM, 0, 0, 0, 7),
        }
    }

    // The instruction data: selector 0, the parameters, the raw bytes.
    let mut data = vec![0u8; DATA_LEN];
    for k in 0..8 {
        let v = match g.r.below(4) {
            0 => g.r.below(8),
            1 => g.r.next(),
            2 => g.r.below(1 << 16),
            _ => g.r.pick(&[0, 1, u64::MAX, 1 << 63, 0xffff_ffff]),
        };
        data[8 + 8 * k..16 + 8 * k].copy_from_slice(&v.to_le_bytes());
    }
    for b in &mut data[72..] {
        *b = g.r.next() as u8;
    }
    if budget {
        for (k, v) in [1u64, 1, 0].into_iter().enumerate() {
            data[8 + 8 * k..16 + 8 * k].copy_from_slice(&v.to_le_bytes());
        }
    }
    Case {
        seed,
        items: g.out,
        data,
        budget,
    }
}

/// A budget case's `main` body. Its instruction count up to the end of the run (the planned fault, or
/// `exit`) is `m0 + per·(T − 1) + 2·(P − 1) + C` for the three parameters `T` (param 0, a loop of
/// `per` instructions), `P` (param 1, a two-instruction loop) and `C` (param 2, 0 or 1: one optional
/// instruction), so the fuzzer can land that point on any instruction count it likes. Everything the
/// count depends on is straight-line or branches on `r9` (a constant), so it is affine in all three.
///
/// The fault (in two budget cases of three) sits in the middle of a block, with instructions after
/// it: that is where the translation, which charges a block at its head or defers the check to the
/// next block, may stop at the limit where the interpreter faults, or the other way round.
fn budget_body(g: &mut Gen) {
    for (r, k) in [(6u8, 0u64), (7, 1), (8, 2)] {
        g.out.push(It::Lddw(r, param(k)));
        g.i(opc::LD_DW_REG, r, r, 0, 0);
    }
    g.locked = 0x3c0;
    let skip = g.label();
    g.out.push(It::J {
        opc: opc::JEQ_IMM,
        dst: 8,
        src: 0,
        imm: 0,
        to: skip,
    });
    g.i(opc::MOV64_IMM, 8, 0, 0, 0);
    g.out.push(It::L(skip));
    let two = g.label();
    g.out.push(It::L(two));
    g.i(opc::SUB64_IMM, 7, 0, 0, 1);
    g.out.push(It::J {
        opc: opc::JNE_IMM,
        dst: 7,
        src: 0,
        imm: 0,
        to: two,
    });
    let head = g.label();
    g.out.push(It::L(head));
    let s = 1 + g.r.below(24);
    let call_at = if g.r.chance(1, 2) {
        Some(g.r.below(s + 1))
    } else {
        None
    };
    for k in 0..=s {
        if Some(k) == call_at {
            let l = g.label();
            g.helpers.push((l, false));
            g.out.push(It::Call(l));
            g.mark_named("budget:call-in-loop");
        }
        if k < s {
            safe_op(g);
        }
    }
    g.i(opc::SUB64_IMM, 6, 0, 0, 1);
    g.out.push(It::J {
        opc: opc::JNE_IMM,
        dst: 6,
        src: 0,
        imm: 0,
        to: head,
    });
    // The tail: straight-line code, split into blocks by jumps on r9 that always or never go.
    let fault = g.r.chance(2, 3);
    let pieces = 1 + g.r.below(3);
    for k in 0..pieces {
        for _ in 0..g.r.below(6) {
            safe_op(g);
        }
        if fault && k == pieces - 1 {
            if g.r.chance(1, 3) {
                // The fault in a callee.
                let l = g.label();
                g.helpers.push((l, true));
                g.out.push(It::Call(l));
            } else {
                budget_fault(g);
            }
        } else {
            let to = g.label();
            let o = g.r.pick(&[opc::JEQ_IMM, opc::JNE_IMM]);
            g.out.push(It::J {
                opc: o,
                dst: 9,
                src: 0,
                imm: 0,
                to,
            });
            if o == opc::JEQ_IMM {
                safe_op(g);
            } else {
                g.i(opc::MOV64_IMM, 0, 0, 0, 0x5eed);
            }
            g.out.push(It::L(to));
        }
    }
    g.locked = 0;
}

/// A budget case's planned fault, in the middle of a block (instructions follow it).
fn budget_fault(g: &mut Gen) {
    let t = g.r.pick(&[
        Terminal::AvOutOfRegion,
        Terminal::AvStraddleStack,
        Terminal::AvStraddleHeap,
        Terminal::DivImmZero,
        Terminal::DivRegZero,
        Terminal::BadLeBe,
    ]);
    g.terminal(t);
    for _ in 0..1 + g.r.below(6) {
        safe_op(g);
    }
}

/// An instruction that cannot fault: any ALU operation but division, or a scratch-frame access.
fn safe_op(g: &mut Gen) {
    if g.r.chance(1, 4) {
        let (ld, _, stx, w) = g.r.pick(&MEM);
        let off = -(g.r.below(256) as i16) - w as i16;
        if g.r.chance(1, 2) {
            let d = g.dst();
            g.i(ld, d, 10, off, 0);
        } else {
            let s = g.src();
            g.i(stx, 10, s, off, 0);
        }
    } else {
        let o = g.r.pick(ALU);
        let d = g.dst();
        let is_reg = o & 0x08 != 0;
        let s = if is_reg { g.src() } else { 0 };
        let k = if is_reg || matches!(o, opc::NEG32 | opc::NEG64) {
            0
        } else {
            g.imm()
        };
        g.i(o, d, s, 0, k);
    }
}

/// A one-line-per-slot listing, for a failure report.
pub fn disassemble(text: &[u8]) -> String {
    let mut s = String::new();
    for (pc, c) in text.chunks(8).enumerate() {
        let w = u64::from_le_bytes(c.try_into().unwrap());
        let i = isa::decode(w);
        s.push_str(&format!(
            "{pc:5}: {w:016x}  opc {:#04x} dst r{} src r{} off {} imm {}\n",
            i.opc, i.dst, i.src, i.off, i.imm
        ));
    }
    s
}
