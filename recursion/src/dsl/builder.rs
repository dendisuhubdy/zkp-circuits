//! The builder: value slots, a linear register allocator with spills, and the control constructs
//! rVM programs are made of.
//!
//! **The allocator.** `r1..r27` are allocatable and `r28..r31` are scratch (`r0` is the constant
//! zero). Every handle is allocated a register when it is created and keeps it until pressure forces
//! a spill; a spilled handle is written to the spill arena — the first [`MEM_BASE`] cells of memory,
//! which is why user allocations start above it — and from then on is reloaded into a scratch
//! register at each use. There is no liveness analysis and no promotion back into a register: a
//! handle is live from its definition to the end of the program, so the allocator's only choice is
//! *which* resident handle to evict, and it evicts the oldest one that the instruction being emitted
//! does not need. That is the "simple linear allocator with spills" spec §4.1 asks for, and every
//! spill and reload is counted in [`Stats`] so the cost is visible rather than inferred.
//!
//! **Why scratch registers exist.** Both operands of an extension binary operation can be spilled,
//! which is two consecutive registers each; `assert_eq` needs a third for its difference. Four is
//! the worst case among the handle-level operations. Six are reserved, because the DSL's own hash
//! layer emits raw sequences (see the `raw_*` hooks below) whose deepest one — the Merkle walk's
//! child select — needs a reloaded index bit, two reloaded base addresses and three working
//! registers at once. [`Builder::take_scratch`] asserts the bound rather than silently aliasing.
//!
//! **Discipline the code below depends on.** A handle's defining instruction is emitted immediately
//! after the handle is created, with nothing in between that could allocate — otherwise the
//! allocator could spill a register whose value has not been written yet.

use std::collections::VecDeque;

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};

use super::{Array, Ext, Felt, Ptr};
use crate::isa::{Instr, Op, Program, EF, F, MEM_LIMIT, NUM_REGS};

/// The first cell a user allocation can use. Cells `0..MEM_BASE` are the spill arena.
///
/// `2^22`, a quarter of the `2^24`-cell address space. A spilled handle keeps its cell for the
/// rest of the program (there is no liveness analysis and no promotion back into a register), so the
/// arena has to hold *every handle the program ever spills* — and the verifier program spills on the
/// order of `10^6` of them (the FRI reduction alone creates ~10 handle slots per opened column per
/// query). Cells cost nothing on their own: the rVM's memory is addressed, not materialised, so an
/// unused cell is neither a row nor a trace entry. Raising this number moves every user allocation
/// and therefore **changes every program digest**, which is why it is set once, generously, here
/// rather than nudged upwards later. (`2^20` sufficed through phase 5 and overflows in phase 6.)
pub const MEM_BASE: u64 = 1 << 22;

/// The registers handles are allocated from, in allocation-preference order. Width-2 handles take an
/// aligned pair, so `r25` is reachable only by a width-1 handle: twelve pairs, twenty-five singles.
const ALLOCATABLE: [u8; 25] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
];
/// Never allocated to a handle: where a spilled operand is reloaded, where a comparison's difference
/// lands, and where the hash layer's raw sequences do their work. Contiguous, so a width-2 reload can
/// take any two of them in order.
const SCRATCH: [u8; 6] = [26, 27, 28, 29, 30, 31];

/// Should `Builder::checkpoint` publish its value?
///
/// The differential tests need dozens of intermediate values exposed; the shipped program's public
/// values are spec §4.4 exactly. Both builds record the same checkpoint *names*, in the same order,
/// so the two tables line up (`Builder::checkpoint_names`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Checkpoints {
    Off,
    On,
}

/// What a built program cost. `cells` counts the memory cells the program reserves: the spill arena
/// it actually used plus everything [`Builder::alloc`] handed out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub instrs: usize,
    pub spills: usize,
    pub reloads: usize,
    pub perms: usize,
    pub cells: u64,
}

/// Where a handle's value is right now.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Place {
    Reg(u8),
    Mem(u64),
}

#[derive(Clone, Copy, Debug)]
struct Slot {
    width: u8,
    place: Place,
    /// The value, when it is a compile-time constant ([`Builder::constant`], [`Builder::zero`]).
    /// Only [`Builder::counted_loop`] reads it, to reject a statically-zero iteration count; it is
    /// deliberately *not* propagated through arithmetic, because a builder that constant-folded
    /// would emit a different program than the one it was asked for.
    konst: Option<F>,
}

/// A pointer: a value slot holding a base address, plus a compile-time cell delta that is folded
/// into the immediate of whatever `LOAD`/`STORE` uses it.
#[derive(Clone, Copy, Debug)]
struct PtrSlot {
    holder: u32,
    delta: i64,
}

pub struct Builder {
    mode: Checkpoints,
    instrs: Vec<Instr>,
    /// `pc -> name` for the assertion traps, in increasing `pc` (what `Program::checkpoint_at`
    /// binary-searches).
    checkpoints: Vec<(u32, String)>,
    /// The names passed to [`Builder::checkpoint`], in order, whatever the mode.
    names: Vec<String>,
    slots: Vec<Slot>,
    ptrs: Vec<PtrSlot>,
    /// Which handle occupies each register; both halves of a width-2 handle map to it.
    regs: [Option<u32>; NUM_REGS],
    /// The resident handles, oldest allocation first: the spill order.
    order: VecDeque<u32>,
    next_cell: u64,
    next_spill: u64,
    /// Scratch registers taken by the instruction currently being emitted.
    scratch: usize,
    zero: Option<Felt>,
    /// The sixteen cells `dsl::hash` hashes through, allocated on first use (see
    /// [`Builder::hash_scratch`]).
    hash: Option<Ptr>,
    stats: Stats,
}

impl Builder {
    pub fn new(checkpoints: Checkpoints) -> Self {
        Builder {
            mode: checkpoints,
            instrs: Vec::new(),
            checkpoints: Vec::new(),
            names: Vec::new(),
            slots: Vec::new(),
            ptrs: Vec::new(),
            regs: [None; NUM_REGS],
            order: VecDeque::new(),
            next_cell: MEM_BASE,
            next_spill: 0,
            scratch: 0,
            zero: None,
            hash: None,
            stats: Stats::default(),
        }
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// The names passed to [`Builder::checkpoint`], in order. Identical under both
    /// [`Checkpoints`] modes — that is what makes the two builds' checkpoint tables comparable.
    pub fn checkpoint_names(&self) -> &[String] {
        &self.names
    }

    /// Close the program: append `HALT`.
    ///
    /// There is no separate trap block to patch. A failing assertion's `INV` of zero sits inline
    /// right after the branch that skips it (see [`Builder::assert_eq`]), so every trap's `pc`
    /// identifies its own assertion and nothing has to be resolved at the end.
    pub fn finish(mut self) -> Program {
        self.emit(Op::Halt, 0, 0, F::ZERO);
        Program { instrs: self.instrs, checkpoints: self.checkpoints }
    }

    // ---------------------------------------------------------------- values

    pub fn constant(&mut self, v: F) -> Felt {
        self.begin();
        let (id, rd) = self.new_handle(1, &[]);
        self.emit(Op::Faddi, rd, 0, v);
        self.slots[id as usize].konst = Some(v);
        Felt(id)
    }

    /// The constant zero: `r0` itself, so this costs no instruction and never spills.
    pub fn zero(&mut self) -> Felt {
        if let Some(z) = self.zero {
            return z;
        }
        let id = self.slots.len() as u32;
        self.slots.push(Slot { width: 1, place: Place::Reg(0), konst: Some(F::ZERO) });
        let z = Felt(id);
        self.zero = Some(z);
        z
    }

    pub fn add(&mut self, a: Felt, b: Felt) -> Felt {
        self.bin(Op::Fadd, a, b)
    }

    pub fn sub(&mut self, a: Felt, b: Felt) -> Felt {
        self.bin(Op::Fsub, a, b)
    }

    pub fn mul(&mut self, a: Felt, b: Felt) -> Felt {
        self.bin(Op::Fmul, a, b)
    }

    pub fn add_const(&mut self, a: Felt, c: F) -> Felt {
        self.un(Op::Faddi, a, c)
    }

    pub fn mul_const(&mut self, a: Felt, c: F) -> Felt {
        self.un(Op::Fmuli, a, c)
    }

    /// `a⁻¹`, the inverse supplied as a hint; the row constrains `a·a⁻¹ = 1`, so a zero operand is
    /// an unsatisfiable row and an emulator error rather than a silent zero.
    pub fn inv(&mut self, a: Felt) -> Felt {
        self.un(Op::Inv, a, F::ZERO)
    }

    pub fn copy(&mut self, a: Felt) -> Felt {
        self.un(Op::Mov, a, F::ZERO)
    }

    // ------------------------------------------------------- extension values

    pub fn ext_constant(&mut self, v: EF) -> Ext {
        self.begin();
        let c = v.as_basis_coefficients_slice();
        let (c0, c1) = (c[0], c[1]);
        let (id, rd) = self.new_handle(2, &[]);
        self.emit(Op::Faddi, rd, 0, c0);
        self.emit(Op::Faddi, rd + 1, 0, c1);
        Ext(id)
    }

    /// `a` as `a + 0·X`.
    pub fn ext_lift(&mut self, a: Felt) -> Ext {
        self.begin();
        let ra = self.materialise(a.0);
        let (id, rd) = self.new_handle(2, &[ra]);
        self.emit(Op::Mov, rd, ra, F::ZERO);
        self.emit(Op::Mov, rd + 1, 0, F::ZERO);
        Ext(id)
    }

    pub fn ext_add(&mut self, a: Ext, b: Ext) -> Ext {
        self.ebin(Op::Eadd, a, b)
    }

    pub fn ext_sub(&mut self, a: Ext, b: Ext) -> Ext {
        self.ebin(Op::Esub, a, b)
    }

    pub fn ext_mul(&mut self, a: Ext, b: Ext) -> Ext {
        self.ebin(Op::Emul, a, b)
    }

    pub fn ext_mul_base(&mut self, a: Ext, b: Felt) -> Ext {
        self.begin();
        let ra = self.materialise(a.0);
        let rb = self.materialise(b.0);
        let (id, rd) = self.new_handle(2, &[ra, ra + 1, rb]);
        self.emit(Op::Emulf, rd, ra, F::from_u8(rb));
        Ext(id)
    }

    pub fn ext_inv(&mut self, a: Ext) -> Ext {
        self.begin();
        let ra = self.materialise(a.0);
        let (id, rd) = self.new_handle(2, &[ra, ra + 1]);
        self.emit(Op::Einv, rd, ra, F::ZERO);
        Ext(id)
    }

    /// `c0 + c1·X` from its two coefficients: two `MOV`s into an aligned register pair, the dual of
    /// [`Builder::ext_parts`]. This is how a sampled extension challenge is assembled — the
    /// challenger squeezes two base elements and this makes them one handle.
    pub fn ext_from_parts(&mut self, c0: Felt, c1: Felt) -> Ext {
        self.begin();
        let a0 = self.materialise(c0.0);
        let a1 = self.materialise(c1.0);
        let (id, rd) = self.new_handle(2, &[a0, a1]);
        self.emit(Op::Mov, rd, a0, F::ZERO);
        self.emit(Op::Mov, rd + 1, a1, F::ZERO);
        Ext(id)
    }

    /// `(c0, c1)` of `a = c0 + c1·X`.
    pub fn ext_parts(&mut self, a: Ext) -> (Felt, Felt) {
        self.begin();
        let ra = self.materialise(a.0);
        let pinned = [ra, ra + 1];
        let (i0, r0) = self.new_handle(1, &pinned);
        self.emit(Op::Mov, r0, ra, F::ZERO);
        let (i1, r1) = self.new_handle(1, &pinned);
        self.emit(Op::Mov, r1, ra + 1, F::ZERO);
        (Felt(i0), Felt(i1))
    }

    // --------------------------------------------------------------- witness

    pub fn hint(&mut self) -> Felt {
        self.begin();
        let (id, rd) = self.new_handle(1, &[]);
        self.emit(Op::Hint, rd, 0, F::ZERO);
        Felt(id)
    }

    pub fn hint_ext(&mut self) -> Ext {
        self.begin();
        let (id, rd) = self.new_handle(2, &[]);
        self.emit(Op::Hinte, rd, 0, F::ZERO);
        Ext(id)
    }

    /// `n` witness words, read in order into `n` fresh cells.
    ///
    /// The words go through one scratch register rather than through `n` handles: an array is read
    /// back from memory, so keeping every element in a register would only spill it straight back.
    pub fn hint_array(&mut self, n: usize) -> Array<Felt> {
        let base = self.alloc(n as u64);
        let holder = self.ptrs[base.0 as usize].holder;
        self.begin();
        let rp = self.materialise(holder);
        let s = self.take_scratch(1);
        for k in 0..n {
            self.emit(Op::Hint, s, 0, F::ZERO);
            self.emit(Op::Store, s, rp, imm(k as i64));
        }
        Array::new(base, n, 1)
    }

    /// `n` extension elements — `2n` witness words — into `2n` fresh cells.
    pub fn hint_ext_array(&mut self, n: usize) -> Array<Ext> {
        let base = self.alloc(2 * n as u64);
        let holder = self.ptrs[base.0 as usize].holder;
        self.begin();
        let rp = self.materialise(holder);
        let s = self.take_scratch(2);
        for k in 0..n {
            self.emit(Op::Hinte, s, 0, F::ZERO);
            self.emit(Op::Storee, s, rp, imm(2 * k as i64));
        }
        Array::new(base, n, 2)
    }

    // ---------------------------------------------------------------- memory

    /// Reserve `cells` cells. The base is a compile-time constant, materialised once with
    /// `FADDI rd, r0, base`.
    pub fn alloc(&mut self, cells: u64) -> Ptr {
        let base = self.next_cell;
        assert!(base + cells <= MEM_LIMIT, "the rVM's {MEM_LIMIT}-cell memory is full");
        self.next_cell += cells;
        self.stats.cells += cells;
        self.begin();
        let (id, rd) = self.new_handle(1, &[]);
        self.emit(Op::Faddi, rd, 0, F::from_u64(base));
        self.ptrs.push(PtrSlot { holder: id, delta: 0 });
        Ptr(self.ptrs.len() as u32 - 1)
    }

    /// `p` shifted by `cells`. Free: the delta is folded into the immediate of every access made
    /// through the result, and `LOAD`'s immediate is a full field element.
    pub fn offset(&mut self, p: Ptr, cells: i64) -> Ptr {
        let it = self.ptrs[p.0 as usize];
        self.ptrs.push(PtrSlot { holder: it.holder, delta: it.delta + cells });
        Ptr(self.ptrs.len() as u32 - 1)
    }

    pub fn load(&mut self, p: Ptr, off: i64) -> Felt {
        self.begin();
        let (rp, at) = self.address(p, off);
        let (id, rd) = self.new_handle(1, &[rp]);
        self.emit(Op::Load, rd, rp, at);
        Felt(id)
    }

    pub fn store(&mut self, p: Ptr, off: i64, v: Felt) {
        self.begin();
        let rv = self.materialise(v.0);
        let (rp, at) = self.address(p, off);
        self.emit(Op::Store, rv, rp, at);
    }

    pub fn load_ext(&mut self, p: Ptr, off: i64) -> Ext {
        self.begin();
        let (rp, at) = self.address(p, off);
        let (id, rd) = self.new_handle(2, &[rp]);
        self.emit(Op::Loade, rd, rp, at);
        Ext(id)
    }

    pub fn store_ext(&mut self, p: Ptr, off: i64, v: Ext) {
        self.begin();
        let rv = self.materialise(v.0);
        let (rp, at) = self.address(p, off);
        self.emit(Op::Storee, rv, rp, at);
    }

    pub fn get(&mut self, a: Array<Felt>, idx: usize) -> Felt {
        assert!(idx < a.len, "index {idx} is past the end of a {}-element array", a.len);
        self.load(a.base, (idx * a.stride) as i64)
    }

    pub fn get_ext(&mut self, a: Array<Ext>, idx: usize) -> Ext {
        assert!(idx < a.len, "index {idx} is past the end of a {}-element array", a.len);
        self.load_ext(a.base, (idx * a.stride) as i64)
    }

    /// `n` cells from `src + src_off` to `dst + dst_off`, two rows per cell.
    ///
    /// This is the bulk move the hash layer is built out of, and the reason it exists rather than a
    /// `load`/`store` pair per cell is register pressure: `load` creates a *handle*, which lives to
    /// the end of the program, so copying a 121-element sponge message through handles would spill a
    /// hundred of them and pay a third row per cell for the privilege. Here the value goes through
    /// one scratch register and the two base addresses are materialised once for the whole run, so
    /// the cost is exactly `2n` rows and no allocator state changes at all.
    ///
    /// Overlapping ranges copy ascending, cell by cell, with no temporary: a forward overlap
    /// (`dst > src` within the same region) will read cells this call has already written.
    pub fn copy_cells(&mut self, dst: Ptr, dst_off: i64, src: Ptr, src_off: i64, n: usize) {
        if n == 0 {
            return;
        }
        let (from, to) = (self.ptrs[src.0 as usize], self.ptrs[dst.0 as usize]);
        self.begin();
        let rs = self.materialise(from.holder);
        let rd = self.materialise(to.holder);
        let t = self.take_scratch(1);
        for k in 0..n as i64 {
            self.emit(Op::Load, t, rs, imm(from.delta + src_off + k));
            self.emit(Op::Store, t, rd, imm(to.delta + dst_off + k));
        }
    }

    /// `n` zero cells at `p + off`, one row per cell — `r0` is the value, so this needs no register
    /// and creates no handle.
    pub fn zero_cells(&mut self, p: Ptr, off: i64, n: usize) {
        if n == 0 {
            return;
        }
        let it = self.ptrs[p.0 as usize];
        self.begin();
        let rp = self.materialise(it.holder);
        for k in 0..n as i64 {
            self.emit(Op::Store, 0, rp, imm(it.delta + off + k));
        }
    }

    /// The sixteen cells the DSL's hash layer works through, allocated once per program: the eight
    /// permutation lanes `0..8` plus two four-cell scratch digests at `8..12` and `12..16`.
    ///
    /// One shared region, not one per hash: a fresh allocation per `sponge` call would cost a handle
    /// (and an `FADDI`) per call, and the verifier program hashes tens of thousands of times. The
    /// consequence is an aliasing rule, documented on every function in [`super::hash`]: no argument
    /// to a hash primitive may point into this region, and a primitive that has to survive another
    /// one's use of the lanes steps aside into one of the two scratch digests first.
    pub(super) fn hash_scratch(&mut self) -> Ptr {
        if let Some(p) = self.hash {
            return p;
        }
        let p = self.alloc(16);
        self.hash = Some(p);
        p
    }

    // --------------------------------------------------------------- hashing

    /// Permute the eight cells at `p` in place.
    ///
    /// `POSEIDON2`'s pointer is a register with no immediate (spec §3), so a `Ptr` carrying a
    /// compile-time delta costs one `FADDI` to fold it in first.
    pub fn poseidon2(&mut self, p: Ptr) {
        self.begin();
        let it = self.ptrs[p.0 as usize];
        let holder = self.materialise(it.holder);
        let ra = if it.delta == 0 {
            holder
        } else {
            let s = self.take_scratch(1);
            self.emit(Op::Faddi, s, holder, imm(it.delta));
            s
        };
        self.emit(Op::Poseidon2, 0, ra, F::ZERO);
        self.stats.perms += 1;
    }

    // --------------------------------------------------------------- control

    /// `a == b`, or the program traps at a `pc` that names `what`.
    ///
    /// Three rows: the difference, a branch over the trap, and the trap — `INV r1, r0`, the standard
    /// unsatisfiable row. The trap is emitted per assertion rather than shared, so the `pc` in
    /// `ExecError::InverseOfZero` identifies *which* assertion failed with no patching at the end
    /// and no ambiguity. `r1`'s contents are irrelevant: nothing runs after the trap.
    pub fn assert_eq(&mut self, a: Felt, b: Felt, what: &str) {
        self.begin();
        let ra = self.materialise(a.0);
        let rb = self.materialise(b.0);
        let t = self.take_scratch(1);
        self.emit_r(Op::Fsub, t, ra, rb);
        let over = self.instrs.len() as u64 + 2;
        self.emit(Op::Jeq, t, 0, F::from_u64(over));
        self.trap(what);
    }

    /// Two [`Builder::assert_eq`]s, one per coefficient, named `"<what> (c0)"` and `"<what> (c1)"`
    /// so a failure says which half disagreed.
    pub fn assert_eq_ext(&mut self, a: Ext, b: Ext, what: &str) {
        let (a0, a1) = self.ext_parts(a);
        let (b0, b1) = self.ext_parts(b);
        self.assert_eq(a0, b0, &format!("{what} (c0)"));
        self.assert_eq(a1, b1, &format!("{what} (c1)"));
    }

    /// `a != 0` **and** `a⁻¹`, in one row.
    ///
    /// The extension analogue of [`Builder::assert_nonzero`], except that it hands back the inverse
    /// instead of discarding it, because its caller wants both: the verifier's `inv_vanishing` *is*
    /// `1/Z_H(zeta)`, and `Z_H(zeta) != 0` is `p3-batch-stark`'s `OodPointInDomain` check. `EINV` of
    /// zero is exactly the trap, so one `EINV` is the value and the assertion at once — the named
    /// checkpoint sits on that instruction's own `pc`.
    pub fn ext_inv_checked(&mut self, a: Ext, what: &str) -> Ext {
        self.begin();
        let ra = self.materialise(a.0);
        let (id, rd) = self.new_handle(2, &[ra, ra + 1]);
        let at = self.instrs.len() as u32;
        self.emit(Op::Einv, rd, ra, F::ZERO);
        self.checkpoints.push((at, what.to_string()));
        Ext(id)
    }

    /// `a != 0`, in one row: `INV` of zero is exactly the trap, so the inverse *is* the assertion.
    pub fn assert_nonzero(&mut self, a: Felt, what: &str) {
        self.begin();
        let ra = self.materialise(a.0);
        let t = self.take_scratch(1);
        let at = self.instrs.len() as u32;
        self.emit(Op::Inv, t, ra, F::ZERO);
        self.checkpoints.push((at, what.to_string()));
    }

    /// `body` emitted `n` times, with the iteration index as a Rust `usize`. No restriction on what
    /// the body does — every iteration gets its own instructions.
    pub fn unrolled(&mut self, n: usize, mut body: impl FnMut(&mut Self, usize)) {
        for i in 0..n {
            body(self, i);
        }
    }

    /// `body` emitted **once** and executed `n` times, with a down-counter (`n, n-1, …, 1`) as its
    /// index.
    ///
    /// **Precondition: `n >= 1`.** The counter is tested *after* the body, so this is a do-while:
    /// `n = 0` runs the body once and then counts down from `-1`, i.e. `2^64 - 2^32` more times —
    /// not an empty loop but an unbounded one. A caller whose count can be zero has to branch around
    /// the loop itself; nothing in the emitted code can recover from a zero reaching the `MOV`.
    /// When `n` is a compile-time constant ([`Builder::constant`] or [`Builder::zero`]) the builder
    /// checks the precondition and panics on a zero; when it is a runtime value — a round or query
    /// count read off the witness tape, say — the precondition is the caller's to establish.
    ///
    /// Because the body is emitted once, the registers it reads on the second iteration are whatever
    /// the first left behind — so the body must not move any handle that existed before the loop,
    /// the counter above all. The builder snapshots the allocation and panics if the body's net
    /// effect on it is not zero; a body that needs more registers than are free has to communicate
    /// through memory instead. Handles the body *creates* are unconstrained: they are rewritten by
    /// their own instructions every iteration.
    pub fn counted_loop(&mut self, n: Felt, mut body: impl FnMut(&mut Self, Felt)) {
        assert!(
            self.slots[n.0 as usize].konst != Some(F::ZERO),
            "counted_loop: the iteration count is a compile-time zero. The counter is tested after \
             the body, so this would run the body once and then 2^64 - 2^32 more times, not zero \
             times — n >= 1 is the precondition. Branch around the loop instead."
        );
        self.begin();
        let rn = self.materialise(n.0);
        let (ctr, rc) = self.new_handle(1, &[rn]);
        self.emit(Op::Mov, rc, rn, F::ZERO);

        let top = self.instrs.len() as u64;
        let before: Vec<Place> = self.slots.iter().map(|s| s.place).collect();
        body(self, Felt(ctr));
        for (id, was) in before.iter().enumerate() {
            let now = self.slots[id].place;
            assert!(
                now == *was,
                "counted_loop: the body moved handle {id} from {was:?} to {now:?}. A loop body is \
                 emitted once and run many times, so it must leave the allocation of every handle \
                 that existed before it untouched — pass values in and out through memory."
            );
        }

        self.begin();
        self.emit(Op::Faddi, rc, rc, F::NEG_ONE);
        self.emit(Op::Jne, rc, 0, F::from_u64(top));
    }

    // ---------------------------------------------------------------- output

    pub fn public(&mut self, v: Felt) {
        self.begin();
        let ra = self.materialise(v.0);
        self.emit(Op::Public, 0, ra, F::ZERO);
    }

    /// `c0` then `c1`, the order `BasedVectorSpace` reads an extension element in.
    pub fn public_ext(&mut self, v: Ext) {
        self.begin();
        let ra = self.materialise(v.0);
        self.emit(Op::Public, 0, ra, F::ZERO);
        self.emit(Op::Public, 0, ra + 1, F::ZERO);
    }

    /// An intermediate value a differential test wants to see: published under
    /// [`Checkpoints::On`], nothing at all under `Off`. The name is recorded either way.
    pub fn checkpoint(&mut self, name: &str, v: Ext) {
        self.names.push(name.to_string());
        if self.mode == Checkpoints::On {
            self.public_ext(v);
        }
    }

    // ------------------------------------------------------------- emission

    fn begin(&mut self) {
        self.scratch = 0;
    }

    fn emit(&mut self, op: Op, rd: u8, ra: u8, b: F) {
        self.instrs.push(Instr { op, rd, ra, b });
        self.stats.instrs += 1;
    }

    fn emit_r(&mut self, op: Op, rd: u8, ra: u8, rb: u8) {
        self.emit(op, rd, ra, F::from_u8(rb));
    }

    /// The inline trap for an assertion, and the name its `pc` resolves to.
    fn trap(&mut self, what: &str) {
        let at = self.instrs.len() as u32;
        self.emit(Op::Inv, 1, 0, F::ZERO);
        self.checkpoints.push((at, what.to_string()));
    }

    fn un(&mut self, op: Op, a: Felt, c: F) -> Felt {
        self.begin();
        let ra = self.materialise(a.0);
        let (id, rd) = self.new_handle(1, &[ra]);
        self.emit(op, rd, ra, c);
        Felt(id)
    }

    fn bin(&mut self, op: Op, a: Felt, b: Felt) -> Felt {
        self.begin();
        let ra = self.materialise(a.0);
        let rb = self.materialise(b.0);
        let (id, rd) = self.new_handle(1, &[ra, rb]);
        self.emit_r(op, rd, ra, rb);
        Felt(id)
    }

    fn ebin(&mut self, op: Op, a: Ext, b: Ext) -> Ext {
        self.begin();
        let ra = self.materialise(a.0);
        let rb = self.materialise(b.0);
        let (id, rd) = self.new_handle(2, &[ra, ra + 1, rb, rb + 1]);
        self.emit_r(op, rd, ra, rb);
        Ext(id)
    }

    /// The `(register, immediate)` pair an access through `p` at `off` uses.
    fn address(&mut self, p: Ptr, off: i64) -> (u8, F) {
        let it = self.ptrs[p.0 as usize];
        (self.materialise(it.holder), imm(it.delta + off))
    }

    // ------------------------------- raw emission, for the DSL's own hash layer

    // `dsl::hash`'s Merkle select is the one sequence in this crate that wants scratch registers
    // and raw instructions rather than handles: six handles per digest lane, all dead one row after
    // they are born, would spill six live-forever slots per lane and add 75% to the cost of every
    // Merkle level. These four hooks are `pub(super)`, so they are reachable from `dsl::hash` and
    // `dsl::transcript` and from nowhere else. The discipline they demand is the emitter's: call
    // `raw_group` once, then `raw_reg` for every handle operand (a spilled one reloads into scratch,
    // which is why they come first), then `raw_scratch` for working registers, and emit. Nothing
    // that allocates a handle may run in between, or the allocator may move an operand out from
    // under the instructions already emitted.

    /// Start a raw instruction group: releases every scratch register the previous one held.
    pub(super) fn raw_group(&mut self) {
        self.begin();
    }

    /// `n` further contiguous scratch registers, reserved until the next [`Builder::raw_group`].
    pub(super) fn raw_scratch(&mut self, n: usize) -> u8 {
        self.take_scratch(n)
    }

    /// The register holding `v`, reloading a spilled handle into scratch exactly as any operand is.
    pub(super) fn raw_reg(&mut self, v: Felt) -> u8 {
        self.materialise(v.0)
    }

    /// The `(base register, compile-time cell delta)` an access through `p` uses.
    pub(super) fn raw_ptr(&mut self, p: Ptr) -> (u8, i64) {
        let it = self.ptrs[p.0 as usize];
        (self.materialise(it.holder), it.delta)
    }

    /// One instruction, verbatim. `b` is an immediate; use [`Builder::raw_reg_imm`] for a register
    /// in the fourth slot.
    pub(super) fn raw_emit(&mut self, op: Op, rd: u8, ra: u8, b: F) {
        self.emit(op, rd, ra, b);
    }

    /// A register index as the fourth word of an instruction.
    pub(super) fn raw_reg_imm(r: u8) -> F {
        F::from_u8(r)
    }

    /// A signed cell delta as an address immediate.
    pub(super) fn raw_imm(delta: i64) -> F {
        imm(delta)
    }

    // ------------------------------------------------------------ allocation

    /// The register holding `id`, reloading it into scratch if it has been spilled. A reloaded
    /// handle stays in memory: there is no promotion, so each use of a spilled handle costs one
    /// `LOAD`/`LOADE`.
    fn materialise(&mut self, id: u32) -> u8 {
        let slot = self.slots[id as usize];
        match slot.place {
            Place::Reg(r) => r,
            Place::Mem(addr) => {
                let s = self.take_scratch(slot.width as usize);
                let op = if slot.width == 1 { Op::Load } else { Op::Loade };
                self.emit(op, s, 0, F::from_u64(addr));
                self.stats.reloads += 1;
                s
            }
        }
    }

    /// The next `width` scratch registers. Contiguous, so a width-2 reload is a legal `E` operand.
    fn take_scratch(&mut self, width: usize) -> u8 {
        let at = self.scratch;
        assert!(
            at + width <= SCRATCH.len(),
            "one instruction wanted more than {} scratch registers",
            SCRATCH.len()
        );
        self.scratch = at + width;
        SCRATCH[at]
    }

    /// A fresh handle in a fresh register, spilling as needed. `pinned` names the registers the
    /// instruction about to be emitted is reading, which must survive.
    fn new_handle(&mut self, width: u8, pinned: &[u8]) -> (u32, u8) {
        let reg = self.claim(width, pinned);
        let id = self.slots.len() as u32;
        self.slots.push(Slot { width, place: Place::Reg(reg), konst: None });
        self.regs[reg as usize] = Some(id);
        if width == 2 {
            self.regs[reg as usize + 1] = Some(id);
        }
        self.order.push_back(id);
        (id, reg)
    }

    fn claim(&mut self, width: u8, pinned: &[u8]) -> u8 {
        loop {
            if let Some(r) = self.free(width) {
                return r;
            }
            self.spill_oldest(pinned);
        }
    }

    /// A free register, or a free *aligned* consecutive pair for a width-2 handle. Aligning pairs to
    /// odd starts keeps singles from fragmenting the register file into unusable gaps.
    fn free(&self, width: u8) -> Option<u8> {
        let vacant = |r: u8| self.regs[r as usize].is_none();
        if width == 1 {
            ALLOCATABLE.iter().copied().find(|&r| vacant(r))
        } else {
            ALLOCATABLE
                .iter()
                .copied()
                .step_by(2)
                .find(|&r| r < ALLOCATABLE[ALLOCATABLE.len() - 1] && vacant(r) && vacant(r + 1))
        }
    }

    /// Evict the oldest resident handle whose registers this instruction does not need.
    fn spill_oldest(&mut self, pinned: &[u8]) {
        let at = self
            .order
            .iter()
            .position(|&id| {
                let slot = self.slots[id as usize];
                match slot.place {
                    Place::Reg(r) => !(0..slot.width).any(|k| pinned.contains(&(r + k))),
                    Place::Mem(_) => false,
                }
            })
            .expect("every allocatable register is pinned by one instruction");
        let id = self.order.remove(at).expect("position() returned a valid index");
        self.spill(id);
    }

    fn spill(&mut self, id: u32) {
        let slot = self.slots[id as usize];
        let Place::Reg(r) = slot.place else { return };
        let width = slot.width as u64;
        let addr = self.next_spill;
        assert!(
            addr + width <= MEM_BASE,
            "the {MEM_BASE}-cell spill arena is full; raise dsl::MEM_BASE"
        );
        self.next_spill += width;
        self.stats.cells += width;
        let op = if slot.width == 1 { Op::Store } else { Op::Storee };
        self.emit(op, r, 0, F::from_u64(addr));
        self.slots[id as usize].place = Place::Mem(addr);
        self.regs[r as usize] = None;
        if slot.width == 2 {
            self.regs[r as usize + 1] = None;
        }
        self.stats.spills += 1;
    }
}

/// A signed cell delta as an address immediate. Negative deltas are the field's negation, which is
/// the right answer for any address that is actually in range: `base + (-k)` is `base - k`.
fn imm(delta: i64) -> F {
    if delta >= 0 {
        F::from_u64(delta as u64)
    } else {
        F::ZERO - F::from_u64(delta.unsigned_abs())
    }
}
