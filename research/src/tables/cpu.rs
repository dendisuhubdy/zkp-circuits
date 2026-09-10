//! One row per cycle. Fetches from PROGRAM, reads and writes through MEMORY,
//! delegates arithmetic to ALU. The only table with public values.
use super::{bus, limbs, nibble::NibbleCounts, program::MESSAGE_LEN, range::RangeCounts, F};
use crate::emulator::{CycleEvent, Syscall, ECALL_MEM_REG, SLOT_MEM, SLOT_R1, SLOT_R2, SLOT_W};
use crate::isa::{NUM_OUTPUTS, SYS_HALT as SYS_NUM_HALT, SYS_READ_INPUT, SYS_WRITE_OUTPUT};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

pub mod col {
    pub const CLK: usize = 0; pub const PC: usize = 1; pub const NEXT_PC: usize = 2; pub const IS_REAL: usize = 3;
    pub const DEC0: usize = 4;
    pub const RD: usize = 4; pub const RS1: usize = 5; pub const RS2: usize = 6; pub const IMM: usize = 7;
    pub const IS_ALU: usize = 8; pub const ALU_OP: usize = 9; pub const IS_IMM: usize = 10; pub const IS_BRANCH: usize = 11;
    pub const BR_OP: usize = 12; pub const BR_NEG: usize = 13;
    /// M2.5: one-hot per load/store mnemonic, replacing the old `IS_LOAD`/`IS_STORE`
    /// booleans. `is_load`/`is_store` are now *expressions* — `IS_LB+IS_LH+IS_LW` and
    /// `IS_SB+IS_SH+IS_SW` — not columns.
    pub const IS_LB: usize = 14; pub const IS_LH: usize = 15; pub const IS_LW: usize = 16;
    pub const IS_SB: usize = 17; pub const IS_SH: usize = 18; pub const IS_SW: usize = 19;
    /// Set for `LB`/`LH` (signed loads); meaningless (and left 0) on every other row.
    pub const SIGNED: usize = 20;
    pub const IS_JAL: usize = 21; pub const IS_JALR: usize = 22; pub const IS_LUI: usize = 23; pub const IS_AUIPC: usize = 24;
    pub const IS_ECALL: usize = 25; pub const WRITES_RD: usize = 26;
    pub const A: usize = 27; pub const B: usize = 28; pub const C: usize = 29; pub const ALU_OUT: usize = 30; pub const TGT: usize = 31;
    pub const MEM_ADDR: usize = 32; pub const MEM_VAL: usize = 33;
    pub const SYS_HALT: usize = 34; pub const SYS_WRITE: usize = 35; pub const SYS_READ: usize = 36;
    pub const OUT_SEL0: usize = 37;
    /// `WRITTEN_i` is the running count of `OUT_SEL_i` over rows `0..=this one`. It is
    /// boolean on every row, so a slot can be written at most once (the emulator's
    /// `DoubleWrite` rule), and because `OUT_SEL_i` is zero on padding rows the value
    /// survives to the last row, where it says whether slot `i` was ever written.
    pub const WRITTEN0: usize = OUT_SEL0 + crate::isa::NUM_OUTPUTS;  // 45
    /// The four byte limbs of `MEM_ADDR` (the WORD address) on load/store rows: what makes
    /// word alignment a stated constraint rather than a side effect of the memory table's
    /// key ordering. Unchanged in role since M2.3/M2.4 — M2.5 only adds the `OFF0/OFF1`
    /// sub-word offset alongside this, it does not touch what `MA0..3` decompose.
    pub const MA0: usize = WRITTEN0 + crate::isa::NUM_OUTPUTS;       // 53
    /// `MA0+3`'s high nibble, for the alignment bound (see the `is_mem` block in `eval`).
    pub const MA3_HI: usize = MA0 + 4;                               // 57
    /// The byte offset of the access within its word, `ALU_OUT & 3`, as two booleans:
    /// `off = OFF0 + 2*OFF1`. Meaningful (and range-relevant) only on load/store rows.
    pub const OFF0: usize = MA3_HI + 1;                              // 58
    pub const OFF1: usize = OFF0 + 1;                                // 59
    /// The four byte limbs of `MEM_VAL` (the word actually in memory — the read value for
    /// a load, the *pre-store* value for a store) on every load/store row, RANGE8-checked.
    pub const W0: usize = OFF1 + 1;                                  // 60
    /// The byte selected by `OFF0/OFF1` out of `W0..3`: meaningful on `LB`/`SB` rows.
    pub const BYTE: usize = W0 + 4;                                  // 64
    /// The halfword selected by `OFF1` out of `W0..3`: meaningful on `LH`/`SH` rows.
    pub const HALF: usize = BYTE + 1;                                // 65
    /// The sign-relevant byte's high nibble (`BYTE`'s for `LB`, the top byte of `HALF`'s
    /// halfword for `LH`) — an isolated extraction, so its low-nibble companion gets its
    /// own dummy `AND4` range check, exactly the M2.4 sign-bit pattern in `alu.rs`.
    pub const HI: usize = HALF + 1;                                  // 66
    /// The sign bit of that byte: `HI`'s top bit, via `AND4[HI, 8, SGN*8]`.
    pub const SGN: usize = HI + 1;                                   // 67
    /// The four byte limbs of `B` (the value read from `rs2`) on store rows, RANGE8-checked
    /// — this is what ties a store's written bytes back to a value that was actually in a
    /// register (the M1 store-forgery invariant, generalized to sub-word stores).
    pub const RB0: usize = SGN + 1;                                  // 68
    /// The merged word a store writes back: `W0..3` with the bytes `OFF0/OFF1`/width select
    /// replaced by the corresponding bytes of `B` (`RB0..3`), everything else left alone —
    /// a read-modify-write over the addressed word, spelled out per byte.
    pub const MERGED0: usize = RB0 + 4;                              // 72
    pub const WIDTH: usize = MERGED0 + 4;                            // 76
    /// Columns that must be zero on padding rows.
    pub const SELECTORS: [usize; 20] = [
        IS_ALU, IS_IMM, IS_BRANCH, IS_LB, IS_LH, IS_LW, IS_SB, IS_SH, IS_SW, SIGNED,
        IS_JAL, IS_JALR, IS_LUI, IS_AUIPC, IS_ECALL, WRITES_RD, SYS_HALT, SYS_WRITE, SYS_READ, BR_NEG,
    ];
}
pub mod pv { pub const PC_ENTRY: usize = 0; pub const TIER: usize = 1; pub const OUT0: usize = 2; pub const NUM: usize = 2 + crate::isa::NUM_OUTPUTS; }
use col::*;

#[derive(Clone, Copy, Debug, Default)]
pub struct CpuAir;

impl<Fld> BaseAir<Fld> for CpuAir {
    fn width(&self) -> usize { WIDTH }
    fn num_public_values(&self) -> usize { pv::NUM }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for CpuAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let pvs: Vec<AB::Expr> = b.public_values().iter().map(|p| (*p).into()).collect();
        let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let n = |i: usize| -> AB::Expr { m.next(i).unwrap().into() };
        let one = AB::Expr::ONE;
        let four = AB::Expr::from_u32(4);
        let c8 = |k: u32| AB::Expr::from_u32(1u32 << (8 * k));
        let is_real = v(IS_REAL);

        b.assert_bool(is_real.clone());
        for s in SELECTORS { b.assert_bool(v(s)); b.assert_zero((one.clone() - is_real.clone()) * v(s)); }
        {
            let mut f = b.when_first_row();
            f.assert_one(v(IS_REAL));
            f.assert_zero(v(CLK));
            f.assert_eq(v(PC), pvs[pv::PC_ENTRY].clone());
        }
        b.when_last_row().assert_zero(v(IS_REAL));
        {
            let mut t = b.when_transition();
            t.assert_zero((one.clone() - is_real.clone()) * n(IS_REAL));
            t.assert_zero(n(IS_REAL) * (n(CLK) - v(CLK) - one.clone()));
            t.assert_zero(n(IS_REAL) * (n(PC) - v(NEXT_PC)));
            // the last real row is a HALT, and nothing runs after a HALT
            t.assert_zero(is_real.clone() * (one.clone() - n(IS_REAL)) * (one.clone() - v(SYS_HALT)));
            t.assert_zero(v(SYS_HALT) * n(IS_REAL));
        }

        // fetch
        let msg: Vec<AB::Expr> = std::iter::once(v(PC)).chain((0..MESSAGE_LEN - 1).map(|k| v(DEC0 + k))).collect();
        bus::PROGRAM.lookup_key(b, msg, Count::bounded(is_real.clone(), 1));

        // `is_load`/`is_store` are expressions now, not columns (M2.5): one-hot sums over
        // the per-width selectors the program table pre-decodes.
        let is_load = v(IS_LB) + v(IS_LH) + v(IS_LW);
        let is_store = v(IS_SB) + v(IS_SH) + v(IS_SW);
        let is_mem = is_load.clone() + is_store.clone();

        // operand select and ALU delegation
        let b_eff = v(IS_IMM) * v(IMM) + (one.clone() - v(IS_IMM)) * v(B);
        let op1 = v(IS_ALU) * v(ALU_OP) + v(IS_BRANCH) * v(BR_OP);
        let uses_slot1 = v(IS_ALU) + v(IS_BRANCH) + is_mem.clone() + v(IS_JALR);
        bus::ALU.lookup_key(b, [op1, v(A), b_eff, v(ALU_OUT)], Count::bounded(uses_slot1, 1));
        let uses_slot2 = v(IS_BRANCH) + v(IS_JAL) + v(IS_AUIPC);
        bus::ALU.lookup_key(b, [AB::Expr::ZERO, v(PC), v(IMM), v(TGT)], Count::bounded(uses_slot2, 1));

        // rd value
        b.assert_zero(v(IS_ALU) * (v(C) - v(ALU_OUT)));
        b.assert_zero((v(IS_JAL) + v(IS_JALR)) * (v(C) - v(PC) - four.clone()));
        b.assert_zero(v(IS_LUI) * (v(C) - v(IMM)));
        b.assert_zero(v(IS_AUIPC) * (v(C) - v(TGT)));
        // On every other kind of row (branch, store, ecall HALT/WRITE_OUTPUT) nothing above
        // (or below) defines C, and it is never sent on the WRITES_RD/SYS_READ register-write
        // message either, so without this constraint C is a completely free column there: a
        // malicious witness could set it to anything with no other constraint noticing.
        // `cpu_trace` always leaves it at the emulator's own `c = 0` default for these rows
        // (see `emulator::execute`), so this cannot reject any honest trace. Pin it to that
        // same zero sentinel.
        let defines_c = v(IS_ALU) + is_load.clone() + v(IS_JAL) + v(IS_JALR) + v(IS_LUI) + v(IS_AUIPC) + v(SYS_READ);
        b.assert_zero((one.clone() - defines_c) * v(C));

        // next pc
        let taken = v(ALU_OUT) + v(BR_NEG) - v(ALU_OUT) * v(BR_NEG) * AB::Expr::TWO;
        let fallthrough = v(PC) + four.clone();
        b.assert_zero(v(IS_BRANCH) * (v(NEXT_PC) - fallthrough.clone() - taken * (v(TGT) - fallthrough.clone())));
        b.assert_zero(v(IS_JAL) * (v(NEXT_PC) - v(TGT)));
        b.assert_zero(v(IS_JALR) * (v(NEXT_PC) - v(ALU_OUT)));
        b.assert_zero(is_real.clone() * (one.clone() - v(IS_BRANCH) - v(IS_JAL) - v(IS_JALR)) * (v(NEXT_PC) - fallthrough));

        // memory: address, alignment, and the word actually in memory
        //
        // `ALU_OUT` is the byte address; `MEM_ADDR` (word address) and `OFF0/OFF1` (the
        // byte offset within the word, `off = OFF0 + 2*OFF1`) are its quotient and
        // remainder by 4, both *stated*, not just implied by `MEM_ADDR·4 + off = ALU_OUT`
        // alone — that identity is a field relation only, and unconstrained `MEM_ADDR` could
        // satisfy it with `MEM_ADDR = (ALU_OUT − off)·4⁻¹ mod p` for any `off` a cheating
        // witness likes. What rules that out, exactly as it did pre-M2.5 (`docs/01-isa.md`):
        // `MEM_ADDR` is decomposed into four RANGE8-checked byte limbs `MA0..3`, bounded
        // below 2^30 by a nibble bound on the top limb (`MA3_HI`, `AND4[MA3_HI, 0xC, 0]`,
        // the M2.3 replacement for the old `AND8` byte-table check) — so `MEM_ADDR` is an
        // honest integer in `[0, 2^30)`, and with `ALU_OUT` already 32-bit (the ALU table's
        // own limb checks) and `off` a sum of two booleans (`< 4`), `MEM_ADDR·4 + off < 2^32`
        // cannot wrap: the identity holds over the integers, not just mod p.
        b.assert_bool(v(OFF0));
        b.assert_bool(v(OFF1));
        let off = v(OFF0) + AB::Expr::TWO * v(OFF1);
        let mut ma = AB::Expr::ZERO;
        for i in 0..4 { ma += v(MA0 + i) * AB::Expr::from_u32(1 << (8 * i)); }
        b.assert_zero(is_mem.clone() * (v(MEM_ADDR) - ma));
        for i in 0..4 { bus::RANGE8.lookup_key(b, [v(MA0 + i)], Count::bounded(is_mem.clone(), 1)); }
        let ma3_lo = v(MA0 + 3) - AB::Expr::from_u32(16) * v(MA3_HI);
        bus::AND4.lookup_key(b, [ma3_lo, AB::Expr::ZERO, AB::Expr::ZERO], Count::bounded(is_mem.clone(), 1));
        bus::AND4.lookup_key(b, [v(MA3_HI), AB::Expr::from_u32(0xC), AB::Expr::ZERO], Count::bounded(is_mem.clone(), 1));
        b.assert_zero(is_mem.clone() * (v(MEM_ADDR) * four.clone() + off.clone() - v(ALU_OUT)));
        // Sub-word alignment: a full word must sit on a word boundary, a half on a 2-byte
        // boundary; a byte is never misaligned. Spec M2.5, verbatim.
        b.assert_zero((v(IS_LW) + v(IS_SW)) * (v(OFF0) + v(OFF1)));
        b.assert_zero((v(IS_LH) + v(IS_SH)) * v(OFF0));
        b.assert_zero(v(IS_ECALL) * (v(MEM_ADDR) - AB::Expr::from_u32(ECALL_MEM_REG)));

        // The word actually in memory at `MEM_ADDR` (the read value for a load, the
        // pre-store value for a store — `emulator::execute` pushes exactly this as the
        // `SLOT_MEM` read for both), decomposed the same way as `MEM_ADDR`.
        let mem_word = |base: usize| v(base) + v(base + 1) * c8(1) + v(base + 2) * c8(2) + v(base + 3) * c8(3);
        for i in 0..4 { bus::RANGE8.lookup_key(b, [v(W0 + i)], Count::bounded(is_mem.clone(), 1)); }
        b.assert_zero(is_mem.clone() * (v(MEM_VAL) - mem_word(W0)));

        // Byte/halfword select out of the word, by `OFF0/OFF1`.
        let sel = |k: usize| -> AB::Expr {
            match k {
                0 => (one.clone() - v(OFF0)) * (one.clone() - v(OFF1)),
                1 => v(OFF0) * (one.clone() - v(OFF1)),
                2 => (one.clone() - v(OFF0)) * v(OFF1),
                3 => v(OFF0) * v(OFF1),
                _ => unreachable!(),
            }
        };
        let byte = (0..4).map(|k| sel(k) * v(W0 + k)).sum::<AB::Expr>();
        b.assert_zero((v(IS_LB) + v(IS_SB)) * (v(BYTE) - byte));
        let half = (one.clone() - v(OFF1)) * (v(W0) + c8(1) * v(W0 + 1)) + v(OFF1) * (v(W0 + 2) + c8(1) * v(W0 + 3));
        b.assert_zero((v(IS_LH) + v(IS_SH)) * (v(HALF) - half));

        // Sign extension for LB/LH: the sign-relevant byte is BYTE itself for LB, and the
        // top byte of whichever half OFF1 selected for LH (W1 if OFF1=0, W3 if OFF1=1) —
        // reusing the already-committed word limbs rather than dividing HALF back apart.
        // Isolated nibble extraction (this byte's low nibble has no other lookup on this
        // row), so it needs its own dummy AND4 range check — the same pattern as the ALU
        // table's sign-bit extraction (M2.4, `alu.rs::nibble_lo_dummy_range`).
        let sign_byte = v(IS_LB) * v(BYTE) + v(IS_LH) * ((one.clone() - v(OFF1)) * v(W0 + 1) + v(OFF1) * v(W0 + 3));
        let is_sub_load = v(IS_LB) + v(IS_LH);
        let hi_lo = sign_byte - AB::Expr::from_u32(16) * v(HI);
        bus::AND4.lookup_key(b, [hi_lo, AB::Expr::ZERO, AB::Expr::ZERO], Count::bounded(is_sub_load.clone(), 1));
        bus::AND4.lookup_key(b, [v(HI), AB::Expr::from_u32(8), v(SGN) * AB::Expr::from_u32(8)], Count::bounded(is_sub_load, 1));

        // The loaded value, sign/zero-extended.
        let two32 = AB::Expr::from_u64(1u64 << 32);
        let c_load = v(IS_LB) * (v(BYTE) + v(SGN) * v(SIGNED) * (two32.clone() - AB::Expr::from_u32(1 << 8)))
            + v(IS_LH) * (v(HALF) + v(SGN) * v(SIGNED) * (two32 - AB::Expr::from_u32(1 << 16)))
            + v(IS_LW) * v(MEM_VAL);
        b.assert_zero(is_load.clone() * (v(C) - c_load));

        // Stores: `B` (rs2's value, already read every row) decomposes into byte limbs
        // `RB0..3` — exactly the M1 store-forgery invariant (`2c8a39d`), generalized: a
        // store's written bytes must trace back to a value that was actually in a register.
        for i in 0..4 { bus::RANGE8.lookup_key(b, [v(RB0 + i)], Count::bounded(is_store.clone(), 1)); }
        b.assert_zero(is_store.clone() * (v(B) - mem_word(RB0)));
        // Which byte(s) of the word this store overwrites, and with what.
        let selp = |k: usize| -> AB::Expr {
            v(IS_SW) + v(IS_SH) * (if k <= 1 { one.clone() - v(OFF1) } else { v(OFF1) }) + v(IS_SB) * sel(k)
        };
        let bp = |k: usize| -> AB::Expr {
            v(IS_SW) * v(RB0 + k) + v(IS_SH) * (if k == 0 || k == 2 { v(RB0) } else { v(RB0 + 1) }) + v(IS_SB) * v(RB0)
        };
        // MERGED: a read-modify-write over the word, spelled out per byte — untouched bytes
        // carry `W_k` forward, touched bytes take `bp(k)`. (When IS_SW=1, `selp(k)=1` for
        // every k and `bp(k)=RB0+k`, so `MERGED_k = RB0+k`, i.e. `merged = word(RB0) = B` —
        // this is the invariant the doc comment below states in words.)
        for k in 0..4usize {
            b.assert_zero(is_store.clone() * (v(MERGED0 + k) - v(W0 + k) - selp(k) * (bp(k) - v(W0 + k))));
        }
        let merged = mem_word(MERGED0);

        let ts = |slot: u32| v(CLK) * four.clone() + AB::Expr::from_u32(slot);
        let zero = AB::Expr::ZERO;
        bus::MEMORY.send(b, [zero.clone(), v(RS1), ts(SLOT_R1), v(A), zero.clone()], Count::bounded(is_real.clone(), 1));
        bus::MEMORY.send(b, [zero.clone(), v(RS2), ts(SLOT_R2), v(B), zero.clone()], Count::bounded(is_real.clone(), 1));
        // A load's or a store's own access is always a READ of the word that was there —
        // `MEM_VAL`. A store's *write* goes out separately below, on `SLOT_W`.
        bus::MEMORY.send(b, [is_mem.clone(), v(MEM_ADDR), ts(SLOT_MEM), v(MEM_VAL), zero.clone()], Count::bounded(is_mem + v(IS_ECALL), 1));
        // `SLOT_W`: either a register writeback (space 0, addr RD, value C — WRITES_RD or
        // SYS_READ rows) or a store's word write (space 1/RAM, addr MEM_ADDR, value MERGED —
        // the pin that replaces `2c8a39d`'s "a store's mem_val is the rs2 value": now "the
        // written value is MERGED, and MERGED = B when IS_SW", proved structurally by the
        // MERGED formula above). The two never coincide on one row (a store never sets
        // WRITES_RD or SYS_READ), so the shared slot and its four-timestamps-per-cycle
        // scheme still carry exactly one message.
        let slot_w_space = is_store.clone();
        let slot_w_addr = is_store.clone() * v(MEM_ADDR) + (one.clone() - is_store.clone()) * v(RD);
        let slot_w_val = is_store.clone() * merged + (one.clone() - is_store.clone()) * v(C);
        bus::MEMORY.send(b, [slot_w_space, slot_w_addr, ts(SLOT_W), slot_w_val, one.clone()], Count::bounded(v(WRITES_RD) + v(SYS_READ) + is_store, 1));

        // syscalls: a = number, b = arg0, mem_val = arg1
        let sys_sum = v(SYS_HALT) + v(SYS_WRITE) + v(SYS_READ);
        b.assert_zero(v(IS_ECALL) * (sys_sum.clone() - one.clone()));
        b.assert_zero((one.clone() - v(IS_ECALL)) * sys_sum);
        b.assert_zero(v(SYS_HALT) * (v(A) - AB::Expr::from_u32(SYS_NUM_HALT)));
        b.assert_zero(v(SYS_WRITE) * (v(A) - AB::Expr::from_u32(SYS_WRITE_OUTPUT)));
        b.assert_zero(v(SYS_READ) * (v(A) - AB::Expr::from_u32(SYS_READ_INPUT)));
        let mut sel_sum = AB::Expr::ZERO;
        for i in 0..NUM_OUTPUTS {
            let s = v(OUT_SEL0 + i);
            b.assert_bool(s.clone());
            b.assert_zero(s.clone() * (v(B) - AB::Expr::from_u32(i as u32)));
            b.assert_zero(s.clone() * (v(MEM_VAL) - pvs[pv::OUT0 + i].clone()));
            sel_sum += s;
        }
        b.assert_eq(sel_sum, v(SYS_WRITE));
        // Spec §3.4: an output slot no `WRITE_OUTPUT` ever selected is zero. Only the slots
        // a `WRITE_OUTPUT` row selects are pinned above, so without this a never-written
        // slot's `pv[OUT0 + i]` is a free public value. `WRITTEN_i` accumulates `OUT_SEL_i`;
        // asserting it boolean on every row also caps each slot at one write. `OUT_SEL_i` is
        // zero on every padding row (its sum is `SYS_WRITE`, a `SELECTORS` entry), so the
        // accumulator holds its final value through the padding to the last row.
        for i in 0..NUM_OUTPUTS {
            b.assert_bool(v(WRITTEN0 + i));
            b.when_first_row().assert_eq(v(WRITTEN0 + i), v(OUT_SEL0 + i));
            b.when_transition().assert_eq(n(WRITTEN0 + i), v(WRITTEN0 + i) + n(OUT_SEL0 + i));
            b.when_last_row().assert_zero((one.clone() - v(WRITTEN0 + i)) * pvs[pv::OUT0 + i].clone());
        }
    }
}

pub fn public_values(pc_entry: u32, tier_log2: usize, outputs: &[u32; NUM_OUTPUTS]) -> Vec<F> {
    let mut v = vec![F::from_u32(pc_entry), F::from_u64(tier_log2 as u64)];
    v.extend(outputs.iter().map(|o| F::from_u32(*o)));
    v
}

/// `range`/`nibble` receive the `RANGE8`/`AND4` lookups the alignment limbs declare, in
/// lock-step with the interactions the AIR above evaluates.
pub fn cpu_trace(events: &[CycleEvent], height: usize, range: &mut RangeCounts, nibble: &mut NibbleCounts) -> RowMajorMatrix<F> {
    assert!(events.len() < height, "cpu table needs a padding row: {} cycles, height {height}", events.len());
    let mut v = F::zero_vec(height * WIDTH);
    let mut written = [0u32; NUM_OUTPUTS];
    for (i, e) in events.iter().enumerate() {
        let r = &mut v[i * WIDTH..(i + 1) * WIDTH];
        r[CLK] = F::from_u32(e.clk); r[PC] = F::from_u32(e.pc); r[NEXT_PC] = F::from_u32(e.next_pc); r[IS_REAL] = F::ONE;
        for (k, f) in e.dec.to_fields().iter().enumerate() { r[DEC0 + k] = F::from_u32(*f); }
        r[A] = F::from_u32(e.a); r[B] = F::from_u32(e.b); r[C] = F::from_u32(e.c);
        r[ALU_OUT] = F::from_u32(e.alu_out); r[TGT] = F::from_u32(e.tgt);
        r[MEM_ADDR] = F::from_u32(e.mem_addr); r[MEM_VAL] = F::from_u32(e.mem_val);
        let is_load = e.dec.is_lb == 1 || e.dec.is_lh == 1 || e.dec.is_lw == 1;
        let is_store = e.dec.is_sb == 1 || e.dec.is_sh == 1 || e.dec.is_sw == 1;
        if is_load || is_store {
            let ml = limbs(e.mem_addr);
            for k in 0..4 { r[MA0 + k] = ml[k]; range.range8((e.mem_addr >> (8 * k)) & 0xff); }
            let ma3 = (e.mem_addr >> 24) & 0xff;
            let (ma3_lo, ma3_hi) = (ma3 & 0xf, ma3 >> 4);
            r[MA3_HI] = F::from_u32(ma3_hi);
            nibble.and4(ma3_lo, 0);
            nibble.and4(ma3_hi, 0xC);

            // The sub-word offset `ALU_OUT & 3`, and the word actually in memory (`MEM_VAL`
            // — the read value for a load, the pre-store value for a store).
            let off = e.alu_out & 3;
            let (off0, off1) = (off & 1, (off >> 1) & 1);
            r[OFF0] = F::from_u32(off0); r[OFF1] = F::from_u32(off1);
            let wl = limbs(e.mem_val);
            for k in 0..4 { r[W0 + k] = wl[k]; range.range8((e.mem_val >> (8 * k)) & 0xff); }

            if e.dec.is_lb == 1 || e.dec.is_sb == 1 {
                let byte = (e.mem_val >> (8 * off)) & 0xff;
                r[BYTE] = F::from_u32(byte);
            }
            if e.dec.is_lh == 1 || e.dec.is_sh == 1 {
                let half = (e.mem_val >> (16 * off1)) & 0xffff;
                r[HALF] = F::from_u32(half);
            }
            if e.dec.is_lb == 1 || e.dec.is_lh == 1 {
                let sign_byte = if e.dec.is_lb == 1 { (e.mem_val >> (8 * off)) & 0xff } else if off1 == 0 { (e.mem_val >> 8) & 0xff } else { (e.mem_val >> 24) & 0xff };
                let (lo, hi) = (sign_byte & 0xf, sign_byte >> 4);
                r[HI] = F::from_u32(hi);
                r[SGN] = F::from_u32(hi >> 3);
                nibble.and4(lo, 0);
                nibble.and4(hi, 8);
            }
            if is_store {
                let bl = limbs(e.b);
                for k in 0..4 { r[RB0 + k] = bl[k]; range.range8((e.b >> (8 * k)) & 0xff); }
                // Read-modify-write, mirroring `emulator::execute`'s `Store` arm exactly:
                // `e.mem_val` is the pre-store word, `e.b` is rs2's value.
                let merged = if e.dec.is_sw == 1 {
                    e.b
                } else if e.dec.is_sh == 1 {
                    (e.mem_val & !(0xffffu32 << (8 * off))) | ((e.b & 0xffff) << (8 * off))
                } else {
                    (e.mem_val & !(0xffu32 << (8 * off))) | ((e.b & 0xff) << (8 * off))
                };
                let mgl = limbs(merged);
                for k in 0..4 { r[MERGED0 + k] = mgl[k]; }
            }
        }
        match e.sys {
            Some(Syscall::Halt) => r[SYS_HALT] = F::ONE,
            Some(Syscall::WriteOutput { slot, .. }) => { r[SYS_WRITE] = F::ONE; r[OUT_SEL0 + slot as usize] = F::ONE; written[slot as usize] += 1; }
            Some(Syscall::ReadInput { .. }) => r[SYS_READ] = F::ONE,
            None => {}
        }
        for (k, w) in written.iter().enumerate() { r[WRITTEN0 + k] = F::from_u32(*w); }
    }
    // The accumulator must carry its final value through the padding: the last row is where
    // `(1 − written_i)·pv[out_i] = 0` reads it.
    for i in events.len()..height {
        let r = &mut v[i * WIDTH..(i + 1) * WIDTH];
        for (k, w) in written.iter().enumerate() { r[WRITTEN0 + k] = F::from_u32(*w); }
    }
    RowMajorMatrix::new(v, WIDTH)
}
