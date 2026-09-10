//! Every test here builds a wrong witness and checks the verifier rejects it.
//! In debug builds Plonky3 panics inside `prove_batch` on the first violated
//! constraint — either one AIR's own row constraint, or (for a violation only
//! visible across AIR instances, like an unpaid extra table multiplicity) the
//! global lookup-balance check; in release builds it produces a proof that
//! fails to verify. `rejects` accepts any of these — and nothing else.
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;
use rand_zkvm::asm::{ops::*, Assembler};
use rand_zkvm::emulator::{execute, SLOT_W};
use rand_zkvm::guests;
use rand_zkvm::isa::REG_A1;
use rand_zkvm::machine::{build_traces, FriProfile, Machine, Tier, Traces};
use rand_zkvm::tables::{alu, cpu, memory, nibble, program, range, F};
use std::panic::{catch_unwind, AssertUnwindSafe};

/// The panic `p3-batch-stark`'s debug constraint checker raises when a row violates a
/// constraint. Its full form is
/// `"constraints not satisfied on row {row_index}: failed constraints = {rendered}"` —
/// the `panic!` at the end of the row loop in
/// `~/.cargo/registry/src/index.crates.io-*/p3-batch-stark-0.7.0/src/check_constraints.rs`
/// (line 132 in that release). Matching the fixed prefix is what separates "the constraint
/// system caught this" from any other unwind. This check runs *per AIR instance*, using only
/// that instance's own trace, so it only catches a violation that's local to one table's own
/// row constraints (e.g. the range table's `mp·(1 − is_pow2) = 0`).
const CONSTRAINT_PANIC: &str = "constraints not satisfied on row";

/// The panic `p3-lookup`'s debug bus-balance checker
/// (`p3_lookup::debug_util::check_lookups`, `check_lookups`'s `assert_empty`) raises when a
/// *global* lookup — one whose provider and consumers live in different AIR instances, which
/// is every bus in this crate except the ALU/CPU's shared-table cases — has a nonzero net
/// multiplicity for some tuple, after every instance's own `CONSTRAINT_PANIC` pass has
/// already run clean. For a table with no row-level validity marker of its own — the nibble
/// table's every `(a, b)` row is a genuine AND/OR/XOR entry, unlike the range table's
/// `is_pow2` flag — an unpaid extra multiplicity is *only* visible cross-instance: the row
/// itself is perfectly well-formed, so `CONSTRAINT_PANIC` never fires, and this is the sole
/// mechanism left to catch it. It is exactly as much "the constraint system caught this" as
/// `CONSTRAINT_PANIC` — just checked at the scope of the whole batch instead of one row of
/// one instance.
const LOOKUP_BALANCE_PANIC: &str = "Lookup mismatch (";

/// A tamper counts as rejected only if `verify` returned an error, or if the panic came from
/// one of the two constraint-system checks above. Anything else — a trace-builder `assert!`,
/// an index out of bounds — means the test tripped over something other than the constraint
/// it was written for, so it must fail rather than pass for the wrong reason.
fn rejects(f: impl FnOnce() -> Result<(), rand_zkvm::machine::VerifyError>) -> bool {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => false,
        Ok(Err(_)) => true,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<non-string panic payload>".to_string());
            let is_constraint = msg.contains(CONSTRAINT_PANIC) || msg.contains(LOOKUP_BALANCE_PANIC);
            if !is_constraint { eprintln!("rejects(): panic was not a constraint failure: {msg}"); }
            is_constraint
        }
    }
}

#[test]
fn rejects_only_counts_a_constraint_failure_or_a_verify_error() {
    assert!(rejects(|| Err(rand_zkvm::machine::VerifyError::PublicValues)));
    assert!(rejects(|| panic!("constraints not satisfied on row 7: failed constraints = [#1]")));
    assert!(rejects(|| panic!("Lookup mismatch (global lookup 'AND4'): tuple [\"9\", \"6\", \"0\"] has net multiplicity 1. Locations: []")));
    // A trace-builder `assert!` is not the constraint system catching anything.
    assert!(!rejects(|| panic!("alu table needs a padding row: 5 ops, height 4")));
    assert!(!rejects(|| Ok(())));
}

fn setup() -> (Machine, rand_zkvm::isa::Program, Traces) {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let e = execute(&p, &[], 10_000).unwrap();
    let t = build_traces(&p, &e, Tier(10)).unwrap();
    (m, p, t)
}

#[test]
fn honest_traces_pass() {
    let (m, p, t) = setup();
    let proof = m.prove_traces(&p, &t, Tier(10));
    m.verify(&p, &proof).unwrap();
}

#[test]
fn claiming_a_wrong_output_is_rejected() {
    let (m, p, mut t) = setup();
    t.public_values[cpu::pv::OUT0] = F::from_u32(56);   // fib(10) is 55
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

#[test]
fn tampering_a_register_value_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    t.cpu.values[3 * w + cpu::col::C] += F::ONE;         // row 3 writes a wrong rd
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

#[test]
fn skipping_a_cycle_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    let last = (0..t.cpu.height()).rev().find(|r| t.cpu.values[r * w + cpu::col::IS_REAL] == F::ONE).unwrap();
    // mark the row before HALT as padding: the chain of pcs breaks
    t.cpu.values[(last - 1) * w + cpu::col::IS_REAL] = F::ZERO;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

#[test]
fn proof_for_one_program_does_not_verify_another() {
    let m = Machine::new(FriProfile::Test);
    let (proof, _) = m.prove(&guests::fib(10), &[], None).unwrap();
    assert!(rejects(|| m.verify(&guests::fib(11), &proof)));
}

#[test]
fn wrong_tier_claim_is_rejected() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (mut proof, _) = m.prove(&p, &[], None).unwrap();
    proof.tier = Tier(12);
    assert!(rejects(|| m.verify(&p, &proof)));
}

#[test]
fn a_run_that_does_not_fit_the_tier_is_refused() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(300);   // ~1800 cycles > 2^10 - 1
    assert!(matches!(m.prove(&p, &[], Some(Tier(10))), Err(rand_zkvm::machine::ProveError::TooManyCycles { .. })));
    let (proof, _) = m.prove(&p, &[], None).unwrap();
    assert_eq!(proof.tier, Tier(12));
}

#[test]
fn out_of_range_tier_is_an_error_not_a_panic() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (mut proof, _) = m.prove(&p, &[], None).unwrap();
    proof.tier = Tier(99);
    proof.public_values[cpu::pv::TIER] = 99;
    assert!(matches!(m.verify(&p, &proof), Err(rand_zkvm::machine::VerifyError::Tier)));
}

#[test]
fn wrong_entry_point_claim_is_rejected() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (mut proof, _) = m.prove(&p, &[], None).unwrap();
    proof.public_values[cpu::pv::PC_ENTRY] = 4;
    assert!(matches!(m.verify(&p, &proof), Err(rand_zkvm::machine::VerifyError::PublicValues)));
}

/// Rewrite an honest `fib(10)` witness so that it claims `out0 = forged`, using nothing
/// but a *padding* row of the ALU table as the source of the arithmetic that justifies it.
///
/// The ALU table provides `(op, a, b, c)` on the ALU bus with count `MULT`. On a padding
/// row every op flag is zero — so the provided `op` decodes as `Add` — the limb range
/// checks and every arithmetic constraint are gated on a flag or on `is_real`, and (before
/// the `(1 − is_real)·MULT = 0` constraint) `MULT` itself was unconstrained. A padding row
/// could therefore hand the CPU an arbitrary `Add` tuple with arbitrary multiplicity.
///
/// The rewrite is a closed edit: `mv a1, t0` (the instruction that stages the output word)
/// is made to produce `forged` instead of `fib(10)`; the register file, every later `a1`
/// read, the `WRITE_OUTPUT` row's `mem_val` and the public output word follow; the honest
/// ALU row that provided the real tuple is retired to `MULT = 0` so the bus still balances,
/// and the forged tuple is planted on the last (padding) ALU row. Nothing else moves.
fn forge_fib_output_through_an_alu_padding_row(t: &mut Traces, forged: u32) {
    let (wc, wm, wa) = (cpu::col::WIDTH, memory::col::WIDTH, alu::col::WIDTH);
    let new = F::from_u32(forged);

    // The `WRITE_OUTPUT` ecall, and the `mv a1, t0` immediately before it that stages a1.
    let ecall_row = (0..t.cpu.height()).find(|r| t.cpu.values[r * wc + cpu::col::SYS_WRITE] == F::ONE).expect("fib writes an output");
    let mv_row = ecall_row - 1;
    assert_eq!(t.cpu.values[mv_row * wc + cpu::col::IS_ALU], F::ONE, "row before the ecall is `mv a1, t0`");
    assert_eq!(t.cpu.values[mv_row * wc + cpu::col::RD], F::from_u32(REG_A1));
    let a_in = t.cpu.values[mv_row * wc + cpu::col::A];
    let honest = t.cpu.values[mv_row * wc + cpu::col::C];
    let write_ts = 4 * t.cpu.values[mv_row * wc + cpu::col::CLK].as_canonical_u64() + SLOT_W as u64;

    // cpu: the `mv` now yields `forged`, and every later ecall reads the new a1.
    t.cpu.values[mv_row * wc + cpu::col::ALU_OUT] = new;
    t.cpu.values[mv_row * wc + cpu::col::C] = new;
    for r in mv_row + 1..t.cpu.height() {
        if t.cpu.values[r * wc + cpu::col::IS_ECALL] == F::ONE { t.cpu.values[r * wc + cpu::col::MEM_VAL] = new; }
    }
    t.public_values[cpu::pv::OUT0] = new;

    // memory: a1's write and every read of it afterwards.
    for r in 0..t.memory.height() {
        let row = &mut t.memory.values[r * wm..(r + 1) * wm];
        if row[memory::col::IS_REAL] == F::ONE
            && row[memory::col::SPACE] == F::ZERO
            && row[memory::col::ADDR] == F::from_u32(REG_A1)
            && row[memory::col::TS].as_canonical_u64() >= write_ts
        {
            row[memory::col::VALUE] = new;
        }
    }

    // alu: retire one honest provider of the real tuple, plant the forged one on padding.
    let honest_row = (0..t.alu.height())
        .find(|r| {
            let row = &t.alu.values[r * wa..(r + 1) * wa];
            row[alu::col::FLAG0] == F::ONE && row[alu::col::A] == a_in && row[alu::col::B] == F::ZERO && row[alu::col::C] == honest && row[alu::col::MULT] != F::ZERO
        })
        .expect("the honest (Add, a, 0, c) tuple is provided somewhere");
    t.alu.values[honest_row * wa + alu::col::MULT] = F::ZERO;
    let pad = t.alu.height() - 1;
    assert_eq!(t.alu.values[pad * wa + alu::col::IS_REAL], F::ZERO, "last alu row is padding");
    t.alu.values[pad * wa + alu::col::A] = a_in;
    t.alu.values[pad * wa + alu::col::B] = F::ZERO;
    t.alu.values[pad * wa + alu::col::C] = new;
    // `word(A0) = A` and `word(C0) = C` are the only ungated constraints that touch these
    // columns, and the limbs' `RANGE8` lookups are counted by `is_real` — so parking the
    // whole word in limb 0 satisfies the recomposition with no range check to answer to.
    t.alu.values[pad * wa + alu::col::A0] = a_in;
    t.alu.values[pad * wa + alu::col::C0] = new;
    t.alu.values[pad * wa + alu::col::MULT] = F::ONE;
}

#[test]
fn a_tuple_forged_on_an_alu_padding_row_is_rejected() {
    let (m, p, mut t) = setup();
    forge_fib_output_through_an_alu_padding_row(&mut t, 999); // fib(10) is 55
    assert_eq!(t.public_values[cpu::pv::OUT0], F::from_u32(999));
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}


#[test]
fn claiming_a_word_in_an_unwritten_output_slot_is_rejected() {
    let (m, p, mut t) = setup();
    // `fib` writes slot 0 only; spec §3.4 says every slot no WRITE_OUTPUT selected is zero.
    assert_eq!(t.public_values[cpu::pv::OUT0 + 1], F::ZERO);
    t.public_values[cpu::pv::OUT0 + 1] = F::from_u32(7);
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

#[test]
fn non_canonical_public_values_are_an_error_not_a_panic() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (mut proof, _) = m.prove(&p, &[], None).unwrap();
    m.verify(&p, &proof).unwrap();
    // `Val::from_u64` does not reduce, so `out0 + p` is the same field element and would
    // otherwise verify — with a different `to_bytes()` and a different apparent output.
    proof.public_values[cpu::pv::OUT0] += F::ORDER_U64;
    assert!(matches!(m.verify(&p, &proof), Err(rand_zkvm::machine::VerifyError::PublicValues)));
}

#[test]
fn bumping_a_program_multiplicity_on_a_padding_row_is_rejected() {
    let (m, p, mut t) = setup();
    let w = program::col::WIDTH;
    let pad = t.program.height() - 1; // the table is padded past the last instruction
    assert!(pad >= p.len(), "last program row is padding");
    t.program.values[pad * w + program::col::MULT] += F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

#[test]
fn swapping_two_adjacent_memory_rows_is_rejected() {
    let (m, p, mut t) = setup();
    let w = memory::col::WIDTH;
    let real = (0..t.memory.height()).filter(|r| t.memory.values[r * w + memory::col::IS_REAL] == F::ONE).count();
    assert!(real > 4, "fib(10) touches memory plenty");
    // Swapping whole rows leaves the MEMORY multiset and the RANGE8 counts untouched, so
    // both buses still balance: the only thing that can catch this is the ordering AIR.
    let r = real / 2;
    for k in 0..w { t.memory.values.swap(r * w + k, (r + 1) * w + k); }
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

#[test]
fn bumping_a_range_pow2_multiplicity_on_a_non_pow2_row_is_rejected() {
    let (m, p, mut t) = setup();
    let w = range::col::WIDTH;
    let row = 200usize; // a=200 ≥ 32, so is_pow2 is 0 here
    t.range.values[row * w + range::col::M_POW2] += F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

#[test]
fn bumping_a_nibble_and_multiplicity_on_a_padding_row_is_rejected() {
    let (m, p, mut t) = setup();
    let w = nibble::col::WIDTH;
    let row = nibble::row_of(9, 6); // an arbitrary valid nibble pair the honest trace never counts
    t.nibble.values[row * w + nibble::col::M_AND] += F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

/// The memory-path mirror of `forge_fib_output_through_an_alu_padding_row`, ported to
/// M2.5's read-modify-write store: an honest `store 5; load; output` witness is rewritten
/// so the `SW` delivers a value that was never in any register. Before the CPU pinned
/// `MEM_VAL = B` on store rows (`2c8a39d`), nothing tied the value sent on the MEMORY bus
/// to the register the store reads. M2.5 replaced that single pin with the `MERGED0..3`
/// formula (`MERGED_k = W_k + selp(k)*(bp(k) - W_k)`, `bp` built from `RB0..3`, and
/// `is_store*(B - word(RB0))=0` ties `RB0..3` to `B`): on this program's plain `SW`
/// (`off=0`), `selp(k)=1` for every `k`, so the formula forces `MERGED = word(RB0) = B`
/// structurally. This helper forges `MERGED0..3` directly — bypassing `RB0..3`/`B`, which
/// stay untouched and honestly show `5` — so the row constraint above must reject it,
/// exactly as `2c8a39d`'s `MEM_VAL = B` pin did for the old single-column design.
fn forge_a_store(t: &mut Traces, forged: u32) {
    use rand_zkvm::tables::limbs;
    let (wc, wm) = (cpu::col::WIDTH, memory::col::WIDTH);
    let new = F::from_u32(forged);
    let nl = limbs(forged);

    // cpu: the store's own MERGED (the value actually written), the load that reads it
    // back (its own, independent MEM_VAL/W0..3 word witness), the `mv a1, t1` staging the
    // output word, and every ecall row (each reads `a1` through the memory slot).
    for r in 0..t.cpu.height() {
        let row = &mut t.cpu.values[r * wc..(r + 1) * wc];
        if row[cpu::col::IS_SW] == F::ONE { for k in 0..4 { row[cpu::col::MERGED0 + k] = nl[k]; } }
        if row[cpu::col::IS_LW] == F::ONE {
            row[cpu::col::MEM_VAL] = new;
            for k in 0..4 { row[cpu::col::W0 + k] = nl[k]; }
            row[cpu::col::C] = new;
        }
        if row[cpu::col::IS_ECALL] == F::ONE { row[cpu::col::MEM_VAL] = new; }
        if row[cpu::col::IS_ALU] == F::ONE && row[cpu::col::RD] == F::from_u32(REG_A1) && row[cpu::col::RS1] == F::from_u32(6) {
            row[cpu::col::A] = new; row[cpu::col::ALU_OUT] = new; row[cpu::col::C] = new;
        }
    }
    // memory: the RAM cell, and registers t1 (the load's write, the mv's read) and a1.
    for r in 0..t.memory.height() {
        let row = &mut t.memory.values[r * wm..(r + 1) * wm];
        if row[memory::col::IS_REAL] != F::ONE { continue; }
        let ram = row[memory::col::SPACE] == F::ONE;
        let addr = row[memory::col::ADDR];
        if ram && addr == F::from_u32(0x400) { row[memory::col::VALUE] = new; }
        if !ram && (addr == F::from_u32(6) || addr == F::from_u32(REG_A1)) { row[memory::col::VALUE] = new; }
    }
    t.public_values[cpu::pv::OUT0] = new;
}

#[test]
fn storing_a_value_that_was_never_in_a_register_is_rejected() {
    // li s0, 0x1000 ; li t0, 5 ; sw t0, 0(s0) ; lw t1, 0(s0) ; write_output(0, t1) ; halt
    let mut a = Assembler::new(0);
    a.extend(li(8, 0x1000)); a.extend(li(5, 5));
    a.push(sw(8, 5, 0)); a.push(lw(6, 8, 0));
    a.extend(write_output(0, 6)); a.extend(halt());
    let p = a.assemble();
    let m = Machine::new(FriProfile::Test);
    let e = execute(&p, &[], 10_000).unwrap();
    assert_eq!(e.outputs[0], 5);
    let mut t = build_traces(&p, &e, Tier(10)).unwrap();
    forge_a_store(&mut t, 0x0500_0000);
    assert_eq!(t.public_values[cpu::pv::OUT0], F::from_u32(0x0500_0000));
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

/// M2.4 regression: bitwise rows (`and`/`or`/`xor`) no longer RANGE8-check their
/// `A0..3`/`B0..3`/`C0..3` limbs (`g_ab` is 0 there) — those limbs are now bound
/// solely by the nibble lookups. This bumps the RANGE8 table's own multiplicity at
/// a value that appears as this `and` row's `A0` limb (0x12): nothing on the AND
/// row (or, on inspection, anywhere else in this tiny program) asks the RANGE8 bus
/// for one more count of 0x12, so the bus no longer balances and the proof must
/// fail — confirming the dropped gate didn't leave a residual, silent RANGE8 demand
/// for this limb.
#[test]
fn bumping_range8_on_a_bitwise_rows_now_unconstrained_a_limb_is_rejected() {
    let mut a = Assembler::new(0);
    a.extend(li(5, 0x12)); a.extend(li(6, 0x34));
    a.push(and(7, 5, 6)); a.extend(write_output(0, 7)); a.extend(halt());
    let p = a.assemble();
    let m = Machine::new(FriProfile::Test);
    let e = execute(&p, &[], 10_000).unwrap();
    let mut t = build_traces(&p, &e, Tier(10)).unwrap();
    t.range.values[0x12 * range::col::WIDTH + range::col::M_RANGE] += F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

/// M2.4 regression: `slt`/`sltu`/`eq` rows no longer RANGE8-check their `C0..3`
/// limb (`g_c` is 0 there) — `C` is bound instead by `(cmp+eq)*C*(C-1)=0`. This
/// bumps the RANGE8 table's multiplicity at value 1 (this `slt` row's `C`, and
/// hence `C0`); the RANGE8 bus no longer has a matching demand for that extra
/// count, so the proof must fail.
#[test]
fn bumping_range8_on_an_slt_rows_now_unconstrained_c_limb_is_rejected() {
    let mut a = Assembler::new(0);
    a.extend(li(5, 3)); a.extend(li(6, 9));
    a.push(slt(7, 5, 6)); a.extend(write_output(0, 7)); a.extend(halt());
    let p = a.assemble();
    let m = Machine::new(FriProfile::Test);
    let e = execute(&p, &[], 10_000).unwrap();
    let mut t = build_traces(&p, &e, Tier(10)).unwrap();
    t.range.values[range::col::WIDTH + range::col::M_RANGE] += F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

/// M2.5: a store's `MERGED0..3` is the read-modify-write result, bound per byte by
/// `MERGED_k = W_k + selp(k)*(bp(k) - W_k)`. Corrupting one limb to disagree with that
/// formula — even while leaving the *aggregate* value looking plausible — must be caught
/// by the row constraint directly, not just by an accidental downstream mismatch.
#[test]
fn a_store_that_replaces_the_wrong_byte_is_rejected() {
    let mut a = Assembler::new(0);
    a.extend(li(8, 0x1000)); a.extend(li(5, 0x11223344u32 as i32)); a.extend(li(6, 0xff));
    a.push(sw(8, 5, 0)); a.push(sb(8, 6, 0)); // sets byte 0 to 0xff: word becomes 0x112233ff
    a.push(lw(7, 8, 0)); a.extend(write_output(0, 7)); a.extend(halt());
    let p = a.assemble();
    let m = Machine::new(FriProfile::Test);
    let e = execute(&p, &[], 10_000).unwrap();
    assert_eq!(e.outputs[0], 0x112233ff);
    let mut t = build_traces(&p, &e, Tier(10)).unwrap();
    let w = cpu::col::WIDTH;
    // Find the SB row and corrupt MERGED to replace byte 1 instead of byte 0.
    let sb_row = (0..t.cpu.height()).find(|r| t.cpu.values[r * w + cpu::col::IS_SB] == F::ONE).unwrap();
    t.cpu.values[sb_row * w + cpu::col::MERGED0] = F::from_u32(0x44);     // put the old byte 0 back
    t.cpu.values[sb_row * w + cpu::col::MERGED0 + 1] = F::from_u32(0xff); // and corrupt byte 1 instead
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

/// M2.5: `LB`'s sign extension runs through `SGN`, itself bound to the sign-relevant
/// byte's true top bit only via the `AND4[HI, 8, SGN*8]` lookup — flipping `SGN` (and `C`
/// to match, so the row's own `C` pin stays self-consistent) must be caught by that
/// lookup disagreeing with the nibble table, not by the `C` pin alone.
#[test]
fn a_load_byte_with_flipped_sign_extension_is_rejected() {
    let mut a = Assembler::new(0);
    a.extend(li(8, 0x1000)); a.extend(li(5, 0xffu32 as i32)); // byte 0xff, top bit set
    a.push(sw(8, 5, 0)); a.push(lb(6, 8, 0)); // LB sign-extends: -1 = 0xffffffff
    a.extend(write_output(0, 6)); a.extend(halt());
    let p = a.assemble();
    let m = Machine::new(FriProfile::Test);
    let e = execute(&p, &[], 10_000).unwrap();
    assert_eq!(e.outputs[0], 0xffff_ffff);
    let mut t = build_traces(&p, &e, Tier(10)).unwrap();
    let w = cpu::col::WIDTH;
    let lb_row = (0..t.cpu.height()).find(|r| t.cpu.values[r * w + cpu::col::IS_LB] == F::ONE).unwrap();
    t.cpu.values[lb_row * w + cpu::col::SGN] = F::ZERO; // flip: claim unsigned-looking zero-extend
    t.cpu.values[lb_row * w + cpu::col::C] = F::from_u32(0xff);
    t.public_values[cpu::pv::OUT0] = F::from_u32(0xff);
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

/// M2.5: `IS_LH*OFF0 = 0` is the stated alignment constraint for halfwords — a retagged
/// row claiming `LH` at an odd byte offset must be rejected by the AIR, not merely
/// unreachable through the emulator.
#[test]
fn a_misaligned_lh_is_rejected_by_the_air() {
    let mut a = Assembler::new(0);
    a.extend(li(8, 0x1000)); a.extend(li(5, 0x1234)); a.push(sw(8, 5, 0));
    a.push(lw(6, 8, 0)); // an ordinary LW so the trace has a row to repurpose
    a.extend(write_output(0, 6)); a.extend(halt());
    let p = a.assemble();
    let m = Machine::new(FriProfile::Test);
    let e = execute(&p, &[], 10_000).unwrap();
    let mut t = build_traces(&p, &e, Tier(10)).unwrap();
    let w = cpu::col::WIDTH;
    let lw_row = (0..t.cpu.height()).find(|r| t.cpu.values[r * w + cpu::col::IS_LW] == F::ONE).unwrap();
    // Retag this LW row as an LH with OFF0=1 (byte offset 1 — misaligned for a half).
    t.cpu.values[lw_row * w + cpu::col::IS_LW] = F::ZERO;
    t.cpu.values[lw_row * w + cpu::col::IS_LH] = F::ONE;
    t.cpu.values[lw_row * w + cpu::col::OFF0] = F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

/// M2.5: `SB`'s per-byte `MERGED` formula pins `selp(k)=0` for every byte outside `off`,
/// forcing `MERGED_k = W_k` there — corrupting a byte the store never touches must be
/// caught even though the touched byte (`off`) is still correct.
#[test]
fn a_sb_that_changes_a_byte_outside_its_offset_is_rejected() {
    let mut a = Assembler::new(0);
    a.extend(li(8, 0x1000)); a.extend(li(5, 0x11223344u32 as i32)); a.extend(li(6, 0xff));
    a.push(sw(8, 5, 0)); a.push(sb(8, 6, 1)); // sets byte 1 only: word becomes 0x1122ff44
    a.push(lw(7, 8, 0)); a.extend(write_output(0, 7)); a.extend(halt());
    let p = a.assemble();
    let m = Machine::new(FriProfile::Test);
    let e = execute(&p, &[], 10_000).unwrap();
    assert_eq!(e.outputs[0], 0x1122ff44);
    let mut t = build_traces(&p, &e, Tier(10)).unwrap();
    let w = cpu::col::WIDTH;
    let sb_row = (0..t.cpu.height()).find(|r| t.cpu.values[r * w + cpu::col::IS_SB] == F::ONE).unwrap();
    // Also corrupt byte 2 (outside off=1), leaving byte 1 correct.
    t.cpu.values[sb_row * w + cpu::col::MERGED0 + 2] = F::from_u32(0x00);
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}
