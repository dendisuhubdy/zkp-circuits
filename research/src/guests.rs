//! Guest programs shared by tests and the demo. Registers: t0..t6 = x5..x7,x28..x31; s0.. = x8..
use crate::asm::{ops::*, Assembler};
use crate::isa::*;

const T0: u32 = 5; const T1: u32 = 6; const T2: u32 = 7; const T3: u32 = 28; const T4: u32 = 29; const T5: u32 = 30;
const T6: u32 = 31; const S0: u32 = 8; const S1: u32 = 9;
const HEAP: i32 = 0x1000; // data lives above the code

/// out0 = fib(n) mod 2^32, computed with a counted loop.
pub fn fib(n: u32) -> Program {
    let mut a = Assembler::new(0);
    a.extend(li(T0, 0));            // f0
    a.extend(li(T1, 1));            // f1
    a.extend(li(T2, n as i32));     // counter
    a.label("loop");
    a.branch(BranchCond::Eq, T2, 0, "done");
    a.push(add(T3, T0, T1));
    a.push(mv(T0, T1));
    a.push(mv(T1, T3));
    a.push(addi(T2, T2, -1));
    a.jal(0, "loop");
    a.label("done");
    a.extend(write_output(0, T0));
    a.extend(halt());
    a.assemble()
}

/// Writes 1..=n to HEAP, copies to HEAP+4n, outputs the sum of the copy.
pub fn memcpy(n: u32) -> Program {
    let mut a = Assembler::new(0);
    a.extend(li(T0, HEAP)); a.extend(li(T1, HEAP + 4 * n as i32)); a.extend(li(T2, n as i32)); a.extend(li(T3, 1));
    a.label("fill");
    a.branch(BranchCond::Eq, T2, 0, "copy_setup");
    a.push(sw(T0, T3, 0)); a.push(addi(T0, T0, 4)); a.push(addi(T3, T3, 1)); a.push(addi(T2, T2, -1));
    a.jal(0, "fill");
    a.label("copy_setup");
    a.extend(li(T0, HEAP)); a.extend(li(T2, n as i32)); a.extend(li(T5, 0));
    a.label("copy");
    a.branch(BranchCond::Eq, T2, 0, "done");
    a.push(lw(T4, T0, 0)); a.push(sw(T1, T4, 0)); a.push(lw(T4, T1, 0)); a.push(add(T5, T5, T4));
    a.push(addi(T0, T0, 4)); a.push(addi(T1, T1, 4)); a.push(addi(T2, T2, -1));
    a.jal(0, "copy");
    a.label("done");
    a.extend(write_output(0, T5));
    a.extend(halt());
    a.assemble()
}

/// Stores `values` at HEAP, bubble-sorts them in place (unsigned), outputs min and max.
pub fn bubble_sort(values: &[u32]) -> Program {
    assert!(!values.is_empty(), "bubble_sort guest needs at least one value");
    let n = values.len() as i32;
    let mut a = Assembler::new(0);
    for (i, v) in values.iter().enumerate() {
        a.extend(li(T0, *v as i32)); a.extend(li(T1, HEAP + 4 * i as i32)); a.push(sw(T1, T0, 0));
    }
    a.extend(li(T4, n - 1));                       // outer count
    a.label("outer");
    a.branch(BranchCond::Eq, T4, 0, "done");
    a.extend(li(T0, HEAP)); a.push(mv(T5, T4));    // inner count
    a.label("inner");
    a.branch(BranchCond::Eq, T5, 0, "outer_next");
    a.push(lw(T1, T0, 0)); a.push(lw(T2, T0, 4));
    a.push(sltu(T3, T2, T1));                      // T3 = a[i+1] < a[i]
    a.branch(BranchCond::Eq, T3, 0, "no_swap");
    a.push(sw(T0, T2, 0)); a.push(sw(T0, T1, 4));
    a.label("no_swap");
    a.push(addi(T0, T0, 4)); a.push(addi(T5, T5, -1));
    a.jal(0, "inner");
    a.label("outer_next");
    a.push(addi(T4, T4, -1));
    a.jal(0, "outer");
    a.label("done");
    a.extend(li(T0, HEAP)); a.push(lw(T1, T0, 0)); a.push(lw(T2, T0, 4 * (n - 1)));
    a.extend(write_output(0, T1)); a.extend(write_output(1, T2));
    a.extend(halt());
    a.assemble()
}

/// The confidential-computation demo: reads private inputs 0..3 (balances),
/// sums them, and outputs only whether the sum ≥ `threshold` (1) or not (0).
/// The sum is carry-aware: each addition records whether it wrapped, and a
/// wrap counts as over any 32-bit threshold — the proved relation matches the
/// stated semantics even when the true sum exceeds 2^32.
pub fn balance_check(threshold: u32) -> Program {
    let mut a = Assembler::new(0);
    a.extend(li(T5, 0));            // sum
    a.extend(li(T4, 0));            // wrapped-carry flag
    for idx in 0..4 {
        a.extend(read_input(idx));
        a.push(add(T5, T5, REG_A0));
        a.push(sltu(T2, T5, REG_A0));       // sum < addend ⟺ the add carried out
        a.push(or(T4, T4, T2));
    }
    a.extend(li(T0, threshold as i32));
    a.push(sltu(T1, T5, T0));       // T1 = sum < threshold
    a.push(xori(T1, T1, 1));        // T1 = sum >= threshold
    a.push(or(T1, T1, T4));         // ... or the true sum overflowed 32 bits
    a.extend(write_output(0, T1));
    a.extend(halt());
    a.assemble()
}

/// Exercises every `AluOp` variant and `JALR` through a register-computed target.
///
/// `out0` is an XOR checksum over the results of the bitwise, shift and arithmetic ops (plus
/// the `JALR` link register, which pins `rd = pc + 4`); `out1` is the sum of the six compare
/// results. Both operands have their high bits set and one of them is negative, so `sra`
/// sign-extends, `slt` and `sltu` disagree, and the `and`/`or`/`xor` limbs are non-trivial;
/// every shift amount is at least 8. `AluOp::Eq` has no encoding of its own, so it is
/// reached the only way it can be — through `BEQ`/`BNE`.
pub fn alu_mix() -> Program {
    let mut a = Assembler::new(0);
    a.extend(li(S0, 0));                             // acc
    a.extend(li(S1, 0));                             // compare sum
    a.extend(li(T0, 0xdead_beefu32 as i32));         // negative, high bits set
    a.extend(li(T1, 0x0f0f_1234));                   // positive, high bits set
    let acc = |a: &mut Assembler| a.push(xor(S0, S0, T2));

    a.push(add(T2, T0, T1)); acc(&mut a);
    a.push(sub(T2, T0, T1)); acc(&mut a);
    a.push(and(T2, T0, T1)); acc(&mut a);
    a.push(or (T2, T0, T1)); acc(&mut a);
    a.push(xor(T2, T0, T1)); acc(&mut a);
    // shifts: register form by 12, immediate forms by 20, 24 and 31
    a.extend(li(T3, 12));
    a.push(sll(T2, T1, T3)); acc(&mut a);
    a.push(srl(T2, T0, T3)); acc(&mut a);
    a.push(sra(T2, T0, T3)); acc(&mut a);            // negative sra
    a.push(slli(T2, T1, 20)); acc(&mut a);
    a.push(srli(T2, T0, 24)); acc(&mut a);
    a.push(srai(T2, T0, 31)); acc(&mut a);           // negative sra → all ones
    a.push(andi(T2, T0, -256)); acc(&mut a);
    a.push(ori (T2, T0, 0x7ff)); acc(&mut a);
    a.push(xori(T2, T0, -1)); acc(&mut a);
    // compares with mixed signs: slt and sltu must disagree on (T0, T1)
    let cmp = |a: &mut Assembler, i: Instr| { a.push(i); a.push(add(S1, S1, T2)); };
    cmp(&mut a, slt (T2, T0, T1));                   // signed:   T0 < T1  → 1
    cmp(&mut a, slt (T2, T1, T0));                   //                    → 0
    cmp(&mut a, sltu(T2, T0, T1));                   // unsigned: T0 < T1  → 0
    cmp(&mut a, sltu(T2, T1, T0));                   //                    → 1
    cmp(&mut a, slti (T2, T0, -1));
    cmp(&mut a, sltiu(T2, T1, -1));
    // AluOp::Eq, the only way it is reachable
    a.branch(BranchCond::Eq, T0, T1, "bad");         // not taken
    a.branch(BranchCond::Ne, T0, T1, "call");        // taken
    a.label("bad");
    a.push(addi(S1, 0, 0x7ff));                      // would corrupt out1 if ever reached
    a.label("call");
    // JALR through a register: auipc + addi build the target, jalr links pc + 4 into T6.
    a.push(auipc(T4, 0));                            // T4 = pc of this instruction
    a.push(addi(T4, T4, 16));                        // T4 = address of "target"
    a.push(jalr(T6, T4, 0));
    a.push(addi(S1, 0, 0x7ff));                      // skipped by the jump
    a.label("target");
    a.push(xor(S0, S0, T6));                         // fold the link register into the checksum
    a.extend(write_output(0, S0));
    a.extend(write_output(1, S1));
    a.extend(halt());
    a.assemble()
}

/// (name, program, private inputs)
pub fn all() -> Vec<(&'static str, Program, Vec<u32>)> {
    vec![
        ("fib(20)", fib(20), vec![]),
        ("memcpy(8)", memcpy(8), vec![]),
        ("bubble_sort", bubble_sort(&[9, 3, 0xffff_fff0, 1, 7, 3]), vec![]),
        ("balance_check", balance_check(1000), vec![400, 250, 300, 75]),
        ("alu_mix", alu_mix(), vec![]),
    ]
}

/// The shielded transfer: spends one note and creates one of the same amount and asset.
///
/// Private inputs (`notes::input`): the spend key, the spent note's fields, and the created
/// note's owner, time and randomness. The guest derives `nk = H_NK(sk)` and `pk = H_PK(nk)`
/// itself, so the spent note's owner and the created note's `from` are the address of
/// whoever holds `sk` — that is what authenticates the sender — and it recomputes both
/// commitments plus the nullifier (bound to `cm_in`, not to a sender-chosen nonce) with
/// `arx::emit_hash`. Public outputs (`notes::output`): `cm_in`, `nf`, `cm_out`, and the
/// created note's `time`.
///
/// What it does *not* do in milestone 1: prove `cm_in` is in a commitment tree — there is no
/// `MERKLE_VERIFY` syscall yet, so the ledger checks membership against the public `cm_in`
/// (`ledger.rs`), which leaks which note was spent. `docs/06-viewing-keys.md` states the
/// consequences.
pub fn transfer() -> Program {
    use crate::arx::{self, domain, reg};
    use crate::notes::{input, output, Note};
    const BASE: u32 = 25;                       // s9: RAM base register
    const BUF: i32 = 0;                         // hash message buffer (12 words, zero-padded)
    const INP: i32 = 0x100;                     // the 14 private inputs
    const NK: i32 = 0x200; const PK: i32 = 0x208; const NF: i32 = 0x210; const CM_IN: i32 = 0x218; const CM_OUT: i32 = 0x220;
    let inp = |i: usize| INP + 4 * i as i32;
    let mut a = Assembler::new(0);
    a.extend(li(BASE, HEAP));
    // Read every private input once and keep it in RAM.
    for i in 0..input::COUNT {
        a.extend(read_input(i as u32));
        a.push(sw(BASE, REG_A0, inp(i)));
    }
    let copy = |a: &mut Assembler, src: i32, dst: i32| { a.push(lw(T0, BASE, src)); a.push(sw(BASE, T0, dst)); };
    let zero = |a: &mut Assembler, dst: i32| a.push(sw(BASE, REG_ZERO, dst));
    let store_digest = |a: &mut Assembler, dst: i32| { a.push(sw(BASE, reg::STATE[0], dst)); a.push(sw(BASE, reg::STATE[1], dst + 4)); };
    // nk = H_NK(sk)
    copy(&mut a, inp(input::SK), BUF); copy(&mut a, inp(input::SK + 1), BUF + 4); zero(&mut a, BUF + 8); zero(&mut a, BUF + 12);
    arx::emit_call_hash(&mut a, HEAP + BUF, 2, domain::NK);
    store_digest(&mut a, NK);
    // pk = H_PK(nk)
    copy(&mut a, NK, BUF); copy(&mut a, NK + 4, BUF + 4);
    arx::emit_call_hash(&mut a, HEAP + BUF, 2, domain::PK);
    store_digest(&mut a, PK);
    // cm_in = H_CM(pk, in.from, in.amount, in.asset, in.time, in.r)
    let note_words: [i32; Note::WORDS] = [PK, PK + 4, inp(input::IN_FROM), inp(input::IN_FROM + 1), inp(input::IN_AMOUNT), inp(input::IN_ASSET), inp(input::IN_TIME), inp(input::IN_R), inp(input::IN_R + 1)];
    for (i, src) in note_words.iter().enumerate() { copy(&mut a, *src, BUF + 4 * i as i32); }
    zero(&mut a, BUF + 36); zero(&mut a, BUF + 40); zero(&mut a, BUF + 44);
    arx::emit_call_hash(&mut a, HEAP + BUF, Note::WORDS, domain::CM);
    store_digest(&mut a, CM_IN);
    // nf = H_NF(nk, cm_in) — bound to the commitment, so two notes can never share one
    copy(&mut a, NK, BUF); copy(&mut a, NK + 4, BUF + 4); copy(&mut a, CM_IN, BUF + 8); copy(&mut a, CM_IN + 4, BUF + 12);
    arx::emit_call_hash(&mut a, HEAP + BUF, 4, domain::NF);
    store_digest(&mut a, NF);
    // cm_out = H_CM(out.pk, pk, in.amount, in.asset, out.time, out.r)
    let note_words: [i32; Note::WORDS] = [inp(input::OUT_PK), inp(input::OUT_PK + 1), PK, PK + 4, inp(input::IN_AMOUNT), inp(input::IN_ASSET), inp(input::OUT_TIME), inp(input::OUT_R), inp(input::OUT_R + 1)];
    for (i, src) in note_words.iter().enumerate() { copy(&mut a, *src, BUF + 4 * i as i32); }
    // the padding words are still zero from the cm_in block — nf's message stayed below BUF+16
    arx::emit_call_hash(&mut a, HEAP + BUF, Note::WORDS, domain::CM);
    store_digest(&mut a, CM_OUT);
    // Publish.
    for (slot, src) in [(output::CM_IN, CM_IN), (output::CM_IN + 1, CM_IN + 4), (output::NF, NF), (output::NF + 1, NF + 4), (output::CM_OUT, CM_OUT), (output::CM_OUT + 1, CM_OUT + 4), (output::TIME, inp(input::OUT_TIME))] {
        a.push(lw(T1, BASE, src));
        a.extend(write_output(slot as u32, T1));
    }
    a.extend(halt());
    arx::emit_perm(&mut a);
    arx::emit_hash(&mut a);
    a.assemble()
}

/// Hashes `msg` under `arx::domain::TEST` and outputs the four rate words: the fixture that
/// pins the guest-side `Arx8` to the native one.
pub fn arx_probe(msg: &[u32]) -> Program {
    use crate::arx::{self, domain, reg};
    const BASE: u32 = 25;
    let mut a = Assembler::new(0);
    a.extend(li(BASE, HEAP));
    for (i, w) in msg.iter().enumerate() { a.extend(li(T0, *w as i32)); a.push(sw(BASE, T0, 4 * i as i32)); }
    arx::emit_call_hash(&mut a, HEAP, msg.len(), domain::TEST);
    for i in 0..4 { a.extend(write_output(i as u32, reg::STATE[i])); }
    a.extend(halt());
    arx::emit_perm(&mut a);
    arx::emit_hash(&mut a);
    a.assemble()
}
