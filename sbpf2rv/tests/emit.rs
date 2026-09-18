//! The emitter's C, statement by statement: every instruction class translates to exactly the C
//! text spec §3's table specifies (as `sbpf2rv/src/emit.rs`'s module docs spell it out), over the
//! edge values the spec names — a zero divisor, shift counts at and past the width, the minimum
//! signed immediate, negative offsets. The C's *meaning* is checked end to end by
//! `tests/parity.rs` (and, over the whole opcode set, by Task 5's differential fuzzing); this file
//! pins the *text*, so a change to it is a deliberate one.

use sbpf2rv::emit::{
    emit_block_charge, emit_block_head, emit_insn, emit_lddw, emit_program, SYSCALLS,
};
use sbpf2rv::scan::scan;
use sbpf_core::elf::Program;
use sbpf_core::isa::{self, opc, Insn};
use sbpf_core::syscalls;

fn i(opc: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
    Insn {
        opc,
        dst,
        src,
        off,
        imm,
    }
}

fn e(insn: Insn) -> String {
    emit_insn(10, &insn)
}

// ---- alu64 ------------------------------------------------------------------------------------

#[test]
fn alu64_register_forms() {
    assert_eq!(e(i(opc::ADD64_REG, 3, 4, 0, 0)), "r3 = r3 + r4;");
    assert_eq!(e(i(opc::SUB64_REG, 3, 4, 0, 0)), "r3 = r3 - r4;");
    assert_eq!(e(i(opc::MUL64_REG, 3, 4, 0, 0)), "r3 = r3 * r4;");
    assert_eq!(e(i(opc::OR64_REG, 3, 4, 0, 0)), "r3 = r3 | r4;");
    assert_eq!(e(i(opc::AND64_REG, 3, 4, 0, 0)), "r3 = r3 & r4;");
    assert_eq!(e(i(opc::XOR64_REG, 3, 4, 0, 0)), "r3 = r3 ^ r4;");
    assert_eq!(e(i(opc::MOV64_REG, 3, 10, 0, 0)), "r3 = r10;");
    assert_eq!(e(i(opc::LSH64_REG, 3, 4, 0, 0)), "r3 = r3 << (r4 & 63);");
    assert_eq!(e(i(opc::RSH64_REG, 3, 4, 0, 0)), "r3 = r3 >> (r4 & 63);");
    assert_eq!(
        e(i(opc::ARSH64_REG, 3, 4, 0, 0)),
        "r3 = (uint64_t)((int64_t)r3 >> (r4 & 63));"
    );
    assert_eq!(e(i(opc::NEG64, 3, 0, 0, 0)), "r3 = -r3;");
    assert_eq!(
        e(i(opc::DIV64_REG, 3, 4, 0, 0)),
        "if (r4 == 0) sbpf_trap(SBPF_HALT_DIV_BY_ZERO, 0); r3 = r3 / r4;"
    );
    assert_eq!(
        e(i(opc::MOD64_REG, 3, 3, 0, 0)),
        "if (r3 == 0) sbpf_trap(SBPF_HALT_DIV_BY_ZERO, 0); r3 = r3 % r3;"
    );
}

#[test]
fn alu64_immediate_forms_sign_extend_the_immediate() {
    assert_eq!(e(i(opc::ADD64_IMM, 1, 0, 0, 5)), "r1 = r1 + 5;");
    // A negative immediate is sign-extended to 64 bits: `(uint64_t)-8` is 2^64 - 8.
    assert_eq!(e(i(opc::ADD64_IMM, 1, 0, 0, -8)), "r1 = r1 + (uint64_t)-8;");
    assert_eq!(e(i(opc::SUB64_IMM, 1, 0, 0, 1)), "r1 = r1 - 1;");
    assert_eq!(e(i(opc::MUL64_IMM, 1, 0, 0, 3)), "r1 = r1 * 3;");
    assert_eq!(e(i(opc::OR64_IMM, 1, 0, 0, 1)), "r1 = r1 | 1;");
    assert_eq!(e(i(opc::AND64_IMM, 1, 0, 0, -1)), "r1 = r1 & (uint64_t)-1;");
    assert_eq!(e(i(opc::XOR64_IMM, 1, 0, 0, 7)), "r1 = r1 ^ 7;");
    // i32::MIN is not a C `int` literal (2147483648 is not an int): written as a difference.
    assert_eq!(
        e(i(opc::MOV64_IMM, 1, 0, 0, i32::MIN)),
        "r1 = (uint64_t)(-2147483647 - 1);"
    );
    assert_eq!(e(i(opc::MOV64_IMM, 0, 0, 0, 0)), "r0 = 0;");
    // Shift counts are masked to six bits, whatever the immediate.
    assert_eq!(e(i(opc::LSH64_IMM, 1, 0, 0, 64)), "r1 = r1 << (64 & 63);");
    assert_eq!(e(i(opc::RSH64_IMM, 1, 0, 0, 3)), "r1 = r1 >> (3 & 63);");
    assert_eq!(
        e(i(opc::ARSH64_IMM, 1, 0, 0, -1)),
        "r1 = (uint64_t)((int64_t)r1 >> (-1 & 63));"
    );
    assert_eq!(e(i(opc::DIV64_IMM, 1, 0, 0, 10)), "r1 = r1 / 10;");
    assert_eq!(e(i(opc::MOD64_IMM, 1, 0, 0, -3)), "r1 = r1 % (uint64_t)-3;");
}

#[test]
fn a_zero_immediate_divisor_is_a_static_trap() {
    assert_eq!(
        e(i(opc::DIV64_IMM, 1, 0, 0, 0)),
        "sbpf_trap(SBPF_HALT_DIV_BY_ZERO, 0);"
    );
    assert_eq!(
        e(i(opc::MOD64_IMM, 1, 0, 0, 0)),
        "sbpf_trap(SBPF_HALT_DIV_BY_ZERO, 0);"
    );
    assert_eq!(
        e(i(opc::DIV32_IMM, 1, 0, 0, 0)),
        "sbpf_trap(SBPF_HALT_DIV_BY_ZERO, 0);"
    );
    assert_eq!(
        e(i(opc::MOD32_IMM, 1, 0, 0, 0)),
        "sbpf_trap(SBPF_HALT_DIV_BY_ZERO, 0);"
    );
}

// ---- alu32 ------------------------------------------------------------------------------------

#[test]
fn alu32_add_sub_mul_sign_extend_their_result() {
    // `interp.rs`: the three that sign-extend (`as i32 … as i64 as u64`).
    assert_eq!(
        e(i(opc::ADD32_REG, 1, 2, 0, 0)),
        "r1 = (uint64_t)(int64_t)(int32_t)((uint32_t)r1 + (uint32_t)r2);"
    );
    assert_eq!(
        e(i(opc::SUB32_IMM, 1, 0, 0, -1)),
        "r1 = (uint64_t)(int64_t)(int32_t)((uint32_t)r1 - (uint32_t)-1);"
    );
    assert_eq!(
        e(i(opc::MUL32_IMM, 1, 0, 0, 7)),
        "r1 = (uint64_t)(int64_t)(int32_t)((uint32_t)r1 * 7);"
    );
}

#[test]
fn alu32_everything_else_zero_extends() {
    assert_eq!(
        e(i(opc::OR32_REG, 1, 2, 0, 0)),
        "r1 = (uint32_t)((uint32_t)r1 | (uint32_t)r2);"
    );
    assert_eq!(
        e(i(opc::AND32_IMM, 1, 0, 0, 255)),
        "r1 = (uint32_t)((uint32_t)r1 & 255);"
    );
    assert_eq!(
        e(i(opc::XOR32_IMM, 1, 0, 0, -1)),
        "r1 = (uint32_t)((uint32_t)r1 ^ (uint32_t)-1);"
    );
    // The brief's example, verbatim.
    assert_eq!(
        e(i(opc::LSH32_IMM, 1, 0, 0, 5)),
        "r1 = (uint32_t)((uint32_t)r1 << (5 & 31));"
    );
    assert_eq!(
        e(i(opc::LSH32_REG, 1, 2, 0, 0)),
        "r1 = (uint32_t)((uint32_t)r1 << (r2 & 31));"
    );
    assert_eq!(
        e(i(opc::RSH32_IMM, 1, 0, 0, 32)),
        "r1 = (uint32_t)((uint32_t)r1 >> (32 & 31));"
    );
    assert_eq!(
        e(i(opc::ARSH32_IMM, 1, 0, 0, 4)),
        "r1 = (uint32_t)((int32_t)r1 >> (4 & 31));"
    );
    assert_eq!(
        e(i(opc::ARSH32_REG, 1, 2, 0, 0)),
        "r1 = (uint32_t)((int32_t)r1 >> (r2 & 31));"
    );
    assert_eq!(
        e(i(opc::NEG32, 1, 0, 0, 0)),
        "r1 = (uint32_t)-(uint32_t)r1;"
    );
    assert_eq!(e(i(opc::MOV32_REG, 1, 2, 0, 0)), "r1 = (uint32_t)r2;");
    assert_eq!(e(i(opc::MOV32_IMM, 1, 0, 0, 5)), "r1 = 5;");
    assert_eq!(e(i(opc::MOV32_IMM, 1, 0, 0, -8)), "r1 = (uint32_t)-8;");
    assert_eq!(
        e(i(opc::DIV32_REG, 1, 2, 0, 0)),
        "if ((uint32_t)r2 == 0) sbpf_trap(SBPF_HALT_DIV_BY_ZERO, 0); r1 = (uint32_t)((uint32_t)r1 / (uint32_t)r2);"
    );
    assert_eq!(
        e(i(opc::DIV32_IMM, 1, 0, 0, 3)),
        "r1 = (uint32_t)((uint32_t)r1 / 3);"
    );
    assert_eq!(
        e(i(opc::MOD32_REG, 1, 2, 0, 0)),
        "if ((uint32_t)r2 == 0) sbpf_trap(SBPF_HALT_DIV_BY_ZERO, 0); r1 = (uint32_t)((uint32_t)r1 % (uint32_t)r2);"
    );
    assert_eq!(
        e(i(opc::MOD32_IMM, 1, 0, 0, -3)),
        "r1 = (uint32_t)((uint32_t)r1 % (uint32_t)-3);"
    );
}

#[test]
fn byte_swaps_take_only_16_32_and_64() {
    assert_eq!(e(i(opc::LE, 1, 0, 0, 16)), "r1 = (uint16_t)r1;");
    assert_eq!(e(i(opc::LE, 1, 0, 0, 32)), "r1 = (uint32_t)r1;");
    assert_eq!(e(i(opc::LE, 1, 0, 0, 64)), "(void)r1;");
    assert_eq!(
        e(i(opc::BE, 1, 0, 0, 16)),
        "r1 = __builtin_bswap16((uint16_t)r1);"
    );
    assert_eq!(
        e(i(opc::BE, 1, 0, 0, 32)),
        "r1 = __builtin_bswap32((uint32_t)r1);"
    );
    assert_eq!(e(i(opc::BE, 1, 0, 0, 64)), "r1 = __builtin_bswap64(r1);");
    // Any other width is `Halt::BadInsn(opc)` when executed (`interp.rs`'s `LE`/`BE` arms).
    assert_eq!(
        e(i(opc::LE, 1, 0, 0, 8)),
        "sbpf_trap(SBPF_HALT_BAD_INSN, 0xd4);"
    );
    assert_eq!(
        e(i(opc::BE, 1, 0, 0, 0)),
        "sbpf_trap(SBPF_HALT_BAD_INSN, 0xdc);"
    );
}

// ---- loads and stores -------------------------------------------------------------------------

#[test]
fn loads_and_stores_go_through_the_runtime_at_every_width() {
    // Base register and offset: the runtime adds them, `(base as i64).wrapping_add(off as i64)`.
    assert_eq!(e(i(opc::LD_B_REG, 2, 1, 0, 0)), "r2 = sbpf_ld1(r1, 0);");
    assert_eq!(e(i(opc::LD_H_REG, 2, 1, 6, 0)), "r2 = sbpf_ld2(r1, 6);");
    assert_eq!(e(i(opc::LD_W_REG, 2, 10, -4, 0)), "r2 = sbpf_ld4(r10, -4);");
    assert_eq!(
        e(i(opc::LD_DW_REG, 2, 10, i16::MIN, 0)),
        "r2 = sbpf_ld8(r10, -32768);"
    );
    assert_eq!(
        e(i(opc::ST_B_IMM, 1, 0, 1, -1)),
        "sbpf_st1(r1, 1, (uint64_t)-1);"
    );
    assert_eq!(e(i(opc::ST_H_IMM, 1, 0, 0, 7)), "sbpf_st2(r1, 0, 7);");
    assert_eq!(e(i(opc::ST_W_IMM, 10, 0, -8, 9)), "sbpf_st4(r10, -8, 9);");
    assert_eq!(e(i(opc::ST_DW_IMM, 10, 0, -8, 0)), "sbpf_st8(r10, -8, 0);");
    assert_eq!(e(i(opc::ST_B_REG, 1, 2, 3, 0)), "sbpf_st1(r1, 3, r2);");
    assert_eq!(e(i(opc::ST_H_REG, 1, 2, 0, 0)), "sbpf_st2(r1, 0, r2);");
    assert_eq!(e(i(opc::ST_W_REG, 1, 2, -2, 0)), "sbpf_st4(r1, -2, r2);");
    assert_eq!(
        e(i(opc::ST_DW_REG, 10, 6, -16, 0)),
        "sbpf_st8(r10, -16, r6);"
    );
}

#[test]
fn lddw_is_one_statement_and_traps_without_its_second_slot() {
    let lo = i(opc::LD_DW_IMM, 4, 0, 0, -1);
    let hi = i(0, 0, 0, 0, 0x1234);
    assert_eq!(emit_lddw(&lo, Some(&hi)), "r4 = 0x00001234ffffffffull;");
    assert_eq!(
        emit_lddw(&lo, Some(&i(0, 0, 0, 0, 0))),
        "r4 = 0x00000000ffffffffull;"
    );
    // At the last slot the interpreter's fetch of the high half fails first: BadJump, and the
    // register is never written.
    assert_eq!(emit_lddw(&lo, None), "sbpf_trap(SBPF_HALT_BAD_JUMP, 0);");
}

// ---- control flow -----------------------------------------------------------------------------

#[test]
fn jumps_are_gotos_to_the_target_slot() {
    // pc 10: target = 10 + 1 + off.
    assert_eq!(e(i(opc::JA, 0, 0, 1, 0)), "goto L_12;");
    assert_eq!(e(i(opc::JA, 0, 0, -11, 0)), "goto L_0;");
    // The brief's example, verbatim.
    assert_eq!(
        e(i(opc::JSGT_REG, 1, 2, 1, 0)),
        "if ((int64_t)r1 > (int64_t)r2) goto L_12;"
    );
    assert_eq!(e(i(opc::JEQ_IMM, 1, 0, 1, 0)), "if (r1 == 0) goto L_12;");
    assert_eq!(e(i(opc::JEQ_REG, 1, 2, 1, 0)), "if (r1 == r2) goto L_12;");
    assert_eq!(
        e(i(opc::JNE_IMM, 1, 0, 1, -1)),
        "if (r1 != (uint64_t)-1) goto L_12;"
    );
    assert_eq!(e(i(opc::JNE_REG, 1, 2, 1, 0)), "if (r1 != r2) goto L_12;");
    assert_eq!(
        e(i(opc::JGT_IMM, 1, 0, 1, -1)),
        "if (r1 > (uint64_t)-1) goto L_12;"
    );
    assert_eq!(e(i(opc::JGT_REG, 1, 2, 1, 0)), "if (r1 > r2) goto L_12;");
    assert_eq!(e(i(opc::JGE_IMM, 1, 0, 1, 3)), "if (r1 >= 3) goto L_12;");
    assert_eq!(e(i(opc::JGE_REG, 1, 2, 1, 0)), "if (r1 >= r2) goto L_12;");
    assert_eq!(e(i(opc::JLT_IMM, 1, 0, 1, 3)), "if (r1 < 3) goto L_12;");
    assert_eq!(e(i(opc::JLT_REG, 1, 2, 1, 0)), "if (r1 < r2) goto L_12;");
    assert_eq!(e(i(opc::JLE_IMM, 1, 0, 1, 3)), "if (r1 <= 3) goto L_12;");
    assert_eq!(e(i(opc::JLE_REG, 1, 2, 1, 0)), "if (r1 <= r2) goto L_12;");
    assert_eq!(
        e(i(opc::JSET_IMM, 1, 0, 1, 8)),
        "if ((r1 & 8) != 0) goto L_12;"
    );
    assert_eq!(
        e(i(opc::JSET_REG, 1, 2, 1, 0)),
        "if ((r1 & r2) != 0) goto L_12;"
    );
    // Signed compares against an immediate compare with the sign-extended immediate.
    assert_eq!(
        e(i(opc::JSGT_IMM, 1, 0, 1, -1)),
        "if ((int64_t)r1 > -1) goto L_12;"
    );
    assert_eq!(
        e(i(opc::JSGE_IMM, 1, 0, 1, i32::MIN)),
        "if ((int64_t)r1 >= (-2147483647 - 1)) goto L_12;"
    );
    assert_eq!(
        e(i(opc::JSGE_REG, 1, 2, 1, 0)),
        "if ((int64_t)r1 >= (int64_t)r2) goto L_12;"
    );
    assert_eq!(
        e(i(opc::JSLT_IMM, 1, 0, 1, 0)),
        "if ((int64_t)r1 < 0) goto L_12;"
    );
    assert_eq!(
        e(i(opc::JSLT_REG, 1, 2, 1, 0)),
        "if ((int64_t)r1 < (int64_t)r2) goto L_12;"
    );
    assert_eq!(
        e(i(opc::JSLE_IMM, 1, 0, 1, 5)),
        "if ((int64_t)r1 <= 5) goto L_12;"
    );
    assert_eq!(
        e(i(opc::JSLE_REG, 1, 2, 1, 0)),
        "if ((int64_t)r1 <= (int64_t)r2) goto L_12;"
    );
}

#[test]
fn calls_exit_and_syscalls() {
    // Internal call: `imm` is the slot offset (pc 10 + 1 + 4 = 15), depth check inside the macro.
    // Out of context, every register goes in and r0..r5 come back.
    const ALL: &str = "(r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10 + SBPF_STACK_FRAME)";
    const BACK: &str = "r0 = x_.r0; r1 = x_.r1; r2 = x_.r2; r3 = x_.r3; r4 = x_.r4; r5 = x_.r5;";
    assert_eq!(
        e(i(opc::CALL_IMM, 0, 0, 0, 4)),
        format!("SBPF_CALL(f_15{ALL}, {BACK});")
    );
    // callx: v1 takes the target address from the register the immediate names.
    assert_eq!(
        e(i(opc::CALL_REG, 0, 0, 0, 3)),
        format!("SBPF_CALLX(r3, {ALL}, {BACK});")
    );
    assert_eq!(e(i(opc::EXIT, 0, 0, 0, 0)), "SBPF_RETURN();");
    let log = syscalls::murmur3_32(b"sol_log_", 0) as i32;
    assert_eq!(
        e(i(opc::CALL_IMM, 0, 1, 0, log)),
        "r0 = sbpf_sys_log(r1, r2, r3, r4, r5);"
    );
    // An unimplemented syscall (here `sol_set_return_data`, which the SPL Token ELF names) is the
    // interpreter's own `Halt::UnknownSyscall(hash)`.
    let h = syscalls::murmur3_32(b"sol_set_return_data", 0);
    assert_eq!(
        e(i(opc::CALL_IMM, 0, 1, 0, h as i32)),
        format!("sbpf_trap(SBPF_HALT_UNKNOWN_SYSCALL, {h:#010x}u);")
    );
}

#[test]
fn every_supported_syscall_has_a_runtime_function_and_nothing_else_does() {
    let mut ours: Vec<u32> = SYSCALLS.iter().map(|(h, _)| *h).collect();
    let mut theirs: Vec<u32> = syscalls::SUPPORTED.iter().map(|(h, _)| *h).collect();
    ours.sort();
    theirs.sort();
    assert_eq!(ours, theirs);
    // Each name is declared by the runtime header.
    let header =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../sbpf-rt/sbpf_rt.h"))
            .unwrap();
    for (_, f) in SYSCALLS {
        assert!(
            header.contains(&format!("uint64_t {f}(uint64_t r1,")),
            "{f} is not in sbpf_rt.h"
        );
    }
}

#[test]
fn a_block_head_charges_the_whole_block() {
    // The function-local copy of `sbpf_budget` (synced around calls), and one shared trap per function.
    assert_eq!(emit_block_head(3), "if ((budget -= 3) < 0) goto L_limit;");
    // A block whose check is deferred to its successors only charges.
    assert_eq!(emit_block_charge(3), "budget -= 3;");
}

// ---- whole functions --------------------------------------------------------------------------

fn text(insns: &[Insn]) -> Vec<u8> {
    insns
        .iter()
        .flat_map(|i| isa::encode(*i).to_le_bytes())
        .collect()
}

/// A two-function program: the entry calls pc 4, which returns 7; a loop; the emitted C carries one
/// function per sBPF function, the budget charge at every block head, and the entry's register
/// state (`r1` the input region, `r10` the top of frame 0).
#[test]
fn a_small_program_translates_to_the_expected_functions() {
    let t = text(&[
        i(opc::MOV64_IMM, 6, 0, 0, 3), // 0: r6 = 3
        i(opc::SUB64_IMM, 6, 0, 0, 1), // 1: loop: r6 -= 1
        i(opc::JNE_IMM, 6, 0, -2, 0),  // 2: if r6 != 0 goto 1
        i(opc::CALL_IMM, 0, 0, 0, 1),  // 3: call 5
        i(opc::EXIT, 0, 0, 0, 0),      // 4: exit
        i(opc::MOV64_IMM, 0, 0, 0, 7), // 5: r0 = 7
        i(opc::EXIT, 0, 0, 0, 0),      // 6: exit
    ]);
    let p = Program::from_text(&t).unwrap();
    let s = scan(&p);
    let out = emit_program(&p, &s);
    let c = &out.c;
    assert_eq!(out.functions, 2);
    assert_eq!(out.instructions, 7);
    assert!(c.contains("#include \"sbpf_rt.h\""), "{c}");
    assert!(c.contains("SBPF_FN f_0(uint64_t r0, uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r6, uint64_t r7, uint64_t r8, uint64_t r9, uint64_t r10)"), "{c}");
    assert!(c.contains("SBPF_FN f_5("), "{c}");
    // Block 0 is one instruction and falls into the loop head; the loop is two. Block 0 only
    // charges: its one successor checks (a deferred check). The loop head checks — it is its own
    // successor — and so do the call and the exit.
    assert!(
        c.contains("L_0:\n    budget -= 1;\n    r6 = 3;\n    goto L_1;\n"),
        "{c}"
    );
    assert!(c.contains("L_1:\n    if ((budget -= 2) < 0) goto L_limit;\n    r6 = r6 - 1;\n    if (r6 != 0) goto L_1;\n    goto L_3;\n"), "{c}");
    // Liveness: f_5 reads nothing before writing it and writes only r0, so nothing goes in (0 for
    // r0..r9) and only r0 comes back.
    assert!(c.contains("L_3:\n    if ((budget -= 1) < 0) goto L_limit;\n    SBPF_CALL(f_5(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, r10 + SBPF_STACK_FRAME), r0 = x_.r0;);\n    goto L_4;\n"), "{c}");
    assert!(c.contains("    SBPF_RETURN();\n"), "{c}");
    assert!(
        c.contains("L_limit:\n    sbpf_trap(SBPF_HALT_INSTRUCTION_LIMIT, 0);\n}"),
        "{c}"
    );
    // `Vm::new`: r1 = the input region, r10 = the top of frame 0, everything else zero.
    assert!(
        c.contains("f_0(0, r1, r2, r3, r4, r5, 0, 0, 0, 0, SBPF_REGION_STACK + SBPF_STACK_FRAME)"),
        "{c}"
    );
    assert!(
        c.contains("sbpf_rt_enter(sbpf_entry_fn, SBPF_REGION_INPUT, 0, 0, 0, 0, r0)"),
        "{c}"
    );
    // callx can land on either function.
    assert!(
        c.contains("case 0: return f_0;\n") && c.contains("case 5: return f_5;\n"),
        "{c}"
    );
}

/// The traps the scanner plants: a bad register never runs (the block is charged for it, not
/// translated); running off the end of the text costs the failed fetch too.
#[test]
fn trap_blocks_charge_what_the_interpreter_counts() {
    // 0: mov r11, 1 — a register nibble above r10: BadInsn(0xb7), one instruction charged.
    let t = text(&[i(opc::MOV64_IMM, 11, 0, 0, 1)]);
    let p = Program::from_text(&t).unwrap();
    let c = emit_program(&p, &scan(&p)).c;
    assert!(
        c.contains("L_0:\n    budget -= 1;\n    sbpf_trap(SBPF_HALT_BAD_INSN, 0xb7);\n"),
        "{c}"
    );
    assert!(!c.contains("r11"), "{c}");

    // 0: mov r0, 1 and then nothing: the instruction runs, then the fetch of slot 1 fails.
    let t = text(&[i(opc::MOV64_IMM, 0, 0, 0, 1)]);
    let p = Program::from_text(&t).unwrap();
    let c = emit_program(&p, &scan(&p)).c;
    assert!(
        c.contains("L_0:\n    budget -= 2;\n    r0 = 1;\n    sbpf_trap(SBPF_HALT_BAD_JUMP, 0);\n"),
        "{c}"
    );

    // 0: call 1 at the very end: the callee's exit fails to fetch the return slot — inside the
    // exit, so nothing more is charged after the call.
    let t = text(&[
        i(opc::JA, 0, 0, 1, 0),
        i(opc::EXIT, 0, 0, 0, 0),
        i(opc::CALL_IMM, 0, 0, 0, -2),
    ]);
    let p = Program::from_text(&t).unwrap();
    let c = emit_program(&p, &scan(&p)).c;
    assert!(c.contains("    SBPF_CALL(f_1(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, r10 + SBPF_STACK_FRAME), );\n    sbpf_trap(SBPF_HALT_BAD_JUMP, 0);\n"), "{c}");
}

/// A function whose entry lies inside another's code is emitted once, as an entry label of the
/// larger one: pc 0 falls into pc 1, which is also a function (a `call` target).
#[test]
fn a_function_inside_another_is_merged_into_it() {
    let t = text(&[
        i(opc::CALL_IMM, 0, 0, 0, 0), // 0: call 1 — pc 1 is a function; the call returns to pc 1
        i(opc::MOV64_IMM, 0, 0, 0, 7), // 1: r0 = 7
        i(opc::EXIT, 0, 0, 0, 0),     // 2: exit
    ]);
    let p = Program::from_text(&t).unwrap();
    let s = scan(&p);
    assert_eq!(s.functions.len(), 2);
    let c = emit_program(&p, &s).c;
    assert!(c.contains("SBPF_FN f_0("), "{c}");
    assert!(!c.contains("SBPF_FN f_1("), "{c}");
    // The call selects the entry, the host dispatches on it.
    assert!(c.contains("SBPF_CALL((sbpf_sel = 2u, f_0)(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, r10 + SBPF_STACK_FRAME), r0 = x_.r0;);"), "{c}");
    assert!(
        c.contains("    switch (sel) {\n    case 2u: goto L_1;\n    }\n"),
        "{c}"
    );
    assert!(
        c.contains("    case 1: sbpf_sel = 2u; return f_0;\n"),
        "{c}"
    );
}

/// Deferred checks: no two unchecked blocks are adjacent, and a block ending in `exit` or a call
/// always checks. A chain of straight-line blocks split by jump targets alternates.
#[test]
fn a_deferred_check_is_never_next_to_another() {
    // 0: jeq r1, 0, +1 (-> 2 or 1); 1: mov r0, 1; 2: jeq r2, 0, +1 (-> 4 or 3); 3: mov r0, 2;
    // 4: exit.
    let t = text(&[
        i(opc::JEQ_IMM, 1, 0, 1, 0),
        i(opc::MOV64_IMM, 0, 0, 0, 1),
        i(opc::JEQ_IMM, 2, 0, 1, 0),
        i(opc::MOV64_IMM, 0, 0, 0, 2),
        i(opc::EXIT, 0, 0, 0, 0),
    ]);
    let p = Program::from_text(&t).unwrap();
    let c = emit_program(&p, &scan(&p)).c;
    let head = |pc: usize| {
        let at = c
            .find(&format!("L_{pc}:\n"))
            .unwrap_or_else(|| panic!("no L_{pc}:\n{c}"));
        c[at..].lines().nth(1).unwrap().trim().to_string()
    };
    // 0 has no unchecked neighbour yet: deferred. 1 and 2 follow it: checked. 3 follows only 2:
    // deferred. 4 ends in exit: checked.
    assert_eq!(head(0), "budget -= 1;");
    assert_eq!(head(1), "if ((budget -= 1) < 0) goto L_limit;");
    assert_eq!(head(2), "if ((budget -= 1) < 0) goto L_limit;");
    assert_eq!(head(3), "budget -= 1;");
    assert_eq!(head(4), "if ((budget -= 1) < 0) goto L_limit;");
}
