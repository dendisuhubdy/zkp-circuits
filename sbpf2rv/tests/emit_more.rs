//! The emitter's C beyond `tests/emit.rs`: the immediates at the extremes of their ranges in
//! every family, the register mapping (eleven C locals, a writable `r10`, nothing above it), the
//! frame handling at every call, the `callx` dispatch, the prelude's depth check, the order and
//! count of what is emitted, and the two panics on misuse. Text is pinned exactly, as in
//! `tests/emit.rs`, so a change to it is a deliberate one.

use sbpf2rv::emit::{emit_cond, emit_insn, emit_lddw, emit_program, use_def, ENTRY_SYMBOL};
use sbpf2rv::scan::scan;
use sbpf_core::elf::Program;
use sbpf_core::isa::{self, opc, Insn};
use sbpf_core::memory::REGION_PROGRAM;

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

fn text(insns: &[Insn]) -> Vec<u8> {
    insns
        .iter()
        .flat_map(|i| isa::encode(*i).to_le_bytes())
        .collect()
}

fn c_of(insns: &[Insn]) -> String {
    let t = text(insns);
    let p = Program::from_text(&t).unwrap();
    emit_program(&p, &scan(&p)).c
}

// ---- immediates at the extremes ----------------------------------------------------------------------

#[test]
fn i32_min_is_written_as_a_difference_in_every_family() {
    const MIN: &str = "(-2147483647 - 1)";
    assert_eq!(
        e(i(opc::ADD64_IMM, 1, 0, 0, i32::MIN)),
        format!("r1 = r1 + (uint64_t){MIN};")
    );
    assert_eq!(
        e(i(opc::MUL64_IMM, 1, 0, 0, i32::MIN)),
        format!("r1 = r1 * (uint64_t){MIN};")
    );
    assert_eq!(
        e(i(opc::DIV64_IMM, 1, 0, 0, i32::MIN)),
        format!("r1 = r1 / (uint64_t){MIN};")
    );
    assert_eq!(
        e(i(opc::LSH64_IMM, 1, 0, 0, i32::MIN)),
        format!("r1 = r1 << ({MIN} & 63);")
    );
    assert_eq!(
        e(i(opc::ARSH32_IMM, 1, 0, 0, i32::MIN)),
        format!("r1 = (uint32_t)((int32_t)r1 >> ({MIN} & 31));")
    );
    assert_eq!(
        e(i(opc::MOV32_IMM, 1, 0, 0, i32::MIN)),
        format!("r1 = (uint32_t){MIN};")
    );
    assert_eq!(
        e(i(opc::ADD32_IMM, 1, 0, 0, i32::MIN)),
        format!("r1 = (uint64_t)(int64_t)(int32_t)((uint32_t)r1 + (uint32_t){MIN});")
    );
    assert_eq!(
        e(i(opc::DIV32_IMM, 1, 0, 0, i32::MIN)),
        format!("r1 = (uint32_t)((uint32_t)r1 / (uint32_t){MIN});")
    );
    assert_eq!(
        e(i(opc::ST_DW_IMM, 1, 0, 0, i32::MIN)),
        format!("sbpf_st8(r1, 0, (uint64_t){MIN});")
    );
    assert_eq!(
        e(i(opc::ST_B_IMM, 1, 0, 0, i32::MIN)),
        format!("sbpf_st1(r1, 0, (uint64_t){MIN});")
    );
    assert_eq!(
        e(i(opc::JEQ_IMM, 1, 0, 1, i32::MIN)),
        format!("if (r1 == (uint64_t){MIN}) goto L_12;")
    );
    assert_eq!(
        e(i(opc::JSET_IMM, 1, 0, 1, i32::MIN)),
        format!("if ((r1 & (uint64_t){MIN}) != 0) goto L_12;")
    );
    assert_eq!(
        e(i(opc::JSLT_IMM, 1, 0, 1, i32::MIN)),
        format!("if ((int64_t)r1 < {MIN}) goto L_12;")
    );
    assert_eq!(
        emit_lddw(
            &i(opc::LD_DW_IMM, 1, 0, 0, i32::MIN),
            Some(&i(0, 0, 0, 0, i32::MIN))
        ),
        "r1 = 0x8000000080000000ull;"
    );
}

#[test]
fn i32_max_and_minus_one_are_plain_or_cast_literals() {
    assert_eq!(
        e(i(opc::ADD64_IMM, 1, 0, 0, i32::MAX)),
        "r1 = r1 + 2147483647;"
    );
    assert_eq!(
        e(i(opc::JGE_IMM, 1, 0, 1, i32::MAX)),
        "if (r1 >= 2147483647) goto L_12;"
    );
    assert_eq!(
        e(i(opc::JSGE_IMM, 1, 0, 1, i32::MAX)),
        "if ((int64_t)r1 >= 2147483647) goto L_12;"
    );
    assert_eq!(e(i(opc::MOV32_IMM, 1, 0, 0, i32::MAX)), "r1 = 2147483647;");
    assert_eq!(
        e(i(opc::RSH64_IMM, 1, 0, 0, i32::MAX)),
        "r1 = r1 >> (2147483647 & 63);"
    );
    assert_eq!(
        e(i(opc::LSH32_IMM, 1, 0, 0, -1)),
        "r1 = (uint32_t)((uint32_t)r1 << (-1 & 31));"
    );
    assert_eq!(
        e(i(opc::JSET_IMM, 1, 0, 1, -1)),
        "if ((r1 & (uint64_t)-1) != 0) goto L_12;"
    );
    assert_eq!(
        e(i(opc::JLE_IMM, 1, 0, 1, -1)),
        "if (r1 <= (uint64_t)-1) goto L_12;"
    );
    assert_eq!(
        e(i(opc::JSLE_IMM, 1, 0, 1, -1)),
        "if ((int64_t)r1 <= -1) goto L_12;"
    );
    assert_eq!(
        e(i(opc::ST_W_IMM, 1, 0, -1, -1)),
        "sbpf_st4(r1, -1, (uint64_t)-1);"
    );
}

#[test]
fn offsets_at_the_extremes_of_i16() {
    assert_eq!(
        e(i(opc::LD_B_REG, 2, 1, i16::MAX, 0)),
        "r2 = sbpf_ld1(r1, 32767);"
    );
    assert_eq!(
        e(i(opc::ST_H_REG, 2, 1, i16::MIN, 0)),
        "sbpf_st2(r2, -32768, r1);"
    );
    // Out of context the jump's label is pc + 1 + off, whatever it is; inside a function the scan
    // redirects an out-of-text target to the shared trap block instead.
    assert_eq!(e(i(opc::JA, 0, 0, i16::MAX, 0)), "goto L_32778;");
    assert_eq!(e(i(opc::JA, 0, 0, i16::MIN, 0)), "goto L_-32757;");
    assert_eq!(e(i(opc::JNE_REG, 1, 2, -11, 0)), "if (r1 != r2) goto L_0;");
}

#[test]
fn an_unassigned_opcode_out_of_context_is_a_bad_insn_trap_with_its_byte() {
    assert_eq!(
        e(i(0x00, 0, 0, 0, 0)),
        "sbpf_trap(SBPF_HALT_BAD_INSN, 0x00);"
    );
    assert_eq!(
        e(i(0xf7, 1, 0, 0, 5)),
        "sbpf_trap(SBPF_HALT_BAD_INSN, 0xf7);"
    );
    assert_eq!(
        e(i(0x9d, 0, 0, 0, 0)),
        "sbpf_trap(SBPF_HALT_BAD_INSN, 0x9d);"
    );
}

#[test]
#[should_panic(expected = "lddw spans two slots")]
fn emit_insn_refuses_an_lddw() {
    e(i(opc::LD_DW_IMM, 1, 0, 0, 0));
}

#[test]
#[should_panic(expected = "is not a conditional jump")]
fn emit_cond_refuses_anything_but_a_conditional_jump() {
    emit_cond(&i(opc::JA, 0, 0, 0, 0));
}

#[test]
fn emit_cond_covers_all_22_and_use_def_reads_what_they_compare() {
    let jumps: Vec<u8> = (0..=255u8)
        .filter(|&o| isa::classify(o) == Some(isa::Class::Jmp) && o != opc::JA)
        .collect();
    assert_eq!(jumps.len(), 22);
    for o in jumps {
        let c = emit_cond(&i(o, 3, 4, 0, 5));
        assert!(c.contains("r3"), "{o:#04x}: {c}");
        let (used, defined) = use_def(&i(o, 3, 4, 0, 5));
        assert_eq!(defined, 0, "{o:#04x} writes nothing");
        if o & 0x08 != 0 {
            assert!(c.contains("r4"), "{o:#04x}: {c}");
            assert_eq!(used, (1 << 3) | (1 << 4), "{o:#04x}");
        } else {
            assert!(!c.contains("r4"), "{o:#04x}: {c}");
            assert_eq!(used, 1 << 3, "{o:#04x}");
        }
    }
}

// ---- registers ------------------------------------------------------------------------------------------

#[test]
fn every_register_is_a_c_parameter_and_nothing_above_r10_is_ever_named() {
    // Uses all eleven registers, r10 included as a plain operand and as a destination.
    let mut p = Vec::new();
    for r in 0..=10u8 {
        p.push(i(opc::ADD64_IMM, r, 0, 0, r as i32));
    }
    p.push(i(opc::MOV64_REG, 0, 10, 0, 0));
    p.push(i(opc::EXIT, 0, 0, 0, 0));
    let c = c_of(&p);
    assert!(c.contains("SBPF_FN f_0(uint64_t r0, uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r6, uint64_t r7, uint64_t r8, uint64_t r9, uint64_t r10) {"), "{c}");
    for r in 0..=10u8 {
        assert!(c.contains(&format!("    r{r} = r{r} + {r};\n")), "{c}");
    }
    assert!(c.contains("    r0 = r10;\n"), "{c}");
    for r in 11..=15u8 {
        assert!(!c.contains(&format!("r{r}")), "r{r} must not appear:\n{c}");
    }
    // No `typedef`'d register file, no array: the registers are the eleven locals and nothing else
    // in the function reads or writes them by index.
    assert!(!c.contains("regs["), "{c}");
}

#[test]
fn a_write_to_r10_is_an_ordinary_local_assignment() {
    assert_eq!(e(i(opc::MOV64_REG, 10, 1, 0, 0)), "r10 = r1;");
    assert_eq!(
        e(i(opc::ADD64_IMM, 10, 0, 0, -4096)),
        "r10 = r10 + (uint64_t)-4096;"
    );
    assert_eq!(
        e(i(opc::LD_DW_REG, 10, 10, 0, 0)),
        "r10 = sbpf_ld8(r10, 0);"
    );
    assert_eq!(e(i(opc::MOV32_IMM, 10, 0, 0, 0)), "r10 = 0;");
    assert_eq!(use_def(&i(opc::MOV64_REG, 10, 1, 0, 0)), (1 << 1, 1 << 10));
}

// ---- frames and calls ----------------------------------------------------------------------------------------

#[test]
fn every_call_hands_the_callee_r10_one_frame_up_and_the_prelude_checks_the_depth() {
    // Two internal calls and a callx; every call site's last argument is the advanced r10.
    let mut p = vec![
        i(opc::CALL_IMM, 0, 0, 0, 5), // 0: call 6
        i(opc::CALL_IMM, 0, 0, 0, 6), // 1: call 8
        i(
            opc::LD_DW_IMM,
            3,
            0,
            0,
            (REGION_PROGRAM + 8 * 6) as u32 as i32,
        ), // 2-3
        i(0, 0, 0, 0, ((REGION_PROGRAM + 8 * 6) >> 32) as i32),
        i(opc::CALL_REG, 0, 0, 0, 3),  // 4: callx r3
        i(opc::EXIT, 0, 0, 0, 0),      // 5
        i(opc::MOV64_IMM, 0, 0, 0, 1), // 6
        i(opc::EXIT, 0, 0, 0, 0),      // 7
        i(opc::MOV64_IMM, 1, 0, 0, 2), // 8
        i(opc::EXIT, 0, 0, 0, 0),      // 9
    ];
    p.push(i(opc::EXIT, 0, 0, 0, 0)); // 10: unreachable
    let c = c_of(&p);
    let sites: Vec<&str> = c
        .lines()
        .filter(|l| l.starts_with("    SBPF_CALL(") || l.starts_with("    SBPF_CALLX("))
        .collect();
    assert_eq!(sites.len(), 3, "{c}");
    for s in &sites {
        assert!(s.contains(", r10 + SBPF_STACK_FRAME)"), "{s}");
    }
    assert!(sites[0].starts_with("    SBPF_CALL(f_6(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, r10 + SBPF_STACK_FRAME), r0 = x_.r0;);"), "{}", sites[0]);
    assert!(sites[1].starts_with("    SBPF_CALL(f_8(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, r10 + SBPF_STACK_FRAME), r1 = x_.r1;);"), "{}", sites[1]);
    // The prelude: one global depth, checked before the callee runs, decremented after.
    assert!(c.contains("static uint32_t sbpf_depth;"), "{c}");
    assert!(
        c.contains("if (++sbpf_depth == SBPF_MAX_CALL_DEPTH) sbpf_trap(SBPF_HALT_CALL_DEPTH, 0);"),
        "{c}"
    );
    assert!(c.contains("sbpf_depth--;"), "{c}");
    // The entry resets it, and the entry function gets frame 0's top.
    assert!(
        c.contains(&format!(
            "uint32_t {ENTRY_SYMBOL}(uint64_t *r0) {{\n    sbpf_depth = 0;\n"
        )),
        "{c}"
    );
    assert!(
        c.contains("SBPF_REGION_STACK + SBPF_STACK_FRAME).r0;"),
        "{c}"
    );
}

#[test]
fn a_call_to_a_bad_target_pushes_the_frame_before_trapping() {
    let c = c_of(&[i(opc::CALL_IMM, 0, 0, 0, 100), i(opc::EXIT, 0, 0, 0, 0)]);
    // A block with no successor defers its check (there is nothing after it to check at, and it
    // traps anyway): charged, not checked.
    assert!(
        c.contains("L_0:\n    budget -= 1;\n    SBPF_CALL_BAD_TARGET();\n"),
        "{c}"
    );
    assert!(c.contains("#define SBPF_CALL_BAD_TARGET() \\\n    do { \\\n        SBPF_DEPTH_PUSH(); \\\n        sbpf_trap(SBPF_HALT_BAD_JUMP, 0); \\\n    } while (0)"), "{c}");
}

#[test]
fn the_callx_switch_lists_exactly_the_scanned_targets_and_guards_the_high_half() {
    let addr = |pc: u64| REGION_PROGRAM + 8 * pc;
    let lddw = |d: u8, v: u64| {
        [
            i(opc::LD_DW_IMM, d, 0, 0, v as u32 as i32),
            i(0, 0, 0, 0, (v >> 32) as i32),
        ]
    };
    let mut p = lddw(3, addr(5)).to_vec(); // 0-1
    p.push(i(opc::CALL_REG, 0, 0, 0, 3)); // 2
    p.push(i(opc::CALL_IMM, 0, 0, 0, 3)); // 3: call 7
    p.push(i(opc::EXIT, 0, 0, 0, 0)); // 4
    p.push(i(opc::MOV64_IMM, 0, 0, 0, 1)); // 5
    p.push(i(opc::EXIT, 0, 0, 0, 0)); // 6
    p.push(i(opc::MOV64_IMM, 0, 0, 0, 2)); // 7
    p.push(i(opc::EXIT, 0, 0, 0, 0)); // 8
    p.extend(lddw(4, addr(9))); // 9-10: names itself (an lddw whose value is its own pc)
    p.push(i(opc::EXIT, 0, 0, 0, 0)); // 11
    let t = text(&p);
    let prog = Program::from_text(&t).unwrap();
    let s = scan(&prog);
    assert_eq!(s.callx_targets, vec![0, 5, 7, 9]);
    let c = emit_program(&prog, &s).c;
    let at = c
        .find("static sbpf_callee sbpf_callx_target(uint64_t addr) {")
        .unwrap();
    let body: Vec<&str> = c[at..].lines().take(10).collect();
    assert_eq!(body[1], "    uint64_t slot = (addr - sbpf_r.text_va) / 8;");
    assert_eq!(
        body[2],
        "    if (slot >> 32) sbpf_trap(SBPF_HALT_BAD_JUMP, 0);"
    );
    assert_eq!(body[3], "    switch ((uint32_t)slot) {");
    assert_eq!(body[4], "    case 0: return f_0;");
    assert_eq!(body[5], "    case 5: return f_5;");
    assert_eq!(body[6], "    case 7: return f_7;");
    assert_eq!(body[7], "    case 9: return f_9;");
    assert_eq!(body[8], "    default: sbpf_trap(SBPF_HALT_BAD_JUMP, 0);");
    assert_eq!(c.matches("    case ").count(), 4, "{c}");
}

#[test]
fn functions_are_emitted_entry_first_then_ascending_and_counted_once() {
    // Entry at 4; functions at 0 and 2 found through calls.
    let p = [
        i(opc::MOV64_IMM, 0, 0, 0, 1), // 0: f_0
        i(opc::EXIT, 0, 0, 0, 0),      // 1
        i(opc::MOV64_IMM, 0, 0, 0, 2), // 2: f_2
        i(opc::EXIT, 0, 0, 0, 0),      // 3
        i(opc::CALL_IMM, 0, 0, 0, -5), // 4: entry: call 0
        i(opc::CALL_IMM, 0, 0, 0, -4), // 5: call 2
        i(opc::EXIT, 0, 0, 0, 0),      // 6
    ];
    let t = text(&p);
    let prog = Program {
        entry_pc: 4,
        ..Program::from_text(&t).unwrap()
    };
    let s = scan(&prog);
    assert_eq!(
        s.functions.iter().map(|f| f.entry).collect::<Vec<_>>(),
        vec![4, 0, 2]
    );
    let out = emit_program(&prog, &s);
    assert_eq!(
        (out.functions, out.blocks, out.instructions),
        (3, 2 + 1 + 1 + 1, 7)
    );
    let defs: Vec<usize> = out
        .c
        .lines()
        .filter_map(|l| {
            l.strip_prefix("SBPF_FN f_")?
                .split('(')
                .next()?
                .parse()
                .ok()
        })
        .collect();
    // Declarations first (all three), then definitions, in the scan's order.
    assert_eq!(defs, vec![4, 0, 2, 4, 0, 2], "{}", out.c);
    assert!(out.c.contains("return f_4(0, r1, r2, r3, r4, r5, 0, 0, 0, 0, SBPF_REGION_STACK + SBPF_STACK_FRAME).r0;"), "{}", out.c);
}

// ---- budget edges ------------------------------------------------------------------------------------------------

#[test]
fn an_lddw_in_the_last_slot_is_charged_once_and_traps_as_the_fetch_of_its_high_half() {
    let c = c_of(&[i(opc::LD_DW_IMM, 0, 0, 0, 1)]);
    assert!(
        c.contains("L_0:\n    budget -= 1;\n    sbpf_trap(SBPF_HALT_BAD_JUMP, 0);\n"),
        "{c}"
    );
    assert!(
        !c.contains("r0 = 0x"),
        "the register is never written:\n{c}"
    );
    // After a real instruction: two charged — the mov, and the lddw whose own fetch fails.
    let c = c_of(&[i(opc::MOV64_IMM, 0, 0, 0, 3), i(opc::LD_DW_IMM, 0, 0, 0, 1)]);
    assert!(
        c.contains("L_0:\n    budget -= 2;\n    r0 = 3;\n    sbpf_trap(SBPF_HALT_BAD_JUMP, 0);\n"),
        "{c}"
    );
}

#[test]
fn a_jump_to_a_bad_target_is_a_shared_block_charged_for_the_failed_fetch() {
    // 0: jeq r1, 0, +100 (taken: out of text); 1: ja +100; 2: exit (unreachable).
    let c = c_of(&[
        i(opc::JEQ_IMM, 1, 0, 100, 0),
        i(opc::JA, 0, 0, 100, 0),
        i(opc::EXIT, 0, 0, 0, 0),
    ]);
    assert!(
        c.contains("    if (r1 == 0) goto L_3;\n    goto L_1;\n"),
        "{c}"
    );
    assert!(
        c.contains("L_1:\n    if ((budget -= 1) < 0) goto L_limit;\n    goto L_3;\n"),
        "{c}"
    );
    assert!(c.contains("L_3:\n    if ((budget -= 1) < 0) goto L_limit;\n    sbpf_trap(SBPF_HALT_BAD_JUMP, 0);\n"), "{c}");
    assert_eq!(c.matches("L_3:\n").count(), 1, "one shared block");
    assert!(
        !c.contains("L_2:"),
        "unreachable code is not translated:\n{c}"
    );
}

#[test]
fn a_syscall_inside_a_function_sets_r0_and_continues_or_traps() {
    let log = sbpf_core::syscalls::SOL_LOG as i32;
    let nope = sbpf_core::syscalls::murmur3_32(b"sol_nope", 0);
    let c = c_of(&[
        i(opc::CALL_IMM, 0, 1, 0, log),
        i(opc::CALL_IMM, 0, 1, 0, nope as i32),
        i(opc::EXIT, 0, 0, 0, 0),
    ]);
    // Block 0's one successor checks, so block 0 only charges.
    assert!(
        c.contains(
            "L_0:\n    budget -= 1;\n    r0 = sbpf_sys_log(r1, r2, r3, r4, r5);\n    goto L_1;\n"
        ),
        "{c}"
    );
    assert!(c.contains(&format!("L_1:\n    if ((budget -= 1) < 0) goto L_limit;\n    sbpf_trap(SBPF_HALT_UNKNOWN_SYSCALL, {nope:#010x}u);\n    goto L_2;\n")), "{c}");
}

#[test]
fn liveness_passes_a_register_the_callee_reads_before_writing_and_copies_back_what_it_writes() {
    // f_3 reads r0 and r4 first (r0 += r4), writes r0 and r2.
    let c = c_of(&[
        i(opc::MOV64_IMM, 4, 0, 0, 9), // 0
        i(opc::CALL_IMM, 0, 0, 0, 1),  // 1: call 3
        i(opc::EXIT, 0, 0, 0, 0),      // 2
        i(opc::ADD64_REG, 0, 4, 0, 0), // 3
        i(opc::MOV64_IMM, 2, 0, 0, 1), // 4
        i(opc::EXIT, 0, 0, 0, 0),      // 5
    ]);
    assert!(c.contains("SBPF_CALL(f_3(r0, 0, 0, 0, r4, 0, 0, 0, 0, 0, r10 + SBPF_STACK_FRAME), r0 = x_.r0; r2 = x_.r2;);"), "{c}");
}
