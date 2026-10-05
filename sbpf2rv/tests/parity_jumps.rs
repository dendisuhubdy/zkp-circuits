//! Differential tests of control flow (`tests/common`'s host harness): every one of the 22
//! conditional jumps in both forms over signed and unsigned boundary operands, `ja` backwards and
//! out of the text, the instruction limit at its exact edge, internal calls (the calling
//! convention, the depth limit, a bad target), `callx` by register, syscalls by hash, and every
//! `BadInsn` the interpreter raises before dispatch. Each program's outcome is pinned to the value
//! `interp.rs` gives as well as compared across the two sides.

mod common;

use common::{exit, i, interpret, lddw, mov, parity_bare, run_c, set, text, HALT_BAD_JUMP};
use sbpf_core::elf::Program;
use sbpf_core::interp::{Halt, MAX_INSTRUCTIONS};
use sbpf_core::isa::{self, opc, Insn};
use sbpf_core::memory::{REGION_PROGRAM, REGION_STACK, STACK_FRAME};
use sbpf_core::syscalls;

// ---- the 22 conditional jumps ----------------------------------------------------------------------

/// `interp.rs`'s condition for `o` with `d` and the sign-extended right operand `y`.
fn cond(o: u8, d: u64, y: u64) -> bool {
    use opc::*;
    let (sd, sy) = (d as i64, y as i64);
    match o {
        JEQ_IMM | JEQ_REG => d == y,
        JNE_IMM | JNE_REG => d != y,
        JGT_IMM | JGT_REG => d > y,
        JGE_IMM | JGE_REG => d >= y,
        JLT_IMM | JLT_REG => d < y,
        JLE_IMM | JLE_REG => d <= y,
        JSET_IMM | JSET_REG => d & y != 0,
        JSGT_IMM | JSGT_REG => sd > sy,
        JSGE_IMM | JSGE_REG => sd >= sy,
        JSLT_IMM | JSLT_REG => sd < sy,
        JSLE_IMM | JSLE_REG => sd <= sy,
        _ => unreachable!(),
    }
}

const DS: [u64; 8] = [
    0,
    1,
    7,
    u64::MAX,
    1 << 63,
    (1 << 63) - 1,
    0xFFFF_FFFF,
    0xFFFF_FFFF_8000_0000,
];
const IMMS: [i32; 6] = [0, 1, -1, 7, i32::MIN, i32::MAX];

/// One program per opcode: for each `(d, y)` pair, `r0 <<= 1`, then the jump over a `ja` that
/// skips `r0 |= 1` — so bit k of `r0` (from the top) says whether case k was taken. The expected
/// word is folded from [`cond`].
fn truth_table(o: u8) -> (Vec<Insn>, u64) {
    let is_reg = o & 0x08 != 0;
    let mut p = vec![mov(0, 0)];
    let mut want = 0u64;
    let pairs: Vec<(u64, u64)> = if is_reg {
        DS.iter()
            .flat_map(|&d| DS.iter().map(move |&s| (d, s)))
            .collect()
    } else {
        DS.iter()
            .flat_map(|&d| IMMS.iter().map(move |&k| (d, k as i64 as u64)))
            .collect()
    };
    for (d, y) in pairs {
        p.push(i(opc::LSH64_IMM, 0, 0, 0, 1));
        p.extend(set(1, d));
        if is_reg {
            p.extend(set(2, y));
            p.push(i(o, 1, 2, 1, 0));
        } else {
            p.push(i(o, 1, 0, 1, y as i32));
        }
        p.push(i(opc::JA, 0, 0, 1, 0));
        p.push(i(opc::OR64_IMM, 0, 0, 0, 1));
        want = (want << 1) | u64::from(cond(o, d, y));
    }
    p.push(exit());
    (p, want)
}

#[test]
fn every_conditional_jump_against_signed_and_unsigned_boundary_operands() {
    let opcodes: Vec<u8> = (0..=255u8)
        .filter(|&o| isa::classify(o) == Some(isa::Class::Jmp) && o != opc::JA)
        .collect();
    assert_eq!(opcodes.len(), 22);
    let tables: Vec<(Vec<Insn>, u64)> = opcodes.iter().map(|&o| truth_table(o)).collect();
    let programs: Vec<Vec<Insn>> = tables.iter().map(|(p, _)| p.clone()).collect();
    let r = parity_bare("cond_jumps", &programs);
    for ((o, (_, want)), got) in opcodes.iter().zip(&tables).zip(&r) {
        assert_eq!(*got, Ok(*want), "{o:#04x}");
    }
    // The tables are not degenerate: no opcode's word is all-taken or all-not-taken.
    for (o, (_, want)) in opcodes.iter().zip(&tables) {
        let bits = if o & 0x08 != 0 { 64 } else { 48 };
        let mask = if bits == 64 {
            u64::MAX
        } else {
            (1 << bits) - 1
        };
        assert!(*want != 0 && *want != mask, "{o:#04x}: {want:#x}");
    }
}

#[test]
fn signed_and_unsigned_compares_disagree_exactly_where_the_sign_bit_is_set() {
    // d = 2^63, y = 1: unsigned d > y, signed d < y. Both forms, one program each.
    let prog = |o: u8| -> Vec<Insn> {
        let mut p = lddw(1, 1 << 63).to_vec();
        p.push(mov(2, 1));
        p.push(i(o, 1, 2, 2, 0)); // taken -> pc + 3
        p.push(mov(0, 0));
        p.push(exit());
        p.push(mov(0, 1));
        p.push(exit());
        p
    };
    let r = parity_bare(
        "signed_vs_unsigned",
        &[
            prog(opc::JGT_REG),
            prog(opc::JSGT_REG),
            prog(opc::JLT_REG),
            prog(opc::JSLT_REG),
        ],
    );
    assert_eq!(r, vec![Ok(1), Ok(0), Ok(0), Ok(1)]);
}

// ---- ja ----------------------------------------------------------------------------------------------

#[test]
fn a_backward_ja_loop_counts_down() {
    // 0: r1 = 10; 1: r0 += r1; 2: r1 -= 1; 3: jeq r1, 0, +1 (-> 5); 4: ja -4 (-> 1); 5: exit.
    let p = vec![
        mov(1, 10),
        i(opc::ADD64_REG, 0, 1, 0, 0),
        i(opc::SUB64_IMM, 1, 0, 0, 1),
        i(opc::JEQ_IMM, 1, 0, 1, 0),
        i(opc::JA, 0, 0, -4, 0),
        exit(),
    ];
    assert_eq!(parity_bare("ja_loop", &[p]), vec![Ok(55)]);
}

#[test]
fn a_ja_to_itself_runs_into_the_instruction_limit() {
    let r = parity_bare(
        "ja_self",
        &[
            vec![i(opc::JA, 0, 0, -1, 0)],
            vec![mov(0, 3), i(opc::JA, 0, 0, -1, 0), exit()],
        ],
    );
    assert_eq!(r, vec![Err(Halt::InstructionLimit); 2]);
}

#[test]
fn jumps_out_of_the_text_halt_bad_jump_only_when_taken() {
    let r = parity_bare(
        "jump_out",
        &[
            vec![i(opc::JA, 0, 0, 100, 0), exit()],
            vec![mov(0, 1), i(opc::JA, 0, 0, -5, 0), exit()],
            // Taken past the end; not taken into `exit`.
            vec![mov(1, 0), i(opc::JEQ_IMM, 1, 0, 100, 0), exit()],
            vec![mov(1, 1), i(opc::JEQ_IMM, 1, 0, 100, 0), exit()],
            // Taken to a real slot; not taken off the end of the text.
            vec![mov(1, 1), i(opc::JEQ_IMM, 1, 0, -2, 0)],
            vec![i(opc::JNE_IMM, 1, 0, -2, 0)],
            // The last `ja` lands exactly one past the end.
            vec![i(opc::JA, 0, 0, 0, 0)],
            // `ja +0` is a no-op.
            vec![i(opc::JA, 0, 0, 0, 0), mov(0, 9), exit()],
        ],
    );
    assert_eq!(r[0], Err(Halt::BadJump));
    assert_eq!(r[1], Err(Halt::BadJump), "before slot 0");
    assert_eq!(r[2], Err(Halt::BadJump));
    assert_eq!(r[3], Ok(0));
    assert_eq!(
        r[4],
        Err(Halt::BadJump),
        "the not-taken side falls off the text"
    );
    assert_eq!(
        r[5],
        Err(Halt::BadJump),
        "r1 is the input region, never 0: taken, to slot -1"
    );
    assert_eq!(r[6], Err(Halt::BadJump));
    assert_eq!(r[7], Ok(9));
}

#[test]
fn a_jump_onto_an_lddws_second_slot_runs_whatever_decodes_there() {
    // 0: ja +1 -> slot 2, the high half of the `lddw` at 1-2. As its own instruction it is
    // `mov r0, 7` in the first program and opcode 0 in the second.
    let p = |hi: Insn| -> Vec<Insn> {
        vec![
            i(opc::JA, 0, 0, 1, 0),
            i(opc::LD_DW_IMM, 1, 0, 0, 0x1111),
            hi,
            exit(),
        ]
    };
    let r = parity_bare(
        "lddw_second_slot",
        &[
            p(i(opc::MOV64_IMM, 0, 0, 0, 7)),
            p(i(0, 0, 0, 0, 7)),
            // Reached in order instead: the `lddw` consumes its second slot.
            vec![
                i(opc::LD_DW_IMM, 0, 0, 0, 0x1111),
                i(opc::MOV64_IMM, 0, 0, 0, 7),
                exit(),
            ],
        ],
    );
    assert_eq!(r[0], Ok(7));
    assert_eq!(r[1], Err(Halt::BadInsn(0)));
    assert_eq!(r[2], Ok(0x0000_0007_0000_1111));
}

// ---- the instruction limit -------------------------------------------------------------------------

/// `mov r1, t; L: r1 -= 1; jne r1, 0, L; <tail>`: `2 + 2t + tail.len()` instructions when it runs
/// to the end.
fn countdown(t: i32, tail: &[Insn]) -> Vec<Insn> {
    let mut p = vec![
        mov(1, t),
        i(opc::SUB64_IMM, 1, 0, 0, 1),
        i(opc::JNE_IMM, 1, 0, -2, 0),
    ];
    p.extend_from_slice(tail);
    p
}

#[test]
fn the_instruction_limit_halts_the_200_001st_instruction_and_not_the_200_000th() {
    let half = (MAX_INSTRUCTIONS / 2) as i32; // 100 000
    let cases = [
        // 2t + 2 == 200 000: the `exit` is the 200 000th instruction and runs.
        countdown(half - 1, &[exit()]),
        // 2t + 3 == 200 001: `mov r0, 5` is the 200 000th, `exit` would be the 200 001st.
        countdown(half - 1, &[mov(0, 5), exit()]),
        // 2t + 3 == 199 999.
        countdown(half - 2, &[mov(0, 5), exit()]),
        // 2t + 2 == 200 002.
        countdown(half, &[exit()]),
    ];
    let meters: Vec<u64> = cases.iter().map(|p| interpret(&text(p), &[]).2).collect();
    assert_eq!(meters, vec![200_000, 200_000, 199_999, 200_000]);
    let r = parity_bare("limit_edge", &cases);
    assert_eq!(r[0], Ok(0));
    assert_eq!(r[1], Err(Halt::InstructionLimit));
    assert_eq!(r[2], Ok(5));
    assert_eq!(r[3], Err(Halt::InstructionLimit));
}

// ---- calls -------------------------------------------------------------------------------------------

#[test]
fn a_call_restores_r6_to_r10_and_keeps_the_callees_r0_to_r5() {
    // Caller: r6..r9 = 6..9, [r10-8] = 11, call f, then r0 = f's r0 + r6+r7+r8+r9 + [r10-8] +
    // [the callee's r10-8] + r1 (the callee's). Callee f (pc 12): clobbers r6..r9, writes its own
    // frame, r1 = 1000, r0 = 100.
    let p = vec![
        mov(6, 6),                                           // 0
        mov(7, 7),                                           // 1
        mov(8, 8),                                           // 2
        mov(9, 9),                                           // 3
        i(opc::ST_DW_IMM, 10, 0, -8, 11),                    // 4
        i(opc::CALL_IMM, 0, 0, 0, 12 - 6),                   // 5: call 12
        i(opc::ADD64_REG, 0, 6, 0, 0),                       // 6
        i(opc::ADD64_REG, 0, 7, 0, 0),                       // 7
        i(opc::ADD64_REG, 0, 8, 0, 0),                       // 8
        i(opc::ADD64_REG, 0, 9, 0, 0),                       // 9
        i(opc::ADD64_REG, 0, 1, 0, 0),                       // 10
        i(opc::JA, 0, 0, 7, 0),                              // 11: -> 19
        mov(6, 60),                                          // 12: f
        mov(7, 70),                                          // 13
        mov(8, 80),                                          // 14
        mov(9, 90),                                          // 15
        i(opc::ST_DW_IMM, 10, 0, -8, 22),                    // 16
        mov(1, 1000),                                        // 17
        mov(0, 100),                     // 18: falls into the shared exit — a jump target
        i(opc::LD_DW_REG, 2, 10, -8, 0), // 19: r2 = [r10-8]
        i(opc::ADD64_REG, 0, 2, 0, 0),   // 20
        i(opc::LD_DW_REG, 2, 10, STACK_FRAME as i16 - 8, 0), // 21: the callee's frame
        i(opc::ADD64_REG, 0, 2, 0, 0),   // 22
        exit(),                          // 23
    ];
    // f runs 12..23: its exit adds its own [r10-8] (22) and its frame-above's [r10+4088] (0).
    // Returns r0 = 100 + 22 + 0 = 122, r1 = 1000. The caller: 122 + 30 + 1000 + 11 + 22.
    assert_eq!(
        parity_bare("call_convention", &[p]),
        vec![Ok(122 + 30 + 1000 + 11 + 22)]
    );
}

/// `0: r1 = n; 1: jeq r1, 0, +2; 2: r1 -= 1; 3: call 1; 4: r0 += 1; 5: exit` — `n` nested calls,
/// each level adding one on the way out.
fn recursion(n: i32) -> Vec<Insn> {
    vec![
        mov(1, n),
        i(opc::JEQ_IMM, 1, 0, 2, 0),
        i(opc::SUB64_IMM, 1, 0, 0, 1),
        i(opc::CALL_IMM, 0, 0, 0, 1 - 4),
        i(opc::ADD64_IMM, 0, 0, 0, 1),
        exit(),
    ]
}

#[test]
fn the_eighth_nested_call_is_refused_and_the_seventh_is_not() {
    let r = parity_bare(
        "call_depth",
        &[recursion(0), recursion(1), recursion(7), recursion(8)],
    );
    assert_eq!(r, vec![Ok(1), Ok(2), Ok(8), Err(Halt::CallDepth)]);
}

#[test]
fn a_call_to_a_bad_target_checks_the_depth_first() {
    // f: `jeq r1, 0, +2 (-> bad); r1 -= 1; call f; exit; bad: call +1000`.
    let p = |n: i32| -> Vec<Insn> {
        vec![
            mov(1, n),
            i(opc::JEQ_IMM, 1, 0, 3, 0),      // 1: -> 5
            i(opc::SUB64_IMM, 1, 0, 0, 1),    // 2
            i(opc::CALL_IMM, 0, 0, 0, 1 - 4), // 3: call 1
            exit(),                           // 4
            i(opc::CALL_IMM, 0, 0, 0, 1000),  // 5: bad target
            exit(),                           // 6
        ]
    };
    let r = parity_bare("bad_call_depth", &[p(0), p(2), p(7)]);
    assert_eq!(r[0], Err(Halt::BadJump));
    assert_eq!(r[1], Err(Halt::BadJump));
    assert_eq!(
        r[2],
        Err(Halt::CallDepth),
        "the frame is pushed before the target is fetched"
    );
}

#[test]
fn a_call_imm_with_src_between_2_and_10_is_bad_insn() {
    let r = parity_bare(
        "call_src",
        &[
            vec![mov(0, 1), i(opc::CALL_IMM, 0, 2, 0, 0), exit()],
            vec![mov(0, 1), i(opc::CALL_IMM, 0, 10, 0, 0), exit()],
        ],
    );
    assert_eq!(r, vec![Err(Halt::BadInsn(opc::CALL_IMM)); 2]);
}

// ---- callx ----------------------------------------------------------------------------------------------

/// `0-1: lddw r3, target; 2: callx r3; 3: exit; 4: A: r0 = 44; exit; 6: B: r0 = 66; exit;
/// 8-11: lddw r4, &A; lddw r5, &B` (dead: the table that names A and B as entries to the
/// scanner, whatever `target` is). 12 slots.
fn callx_program(target: u64, reg: i32) -> Vec<Insn> {
    let mut p = lddw(3, target).to_vec();
    p.push(i(opc::CALL_REG, 0, 0, 0, reg));
    p.push(exit());
    p.push(mov(0, 44));
    p.push(exit());
    p.push(mov(0, 66));
    p.push(exit());
    p.extend(lddw(4, REGION_PROGRAM + 8 * 4));
    p.extend(lddw(5, REGION_PROGRAM + 8 * 6));
    p
}

#[test]
fn callx_reaches_either_known_function_by_its_address() {
    let r = parity_bare(
        "callx",
        &[
            callx_program(REGION_PROGRAM + 8 * 6, 3),
            callx_program(REGION_PROGRAM + 8 * 4, 3),
            // An unaligned address is truncated to its slot by `(addr - text_va) / 8`.
            callx_program(REGION_PROGRAM + 8 * 6 + 4, 3),
            // One past the text, a null address, and the stack address in r10.
            callx_program(REGION_PROGRAM + 8 * 12, 3),
            callx_program(0, 3),
            callx_program(REGION_PROGRAM + 8 * 6, 10),
            // A register number above r10.
            callx_program(REGION_PROGRAM + 8 * 6, 11),
            // callx at the depth limit: 8 pushes.
            {
                let mut p = vec![mov(1, 8)];
                p.extend(lddw(3, REGION_PROGRAM + 8 * 3));
                p.push(i(opc::JEQ_IMM, 1, 0, 2, 0)); // 3: f -> 6 when done
                p.push(i(opc::SUB64_IMM, 1, 0, 0, 1));
                p.push(i(opc::CALL_REG, 0, 0, 0, 3));
                p.push(i(opc::ADD64_IMM, 0, 0, 0, 1)); // 6
                p.push(exit());
                p
            },
        ],
    );
    assert_eq!(r[0], Ok(66));
    assert_eq!(r[1], Ok(44));
    assert_eq!(r[2], Ok(66));
    assert_eq!(r[3], Err(Halt::BadJump));
    assert_eq!(r[4], Err(Halt::BadJump));
    assert_eq!(r[5], Err(Halt::BadJump));
    assert_eq!(r[6], Err(Halt::BadInsn(opc::CALL_REG)));
    assert_eq!(r[7], Err(Halt::CallDepth));
    assert_eq!(
        REGION_STACK + STACK_FRAME as u64,
        0x2_0000_1000,
        "r10's initial value"
    );
}

/// Accepted divergence #1 (README): a `callx` to a slot that is real code but no known function
/// entry — here A's `exit` at pc 5, reached through an address *computed* at run time (`&A + 8`),
/// since any `lddw` constant that lands on an instruction is itself taken for an entry — runs on
/// the interpreter (the `exit` pops the frame, `r0` is still 0) and halts `BadJump` on the
/// translation. Pinned here so a change to that ruling is a deliberate one.
#[test]
fn callx_to_code_that_is_not_a_known_entry_is_the_accepted_divergence() {
    // 0-1: lddw r3, &A; 2: r3 += 8 (A's `exit` at pc 6, named by no constant); 3: callx r3;
    // 4: exit; 5: A: r0 = 44; 6: exit; 7: B: r0 = 66; 8: exit; 9-12: the table naming A and B.
    let mut p = lddw(3, REGION_PROGRAM + 8 * 5).to_vec();
    p.push(i(opc::ADD64_IMM, 3, 0, 0, 8));
    p.push(i(opc::CALL_REG, 0, 0, 0, 3));
    p.push(exit());
    p.push(mov(0, 44));
    p.push(exit());
    p.push(mov(0, 66));
    p.push(exit());
    p.extend(lddw(4, REGION_PROGRAM + 8 * 5));
    p.extend(lddw(5, REGION_PROGRAM + 8 * 7));
    let t = text(&p);
    {
        let prog = Program::from_text(&t).unwrap();
        let s = sbpf2rv::scan::scan(&prog);
        assert_eq!(s.callx_targets, vec![0, 5, 7], "pc 6 is nobody's entry");
    }
    let (result, seen, _) = interpret(&t, &[]);
    assert_eq!(result, Ok(0), "the interpreter runs the exit at pc 6");
    let c = &run_c("callx_divergence", &[(t.clone(), Vec::new())])[0];
    assert_eq!(c.code, HALT_BAD_JUMP, "the translation refuses it: {c:?}");
    assert_eq!(
        (c.stack, c.heap),
        (seen.stack, seen.heap),
        "nothing was written on either side"
    );
}

// ---- syscalls ---------------------------------------------------------------------------------------------

#[test]
fn syscalls_by_hash_run_trap_or_halt_unknown() {
    let sys = |hash: u32| i(opc::CALL_IMM, 0, 1, 0, hash as i32);
    let unknown = syscalls::murmur3_32(b"sol_get_sysvar", 0);
    let cpi = syscalls::murmur3_32(b"sol_invoke_signed_rust", 0);
    let r = parity_bare(
        "syscalls_hash",
        &[
            vec![mov(0, 9), sys(syscalls::SOL_LOG_64), exit()],
            vec![mov(0, 9), sys(syscalls::SOL_LOG_COMPUTE_UNITS), exit()],
            vec![mov(0, 9), sys(unknown), exit()],
            vec![mov(0, 9), sys(cpi), exit()],
            vec![mov(0, 9), sys(syscalls::ABORT), exit()],
            vec![mov(0, 9), sys(syscalls::SOL_PANIC), exit()],
            // Register state after a syscall: r1..r5 survive, r0 is its result.
            vec![
                mov(1, 5),
                mov(2, 6),
                sys(syscalls::SOL_LOG_64),
                i(opc::ADD64_REG, 1, 2, 0, 0),
                i(opc::ADD64_REG, 0, 1, 0, 0),
                exit(),
            ],
        ],
    );
    assert_eq!(r[0], Ok(0), "the log family returns 0");
    assert_eq!(r[1], Ok(0));
    assert_eq!(r[2], Err(Halt::UnknownSyscall(unknown)));
    assert_eq!(
        r[3],
        Err(Halt::UnknownSyscall(cpi)),
        "CPI is unknown at run time"
    );
    assert_eq!(r[4], Err(Halt::Trap("abort")));
    assert_eq!(r[5], Err(Halt::Trap("sol_panic_")));
    assert_eq!(r[6], Ok(11));
}

// ---- BadInsn before dispatch --------------------------------------------------------------------------------

#[test]
fn a_register_above_r10_halts_bad_insn_in_every_class_without_running() {
    let bad = [
        i(opc::ADD64_IMM, 11, 0, 0, 1),
        i(opc::LD_W_REG, 0, 12, 0, 0),
        i(opc::ST_DW_IMM, 15, 0, 0, 0),
        i(opc::JEQ_REG, 1, 11, 1, 0),
        i(opc::JA, 11, 0, 0, 0),
        i(opc::EXIT, 11, 0, 0, 0),
        i(opc::CALL_IMM, 11, 0, 0, 0),
        i(opc::LD_DW_IMM, 13, 0, 0, 0),
        i(opc::MOV32_REG, 1, 14, 0, 0),
        i(opc::BE, 11, 0, 0, 64),
        i(opc::NEG64, 0, 11, 0, 0),
        i(opc::ST_B_REG, 1, 11, 0, 0),
    ];
    let programs: Vec<Vec<Insn>> = bad
        .iter()
        .map(|b| {
            let mut p = vec![mov(0, 7), i(opc::ST_DW_IMM, 10, 0, -8, 3)];
            p.push(*b);
            p.push(i(0, 0, 0, 0, 0)); // an lddw's second slot, never fetched
            p.push(exit());
            p
        })
        .collect();
    let r = parity_bare("bad_registers", &programs);
    for (b, r) in bad.iter().zip(&r) {
        assert_eq!(*r, Err(Halt::BadInsn(b.opc)), "{b:?}");
    }
}

#[test]
fn v2_and_unassigned_opcodes_halt_bad_insn_with_the_byte() {
    // A sample of the bytes `isa::classify` leaves out: the PQR class (v2's `sdiv`/`srem`/`lmul`…),
    // `hor64`, v2's `return`, and plain gaps.
    let bytes = [
        0x00, 0x06, 0x0e, 0x36, 0x3e, 0x46, 0x4e, 0x56, 0x5e, 0x66, 0x6e, 0x76, 0x7e, 0x86, 0x8e,
        0x96, 0x9d, 0x9e, 0xb6, 0xbe, 0xc6, 0xce, 0xe6, 0xee, 0xf6, 0xf7, 0xfe, 0xff,
    ];
    for b in bytes {
        assert_eq!(isa::classify(b), None, "{b:#04x} is a v1 opcode");
    }
    let programs: Vec<Vec<Insn>> = bytes
        .iter()
        .map(|&b| vec![mov(0, 7), i(b, 1, 2, 3, 4), exit()])
        .collect();
    let r = parity_bare("bad_opcodes", &programs);
    for (b, r) in bytes.iter().zip(&r) {
        assert_eq!(*r, Err(Halt::BadInsn(*b)), "{b:#04x}");
    }
}
