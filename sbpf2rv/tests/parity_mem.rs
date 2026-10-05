//! Differential tests of memory (`tests/common`'s host harness): loads and stores of every width,
//! their zero-extension and lack of an alignment rule, the four regions and their edges (every
//! fault carries the address the access started at), the stack frame and a writable `r10`, and
//! the syscalls that touch memory (`sol_memset_`/`memcpy_`/`memmove_`/`memcmp_`, `sol_alloc_free_`,
//! `sol_sha256`, the log family's pointer checks). Each program's outcome is pinned to the value
//! `memory.rs`/`syscalls.rs` give as well as compared across the two sides.

mod common;

use common::{exit, fnv, i, interpret, lddw, mov, parity, parity_bare, set, text};
use sbpf_core::interp::Halt;
use sbpf_core::isa::{self, opc, Insn};
use sbpf_core::memory::{
    HEAP_BYTES, REGION_HEAP, REGION_INPUT, REGION_PROGRAM, REGION_STACK, STACK_BYTES, STACK_FRAME,
};
use sbpf_core::syscalls;

const INPUT: [u8; 16] = [
    0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02,
];

fn with_input(programs: &[Vec<Insn>], input: &[u8]) -> Vec<(Vec<Insn>, Vec<u8>)> {
    programs
        .iter()
        .map(|p| (p.clone(), input.to_vec()))
        .collect()
}

/// `r0 = <load width> [r1 + off]; exit`, `r1` being the input region.
fn load(opc: u8, off: i16) -> Vec<Insn> {
    vec![i(opc, 0, 1, off, 0), exit()]
}

fn sys(hash: u32) -> Insn {
    i(opc::CALL_IMM, 0, 1, 0, hash as i32)
}

// ---- loads ------------------------------------------------------------------------------------------

#[test]
fn loads_zero_extend_at_every_width_and_need_no_alignment() {
    let r = parity(
        "loads",
        &with_input(
            &[
                load(opc::LD_B_REG, 0),
                load(opc::LD_H_REG, 0),
                load(opc::LD_W_REG, 0),
                load(opc::LD_DW_REG, 0),
                load(opc::LD_DW_REG, 1),
                load(opc::LD_W_REG, 3),
                load(opc::LD_H_REG, 7),
                load(opc::LD_B_REG, 15),
                load(opc::LD_B_REG, 16),
                load(opc::LD_DW_REG, 8),
                load(opc::LD_DW_REG, 9),
                // A negative offset from past the end.
                vec![
                    i(opc::ADD64_IMM, 1, 0, 0, 16),
                    i(opc::LD_H_REG, 0, 1, -2, 0),
                    exit(),
                ],
                // A load into the base register itself.
                vec![
                    i(opc::LD_W_REG, 1, 1, 4, 0),
                    i(opc::MOV64_REG, 0, 1, 0, 0),
                    exit(),
                ],
            ],
            &INPUT,
        ),
    );
    assert_eq!(r[0], Ok(0xF0));
    assert_eq!(r[1], Ok(0xDEF0));
    assert_eq!(r[2], Ok(0x9ABC_DEF0));
    assert_eq!(r[3], Ok(0x1234_5678_9ABC_DEF0));
    assert_eq!(r[4], Ok(0xAA12_3456_789A_BCDE));
    assert_eq!(r[5], Ok(0x3456_789A));
    assert_eq!(r[6], Ok(0xAA12));
    assert_eq!(r[7], Ok(0x02));
    assert_eq!(r[8], Err(Halt::AccessViolation(REGION_INPUT + 16)));
    assert_eq!(r[9], Ok(0x0201_FFEE_DDCC_BBAA));
    assert_eq!(
        r[10],
        Err(Halt::AccessViolation(REGION_INPUT + 9)),
        "straddling the input's end faults at the access's start"
    );
    assert_eq!(r[11], Ok(0x0201));
    assert_eq!(r[12], Ok(0x1234_5678));
}

#[test]
fn loads_from_the_program_region_read_the_text() {
    // The text is also the read-only run on the host, as `Program::from_text` has it.
    let p = |tail: &[Insn]| -> Vec<Insn> {
        let mut p = lddw(1, REGION_PROGRAM).to_vec();
        p.extend_from_slice(tail);
        p
    };
    let first = p(&[i(opc::LD_DW_REG, 0, 1, 0, 0), exit()]);
    let n = first.len() as i16;
    let r = parity_bare(
        "program_region_loads",
        &[
            first.clone(),
            p(&[i(opc::LD_B_REG, 0, 1, 8 * n - 1, 0), exit()]),
            p(&[i(opc::LD_B_REG, 0, 1, 8 * n, 0), exit()]),
            p(&[i(opc::LD_DW_REG, 0, 1, 8 * n - 4, 0), exit()]),
            // The program region is read-only: a store there faults wherever it is bounded.
            p(&[i(opc::ST_B_IMM, 1, 0, 0, 1), exit()]),
            p(&[i(opc::ST_DW_REG, 1, 1, 8, 0), exit()]),
        ],
    );
    assert_eq!(
        r[0],
        Ok(isa::encode(first[0])),
        "the first slot's own bytes"
    );
    assert_eq!(r[1], Ok(0), "the last byte of `exit`'s slot");
    assert_eq!(
        r[2],
        Err(Halt::AccessViolation(REGION_PROGRAM + 8 * n as u64))
    );
    assert_eq!(
        r[3],
        Err(Halt::AccessViolation(REGION_PROGRAM + 8 * n as u64 - 4))
    );
    assert_eq!(r[4], Err(Halt::AccessViolation(REGION_PROGRAM)));
    assert_eq!(r[5], Err(Halt::AccessViolation(REGION_PROGRAM + 8)));
}

// ---- stores -----------------------------------------------------------------------------------------

/// A store, and what it does to a 16-byte model of the input region.
fn store(opc: u8, off: i16, imm: i32, src: u8, src_val: u64, model: &mut [u8; 16]) -> Insn {
    let (size, from_reg) = match opc {
        opc::ST_B_IMM => (1, false),
        opc::ST_H_IMM => (2, false),
        opc::ST_W_IMM => (4, false),
        opc::ST_DW_IMM => (8, false),
        opc::ST_B_REG => (1, true),
        opc::ST_H_REG => (2, true),
        opc::ST_W_REG => (4, true),
        _ => (8, true),
    };
    let v = if from_reg { src_val } else { imm as i64 as u64 };
    let at = off as usize;
    for k in 0..size {
        model[at + k] = (v >> (8 * k)) as u8;
    }
    i(opc, 1, src, off, imm)
}

#[test]
fn stores_at_every_width_write_the_low_bytes_of_a_sign_extended_immediate_or_a_register() {
    let v = 0x1122_3344_5566_7788u64;
    let mut model = [0u8; 16];
    let mut p = lddw(2, v).to_vec();
    p.push(store(opc::ST_B_IMM, 0, 0xAB, 0, 0, &mut model));
    p.push(store(opc::ST_H_IMM, 2, -1, 0, 0, &mut model));
    p.push(store(opc::ST_W_IMM, 4, 0x7FFF_FFFF, 0, 0, &mut model));
    p.push(store(opc::ST_DW_IMM, 8, -2, 0, 0, &mut model));
    p.push(store(opc::ST_B_REG, 1, 0, 2, v, &mut model));
    p.push(store(opc::ST_H_REG, 12, 0, 2, v, &mut model));
    p.push(store(opc::ST_W_REG, 8, 0, 2, v, &mut model));
    p.push(store(opc::ST_DW_REG, 3, 0, 2, v, &mut model));
    // An immediate store's `src` nibble is ignored; a register store's `imm` is.
    p.push(store(opc::ST_B_IMM, 15, 0x5A, 2, 0, &mut model));
    p.push(store(opc::ST_B_REG, 14, 0x5A, 2, v, &mut model));
    p.push(i(opc::LD_DW_REG, 0, 1, 0, 0));
    p.push(i(opc::LD_DW_REG, 3, 1, 8, 0));
    p.push(i(opc::XOR64_REG, 0, 3, 0, 0));
    p.push(exit());
    let want = u64::from_le_bytes(model[..8].try_into().unwrap())
        ^ u64::from_le_bytes(model[8..].try_into().unwrap());
    let r = parity("stores", &with_input(&[p.clone()], &[0u8; 16]));
    assert_eq!(r[0], Ok(want));
    // The region afterwards is the model, on both sides (the harness compares them; this pins
    // the interpreter's to the model).
    let (_, seen, _) = interpret(&text(&p), &[0u8; 16]);
    assert_eq!(seen.input, fnv(&model));
}

#[test]
fn stores_straddling_a_regions_end_fault_at_the_access_start_and_write_nothing() {
    let r = parity(
        "store_edges",
        &with_input(
            &[
                vec![i(opc::ST_DW_IMM, 1, 0, 8, 1), exit()],
                vec![i(opc::ST_DW_IMM, 1, 0, 9, 1), exit()],
                vec![i(opc::ST_B_IMM, 1, 0, 15, 1), exit()],
                vec![i(opc::ST_B_IMM, 1, 0, 16, 1), exit()],
                vec![i(opc::ST_H_IMM, 1, 0, -1, 1), exit()],
                vec![i(opc::ST_W_IMM, 1, 0, 14, 1), exit()],
            ],
            &[0u8; 16],
        ),
    );
    assert_eq!(r[0], Ok(0));
    assert_eq!(r[1], Err(Halt::AccessViolation(REGION_INPUT + 9)));
    assert_eq!(r[2], Ok(0));
    assert_eq!(r[3], Err(Halt::AccessViolation(REGION_INPUT + 16)));
    assert_eq!(
        r[4],
        Err(Halt::AccessViolation(REGION_INPUT - 1)),
        "one below the input is the heap's last offset, past its end"
    );
    assert_eq!(r[5], Err(Halt::AccessViolation(REGION_INPUT + 14)));
    // The straddling store wrote nothing: the input is still zero on the interpreter (and so, by
    // the harness, on the translation).
    let (_, seen, _) = interpret(&text(&[i(opc::ST_DW_IMM, 1, 0, 9, 1), exit()]), &[0u8; 16]);
    assert_eq!(seen.input, fnv(&[0u8; 16]));
}

// ---- the stack and r10 ----------------------------------------------------------------------------------

#[test]
fn the_stack_is_one_flat_region_around_the_frame_pointer() {
    let top = REGION_STACK + STACK_BYTES as u64;
    let r = parity_bare(
        "stack_edges",
        &[
            vec![
                i(opc::ST_DW_IMM, 10, 0, -8, 7),
                i(opc::LD_DW_REG, 0, 10, -8, 0),
                exit(),
            ],
            // Above r10 is the next frame: still the stack.
            vec![
                i(opc::ST_DW_IMM, 10, 0, 0, 8),
                i(opc::LD_DW_REG, 0, 10, 0, 0),
                exit(),
            ],
            // The frame's bottom is the region's base; one below it is the program region's top.
            vec![
                i(opc::ST_B_IMM, 10, 0, -(STACK_FRAME as i16), 9),
                i(opc::LD_B_REG, 0, 10, -(STACK_FRAME as i16), 0),
                exit(),
            ],
            vec![
                i(opc::ST_B_IMM, 10, 0, -(STACK_FRAME as i16) - 1, 9),
                exit(),
            ],
            // The region's top.
            {
                let mut p = lddw(2, top - 8).to_vec();
                p.push(i(opc::ST_DW_IMM, 2, 0, 0, 10));
                p.push(i(opc::LD_DW_REG, 0, 2, 0, 0));
                p.push(exit());
                p
            },
            {
                let mut p = lddw(2, top - 8).to_vec();
                p.push(i(opc::ST_DW_IMM, 2, 0, 1, 10));
                p.push(exit());
                p
            },
            {
                let mut p = lddw(2, top).to_vec();
                p.push(i(opc::LD_B_REG, 0, 2, 0, 0));
                p.push(exit());
                p
            },
        ],
    );
    assert_eq!(r[0], Ok(7));
    assert_eq!(r[1], Ok(8));
    assert_eq!(r[2], Ok(9));
    assert_eq!(r[3], Err(Halt::AccessViolation(REGION_STACK - 1)));
    assert_eq!(r[4], Ok(10));
    assert_eq!(r[5], Err(Halt::AccessViolation(top - 7)));
    assert_eq!(r[6], Err(Halt::AccessViolation(top)));
}

#[test]
fn r10_may_be_written_and_a_callee_cannot_change_the_callers() {
    let r = parity(
        "r10_writes",
        &with_input(
            &[
                // r10 = the input region; a store through it lands in the input.
                vec![
                    i(opc::MOV64_REG, 10, 1, 0, 0),
                    i(opc::ST_DW_IMM, 10, 0, 0, 7),
                    i(opc::LD_DW_REG, 0, 1, 0, 0),
                    exit(),
                ],
                // r10 -= one frame: [r10 - 8] is now below the stack.
                vec![
                    i(opc::ADD64_IMM, 10, 0, 0, -(STACK_FRAME as i32)),
                    i(opc::ST_DW_IMM, 10, 0, -8, 7),
                    exit(),
                ],
                // The callee overwrites r10; the caller's comes back with `exit`.
                vec![
                    i(opc::CALL_IMM, 0, 0, 0, 3),    // 0: call 4
                    i(opc::ST_DW_IMM, 10, 0, -8, 1), // 1
                    i(opc::LD_DW_REG, 0, 10, -8, 0), // 2
                    exit(),                          // 3
                    mov(10, 5),                      // 4
                    exit(),                          // 5
                ],
                // The callee's r10 is the caller's plus one frame.
                vec![
                    i(opc::CALL_IMM, 0, 0, 0, 2),   // 0: call 3
                    i(opc::SUB64_REG, 0, 10, 0, 0), // 1: r0 = callee's r10 - r10
                    exit(),                         // 2
                    i(opc::MOV64_REG, 0, 10, 0, 0), // 3
                    exit(),                         // 4
                ],
            ],
            &[0u8; 16],
        ),
    );
    assert_eq!(r[0], Ok(7));
    assert_eq!(r[1], Err(Halt::AccessViolation(REGION_STACK - 8)));
    assert_eq!(r[2], Ok(1));
    assert_eq!(r[3], Ok(STACK_FRAME as u64));
}

#[test]
fn a_fault_after_a_store_keeps_the_store() {
    let p = vec![
        i(opc::ST_DW_IMM, 10, 0, -8, 7),
        i(opc::LD_DW_REG, 0, 0, 0, 0), // r0 is 0: a load through a null pointer
        exit(),
    ];
    let r = parity_bare("store_then_fault", &[p.clone()]);
    assert_eq!(r[0], Err(Halt::AccessViolation(0)));
    let (_, seen, _) = interpret(&text(&p), &[]);
    assert_ne!(
        seen.stack,
        fnv(&[0u8; STACK_BYTES]),
        "the store landed before the fault"
    );
}

// ---- every region's edge -----------------------------------------------------------------------------

#[test]
fn an_access_violation_carries_the_address_the_access_started_at() {
    let at = |addr: u64, opc: u8, off: i16| -> Vec<Insn> {
        let mut p = set(2, addr);
        p.push(i(opc, 0, 2, off, 0));
        p.push(exit());
        p
    };
    let r = parity(
        "av_addresses",
        &with_input(
            &[
                at(0, opc::LD_B_REG, 0),
                at(REGION_HEAP + HEAP_BYTES as u64 - 4, opc::LD_DW_REG, 0),
                at(REGION_HEAP + HEAP_BYTES as u64 - 8, opc::LD_DW_REG, 0),
                at(0x5_0000_0000, opc::LD_B_REG, 0),
                at(REGION_INPUT, opc::LD_DW_REG, -1),
                at(0x4_FFFF_FFFC, opc::LD_DW_REG, 0),
                at(REGION_INPUT + 0xFFFF_FFF0, opc::LD_W_REG, 0),
                at(u64::MAX, opc::LD_B_REG, 1),
                at(REGION_INPUT, opc::LD_B_REG, i16::MIN),
            ],
            &[0u8; 16],
        ),
    );
    assert_eq!(r[0], Err(Halt::AccessViolation(0)));
    assert_eq!(
        r[1],
        Err(Halt::AccessViolation(REGION_HEAP + HEAP_BYTES as u64 - 4))
    );
    assert_eq!(r[2], Ok(0), "the heap's last eight bytes");
    assert_eq!(r[3], Err(Halt::AccessViolation(0x5_0000_0000)));
    assert_eq!(
        r[4],
        Err(Halt::AccessViolation(REGION_INPUT - 1)),
        "a negative offset crosses into the region below"
    );
    assert_eq!(r[5], Err(Halt::AccessViolation(0x4_FFFF_FFFC)));
    assert_eq!(r[6], Err(Halt::AccessViolation(REGION_INPUT + 0xFFFF_FFF0)));
    assert_eq!(
        r[7],
        Err(Halt::AccessViolation(0)),
        "the address wraps to 0"
    );
    assert_eq!(
        r[8],
        Err(Halt::AccessViolation(REGION_INPUT - 32768)),
        "the most negative offset"
    );
}

// ---- syscalls that touch memory ------------------------------------------------------------------------

#[test]
fn memset_memcpy_memmove_and_memcmp_match_byte_for_byte() {
    // Input: 32 bytes, [0..16] = INPUT, the rest zero.
    let mut input = vec![0u8; 32];
    input[..16].copy_from_slice(&INPUT);
    let r = parity(
        "mem_syscalls",
        &with_input(
            &[
                // memset(input, 0x5a, 8); r0 = [input + 0..8]
                vec![
                    mov(2, 0x5a),
                    mov(3, 8),
                    sys(syscalls::SOL_MEMSET),
                    i(opc::LD_DW_REG, 0, 1, 0, 0),
                    exit(),
                ],
                // memcpy(input + 16 <- input, 8); r0 = [input + 16..24]
                vec![
                    i(opc::MOV64_REG, 2, 1, 0, 0),
                    i(opc::ADD64_IMM, 1, 0, 0, 16),
                    mov(3, 8),
                    sys(syscalls::SOL_MEMCPY),
                    i(opc::LD_DW_REG, 0, 1, 0, 0),
                    exit(),
                ],
                // memcpy(input + 4 <- input, 8): overlapping.
                vec![
                    i(opc::MOV64_REG, 2, 1, 0, 0),
                    i(opc::ADD64_IMM, 1, 0, 0, 4),
                    mov(3, 8),
                    sys(syscalls::SOL_MEMCPY),
                    exit(),
                ],
                // memmove(input + 4 <- input, 8): forward overlap, copied backwards.
                vec![
                    i(opc::MOV64_REG, 2, 1, 0, 0),
                    i(opc::ADD64_IMM, 1, 0, 0, 4),
                    mov(3, 8),
                    sys(syscalls::SOL_MEMMOVE),
                    i(opc::LD_DW_REG, 0, 2, 4, 0),
                    exit(),
                ],
                // memmove(input <- input + 4, 8): backward overlap.
                vec![
                    i(opc::MOV64_REG, 2, 1, 0, 0),
                    i(opc::ADD64_IMM, 2, 0, 0, 4),
                    mov(3, 8),
                    sys(syscalls::SOL_MEMMOVE),
                    i(opc::LD_DW_REG, 0, 1, 0, 0),
                    exit(),
                ],
                // memcmp(input, input + 8, 8, &result at input + 24): first difference 0xF0 - 0xAA.
                vec![
                    i(opc::MOV64_REG, 2, 1, 0, 0),
                    i(opc::ADD64_IMM, 2, 0, 0, 8),
                    mov(3, 8),
                    i(opc::MOV64_REG, 4, 1, 0, 0),
                    i(opc::ADD64_IMM, 4, 0, 0, 24),
                    sys(syscalls::SOL_MEMCMP),
                    i(opc::LD_W_REG, 0, 1, 24, 0),
                    exit(),
                ],
                // memcmp(input + 8, input, 8): the other sign, as a u32.
                vec![
                    i(opc::MOV64_REG, 2, 1, 0, 0),
                    i(opc::ADD64_IMM, 1, 0, 0, 8),
                    mov(3, 8),
                    i(opc::MOV64_REG, 4, 2, 0, 0),
                    i(opc::ADD64_IMM, 4, 0, 0, 24),
                    sys(syscalls::SOL_MEMCMP),
                    i(opc::LD_W_REG, 0, 2, 24, 0),
                    exit(),
                ],
                // memcmp of equal bytes writes 0, and a range past the input faults first.
                vec![
                    i(opc::MOV64_REG, 2, 1, 0, 0),
                    mov(3, 16),
                    i(opc::MOV64_REG, 4, 1, 0, 0),
                    i(opc::ADD64_IMM, 4, 0, 0, 24),
                    i(opc::ST_W_IMM, 4, 0, 0, -1),
                    sys(syscalls::SOL_MEMCMP),
                    i(opc::LD_W_REG, 0, 1, 24, 0),
                    exit(),
                ],
                vec![
                    i(opc::MOV64_REG, 2, 1, 0, 0),
                    mov(3, 33),
                    i(opc::MOV64_REG, 4, 1, 0, 0),
                    sys(syscalls::SOL_MEMCMP),
                    exit(),
                ],
                // memset over the input's end writes nothing.
                vec![mov(2, 1), mov(3, 33), sys(syscalls::SOL_MEMSET), exit()],
            ],
            &input,
        ),
    );
    assert_eq!(r[0], Ok(0x5a5a_5a5a_5a5a_5a5a));
    assert_eq!(r[1], Ok(0x1234_5678_9ABC_DEF0));
    assert_eq!(r[2], Err(Halt::Trap("sol_memcpy_ overlap")));
    assert_eq!(
        r[3],
        Ok(0x1234_5678_9ABC_DEF0),
        "the bytes arrive intact at +4"
    );
    assert_eq!(r[4], Ok(0xDDCC_BBAA_1234_5678));
    assert_eq!(r[5], Ok((0xF0i32 - 0xAA) as u32 as u64));
    assert_eq!(r[6], Ok((0xAAi32 - 0xF0) as u32 as u64));
    assert_eq!(r[7], Ok(0));
    assert_eq!(r[8], Err(Halt::AccessViolation(REGION_INPUT)));
    assert_eq!(r[9], Err(Halt::AccessViolation(REGION_INPUT)));
    let (_, seen, _) = interpret(
        &text(&[mov(2, 1), mov(3, 33), sys(syscalls::SOL_MEMSET), exit()]),
        &input,
    );
    assert_eq!(seen.input, fnv(&input), "nothing written");
}

#[test]
fn alloc_free_bumps_the_heap_and_sha256_hashes_through_the_pairs() {
    let mut input = vec![0u8; 80];
    input[..3].copy_from_slice(b"abc");
    let alloc = |size: i32, free: i32| -> Vec<Insn> {
        vec![
            mov(1, size),
            mov(2, free),
            sys(syscalls::SOL_ALLOC_FREE),
            exit(),
        ]
    };
    let r = parity(
        "alloc_sha",
        &with_input(
            &[
                alloc(16, 0),
                alloc(0, 0),
                // Two allocations: the second is eight-aligned after the first.
                vec![
                    mov(1, 3),
                    mov(2, 0),
                    sys(syscalls::SOL_ALLOC_FREE),
                    mov(1, 8),
                    mov(2, 0),
                    sys(syscalls::SOL_ALLOC_FREE),
                    exit(),
                ],
                alloc(HEAP_BYTES as i32, 0),
                alloc(HEAP_BYTES as i32 + 1, 0),
                // `free` is a no-op returning 0.
                alloc(16, 1),
                // sha256: the pair (input, 3) at input + 8, the digest to input + 32.
                vec![
                    i(opc::ST_DW_REG, 1, 1, 8, 0),
                    i(opc::ST_DW_IMM, 1, 0, 16, 3),
                    i(opc::MOV64_REG, 3, 1, 0, 0),
                    i(opc::ADD64_IMM, 3, 0, 0, 32),
                    i(opc::ADD64_IMM, 1, 0, 0, 8),
                    mov(2, 1),
                    sys(syscalls::SOL_SHA256),
                    i(opc::LD_DW_REG, 0, 3, 0, 0),
                    exit(),
                ],
                // The same bytes as two pairs, "a" and "bc".
                vec![
                    i(opc::ST_DW_REG, 1, 1, 8, 0),
                    i(opc::ST_DW_IMM, 1, 0, 16, 1),
                    i(opc::MOV64_REG, 2, 1, 0, 0),
                    i(opc::ADD64_IMM, 2, 0, 0, 1),
                    i(opc::ST_DW_REG, 1, 2, 24, 0),
                    i(opc::ST_DW_IMM, 1, 0, 32, 2),
                    i(opc::MOV64_REG, 3, 1, 0, 0),
                    i(opc::ADD64_IMM, 3, 0, 0, 40),
                    i(opc::ADD64_IMM, 1, 0, 0, 8),
                    mov(2, 2),
                    sys(syscalls::SOL_SHA256),
                    i(opc::LD_DW_REG, 0, 3, 0, 0),
                    exit(),
                ],
                // A pair naming bytes outside every region.
                vec![
                    i(opc::ST_DW_IMM, 1, 0, 8, 0),
                    i(opc::ST_DW_IMM, 1, 0, 16, 1),
                    i(opc::MOV64_REG, 3, 1, 0, 0),
                    i(opc::ADD64_IMM, 1, 0, 0, 8),
                    mov(2, 1),
                    sys(syscalls::SOL_SHA256),
                    exit(),
                ],
            ],
            &input,
        ),
    );
    assert_eq!(r[0], Ok(REGION_HEAP));
    assert_eq!(r[1], Ok(REGION_HEAP), "a zero-sized block at the cursor");
    assert_eq!(r[2], Ok(REGION_HEAP + 8));
    assert_eq!(r[3], Ok(REGION_HEAP), "exactly the heap fits");
    assert_eq!(r[4], Ok(0), "one more does not: a null pointer, not a halt");
    assert_eq!(r[5], Ok(0));
    // SHA-256("abc") = ba7816bf 8f01cfea …: the first eight bytes, little-endian.
    assert_eq!(r[6], Ok(0xeacf_018f_bf16_78ba));
    assert_eq!(r[7], Ok(0xeacf_018f_bf16_78ba), "the pairs are one stream");
    assert_eq!(r[8], Err(Halt::AccessViolation(0)));
}

#[test]
fn the_log_family_checks_its_pointers_and_returns_zero() {
    let r = parity(
        "log_family",
        &with_input(
            &[
                vec![mov(0, 9), mov(2, 16), sys(syscalls::SOL_LOG), exit()],
                vec![mov(0, 9), mov(2, 33), sys(syscalls::SOL_LOG), exit()],
                vec![mov(1, 0), mov(2, 4), sys(syscalls::SOL_LOG), exit()],
                vec![mov(1, 0), mov(2, 0), sys(syscalls::SOL_LOG), exit()],
                vec![mov(0, 9), sys(syscalls::SOL_LOG_PUBKEY), exit()],
                vec![
                    i(opc::ADD64_IMM, 1, 0, 0, 1),
                    sys(syscalls::SOL_LOG_PUBKEY),
                    exit(),
                ],
                vec![mov(1, 0), mov(0, 9), sys(syscalls::SOL_LOG_64), exit()],
            ],
            &[0u8; 32],
        ),
    );
    assert_eq!(r[0], Ok(0));
    assert_eq!(r[1], Err(Halt::AccessViolation(REGION_INPUT)));
    assert_eq!(r[2], Err(Halt::AccessViolation(0)));
    assert_eq!(
        r[3],
        Err(Halt::AccessViolation(0)),
        "a zero length at a null pointer is still checked"
    );
    assert_eq!(r[4], Ok(0));
    assert_eq!(r[5], Err(Halt::AccessViolation(REGION_INPUT + 1)));
    assert_eq!(r[6], Ok(0), "sol_log_64_ reads nothing");
}
