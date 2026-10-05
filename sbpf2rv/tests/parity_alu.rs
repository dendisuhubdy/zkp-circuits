//! Differential tests of the arithmetic classes: hand-assembled programs run through the
//! interpreter and through the emitted C on the host (`tests/common`), and must agree exactly; each
//! program's `r0` (or halt) is also pinned to the value `interp.rs`'s semantics give, so a test
//! fails on a wrong answer even if both sides were wrong the same way. The edges the module docs
//! of `interp.rs` single out: 32-bit `add`/`sub`/`mul` sign-extend where everything else
//! zero-extends, shift counts are masked, division is unsigned and a zero divisor halts whether it
//! is a register or an immediate, `le`/`be` take only 16/32/64.

mod common;

use common::{exit, i, lddw, mov, parity_bare, set};
use sbpf_core::interp::Halt;
use sbpf_core::isa::{opc, Insn};

/// `r1 = a; <op>; r0 = r1; exit` for a 64-bit `op` on `r1` (register form against `r2 = b`).
fn unary(a: u64, op: Insn) -> Vec<Insn> {
    let mut p = set(1, a);
    p.push(op);
    p.push(i(opc::MOV64_REG, 0, 1, 0, 0));
    p.push(exit());
    p
}

fn binary(a: u64, b: u64, op: Insn) -> Vec<Insn> {
    let mut p = set(1, a);
    p.extend(set(2, b));
    p.push(op);
    p.push(i(opc::MOV64_REG, 0, 1, 0, 0));
    p.push(exit());
    p
}

fn imm(opc: u8, k: i32) -> Insn {
    i(opc, 1, 0, 0, k)
}

fn reg(opc: u8) -> Insn {
    i(opc, 1, 2, 0, 0)
}

// ---- alu64 --------------------------------------------------------------------------------------

#[test]
fn alu64_add_sub_mul_wrap_modulo_2_to_the_64() {
    let r = parity_bare(
        "alu64_wrap",
        &[
            unary(u64::MAX, imm(opc::ADD64_IMM, 1)),
            unary(0, imm(opc::SUB64_IMM, 1)),
            binary(0x8000_0000_0000_0001, 2, reg(opc::MUL64_REG)),
            unary(0, imm(opc::ADD64_IMM, -1)),
            unary(1, imm(opc::MUL64_IMM, -1)),
            binary(u64::MAX, u64::MAX, reg(opc::ADD64_REG)),
            binary(5, 7, reg(opc::SUB64_REG)),
            unary(0xFFFF_FFFF, imm(opc::MUL64_IMM, i32::MAX)),
        ],
    );
    assert_eq!(r[0], Ok(0));
    assert_eq!(r[1], Ok(u64::MAX));
    assert_eq!(r[2], Ok(2));
    assert_eq!(r[3], Ok(u64::MAX), "the immediate is sign-extended");
    assert_eq!(r[4], Ok(u64::MAX));
    assert_eq!(r[5], Ok(u64::MAX - 1));
    assert_eq!(r[6], Ok(5u64.wrapping_sub(7)));
    assert_eq!(r[7], Ok(0xFFFF_FFFFu64.wrapping_mul(i32::MAX as u64)));
}

#[test]
fn alu64_div_and_mod_are_unsigned_with_a_sign_extended_immediate() {
    let r = parity_bare(
        "alu64_divmod",
        &[
            // `-1` sign-extends to 2^64 - 1: MAX / MAX = 1, not MAX / 0xFFFF_FFFF.
            unary(u64::MAX, imm(opc::DIV64_IMM, -1)),
            unary(u64::MAX, imm(opc::MOD64_IMM, 10)),
            unary(1 << 63, imm(opc::DIV64_IMM, 2)),
            binary(u64::MAX, 3, reg(opc::DIV64_REG)),
            binary(u64::MAX, 1 << 32, reg(opc::MOD64_REG)),
            // A divisor whose low 32 bits are zero is not zero at 64 bits.
            binary(1 << 40, 1 << 32, reg(opc::DIV64_REG)),
            unary(100, imm(opc::DIV64_IMM, i32::MIN)),
            binary(7, 7, reg(opc::MOD64_REG)),
        ],
    );
    assert_eq!(r[0], Ok(1));
    assert_eq!(r[1], Ok(u64::MAX % 10));
    assert_eq!(r[2], Ok(1 << 62));
    assert_eq!(r[3], Ok(u64::MAX / 3));
    assert_eq!(r[4], Ok(u64::MAX % (1 << 32)));
    assert_eq!(r[5], Ok(1 << 8));
    assert_eq!(r[6], Ok(0), "100 / 0xFFFF_FFFF_8000_0000");
    assert_eq!(r[7], Ok(0));
}

#[test]
fn a_zero_divisor_halts_in_every_form_register_or_immediate() {
    let r = parity_bare(
        "div_by_zero",
        &[
            unary(5, imm(opc::DIV64_IMM, 0)),
            unary(5, imm(opc::MOD64_IMM, 0)),
            binary(5, 0, reg(opc::DIV64_REG)),
            binary(5, 0, reg(opc::MOD64_REG)),
            unary(5, imm(opc::DIV32_IMM, 0)),
            unary(5, imm(opc::MOD32_IMM, 0)),
            binary(5, 0, reg(opc::DIV32_REG)),
            binary(5, 0, reg(opc::MOD32_REG)),
            // The 32-bit forms look only at the divisor's low half: 2^32 is zero to them.
            binary(5, 1 << 32, reg(opc::DIV32_REG)),
            binary(5, 1 << 32, reg(opc::MOD32_REG)),
            // Dividing a register by itself when it is zero halts too.
            unary(0, i(opc::DIV64_REG, 1, 1, 0, 0)),
        ],
    );
    for (k, r) in r.iter().enumerate() {
        assert_eq!(*r, Err(Halt::DivByZero), "program {k}");
    }
}

#[test]
fn shift_counts_are_masked_to_the_width() {
    let r = parity_bare(
        "shift_mask",
        &[
            unary(1, imm(opc::LSH64_IMM, 64)),
            unary(1, imm(opc::LSH64_IMM, 65)),
            binary(u64::MAX, 127, reg(opc::RSH64_REG)),
            unary(1 << 63, imm(opc::ARSH64_IMM, 63)),
            unary(1 << 63, imm(opc::ARSH64_IMM, -1)),
            binary(1 << 63, 1 << 32 | 4, reg(opc::ARSH64_REG)),
            unary(1, imm(opc::LSH32_IMM, 32)),
            unary(1, imm(opc::LSH32_IMM, 33)),
            unary(u64::MAX, imm(opc::RSH32_IMM, 4)),
            unary(0x8000_0000, imm(opc::ARSH32_IMM, 4)),
            unary(0x8000_0000, imm(opc::ARSH32_IMM, -1)),
            binary(0xFFFF_FFFF_8000_0000, 36, reg(opc::ARSH32_REG)),
            binary(0x1_0000_0001, 31, reg(opc::LSH32_REG)),
        ],
    );
    assert_eq!(r[0], Ok(1), "64 & 63 == 0");
    assert_eq!(r[1], Ok(2), "65 & 63 == 1");
    assert_eq!(r[2], Ok(1), "127 & 63 == 63");
    assert_eq!(r[3], Ok(u64::MAX));
    assert_eq!(r[4], Ok(u64::MAX), "-1 & 63 == 63");
    assert_eq!(
        r[5],
        Ok(0xF800_0000_0000_0000),
        "the count's high bits are ignored"
    );
    assert_eq!(r[6], Ok(1), "32 & 31 == 0");
    assert_eq!(r[7], Ok(2));
    assert_eq!(
        r[8],
        Ok(0x0FFF_FFFF),
        "a 32-bit shift drops the high half first"
    );
    assert_eq!(
        r[9],
        Ok(0xF800_0000),
        "arithmetic at 32 bits, zero-extended to 64"
    );
    assert_eq!(r[10], Ok(0xFFFF_FFFF));
    assert_eq!(r[11], Ok(0xF800_0000), "36 & 31 == 4");
    assert_eq!(r[12], Ok(0x8000_0000));
}

// ---- alu32 --------------------------------------------------------------------------------------

#[test]
fn alu32_add_sub_mul_sign_extend_their_32_bit_result() {
    let r = parity_bare(
        "alu32_signext",
        &[
            unary(0x7FFF_FFFF, imm(opc::ADD32_IMM, 1)),
            unary(0, imm(opc::SUB32_IMM, 1)),
            binary(0x1_0000, 0x1_0000, reg(opc::MUL32_REG)),
            unary(0xFFFF_FFFF, imm(opc::MUL32_IMM, 1)),
            // The high half of the operand is dropped before the add.
            unary(1 << 32 | 5, imm(opc::ADD32_IMM, 1)),
            binary(1 << 32 | 5, 1 << 32 | 7, reg(opc::SUB32_REG)),
            unary(3, imm(opc::MUL32_IMM, -1)),
            unary(0, imm(opc::ADD32_IMM, i32::MIN)),
        ],
    );
    assert_eq!(r[0], Ok(0xFFFF_FFFF_8000_0000));
    assert_eq!(r[1], Ok(u64::MAX));
    assert_eq!(r[2], Ok(0));
    assert_eq!(r[3], Ok(u64::MAX));
    assert_eq!(r[4], Ok(6));
    assert_eq!(r[5], Ok(u64::MAX - 1));
    assert_eq!(r[6], Ok(0xFFFF_FFFF_FFFF_FFFD));
    assert_eq!(r[7], Ok(0xFFFF_FFFF_8000_0000));
}

#[test]
fn alu32_logic_div_mod_mov_and_neg_zero_extend() {
    let r = parity_bare(
        "alu32_zeroext",
        &[
            binary(
                0xFFFF_0000_0000_0001,
                0xFFFF_0000_0000_0002,
                reg(opc::OR32_REG),
            ),
            unary(u64::MAX, imm(opc::AND32_IMM, -1)),
            unary(0xAAAA_AAAA_AAAA_AAAA, imm(opc::XOR32_IMM, -1)),
            binary(0, 0xFFFF_FFFF_FFFF_FFF0, reg(opc::MOV32_REG)),
            unary(0, imm(opc::MOV32_IMM, -1)),
            unary(0, imm(opc::MOV32_IMM, i32::MIN)),
            unary(1, i(opc::NEG32, 1, 0, 0, 0)),
            unary(0x8000_0000, i(opc::NEG32, 1, 0, 0, 0)),
            unary(1 << 32, i(opc::NEG32, 1, 0, 0, 0)),
            unary(1, i(opc::NEG64, 1, 0, 0, 0)),
            unary(1 << 63, i(opc::NEG64, 1, 0, 0, 0)),
            unary(0xFFFF_FFFF_0000_000A, imm(opc::DIV32_IMM, 3)),
            binary(
                0xFFFF_FFFF_0000_000A,
                0xFFFF_FFFF_0000_0003,
                reg(opc::MOD32_REG),
            ),
            unary(0xFFFF_FFFF, imm(opc::DIV32_IMM, -1)),
        ],
    );
    assert_eq!(r[0], Ok(3));
    assert_eq!(r[1], Ok(0xFFFF_FFFF));
    assert_eq!(r[2], Ok(0x5555_5555));
    assert_eq!(r[3], Ok(0xFFFF_FFF0));
    assert_eq!(r[4], Ok(0xFFFF_FFFF));
    assert_eq!(r[5], Ok(0x8000_0000));
    assert_eq!(r[6], Ok(0xFFFF_FFFF));
    assert_eq!(
        r[7],
        Ok(0x8000_0000),
        "the one value that is its own 32-bit negation"
    );
    assert_eq!(r[8], Ok(0), "the high half is dropped, and -0 is 0");
    assert_eq!(r[9], Ok(u64::MAX));
    assert_eq!(r[10], Ok(1 << 63));
    assert_eq!(r[11], Ok(3));
    assert_eq!(r[12], Ok(1));
    assert_eq!(r[13], Ok(1), "the immediate is 0xFFFF_FFFF at 32 bits");
}

#[test]
fn byte_swaps_truncate_to_the_width_and_reject_any_other() {
    let v = 0x1234_5678_9ABC_DEF0u64;
    let r = parity_bare(
        "byteswap",
        &[
            unary(v, imm(opc::BE, 16)),
            unary(v, imm(opc::BE, 32)),
            unary(v, imm(opc::BE, 64)),
            unary(v, imm(opc::LE, 16)),
            unary(v, imm(opc::LE, 32)),
            unary(v, imm(opc::LE, 64)),
            unary(v, imm(opc::LE, 8)),
            unary(v, imm(opc::BE, 48)),
            unary(v, imm(opc::BE, 0)),
            unary(v, imm(opc::LE, -16)),
        ],
    );
    assert_eq!(r[0], Ok(0xF0DE));
    assert_eq!(r[1], Ok(0xF0DE_BC9A));
    assert_eq!(r[2], Ok(v.swap_bytes()));
    assert_eq!(r[3], Ok(0xDEF0));
    assert_eq!(r[4], Ok(0x9ABC_DEF0));
    assert_eq!(r[5], Ok(v), "le64 is the identity");
    assert_eq!(r[6], Err(Halt::BadInsn(opc::LE)));
    assert_eq!(r[7], Err(Halt::BadInsn(opc::BE)));
    assert_eq!(r[8], Err(Halt::BadInsn(opc::BE)));
    assert_eq!(r[9], Err(Halt::BadInsn(opc::LE)));
}

#[test]
fn immediates_at_i32_min_and_max_in_every_family() {
    let r = parity_bare(
        "imm_extremes",
        &[
            unary(0, imm(opc::MOV64_IMM, i32::MIN)),
            unary(0, imm(opc::ADD64_IMM, i32::MIN)),
            unary(u64::MAX, imm(opc::AND64_IMM, i32::MIN)),
            unary(2, imm(opc::MUL64_IMM, i32::MIN)),
            unary(0, imm(opc::OR64_IMM, i32::MAX)),
            unary(0, imm(opc::XOR64_IMM, i32::MIN)),
            unary(u64::MAX, imm(opc::DIV64_IMM, i32::MIN)),
            unary(u64::MAX, imm(opc::MOD64_IMM, i32::MAX)),
            unary(1, imm(opc::LSH64_IMM, i32::MIN)),
            unary(1, imm(opc::LSH64_IMM, i32::MAX)),
            unary(0, imm(opc::SUB32_IMM, i32::MIN)),
            unary(u64::MAX, imm(opc::AND32_IMM, i32::MIN)),
            unary(0xFFFF_FFFF, imm(opc::MOD32_IMM, i32::MAX)),
        ],
    );
    assert_eq!(r[0], Ok(0xFFFF_FFFF_8000_0000));
    assert_eq!(r[1], Ok(0xFFFF_FFFF_8000_0000));
    assert_eq!(r[2], Ok(0xFFFF_FFFF_8000_0000));
    assert_eq!(r[3], Ok(0xFFFF_FFFF_0000_0000));
    assert_eq!(r[4], Ok(0x7FFF_FFFF));
    assert_eq!(r[5], Ok(0xFFFF_FFFF_8000_0000));
    assert_eq!(r[6], Ok(1));
    assert_eq!(r[7], Ok(u64::MAX % 0x7FFF_FFFF));
    assert_eq!(r[8], Ok(1), "i32::MIN & 63 == 0");
    assert_eq!(r[9], Ok(1 << 63), "i32::MAX & 63 == 63");
    assert_eq!(
        r[10],
        Ok(0xFFFF_FFFF_8000_0000),
        "0 - (-2^31) at 32 bits is -2^31, sign-extended"
    );
    assert_eq!(r[11], Ok(0x8000_0000));
    assert_eq!(r[12], Ok(0xFFFF_FFFF % 0x7FFF_FFFF));
}

// ---- lddw --------------------------------------------------------------------------------------

#[test]
fn lddw_does_not_smear_a_negative_low_half_and_ignores_the_second_slots_other_fields() {
    let r = parity_bare(
        "lddw_forms",
        &[
            vec![i(opc::LD_DW_IMM, 0, 0, 0, -1), i(0, 0, 0, 0, 0), exit()],
            vec![i(opc::LD_DW_IMM, 0, 0, 0, -1), i(0, 0, 0, 0, -1), exit()],
            // The second slot's opcode, registers and offset are ignored by the fetch: only its
            // `imm` is the high half.
            vec![
                i(opc::LD_DW_IMM, 0, 0, 0, 0x1234),
                i(0x95, 3, 4, -7, 0x5678),
                exit(),
            ],
            vec![
                i(opc::LD_DW_IMM, 0, 0, 0, i32::MIN),
                i(0, 0, 0, 0, i32::MIN),
                exit(),
            ],
            // Writes r0 before anything else: the earlier value is gone.
            {
                let mut p = vec![mov(0, 99)];
                p.extend(lddw(0, 0xDEAD_BEEF_0000_0001));
                p.push(exit());
                p
            },
        ],
    );
    assert_eq!(r[0], Ok(0xFFFF_FFFF));
    assert_eq!(r[1], Ok(u64::MAX));
    assert_eq!(r[2], Ok(0x0000_5678_0000_1234));
    assert_eq!(r[3], Ok(0x8000_0000_8000_0000));
    assert_eq!(r[4], Ok(0xDEAD_BEEF_0000_0001));
}

#[test]
fn an_lddw_in_the_last_slot_is_a_bad_jump_and_writes_nothing() {
    // The interpreter fetches the high half before writing the register: `BadJump`, with the
    // earlier `r0` intact — which is invisible on a halt, so the stack is written instead and must
    // be the same on both sides.
    let r = parity_bare(
        "lddw_truncated",
        &[
            vec![
                i(opc::ST_DW_IMM, 10, 0, -8, 42),
                i(opc::LD_DW_IMM, 0, 0, 0, 1),
            ],
            vec![i(opc::LD_DW_IMM, 0, 0, 0, 1)],
        ],
    );
    assert_eq!(r[0], Err(Halt::BadJump));
    assert_eq!(r[1], Err(Halt::BadJump));
}

// ---- mixed ----------------------------------------------------------------------------------------

#[test]
fn a_chain_of_every_alu64_register_form_matches() {
    // r1 = 0x0123_4567_89AB_CDEF, r2 = 0xFEDC_BA98_7654_3210; one of each 64-bit register op in
    // turn, feeding the next.
    let mut p = lddw(1, 0x0123_4567_89AB_CDEF).to_vec();
    p.extend(lddw(2, 0xFEDC_BA98_7654_3210));
    for o in [
        opc::ADD64_REG,
        opc::XOR64_REG,
        opc::MUL64_REG,
        opc::OR64_REG,
        opc::SUB64_REG,
        opc::AND64_REG,
        opc::RSH64_REG,
        opc::LSH64_REG,
        opc::ARSH64_REG,
        opc::MOD64_REG,
        opc::DIV64_REG,
    ] {
        p.push(reg(o));
    }
    p.push(i(opc::MOV64_REG, 0, 1, 0, 0));
    p.push(exit());
    let want = {
        let (mut a, b) = (0x0123_4567_89AB_CDEFu64, 0xFEDC_BA98_7654_3210u64);
        a = a.wrapping_add(b);
        a ^= b;
        a = a.wrapping_mul(b);
        a |= b;
        a = a.wrapping_sub(b);
        a &= b;
        a = a.wrapping_shr(b as u32);
        a = a.wrapping_shl(b as u32);
        a = (a as i64).wrapping_shr(b as u32) as u64;
        a %= b;
        a / b
    };
    let r = parity_bare("alu64_chain", &[p]);
    assert_eq!(r[0], Ok(want));
}

#[test]
fn a_chain_of_every_alu32_register_form_matches() {
    let mut p = lddw(1, 0x0123_4567_89AB_CDEF).to_vec();
    p.extend(lddw(2, 0xFEDC_BA98_7654_3213));
    for o in [
        opc::ADD32_REG,
        opc::XOR32_REG,
        opc::MUL32_REG,
        opc::OR32_REG,
        opc::SUB32_REG,
        opc::AND32_REG,
        opc::RSH32_REG,
        opc::LSH32_REG,
        opc::ARSH32_REG,
        opc::MOD32_REG,
        opc::DIV32_REG,
    ] {
        p.push(reg(o));
    }
    p.push(i(opc::MOV64_REG, 0, 1, 0, 0));
    p.push(exit());
    let want = {
        let (mut a, b) = (0x0123_4567_89AB_CDEFu64, 0xFEDC_BA98_7654_3213u64);
        let b32 = b as u32;
        a = (a as i32).wrapping_add(b as i32) as i64 as u64;
        a = u64::from(a as u32 ^ b32);
        a = (a as i32).wrapping_mul(b as i32) as i64 as u64;
        a = u64::from(a as u32 | b32);
        a = (a as i32).wrapping_sub(b as i32) as i64 as u64;
        a = u64::from(a as u32 & b32);
        a = u64::from((a as u32).wrapping_shr(b32));
        a = u64::from((a as u32).wrapping_shl(b32));
        a = u64::from((a as i32).wrapping_shr(b32) as u32);
        a = u64::from(a as u32 % b32);
        u64::from(a as u32 / b32)
    };
    let r = parity_bare("alu32_chain", &[p]);
    assert_eq!(r[0], Ok(want));
}
