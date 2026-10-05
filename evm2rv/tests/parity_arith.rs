//! Directed parity for the arithmetic, comparison and bitwise opcodes at their edge operands —
//! wrap-around, division by zero, the signed minimum, `EXP` with a zero base or exponent, shifts
//! at and past 256, the sign boundaries of the signed comparisons — each with its `(status,
//! gas_used, returned word)` pinned, run through the interpreter and both stages built for the
//! host, and again under stage two with every push laundered so the edge reaches `u256.c`
//! (`common/directed.rs`).
//!
//! The operand order is the interpreter's: the top of the stack is `a` and the second `b`, and a
//! binary op computes `a op b` (so `0 - 1` is `PUSH1 1, PUSH0, SUB`). `MAX` is the all-ones word,
//! `MIN` is `2^255` (`PUSH1 1, PUSH1 255, SHL`, 9 gas), `-1` is `PUSH0, NOT` (5 gas).

mod common;

use common::directed::{run_directed, Directed, TAIL};

fn max() -> String {
    format!("7f{}", "ff".repeat(32))
}
const MIN: &str = "600160ff1b";
const NEG1: &str = "5f19";
/// `0 - 2`: PUSH1 2, PUSH0, SUB (8 gas).
const NEG2: &str = "60025f03";

fn code(ops: &[&str]) -> String {
    format!("{}{TAIL}", ops.concat())
}

#[test]
fn add_sub_and_mul_wrap_modulo_2_256() {
    let m = max();
    let cases = vec![
        // 1 + MAX = 0: 3 + 3 + 3.
        Directed::new("add 1 + MAX wraps to 0", &code(&["6001", &m, "01"]), 1, 22).ret_word(0),
        // MAX + MAX = MAX - 1.
        Directed::new("add MAX + MAX = MAX - 1", &code(&[&m, "80", "01"]), 1, 22)
            .ret_hex(&format!("{}fe", "ff".repeat(31))),
        Directed::new("add 0 + 0", &code(&["5f5f01"]), 1, 20).ret_word(0),
        // 0 - 1 = MAX: 3 + 2 + 3.
        Directed::new("sub 0 - 1 = MAX", &code(&["6001", "5f", "03"]), 1, 21).ret_hex(&"ff".repeat(32)),
        // MAX - MAX = 0.
        Directed::new("sub MAX - MAX = 0", &code(&[&m, "80", "03"]), 1, 22).ret_word(0),
        // 5 - 7 = -2.
        Directed::new("sub 5 - 7 = -2", &code(&["6007", "6005", "03"]), 1, 22)
            .ret_hex(&format!("{}fe", "ff".repeat(31))),
        // 2 * 2^255 = 0: 3 + 9 + 5.
        Directed::new("mul 2 * MIN wraps to 0", &code(&["6002", MIN, "02"]), 1, 30).ret_word(0),
        // MAX * MAX = 1: 3 + 3 + 5.
        Directed::new("mul MAX * MAX = 1", &code(&[&m, "80", "02"]), 1, 24).ret_word(1),
        // MAX * 0 = 0.
        Directed::new("mul MAX * 0 = 0", &code(&["5f", &m, "02"]), 1, 23).ret_word(0),
        // 2^128 * 2^128 = 0: PUSH17 (0x01 then 16 zero bytes) twice, 3 + 3 + 5.
        Directed::new(
            "mul 2^128 * 2^128 wraps to 0",
            &code(&[&format!("70{}", "01".to_owned() + &"00".repeat(16)), "80", "02"]),
            1,
            24,
        )
        .ret_word(0),
        // (2^128 - 1)^2 = 2^256 - 2^129 + 1: the top half is ffff…fe, the low half …01.
        Directed::new(
            "mul (2^128 - 1)^2",
            &code(&[&format!("6f{}", "ff".repeat(16)), "80", "02"]),
            1,
            24,
        )
        .ret_hex(&format!("{}fe{}01", "ff".repeat(15), "00".repeat(15))),
    ];
    run_directed("arith-wrap", &cases);
}

#[test]
fn division_and_modulo_edges() {
    let m = max();
    let cases = vec![
        // 7 / 0 = 0: 2 + 3 + 5.
        Directed::new("div 7 / 0 = 0", &code(&["5f", "6007", "04"]), 1, 23).ret_word(0),
        Directed::new("div 0 / 0 = 0", &code(&["5f5f04"]), 1, 22).ret_word(0),
        // MAX / 1 = MAX: 3 + 3 + 5.
        Directed::new("div MAX / 1 = MAX", &code(&["6001", &m, "04"]), 1, 24).ret_hex(&"ff".repeat(32)),
        Directed::new("div 7 / 2 = 3", &code(&["6002", "6007", "04"]), 1, 24).ret_word(3),
        Directed::new("div 1 / MAX = 0", &code(&[&m, "6001", "04"]), 1, 24).ret_word(0),
        Directed::new("div MAX / MAX = 1", &code(&[&m, "80", "04"]), 1, 24).ret_word(1),
        // -1 / 0 = 0 (signed): 2 + 5 + 5.
        Directed::new("sdiv -1 / 0 = 0", &code(&["5f", NEG1, "05"]), 1, 25).ret_word(0),
        // -1 / -1 = 1: 5 + 5 + 5.
        Directed::new("sdiv -1 / -1 = 1", &code(&[NEG1, NEG1, "05"]), 1, 28).ret_word(1),
        // MIN / 2 = -2^254: 3 + 9 + 5.
        Directed::new("sdiv MIN / 2 = -2^254", &code(&["6002", MIN, "05"]), 1, 30)
            .ret_hex(&format!("c0{}", "00".repeat(31))),
        // 7 / -2 = -3, truncated toward zero: 8 + 3 + 5.
        Directed::new("sdiv 7 / -2 = -3", &code(&[NEG2, "6007", "05"]), 1, 29)
            .ret_hex(&format!("{}fd", "ff".repeat(31))),
        // -7 / -2 = 3: push -2 (8), push -7 (PUSH1 7, PUSH0, SUB = 8), SDIV (5).
        Directed::new("sdiv -7 / -2 = 3", &code(&[NEG2, "60075f03", "05"]), 1, 34).ret_word(3),
        // MIN / -1 = MIN is in tests/opcodes.rs; MIN / 1 = MIN here: 3 + 9 + 5.
        Directed::new("sdiv MIN / 1 = MIN", &code(&["6001", MIN, "05"]), 1, 30)
            .ret_hex(&format!("80{}", "00".repeat(31))),
        // MAX % 2 = 1: 3 + 3 + 5.
        Directed::new("mod MAX % 2 = 1", &code(&["6002", &m, "06"]), 1, 24).ret_word(1),
        Directed::new("mod 7 % 0 = 0", &code(&["5f", "6007", "06"]), 1, 23).ret_word(0),
        Directed::new("mod 7 % 7 = 0", &code(&["6007", "80", "06"]), 1, 24).ret_word(0),
        Directed::new("mod 7 % 1 = 0", &code(&["6001", "6007", "06"]), 1, 24).ret_word(0),
        // MIN % -1 = 0: 5 + 9 + 5.
        Directed::new("smod MIN % -1 = 0", &code(&[NEG1, MIN, "07"]), 1, 32).ret_word(0),
        // -7 % 3 = -1 (the sign of the dividend): PUSH1 3 (3), -7 (8), SMOD (5).
        Directed::new("smod -7 % 3 = -1", &code(&["6003", "60075f03", "07"]), 1, 29)
            .ret_hex(&"ff".repeat(32)),
        // (MAX + 2) mod MAX = 2: no overflow in the sum. 3 + 3 + 3 + 8.
        Directed::new("addmod (MAX + 2) mod MAX = 2", &code(&[&m, "6002", &m, "08"]), 1, 30).ret_word(2),
        // (MAX + MAX) mod (MAX - 1)... keep it checkable: (MAX + MAX) mod 10 = (2 * MAX) mod 10;
        // MAX ≡ 5 mod 10 (2^256 ≡ 6 mod 10, minus one), so 2 * 5 mod 10 = 0.
        Directed::new("addmod (MAX + MAX) mod 10 = 0", &code(&["600a", &m, "80", "08"]), 1, 30).ret_word(0),
        // N = 0 is 0: 2 + 3 + 3 + 8.
        Directed::new("addmod with N = 0 is 0", &code(&["5f", "6001", "6002", "08"]), 1, 29).ret_word(0),
        Directed::new("addmod (3 + 4) mod 5 = 2", &code(&["6005", "6004", "6003", "08"]), 1, 30).ret_word(2),
        // (MAX * MAX) mod 12: MAX ≡ 3 mod 12, so 9. 3 + 3 + 3 + 8.
        Directed::new("mulmod (MAX * MAX) mod 12 = 9", &code(&["600c", &m, "80", "09"]), 1, 30).ret_word(9),
        Directed::new("mulmod with N = 0 is 0", &code(&["5f", "6003", "6004", "09"]), 1, 29).ret_word(0),
        // (MAX * MAX) mod MAX = 0.
        Directed::new("mulmod (MAX * MAX) mod MAX = 0", &code(&[&m, "80", "80", "09"]), 1, 30).ret_word(0),
        Directed::new("mulmod (3 * 4) mod 5 = 2", &code(&["6005", "6004", "6003", "09"]), 1, 30).ret_word(2),
    ];
    run_directed("arith-div", &cases);
}

#[test]
fn exp_and_signextend_edges() {
    let m = max();
    let cases = vec![
        // EXP pops the base (top) then the exponent: 10 + 50 per exponent byte.
        // 0^5 = 0: 3 + 2 + 60.
        Directed::new("exp 0^5 = 0", &code(&["6005", "5f", "0a"]), 1, 78).ret_word(0),
        // 5^0 = 1: the exponent has no bytes: 2 + 3 + 10.
        Directed::new("exp 5^0 = 1", &code(&["5f", "6005", "0a"]), 1, 28).ret_word(1),
        // 0^0 = 1 is in tests/opcodes.rs. 2^256 = 0: the exponent 0x0100 has two bytes.
        Directed::new("exp 2^256 wraps to 0", &code(&["610100", "6002", "0a"]), 1, 129).ret_word(0),
        Directed::new("exp 2^255 = MIN", &code(&["60ff", "6002", "0a"]), 1, 79)
            .ret_hex(&format!("80{}", "00".repeat(31))),
        Directed::new("exp 3^2 = 9", &code(&["6002", "6003", "0a"]), 1, 79).ret_word(9),
        // 1^MAX: 32 exponent bytes, 10 + 1 600.
        Directed::new("exp 1^MAX = 1", &code(&[&m, "6001", "0a"]), 1, 1629).ret_word(1),
        // (-1)^2 = 1.
        Directed::new("exp MAX^2 = 1", &code(&["6002", &m, "0a"]), 1, 79).ret_word(1),
        // (-1)^3 = -1.
        Directed::new("exp MAX^3 = MAX", &code(&["6003", &m, "0a"]), 1, 79).ret_hex(&"ff".repeat(32)),
        // 10^18: the exponent 18 is one byte.
        Directed::new("exp 10^18", &code(&["6012", "600a", "0a"]), 1, 79).ret_word(1_000_000_000_000_000_000),
        // SIGNEXTEND pops b (top) then x. b = 32 leaves the word unchanged: 3 + 3 + 5.
        Directed::new(
            "signextend b=32 unchanged",
            &code(&[&format!("7f80{}01", "00".repeat(30)), "6020", "0b"]),
            1,
            24,
        )
        .ret_hex(&format!("80{}01", "00".repeat(30))),
        Directed::new("signextend b=MAX unchanged", &code(&["617fff", &m, "0b"]), 1, 24).ret_word(0x7fff),
        // b = 1 of 0x8000: bit 15 set, so bits 16.. become ones.
        Directed::new("signextend b=1 of 0x8000", &code(&["618000", "6001", "0b"]), 1, 24)
            .ret_hex(&format!("{}8000", "ff".repeat(30))),
        Directed::new("signextend b=1 of 0x7fff", &code(&["617fff", "6001", "0b"]), 1, 24).ret_word(0x7fff),
        // b = 1 of 0x17fff: bit 15 of the low two bytes is clear, so the byte above is cleared.
        Directed::new("signextend b=1 clears above byte 1", &code(&["62017fff", "6001", "0b"]), 1, 24)
            .ret_word(0x7fff),
        Directed::new("signextend b=0 of 0x7f", &code(&["607f", "5f", "0b"]), 1, 23).ret_word(0x7f),
        Directed::new("signextend b=0 of 0x180", &code(&["610180", "5f", "0b"]), 1, 23)
            .ret_hex(&format!("{}80", "ff".repeat(31))),
    ];
    run_directed("arith-exp", &cases);
}

#[test]
fn comparisons_at_the_sign_boundaries() {
    let m = max();
    let cases = vec![
        // LT: a < b with a the top. 0 < MAX: 3 + 2 + 3.
        Directed::new("lt 0 < MAX", &code(&[&m, "5f", "10"]), 1, 21).ret_word(1),
        Directed::new("lt MAX < 0", &code(&["5f", &m, "10"]), 1, 21).ret_word(0),
        Directed::new("lt 5 < 5", &code(&["6005", "6005", "10"]), 1, 22).ret_word(0),
        Directed::new("gt MAX > 0", &code(&["5f", &m, "11"]), 1, 21).ret_word(1),
        Directed::new("gt 0 > MAX", &code(&[&m, "5f", "11"]), 1, 21).ret_word(0),
        Directed::new("gt 5 > 5", &code(&["6005", "6005", "11"]), 1, 22).ret_word(0),
        // Signed: MIN < MAX (-2^255 < -1): 3 + 9 + 3.
        Directed::new("slt MIN < MAX", &code(&[&m, MIN, "12"]), 1, 28).ret_word(1),
        Directed::new("sgt MIN > MAX", &code(&[&m, MIN, "13"]), 1, 28).ret_word(0),
        // -1 < 0 signed, but not unsigned: 2 + 5 + 3.
        Directed::new("slt -1 < 0", &code(&["5f", NEG1, "12"]), 1, 23).ret_word(1),
        Directed::new("lt -1 < 0 (unsigned: MAX < 0)", &code(&["5f", NEG1, "10"]), 1, 23).ret_word(0),
        // 0 > -1 signed; 0 > MAX unsigned is false: 5 + 2 + 3.
        Directed::new("sgt 0 > -1", &code(&[NEG1, "5f", "13"]), 1, 23).ret_word(1),
        Directed::new("gt 0 > -1 (unsigned)", &code(&[NEG1, "5f", "11"]), 1, 23).ret_word(0),
        // MIN < 0 signed, MIN > 0 unsigned: 2 + 9 + 3.
        Directed::new("slt MIN < 0", &code(&["5f", MIN, "12"]), 1, 27).ret_word(1),
        Directed::new("lt MIN < 0 (unsigned)", &code(&["5f", MIN, "10"]), 1, 27).ret_word(0),
        // MIN < MIN - 1? MIN - 1 = 0x7fff…ff (the signed maximum): MIN < it, signed.
        // MIN - 1 is MIN, PUSH1 1, SWAP1, SUB (18 gas): 9 + 18 + 9 + 3 and 9 + 9 + 18 + 3.
        Directed::new("slt MIN < MIN - 1", &code(&[MIN, "6001", "90", "03", MIN, "12"]), 1, 43).ret_word(1),
        Directed::new("sgt MIN - 1 > MIN", &code(&[MIN, MIN, "6001", "90", "03", "13"]), 1, 43).ret_word(1),
        Directed::new("slt -1 < -2", &code(&[NEG2, NEG1, "12"]), 1, 29).ret_word(0),
        Directed::new("sgt -1 > -2", &code(&[NEG2, NEG1, "13"]), 1, 29).ret_word(1),
        // EQ and ISZERO.
        Directed::new("eq MAX == MAX", &code(&[&m, "80", "14"]), 1, 22).ret_word(1),
        Directed::new("eq 0 == 1", &code(&["6001", "5f", "14"]), 1, 21).ret_word(0),
        Directed::new("eq MIN == MIN - 1", &code(&[MIN, MIN, "6001", "90", "03", "14"]), 1, 43).ret_word(0),
        Directed::new("iszero 0", &code(&["5f", "15"]), 1, 18).ret_word(1),
        Directed::new("iszero MAX", &code(&[&m, "15"]), 1, 19).ret_word(0),
        Directed::new("iszero MIN", &code(&[MIN, "15"]), 1, 25).ret_word(0),
        // A nonzero only in a middle limb: PUSH20 1 then 19 zero bytes.
        Directed::new(
            "iszero 2^152",
            &code(&[&format!("73{}", "01".to_owned() + &"00".repeat(19)), "15"]),
            1,
            19,
        )
        .ret_word(0),
        Directed::new("iszero of iszero 7", &code(&["6007", "15", "15"]), 1, 22).ret_word(1),
    ];
    run_directed("arith-cmp", &cases);
}

#[test]
fn bitwise_ops_and_shifts_at_and_past_256() {
    let m = max();
    let cases = vec![
        // AND/OR/XOR/NOT: 3 + 3 + 3.
        Directed::new("and MAX & 0xf0", &code(&["60f0", &m, "16"]), 1, 22).ret_word(0xf0),
        Directed::new("and MIN & MAX", &code(&[&m, MIN, "16"]), 1, 28).ret_hex(&format!("80{}", "00".repeat(31))),
        Directed::new("or MAX | 0", &code(&["5f", &m, "17"]), 1, 21).ret_hex(&"ff".repeat(32)),
        Directed::new("or MIN | 1", &code(&["6001", MIN, "17"]), 1, 28).ret_hex(&format!("80{}01", "00".repeat(30))),
        Directed::new("xor MAX ^ MAX", &code(&[&m, "80", "18"]), 1, 22).ret_word(0),
        Directed::new("xor MAX ^ 0xff", &code(&["60ff", &m, "18"]), 1, 22).ret_hex(&format!("{}00", "ff".repeat(31))),
        Directed::new("not 0", &code(&["5f", "19"]), 1, 18).ret_hex(&"ff".repeat(32)),
        Directed::new("not MAX", &code(&[&m, "19"]), 1, 19).ret_word(0),
        Directed::new("not MIN", &code(&[MIN, "19"]), 1, 25).ret_hex(&format!("7f{}", "ff".repeat(31))),
        // BYTE pops the index (top) then the word; index 0 is the most significant byte.
        Directed::new("byte 0 of MIN", &code(&[MIN, "5f", "1a"]), 1, 27).ret_word(0x80),
        Directed::new("byte 31 of MAX", &code(&[&m, "601f", "1a"]), 1, 22).ret_word(0xff),
        Directed::new("byte 30 of 0xabcd", &code(&["61abcd", "601e", "1a"]), 1, 22).ret_word(0xab),
        Directed::new("byte 255 is 0", &code(&[&m, "60ff", "1a"]), 1, 22).ret_word(0),
        // The shifts pop the shift (top) then the value.
        Directed::new("shl 1 by 255 = MIN", &code(&["6001", "60ff", "1b"]), 1, 22)
            .ret_hex(&format!("80{}", "00".repeat(31))),
        Directed::new("shl 1 by 256 = 0", &code(&["6001", "610100", "1b"]), 1, 22).ret_word(0),
        Directed::new("shl 1 by 257 = 0", &code(&["6001", "610101", "1b"]), 1, 22).ret_word(0),
        Directed::new("shl MAX by 1", &code(&[&m, "6001", "1b"]), 1, 22).ret_hex(&format!("{}fe", "ff".repeat(31))),
        Directed::new("shl by 0", &code(&["61abcd", "5f", "1b"]), 1, 21).ret_word(0xabcd),
        // Shifts by a word with a nonzero high limb: 3 + 9 + 3.
        Directed::new("shl 1 by MIN = 0", &code(&["6001", MIN, "1b"]), 1, 28).ret_word(0),
        Directed::new("shl by 2^32 = 0", &code(&["6001", "640100000000", "1b"]), 1, 22).ret_word(0),
        Directed::new("shr MAX by 255 = 1", &code(&[&m, "60ff", "1c"]), 1, 22).ret_word(1),
        Directed::new("shr MAX by 256 = 0", &code(&[&m, "610100", "1c"]), 1, 22).ret_word(0),
        Directed::new("shr MAX by MAX = 0", &code(&[&m, "80", "1c"]), 1, 22).ret_word(0),
        Directed::new("shr by 0", &code(&["61abcd", "5f", "1c"]), 1, 21).ret_word(0xabcd),
        Directed::new("shr MIN by 255 = 1", &code(&[MIN, "60ff", "1c"]), 1, 28).ret_word(1),
        Directed::new("shr 0xabcd by 8", &code(&["61abcd", "6008", "1c"]), 1, 22).ret_word(0xab),
        // SAR: the sign fills (tests/opcodes.rs has -1 by 255, MIN by 256 and 254, positive by 300).
        Directed::new("sar -1 by 0", &code(&[&m, "5f", "1d"]), 1, 21).ret_hex(&"ff".repeat(32)),
        Directed::new("sar positive by 0", &code(&["61abcd", "5f", "1d"]), 1, 21).ret_word(0xabcd),
        // -256 >> 8 = -1: push -256 (PUSH2 0x100, PUSH0, SUB: 8), PUSH1 8, SAR.
        Directed::new("sar -256 by 8 = -1", &code(&["6101005f03", "6008", "1d"]), 1, 27).ret_hex(&"ff".repeat(32)),
        Directed::new("sar MIN by 1", &code(&[MIN, "6001", "1d"]), 1, 28).ret_hex(&format!("c0{}", "00".repeat(31))),
        Directed::new("sar MIN by 255 = -1", &code(&[MIN, "60ff", "1d"]), 1, 28).ret_hex(&"ff".repeat(32)),
        Directed::new("sar positive by 256 = 0", &code(&["61abcd", "610100", "1d"]), 1, 22).ret_word(0),
        Directed::new("sar -1 by MIN = -1", &code(&[NEG1, MIN, "1d"]), 1, 30).ret_hex(&"ff".repeat(32)),
        Directed::new("sar 0xabcd by 8", &code(&["61abcd", "6008", "1d"]), 1, 22).ret_word(0xab),
    ];
    run_directed("arith-bits", &cases);
}
