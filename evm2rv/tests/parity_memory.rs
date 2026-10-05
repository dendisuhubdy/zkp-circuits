//! Directed parity for memory, the data copies, `KECCAK256`, the logs and storage: unaligned
//! `MLOAD`/`MSTORE`/`MSTORE8`, `MSIZE` after each, the 64 KiB memory cap and offsets past `u32`
//! (`OutOfBounds`, status 2), `RETURN`/`REVERT` with and without data and at the 1 024-byte cap,
//! `KECCAK256` of nothing, one word, two words and calldata, `CALLDATALOAD`/`CALLDATACOPY`/
//! `CODECOPY` past their sources (zero-filled) and with zero length at absurd offsets (legal),
//! `RETURNDATASIZE`/`RETURNDATACOPY` in a contract that never calls, `LOG0`–`LOG4` and the log
//! cap, and `SLOAD`/`SSTORE` round trips through every transition (zero → nonzero → zero), with
//! and without a witness. Pins: `(status, gas_used, return data, logs)`; both stages must agree
//! with the interpreter (`common/directed.rs`).
//!
//! Memory expansion costs `3w + w²/512` for `w` words; `TAIL` is 13 gas on fresh memory and 10
//! once the first word exists.

mod common;

use common::directed::{bytes, run_directed, word, Directed, TAIL};
use rand_zkvm::keccak::keccak256;

const KECCAK_EMPTY: &str = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
const KECCAK_ZERO_WORD: &str = "290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563";
const KECCAK_TWO_ZERO_WORDS: &str = "ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5";
const KECCAK_ABC: &str = "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45";

#[test]
fn mload_mstore_mstore8_and_msize() {
    let mut aabb_shifted = vec![0u8; 29];
    aabb_shifted.extend_from_slice(&[0xaa, 0xbb, 0x00]);
    let cases = vec![
        // MSTORE(0, 0xaa), MLOAD(0): 3 + 2 + 3 + 3 (one word) + 2 + 3, TAIL 10.
        Directed::new("mstore then mload at 0", &format!("60aa5f52 5f51{TAIL}"), 1, 26).ret_word(0xaa),
        // MLOAD(1) reads bytes 1..33: the word shifted left a byte; the second word costs 3 more.
        Directed::new("mload at 1 is unaligned", &format!("61aabb5f52 600151{TAIL}"), 1, 30)
            .ret_bytes(aabb_shifted),
        // MSTORE at 1: the word lands in bytes 1..33 (two words, cost 6), and MLOAD(1) reads it
        // back: 3 + 3 + 9, 3 + 3; TAIL 10.
        Directed::new("mstore at 1 then mload at 1", &format!("60aa600152 600151{TAIL}"), 1, 31).ret_word(0xaa),
        // ... while MLOAD(0) sees only its first 31 bytes, all zero.
        Directed::new("mstore at 1 then mload at 0", &format!("60aa600152 5f51{TAIL}"), 1, 30).ret_word(0),
        // MSTORE8(31, 0xab), MLOAD(0): the low byte.
        Directed::new("mstore8 at 31 then mload 0", &format!("60ab601f53 5f51{TAIL}"), 1, 27).ret_word(0xab),
        // MSTORE8(0, 0xab): the high byte.
        Directed::new("mstore8 at 0 then mload 0", &format!("60ab5f53 5f51{TAIL}"), 1, 26)
            .ret_hex(&format!("ab{}", "00".repeat(31))),
        // MSTORE8 of a word: only the low byte lands (0xcd), the rest of the word is zero.
        Directed::new("mstore8 stores the low byte", &format!("61abcd5f53 5f51{TAIL}"), 1, 26)
            .ret_hex(&format!("cd{}", "00".repeat(31))),
        // MSTORE8 at 32 expands to two words (cost 6).
        Directed::new("mstore8 at 32 expands to 64", &format!("60ab602053 59{TAIL}"), 1, 27).ret_word(64),
        Directed::new("msize starts at 0", &format!("59{TAIL}"), 1, 15).ret_word(0),
        // MLOAD(0) alone expands to 32: 2 + 3 + 3, POP, MSIZE.
        Directed::new("msize after mload at 0", &format!("5f5150 59{TAIL}"), 1, 22).ret_word(32),
        // MLOAD(33): bytes 33..65, three words (cost 9).
        Directed::new("msize after mload at 33", &format!("60215150 59{TAIL}"), 1, 29).ret_word(96),
        // MSIZE does not grow from a second read of the same word: 8 + 5 + 2 + 2; TAIL 10.
        Directed::new("msize after two mloads", &format!("5f51505f5150 59{TAIL}"), 1, 29).ret_word(32),
        // The top of memory: MLOAD(65 504) reaches exactly 65 536 = 2 048 words:
        // 3 · 2048 + 2048² / 512 = 14 336.
        Directed::new("mload at the top of memory", &format!("61ffe051{TAIL}"), 1, 14352).ret_word(0),
        Directed::new("mload one byte past the cap", "61ffe151", 2, 100_000),
        Directed::new("mstore at the cap", "60aa6201000052", 2, 100_000),
        Directed::new("mstore8 at the cap", "60ab6201000053", 2, 100_000),
        Directed::new("mstore8 at the last byte", &format!("60ab61ffff53 59{TAIL}"), 1, 14357).ret_word(65536),
        // Offsets past u32: OutOfBounds, status 2.
        Directed::new("mload at 2^32", "64010000000051", 2, 100_000),
        Directed::new("mstore at 2^32 - 1", "60aa63ffffffff52", 2, 100_000),
        Directed::new("mload at MAX", &format!("7f{}51", "ff".repeat(32)), 2, 100_000),
        // Out of gas on the expansion itself, inside the limit's reach of the head: the head
        // charges 6, the expansion 14 336 more than the 100 left.
        Directed::new("mload expansion out of gas", "61ffe051", 2, 100).gas_limit(100),
    ];
    run_directed("memory-ops", &cases);
}

#[test]
fn return_and_revert_data_ranges() {
    let mut zeros_1024 = vec![0u8; 1024];
    zeros_1024[0] = 0;
    let cases = vec![
        // RETURN(huge, 0) is legal: a zero length touches nothing. 2 + 3.
        Directed::new("return of zero length at MAX", &format!("5f7f{}f3", "ff".repeat(32)), 1, 5).ret_hex(""),
        Directed::new("return of zero length at 2^32", "5f640100000000f3", 1, 5).ret_hex(""),
        Directed::new("return (0, 0)", "5f5ff3", 1, 4).ret_hex(""),
        // RETURN(0, 1024): 32 words, 96 + 2 = 98; 3 + 2 + 98.
        Directed::new("return of exactly 1024 bytes", "6104005ff3", 1, 103).ret_bytes(zeros_1024),
        Directed::new("return of 1025 bytes is over the cap", "6104015ff3", 2, 100_000),
        // RETURN(16, 32) after MSTORE(0, x) (11): bytes 16..48, two words (3 more): 3 + 3 + 3.
        Directed::new("return of a misaligned range", "61abcd5f52 6020 6010 f3", 1, 20)
            .ret_hex(&format!("{}abcd{}", "00".repeat(14), "00".repeat(16))),
        // RETURN(65 504, 32): the last word of memory, 14 336 of expansion.
        Directed::new("return of the last word of memory", "602061ffe0f3", 1, 14342).ret_word(0),
        Directed::new("return past the memory cap", "602061ffe1f3", 2, 100_000),
        Directed::new("return of length 2^32", "6401000000005ff3", 2, 100_000),
        // REVERT with data: status 0, the data bound by the digest.
        Directed::new("revert with one word", "60aa5f52 6020 5f fd", 0, 16).ret_word(0xaa),
        Directed::new("revert (0, 0)", "5f5ffd", 0, 4).ret_hex(""),
        Directed::new("revert of zero length at MAX", &format!("5f7f{}fd", "ff".repeat(32)), 0, 5).ret_hex(""),
        Directed::new("revert of 1025 bytes is over the cap", "6104015ffd", 2, 100_000),
        // A revert spends only what ran: nothing after it.
        Directed::new("revert then dead code", "5f5ffd 6001600201", 0, 4).ret_hex(""),
        // Out of gas exactly: PUSH1 1, PUSH1 2, ADD, STOP is 9.
        Directed::new("out of gas by one", "6001600201 00", 2, 8).gas_limit(8),
        Directed::new("exact gas", "6001600201 00", 1, 9).gas_limit(9),
        Directed::new("a return at exactly its gas", "60aa5f52 6020 5f f3", 1, 16).gas_limit(16).ret_word(0xaa),
        Directed::new("a return one short of its gas", "60aa5f52 6020 5f f3", 2, 15).gas_limit(15),
    ];
    run_directed("memory-return", &cases);
}

#[test]
fn keccak256_over_nothing_words_and_calldata() {
    let zeros_64k = vec![0u8; 65536];
    let cases = vec![
        // KECCAK256(0, 0): 2 + 2 + 30.
        Directed::new("keccak of nothing", &format!("5f5f20{TAIL}"), 1, 47).ret_hex(KECCAK_EMPTY),
        // Offset on top, size second: KECCAK256(0, 32): 3 + 2 + 30 + 6 + 3 (expansion); TAIL 10.
        Directed::new("keccak of one zero word", &format!("60205f20{TAIL}"), 1, 54).ret_hex(KECCAK_ZERO_WORD),
        Directed::new("keccak of two zero words", &format!("60405f20{TAIL}"), 1, 63).ret_hex(KECCAK_TWO_ZERO_WORDS),
        // 33 bytes: two words of hashing, two of memory.
        Directed::new("keccak of 33 zero bytes", &format!("60215f20{TAIL}"), 1, 63)
            .ret_bytes(keccak256(&[0u8; 33]).to_vec()),
        // A zero-length hash at an absurd offset is the empty hash and expands nothing.
        Directed::new("keccak of zero length at MAX", &format!("5f7f{}20{TAIL}", "ff".repeat(32)), 1, 48)
            .ret_hex(KECCAK_EMPTY),
        // CALLDATACOPY(0, 0, 3) then KECCAK256(0, 3): 3 + 2 + 2 + (3 + 3 + 3) + 3 + 2 + 36; TAIL 10.
        Directed::new("keccak of 'abc' from calldata", &format!("60035f5f37 60035f20{TAIL}"), 1, 67)
            .calldata("616263")
            .ret_hex(KECCAK_ABC),
        // The word written by MSTORE hashed back: keccak of 0x…aa.
        // MSTORE (11), then 3 + 2 + 36 (no further expansion); TAIL 10.
        Directed::new("keccak of a stored word", &format!("60aa5f52 60205f20{TAIL}"), 1, 62)
            .ret_bytes(keccak256(&word(0xaa)).to_vec()),
        // The whole of memory: 2 048 words of hashing (12 288) + 30, 14 336 of expansion.
        Directed::new("keccak of all 64 KiB", &format!("620100005f20{TAIL}"), 1, 26669)
            .ret_bytes(keccak256(&zeros_64k).to_vec()),
        Directed::new("keccak past the memory cap", "620100015f20", 2, 100_000),
        Directed::new("keccak of length 2^32", "6401000000005f20", 2, 100_000),
        Directed::new("keccak at offset 2^32", "602064010000000020", 2, 100_000),
        // The cost is charged before the expansion: 30 + 6 exceeds a limit of 40 after the head's 5.
        Directed::new("keccak out of gas", "60205f20", 2, 40).gas_limit(40),
    ];
    run_directed("memory-keccak", &cases);
}

#[test]
fn calldata_code_and_return_data_reads_past_their_bounds() {
    let cd = "0102030405";
    let mut padded = bytes(cd);
    padded.resize(32, 0);
    let mut from3 = bytes("0405");
    from3.resize(32, 0);
    let code_copy = format!("60205f5f39 5f51{TAIL}");
    let mut self_bytes = bytes(&code_copy);
    self_bytes.resize(32, 0);
    let cases = vec![
        // CALLDATALOAD at 0 of a 32-byte word: 2 + 3.
        Directed::new("calldataload at 0", &format!("5f35{TAIL}"), 1, 18)
            .calldata_bytes(word(0x1234))
            .ret_word(0x1234),
        // At 30 of a 32-byte word: the last two bytes, then zeros.
        Directed::new("calldataload at 30 straddles the end", &format!("601e35{TAIL}"), 1, 19)
            .calldata_bytes(word(0x1234))
            .ret_hex(&format!("1234{}", "00".repeat(30))),
        Directed::new("calldataload at 32 is zero", &format!("602035{TAIL}"), 1, 19)
            .calldata_bytes(word(0x1234))
            .ret_word(0),
        Directed::new("calldataload at 2^32 is zero", &format!("64010000000035{TAIL}"), 1, 19)
            .calldata_bytes(word(0x1234))
            .ret_word(0),
        Directed::new("calldataload at MAX is zero", &format!("7f{}35{TAIL}", "ff".repeat(32)), 1, 19)
            .calldata_bytes(word(0x1234))
            .ret_word(0),
        Directed::new("calldataload of five bytes", &format!("5f35{TAIL}"), 1, 18)
            .calldata(cd)
            .ret_bytes(padded.clone()),
        Directed::new("calldataload with no calldata", &format!("5f35{TAIL}"), 1, 18).ret_word(0),
        Directed::new("calldatasize of five bytes", &format!("36{TAIL}"), 1, 15).calldata(cd).ret_word(5),
        Directed::new("calldatasize of nothing", &format!("36{TAIL}"), 1, 15).ret_word(0),
        // CALLDATACOPY(0, 0, 32) of five bytes: 3 + 2 + 2 + 3 + 3 (one word) + 3; MLOAD 5; TAIL 10.
        Directed::new("calldatacopy pads with zeros", &format!("60205f5f37 5f51{TAIL}"), 1, 31)
            .calldata(cd)
            .ret_bytes(padded),
        Directed::new("calldatacopy from 3", &format!("6020 6003 5f 37 5f51{TAIL}"), 1, 32)
            .calldata(cd)
            .ret_bytes(from3),
        // Zero length at an absurd destination: nothing expands, nothing is charged for it.
        Directed::new("calldatacopy of zero length at MAX", &format!("5f5f7f{}3700", "ff".repeat(32)), 1, 10)
            .calldata(cd),
        // A source past u32 reads padding only.
        Directed::new("calldatacopy from MAX", &format!("60207f{}5f37 5f51{TAIL}", "ff".repeat(32)), 1, 32)
            .calldata(cd)
            .ret_word(0),
        Directed::new("calldatacopy past the memory cap", "620100015f5f37", 2, 100_000).calldata(cd),
        Directed::new("calldatacopy to 2^32", "60205f64010000000037", 2, 100_000).calldata(cd),
        // CODESIZE of this 7-byte contract.
        Directed::new("codesize", &format!("38{TAIL}"), 1, 15).ret_word(7).ret_moves(),
        // CODECOPY(0, 0, 32) of the contract itself.
        Directed::new("codecopy of the code itself", &code_copy, 1, 31)
            .ret_bytes(self_bytes)
            .ret_moves(),
        Directed::new("codecopy from MAX is zeros", &format!("60207f{}5f39 5f51{TAIL}", "ff".repeat(32)), 1, 32)
            .ret_word(0)
            .ret_moves(),
        Directed::new("codecopy of zero length at MAX", &format!("5f5f7f{}3900", "ff".repeat(32)), 1, 10),
        Directed::new("codecopy past the memory cap", "620100015f5f39", 2, 100_000),
        // No call in the code: the return data is always empty.
        Directed::new("returndatasize without a call", &format!("3d{TAIL}"), 1, 15).ret_word(0),
        // RETURNDATACOPY of zero length is a no-op wherever it points; any other length traps.
        Directed::new("returndatacopy of zero length", "5f5f5f3e00", 1, 9),
        Directed::new("returndatacopy of zero length at MAX", &format!("5f7f{}5f3e00", "ff".repeat(32)), 1, 10),
        Directed::new("returndatacopy of one byte traps", "60015f5f3e00", 2, 100_000),
        Directed::new("returndatacopy of one byte from 2^32 traps", "60016401000000005f3e00", 2, 100_000),
    ];
    run_directed("memory-copies", &cases);
}

#[test]
fn logs_from_log0_to_log4_and_the_cap() {
    let topic = format!("7f{}", "11".repeat(32));
    let cases = vec![
        // LOG0 of nothing: 2 + 2 + 375.
        Directed::new("log0 of nothing", "5f5fa000", 1, 379).logs(1),
        // LOG0 of 32 bytes after an MSTORE: 11 + 3 + 2 + 375 + 256.
        Directed::new("log0 of one word", "60aa5f52 60205fa000", 1, 647).logs(1),
        // LOG1: the topic below the size and offset: 11 + 3 + 3 + 2 + 750 + 256.
        Directed::new("log1 of one word", &format!("60aa5f52 {topic}60205fa100"), 1, 1025).logs(1),
        // LOG2 of nothing: 3 + 3 + 2 + 2 + 375 + 750.
        Directed::new("log2 of nothing", "60026001 5f5fa200", 1, 1135).logs(1),
        Directed::new("log3 of nothing", "600360026001 5f5fa300", 1, 1513).logs(1),
        // LOG4: 12 + 4 + 375 + 1 500.
        Directed::new("log4 of nothing", "6004600360026001 5f5fa400", 1, 1891).logs(1),
        // LOG4 with four full-word topics and 64 bytes of data from a zero memory (expansion 6):
        // 12 + 5 + 375 + 1 500 + 512 + 6.
        Directed::new("log4 of two words", &format!("{topic}{topic}{topic}{topic} 60405fa400"), 1, 2410).logs(1),
        // Zero-length data at an absurd offset: legal, nothing expands.
        Directed::new("log0 of zero length at MAX", &format!("5f7f{}a000", "ff".repeat(32)), 1, 380).logs(1),
        // The data is bound: two LOG0s over different words produce different digests from each
        // other (checked by the interpreter parity), and eight logs fit.
        Directed::new("eight log0s fit", &"5f5fa0".repeat(8), 1, 3032).logs(8),
        Directed::new("nine log0s are over the cap", &"5f5fa0".repeat(9), 2, 100_000),
        Directed::new("log data of length 2^32", "6401000000005fa0", 2, 100_000),
        Directed::new("log data past the memory cap", "620100015fa0", 2, 100_000),
        // Out of gas inside the log's own charge: the head takes 4, 375 is more than the 100 left.
        Directed::new("log0 out of gas", "5f5fa000", 2, 100).gas_limit(100),
        // A log followed by a revert is not kept: the status is 0 and the digest binds no logs.
        Directed::new("a log then a revert", "5f5fa0 5f5ffd", 0, 383).logs(1),
    ];
    run_directed("memory-logs", &cases);
}

#[test]
fn storage_round_trips_with_and_without_witnesses() {
    let cases = vec![
        // SLOAD with no witness for the slot: NoWitness, status 2.
        Directed::new("sload without a witness", "60055400", 2, 100_000),
        Directed::new("sstore without a witness", "602a60055500", 2, 100_000),
        // With a witness of an empty slot: 0, for 3 + 2 100.
        Directed::new("sload of an empty slot", &format!("600554{TAIL}"), 1, 2116).touched(5).ret_word(0),
        Directed::new("sload of a set slot", &format!("600554{TAIL}"), 1, 2116)
            .storage(5, 42)
            .touched(5)
            .ret_word(42),
        // A witness for another slot does not help.
        Directed::new("sload with the wrong witness", "60055400", 2, 100_000).storage(6, 1).touched(6),
        // SSTORE zero → nonzero: 20 000.
        Directed::new("sstore zero to nonzero", "602a60055500", 1, 20006).touched(5),
        // nonzero → zero: a reset, 2 900 (no refunds).
        Directed::new("sstore nonzero to zero", "5f60055500", 1, 2905).storage(5, 42).touched(5),
        Directed::new("sstore nonzero to nonzero", "604360055500", 1, 2906).storage(5, 42).touched(5),
        Directed::new("sstore zero to zero", "5f60055500", 1, 2905).touched(5),
        Directed::new("sstore the same value", "602a60055500", 1, 2906).storage(5, 42).touched(5),
        // Round trip in one call: SSTORE then SLOAD: 20 006 + 3 + 2 100.
        Directed::new("sstore then sload", &format!("602a600555 600554{TAIL}"), 1, 22122)
            .touched(5)
            .ret_word(42),
        // zero → nonzero → zero, then read: 20 006 + 2 905 + 2 103.
        Directed::new("sstore zero to nonzero to zero", &format!("602a600555 5f600555 600554{TAIL}"), 1, 25027)
            .touched(5)
            .ret_word(0),
        // Two slots, two witnesses, each read back: 2 × 20 006 + 2 × 2 103 + 3.
        Directed::new("two slots", &format!("6001600555 6002600655 600554600654 01{TAIL}"), 1, 44234)
            .touched(5)
            .touched(6)
            .ret_word(3),
        // Out of gas on the SSTORE's own charge: the head takes 6, then 20 000 of 20 005.
        Directed::new("sstore out of gas", "602a60055500", 2, 20005).touched(5).gas_limit(20005),
        Directed::new("sstore at exactly its gas", "602a60055500", 1, 20006).touched(5).gas_limit(20006),
        // A store then a revert: the pre-state root is what the digest binds.
        Directed::new("sstore then revert", "602a600555 5f5ffd", 0, 20010).touched(5),
        // A full-word slot (0xcdcd…cd) and a full-word value: the store, then the load: 20 006 +
        // 2 103.
        Directed::new(
            "sstore of a full word at a full-word slot",
            &format!("7f{}7f{}55 7f{}54{TAIL}", "ab".repeat(32), "cd".repeat(32), "cd".repeat(32)),
            1,
            22122,
        )
        .touched_word([0xcdcd_cdcd; 8])
        .ret_hex(&"ab".repeat(32)),
    ];
    run_directed("memory-storage", &cases);
}
