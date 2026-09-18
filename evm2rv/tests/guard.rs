//! The code guard (Task 9, `evm2rv::guard`): `contract.c` carries the digest of the bytecode it was
//! translated from, and the shim refuses an input vector with any other code before anything
//! runs — status 2, `gas_used` 0, the interpreter's `pre_halt` (`OutOfBounds`).
//!
//! `tests/parity.rs` checks the ERC-20 (its vectors pass, and a code one byte different is
//! refused); the fuzz corpus checks it on every case. Here: the digest's message and chaining, and
//! the shim's own digest (its chunked `POSEIDON2` calls, `main.rs`'s `is_the_translated_code`)
//! against the host's on codes long enough to need a second call.

mod common;

use common::{build_shim, encoded_halt, root, run};
use evm2rv::emit::Stage;
use evm2rv::guard::{chained_digest, code_digest, code_words, DIGEST_CHUNK};
use evm_core::abi::public_output;
use evm_core::interp::{Halt, Log, Outcome, MAX_LOGS, MAX_RETURN_BYTES};
use evm_core::u256::U256;
use rand_zkvm::evm::{EvmCall, HostRef, SparseTree};
use rand_zkvm::hash::sponge_hash;

/// The message is the length, then the bytes four per word little-endian: `60` and `6000` pack
/// to the same word, so only the length tells them apart.
#[test]
fn the_message_carries_the_length() {
    assert_eq!(code_words(&[0x60]), vec![1, 0x60]);
    assert_eq!(code_words(&[0x60, 0x00]), vec![2, 0x60]);
    assert_eq!(code_words(&[1, 2, 3, 4, 5]), vec![5, 0x0403_0201, 5]);
    assert_eq!(code_words(&[]), vec![0]);
    assert_ne!(code_digest(&[0x60]), code_digest(&[0x60, 0x00]));
}

/// One call up to 4 096 words; past that, each later call hashes the previous digest followed
/// by the next 4 088 words.
#[test]
fn the_digest_chains_past_one_call() {
    let words: Vec<u32> = (0..(2 * DIGEST_CHUNK + 100) as u32)
        .map(|i| i.wrapping_mul(0x9e37_79b9))
        .collect();
    assert_eq!(
        chained_digest(&words[..DIGEST_CHUNK]),
        sponge_hash(&words[..DIGEST_CHUNK])
    );
    let d1 = sponge_hash(&words[..DIGEST_CHUNK]);
    let mut m = d1.to_vec();
    m.push(words[DIGEST_CHUNK]);
    assert_eq!(chained_digest(&words[..DIGEST_CHUNK + 1]), sponge_hash(&m));
    let mut m = d1.to_vec();
    m.extend_from_slice(&words[DIGEST_CHUNK..2 * DIGEST_CHUNK - 8]);
    let d2 = sponge_hash(&m);
    let mut m = d2.to_vec();
    m.extend_from_slice(&words[2 * DIGEST_CHUNK - 8..]);
    assert_eq!(chained_digest(&words), sponge_hash(&m));
}

/// A contract of `len` bytes: it returns `CODESIZE` and the code's last 32 bytes (read with
/// `CODECOPY`, so the run reads the input vector's code), then dead `PUSH32`s up to `len`.
fn long_code(len: usize) -> Vec<u8> {
    let mut c = vec![
        0x38, 0x5f, 0x52, // CODESIZE PUSH0 MSTORE
        0x60, 0x20, 0x60, 0x20, 0x38, 0x03, 0x60, 0x20, 0x39, // CODECOPY(32, CODESIZE-32, 32)
        0x60, 0x40, 0x5f, 0xf3, // RETURN(0, 64)
    ];
    let mut k = 0u8;
    while c.len() < len {
        c.push(0x7f);
        for _ in 0..32 {
            k = k.wrapping_mul(31).wrapping_add(7);
            c.push(k);
        }
    }
    c.truncate(len);
    c
}

fn call_of(code: Vec<u8>) -> EvmCall {
    EvmCall {
        code,
        calldata: vec![],
        address: U256::from_u32(0xc0de),
        caller: U256::from_u32(0xca11),
        callvalue: U256::ZERO,
        gas_limit: 100_000,
        tree: SparseTree::new(),
        touched: vec![],
    }
}

/// Two codes long enough for a second `POSEIDON2` call, through the real pipeline (stage two, the
/// default): 16 381 bytes (the message is 4 097 words, and the last, partial word starts the second
/// call) and 24 575 bytes (6 145 words, one byte under `MAX_CODE_BYTES`). Each runs as the
/// interpreter runs it, so the shim's digest equals the host's; with its last byte changed, it is
/// refused.
#[test]
fn long_codes_pass_the_guard_and_one_changed_byte_is_refused() {
    for len in [4 * (DIGEST_CHUNK - 1) + 1, 24_575] {
        assert!(code_words(&long_code(len)).len() > DIGEST_CHUNK);
        let dir = root().join(format!("evm2rv/target/guard/long-{len}"));
        std::fs::create_dir_all(&dir).unwrap();
        let hex = dir.join("code.bin");
        std::fs::write(&hex, long_code(len)).unwrap();
        let (plain, _) = build_shim(&hex, &dir.join("plain"), "guard-long", false, Stage::Two);
        let (outcome, _) = build_shim(&hex, &dir.join("outcome"), "guard-long", true, Stage::Two);

        let call = call_of(long_code(len));
        let (want, o, _) = call.expected();
        assert_eq!((want[0], o.halt), (1, Halt::Return), "{len}");
        let (got, cycles) = run(&plain, &call.input_words());
        assert_eq!(got, want, "{len} bytes: the eight public words");
        let (dbg, _) = run(&outcome, &call.input_words());
        assert_eq!(dbg[7] as u64, o.gas_used, "{len} bytes: gas_used");
        eprintln!("guard: {len} bytes of code run in {cycles} cycles");

        let mut other = call_of(long_code(len));
        *other.code.last_mut().unwrap() ^= 0x80;
        let (interp, o, _) = other.expected();
        assert_eq!(interp[0], 1, "the interpreter runs the other code");
        assert_eq!(o.halt, Halt::Return);
        let pre = Outcome {
            halt: Halt::OutOfBounds,
            gas_used: 0,
            ret: [0; MAX_RETURN_BYTES],
            ret_len: 0,
            logs: [Log::EMPTY; MAX_LOGS],
            n_logs: 0,
        };
        let r = other.tree.root();
        let want = public_output(&mut HostRef, &other.code, &r, &r, &pre);
        let (got, cycles) = run(&plain, &other.input_words());
        assert_eq!(
            got, want,
            "{len} bytes, last byte changed: the pre_halt output"
        );
        let (dbg, _) = run(&outcome, &other.input_words());
        assert_eq!((dbg[0], dbg[6], dbg[7]), (2, encoded_halt(&pre), 0));
        eprintln!("guard: {len} bytes, last byte changed: refused in {cycles} cycles");
    }
}

/// A code one byte longer than what it was translated from: the source plus a trailing `0x00`
/// (unreached — the fixed prefix already `RETURN`s), through the real pipeline. `code_words`
/// packs bytes four to a word, so a code whose length is not a multiple of four already carries
/// implicit zero padding in its last word; appending a real `0x00` there can leave every packed
/// word bit-identical (`the_message_carries_the_length` above: `code_words(&[0x60])` and
/// `code_words(&[0x60, 0x00])` share their one data word). Only the message's leading length word
/// tells the two codes apart, so this pins that the guard is keyed on it.
#[test]
fn a_trailing_zero_byte_is_refused_by_the_guard() {
    let code = long_code(64);
    let dir = root().join("evm2rv/target/guard/trailing-zero");
    std::fs::create_dir_all(&dir).unwrap();
    let hex = dir.join("code.bin");
    std::fs::write(&hex, &code).unwrap();
    let (plain, _) = build_shim(
        &hex,
        &dir.join("plain"),
        "guard-trailing-zero",
        false,
        Stage::Two,
    );
    let (outcome, _) = build_shim(
        &hex,
        &dir.join("outcome"),
        "guard-trailing-zero",
        true,
        Stage::Two,
    );

    let mut extended = code.clone();
    extended.push(0x00);
    let call = call_of(extended.clone());
    let pre = Outcome {
        halt: Halt::OutOfBounds,
        gas_used: 0,
        ret: [0; MAX_RETURN_BYTES],
        ret_len: 0,
        logs: [Log::EMPTY; MAX_LOGS],
        n_logs: 0,
    };
    let r = call.tree.root();
    let want = public_output(&mut HostRef, &extended, &r, &r, &pre);
    let (got, cycles) = run(&plain, &call.input_words());
    assert_eq!(
        got, want,
        "source code plus a trailing 0x00: the pre_halt output"
    );
    let (dbg, _) = run(&outcome, &call.input_words());
    assert_eq!(
        (dbg[0], dbg[6], dbg[7]),
        (2, encoded_halt(&pre), 0),
        "status 2, OutOfBounds, gas_used 0"
    );
    eprintln!("guard: source plus a trailing 0x00 refused in {cycles} cycles");
}
