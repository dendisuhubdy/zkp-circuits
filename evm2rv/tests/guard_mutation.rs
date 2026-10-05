//! The code guard under mutation (`src/guard.rs`): every single-bit flip, byte replacement,
//! truncation, extension and shift of a code changes its digest; the message packs the length
//! and the bytes as documented; the digest is the same at both stages and whatever the chain id;
//! and, through the host harness, a translated contract refuses every one-byte mutation of its
//! code at every position (status 2, `gas_used` 0, `OutOfBounds`, the `pre_halt` output) while
//! accepting the genuine code under any calldata, caller, value or gas limit — the guard binds the
//! code and nothing else.

mod common;

use std::collections::BTreeSet;

use common::{host, STAGES};
use evm2rv::emit::{translate, Options};
use evm2rv::guard::{chained_digest, code_digest, code_digest_c, code_words, DIGEST_CHUNK};
use evm_core::abi::public_output;
use evm_core::interp::{Halt, Log, Outcome, MAX_LOGS, MAX_RETURN_BYTES};
use evm_core::u256::U256;
use rand_zkvm::evm::{EvmCall, HostRef, SparseTree};
use rand_zkvm::hash::sponge_hash;

/// A 64-byte code with every byte distinct.
fn sixty_four() -> Vec<u8> {
    (0..64u8).map(|i| i.wrapping_mul(0x4f).wrapping_add(0x11)).collect()
}

#[test]
fn every_single_bit_flip_changes_the_digest() {
    let code = sixty_four();
    let d0 = code_digest(&code);
    let mut seen = BTreeSet::new();
    seen.insert(d0);
    for i in 0..code.len() {
        for bit in 0..8 {
            let mut c = code.clone();
            c[i] ^= 1 << bit;
            let d = code_digest(&c);
            assert_ne!(d, d0, "byte {i} bit {bit}");
            assert!(seen.insert(d), "byte {i} bit {bit}: a digest collision");
        }
    }
    assert_eq!(seen.len(), 1 + 64 * 8);
}

#[test]
fn every_byte_value_at_the_ends_and_the_middle_changes_the_digest() {
    let code = sixty_four();
    let d0 = code_digest(&code);
    for i in [0usize, 1, 3, 4, 31, 32, 62, 63] {
        let mut seen = BTreeSet::new();
        for v in 0..=255u8 {
            let mut c = code.clone();
            c[i] = v;
            let d = code_digest(&c);
            if v == code[i] {
                assert_eq!(d, d0);
            } else {
                assert_ne!(d, d0, "byte {i} = {v:#04x}");
            }
            assert!(seen.insert(d), "byte {i} = {v:#04x}: a collision");
        }
        assert_eq!(seen.len(), 256);
    }
}

#[test]
fn truncation_extension_and_shifts_change_the_digest() {
    let code = sixty_four();
    let d0 = code_digest(&code);
    let mut seen = BTreeSet::new();
    seen.insert(d0);
    for n in 1..=64 {
        assert!(seen.insert(code_digest(&code[..64 - n])), "truncated by {n}");
    }
    for n in 1..=8 {
        let mut c = code.clone();
        c.extend(std::iter::repeat_n(0u8, n));
        assert!(seen.insert(code_digest(&c)), "extended by {n} zero bytes");
        let mut c = code.clone();
        c.extend(std::iter::repeat_n(0xffu8, n));
        assert!(seen.insert(code_digest(&c)), "extended by {n} 0xff bytes");
    }
    let mut c = vec![0u8];
    c.extend(&code);
    assert!(seen.insert(code_digest(&c)), "a zero byte prepended");
    let mut c = code.clone();
    c.rotate_left(1);
    assert!(seen.insert(code_digest(&c)), "rotated");
    let mut c = code.clone();
    c.swap(0, 63);
    assert!(seen.insert(code_digest(&c)), "two bytes swapped");
    // The same bytes in another order, where the words differ but not the length.
    let mut c = code.clone();
    c.reverse();
    assert!(seen.insert(code_digest(&c)), "reversed");
    // `60 00` and `60` are the classic pair the length word separates.
    assert_ne!(code_digest(&[0x60]), code_digest(&[0x60, 0x00]));
    assert_ne!(code_digest(&[]), code_digest(&[0x00]));
    assert_ne!(code_digest(&[0x00]), code_digest(&[0x00, 0x00]));
}

#[test]
fn the_message_packs_the_length_then_four_bytes_a_word_little_endian() {
    assert_eq!(code_words(&[]), vec![0]);
    assert_eq!(code_words(&[0xaa]), vec![1, 0xaa]);
    assert_eq!(code_words(&[1, 2]), vec![2, 0x0201]);
    assert_eq!(code_words(&[1, 2, 3]), vec![3, 0x0003_0201]);
    assert_eq!(code_words(&[1, 2, 3, 4]), vec![4, 0x0403_0201]);
    assert_eq!(code_words(&[1, 2, 3, 4, 5]), vec![5, 0x0403_0201, 5]);
    assert_eq!(
        code_words(&[1, 2, 3, 4, 5, 6, 7, 8, 9]),
        vec![9, 0x0403_0201, 0x0807_0605, 9]
    );
    for n in 0..100usize {
        let code: Vec<u8> = (0..n as u8).collect();
        assert_eq!(code_words(&code).len(), 1 + n.div_ceil(4), "{n}");
    }
    // The digest is deterministic and is `chained_digest` of the message.
    let code = sixty_four();
    assert_eq!(code_digest(&code), code_digest(&code));
    assert_eq!(code_digest(&code), chained_digest(&code_words(&code)));
    assert_eq!(code_digest(&[]), sponge_hash(&[0]));
    // One `POSEIDON2` call up to 4 096 words: a 16 380-byte code is exactly 4 096 words.
    let long: Vec<u8> = (0..16_380u32).map(|i| i as u8).collect();
    assert_eq!(code_words(&long).len(), DIGEST_CHUNK);
    assert_eq!(code_digest(&long), sponge_hash(&code_words(&long)));
    // One byte more needs a second call, over the first digest and the one extra word.
    let mut longer = long.clone();
    longer.push(0x5b);
    assert_eq!(code_words(&longer).len(), DIGEST_CHUNK + 1);
    let mut m = sponge_hash(&code_words(&longer)[..DIGEST_CHUNK]).to_vec();
    m.push(0x5b);
    assert_eq!(code_digest(&longer), sponge_hash(&m));
    assert_ne!(code_digest(&longer), sponge_hash(&code_words(&longer)[..DIGEST_CHUNK]));
}

#[test]
fn the_emitted_constant_is_the_digest_at_both_stages_whatever_the_chain_id() {
    let code = sixty_four();
    let d = code_digest(&code);
    let tail = code_digest_c(&d);
    assert!(tail.contains("static const uint32_t d[8] = {"));
    for w in d {
        assert!(tail.contains(&format!("0x{w:08x}u")), "{w:#x}");
    }
    assert!(tail.ends_with("return d;\n}\n"));
    for stage in STAGES {
        for chain_id in [None, Some(1), Some(u64::MAX)] {
            let c = translate(&code, &Options { chain_id, stage }).unwrap().c;
            assert!(c.ends_with(&tail), "{stage:?} {chain_id:?}");
            assert_eq!(c.matches("evm_code_digest").count(), 2, "one declaration, one definition");
        }
    }
    // Different codes, different constants.
    let mut other = code.clone();
    other[10] ^= 0x40;
    let c = translate(&other, &Options::default()).unwrap().c;
    assert!(!c.ends_with(&tail));
    assert!(c.ends_with(&code_digest_c(&code_digest(&other))));
}

/// CODESIZE, PUSH0, MSTORE, PUSH1 32, PUSH0, RETURN: returns its own length (7). Every mutation
/// below keeps the interpreter happy (it runs whatever code it is given) and is refused by the
/// guard.
const SELF_SIZE: [u8; 7] = [0x38, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3];

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

fn pre_halt() -> Outcome {
    Outcome {
        halt: Halt::OutOfBounds,
        gas_used: 0,
        ret: [0; MAX_RETURN_BYTES],
        ret_len: 0,
        logs: [Log::EMPTY; MAX_LOGS],
        n_logs: 0,
    }
}

#[test]
fn a_translated_contract_refuses_every_one_byte_mutation_at_every_position() {
    let cs: Vec<String> = STAGES
        .iter()
        .map(|&stage| {
            translate(
                &SELF_SIZE,
                &Options {
                    chain_id: None,
                    stage,
                },
            )
            .unwrap()
            .c
        })
        .collect();
    let lib = host::build("guard-mutation", &cs);
    // The genuine code runs: status 1, 7 returned.
    for (k, stage) in STAGES.iter().enumerate() {
        let call = call_of(SELF_SIZE.to_vec());
        let (want, o, _) = call.expected();
        assert_eq!((want[0], o.halt), (1, Halt::Return));
        let (got, t, _) = lib.run_words(&mut HostRef, k, &call.input_words());
        assert_eq!(got, want, "{stage:?}: the genuine code");
        assert_eq!(t.ret[..32], U256::from_u32(7).to_be_bytes(), "{stage:?}");
    }
    let mut refused = 0;
    let mut mutations: Vec<(String, Vec<u8>)> = Vec::new();
    for i in 0..SELF_SIZE.len() {
        for (how, f) in [
            ("bit 0", (|b: u8| b ^ 0x01) as fn(u8) -> u8),
            ("bit 7", |b| b ^ 0x80),
            ("0xff", |_| 0xff),
            ("0x00", |_| 0x00),
        ] {
            let mut c = SELF_SIZE.to_vec();
            c[i] = f(c[i]);
            if c == SELF_SIZE {
                continue;
            }
            mutations.push((format!("byte {i} {how}"), c));
        }
    }
    let mut c = SELF_SIZE.to_vec();
    c.push(0x00);
    mutations.push(("a trailing zero byte".into(), c));
    let mut c = SELF_SIZE.to_vec();
    c.push(0x5b);
    mutations.push(("a trailing JUMPDEST".into(), c));
    mutations.push(("the last byte dropped".into(), SELF_SIZE[..6].to_vec()));
    mutations.push(("the first byte dropped".into(), SELF_SIZE[1..].to_vec()));
    let mut c = vec![0x5b];
    c.extend(SELF_SIZE);
    mutations.push(("a leading JUMPDEST".into(), c));
    mutations.push(("empty code".into(), vec![]));
    mutations.push(("the code twice".into(), [SELF_SIZE, SELF_SIZE].concat()));
    for (name, code) in &mutations {
        let call = call_of(code.clone());
        let words = call.input_words();
        let root = call.tree.root();
        let want = public_output(&mut HostRef, code, &root, &root, &pre_halt());
        for (k, stage) in STAGES.iter().enumerate() {
            let (got, t, _) = lib.run_words(&mut HostRef, k, &words);
            assert_eq!(got, want, "{name} ({stage:?}): the pre_halt output");
            assert_eq!(got[0], 2, "{name} ({stage:?}): status");
            assert_eq!(t.gas_used, 0, "{name} ({stage:?}): nothing spent");
            assert_eq!(t.halt, Halt::OutOfBounds, "{name} ({stage:?}): the halt");
            assert_eq!(t.ret_len, 0, "{name} ({stage:?}): no return data");
        }
        refused += 1;
    }
    assert!(refused >= 7 * 3 + 7, "{refused} mutations");
    eprintln!("guard: {refused} mutations of a 7-byte code refused at both stages");
}

/// The guard binds the code only: the same code under other calldata, callers, values and gas
/// limits is accepted, and its result follows the interpreter's.
#[test]
fn the_genuine_code_is_accepted_under_any_other_input() {
    // CALLDATASIZE, CALLVALUE, ADD, CALLER, ADD, then return it: the environment all the way.
    let code = vec![0x36, 0x34, 0x01, 0x33, 0x01, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3];
    let cs: Vec<String> = STAGES
        .iter()
        .map(|&stage| {
            translate(
                &code,
                &Options {
                    chain_id: None,
                    stage,
                },
            )
            .unwrap()
            .c
        })
        .collect();
    let lib = host::build("guard-accept", &cs);
    let inputs: Vec<(Vec<u8>, U256, U256, u64, u32)> = vec![
        (vec![], U256::from_u32(0xca11), U256::ZERO, 100_000, 1),
        (vec![1, 2, 3], U256::from_u32(1), U256::from_u32(5), 100_000, 1),
        (vec![0; 4096], U256::MAX, U256::from_u64(1 << 40), 100_000, 1),
        (vec![7; 100], U256::ZERO, U256::ZERO, 1_000, 1),
        // Out of gas: still the genuine code, so the halt is the interpreter's OutOfGas, not the
        // guard's OutOfBounds.
        (vec![], U256::from_u32(0xca11), U256::ZERO, 10, 2),
        (vec![], U256::from_u32(0xca11), U256::ZERO, 0, 2),
    ];
    for (calldata, caller, callvalue, gas, status) in inputs {
        let call = EvmCall {
            code: code.clone(),
            calldata: calldata.clone(),
            address: U256::from_u32(0xc0de),
            caller,
            callvalue,
            gas_limit: gas,
            tree: SparseTree::new(),
            touched: vec![],
        };
        let (want, o, _) = call.expected();
        assert_eq!(want[0], status, "calldata {} gas {gas}", calldata.len());
        for (k, stage) in STAGES.iter().enumerate() {
            let (got, t, _) = lib.run_words(&mut HostRef, k, &call.input_words());
            assert_eq!(got, want, "{stage:?}: calldata {} gas {gas}", calldata.len());
            assert_eq!(t.gas_used, o.gas_used);
            assert_ne!(t.halt, Halt::OutOfBounds, "{stage:?}: the guard must not fire");
            if status == 1 {
                let sum = U256::from_u32(calldata.len() as u32).add(&callvalue).add(&caller);
                assert_eq!(t.ret[..32], sum.to_be_bytes(), "{stage:?}");
            } else {
                assert_eq!(t.gas_used, gas, "{stage:?}: the limit spent");
            }
        }
    }
}

/// Laundering a code (`common::launder`) changes it, so it changes the digest: the laundered
/// twin of every directed case runs under its own guard constant, never the original's.
#[test]
fn a_laundered_code_has_its_own_digest() {
    let code = sixty_four();
    let l = common::launder(&code);
    assert_ne!(l, code);
    assert_ne!(code_digest(&l), code_digest(&code));
    // No pushes, nothing to launder: the same code, the same digest.
    let plain = [0x5b, 0x01, 0x50, 0x00];
    assert_eq!(common::launder(&plain), plain);
    assert_eq!(code_digest(&common::launder(&plain)), code_digest(&plain));
}
