//! Directed opcode tests, each a bytecode with its expected (status, gas_used), run through the
//! interpreter and through the translation built for the host (`common/host.rs`) — both must give
//! the pinned pair and the same eight public words.
//!
//! This is where every divergence the differential fuzzer (`tests/fuzz.rs`) finds and fixes lands
//! (Task 6, ruling 6). The Task 6 corpus found none between the translation and the interpreter;
//! the cases below are the opcodes Task 4's review named as covered by string tests only
//! (SIGNEXTEND, SAR, BYTE, SDIV, SMOD, EXP, MSTORE8, CODECOPY, GAS, PC, dynamic bad jumps), at
//! their edges, each now executed and pinned. Most store a result at 0 and `RETURN(0, 32)`
//! (`TAIL`), so the returned word is compared too. Every case runs under both stages (Task 8).
//!
//! Stage two folds these cases' constant operands at translation (the interpreter's own `U256`),
//! so each also runs a second time under stage two with every push laundered ([`launder`]): its
//! u256 edges and dynamic bad jumps then reach `u256.c` and the jump dispatch through stage two's
//! emitter (Task 8 review, Important 1).

mod common;

use common::{host, STAGES};
use evm2rv::emit::{translate, Options, Stage};
use evm_core::abi::{run_call_with, Workspace};
use rand_zkvm::evm::{EvmCall, HostRef, SparseTree};

/// PUSH0, MSTORE, PUSH1 32, PUSH0, RETURN: the top of the stack returned as one word.
const TAIL: &str = "5f5260205ff3";

/// (name, code hex, calldata hex, expected status, expected gas_used (the limit is 100 000),
/// expected return word hex or "" for none)
const CASES: &[(&str, &str, &str, u32, u64, &str)] = &[
    // SIGNEXTEND from byte 30: bit 247 set, so bits 248.. become ones.
    (
        "signextend b=30, negative",
        "7f0080000000000000000000000000000000000000000000000000000000000000601e0b",
        "",
        1,
        24,
        "ff80000000000000000000000000000000000000000000000000000000000000",
    ),
    (
        "signextend b=30, positive clears the top byte",
        "7f7f7f000000000000000000000000000000000000000000000000000000000000601e0b",
        "",
        1,
        24,
        "007f000000000000000000000000000000000000000000000000000000000000",
    ),
    (
        "signextend b=0 of 0xff",
        "60ff5f0b",
        "",
        1,
        23,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ),
    (
        "signextend b=31: unchanged",
        "7fff00000000000000000000000000000000000000000000000000000000001234601f0b",
        "",
        1,
        24,
        "ff00000000000000000000000000000000000000000000000000000000001234",
    ),
    (
        "signextend b=2^255: unchanged",
        "61f234600160ff1b0b",
        "",
        1,
        30,
        "000000000000000000000000000000000000000000000000000000000000f234",
    ),
    // SAR: the sign fills.
    (
        "sar -1 by 255",
        "5f1960ff1d",
        "",
        1,
        24,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ),
    (
        "sar 2^255 by 256",
        "600160ff1b6101001d",
        "",
        1,
        28,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ),
    (
        "sar 2^255 by 254",
        "600160ff1b60fe1d",
        "",
        1,
        28,
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
    ),
    (
        "sar positive by 300",
        "7f7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff61012c1d",
        "",
        1,
        22,
        "0000000000000000000000000000000000000000000000000000000000000000",
    ),
    // BYTE: index 31 is the least significant; 32 and 2^255 are zero.
    (
        "byte 31",
        "61abcd601f1a",
        "",
        1,
        22,
        "00000000000000000000000000000000000000000000000000000000000000cd",
    ),
    (
        "byte 32",
        "61abcd60201a",
        "",
        1,
        22,
        "0000000000000000000000000000000000000000000000000000000000000000",
    ),
    (
        "byte 2^255",
        "61abcd600160ff1b1a",
        "",
        1,
        28,
        "0000000000000000000000000000000000000000000000000000000000000000",
    ),
    // SDIV and SMOD: the signed edges.
    (
        "sdiv MIN / -1",
        "5f19600160ff1b05",
        "",
        1,
        32,
        "8000000000000000000000000000000000000000000000000000000000000000",
    ),
    (
        "sdiv -7 / 2",
        "600260065f190305",
        "",
        1,
        32,
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
    ),
    (
        "smod -7 % 2",
        "600260065f190307",
        "",
        1,
        32,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ),
    (
        "smod 7 % -2",
        "60015f1903600707",
        "",
        1,
        32,
        "0000000000000000000000000000000000000000000000000000000000000001",
    ),
    (
        "smod by 0",
        "5f600707",
        "",
        1,
        23,
        "0000000000000000000000000000000000000000000000000000000000000000",
    ),
    // EXP: 10 + 50 per byte of the exponent.
    (
        "exp 2^255",
        "60ff60020a",
        "",
        1,
        79,
        "8000000000000000000000000000000000000000000000000000000000000000",
    ),
    (
        "exp 3^(2^255): 32 exponent bytes",
        "600160ff1b60030a",
        "",
        1,
        1635,
        "0000000000000000000000000000000000000000000000000000000000000001",
    ),
    (
        "exp 0^0",
        "5f5f0a",
        "",
        1,
        27,
        "0000000000000000000000000000000000000000000000000000000000000001",
    ),
    // MSTORE8 stores the low byte of the value, unsaturated.
    (
        "mstore8 of 2^32 + 0x12",
        "6401000000125f5360205ff3",
        "",
        1,
        16,
        "1200000000000000000000000000000000000000000000000000000000000000",
    ),
    (
        "mstore8 at 65535 then msize",
        "60ab61ffff5359",
        "",
        1,
        14357,
        "0000000000000000000000000000000000000000000000000000000000010000",
    ),
    (
        "mstore8 at 65536: out of bounds",
        "60ab620100005300",
        "",
        2,
        100000,
        "",
    ),
    // CODECOPY: past the end is zero padding; a source past 2^32 reads only padding.
    (
        "codecopy across the end",
        "60206004 5f39 60205ff3",
        "",
        1,
        22,
        "5f3960205ff30000000000000000000000000000000000000000000000000000",
    ),
    (
        "codecopy from 2^32",
        "6020640100000000 5f39 60205ff3",
        "",
        1,
        22,
        "0000000000000000000000000000000000000000000000000000000000000000",
    ),
    // GAS mid-block: what is left after its own 2, the rest of the block not yet spent.
    (
        "gas mid-block: 99 998 after its own 2",
        "5a600160010150",
        "",
        1,
        26,
        "000000000000000000000000000000000000000000000000000000000001869e",
    ),
    (
        "gas after a jump: 3 + 8 + 1 + 2 spent",
        "6003565b5a",
        "",
        1,
        27,
        "0000000000000000000000000000000000000000000000000000000000018692",
    ),
    // PC.
    (
        "pc",
        "5b5b5b58",
        "",
        1,
        18,
        "0000000000000000000000000000000000000000000000000000000000000003",
    ),
    // Dynamic jumps: to a non-jumpdest, to a JUMPDEST byte inside push data, past the code, above
    // 2^32; and a JUMPI not taken to a bogus destination (never checked).
    (
        "dynamic jump to a non-jumpdest",
        "60035f0156",
        "",
        2,
        100000,
        "",
    ),
    (
        "dynamic jump into push data",
        "60025f01566000005b00",
        "",
        2,
        100000,
        "",
    ),
    (
        "dynamic jump past the code",
        "61fff05f0156",
        "",
        2,
        100000,
        "",
    ),
    (
        "dynamic jump above 2^32",
        "6401000000005f0156",
        "",
        2,
        100000,
        "",
    ),
    (
        "jumpi not taken, bogus destination",
        "5f61fff05f0157600a",
        "",
        1,
        36,
        "",
    ),
    (
        "jumpi taken, bogus destination",
        "600161fff05f0157",
        "",
        2,
        100000,
        "",
    ),
];

/// `code` with every push laundered (Task 8 review, Important 1): after each `PUSHn`,
/// `CALLDATASIZE DUP1 XOR XOR` (x ^ (cs ^ cs) = x, as `gen::launder` does), so the word is known
/// only at run time. Stage two folds a directed case's constant operands away at translation; its
/// laundered twin reaches the runtime (`u256.c`, the jump dispatch) through stage two's emitter.
/// A push whose value is a `JUMPDEST`'s pc is moved to that `JUMPDEST`'s new pc, so a valid jump
/// stays valid.
fn launder(code: &[u8]) -> Vec<u8> {
    let jds = evm2rv::blocks::jumpdests(code);
    let mut out = Vec::new();
    let mut new_pc = vec![0usize; code.len() + 1];
    let mut pushes: Vec<(usize, usize, usize)> = Vec::new(); // (new offset of the immediate, n, old pc)
    let mut i = 0;
    while i < code.len() {
        new_pc[i] = out.len();
        let op = code[i];
        out.push(op);
        if (0x5f..=0x7f).contains(&op) {
            let n = (op - 0x5f) as usize;
            pushes.push((out.len(), n, i));
            for k in 0..n {
                out.push(code.get(i + 1 + k).copied().unwrap_or(0));
            }
            out.extend_from_slice(&[0x36, 0x80, 0x18, 0x18]);
            i += 1 + n;
        } else {
            i += 1;
        }
    }
    for (at, n, _) in pushes {
        if n == 0 || n > 8 {
            continue;
        }
        let v = out[at..at + n].iter().fold(0u64, |v, &b| v << 8 | b as u64) as usize;
        if jds.binary_search(&v).is_ok() {
            let t = new_pc[v] as u64;
            if n == 8 || t < 1 << (8 * n) {
                for k in 0..n {
                    out[at + k] = (t >> (8 * (n - 1 - k))) as u8;
                }
            }
        }
    }
    out
}

/// The runtime call a laundered case must reach under stage two, by its name's first word.
fn runtime_call(name: &str) -> Option<&'static str> {
    Some(match name.split_whitespace().next()? {
        "signextend" => "u256_signextend(",
        "sar" => "u256_sar(",
        "byte" => "u256_byte(",
        "sdiv" => "u256_sdiv(",
        "smod" => "u256_smod(",
        "exp" => "evm_exp(",
        "dynamic" | "jumpi" => "goto dispatch;",
        _ => return None,
    })
}

#[test]
fn directed_opcodes_match_the_interpreter_and_their_pins() {
    let codes: Vec<Vec<u8>> = CASES
        .iter()
        .map(|&(_, code, _, status, _, _)| {
            let mut c = hex::decode(code.replace(' ', "")).unwrap();
            // A success returns its top word, a halt does not need the tail.
            if status == 1 && !code.ends_with("f3") {
                c.extend(hex::decode(TAIL).unwrap());
            }
            c
        })
        .collect();
    // Each case at stage one, then at stage two.
    let cs: Vec<String> = STAGES
        .iter()
        .flat_map(|&stage| {
            codes.iter().map(move |c| {
                translate(
                    c,
                    &Options {
                        chain_id: None,
                        stage,
                    },
                )
                .unwrap()
                .c
            })
        })
        .collect();
    // Then every case laundered, at stage two.
    let laundered: Vec<Vec<u8>> = codes.iter().map(|c| launder(c)).collect();
    let mut cs = cs;
    for (c, &(name, ..)) in laundered.iter().zip(CASES) {
        let t = translate(
            c,
            &Options {
                chain_id: None,
                stage: Stage::Two,
            },
        )
        .unwrap()
        .c;
        if let Some(call) = runtime_call(name) {
            assert!(
                t.contains(call),
                "{name}, laundered: stage two does not reach {call}"
            );
        }
        cs.push(t);
    }
    let lib = host::build("opcodes", &cs);
    let mut ws = Box::new(Workspace::ZERO);
    let mut table = String::new();
    for (i, (&(name, _, cd, status, gas, ret), code)) in CASES.iter().zip(&codes).enumerate() {
        let call = EvmCall {
            code: code.clone(),
            calldata: hex::decode(cd).unwrap(),
            address: evm_core::u256::U256::from_u32(0xc0de),
            caller: evm_core::u256::U256::from_u32(0xca11),
            callvalue: evm_core::u256::U256::ZERO,
            gas_limit: 100_000,
            tree: SparseTree::new(),
            touched: vec![],
        };
        let words = call.input_words();
        let (want, o) = run_call_with(
            &mut HostRef,
            &mut ws,
            |k| words[k as usize],
            words.len() as u32,
        );
        let hexret = hex::encode(&o.ret[..o.ret_len]);
        table.push_str(&format!(
            "{name}: status {} gas {} ret {hexret}\n",
            want[0], o.gas_used
        ));
        for (k, stage) in STAGES.iter().enumerate() {
            let (got, t, _) = lib.run_words(&mut HostRef, k * CASES.len() + i, &words);
            assert_eq!(got, want, "{name} ({stage:?}): the eight words");
            assert_eq!(t.gas_used, o.gas_used, "{name} ({stage:?}): gas_used");
        }
        assert_eq!(want[0], status, "{name}: status");
        assert_eq!(o.gas_used, gas, "{name}: gas_used pin");
        if !ret.is_empty() {
            assert_eq!(hexret, ret, "{name}: the returned word");
        }

        // The laundered twin at stage two, against the interpreter over the same laundered code:
        // the same eight words and gas, and the case's own status. The returned word is the pin's
        // too, unless the case returns something laundering moves (code bytes, a pc, the gas).
        let call = EvmCall {
            code: laundered[i].clone(),
            ..call
        };
        let words = call.input_words();
        let (want, o) = run_call_with(
            &mut HostRef,
            &mut ws,
            |k| words[k as usize],
            words.len() as u32,
        );
        let (got, t, _) = lib.run_words(&mut HostRef, 2 * CASES.len() + i, &words);
        assert_eq!(got, want, "{name} (laundered, Two): the eight words");
        assert_eq!(t.gas_used, o.gas_used, "{name} (laundered, Two): gas_used");
        assert_eq!(want[0], status, "{name} (laundered): status");
        let moves = ["codecopy", "gas", "pc"].contains(&name.split_whitespace().next().unwrap());
        if !ret.is_empty() && !moves {
            assert_eq!(
                hex::encode(&o.ret[..o.ret_len]),
                ret,
                "{name} (laundered): the returned word"
            );
        }
    }
    eprintln!("{table}");
}
