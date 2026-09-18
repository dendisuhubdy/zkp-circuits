//! Task 8: stage two's analysis — register lifting per block (`src/lift.rs`, the spec's §4).
//!
//! The text tests pin what the analysis emits: straight-line arithmetic touches no stack array,
//! a block's live values are spilled to the array exactly at its exit (a `JUMPI` spills before it
//! branches, so both successors see the same stack), an entry slot the block leaves in place is
//! never rewritten, and `DUP`/`SWAP` of entry slots move nothing until the exit, where a
//! permutation is resolved through one temporary.
//!
//! The directed runs are the lifting hazards, each a hand-assembled contract run through the
//! interpreter and through both stages built for the host (`common/host.rs`); the three must agree
//! on the eight public words and `gas_used`. A contract that calls a precompile has no interpreter
//! oracle (it traps on every call), so there stage two is held to stage one.
//!
//! The frame test bounds the C stack: no block holds more than `MAX_LOCALS` lifted words, and
//! `evm_entry`'s frame, measured by clang's `-fstack-usage` for rv32im with the shim's flags,
//! stays under 4 KiB for the ERC-20 and for the corpus's heaviest contracts.

mod common;

use std::path::PathBuf;
use std::process::Command;

use common::{host, root};
use evm2rv::emit::{translate, Options, Stage};
use evm2rv::lift::MAX_LOCALS;
use evm2rv::shim::C_FLAGS;
use evm_core::abi::{run_call_with, Workspace};
use rand_zkvm::evm::{EvmCall, HostRef, SparseTree};

fn opts(stage: Stage) -> Options {
    Options {
        chain_id: None,
        stage,
    }
}

fn two(code: &[u8]) -> String {
    translate(code, &opts(Stage::Two)).unwrap().c
}

/// The emitted line of the op at `pc`.
fn line_of(c: &str, pc: usize) -> &str {
    let tag = format!("/* {pc:#06x} ");
    c.lines()
        .find(|l| l.trim_start().starts_with(&tag))
        .unwrap_or_else(|| panic!("no line for pc {pc:#06x}:\n{c}"))
}

/// Every way the C can reach the memory stack: the array, the block's base pointer into it, and
/// the depth moving.
fn touches_the_array(c: &str) -> bool {
    [
        "evm_stack",
        "sp_",
        "evm_sp +=",
        "evm_sp -=",
        "evm_sp++",
        "evm_sp--",
    ]
    .iter()
    .any(|s| c.contains(s))
}

// ---- the analysis, on the emitted text -------------------------------------------------------

/// The brief's case: `PUSH1 1 PUSH1 2 ADD PUSH1 3 MUL STOP` emits no array access (stage one does:
/// every push, and each operation's operands and result). The head's checks and charge stay.
#[test]
fn straight_line_arithmetic_never_touches_the_array() {
    let code = [0x60, 1, 0x60, 2, 0x01, 0x60, 3, 0x02, 0x00];
    let c = two(&code);
    assert!(!touches_the_array(&c), "{c}");
    assert!(
        c.contains("if (evm_sp + 2u > STACK_LIMIT) { evm_halt(EVM_HALT_STACK_OVERFLOW, 0); }"),
        "{c}"
    );
    assert!(c.contains("evm_charge(17);"), "{c}");
    let one = translate(&code, &opts(Stage::One)).unwrap().c;
    assert!(touches_the_array(&one), "{one}");

    // The same shape over runtime values: CALLDATASIZE twice, ADD, CALLDATASIZE, MUL, then
    // MSTORE(0, ·) and RETURN(0, 32). The words live in locals; still no array access.
    let code = [
        0x36, 0x36, 0x01, 0x36, 0x02, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3,
    ];
    let e = translate(&code, &opts(Stage::Two)).unwrap();
    assert!(!touches_the_array(&e.c), "{}", e.c);
    assert!(e.locals >= 2, "{}", e.c);
    assert!(line_of(&e.c, 2).contains("u256_add(&r"), "{}", e.c);
}

/// A block ending in `JUMPI` spills its live values before it branches, so the taken and the
/// fall-through successor both find the stack in the array, at the right depth. An entry slot
/// the block leaves where it was is not rewritten.
///
/// 0 CALLDATASIZE | 1 JUMPDEST, CALLDATASIZE, PUSH1 1, PUSH1 9, JUMPI | 8 STOP | 9 JUMPDEST, STOP
#[test]
fn a_block_ending_in_jumpi_spills_its_live_slots() {
    let code = [
        0x36, 0x5b, 0x36, 0x60, 0x01, 0x60, 0x09, 0x57, 0x00, 0x5b, 0x00,
    ];
    let c = two(&code);
    // The first block falls through into a jumpdest: its one value is spilled at the exit.
    let first = c.find("/* [0x0001,").expect(&c);
    let fall = &c[..first];
    assert!(fall.contains("sp_[0] = r"), "{c}");
    assert!(fall.contains("evm_sp += 1;"), "{c}");

    // The JUMPI's block: CALLDATASIZE is computed into a local, not the array ...
    assert!(!line_of(&c, 2).contains("sp_["), "{c}");
    // ... and spilled, with the depth, before the branch — and the entry slot below it, which the
    // block never moved, is left alone.
    let j = line_of(&c, 7);
    let spill = j.find("sp_[0] = r").expect(j);
    let depth = j.find("evm_sp += 1;").expect(j);
    let branch = j.find("goto L_9;").expect(j);
    assert!(spill < branch && depth < branch, "{j}");
    assert!(!j.contains("sp_[-1] ="), "{j}");
}

/// `DUPn` and `SWAPn` of entry slots only rename: their lines carry no code. At the exit, the
/// 3-cycle `SWAP2 SWAP1` leaves is written back through one temporary.
///
/// 0 CALLDATASIZE ×3 | 3 JUMPDEST, SWAP2, SWAP1 | 6 JUMPDEST, STOP
#[test]
fn swaps_of_entry_slots_move_nothing_until_the_exit() {
    let code = [0x36, 0x36, 0x36, 0x5b, 0x91, 0x90, 0x5b, 0x00];
    let c = two(&code);
    for pc in [4, 5] {
        let l = line_of(&c, pc);
        assert!(l.trim_end().ends_with("*/"), "no code for a swap: {l}");
    }
    let b = &c[c.find("/* [0x0003,").expect(&c)..c.find("/* [0x0006,").expect(&c)];
    assert!(b.contains("t_ = sp_["), "{b}");
    assert_eq!(
        b.matches("sp_[").count(),
        6,
        "one save, two copies, one restore: {b}"
    );

    // A DUP of an entry slot is a rename too: 0 CALLDATASIZE | 1 JUMPDEST, DUP1, DUP1, STOP.
    let c = two(&[0x36, 0x5b, 0x80, 0x80, 0x00]);
    for pc in [2, 3] {
        let l = line_of(&c, pc);
        assert!(l.trim_end().ends_with("*/"), "no code for a dup: {l}");
    }
}

// ---- the hazards, run ------------------------------------------------------------------------

/// Hand-assembled contracts, each with the calldata it runs on.
struct Case {
    name: &'static str,
    code: Vec<u8>,
    calldata: Vec<u8>,
    /// No interpreter oracle (a call reaches a precompile): stage two is held to stage one.
    calls: bool,
}

fn word(v: u64) -> Vec<u8> {
    let mut w = vec![0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

/// More live words than the cap in one block: 120 × (CALLDATASIZE, PUSH1 i, ADD), then 119 ×
/// ADD, and the sum returned.
fn over_the_cap() -> Vec<u8> {
    let mut big = Vec::new();
    for i in 0..120u8 {
        big.extend([0x36, 0x60, i, 0x01]);
    }
    big.extend(std::iter::repeat_n(0x01, 119));
    big.extend([0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]);
    big
}

fn cases() -> Vec<Case> {
    let mut v = Vec::new();
    let three = [word(0xa1), word(0xb2), word(0xc3)].concat();

    // A 3-cycle of entry slots across a fall-through: [a, b, c] -> SWAP2, SWAP1 -> [c, a, b].
    v.push(Case {
        name: "rotation",
        code: [
            &[0x5f, 0x35, 0x60, 0x20, 0x35, 0x60, 0x40, 0x35][..], // a, b, c
            &[0x5b, 0x91, 0x90],                                   // 8: SWAP2, SWAP1
            &[0x5b, 0x5f, 0x52, 0x60, 0x20, 0x52, 0x60, 0x40, 0x52], // 11: store b, a, c
            &[0x60, 0x60, 0x5f, 0xf3],
        ]
        .concat(),
        calldata: three.clone(),
        calls: false,
    });

    // A DUP of an entry slot, which the exit then overwrites: [a, b] -> DUP2, CALLDATASIZE,
    // SWAP3 -> [cs, b, a, a]; the copies of `a` must be read before its slot is written.
    v.push(Case {
        name: "dup then overwrite",
        code: [
            &[0x5f, 0x35, 0x60, 0x20, 0x35][..],
            &[0x5b, 0x81, 0x36, 0x92],
            &[
                0x5b, 0x5f, 0x52, 0x60, 0x20, 0x52, 0x60, 0x40, 0x52, 0x60, 0x60, 0x52,
            ],
            &[0x60, 0x80, 0x5f, 0xf3],
        ]
        .concat(),
        calldata: three.clone(),
        calls: false,
    });

    // JUMPI whose destination is an entry slot the exit overwrites: [dest] -> CALLDATASIZE,
    // SWAP1, PUSH1 1, SWAP1, JUMPI. The destination must be read before the spill.
    v.push(Case {
        name: "jumpi destination in a spilled slot",
        code: [
            &[0x5f, 0x35][..],
            &[0x5b, 0x36, 0x90, 0x60, 0x01, 0x90, 0x57, 0x00], // 2
            &[0x5b, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3],       // 10
        ]
        .concat(),
        calldata: word(10),
        calls: false,
    });

    // The same for JUMP: [dest] -> CALLDATASIZE, SWAP1, JUMP.
    v.push(Case {
        name: "jump destination in a spilled slot",
        code: [
            &[0x5f, 0x35][..],
            &[0x5b, 0x36, 0x90, 0x56, 0x00],             // 2
            &[0x5b, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3], // 7
        ]
        .concat(),
        calldata: word(7),
        calls: false,
    });

    // LOG3 over an entry slot, a local and a constant: [e] -> CALLDATASIZE, PUSH32 k, PUSH1 32,
    // PUSH0, LOG3 (after an MSTORE, so the data is not all zero).
    let mut log = vec![0x5f, 0x35, 0x5b, 0x60, 0x77, 0x5f, 0x52, 0x36, 0x7f];
    log.extend((1..=32).collect::<Vec<u8>>());
    log.extend([0x60, 0x20, 0x5f, 0xa3, 0x00]);
    v.push(Case {
        name: "log over mixed topics",
        code: log,
        calldata: word(0xdead_beef),
        calls: false,
    });

    v.push(Case {
        name: "over the cap",
        code: over_the_cap(),
        calldata: word(5),
        calls: false,
    });

    // DUP16 and SWAP16 across a mix: 16 distinct locals, then a block that reaches the bottom one
    // (DUP16), trades it with the top (SWAP16), adds, SWAP1, SWAP15, adds twice, and returns two
    // words.
    let mut deep = Vec::new();
    for i in 0..16u8 {
        deep.extend([0x36, 0x60, i * 7 + 1, 0x02]); // CALLDATASIZE * (7i + 1)
    }
    deep.extend([0x5b, 0x8f, 0x9f, 0x01, 0x90, 0x9e, 0x01, 0x01]);
    deep.extend([0x5b, 0x5f, 0x52, 0x60, 0x20, 0x52, 0x60, 0x40, 0x5f, 0xf3]);
    v.push(Case {
        name: "dup16 and swap16",
        code: deep,
        calldata: word(3),
        calls: false,
    });

    // GAS and MSIZE are snapshots at their point in the block, runtime calls in between.
    v.push(Case {
        name: "gas and msize snapshots",
        code: vec![
            0x59, 0x60, 0x40, 0x51, 0x50, 0x59, 0x5a, 0x60, 0x80, 0x52, 0x60, 0xa0, 0x52, 0x60,
            0xc0, 0x52, 0x60, 0xe0, 0x60, 0x80, 0xf3,
        ],
        calldata: vec![],
        calls: false,
    });

    // A STATICCALL to identity in a lifted block, a local live across it: MSTORE(0, k);
    // CALLDATASIZE; STATICCALL(GAS, 4, 0, 32, 32, 32); ADD; MSTORE(64, ·); RETURN(0, 96).
    let mut call = vec![0x7f];
    call.extend((101..=132).collect::<Vec<u8>>());
    call.extend([0x5f, 0x52, 0x36]);
    call.extend([
        0x60, 0x20, 0x60, 0x20, 0x60, 0x20, 0x5f, 0x60, 0x04, 0x5a, 0xfa,
    ]);
    call.extend([0x01, 0x60, 0x40, 0x52, 0x60, 0x60, 0x5f, 0xf3]);
    v.push(Case {
        name: "a precompile call with a local live across it",
        code: call,
        calldata: word(9),
        calls: true,
    });
    v
}

/// Every hazard through the interpreter and both stages: the same eight words and `gas_used`
/// (stage two against stage one where the interpreter traps on the call), and each is a success,
/// so the returned data is compared through the digest.
#[test]
fn the_lifting_hazards_match_the_interpreter_and_stage_one() {
    let cases = cases();
    let mut cs = Vec::new();
    for c in &cases {
        for stage in [Stage::One, Stage::Two] {
            cs.push(translate(&c.code, &opts(stage)).unwrap().c);
        }
    }
    let lib = host::build("lift-hazards", &cs);
    let mut ws = Box::new(Workspace::ZERO);
    for (i, c) in cases.iter().enumerate() {
        let call = EvmCall {
            code: c.code.clone(),
            calldata: c.calldata.clone(),
            address: evm_core::u256::U256::from_u32(0xc0de),
            caller: evm_core::u256::U256::from_u32(0xca11),
            callvalue: evm_core::u256::U256::ZERO,
            gas_limit: 1_000_000,
            tree: SparseTree::new(),
            touched: vec![],
        };
        let words = call.input_words();
        let (w1, o1, _) = lib.run_words(&mut HostRef, 2 * i, &words);
        let (w2, o2, _) = lib.run_words(&mut HostRef, 2 * i + 1, &words);
        assert_eq!(w2[0], 1, "{}: stage two succeeds ({:?})", c.name, o2.halt);
        assert_eq!(
            (w2, o2.gas_used, o2.halt),
            (w1, o1.gas_used, o1.halt),
            "{}: stage two against stage one",
            c.name
        );
        if !c.calls {
            let (want, o) = run_call_with(
                &mut HostRef,
                &mut ws,
                |k| words[k as usize],
                words.len() as u32,
            );
            assert_eq!(w2, want, "{}: the eight words", c.name);
            assert_eq!(o2.gas_used, o.gas_used, "{}: gas_used", c.name);
        }
        eprintln!(
            "{}: status {} gas_used {} ret {}",
            c.name,
            w2[0],
            o2.gas_used,
            hex::encode(&o2.ret[..o2.ret_len])
        );
    }
}

// ---- the frame ------------------------------------------------------------------------------

fn erc20_code() -> Vec<u8> {
    let text =
        std::fs::read_to_string(root().join("guests-compiled/evm/contracts/erc20.runtime.hex"))
            .unwrap();
    hex::decode(text.trim()).unwrap()
}

fn riscv_clang() -> PathBuf {
    ["/opt/homebrew/opt/llvm/bin/clang", "clang"]
        .into_iter()
        .map(PathBuf::from)
        .chain(std::env::var_os("CLANG").map(PathBuf::from))
        .find(|c| {
            Command::new(c)
                .arg("--print-targets")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("riscv32"))
                .unwrap_or(false)
        })
        .expect("a clang with a riscv32 target (brew install llvm, or set CLANG)")
}

/// `evm_entry`'s frame in bytes, as clang's `-fstack-usage` reports it for rv32im with the
/// shim's flags.
fn frame(name: &str, c: &str) -> u64 {
    let dir = root().join("evm2rv/target/lift-frame");
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join(format!("{name}.c"));
    std::fs::write(&src, c).unwrap();
    let obj = dir.join(format!("{name}.o"));
    let o = Command::new(riscv_clang())
        .args(C_FLAGS)
        .args(["-fstack-usage", "-c", "-I"])
        .arg(root().join("evm-rt"))
        .arg(&src)
        .arg("-o")
        .arg(&obj)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let su = std::fs::read_to_string(dir.join(format!("{name}.su"))).unwrap();
    su.lines()
        .find(|l| l.contains(":evm_entry\t"))
        .and_then(|l| l.split('\t').nth(1))
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no evm_entry in {su}"))
}

/// Rule 5: no block holds more than `MAX_LOCALS` lifted words (32 bytes each), and the frame the
/// compiler actually gives `evm_entry` stays under 4 KiB — for the ERC-20, and for the corpus's
/// contracts with the most locals.
#[test]
fn the_frame_stays_within_its_budget() {
    const BUDGET: u64 = 4096;
    let erc20 = translate(&erc20_code(), &opts(Stage::Two)).unwrap();
    assert!(erc20.locals <= MAX_LOCALS);
    let f = frame("erc20", &erc20.c);
    eprintln!("frame: ERC-20 {} locals, evm_entry {f} bytes", erc20.locals);
    assert!(f <= BUDGET, "ERC-20 frame {f}");

    // A block that would hold 120 words holds at most MAX_LOCALS: the cap's own frame.
    let cap = translate(&over_the_cap(), &opts(Stage::Two)).unwrap();
    // It spills with four locals still free (room for one operation's constants and result).
    assert!(
        cap.locals <= MAX_LOCALS && cap.locals + 4 > MAX_LOCALS,
        "the cap is reached, and held: {}",
        cap.locals
    );
    let f = frame("over-the-cap", &cap.c);
    eprintln!(
        "frame: over the cap, {} locals, evm_entry {f} bytes",
        cap.locals
    );
    assert!(f <= BUDGET, "the cap's frame {f}");

    let n: u64 = std::env::var("EVM2RV_FUZZ_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000);
    let mut all: Vec<(usize, u64, String)> = (0..n)
        .map(|s| {
            let c = evm2rv::gen::case(s);
            let e = translate(
                &c.code,
                &Options {
                    chain_id: c.chain_id,
                    stage: Stage::Two,
                },
            )
            .unwrap();
            (e.locals, s, e.c)
        })
        .collect();
    assert!(
        all.iter().all(|(l, _, _)| *l <= MAX_LOCALS),
        "a corpus contract over the cap"
    );
    all.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let mut worst = 0;
    for (locals, seed, c) in all.iter().take(8) {
        let f = frame(&format!("seed-{seed}"), c);
        eprintln!("frame: corpus seed {seed}: {locals} locals, evm_entry {f} bytes");
        assert!(f <= BUDGET, "seed {seed}: frame {f}");
        worst = worst.max(f);
    }
    eprintln!(
        "frame: corpus of {n}: at most {} locals; the largest frame measured {worst} bytes",
        all[0].0
    );
}
