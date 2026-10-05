//! The emitter's shape, independent of any one opcode (`src/emit.rs`, `src/lift.rs`): the same
//! input gives byte-identical C (both stages, the ERC-20 and the corpus, and the CLI's five
//! files), the two stages differ only where they should, the chain id reaches the C only as the
//! `CHAINID` constant (and the header comment), the counts the CLI prints are the analysis's, every
//! op has exactly one labelled line in pc order, every label is a block start and every `goto`
//! has its label, the dispatch switch lists exactly the jumpdests, and push data never shows up
//! as an op.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

use evm2rv::blocks::{blocks, jumpdests};
use evm2rv::emit::{mnemonic, translate, Emitted, Options, Stage};
use evm2rv::lift::MAX_LOCALS;

const STAGES: [Stage; 2] = [Stage::One, Stage::Two];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .unwrap()
}

fn erc20_code() -> Vec<u8> {
    let text =
        std::fs::read_to_string(root().join("guests-compiled/evm/contracts/erc20.runtime.hex"))
            .unwrap();
    hex::decode(text.trim()).unwrap()
}

fn emit(code: &[u8], stage: Stage, chain_id: Option<u64>) -> Emitted {
    translate(code, &Options { chain_id, stage }).unwrap()
}

/// A sample of the corpus: 150 seeds of each style.
fn corpus() -> Vec<(u64, Vec<u8>, Option<u64>)> {
    (0..150u64)
        .flat_map(|s| {
            let a = evm2rv::gen::case(s);
            let b = evm2rv::gen::case_opaque(s);
            [(s, a.code, a.chain_id), (s, b.code, b.chain_id)]
        })
        .collect()
}

#[test]
fn the_same_input_gives_byte_identical_c() {
    let erc20 = erc20_code();
    for stage in STAGES {
        let a = emit(&erc20, stage, None);
        let b = emit(&erc20, stage, None);
        assert_eq!(a.c, b.c, "{stage:?}: the ERC-20");
        assert_eq!((a.blocks, a.opcodes, a.locals), (b.blocks, b.opcodes, b.locals));
        for (seed, code, chain_id) in corpus() {
            let a = emit(&code, stage, chain_id);
            let b = emit(&code, stage, chain_id);
            assert_eq!(a.c, b.c, "{stage:?}: seed {seed}");
        }
    }
    // Across processes too: the CLI, run twice into two directories.
    let bin = env!("CARGO_BIN_EXE_evm2rv");
    let base = root().join("evm2rv/target/emit-determinism");
    let mut outs = Vec::new();
    for k in 0..2 {
        let dir = base.join(format!("run{k}"));
        let _ = std::fs::remove_dir_all(&dir);
        let o = Command::new(bin)
            .arg(root().join("guests-compiled/evm/contracts/erc20.runtime.hex"))
            .arg("--out")
            .arg(&dir)
            .args(["--name", "same"])
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let files: Vec<String> = ["contract.c", "Cargo.toml", "Cargo.lock", "build.rs", "src/main.rs", "shim.ld"]
            .iter()
            .map(|f| std::fs::read_to_string(dir.join(f)).unwrap())
            .collect();
        // The `wrote` line names the directory; everything before it is the report.
        let stdout = String::from_utf8_lossy(&o.stdout);
        let report: Vec<&str> = stdout.lines().take_while(|l| !l.starts_with("wrote")).collect();
        assert!(stdout.contains("wrote "), "{stdout}");
        outs.push((report.join("\n"), files));
    }
    assert_eq!(outs[0].0, outs[1].0, "the CLI's report");
    assert!(outs[0].0.contains("74 blocks, 798 opcodes, 51 jumpdests (stage 2)"));
    assert_eq!(outs[0].1, outs[1].1, "the five files");
    // ... and the file is the library's translation, stage two.
    assert_eq!(outs[0].1[0], emit(&erc20, Stage::Two, None).c);
}

#[test]
fn the_two_stages_differ_in_the_body_and_share_the_guard_and_the_heads() {
    let erc20 = erc20_code();
    let one = emit(&erc20, Stage::One, None);
    let two = emit(&erc20, Stage::Two, None);
    assert_ne!(one.c, two.c);
    assert!(one.c.contains("(stage one)") && two.c.contains("(stage two)"));
    assert_eq!(one.locals, 0);
    assert!(two.locals > 0 && two.locals <= MAX_LOCALS);
    assert_eq!((one.blocks, one.opcodes), (two.blocks, two.opcodes));
    // The guard's tail is identical.
    let tail = |c: &str| c[c.find("/* The code guard").unwrap()..].to_string();
    assert_eq!(tail(&one.c), tail(&two.c));
    // Every block head comment (`/* [start, end) min_depth …, static gas … */`, after the
    // block's label when it has one) is identical and in the same order: the analysis is shared.
    let heads = |c: &str| -> Vec<String> {
        c.lines()
            .filter_map(|l| l.find("/* [0x").map(|i| l[i..].to_string()))
            .collect()
    };
    assert_eq!(heads(&one.c), heads(&two.c));
    assert_eq!(heads(&one.c).len(), 74);
    // ... and every `evm_charge(n)` in the same order.
    let charges = |c: &str| -> Vec<String> {
        c.lines()
            .filter(|l| l.contains("evm_charge("))
            .map(|l| l.trim().to_string())
            .collect()
    };
    assert_eq!(charges(&one.c), charges(&two.c));
    // The sixteen-byte DUP/SWAP are array moves in stage one and nothing in stage two: stage two's
    // C is shorter for the ERC-20.
    assert!(two.c.len() < one.c.len(), "{} vs {}", two.c.len(), one.c.len());
}

#[test]
fn the_chain_id_reaches_the_c_only_through_chainid_and_the_header() {
    let erc20 = erc20_code();
    assert!(!blocks(&erc20).iter().any(|b| b.ops.iter().any(|o| o.opcode == 0x46)));
    let strip_header = |c: &str| c.lines().skip(1).collect::<Vec<_>>().join("\n");
    for stage in STAGES {
        let none = emit(&erc20, stage, None).c;
        let some = emit(&erc20, stage, Some(12)).c;
        assert_ne!(none, some, "the header names the constant");
        assert!(some.lines().next().unwrap().contains("CHAINID 12"));
        assert!(!none.lines().next().unwrap().contains("CHAINID"));
        assert_eq!(strip_header(&none), strip_header(&some), "{stage:?}: the body is the same");
        // With CHAINID in the code, the constant differs and so does the body.
        let code = [0x46, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3];
        let a = emit(&code, stage, Some(1)).c;
        let b = emit(&code, stage, Some(2)).c;
        assert_ne!(strip_header(&a), strip_header(&b));
        assert!(a.contains("0x1u") || a.contains("0x1ull"), "{a}");
        assert!(b.contains("0x2u") || b.contains("0x2ull"), "{b}");
    }
}

#[test]
fn the_counts_are_the_analysis_s() {
    for (seed, code, chain_id) in corpus() {
        let bs = blocks(&code);
        for stage in STAGES {
            let e = emit(&code, stage, chain_id);
            assert_eq!(e.blocks, bs.len(), "seed {seed} {stage:?}: blocks");
            assert_eq!(
                e.opcodes,
                bs.iter().map(|b| b.ops.len()).sum::<usize>(),
                "seed {seed} {stage:?}: opcodes"
            );
            match stage {
                Stage::One => assert_eq!(e.locals, 0),
                Stage::Two => assert!(e.locals <= MAX_LOCALS),
            }
        }
    }
    let erc20 = erc20_code();
    let e = emit(&erc20, Stage::Two, None);
    assert_eq!((e.blocks, e.opcodes), (74, 798));
    assert_eq!(jumpdests(&erc20).len(), 51);
    assert!(e.c.starts_with("/* Generated by evm2rv (stage two) from 1296 bytes of EVM runtime bytecode: 74 blocks, 51 jumpdests."));
}

/// The op comments in `c`, in order: `(pc, mnemonic)`.
fn op_lines(c: &str) -> Vec<(usize, String)> {
    c.lines()
        .filter_map(|l| {
            let t = l.trim_start();
            let t = t.strip_prefix("/* 0x")?;
            let (pc, rest) = t.split_once(' ')?;
            let name = rest.split_whitespace().next()?;
            Some((usize::from_str_radix(pc, 16).ok()?, name.to_string()))
        })
        .collect()
}

#[test]
fn every_op_has_exactly_one_line_in_pc_order_and_push_data_is_never_an_op() {
    let erc20 = erc20_code();
    let mut inputs: Vec<(String, Vec<u8>, Option<u64>)> = vec![("erc20".into(), erc20, None)];
    inputs.extend(
        corpus()
            .into_iter()
            .take(100)
            .map(|(s, c, id)| (format!("seed {s}"), c, id)),
    );
    // Push data that spells every opcode: PUSH32 of 0x00..0x1f, PUSH32 of 0x20..0x3f, …, STOP.
    let mut spell = Vec::new();
    for k in 0..8u8 {
        spell.push(0x7f);
        spell.extend((0..32u8).map(|i| k * 32 + i));
    }
    spell.push(0x00);
    inputs.push(("push data spelling every byte".into(), spell, None));
    for (name, code, chain_id) in inputs {
        let want: Vec<(usize, String)> = blocks(&code)
            .iter()
            .flat_map(|b| b.ops.iter().map(|o| (o.pc, mnemonic(o.opcode))))
            .collect();
        for stage in STAGES {
            let c = emit(&code, stage, chain_id).c;
            assert_eq!(op_lines(&c), want, "{name} ({stage:?})");
        }
    }
    // The spelled code has nine ops and no INVALID/JUMP/… line.
    let c = emit(&{
        let mut s = Vec::new();
        for k in 0..8u8 {
            s.push(0x7f);
            s.extend((0..32u8).map(|i| k * 32 + i));
        }
        s.push(0x00);
        s
    }, Stage::One, None).c;
    assert_eq!(op_lines(&c).len(), 9);
    assert!(!c.contains(" INVALID ") && !c.contains(" JUMP ") && !c.contains(" SSTORE "));
}

#[test]
fn labels_gotos_and_the_dispatch_switch_are_consistent() {
    let erc20 = erc20_code();
    let mut inputs: Vec<(String, Vec<u8>, Option<u64>)> = vec![("erc20".into(), erc20, None)];
    inputs.extend(corpus().into_iter().map(|(s, c, id)| (format!("seed {s}"), c, id)));
    for (name, code, chain_id) in inputs {
        let starts: BTreeSet<usize> = blocks(&code).iter().map(|b| b.start).collect();
        let jd: BTreeSet<usize> = jumpdests(&code).into_iter().collect();
        for stage in STAGES {
            let c = emit(&code, stage, chain_id).c;
            let labels: BTreeSet<usize> = c
                .lines()
                .filter_map(|l| l.strip_prefix("L_")?.split(':').next()?.parse().ok())
                .collect();
            let gotos: BTreeSet<usize> = c
                .match_indices("goto L_")
                .filter_map(|(i, _)| {
                    c[i + 7..].split(';').next()?.parse().ok()
                })
                .collect();
            assert!(labels.is_subset(&starts), "{name} ({stage:?}): a label that is no block start");
            assert!(gotos.is_subset(&labels), "{name} ({stage:?}): a goto without its label: {:?}", gotos.difference(&labels));
            assert!(labels.is_subset(&gotos), "{name} ({stage:?}): an unused label: {:?}", labels.difference(&gotos));
            assert!(gotos.contains(&0), "{name} ({stage:?}): the entry jumps to L_0");
            let cases: BTreeSet<usize> = c
                .lines()
                .filter_map(|l| l.trim().strip_prefix("case ")?.split('u').next()?.parse().ok())
                .collect();
            let dynamic = c.contains("goto dispatch;");
            assert_eq!(c.contains("switch (jd)"), dynamic, "{name} ({stage:?})");
            if dynamic {
                assert_eq!(cases, jd, "{name} ({stage:?}): the switch lists the jumpdests");
                assert!(c.contains("default: evm_halt(EVM_HALT_BAD_JUMP, 0);"));
            } else {
                assert!(cases.is_empty());
            }
            // One entry, one guard, one trailing STOP.
            assert_eq!(c.matches("void evm_entry(void) {").count(), 1);
            assert_eq!(c.matches("/* running off the end of the code */").count(), 1);
            assert_eq!(c.matches("const uint32_t *evm_code_digest(void) {").count(), 1);
        }
    }
}

#[test]
fn stage_two_folds_constants_and_stage_one_does_not() {
    // PUSH1 2, PUSH1 3, MUL, PUSH1 4, ADD, PUSH0, MSTORE, PUSH1 32, PUSH0, RETURN: 10, returned.
    let code = [0x60, 2, 0x60, 3, 0x02, 0x60, 4, 0x01, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3];
    let one = emit(&code, Stage::One, None).c;
    let two = emit(&code, Stage::Two, None).c;
    assert!(one.contains("u256_mul(") && one.contains("u256_add("), "{one}");
    assert!(!two.contains("u256_mul(") && !two.contains("u256_add("), "{two}");
    // The folded result (10 = 0xa) is materialized for the MSTORE, as a static constant or an
    // immediate, and the offsets are literals.
    assert!(two.contains("0xau"), "{two}");
    assert!(two.contains("evm_mstore(0x0u, "), "{two}");
    assert!(two.contains("evm_return(0x0u, 0x20u);"), "{two}");
    assert!(one.contains("evm_return(u256_sat_u32(&evm_stack[evm_sp-1]), u256_sat_u32(&evm_stack[evm_sp-2]));"), "{one}");
    // EXP is never folded: its gas depends on the operand.
    let code = [0x60, 2, 0x60, 3, 0x0a, 0x00];
    for stage in STAGES {
        assert!(emit(&code, stage, None).c.contains("evm_exp("), "{stage:?}");
    }
    // A constant offset past u32 saturates at translation, as the runtime would.
    let code = [0x60, 1, 0x64, 1, 0, 0, 0, 0, 0x52, 0x00]; // MSTORE(2^32, 1)
    let two = emit(&code, Stage::Two, None).c;
    assert!(two.contains("evm_mstore(0xffffffffu, "), "{two}");
}
