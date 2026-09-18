//! `evm2rv <contract> [--out <dir>] [--chain-id <N>]` — the CLI. Task 4's stage-one emitter fills
//! in `--out`; today this stub runs the block analysis (Task 3) and prints a summary, so the
//! crate has a working binary — and something to eyeball a contract's blocks and warnings with —
//! from the start.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

/// Translate EVM runtime bytecode into RV32 C.
#[derive(Parser, Debug)]
#[command(name = "evm2rv")]
struct Args {
    /// The contract's runtime bytecode (not the creation code): a `.bin` (raw bytes) or `.hex`
    /// (ASCII hex, an optional `0x` prefix) file.
    contract: PathBuf,

    /// Where the translated crate is written. Unused until Task 4's emitter lands.
    #[arg(long)]
    out: Option<PathBuf>,

    /// The constant `CHAINID` returns, baked into the translated C. Task 4 makes this required
    /// when the code contains `CHAINID`; today it is accepted and otherwise ignored.
    #[arg(long = "chain-id")]
    chain_id: Option<u64>,
}

/// A `.hex` file is ASCII hex (an optional `0x` prefix); anything else is read as raw bytes.
fn read_bytecode(path: &PathBuf) -> Result<Vec<u8>> {
    if let Ok(text) = fs::read_to_string(path) {
        let trimmed = text.trim();
        let hex_digits = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        if !hex_digits.is_empty() && hex_digits.chars().all(|c| c.is_ascii_hexdigit()) {
            return hex::decode(hex_digits).context("decoding hex bytecode");
        }
    }
    fs::read(path).with_context(|| format!("reading {}", path.display()))
}

fn main() -> Result<()> {
    let args = Args::parse();
    let code = read_bytecode(&args.contract)?;

    let jd = evm2rv::blocks::jumpdests(&code);
    let blocks = evm2rv::blocks::blocks(&code);
    let warns = evm2rv::blocks::warnings(&code);

    println!(
        "{} code bytes, {} jumpdests, {} blocks",
        code.len(),
        jd.len(),
        blocks.len()
    );
    for b in &blocks {
        println!(
            "  [{:#06x}, {:#06x}) {} ops, static_gas {}, min_depth {}, max_growth {}, term {:?}",
            b.start,
            b.end,
            b.ops.len(),
            b.static_gas,
            b.min_depth,
            b.max_growth,
            b.term
        );
    }

    if warns.is_empty() {
        println!("no trapping opcodes present");
    } else {
        println!("warnings ({} occurrence(s)):", warns.len());
        for (pc, op) in &warns {
            println!(
                "  pc {pc:#06x}: opcode {op:#04x} — the cross-contract family, traps at translation or (the call family) at runtime on a non-precompile target"
            );
        }
    }

    if let Some(chain_id) = args.chain_id {
        println!("--chain-id {chain_id} (bound once the emitter lands)");
    }
    if args.out.is_some() {
        println!("--out is not yet implemented (Task 4)");
    }
    Ok(())
}
