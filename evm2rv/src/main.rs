//! `evm2rv <contract> --out <dir> [--name <crate>] [--stage 1|2] [--chain-id <N>]` — the CLI
//! (`--stage 2`, register lifting, is the default).
//!
//! Translates the contract's runtime bytecode into `<dir>/contract.c` and writes the shim crate
//! around it (`Cargo.toml`, `Cargo.lock`, `build.rs`, `src/main.rs`, `shim.ld`), ready for
//! `rand-guest build <dir> --max-words 65535`. Prints the block and opcode counts and a warning
//! per trapping opcode present (a call-family opcode: unless its target is a precompile). Without
//! `--out` it only analyses and prints.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Parser;

use evm2rv::blocks::Warning;
use evm2rv::emit::{mnemonic, translate, Options, Stage};

/// Translate EVM runtime bytecode into RV32 C and a zkVM shim crate.
#[derive(Parser, Debug)]
#[command(name = "evm2rv")]
struct Args {
    /// The contract's runtime bytecode (not the creation code). A `.hex` file is hex text
    /// (whitespace ignored, an optional `0x` prefix; anything else is an error); a file with any
    /// other extension is the raw bytes.
    contract: PathBuf,

    /// Where the shim crate is written (inside a circuits checkout, as `rand-guest build`
    /// requires). Without it, the contract is only analysed.
    #[arg(long)]
    out: Option<PathBuf>,

    /// The shim crate's package name. Defaults to the contract file's stem.
    #[arg(long)]
    name: Option<String>,

    /// 2 (the default): register lifting, each block's words in C locals. 1: the memory-stack
    /// translation. Both give the same results and gas; stage two runs in fewer cycles, and each
    /// is its own program (its own `hc`).
    #[arg(long, default_value_t = 2)]
    stage: u8,

    /// The constant `CHAINID` returns, baked into the translated C (so the image hash binds it).
    /// Required when the code contains `CHAINID`.
    #[arg(long = "chain-id")]
    chain_id: Option<u64>,
}

/// The input format is the extension's: a `.hex` file is hex text — every whitespace character
/// is stripped, an optional `0x` prefix is allowed, and anything that is then not an even number
/// of hex digits is an error (never a fall back to raw bytes). Every other extension, or none, is
/// the raw bytes.
fn read_bytecode(path: &Path) -> Result<Vec<u8>> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if path.extension().is_some_and(|e| e == "hex") {
        let text = std::str::from_utf8(&bytes)
            .with_context(|| format!("{} is a .hex file but not text", path.display()))?;
        let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        let digits = digits.strip_prefix("0x").unwrap_or(&digits);
        return hex::decode(digits)
            .with_context(|| format!("{} is a .hex file but not valid hex", path.display()));
    }
    Ok(bytes)
}

fn main() -> Result<()> {
    let args = Args::parse();
    let stage = match args.stage {
        1 => Stage::One,
        2 => Stage::Two,
        s => bail!("--stage {s}: the stages are 1 and 2"),
    };
    let code = read_bytecode(&args.contract)?;
    let opts = Options {
        chain_id: args.chain_id,
        stage,
    };
    let emitted = translate(&code, &opts)?;
    let jd = evm2rv::blocks::jumpdests(&code);
    println!(
        "{} code bytes: {} blocks, {} opcodes, {} jumpdests (stage {})",
        code.len(),
        emitted.blocks,
        emitted.opcodes,
        jd.len(),
        args.stage
    );
    if let Some(id) = args.chain_id {
        println!("CHAINID is the constant {id}");
    }

    let warns = evm2rv::blocks::warnings(&code);
    if warns.is_empty() {
        println!("no trapping opcodes present");
    } else {
        println!("warnings ({}):", warns.len());
        for w in &warns {
            match w {
                Warning::Trap { pc, opcode } => println!(
                    "  pc {pc:#06x}: {} ({opcode:#04x}) traps (status 2): outside what a single-contract proof can run",
                    mnemonic(*opcode)
                ),
                Warning::Call { pc, opcode } => println!(
                    "  pc {pc:#06x}: {} ({opcode:#04x}) traps (status 2) unless the target is a precompile (addresses 1-9)",
                    mnemonic(*opcode)
                ),
                Warning::CodeTooLarge { len } => println!(
                    "  the code is {len} bytes, over MAX_CODE_BYTES: the interpreter runs nothing, and neither does the translation (OutOfBounds)"
                ),
            }
        }
    }

    if let Some(out) = &args.out {
        let name = match &args.name {
            Some(n) => evm2rv::shim::crate_name(n),
            None => evm2rv::shim::crate_name(
                &args
                    .contract
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            ),
        };
        evm2rv::shim::write_crate(out, &name, &emitted.c)?;
        println!(
            "wrote {} (crate {name}): contract.c, Cargo.toml, Cargo.lock, build.rs, src/main.rs, shim.ld",
            out.display()
        );
    }
    Ok(())
}
