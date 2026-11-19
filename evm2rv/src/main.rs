//! `evm2rv <contract> --out <dir> [--name <crate>] [--stage 1|2] [--chain-id <N>]` — the CLI
//! (`--stage 2`, register lifting, is the default).
//!
//! Translates the contract's runtime bytecode into `<dir>/contract.c` and writes the shim crate
//! around it (`Cargo.toml`, `Cargo.lock`, `build.rs`, `src/main.rs`, `shim.ld`), ready for
//! `rand-guest build <dir> --max-words 65535`. Prints the block and opcode counts and a warning
//! per trapping opcode present (a call-family opcode: unless its target is a precompile). Without
//! `--out` it only analyses and prints.
//!
//! `evm2rv check <contract> [--interpreter]` — the pre-flight scan (ZKVM-121): every opcode in the
//! contract that traps or may trap, by offset, with the compatibility table's reason
//! (`evm2rv::compat`, published as `COMPATIBILITY.md`). It translates nothing. Exit status: 0 when
//! nothing in the code traps, 1 when an opcode that always traps is present (or the code is over
//! the size cap), 2 when the only findings are opcodes that trap for some operands (a call, which
//! runs only to a precompile; `RETURNDATACOPY`). By default the verdict is for a translation;
//! `--interpreter` gives it for the interpreter, where `CHAINID`, `ORIGIN` and every call trap.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use evm2rv::blocks::Warning;
use evm2rv::compat::{self, Behaviour, Severity};
use evm2rv::compat::name as mnemonic;
use evm2rv::emit::{translate, Options, Stage};

/// Translate EVM runtime bytecode into RV32 C and a zkVM shim crate.
#[derive(Parser, Debug)]
#[command(name = "evm2rv", args_conflicts_with_subcommands = true)]
struct Args {
    #[command(subcommand)]
    command: Option<Cmd>,

    /// The contract's runtime bytecode (not the creation code). A `.hex` file is hex text
    /// (whitespace ignored, an optional `0x` prefix; anything else is an error); a file with any
    /// other extension is the raw bytes.
    #[arg(required = true)]
    contract: Option<PathBuf>,

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

#[derive(Subcommand, Debug)]
enum Cmd {
    /// List every opcode in the contract that traps or may trap, with its offset and the reason
    /// (COMPATIBILITY.md). Exit status 0: nothing traps; 1: something always traps; 2: something
    /// traps for some operands.
    Check {
        /// The contract's runtime bytecode: a `.hex` file is hex text, anything else raw bytes.
        contract: PathBuf,

        /// Give the verdict for the interpreter (`evm.bin`) instead of a translation: `CHAINID`,
        /// `ORIGIN` and every call trap there.
        #[arg(long)]
        interpreter: bool,
    },
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

fn behaviour(b: Behaviour) -> &'static str {
    match b {
        Behaviour::Runs => "runs",
        Behaviour::RunsIf => "runs for some operands",
        Behaviour::Traps => "traps",
        Behaviour::Invalid => "invalid",
        Behaviour::Undefined => "undefined",
    }
}

/// `evm2rv check`: print the report and return the exit status.
fn check(contract: &Path, interpreter: bool) -> Result<u8> {
    let code = read_bytecode(contract)?;
    let r = compat::check(&code);
    println!("{}: {} code bytes", contract.display(), code.len());
    if let Some(len) = r.code_too_large {
        println!(
            "the code is {len} bytes, over the {} byte cap: nothing in it runs (OutOfBounds, status 2)",
            evm_core_max_code()
        );
        return Ok(1);
    }
    for f in &r.findings {
        let verdict = match f.severity {
            Severity::Traps => "TRAPS",
            Severity::MayTrap => "MAY TRAP",
            Severity::InterpreterOnly => "interpreter only",
        };
        println!(
            "  pc {:#06x}: {} ({:#04x}) {verdict}: interpreter {}, translation {}: {}",
            f.pc,
            f.name,
            f.opcode,
            behaviour(f.interp),
            behaviour(f.xlat),
            f.reason
        );
    }
    let count = |s: Severity| r.findings.iter().filter(|f| f.severity == s).count();
    println!(
        "{} always trap, {} may trap, {} trap in the interpreter only",
        count(Severity::Traps),
        count(Severity::MayTrap),
        count(Severity::InterpreterOnly)
    );
    if r.gas_differs > 0 {
        println!(
            "{} SLOAD/SSTORE: their gas is not mainnet's (COMPATIBILITY.md)",
            r.gas_differs
        );
    }
    if r.undefined > 0 {
        println!(
            "{} undefined bytes (they halt on mainnet too; data embedded in the code reads as these)",
            r.undefined
        );
    }
    let status = if interpreter {
        // In the interpreter every finding is a trap, except the conditional RETURNDATACOPY.
        if r.findings.iter().any(|f| f.interp == Behaviour::Traps) {
            1
        } else if r.interpreter_traps() {
            2
        } else {
            0
        }
    } else if r.traps() {
        1
    } else if r.may_trap() {
        2
    } else {
        0
    };
    let path = if interpreter { "the interpreter" } else { "a translation" };
    println!(
        "{}",
        match status {
            0 => format!("clean: nothing in this code traps in {path}"),
            1 => format!("not clean: an opcode in this code always traps in {path}"),
            _ => format!("conditional: an opcode in this code traps for some operands in {path}"),
        }
    );
    Ok(status)
}

fn evm_core_max_code() -> usize {
    compat::CAPS
        .iter()
        .find(|c| c.what == "code")
        .map_or(0, |c| c.limit)
}

fn main() -> Result<()> {
    let args = Args::parse();
    if let Some(Cmd::Check { contract, interpreter }) = &args.command {
        let status = check(contract, *interpreter)?;
        std::process::exit(status.into());
    }
    let contract = args.contract.clone().context("no contract given")?;
    let stage = match args.stage {
        1 => Stage::One,
        2 => Stage::Two,
        s => bail!("--stage {s}: the stages are 1 and 2"),
    };
    let code = read_bytecode(&contract)?;
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
                &contract
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
