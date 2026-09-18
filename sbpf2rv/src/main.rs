//! `sbpf2rv <program.so>`: loads an sBPF ELF and reports the scan — functions, blocks and any
//! refusal. The emitter (`program.c`, the shim crate) is a later task; this stub is enough to
//! exercise the scanner end to end against a real ELF from the command line.

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use sbpf2rv::scan::scan;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "sbpf2rv", version, about = "Scan an sBPF ELF (the C emitter is a later task)")]
struct Cli {
    /// The sBPF v1 shared object to scan.
    program: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut elf = std::fs::read(&cli.program)
        .with_context(|| format!("reading {}", cli.program.display()))?;
    let program = sbpf_core::elf::load(&mut elf)
        .map_err(|halt| anyhow!("{} is not a loadable sBPF v1 ELF: {halt:?}", cli.program.display()))?;
    let scanned = scan(&program).map_err(|refusal| anyhow!("sbpf2rv refuses this program: {refusal:?}"))?;
    println!(
        "entry pc {}: {} function(s), {} callx target(s)",
        scanned.entry,
        scanned.functions.len(),
        scanned.callx_targets.len(),
    );
    for f in &scanned.functions {
        println!("  fn {}: {} block(s)", f.entry, f.blocks.len());
    }
    Ok(())
}
