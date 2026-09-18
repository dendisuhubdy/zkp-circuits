//! `sbpf2rv <program.so> --out <dir> [--name <crate>]`: loads an sBPF ELF, scans and translates it,
//! and writes the shim crate `rand-guest build <dir>` turns into an image — `program.c`,
//! `Cargo.toml`, `Cargo.lock`, `build.rs`, `src/main.rs` and `shim.ld` (see `sbpf2rv::shim`).
//! Without `--out` it only reports the scan. The scan refuses nothing about the program's content (see `scan::scan`'s
//! docs); loading the ELF can fail, with the interpreter's own refusal, and a pathological ELF can
//! exceed the scan's work limit (`scan::MAX_SCAN_STEPS`).

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use sbpf2rv::{emit, scan::try_scan, shim};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "sbpf2rv",
    version,
    about = "Translate an sBPF ELF into C and the shim crate rand-guest builds"
)]
struct Cli {
    /// The sBPF v1 shared object to translate.
    program: PathBuf,
    /// Where to write the shim crate (created if needed; must be inside a circuits checkout).
    #[arg(long)]
    out: Option<PathBuf>,
    /// The crate's name (default: the ELF's file stem).
    #[arg(long)]
    name: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let source = std::fs::read(&cli.program)
        .with_context(|| format!("reading {}", cli.program.display()))?;
    // `load` relocates in place; the ELF guard's digest is of the bytes as published.
    let mut elf = source.clone();
    let program = sbpf_core::elf::load(&mut elf).map_err(|halt| {
        anyhow!(
            "{} is not a loadable sBPF v1 ELF: {halt:?}",
            cli.program.display()
        )
    })?;
    let scanned = try_scan(&program).map_err(|e| anyhow!("{}: {e}", cli.program.display()))?;
    let emitted = emit::emit_program(&program, &scanned);
    println!(
        "entry pc {}: {} function(s), {} block(s), {} instruction(s), {} callx target(s), 0 refusal(s), {} warning(s)",
        scanned.entry,
        emitted.functions,
        emitted.blocks,
        emitted.instructions,
        scanned.callx_targets.len(),
        scanned.warnings.len(),
    );
    for f in &scanned.functions {
        println!("  fn {}: {} block(s)", f.entry, f.blocks.len());
    }
    // Nothing is refused (the interpreter refuses none of it at load either); a warning names code
    // translated as the interpreter's own runtime trap, so proof coverage stops wherever it is.
    for w in &scanned.warnings {
        println!("  warning: {w:?}");
    }
    if let Some(out) = &cli.out {
        let stem = cli
            .program
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let name = match &cli.name {
            Some(n) => {
                let clean = shim::crate_name(n);
                anyhow::ensure!(
                    &clean == n,
                    "--name {n:?} is not a crate name (try {clean:?})"
                );
                clean
            }
            None => shim::crate_name(&stem),
        };
        shim::write_crate(out, &name, &emitted.c, &source)?;
        println!(
            "wrote {} ({} bytes of C) and the {name} shim crate: rand-guest build {}",
            out.join("program.c").display(),
            emitted.c.len(),
            out.display()
        );
    }
    Ok(())
}
