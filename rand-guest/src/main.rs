//! `rand-guest`: one binary from a guest's source to the image the chain deploys.

use anyhow::{bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
use rand_guest::{build, check, pack};
use rand_zkvm::isa::Program;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rand-guest", version, about = "Rand zkVM toolchain: build, check, pack, run and describe a guest")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum Lang {
    Rust,
    C,
}

#[derive(Subcommand)]
enum Cmd {
    /// Compile a guest directory to a packed image, checking it on the way.
    Build {
        dir: PathBuf,
        #[arg(long, value_enum, default_value_t = Lang::Rust)]
        lang: Lang,
        /// The linker script, relative to the guest directory as the Makefiles write it
        /// (default: the one `.ld` in the guest, else `guest-sdk/guest.ld`).
        #[arg(long)]
        ld: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, default_value_t = 4096)]
        max_words: usize,
    },
    /// The ISA report over an ELF or an image.
    Check {
        file: PathBuf,
        #[arg(long, default_value_t = 4096)]
        max_words: usize,
    },
    /// Pack an ELF into the image container.
    Pack {
        elf: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Run an image on the emulator with the given inputs.
    Run {
        image: PathBuf,
        #[arg(long = "input", num_args = 0..)]
        inputs: Vec<u32>,
        #[arg(long = "public", num_args = 0..)]
        public: Vec<u32>,
    },
    /// Words, hc, the cap.
    Info {
        image: PathBuf,
        #[arg(long, default_value_t = 4096)]
        max_words: usize,
    },
}

fn hex8(w: &[u32; 8]) -> String {
    w.iter().map(|x| format!("{x:08x}")).collect()
}

/// The two on-disk forms an image handed to this tool can take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Loaded {
    /// The M4.3 container `build`/`pack` themselves emit (`IMAGE_MAGIC` first word):
    /// `Program::from_flat_image`.
    Image,
    /// A bare flat binary, no header: what a guest with no data segment was committed as before
    /// this tool existed (`guests-compiled/bin/fib.bin`, `keccak256.bin` —
    /// `research/src/guests.rs`'s `compiled::fib`/`compiled::keccak256`). Always loaded at
    /// `guest-sdk/guest.ld`'s fixed `ORIGIN`, `0x1000`, since a flat binary carries no base of
    /// its own.
    Flat,
}

impl std::fmt::Display for Loaded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Loaded::Image => write!(f, "image container"),
            Loaded::Flat => write!(f, "flat binary (legacy, base 0x1000)"),
        }
    }
}

/// The loader's own view of an image: what it will be on chain, which is what the cap is measured
/// against. The prologue is not a function of the data word count — `li` is one word or two and
/// the base register is reset periodically — so it is counted, never estimated.
///
/// Tries the image container first, since that is what a fresh `build`/`pack` produces; a
/// `Magic` mismatch alone (not any other container error) falls back to the flat form, so every
/// subcommand that takes an image accepts both without asking the caller which one it has.
fn load(image: &[u8]) -> Result<(Program, Loaded)> {
    match Program::from_flat_image(image) {
        Ok(p) => Ok((p, Loaded::Image)),
        Err(rand_zkvm::isa::LoadError::Magic(_)) => {
            let p = Program::from_flat_binary(0x1000, image).map_err(|e| anyhow::anyhow!("{e:?}"))?;
            Ok((p, Loaded::Flat))
        }
        Err(e) => Err(anyhow::anyhow!("{e:?}")),
    }
}

fn report_image(image: &[u8], max_words: usize) -> Result<check::Report> {
    let (program, form) = load(image)?;
    match form {
        Loaded::Image => {
            let (info, text, _data) = pack::split(image)?;
            Ok(check::check_text(info.text_base, &text, program.words.len(), max_words))
        }
        // No container header, so no separate prologue: the whole program is the text, starting
        // at the loader's own base_pc (`check_text`'s doc: "for a bare text with no data it is
        // simply text.len()").
        Loaded::Flat => Ok(check::check_text(program.base_pc, &program.words, program.words.len(), max_words)),
    }
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Build { dir, lang, ld, out, max_words } => {
            let out = out.unwrap_or_else(|| dir.join("image.bin"));
            let b = match lang {
                Lang::Rust => build::build_rust(&dir, ld.as_deref(), &out)?,
                Lang::C => build::build_c(&dir, ld.as_deref(), &out)?,
            };
            let image = std::fs::read(&b.image)?;
            let r = report_image(&image, max_words)?;
            println!("{r}");
            println!("wrote {} ({} words, hc {})", b.image.display(), b.words, hex8(&b.hc));
            if !r.is_ok() {
                bail!("the image is rejected by the checker (it was still written)");
            }
        }
        Cmd::Check { file, max_words } => {
            let bytes = std::fs::read(&file)?;
            let r = if bytes.starts_with(b"\x7fELF") {
                report_image(&pack::pack(&bytes)?, max_words)?
            } else {
                report_image(&bytes, max_words)?
            };
            println!("{r}");
            if !r.is_ok() {
                std::process::exit(1);
            }
        }
        Cmd::Pack { elf, out } => {
            let image = pack::pack(&std::fs::read(&elf)?)?;
            let out = out.unwrap_or_else(|| elf.with_extension("bin"));
            std::fs::write(&out, &image)?;
            use sha2::Digest;
            std::fs::write(
                format!("{}.sha256", out.display()),
                format!("{}  {}\n", hex::encode(sha2::Sha256::digest(&image)), out.file_name().unwrap().to_string_lossy()),
            )?;
            println!("wrote {} ({} bytes)", out.display(), image.len());
        }
        Cmd::Run { image, inputs, public } => {
            let bytes = std::fs::read(&image)?;
            let (program, _form) = load(&bytes)?;
            let max = rand_zkvm::machine::Tier(*rand_zkvm::machine::TIERS.last().unwrap()).max_cycles();
            match rand_zkvm::emulator::execute(&program, &inputs, &public, max) {
                Ok(exec) => {
                    for (i, w) in exec.outputs.iter().enumerate() { println!("out[{i}] = {w}"); }
                    let cycles = exec.cycles();
                    println!("cycles {cycles}");
                    match rand_zkvm::machine::Tier::for_cycles(cycles + program.digest_rows() + rand_zkvm::hash::input_digest_row_count(inputs.len()) + rand_zkvm::hash::public_digest_row_count(public.len())) {
                        Some(t) => println!("tier {}", t.0),
                        None => println!("no tier fits {cycles} cycles"),
                    }
                    if !exec.halted { println!("note: the program did not halt (ran out of the largest tier's budget)"); }
                }
                Err(e) => {
                    // The emulator's error carries the faulting pc where it has one; print what it has.
                    println!("trap at pc: {e:?}");
                    std::process::exit(2);
                }
            }
        }
        Cmd::Info { image, max_words } => {
            let bytes = std::fs::read(&image)?;
            let (program, form) = load(&bytes)?;
            println!("form: {form}");
            match form {
                Loaded::Image => {
                    let (info, text, data) = pack::split(&bytes)?;
                    let nonzero = data.iter().filter(|w| **w != 0).count();
                    println!(
                        "text {} words at {:#x}; data {} words ({} non-zero) at {:#x}; prologue {} words; program {} words from base_pc {:#x}",
                        text.len(),
                        info.text_base,
                        data.len(),
                        nonzero,
                        info.data_base,
                        program.words.len() - text.len(),
                        program.words.len(),
                        program.base_pc
                    );
                }
                // No container header, so `pack::split` (which reads the header) does not apply:
                // the whole program is the text, no separate prologue or data segment.
                Loaded::Flat => {
                    println!("{} words from base_pc {:#x}", program.words.len(), program.base_pc);
                }
            }
            println!("hc {}", hex8(&program.digest()));
            println!("{} words against a cap of {max_words}: {}", program.words.len(), if program.words.len() <= max_words { "fits" } else { "does not fit" });
        }
    }
    Ok(())
}
