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

/// The loader's own view of an image: what it will be on chain, which is what the cap is measured
/// against. The prologue is not a function of the data word count — `li` is one word or two and
/// the base register is reset periodically — so it is counted, never estimated.
fn load(image: &[u8]) -> Result<Program> {
    Program::from_flat_image(image).map_err(|e| anyhow::anyhow!("{e:?}"))
}

fn report_image(image: &[u8], max_words: usize) -> Result<check::Report> {
    let (info, text, _data) = pack::split(image)?;
    let program = load(image)?;
    Ok(check::check_text(info.text_base, &text, program.words.len(), max_words))
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
        Cmd::Run { .. } => bail!("run lands in the next task"),
        Cmd::Info { image, max_words } => {
            let bytes = std::fs::read(&image)?;
            let (info, text, data) = pack::split(&bytes)?;
            let program = load(&bytes)?;
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
            println!("hc {}", hex8(&program.digest()));
            println!("{} words against a cap of {max_words}: {}", program.words.len(), if program.words.len() <= max_words { "fits" } else { "does not fit" });
        }
    }
    Ok(())
}
