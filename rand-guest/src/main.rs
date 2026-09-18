//! `rand-guest`: one binary from a guest's source to the image the chain deploys.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use rand_guest::{build, chain, check, pack};
use rand_zkvm::isa::{LoadError, Program, IMAGE_MAGIC};
use rand_zkvm::machine::{Tier, TIERS};
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
        /// The linker script, relative to the guest directory as the former Makefiles wrote it
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
        /// Also say whether the run fits this tier (one of the machine's tiers: 10, 12, …, 20).
        #[arg(long)]
        tier: Option<usize>,
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
/// The form is read off the first word — `IMAGE_MAGIC` is a container, anything else a flat
/// binary — so every subcommand that takes an image accepts both without asking the caller which
/// one it has. (Not "try the container loader and fall back on its `Magic` error": that loader
/// checks the length against its six-word header first, so a flat binary shorter than six words
/// would come back as `Length`, not `Magic`, and never reach the flat loader.)
fn load(image: &[u8]) -> std::result::Result<(Program, Loaded), LoadError> {
    if is_container(image) {
        Ok((Program::from_flat_image(image)?, Loaded::Image))
    } else {
        Ok((Program::from_flat_binary(FLAT_BASE, image)?, Loaded::Flat))
    }
}

fn is_container(image: &[u8]) -> bool {
    image.len() >= 4 && u32::from_le_bytes(image[..4].try_into().unwrap()) == IMAGE_MAGIC
}

/// `guest-sdk/guest.ld`'s `ORIGIN`: where a headerless flat binary is loaded, since it carries no
/// base of its own.
const FLAT_BASE: u32 = 0x1000;

/// What `check` (and `build`, through the same path) makes of an image: the report, and the
/// loader's program when the loader accepted it.
struct Checked {
    report: check::Report,
    /// `None` when the loader refused an undecodable word — which the report then names.
    program: Option<Program>,
    /// Set when the loader refused the image for a decode reason: the report is still printed,
    /// but its word count is the text alone, since the prologue is the loader's to count.
    uncounted: Option<LoadError>,
}

/// The ISA report over an image in either form.
///
/// The checker runs over the *text words themselves* — the container's text segment
/// (`pack::split`), or the whole of a flat binary — before, and independently of, the loader: the
/// loader refuses any word `Instr::decode` rejects, so asking it first would turn every
/// decode-class finding (`Compressed`, `Undecodable`, `Fence`, `Csr`, `Ebreak`) into a bare
/// `LoadError::Decode` instead of the named line the checker exists to print. The loader is then
/// asked only for the program word count the cap is measured against; if it refuses the image for
/// a decode reason the report stands with `text.len()` as the count, and any other loader error is
/// an error of its own.
fn report_image(image: &[u8], max_words: usize) -> Result<Checked> {
    let (base, text) = if is_container(image) {
        let (info, text, _data) = pack::split(image).context("reading the image container's segments")?;
        (info.text_base, text)
    } else {
        // No container header, so no separate prologue: the whole program is the text, starting
        // at the flat loader's base (`check_text`'s doc: "for a bare text with no data it is
        // simply text.len()").
        if image.is_empty() || image.len() % 4 != 0 {
            bail!("not an image container and not a flat binary: {} bytes is not a whole, non-zero number of words", image.len());
        }
        (FLAT_BASE, image.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect())
    };
    match load(image) {
        Ok((program, _)) => {
            let report = check::check_text(base, &text, program.words.len(), max_words);
            Ok(Checked { report, program: Some(program), uncounted: None })
        }
        Err(e @ LoadError::Decode { .. }) => {
            let report = check::check_text(base, &text, text.len(), max_words);
            Ok(Checked { report, program: None, uncounted: Some(e) })
        }
        Err(e) => bail!("the loader refuses the image: {e:?}"),
    }
}

impl std::fmt::Display for Checked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(e) = &self.uncounted {
            writeln!(f, "note: the loader refuses this image ({e:?}), so its data prologue could not be counted; the word count below is the text alone")?;
        }
        write!(f, "{}", self.report)
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
            let image = std::fs::read(&b.image).with_context(|| format!("reading back {}", b.image.display()))?;
            let c = report_image(&image, max_words).with_context(|| format!("checking {}", b.image.display()))?;
            println!("{c}");
            match &c.program {
                Some(p) => println!(
                    "wrote {} and its .sha256 ({} words, hc {}, program id {})",
                    b.image.display(),
                    p.words.len(),
                    hex8(&p.digest()),
                    hex::encode(chain::program_id(p.base_pc, &p.words))
                ),
                None => println!("wrote {} (the loader refuses it: no hc)", b.image.display()),
            }
            if !c.report.is_ok() {
                bail!("the image is rejected by the checker (it was still written)");
            }
        }
        Cmd::Check { file, max_words } => {
            let bytes = std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            let image = if bytes.starts_with(b"\x7fELF") {
                pack::pack(&bytes).with_context(|| format!("packing the ELF {}", file.display()))?
            } else {
                bytes
            };
            let c = report_image(&image, max_words).with_context(|| format!("checking {}", file.display()))?;
            println!("{c}");
            if !c.report.is_ok() {
                std::process::exit(1);
            }
        }
        Cmd::Pack { elf, out } => {
            let bytes = std::fs::read(&elf).with_context(|| format!("reading {}", elf.display()))?;
            let image = pack::pack(&bytes).with_context(|| format!("packing {}", elf.display()))?;
            let out = out.unwrap_or_else(|| elf.with_extension("bin"));
            pack::write_image(&out, &image)?;
            println!("wrote {} ({} bytes) and {}.sha256", out.display(), image.len(), out.display());
        }
        Cmd::Run { image, inputs, public, tier } => {
            if let Some(t) = tier {
                if !TIERS.contains(&t) {
                    bail!("--tier {t} is not one of the machine's tiers {TIERS:?}");
                }
            }
            let bytes = std::fs::read(&image).with_context(|| format!("reading {}", image.display()))?;
            let (program, _form) = load(&bytes).map_err(|e| anyhow::anyhow!("{e:?}")).with_context(|| format!("loading {}", image.display()))?;
            let max = Tier(*TIERS.last().unwrap()).max_cycles();
            match rand_zkvm::emulator::execute(&program, &inputs, &public, max) {
                Ok(exec) => {
                    for (i, w) in exec.outputs.iter().enumerate() { println!("out[{i}] = {w}"); }
                    let cycles = exec.cycles();
                    println!("cycles {cycles}");
                    // Mirrors `Machine::prove_salted`'s `None =>` arm term by term (`research/src/machine.rs`
                    // ~1226-1235): the cycle budget alone is not enough to pick a tier — the Poseidon2 table
                    // holds only `2^(t-3)` blocks against up to ~`2^t` permutation-emitting rows (digest,
                    // indigest, public-digest and in-guest `POSEIDON2` absorb rows all cost one permutation
                    // each), a second, independent constraint from the cycle one (Audit ZH1, `Tier::for_workload`'s
                    // doc comment) — so the tier this prints must be picked by `Tier::for_workload`, not
                    // `Tier::for_cycles`, or `run` could report a tier that `prove` would refuse.
                    let digest_rows = program.digest_rows() + rand_zkvm::hash::input_digest_row_count(inputs.len()) + rand_zkvm::hash::public_digest_row_count(public.len());
                    let total_cycles = cycles + digest_rows;
                    let absorb_rows = exec.events.iter().filter(|e| matches!(e.hash_row, Some(rand_zkvm::emulator::HashRow::Absorb { .. }))).count();
                    let permutations = digest_rows + absorb_rows;
                    match Tier::for_workload(total_cycles, permutations) {
                        Some(t) => println!("tier {}", t.0),
                        None => println!("no tier fits: cycles {total_cycles}, Poseidon2 permutations {permutations}"),
                    }
                    if let Some(t) = tier {
                        // The same rule `Tier::for_workload` applies to every tier it tries, stated
                        // for this one tier with both budgets printed.
                        let t = Tier(t);
                        let (cycle_budget, perm_budget) = (t.max_cycles(), t.poseidon2_height() / rand_zkvm::tables::poseidon2::BLOCK);
                        let fits = total_cycles <= t.max_cycles() && permutations * rand_zkvm::tables::poseidon2::BLOCK <= t.poseidon2_height();
                        println!(
                            "tier {}: {} (cycles {total_cycles} of {cycle_budget}, Poseidon2 permutations {permutations} of {perm_budget})",
                            t.0,
                            if fits { "fits" } else { "does not fit" }
                        );
                    }
                }
                Err(e) => {
                    // The emulator's error carries no pc to print; the error itself says what trapped.
                    println!("trap: {e:?}");
                    std::process::exit(2);
                }
            }
        }
        Cmd::Info { image, max_words } => {
            let bytes = std::fs::read(&image).with_context(|| format!("reading {}", image.display()))?;
            let (program, form) = load(&bytes).map_err(|e| anyhow::anyhow!("{e:?}")).with_context(|| format!("loading {}", image.display()))?;
            println!("form: {form}");
            match form {
                Loaded::Image => {
                    let (info, text, data) = pack::split(&bytes).with_context(|| format!("reading {}'s segments", image.display()))?;
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
            println!("program id {}", hex::encode(chain::program_id(program.base_pc, &program.words)));
            println!("{} words against a cap of {max_words}: {}", program.words.len(), if program.words.len() <= max_words { "fits" } else { "does not fit" });
        }
    }
    Ok(())
}
