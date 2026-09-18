# `rand-guest` toolchain — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One binary, `rand-guest`, that builds a Rust or C guest into the zkVM's image container, checks it against the machine's instruction set before anyone proves it, packs it, runs it on the emulator, and reports what it is.

**Architecture:** A new standalone crate `rand-guest/` in the circuits repo (its own workspace root like every guest crate) depending on the research crate `rand_zkvm` by path for the decoder, the loader, the digest and the emulator. Five subcommands over four modules: `elf` (ELF32 section reader, a port of `mkimage.py`), `pack` (the container), `check` (the ISA report), `build` (rustc/clang drivers), plus `run`/`info` in `main.rs`. The four committed guests must rebuild byte-identically before their Makefiles and `mkimage.py` are deleted.

**Tech Stack:** Rust 1.98.1 (the repo's `rust-toolchain.toml`), `rand_zkvm` (research crate), clap 4, anyhow, sha2; rustc target `riscv32im-unknown-none-elf` with `llvm-tools`; Homebrew LLVM clang for C (`/opt/homebrew/opt/llvm/bin/clang`, override with `CLANG`), `rust-lld` from the Rust sysroot.

**Spec:** `docs/superpowers/specs/2026-09-18-rand-guest-toolchain-design.md`

## Global Constraints

- The container format is exactly `Program::from_flat_image`'s: header words `[0x444e4152, 1, text_base, n_text, data_base, n_data]`, then text, then the data span; `.bss` never appears. The packer must reproduce `guests-compiled/bin/{fib,keccak256,evm,sbpf}.bin` byte for byte (their `sha256` files beside them are the pins).
- Target flags, verbatim from the existing Makefiles: `-C link-arg=-T<script>`, `-C target-feature=-unaligned-scalar-mem`, `--remap-path-prefix=<checkout root>=/rand-circuits`; the pinned toolchain is `+1.98.1`; the target is `riscv32im-unknown-none-elf`; never `rv32imc`.
- The checker's decoder is `rand_zkvm::isa::Instr::decode`; the accepted set is whatever it decodes plus `ECALL`; a word with `(w & 3) != 3` is a compressed encoding and is rejected by name.
- The chain's deploy cap is a `--max-words` flag defaulting to `4096` (fullnode's `MAX_PROGRAM_WORDS` today); the loader's own limit is `u16::MAX` words.
- No new dependency on anything in `fullnode`; nothing in `research/src` changes.
- Commit messages: a prefix (`rand-guest:`, `guests-compiled:`, `docs:`), a body saying why, and the two attribution lines from the session's system reminder.
- Run tests from the crate: `cd rand-guest && cargo test`. The byte-identity tests need the riscv32im target (`rustup +1.98.1 target add riscv32im-unknown-none-elf` and `rustup +1.98.1 component add llvm-tools`); the C tests need a RISC-V clang and are `#[ignore]`d when `rand_guest::build::find_clang()` returns `None`.

---

## File structure

| path | responsibility |
|---|---|
| `rand-guest/Cargo.toml` | the crate, `[[bin]] rand-guest`, `[workspace]` root |
| `rand-guest/src/main.rs` | clap: `build`, `check`, `pack`, `run`, `info`; printing |
| `rand-guest/src/elf.rs` | ELF32 LE section table reader; `Section { name, addr, offset, size, progbits, alloc }`; `read_sections(bytes)`; `text_words`, `symbol` lookup for `_start` |
| `rand-guest/src/pack.rs` | `pack(elf) -> Result<Vec<u8>>` (the container), `image_parts(image) -> (text_base, text, data_base, data)` |
| `rand-guest/src/check.rs` | `check_text(base, words, max_words) -> Report`; the rules; `Report::is_ok()` and `Display` |
| `rand-guest/src/build.rs` | `build_rust(dir, ld, out)`, `build_c(dir, ld, out)`, `find_clang()`, `flags(root)` |
| `rand-guest/guest.h` | the C syscall wrappers and `halt`, shipped with the binary via `include_str!` |
| `rand-guest/tests/pack.rs`, `tests/check.rs`, `tests/build.rs`, `tests/run.rs` | integration tests |
| `guests-compiled/c-fib/{fib.c}` | the fifth guest, in C |
| `guests-compiled/README.md`, `research/docs/01-isa.md` | docs: how a guest is built now |

---

### Task 1: the crate, the ELF reader and the packer, pinned to the four committed images

**Files:**
- Create: `rand-guest/Cargo.toml`, `rand-guest/src/main.rs`, `rand-guest/src/elf.rs`, `rand-guest/src/pack.rs`, `rand-guest/src/lib.rs`
- Test: `rand-guest/tests/pack.rs`

**Interfaces:**
- Produces: `rand_guest::elf::{Section, read_sections(&[u8]) -> Result<Vec<Section>>}`; `rand_guest::pack::pack(&[u8]) -> Result<Vec<u8>>`; `rand_guest::pack::describe(&[u8]) -> Result<ImageInfo { text_base, n_text, data_base, n_data }>`.

- [ ] **Step 1: Write the failing test**

`rand-guest/tests/pack.rs`:

```rust
//! The packer reproduces the committed images byte for byte from the guests' ELFs. The ELFs are
//! built here with the same cargo invocation the Makefiles use, so this test needs the
//! riscv32im target and llvm-tools installed (`rustup +1.98.1 target add …`).

use std::path::PathBuf;
use std::process::Command;

fn root() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..") }

/// Builds a guest exactly as its Makefile does and returns the ELF path.
fn build_guest_elf(name: &str, crate_name: &str, ld: &str) -> PathBuf {
    let dir = root().join("guests-compiled").join(name);
    let flags = format!(
        "[\"-C\",\"link-arg=-T{ld}\",\"-C\",\"target-feature=-unaligned-scalar-mem\",\"--remap-path-prefix={}=/rand-circuits\"]",
        root().canonicalize().unwrap().display()
    );
    let status = Command::new("cargo")
        .args(["+1.98.1", "build", "--release", "--target", "riscv32im-unknown-none-elf", "--config"])
        .arg(format!("target.riscv32im-unknown-none-elf.rustflags={flags}"))
        .current_dir(&dir)
        .status()
        .expect("cargo runs");
    assert!(status.success(), "building {name}");
    dir.join("target/riscv32im-unknown-none-elf/release").join(crate_name)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}

fn pinned(name: &str) -> String {
    let text = std::fs::read_to_string(root().join("guests-compiled/bin").join(format!("{name}.bin.sha256"))).unwrap();
    text.split_whitespace().next().unwrap().to_string()
}

#[test]
fn the_packer_reproduces_every_committed_image() {
    // (guest dir, ELF name, linker script relative to the guest dir)
    for (name, elf, ld) in [
        ("fib", "fib-guest", "../../guest-sdk/guest.ld"),
        ("keccak256", "keccak256-guest", "../../guest-sdk/guest.ld"),
        ("evm", "evm-guest", "evm.ld"),
        ("sbpf", "sbpf-guest", "sbpf.ld"),
    ] {
        let elf_bytes = std::fs::read(build_guest_elf(name, elf, ld)).unwrap();
        let image = rand_guest::pack::pack(&elf_bytes).unwrap();
        assert_eq!(sha256_hex(&image), pinned(name), "{name}.bin");
        let info = rand_guest::pack::describe(&image).unwrap();
        assert!(info.n_text > 0);
    }
}

#[test]
fn a_non_elf_is_refused_by_name() {
    let err = rand_guest::pack::pack(b"not an elf at all").unwrap_err().to_string();
    assert!(err.contains("ELF32"), "{err}");
}
```

Check the actual ELF names and linker-script paths against each guest's `Makefile` and `.cargo/config.toml` before running: `fib` and `keccak256` link with `-T../../guest-sdk/guest.ld` from `.cargo/config.toml`, `evm` and `sbpf` with their own `.ld` via `--config` (their `.cargo/config.toml`, if present, must not add a second `-T`; the `--config` flags replace the file's `rustflags`, which is what the Makefiles rely on).

- [ ] **Step 2: Create the crate so the test fails on missing items**

`rand-guest/Cargo.toml`:

```toml
[package]
name = "rand-guest"
version = "0.1.0"
edition = "2021"
description = "The Rand zkVM toolchain: build a Rust or C guest into the image the chain deploys, check it against the machine, run it"

[lib]
path = "src/lib.rs"

[[bin]]
name = "rand-guest"
path = "src/main.rs"

[dependencies]
rand_zkvm = { path = "../research" }
clap = { version = "4.4", features = ["derive"] }
anyhow = "1"
sha2 = "0.10"
hex = "0.4"

[dev-dependencies]
tempfile = "3"

# Its own workspace root, like every guest crate: never swept into research's cargo test.
[workspace]
```

`src/lib.rs`: `pub mod elf; pub mod pack; pub mod check; pub mod build;` (create `check.rs` and `build.rs` as empty modules for now). `src/main.rs`: `fn main() {}`.

Run: `cd rand-guest && cargo test --test pack`
Expected: compile error, `pack` and `describe` missing.

- [ ] **Step 3: Write `elf.rs`, a port of `mkimage.py`'s section reader**

```rust
//! ELF32 little-endian section table, read directly — the guest toolchain needs nothing
//! but this (a port of the former `guests-compiled/mkimage.py`).

use anyhow::{bail, Context, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub addr: u32,
    pub offset: u32,
    pub size: u32,
    /// `SHT_PROGBITS`
    pub progbits: bool,
    /// `SHF_ALLOC`
    pub alloc: bool,
}

const SHT_PROGBITS: u32 = 1;
const SHF_ALLOC: u32 = 0x2;

fn u16_at(b: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(b.get(at..at + 2).context("ELF header truncated")?.try_into()?))
}
fn u32_at(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(b.get(at..at + 4).context("ELF header truncated")?.try_into()?))
}

pub fn read_sections(elf: &[u8]) -> Result<Vec<Section>> {
    if elf.len() < 0x34 || &elf[..4] != b"\x7fELF" || elf[4] != 1 || elf[5] != 1 {
        bail!("not an ELF32 little-endian file");
    }
    let e_shoff = u32_at(elf, 0x20)? as usize;
    let e_shentsize = u16_at(elf, 0x2e)? as usize;
    let e_shnum = u16_at(elf, 0x30)? as usize;
    let e_shstrndx = u16_at(elf, 0x32)? as usize;
    let mut raw = Vec::with_capacity(e_shnum);
    for i in 0..e_shnum {
        let base = e_shoff + i * e_shentsize;
        raw.push((u32_at(elf, base)?, u32_at(elf, base + 4)?, u32_at(elf, base + 8)?, u32_at(elf, base + 12)?, u32_at(elf, base + 16)?, u32_at(elf, base + 20)?));
    }
    let strtab_off = raw.get(e_shstrndx).context("no section name table")?.4 as usize;
    let mut out = Vec::with_capacity(e_shnum);
    for (name, typ, flags, addr, off, size) in raw {
        let start = strtab_off + name as usize;
        let end = elf[start..].iter().position(|&b| b == 0).map(|p| start + p).context("unterminated section name")?;
        out.push(Section {
            name: String::from_utf8_lossy(&elf[start..end]).into_owned(),
            addr, offset: off, size,
            progbits: typ == SHT_PROGBITS,
            alloc: flags & SHF_ALLOC != 0,
        });
    }
    Ok(out)
}
```

- [ ] **Step 4: Write `pack.rs`**

```rust
//! The image container `Program::from_flat_image` loads, built from an ELF the way
//! `mkimage.py` built it: `.text`, then every other allocated PROGBITS section as one span from
//! the lowest to the highest address, gaps zero-filled. `.bss` never appears.

use crate::elf::read_sections;
use anyhow::{bail, Result};
use rand_zkvm::isa::{IMAGE_HEADER_WORDS, IMAGE_MAGIC, IMAGE_VERSION};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageInfo { pub text_base: u32, pub n_text: usize, pub data_base: u32, pub n_data: usize }

pub fn pack(elf: &[u8]) -> Result<Vec<u8>> {
    let loadable: Vec<_> = read_sections(elf)?.into_iter().filter(|s| s.progbits && s.alloc && s.size > 0).collect();
    let text: Vec<_> = loadable.iter().filter(|s| s.name == ".text").collect();
    let [text] = text[..] else { bail!("expected exactly one non-empty .text section, found {}", text.len()) };
    if text.addr % 4 != 0 || text.size % 4 != 0 {
        bail!(".text must be word-aligned in both address ({:#x}) and size ({})", text.addr, text.size);
    }
    let text_bytes = &elf[text.offset as usize..(text.offset + text.size) as usize];
    let mut data_sections: Vec<_> = loadable.iter().filter(|s| s.name != ".text").collect();
    data_sections.sort_by_key(|s| s.addr);
    let (data_base, data_bytes) = if let Some(first) = data_sections.first() {
        let base = first.addr;
        let end = data_sections.iter().map(|s| s.addr + s.size).max().unwrap();
        if base % 4 != 0 { bail!("data segment base {base:#x} is not word-aligned"); }
        if base < text.addr + text.size { bail!("the data segment overlaps .text"); }
        let mut data = vec![0u8; ((end - base) as usize + 3) / 4 * 4];
        for s in &data_sections {
            let at = (s.addr - base) as usize;
            data[at..at + s.size as usize].copy_from_slice(&elf[s.offset as usize..(s.offset + s.size) as usize]);
        }
        (base, data)
    } else {
        (0, Vec::new())
    };
    let mut out = Vec::with_capacity(4 * IMAGE_HEADER_WORDS + text_bytes.len() + data_bytes.len());
    for w in [IMAGE_MAGIC, IMAGE_VERSION, text.addr, text.size / 4, data_base, (data_bytes.len() / 4) as u32] {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out.extend_from_slice(text_bytes);
    out.extend_from_slice(&data_bytes);
    Ok(out)
}

pub fn describe(image: &[u8]) -> Result<ImageInfo> {
    if image.len() < 4 * IMAGE_HEADER_WORDS || image.len() % 4 != 0 { bail!("not an image: {} bytes", image.len()); }
    let w = |i: usize| u32::from_le_bytes(image[4 * i..4 * i + 4].try_into().unwrap());
    if w(0) != IMAGE_MAGIC { bail!("not an image: magic {:#x}", w(0)); }
    if w(1) != IMAGE_VERSION { bail!("image version {} is not {IMAGE_VERSION}", w(1)); }
    Ok(ImageInfo { text_base: w(2), n_text: w(3) as usize, data_base: w(4), n_data: w(5) as usize })
}

/// The text words of an image (for the checker) and its data words.
pub fn split(image: &[u8]) -> Result<(ImageInfo, Vec<u32>, Vec<u32>)> {
    let info = describe(image)?;
    let body: Vec<u32> = image[4 * IMAGE_HEADER_WORDS..].chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
    if body.len() != info.n_text + info.n_data { bail!("image body has {} words, header says {} + {}", body.len(), info.n_text, info.n_data); }
    let (t, d) = body.split_at(info.n_text);
    Ok((info, t.to_vec(), d.to_vec()))
}
```

- [ ] **Step 5: Run the tests**

Run: `cd rand-guest && cargo test --test pack`
Expected: both PASS. If a guest's image differs, diff the header words first (`describe` on both), then the data span: the usual cause is a second `-T` from a `.cargo/config.toml` the Makefile's `--config` overrides.

- [ ] **Step 6: Commit**

```bash
git add rand-guest
git commit -m "rand-guest: the crate, the ELF32 section reader and the packer — mkimage.py in Rust, pinned to the four committed images byte for byte

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013dJJAGbDPDmf9i6UsXLxvB"
```

---

### Task 2: the checker

**Files:**
- Create: `rand-guest/src/check.rs`
- Test: `rand-guest/tests/check.rs`

**Interfaces:**
- Produces: `rand_guest::check::{check_text(base_pc: u32, text: &[u32], data_words: usize, max_words: usize) -> Report, Report { findings: Vec<Finding>, words: usize, cap: usize, unresolved_ecalls: usize }, Finding { addr: u32, word: u32, rule: Rule, what: String }, Rule { Compressed, Undecodable, Fence, Csr, Ebreak, Syscall, Cap, Layout }, Report::is_ok()}`; `impl Display for Report`.

- [ ] **Step 1: Write the failing tests**

`rand-guest/tests/check.rs`:

```rust
//! Every rule the checker enforces, one rejection each, on hand-assembled words — no compiler
//! needed. Encodings: RV32I as in research/src/isa.rs's encoder.

use rand_guest::check::{check_text, Rule};
use rand_zkvm::isa::Instr;

fn enc(i: Instr) -> u32 { i.encode() }

fn ok_program() -> Vec<u32> {
    // li a7, 0 ; ecall  (HALT)
    vec![enc(Instr::AluImm { op: rand_zkvm::isa::AluOp::Add, rd: 17, rs1: 0, imm: 0 }), enc(Instr::Ecall)]
}

#[test]
fn a_clean_program_passes_with_no_findings() {
    let r = check_text(0x1000, &ok_program(), 0, 4096);
    assert!(r.is_ok(), "{r}");
    assert_eq!(r.words, 2);
}

#[test]
fn a_compressed_encoding_is_named() {
    let mut p = ok_program();
    p.push(0x0000_4501); // c.li a0, 0 — a 16-bit encoding: low bits are not 0b11
    let r = check_text(0x1000, &p, 0, 4096);
    assert!(r.findings.iter().any(|f| f.rule == Rule::Compressed), "{r}");
}

#[test]
fn fence_csr_and_ebreak_are_named_not_lumped_as_undecodable() {
    for (word, rule) in [(0x0ff0_000f, Rule::Fence), (0xc000_2573, Rule::Csr), (0x0010_0073, Rule::Ebreak)] {
        let mut p = ok_program();
        p.insert(0, word);
        let r = check_text(0x1000, &p, 0, 4096);
        assert!(r.findings.iter().any(|f| f.rule == rule && f.word == word), "{word:#x}: {r}");
    }
}

#[test]
fn an_unknown_syscall_number_is_named_and_a_known_one_is_not() {
    let bad = vec![enc(Instr::AluImm { op: rand_zkvm::isa::AluOp::Add, rd: 17, rs1: 0, imm: 99 }), enc(Instr::Ecall)];
    let r = check_text(0x1000, &bad, 0, 4096);
    assert!(r.findings.iter().any(|f| f.rule == Rule::Syscall && f.what.contains("99")), "{r}");
    assert!(check_text(0x1000, &ok_program(), 0, 4096).is_ok());
}

#[test]
fn an_ecall_whose_a7_is_not_static_is_a_warning_not_a_finding() {
    // a7 = a0 ; ecall
    let p = vec![enc(Instr::AluReg { op: rand_zkvm::isa::AluOp::Add, rd: 17, rs1: 10, rs2: 0 }), enc(Instr::Ecall)];
    let r = check_text(0x1000, &p, 0, 4096);
    assert!(r.is_ok());
    assert_eq!(r.unresolved_ecalls, 1);
}

#[test]
fn the_cap_counts_text_plus_data_prologue() {
    // 4 data words cost 8 prologue instructions (li/sw per word); 2 text words + 8 = 10 > cap 9.
    let r = check_text(0x1000, &ok_program(), 4, 9);
    assert!(r.findings.iter().any(|f| f.rule == Rule::Cap), "{r}");
    assert!(check_text(0x1000, &ok_program(), 4, 10).is_ok());
}

#[test]
fn a_misaligned_base_is_a_layout_finding() {
    let r = check_text(0x1002, &ok_program(), 0, 4096);
    assert!(r.findings.iter().any(|f| f.rule == Rule::Layout), "{r}");
}
```

If `Instr::encode` is not public in the research crate, encode the two `ok_program` words by hand (`addi a7, x0, 0` = `0x0000_0893`, `ecall` = `0x0000_0073`) and `addi a7, x0, 99` = `0x0630_0893`, `add a7, a0, x0` = `0x0005_08b3`.

- [ ] **Step 2: Run to verify they fail**

Run: `cd rand-guest && cargo test --test check`
Expected: compile error, `check_text` missing.

- [ ] **Step 3: Write `check.rs`**

```rust
//! The ISA report: every text word decoded with the machine's own decoder, syscall numbers
//! resolved where they are static, the layout and the cap. A guest that passes cannot fail
//! in-circuit for an encoding, syscall-number or layout reason.

use rand_zkvm::isa::{AluOp, DecodeError, Instr};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule { Compressed, Undecodable, Fence, Csr, Ebreak, Syscall, Cap, Layout }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding { pub addr: u32, pub word: u32, pub rule: Rule, pub what: String }

#[derive(Clone, Debug, Default)]
pub struct Report {
    pub findings: Vec<Finding>,
    /// Text words plus the data prologue's words (two per non-zero data word: `li` + `sw`,
    /// which is what `Program::from_flat_image` emits; a zero data word costs nothing).
    pub words: usize,
    pub cap: usize,
    pub unresolved_ecalls: usize,
}

impl Report {
    pub fn is_ok(&self) -> bool { self.findings.is_empty() }
}

/// The syscall numbers the machine implements (research/docs/01-isa.md "Syscall ABI").
pub const SYSCALLS: [(u32, &str); 7] = [(0, "HALT"), (1, "WRITE_OUTPUT"), (2, "READ_INPUT"), (3, "POSEIDON2"), (4, "KECCAK"), (5, "SHA256"), (6, "READ_PUBLIC")];

const OP_MISC_MEM: u32 = 0x0f;
const OP_SYSTEM: u32 = 0x73;

/// `data_nonzero` is how many data words are non-zero (the prologue skips zeros); pass the total
/// when the caller has not counted, which only over-estimates.
pub fn check_text(base_pc: u32, text: &[u32], data_nonzero: usize, max_words: usize) -> Report {
    let mut r = Report { cap: max_words, ..Default::default() };
    if base_pc % 4 != 0 {
        r.findings.push(Finding { addr: base_pc, word: 0, rule: Rule::Layout, what: format!("text base {base_pc:#x} is not word-aligned") });
    }
    // The last `addi a7, x0, n` seen in straight-line code; cleared by any write to a7 that is
    // not that shape, and by any control transfer (a branch target could arrive with any a7).
    let mut a7: Option<u32> = None;
    for (i, &w) in text.iter().enumerate() {
        let addr = base_pc.wrapping_add(4 * i as u32);
        if w & 3 != 3 {
            r.findings.push(Finding { addr, word: w, rule: Rule::Compressed, what: "16-bit (RVC) encoding; the machine decodes only 32-bit RV32IM".into() });
            continue;
        }
        match Instr::decode(w) {
            Ok(Instr::Ecall) => match a7 {
                Some(n) if SYSCALLS.iter().any(|(k, _)| *k == n) => {}
                Some(n) => r.findings.push(Finding { addr, word: w, rule: Rule::Syscall, what: format!("ecall with a7 = {n}, which is no syscall the machine implements") }),
                None => r.unresolved_ecalls += 1,
            },
            Ok(Instr::AluImm { op: AluOp::Add, rd: 17, rs1: 0, imm }) => a7 = Some(imm),
            Ok(Instr::AluImm { rd: 17, .. }) | Ok(Instr::AluReg { rd: 17, .. }) | Ok(Instr::Lui { rd: 17, .. }) | Ok(Instr::Auipc { rd: 17, .. }) | Ok(Instr::Load { rd: 17, .. }) | Ok(Instr::Jal { rd: 17, .. }) | Ok(Instr::Jalr { rd: 17, .. }) => a7 = None,
            Ok(Instr::Jal { .. }) | Ok(Instr::Jalr { .. }) | Ok(Instr::Branch { .. }) => a7 = None,
            Ok(_) => {}
            Err(e) => {
                let opcode = w & 0x7f;
                let (rule, what) = match (opcode, e) {
                    (OP_MISC_MEM, _) => (Rule::Fence, "FENCE/FENCE.I: the machine has no memory ordering instructions".to_string()),
                    (OP_SYSTEM, _) if w == 0x0010_0073 => (Rule::Ebreak, "EBREAK: traps are not modelled".to_string()),
                    (OP_SYSTEM, _) => (Rule::Csr, "CSR instruction: the machine has no CSRs".to_string()),
                    (_, DecodeError::Opcode(o)) => (Rule::Undecodable, format!("opcode {o:#x} is outside RV32IM as the machine implements it")),
                    (_, DecodeError::Funct(f)) => (Rule::Undecodable, format!("funct {f:#x} is not an RV32IM encoding")),
                    (_, DecodeError::Shamt(s)) => (Rule::Undecodable, format!("shift amount {s} is out of range")),
                };
                r.findings.push(Finding { addr, word: w, rule, what });
            }
        }
    }
    r.words = text.len() + 2 * data_nonzero;
    if r.words > max_words {
        r.findings.push(Finding { addr: base_pc, word: 0, rule: Rule::Cap, what: format!("{} words (text {} + prologue {}) exceed the cap of {max_words}", r.words, text.len(), 2 * data_nonzero) });
    }
    r
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for x in &self.findings {
            writeln!(f, "{:#010x}  {:#010x}  {:?}: {}", x.addr, x.word, x.rule, x.what)?;
        }
        writeln!(f, "{} words against a cap of {} ({}); {} ecall(s) with a non-static a7", self.words, self.cap, if self.words <= self.cap { "fits" } else { "does not fit" }, self.unresolved_ecalls)?;
        write!(f, "{}", if self.is_ok() { "OK" } else { "REJECTED" })
    }
}
```

Verify against `research/src/isa.rs`: the `Instr` variants and field names above are the crate's (`AluImm { op, rd, rs1, imm }`, `Ecall`, …); `DecodeError::{Opcode, Funct, Shamt}`. If `Instr::decode` returns `Ecall` for every `OP_SYSTEM` word with `funct3 = 0`, add an explicit `w == 0x0010_0073` check before the decode so `EBREAK` is not accepted as an `ECALL`; the test for `Ebreak` will tell you.

- [ ] **Step 4: Run the tests**

Run: `cd rand-guest && cargo test --test check`
Expected: all seven PASS.

- [ ] **Step 5: Commit**

```bash
git add rand-guest/src/check.rs rand-guest/tests/check.rs
git commit -m "rand-guest: the ISA checker — every text word through the machine's decoder, RVC/FENCE/CSR/EBREAK named, static syscall numbers checked, the prologue counted against the cap

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013dJJAGbDPDmf9i6UsXLxvB"
```

---

### Task 3: `build --lang rust`, and the CLI with `check`, `pack`, `info`

**Files:**
- Create: `rand-guest/src/build.rs` (the Rust half), `rand-guest/src/main.rs` (all five subcommands; `run` lands in Task 4)
- Test: `rand-guest/tests/build.rs`

**Interfaces:**
- Produces: `rand_guest::build::{flags(root: &Path, ld: &Path) -> Vec<String>, build_rust(dir: &Path, ld: Option<&Path>, out: &Path) -> Result<BuildOutput { elf: PathBuf, image: PathBuf, hc: [u32; 8], words: usize }>, find_ld(dir) -> PathBuf}`.
- CLI: `rand-guest build <dir> [--lang rust|c] [--ld script] [--out image.bin] [--max-words N]`, `rand-guest check <file> [--max-words N]`, `rand-guest pack <elf> [--out image.bin]`, `rand-guest info <image.bin> [--max-words N]`.

- [ ] **Step 1: Write the failing test**

`rand-guest/tests/build.rs`:

```rust
//! `rand-guest build` over the four committed guests gives their committed images.

use std::path::PathBuf;
use std::process::Command;

fn root() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..") }
fn bin() -> PathBuf { PathBuf::from(env!("CARGO_BIN_EXE_rand-guest")) }
fn pinned(name: &str) -> String {
    std::fs::read_to_string(root().join("guests-compiled/bin").join(format!("{name}.bin.sha256"))).unwrap().split_whitespace().next().unwrap().to_string()
}

#[test]
fn build_reproduces_every_committed_image_and_reports_hc() {
    let tmp = tempfile::tempdir().unwrap();
    for name in ["fib", "keccak256", "evm", "sbpf"] {
        let out = tmp.path().join(format!("{name}.bin"));
        let o = Command::new(bin()).args(["build"]).arg(root().join("guests-compiled").join(name)).arg("--out").arg(&out).output().unwrap();
        assert!(o.status.success(), "{name}: {}", String::from_utf8_lossy(&o.stderr));
        let image = std::fs::read(&out).unwrap();
        use sha2::Digest;
        assert_eq!(hex::encode(sha2::Sha256::digest(&image)), pinned(name), "{name}");
        let stdout = String::from_utf8_lossy(&o.stdout);
        assert!(stdout.contains("hc "), "{stdout}");
        assert!(stdout.contains("words"), "{stdout}");
    }
}

#[test]
fn info_and_check_agree_with_build_on_the_evm_image() {
    let image = root().join("guests-compiled/bin/evm.bin");
    let info = Command::new(bin()).args(["info"]).arg(&image).output().unwrap();
    let s = String::from_utf8_lossy(&info.stdout);
    assert!(s.contains("text 18009") || s.contains("18009"), "{s}");
    assert!(s.contains("does not fit"), "the interpreter is over the 4096 cap: {s}");
    let check = Command::new(bin()).args(["check"]).arg(&image).args(["--max-words", "65535"]).output().unwrap();
    assert!(check.status.success(), "{}", String::from_utf8_lossy(&check.stdout));
}
```

The exact `evm.bin` text word count is what `describe` reports; the interpreter's docs say 18 009 program words including the prologue — use whatever `info` prints for `text` after the first run and pin that number in the assertion.

- [ ] **Step 2: Run to verify it fails**

Run: `cd rand-guest && cargo test --test build`
Expected: the binary has no subcommands yet; failure.

- [ ] **Step 3: Write the Rust half of `build.rs`**

```rust
//! Driving rustc (and, in Task 6, clang) for the guest target, then pack. The flags are the
//! four Makefiles', generated here so no guest carries them.

use crate::pack;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const TARGET: &str = "riscv32im-unknown-none-elf";
pub const TOOLCHAIN: &str = "1.98.1";

pub struct BuildOutput { pub elf: PathBuf, pub image: PathBuf, pub hc: [u32; 8], pub words: usize }

/// The rustflags list every guest gets. `root` is the checkout root (for the path remap), `ld`
/// the linker script as the guest crate sees it.
pub fn flags(root: &Path, ld: &Path) -> Vec<String> {
    vec![
        "-C".into(), format!("link-arg=-T{}", ld.display()),
        "-C".into(), "target-feature=-unaligned-scalar-mem".into(),
        format!("--remap-path-prefix={}=/rand-circuits", root.display()),
    ]
}

/// A guest's linker script: the one `.ld` in its directory, else `guest-sdk/guest.ld`.
pub fn find_ld(dir: &Path, root: &Path) -> Result<PathBuf> {
    let mut lds: Vec<_> = std::fs::read_dir(dir)?.flatten().map(|e| e.path()).filter(|p| p.extension().map_or(false, |e| e == "ld")).collect();
    match lds.len() {
        0 => Ok(root.join("guest-sdk/guest.ld")),
        1 => Ok(lds.remove(0)),
        n => bail!("{n} linker scripts in {}; pass --ld", dir.display()),
    }
}

pub fn checkout_root(dir: &Path) -> Result<PathBuf> {
    // The directory holding `guest-sdk/`: walk up from the guest.
    let mut p = dir.canonicalize()?;
    loop {
        if p.join("guest-sdk/guest.ld").exists() { return Ok(p); }
        if !p.pop() { bail!("{} is not inside a circuits checkout (no guest-sdk/ above it)", dir.display()); }
    }
}

pub fn build_rust(dir: &Path, ld: Option<&Path>, out: &Path) -> Result<BuildOutput> {
    let root = checkout_root(dir)?;
    let ld = match ld { Some(l) => l.to_path_buf(), None => find_ld(dir, &root)? };
    // The script path is resolved relative to the guest dir by rust-lld, as the Makefiles do;
    // make it absolute so `--config` works from anywhere.
    let ld_abs = if ld.is_absolute() { ld } else { dir.join(ld) };
    let flags: Vec<String> = flags(&root, &ld_abs).into_iter().map(|f| format!("{f:?}")).collect();
    let config = format!("target.{TARGET}.rustflags=[{}]", flags.join(","));
    let status = Command::new("cargo")
        .arg(format!("+{TOOLCHAIN}")).args(["build", "--release", "--target", TARGET, "--config"]).arg(&config)
        .current_dir(dir).status().context("running cargo (is the pinned toolchain installed?)")?;
    if !status.success() { bail!("cargo build failed for {}", dir.display()); }
    let elf = find_elf(&dir.join("target").join(TARGET).join("release"))?;
    let image = pack::pack(&std::fs::read(&elf)?)?;
    std::fs::write(out, &image)?;
    let program = rand_zkvm::isa::Program::from_flat_image(&image).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    Ok(BuildOutput { elf, image: out.to_path_buf(), hc: program.digest(), words: program.words.len() })
}

/// The one executable ELF in the release dir (cargo names it after the bin target).
fn find_elf(release: &Path) -> Result<PathBuf> {
    let mut elfs: Vec<_> = std::fs::read_dir(release)?.flatten().map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_none() && std::fs::read(p).map(|b| b.starts_with(b"\x7fELF")).unwrap_or(false)).collect();
    match elfs.len() { 1 => Ok(elfs.remove(0)), 0 => bail!("no ELF in {}", release.display()), _ => bail!("several ELFs in {}; the guest must have one bin target", release.display()) }
}
```

`format!("{f:?}")` quotes each flag as a TOML string; check the resulting `--config` against the `evm` Makefile's `RUSTFLAGS_LIST` shape (`["-C","link-arg=-T…", …]`) — it must be a TOML array of strings.

- [ ] **Step 4: Write `main.rs`**

```rust
use anyhow::{bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
use rand_guest::{build, check, pack};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rand-guest", version, about = "Rand zkVM toolchain: build, check, pack, run and describe a guest")]
struct Cli { #[command(subcommand)] cmd: Cmd }

#[derive(Clone, Copy, ValueEnum)]
enum Lang { Rust, C }

#[derive(Subcommand)]
enum Cmd {
    /// Compile a guest directory to a packed image, checking it on the way.
    Build { dir: PathBuf, #[arg(long, value_enum, default_value_t = Lang::Rust)] lang: Lang, #[arg(long)] ld: Option<PathBuf>, #[arg(long)] out: Option<PathBuf>, #[arg(long, default_value_t = 4096)] max_words: usize },
    /// The ISA report over an ELF or an image.
    Check { file: PathBuf, #[arg(long, default_value_t = 4096)] max_words: usize },
    /// Pack an ELF into the image container.
    Pack { elf: PathBuf, #[arg(long)] out: Option<PathBuf> },
    /// Run an image on the emulator with the given inputs.
    Run { image: PathBuf, #[arg(long = "input", num_args = 0..)] inputs: Vec<u32>, #[arg(long = "public", num_args = 0..)] public: Vec<u32> },
    /// Words, hc, program id, the cap.
    Info { image: PathBuf, #[arg(long, default_value_t = 4096)] max_words: usize },
}

fn hex8(w: &[u32; 8]) -> String { w.iter().map(|x| format!("{x:08x}")).collect() }

fn report_image(image: &[u8], max_words: usize) -> Result<check::Report> {
    let (info, text, data) = pack::split(image)?;
    let nonzero = data.iter().filter(|w| **w != 0).count();
    Ok(check::check_text(info.text_base, &text, nonzero, max_words))
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Build { dir, lang, ld, out, max_words } => {
            let out = out.unwrap_or_else(|| dir.join("image.bin"));
            let b = match lang { Lang::Rust => build::build_rust(&dir, ld.as_deref(), &out)?, Lang::C => build::build_c(&dir, ld.as_deref(), &out)? };
            let image = std::fs::read(&b.image)?;
            let r = report_image(&image, max_words)?;
            println!("{r}");
            println!("wrote {} ({} words, hc {})", b.image.display(), b.words, hex8(&b.hc));
            if !r.is_ok() { bail!("the image is rejected by the checker (it was still written)"); }
        }
        Cmd::Check { file, max_words } => {
            let bytes = std::fs::read(&file)?;
            let r = if bytes.starts_with(b"\x7fELF") { report_image(&pack::pack(&bytes)?, max_words)? } else { report_image(&bytes, max_words)? };
            println!("{r}");
            if !r.is_ok() { std::process::exit(1); }
        }
        Cmd::Pack { elf, out } => {
            let image = pack::pack(&std::fs::read(&elf)?)?;
            let out = out.unwrap_or_else(|| elf.with_extension("bin"));
            std::fs::write(&out, &image)?;
            use sha2::Digest;
            std::fs::write(format!("{}.sha256", out.display()), format!("{}  {}\n", hex::encode(sha2::Sha256::digest(&image)), out.file_name().unwrap().to_string_lossy()))?;
            println!("wrote {} ({} bytes)", out.display(), image.len());
        }
        Cmd::Run { .. } => bail!("run lands in the next task"),
        Cmd::Info { image, max_words } => {
            let bytes = std::fs::read(&image)?;
            let (info, text, data) = pack::split(&bytes)?;
            let program = rand_zkvm::isa::Program::from_flat_image(&bytes).map_err(|e| anyhow::anyhow!("{e:?}"))?;
            let nonzero = data.iter().filter(|w| **w != 0).count();
            println!("text {} words at {:#x}; data {} words ({} non-zero) at {:#x}; prologue {} words; program {} words from base_pc {:#x}",
                text.len(), info.text_base, data.len(), nonzero, info.data_base, 2 * nonzero, program.words.len(), program.base_pc);
            println!("hc {}", hex8(&program.digest()));
            println!("{} words against a cap of {max_words}: {}", program.words.len(), if program.words.len() <= max_words { "fits" } else { "does not fit" });
        }
    }
    Ok(())
}
```

Add `build_c` as a stub returning `bail!("C support lands in Task 6")` so this compiles.

- [ ] **Step 5: Run the tests**

Run: `cd rand-guest && cargo test --test build`
Expected: PASS. Then run `cargo test` for the whole crate to confirm Tasks 1–2 still pass.

The spec's reproducibility property (the same source from two checkout paths gives the same
bytes) is what `--remap-path-prefix` buys and what the byte-identity test already exercises
against images built on another machine; a two-checkout test is not added here.

- [ ] **Step 6: Commit**

```bash
git add rand-guest
git commit -m "rand-guest: build --lang rust, check, pack, info — the four Makefiles' cargo invocation generated, the image checked and its hc printed

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013dJJAGbDPDmf9i6UsXLxvB"
```

---

### Task 4: `run`

**Files:**
- Modify: `rand-guest/src/main.rs` (the `Run` arm)
- Test: `rand-guest/tests/run.rs`

**Interfaces:**
- CLI: `rand-guest run <image.bin> [--input w …] [--public w …]` prints `out[0..8]`, `cycles N`, `tier T` (or `no tier fits`), and on a trap `trap at pc … : <ExecError>` with exit code 2.

- [ ] **Step 1: Write the failing test**

```rust
//! `run` executes the committed images on the emulator and reports what the research crate's
//! own tests report.

use std::path::PathBuf;
use std::process::Command;

fn root() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..") }
fn bin() -> PathBuf { PathBuf::from(env!("CARGO_BIN_EXE_rand-guest")) }

#[test]
fn fib_20_runs_to_6765_with_a_tier() {
    let o = Command::new(bin()).args(["run"]).arg(root().join("guests-compiled/bin/fib.bin")).args(["--input", "20"]).output().unwrap();
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{s}");
    assert!(s.contains("out[0] = 6765"), "{s}");
    assert!(s.contains("cycles "), "{s}");
    assert!(s.contains("tier 10"), "{s}");
}

#[test]
fn a_trap_is_reported_with_its_pc_and_exit_code_2() {
    // fib with no input: READ_INPUT 0 past an empty vector is an input-index trap.
    let o = Command::new(bin()).args(["run"]).arg(root().join("guests-compiled/bin/fib.bin")).output().unwrap();
    assert_eq!(o.status.code(), Some(2));
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(s.contains("trap at pc"), "{s}");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd rand-guest && cargo test --test run`
Expected: fails ("run lands in the next task").

- [ ] **Step 3: Implement the `Run` arm**

```rust
        Cmd::Run { image, inputs, public } => {
            let bytes = std::fs::read(&image)?;
            let program = rand_zkvm::isa::Program::from_flat_image(&bytes).map_err(|e| anyhow::anyhow!("{e:?}"))?;
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
```

The tier arithmetic mirrors `Machine::prove_salted`'s (`research/src/machine.rs`, the `None =>` arm: cycles + program digest rows + input digest rows + public digest rows); copy the exact expression from there. If `ExecError` does not carry the pc, extend the message with the last executed event's pc from a partial `Execution` if the emulator exposes one; otherwise print the error alone and keep the "trap at pc" prefix — the test only checks the prefix.

- [ ] **Step 4: Run the tests, then the whole crate**

Run: `cd rand-guest && cargo test`
Expected: all PASS; the `fib` cycle count printed should equal what `research/tests` reports for `guests::compiled::fib()` at n = 20 (grep `6765` there for the pinned number and add it to the assertion).

- [ ] **Step 5: Commit**

```bash
git add rand-guest
git commit -m "rand-guest: run — an image on the emulator with its inputs: the eight outputs, the cycle count, the smallest tier that fits, or the trap

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013dJJAGbDPDmf9i6UsXLxvB"
```

---

### Task 5: replace the Makefiles and `mkimage.py`

**Files:**
- Delete: `guests-compiled/mkimage.py`, `guests-compiled/{fib,keccak256,evm,sbpf}/Makefile`, `guests-compiled/{fib,keccak256}/.cargo/config.toml` (the flags now come from `rand-guest`)
- Modify: `guests-compiled/README.md` (or create it), `research/docs/01-isa.md` §"The image container" (one paragraph: built by `rand-guest`), `research/docs/04-guests.md` (the build line)
- Test: `rand-guest/tests/build.rs` already pins the four images; add a test that the deleted files are gone and a `cargo build` in a guest dir without the toolchain still fails loudly (no flags → the `rand-guest build` path is the only one)

- [ ] **Step 1: Confirm the gate**

Run: `cd rand-guest && cargo test --test build` — must PASS before anything is deleted.

- [ ] **Step 2: Delete and document**

```bash
git rm guests-compiled/mkimage.py guests-compiled/fib/Makefile guests-compiled/keccak256/Makefile guests-compiled/evm/Makefile guests-compiled/sbpf/Makefile guests-compiled/fib/.cargo/config.toml guests-compiled/keccak256/.cargo/config.toml
```

Check `evm` and `sbpf` for `.cargo/config.toml` too; delete if present. Write `guests-compiled/README.md`:

```markdown
# Compiled guests

Built with the toolchain, never by hand:

    cd rand-guest && cargo run -- build ../guests-compiled/<guest> --out ../guests-compiled/bin/<guest>.bin

`rand-guest build` compiles with the pinned toolchain and the fixed flags, checks the ELF
against the machine, packs the image and prints its `hc`. `bin/<guest>.bin.sha256` pins each
image; `rand-guest/tests/build.rs` rebuilds all four and compares. A guest with a data segment
links with its own `.ld` (`evm.ld`, `sbpf.ld`: `guest.ld` with `ORIGIN` raised for the
prologue), which `rand-guest` finds by itself.
```

Update the two docs' build sentences to point here. Keep every Makefile comment that explained a flag: move the `evm` Makefile's comment block on jump tables and the remap into `rand-guest/src/build.rs` above `flags`, verbatim, so the reasoning survives the deletion.

- [ ] **Step 3: Run the full crate tests once more, then commit**

```bash
cd rand-guest && cargo test
git add -A guests-compiled rand-guest research/docs
git commit -m "guests-compiled: built by rand-guest — the four Makefiles, mkimage.py and the per-guest cargo configs go, their flag comments move into rand-guest, the images stay pinned

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013dJJAGbDPDmf9i6UsXLxvB"
```

---

### Task 6: the C path — `guest.h`, `_start`, clang, and a fifth guest

**Files:**
- Create: `rand-guest/guest.h`, `rand-guest/start.S`, `guests-compiled/c-fib/fib.c`
- Modify: `rand-guest/src/build.rs` (`find_clang`, `build_c`), `rand-guest/tests/build.rs` (the C test, gated)

**Interfaces:**
- Produces: `build::find_clang() -> Option<PathBuf>` (`$CLANG`, else `/opt/homebrew/opt/llvm/bin/clang`, else `clang` on PATH — accepted only if `clang --print-targets` lists `riscv32`); `build::build_c(dir, ld, out) -> Result<BuildOutput>`.
- Prerequisite, ruled by the user 2026-09-18: `brew install llvm` on this machine (the implementer runs it if `/opt/homebrew/opt/llvm/bin/clang` is absent).

- [ ] **Step 1: Write the failing test**

Append to `rand-guest/tests/build.rs`:

```rust
#[test]
fn a_c_guest_builds_checks_and_runs_like_the_rust_one() {
    let Some(_) = rand_guest::build::find_clang() else { eprintln!("no RISC-V clang; skipping"); return; };
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("c-fib.bin");
    let o = Command::new(bin()).args(["build", "--lang", "c"]).arg(root().join("guests-compiled/c-fib")).arg("--out").arg(&out).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let r = Command::new(bin()).args(["run"]).arg(&out).args(["--input", "20"]).output().unwrap();
    let s = String::from_utf8_lossy(&r.stdout);
    assert!(s.contains("out[0] = 6765"), "{s}");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd rand-guest && cargo test --test build a_c_guest`
Expected: `build_c` bails.

- [ ] **Step 3: Write `guest.h` and `start.S`**

`rand-guest/guest.h` — the SDK's wrappers in C, each an `ecall` with the number in `a7` and the arguments in `a0`/`a1`, exactly as `guest-sdk/src/lib.rs`'s `asm!` blocks (copy the register usage from there):

```c
#ifndef RAND_GUEST_H
#define RAND_GUEST_H
#include <stdint.h>
#include <stddef.h>

#define RAND_SYS_HALT 0
#define RAND_SYS_WRITE_OUTPUT 1
#define RAND_SYS_READ_INPUT 2
#define RAND_SYS_POSEIDON2 3
#define RAND_SYS_KECCAK 4
#define RAND_SYS_SHA256 5
#define RAND_SYS_READ_PUBLIC 6

static inline uint32_t rand_read_input(uint32_t idx) {
    register uint32_t a0 __asm__("a0") = idx;
    register uint32_t a7 __asm__("a7") = RAND_SYS_READ_INPUT;
    __asm__ volatile("ecall" : "+r"(a0) : "r"(a7) : "memory");
    return a0;
}
static inline uint32_t rand_read_public(uint32_t idx) {
    register uint32_t a0 __asm__("a0") = idx;
    register uint32_t a7 __asm__("a7") = RAND_SYS_READ_PUBLIC;
    __asm__ volatile("ecall" : "+r"(a0) : "r"(a7) : "memory");
    return a0;
}
static inline void rand_write_output(uint32_t slot, uint32_t word) {
    register uint32_t a0 __asm__("a0") = slot;
    register uint32_t a1 __asm__("a1") = word;
    register uint32_t a7 __asm__("a7") = RAND_SYS_WRITE_OUTPUT;
    __asm__ volatile("ecall" : : "r"(a0), "r"(a1), "r"(a7) : "memory");
}
static inline void rand_poseidon2(uint32_t *ptr, uint32_t n) {
    register uint32_t a0 __asm__("a0") = (uint32_t)(uintptr_t)ptr;
    register uint32_t a1 __asm__("a1") = n;
    register uint32_t a7 __asm__("a7") = RAND_SYS_POSEIDON2;
    __asm__ volatile("ecall" : : "r"(a0), "r"(a1), "r"(a7) : "memory");
}
static inline void rand_keccak(uint32_t *ptr) {
    register uint32_t a0 __asm__("a0") = (uint32_t)(uintptr_t)ptr;
    register uint32_t a7 __asm__("a7") = RAND_SYS_KECCAK;
    __asm__ volatile("ecall" : : "r"(a0), "r"(a7) : "memory");
}
static inline void rand_sha256_compress(uint32_t *ptr) {
    register uint32_t a0 __asm__("a0") = (uint32_t)(uintptr_t)ptr;
    register uint32_t a7 __asm__("a7") = RAND_SYS_SHA256;
    __asm__ volatile("ecall" : : "r"(a0), "r"(a7) : "memory");
}
__attribute__((noreturn)) static inline void rand_halt(void) {
    register uint32_t a7 __asm__("a7") = RAND_SYS_HALT;
    __asm__ volatile("ecall" : : "r"(a7) : "memory");
    __builtin_unreachable();
}
#endif
```

Check each wrapper's argument registers against `guest-sdk/src/lib.rs` (which register `WRITE_OUTPUT`'s slot and word use, and `POSEIDON2`'s pointer and count) and correct the C to match; the SDK is the authority.

`rand-guest/start.S` — the SDK's `_start`, verbatim:

```asm
    .section .text._start
    .global _start
_start:
    la sp, __stack_top
    call main
    li a7, 0
    ecall
```

- [ ] **Step 4: Implement `find_clang` and `build_c`**

```rust
pub fn find_clang() -> Option<PathBuf> {
    let candidates = [std::env::var("CLANG").ok().map(PathBuf::from), Some(PathBuf::from("/opt/homebrew/opt/llvm/bin/clang")), Some(PathBuf::from("clang"))];
    candidates.into_iter().flatten().find(|c| {
        Command::new(c).arg("--print-targets").output().map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("riscv32")).unwrap_or(false)
    })
}

/// `ld.lld` from the pinned Rust sysroot's llvm-tools, so C needs only clang installed.
fn rust_lld() -> Result<PathBuf> {
    let sysroot = String::from_utf8(Command::new("rustc").arg(format!("+{TOOLCHAIN}")).args(["--print", "sysroot"]).output()?.stdout)?;
    let host = String::from_utf8(Command::new("rustc").arg(format!("+{TOOLCHAIN}")).arg("-vV").output()?.stdout)?.lines().find_map(|l| l.strip_prefix("host: ")).context("rustc host")?.to_string();
    let p = PathBuf::from(sysroot.trim()).join("lib/rustlib").join(host).join("bin/rust-lld");
    if !p.exists() { bail!("{} not found: rustup +{TOOLCHAIN} component add llvm-tools", p.display()); }
    Ok(p)
}

pub fn build_c(dir: &Path, ld: Option<&Path>, out: &Path) -> Result<BuildOutput> {
    let clang = find_clang().context("no clang with a riscv32 target: brew install llvm, or set CLANG")?;
    let root = checkout_root(dir)?;
    let ld = match ld { Some(l) => l.to_path_buf(), None => find_ld(dir, &root)? };
    let ld_abs = if ld.is_absolute() { ld } else { dir.join(ld) };
    let target_dir = dir.join("target/rand-guest");
    std::fs::create_dir_all(&target_dir)?;
    let tool_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    std::fs::write(target_dir.join("guest.h"), include_str!("../guest.h"))?;
    std::fs::write(target_dir.join("start.S"), include_str!("../start.S"))?;
    let mut sources: Vec<PathBuf> = std::fs::read_dir(dir)?.flatten().map(|e| e.path()).filter(|p| p.extension().map_or(false, |e| e == "c")).collect();
    sources.sort();
    if sources.is_empty() { bail!("no .c files in {}", dir.display()); }
    let mut objects = Vec::new();
    for src in sources.iter().chain(std::iter::once(&target_dir.join("start.S"))) {
        let obj = target_dir.join(src.file_name().unwrap()).with_extension("o");
        let status = Command::new(&clang)
            .args(["--target=riscv32-unknown-none-elf", "-march=rv32im", "-mabi=ilp32", "-mno-relax", "-nostdlib", "-ffreestanding", "-fno-builtin", "-Os", "-c"])
            .arg("-I").arg(&target_dir)
            .arg(format!("-fdebug-prefix-map={}=/rand-circuits", root.display()))
            .arg(src).arg("-o").arg(&obj).status()?;
        if !status.success() { bail!("clang failed on {}", src.display()); }
        objects.push(obj);
    }
    let elf = target_dir.join("guest.elf");
    let status = Command::new(rust_lld()?).arg("-flavor").arg("gnu").arg("-T").arg(&ld_abs).args(&objects).arg("-o").arg(&elf).status()?;
    if !status.success() { bail!("linking {} failed", elf.display()); }
    let image = pack::pack(&std::fs::read(&elf)?)?;
    std::fs::write(out, &image)?;
    let program = rand_zkvm::isa::Program::from_flat_image(&image).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let _ = tool_dir;
    Ok(BuildOutput { elf, image: out.to_path_buf(), hc: program.digest(), words: program.words.len() })
}
```

`guests-compiled/c-fib/fib.c`:

```c
#include "guest.h"

static uint32_t fib(uint32_t n) {
    uint32_t a = 0, b = 1;
    for (uint32_t i = 0; i < n; i++) { uint32_t c = a + b; a = b; b = c; }
    return a;
}

void main(void) {
    rand_write_output(0, fib(rand_read_input(0)));
    rand_halt();
}
```

If clang emits a call to a compiler-runtime helper (`__mulsi3` and friends are not needed on rv32im; `memcpy`/`memset` can appear for struct copies), add a tiny `rt.c` with those two next to `start.S` and compile it in; the checker will name any instruction outside the set if `-march` drifted.

- [ ] **Step 5: Install LLVM if absent, run the test, run the checker over the C image**

```bash
[ -x /opt/homebrew/opt/llvm/bin/clang ] || brew install llvm
cd rand-guest && cargo test --test build a_c_guest -- --nocapture
cargo run -- check ../guests-compiled/c-fib/target/rand-guest/guest.elf
```

Expected: PASS, and the checker reports `OK`.

- [ ] **Step 6: Commit**

```bash
git add rand-guest guests-compiled/c-fib
git commit -m "rand-guest: the C path — guest.h with the syscall wrappers, the SDK's _start, clang for rv32im linked with rust-lld, and c-fib as the fifth guest

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013dJJAGbDPDmf9i6UsXLxvB"
```

---

### Task 7: docs and the circuits AGENTS.md entry

**Files:**
- Create: `rand-guest/README.md`
- Modify: `README.md` (the crate table gains a row), `AGENTS.md` (a dated entry), `research/docs/05-roadmap.md` (v0.3 line)

- [ ] **Step 1: Write `rand-guest/README.md`**

The five subcommands with one example each, the flags table, "what check rejects", the cap flag and why it defaults to 4096 (fullnode's cap today; 65 535 on the v0.3 chain), the C prerequisites (`brew install llvm`, `rustup component add llvm-tools`), and the byte-identity rule for the committed guests.

- [ ] **Step 2: The crate table and AGENTS.md**

Add the row `| \`rand-guest\` | the guest toolchain: build (Rust, C), check, pack, run, info |` to the root README's table in the same shape as the others. In `AGENTS.md`, a dated entry in the file's voice: what landed, the byte-identity gate, the one trap (a guest with a data segment needs its own `.ld` with `ORIGIN` raised, and `rand-guest` picks the one `.ld` in the guest dir).

- [ ] **Step 3: Commit**

```bash
git add rand-guest/README.md README.md AGENTS.md research/docs/05-roadmap.md
git commit -m "docs: rand-guest — the toolchain's README, the crate row, the AGENTS.md entry, the v0.3 roadmap line

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013dJJAGbDPDmf9i6UsXLxvB"
```
