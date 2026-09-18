//! The packer reproduces the committed images from the guests' ELFs. The ELFs are built here by
//! `build::build_rust`, the one cargo invocation the tool has, so this test needs the riscv32im
//! target and llvm-tools installed (`rustup +1.98.1 target add …`).

use std::path::PathBuf;
use rand_zkvm::isa::Program;

fn root() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..") }

/// Builds a guest and packs it, through the tool itself: `build_rust` generates the whole
/// rustflags set (`-T`, the target feature, the remap) and passes it as `--config`. No guest
/// carries rustflags of its own any more — cargo *merges* `--config` rustflags with a
/// `.cargo/config.toml`'s rather than overriding them, so a guest that also carried them would
/// link with a duplicate `-T` ("region 'RAM' already defined").
fn build_guest_image(name: &str) -> Vec<u8> {
    let dir = root().join("guests-compiled").join(name);
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join(format!("{name}.bin"));
    rand_guest::build::build_rust(&dir, None, &out).expect("building the guest");
    std::fs::read(&out).unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}

fn pinned(name: &str) -> String {
    let text = std::fs::read_to_string(root().join("guests-compiled/bin").join(format!("{name}.bin.sha256"))).unwrap();
    text.split_whitespace().next().unwrap().to_string()
}

fn pinned_bytes(name: &str) -> Vec<u8> {
    std::fs::read(root().join("guests-compiled/bin").join(format!("{name}.bin"))).unwrap()
}

#[test]
fn the_packer_reproduces_every_committed_image() {
    // Two gates, because the four pins are two different formats. `evm` and `sbpf` have a data
    // segment, so their Makefiles run the ELF through `mkimage.py` (`pack`'s Rust port); those two
    // are gated byte for byte against the committed `.bin.sha256`. `fib` and `keccak256` have no
    // data segment at all, so their Makefiles just `objcopy -O binary` the ELF — a headerless flat
    // binary loaded by `Program::from_flat_binary(0x1000, …)` (`research/src/guests.rs`, pinned
    // again by `research/tests/isa.rs`) — and that pin is a shared fixture this task does not
    // touch. `pack()` still emits the one container format the spec gives it, even with no data
    // segment, but `Program::from_flat_image`'s `n_data = 0` case is defined to decode to the
    // word-for-word same `Program` as `from_flat_binary` on the same text — so `fib`/`keccak256`
    // are gated at the program level instead: same `base_pc`, same `words`, same `digest()`.
    for name in ["fib", "keccak256", "evm", "sbpf"] {
        let image = build_guest_image(name);
        if name == "fib" || name == "keccak256" {
            let from_image = Program::from_flat_image(&image).unwrap();
            let from_flat = Program::from_flat_binary(0x1000, &pinned_bytes(name)).unwrap();
            assert_eq!(from_image, from_flat, "{name}: Program");
            assert_eq!(from_image.digest(), from_flat.digest(), "{name}: digest");
        } else {
            assert_eq!(sha256_hex(&image), pinned(name), "{name}.bin");
        }
        let info = rand_guest::pack::describe(&image).unwrap();
        assert!(info.n_text > 0);
    }
}

#[test]
fn a_non_elf_is_refused_by_name() {
    let err = rand_guest::pack::pack(b"not an elf at all").unwrap_err().to_string();
    assert!(err.contains("ELF32"), "{err}");
}

// --- Minimal ELF32-LE builders, no compiler: a 52-byte header, a 24-byte-entry section table,
// and (where needed) a short string table — just enough for `read_sections`/`pack` to parse a
// structurally plausible but corrupt file, without ever needing a real object.

/// A 52-byte (`0x34`) ELF32-LE header naming the section table (`e_shoff`/`e_shentsize`/
/// `e_shnum`/`e_shstrndx`) at the offsets `elf::read_sections` reads them from.
fn elf_header(e_shoff: u32, e_shentsize: u16, e_shnum: u16, e_shstrndx: u16) -> Vec<u8> {
    let mut h = vec![0u8; 0x34];
    h[0..4].copy_from_slice(b"\x7fELF");
    h[4] = 1; // EI_CLASS = ELFCLASS32
    h[5] = 1; // EI_DATA = ELFDATA2LSB
    h[0x20..0x24].copy_from_slice(&e_shoff.to_le_bytes());
    h[0x2e..0x30].copy_from_slice(&e_shentsize.to_le_bytes());
    h[0x30..0x32].copy_from_slice(&e_shnum.to_le_bytes());
    h[0x32..0x34].copy_from_slice(&e_shstrndx.to_le_bytes());
    h
}

/// A 24-byte `Elf32_Shdr` prefix: `sh_name`, `sh_type`, `sh_flags`, `sh_addr`, `sh_offset`,
/// `sh_size` — the six fields `elf::read_sections` reads (it never touches `sh_link` onward, so
/// the real 40-byte struct is not needed).
fn section_entry(name: u32, typ: u32, flags: u32, addr: u32, offset: u32, size: u32) -> [u8; 24] {
    let mut e = [0u8; 24];
    e[0..4].copy_from_slice(&name.to_le_bytes());
    e[4..8].copy_from_slice(&typ.to_le_bytes());
    e[8..12].copy_from_slice(&flags.to_le_bytes());
    e[12..16].copy_from_slice(&addr.to_le_bytes());
    e[16..20].copy_from_slice(&offset.to_le_bytes());
    e[20..24].copy_from_slice(&size.to_le_bytes());
    e
}

const SHT_PROGBITS: u32 = 1;
const SHF_ALLOC: u32 = 0x2;

#[test]
fn a_text_span_past_the_end_of_the_file_is_refused_not_panicked() {
    // header(52) + 2 section entries(24 each) = 100, then a 7-byte string table ("\0.text\0").
    // Section 0 doubles as the string table (e_shstrndx = 0), its `sh_offset`/`sh_size` pointing
    // at those 7 bytes. Section 1 is ".text": PROGBITS, ALLOC, word-aligned addr and size, but its
    // `sh_offset` (107, the end of this file) plus its `sh_size` (64) reaches 171 — past the
    // file's actual 107 bytes. `read_sections` parses this fine (the name resolves); `pack` must
    // then refuse it, not panic computing the span.
    let mut elf = elf_header(52, 24, 2, 0);
    elf.extend_from_slice(&section_entry(0, 3, 0, 0, 100, 7)); // section 0: the string table
    elf.extend_from_slice(&section_entry(1, SHT_PROGBITS, SHF_ALLOC, 0x1000, 107, 64)); // .text
    elf.extend_from_slice(b"\0.text\0");
    assert_eq!(elf.len(), 107);

    let err = rand_guest::pack::pack(&elf).unwrap_err().to_string();
    assert!(err.contains("outside the file"), "{err}");
}

#[test]
fn a_section_name_past_the_string_table_is_refused_not_panicked() {
    // header(52) + 1 section entry(24) = 76 bytes total. The lone section is its own
    // (self-referential) string table via `e_shstrndx = 0`, with `sh_offset = 0` — but its
    // `sh_name` is 100000, so `read_sections`'s name lookup (`strtab_off + sh_name`) lands far
    // past the 76-byte file. Must be refused, not indexed into.
    let mut elf = elf_header(52, 24, 1, 0);
    elf.extend_from_slice(&section_entry(100_000, SHT_PROGBITS, SHF_ALLOC, 0x1000, 0, 0));
    assert_eq!(elf.len(), 76);

    let err = rand_guest::pack::pack(&elf).unwrap_err().to_string();
    assert!(err.contains("outside the file"), "{err}");
}
