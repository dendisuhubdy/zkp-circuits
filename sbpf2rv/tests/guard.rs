//! The ELF guard (`shim::view_words`/`view_digest`) and the translation's determinism. The guard
//! binds the *loaded program* — text, read-only run, addresses, entry — so any ELF that loads to a
//! different program (one text or rodata byte, a different entry, a different program of the same
//! length) has a different digest, and any ELF that loads to the same program (header padding the
//! loader never reads) has the same one. `tests/parity.rs` checks the refusal end to end on the
//! real image; this file pins the digest itself, cheaply, on hand-built files and the committed
//! SPL Token ELF, and that `sbpf2rv` is byte-for-byte deterministic.

#[path = "../../research/tests/common/sbpf_elf_builder.rs"]
#[rustfmt::skip] // research's file, formatted (or not) by research
#[allow(dead_code)]
mod builder;

use builder::{build_elf, TEXT_ADDR};
use sbpf2rv::emit::emit_program;
use sbpf2rv::scan::scan;
use sbpf2rv::shim::{
    chained_digest, crate_name, view_digest, view_digest_c, view_words, write_crate, DIGEST_CHUNK,
    TEXT_NOT_IN_RODATA,
};
use sbpf_core::elf::Program;
use sbpf_core::isa::{self, opc, Insn};
use sbpf_core::memory::REGION_PROGRAM;
use std::path::{Path, PathBuf};
use std::process::Command;

fn i(opc: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
    Insn {
        opc,
        dst,
        src,
        off,
        imm,
    }
}

fn text(insns: &[Insn]) -> Vec<u8> {
    insns
        .iter()
        .flat_map(|i| isa::encode(*i).to_le_bytes())
        .collect()
}

fn small(imm: i32, rodata: &[u8], entry: usize) -> Vec<u8> {
    build_elf(
        &text(&[i(opc::MOV64_IMM, 0, 0, 0, imm), i(opc::EXIT, 0, 0, 0, 0)]),
        rodata,
        &[],
        &[],
        entry,
    )
}

fn digest_of(elf: &[u8]) -> [u32; 8] {
    let mut e = elf.to_vec();
    view_digest(&sbpf_core::elf::load(&mut e).unwrap())
}

fn words_of(elf: &[u8]) -> Vec<u32> {
    let mut e = elf.to_vec();
    view_words(&sbpf_core::elf::load(&mut e).unwrap())
}

/// `name`'s `(sh_offset, sh_size)` in an ELF64 file.
fn section(elf: &[u8], name: &str) -> (usize, usize) {
    let u16_at = |o: usize| u16::from_le_bytes(elf[o..o + 2].try_into().unwrap()) as usize;
    let u32_at = |o: usize| u32::from_le_bytes(elf[o..o + 4].try_into().unwrap()) as usize;
    let u64_at = |o: usize| u64::from_le_bytes(elf[o..o + 8].try_into().unwrap()) as usize;
    let (shoff, shnum, shstrndx) = (u64_at(0x28), u16_at(0x3c), u16_at(0x3e));
    let hdr = |k: usize| shoff + k * 64;
    let strtab = u64_at(hdr(shstrndx) + 0x18);
    (0..shnum)
        .find_map(|k| {
            let at = strtab + u32_at(hdr(k));
            let end = at + elf[at..].iter().position(|&b| b == 0).unwrap();
            (&elf[at..end] == name.as_bytes())
                .then(|| (u64_at(hdr(k) + 0x18), u64_at(hdr(k) + 0x20)))
        })
        .unwrap_or_else(|| panic!("no {name} section"))
}

fn spl_token() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../guests-compiled/sbpf/programs/spl_token.so"
    ))
    .expect("the committed SPL Token ELF")
}

fn work(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/guard")
        .join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

// ---- the view ---------------------------------------------------------------------------------------

#[test]
fn the_view_is_the_header_then_the_read_only_run_packed_once() {
    let rodata = [1u8, 2, 3, 4, 5, 6, 7, 8, 9];
    let w = words_of(&small(7, &rodata, 1));
    let t = text(&[i(opc::MOV64_IMM, 0, 0, 0, 7), i(opc::EXIT, 0, 0, 0, 0)]);
    // The run: the 16-byte text, then the 9 data bytes at the next 8-aligned address (no gap
    // here), 25 bytes: 7 words, the last zero-padded.
    let va = REGION_PROGRAM + TEXT_ADDR;
    assert_eq!(
        &w[..8],
        &[
            va as u32,
            (va >> 32) as u32,
            16,
            va as u32,
            (va >> 32) as u32,
            25,
            1,
            0
        ]
    );
    assert_eq!(w.len(), 8 + 7);
    let mut run = t.clone();
    run.extend_from_slice(&rodata);
    run.resize(28, 0);
    let packed: Vec<u32> = run
        .chunks(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect();
    assert_eq!(&w[8..], &packed[..]);
}

#[test]
fn a_text_that_is_not_a_span_of_the_run_is_hashed_after_it() {
    let t = text(&[i(opc::EXIT, 0, 0, 0, 0)]);
    let data = [0xABu8; 12];
    let p = Program {
        text: &t,
        text_va: REGION_PROGRAM,
        rodata: &data,
        rodata_va: REGION_PROGRAM + 0x1000,
        entry_pc: 0,
        relocs_applied: false,
    };
    let w = view_words(&p);
    assert_eq!(w[7], TEXT_NOT_IN_RODATA);
    assert_eq!(w.len(), 8 + 3 + 2);
    assert_eq!(&w[8..11], &[0xABAB_ABAB; 3]);
    assert_eq!(&w[11..], &[0x95, 0]);
    // `Program::from_text`: the text is the run, at offset 0, hashed once.
    let p = Program::from_text(&t).unwrap();
    let w = view_words(&p);
    assert_eq!(w[7], 0);
    assert_eq!(w.len(), 8 + 2);
}

// ---- what changes the digest -----------------------------------------------------------------------

#[test]
fn one_text_byte_anywhere_changes_the_digest() {
    let base = small(7, &[9; 8], 0);
    let d0 = digest_of(&base);
    let (off, len) = section(&base, ".text");
    assert_eq!(len, 16);
    let mut seen = vec![d0];
    for k in 0..len {
        let mut elf = base.clone();
        elf[off + k] ^= 0x01;
        // Not every flip loads (the opcode byte of a slot may become unassigned — still loads,
        // the loader checks no semantics — but a `call` nibble above 1 would not); these all do.
        let d = digest_of(&elf);
        assert!(!seen.contains(&d), "byte {k}");
        seen.push(d);
    }
}

#[test]
fn one_rodata_byte_changes_the_digest_and_the_entry_alone_does_too() {
    let a = small(7, &[9; 8], 0);
    let mut b = small(7, &[9; 8], 0);
    let (off, _) = section(&b, ".rodata");
    b[off + 3] ^= 0x80;
    assert_ne!(digest_of(&a), digest_of(&b));
    let c = small(7, &[9; 8], 1);
    let (wa, wc) = (words_of(&a), words_of(&c));
    assert_eq!(wa.len(), wc.len());
    let differing: Vec<usize> = (0..wa.len()).filter(|&k| wa[k] != wc[k]).collect();
    assert_eq!(differing, vec![6], "only the entry word");
    assert_ne!(digest_of(&a), digest_of(&c));
}

#[test]
fn a_different_program_of_the_same_length_is_a_different_digest() {
    let a = digest_of(&small(7, &[], 0));
    let b = digest_of(&small(8, &[], 0));
    let c = {
        let mut e = build_elf(
            &text(&[i(opc::MOV64_IMM, 1, 0, 0, 7), i(opc::EXIT, 0, 0, 0, 0)]),
            &[],
            &[],
            &[],
            0,
        );
        view_digest(&sbpf_core::elf::load(&mut e).unwrap())
    };
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(b, c);
    assert_eq!(
        a,
        digest_of(&small(7, &[], 0)),
        "and the same program is the same digest"
    );
}

#[test]
fn bytes_the_loader_never_reads_do_not_change_the_digest() {
    let base = small(7, &[9; 8], 0);
    let d0 = digest_of(&base);
    for (what, at) in [("EI_PAD", 12usize), ("EI_PAD last", 15), ("e_version", 20)] {
        let mut elf = base.clone();
        elf[at] ^= 0x5a;
        assert_eq!(words_of(&elf), words_of(&base), "{what}");
        assert_eq!(digest_of(&elf), d0, "{what}");
    }
    // The section header string table's own name is read by nobody either.
    let mut elf = base.clone();
    let at = elf.windows(10).position(|w| w == b".shstrtab\0").unwrap();
    elf[at + 1] = b'S';
    assert_eq!(digest_of(&elf), d0);
}

#[test]
fn the_spl_token_digest_changes_with_one_text_byte_the_transfer_never_runs() {
    let base = spl_token();
    let d0 = digest_of(&base);
    let (off, len) = section(&base, ".text");
    let mut elf = base.clone();
    // The high byte of the last slot's immediate — well past the transfer's code.
    elf[off + len - 1] ^= 0x01;
    assert_ne!(digest_of(&elf), d0);
    let mut elf = base.clone();
    elf[12] ^= 0x5a;
    assert_eq!(digest_of(&elf), d0, "the parity test's padding twin");
    // The README's figures: an 8-word header and the run's 26 364 words, more than one chunk.
    let w = words_of(&base);
    assert_eq!(w.len(), 8 + 26_364);
    assert!(w.len() > DIGEST_CHUNK);
    assert_ne!(
        d0,
        rand_zkvm::hash::sponge_hash(&w),
        "chained, not one call"
    );
}

// ---- the chain -------------------------------------------------------------------------------------

#[test]
fn the_chained_digest_is_one_sponge_call_up_to_a_chunk_and_a_manual_chain_past_it() {
    let words =
        |n: usize| -> Vec<u32> { (0..n as u32).map(|k| k.wrapping_mul(0x9e37_79b9)).collect() };
    for n in [1, 8, DIGEST_CHUNK - 1, DIGEST_CHUNK] {
        let w = words(n);
        assert_eq!(chained_digest(&w), rand_zkvm::hash::sponge_hash(&w), "{n}");
    }
    // Two calls: the second over the first digest and the remaining words.
    for n in [DIGEST_CHUNK + 1, DIGEST_CHUNK + 100, 2 * DIGEST_CHUNK - 8] {
        let w = words(n);
        let d1 = rand_zkvm::hash::sponge_hash(&w[..DIGEST_CHUNK]);
        let mut msg = d1.to_vec();
        msg.extend_from_slice(&w[DIGEST_CHUNK..]);
        assert_eq!(
            chained_digest(&w),
            rand_zkvm::hash::sponge_hash(&msg),
            "{n}"
        );
        assert_ne!(chained_digest(&w), rand_zkvm::hash::sponge_hash(&w), "{n}");
    }
    // Three calls: 4096, then 4088, then the rest.
    let n = 2 * DIGEST_CHUNK - 7;
    let w = words(n);
    let d1 = rand_zkvm::hash::sponge_hash(&w[..DIGEST_CHUNK]);
    let mut m2 = d1.to_vec();
    m2.extend_from_slice(&w[DIGEST_CHUNK..2 * DIGEST_CHUNK - 8]);
    let d2 = rand_zkvm::hash::sponge_hash(&m2);
    let mut m3 = d2.to_vec();
    m3.extend_from_slice(&w[2 * DIGEST_CHUNK - 8..]);
    assert_eq!(chained_digest(&w), rand_zkvm::hash::sponge_hash(&m3));
}

#[test]
fn the_c_constant_is_the_eight_words_as_hex() {
    let c = view_digest_c(&[0, 1, 0xdead_beef, u32::MAX, 4, 5, 6, 7]);
    assert!(c.ends_with(
        "const uint32_t sbpf_view_digest[8] = {0x00000000u, 0x00000001u, 0xdeadbeefu, 0xffffffffu, 0x00000004u, 0x00000005u, 0x00000006u, 0x00000007u};\n"
    ), "{c}");
    assert!(
        c.starts_with("\n/* The ELF guard (sbpf2rv::shim::view_digest)"),
        "{c}"
    );
}

// ---- determinism --------------------------------------------------------------------------------------

#[test]
fn emitting_the_same_program_twice_is_byte_identical() {
    let mut e = spl_token();
    let p = sbpf_core::elf::load(&mut e).unwrap();
    let a = emit_program(&p, &scan(&p));
    let b = emit_program(&p, &scan(&p));
    assert_eq!(a.c, b.c);
    assert_eq!(
        (a.functions, a.blocks, a.instructions),
        (b.functions, b.blocks, b.instructions)
    );
    // The README's walkthrough counts.
    assert_eq!((a.functions, a.blocks, a.instructions), (30, 3546, 12061));
}

#[test]
fn write_crate_is_deterministic_and_ends_program_c_with_the_guard() {
    let mut e = small(7, &[], 0);
    let p = sbpf_core::elf::load(&mut e).unwrap();
    let c = emit_program(&p, &scan(&p)).c;
    let d = view_digest(&p);
    let (a, b) = (work("crate-a"), work("crate-b"));
    write_crate(&a, "guard-test", &c, &d).unwrap();
    write_crate(&b, "guard-test", &c, &d).unwrap();
    for f in [
        "program.c",
        "Cargo.toml",
        "Cargo.lock",
        "build.rs",
        "src/main.rs",
        "shim.ld",
    ] {
        assert_eq!(
            std::fs::read(a.join(f)).unwrap(),
            std::fs::read(b.join(f)).unwrap(),
            "{f}"
        );
    }
    let pc = std::fs::read_to_string(a.join("program.c")).unwrap();
    assert!(pc.starts_with(&c));
    assert!(pc.ends_with(&view_digest_c(&d)));
    let toml = std::fs::read_to_string(a.join("Cargo.toml")).unwrap();
    assert!(toml.contains("name = \"guard-test\""));
    // Both crates sit four levels below the checkout root (sbpf2rv/target/guard/crate-a): the
    // relative paths say so.
    assert!(
        toml.contains("sbpf-core = { path = \"../../../../guests-compiled/sbpf-core\" }"),
        "{toml}"
    );
}

#[test]
fn the_cli_translates_the_same_elf_to_the_same_bytes_twice() {
    let elf = small(7, &[3; 8], 0);
    let src = work("cli-src").join("p.so");
    std::fs::write(&src, &elf).unwrap();
    let (a, b) = (work("cli-a"), work("cli-b"));
    for out in [&a, &b] {
        let o = Command::new(env!("CARGO_BIN_EXE_sbpf2rv"))
            .arg(&src)
            .arg("--out")
            .arg(out)
            .args(["--name", "twin"])
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    }
    for f in [
        "program.c",
        "Cargo.toml",
        "Cargo.lock",
        "build.rs",
        "src/main.rs",
        "shim.ld",
    ] {
        assert_eq!(
            std::fs::read(a.join(f)).unwrap(),
            std::fs::read(b.join(f)).unwrap(),
            "{f}"
        );
    }
    let pc = std::fs::read_to_string(a.join("program.c")).unwrap();
    assert!(
        pc.ends_with(&view_digest_c(&digest_of(&elf))),
        "the guard is the ELF's digest"
    );
}

#[test]
fn crate_name_normalises_a_file_stem() {
    assert_eq!(crate_name("spl_token"), "spl_token");
    assert_eq!(crate_name("Spl Token.v2"), "spl-token-v2");
    assert_eq!(crate_name("1abc"), "sbpf-1abc");
    assert_eq!(crate_name("-x"), "sbpf--x");
    assert_eq!(crate_name(""), "sbpf-");
    assert_eq!(crate_name("fine-name"), "fine-name");
}
