//! Interpreter parity, end to end (spec §6): an ELF goes through `sbpf2rv`, the generated shim crate
//! through `rand-guest build`, and the image through `rand-guest run` with the vector's two input
//! segments (public = the ELF's words, private = the instruction's, exactly as the interpreter's own
//! tests feed them). The eight output words must equal both
//!
//! * `sbpf_core::abi::run_call` on the host (`SbpfCall::expected`), and
//! * the committed interpreter guest `guests-compiled/bin/sbpf.bin` on the emulator,
//!
//! and the halt must equal the interpreter's `Result<u64, Halt>`. The halt is compared through the
//! shim's test-only `halt-words` cargo feature (a second build of the same generated crate): with it
//! on, the image writes `[status, halt code, payload lo, payload hi, 0, 0, 0, 0]` instead of the
//! digest, where the code is the `Halt` variant's declaration index (0 = returned, payload `r0`) —
//! the same numbering as `sbpf-rt`'s `SBPF_HALT_*`, mapped back through the shim's `halt_from`.
//!
//! Vectors: the SPL Token `Transfer` (status 1), the same with too large an amount (status 0), a
//! `Transfer` with too few accounts (the program's own `NotEnoughAccountKeys`, status 0), a region
//! claiming more than `MAX_ACCOUNTS` accounts (refused by the harness before anything runs, status
//! 2), and a hand-built program that writes an account and then loads through a null pointer
//! (`Halt::AccessViolation(0)`, status 2 over the pre-state).
//!
//! Needs a clang with a RISC-V target (Homebrew LLVM's, or `$CLANG`) and the pinned toolchain's
//! `riscv32im-unknown-none-elf` target; fails loudly without either. Slow (it compiles the whole
//! translated SPL Token program twice, and runs the interpreter guest on the emulator): run it with
//! `--nocapture` to see the cycle counts and program sizes it measures.

#[path = "../../research/tests/common/sbpf_elf_builder.rs"]
#[rustfmt::skip] // research's file, formatted (or not) by research
#[allow(dead_code)]
mod builder;

use rand_zkvm::sbpf::{self, asm, insn, lddw, spl_transfer, Account, SbpfCall};
use sbpf_core::abi;
use sbpf_core::interp::Halt;
use sbpf_core::isa::{opc, Insn};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Where the generated crates go: inside the checkout (`rand-guest build` finds `guest-sdk/` by
/// walking up from the guest), under this crate's own ignored `target/`.
fn work() -> PathBuf {
    let d = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/parity");
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A nested cargo must not inherit the outer test's target directory or flags.
fn clean(c: &mut Command) -> &mut Command {
    for v in [
        "CARGO_TARGET_DIR",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_TARGET",
        "CARGO_MAKEFLAGS",
        "MAKEFLAGS",
        "MFLAGS",
    ] {
        c.env_remove(v);
    }
    c
}

/// A clang that really targets the machine — `$CLANG`, else Homebrew's — probed by compiling an
/// empty file for `riscv32-unknown-none-elf`, as build.rs will. Fails loudly otherwise: this test
/// cannot run without one (Apple's clang has no RISC-V backend).
fn require_clang() {
    let clang = std::env::var_os("CLANG").map_or_else(
        || PathBuf::from("/opt/homebrew/opt/llvm/bin/clang"),
        PathBuf::from,
    );
    let empty = work().join("empty.c");
    std::fs::write(&empty, "").unwrap();
    let o = Command::new(&clang)
        .args([
            "--target=riscv32-unknown-none-elf",
            "-march=rv32im",
            "-mabi=ilp32",
            "-c",
            "-o",
        ])
        .arg(work().join("empty.o"))
        .arg(&empty)
        .output();
    match o {
        Ok(o) if o.status.success() => {}
        Ok(o) => panic!(
            "{} cannot compile for riscv32-unknown-none-elf: {}\n`brew install llvm` or set $CLANG",
            clang.display(),
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => panic!(
            "no RISC-V clang at {} ({e}): `brew install llvm` or set $CLANG",
            clang.display()
        ),
    }
}

/// The `rand-guest` binary, built once (release: its emulator runs the interpreter guest).
fn rand_guest() -> PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let manifest = root().join("rand-guest/Cargo.toml");
        let o = clean(
            Command::new("cargo")
                .args(["+1.98.1", "build", "--release", "--manifest-path"])
                .arg(&manifest),
        )
        .output()
        .unwrap();
        assert!(
            o.status.success(),
            "building rand-guest: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        root().join("rand-guest/target/release/rand-guest")
    })
    .clone()
}

fn check(o: &std::process::Output, what: &str) -> String {
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(
        o.status.success(),
        "{what} failed:\n{out}\n{}",
        String::from_utf8_lossy(&o.stderr)
    );
    out
}

/// One translated program, built twice: the production image and the `halt-words` one.
struct Translated {
    image: PathBuf,
    halt_image: PathBuf,
    words: usize,
    hc: String,
}

fn translate(elf: &Path, name: &str) -> Translated {
    require_clang();
    let dir = work().join(name);
    let o = Command::new(env!("CARGO_BIN_EXE_sbpf2rv"))
        .arg(elf)
        .arg("--out")
        .arg(&dir)
        .args(["--name", name])
        .output()
        .unwrap();
    let report = check(&o, "sbpf2rv");
    eprintln!("sbpf2rv {}:\n{report}", elf.display());
    for f in [
        "program.c",
        "Cargo.toml",
        "Cargo.lock",
        "build.rs",
        "src/main.rs",
        "shim.ld",
    ] {
        assert!(dir.join(f).exists(), "{f} was not generated");
    }
    // What the image depends on is stated in the crate, not taken from the builder's environment:
    // exact pins, and the harness profile.
    let toml = std::fs::read_to_string(dir.join("Cargo.toml")).unwrap();
    for line in [
        "cc = \"=1.4.6\"",
        "[profile.release]\nopt-level = \"s\"",
        "[profile.release.package.\"*\"]\nopt-level = 3",
    ] {
        assert!(toml.contains(line), "Cargo.toml lacks {line:?}:\n{toml}");
    }

    // The `halt-words` twin: the same generated crate with the test-only feature on by default
    // (`rand-guest build` has no `--features`).
    let halt_dir = work().join(format!("{name}-halt"));
    let o = Command::new(env!("CARGO_BIN_EXE_sbpf2rv"))
        .arg(elf)
        .arg("--out")
        .arg(&halt_dir)
        .args(["--name", name])
        .output()
        .unwrap();
    check(&o, "sbpf2rv (halt-words twin)");
    let toml = std::fs::read_to_string(halt_dir.join("Cargo.toml")).unwrap();
    assert!(toml.contains("default = []"), "{toml}");
    std::fs::write(
        halt_dir.join("Cargo.toml"),
        toml.replace("default = []", "default = [\"halt-words\"]"),
    )
    .unwrap();

    let build = |d: &Path| -> (PathBuf, String) {
        let image = d.join("image.bin");
        let lock = std::fs::read(d.join("Cargo.lock")).expect("sbpf2rv writes Cargo.lock");
        // The cap is measured separately (`info` below), so the build itself is not refused over it.
        let o = clean(
            Command::new(rand_guest())
                .arg("build")
                .arg(d)
                .arg("--out")
                .arg(&image)
                .args(["--max-words", "1000000"]),
        )
        .output()
        .unwrap();
        let out = check(&o, &format!("rand-guest build {}", d.display()));
        let err = String::from_utf8_lossy(&o.stderr).into_owned();
        // Reproducible: the generated lock is complete, so cargo resolves nothing and rewrites
        // nothing, and the build names the clang it used.
        for word in ["Locking", "Updating"] {
            assert!(
                !err.contains(word) && !out.contains(word),
                "cargo resolved something ({word}):\n{err}"
            );
        }
        assert_eq!(
            std::fs::read(d.join("Cargo.lock")).unwrap(),
            lock,
            "the build changed Cargo.lock"
        );
        assert!(
            err.contains("sbpf2rv: clang "),
            "build.rs names its clang:\n{err}"
        );
        (image, out)
    };
    let (image, b) = build(&dir);
    eprintln!("{b}");
    let (halt_image, _) = build(&halt_dir);

    let o = Command::new(rand_guest())
        .arg("info")
        .arg(&image)
        .args(["--max-words", "65535"])
        .output()
        .unwrap();
    let info = check(&o, "rand-guest info");
    eprintln!("{info}");
    let words = info
        .lines()
        .find_map(|l| {
            l.split_once(" words against a cap of ")
                .map(|(n, _)| n.trim().parse::<usize>().unwrap())
        })
        .expect("info prints the word count");
    Translated {
        image,
        halt_image,
        words,
        hc: hc_of(&info),
    }
}

fn hc_of(info: &str) -> String {
    info.lines()
        .find_map(|l| l.strip_prefix("hc "))
        .expect("info prints hc")
        .trim()
        .to_string()
}

/// `rand-guest run`: the eight words and the cycle count.
fn run(image: &Path, call: &SbpfCall) -> ([u32; 8], usize) {
    let mut c = Command::new(rand_guest());
    c.arg("run").arg(image).arg("--public");
    for w in call.public_words() {
        c.arg(w.to_string());
    }
    c.arg("--input");
    for w in call.input_words() {
        c.arg(w.to_string());
    }
    let s = check(
        &c.output().unwrap(),
        &format!("rand-guest run {}", image.display()),
    );
    let mut out = [0u32; 8];
    for (i, w) in out.iter_mut().enumerate() {
        let tag = format!("out[{i}] = ");
        let line = s
            .lines()
            .find(|l| l.starts_with(&tag))
            .unwrap_or_else(|| panic!("no out[{i}]:\n{s}"));
        *w = line[tag.len()..].trim().parse().unwrap();
    }
    let cycles = s
        .lines()
        .find_map(|l| l.strip_prefix("cycles "))
        .expect("a cycle count")
        .trim()
        .parse()
        .unwrap();
    (out, cycles)
}

/// `Result<u64, Halt>` as the `halt-words` image writes it after `status`.
fn halt_words(r: &Result<u64, Halt>) -> [u32; 3] {
    const TRAPS: [&str; 3] = ["abort", "sol_panic_", "sol_memcpy_ overlap"];
    let (code, payload) = match *r {
        Ok(r0) => (0, r0),
        Err(Halt::Exit) => (0, 0),
        Err(Halt::AccessViolation(a)) => (1, a),
        Err(Halt::BadInsn(o)) => (2, o as u64),
        Err(Halt::DivByZero) => (3, 0),
        Err(Halt::UnknownSyscall(h)) => (4, h as u64),
        Err(Halt::CallDepth) => (5, 0),
        Err(Halt::InstructionLimit) => (6, 0),
        Err(Halt::BadElf) => (7, 0),
        Err(Halt::BadJump) => (8, 0),
        Err(Halt::StackOverflow) => (9, 0),
        Err(Halt::Trap(s)) => (
            10,
            TRAPS
                .iter()
                .position(|t| *t == s)
                .map_or(u64::MAX, |i| i as u64),
        ),
    };
    [code, payload as u32, (payload >> 32) as u32]
}

/// The whole comparison for one vector.
fn parity(
    t: &Translated,
    interp_image: Option<&Path>,
    what: &str,
    call: &SbpfCall,
    want_status: u32,
) -> Result<u64, Halt> {
    let (want, result, _) = call.expected();
    assert_eq!(want[0], want_status, "{what}: the interpreter's own status");
    let (got, cycles) = run(&t.image, call);
    assert_eq!(
        got, want,
        "{what}: translated vs sbpf_core::abi::run_call on the host"
    );
    let (halt, _) = run(&t.halt_image, call);
    let hw = halt_words(&result);
    assert_eq!(
        halt,
        [want_status, hw[0], hw[1], hw[2], 0, 0, 0, 0],
        "{what}: translated halt vs the interpreter's {result:?}"
    );
    match interp_image {
        Some(interp) => {
            let (via_interp, interp_cycles) = run(interp, call);
            assert_eq!(
                via_interp, want,
                "{what}: sbpf.bin on the emulator vs the host"
            );
            eprintln!("{what}: {result:?}, status {want_status}; cycles translated {cycles}, interpreter guest {interp_cycles}");
        }
        None => eprintln!("{what}: {result:?}, status {want_status}; cycles translated {cycles}"),
    }
    result
}

/// `hc` of the translated SPL Token image (Homebrew clang 23.1.1, rustc 1.98.1).
const SPL_TOKEN_HC: &str = "f382dd28e4c363709afed9dc7cacd11508e61739617626f7a1a4d69e93d1920e";

fn interpreter_guest() -> PathBuf {
    root().join("guests-compiled/bin/sbpf.bin")
}

#[test]
fn the_spl_token_transfer_translates_and_matches_the_interpreter_word_for_word() {
    let elf = root().join("guests-compiled/sbpf/programs/spl_token.so");
    assert_eq!(
        std::fs::read(&elf).unwrap(),
        sbpf::SPL_TOKEN_ELF,
        "the interpreter's tests use this file"
    );
    let t = translate(&elf, "spl-token");
    eprintln!(
        "translated SPL Token: {} program words (cap 65 535), hc {}",
        t.words, t.hc
    );
    assert!(
        t.words <= 65_535,
        "the translated SPL Token program is {} words, over the machine's cap",
        t.words
    );

    // Reproducible: a verifier regenerating the crate somewhere else gets the same image (the paths
    // into the checkout are relative, and both compilers remap the checkout's own path).
    let elsewhere = work().join("repro/one/level/deeper");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let dir = elsewhere.join("spl-token");
    let o = Command::new(env!("CARGO_BIN_EXE_sbpf2rv"))
        .arg(&elf)
        .arg("--out")
        .arg(&dir)
        .args(["--name", "spl-token"])
        .output()
        .unwrap();
    check(&o, "sbpf2rv (elsewhere)");
    let image = dir.join("image.bin");
    // … and with C flags in the environment, under every spelling `cc` reads: build.rs removes them.
    let o = clean(
        Command::new(rand_guest())
            .arg("build")
            .arg(&dir)
            .arg("--out")
            .arg(&image)
            .args(["--max-words", "65535"])
            .env("CFLAGS", "-O0 -g")
            .env("TARGET_CFLAGS", "-DSBPF_USIZE_MAX=1")
            .env("CFLAGS_riscv32im_unknown_none_elf", "-O3")
            .env("CFLAGS_riscv32im-unknown-none-elf", "-fno-inline"),
    )
    .output()
    .unwrap();
    check(&o, "rand-guest build (elsewhere, with CFLAGS)");
    let o = Command::new(rand_guest())
        .arg("info")
        .arg(&image)
        .output()
        .unwrap();
    assert_eq!(
        hc_of(&check(&o, "rand-guest info (elsewhere)")),
        t.hc,
        "the image depends on where it was generated"
    );
    // The image is pinned: a change to the emitter, the runtime, the harness or the toolchain that
    // moves it has to update this line on purpose.
    assert_eq!(t.hc, SPL_TOKEN_HC, "the translated SPL Token image moved");
    let interp = interpreter_guest();

    // The transfer.
    assert_eq!(
        parity(&t, Some(&interp), "transfer 250", &spl_transfer(250), 1),
        Ok(0)
    );

    // Too much: `InsufficientFunds`, a non-zero r0, status 0 over the pre-state.
    let r = parity(
        &t,
        Some(&interp),
        "transfer too much",
        &spl_transfer(u64::MAX / 2),
        0,
    );
    assert!(matches!(r, Ok(c) if c != 0), "{r:?}");

    // A bad account count, two ways. Too few for `Transfer` — the program's own error:
    let full = spl_transfer(250);
    let accounts: Vec<Account> = sbpf::deserialize_accounts(&full.input);
    let (data, id) = sbpf::deserialize_instruction(&full.input);
    let short = SbpfCall {
        elf: full.elf.clone(),
        input: sbpf::serialize_aligned(&accounts[..2], &data, &id),
    };
    let r = parity(&t, Some(&interp), "transfer with two accounts", &short, 0);
    assert!(matches!(r, Ok(c) if c != 0), "{r:?}");
    // And more than `MAX_ACCOUNTS` claimed: the harness refuses the region before anything runs.
    let mut over = full.clone();
    over.input[0..8].copy_from_slice(&(abi::MAX_ACCOUNTS as u64 + 1).to_le_bytes());
    assert_eq!(
        parity(
            &t,
            Some(&interp),
            "an account count above MAX_ACCOUNTS",
            &over,
            2
        ),
        Err(Halt::BadElf)
    );
}

/// A program that writes account 0's lamports and then loads through `r0` (zero): the write
/// happened, the halt is `AccessViolation(0)`, and the published post-state is the pre-state.
#[test]
fn an_access_violation_halts_exactly_as_the_interpreter_does() {
    const LAMPORTS_AT: i16 = 8 + 8 + 32 + 32;
    let mut p: Vec<[u8; 8]> = Vec::new();
    p.extend_from_slice(&lddw(2, 999));
    p.push(insn(opc::ST_DW_REG, 1, 2, LAMPORTS_AT, 0));
    p.push(insn(opc::LD_DW_REG, 3, 0, 0, 0));
    p.push(insn(opc::EXIT, 0, 0, 0, 0));
    let elf = builder::build_elf(&asm(&p), &[], &[], &[], 0);
    let path = work().join("access-violation.so");
    std::fs::write(&path, &elf).unwrap();
    let t = translate(&path, "access-violation");

    let full = spl_transfer(250);
    let call = SbpfCall {
        elf,
        input: full.input.clone(),
    };
    assert_eq!(
        parity(
            &t,
            Some(&interpreter_guest()),
            "load through a null pointer",
            &call,
            2
        ),
        Err(Halt::AccessViolation(0))
    );
}

// ---- the call and budget vectors (fix round 1) ------------------------------------------------

/// A tiny assembler with labels, for the one hand-built program that carries every call and budget
/// vector (a case selector in the instruction data picks which), so one image serves them all.
enum It {
    /// One instruction.
    I(Insn),
    /// `lddw dst, imm`.
    Lddw(u8, u64),
    /// A jump (`ja` or conditional, immediate form) to a label.
    J {
        opc: u8,
        dst: u8,
        imm: i32,
        to: String,
    },
    /// An internal `call` to a label.
    Call(String),
    /// `lddw dst, <the label's address>` — a function pointer for `callx`.
    Addr(u8, String),
    /// A label.
    L(String),
}

fn ins(opc: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
    Insn {
        opc,
        dst,
        src,
        off,
        imm,
    }
}

fn assemble(items: &[It], text_va: u64) -> Vec<u8> {
    use std::collections::HashMap;
    let mut at: HashMap<&str, usize> = HashMap::new();
    let mut pc = 0;
    for it in items {
        match it {
            It::L(l) => assert!(at.insert(l, pc).is_none(), "label {l} twice"),
            It::Lddw(..) | It::Addr(..) => pc += 2,
            _ => pc += 1,
        }
    }
    let rel = |to: &str, pc: usize| at[to] as i64 - (pc as i64 + 1);
    let lddw = |d: u8, v: u64| {
        [
            ins(opc::LD_DW_IMM, d, 0, 0, v as u32 as i32),
            ins(0, 0, 0, 0, (v >> 32) as u32 as i32),
        ]
    };
    let mut out: Vec<Insn> = Vec::new();
    for it in items {
        let pc = out.len();
        match it {
            It::I(i) => out.push(*i),
            It::Lddw(d, v) => out.extend(lddw(*d, *v)),
            It::J { opc, dst, imm, to } => out.push(ins(*opc, *dst, 0, rel(to, pc) as i16, *imm)),
            It::Call(to) => out.push(ins(opc::CALL_IMM, 0, 0, 0, rel(to, pc) as i32)),
            It::Addr(d, to) => out.extend(lddw(*d, text_va + 8 * at[to.as_str()] as u64)),
            It::L(_) => {}
        }
    }
    out.iter()
        .flat_map(|i| sbpf_core::isa::encode(*i).to_le_bytes())
        .collect()
}

/// The dead instructions padding each big budget-loop iteration: charged like any other (the
/// interpreter counts them) but deleted by clang, so 200 000 sBPF instructions cost the translated
/// image few enough cycles to fit the machine's largest tier.
const PAD: usize = 18;

/// The vector program. `main` loads `case`, `a`, `b`, `c` (u64s at `r1 + 16..48`, the instruction
/// data of a region with no accounts) into r2..r5 and jumps to the case.
fn vector_program() -> Vec<It> {
    use It::*;
    let l = |s: &str| L(s.to_string());
    let j = |opc: u8, dst: u8, imm: i32, to: &str| J {
        opc,
        dst,
        imm,
        to: to.to_string(),
    };
    let call = |to: &str| Call(to.to_string());
    let i = |opc: u8, dst: u8, src: u8, off: i16, imm: i32| I(ins(opc, dst, src, off, imm));
    let exit = || I(ins(opc::EXIT, 0, 0, 0, 0));
    let mov = |d: u8, v: i32| I(ins(opc::MOV64_IMM, d, 0, 0, v));
    let movr = |d: u8, s: u8| I(ins(opc::MOV64_REG, d, s, 0, 0));
    let add = |d: u8, s: u8| I(ins(opc::ADD64_REG, d, s, 0, 0));
    let lsh = |d: u8, v: i32| I(ins(opc::LSH64_IMM, d, 0, 0, v));

    let cases = [
        (1, "c_stb"),
        (2, "c_sth"),
        (3, "c_stw"),
        (4, "c_stdw"),
        (5, "c_regs_in"),
        (6, "c_some_out"),
        (7, "c_member"),
        (8, "c_member_x"),
        (9, "c_host"),
        (10, "c_depth"),
        (11, "c_r10"),
        (12, "c_budget"),
        (13, "c_av"),
        (14, "c_badinsn"),
        (15, "c_stimm"),
        (16, "c_host_x"),
    ];
    let mut p = vec![
        l("main"),
        i(opc::LD_DW_REG, 2, 1, 16, 0),
        i(opc::LD_DW_REG, 3, 1, 24, 0),
        i(opc::LD_DW_REG, 4, 1, 32, 0),
        i(opc::LD_DW_REG, 5, 1, 40, 0),
    ];
    for (k, to) in cases {
        p.push(j(opc::JEQ_IMM, 2, k, to));
    }
    p.extend([mov(0, 0xdead), exit()]);

    // A callee that reads its argument (r3, set only by the caller) only through a store.
    for (w, st, ld) in [
        ("b", opc::ST_B_REG, opc::LD_B_REG),
        ("h", opc::ST_H_REG, opc::LD_H_REG),
        ("w", opc::ST_W_REG, opc::LD_W_REG),
        ("dw", opc::ST_DW_REG, opc::LD_DW_REG),
    ] {
        p.extend([
            l(&format!("c_st{w}")),
            Lddw(3, 0x1122_3344_5566_7788),
            call(&format!("f_st{w}")),
            exit(),
        ]);
        p.extend([
            l(&format!("f_st{w}")),
            i(st, 10, 3, -8, 0),
            i(ld, 0, 10, -8, 0),
            exit(),
        ]);
    }
    // A store immediate whose encoding carries src = 3: nothing but its base is read.
    p.extend([l("c_stimm"), mov(3, 0x42), call("f_stimm"), exit()]);
    p.extend([
        l("f_stimm"),
        i(opc::ST_DW_IMM, 10, 3, -8, 0x77),
        i(opc::LD_DW_REG, 0, 10, -8, 0),
        exit(),
    ]);

    // A callee that reads r0 and r6..r9 before writing them, then clobbers r6..r9 (which the
    // caller must get back as they were).
    p.extend([
        l("c_regs_in"),
        mov(0, 1),
        mov(6, 2),
        mov(7, 3),
        mov(8, 4),
        mov(9, 5),
        call("f_regs_in"),
    ]);
    p.extend([add(0, 6), movr(1, 9), lsh(1, 40), add(0, 1), exit()]);
    p.push(l("f_regs_in"));
    for (r, sh) in [(6, 8), (7, 16), (8, 24), (9, 32)] {
        p.extend([movr(1, r), lsh(1, sh), add(0, 1)]);
    }
    p.extend([mov(6, 0), mov(7, 0), mov(8, 0), mov(9, 0), exit()]);

    // A callee that writes only some of r0..r5 — r3 only on one path, chosen by `b` (in r4).
    p.extend([
        l("c_some_out"),
        mov(0, 0),
        mov(1, 1),
        mov(2, 2),
        mov(3, 3),
        mov(5, 5),
        call("f_some"),
    ]);
    for (r, sh) in [(1, 4), (2, 8), (3, 16), (4, 24), (5, 32)] {
        p.extend([movr(6, r), lsh(6, sh), add(0, 6)]);
    }
    p.push(exit());
    p.extend([
        l("f_some"),
        j(opc::JEQ_IMM, 4, 4, "some_skip"),
        mov(3, 9),
        l("some_skip"),
        mov(2, 7),
        mov(0, 0x50),
        exit(),
    ]);

    // A function inside another's code (merged into it): called directly and through callx, and
    // its host called both ways too.
    p.extend([
        l("f_host"),
        mov(0, 100),
        l("f_member"),
        i(opc::ADD64_IMM, 0, 0, 0, 5),
        exit(),
    ]);
    p.extend([l("c_member"), mov(0, 1000), call("f_member"), exit()]);
    p.extend([
        l("c_member_x"),
        mov(0, 2000),
        Addr(5, "f_member".into()),
        i(opc::CALL_REG, 0, 0, 0, 5),
        exit(),
    ]);
    p.extend([l("c_host"), mov(0, 0), call("f_host"), exit()]);
    p.extend([
        l("c_host_x"),
        Addr(5, "f_host".into()),
        i(opc::CALL_REG, 0, 0, 0, 5),
        exit(),
    ]);

    // Recursion `a` levels below the case's own call: depth a + 1; the 8th push is CallDepth.
    p.extend([l("c_depth"), movr(1, 3), call("f_rec"), exit()]);
    p.extend([
        l("f_rec"),
        j(opc::JEQ_IMM, 1, 0, "rec_done"),
        i(opc::SUB64_IMM, 1, 0, 0, 1),
        call("f_rec"),
    ]);
    p.extend([l("rec_done"), mov(0, 0x55), exit()]);

    // A program that moves r10: the callee's frame is one frame above the *moved* r10, and the
    // caller gets its moved r10 back. r0 = 4096 + 0x33.
    p.extend([
        l("c_r10"),
        i(opc::ADD64_IMM, 10, 0, 0, -512),
        i(opc::ST_DW_IMM, 10, 0, -8, 0x33),
        call("f_r10"),
        i(opc::SUB64_REG, 0, 10, 0, 0),
        i(opc::LD_DW_REG, 2, 10, -8, 0),
        add(0, 2),
        exit(),
    ]);
    p.extend([
        l("f_r10"),
        movr(0, 10),
        i(opc::ST_DW_IMM, 10, 0, -8, 1),
        exit(),
    ]);

    // The budget: one optional instruction (c != 0), `b` iterations of a 2-instruction loop, then
    // `a` iterations of a (3 + PAD)-instruction loop in two blocks, then `r0 = 0; exit`.
    p.extend([l("c_budget"), j(opc::JEQ_IMM, 5, 0, "b_small"), mov(7, 0)]);
    p.extend([
        l("b_small"),
        i(opc::SUB64_IMM, 4, 0, 0, 1),
        j(opc::JNE_IMM, 4, 0, "b_small"),
    ]);
    p.extend([
        l("b_big"),
        i(opc::SUB64_IMM, 3, 0, 0, 1),
        j(opc::JEQ_IMM, 3, 0, "b_done"),
    ]);
    for k in 0..PAD {
        p.push(mov(7, k as i32));
    }
    p.extend([j(opc::JA, 0, 0, "b_big"), l("b_done"), mov(0, 0), exit()]);

    // A fault's payload, and a refused opcode.
    p.extend([l("c_av"), i(opc::LD_DW_REG, 3, 0, 0x123, 0), exit()]);
    p.extend([l("c_badinsn"), mov(0, 0), i(0xff, 0, 0, 0, 0), exit()]);
    p
}

fn vector_call(elf: &[u8], case: u64, a: u64, b: u64, c: u64) -> SbpfCall {
    let data: Vec<u8> = [case, a, b, c]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    SbpfCall {
        elf: elf.to_vec(),
        input: sbpf::serialize_aligned(&[], &data, &[9u8; 32]),
    }
}

/// How many instructions the interpreter executes on a vector (natively).
fn instructions(call: &SbpfCall) -> u64 {
    sbpf::run_elf(&mut call.elf.clone(), &mut call.input.clone()).instructions
}

/// Fix round 1: the call convention's corners and the budget boundary, through the emulator,
/// against the interpreter — one program, one image (and its halt-words twin), a case per vector.
#[test]
fn the_call_and_budget_vectors_match_the_interpreter() {
    // Assemble once to learn where the loader puts the text, then again with the real addresses.
    let text_va = {
        let mut e = builder::build_elf(&assemble(&vector_program(), 0), &[], &[], &[], 0);
        sbpf_core::elf::load(&mut e).unwrap().text_va
    };
    let elf = builder::build_elf(&assemble(&vector_program(), text_va), &[], &[], &[], 0);
    let path = work().join("vectors.so");
    std::fs::write(&path, &elf).unwrap();
    let t = translate(&path, "vectors");
    let interp = interpreter_guest();
    let interp = Some(interp.as_path());
    let v = |case, a, b, c| vector_call(&elf, case, a, b, c);
    let ok = |r: Result<u64, Halt>, want: u64, what: &str| assert_eq!(r, Ok(want), "{what}");

    for (case, what, mask) in [
        (1, "stxb", 0xff),
        (2, "stxh", 0xffff),
        (3, "stxw", 0xffff_ffff),
        (4, "stxdw", u64::MAX),
    ] {
        let r = parity(
            &t,
            interp,
            &format!("a callee reads its argument through {what}"),
            &v(case, 0, 0, 0),
            0,
        );
        ok(r, 0x1122_3344_5566_7788 & mask, what);
    }
    ok(
        parity(
            &t,
            interp,
            "a store immediate reads no source",
            &v(15, 0, 0, 0),
            0,
        ),
        0x77,
        "st imm",
    );
    ok(
        parity(
            &t,
            interp,
            "a callee reads r0 and r6..r9 before writing them",
            &v(5, 0, 0, 0),
            0,
        ),
        1 + (2 << 8) + (3 << 16) + (4 << 24) + (5 << 32) + 2 + (5 << 40),
        "regs in",
    );
    let some = |r3: u64, r4: u64| 0x50 + (1 << 4) + (7 << 8) + (r3 << 16) + (r4 << 24) + (5 << 32);
    let r = parity(
        &t,
        interp,
        "a callee writes r0 and r2 (r3 not on this path)",
        &v(6, 0, 4, 0),
        0,
    );
    ok(r, some(3, 4), "some out");
    ok(
        parity(
            &t,
            interp,
            "a callee writes r0, r2 and r3",
            &v(6, 0, 5, 0),
            0,
        ),
        some(9, 5),
        "some out, r3",
    );
    ok(
        parity(
            &t,
            interp,
            "a call to a merged member entry",
            &v(7, 0, 0, 0),
            0,
        ),
        1005,
        "member",
    );
    ok(
        parity(
            &t,
            interp,
            "a callx to a merged member entry",
            &v(8, 0, 0, 0),
            0,
        ),
        2005,
        "member callx",
    );
    ok(
        parity(&t, interp, "a call to the member's host", &v(9, 0, 0, 0), 0),
        105,
        "host",
    );
    ok(
        parity(
            &t,
            interp,
            "a callx to the member's host",
            &v(16, 0, 0, 0),
            0,
        ),
        105,
        "host callx",
    );
    ok(
        parity(&t, interp, "call depth 7", &v(10, 6, 0, 0), 0),
        0x55,
        "depth 7",
    );
    assert_eq!(
        parity(&t, interp, "call depth 8", &v(10, 7, 0, 0), 2),
        Err(Halt::CallDepth)
    );
    ok(
        parity(&t, interp, "a program that moves r10", &v(11, 0, 0, 0), 0),
        4096 + 0x33,
        "r10",
    );
    assert_eq!(
        parity(&t, interp, "a fault's payload", &v(13, 0, 0, 0), 2),
        Err(Halt::AccessViolation(0x123))
    );
    assert_eq!(
        parity(&t, interp, "a refused opcode", &v(14, 0, 0, 0), 2),
        Err(Halt::BadInsn(0xff))
    );

    // The budget. The count is affine in (a, b, c) — measured, not assumed: 3 + PAD per big
    // iteration after the first, 2 per small one, 1 for c. The trip counts come from the input, so
    // clang cannot fold the loops. The interpreter guest cannot run these (200 000 interpreted
    // instructions are millions of cycles, past the machine's largest tier), so they compare with
    // the host interpreter only.
    let big = 3 + PAD as u64;
    let base = instructions(&v(12, 1, 1, 0));
    for (a, b, c) in [(2, 1, 0), (1, 2, 0), (1, 1, 1), (7, 5, 1)] {
        assert_eq!(
            instructions(&v(12, a, b, c)),
            base + big * (a - 1) + 2 * (b - 1) + c,
            "affine at {a} {b} {c}"
        );
    }
    // Parameters that make the whole run exactly `total` instructions.
    let exactly = |total: u64| {
        let rest = total - base;
        let a = rest / big - 1;
        let r = rest - big * a;
        (a + 1, r / 2 + 1, r % 2)
    };
    let (a, b, c) = exactly(200_000);
    assert_eq!(instructions(&v(12, a, b, c)), 200_000);
    assert_eq!(
        parity(&t, None, "exactly 200 000 instructions", &v(12, a, b, c), 1),
        Ok(0)
    );
    let (a, b, c) = exactly(200_001);
    let what = "200 001 instructions (the 200 001st is the exit)";
    assert_eq!(
        parity(&t, None, what, &v(12, a, b, c), 2),
        Err(Halt::InstructionLimit)
    );

    // The limit crossed inside each of the big loop's two blocks (one of them only charges and
    // leaves its check to the other): the 200 001st instruction's position in an iteration is
    // 0 (the sub) or 1 (the jeq) in the first block, 2.. in the second.
    let pre = |b: u64, c: u64| instructions(&v(12, 1, b, c)) - 4; // before the big loop's first sub
    for second in [false, true] {
        let (b, c) = (1..40u64)
            .flat_map(|b| [(b, 0), (b, 1)])
            .find(|&(b, c)| ((200_001 - pre(b, c) - 1) % big >= 2) == second)
            .unwrap();
        let what = if second {
            "the limit crossed in the big loop's second block"
        } else {
            "the limit crossed in its first block"
        };
        assert_eq!(
            parity(&t, None, what, &v(12, 20_000, b, c), 2),
            Err(Halt::InstructionLimit),
            "{what}"
        );
    }
}
