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
use sbpf_core::isa::opc;
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

fn require_clang() {
    if let Some(c) = std::env::var_os("CLANG") {
        assert!(
            Path::new(&c).exists(),
            "$CLANG is {c:?}, which does not exist"
        );
        return;
    }
    assert!(
        Path::new("/opt/homebrew/opt/llvm/bin/clang").exists(),
        "no RISC-V clang: `brew install llvm` (for /opt/homebrew/opt/llvm/bin/clang) or set $CLANG — this test cannot run without one"
    );
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
    for f in ["program.c", "Cargo.toml", "build.rs", "src/main.rs"] {
        assert!(dir.join(f).exists(), "{f} was not generated");
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
        (
            image,
            check(&o, &format!("rand-guest build {}", d.display())),
        )
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
    let o = clean(
        Command::new(rand_guest())
            .arg("build")
            .arg(&dir)
            .arg("--out")
            .arg(&image)
            .args(["--max-words", "65535"]),
    )
    .output()
    .unwrap();
    check(&o, "rand-guest build (elsewhere)");
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
