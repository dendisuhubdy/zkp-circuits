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
//! Vectors: the SPL Token `Transfer` (status 1), the same with too large an amount (status 0),
//! `MintTo` and `Burn` (status 1) with their failing cases — a mint signed by someone other than the
//! mint authority (`OwnerMismatch`) and a burn of more than the balance (`InsufficientFunds`),
//! status 0 — a `Transfer` with too few accounts (the program's own `NotEnoughAccountKeys`, status 0), a region
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

#[path = "../src/gen.rs"]
#[allow(dead_code)]
mod gen;

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
    let (out, cycles, _) = run_tiered(image, call);
    (out, cycles)
}

/// `rand-guest run`: the eight words, the cycle count, and the tier it reports (`Tier::for_workload`
/// over the cycles plus the digest rows; `None` if none fits).
fn run_tiered(image: &Path, call: &SbpfCall) -> ([u32; 8], usize, Option<usize>) {
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
    let tier = s
        .lines()
        .find_map(|l| l.strip_prefix("tier ")?.trim().parse().ok());
    assert!(
        tier.is_some() || s.contains("no tier fits"),
        "rand-guest run names a tier:\n{s}"
    );
    (out, cycles, tier)
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

/// One vector's measurements: `rand-guest run` on both images, and what the interpreter executed.
struct Row {
    what: String,
    result: Result<u64, Halt>,
    status: u32,
    /// sBPF instructions the interpreter executes (natively, `sbpf_core`'s meter).
    insns: u64,
    translated: (usize, Option<usize>),
    interpreted: Option<(usize, Option<usize>)>,
}

/// The whole comparison for one vector.
fn parity(
    t: &Translated,
    interp_image: Option<&Path>,
    what: &str,
    call: &SbpfCall,
    want_status: u32,
) -> Result<u64, Halt> {
    parity_measured(t, interp_image, what, call, want_status).result
}

/// [`parity`], and the cycles and tier each image took.
fn parity_measured(
    t: &Translated,
    interp_image: Option<&Path>,
    what: &str,
    call: &SbpfCall,
    want_status: u32,
) -> Row {
    let (want, result, _) = call.expected();
    assert_eq!(want[0], want_status, "{what}: the interpreter's own status");
    let (got, cycles, tier) = run_tiered(&t.image, call);
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
    let interpreted = match interp_image {
        Some(interp) => {
            let (via_interp, interp_cycles, interp_tier) = run_tiered(interp, call);
            assert_eq!(
                via_interp, want,
                "{what}: sbpf.bin on the emulator vs the host"
            );
            eprintln!("{what}: {result:?}, status {want_status}; cycles translated {cycles}, interpreter guest {interp_cycles}");
            Some((interp_cycles, interp_tier))
        }
        None => {
            eprintln!("{what}: {result:?}, status {want_status}; cycles translated {cycles}");
            None
        }
    };
    // A refused ELF or region never reaches the program: nothing executes.
    let insns = match result {
        Err(Halt::BadElf) => 0,
        _ => instructions(call),
    };
    Row {
        what: what.to_string(),
        result,
        status: want_status,
        insns,
        translated: (cycles, tier),
        interpreted,
    }
}

/// The measured rows as the README's table.
fn table(rows: &[Row], words: usize, interp_words: usize) -> String {
    let tier = |t: Option<usize>| t.map_or("none".to_string(), |t| t.to_string());
    let mut s = format!(
        "| vector | result | status | sBPF insns | translated cycles | tier | sbpf.bin cycles | tier \
         | saved |\n|---|---|---|---|---|---|---|---|---|\n(image words: translated {words}, \
         sbpf.bin {interp_words})\n"
    );
    for r in rows {
        let (ic, it) = r.interpreted.unwrap_or((0, None));
        s.push_str(&format!(
            "| {} | `{:?}` | {} | {} | {} | {} | {} | {} | {} |\n",
            r.what,
            r.result,
            r.status,
            r.insns,
            r.translated.0,
            tier(r.translated.1),
            ic,
            tier(it),
            ic as i64 - r.translated.0 as i64
        ));
    }
    s
}

/// `rand-guest info`'s program word count for an image.
fn image_words(image: &Path) -> usize {
    let o = Command::new(rand_guest())
        .arg("info")
        .arg(image)
        .args(["--max-words", "65535"])
        .output()
        .unwrap();
    check(&o, "rand-guest info")
        .lines()
        .find_map(|l| {
            l.split_once(" words against a cap of ")
                .map(|(n, _)| n.trim().parse::<usize>().unwrap())
        })
        .expect("info prints the word count")
}

// ---- the SPL Token `MintTo` and `Burn` vectors -----------------------------------------------------

/// `spl_token::instruction::TokenInstruction::MintTo`'s discriminant.
const MINT_TO_TAG: u8 = 7;
/// `spl_token::instruction::TokenInstruction::Burn`'s discriminant.
const BURN_TAG: u8 = 8;

/// `research`'s fixture key: a 32-byte key from one byte, its last byte perturbed (the same
/// function as `rand_zkvm::sbpf`'s private `key`, so these accounts are the transfer fixture's).
fn key(tag: u8) -> [u8; 32] {
    let mut k = [tag; 32];
    k[31] = tag ^ 0x5a;
    k
}

/// An account in the transfer fixture's shape: lamports and rent epoch as it has them.
fn account(key: [u8; 32], owner: [u8; 32], data: Vec<u8>, signer: bool, writable: bool) -> Account {
    Account {
        key,
        owner,
        lamports: match data.len() {
            0 => 1_000_000_000,
            sbpf::MINT_LEN => 1_461_600,
            _ => 2_039_280,
        },
        data,
        is_signer: signer,
        is_writable: writable,
        executable: false,
        rent_epoch: u64::MAX,
    }
}

/// The transfer fixture's mint, token account and owner, and `amount` as a tagged instruction.
fn spl_parts(tag: u8, amount: u64) -> ([u8; 32], [u8; 32], Vec<u8>) {
    let mut data = vec![tag];
    data.extend_from_slice(&amount.to_le_bytes());
    (key(1), key(2), data)
}

/// An SPL Token `MintTo` of `amount` to the transfer fixture's source account (holding
/// `SPL_TRANSFER_SOURCE_BALANCE`), in the order `process_mint_to` reads them: `[mint (writable),
/// destination (writable), authority (signer)]`. The mint's authority is the fixture's owner;
/// `signer` is who signs as the authority — the owner, or (the failing case) someone else, which
/// `validate_owner` refuses with `TokenError::OwnerMismatch`.
fn spl_mint_to(amount: u64, signer: [u8; 32]) -> SbpfCall {
    let (mint, owner, data) = spl_parts(MINT_TO_TAG, amount);
    let supply = sbpf::SPL_TRANSFER_SOURCE_BALANCE + sbpf::SPL_TRANSFER_DEST_BALANCE;
    let accounts = [
        account(
            mint,
            sbpf::SPL_TOKEN_ID,
            sbpf::mint_data(Some(owner), supply, 6),
            false,
            true,
        ),
        account(
            key(3),
            sbpf::SPL_TOKEN_ID,
            sbpf::token_account_data(mint, owner, sbpf::SPL_TRANSFER_SOURCE_BALANCE),
            false,
            true,
        ),
        account(signer, [0u8; 32], Vec::new(), true, false),
    ];
    SbpfCall {
        elf: sbpf::SPL_TOKEN_ELF.to_vec(),
        input: sbpf::serialize_aligned(&accounts, &data, &sbpf::SPL_TOKEN_ID),
    }
}

/// An SPL Token `Burn` of `amount` from the transfer fixture's source account, in the order
/// `process_burn` reads them: `[source (writable), mint (writable), owner (signer)]`. More than
/// the source holds is the failing case: `TokenError::InsufficientFunds`.
fn spl_burn(amount: u64) -> SbpfCall {
    let (mint, owner, data) = spl_parts(BURN_TAG, amount);
    let supply = sbpf::SPL_TRANSFER_SOURCE_BALANCE + sbpf::SPL_TRANSFER_DEST_BALANCE;
    let accounts = [
        account(
            key(3),
            sbpf::SPL_TOKEN_ID,
            sbpf::token_account_data(mint, owner, sbpf::SPL_TRANSFER_SOURCE_BALANCE),
            false,
            true,
        ),
        account(
            mint,
            sbpf::SPL_TOKEN_ID,
            sbpf::mint_data(Some(owner), supply, 6),
            false,
            true,
        ),
        account(owner, [0u8; 32], Vec::new(), true, false),
    ];
    SbpfCall {
        elf: sbpf::SPL_TOKEN_ELF.to_vec(),
        input: sbpf::serialize_aligned(&accounts, &data, &sbpf::SPL_TOKEN_ID),
    }
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

    let mut rows = Vec::new();
    let mut measure = |what: &str, call: &SbpfCall, status: u32| -> Result<u64, Halt> {
        let row = parity_measured(&t, Some(&interp), what, call, status);
        let r = row.result;
        rows.push(row);
        r
    };

    // The transfer.
    assert_eq!(measure("transfer 250", &spl_transfer(250), 1), Ok(0));

    // Too much: `InsufficientFunds`, a non-zero r0, status 0 over the pre-state.
    let r = measure("transfer too much", &spl_transfer(u64::MAX / 2), 0);
    assert!(matches!(r, Ok(c) if c != 0), "{r:?}");

    // `MintTo` and `Burn`, each with its failing case. `TokenError` is `repr(u32)` and a
    // `ProgramError::Custom(n)` returns `n` in r0: `InsufficientFunds` = 1, `OwnerMismatch` = 4.
    assert_eq!(measure("MintTo 250", &spl_mint_to(250, key(2)), 1), Ok(0));
    assert_eq!(
        measure(
            "MintTo 250 signed by someone else",
            &spl_mint_to(250, key(5)),
            0
        ),
        Ok(4)
    );
    assert_eq!(measure("Burn 250", &spl_burn(250), 1), Ok(0));
    assert_eq!(
        measure(
            "Burn 1 000 001 (balance 1 000 000)",
            &spl_burn(sbpf::SPL_TRANSFER_SOURCE_BALANCE + 1),
            0
        ),
        Ok(1)
    );

    // A bad account count, two ways. Too few for `Transfer` — the program's own error:
    let full = spl_transfer(250);
    let accounts: Vec<Account> = sbpf::deserialize_accounts(&full.input);
    let (data, id) = sbpf::deserialize_instruction(&full.input);
    let short = SbpfCall {
        elf: full.elf.clone(),
        input: sbpf::serialize_aligned(&accounts[..2], &data, &id),
    };
    let r = measure("transfer with two accounts", &short, 0);
    assert!(matches!(r, Ok(c) if c != 0), "{r:?}");
    // And more than `MAX_ACCOUNTS` claimed: the harness refuses the region before anything runs.
    let mut over = full.clone();
    over.input[0..8].copy_from_slice(&(abi::MAX_ACCOUNTS as u64 + 1).to_le_bytes());
    assert_eq!(
        measure("an account count above MAX_ACCOUNTS", &over, 2),
        Err(Halt::BadElf)
    );
    eprintln!(
        "cycles, from rand-guest run on each image:\n{}",
        table(&rows, t.words, image_words(&interp))
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

// ---- a sample of the fuzz corpus through the real pipeline (Task 5) ------------------------------

/// `tests/fuzz.rs` runs its programs through the emitted C compiled for the *host*. This runs a
/// sample of the same generator's programs through the real pipeline — `sbpf2rv`, `rand-guest
/// build`, `rand-guest run` — so the host build cannot drift from the target's: the eight words
/// must equal `run_call`'s and the halt (with its payload, and `r0`) the interpreter's.
///
/// Several cases share one ELF behind a dispatcher on the instruction data's first word (the
/// generator reserves it as a selector), so each image is built once. The sample is taken from seed
/// 1 000 000 on, among cases that are not budget cases, run under 4 000 instructions alone (the
/// machine's cycle tiers) and can be an ELF at all ([`fuzz_elf`]), 12 per image, 3 images: first
/// the earliest cases that fill [`SAMPLE_QUOTAS`] — the outcomes and paths the host build cannot
/// vouch for on the target (a `DivByZero` and a `CallDepth` halt, `sol_sha256`'s real
/// compressions, and 64-bit division and remainder, which RV32IM has no instruction for) — then
/// the earliest of the rest. The mix is asserted afterwards, on the real run: the halts from the
/// interpreter the translation matched, and the division helpers from a pc histogram of the
/// translated image on the emulator against its own symbols.
///
/// Which 64-bit division runs: the shim is a Rust crate, so `compiler_builtins`' `__udivdi3` and
/// `__umoddi3` (over its `specialized_div_rem::u64_div_rem`) — rand-guest's `rt.c` is not linked
/// into shim images. sBPF v1 has no signed division, so `__divdi3`/`__moddi3` never occur; the test
/// asserts they are absent. A case that `callx`es the pad (the accepted divergence) is kept and
/// asserted to be exactly that.
#[test]
fn a_sample_of_the_fuzz_corpus_matches_through_the_real_pipeline() {
    use sbpf_core::memory::REGION_PROGRAM;
    let mut need: std::collections::BTreeMap<&str, usize> = SAMPLE_QUOTAS.iter().copied().collect();
    let mut picked: Vec<(gen::Case, Vec<&str>)> = Vec::new();
    let mut seed = 1_000_000u64;
    while picked.len() < 36 {
        let c = gen::case(seed);
        seed += 1;
        if c.budget {
            continue;
        }
        let (text, _) = gen::assemble(&c.items, REGION_PROGRAM);
        let (instructions, result, marks) = run_with_marks(&text, &c.data);
        if instructions >= 4_000 || call_srcs(&text).iter().any(|&s| s > 1) {
            continue;
        }
        let tags = sample_tags(&result, &marks);
        let fills = tags.iter().any(|t| need.get(t).is_some_and(|&n| n > 0));
        let open: usize = need.values().sum();
        if fills || picked.len() + open < 36 {
            for t in &tags {
                if let Some(n) = need.get_mut(t) {
                    *n = n.saturating_sub(1);
                }
            }
            picked.push((c, tags));
        }
    }
    assert!(
        need.values().all(|&n| n == 0),
        "the sample could not fill its quotas: {need:?}"
    );
    let mut checked = 0;
    let mut halts: std::collections::BTreeMap<String, usize> = Default::default();
    let mut tagged: std::collections::BTreeMap<&str, usize> = Default::default();
    // (helper, cycles spent in it) over the division cases' emulator runs.
    let mut helper_cycles: std::collections::BTreeMap<&str, usize> = Default::default();
    for (g, group) in picked.chunks(12).enumerate() {
        // The dispatcher: r2 = selector; jump to case k with r2 zero again, so every case starts
        // from `Vm::new`'s registers.
        use gen::It;
        let mut items = vec![It::L(0), It::I(ins(opc::LD_DW_REG, 2, 1, 16, 0))];
        let land = |k: usize| 0xfff0_0000 + k as u64;
        let start = |k: usize| 0xfff1_0000 + k as u64;
        for k in 0..group.len() {
            items.push(It::J {
                opc: opc::JEQ_IMM,
                dst: 2,
                src: 0,
                imm: k as i32,
                to: land(k),
            });
        }
        items.push(It::I(ins(opc::MOV64_IMM, 0, 0, 0, 0xdead)));
        items.push(It::I(ins(opc::EXIT, 0, 0, 0, 0)));
        for k in 0..group.len() {
            items.push(It::L(land(k)));
            items.push(It::I(ins(opc::MOV64_IMM, 2, 0, 0, 0)));
            items.push(It::J {
                opc: opc::JA,
                dst: 0,
                src: 0,
                imm: 0,
                to: start(k),
            });
        }
        for (k, (c, _)) in group.iter().enumerate() {
            items.push(It::L(start(k)));
            items.extend(gen::relabel(&c.items, k as u64 + 1));
        }
        let text_va = {
            let mut e = fuzz_elf(&gen::assemble(&items, 0).0);
            sbpf_core::elf::load(&mut e).unwrap().text_va
        };
        let elf = fuzz_elf(&gen::assemble(&items, text_va).0);
        let name = format!("fuzz-sample-{g}");
        let path = work().join(format!("{name}.so"));
        std::fs::write(&path, &elf).unwrap();
        let t = translate(&path, &name);
        assert!(t.words <= 65_535, "{name}: {} words, over the cap", t.words);
        let symbols = symbols(&work().join(&name), &name);
        for gone in ["__divdi3", "__moddi3"] {
            assert!(
                !symbols.iter().any(|(_, _, n)| n == gone),
                "{name}: {gone} is linked, but sBPF v1 has no signed division"
            );
        }
        for (k, (c, tags)) in group.iter().enumerate() {
            let mut data = c.data.clone();
            data[..8].copy_from_slice(&(k as u64).to_le_bytes());
            let call = SbpfCall {
                elf: elf.clone(),
                input: sbpf::serialize_aligned(&[], &data, &[7u8; 32]),
            };
            let (want, result, _) = call.expected();
            let what = format!("{name} case {k} (seed {})", c.seed);
            let (got, _) = run(&t.image, &call);
            assert_eq!(got, want, "{what}: eight words, translated vs run_call");
            let (halt, _) = run(&t.halt_image, &call);
            let accepted = matches!(result, Err(Halt::AccessViolation(gen::MAGIC)));
            let hw = if accepted {
                // The callx to the pad: the translation halts BadJump at the callx.
                halt_words(&Err(Halt::BadJump))
            } else {
                halt_words(&result)
            };
            assert_eq!(
                halt,
                [want[0], hw[0], hw[1], hw[2], 0, 0, 0, 0],
                "{what}: translated halt vs the interpreter's {result:?}"
            );
            let key = match result {
                Ok(_) => "exit".to_string(),
                Err(h) if accepted => format!("{h:?} (accepted: translated BadJump)"),
                Err(h) => format!("{h:?}").split('(').next().unwrap().to_string(),
            };
            *halts.entry(key).or_default() += 1;
            for t in tags {
                *tagged.entry(t).or_default() += 1;
            }
            // The division cases, on the emulator: the cycles spent inside each helper.
            if tags.iter().any(|t| t.starts_with("64-bit")) {
                let bytes = std::fs::read(&t.image).unwrap();
                let program = rand_zkvm::isa::Program::from_flat_image(&bytes).unwrap();
                let exec = rand_zkvm::emulator::execute(
                    &program,
                    &call.input_words(),
                    &call.public_words(),
                    1 << 21,
                )
                .unwrap();
                assert_eq!(
                    exec.outputs, want,
                    "{what}: the library emulator vs rand-guest run"
                );
                for helper in ["__udivdi3", "__umoddi3", "u64_div_rem"] {
                    let n = cycles_in(&symbols, helper, &exec);
                    *helper_cycles.entry(helper).or_default() += n;
                }
            }
            checked += 1;
        }
        eprintln!("{name}: {} program words, 12 cases equal", t.words);
    }
    eprintln!(
        "real-pipeline sample: {checked} cases, outcomes {halts:?}, tags {tagged:?}, cycles in \
         the 64-bit division helpers {helper_cycles:?}"
    );
    assert_eq!(checked, 36);
    // The mix, as the real runs came out.
    for (halt, at_least) in [("DivByZero", 1), ("CallDepth", 1)] {
        assert!(
            halts.get(halt).copied().unwrap_or(0) >= at_least,
            "the sample has no {halt} halt: {halts:?}"
        );
    }
    for (tag, at_least) in SAMPLE_QUOTAS {
        assert!(
            tagged.get(tag).copied().unwrap_or(0) >= *at_least,
            "the sample has fewer than {at_least} cases of {tag}: {tagged:?}"
        );
    }
    for helper in ["__udivdi3", "__umoddi3"] {
        assert!(
            helper_cycles.get(helper).copied().unwrap_or(0) > 0,
            "no sample case ran {helper} on the emulator: {helper_cycles:?}"
        );
    }
}

/// What the real-pipeline sample must contain, as `(tag, cases)`; see [`sample_tags`].
const SAMPLE_QUOTAS: &[(&str, usize)] = &[
    ("halt DivByZero", 2),
    ("halt CallDepth", 2),
    ("sol_sha256", 3),
    ("64-bit division by a register", 2),
    ("64-bit remainder by a register", 2),
];

/// A case's tags, from its interpreter run on the host: its halt, and what its coverage marks say
/// ran. The register forms of 64-bit division are the ones clang cannot turn into a multiply, so
/// they are what reaches the division helpers.
fn sample_tags(result: &Result<u64, Halt>, marks: &[u8]) -> Vec<&'static str> {
    let mut v = Vec::new();
    match result {
        Err(Halt::DivByZero) => v.push("halt DivByZero"),
        Err(Halt::CallDepth) => v.push("halt CallDepth"),
        _ => {}
    }
    let named = |n: &str| marks[gen::named(n) as usize] != 0;
    if named("sys:sol_sha256") {
        v.push("sol_sha256");
    }
    if marks[opc::DIV64_REG as usize] != 0 {
        v.push("64-bit division by a register");
    }
    if marks[opc::MOD64_REG as usize] != 0 {
        v.push("64-bit remainder by a register");
    }
    v
}

/// A generated case run by the interpreter on the host exactly as `tests/fuzz.rs` runs it: the
/// instruction count, the result, and the coverage page.
fn run_with_marks(text: &[u8], data: &[u8]) -> (u64, Result<u64, Halt>, Vec<u8>) {
    use sbpf_core::memory::{Memory, HEAP_BYTES, REGION_HEAP, STACK_BYTES};
    let p = sbpf_core::elf::Program::from_text(text).unwrap();
    let mut stack = vec![0u8; STACK_BYTES].into_boxed_slice();
    let mut heap = vec![0u8; HEAP_BYTES].into_boxed_slice();
    let mut input = gen::input_region(data);
    let (result, n) = {
        let mem = Memory {
            text: p.text,
            text_va: p.text_va,
            rodata: p.rodata,
            rodata_base: p.rodata_va,
            stack: (&mut stack[..]).try_into().unwrap(),
            heap: (&mut heap[..]).try_into().unwrap(),
            input: &mut input,
        };
        let mut h = sbpf::HostRef;
        let mut vm = sbpf_core::interp::Vm::new(&mut h, &p, mem);
        let r = vm.run();
        (r, vm.instructions_executed())
    };
    let m = (gen::MARK_BASE - REGION_HEAP) as usize;
    (n, result, heap[m..m + gen::MARK_BYTES as usize].to_vec())
}

/// The generated crate's ELF's symbols, `(start, end, name)`, from `llvm-nm -n` beside the clang
/// the build used — each symbol runs to the next one's address.
fn symbols(dir: &Path, name: &str) -> Vec<(u32, u32, String)> {
    let elf = dir
        .join("target/riscv32im-unknown-none-elf/release")
        .join(name);
    let o = Command::new(llvm_tool("llvm-nm"))
        .args(["-n", "--defined-only"])
        .arg(&elf)
        .output()
        .unwrap();
    let out = check(&o, &format!("llvm-nm {}", elf.display()));
    let syms: Vec<(u32, String)> = out
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let a = u32::from_str_radix(f.next()?, 16).ok()?;
            let _kind = f.next()?;
            Some((a, f.next()?.to_string()))
        })
        .collect();
    syms.iter()
        .enumerate()
        .map(|(i, (a, n))| {
            let end = syms[i + 1..]
                .iter()
                .map(|(b, _)| *b)
                .find(|b| b > a)
                .unwrap_or(u32::MAX);
            (*a, end, n.clone())
        })
        .collect()
}

/// Cycles `exec` spent with the pc inside the symbol called `name`, or (a mangled Rust symbol)
/// whose name contains `name` as a path segment.
fn cycles_in(
    symbols: &[(u32, u32, String)],
    name: &str,
    exec: &rand_zkvm::emulator::Execution,
) -> usize {
    let segment = format!("{}{name}", name.len());
    let ranges: Vec<(u32, u32)> = symbols
        .iter()
        .filter(|(_, _, n)| n == name || n.ends_with(&segment))
        .map(|&(a, b, _)| (a, b))
        .collect();
    exec.events
        .iter()
        .filter(|e| ranges.iter().any(|&(a, b)| (a..b).contains(&e.pc)))
        .count()
}

/// The `src` of every `call imm` in `text`, walking it as the loader does (an `lddw` is two slots).
fn call_srcs(text: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    let mut i = 0;
    while i + 8 <= text.len() {
        if text[i] == opc::CALL_IMM {
            v.push(text[i + 1] >> 4);
        }
        i += if text[i] == opc::LD_DW_IMM { 16 } else { 8 };
    }
    v
}

/// A generated text as an SBPF v1 shared object. The generator writes a syscall the way the
/// *interpreter* holds it (`src = 1`, the name's hash); a file says it the way the toolchain does —
/// an unresolved `call` plus an `R_BPF_64_32` naming the symbol, which `elf::load` turns back into
/// exactly that. An unsupported hash becomes a symbol no syscall has.
fn fuzz_elf(text: &[u8]) -> Vec<u8> {
    use builder::{Rel, Sym, R_BPF_64_32, TEXT_ADDR};
    let mut text = text.to_vec();
    let mut syms: Vec<Sym> = Vec::new();
    let mut rels: Vec<Rel> = Vec::new();
    let mut i = 0;
    while i + 8 <= text.len() {
        if text[i] == opc::CALL_IMM && text[i + 1] >> 4 == 1 {
            let hash = u32::from_le_bytes(text[i + 4..i + 8].try_into().unwrap());
            let name = sbpf_core::syscalls::SUPPORTED
                .iter()
                .find(|(h, _)| *h == hash)
                .map_or("sol_fuzz_unknown_", |(_, n)| n);
            let k = match syms.iter().position(|s| s.name == name) {
                Some(k) => k,
                None => {
                    syms.push(Sym {
                        name,
                        info: 0x10,
                        value: 0,
                    });
                    syms.len() - 1
                }
            };
            rels.push(Rel {
                offset: TEXT_ADDR + i as u64,
                sym: k as u32 + 1,
                kind: R_BPF_64_32,
            });
            text[i + 1] &= 0x0f;
            text[i + 4..i + 8].copy_from_slice(&(-1i32).to_le_bytes());
        }
        i += if text[i] == opc::LD_DW_IMM { 16 } else { 8 };
    }
    builder::build_elf(&text, &[], &syms, &rels, 0)
}

// ---- one real proof ----------------------------------------------------------------------------------

/// The translated SPL Token `Transfer` proved and verified — once, under the research prover's test
/// profile (`FriProfile::Test`: 16 queries, 4 PoW bits), as `research/tests/backend.rs` proves its
/// guests: `Machine::prove` over the image with the call's two input segments, then `verify`
/// against the image's `hc` and `verify_public` against the ELF words (which is what binds the
/// program a chain means: `verify` alone would accept a proof of any image's run).
///
/// The run is 692 854 cycles, `Tier(20)`: a 2^20-row batch, the size research's own
/// `compiled_sbpf_spl_token_transfer_proves_and_verifies` (the interpreter's twin of this test) is
/// ignored for on a 48 GB machine. Run it explicitly, in release, where the memory is:
///
/// ```text
/// cd sbpf2rv && cargo +1.98.1 test --release --test parity \
///     the_translated_spl_token_transfer_proves_and_verifies -- --ignored --nocapture
/// ```
///
/// `README.md` records what running it here measured.
#[test]
#[ignore = "Tier(20) proof: run once on this 48 GB laptop on 2026-09-18 and stopped at 225 s at a \
            30.8 GB peak footprint, still proving (README.md, \"One real proof\"); needs a >= 64 GB \
            machine, like research's interpreter twin of this test"]
fn the_translated_spl_token_transfer_proves_and_verifies() {
    use rand_zkvm::machine::{FriProfile, Machine};
    let elf = root().join("guests-compiled/sbpf/programs/spl_token.so");
    let t = translate(&elf, "spl-token");
    assert_eq!(t.hc, SPL_TOKEN_HC, "the translated SPL Token image moved");
    let program =
        rand_zkvm::isa::Program::from_flat_image(&std::fs::read(&t.image).unwrap()).unwrap();
    let call = spl_transfer(250);
    let (want, result, _) = call.expected();
    assert_eq!(result, Ok(0));
    let (inputs, public) = (call.input_words(), call.public_words());
    let m = Machine::new(FriProfile::Test);
    eprintln!(
        "proving: {} program words, {} private words, {} public words",
        program.words.len(),
        inputs.len(),
        public.len()
    );
    let t0 = std::time::Instant::now();
    let (proof, exec) = m.prove(&program, &inputs, &public, None).unwrap();
    let prove = t0.elapsed();
    assert_eq!(exec.outputs, want, "the proved run's words vs run_call");
    let t1 = std::time::Instant::now();
    m.verify(&program.digest(), &proof).unwrap();
    m.verify_public(&program.digest(), &public, &proof).unwrap();
    let verify = t1.elapsed();
    eprintln!(
        "translated SPL Token transfer: {} cycles, tier {}, proof {} bytes, prove {prove:?}, \
         verify + verify_public {verify:?}",
        exec.cycles(),
        proof.tier.0,
        proof.size()
    );
}

// ---- where the cycles go ----------------------------------------------------------------------------

/// Where each image's cycles go, for the three successful SPL Token vectors: the harness's stages
/// against the program's own execution. A measurement, not an assertion (`#[ignore]`d; it builds
/// two more images and runs six executions on the emulator):
///
/// ```text
/// cd sbpf2rv && cargo +1.98.1 test --test parity where_the_cycles_go -- --ignored --nocapture
/// ```
///
/// Both images are built without debug info, and the harness is inlined into `main`, so symbols
/// alone cannot split it. So each image gets a *line-table twin*: the same crate rebuilt with
/// `profile.release.debug = "line-tables-only"` into a separate target directory, which must pack
/// to the very same image bytes (debug info changes no code), and whose line tables then name,
/// through `llvm-symbolizer --inlining`, the inlined function every pc belongs to. A shadow call
/// stack replayed from the pc sequence attributes shared helpers (`memset`, `memcpy`, the SHA-256
/// block function, `check_zeros`) to whoever called them. The first stage in [`STAGES`] that any
/// frame on the stack matches is the cycle's stage.
#[test]
#[ignore = "measurement: builds two line-table twins and profiles six runs; see the doc comment"]
fn where_the_cycles_go() {
    let elf = root().join("guests-compiled/sbpf/programs/spl_token.so");
    let t = translate(&elf, "spl-token");
    let prof = work().join("profile");
    std::fs::create_dir_all(&prof).unwrap();
    let shim = work().join("spl-token");
    let twins = [
        (
            "translated",
            t.image.clone(),
            line_table_twin(
                &shim,
                &shim.join("shim.ld"),
                &prof.join("translated"),
                "spl-token",
                &t.image,
            ),
        ),
        (
            "sbpf.bin",
            interpreter_guest(),
            line_table_twin(
                &root().join("guests-compiled/sbpf"),
                &root().join("guests-compiled/sbpf/sbpf.ld"),
                &prof.join("interpreter"),
                "sbpf-guest",
                &interpreter_guest(),
            ),
        ),
    ];
    for (what, call) in [
        ("transfer 250", spl_transfer(250)),
        ("MintTo 250", spl_mint_to(250, key(2))),
        ("Burn 250", spl_burn(250)),
    ] {
        let insns = instructions(&call);
        for (image_name, image, twin) in &twins {
            let split = cycle_split(image, twin, &call);
            let total: usize = split.iter().map(|(_, n)| n).sum();
            eprintln!("{what} on {image_name}: {total} cycles, {insns} sBPF instructions");
            for (stage, n) in &split {
                eprintln!(
                    "  {n:8}  {:5.1}%  {stage}",
                    100.0 * *n as f64 / total as f64
                );
            }
        }
    }
}

/// One stage of a run, and the frames that identify it.
struct Stage {
    name: &'static str,
    /// A (demangled, inlined) Rust function name containing one of these.
    words: &'static [&'static str],
    /// A C function (no `::` in its name: the translated code and `sbpf-rt`, which carry no line
    /// tables) starting with one of these.
    c_prefixes: &'static [&'static str],
    /// A frame in one of these source files.
    files: &'static [&'static str],
}

/// The harness's stages and the program's execution. The first stage any frame on the shadow
/// stack matches is the cycle's, so a `check_region` inside `decode_input` is `check_region`'s.
const STAGES: &[Stage] = &[
    Stage {
        name: "check_region: the zero scan pinning the region",
        words: &["check_region", "check_zeros"],
        c_prefixes: &[],
        files: &[],
    },
    Stage {
        name: "canonical input_hash",
        words: &["canonical_input_hash"],
        c_prefixes: &[],
        files: &[],
    },
    Stage {
        name: "output_hash",
        words: &["output_hash"],
        c_prefixes: &[],
        files: &[],
    },
    Stage {
        name: "public output words, program id",
        words: &["public_output", "program_id", "write_output"],
        c_prefixes: &[],
        files: &[],
    },
    Stage {
        name: "elf::load: parse, relocate, hash syscall names",
        words: &["murmur3"],
        c_prefixes: &[],
        files: &["elf.rs"],
    },
    Stage {
        name: "program: sBPF execution (interpreter, or translated code + sbpf-rt)",
        words: &[],
        c_prefixes: &["f_", "sbpf_", "OUTLINED_FUNCTION", "slice"],
        files: &["interp.rs", "memory.rs", "syscalls.rs"],
    },
    Stage {
        name: "decode_input: read both tapes",
        words: &["decode_input"],
        c_prefixes: &[],
        files: &[],
    },
    Stage {
        name: "zero the sBPF stack and heap",
        words: &["fill<"],
        c_prefixes: &[],
        files: &[],
    },
];

impl Stage {
    fn claims(&self, function: &str, file: &str) -> bool {
        self.words.iter().any(|w| function.contains(w))
            || (!function.contains("::") && self.c_prefixes.iter().any(|p| function.starts_with(p)))
            || self.files.contains(&file)
    }
}

/// Rebuilds `dir` (a Rust guest crate) exactly as `rand-guest build` does but with line tables,
/// into `target_dir`, and returns the ELF — after requiring that it packs to `image`'s bytes.
fn line_table_twin(dir: &Path, ld: &Path, target_dir: &Path, bin: &str, image: &Path) -> PathBuf {
    let root = root().canonicalize().unwrap();
    // `rand-guest`'s `build::flags`, verbatim.
    let flags = [
        "-C".to_string(),
        format!("link-arg=-T{}", ld.canonicalize().unwrap().display()),
        "-C".into(),
        "target-feature=-unaligned-scalar-mem".into(),
        format!("--remap-path-prefix={}=/rand-circuits", root.display()),
    ];
    let quoted: Vec<String> = flags.iter().map(|f| format!("{f:?}")).collect();
    let o = clean(
        Command::new("cargo")
            .args(["+1.98.1", "build", "--release", "--locked"])
            .args(["--target", "riscv32im-unknown-none-elf", "--config"])
            .arg(format!(
                "target.riscv32im-unknown-none-elf.rustflags=[{}]",
                quoted.join(",")
            ))
            .args([
                "--config",
                "profile.release.debug=\"line-tables-only\"",
                "--target-dir",
            ])
            .arg(target_dir)
            .current_dir(dir),
    )
    .output()
    .unwrap();
    assert!(
        o.status.success(),
        "line-table build of {}: {}",
        dir.display(),
        String::from_utf8_lossy(&o.stderr)
    );
    let elf = target_dir
        .join("riscv32im-unknown-none-elf/release")
        .join(bin);
    let packed = target_dir.join("twin.bin");
    check(
        &Command::new(rand_guest())
            .arg("pack")
            .arg(&elf)
            .arg("--out")
            .arg(&packed)
            .output()
            .unwrap(),
        "rand-guest pack (line-table twin)",
    );
    assert_eq!(
        std::fs::read(&packed).unwrap(),
        std::fs::read(image).unwrap(),
        "{}'s line-table twin is not the same image: its lines would describe other code",
        dir.display()
    );
    elf
}

/// One run of `image` over `call` on the emulator, its cycles attributed to [`STAGES`] through
/// `elf`'s line tables (anything no stage claims is "other").
fn cycle_split(image: &Path, elf: &Path, call: &SbpfCall) -> Vec<(String, usize)> {
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    let program = rand_zkvm::isa::Program::from_flat_image(&std::fs::read(image).unwrap()).unwrap();
    let exec =
        rand_zkvm::emulator::execute(&program, &call.input_words(), &call.public_words(), 1 << 21)
            .unwrap();
    // Function entry points: a jump to one that does not fall through from the previous pc is a
    // call (the caller's pc is pushed); a jump to 4 past a pushed call site returns to it.
    let starts: BTreeSet<u32> = nm_starts(elf);
    let mut stack: Vec<u32> = Vec::new();
    let mut by: HashMap<(Vec<u32>, u32), usize> = HashMap::new();
    let mut prev: Option<u32> = None;
    for e in &exec.events {
        let pc = e.pc;
        if let Some(p) = prev {
            if pc != p.wrapping_add(4) {
                if let Some(k) = stack.iter().rposition(|&c| c.wrapping_add(4) == pc) {
                    stack.truncate(k);
                } else if starts.contains(&pc) {
                    stack.push(p);
                }
            }
        }
        *by.entry((stack.clone(), pc)).or_default() += 1;
        prev = Some(pc);
    }
    let mut pcs: BTreeSet<u32> = BTreeSet::new();
    for (st, pc) in by.keys() {
        pcs.insert(*pc);
        pcs.extend(st.iter().copied());
    }
    let frames = inline_frames(elf, &pcs);
    let mut split: BTreeMap<String, usize> = BTreeMap::new();
    for ((st, pc), n) in &by {
        let chain: Vec<&(String, String)> = st
            .iter()
            .chain(std::iter::once(pc))
            .flat_map(|a| frames.get(a).into_iter().flatten())
            .collect();
        let stage = STAGES
            .iter()
            .find(|s| chain.iter().any(|(f, file)| s.claims(f, file)))
            .map_or("other: entry, glue", |s| s.name);
        *split.entry(stage.to_string()).or_default() += n;
    }
    let mut v: Vec<(String, usize)> = split.into_iter().collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.1));
    v
}

/// Every function symbol's address in `elf` (`llvm-nm`, text symbols only).
fn nm_starts(elf: &Path) -> std::collections::BTreeSet<u32> {
    let o = Command::new(llvm_tool("llvm-nm"))
        .args(["-n", "--defined-only"])
        .arg(elf)
        .output()
        .unwrap();
    check(&o, "llvm-nm")
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let a = u32::from_str_radix(f.next()?, 16).ok()?;
            matches!(f.next()?, "t" | "T").then_some(a)
        })
        .collect()
}

/// `(function, source file)` for every inlined frame at each pc, outermost first
/// (`llvm-symbolizer --inlining`: a block of `function` / `file:line:column` line pairs per
/// address, innermost first, blocks separated by a blank line).
fn inline_frames(
    elf: &Path,
    pcs: &std::collections::BTreeSet<u32>,
) -> std::collections::HashMap<u32, Vec<(String, String)>> {
    use std::io::Write as _;
    let mut child = Command::new(llvm_tool("llvm-symbolizer"))
        .args(["--inlining", "--demangle", "--obj"])
        .arg(elf)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let input: String = pcs.iter().map(|a| format!("{a:#x}\n")).collect();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
    let out = child.wait_with_output().unwrap();
    writer.join().unwrap().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let blocks: Vec<&str> = text
        .split("\n\n")
        .filter(|b| !b.trim().is_empty())
        .collect();
    assert_eq!(
        blocks.len(),
        pcs.len(),
        "llvm-symbolizer answered every address"
    );
    pcs.iter()
        .zip(blocks)
        .map(|(&a, b)| {
            let lines: Vec<&str> = b.lines().collect();
            let mut frames: Vec<(String, String)> = lines
                .chunks(2)
                .map(|p| {
                    let file = p.get(1).map_or("", |l| l.split(':').next().unwrap_or(""));
                    let file = file.rsplit('/').next().unwrap_or("").to_string();
                    (p[0].to_string(), file)
                })
                .collect();
            frames.reverse();
            (a, frames)
        })
        .collect()
}

/// An LLVM tool beside the clang the builds use (`$CLANG`, else Homebrew's).
fn llvm_tool(name: &str) -> PathBuf {
    std::env::var_os("CLANG")
        .map_or_else(
            || PathBuf::from("/opt/homebrew/opt/llvm/bin/clang"),
            PathBuf::from,
        )
        .with_file_name(name)
}
