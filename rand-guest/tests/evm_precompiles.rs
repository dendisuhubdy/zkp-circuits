//! evm-rt's nine precompiles on the machine: `evm-rt/test/rv32-precompiles` is a C guest that
//! includes the runtime's sources and checks one known answer per run (the vectors are
//! `evm-rt/test/precompile_vectors.h`, parsed here; their sources are in that file). On the
//! machine, sha256 compresses on the SHA-256 coprocessor and ecrecover hashes on the Keccak one —
//! the paths the host suite replaces with portable C — so this is where those agree with the
//! answers. Gated, like the c-fib and evm-rt tests, on a clang with a `riscv32` target.
//!
//! * `every_vector_that_fits_the_largest_tier_passes_on_the_machine` runs every vector under
//!   `rand-guest run`, whose cycle budget is the largest tier's (2^20). A vector must either pass
//!   or run out of that budget; the sha256, ripemd160 and identity vectors must all pass.
//! * `precompile_cycles` (ignored: minutes in release) is for the precompiles past 2^20, which
//!   `rand-guest run` cannot finish and whose event log (about 1.2 GB per 2^20 cycles) could not
//!   be held for a full run. It counts cycles with `support/count.rs`, the emulator's own instruction
//!   semantics without the per-cycle event log (every instruction the guest executes is one
//!   cycle; the guest makes no `POSEIDON2` call, the one syscall that takes several rows). The
//!   count is checked to equal `rand-guest run`'s on every representative that fits, and the
//!   guest's verdict is checked on every one, and then on every vector. Run it with
//!   `cargo test --release --test evm_precompiles -- --ignored --nocapture`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

#[path = "support/count.rs"]
mod count;

use count::count;
use rand_zkvm::isa::Program;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}
fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rand-guest"))
}

/// One `precompile_vectors.h` entry.
#[derive(Clone, Debug)]
struct Vector {
    name: String,
    addr: u32,
    input: Vec<u8>,
    output: Vec<u8>,
    gas: u64,
    ok: bool,
}

fn vectors() -> Vec<Vector> {
    let text = std::fs::read_to_string(root().join("evm-rt/test/precompile_vectors.h")).unwrap();
    // `{"source", "name", addr,\n "in",\n "out", gasull, ok},`
    let mut out = Vec::new();
    let body = &text[text.find("PC_VECTORS[] = {").unwrap()..];
    for entry in body.split("\n    {\"").skip(1) {
        let fields: Vec<&str> = entry.split('"').collect();
        // fields: source, ", ", name, ", addr,\n     ", in, ",\n     ", out, ", gasull, ok},..."
        let name = fields[2].to_string();
        let addr: u32 = fields[3].trim_matches(|c: char| !c.is_ascii_digit()).parse().unwrap();
        let input = hex::decode(fields[4]).unwrap();
        let output = hex::decode(fields[6]).unwrap();
        let tail: Vec<&str> = fields[7].split(|c: char| c == ',' || c == '}').map(str::trim).filter(|s| !s.is_empty()).collect();
        let gas: u64 = tail[0].trim_end_matches("ull").parse().unwrap();
        let ok = tail[1] == "1";
        out.push(Vector { name, addr, input, output, gas, ok });
    }
    assert!(out.len() > 100, "parsed {} vectors", out.len());
    out
}

fn pack(bytes: &[u8]) -> Vec<u32> {
    bytes.chunks(4).map(|c| {
        let mut w = [0u8; 4];
        w[..c.len()].copy_from_slice(c);
        u32::from_le_bytes(w)
    }).collect()
}

/// The guest's mode-1 input for `v`.
fn input_words(v: &Vector) -> Vec<u32> {
    let mut w = vec![1, v.addr, v.input.len() as u32];
    w.extend(pack(&v.input));
    w.push(v.ok as u32);
    w.push(v.output.len() as u32);
    w.extend(pack(&v.output));
    w
}

/// The guest image, built once (`None`: no RISC-V clang).
fn image() -> Option<&'static Path> {
    static IMG: OnceLock<Option<PathBuf>> = OnceLock::new();
    IMG.get_or_init(|| {
        rand_guest::build::find_clang().ok()?;
        let dir = std::env::temp_dir().join(format!("evm_precompiles_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("pc.bin");
        let o = Command::new(bin())
            .args(["build", "--lang", "c"])
            .arg(root().join("evm-rt/test/rv32-precompiles"))
            .arg("--out")
            .arg(&out)
            .args(["--max-words", "65535"])
            .output()
            .unwrap();
        assert!(o.status.success(), "{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        Some(out)
    })
    .as_deref()
}

/// `rand-guest run`: the eight outputs and the cycles, or `None` when it ran out of cycles.
fn run(img: &Path, words: &[u32]) -> Option<([u32; 8], u64)> {
    let r = Command::new(bin()).arg("run").arg(img).arg("--input").args(words.iter().map(u32::to_string)).output().unwrap();
    let s = String::from_utf8_lossy(&r.stdout);
    if s.contains("trap: OutOfCycles") {
        return None;
    }
    assert!(r.status.success(), "{s}");
    let mut out = [0u32; 8];
    for (i, w) in out.iter_mut().enumerate() {
        let p = format!("out[{i}] = ");
        *w = s.lines().find_map(|l| l.strip_prefix(&p)).unwrap().parse().unwrap();
    }
    let cycles = s.lines().find_map(|l| l.strip_prefix("cycles ")).unwrap().parse().unwrap();
    Some((out, cycles))
}

fn check_outputs(v: &Vector, out: &[u32; 8]) {
    assert_eq!(out[2], 1, "{} {}: the guest's verdict (r {}, out_len {})", v.addr, v.name, out[0], out[1]);
    assert_eq!(out[3] as u64 | (out[4] as u64) << 32, v.gas, "{} {}: RequiredGas", v.addr, v.name);
}

#[test]
fn every_vector_that_fits_the_largest_tier_passes_on_the_machine() {
    let Some(img) = image() else {
        eprintln!("no RISC-V clang; skipping");
        return;
    };
    let (mut ran, mut over) = (0, Vec::new());
    for v in vectors() {
        match run(img, &input_words(&v)) {
            Some((out, _)) => {
                check_outputs(&v, &out);
                ran += 1;
            }
            None => {
                assert!(![2, 3, 4].contains(&v.addr), "{} {} must fit the largest tier", v.addr, v.name);
                over.push(format!("{} {}", v.addr, v.name));
            }
        }
    }
    eprintln!("{ran} vectors passed on the machine; {} past 2^20 cycles: {over:?}", over.len());
    assert!(ran >= 60, "{ran}");
}

// ---------------------------------------------------------------------------------------------
// The cycle count past the largest tier.

#[test]
#[ignore]
fn precompile_cycles() {
    let Some(img) = image() else {
        eprintln!("no RISC-V clang; skipping");
        return;
    };
    let bytes = std::fs::read(img).unwrap();
    let program = Program::from_flat_image(&bytes).unwrap();
    let all = vectors();
    let reps = [
        (1, "ValidKey"),
        (2, "FIPS 180-2 B.1 abc"),
        (2, "200 bytes"),
        (3, "'abc'"),
        (4, "100 bytes"),
        (5, "nagydani-1-square"),
        (5, "nagydani-1-pow0x10001"),
        (5, "eip_example1"),
        (5, "nagydani-5-pow0x10001"),
        (6, "chfast1"),
        (7, "chfast1"),
        (8, "one_point"),
        (8, "jeff1"),
        (9, "vector 5"),
    ];
    println!("| addr | vector | gas | cycles | 2^20 tier |");
    for (addr, name) in reps {
        let v = all.iter().find(|v| v.addr == addr && v.name == name).unwrap_or_else(|| panic!("{addr} {name}"));
        let words = input_words(v);
        let t = std::time::Instant::now();
        let (out, n) = count(&program, &words, 20_000_000_000);
        check_outputs(v, &out);
        // Where `rand-guest run` can finish, the count is its count.
        if n < 1 << 20 {
            let (rout, rn) = run(img, &words).expect("under 2^20 cycles");
            assert_eq!((rout, rn), (out, n), "{addr} {name}: the counter against rand-guest run");
        }
        println!(
            "| {addr} | {name} | {} | {n} | {} | ({:.1}s)",
            v.gas,
            if n < 1 << 20 { "fits" } else { "exceeds" },
            t.elapsed().as_secs_f64()
        );
    }
    // And every vector's verdict under the machine's semantics, the ones past 2^20 included.
    let mut worst: Vec<(u64, String)> = Vec::new();
    for v in &all {
        let (out, n) = count(&program, &input_words(v), 20_000_000_000);
        check_outputs(v, &out);
        worst.push((n, format!("{} {}", v.addr, v.name)));
    }
    worst.sort();
    println!("{} vectors pass under the counter; the most cycles: {:?}", all.len(), &worst[worst.len() - 3..]);
}
