//! ZKVM-119: a guest author can see what a run did — where a trap happened (pc, function, the
//! instructions before it), where the cycles went (`profile`), and how deep the stack got.
//!
//! The Rust guests need the pinned toolchain with the guest target (as `tests/build.rs`); the C
//! ones need the pinned clang and are skipped without it.

use rand_guest::profile::{profile, stack_use, Symbols};
use rand_zkvm::emulator::{execute, execute_traced, ExecError, TRAP_HISTORY};
use rand_zkvm::isa::Program;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rand-guest"))
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

/// A guest with one function the compiler may not inline, which refuses an input over 20 from
/// inside it: `out[0] = sum of i*i for i < n`.
const GUEST: &str = r#"#![no_std]
#![no_main]
use guest_sdk::{halt, read_input, require, write_output};

#[inline(never)]
fn work(n: u32) -> u32 {
    require!(n <= 20);
    let mut s = 0u32;
    let mut i = 0;
    while i < n {
        s = s.wrapping_add(core::hint::black_box(i) * i);
        i += 1;
    }
    s
}

#[no_mangle]
pub extern "C" fn main() -> ! {
    write_output(0, work(read_input(0)));
    halt();
}
"#;

/// `guests-compiled/fib`'s crate with `main.rs` replaced, built; returns the directory (kept alive
/// by the caller), the image and the linked ELF.
fn built() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let guest = tempfile::tempdir_in(root().join("guests-compiled")).unwrap();
    let src = root().join("guests-compiled/fib");
    std::fs::create_dir_all(guest.path().join("src")).unwrap();
    for f in ["Cargo.toml", "Cargo.lock"] {
        std::fs::copy(src.join(f), guest.path().join(f)).unwrap();
    }
    std::fs::write(guest.path().join("src/main.rs"), GUEST).unwrap();
    let image = guest.path().join("image.bin");
    let o = Command::new(bin()).arg("build").arg(guest.path()).arg("--out").arg(&image).output().unwrap();
    assert!(o.status.success(), "{}", text(&o));
    let elf = guest.path().join("target/riscv32im-unknown-none-elf/release/fib-guest");
    (guest, image, elf)
}

fn load(image: &Path) -> Program {
    Program::from_flat_image(&std::fs::read(image).unwrap()).unwrap()
}

#[test]
fn a_trap_reports_its_pc_its_function_and_the_instructions_before_it() {
    let (_guest, image, elf) = built();
    let program = load(&image);

    // The library: the same error `execute` gives, with the place.
    let trap = execute_traced(&program, &[21], &[], 1 << 16).unwrap_err();
    assert_eq!(trap.error, execute(&program, &[21], &[], 1 << 16).unwrap_err());
    assert_eq!(trap.error, ExecError::InputIndex(u32::MAX));
    assert_eq!(program.instr_at(trap.pc), Some(rand_zkvm::isa::Instr::Ecall), "a refusal traps on its ecall");
    assert_eq!(trap.recent.last(), Some(&trap.pc));
    assert!(trap.recent.len() <= TRAP_HISTORY && trap.recent.len() as usize == (trap.cycle + 1).min(TRAP_HISTORY), "{trap:?}");
    let symbols = Symbols::from_elf(&std::fs::read(&elf).unwrap()).unwrap();
    let (name, _) = symbols.lookup(trap.pc).expect("the trapping pc is inside a function");
    assert!(name.ends_with("::work"), "{name}");
    // A run that does not trap is the same run either way.
    assert_eq!(execute_traced(&program, &[20], &[], 1 << 16).unwrap().outputs, execute(&program, &[20], &[], 1 << 16).unwrap().outputs);
    // Out of cycles is placed too: at the instruction the budget ran out before.
    let t = execute_traced(&program, &[20], &[], 10).unwrap_err();
    assert_eq!((t.error, t.cycle), (ExecError::OutOfCycles(10), 10));

    // The CLI, with the ELF: pc, function and offset; with --trace, the history.
    let o = Command::new(bin()).arg("run").arg(&image).args(["--input", "21", "--trace", "--elf"]).arg(&elf).output().unwrap();
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    let s = text(&o);
    assert!(s.contains("trap: InputIndex(4294967295)"), "{s}");
    assert!(s.contains(&format!("at pc {:#x} (", trap.pc)) && s.contains("::work"), "{s}");
    assert!(s.contains(&format!("after {} cycles", trap.cycle)), "{s}");
    assert!(s.contains("instructions, oldest first:") && s.contains("Ecall"), "{s}");
    // Without it: the pc alone, and a hint.
    let o = Command::new(bin()).arg("run").arg(&image).args(["--input", "21"]).output().unwrap();
    let s = text(&o);
    assert!(s.contains(&format!("at pc {:#x} after", trap.pc)) && s.contains("no symbols: pass --elf"), "{s}");
    assert!(!s.contains("oldest first"), "{s}");
}

#[test]
fn profile_accounts_for_every_cycle_by_function_syscall_and_stack() {
    let (guest, image, elf) = built();
    let program = load(&image);
    let exec = execute(&program, &[20], &[], 1 << 16).unwrap();
    let symbols = Symbols::from_elf(&std::fs::read(&elf).unwrap()).unwrap();
    let p = profile(&exec, &symbols);
    assert_eq!(p.cycles, exec.cycles() as u64);
    assert_eq!(p.functions.iter().map(|f| f.1).sum::<u64>(), p.cycles, "every cycle is in one function");
    assert_eq!(p.folded.iter().map(|f| f.1).sum::<u64>(), p.cycles, "and on one stack");
    assert!(p.functions.iter().all(|f| f.0.is_some()), "every pc of this guest has a symbol: {:?}", p.functions);
    let work = p.functions.iter().find(|f| f.0.as_deref().is_some_and(|n| n.ends_with("::work"))).expect("work is profiled");
    assert_eq!(p.functions[0].0, work.0, "the loop is where the cycles are: {:?}", p.functions);
    let sys = |n: &str| p.syscalls.iter().find(|s| s.0 == n).map(|s| (s.1, s.2));
    assert_eq!(sys("READ_INPUT"), Some((1, 1)));
    assert_eq!(sys("WRITE_OUTPUT"), Some((1, 1)));
    assert_eq!(sys("HALT"), Some((1, 1)));
    let stack = p.folded.iter().find(|f| f.0.ends_with("::work")).expect("a stack ending in work");
    assert!(stack.0.starts_with("_start;main;"), "{}", stack.0);
    assert_eq!(stack.1, work.1);
    // No symbols: the totals still hold, under one unknown name.
    let bare = profile(&exec, &Symbols::default());
    assert_eq!(bare.functions, vec![(None, p.cycles)]);

    // The CLI prints the same and writes the folded file.
    let folded = guest.path().join("out.folded");
    let o = Command::new(bin()).arg("profile").arg(&image).args(["--input", "20", "--elf"]).arg(&elf).arg("--folded").arg(&folded).output().unwrap();
    assert!(o.status.success(), "{}", text(&o));
    let s = text(&o);
    assert!(s.contains(&format!("cycles {}", p.cycles)) && s.contains("::work") && s.contains("READ_INPUT") && s.contains("stack: "), "{s}");
    let lines = std::fs::read_to_string(&folded).unwrap();
    let total: u64 = lines.lines().map(|l| l.rsplit_once(' ').unwrap().1.parse::<u64>().unwrap()).sum();
    assert_eq!(total, p.cycles);
    // A trapping run has no profile: the trap is reported instead.
    let o = Command::new(bin()).arg("profile").arg(&image).args(["--input", "21"]).output().unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(text(&o).contains("trap: InputIndex(4294967295)"), "{}", text(&o));
}

/// The published `keccak256` guest keeps a 136-byte message and the sponge state on its stack.
#[test]
fn run_reports_the_stack_depth_and_warns_past_the_reserved_size() {
    let image = root().join("guests-compiled/bin/keccak256.bin");
    let program = Program::from_flat_binary(0x1000, &std::fs::read(&image).unwrap()).unwrap();
    let exec = execute(&program, &[4, 1], &[], 1 << 16).unwrap();
    let u = stack_use(&exec).expect("the guest sets sp");
    assert!(u.depth() > 136 && u.depth() < 65536, "{u:?}");
    assert_eq!(u.top % 16, 0, "the top is the linker script's aligned __stack_top, not the auipc's intermediate value: {u:?}");
    let run = |extra: &[&str]| text(&Command::new(bin()).arg("run").arg(&image).args(["--input", "4", "1"]).args(extra).output().unwrap());
    let s = run(&[]);
    assert!(s.contains(&format!("stack: {} bytes used", u.depth())) && !s.contains("warning: the stack"), "{s}");
    let s = run(&["--stack-bytes", "128"]);
    assert!(s.contains("warning: the stack went") && s.contains("past the 128"), "{s}");
}

/// `guest.h`'s `rand_poseidon2_len` and `rand_modq` against the host's own arithmetic.
#[test]
fn the_c_wrappers_for_poseidon2_len_and_modq_match_the_host() {
    let Ok(_) = rand_guest::build::find_clang() else { eprintln!("no RISC-V clang; skipping"); return; };
    let guest = tempfile::tempdir_in(root().join("guests-compiled")).unwrap();
    std::fs::write(
        guest.path().join("main.c"),
        r#"#include "guest.h"
static uint32_t buf[8];
static uint32_t arena[256];
void main(void) {
    if (rand_read_input(0) == 0) {
        for (uint32_t i = 0; i < 3; i++) {
            buf[i] = rand_read_input(1 + i);
        }
        rand_poseidon2_len(buf, 3);
        for (uint32_t i = 0; i < 8; i++) {
            rand_write_output(i, buf[i]);
        }
    } else {
        for (uint32_t i = 0; i < 256; i++) {
            arena[i] = 3 * i + 1;
        }
        rand_modq(arena, rand_modq_a1(RAND_MODQ_NTT, 0, 0, 0));
        for (uint32_t i = 0; i < 8; i++) {
            rand_write_output(i, arena[31 * i]);
        }
    }
    rand_halt();
}
"#,
    )
    .unwrap();
    let image = guest.path().join("image.bin");
    let o = Command::new(bin()).args(["build", "--lang", "c"]).arg(guest.path()).arg("--out").arg(&image).output().unwrap();
    assert!(o.status.success(), "{}", text(&o));
    let program = load(&image);
    let exec = execute(&program, &[0, 7, 8, 9], &[], 1 << 16).unwrap();
    assert_eq!(exec.outputs, rand_zkvm::hash::sponge_hash_len(&[7, 8, 9]));
    let exec = execute(&program, &[1], &[], 1 << 16).unwrap();
    let mut poly: rand_zkvm::modq::Poly = core::array::from_fn(|i| 3 * i as u32 + 1);
    rand_zkvm::modq::ntt(&mut poly);
    assert_eq!(exec.outputs, core::array::from_fn(|i| poly[31 * i]));
}

/// `guest-sdk/README.md`'s worked example is the code in that file: built here as written, it
/// accepts a true statement, refuses a false one, and links no panic machinery.
#[test]
fn the_sdk_readmes_worked_example_builds_accepts_and_refuses() {
    let readme = std::fs::read_to_string(root().join("guest-sdk/README.md")).unwrap();
    let code = readme.split("```rust\n").nth(1).expect("a rust block").split("```").next().unwrap();
    let guest = tempfile::tempdir_in(root().join("guests-compiled")).unwrap();
    let src = root().join("guests-compiled/fib");
    std::fs::create_dir_all(guest.path().join("src")).unwrap();
    for f in ["Cargo.toml", "Cargo.lock"] {
        std::fs::copy(src.join(f), guest.path().join(f)).unwrap();
    }
    std::fs::write(guest.path().join("src/main.rs"), code).unwrap();
    let image = guest.path().join("image.bin");
    let o = Command::new(bin()).arg("build").arg(guest.path()).arg("--out").arg(&image).output().unwrap();
    assert!(o.status.success(), "the example must build without --allow-panic: {}", text(&o));
    let program = load(&image);
    let secret = [5u32, 6, 7, 8];
    let digest = rand_zkvm::hash::sponge_hash_len(&secret);
    let public = |limit: u32| [&[limit][..], &digest[..]].concat();
    assert_eq!(execute(&program, &secret, &public(10), 1 << 16).unwrap().outputs[0], 1);
    assert_eq!(execute(&program, &secret, &public(4), 1 << 16).unwrap_err(), ExecError::InputIndex(u32::MAX), "over the limit");
    let mut wrong = public(10);
    wrong[8] ^= 1;
    assert_eq!(execute(&program, &secret, &wrong, 1 << 16).unwrap_err(), ExecError::InputIndex(u32::MAX), "another digest");
    assert_eq!(execute(&program, &[5, 6, 7, 9], &public(10), 1 << 16).unwrap_err(), ExecError::InputIndex(u32::MAX), "another secret");
}
