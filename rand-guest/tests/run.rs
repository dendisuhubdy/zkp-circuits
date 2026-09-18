//! `run` executes the committed images on the emulator and reports what the research crate's
//! own tests report.

use std::path::PathBuf;
use std::process::Command;

const PIN_FIB: usize = 136;
const PIN_KECCAK: usize = 2_848;
const PIN_SBPF: usize = 694_498;

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
fn a_trap_is_reported_with_exit_code_2() {
    // fib with no input: READ_INPUT 0 past an empty vector is an input-index trap.
    let o = Command::new(bin()).args(["run"]).arg(root().join("guests-compiled/bin/fib.bin")).output().unwrap();
    assert_eq!(o.status.code(), Some(2));
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(s.contains("trap: "), "{s}");
}

/// `run`'s tier pick must agree with what `Machine::prove` would pick, not just fit the cycle
/// budget: `Tier::for_workload`'s Poseidon2-permutation term (the digest/indigest/public-digest
/// rows plus any in-guest `POSEIDON2` absorb rows) is a second, independent constraint
/// (`research/src/machine.rs`'s `Machine::prove_salted`, the `None =>` arm; audit ZH1). This test
/// pins the *agreement*, not a number: it recomputes the same `Tier::for_workload(cycles,
/// permutations)` call host-side, from a plain `emulator::execute` of the same guest and input,
/// and checks `run`'s printed tier equals whatever that comes out to.
#[test]
fn keccak256_picks_the_tier_prove_would_pick() {
    use rand_zkvm::emulator::{self, HashRow};
    use rand_zkvm::isa::Program;
    use rand_zkvm::machine::{Tier, TIERS};

    let image = std::fs::read(root().join("guests-compiled/bin/keccak256.bin")).unwrap();
    let program = Program::from_flat_binary(0x1000, &image).unwrap();

    // `research/src/guests.rs`'s `compiled::keccak256` doc comment: input[0] is the message's
    // byte length, input[1..] the message four bytes per word little-endian. A short message is
    // enough — the test only needs a real execution to pull real digest/absorb-row counts from.
    let msg: Vec<u8> = (0..16u8).map(|i| i.wrapping_mul(31)).collect();
    let mut inputs = vec![msg.len() as u32];
    for c in msg.chunks(4) {
        let mut w = [0u8; 4];
        w[..c.len()].copy_from_slice(c);
        inputs.push(u32::from_le_bytes(w));
    }

    let max = Tier(*TIERS.last().unwrap()).max_cycles();
    let exec = emulator::execute(&program, &inputs, &[], max).unwrap();
    // Term by term, `Machine::prove_salted`'s `None =>` arm.
    let digest_rows = program.digest_rows() + rand_zkvm::hash::input_digest_row_count(inputs.len()) + rand_zkvm::hash::public_digest_row_count(0);
    let cycles = exec.cycles() + digest_rows;
    let absorb_rows = exec.events.iter().filter(|e| matches!(e.hash_row, Some(HashRow::Absorb { .. }))).count();
    let permutations = digest_rows + absorb_rows;
    let want = Tier::for_workload(cycles, permutations).expect("some tier fits this small workload");

    let mut args = vec!["run".to_string(), root().join("guests-compiled/bin/keccak256.bin").to_string_lossy().into_owned(), "--input".to_string()];
    args.extend(inputs.iter().map(|w| w.to_string()));
    let o = Command::new(bin()).args(&args).output().unwrap();
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{s}");
    assert!(s.contains(&format!("tier {}", want.0)), "wanted tier {}: {s}", want.0);
}

/// Runs `image` with `inputs`/`public` through `rand-guest run`, passing each vector as one flag
/// followed by its words, and returns stdout.
fn run(image: &str, inputs: &[u32], public: &[u32], extra: &[&str]) -> String {
    let mut c = Command::new(bin());
    c.arg("run").arg(root().join("guests-compiled/bin").join(image));
    if !inputs.is_empty() {
        c.arg("--input").args(inputs.iter().map(u32::to_string));
    }
    if !public.is_empty() {
        c.arg("--public").args(public.iter().map(u32::to_string));
    }
    let o = c.args(extra).output().unwrap();
    let s = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(o.status.success(), "{image}: {s}{}", String::from_utf8_lossy(&o.stderr));
    s
}

fn cycles_of(s: &str) -> usize {
    s.lines().find_map(|l| l.strip_prefix("cycles ")).expect("a cycles line").parse().unwrap()
}

/// `keccak256`'s input for a message: its byte length, then the bytes four per word LE.
fn keccak_inputs(msg: &[u8]) -> Vec<u32> {
    let mut inputs = vec![msg.len() as u32];
    for c in msg.chunks(4) {
        let mut w = [0u8; 4];
        w[..c.len()].copy_from_slice(c);
        inputs.push(u32::from_le_bytes(w));
    }
    inputs
}

/// `run`'s executed-cycle count for each of the four committed guests, on the inputs
/// `research/tests/e2e.rs` runs each of them with: `fib(20)`
/// (`compiled_fib_proves_and_verifies`), Keccak-256 of the 135-byte message
/// (`compiled_keccak256_matches_the_host_in_one_permutation`), the ERC-20 `transfer` of 250 from a
/// balance of 1 000 (`compiled_evm_erc20_transfer_binds_the_state_root_transition`; 121 638
/// executed cycles, `research/docs/04-guests.md`), and the SPL Token `Transfer` of 250
/// (`compiled_sbpf_spl_token_transfer_executes_and_publishes_the_bound_digest`). A different count
/// means the image or the emulator changed.
#[test]
fn run_reproduces_the_committed_guests_cycle_counts() {
    let fib = run("fib.bin", &[20], &[], &[]);
    assert!(fib.contains("out[0] = 6765"), "{fib}");
    let msg: Vec<u8> = (0..135u8).map(|i| i.wrapping_mul(31)).collect();
    let keccak = run("keccak256.bin", &keccak_inputs(&msg), &[], &[]);
    use evm_core::u256::U256;
    use rand_zkvm::evm::{erc20_transfer, ALICE, BOB};
    let call = erc20_transfer(ALICE, BOB, U256::from_u32(250), &[(ALICE, U256::from_u32(1000))]);
    let evm = run("evm.bin", &call.input_words(), &[], &[]);
    let (want, _, _) = call.expected();
    for (i, w) in want.iter().enumerate() {
        assert!(evm.contains(&format!("out[{i}] = {w}\n")), "evm out[{i}]: {evm}");
    }
    let spl = rand_zkvm::sbpf::spl_transfer(250);
    let sbpf = run("sbpf.bin", &spl.input_words(), &spl.public_words(), &[]);
    let (want, _, _) = spl.expected();
    for (i, w) in want.iter().enumerate() {
        assert!(sbpf.contains(&format!("out[{i}] = {w}\n")), "sbpf out[{i}]: {sbpf}");
    }
    let got = [cycles_of(&fib), cycles_of(&keccak), cycles_of(&evm), cycles_of(&sbpf)];
    eprintln!("cycles: fib {} keccak256 {} evm {} sbpf {}", got[0], got[1], got[2], got[3]);
    assert_eq!(got, [PIN_FIB, PIN_KECCAK, 121_638, PIN_SBPF]);
}

/// `--tier t` states the same rule `Tier::for_workload` applies, for one tier, with both budgets:
/// `fib(20)` fits tier 10; the ERC-20 transfer (tier 18, `research/docs/04-guests.md`) does not fit
/// tier 16 and does fit tier 18. Its all-in figures are `Machine::prove_salted`'s: 126 374 cycles
/// is 04-guests.md's 126 373 plus the one public-digest row an empty public segment still costs,
/// and 5 407 permutations counts the digest rows and the `Absorb` rows only, as the prover does
/// (04-guests.md's 5 805 counts every hash row, the ecall rows included).
#[test]
fn run_says_whether_the_workload_fits_a_given_tier() {
    let s = run("fib.bin", &[20], &[], &["--tier", "10"]);
    assert!(s.contains("tier 10: fits (cycles "), "{s}");
    assert!(s.contains(" of 1023, Poseidon2 permutations "), "{s}");
    use evm_core::u256::U256;
    use rand_zkvm::evm::{erc20_transfer, ALICE, BOB};
    let call = erc20_transfer(ALICE, BOB, U256::from_u32(250), &[(ALICE, U256::from_u32(1000))]);
    let s = run("evm.bin", &call.input_words(), &[], &["--tier", "16"]);
    assert!(s.contains("tier 18\n"), "{s}");
    assert!(s.contains("tier 16: does not fit (cycles 126374 of 65535, Poseidon2 permutations 5407 of 8192)"), "{s}");
    let s = run("evm.bin", &call.input_words(), &[], &["--tier", "18"]);
    assert!(s.contains("tier 18: fits (cycles 126374 of 262143, Poseidon2 permutations 5407 of 32768)"), "{s}");
    let o = Command::new(bin()).arg("run").arg(root().join("guests-compiled/bin/fib.bin")).args(["--input", "20", "--tier", "11"]).output().unwrap();
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("not one of the machine's tiers"));
}
