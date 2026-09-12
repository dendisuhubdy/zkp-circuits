use p3_matrix::Matrix;
use rand_zkvm::asm::{ops::*, Assembler};
use rand_zkvm::guests;
use rand_zkvm::machine::{FriProfile, Machine, Tier};

/// M3.4 (fix): the program table's height is proof-declared, not derived from the tier
/// (`tables::program::program_log_height`'s doc comment) — a program can be far longer than
/// `Tier::cpu_height()` while still executing briefly, since a digest row absorbs up to 4
/// `PROGRAM_WORD`s per *cycle* but a program's word count has no such per-cycle cap. Build one:
/// a trivial computation followed by a large block of never-executed instructions, long enough
/// that the program table alone would have overflowed a small tier's `cpu_height()`-sized table
/// under the pre-fix code (`Tier::program_height() = cpu_height()`, since deleted).
///
/// The tier this proves at is `Tier(14)`, not `Tier(10)` (whose `cpu_height` the program's
/// length is checked against): the ~300 digest-row permutations this program's length costs
/// need a `poseidon2_height` budget only `Tier(14)` (or higher) provides —
/// `Tier::poseidon2_height`'s own scaling relative to `cpu_height` is a separate, pre-existing
/// concern this fix does not touch (see the fix report). What this test isolates is exactly
/// the bug this fix closes: the *program table's own height* — independently confirmed below
/// via `traces.program.height()` — tracks the program's length, not the tier, so it is not the
/// thing that would have forced a larger tier here.
#[test]
fn a_program_much_longer_than_a_small_tiers_cpu_height_but_briefly_executed_proves() {
    use rand_zkvm::machine::build_traces_salted;
    let m = Machine::new(FriProfile::Test);
    let mut a = Assembler::new(0);
    a.extend(li(5, 42)); // t0 = 42
    a.extend(write_output(0, 5));
    a.extend(halt());
    // Never executed (the guest already halted above) — padding to push `len` past
    // `Tier(10).cpu_height()` (1 024) without meaningfully touching the cycle count.
    for _ in 0..1200 {
        a.push(addi(0, 0, 0)); // a decodable no-op: x0 = x0 + 0
    }
    let p = a.assemble();
    assert!(p.len() > Tier(10).cpu_height(), "program must exceed a small tier's cpu height to exercise the fix");

    let exec = rand_zkvm::emulator::execute(&p, &[], 1 << 20).unwrap();
    assert!(exec.cycles() < 20, "only the leading few instructions ever execute");
    let traces = build_traces_salted(&p, &[], [0u32; 4], &exec, Tier(14)).unwrap();
    // The program table's own height is driven by the program's length (`program_log_height`),
    // not by `Tier(14).cpu_height()` (16 384) — it is far smaller, and in particular still
    // bigger than `Tier(10).cpu_height()` would have offered, confirming the fix actually sized
    // the table from `p.len()` rather than coincidentally inheriting a large tier's height.
    assert!(traces.program.height() > Tier(10).cpu_height());
    assert!(traces.program.height() < Tier(14).cpu_height());

    let proof = m.prove_traces(&p, &traces, Tier(14));
    assert_eq!(exec.outputs[0], 42);
    m.verify(&p.digest(), &proof).unwrap();
}

#[test]
fn every_guest_proves_and_verifies() {
    let m = Machine::new(FriProfile::Test);
    // M4.1 salted H_IN (controller ruling): `prove_salted` with a fixed salt, so the expected
    // H_IN below is reproducible — `prove`'s own OS-entropy salt would make it a different,
    // unpredictable value on every run.
    let salt = [11u32, 22, 33, 44];
    for (name, program, inputs) in guests::all() {
        let (proof, exec) = m.prove_salted(&program, &inputs, salt, None).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(proof.tier, Tier(10), "{name} should fit the smallest tier");
        assert_eq!(proof.public_values[2], exec.outputs[0] as u64);
        m.verify(&program.digest(), &proof).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert!(proof.size() > 0);

        use rand_zkvm::tables::cpu::pv;
        let expected_hin = rand_zkvm::hash::input_digest(salt, &inputs);
        for k in 0..8 {
            assert_eq!(proof.public_values[pv::IN0 + k], expected_hin[k] as u64, "{name}: H_IN word {k}");
        }
    }
}

/// M4.2: the end-to-end anchor for the whole `KECCAK` path — guest sponge, `SYS_KECCAK` cpu
/// row, the keccak chip's 24 rounds and its own `MEMORY` traffic, the proof-declared keccak
/// height — checked against the host `keccak::keccak256` for the same message.
#[test]
fn keccak_demo_proves_and_verifies_at_tier_10() {
    let m = Machine::new(FriProfile::Test);
    let msg: Vec<u8> = (0..64u8).collect();
    let p = guests::keccak_demo(&msg);
    let exec = rand_zkvm::emulator::execute(&p, &[], Tier(10).max_cycles()).unwrap();
    let want = rand_zkvm::keccak::keccak256(&msg);
    for k in 0..8 {
        assert_eq!(exec.outputs[k], u32::from_le_bytes(want[4 * k..4 * k + 4].try_into().unwrap()), "digest word {k}");
    }
    let t0 = std::time::Instant::now();
    let (proof, _) = m.prove_salted(&p, &[], [1, 2, 3, 4], Some(Tier(10))).unwrap();
    let prove_time = t0.elapsed();
    assert_eq!(proof.keccak_log_height, 5, "one permutation fits the minimum block");
    let t1 = std::time::Instant::now();
    m.verify(&p.digest(), &proof).unwrap();
    eprintln!(
        "keccak_demo(64 bytes): tier {:?}, {} cycles, proof {} bytes, prove {:?}, verify {:?}",
        proof.tier, exec.cycles(), proof.size(), prove_time, t1.elapsed()
    );
}

/// The keccak table is present in every proof, keccak-free guests included: its height floors
/// at one (padding) block, which the verifier checks the declaration against.
#[test]
fn a_guest_without_keccak_declares_the_minimum_keccak_height() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (proof, _) = m.prove_salted(&p, &[], [0; 4], Some(Tier(10))).unwrap();
    assert_eq!(proof.keccak_log_height, 5);
    m.verify(&p.digest(), &proof).unwrap();
}

/// M4.2 (controller ruling 1): the memory table's height is **proof-declared**, floored at the
/// tier's own `2^(t+2)`. A keccak-free guest declares exactly that floor — the first cut of
/// M4.2 sized the table `log2_ceil(2^(t+2) + 100·2^(klh−5))`, and since `klh` floors at 5 the
/// `+100` term was never zero, so *every* proof in existence paid for a doubled memory table.
#[test]
fn a_keccak_free_proof_declares_the_tier_floor_memory_height() {
    use rand_zkvm::machine::build_traces_salted;
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let exec = rand_zkvm::emulator::execute(&p, &[], Tier(10).max_cycles()).unwrap();
    let accesses: usize = exec.events.iter().map(|e| e.accesses.len() + e.keccak_accesses.len()).sum();
    assert!(accesses < 1 << 12, "fib(10) is nowhere near the tier-10 floor: {accesses} accesses");
    let t = build_traces_salted(&p, &[], [0; 4], &exec, Tier(10)).unwrap();
    assert_eq!(t.mem_log_height, 12, "exactly `t + 2`");
    assert_eq!(t.memory.height(), 1 << 12);
    let proof = m.prove_traces(&p, &t, Tier(10));
    assert_eq!(proof.mem_log_height, 12);
    m.verify(&p.digest(), &proof).unwrap();
}

/// Three permutations are 300 memory accesses — real traffic the table has to hold, but still
/// two orders of magnitude below tier 10's 4 096-row floor, so the declared height does not
/// move. This is the regression the ruling exists for: under the old tier-derived formula this
/// same guest declared 13, doubling the table to buy 300 rows of room it already had.
#[test]
fn a_few_keccak_permutations_still_fit_under_the_tier_floor() {
    use rand_zkvm::machine::build_traces_salted;
    const BUF: i32 = 0x1000;
    let m = Machine::new(FriProfile::Test);
    let mut a = Assembler::new(0);
    a.extend(li(8, BUF));
    a.extend(li(5, 0x1234_5678));
    a.push(sw(8, 5, 0));
    for _ in 0..3 {
        a.extend(call_keccak(BUF / 4));
    }
    a.push(lw(5, 8, 0));
    a.extend(write_output(0, 5));
    a.extend(halt());
    let p = a.assemble();
    let exec = rand_zkvm::emulator::execute(&p, &[], Tier(10).max_cycles()).unwrap();
    assert_eq!(exec.events.iter().filter(|e| e.keccak_row.is_some()).count(), 3);
    let t = build_traces_salted(&p, &[], [0; 4], &exec, Tier(10)).unwrap();
    // Three permutations need three 32-row blocks -> 128 rows -> 2^7.
    assert_eq!(t.keccak_log_height, 7);
    let accesses: usize = exec.events.iter().map(|e| e.accesses.len() + e.keccak_accesses.len()).sum();
    assert!((300..1 << 12).contains(&accesses), "{accesses} accesses: real keccak traffic, still under the floor");
    assert_eq!(t.mem_log_height, 12, "the tier floor still wins");
    assert_eq!(t.memory.height(), 1 << 12);
    let proof = m.prove_traces(&p, &t, Tier(10));
    assert_eq!(proof.keccak_log_height, 7);
    assert_eq!(proof.mem_log_height, 12);
    m.verify(&p.digest(), &proof).unwrap();
}

/// And when the traffic genuinely outgrows the floor, the declaration follows it: 40
/// permutations are 4 000 chip-sent accesses on their own, past tier 10's 4 096-row floor once
/// the guest's own register traffic is added. The memory trace is sized by the declared value
/// and the verifier's degree-bits check agrees with it.
#[test]
fn enough_keccak_permutations_raise_the_declared_memory_height_past_the_floor() {
    use rand_zkvm::machine::build_traces_salted;
    const BUF: i32 = 0x1000;
    let m = Machine::new(FriProfile::Test);
    let mut a = Assembler::new(0);
    for _ in 0..40 {
        a.extend(call_keccak(BUF / 4));
    }
    a.extend(halt());
    let p = a.assemble();
    let exec = rand_zkvm::emulator::execute(&p, &[], Tier(10).max_cycles()).unwrap();
    assert_eq!(exec.events.iter().filter(|e| e.keccak_row.is_some()).count(), 40);
    let t = build_traces_salted(&p, &[], [0; 4], &exec, Tier(10)).unwrap();
    let accesses: usize = exec.events.iter().map(|e| e.accesses.len() + e.keccak_accesses.len()).sum();
    assert!(((1 << 12)..1 << 13).contains(&accesses), "{accesses} accesses: past the floor, inside one more bit");
    assert_eq!(t.mem_log_height, 13, "the access count now drives the height");
    assert_eq!(t.memory.height(), 1 << 13);
    // 40 permutations need 40 blocks -> 1 280 rows -> 2^11, comfortably inside tier 10's own
    // ceiling of `t + 5 = 15`.
    assert_eq!(t.keccak_log_height, 11);
    let proof = m.prove_traces(&p, &t, Tier(10));
    assert_eq!(proof.mem_log_height, 13);
    m.verify(&p.digest(), &proof).unwrap();
}

#[test]
fn tier_padding_hides_cycle_count() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(5);
    let (p10, e) = m.prove(&p, &[], Some(Tier(10))).unwrap();
    let (p12, _) = m.prove(&p, &[], Some(Tier(12))).unwrap();
    assert!(e.cycles() < 100);
    m.verify(&p.digest(), &p10).unwrap();
    m.verify(&p.digest(), &p12).unwrap();
    assert_ne!(p10.batch.degree_bits, p12.batch.degree_bits);
    assert_eq!(p10.public_values[1], 10);
    assert_eq!(p12.public_values[1], 12);
}

#[test]
fn a_fresh_verifier_accepts_the_proof() {
    let prover = Machine::new(FriProfile::Test);
    let verifier = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (proof, _) = prover.prove(&p, &[], None).unwrap();
    // M3.4: the verifier never touches `p`'s words at all — only its digest, `hc`, which
    // both sides compute identically (`Program::digest` is a pure host-side function, no
    // `Machine` involved) and which the proof itself carries as a public value.
    verifier.verify(&p.digest(), &proof).unwrap();
    assert_eq!(p.code_hash(), p.digest().iter().map(|w| format!("{w:08x}")).collect::<String>());
    assert_ne!(p.code_hash(), guests::fib(11).code_hash());
}

#[test]
fn verifier_key_is_cached_after_first_verify() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (proof, _) = m.prove(&p, &[], None).unwrap();
    let t0 = std::time::Instant::now();
    m.verify(&p.digest(), &proof).unwrap();
    let first = t0.elapsed();
    let t1 = std::time::Instant::now();
    m.verify(&p.digest(), &proof).unwrap();
    let second = t1.elapsed();
    // Threshold retuned in M2.3: splitting the 2^16-row byte table into the 256-row range
    // and nibble tables made the uncached key build itself much cheaper, so the fixed
    // per-verify FRI-opening cost that caching can't remove is now a bigger share of
    // `first` — the measured ratio dropped from well under 10% to a consistent ~23-24%
    // (repeated locally), so 10% is no longer a safe bound. 40% keeps a comfortable margin
    // above that while still requiring a real, substantial caching win, not just noise.
    assert!(
        second < first * 2 / 5,
        "cached verify should be under 40% of the first: first={first:?} second={second:?}"
    );
    assert_eq!(m.cached_keys(), 1);
}

#[test]
#[ignore]
fn measure_production_profile_at_tier_10_and_12() {
    let m = Machine::new(FriProfile::Production);
    // `fib(650)` runs 3910 cycles: past tier 10's max (1023) and within tier 12's max
    // (4095), so `prove(.., Some(Tier(12)))` actually exercises tier 12's padded height
    // rather than erroring `TooManyCycles` (as `fib(900)`, 5410 cycles, does).
    for (label, tier, n) in [("tier 10", Tier(10), 10u32), ("tier 12", Tier(12), 650u32)] {
        let p = guests::fib(n);
        let t0 = std::time::Instant::now();
        let (proof, _) = m.prove(&p, &[], Some(tier)).unwrap();
        let prove_time = t0.elapsed();
        let t1 = std::time::Instant::now();
        m.verify(&p.digest(), &proof).unwrap();
        let verify_time = t1.elapsed();
        println!("{label}: proof size = {} bytes, prove = {:?}, verify = {:?}", proof.size(), prove_time, verify_time);
    }
}

#[test]
fn compiled_fib_matches_the_hand_written_guest() {
    use rand_zkvm::emulator::execute;
    let compiled = guests::compiled::fib();
    let hand = guests::fib(20);
    let exec_c = execute(&compiled, &[20], 50_000).unwrap();
    let exec_h = execute(&hand, &[], 50_000).unwrap();
    assert_eq!(exec_c.outputs[0], exec_h.outputs[0]);
}

#[test]
fn compiled_fib_proves_and_verifies() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::compiled::fib();
    let (proof, exec) = m.prove(&p, &[20], None).unwrap();
    eprintln!("compiled fib(20): tier {:?}, {} cycles, proof {} bytes", proof.tier, exec.cycles(), proof.size());
    m.verify(&p.digest(), &proof).unwrap();
}

/// The M4.2 exit test: Keccak-256 of a 135-byte message (one byte shy of the 136-byte rate, so
/// the `0x01`/`0x80` padding still fits the same block) computed by a *compiled* guest —
/// `guest_sdk::keccak256`'s sponge over the `KECCAK` syscall, built by
/// `guests-compiled/keccak256`'s Makefile — matches the host `keccak::keccak256`, in exactly one
/// permutation, and the whole thing proves and verifies.
#[test]
fn compiled_keccak256_matches_the_host_in_one_permutation() {
    use rand_zkvm::keccak;
    let m = Machine::new(FriProfile::Test);
    let p = guests::compiled::keccak256();
    let msg: Vec<u8> = (0..135u8).map(|i| i.wrapping_mul(31)).collect();
    let mut inputs = vec![msg.len() as u32];
    for c in msg.chunks(4) {
        let mut w = [0u8; 4];
        w[..c.len()].copy_from_slice(c);
        inputs.push(u32::from_le_bytes(w));
    }
    let exec = rand_zkvm::emulator::execute(&p, &inputs, Tier(12).max_cycles()).unwrap();
    let want = keccak::keccak256(&msg);
    for k in 0..8 {
        assert_eq!(exec.outputs[k], u32::from_le_bytes(want[4 * k..4 * k + 4].try_into().unwrap()), "digest word {k}");
    }
    assert_eq!(exec.events.iter().filter(|e| e.keccak_row.is_some()).count(), 1, "one rate block, one permutation");
    let t0 = std::time::Instant::now();
    let (proof, _) = m.prove_salted(&p, &inputs, [5, 6, 7, 8], None).unwrap();
    let prove_time = t0.elapsed();
    assert_eq!(proof.keccak_log_height, 5, "one permutation fits the minimum block");
    let t1 = std::time::Instant::now();
    m.verify(&p.digest(), &proof).unwrap();
    eprintln!(
        "keccak256 guest: {} words, {} cycles, tier {}, keccak_log_height {}, mem_log_height {}, proof {} bytes, prove {:?}, verify {:?}",
        p.words.len(), exec.cycles(), proof.tier.0, proof.keccak_log_height, proof.mem_log_height,
        proof.to_bytes().len(), prove_time, t1.elapsed()
    );
}
