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
/// length is checked against): the program is 1 207 words, i.e. 302 digest-row permutations
/// plus 1 indigest-row one — 303 permutation blocks, past `Tier(10).poseidon2_height()`'s 128
/// (audit ZL4, 2026-09-12: the old wording's arithmetic was wrong; `Tier(12)`'s 512 would
/// actually suffice, and 14 is chosen only for margin). `Tier::poseidon2_height`'s scaling
/// relative to `cpu_height` is a separate concern — since the 2026-09-12 audit fix,
/// `build_traces_salted` rejects a tier whose permutation budget the workload exceeds with a
/// clean `ProveError::TooManyPoseidon2Permutations`, and the auto-tier pick
/// (`Tier::for_workload`) climbs past it instead of hitting `poseidon2_trace`'s old capacity
/// panic. What this test isolates is exactly the bug this fix closes: the *program table's own
/// height* — independently confirmed below via `traces.program.height()` — tracks the program's
/// length, not the tier, so it is not the thing that would have forced a larger tier here.
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
    assert_eq!(p.len(), 1_207, "the permutation arithmetic in this test's doc comment");
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
    // M4.2 (Task 6): a proof that *does* call `KECCAK` carries the ninth instance.
    assert_eq!(proof.batch.degree_bits.len(), 9, "nine tables when the keccak table is present");
    let t1 = std::time::Instant::now();
    m.verify(&p.digest(), &proof).unwrap();
    eprintln!(
        "keccak_demo(64 bytes): tier {:?}, {} cycles, proof {} bytes, prove {:?}, verify {:?}",
        proof.tier, exec.cycles(), proof.size(), prove_time, t1.elapsed()
    );
}

/// Measured on the branch base `b1d01d9` — the last commit before the keccak table — with
/// `guests::fib(10)` at `Tier(10)` and `FriProfile::Test`, three consecutive proofs:
/// 274 156 / 275 916 / 276 684 bytes (the hiding PCS's fresh per-proof entropy moves the
/// postcard encoding by a few hundred bytes run to run). This constant is the middle of that
/// spread; `SIZE_BAND_PCT` is the tolerance around it.
const PRE_M4_2_TIER_10_TEST_PROFILE_BYTES: usize = 275_916;

/// Tolerance, in percent, on the size assertion in `a_keccak_free_proof_carries_no_keccak_table`.
///
/// Derived, not picked: the three measured proofs above span 274 156..276 684, i.e. ±0.5% around
/// the constant, so 5% is ~10x the per-proof entropy noise — room for the odd extra
/// declared-height byte or an upstream postcard tweak. The thing the assertion exists to detect
/// is an order of magnitude beyond it: a 2 612-column keccak table adds roughly +450 KB at this
/// profile (+1.91 MB at the production one), i.e. +160%, so the band would have to be ~32x wider
/// before the regression could hide inside it. The load-bearing check is the
/// `degree_bits.len() == 8` assertion; this one is the size corroboration.
const SIZE_BAND_PCT: usize = 5;

/// M4.2 (Task 6): the keccak table is **optional per proof**. A guest that never executes a
/// `KECCAK` syscall declares `keccak_log_height = 0`, the batch has eight instances rather than
/// nine, and the proof is back to its pre-M4.2 size — the padding block that used to cost every
/// proof ~1.91 MB at the production profile (~705 KB at the 27 queries M4.2 measured) is simply
/// not there.
///
/// The cpu table is unchanged by this: with no keccak table in the batch, the `KECCAK` bus has
/// no provider at all, so a cpu row claiming `SYS_KECCAK = 1` leaves that bus unbalanced (see
/// `tests/cheating.rs::a_keccak_syscall_without_a_keccak_table_is_rejected`).
#[test]
fn a_keccak_free_proof_carries_no_keccak_table() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (proof, _) = m.prove_salted(&p, &[], [0; 4], Some(Tier(10))).unwrap();
    assert_eq!(proof.keccak_log_height, 0, "no KECCAK call, no keccak table");
    assert_eq!(proof.batch.degree_bits.len(), 8, "eight instances, not nine");
    m.verify(&p.digest(), &proof).unwrap();

    let size = proof.to_bytes().len();
    let lo = PRE_M4_2_TIER_10_TEST_PROFILE_BYTES * (100 - SIZE_BAND_PCT) / 100;
    let hi = PRE_M4_2_TIER_10_TEST_PROFILE_BYTES * (100 + SIZE_BAND_PCT) / 100;
    assert!(
        (lo..=hi).contains(&size),
        "keccak-free proof should be back within {SIZE_BAND_PCT}% of the pre-M4.2 size \
         ({PRE_M4_2_TIER_10_TEST_PROFILE_BYTES} bytes): got {size}"
    );
    eprintln!("keccak-free fib(10) at tier 10, Test profile: {size} bytes (pre-M4.2: {PRE_M4_2_TIER_10_TEST_PROFILE_BYTES})");
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

/// M4.4: the end-to-end anchor for the whole `SHA256` path — the guest's own padding, the
/// `SYS_SHA256` cpu row, the sha256 chip's 64 rounds and its own 32 `MEMORY` accesses, the
/// proof-declared sha256 height — checked against the host `sha256::sha256` for the same
/// message. One 55-byte message is one padded 512-bit block, i.e. exactly one compression, so
/// `sha256_log_height` sits at its floor of 6 (one 64-row block).
#[test]
fn sha256_demo_proves_and_verifies_with_one_sha256_block() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::sha256_demo();
    let exec = rand_zkvm::emulator::execute(&p, &[], Tier(10).max_cycles()).unwrap();
    // 55 bytes: the largest message whose `0x80 ‖ zeros ‖ be64(bitlen)` padding still fits one
    // 64-byte block. `guests::SHA256_DEMO_MSG` is the same literal the guest hashes; the length
    // assertion is what keeps the two from drifting into a two-block message, which
    // `sha256_demo` (a single `SHA256` call, no Merkle–Damgård loop) could not hash.
    let msg = b"The quick brown fox jumps over the lazy dog............";
    assert_eq!(msg.len(), 55, "one padded block");
    assert_eq!(msg, guests::SHA256_DEMO_MSG, "the test and the guest hash the same message");
    let want = rand_zkvm::sha256::sha256(msg);
    for k in 0..8 {
        assert_eq!(
            exec.outputs[k],
            u32::from_be_bytes(want[4 * k..4 * k + 4].try_into().unwrap()),
            "digest word {k}",
        );
    }
    assert_eq!(exec.events.iter().filter(|e| e.sha256_row.is_some()).count(), 1, "one compression");
    let t0 = std::time::Instant::now();
    let (proof, _) = m.prove_salted(&p, &[], [1, 2, 3, 4], None).unwrap();
    let prove_time = t0.elapsed();
    assert_eq!(proof.tier, Tier(10));
    assert_eq!(proof.sha256_log_height, 6, "one compression fills the minimum block exactly");
    assert_eq!(proof.keccak_log_height, 0, "and it calls no KECCAK, so that table is absent");
    // Nine instances: the eight every proof carries plus the sha256 chip. The keccak chip is
    // the one that is absent here — the sha256 entry is the *tenth* slot in `chips()` order, so
    // a batch can carry either, both or neither.
    assert_eq!(proof.batch.degree_bits.len(), 9, "eight tables plus sha256");
    let t1 = std::time::Instant::now();
    m.verify(&p.digest(), &proof).unwrap();
    eprintln!(
        "sha256_demo(55 bytes): tier {:?}, {} cycles, proof {} bytes, prove {:?}, verify {:?}",
        proof.tier, exec.cycles(), proof.size(), prove_time, t1.elapsed()
    );
}

/// The sha256 table is optional per proof exactly as the keccak table is (M4.2 Task 6's
/// pattern, applied to a 466-column chip): a guest that never executes `SHA256` declares
/// `sha256_log_height = 0` and the batch has no sha256 instance at all, which is what makes a
/// cpu row claiming `SYS_SHA256` unprovable there (`tests/cheating.rs::
/// sha256_row_without_a_sha256_table_is_rejected`).
#[test]
fn a_sha256_free_proof_carries_no_sha256_table() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (proof, _) = m.prove_salted(&p, &[], [1, 2, 3, 4], Some(Tier(10))).unwrap();
    assert_eq!(proof.sha256_log_height, 0, "no SHA256 call, no sha256 table");
    assert_eq!(proof.keccak_log_height, 0, "and no KECCAK call either");
    assert_eq!(proof.batch.degree_bits.len(), 8, "the eight tables every proof carries");
    m.verify(&p.digest(), &proof).unwrap();
}

/// What one declared sha256 table costs a proof, measured the way M4.2 measured keccak's: the
/// **same guest**, the same tier, the same declared heights, differing only in whether the batch
/// carries the sha256 instance. `fib(10)` makes no `SHA256` call, so its honest sha256 table is a
/// single all-padding block — which is a perfectly provable witness (AGENTS.md invariant 2: with
/// `IS_REAL = 0` every bus count on every row is zero, so the block sends no memory traffic and
/// provides no `SHA256` entry), and that is exactly the shape a non-optional chip would have
/// forced on every proof in existence. Both proofs verify; the delta between them is the number
/// `docs/03-privacy.md` carries.
///
/// The assertions are deliberately loose (the hiding PCS moves each encoding ~1% run to run);
/// what they pin is the order of magnitude, i.e. that the instance is neither free nor
/// keccak-sized.
#[test]
fn a_declared_sha256_table_costs_about_a_hundred_kilobytes_at_the_test_profile() {
    use rand_zkvm::machine::build_traces_salted;
    use rand_zkvm::tables::sha256;
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let exec = rand_zkvm::emulator::execute(&p, &[], Tier(10).max_cycles()).unwrap();
    let mut t = build_traces_salted(&p, &[], [1, 2, 3, 4], &exec, Tier(10)).unwrap();
    assert_eq!(t.sha256_log_height, 0, "fib makes no SHA256 call");
    let free = m.prove_traces(&p, &t, Tier(10));
    m.verify(&p.digest(), &free).unwrap();

    t.sha256 = Some(sha256::sha256_trace(&[], sha256::MIN_LOG_HEIGHT));
    t.sha256_log_height = sha256::MIN_LOG_HEIGHT;
    let carried = m.prove_traces(&p, &t, Tier(10));
    m.verify(&p.digest(), &carried).unwrap();

    let (a, b) = (free.size(), carried.size());
    eprintln!(
        "Test profile, tier 10, fib(10): sha256 table absent {a} bytes, one padding block {b} bytes, delta {} bytes",
        b as i64 - a as i64,
    );
    assert!(b > a + 50_000, "a 466 + 10-column instance is not free: {a} -> {b}");
    assert!(b < a + 200_000, "nor is it keccak-sized: {a} -> {b}");
}

/// The same comparison at the profile that actually ships (80 queries, blowup 8, 20 PoW bits) —
/// the number `docs/03-privacy.md`'s profile table needs, and the one that says whether a guest
/// calling `SHA256` still fits the node's proof cap. Ignored for the same reason
/// `measure_production_profile_at_tier_10_and_12` is: two production-profile proofs are ~13 s.
#[test]
#[ignore]
fn measure_the_sha256_table_cost_at_the_production_profile() {
    use rand_zkvm::machine::build_traces_salted;
    use rand_zkvm::tables::sha256;
    let m = Machine::new(FriProfile::Production);
    let p = guests::fib(10);
    let exec = rand_zkvm::emulator::execute(&p, &[], Tier(10).max_cycles()).unwrap();
    let mut t = build_traces_salted(&p, &[], [1, 2, 3, 4], &exec, Tier(10)).unwrap();
    let t0 = std::time::Instant::now();
    let free = m.prove_traces(&p, &t, Tier(10));
    let free_prove = t0.elapsed();
    m.verify(&p.digest(), &free).unwrap();
    t.sha256 = Some(sha256::sha256_trace(&[], sha256::MIN_LOG_HEIGHT));
    t.sha256_log_height = sha256::MIN_LOG_HEIGHT;
    let t1 = std::time::Instant::now();
    let carried = m.prove_traces(&p, &t, Tier(10));
    let carried_prove = t1.elapsed();
    m.verify(&p.digest(), &carried).unwrap();
    println!(
        "Production profile, tier 10, fib(10): sha256 absent {} bytes ({:?} to prove), one block {} bytes ({:?}), delta {} bytes",
        free.size(), free_prove, carried.size(), carried_prove,
        carried.size() as i64 - free.size() as i64,
    );
    // And a guest that genuinely hashes, for the whole-proof number.
    let d = guests::sha256_demo();
    let t2 = std::time::Instant::now();
    let (proof, dexec) = m.prove_salted(&d, &[], [1, 2, 3, 4], Some(Tier(10))).unwrap();
    let demo_prove = t2.elapsed();
    m.verify(&d.digest(), &proof).unwrap();
    println!(
        "Production profile, tier 10, sha256_demo: {} words, {} cycles, slh {}, mem 2^{}, {} bytes ({:?} to prove)",
        d.words.len(), dexec.cycles(), proof.sha256_log_height, proof.mem_log_height, proof.size(), demo_prove,
    );
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

    // M4.2 (Task 6): `keccak_log_height` is part of the cache key, and `0` (no keccak table,
    // eight instances) is a *distinct* key from `5` (one block, nine instances) — they are
    // different chip sets, so they cannot share a `CommonData`. Everything else held equal
    // (same tier, same declared program/input heights), asking for both must miss the
    // cache separately and hand back two different keys.
    assert_eq!(proof.keccak_log_height, 0, "fib is keccak-free");
    assert_eq!(proof.sha256_log_height, 0, "and sha256-free");
    let (t, plh, ilh) = (proof.tier, proof.program_log_height, proof.input_log_height);
    let bare = m.verifier_key(t, plh, ilh, 0, 0);
    assert_eq!(m.cached_keys(), 1, "the hash-table-free key is the one `verify` already cached");
    let with_keccak = m.verifier_key(t, plh, ilh, 5, 0);
    assert_eq!(m.cached_keys(), 2, "`keccak_log_height = 5` is a different cache key from `0`");
    assert!(!std::sync::Arc::ptr_eq(&bare, &with_keccak));
    // M4.4: `sha256_log_height` is the key's fifth component, and independent of the fourth —
    // the four combinations of "declares a keccak table" x "declares a sha256 table" are four
    // different chip sets and therefore four different `CommonData`s.
    let with_sha256 = m.verifier_key(t, plh, ilh, 0, 6);
    assert_eq!(m.cached_keys(), 3, "`sha256_log_height = 6` is a different cache key again");
    let with_both = m.verifier_key(t, plh, ilh, 5, 6);
    assert_eq!(m.cached_keys(), 4, "and both together is a fourth");
    assert!(!std::sync::Arc::ptr_eq(&with_keccak, &with_sha256));
    assert_eq!(bare.lookups.len(), 8, "eight instances");
    assert_eq!(with_keccak.lookups.len(), 9, "nine instances");
    assert_eq!(with_sha256.lookups.len(), 9, "nine instances — sha256 in keccak's place");
    assert_eq!(with_both.lookups.len(), 10, "ten instances");
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
    // Audit ZM1 (2026-09-12): what a proof that *does* carry the keccak table costs at the
    // restored 80-query profile — the same comparison `docs/03-privacy.md`'s M4.2 table makes,
    // re-measured because FRI leaf openings scale with the query count.
    let msg: Vec<u8> = (0..64u8).collect();
    let p = guests::keccak_demo(&msg);
    let t0 = std::time::Instant::now();
    let (proof, _) = m.prove(&p, &[], Some(Tier(10))).unwrap();
    let prove_time = t0.elapsed();
    assert_eq!(proof.keccak_log_height, 5);
    let t1 = std::time::Instant::now();
    m.verify(&p.digest(), &proof).unwrap();
    println!("tier 10 with a keccak table: proof size = {} bytes, prove = {:?}, verify = {:?}", proof.size(), prove_time, t1.elapsed());
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

/// Audit ZM2 (2026-09-12), a *completeness* regression: the memory table's host-side sort key
/// packed `(space << 30) | addr` while the AIR recomputes `SPACE·2^30 + ADDR`. The two coincide
/// only below `addr < 2^30` — and `POSEIDON2`'s derived addresses legitimately reach past it
/// (`HASH_PTR < 2^30` is the AIR's bound, plus up to 4099 words). With `|`, an honest execution
/// whose hash addresses straddle `2^30` sorted its rows into an order whose in-circuit keys
/// *decrease* at the boundary, and the `dk` delta limbs then rejected the honest witness (and
/// `(1, x)` / `(1, 2^30 + x)` collided into one key outright). Latent only because every
/// current guest uses low memory; the hash syscall is exactly the feature that can reach there.
///
/// `ptr = 2^30 - 4` with `n = 4`: the absorb row reads `2^30-4 .. 2^30-1`, and the two
/// write-back rows write `2^30-4 .. 2^30+3` — straddling the boundary in one honest call.
#[test]
fn a_hash_call_whose_addresses_straddle_2_to_the_30_proves() {
    let m = Machine::new(FriProfile::Test);
    let mut a = Assembler::new(0);
    a.extend(call_poseidon2(((1u32 << 30) - 4) as i32, 4));
    a.extend(li(5, 7));
    a.extend(write_output(0, 5));
    a.extend(halt());
    let p = a.assemble();
    let (proof, exec) = m.prove(&p, &[], None).unwrap();
    assert_eq!(exec.outputs[0], 7);
    m.verify(&p.digest(), &proof).unwrap();
}

// ---- M4.4's exit test: an SPL Token `Transfer` through the compiled sBPF guest ------------------
//
// **The proving half of this exit test does not pass, and is `#[ignore]`d with the measurement that
// says why.** The guest is correct — `compiled_sbpf_spl_token_transfer_executes_and_publishes_the_
// bound_digest` below runs it in the machine's own executor and gets the eight words `sbpf-core`
// produces natively, over the real SPL Token ELF fetched from mainnet — but it takes **1 753 945
// cycles**, and the largest tier this machine has is 20, whose budget is 1 048 575
// (`machine::TIERS`). The M4.4 plan requires tier ≤ 18 (262 143).
//
// The cause is one of the plan's own rulings, and it is structural rather than a matter of tuning
// (measured breakdown in `docs/04-guests.md`):
//
// * `program_hash = sha256(elf bytes)` is computed **inside the guest**, over all 108 600 bytes of
//   the committed ELF. That is 1 698 of the 2 368 compressions (72 %) and 27 151 of the 37 609 input
//   words (72 %) — about 1.20 M of the 1.75 M cycles — spent on a program the run otherwise reads a
//   few thousand bytes of. The plan anticipated exactly this ("the ELF's ~1 600 compressions
//   dominate the row count … a follow-up may bind the program by a cached digest instead") but still
//   made tier ≤ 18 an exit criterion; for a 108 KB program the two cannot both hold.
// * `input_hash` is over the *aligned* region, which is 40 960 of its 41 825 bytes of
//   `MAX_PERMITTED_DATA_INCREASE` realloc padding — 98 % zeros. 640 of its 654 compressions hash
//   nothing but those zeros.
//
// Together those two account for ~1.5 M of the 1.75 M. Neither can be fixed inside Task 6's remit:
// the first needs the public-output ruling changed (a declared or cached program digest), the second
// needs `input_hash` taken over a canonical unpadded encoding of the instruction. With both, the
// remaining work is ~250 k cycles, i.e. tier 18 — which is the recommendation this task's report
// carries.

/// M4.4's exit test, the executor half — this one passes. The compiled sBPF guest runs an SPL Token
/// `Transfer` over the ELF fetched from the live program account, and the eight public output words
/// it publishes are exactly the ones `sbpf-core` produces natively: `out0 = 1` (the program returned
/// `r0 == 0`) and `out1..7` the Poseidon2 digest over the program, the instruction and the accounts'
/// post-state, all three bound through SHA-256 and therefore through the M4.4 chip.
///
/// Every number the M4.4 plan asks Task 6 to record is printed here and pinned below.
#[test]
fn compiled_sbpf_spl_token_transfer_executes_and_publishes_the_bound_digest() {
    use rand_zkvm::sbpf::{deserialize_accounts, spl_transfer, TOKEN_AMOUNT_AT};
    let p = guests::compiled::sbpf();
    let call = spl_transfer(250);
    let inputs = call.input_words();
    let (want, r0, post) = call.expected();
    assert_eq!(r0, Ok(0));
    assert_eq!(want[0], 1);

    // The transfer really moved the balance, in the fixture's own terms.
    let pre = deserialize_accounts(&call.input);
    let bal =
        |d: &[u8]| u64::from_le_bytes(d[TOKEN_AMOUNT_AT..TOKEN_AMOUNT_AT + 8].try_into().unwrap());
    assert_eq!(bal(&pre[0].data) - 250, bal(&post[0].data));
    assert_eq!(bal(&pre[1].data) + 250, bal(&post[1].data));

    // The cap is not a tier's budget: see the comment above this test. It is a bound that fails
    // loudly if the guest ever runs away, rather than the tier the plan asked for.
    const CYCLE_CAP: usize = 4_000_000;
    let exec = rand_zkvm::emulator::execute(&p, &inputs, CYCLE_CAP).unwrap();
    assert_eq!(exec.outputs, want, "the in-circuit guest and the native run must agree");

    let compressions = exec.events.iter().filter(|e| e.sha256_row.is_some()).count();
    // A pure function of the two input lengths: ceil-with-padding over 108 600 ELF bytes (1 698) and
    // 41 825 instruction-region bytes (654), plus the pre- and post-state account walks (8 each).
    assert_eq!(compressions, 2_368, "1698 program + 654 input + 2x8 accounts");
    assert_eq!(
        rand_zkvm::tables::sha256::sha256_log_height(compressions),
        18,
        "2 368 blocks of 64 rows",
    );
    // Two bounds, in both directions, and neither is decoration. The upper one catches a runaway;
    // the lower one is the tripwire that says the milestone's blocker has been lifted — if the guest
    // ever fits `Tier(20)`, the real exit test can be un-ignored and this assertion is the thing
    // that will tell whoever did it.
    assert!(
        exec.cycles() <= 1_800_000,
        "{} cycles, was 1 753 945 when M4.4 measured it",
        exec.cycles()
    );
    assert!(
        exec.cycles() > Tier(20).max_cycles(),
        "{} cycles now fits Tier(20): un-ignore \
         compiled_sbpf_spl_token_transfer_proves_and_verifies and re-measure the docs",
        exec.cycles()
    );
    // The sBPF instruction count is the interpreter's own meter, which only the native run can
    // report — the executor counts RV32 cycles, not sBPF instructions.
    let native = rand_zkvm::sbpf::run_elf(&mut call.elf.clone(), &mut call.input.clone());
    assert_eq!(native.result, Ok(0));
    eprintln!(
        "sbpf spl transfer: {} program words, {} input words, {} cycles, {} sBPF instructions, \
         frame high-water {}, {} sha256 compressions, sha256_log_height {}, needs a tier above {} \
         (max {:?})",
        p.len(),
        inputs.len(),
        exec.cycles(),
        native.instructions,
        native.max_depth,
        compressions,
        rand_zkvm::tables::sha256::sha256_log_height(compressions),
        Tier(20).max_cycles(),
        Tier(20),
    );
}

/// A transfer exceeding the source balance returns `TokenError::InsufficientFunds` (`r0 != 0`):
/// status 0, and the pre-state bound as the post-state. The executor agrees with the native run, so
/// the failure path is in-circuit code too — and it is the rule that stops a partial effect being
/// published.
#[test]
fn compiled_sbpf_spl_token_transfer_of_too_much_fails_cleanly() {
    let p = guests::compiled::sbpf();
    let call = rand_zkvm::sbpf::spl_transfer(u64::MAX / 2);
    let (want, r0, post) = call.expected();
    assert!(matches!(r0, Ok(code) if code != 0));
    assert_eq!(want[0], 0);
    assert_eq!(post, rand_zkvm::sbpf::deserialize_accounts(&call.input));
    let exec = rand_zkvm::emulator::execute(&p, &call.input_words(), 4_000_000).unwrap();
    assert_eq!(exec.outputs, want);
    // Status 0 is not the only difference from the success case: the digest words differ too,
    // because a successful transfer's post-state is not its pre-state.
    let ok = rand_zkvm::sbpf::spl_transfer(250).expected().0;
    assert_ne!(&want[1..], &ok[1..], "the two runs must not publish the same digest");
}

/// M4.4's exit test as the plan wrote it: the `Transfer` proves and verifies at tier 18 or lower.
///
/// `#[ignore]`d because it cannot pass on this machine — see the comment above
/// `compiled_sbpf_spl_token_transfer_executes_and_publishes_the_bound_digest` for the measured
/// reason and what has to change. It is written out in full so that the moment a declared program
/// digest or a canonical instruction encoding lands, un-ignoring this is the whole of the work.
#[test]
#[ignore = "1 753 945 cycles: above Tier(20)'s 1 048 575 budget, let alone the plan's tier 18 — \
            72 % of it is program_hash over the 108 600-byte ELF (docs/04-guests.md)"]
fn compiled_sbpf_spl_token_transfer_proves_and_verifies() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::compiled::sbpf();
    let call = rand_zkvm::sbpf::spl_transfer(250);
    let inputs = call.input_words();
    let (want, _r0, _post) = call.expected();
    let exec = rand_zkvm::emulator::execute(&p, &inputs, Tier(18).max_cycles()).unwrap();
    assert_eq!(exec.outputs, want);
    let (proof, _) = m.prove_salted(&p, &inputs, [13, 14, 15, 16], None).unwrap();
    eprintln!(
        "sbpf spl transfer: {} program words, {} input words, {} cycles, {} sha256 compressions, \
         tier {}, sha256_log_height {}, mem_log_height {}, proof {} bytes",
        p.len(),
        inputs.len(),
        exec.cycles(),
        exec.events.iter().filter(|e| e.sha256_row.is_some()).count(),
        proof.tier.0,
        proof.sha256_log_height,
        proof.mem_log_height,
        proof.size(),
    );
    m.verify(&p.digest(), &proof).unwrap();
    assert!(proof.tier.0 <= 18, "M4.4 requires tier <= 18");
    assert!(proof.sha256_log_height >= 6);
}

/// Where the sBPF guest's cycles go, as a pc histogram mapped onto the guest binary's symbols — the
/// breakdown the M4.4 plan asks for whenever the exit test lands above tier 16, and the measurement
/// `docs/04-guests.md`'s cost table is built from. Writes `sbpf-pc-histogram.txt` into the
/// temporary directory; pair it with
/// `llvm-nm -n --defined-only guests-compiled/sbpf/target/riscv32im-unknown-none-elf/release/sbpf-guest`.
/// `#[ignore]`d because it is a measurement, not an assertion.
#[test]
#[ignore = "measurement: writes a pc histogram for docs/04-guests.md"]
fn sbpf_cycle_breakdown_by_pc() {
    use std::collections::BTreeMap;
    let p = guests::compiled::sbpf();
    let call = rand_zkvm::sbpf::spl_transfer(250);
    let exec = rand_zkvm::emulator::execute(&p, &call.input_words(), 4_000_000).unwrap();
    let mut hist: BTreeMap<u32, usize> = BTreeMap::new();
    for e in &exec.events {
        *hist.entry(e.pc).or_default() += 1;
    }
    let path = std::env::temp_dir().join("sbpf-pc-histogram.txt");
    let mut out = String::new();
    for (pc, n) in &hist {
        out.push_str(&format!("{pc} {n}\n"));
    }
    std::fs::write(&path, out).unwrap();
    eprintln!("{} distinct pcs, {} cycles -> {}", hist.len(), exec.cycles(), path.display());
}
