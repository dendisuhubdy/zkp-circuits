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
    let (t, plh, ilh) = (proof.tier, proof.program_log_height, proof.input_log_height);
    let keccak_free = m.verifier_key(t, plh, ilh, 0);
    assert_eq!(m.cached_keys(), 1, "the keccak-free key is the one `verify` already cached");
    let with_keccak = m.verifier_key(t, plh, ilh, 5);
    assert_eq!(m.cached_keys(), 2, "`keccak_log_height = 5` is a different cache key from `0`");
    assert!(!std::sync::Arc::ptr_eq(&keccak_free, &with_keccak));
    assert_eq!(keccak_free.lookups.len(), 8, "eight instances");
    assert_eq!(with_keccak.lookups.len(), 9, "nine instances");
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

/// **M4.3's exit test, part 1 — always run.** An ERC-20 `transfer` — Solidity's own runtime
/// bytecode, run by the compiled EVM interpreter guest with the contract's storage supplied as
/// depth-32 Poseidon2 Merkle witnesses — executes in the guest and its public output binds the
/// state-root transition; the workload's tier is pinned here too.
///
/// Part 2, the proof itself, is `compiled_evm_erc20_transfer_proves_at_tier_18`, which is
/// `#[ignore]`d: a tier-18 batch is 2^18 cpu rows, 2^20 memory and poseidon2 rows and a 2 612-column
/// keccak table, and proving it peaked at ~25 GB resident and was OOM-killed twice on a 48 GB
/// machine. The always-run proof of this same guest binary is
/// `compiled_evm_storage_read_write_and_return_proves_and_verifies` below, which fits tier 16.
///
/// The pre-state seeds `_balances[ALICE] = 1000` and `_totalSupply` through witnesses, so the
/// runtime bytecode alone executes (there is no constructor). The guest's eight outputs are
/// checked against a native run of the same `evm-core` code — a proof only says that *some*
/// consistent execution exists, so the semantics are pinned on the host — and the digest is then
/// recomputed from the host's own post-state root, which is what "the transition is bound" means:
/// a verifier holding `(codehash, pre_root, post_root, return data, logs)` gets these seven words
/// and no other post-root does.
#[test]
fn compiled_evm_erc20_transfer_binds_the_state_root_transition() {
    use evm_core::u256::U256;
    use rand_zkvm::emulator::execute;
    use rand_zkvm::evm::{erc20_transfer, ALICE, BOB};
    use rand_zkvm::hash::input_digest_row_count;
    let p = guests::compiled::evm();
    let call = erc20_transfer(ALICE, BOB, U256::from_u32(250), &[(ALICE, U256::from_u32(1000))]);
    let inputs = call.input_words();
    let (want, outcome, post) = call.expected();
    assert_eq!(outcome.status(), 1, "the native run must succeed");
    assert_eq!(outcome.n_logs, 1, "one Transfer event");
    assert_ne!(post.root(), call.tree.root(), "the transfer moved the storage root");

    // `Tier(18)` is the machine's next rung above 16: `machine::TIERS` is [10, 12, 14, 16, 18, 20],
    // even only, so a workload over tier 16's 65 535 cycles pays for 2^18 rows whatever it uses.
    let exec = execute(&p, &inputs, Tier(18).max_cycles()).unwrap();
    assert_eq!(exec.outputs, want, "the guest's outputs disagree with the native run");

    // The tier the prover would pick, pinned as a number without paying for the proof: this is the
    // same arithmetic `Machine::prove` does with `tier: None` (`exec.cycles()` plus both digest
    // prefixes, against the cycle and Poseidon2-permutation budgets).
    let digest_rows = p.digest_rows();
    let indigest_rows = input_digest_row_count(inputs.len());
    let absorb = exec.events.iter().filter(|e| e.hash_row.is_some()).count();
    let cycles = exec.cycles() + digest_rows + indigest_rows;
    let perms = digest_rows + indigest_rows + absorb;
    eprintln!(
        "evm erc20 transfer: {} program words ({} of prologue), {} input words, {} cycles ({} executed + {} digest + {} indigest), {} poseidon2 permutations, {} keccak permutations, tier {:?}",
        p.words.len(), (0x1_0000 - p.base_pc) / 4, inputs.len(), cycles, exec.cycles(), digest_rows, indigest_rows,
        perms, exec.events.iter().filter(|e| e.keccak_row.is_some()).count(),
        Tier::for_workload(cycles, perms)
    );
    // The plan's exit criterion was tier ≤ 16 and the spec's estimate tier 14; the measured cost is
    // tier 18 — pinned so any change to the interpreter, the guest's program size or the input
    // layout that moves the cost fails a test rather than quietly growing a proof. Tier 16 would
    // need the whole call under 65 535 cycles, i.e. roughly half of what it costs
    // (`docs/05-roadmap.md`'s deviation 7 has the breakdown and the named follow-ups).
    assert_eq!(Tier::for_workload(cycles, perms), Some(Tier(18)), "M4.3 measures at tier 18");
    assert!(cycles > Tier(16).max_cycles(), "and not because of the permutation budget");

    // the post-tree the host derived agrees with what the guest bound: recompute the digest from
    // the host's post root, and check no *other* root gives these words.
    let mut h = rand_zkvm::evm::HostRef;
    assert_eq!(
        evm_core::abi::public_output(&mut h, &call.code, &call.tree.root(), &post.root(), &outcome),
        want
    );
    assert_ne!(
        evm_core::abi::public_output(&mut h, &call.code, &call.tree.root(), &call.tree.root(), &outcome),
        want,
        "the pre-root must not produce the same digest as the post-root"
    );
}

/// **M4.3's exit test, part 2** — the ERC-20 `transfer` proof itself, `#[ignore]`d because of its
/// size, not its correctness: the workload is tier 18 (2^18 cpu rows, 2^20 memory and poseidon2
/// rows, plus the 2 612-column keccak table), which peaked at ~25 GB resident and was OOM-killed
/// twice on the 48 GB machine M4.3 was developed on. Run it explicitly, with room:
/// `cargo +1.98.1 test --release --test e2e erc20_transfer_proves -- --ignored --nocapture`.
///
/// Everything about the call that does *not* need 25 GB —the guest's outputs, the digest binding,
/// the tier — is asserted by part 1, which always runs, and the same guest binary is proved at
/// tier 16 by the test below. What this one adds is the end-to-end fact for the milestone's own
/// wording: this proof verifies.
#[test]
#[ignore]
fn compiled_evm_erc20_transfer_proves_at_tier_18() {
    use evm_core::u256::U256;
    use rand_zkvm::evm::{erc20_transfer, ALICE, BOB};
    let m = Machine::new(FriProfile::Test);
    let p = guests::compiled::evm();
    let call = erc20_transfer(ALICE, BOB, U256::from_u32(250), &[(ALICE, U256::from_u32(1000))]);
    let inputs = call.input_words();
    let t0 = std::time::Instant::now();
    let (proof, exec) = m.prove_salted(&p, &inputs, [9, 10, 11, 12], None).unwrap();
    let prove_time = t0.elapsed();
    assert_eq!(exec.outputs, call.expected().0);
    let t1 = std::time::Instant::now();
    m.verify(&p.digest(), &proof).unwrap();
    eprintln!(
        "evm erc20 transfer proof: tier {}, keccak_log_height {}, mem_log_height {}, proof {} bytes, prove {:?}, verify {:?}",
        proof.tier.0, proof.keccak_log_height, proof.mem_log_height, proof.to_bytes().len(),
        prove_time, t1.elapsed()
    );
    assert_eq!(proof.tier.0, 18);
}

/// The compiled EVM guest proved and verified **inside the suite**: a call that reads a storage
/// slot, writes it back incremented and returns it — `SLOAD`, `SSTORE`, `MSTORE`, `RETURN`, one
/// witness verified and one Merkle path recomputed — through the same `evm.bin`, the same `hc` and
/// the same `EVM_OUT` output digest as the ERC-20 transfer, at tier 16 rather than 18 because 18
/// bytes of bytecode need neither the ERC-20's 1 296-byte `codehash` nor its second Merkle walk.
///
/// This is the test that says "the EVM interpreter guest is provable": the storage tree, the
/// 256-bit arithmetic, the `POSEIDON2` walk and the public output are all in-circuit here. The
/// ERC-20 transfer above is the same machinery on a bigger call.
#[test]
fn compiled_evm_storage_read_write_and_return_proves_and_verifies() {
    use evm_core::u256::U256;
    use rand_zkvm::evm::{EvmCall, SparseTree};
    let m = Machine::new(FriProfile::Test);
    let p = guests::compiled::evm();
    let mut tree = SparseTree::new();
    tree.insert(U256::from_u32(1), U256::from_u32(41));
    // PUSH1 1; SLOAD; PUSH1 1; ADD; PUSH1 1; SSTORE; PUSH1 1; SLOAD; PUSH0; MSTORE; PUSH1 32;
    // PUSH0; RETURN — reads slot 1 (41), writes 42 back and returns it.
    let call = EvmCall {
        code: vec![
            0x60, 0x01, 0x54, 0x60, 0x01, 0x01, 0x60, 0x01, 0x55, 0x60, 0x01, 0x54, 0x5f, 0x52,
            0x60, 0x20, 0x5f, 0xf3,
        ],
        calldata: vec![],
        address: U256::from_u32(0xaaaa),
        caller: U256::from_u32(0xcafe),
        callvalue: U256::ZERO,
        gas_limit: 100_000,
        tree,
        touched: vec![U256::from_u32(1)],
    };
    let inputs = call.input_words();
    let (want, outcome, post) = call.expected();
    assert_eq!(outcome.status(), 1);
    assert_eq!(&outcome.ret[..outcome.ret_len], &U256::from_u32(42).to_be_bytes());
    assert_ne!(post.root(), call.tree.root(), "the SSTORE moved the root");

    let t0 = std::time::Instant::now();
    let (proof, exec) = m.prove_salted(&p, &inputs, [13, 14, 15, 16], None).unwrap();
    let prove_time = t0.elapsed();
    assert_eq!(exec.outputs, want, "the guest's outputs disagree with the native run");
    let t1 = std::time::Instant::now();
    m.verify(&p.digest(), &proof).unwrap();
    eprintln!(
        "evm sload/sstore/return: {} program words, {} input words, {} cycles, {} poseidon2 permutations, {} keccak permutations, tier {}, keccak_log_height {}, mem_log_height {}, proof {} bytes, prove {:?}, verify {:?}",
        p.words.len(), inputs.len(), exec.cycles(),
        exec.events.iter().filter(|e| e.hash_row.is_some()).count(),
        exec.events.iter().filter(|e| e.keccak_row.is_some()).count(),
        proof.tier.0, proof.keccak_log_height, proof.mem_log_height, proof.to_bytes().len(),
        prove_time, t1.elapsed()
    );
    assert_eq!(proof.tier.0, 16, "one witness and 18 bytes of code fit tier 16");
}

/// `balanceOf`, `approve` and a `transfer` that exceeds the balance all run under the same guest
/// binary — one interpreter, four call shapes — and the revert carries the `require` message.
///
/// Executed, not proved: the proof in the exit test above is what shows the guest provable, and a
/// second (four-minute) proof of the same program with different private inputs would add nothing
/// to it. These run on the emulator, which is the same semantics the AIR enforces.
#[test]
fn compiled_evm_balance_of_approve_and_a_revert_execute_correctly() {
    use evm_core::u256::U256;
    use rand_zkvm::emulator::execute;
    use rand_zkvm::evm::*;
    let p = guests::compiled::evm();
    let cycles = Tier(18).max_cycles();

    // balanceOf(ALICE) returns the seeded balance and touches only that slot
    let mut bal = erc20_transfer(ALICE, BOB, U256::ZERO, &[(ALICE, U256::from_u32(1000))]);
    bal.calldata = abi_call("balanceOf(address)", &[ALICE]);
    bal.touched = vec![mapping_slot(&ALICE, SLOT_BALANCES)];
    let (want, o, bal_post) = bal.expected();
    assert_eq!(o.status(), 1);
    assert_eq!(U256::from_be_slice(&o.ret[..32]), U256::from_u32(1000));
    assert_eq!(bal_post.root(), bal.tree.root(), "a view call moves no storage");
    assert_eq!(execute(&p, &bal.input_words(), cycles).unwrap().outputs, want);

    // approve(BOB, 5): writes _allowances[ALICE][BOB] — the *nested* mapping, whose key is
    // keccak(BOB ‖ keccak(ALICE ‖ 1)) — and emits one Approval
    let mut ap = erc20_transfer(ALICE, BOB, U256::ZERO, &[]);
    ap.calldata = abi_call("approve(address,uint256)", &[BOB, U256::from_u32(5)]);
    ap.touched = vec![mapping_slot2(&ALICE, &BOB, SLOT_ALLOWANCES)];
    let (want_ap, o_ap, ap_post) = ap.expected();
    assert_eq!(o_ap.status(), 1);
    assert_eq!(o_ap.n_logs, 1, "Approval");
    assert_eq!(o_ap.logs[0].n_topics, 3);
    assert_ne!(ap_post.root(), ap.tree.root(), "the allowance was written");
    assert_eq!(execute(&p, &ap.input_words(), cycles).unwrap().outputs, want_ap);

    // transfer of 5000 against a balance of 1000 reverts with the require message
    let over = erc20_transfer(ALICE, BOB, U256::from_u32(5000), &[(ALICE, U256::from_u32(1000))]);
    let (want_r, o_r, over_post) = over.expected();
    assert_eq!(o_r.status(), 0);
    // The revert data is Solidity's ABI-encoded `Error(string)`, not the bare message: the
    // selector, the string's offset, its length, then the padded bytes. Decoding it is the point —
    // a `require` message reaches the chain only through the public output's return-data hash, so
    // the guest has to reproduce the encoding byte for byte, padding included.
    assert_eq!(&o_r.ret[..4], &selector("Error(string)"), "an ABI-encoded Error(string)");
    assert_eq!(U256::from_be_slice(&o_r.ret[4..36]), U256::from_u32(0x20), "the string's offset");
    let n = U256::from_be_slice(&o_r.ret[36..68]).low_u32() as usize;
    assert_eq!(
        core::str::from_utf8(&o_r.ret[68..68 + n]).unwrap(),
        "ERC20: transfer amount exceeds balance"
    );
    assert_eq!(o_r.ret_len, 68 + n.next_multiple_of(32), "the message is right-padded to a word");
    assert_eq!(over_post.root(), over.tree.root(), "a revert moves no storage");
    assert_eq!(execute(&p, &over.input_words(), cycles).unwrap().outputs, want_r);

    // every one of the four calls is a different public output under one program digest
    let exit = erc20_transfer(ALICE, BOB, U256::from_u32(250), &[(ALICE, U256::from_u32(1000))]);
    let outs = [want, want_ap, want_r, exit.expected().0];
    for (i, a) in outs.iter().enumerate() {
        for b in &outs[i + 1..] {
            assert_ne!(a, b, "two calls must not share a public output");
        }
    }
}

/// What an EVM-call proof costs at the profile a chain would use (80 queries, blowup 8, 20 PoW
/// bits), the figure `docs/03-privacy.md` and `docs/04-guests.md` quote: the keccak table is
/// present, so this is far above the keccak-free guests' ~1.25 MB. Ignored by default — one
/// production-profile tier-16 proof is minutes of wall time.
#[test]
#[ignore]
fn measure_production_profile_evm_erc20_transfer() {
    use evm_core::u256::U256;
    use rand_zkvm::evm::{erc20_transfer, ALICE, BOB};
    let m = Machine::new(FriProfile::Production);
    let p = guests::compiled::evm();
    let call = erc20_transfer(ALICE, BOB, U256::from_u32(250), &[(ALICE, U256::from_u32(1000))]);
    let inputs = call.input_words();
    let t0 = std::time::Instant::now();
    let (proof, exec) = m.prove_salted(&p, &inputs, [9, 10, 11, 12], None).unwrap();
    let prove_time = t0.elapsed();
    assert_eq!(exec.outputs, call.expected().0);
    let t1 = std::time::Instant::now();
    m.verify(&p.digest(), &proof).unwrap();
    println!(
        "evm erc20 transfer at the production profile: tier {}, keccak_log_height {}, proof {} bytes, prove {:?}, verify {:?}",
        proof.tier.0, proof.keccak_log_height, proof.to_bytes().len(), prove_time, t1.elapsed()
    );
}
