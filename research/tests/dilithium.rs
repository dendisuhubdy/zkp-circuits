use dilithium_core::{shake256, Shake};
use rand_zkvm::dilithium_host::HostKeccak;

#[test]
fn shake256_matches_the_crate() {
    // crystals-dilithium exposes its fips202; compare against a fixed vector instead so the test
    // does not depend on a private module: SHAKE256("") first 32 bytes (FIPS 202 test vector).
    let mut out = [0u8; 32];
    shake256(&mut HostKeccak, &[b""], &mut out);
    assert_eq!(hex(&out), "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
}

#[test]
fn shake128_streams_across_block_boundaries() {
    let mut a = Shake::new128(HostKeccak);
    a.absorb(&[7u8; 300]);
    a.finalize();
    let mut whole = [0u8; 400];
    a.squeeze(&mut whole);
    let mut b = Shake::new128(HostKeccak);
    b.absorb(&[7u8; 100]); b.absorb(&[7u8; 200]);
    b.finalize();
    let mut parts = [0u8; 400];
    b.squeeze(&mut parts[..168]); b.squeeze(&mut parts[168..]);
    assert_eq!(whole, parts);
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

#[test]
fn shake128_empty_known_answer() {
    let mut a = Shake::new128(HostKeccak);
    a.finalize();
    let mut out = [0u8; 32];
    a.squeeze(&mut out);
    assert_eq!(hex(&out), "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
}

fn oracle(rate128: bool, input: &[u8], n: usize) -> Vec<u8> {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut out = vec![0u8; n];
    if rate128 {
        let mut h = sha3::Shake128::default();
        h.update(input);
        h.finalize_xof().read(&mut out);
    } else {
        let mut h = sha3::Shake256::default();
        h.update(input);
        h.finalize_xof().read(&mut out);
    }
    out
}

#[test]
fn shake_matches_sha3_across_rate_boundaries() {
    let data: Vec<u8> = (0..700u32).map(|i| (i * 31 + 7) as u8).collect();
    for rate128 in [true, false] {
        let rate = if rate128 { 168 } else { 136 };
        for len in [0, 1, 7, 8, 9, rate - 1, rate, rate + 1, 2 * rate, 2 * rate + 5, 700] {
            // squeeze longer than one rate, in odd-sized pieces
            let n = 3 * rate + 11;
            let want = oracle(rate128, &data[..len], n);
            let mut s = if rate128 { Shake::new128(HostKeccak) } else { Shake::new256(HostKeccak) };
            // absorb in ragged pieces so lane alignment varies
            let mut i = 0;
            let mut step = 3;
            while i < len {
                let j = (i + step).min(len);
                s.absorb(&data[i..j]);
                i = j;
                step = step * 2 + 1;
            }
            s.finalize();
            let mut got = vec![0u8; n];
            let (x, rest) = got.split_at_mut(5);
            let (y, z) = rest.split_at_mut(rate);
            s.squeeze(x);
            s.squeeze(y);
            s.squeeze(z);
            assert_eq!(got, want, "rate128={rate128} len={len}");
        }
    }
}

#[test]
fn shake256_one_shot_matches_sha3() {
    let mut out = [0u8; 200];
    shake256(&mut HostKeccak, &[&[1u8; 136], b"abc"], &mut out);
    let mut inp = vec![1u8; 136];
    inp.extend_from_slice(b"abc");
    assert_eq!(out.to_vec(), oracle(false, &inp, 200));
}

// ---------------------------------------------------------------------------------------------
// Task 2: round-3 Dilithium2 verify, agreeing with `crystals_dilithium::dilithium2`.
// ---------------------------------------------------------------------------------------------

use crystals_dilithium::dilithium2::{Keypair, PublicKey};

fn case(seed: u64, msg_len: usize) -> (Keypair, Vec<u8>) {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&seed.to_le_bytes());
    let kp = Keypair::generate(Some(&s)).unwrap();
    let msg: Vec<u8> = (0..msg_len).map(|i| (i as u64 * 31 + seed) as u8).collect();
    (kp, msg)
}

fn ours(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    dilithium_core::verify(&mut HostKeccak, pk.try_into().unwrap(), msg, sig.try_into().unwrap())
}

fn theirs(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    PublicKey::from_bytes(pk).unwrap().verify(msg, sig)
}

#[test]
fn sizes_match_the_crate() {
    assert_eq!(dilithium_core::PK_BYTES, crystals_dilithium::dilithium2::PUBLICKEYBYTES);
    assert_eq!(dilithium_core::SIG_BYTES, crystals_dilithium::dilithium2::SIGNBYTES);
}

#[test]
fn honest_signatures_verify_and_agree_with_the_crate() {
    for seed in 0..200u64 {
        let (kp, msg) = case(seed, (seed as usize * 7) % 300);
        let sig = kp.sign(&msg);
        let pkb = kp.public.to_bytes();
        assert!(PublicKey::from_bytes(&pkb).unwrap().verify(&msg, &sig));
        assert!(ours(&pkb, &msg, &sig), "seed {seed}");
    }
}

#[test]
fn tampering_with_any_part_is_rejected() {
    let (kp, msg) = case(1, 45);
    let sig = kp.sign(&msg);
    let pkb = kp.public.to_bytes();
    for i in (0..sig.len()).step_by(37) {
        let mut s = sig.to_vec(); s[i] ^= 1;
        let theirs = PublicKey::from_bytes(&pkb).unwrap().verify(&msg, &s);
        assert_eq!(ours(&pkb, &msg, &s), theirs, "sig byte {i}");
    }
    let mut m = msg.clone(); m[0] ^= 1;
    assert!(!ours(&pkb, &m, &sig));
    let mut p = pkb.to_vec(); p[40] ^= 1;
    assert!(!ours(&p, &msg, &sig));
}

const HINT: usize = 32 + 4 * 576; // the OMEGA + K hint bytes at the end of the signature
const OMEGA: usize = 80;

/// The hint section's K cumulative counts.
fn hint_counts(sig: &[u8]) -> [usize; 4] {
    core::array::from_fn(|i| sig[HINT + OMEGA + i] as usize)
}

/// Controller ruling R2: each class is built from the decoded hint section of the real signature,
/// so it is genuinely malformed for this signature (not just for some signatures).
#[test]
fn malformed_signatures_agree_with_the_crate() {
    let (kp, msg) = case(2, 45);
    let sig = kp.sign(&msg);
    let pkb = kp.public.to_bytes();
    let counts = hint_counts(&sig);
    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();

    // count > OMEGA
    let mut s = sig.to_vec(); s[HINT + OMEGA] = OMEGA as u8 + 1; cases.push(("count > OMEGA", s));

    // non-monotone count: the first polynomial i with a hint gets a successor count one less
    let i = (0..3).find(|&i| counts[i] >= 1).expect("a hint in polys 0..3");
    let mut s = sig.to_vec(); s[HINT + OMEGA + i + 1] = (counts[i] - 1) as u8;
    cases.push(("non-monotone count", s));

    // nonzero tail: a nonzero byte right after the true total count
    let total = counts[3];
    assert!(total < OMEGA, "honest total {total} leaves no tail");
    let mut s = sig.to_vec(); s[HINT + total] = 1; cases.push(("nonzero tail", s));

    // indices not strictly increasing: a polynomial with >= 2 hints gets a repeated index
    let mut start = 0;
    let mut found = None;
    for &end in &counts {
        if end >= start + 2 { found = Some(start); break; }
        start = end;
    }
    let st = found.expect("a polynomial with >= 2 hints");
    let mut s = sig.to_vec(); s[HINT + st + 1] = s[HINT + st]; cases.push(("repeated index", s));
    let mut s = sig.to_vec(); s[HINT + st + 1] = s[HINT + st].wrapping_sub(1);
    if s[HINT + st] > 0 { cases.push(("decreasing index", s)); }

    // ‖z‖∞ too big
    let mut s = sig.to_vec(); for b in &mut s[32..32 + 18] { *b = 0xff; } cases.push(("‖z‖∞", s));

    // Non-canonical encodings of the *same* h: a lax parser would accept these as the honest
    // signature, so only the encoding checks reject them (the soundness-relevant malleability).
    // (a) a polynomial's first index written twice, later indices and counts shifted up by one
    let p = counts.iter().position(|&e| e >= 1).unwrap();
    let st0 = if p == 0 { 0 } else { counts[p - 1] };
    let mut s = sig.to_vec();
    s.copy_within(HINT + st0..HINT + total, HINT + st0 + 1);
    for q in p..4 { s[HINT + OMEGA + q] += 1; }
    cases.push(("duplicated index, same h", s));
    // (b) two indices of one polynomial swapped
    let mut s = sig.to_vec(); s.swap(HINT + st, HINT + st + 1); cases.push(("swapped indices, same h", s));

    for (name, s) in cases.iter() {
        let t = theirs(&pkb, &msg, s);
        assert_eq!(ours(&pkb, &msg, s), t, "case {name}");
        assert!(!t, "case {name} should be malformed");
    }
}

/// A deterministic splitmix64 stream, so the fuzz cases are reproducible without a dependency.
struct Mix(u64);
impl Mix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn fill(&mut self, b: &mut [u8]) { for x in b { *x = self.next() as u8; } }
}

#[test]
fn random_garbage_never_panics_and_agrees() {
    let mut r = Mix(0xd111_7401);
    let (kp, msg) = case(3, 64);
    let honest_sig = kp.sign(&msg);
    let honest_pk = kp.public.to_bytes();
    for n in 0..300 {
        let mut pk = [0u8; 1312];
        let mut sig = [0u8; 2420];
        r.fill(&mut pk);
        r.fill(&mut sig);
        match n % 3 {
            // fully random: almost always stops in the hint checks
            0 => {}
            // random c and z with an honest hint section and key: runs the whole pipeline
            1 => { pk = honest_pk; sig[HINT..].copy_from_slice(&honest_sig[HINT..]); }
            // honest signature and message under a random key
            _ => { sig = honest_sig; }
        }
        assert_eq!(ours(&pk, &msg, &sig), theirs(&pk, &msg, &sig), "garbage case {n}");
    }
}

#[test]
fn hint_section_mutations_agree_with_the_crate() {
    // Small perturbations of the honest hint section: counts and indices near their valid ranges.
    let mut r = Mix(0x4a17);
    let (kp, msg) = case(4, 10);
    let sig = kp.sign(&msg);
    let pkb = kp.public.to_bytes();
    let mut rejected = 0;
    for n in 0..400 {
        let mut s = sig;
        for _ in 0..1 + (r.next() % 3) {
            let pos = HINT + (r.next() as usize % (OMEGA + 4));
            let v = r.next();
            s[pos] = match v % 4 {
                0 => s[pos].wrapping_add(1),
                1 => s[pos].wrapping_sub(1),
                2 => (v >> 8) as u8 % (OMEGA as u8 + 2),
                _ => (v >> 8) as u8,
            };
        }
        let t = theirs(&pkb, &msg, &s);
        assert_eq!(ours(&pkb, &msg, &s), t, "mutation {n}");
        rejected += !t as usize;
    }
    assert!(rejected > 300, "only {rejected} mutations rejected");
}

/// The one encoding check the end-to-end tests cannot isolate: a non-monotone count list whose
/// lax decoding (skip the empty range, re-read earlier bytes) equals a canonical h. Pinned against
/// the reference's `unpack_sig` logic (sign/lvl2.rs via packing/lvl2.rs), which the crate keeps
/// private: canonical `[5, 5]` / counts `[1, 1, 2, 2]` is accepted; `[5]` / `[1, 0, 1, 1]` (same h
/// under a lax parser) is rejected.
#[test]
fn unpack_sig_encoding_checks_are_pinned() {
    use dilithium_core::packing::unpack_sig;
    use dilithium_core::poly::{Polyveck, Polyvecl};
    let run = |idx: &[u8], counts: [u8; 4]| {
        let mut sig = [0u8; 2420];
        sig[HINT..HINT + idx.len()].copy_from_slice(idx);
        sig[HINT + OMEGA..].copy_from_slice(&counts);
        let (mut c, mut z, mut h) = ([0u8; 32], Polyvecl::default(), Polyveck::default());
        let ok = unpack_sig(&mut c, &mut z, &mut h, &sig);
        let set: Vec<(usize, usize)> = (0..4)
            .flat_map(|i| (0..256).map(move |j| (i, j)))
            .filter(|&(i, j)| h.vec[i].coeffs[j] != 0)
            .collect();
        (ok, set)
    };
    assert_eq!(run(&[5, 5], [1, 1, 2, 2]), (true, vec![(0, 5), (2, 5)]));
    assert!(!run(&[5], [1, 0, 1, 1]).0);
    assert!(!run(&[5, 5], [2, 2, 2, 2]).0, "repeated index in one polynomial");
    assert!(!run(&[6, 5], [2, 2, 2, 2]).0, "decreasing indices in one polynomial");
    assert!(run(&[6, 5], [1, 2, 2, 2]).0, "the first index of a polynomial is unordered vs the last");
    assert!(!run(&[5, 0, 1], [1, 1, 1, 1]).0, "nonzero tail");
    assert!(!run(&[], [81, 81, 81, 81]).0, "count > OMEGA");
    // count > OMEGA that is otherwise consistent: indices 1..=80 then the count byte 81 itself
    // reads as an 81st increasing index, and the later counts are monotone.
    let idx: Vec<u8> = (1..=80).collect();
    assert!(!run(&idx, [81, 81, 81, 81]).0, "count > OMEGA, otherwise consistent");
    assert!(run(&idx, [80, 80, 80, 80]).0, "a full hint section at exactly OMEGA");
    assert!(run(&[], [0, 0, 0, 0]).0);
}

fn words(b: &[u8]) -> Vec<u32> {
    b.chunks(4).map(|c| { let mut w = [0u8; 4]; w[..c.len()].copy_from_slice(c); u32::from_le_bytes(w) }).collect()
}

#[test]
fn the_guest_verifies_like_the_host_and_reports_its_cycles() {
    use rand_zkvm::emulator::Syscall;
    use rand_zkvm::machine::Tier;
    let p = rand_zkvm::guests::compiled::dilithium_verify();
    eprintln!("dilithium-verify: {} program words", p.words.len());
    for (seed, flip) in [(3u64, false), (4, true)] {
        let (kp, msg) = case(seed, 45);
        let mut sig = kp.sign(&msg).to_vec();
        if flip { sig[100] ^= 1; }
        let mut input = words(&kp.public.to_bytes());
        input.extend(words(&sig));
        input.push(msg.len() as u32);
        input.extend(words(&msg));
        let exec = rand_zkvm::emulator::execute(&p, &input, &[], Tier(22).max_cycles()).unwrap();
        assert!(exec.halted);
        assert_eq!(exec.outputs[0], (!flip) as u32);
        let perms = exec.events.iter().filter(|e| matches!(e.sys, Some(Syscall::Keccak { .. }))).count();
        assert!(exec.cycles() < 1_048_575, "one signature must fit tier 20 (2^20 - 1 cycles)");
        assert!(perms > 0);
        eprintln!("dilithium2 verify in the rVM: {} cycles, {} keccak permutations (valid = {})", exec.cycles(), perms, !flip);
        for m in [1usize, 2, 3, 5] {
            eprintln!("  M = {m}: {} cycles -> {:?}", m * exec.cycles(), Tier::for_workload(m * exec.cycles(), 0));
        }
    }
}
