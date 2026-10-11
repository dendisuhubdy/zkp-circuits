use rand_zkvm::msauth::*;
use rand_zkvm::notes::{domain, hash};

#[test]
fn tags_are_node_local_and_distinct() {
    let tags = [AUTH, MS_LEAF, MS_NODE, MS_POLICY, NK_MS];
    for t in tags { assert!(t >= 64 && t != 0xff && t != 64); }
    let mut s = tags.to_vec(); s.sort(); s.dedup(); assert_eq!(s.len(), 5);
    assert!(![domain::NK, domain::PK].iter().any(|d| tags.contains(d)));
}

#[test]
fn the_merkle_path_of_every_signer_reaches_the_root() {
    let pks: Vec<[u8; 1312]> = (0..3u8).map(|i| [i + 1; 1312]).collect();
    let (root, paths) = signer_tree(&pks);
    for (i, pk) in pks.iter().enumerate() {
        let mut cur = leaf(pk);
        for (lvl, sib) in paths[i].iter().enumerate() {
            let mut m = [0u32; 16];
            if (i >> lvl) & 1 == 0 { m[..8].copy_from_slice(&cur); m[8..].copy_from_slice(sib); }
            else { m[..8].copy_from_slice(sib); m[8..].copy_from_slice(&cur); }
            cur = hash(MS_NODE, &m);
        }
        assert_eq!(cur, root);
    }
}

#[test]
fn the_policy_binds_threshold_keys_and_msk() {
    let pks: Vec<[u8; 1312]> = (0..3u8).map(|i| [i + 1; 1312]).collect();
    let (root, _) = signer_tree(&pks);
    let msk = [9u32; 8];
    assert_ne!(nk(&msk, &policy(2, &root)), nk(&msk, &policy(3, &root)));
    assert_ne!(nk(&msk, &policy(2, &root)), nk(&[8u32; 8], &policy(2, &root)));
    let (root2, _) = signer_tree(&pks[..2]);
    assert_ne!(policy(2, &root), policy(2, &root2));
}

#[test]
fn the_witness_has_its_fixed_length_whatever_m() {
    let s = |i| Slot { index: i, pk: [1; 1312], sig: [2; 2420], path: [[0; 8]; DEPTH] };
    assert_eq!(msauth_inputs(&[0; 8], &[0; 8], 1, &[s(0)]).len(), MSAUTH_WORDS);
    assert_eq!(msauth_inputs(&[0; 8], &[0; 8], 2, &[s(0), s(2)]).len(), MSAUTH_WORDS);
}

#[test]
fn the_signing_message_is_prefix_then_binding() {
    let m = signing_message(&[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(&m[..13], b"rand-msauth-1");
    assert_eq!(&m[13..17], &1u32.to_le_bytes());
}

#[test]
fn the_witness_offsets_are_pinned() {
    let s = |i| Slot { index: i, pk: [1; 1312], sig: [2; 2420], path: [[7; 8]; DEPTH] };
    let w = msauth_inputs(&[3; 8], &[4; 8], 2, &[s(5), s(9)]);
    assert_eq!(&w[0..8], &[3u32; 8]);
    assert_eq!(&w[8..16], &[4u32; 8]);
    assert_eq!(w[16], 2);
    assert_eq!(w[17], 1);
    assert_eq!(w[18], 5);
    assert_eq!(w[19], 0x01010101);
    assert_eq!(w[17 + 330], 0x02020202);
    assert_eq!(w[17 + 935], 7);
    assert_eq!(w[17 + 967], 1);
    assert_eq!(w[17 + 967 + 1], 9);
    assert!(w[17 + 2 * 967..].iter().all(|&x| x == 0));
}

#[test]
#[should_panic]
fn an_out_of_range_signer_index_is_refused() {
    let s = Slot { index: 16, pk: [1; 1312], sig: [2; 2420], path: [[0; 8]; DEPTH] };
    msauth_inputs(&[0; 8], &[0; 8], 1, &[s]);
}

// ---- Task 5: the compiled `msauth` guest and its cheating suite -------------------------------

use crystals_dilithium::dilithium2::Keypair;
use rand_zkvm::{emulator::execute, guests::compiled, machine::Tier};

struct Fixture { kps: Vec<Keypair>, pks: Vec<[u8; 1312]>, root: Word8, paths: Vec<[Word8; DEPTH]> }
fn fixture(n: usize) -> Fixture {
    fixture_seeded(n, 0)
}
fn fixture_seeded(n: usize, tag: u8) -> Fixture {
    let kps: Vec<Keypair> = (0..n)
        .map(|i| {
            let mut seed = [i as u8 + 1; 32];
            seed[31] = tag;
            Keypair::generate(Some(&seed)).unwrap()
        })
        .collect();
    let pks: Vec<[u8; 1312]> = kps.iter().map(|k| k.public.to_bytes().try_into().unwrap()).collect();
    let (root, paths) = signer_tree(&pks);
    Fixture { kps, pks, root, paths }
}
type Word8 = rand_zkvm::notes::Word8;
const BINDING: [u32; 8] = [11, 22, 33, 44, 55, 66, 77, 88];
const MSK: Word8 = [5; 8];
const SALT: Word8 = [6; 8];

fn slot(f: &Fixture, i: usize, binding: &[u32; 8]) -> Slot {
    let sig = f.kps[i].sign(&signing_message(binding)); // `Signature = [u8; 2420]`
    Slot { index: i as u32, pk: f.pks[i], sig, path: f.paths[i] }
}
fn exec(input: &[u32], binding: &[u32; 8]) -> rand_zkvm::emulator::Execution {
    let e = execute(&compiled::msauth(), input, binding, Tier(22).max_cycles()).unwrap();
    assert!(e.halted);
    e
}
fn run(input: &[u32], binding: &[u32; 8]) -> [u32; 8] {
    exec(input, binding).outputs[..8].try_into().unwrap()
}
fn expected(f: &Fixture, t: u32) -> Word8 { auth_commit(&nk(&MSK, &policy(t, &f.root)), &SALT) }

#[test]
fn two_of_three_publishes_the_hosts_commit() {
    let f = fixture(3);
    let input = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0, &BINDING), slot(&f, 2, &BINDING)]);
    assert_eq!(run(&input, &BINDING), expected(&f, 2));
}

#[test]
fn below_threshold_is_refused() {
    let f = fixture(3);
    let input = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0, &BINDING)]);
    assert_eq!(run(&input, &BINDING)[7], 0xdead_beef);
}

#[test]
fn duplicate_index_is_refused() {
    let f = fixture(3);
    let s = slot(&f, 1, &BINDING);
    let input = msauth_inputs(&MSK, &SALT, 2, &[s.clone(), s]);
    assert_eq!(run(&input, &BINDING)[7], 0xdead_beef);
}

#[test]
fn slots_from_two_policies_are_refused() {
    let (a, b) = (fixture(3), fixture(4));
    let input = msauth_inputs(&MSK, &SALT, 2, &[slot(&a, 0, &BINDING), slot(&b, 3, &BINDING)]);
    assert_eq!(run(&input, &BINDING)[7], 0xdead_beef);
}

#[test]
fn signature_over_another_binding_is_refused() {
    let f = fixture(3);
    let other = [0u32; 8];
    let input = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0, &BINDING), slot(&f, 1, &other)]);
    assert_eq!(run(&input, &BINDING)[7], 0xdead_beef);
}

#[test]
fn one_bad_signature_among_enough_good_ones_is_refused() {
    let f = fixture(3);
    let mut bad = slot(&f, 2, &BINDING);
    bad.sig[200] ^= 1;
    let input = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0, &BINDING), slot(&f, 1, &BINDING), bad]);
    assert_eq!(run(&input, &BINDING)[7], 0xdead_beef);
}

#[test]
fn threshold_zero_and_over_m_max_are_refused() {
    let f = fixture(3);
    for t in [0, M_MAX as u32 + 1] {
        let input = msauth_inputs(&MSK, &SALT, t, &[slot(&f, 0, &BINDING), slot(&f, 1, &BINDING)]);
        assert_eq!(run(&input, &BINDING)[7], 0xdead_beef, "threshold {t}");
    }
}

#[test]
fn index_out_of_range_and_non_boolean_active_are_refused() {
    let f = fixture(3);
    // `msauth_inputs` itself refuses index 16 (Task 4), so the cheat is written into the
    // witness word directly: slot 0's `index` is word 18.
    let mut input = msauth_inputs(&MSK, &SALT, 1, &[slot(&f, 0, &BINDING)]);
    input[18] = 16;
    assert_eq!(run(&input, &BINDING)[7], 0xdead_beef);
    let mut input = msauth_inputs(&MSK, &SALT, 1, &[slot(&f, 0, &BINDING)]);
    input[17] = 2; // slot 0's `active`
    assert_eq!(run(&input, &BINDING)[7], 0xdead_beef);
}

#[test]
fn a_wrong_msk_publishes_a_different_commit() {
    let f = fixture(3);
    let input = msauth_inputs(&[4; 8], &SALT, 2, &[slot(&f, 0, &BINDING), slot(&f, 1, &BINDING)]);
    assert_ne!(run(&input, &BINDING), expected(&f, 2));
}

/// Beyond the brief: the guest and the host model agree on random policies, and dropping one
/// signer from an exactly-at-threshold witness is refused.
#[test]
fn the_guest_matches_the_host_model_on_random_policies() {
    let mut x: u64 = 0x5eed_0f_75a7;
    let mut next = move || {
        // splitmix64
        x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    };
    for case in 0..20u8 {
        let n = 1 + (next() % 16) as usize;
        let t = 1 + (next() % n.min(M_MAX) as u64) as u32;
        let count = t as usize + (next() % (n.min(M_MAX) - t as usize + 1) as u64) as usize;
        // `count` distinct indices of `0..n`, sorted increasing (partial Fisher-Yates).
        let mut pool: Vec<usize> = (0..n).collect();
        for i in 0..count {
            let j = i + (next() % (n - i) as u64) as usize;
            pool.swap(i, j);
        }
        let mut idx = pool[..count].to_vec();
        idx.sort();
        let msk: Word8 = core::array::from_fn(|_| next() as u32);
        let salt: Word8 = core::array::from_fn(|_| next() as u32);
        let binding: [u32; 8] = core::array::from_fn(|_| next() as u32);
        let f = fixture_seeded(n, case);
        let slots: Vec<Slot> = idx.iter().map(|&i| slot(&f, i, &binding)).collect();
        let want = auth_commit(&nk(&msk, &policy(t, &f.root)), &salt);
        let got = run(&msauth_inputs(&msk, &salt, t, &slots), &binding);
        assert_eq!(got, want, "case {case}: n {n} t {t} idx {idx:?}");
        if count == t as usize {
            let drop = (next() % count as u64) as usize;
            let mut fewer = slots.clone();
            fewer.remove(drop);
            let out = run(&msauth_inputs(&msk, &salt, t, &fewer), &binding);
            assert_eq!(out[7], 0xdead_beef, "case {case}: dropped slot {drop} of {count}");
        }
    }
}

/// Prints the cycle count at 1, 2 and 3 active slots and the lowest stack word touched
/// (`--nocapture`), and holds each run to the tier-22 cycle budget.
#[test]
fn cycles_at_one_two_and_three_signers() {
    let f = fixture(3);
    for k in 1..=3 {
        let slots: Vec<Slot> = (0..k).map(|i| slot(&f, i, &BINDING)).collect();
        let e = exec(&msauth_inputs(&MSK, &SALT, 1, &slots), &BINDING);
        assert_eq!(e.outputs[..8], expected(&f, 1));
        let top = e.events.iter().flat_map(|ev| ev.accesses.iter()).map(|a| a.addr).max().unwrap();
        let low = e
            .events
            .iter()
            .flat_map(|ev| ev.accesses.iter())
            .map(|a| a.addr)
            .filter(|&a| a + 0x4000 > top) // the 64 KiB stack is 0x4000 words below the top
            .min()
            .unwrap();
        eprintln!("msauth: {k} active slot(s): {} cycles; stack words {:#x}..={:#x} ({} B)", e.cycles(), low, top, 4 * (top - low + 1));
    }
}
