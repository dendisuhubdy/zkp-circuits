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
