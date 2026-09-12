use rand_zkvm::keccak::{keccak256, keccak_f, state_to_words, words_to_state, RC, ROT};

#[test]
fn keccak256_matches_known_vectors() {
    assert_eq!(hex::encode(keccak256(b"")), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    assert_eq!(hex::encode(keccak256(b"abc")), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
    // exactly one rate block minus one byte, and exactly one rate block (two permutations)
    assert_eq!(keccak256(&[0u8; 135]).len(), 32);
    assert_ne!(keccak256(&[0u8; 135]), keccak256(&[0u8; 136]));
}

#[test]
fn keccak_f_matches_p3_keccak_and_words_roundtrip() {
    use p3_symmetric::Permutation;
    let mut s = [0u64; 25];
    for (i, l) in s.iter_mut().enumerate() { *l = 0x0123_4567_89ab_cdef_u64.rotate_left(i as u32 * 3) ^ i as u64; }
    let mut ours = s;
    keccak_f(&mut ours);
    let mut theirs = s;
    p3_keccak::KeccakF.permute_mut(&mut theirs);
    assert_eq!(ours, theirs);
    let w = state_to_words(&s);
    assert_eq!(w[0], s[0] as u32);
    assert_eq!(w[1], (s[0] >> 32) as u32);
    assert_eq!(words_to_state(&w), s);
    assert_eq!(RC[0], 1);
    assert_eq!(RC[23], 0x8000_0000_8000_8008);
    assert_eq!(ROT[0][0], 0);
    assert_eq!(ROT[1][0], 1);
    assert_eq!(ROT[0][1], 36);
}

/// The guest SDK's `keccak256` (`guest-sdk/src/lib.rs`) is a software sponge *over the syscall*:
/// a 50-word state permuted in place by `KECCAK`, a 34-word (136-byte) rate, and `0x01`/`0x80`
/// padding. `guest-sdk` only builds for `riscv32im-unknown-none-elf`, so its algorithm is
/// transcribed here — with `keccak_f` standing in for the syscall — and checked against the host
/// `keccak256` at every block-boundary case: empty, short, one byte shy of the rate, exactly the
/// rate (which needs a whole extra all-padding block), one byte past it, and two full blocks.
fn sdk_keccak256(msg: &[u8]) -> [u8; 32] {
    // stand-in for `keccak(state.as_mut_ptr())`
    let keccak = |state: &mut [u32; 50]| {
        let mut st = words_to_state(state);
        keccak_f(&mut st);
        *state = state_to_words(&st);
    };
    let mut state = [0u32; 50];
    let mut block = [0u8; 136];
    let mut off = 0;
    loop {
        let take = core::cmp::min(136, msg.len() - off);
        block.fill(0);
        block[..take].copy_from_slice(&msg[off..off + take]);
        let last = take < 136;
        if last { block[take] ^= 0x01; block[135] ^= 0x80; }
        for i in 0..34 { state[i] ^= u32::from_le_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]); }
        keccak(&mut state);
        off += take;
        if last { break; }
    }
    let mut out = [0u8; 32];
    for i in 0..8 { out[4 * i..4 * i + 4].copy_from_slice(&state[i].to_le_bytes()); }
    out
}

#[test]
fn the_guest_sdk_sponge_matches_the_host_keccak256() {
    for len in [0usize, 1, 135, 136, 137, 272] {
        let msg: Vec<u8> = (0..len).map(|i| (7 * i + 1) as u8).collect();
        assert_eq!(sdk_keccak256(&msg), keccak256(&msg), "len {len}");
    }
}
