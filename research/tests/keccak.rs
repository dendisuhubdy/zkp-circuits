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
