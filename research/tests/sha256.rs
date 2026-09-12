use rand_zkvm::sha256::{bytes_to_words, compress, sha256, IV, K};
use sha2::Digest;

#[test]
fn sha256_matches_fips_vectors_and_the_sha2_crate() {
    assert_eq!(hex::encode(sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(hex::encode(sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(hex::encode(sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(48);
    for _ in 0..1_000 {
        let n = rand::RngExt::random_range(&mut rng, 0..300usize);
        let msg: Vec<u8> = (0..n).map(|_| rand::RngExt::random(&mut rng)).collect();
        assert_eq!(sha256(&msg), <[u8; 32]>::from(sha2::Sha256::digest(&msg)), "len {n}");
    }
    assert_eq!(K[0], 0x428a2f98); assert_eq!(K[63], 0xc67178f2); assert_eq!(IV[0], 0x6a09e667); assert_eq!(IV[7], 0x5be0cd19);
}

#[test]
fn compress_matches_sha2_compress256_on_a_thousand_blocks() {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(49);
    for _ in 0..1_000 {
        let mut state: [u32; 8] = core::array::from_fn(|_| rand::RngExt::random(&mut rng));
        let bytes: [u8; 64] = core::array::from_fn(|_| rand::RngExt::random(&mut rng));
        let mut theirs = state;
        sha2::compress256(&mut theirs, &[bytes.into()]);
        compress(&mut state, &bytes_to_words(&bytes));
        assert_eq!(state, theirs);
    }
}
