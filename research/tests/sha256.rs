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

/// The guest SDK's `sha256` (`guest-sdk/src/lib.rs`) is a software Merkle–Damgård loop *over the
/// syscall*: a 24-word buffer whose words `16..24` hold the chaining state, the block packed
/// big-endian into words `0..16`, and `SHA256` compressing it in place. `guest-sdk` only builds
/// for `riscv32im-unknown-none-elf`, so its algorithm is transcribed here — with `compress`
/// standing in for the syscall — and checked against the host `sha256` at every block-boundary
/// case: empty, short, either side of the 56-byte length-field cutoff (56 is the first length
/// whose padding needs a whole extra block), either side of a full 64-byte block, and the same
/// three cases one block further along.
fn sdk_sha256(msg: &[u8]) -> [u8; 32] {
    // stand-in for `sha256_compress(buf.as_mut_ptr())`
    let compress_syscall = |buf: &mut [u32; 24]| {
        let block: [u32; 16] = buf[..16].try_into().unwrap();
        let mut h: [u32; 8] = buf[16..].try_into().unwrap();
        compress(&mut h, &block);
        buf[16..].copy_from_slice(&h);
    };
    let compress_block = |buf: &mut [u32; 24], block: &[u8; 64]| {
        for i in 0..16 {
            buf[i] = u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
        }
        compress_syscall(buf);
    };

    let mut buf = [0u32; 24];
    buf[16..].copy_from_slice(&IV);
    let mut block = [0u8; 64];
    let mut off = 0;
    while msg.len() - off >= 64 {
        block.copy_from_slice(&msg[off..off + 64]);
        compress_block(&mut buf, &block);
        off += 64;
    }
    let rest = msg.len() - off;
    block.fill(0);
    block[..rest].copy_from_slice(&msg[off..]);
    block[rest] = 0x80;
    if rest >= 56 {
        compress_block(&mut buf, &block);
        block.fill(0);
    }
    block[56..].copy_from_slice(&(msg.len() as u64).wrapping_mul(8).to_be_bytes());
    compress_block(&mut buf, &block);

    let mut out = [0u8; 32];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&buf[16 + i].to_be_bytes());
    }
    out
}

#[test]
fn the_guest_sdk_merkle_damgard_loop_matches_the_host_sha256() {
    for len in [0usize, 1, 55, 56, 63, 64, 65, 119, 120, 128] {
        let msg: Vec<u8> = (0..len).map(|i| (7 * i + 1) as u8).collect();
        assert_eq!(sdk_sha256(&msg), sha256(&msg), "len {len}");
    }
}
