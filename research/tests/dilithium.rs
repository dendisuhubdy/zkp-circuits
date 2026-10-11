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
