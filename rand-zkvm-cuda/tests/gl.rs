use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use rand_zkvm_cuda::device::gl;

fn g(x: u64) -> Goldilocks { Goldilocks::from_u64(x) }
fn c(x: Goldilocks) -> u64 { x.as_canonical_u64() }

const EDGE: [u64; 8] = [0, 1, 2, gl::P - 1, gl::P - 2, 1 << 32, (1 << 32) - 1, 0x7fff_ffff_8000_0001];

#[test]
fn add_sub_mul_match_plonky3() {
    let mut rng = StdRng::seed_from_u64(1);
    let mut cases: Vec<(u64, u64)> = EDGE.iter().flat_map(|&a| EDGE.iter().map(move |&b| (a, b))).collect();
    for _ in 0..10_000 { cases.push((rng.random::<u64>() % gl::P, rng.random::<u64>() % gl::P)); }
    for (a, b) in cases {
        assert_eq!(gl::add(a, b), c(g(a) + g(b)), "add {a} {b}");
        assert_eq!(gl::sub(a, b), c(g(a) - g(b)), "sub {a} {b}");
        assert_eq!(gl::mul(a, b), c(g(a) * g(b)), "mul {a} {b}");
        assert_eq!(gl::neg(a), c(-g(a)), "neg {a}");
    }
}

#[test]
fn reduce128_handles_full_range() {
    for x in [0u128, 1, (gl::P as u128) * (gl::P as u128) - 1, u128::MAX >> 1, (1u128 << 96) + 5, (1u128 << 64) - 1] {
        assert_eq!(gl::reduce128(x), (x % gl::P as u128) as u64);
    }
}

#[test]
fn pow_and_inv() {
    let mut rng = StdRng::seed_from_u64(2);
    for _ in 0..1000 {
        let a = rng.random::<u64>() % gl::P;
        let e = rng.random::<u64>();
        assert_eq!(gl::pow(a, e), c(g(a).exp_u64(e)));
        if a != 0 { assert_eq!(gl::inv(a), c(g(a).inverse())); }
    }
    assert_eq!(gl::pow(7, 0), 1);
}

#[test]
fn outputs_are_canonical() {
    assert!(gl::add(gl::P - 1, gl::P - 1) < gl::P);
    assert!(gl::mul(gl::P - 1, gl::P - 1) < gl::P);
    assert_eq!(gl::reduce(gl::P), 0);
}
