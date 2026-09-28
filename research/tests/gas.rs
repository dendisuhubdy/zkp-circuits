mod common;
use rand_zkvm::gas::{gas_max, KECCAK_GAS, POSEIDON2_ABSORB_GAS, SHA256_GAS};
use rand_zkvm::machine::{check_public_values, Tier, VerifyError};
use rand_zkvm::tables::cpu::pv;

#[test]
fn the_public_value_layout_gains_gas_limit_last() {
    assert_eq!(pv::GAS, 34);
    assert_eq!(pv::NUM, 35);
    assert_eq!((KECCAK_GAS, SHA256_GAS, POSEIDON2_ABSORB_GAS), (192, 64, 3));
}

#[test]
fn gas_max_is_the_headers_ceiling() {
    assert_eq!(gas_max(Tier(10), 0, 0), 1_023);
    assert_eq!(gas_max(Tier(10), 5, 0), 1_023 + 191);
    assert_eq!(gas_max(Tier(10), 0, 6), 1_023 + 63);
    assert_eq!(gas_max(Tier(14), 12, 13), 16_383 + 128 * 191 + 128 * 63);
    assert_eq!(gas_max(Tier(20), 20, 20), 1_048_575 + 32_768 * 191 + 16_384 * 63);
}

/// Review focus 3: a limit past the header's ceiling is refused natively, before any key.
///
/// Deviation from the brief's verbatim listing: `machine::Proof` carries a `BatchProof<Config>`
/// (from `p3_batch_stark`, not vendored here) that is not `Clone`, so two independent
/// `proof.clone()`s cannot be made. `tests/bundle.rs::a_malformed_proof_is_rejected_as_a_proof_error`
/// already established the idiom for this exact situation in this crate: one mutable proof,
/// `public_values` (a plain `Vec<u64>`, which *is* `Clone`) saved and restored between checks.
#[test]
fn a_limit_above_the_header_ceiling_is_refused() {
    let (p, mut proof) = common::fib_proof_tier_10();   // the helper the executor tests use for a real tier-10 proof
    let hc = p.digest();
    assert_eq!(check_public_values(&hc, &proof), Ok(()));
    let honest_pvs = proof.public_values.clone();

    proof.public_values[pv::GAS] = gas_max(Tier(10), 0, 0) + 1;
    assert_eq!(check_public_values(&hc, &proof), Err(VerifyError::GasLimit));

    proof.public_values = honest_pvs;
    proof.public_values[pv::GAS] = u64::MAX;
    assert_eq!(check_public_values(&hc, &proof), Err(VerifyError::PublicValues));
}
