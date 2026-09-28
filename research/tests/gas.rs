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

// ─────────────────────── Task A2: `gas_of`, the native meter over an execution ───────────────────────

mod gas_of_tests {
    use rand_zkvm::asm::{ops::*, Assembler};
    use rand_zkvm::emulator::{execute, HashRow, Syscall};
    use rand_zkvm::gas::gas_of;
    use rand_zkvm::guests;

    /// The digest-prefix rows every execution pays once, for the given input/public counts —
    /// the same three calls `gas_of` itself makes.
    fn digest_rows(p: &rand_zkvm::isa::Program, n_inputs: usize, n_public: usize) -> usize {
        p.digest_rows() + rand_zkvm::hash::input_digest_row_count(n_inputs) + rand_zkvm::hash::public_digest_row_count(n_public)
    }

    /// A hash-free program: gas is exactly the digest rows plus one per cycle.
    #[test]
    fn gas_of_counts_rows_with_no_hash_syscall() {
        let mut a = Assembler::new(0);
        a.push(addi(5, 0, 7));
        a.push(addi(6, 5, 1));
        a.extend(halt());
        let p = a.assemble();
        let e = execute(&p, &[], &[], 1_000).unwrap();
        let rows = digest_rows(&p, 0, 0);
        assert_eq!(gas_of(&p, &[], &[], &e.events), (rows + e.events.len()) as u64);
    }

    /// `guests::keccak_demo(b"hi")` is one `SYS_KECCAK` row plus its permutation (see
    /// `tests/cheating.rs`'s `setup_keccak`): the KECCAK row still counts once toward the plain
    /// per-row sum, and `gas_of` must add 191 more for it (`KECCAK_GAS - 1`).
    #[test]
    fn gas_of_charges_191_beyond_its_base_row_for_a_keccak_call() {
        let p = guests::keccak_demo(b"hi");
        let e = execute(&p, &[], &[], 10_000).unwrap();
        let keccaks = e.events.iter().filter(|ev| matches!(ev.sys, Some(Syscall::Keccak { .. }))).count() as u64;
        assert_eq!(keccaks, 1, "keccak_demo hashes exactly one rate block");
        let rows = digest_rows(&p, 0, 0);
        let expected = (rows + e.events.len()) as u64 + keccaks * 191;
        assert_eq!(gas_of(&p, &[], &[], &e.events), expected);
    }

    /// `guests::poseidon2_demo` over 8 words absorbs at rate 4, so two `HashRow::Absorb` rows;
    /// `gas_of` must add 2 more for each (`POSEIDON2_ABSORB_GAS - 1`), i.e. +4 total.
    #[test]
    fn gas_of_charges_2_beyond_its_base_row_per_poseidon2_absorb_row() {
        let p = guests::poseidon2_demo(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let e = execute(&p, &[], &[], 10_000).unwrap();
        let absorbs = e.events.iter().filter(|ev| matches!(ev.hash_row, Some(HashRow::Absorb { .. }))).count() as u64;
        assert_eq!(absorbs, 2, "8 words at rate 4 absorb in exactly two blocks");
        let rows = digest_rows(&p, 0, 0);
        let expected_extra = absorbs * 2;
        assert_eq!(expected_extra, 4, "the brief's worked example: 2 absorb rows -> +4 gas");
        let expected = (rows + e.events.len()) as u64 + expected_extra;
        assert_eq!(gas_of(&p, &[], &[], &e.events), expected);
    }

    /// `POSEIDON2_LEN` (HCS-4/cs7) shares the same absorb-row weight — `gas_of` must not
    /// special-case it away just because its ecall's `sys` variant differs from `Poseidon2`.
    #[test]
    fn gas_of_charges_the_same_absorb_weight_for_poseidon2_len() {
        let p = guests::poseidon2_len_demo(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let e = execute(&p, &[], &[], 10_000).unwrap();
        let absorbs = e.events.iter().filter(|ev| matches!(ev.hash_row, Some(HashRow::Absorb { .. }))).count() as u64;
        assert_eq!(absorbs, 2);
        let rows = digest_rows(&p, 0, 0);
        let expected = (rows + e.events.len()) as u64 + absorbs * 2;
        assert_eq!(gas_of(&p, &[], &[], &e.events), expected);
    }
}
