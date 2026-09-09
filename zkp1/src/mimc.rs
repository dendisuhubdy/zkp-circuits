//! Circuit 2: prove you know a preimage x such that MiMC(x) = h.
//!
//! This is the "hello world" of useful ZK: h is public, x is secret, and
//! the proof says "I know something that hashes to h" without revealing it.
//! Replace MiMC with Poseidon and you have the core of Tornado Cash /
//! Semaphore / zk-rollup membership proofs.
//!
//! ## Why MiMC and not SHA-256?
//!
//! Circuits are arithmetic (add/multiply mod r). SHA-256 is bitwise
//! (XOR, rotate) and costs ~25 000 constraints. MiMC is *designed* for
//! circuits: each round is one cube-ish power of a field element:
//!
//! ```text
//!     x_{i+1} = (x_i + k + c_i)^7
//! ```
//!
//! and x^7 costs 3 multiplications (x², x⁴ = (x²)², x⁷ = x⁴·x²·x) - so a
//! whole round is 3-4 constraints. Exponent 7 is used because gcd(7, r-1)=1
//! on BN254, making the map a permutation (3 and 5 both divide r-1).
//!
//! ## Gadgets
//!
//! Instead of writing A·B=C by hand, we use `FpVar<Fr>` from ark-r1cs-std.
//! It overloads `+`, `*` etc. and emits the constraints for us. The final
//! `enforce_equal` pins the in-circuit result to the public input.

use crate::Fr;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, fields::FieldVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Toy round count. circomlib's MiMC7 uses 91. The *structure* is what we
/// are learning here; security margins are a separate topic.
pub const ROUNDS: usize = 10;

/// Round constants. Real deployments derive these from a nothing-up-my-
/// sleeve seed (circomlib hashes the string "mimc"). We just count.
pub fn round_constants() -> Vec<Fr> {
    (0..ROUNDS).map(|i| Fr::from((i as u64 + 1) * 7919)).collect()
}

/// Native (out-of-circuit) MiMC. The prover runs this to learn h, and it
/// is also our reference implementation for the tests.
pub fn mimc(x: Fr, k: Fr) -> Fr {
    let mut acc = x;
    for c in round_constants() {
        acc = (acc + k + c).pow([7u64]);
    }
    acc + k
}

#[derive(Clone)]
pub struct MimcPreimageCircuit {
    /// Private: the preimage.
    pub x: Option<Fr>,
    /// Public: the key (could be a domain separator, or zero).
    pub k: Option<Fr>,
    /// Public: the hash we claim to know a preimage of.
    pub h: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for MimcPreimageCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocation via gadgets. Same public/private distinction as before,
        // but we get back `FpVar`s that support arithmetic operators.
        let x = FpVar::new_witness(cs.clone(), || self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let k = FpVar::new_input(cs.clone(), || self.k.ok_or(SynthesisError::AssignmentMissing))?;
        let h = FpVar::new_input(cs.clone(), || self.h.ok_or(SynthesisError::AssignmentMissing))?;

        // The same loop as `mimc()`, but every `*` becomes a constraint.
        let mut acc = x;
        for c in round_constants() {
            let t = &acc + &k + FpVar::constant(c); // additions: free
            let t2 = &t * &t;                       // 1 constraint
            let t4 = &t2 * &t2;                     // 1 constraint
            let t6 = &t4 * &t2;                     // 1 constraint
            acc = &t6 * &t;                         // 1 constraint  -> t^7
        }
        let computed = &acc + &k;

        // "The value I computed from my secret equals the public h."
        computed.enforce_equal(&h)?;
        Ok(())
    }
}

/// Convenience: build a fully-assigned circuit from a secret and key.
impl MimcPreimageCircuit {
    pub fn with_secret(x: Fr, k: Fr) -> Self {
        MimcPreimageCircuit { x: Some(x), k: Some(k), h: Some(mimc(x, k)) }
    }
    pub fn blank() -> Self {
        MimcPreimageCircuit { x: None, k: None, h: None }
    }
    /// Public inputs in the order they were allocated: [k, h].
    pub fn public_inputs(&self) -> Vec<Fr> {
        vec![self.k.unwrap(), self.h.unwrap()]
    }
}

/// Helper so `main` can print field elements compactly.
pub fn short_hex(f: &Fr) -> String {
    let bytes = f.into_bigint().to_bytes_be();
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    format!("0x{}…{}", &hex[..8], &hex[hex.len() - 8..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn circuit_matches_native() {
        let x = Fr::from(42u64);
        let k = Fr::from(0u64);
        let cs = ConstraintSystem::<Fr>::new_ref();
        MimcPreimageCircuit::with_secret(x, k).generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        // 4 multiplications per round + 1 equality
        assert_eq!(cs.num_constraints(), 4 * ROUNDS + 1);
    }

    #[test]
    fn wrong_preimage_fails() {
        let k = Fr::from(0u64);
        let h = mimc(Fr::from(42u64), k);
        let cs = ConstraintSystem::<Fr>::new_ref();
        MimcPreimageCircuit { x: Some(Fr::from(43u64)), k: Some(k), h: Some(h) }
            .generate_constraints(cs.clone())
            .unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
}
