//! A SNARK-friendly 2-to-1 hash, native and as a circuit gadget.
//!
//! Tornado uses MiMC-Sponge (circomlib); Zcash Orchard uses Poseidon /
//! Sinsemilla. We use a simple MiMC construction:
//!
//! ```text
//!   H(l, r):  x = l
//!             for i in 0..ROUNDS:  x = (x + r + c_i)^7
//!             return x + r
//! ```
//!
//! The *same* arithmetic must exist twice: once over `Fr` for the contract
//! and the wallet, once over `FpVar<Fr>` for the circuit. If they ever
//! disagree, honest proofs fail to verify — keep them side by side.

use crate::Fr;
use ark_ff::Field;
use ark_r1cs_std::{fields::fp::FpVar, fields::FieldVar};
use ark_relations::r1cs::SynthesisError;

pub const ROUNDS: usize = 20;

fn constants() -> impl Iterator<Item = Fr> {
    (0..ROUNDS).map(|i| Fr::from((i as u64 + 1) * 0x9e37_79b9))
}

/// Native H(l, r).
pub fn hash2(l: Fr, r: Fr) -> Fr {
    let mut x = l;
    for c in constants() {
        x = (x + r + c).pow([7u64]);
    }
    x + r
}

/// Native H(x) = H(x, 0), for the nullifier hash.
pub fn hash1(x: Fr) -> Fr {
    hash2(x, Fr::from(0u64))
}

/// In-circuit H(l, r): 4 constraints per round.
pub fn hash2_gadget(l: &FpVar<Fr>, r: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let mut x = l.clone();
    for c in constants() {
        let t = &x + r + FpVar::constant(c);
        let t2 = &t * &t;
        let t4 = &t2 * &t2;
        let t6 = &t4 * &t2;
        x = &t6 * &t;
    }
    Ok(x + r)
}

pub fn hash1_gadget(x: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    hash2_gadget(x, &FpVar::constant(Fr::from(0u64)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::{alloc::AllocVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn gadget_matches_native() {
        let (l, r) = (Fr::from(11u64), Fr::from(22u64));
        let cs = ConstraintSystem::<Fr>::new_ref();
        let lv = FpVar::new_witness(cs.clone(), || Ok(l)).unwrap();
        let rv = FpVar::new_witness(cs.clone(), || Ok(r)).unwrap();
        let hv = hash2_gadget(&lv, &rv).unwrap();
        assert_eq!(hv.value().unwrap(), hash2(l, r));
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), 4 * ROUNDS);
    }
}
