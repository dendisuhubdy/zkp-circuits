//! Circuit 1: prove you know x such that x³ + x + 5 = out, for a public out.
//!
//! This is Vitalik's example from "QAPs: from Zero to Hero". It is small
//! enough to hand-flatten into rank-1 constraints, so we build it at the
//! lowest level arkworks offers, with no gadget helpers. Once you see this,
//! everything else is the same idea with more wires.
//!
//! ## What is a circuit?
//!
//! A SNARK cannot prove arbitrary Rust. It proves statements of the form
//! "there exist private values w such that a fixed system of quadratic
//! equations over a finite field is satisfied". That system is the circuit.
//!
//! ## What is R1CS?
//!
//! Rank-1 Constraint System: every constraint has the shape
//!
//! ```text
//!     ⟨A, z⟩ · ⟨B, z⟩ = ⟨C, z⟩
//! ```
//!
//! where z is the vector of *all* wire values (1, public inputs, private
//! witness) and A, B, C are sparse vectors of constants. In words: a linear
//! combination of wires, TIMES a linear combination of wires, EQUALS a
//! linear combination of wires. One multiplication per constraint.
//!
//! ## Flattening x³ + x + 5 = out
//!
//! We introduce intermediate wires so each step is one multiplication:
//!
//! ```text
//!     sym1 = x * x          (constraint 1)
//!     y    = sym1 * x       (constraint 2)     -- y = x³
//!     sym2 = y + x          (linear, free)
//!     out  = sym2 + 5       (linear, free)
//! ```
//!
//! Additions are free: they fold into the linear combinations. Only
//! multiplications cost a constraint, so we can merge the last two into
//! the second gate's C side and get away with 2 constraints... but we
//! keep a third, (y + x + 5) * 1 = out, so every wire is explicit.

use crate::Fr;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
};

#[derive(Clone)]
pub struct CubicCircuit {
    /// Private witness. `None` during setup (the setup only needs the
    /// *shape* of the circuit, never actual values).
    pub x: Option<Fr>,
    /// Public input. The verifier will be given this value.
    pub out: Option<Fr>,
}

impl CubicCircuit {
    /// Compute the public output for a given secret, outside the circuit.
    pub fn eval(x: Fr) -> Fr {
        x * x * x + x + Fr::from(5u64)
    }
}

/// `ConstraintSynthesizer` is the trait arkworks uses to mean "a circuit".
/// `generate_constraints` is called in two modes:
///   * setup mode: values are ignored, only the constraint *structure* matters
///   * proving mode: values are filled in to produce a satisfying assignment
impl ConstraintSynthesizer<Fr> for CubicCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // --- Allocate wires ------------------------------------------------
        // `new_witness_variable`: private, known only to the prover.
        // `new_input_variable`:   public, agreed on by prover and verifier.
        let x = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let out = cs.new_input_variable(|| self.out.ok_or(SynthesisError::AssignmentMissing))?;

        // Intermediate wires. The closures compute the witness values; in
        // setup mode they are never called.
        let sym1 = cs.new_witness_variable(|| {
            let x = self.x.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(x * x)
        })?;
        let y = cs.new_witness_variable(|| {
            let x = self.x.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(x * x * x)
        })?;

        // --- Constraints: each is  A · B = C  ------------------------------
        // `lc!() + var` builds a linear combination. `Variable::One` is the
        // constant wire whose value is always 1.

        // (1)  x * x = sym1
        cs.enforce_constraint(lc!() + x, lc!() + x, lc!() + sym1)?;

        // (2)  sym1 * x = y
        cs.enforce_constraint(lc!() + sym1, lc!() + x, lc!() + y)?;

        // (3)  (y + x + 5) * 1 = out
        cs.enforce_constraint(
            lc!() + y + x + (Fr::from(5u64), Variable::One),
            lc!() + Variable::One,
            lc!() + out,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn satisfied_with_correct_witness() {
        let x = Fr::from(3u64);
        let circuit = CubicCircuit { x: Some(x), out: Some(CubicCircuit::eval(x)) };
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), 3);
    }

    #[test]
    fn unsatisfied_with_wrong_witness() {
        let circuit = CubicCircuit { x: Some(Fr::from(4u64)), out: Some(Fr::from(35u64)) };
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
}
