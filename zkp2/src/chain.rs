//! SNARK-side arithmetization: the x³ + K chain as an **R1CS circuit**.
//!
//! ## How a SNARK sees a computation
//!
//! A SNARK does not see a *loop*. It sees a fixed, fully unrolled set of
//! wires and gates, laid out once at setup time. Every iteration of the
//! chain becomes its own two multiplication gates:
//!
//! ```text
//!     x_i · x_i   = sq_i            (gate 2i)
//!     sq_i · x_i  = cube_i          (gate 2i+1)
//!     x_{i+1}     = cube_i + K      (linear, free — folded into the next gate)
//! ```
//!
//! So the circuit has 2·N constraints and ~2·N witness wires. If you wanted
//! N = 1 000 000 you would need a two-million-constraint circuit, a proving
//! key of several hundred MB, and a fresh trusted setup for that exact N.
//!
//! Contrast `zkp3/src/air.rs`: the STARK describes the *same step once* as a
//! transition constraint and lets the trace length carry N. That is what
//! "scalable" means in STARK: the description of the computation does not
//! grow with the number of steps.
//!
//! ## Trusted setup depends on THIS structure
//!
//! Groth16's proving/verifying keys encode the constraint matrices A, B, C
//! evaluated at a secret point τ. Change N, change K, add a gate — and you
//! need a new setup. The STARK verifier needs nothing beyond the AIR code.

use crate::{Fr, K, N_STEPS};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, fields::FieldVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Native evaluation of the chain, used by the prover to learn y and by the
/// STARK crate as the "reference" — except that zkp3 runs it in a different
/// field, so the numeric y differs between the two crates (see the STARK's
/// `field` note).
pub fn chain(x0: Fr) -> Fr {
    let k = Fr::from(K);
    let mut x = x0;
    for _ in 0..N_STEPS {
        x = x * x * x + k;
    }
    x
}

#[derive(Clone)]
pub struct ChainCircuit {
    /// Private witness x₀.
    pub x0: Option<Fr>,
    /// Public output y.
    pub y: Option<Fr>,
}

impl ChainCircuit {
    pub fn blank() -> Self {
        ChainCircuit { x0: None, y: None }
    }
    pub fn with_secret(x0: Fr) -> Self {
        ChainCircuit { x0: Some(x0), y: Some(chain(x0)) }
    }
}

impl ConstraintSynthesizer<Fr> for ChainCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // SNARK: public inputs are *wires* allocated in the constraint
        // system; their values are supplied separately to the verifier.
        let y = FpVar::new_input(cs.clone(), || self.y.ok_or(SynthesisError::AssignmentMissing))?;
        let mut x = FpVar::new_witness(cs.clone(), || self.x0.ok_or(SynthesisError::AssignmentMissing))?;
        let k = FpVar::constant(Fr::from(K));

        // The loop runs *at circuit-construction time*. It emits 2·N gates.
        // Nothing here executes at verification time — the verifier only
        // ever sees the verifying key that this structure produced.
        for _ in 0..N_STEPS {
            let sq = &x * &x;      // constraint: x·x = sq
            let cube = &sq * &x;   // constraint: sq·x = cube
            x = cube + &k;         // free: addition folds into linear combos
        }

        // Tie the last wire to the public input.
        x.enforce_equal(&y)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn two_constraints_per_step() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        ChainCircuit::with_secret(Fr::from(3u64)).generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), 2 * N_STEPS + 1);
    }

    #[test]
    fn wrong_start_unsatisfied() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        ChainCircuit { x0: Some(Fr::from(4u64)), y: Some(chain(Fr::from(3u64))) }
            .generate_constraints(cs.clone())
            .unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
}
