//! STARK-side arithmetization: the x³ + K chain as an **AIR**
//! (Algebraic Intermediate Representation) over an execution trace.
//!
//! ## How a STARK sees a computation
//!
//! | step | x        |
//! |------|----------|
//! | 0    | x₀       |   ← private start
//! | 1    | x₀³ + K  |
//! | 2    | …        |
//! | N-1  | y        |   ← public end
//!
//! One column, N rows. Two kinds of rule:
//!
//! 1. **Transition constraint** — holds between EVERY consecutive pair of rows:
//! ```text
//!        next − (cur³ + K) = 0
//! ```
//!    Written once, regardless of N. Compare `zkp2/src/chain.rs`, where the
//!    same step is emitted 63 times as separate gates.
//!
//! 2. **Boundary assertion** — pins specific cells to public values:
//! ```text
//!        trace[N−1] = y
//! ```
//!    We deliberately do NOT assert trace[0] = x₀: that keeps x₀ private.
//!    (winterfell's own doc example makes the start public; we drop that.)
//!
//! ## Why the degree matters
//!
//! The prover interpolates the column into a polynomial T(X) of degree N−1
//! and the verifier needs the constraint polynomial
//! ```text
//!     C(X) = T(gX) − T(X)³ − K
//! ```
//! to vanish on all N−1 transition points. Degree of C is 3·(N−1), which
//! is why we declare `TransitionConstraintDegree::new(3)`. The prover
//! extends T to a larger "blowup" domain (8× here) so that a cheating
//! prover, who can only satisfy the constraint on a few points, is caught
//! by random FRI queries with high probability. The blowup factor and
//! query count set the soundness — no secret τ is involved anywhere.

use crate::{Felt, K};
use winterfell::{
    math::{FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo, TransitionConstraintDegree,
};

/// Only y is public. In zkp2 this is the single `new_input` wire.
#[derive(Clone, Copy, Debug)]
pub struct PublicInputs {
    pub result: Felt,
}

/// The verifier feeds public inputs into the Fiat-Shamir transcript, so
/// winterfell needs to know how to serialize them as field elements.
impl ToElements<Felt> for PublicInputs {
    fn to_elements(&self) -> Vec<Felt> {
        vec![self.result]
    }
}

pub struct ChainAir {
    context: AirContext<Felt>,
    result: Felt,
}

impl Air for ChainAir {
    type BaseField = Felt;
    type PublicInputs = PublicInputs;

    /// Called by BOTH prover and verifier. There is no key to load: the AIR
    /// *is* the verifier's entire description of the computation. This is
    /// the STARK counterpart of Groth16's setup(), except it is pure code
    /// with no secrets and no output artefact.
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(trace_info.width(), 1, "one column: the running value x");
        let degrees = vec![TransitionConstraintDegree::new(3)]; // cur³ ⇒ degree 3
        let num_assertions = 1; // only the final value
        ChainAir {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            result: pub_inputs.result,
        }
    }

    /// The step, written ONCE. `frame` holds rows i and i+1. The prover
    /// evaluates this on the extended domain to build the constraint
    /// polynomial; the verifier evaluates it at one random out-of-domain
    /// point z to check the prover's claimed values are consistent.
    fn evaluate_transition<E: FieldElement + From<Felt>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current()[0];
        let next = frame.next()[0];
        // next − (cur³ + K)  must be 0 on every transition
        result[0] = next - (cur.exp(3u32.into()) + E::from(Felt::new(K as u128)));
    }

    /// Boundary constraints: which cells are tied to public inputs.
    fn get_assertions(&self) -> Vec<Assertion<Felt>> {
        let last = self.trace_length() - 1;
        vec![Assertion::single(0, last, self.result)]
    }

    fn context(&self) -> &AirContext<Felt> {
        &self.context
    }
}
