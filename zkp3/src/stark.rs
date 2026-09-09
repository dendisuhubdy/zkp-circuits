//! STARK-side proof system: winterfell prover + verifier.
//!
//! Compare each function with its counterpart in `zkp2/src/snark.rs`.
//!
//! ## (no setup)     ← the SNARK's setup() has no counterpart here
//!
//! ## build_trace()  ← the SNARK has no counterpart: witness generation is
//! ```text
//!                     folded into the circuit closures
//! ```
//! Actually run the computation and write every intermediate state into a
//! table. The trace is the witness. For N steps it is N rows.
//!
//! ## prove()
//!   1. Interpolate each trace column into a polynomial (FFT).
//!   2. Evaluate it on a domain `blowup`× larger (low-degree extension).
//!   3. Merkle-commit to those evaluations (Blake3).   ← hashes, not curve points
//!   4. Fiat-Shamir: derive random challenges from the Merkle roots.
//!   5. Combine all constraints into one composition polynomial, commit.
//!   6. Run FRI to prove the composition polynomial has low degree:
//! ```text
//!      repeatedly fold the polynomial in half, committing each layer,
//!      until it is a constant.
//! ```
//!   7. Open the commitments at `num_queries` random positions.
//! All of this is field arithmetic + hashing. No elliptic curves anywhere.
//!
//! ## verify()
//! Recompute the Fiat-Shamir challenges from the Merkle roots in the proof,
//! check the AIR constraints at the out-of-domain point, and check every
//! FRI layer's Merkle paths at the queried positions. Work is
//! O(num_queries · log(N·blowup)) hashes — logarithmic, not constant.
//!
//! ## Where soundness comes from
//! `ProofOptions` below IS the security parameter. More queries, bigger
//! blowup, or an extension field each buy more bits. winterfell computes the
//! resulting security level for you; the demo prints it. In the SNARK the
//! equivalent knob is the curve's group order — fixed at 254 bits.

use crate::air::{ChainAir, PublicInputs};
use crate::{Felt, K, N_STEPS, TRACE_LEN};
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::FieldElement,
    matrix::ColMatrix,
    verify, AcceptableOptions, AuxRandElements, BatchingMethod, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, FieldExtension, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain, Trace,
    TraceInfo, TracePolyTable, TraceTable, VerifierError,
};

/// The hash function that replaces the SNARK's elliptic curve.
pub type Hash = Blake3_256<Felt>;
/// Merkle tree over that hash = the polynomial commitment scheme.
pub type Vc = MerkleTree<Hash>;
type Coin = DefaultRandomCoin<Hash>;

/// Native chain evaluation in the STARK's 128-bit field.
pub fn chain(x0: Felt) -> Felt {
    let k = Felt::new(K as u128);
    let mut x = x0;
    for _ in 0..N_STEPS {
        x = x.exp(3) + k;
    }
    x
}

/// WITNESS GENERATION. Execute the computation and record every state.
/// This table is what the prover commits to. Note the loop actually runs
/// here at prove time — in zkp2 the "loop" ran once, at circuit-build time,
/// and produced gates rather than values.
///
/// TRACE_LEN rows ⇒ N_STEPS = TRACE_LEN − 1 applications of the step.
pub fn build_trace(x0: Felt) -> TraceTable<Felt> {
    let mut trace = TraceTable::new(1, TRACE_LEN);
    trace.fill(
        |state| state[0] = x0,
        |_step, state| state[0] = state[0].exp(3) + Felt::new(K as u128),
    );
    trace
}

/// SECURITY PARAMETERS. This is the STARK's analogue of "which curve".
///   num_queries      : 32 random openings → each cheating attempt survives
///                       one query with prob ≈ 1/blowup
///   blowup_factor    : 8  → trace extended 8× before committing
///   grinding_factor  : 0  → no proof-of-work on the transcript
///   field_extension  : None → challenges drawn from the 128-bit base field
///   fri_folding      : 4  → each FRI round quarters the degree
///   fri_remainder    : 31 → stop folding at degree ≤ 31 and send it in clear
pub fn options() -> ProofOptions {
    ProofOptions::new(32, 8, 0, FieldExtension::None, 4, 31, BatchingMethod::Linear, BatchingMethod::Linear)
}

pub struct ChainProver {
    options: ProofOptions,
}

impl ChainProver {
    pub fn new() -> Self {
        ChainProver { options: options() }
    }
}

impl Default for ChainProver {
    fn default() -> Self {
        Self::new()
    }
}

/// Most of this is winterfell plumbing selecting default components. The
/// three lines that carry meaning are the associated types `HashFn` and
/// `VC` (hash-based commitments) and `Air` (our constraint description).
impl Prover for ChainProver {
    type BaseField = Felt;
    type Air = ChainAir;
    type Trace = TraceTable<Felt>;
    type HashFn = Hash;
    type VC = Vc;
    type RandomCoin = Coin;
    type TraceLde<E: FieldElement<BaseField = Felt>> = DefaultTraceLde<E, Hash, Vc>;
    type ConstraintCommitment<E: FieldElement<BaseField = Felt>> = DefaultConstraintCommitment<E, Hash, Vc>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Felt>> = DefaultConstraintEvaluator<'a, ChainAir, E>;

    /// Public inputs are read *off the trace*: only the last cell.
    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        PublicInputs { result: trace.get(0, trace.length() - 1) }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Felt>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Felt>,
        domain: &StarkDomain<Felt>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Felt>>(
        &self,
        air: &'a ChainAir,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Felt>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Felt>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(composition_poly_trace, num_constraint_composition_columns, domain, partition_options)
    }
}

/// PROVE. Input: the trace (witness). No key. Output: a self-contained proof.
pub fn prove(x0: Felt) -> Proof {
    let trace = build_trace(x0);
    ChainProver::new().prove(trace).expect("prove")
}

/// VERIFY. Input: proof + public inputs + a policy on acceptable security.
/// Nothing else — no verifying key, no curve parameters. The AIR type
/// parameter is the "key".
pub fn verify_proof(proof: Proof, result: Felt) -> Result<(), VerifierError> {
    let policy = AcceptableOptions::MinConjecturedSecurity(80);
    verify::<ChainAir, Hash, Coin, Vc>(proof, PublicInputs { result }, &policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_to_end() {
        let x0 = Felt::new(3);
        let y = chain(x0);
        let proof = prove(x0);
        assert!(verify_proof(proof.clone(), y).is_ok());
        assert!(verify_proof(proof, y + Felt::ONE).is_err());
    }

    #[test]
    fn trace_ends_at_result() {
        let x0 = Felt::new(3);
        let tr = build_trace(x0);
        assert_eq!(tr.get(0, TRACE_LEN - 1), chain(x0));
    }

    #[test]
    fn tampered_trace_is_rejected() {
        // A prover who edits the trace so the last row is a chosen y but the
        // transition rule is broken somewhere in the middle.
        let x0 = Felt::new(3);
        let mut trace = build_trace(x0);
        let fake_y = Felt::new(12345);
        trace.set(0, TRACE_LEN - 1, fake_y);
        let proof = ChainProver::new().prove(trace);
        // winterfell may refuse in debug (constraint check) or emit a proof
        // that fails verification; either outcome is a rejection.
        match proof {
            Ok(p) => assert!(verify_proof(p, fake_y).is_err()),
            Err(_) => {}
        }
    }
}
