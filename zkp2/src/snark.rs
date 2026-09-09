//! SNARK-side proof system: Groth16 on BN254.
//!
//! Compare each function with its counterpart in `zkp3/src/stark.rs`.
//!
//! ## setup()      ← STARK has no equivalent
//! Samples secret τ, α, β, γ, δ and publishes curve points [τⁱ]₁, [τⁱ]₂ …
//! folded through the circuit's A/B/C matrices. Whoever knows τ can forge
//! proofs, so τ must be destroyed (the "toxic waste"). Production systems
//! run an MPC ceremony where hundreds of parties each contribute randomness;
//! it is secure if *at least one* of them was honest. A STARK has no such
//! ceremony because it commits to polynomials with hashes, not with powers
//! of a secret point.
//!
//! ## prove()
//! Cost is dominated by multi-scalar multiplications on the curve: one
//! 254-bit scalar × point per wire, for every wire. Curve ops are ~100×
//! slower than 64-bit field ops, which is why STARK provers are faster for
//! large computations despite doing more FFT work.
//!
//! ## verify()
//! Three pairings, a fixed-size computation regardless of N. The pairing is
//! what lets the verifier check a polynomial identity "in the exponent"
//! without ever seeing the polynomial — this is the bilinear-map trick that
//! a hash-based STARK cannot use, and the reason a STARK verifier instead
//! has to open Merkle paths at random points (FRI).
//!
//! ## What zero-knowledge costs here: nothing extra
//! Groth16 blinds A with r·δ and C with s·δ - the randomness is baked into
//! the proof equation, so ZK is free. In a STARK, ZK is a separate step
//! (adding random rows to the trace) and winterfell 0.13 does not do it.

use ark_bn254::Bn254;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};

use crate::Fr;

pub type Pk = ProvingKey<Bn254>;
pub type Vk = VerifyingKey<Bn254>;
pub type SnarkProof = Proof<Bn254>;

/// TRUSTED SETUP. Circuit-specific. The STARK crate has no such function.
pub fn setup<C: ConstraintSynthesizer<Fr>, R: RngCore + CryptoRng>(circuit: C, rng: &mut R) -> (Pk, Vk) {
    Groth16::<Bn254>::circuit_specific_setup(circuit, rng).expect("setup")
}

/// Needs the proving key (which embeds τ-derived points) and the witness.
///
/// Groth16 itself never rejects a bad witness: ark-groth16's prover has a
/// `debug_assert!(cs.is_satisfied())` that panics in debug builds, and in
/// release builds it silently emits a proof the verifier will reject. A
/// real prover checks its own witness first, so we do that here and return
/// `SynthesisError::Unsatisfiable` instead of calling into the library.
pub fn prove<C: ConstraintSynthesizer<Fr> + Clone, R: RngCore + CryptoRng>(
    pk: &Pk,
    circuit: C,
    rng: &mut R,
) -> Result<SnarkProof, SynthesisError> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.clone().generate_constraints(cs.clone())?;
    if !cs.is_satisfied()? {
        return Err(SynthesisError::Unsatisfiable);
    }
    Groth16::<Bn254>::prove(pk, circuit, rng)
}

/// Needs the verifying key (a few curve points), public inputs, proof.
pub fn verify(vk: &Vk, public_inputs: &[Fr], proof: &SnarkProof) -> bool {
    let pvk = ark_groth16::prepare_verifying_key(vk);
    Groth16::<Bn254>::verify_with_processed_vk(&pvk, public_inputs, proof).unwrap_or(false)
}

pub fn size_of<T: CanonicalSerialize>(t: &T) -> usize {
    t.compressed_size()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{chain, ChainCircuit};

    #[test]
    fn end_to_end() {
        let mut rng = rand::rngs::OsRng;
        let (pk, vk) = setup(ChainCircuit::blank(), &mut rng);
        let x0 = Fr::from(3u64);
        let y = chain(x0);
        let proof = prove(&pk, ChainCircuit::with_secret(x0), &mut rng).unwrap();
        assert!(verify(&vk, &[y], &proof));
        assert!(!verify(&vk, &[y + Fr::from(1u64)], &proof));
        assert_eq!(size_of(&proof), 128);
    }

    #[test]
    fn wrong_witness_refused_by_prover() {
        let mut rng = rand::rngs::OsRng;
        let (pk, _vk) = setup(ChainCircuit::blank(), &mut rng);
        let y = chain(Fr::from(3u64));
        let res = prove(&pk, ChainCircuit { x0: Some(Fr::from(4u64)), y: Some(y) }, &mut rng);
        assert!(matches!(res, Err(SynthesisError::Unsatisfiable)));
    }

    /// ark-groth16's prover has `debug_assert!(cs.is_satisfied())`, so a proof
    /// forged from a bad witness can only be produced in a release build
    /// (`cargo test --release`). There, the verifier rejects it.
    #[test]
    #[cfg(not(debug_assertions))]
    fn forged_proof_rejected_by_verifier() {
        let mut rng = rand::rngs::OsRng;
        let (pk, vk) = setup(ChainCircuit::blank(), &mut rng);
        let y = chain(Fr::from(3u64));
        let forged = Groth16::<Bn254>::prove(&pk, ChainCircuit { x0: Some(Fr::from(4u64)), y: Some(y) }, &mut rng).unwrap();
        assert!(!verify(&vk, &[y], &forged));
    }
}
