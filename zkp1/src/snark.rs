//! Groth16 in three calls. This module is deliberately thin: the library
//! does the heavy lifting, the point is to name the moving parts.
//!
//! ## The three phases
//!
//! 1. **Setup**  `(pk, vk) ← Setup(circuit shape, randomness τ)`
//!    Produces a proving key and a verifying key *for this specific circuit*.
//!    The randomness τ ("toxic waste") must be destroyed: anyone holding it
//!    can forge proofs. Real deployments run a multi-party ceremony so that
//!    no single participant ever sees τ. Here we just use an RNG and forget it.
//!
//! 2. **Prove**  `π ← Prove(pk, public inputs, private witness)`
//!    The prover evaluates the circuit, gets a satisfying assignment, and
//!    compresses "this assignment satisfies every constraint" into three
//!    elliptic-curve points (A, B, C). ~128 bytes on BN254. Constant size,
//!    no matter how many constraints the circuit has - that's the "S" in SNARK.
//!
//! 3. **Verify** `{0,1} ← Verify(vk, public inputs, π)`
//!    A handful of pairing checks:  e(A, B) = e(α, β) · e(L(pub), γ) · e(C, δ).
//!    Milliseconds, independent of circuit size. This is what an on-chain
//!    verifier contract does.
//!
//! ## Where does the zero-knowledge come from?
//!
//! Prove() blinds A and C with fresh randomness (r, s). Two proofs of the
//! same statement are completely different byte strings, and the witness
//! only ever appears "in the exponent" of curve points, hidden by the
//! discrete-log problem.

use ark_bn254::Bn254;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};

use crate::Fr;

pub type Pk = ProvingKey<Bn254>;
pub type Vk = VerifyingKey<Bn254>;
pub type Pi = Proof<Bn254>;

/// Phase 1. `circuit` should have *no* assigned values - only its shape is used.
pub fn setup<C, R>(circuit: C, rng: &mut R) -> (Pk, Vk)
where
    C: ConstraintSynthesizer<Fr>,
    R: RngCore + CryptoRng,
{
    Groth16::<Bn254>::circuit_specific_setup(circuit, rng).expect("setup")
}

/// Phase 2. `circuit` must carry the full witness.
pub fn prove<C, R>(pk: &Pk, circuit: C, rng: &mut R) -> Result<Pi, ark_relations::r1cs::SynthesisError>
where
    C: ConstraintSynthesizer<Fr>,
    R: RngCore + CryptoRng,
{
    Groth16::<Bn254>::prove(pk, circuit, rng)
}

/// Phase 3. Only the verifying key, the public inputs, and the proof.
/// Note what is *absent*: the circuit, the witness, the proving key.
pub fn verify(vk: &Vk, public_inputs: &[Fr], proof: &Pi) -> bool {
    let pvk: PreparedVerifyingKey<Bn254> = ark_groth16::prepare_verifying_key(vk);
    Groth16::<Bn254>::verify_with_processed_vk(&pvk, public_inputs, proof).unwrap_or(false)
}

/// Serialized size in bytes (compressed), for the demo's size table.
pub fn size_of<T: CanonicalSerialize>(t: &T) -> usize {
    t.compressed_size()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cubic::CubicCircuit;
    use crate::mimc::{mimc, MimcPreimageCircuit};

    #[test]
    fn cubic_end_to_end() {
        let mut rng = rand::rngs::OsRng;
        let (pk, vk) = setup(CubicCircuit { x: None, out: None }, &mut rng);
        let x = Fr::from(3u64);
        let out = CubicCircuit::eval(x);
        let proof = prove(&pk, CubicCircuit { x: Some(x), out: Some(out) }, &mut rng).unwrap();
        assert!(verify(&vk, &[out], &proof));
        assert!(!verify(&vk, &[out + Fr::from(1u64)], &proof));
        assert_eq!(size_of(&proof), 128);
    }

    #[test]
    fn cubic_wrong_witness_rejected() {
        use ark_relations::r1cs::ConstraintSystem;
        let mut rng = rand::rngs::OsRng;
        let (pk, vk) = setup(CubicCircuit { x: None, out: None }, &mut rng);
        let out = CubicCircuit::eval(Fr::from(3u64));
        let bad = CubicCircuit { x: Some(Fr::from(4u64)), out: Some(out) };

        // The witness must fail the constraints themselves.
        let cs = ConstraintSystem::<Fr>::new_ref();
        bad.clone().generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());

        // ark-groth16's prover has `debug_assert!(cs.is_satisfied())`, so forging a
        // proof from a bad witness panics in debug builds. Only a release build
        // (`cargo test --release`) can show that the forged proof is rejected.
        if cfg!(debug_assertions) {
            return;
        }
        let proof = prove(&pk, bad, &mut rng).unwrap();
        assert!(!verify(&vk, &[out], &proof));
    }

    #[test]
    fn mimc_end_to_end() {
        let mut rng = rand::rngs::OsRng;
        let (pk, vk) = setup(MimcPreimageCircuit::blank(), &mut rng);
        let (x, k) = (Fr::from(7u64), Fr::from(1u64));
        let circuit = MimcPreimageCircuit::with_secret(x, k);
        let public = circuit.public_inputs();
        let proof = prove(&pk, circuit, &mut rng).unwrap();
        assert!(verify(&vk, &public, &proof));
        assert!(!verify(&vk, &[k, mimc(Fr::from(8u64), k)], &proof));
    }
}
