//! The shielded **transfer circuit**: 1 input note → 2 output notes + v_pub.
//!
//! Read this next to `zkp6/src/circuit.rs`. Everything Tornado does is here
//! too (membership + nullifier); the additions are marked ★.

use crate::hash::{hash1_gadget, hash2_gadget};
use crate::merkle::{root_gadget, MerklePath};
use crate::note::{Note, SpendingKey};
use crate::{Fr, TREE_DEPTH, VALUE_BITS};
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar, fields::FieldVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

#[derive(Clone)]
pub struct TransferCircuit {
    // ---- public ----
    pub root: Option<Fr>,
    pub nullifier: Option<Fr>,
    pub cm_out: [Option<Fr>; 2],
    pub v_pub: Option<u64>,
    // ---- private ----
    pub sk: Option<SpendingKey>,
    pub note_in: Option<Note>,
    pub path: Option<MerklePath>,
    pub notes_out: [Option<Note>; 2],
}

impl TransferCircuit {
    pub fn blank() -> Self {
        TransferCircuit {
            root: None,
            nullifier: None,
            cm_out: [None, None],
            v_pub: None,
            sk: None,
            note_in: None,
            path: None,
            notes_out: [None, None],
        }
    }
    pub fn public_inputs(&self) -> Vec<Fr> {
        vec![
            self.root.unwrap(),
            self.nullifier.unwrap(),
            self.cm_out[0].unwrap(),
            self.cm_out[1].unwrap(),
            Fr::from(self.v_pub.unwrap()),
        ]
    }
}

/// ★ Range check: prove `v` fits in VALUE_BITS bits.
///
/// Why this is *essential* and not a nicety: the balance equation
/// v = v1 + v2 + v_pub holds mod r (a 254-bit prime). Without a range check
/// a thief could set v1 = 5 and v2 = r − 5 + v: the sum wraps to v, the
/// proof verifies, and note 2 is now worth "r − 5 + v" — effectively
/// infinite money. Zcash's 2018 counterfeiting bug was in exactly this
/// area (a soundness flaw in the original Sprout range/balance proof).
///
/// Cost: 64 Boolean witnesses (1 constraint each to enforce b·(1−b)=0) plus
/// one linear constraint tying Σ bᵢ·2ⁱ to v.
fn enforce_u64(cs: ConstraintSystemRef<Fr>, v: &FpVar<Fr>, value: Option<u64>) -> Result<(), SynthesisError> {
    let mut acc = FpVar::zero();
    let mut coeff = Fr::from(1u64);
    for i in 0..VALUE_BITS {
        let bit = Boolean::new_witness(cs.clone(), || value.map(|x| (x >> i) & 1 == 1).ok_or(SynthesisError::AssignmentMissing))?;
        // Boolean → field element (0 or 1), scaled by 2^i
        let bit_fp: FpVar<Fr> = From::from(bit);
        acc += bit_fp * coeff;
        coeff = coeff + coeff;
    }
    acc.enforce_equal(v)
}

/// In-circuit note commitment, mirroring `Note::commitment`.
fn commitment_gadget(v: &FpVar<Fr>, pk: &FpVar<Fr>, rho: &FpVar<Fr>, r: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    hash2_gadget(&hash2_gadget(v, pk)?, &hash2_gadget(rho, r)?)
}

impl ConstraintSynthesizer<Fr> for TransferCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let miss = || SynthesisError::AssignmentMissing;
        let fr_u64 = |x: Option<u64>| x.map(Fr::from).ok_or(miss());

        // ---- public inputs, in public_inputs() order ----
        let root = FpVar::new_input(cs.clone(), || self.root.ok_or(miss()))?;
        let nullifier = FpVar::new_input(cs.clone(), || self.nullifier.ok_or(miss()))?;
        let cm_out0 = FpVar::new_input(cs.clone(), || self.cm_out[0].ok_or(miss()))?;
        let cm_out1 = FpVar::new_input(cs.clone(), || self.cm_out[1].ok_or(miss()))?;
        let v_pub = FpVar::new_input(cs.clone(), || fr_u64(self.v_pub))?;

        // ---- private: spending key and input note ----
        let sk = FpVar::new_witness(cs.clone(), || self.sk.map(|k| k.0).ok_or(miss()))?;
        let n = self.note_in;
        let v_in = FpVar::new_witness(cs.clone(), || fr_u64(n.map(|n| n.value)))?;
        let rho_in = FpVar::new_witness(cs.clone(), || n.map(|n| n.rho).ok_or(miss()))?;
        let r_in = FpVar::new_witness(cs.clone(), || n.map(|n| n.r).ok_or(miss()))?;
        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        let mut is_right = Vec::with_capacity(TREE_DEPTH);
        for d in 0..TREE_DEPTH {
            siblings.push(FpVar::new_witness(cs.clone(), || self.path.as_ref().map(|p| p.siblings[d]).ok_or(miss()))?);
            is_right.push(Boolean::new_witness(cs.clone(), || self.path.as_ref().map(|p| p.is_right[d]).ok_or(miss()))?);
        }

        // ★ ownership: the input note's pk must be H(sk). The note's pk is
        //   not a witness — it is *derived* from sk, so the prover cannot
        //   claim a note that belongs to someone else's key.
        let pk_in = hash1_gadget(&sk)?;

        // membership (same as Tornado)
        let cm_in = commitment_gadget(&v_in, &pk_in, &rho_in, &r_in)?;
        root_gadget(&cm_in, &siblings, &is_right)?.enforce_equal(&root)?;

        // ★ nullifier bound to the spending key, not to a shared secret
        hash2_gadget(&sk, &rho_in)?.enforce_equal(&nullifier)?;

        // ---- private: output notes ----
        let mut v_out_sum = FpVar::zero();
        for (i, cm_pub) in [cm_out0, cm_out1].iter().enumerate() {
            let o = self.notes_out[i];
            let v = FpVar::new_witness(cs.clone(), || fr_u64(o.map(|o| o.value)))?;
            let pk = FpVar::new_witness(cs.clone(), || o.map(|o| o.pk).ok_or(miss()))?;
            let rho = FpVar::new_witness(cs.clone(), || o.map(|o| o.rho).ok_or(miss()))?;
            let r = FpVar::new_witness(cs.clone(), || o.map(|o| o.r).ok_or(miss()))?;

            // ★ the public commitment really commits to (v, pk, ρ, r)
            commitment_gadget(&v, &pk, &rho, &r)?.enforce_equal(cm_pub)?;
            // ★ no wrap-around
            enforce_u64(cs.clone(), &v, o.map(|o| o.value))?;
            v_out_sum += v;
        }

        // ★ value conservation: v_in = v_out1 + v_out2 + v_pub
        (v_out_sum + v_pub).enforce_equal(&v_in)?;

        Ok(())
    }
}
