//! The Tornado Cash **withdraw circuit**.
//!
//! ```text
//!   public:   root, nullifierHash, recipient
//!   private:  nullifier ν, secret s, Merkle path (siblings + position bits)
//!
//!   constraints:
//!     (1) commitment    = H(ν, s)
//!     (2) nullifierHash = H(ν)
//!     (3) MerkleRoot(commitment, path) = root
//!     (4) recipient is "used" (so it is bound into the proof)
//! ```
//!
//! Note what is NOT proven: the amount. Every note is worth exactly one
//! denomination, fixed by the contract, so there is nothing to check. Zcash
//! (zkp4) has to do much more work because its notes carry arbitrary values.

use crate::hash::{hash1_gadget, hash2_gadget};
use crate::merkle::{root_gadget, MerklePath};
use crate::{Fr, TREE_DEPTH};
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

#[derive(Clone)]
pub struct WithdrawCircuit {
    // public
    pub root: Option<Fr>,
    pub nullifier_hash: Option<Fr>,
    pub recipient: Option<Fr>,
    // private
    pub nullifier: Option<Fr>,
    pub secret: Option<Fr>,
    pub path: Option<MerklePath>,
}

impl WithdrawCircuit {
    pub fn blank() -> Self {
        WithdrawCircuit { root: None, nullifier_hash: None, recipient: None, nullifier: None, secret: None, path: None }
    }
    /// Public inputs, in allocation order.
    pub fn public_inputs(&self) -> Vec<Fr> {
        vec![self.root.unwrap(), self.nullifier_hash.unwrap(), self.recipient.unwrap()]
    }
}

impl ConstraintSynthesizer<Fr> for WithdrawCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let miss = || SynthesisError::AssignmentMissing;

        // ---- public inputs (order matters: must match public_inputs()) ----
        let root = FpVar::new_input(cs.clone(), || self.root.ok_or(miss()))?;
        let nullifier_hash = FpVar::new_input(cs.clone(), || self.nullifier_hash.ok_or(miss()))?;
        let recipient = FpVar::new_input(cs.clone(), || self.recipient.ok_or(miss()))?;

        // ---- private witness ----
        let nullifier = FpVar::new_witness(cs.clone(), || self.nullifier.ok_or(miss()))?;
        let secret = FpVar::new_witness(cs.clone(), || self.secret.ok_or(miss()))?;
        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        let mut is_right = Vec::with_capacity(TREE_DEPTH);
        for d in 0..TREE_DEPTH {
            siblings.push(FpVar::new_witness(cs.clone(), || self.path.as_ref().map(|p| p.siblings[d]).ok_or(miss()))?);
            is_right.push(Boolean::new_witness(cs.clone(), || self.path.as_ref().map(|p| p.is_right[d]).ok_or(miss()))?);
        }

        // (1) commitment = H(ν, s)
        let commitment = hash2_gadget(&nullifier, &secret)?;

        // (2) nullifierHash = H(ν)
        hash1_gadget(&nullifier)?.enforce_equal(&nullifier_hash)?;

        // (3) the commitment sits in the tree with this root
        root_gadget(&commitment, &siblings, &is_right)?.enforce_equal(&root)?;

        // (4) bind the recipient. A public input that no constraint touches
        //     could be dropped by an optimizer; Tornado adds exactly this
        //     "recipientSquare" constraint for the same reason.
        let _recipient_sq = &recipient * &recipient;

        Ok(())
    }
}
