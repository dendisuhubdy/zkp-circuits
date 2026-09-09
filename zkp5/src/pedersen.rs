//! Pedersen commitments: C = γ·G + v·H.
//!
//! * hiding: γ is random, so C says nothing about v
//! * binding: opening to a different (v', γ') needs log_G(H), which nobody knows
//! * homomorphic: C₁ + C₂ = (γ₁+γ₂)·G + (v₁+v₂)·H
//!
//! The last property is the whole balance proof. If the sender chooses the
//! output blindings so that Σγ_in = Σγ_out, then
//!
//! ```text
//!     Σ C_in − Σ C_out − fee·H  =  (Σv_in − Σv_out − fee)·H
//! ```
//!
//! and this is the identity point iff the values balance. Nobody needs a
//! circuit to check it: one point addition per commitment.
//!
//! In a real transaction the inputs' blindings are known to the sender (they
//! were derived when the outputs were received) but are *not* the ones the
//! chain sees in the ring — the ring contains decoys. So Monero introduces a
//! **pseudo-output** commitment C'_i per input: same value, fresh blinding.
//! The ring signature proves C_real − C' is a commitment to zero; the chain
//! checks Σ C' = Σ C_out + fee·H in the clear.

use crate::{hp, Point, Scalar};
use bulletproofs::PedersenGens;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;

/// H: a second generator with unknown discrete log w.r.t. G. Monero derives
/// it by hashing G; we hash a fixed tag.
pub fn h_gen() -> Point {
    hp(b"monero-H-generator", &[])
}

pub fn commit(value: u64, blinding: &Scalar) -> Point {
    blinding * G + Scalar::from(value) * h_gen()
}

/// The generator pair in the layout the `bulletproofs` crate expects:
/// `B` for the value, `B_blinding` for the blinding — so its commitments
/// are byte-identical to ours.
pub fn gens() -> PedersenGens {
    PedersenGens { B: h_gen(), B_blinding: G }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn homomorphic_and_matches_bulletproofs() {
        let mut rng = rand::rngs::OsRng;
        let (g1, g2) = (Scalar::random(&mut rng), Scalar::random(&mut rng));
        assert_eq!(commit(3, &g1) + commit(4, &g2), commit(7, &(g1 + g2)));
        assert_eq!(gens().commit(Scalar::from(3u64), g1), commit(3, &g1));
    }
}
