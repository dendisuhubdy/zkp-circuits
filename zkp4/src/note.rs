//! Keys and notes, native side. The circuit in `circuit.rs` recomputes every
//! hash here in-circuit; the two must agree exactly.

use crate::hash::{hash1, hash2};
use crate::Fr;
use ark_std::UniformRand;

/// A wallet's spending key. In Zcash this expands into several sub-keys;
/// we keep one and derive the public key by hashing.
#[derive(Clone, Copy, Debug)]
pub struct SpendingKey(pub Fr);

impl SpendingKey {
    pub fn random<R: rand::Rng>(rng: &mut R) -> Self {
        SpendingKey(Fr::rand(rng))
    }
    /// The shielded "address". Anyone can pay to it; only sk can spend from it.
    pub fn public_key(&self) -> Fr {
        hash1(self.0)
    }
    /// nf = H(sk, ρ). Only the owner can compute it, and it is fixed per
    /// note, so the chain can reject a second spend without learning which
    /// commitment it belongs to.
    pub fn nullifier(&self, note: &Note) -> Fr {
        hash2(self.0, note.rho)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Note {
    pub value: u64,
    pub pk: Fr,
    pub rho: Fr,
    pub r: Fr,
}

impl Note {
    pub fn new<R: rand::Rng>(value: u64, pk: Fr, rng: &mut R) -> Self {
        Note { value, pk, rho: Fr::rand(rng), r: Fr::rand(rng) }
    }
    /// cm = H( H(v, pk), H(ρ, r) ).  Hiding (r is random) and binding.
    pub fn commitment(&self) -> Fr {
        hash2(hash2(Fr::from(self.value), self.pk), hash2(self.rho, self.r))
    }
}
