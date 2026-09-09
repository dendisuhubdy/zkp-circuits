//! CLSAG: Concise Linkable Spontaneous Anonymous Group signature
//! (Goodell–Noether–RandomRun 2019, Monero's signature since 2020).
//!
//! ## Idea, from a plain Schnorr signature upward
//!
//! Schnorr: prove knowledge of x with P = xG.  Pick α, L = αG, c = H(m, L),
//! s = α − c·x. Verifier recomputes L' = sG + cP and checks H(m, L') = c.
//!
//! Ring: given P_0 … P_{n−1}, prove knowledge of *some* x_π without revealing
//! π. Arrange the challenges in a **ring**: c_{i+1} = H(m, L_i) where
//! L_i = s_i·G + c_i·P_i. For every i ≠ π the prover picks s_i at random and
//! just computes c_{i+1}. Only at i = π must the prover close the loop, and
//! only x_π lets them: they start the ring *at* π with a fresh α, go all the
//! way round computing challenges, and finally solve s_π = α − c_π·x_π so
//! that L_π = αG. The verifier walks the ring from c_0 and checks it closes.
//! Every index looks the same to them.
//!
//! Linkable: also publish the key image I = x_π·Hp(P_π) and thread it
//! through a second sequence R_i = s_i·Hp(P_i) + c_i·I. Same x ⇒ same I,
//! so spending the same output twice is detectable, but I reveals nothing
//! about which P (that would need solving discrete log in Hp(P)).
//!
//! CLSAG: sign for TWO keys per ring member at once — the one-time key P_i
//! and the commitment difference C_i − C' — by aggregating them with hash
//! weights μ_P, μ_C into W_i = μ_P·P_i + μ_C·(C_i − C'). One ring of
//! challenges covers both "I own this output" and "its amount equals my
//! pseudo-output's amount". That is what makes it *concise*: one s per
//! member instead of two (MLSAG).

use crate::{hp, hs, pt, Point, Scalar};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;

#[derive(Clone)]
pub struct Signature {
    pub c0: Scalar,
    pub s: Vec<Scalar>,
    /// Key image of the spent output's one-time key.
    pub key_image: Point,
    /// Auxiliary image for the commitment key (needed to verify).
    pub d: Point,
}

impl Signature {
    pub fn size_bytes(&self) -> usize {
        32 * (2 + self.s.len()) + 32
    }
}

fn ring_bytes(ring: &[(Point, Point)], pseudo_out: &Point) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 * (2 * ring.len() + 1));
    for (p, c) in ring {
        v.extend_from_slice(&pt(p));
        v.extend_from_slice(&pt(c));
    }
    v.extend_from_slice(&pt(pseudo_out));
    v
}

fn aggregation_coeffs(ring: &[(Point, Point)], pseudo_out: &Point, i: &Point, d: &Point) -> (Scalar, Scalar) {
    let rb = ring_bytes(ring, pseudo_out);
    let mu_p = hs(b"CLSAG_agg_0", &[&rb, &pt(i), &pt(d)]);
    let mu_c = hs(b"CLSAG_agg_1", &[&rb, &pt(i), &pt(d)]);
    (mu_p, mu_c)
}

fn round_challenge(msg: &[u8], rb: &[u8], l: &Point, r: &Point) -> Scalar {
    hs(b"CLSAG_round", &[msg, rb, &pt(l), &pt(r)])
}

/// `ring[i] = (P_i, C_i)`; the signer owns index `pi` with one-time secret
/// `x` (P_π = xG) and knows the commitment blinding difference `z` such that
/// C_π − pseudo_out = z·G (i.e. both commit to the same value).
pub fn sign<R: rand::Rng + rand::CryptoRng>(
    msg: &[u8],
    ring: &[(Point, Point)],
    pseudo_out: &Point,
    pi: usize,
    x: &Scalar,
    z: &Scalar,
    rng: &mut R,
) -> Signature {
    let n = ring.len();
    let hp_pi = hp(b"CLSAG_Hp", &[&pt(&ring[pi].0)]);
    let key_image = x * hp_pi;
    let d = z * hp_pi;
    let (mu_p, mu_c) = aggregation_coeffs(ring, pseudo_out, &key_image, &d);
    let rb = ring_bytes(ring, pseudo_out);
    let w_img = mu_p * key_image + mu_c * d;

    // start the ring at π with a fresh nonce
    let alpha = Scalar::random(rng);
    let mut c = vec![Scalar::ZERO; n];
    let mut s = vec![Scalar::ZERO; n];
    c[(pi + 1) % n] = round_challenge(msg, &rb, &(alpha * G), &(alpha * hp_pi));

    // walk the ring: π+1, π+2, …, π−1
    for k in 1..n {
        let i = (pi + k) % n;
        s[i] = Scalar::random(rng);
        let w_i = mu_p * ring[i].0 + mu_c * (ring[i].1 - pseudo_out);
        let hp_i = hp(b"CLSAG_Hp", &[&pt(&ring[i].0)]);
        let l = s[i] * G + c[i] * w_i;
        let r = s[i] * hp_i + c[i] * w_img;
        c[(i + 1) % n] = round_challenge(msg, &rb, &l, &r);
    }

    // close the loop at π — the only step that needs the secrets
    s[pi] = alpha - c[pi] * (mu_p * x + mu_c * z);

    Signature { c0: c[0], s, key_image, d }
}

pub fn verify(msg: &[u8], ring: &[(Point, Point)], pseudo_out: &Point, sig: &Signature) -> bool {
    let n = ring.len();
    if sig.s.len() != n {
        return false;
    }
    let (mu_p, mu_c) = aggregation_coeffs(ring, pseudo_out, &sig.key_image, &sig.d);
    let rb = ring_bytes(ring, pseudo_out);
    let w_img = mu_p * sig.key_image + mu_c * sig.d;

    // walk the whole ring from c_0; it must come back to c_0
    let mut c = sig.c0;
    for i in 0..n {
        let w_i = mu_p * ring[i].0 + mu_c * (ring[i].1 - pseudo_out);
        let hp_i = hp(b"CLSAG_Hp", &[&pt(&ring[i].0)]);
        let l = sig.s[i] * G + c * w_i;
        let r = sig.s[i] * hp_i + c * w_img;
        c = round_challenge(msg, &rb, &l, &r);
    }
    c == sig.c0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pedersen::commit;
    use rand::Rng;

    fn ring_with_secret(n: usize, pi: usize, rng: &mut rand::rngs::OsRng) -> (Vec<(Point, Point)>, Point, Scalar, Scalar) {
        let mut ring = Vec::new();
        for _ in 0..n {
            ring.push((Scalar::random(rng) * G, commit(rng.gen_range(0..100), &Scalar::random(rng))));
        }
        let x = Scalar::random(rng);
        let gamma = Scalar::random(rng);
        let gamma_pseudo = Scalar::random(rng);
        ring[pi] = (x * G, commit(42, &gamma));
        let pseudo = commit(42, &gamma_pseudo);
        (ring, pseudo, x, gamma - gamma_pseudo)
    }

    #[test]
    fn signs_and_verifies_from_any_index() {
        let mut rng = rand::rngs::OsRng;
        for pi in [0, 3, 10] {
            let (ring, pseudo, x, z) = ring_with_secret(11, pi, &mut rng);
            let sig = sign(b"tx", &ring, &pseudo, pi, &x, &z, &mut rng);
            assert!(verify(b"tx", &ring, &pseudo, &sig));
            assert!(!verify(b"other tx", &ring, &pseudo, &sig));
        }
    }

    #[test]
    fn wrong_secret_or_wrong_amount_fails() {
        let mut rng = rand::rngs::OsRng;
        let (ring, pseudo, x, z) = ring_with_secret(11, 4, &mut rng);
        let sig = sign(b"tx", &ring, &pseudo, 4, &Scalar::random(&mut rng), &z, &mut rng);
        assert!(!verify(b"tx", &ring, &pseudo, &sig));
        // pseudo-output that commits to a different value
        let pseudo_bad = commit(43, &Scalar::random(&mut rng));
        let sig = sign(b"tx", &ring, &pseudo_bad, 4, &x, &z, &mut rng);
        assert!(!verify(b"tx", &ring, &pseudo_bad, &sig));
    }

    #[test]
    fn key_image_is_deterministic_per_key() {
        let mut rng = rand::rngs::OsRng;
        let (ring, pseudo, x, z) = ring_with_secret(11, 2, &mut rng);
        let a = sign(b"tx1", &ring, &pseudo, 2, &x, &z, &mut rng);
        let b = sign(b"tx2", &ring, &pseudo, 2, &x, &z, &mut rng);
        assert_eq!(a.key_image, b.key_image);
        assert_ne!(a.s, b.s);
    }
}
