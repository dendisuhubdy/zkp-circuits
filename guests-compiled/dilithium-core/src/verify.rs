//! Port of `crystals-dilithium` 2.0.0 `sign/lvl2.rs` `verify` (reached from `dilithium2.rs:245`,
//! `PublicKey::verify`). Each `fips202` call goes through [`Shake`] / [`shake256`] over the
//! caller's [`Keccak`].
//!
//! Shape change, same output: the reference expands all of A (`matrix_expand`) and then multiplies
//! (`matrix_pointwise_montgomery`); here one row of A is expanded and consumed at a time, and the
//! `t1_2` copy is gone (`k_pointwise_poly_montgomery` is in place). The order of the independent
//! steps (challenge, A, NTT of z) is the reference's.
use crate::params::{self as p, CRHBYTES, SEEDBYTES};
use crate::poly::{self, Poly, Polyveck, Polyvecl};
use crate::{packing, shake256, Keccak, Shake};

/// Verify a round-3 Dilithium2 signature `sig` on `m` under `pk`. Agrees with
/// `crystals_dilithium::dilithium2::PublicKey::verify` on every input; never panics; no heap.
pub fn verify<K: Keccak>(
    k: &mut K,
    pk: &[u8; p::PUBLICKEYBYTES],
    m: &[u8],
    sig: &[u8; p::SIGNBYTES],
) -> bool {
    let mut buf = [0u8; p::K * p::POLYW1_PACKEDBYTES];
    let mut rho = [0u8; SEEDBYTES];
    let mut mu = [0u8; CRHBYTES];
    let mut c = [0u8; SEEDBYTES];
    let mut c2 = [0u8; SEEDBYTES];
    let mut cp = Poly::default();
    let (mut row, mut z) = (Polyvecl::default(), Polyvecl::default());
    let (mut t1, mut w1, mut h) = (
        Polyveck::default(),
        Polyveck::default(),
        Polyveck::default(),
    );

    // (sig.len() != SIGNBYTES is unrepresentable: `sig` is a fixed-size array.)

    packing::unpack_pk(&mut rho, &mut t1, pk);
    if !packing::unpack_sig(&mut c, &mut z, &mut h, sig) {
        return false;
    }
    if poly::l_chknorm(&z, (p::GAMMA1 - p::BETA) as i32) > 0 {
        return false;
    }

    // Compute CRH(CRH(rho, t1), msg)
    shake256(k, &[pk], &mut mu[..SEEDBYTES]);
    let mut state = Shake::new256(&mut *k); // shake256_init()
    state.absorb(&mu[..SEEDBYTES]);
    state.absorb(m);
    state.finalize();
    state.squeeze(&mut mu);

    // Matrix-vector multiplication; compute Az - c2^dt1
    poly::challenge(k, &mut cp, &c);

    poly::l_ntt(&mut z);
    for i in 0..p::K {
        // matrix_expand row i, then matrix_pointwise_montgomery row i
        poly::matrix_expand_row(k, &mut row, &rho, i);
        poly::l_pointwise_acc_montgomery(&mut w1.vec[i], &row, &z);
    }

    poly::ntt(&mut cp);
    poly::k_shiftl(&mut t1);
    poly::k_ntt(&mut t1);
    poly::k_pointwise_poly_montgomery(&mut t1, &cp);

    poly::k_sub(&mut w1, &t1);
    poly::k_reduce(&mut w1);
    poly::k_invntt_tomont(&mut w1);

    // Reconstruct w1
    poly::k_caddq(&mut w1);
    poly::k_use_hint(&mut w1, &h);
    poly::k_pack_w1(&mut buf, &w1);

    // Call random oracle and verify challenge
    let mut state = Shake::new256(&mut *k);
    state.absorb(&mu);
    state.absorb(&buf);
    state.finalize();
    state.squeeze(&mut c2);
    // Doesn't require constant time equality check
    if c != c2 {
        return false;
    }
    true
}
