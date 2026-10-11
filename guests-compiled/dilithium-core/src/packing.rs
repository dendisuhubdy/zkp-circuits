//! Port of the verify half of `crystals-dilithium` 2.0.0 `packing/lvl2.rs`: `unpack_pk` and
//! `unpack_sig`, with every hint check. Inputs are fixed-size arrays; sub-arrays are taken with
//! `first_chunk`, whose `None` arm is unreachable at these constant offsets (it rejects rather
//! than panics).
use crate::params::{self, OMEGA, POLYT1_PACKEDBYTES, POLYZ_PACKEDBYTES, SEEDBYTES};
use crate::poly::{self, Polyveck, Polyvecl};

const K: usize = params::K;
const L: usize = params::L;

/// Unpack public key pk = (rho, t1).
pub fn unpack_pk(rho: &mut [u8; SEEDBYTES], t1: &mut Polyveck, pk: &[u8; params::PUBLICKEYBYTES]) {
    if let Some(r) = pk.first_chunk::<SEEDBYTES>() {
        *rho = *r;
    }
    for i in 0..K {
        if let Some(a) =
            pk[SEEDBYTES + i * POLYT1_PACKEDBYTES..].first_chunk::<POLYT1_PACKEDBYTES>()
        {
            poly::t1_unpack(&mut t1.vec[i], a);
        }
    }
}

/// Unpack signature sig = (c, z, h). Returns `false` on a malformed hint section, exactly where
/// the reference does. `h` must arrive zeroed (the reference's `Polyveck::default()`).
#[allow(clippy::needless_range_loop)]
pub fn unpack_sig(
    c: &mut [u8; SEEDBYTES],
    z: &mut Polyvecl,
    h: &mut Polyveck,
    sig: &[u8; params::SIGNBYTES],
) -> bool {
    match sig.first_chunk::<SEEDBYTES>() {
        Some(cc) => *c = *cc,
        None => return false,
    }

    let mut idx = SEEDBYTES;
    for i in 0..L {
        match sig[idx + i * POLYZ_PACKEDBYTES..].first_chunk::<POLYZ_PACKEDBYTES>() {
            Some(a) => poly::z_unpack(&mut z.vec[i], a),
            None => return false,
        }
    }
    idx += L * POLYZ_PACKEDBYTES;

    // The hint section: OMEGA index bytes, then K cumulative counts.
    let hint = match sig[idx..].first_chunk::<{ params::POLYVECH_PACKEDBYTES }>() {
        Some(hint) => hint,
        None => return false,
    };

    let mut k: usize = 0;
    for i in 0..K {
        if hint[OMEGA + i] < k as u8 || hint[OMEGA + i] > OMEGA as u8 {
            return false;
        }
        for j in k..hint[OMEGA + i] as usize {
            if j > k && hint[j] <= hint[j - 1] {
                return false;
            }
            h.vec[i].coeffs[hint[j] as usize] = 1;
        }
        k = hint[OMEGA + i] as usize;
    }

    for j in k..OMEGA {
        if hint[j] > 0 {
            return false;
        }
    }

    true
}
