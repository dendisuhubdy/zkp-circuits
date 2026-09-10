//! The Poseidon2 sponge exactly as the `POSEIDON2` syscall/chip compute it, for host-side use
//! (guest wrapper generation, the emulator's own reference implementation, and any future
//! ledger/tree code). The chip proves the same sponge, round by round, over the `POSEIDON2`
//! bus (`tables::poseidon2`); this module has no trace columns and no AIR, only the plain
//! arithmetic, so it doubles as the M3-correctness anchor tests compare the emulator/chip
//! against.
use crate::machine::{permutation, Perm, Val};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge, Permutation};
use std::sync::OnceLock;

/// `machine::permutation()` redraws the whole round-constant RNG stream on every call; this
/// crate's hash paths (absorbing one 32-row block per call) run it often enough — up to 1024
/// times for a single `n = 4096` syscall — that redoing that draw per call is wasteful (the
/// arithmetic below is the cheap part). Cached the same way `tables::poseidon2::round_constants`
/// caches its own RNG replay.
fn perm() -> &'static Perm {
    static PERM: OnceLock<Perm> = OnceLock::new();
    PERM.get_or_init(permutation)
}

/// One raw width-8 permutation over field elements — exactly what the `POSEIDON2` chip's bus
/// entry carries and what `emulator.rs`'s absorb loop chains between blocks. A sponge state's
/// lanes are *not* bounded to `u32` in general (only the rate lanes get overwritten by small
/// absorbed words; the capacity lanes, and any lane after a permutation, are uniformly-
/// distributed field elements that routinely exceed `u32::MAX`), so the emulator must carry the
/// running state as `[Val; 8]`, not `[u32; 8]` — [`permute_words`] below, which round-trips
/// through `u32`, is only a test convenience for states that happen to be small.
pub fn permute_state(state: [Val; 8]) -> [Val; 8] {
    let mut s = state;
    perm().permute_mut(&mut s);
    s
}

/// `permute_state` with a lossy `u32` in/out convenience wrapper: **only** correct when both
/// the input and the output lanes are individually known to be `< 2^32` (e.g. a test fixture's
/// small hand-picked state). It must never be used for the real absorb chain (see
/// `permute_state`'s doc comment) or to read out a final digest (whose canonical `u64` can
/// exceed `u32::MAX` — use [`split_digest`] for that).
pub fn permute_words(state: [u32; 8]) -> [u32; 8] {
    let s = permute_state(state.map(Val::from_u32));
    s.map(|x| x.as_canonical_u64() as u32)
}

/// Splits 4 canonical Goldilocks field-element digest lanes into 8 lo/hi machine words: lane
/// `i`'s canonical `u64` becomes words `2i` (low 32 bits) and `2i+1` (high 32 bits).
pub fn split_digest(elems: [Val; 4]) -> [u32; 8] {
    let mut out = [0u32; 8];
    for (i, e) in elems.iter().enumerate() {
        let v = e.as_canonical_u64();
        out[2 * i] = v as u32;
        out[2 * i + 1] = (v >> 32) as u32;
    }
    out
}

/// The sponge the `POSEIDON2` syscall computes over `msg` (each element already a small `u32`,
/// absorbed as a field element directly — rate 4, overwrite mode, no padding:
/// `PaddingFreeSponge<_, 8, 4, 4>` semantics, matching `p3_symmetric::sponge::PaddingFreeSponge`
/// exactly, empty input included: `sponge_hash(&[])` performs no permutation and returns the
/// all-zero digest), returning the 8 lo/hi digest words.
pub fn sponge_hash(msg: &[u32]) -> [u32; 8] {
    let sponge = PaddingFreeSponge::<_, 8, 4, 4>::new(perm().clone());
    let elems: Vec<Val> = msg.iter().copied().map(Val::from_u32).collect();
    let digest: [Val; 4] = sponge.hash_iter(elems);
    split_digest(digest)
}
