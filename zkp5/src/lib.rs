//! zkp5 — **Monero**-style private transactions, simulated end to end.
//!
//! Monero is the odd one out in this series: there is **no SNARK and no
//! circuit**. Privacy comes from four older, cheaper primitives composed on
//! the Ed25519 curve (we use its Ristretto encoding):
//!
//! ```text
//!   WHO RECEIVES   stealth addresses      each output goes to a fresh one-time key P,
//!                                         derivable only by the recipient's view key
//!   HOW MUCH       Pedersen commitments   C = γ·G + v·H hides v; commitments add up,
//!                                         so  Σ C_in − Σ C_out − fee·H  = 0  proves balance
//!                  Bulletproofs           range proof that each v_out ∈ [0, 2⁶⁴)
//!                                         (else negative outputs would create coins)
//!   WHO SPENDS     CLSAG ring signature   "one of these 11 outputs is mine and I signed
//!                                         with its key" — without saying which
//!   NO DOUBLE      key image I = x·Hp(P)  deterministic per output; the chain rejects a
//!   SPEND                                 repeat but cannot map I back to P
//! ```
//!
//! ## Monero vs Zcash vs Tornado, in one table
//!
//! |                    | Tornado (zkp6)      | Zcash (zkp4)         | Monero (this crate)          |
//! |--------------------|---------------------|----------------------|------------------------------|
//! | proof system       | Groth16 SNARK       | Groth16 SNARK        | ring signature + Bulletproofs|
//! | trusted setup      | yes                 | yes (Sapling; Halo2 removed it in Orchard) | **no** |
//! | anonymity set      | whole pool          | whole pool           | **ring size (16)** per input |
//! | hides amount       | fixed denomination  | yes                  | yes                          |
//! | hides recipient    | n/a                 | yes                  | yes (stealth address)        |
//! | spend proof size   | 128 B               | 128 B                | ~1.5 KB (ring 11) + ~700 B BP |
//! | verify cost        | 3 pairings          | 3 pairings           | ~2·ring scalar mults + BP    |
//! | double-spend tag   | nullifier H(ν)      | nullifier H(sk, ρ)   | key image x·Hp(P)            |
//! | post-quantum       | no                  | no                   | no                           |
//! | mandatory privacy  | opt-in              | opt-in (t-addrs)     | **every tx**                 |
//!
//! The deepest difference is the anonymity set. A SNARK proves membership
//! in a tree of *every* note ever created at constant cost. A ring
//! signature's cost grows linearly with ring size, so Monero picks a
//! handful of decoys per input. Each transaction says "one of these 16".
//!
//! Layout:
//!   `keys.rs`      view/spend keys, stealth one-time addresses, amount ECDH
//!   `pedersen.rs`  commitments C = γG + vH and the H generator
//!   `clsag.rs`     CLSAG linkable ring signature (hand-written, ~100 lines)
//!   `tx.rs`        transaction build / verify, chain state, key images
//!   `viz.rs`       stdout drawings of the output set, rings, key images, wallet balances
//!   `main.rs`      Alice pays Bob with 10 decoys; attacks

pub mod clsag;
pub mod keys;
pub mod pedersen;
pub mod tx;
pub mod viz;

pub use curve25519_dalek::ristretto::RistrettoPoint as Point;
pub use curve25519_dalek::scalar::Scalar;

/// Monero mainnet uses 16 since 2022 (11 before). We use 11.
pub const RING_SIZE: usize = 11;

/// Hash-to-scalar with a domain tag. Used everywhere a challenge or derived
/// scalar is needed.
pub fn hs(domain: &[u8], parts: &[&[u8]]) -> Scalar {
    use sha2::{Digest, Sha512};
    let mut h = Sha512::new();
    h.update(domain);
    for p in parts {
        h.update(p);
    }
    Scalar::from_hash(h)
}

/// Hash-to-point Hp(·). Needed for key images: I = x·Hp(P) must use a point
/// whose discrete log w.r.t. G is unknown, otherwise I would leak x.
pub fn hp(domain: &[u8], parts: &[&[u8]]) -> Point {
    use sha2::{Digest, Sha512};
    let mut h = Sha512::new();
    h.update(domain);
    for p in parts {
        h.update(p);
    }
    Point::from_hash(h)
}

pub fn pt(p: &Point) -> [u8; 32] {
    p.compress().to_bytes()
}
