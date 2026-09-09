//! zkp4 — **Zcash**-style shielded pool, simulated end to end.
//!
//! Compare with `../zkp6` (Tornado Cash). Tornado hides *which* deposit a
//! withdrawal spends, but every note is worth exactly one denomination and
//! money only moves in and out of the pool. Zcash notes carry **arbitrary
//! values**, can be **spent to other shielded notes** without ever leaving
//! the pool, and are owned by a **key** rather than by whoever holds a
//! secret string. Each of those three upgrades costs circuit constraints.
//!
//! ```text
//!   NOTE           n = (value v, owner pk, ρ, r)          ρ: unique per note, r: randomness
//!   COMMITMENT     cm = H( H(v, pk), H(ρ, r) )            published on chain
//!   OWNER KEY      pk = H(sk)                              sk never leaves the wallet
//!   NULLIFIER      nf = H(sk, ρ)                           published when n is spent
//!
//!   SHIELDED TRANSFER  (1 input note → 2 output notes, optional public withdrawal v_pub)
//!
//!   public:   root, nf, cm_out1, cm_out2, v_pub
//!   private:  sk, input note (v, ρ, r, Merkle path), output notes (v1, pk1, ρ1, r1), (v2, pk2, ρ2, r2)
//!   proves:   cm(input) ∈ tree(root)              (membership, as in Tornado)
//!             pk(input) = H(sk)                    (ownership — Tornado has no such thing)
//!             nf = H(sk, ρ)                        (nullifier bound to sk, not to a shared secret)
//!             cm_out1, cm_out2 well-formed          (outputs are real commitments)
//!             v = v1 + v2 + v_pub                   (no inflation — Tornado has no values at all)
//!             v1, v2 < 2^64                         (no wrap-around: field arithmetic is mod r!)
//! ```
//!
//! What the chain sees for a shielded transfer: one nullifier, two
//! commitments, v_pub (0 for a fully shielded transfer). No values, no
//! addresses, no link between the spent note and the new ones.
//!
//! Real Zcash (Sapling/Orchard) differs in engineering, not in shape:
//! Pedersen/Sinsemilla commitments instead of MiMC, value commitments with
//! a homomorphic balance check outside the circuit so inputs and outputs
//! can be proven separately, a full key hierarchy (ask, nsk, ovk, ivk…), and
//! encrypted note ciphertexts so the recipient can find their notes. The
//! last one we simulate by handing the note over "off-chain".
//!
//! Layout:
//!   `hash.rs`, `merkle.rs`  identical to zkp6
//!   `note.rs`               keys, notes, commitments, nullifiers (native)
//!   `circuit.rs`            the transfer circuit
//!   `ledger.rs`             simulated chain: transparent balances + shielded pool
//!   `viz.rs`                stdout drawings of the commitment tree and balances
//!   `main.rs`               Alice shields, pays Bob, Bob unshields; attacks

pub mod circuit;
pub mod hash;
pub mod ledger;
pub mod merkle;
pub mod note;
pub mod viz;

pub type Fr = ark_bn254::Fr;
pub const TREE_DEPTH: usize = 8;
/// Values are u64 zatoshi-style integers; the circuit range-checks to this.
pub const VALUE_BITS: usize = 64;
