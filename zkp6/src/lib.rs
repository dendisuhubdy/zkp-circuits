//! zkp6 — **Tornado Cash**, simulated end to end.
//!
//! Tornado Cash is a *mixer*: you deposit a fixed amount (say 1 ETH) into a
//! smart contract along with a commitment, and later *anyone* holding the
//! secret behind that commitment can withdraw 1 ETH to a fresh address. The
//! contract cannot tell which deposit a withdrawal corresponds to — that link
//! is exactly what the zero-knowledge proof hides.
//!
//! ```text
//!   DEPOSIT                                    WITHDRAW
//!   -------                                    --------
//!   pick nullifier ν, secret s (random)        prove in ZK:
//!   commitment C = H(ν, s)                       • I know (ν, s) with H(ν, s) = C
//!   send 1 ETH + C  → contract                   • C is a leaf of the Merkle tree
//!   contract inserts C into Merkle tree            with the public root R
//!                                                • nullifierHash = H(ν)        (public)
//!                                                • recipient address            (public, bound)
//!                                              contract checks:
//!                                                proof valid, R is a known root,
//!                                                nullifierHash unseen → pay recipient 1 ETH,
//!                                                record nullifierHash
//! ```
//!
//! Why each piece exists:
//!
//! * **Commitment C = H(ν, s)** hides ν and s on deposit. The tree holds only
//!   commitments, so the chain sees no secrets.
//! * **Merkle membership** lets the withdrawer prove "my C is *somewhere* in
//!   the tree" without saying where. The proof is the same size whether the
//!   tree has 2 leaves or 2²⁰ — that's why a SNARK is used, not a plain
//!   Merkle path (which would reveal the leaf index and so the deposit).
//! * **Nullifier hash H(ν)** prevents double-withdrawal. It is deterministic
//!   per note, so a second withdrawal shows the same value and is refused —
//!   yet it cannot be linked back to C because H(ν) ≠ H(ν, s) and ν is
//!   secret.
//! * **Recipient in the circuit** stops front-running: a relayer who sees the
//!   proof in the mempool cannot swap in their own address, because the proof
//!   is bound to the original recipient.
//!
//! Layout:
//!   `hash.rs`    MiMC-based hash, native + in-circuit gadget
//!   `merkle.rs`  full binary Merkle tree (native) + path-verification gadget
//!   `circuit.rs` the withdraw circuit
//!   `mixer.rs`   the simulated contract: balances, tree, roots, nullifiers
//!   `cli.rs`     the wallet: deposit prints a note; withdraw takes only a note
//!   `main.rs`    Alice / Bob / Carol scenario

pub mod circuit;
pub mod cli;
pub mod hash;
pub mod merkle;
pub mod mixer;

pub type Fr = ark_bn254::Fr;

/// Tree depth. Tornado uses 20 (≈1M deposits). 8 keeps setup fast and the
/// constraint count readable; nothing else changes.
pub const TREE_DEPTH: usize = 8;

/// Turn a human-readable name ("alice") into a field element usable as an
/// "address" inside the circuit.
pub fn addr(name: &str) -> Fr {
    use ark_ff::PrimeField;
    Fr::from_le_bytes_mod_order(name.as_bytes())
}
