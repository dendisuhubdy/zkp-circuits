//! zkp3 — the **STARK** half of a matched pair. `../zkp2` proves the *same*
//! statement with a **SNARK** (Groth16). Read them side by side.
//!
//! ┌──────────────────────────────────────────────────────────────────────────┐
//! │ THE STATEMENT (identical in zkp2 and zkp3)                               │
//! │                                                                          │
//! │   "I know a secret x₀ such that running                                  │
//! │        x ← x³ + K                                                        │
//! │    for N steps ends at the public value  y."                             │
//! │                                                                          │
//! │   private:  x₀            public:  y      fixed:  N = 63, K = 42         │
//! └──────────────────────────────────────────────────────────────────────────┘
//!
//! ## What is different on this side
//!
//! * **No setup.** Nothing in this crate has to be generated before proving,
//!   and nothing has to be kept secret. The verifier only needs the AIR code
//!   in `air.rs` and the proof. "Transparent."
//!
//! * **Hashes, not curves.** The prover commits to polynomials by Merkle-
//!   hashing their evaluations (Blake3 here). Soundness rests only on the
//!   hash being collision-resistant — no discrete log, no pairings, so no
//!   known quantum attack. This is why STARKs are called post-quantum.
//!
//! * **Trace, not circuit.** The computation is described as an execution
//!   trace (a table: one row per step) plus *transition constraints* that
//!   every adjacent pair of rows must satisfy. The step is written once;
//!   N only sets the table height. See `air.rs`.
//!
//! * **Small field.** We compute in a 128-bit prime field (winterfell's
//!   f128) instead of BN254's 254-bit scalar field. STARK fields are chosen
//!   for fast FFTs, not for a curve, so they can be small. Consequence: the
//!   numeric value of y differs from zkp2's y. Same computation, different
//!   modulus.
//!
//! * **Bigger proof, more verifier work.** The verifier checks FRI
//!   (Fast Reed-Solomon IOP of proximity): it opens ~30–50 random Merkle
//!   paths through log₂(N·blowup) rounds. Proof ≈ tens of KB; verify
//!   ≈ milliseconds; both grow poly-logarithmically in N, not constant.
//!
//! * **Zero-knowledge is NOT automatic.** winterfell 0.13 produces a
//!   succinct, transparent argument of knowledge but does not mask the
//!   trace, so it is a "STARK" without the "Z" — exactly how StarkNet and
//!   Miden use it. Adding ZK means appending random rows to the trace and
//!   blinding the low-degree extension; some libraries (e.g. Stone, RISC
//!   Zero) do this. Groth16 in zkp2 gets ZK for free from its blinding
//!   scalars r, s.

pub mod air;
pub mod stark;

pub use winterfell::math::fields::f128::BaseElement as Felt;

/// Rows in the execution trace. winterfell needs a power of two ≥ 8 (FFTs).
pub const TRACE_LEN: usize = 64;
/// Number of x ← x³ + K transitions. A trace of R rows has R−1 transitions,
/// so this is 63. zkp2 uses the same constant so both crates prove the
/// identical statement. (Off-by-one here is the classic STARK bug: the
/// verifier silently rejects because the public y does not match the trace.)
pub const N_STEPS: usize = TRACE_LEN - 1;
/// The additive constant K.
pub const K: u64 = 42;
