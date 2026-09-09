//! zkp2 — the **SNARK** half of a matched pair. `../zkp3` proves the *same*
//! statement with a **STARK**. Read them side by side.
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
//! ## SNARK vs STARK in one table
//!
//! |                       | SNARK (this crate: Groth16)    | STARK (zkp3: winterfell)          |
//! |-----------------------|--------------------------------|-----------------------------------|
//! | arithmetization       | R1CS circuit (A·B = C gates)   | AIR: execution trace + transition |
//! | setup                 | trusted, per-circuit (toxic τ) | none — "transparent"              |
//! | commitment            | elliptic-curve points, pairings| Merkle trees of hashes + FRI      |
//! | crypto assumption     | discrete log / knowledge-of-exp| collision-resistant hash only     |
//! | post-quantum          | no                             | yes                               |
//! | field                 | ~254-bit (curve scalar field)  | 64/128-bit, chosen for FFT speed  |
//! | proof size            | 128 bytes, constant            | tens of KB, grows ~log²(N)        |
//! | verify cost           | 3 pairings, constant           | O(log²N) hashes + field ops       |
//! | prover cost           | O(N log N) *curve* ops (slow)  | O(N log N) *field* ops (fast)     |
//! | zero-knowledge        | built in (blinded A, C)        | optional add-on (trace masking)   |
//!
//! The letters spell it out: S-N-ARK = Succinct Non-interactive ARgument of
//! Knowledge. S-T-ARK = Scalable Transparent ARgument of Knowledge.
//! "Transparent" is the headline difference: no trusted setup.

pub mod chain;
pub mod snark;

pub type Fr = ark_bn254::Fr;

/// Number of x ← x³ + K iterations. Shared with zkp3, whose execution trace
/// must have a power-of-two number of rows: 64 rows ⇒ 63 transitions. The
/// SNARK has no such restriction (any N works), but we match so both crates
/// prove the identical statement.
pub const N_STEPS: usize = 63;
/// The additive constant K.
pub const K: u64 = 42;
