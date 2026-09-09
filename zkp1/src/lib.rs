//! zkp1 — a zk-SNARK walkthrough in Rust.
//!
//! Two circuits, one proof system:
//!   * `cubic`  — the classic  x³ + x + 5 = 35, written as raw R1CS gates so
//!                you can see exactly what a "constraint" is.
//!   * `mimc`   — prove you know the preimage of a hash, written with
//!                arkworks gadgets, the way real circuits are written.
//!
//! `snark.rs` wraps Groth16's three functions: setup, prove, verify.
//! Run `cargo run --release` for a narrated demo.

pub mod cubic;
pub mod mimc;
pub mod snark;

/// The scalar field of BN254 — every wire in our circuits holds one of
/// these. It is a prime field with a ~254-bit modulus r. Arithmetic
/// "in the circuit" is arithmetic mod r, nothing more exotic.
pub type Fr = ark_bn254::Fr;
