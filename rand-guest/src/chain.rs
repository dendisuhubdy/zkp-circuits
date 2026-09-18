//! What the chain calls a program, as distinct from what the circuit calls it.
//!
//! Two identities, not one: `hc` (`Program::digest`) is the zkVM's in-circuit Poseidon2 digest the
//! verifier checks a proof against; the **program id** is the chain's content address, the key a
//! deployed program is stored and called under. They are computed over the same `(base_pc, words)`
//! with different hashes, so neither can be derived from the other.

/// fullnode's `randprotocol_core::program::program_id`, byte for byte:
/// `blake3("rand-program" ‖ base_pc as u32 LE ‖ each word as u32 LE)` — `Hash::digest_domain` feeds
/// the domain and then the data into one hasher, so the domain is a plain prefix, not a key or a
/// derive-key context. `base_pc` and `words` are the loader's `Program` (the text plus the data
/// prologue for an image container), which is what a deploy carries.
pub fn program_id(base_pc: u32, words: &[u32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"rand-program");
    h.update(&base_pc.to_le_bytes());
    for w in words {
        h.update(&w.to_le_bytes());
    }
    *h.finalize().as_bytes()
}
