//! HCS-1 (the 2026-09-27 zkVM review), the rVM's half: a known-answer test on the verifier key.
//!
//! The rVM's key is program-dependent (the program table is preprocessed) and, like the RV32
//! machine's, its preprocessed commitment is salted from a deterministic stream
//! (`machine::key_config`) that every aggregate verifier must agree on, exactly as
//! `research/tests/verifier_key.rs` explains for the RV32 keys. Through constraint set 6 that was
//! `StdRng::seed_from_u64(KEY_SEED)`; since constraint set 7 it is `key_derivation_v2`'s stream
//! under the rVM's own labels, so no `rand` release can move it. What it pins is the sixteen-element Merkle cap itself (the value `InnerKey`/`RvmKey`
//! absorb), in canonical form, for a two-instruction program at tier 8, with and without the reduce
//! chip declared (two caps: `WANT`, `WANT_REDUCE`) — the cap is the part the salt stream decides, and a changed stream, salt draw or
//! preprocessed table changes it. **A red here is a consensus event for any chain with an
//! aggregation section** (none is live): re-pinning it means new aggregate verifier keys.

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use recursion::isa::{Instr, Op, Program};
use recursion::machine::{FriProfile, Machine, Tier};

use recursion::isa::F;

fn cap_hex(m: &Machine, p: &Program, reduce: bool) -> Vec<String> {
    let common = m.verifier_key(p, Tier(8), if reduce { 4 } else { 0 });
    let pre = common.preprocessed.as_ref().expect("the program and range tables are preprocessed");
    pre.commitment.roots().iter().flatten().map(|x| format!("{:016x}", x.as_canonical_u64())).collect()
}

/// The cap, in `roots()` order: four digests of four elements.
///
/// Cut D: declaring the reduce chip adds its preprocessed region (an empty layout: all-zero rows),
/// so the cap differs; both caps are pinned.
///
/// Re-pinned for constraint set 7 (HCS-1): the rVM's key config draws its salts from
/// `key_derivation_v2`'s stream under the labels `rvm/key/mmcs` / `rvm/key/pcs`
/// (`machine::KEY_MMCS_LABEL`) instead of `StdRng::seed_from_u64(KEY_SEED)`. The constraint-set-6
/// cap began `730a4ee1a0135cf8, 17b7e54ab9062ce6, …`.
const WANT: [&str; 16] = [
    "dd11c3f0972cfe5b", "c8cc668625c3cda5", "9e695f7c48876311", "782b0b7c2742bd8e",
    "b104c3e9e14280b7", "e040e7a21ed9b82b", "0a684ae7b7fea111", "3662a86ee43d59df",
    "5187eb9262fe7545", "75812053c8016414", "9ea79ab7026af43e", "55e479637883af85",
    "c6c360a80fcc32a3", "7aaca7245e6a835a", "259781276e93c195", "fbde180612a69b9c",
];

/// The cap with the reduce chip declared at height 2^4 over an empty layout (Cut D).
const WANT_REDUCE: [&str; 16] = [
    "1136b74d8a91c107", "6258d923b5ea625f", "173ec4fd5207f709", "06778b2457b28d8a",
    "21343da5240c9ac1", "a937ceb108825c66", "c4dce8f6b47785d9", "73d287b349af9df4",
    "1be802bd479d578b", "4684eed2bfc90ca0", "e4336bb4cff37548", "a86e894c75054b0b",
    "d100180542ecc455", "1dfe8e0aa5b002e9", "f4adcfaf2ed4d621", "f212c834ec31eb56",
];

#[test]
fn the_rvm_verifier_keys_answer_their_known_caps() {
    let p = Program {
        instrs: vec![
            Instr { op: Op::Faddi, rd: 1, ra: 0, b: F::from_u64(7) },
            Instr { op: Op::Halt, rd: 0, ra: 0, b: F::ZERO },
        ],
        checkpoints: vec![],
        reduce_layout: vec![],
    };
    // Both profiles: the profile changes FRI's query count and grinding, never the preprocessed
    // commitment, so one pin serves both (measured, as in `research/tests/verifier_key.rs`).
    for profile in [FriProfile::Test, FriProfile::Production] {
        let m = Machine::new(profile);
        let (plain, reduce) = (cap_hex(&m, &p, false), cap_hex(&m, &p, true));
        eprintln!("{profile:?} no reduce: {plain:?}");
        eprintln!("{profile:?} reduce:    {reduce:?}");
        assert_eq!(plain, WANT, "{profile:?}: the rVM verifier key changed (no reduce chip)");
        assert_eq!(reduce, WANT_REDUCE, "{profile:?}: the rVM verifier key changed (reduce chip declared)");
    }
}
