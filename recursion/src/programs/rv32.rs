//! The RV32-machine verifier, as an rVM program.
//!
//! Phases 0–4 — the declared shape, the batch transcript's eight observe/sample steps, and the
//! cross-AIR lookup terminal sum. Phase 5 (the per-instance constraint evaluation at `zeta`) and
//! phases 6–8 (the FRI query phase, the acceptance and spec §4.4's public values) are the following
//! two tasks; nothing half-built is called from here, so the program this file produces today is a
//! complete, self-consistent program that happens to stop after `zeta`.
//!
//! **The transcript order is `verify_batch`'s, the *read* order is the tape's, and the two are not
//! the same thing.** `p3-batch-stark`'s transcript observes the main cap before the public values,
//! while the tape (`crate::witness::Segment`) carries the public values first and all four caps in
//! one run — because the four caps are consumed across three different phases and a segment table
//! with a run per cap would be a table of sixteen-word segments for no benefit. So the program reads
//! each segment once, in tape order, and observes what it has read in the transcript's order. Every
//! `HINT` below is therefore positioned by `crate::witness`, and every `observe`/`sample` by
//! `p3-batch-stark-0.7.0/src/verifier/mod.rs:459-606`.

use crate::dsl::transcript::DslChallenger;
use crate::dsl::{Builder, Checkpoints, Digest, DIGEST_ELEMS};
use crate::isa::EF;
use crate::shape::{InnerKey, InnerShape, PV_INSTANCE};
use p3_field::PrimeCharacteristicRing;

use super::VerifierProgram;

/// The cap size, in words: four digests of four elements (`cap_height = 2`).
const CAP_WORDS: usize = (1 << crate::shape::CAP_HEIGHT) * DIGEST_ELEMS;

/// Reads sixteen witness words into four `Digest`s: one `MerkleCap` of `cap_height = 2`.
///
/// Through [`Builder::hint_array`], so the sixteen words cost two rows each and create no handles —
/// a cap is hashed out of memory, never out of registers.
fn read_cap(b: &mut Builder) -> [Digest; 4] {
    let a = b.hint_array(CAP_WORDS);
    std::array::from_fn(|i| Digest(b.offset(a.base, (i * DIGEST_ELEMS) as i64)))
}

/// The same shape from compile-time constants: the inner preprocessed cap is a machine constant, so
/// the program carries it as sixteen immediates instead of reading it off the tape. Nothing a prover
/// supplies can move it.
fn constant_cap(b: &mut Builder, cap: &[[crate::isa::F; 4]; 4]) -> [Digest; 4] {
    let p = b.alloc(CAP_WORDS as u64);
    for (i, v) in cap.iter().flatten().enumerate() {
        let c = b.constant(*v);
        b.store(p, i as i64, c);
    }
    std::array::from_fn(|i| Digest(b.offset(p, (i * DIGEST_ELEMS) as i64)))
}

/// Builds the verifier program for one inner shape.
pub fn verify_rv32(shape: &InnerShape, key: &InnerKey, cp: Checkpoints) -> VerifierProgram {
    let n = shape.instances();
    let mut b = Builder::new(cp);

    // ── phase 0: the header. Read the proof's declared shape and pin it to this program's own, so
    // a proof of another shape is refused here instead of being read with the wrong field widths.
    for (k, want) in shape.header_words().iter().enumerate() {
        let got = b.hint();
        let w = b.constant(*want);
        b.assert_eq(got, w, &format!("header word {k}"));
    }

    // ── the tape's next four segments, read in tape order and observed below in transcript order.
    // `PublicValues`: instance 1 (the cpu table) owns all of them.
    let pvs = b.hint_array(shape.num_public_values[PV_INSTANCE]);
    // `Commitments`: main, permutation, quotient_chunks, random — `BatchCommitments`' field order,
    // which is also the order the transcript observes them in.
    let main_cap = read_cap(&mut b);
    let perm_cap = read_cap(&mut b);
    let q_cap = read_cap(&mut b);
    let r_cap = read_cap(&mut b);
    // `LookupTerminals`: one extension element per instance that declares lookups, in instance
    // order — `lookup_terminals.iter().flatten()`.
    let terminals: Vec<_> = (0..n)
        .filter(|&i| shape.num_lookups[i] > 0)
        .map(|_| b.hint_ext())
        .collect();

    // ── phase 1: the challenger, the instance count and the per-instance binding.
    let mut ch = DslChallenger::new(&mut b);
    ch.observe_usize(&mut b, n);
    for i in 0..n {
        let ext_db = shape.degree_bits[i];
        ch.observe_usize(&mut b, ext_db);
        // `base_db = ext_db - is_zk`, and `is_zk() == true` for this machine's config.
        ch.observe_usize(&mut b, ext_db - 1);
        ch.observe_usize(&mut b, shape.widths[i]);
        // The *committed* chunk count: `(1 << log_num_quotient_chunks) << is_zk`.
        ch.observe_usize(&mut b, (1 << shape.log_num_quotient_chunks[i]) << 1);
    }

    // ── phase 2: the main commitment, the public values, the preprocessed widths and cap.
    ch.observe_cap(&mut b, &main_cap);
    for k in 0..shape.num_public_values[PV_INSTANCE] {
        let v = b.get(pvs, k);
        ch.observe(&mut b, v);
    }
    for i in 0..n {
        ch.observe_usize(&mut b, shape.preprocessed_widths[i]);
    }
    let pre_cap = constant_cap(&mut b, &key.cap);
    ch.observe_cap(&mut b, &pre_cap);

    // ── phase 3: the lookup challenges, the permutation commitment, the terminals, alpha.
    // `sample_perm_challenges` draws exactly this pair; every bus offset it derives is arithmetic on
    // it, which is phase 5's job (`emit_lookup_challenges`).
    let lookup_alpha = ch.sample_ext(&mut b);
    b.checkpoint("lookup_alpha", lookup_alpha);
    let lookup_beta = ch.sample_ext(&mut b);
    b.checkpoint("lookup_beta", lookup_beta);
    ch.observe_cap(&mut b, &perm_cap);
    for t in &terminals {
        ch.observe_ext(&mut b, *t);
    }
    let alpha = ch.sample_ext(&mut b);
    b.checkpoint("alpha", alpha);

    // ── phase 4: the quotient and random commitments, then zeta.
    ch.observe_cap(&mut b, &q_cap);
    ch.observe_cap(&mut b, &r_cap);
    let zeta = ch.sample_ext(&mut b);
    b.checkpoint("zeta", zeta);

    // ── the cross-AIR terminal sum (`LogUpGadget::verify_terminal_sum`): the sum over instances must
    // be zero. Checked here because the terminals are already in hand; the native verifier checks it
    // last, and the order does not matter — nothing downstream reads the sum.
    let mut sum = b.ext_constant(EF::ZERO);
    for t in &terminals {
        sum = b.ext_add(sum, *t);
    }
    // Both coefficients under *one* name, rather than `assert_eq_ext`'s `"… (c0)"`/`"… (c1)"` pair:
    // either failing means the same thing — the batch's lookups do not balance — and the tamper
    // tests name the step, not the coefficient. (`DslChallenger::sample_bits`' two canonicality
    // assertions share a name for the same reason.)
    let (c0, c1) = b.ext_parts(sum);
    let zero = b.zero();
    b.assert_eq(c0, zero, "lookup terminal sum");
    b.assert_eq(c1, zero, "lookup terminal sum");

    // Phase 5 is Task 5 and phases 6–8 are Task 6. They append to this function; the values they
    // need are exactly the ones in scope here (`pvs`, `zeta`, `alpha`, the lookup pair, `terminals`,
    // and the four caps for the query phase's root comparisons), which is why they are bound to
    // names rather than consumed in place.
    let _ = (lookup_beta, main_cap, perm_cap, q_cap, r_cap);

    let stats = b.stats();
    let checkpoint_names = b.checkpoint_names().to_vec();
    VerifierProgram {
        program: b.finish(),
        shape: shape.clone(),
        key: key.clone(),
        checkpoints: cp,
        stats,
        checkpoint_names,
    }
}
