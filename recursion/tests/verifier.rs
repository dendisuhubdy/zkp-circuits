//! The verifier program, against a real `rand_zkvm` bundle proof.
//!
//! Every expectation here comes from the *same* Plonky3 code `Machine::verify` runs:
//! `reference::replay` is a host-side replay of the transcript built out of `p3-challenger`,
//! `p3_batch_stark::verifier::commitments_with_opening_points`, `p3_uni_stark`'s own
//! `recompose_quotient_from_chunks` and folder, and `p3_fri::verifier`'s `open_inputs`/`fold_query`
//! — not a second implementation of any of them. The program is then compared against that replay
//! value by value, so "the rVM reproduces the transcript" is a checked claim about bit-exactness
//! rather than about acceptance.
mod common;

use p3_field::PrimeCharacteristicRing;
use rand_zkvm::machine::{FriProfile, Machine};
use recursion::dsl::Checkpoints;
use recursion::emulator::{execute, ExecError};
use recursion::isa::F;
use recursion::programs::verify_rv32;
use recursion::reference::replay;
use recursion::shape::{InnerKey, InnerShape};
use recursion::witness::WitnessTape;

fn one_test_proof() -> (common::BundleProof, InnerShape, InnerKey) {
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let shape = InnerShape::of(
        FriProfile::Test,
        p.proof.tier,
        p.proof.program_log_height,
        p.proof.input_log_height,
        p.proof.keccak_log_height,
        p.proof.sha256_log_height,
        p.proof.mem_log_height,
    );
    let key = InnerKey::of(FriProfile::Test, &shape);
    (p, shape, key)
}

#[test]
fn the_witness_tape_layout_is_pinned() {
    let (p, shape, key) = one_test_proof();
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let names: Vec<_> = tape.segments.iter().map(|(s, _, _)| *s).collect();
    use recursion::witness::Segment::*;
    assert_eq!(
        names,
        vec![
            Header,
            PublicValues,
            Commitments,
            LookupTerminals,
            OpenedValues,
            RandomOpenings,
            FriCommits,
            FinalPoly,
            QueryPow,
            QueryBits,
            InputOpenings,
            InputPaths,
            CommitPhaseOpenings,
            CommitPhasePaths
        ]
    );
    // Segments tile the tape exactly, in order, with no gap and no overlap.
    let mut at = 0usize;
    for (_, start, len) in &tape.segments {
        assert_eq!(*start, at);
        at += len;
    }
    assert_eq!(at, tape.words.len());
    assert_eq!(at, tape.len());
    // The header is the proof's own declared shape, so a shape mismatch is visible immediately.
    assert_eq!(tape.words[0], F::from_usize(p.proof.tier.0));
    assert!(shape.matches(&p.proof));
    println!("{}", tape.describe());
}

#[test]
fn the_host_transcript_replay_reproduces_machine_verifys_acceptance() {
    let (p, shape, key) = one_test_proof();
    let m = Machine::new(FriProfile::Test);
    m.verify(&p.hc, &p.proof).expect("the fixture proof verifies natively");
    let r = replay(FriProfile::Test, &shape, &key, &p.proof).expect("the replay accepts it too");
    assert_eq!(r.indices.len(), shape.num_queries);
    assert_eq!(r.betas.len(), shape.log_arities.len());
    assert_eq!(
        r.log_global_max_height,
        shape.log_arities.iter().sum::<usize>() + 3 /* log_blowup */
    );
    // The replay is the transcript, so its zeta must also satisfy the quotient identity the
    // native verifier checked: accumulator * inv_vanishing == quotient, per instance.
    assert_eq!(r.accumulators.len(), r.quotients.len());
    for i in 0..r.quotients.len() {
        assert_eq!(
            r.accumulators[i] * r.selectors[i].inv_vanishing, r.quotients[i],
            "instance {i}'s quotient identity"
        );
    }
}

#[test]
fn the_program_reproduces_the_lookup_challenges_alpha_and_zeta() {
    let (p, shape, key) = one_test_proof();
    let r = replay(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let vp = verify_rv32(&shape, &key, Checkpoints::On);
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let exec = execute(&vp.program, &tape.words, 100_000_000).expect("the program accepts");
    let cp = recursion::programs::checkpoint_values(&vp, &exec);
    assert_eq!(cp["lookup_alpha"], r.lookup_alpha);
    assert_eq!(cp["lookup_beta"], r.lookup_beta);
    assert_eq!(cp["alpha"], r.alpha);
    assert_eq!(cp["zeta"], r.zeta);
    // Phases 0–4 consume exactly the first four segments and stop — which is the invariant that
    // makes the tape's segment boundaries real rather than decorative. Task 6's measurement asserts
    // the finished program consumes *all* of it; this is the same claim at this task's boundary.
    let consumed: usize = tape.segments[..4].iter().map(|(_, _, len)| len).sum();
    assert_eq!(exec.hints_read, consumed, "phases 0–4 read Header..LookupTerminals, no more");
}

/// The one assertion phases 0–4 make beyond the declared shape: `LogUpGadget::verify_terminal_sum`.
/// Without this test, deleting it goes unnoticed — the transcript tests only compare challenges.
#[test]
fn a_tampered_lookup_terminal_is_refused_at_the_terminal_sum_checkpoint() {
    let (p, shape, key) = one_test_proof();
    let vp = verify_rv32(&shape, &key, Checkpoints::Off);
    let mut tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let (_, start, len) = *tape
        .segments
        .iter()
        .find(|(s, _, _)| *s == recursion::witness::Segment::LookupTerminals)
        .unwrap();
    assert!(len > 0, "this machine's batch has lookups");
    for k in [0usize, 1, len - 1] {
        let mut t = tape.clone();
        t.words[start + k] += F::ONE;
        match execute(&vp.program, &t.words, 100_000_000) {
            Err(ExecError::InverseOfZero { pc }) => assert_eq!(
                vp.program.checkpoint_at(pc),
                Some("lookup terminal sum"),
                "terminal word {k}"
            ),
            other => panic!("terminal word {k}: expected a refusal, got {other:?}"),
        }
    }
    // And the untampered tape still runs, so the refusal is about the tamper.
    tape.words[start] += F::ZERO;
    execute(&vp.program, &tape.words, 100_000_000).expect("the honest tape is accepted");
}

/// `OpenedValues` and `RandomOpenings` are the two biggest segments phases 0–4 do not read, and
/// Tasks 5 and 6 will size their reads from the [`InnerShape`] alone. So the pin is exactly that:
/// the segment lengths derived from the shape, with no reference to the proof's own nesting — which
/// is what makes the amendment to the brief's table (the permutation openings belong in segment 5,
/// because `OpenedValuesWithLookups` has two fields beyond `OpenedValues` and the constraint check
/// needs both) a checked claim rather than a comment.
#[test]
fn the_opened_value_segments_are_sized_by_the_shape_alone() {
    let (p, shape, key) = one_test_proof();
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let seg = |s: recursion::witness::Segment| {
        tape.segments.iter().find(|(x, _, _)| *x == s).unwrap().2
    };
    let n = shape.instances();
    // Per instance: trace_local, trace_next?, preprocessed_local, preprocessed_next?, one chunk per
    // committed quotient chunk (each `Challenge::DIMENSION = 2` elements wide), random (2), and the
    // permutation openings at both points (`aux_width = num_lookups + 1`, 2 elements each).
    let mut opened = 0usize;
    let mut random = 0usize;
    for i in 0..n {
        let w = shape.widths[i];
        let pre = shape.preprocessed_widths[i];
        let chunks = (1usize << shape.log_num_quotient_chunks[i]) << 1;
        let aux = if shape.num_lookups[i] > 0 { shape.num_lookups[i] + 1 } else { 0 };
        opened += w
            + if shape.main_next[i] { w } else { 0 }
            + pre
            + if shape.pre_next[i] { pre } else { 0 }
            + chunks * 2
            + 2
            + 2 * aux * 2;
        // The hiding wrapper's four hidden values per opened point, for every round but the
        // preprocessed one: `random` (one point), `main` (one or two), each quotient chunk (one),
        // and `permutation` (two, only where there are lookups).
        random += 1 + (1 + shape.main_next[i] as usize) + chunks + if aux > 0 { 2 } else { 0 };
    }
    assert_eq!(seg(recursion::witness::Segment::OpenedValues), 2 * opened);
    assert_eq!(seg(recursion::witness::Segment::RandomOpenings), 2 * 4 * random);
}

/// `QueryBits` is 65 words per sampled element and nothing in phases 0–4 reads it, so without this
/// its bit order, its group order and its canonicality hint would go unchecked until Task 6 — and a
/// mistake in any of them is a tape the finished program cannot consume.
///
/// The claims are the ones the program's `sample_bits` makes: each group's sixty-four little-endian
/// bits are a decomposition of a canonical Goldilocks element, the hint is that element's low half
/// inverted, the low `log_global_max_height` bits are the query index the Merkle proofs were checked
/// against, and the PoW group comes first and grinds.
#[test]
fn the_query_bit_segment_decodes_to_the_sampled_query_indices() {
    let (p, shape, key) = one_test_proof();
    let r = replay(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let (_, start, len) = *tape
        .segments
        .iter()
        .find(|(s, _, _)| *s == recursion::witness::Segment::QueryBits)
        .unwrap();
    // One group per query, plus one for the query proof-of-work check (4 bits at this profile).
    assert_eq!(shape.query_pow_bits, 4);
    assert_eq!(len, 65 * (shape.num_queries + 1));

    let group = |g: usize| -> (u64, F) {
        let at = start + 65 * g;
        let mut v = 0u64;
        for k in (0..64).rev() {
            let bit = tape.words[at + k];
            assert!(bit == F::ZERO || bit == F::ONE, "group {g} bit {k} is not boolean");
            v = (v << 1) | (bit == F::ONE) as u64;
        }
        (v, tape.words[at + 64])
    };
    let canonical = |v: u64| {
        // `p = 2^64 - 2^32 + 1`: the elements with a second 64-bit decomposition are exactly those
        // with the high half all ones and a non-zero low half.
        !(v >> 32 == 0xFFFF_FFFF && v & 0xFFFF_FFFF != 0)
    };

    let (pow, hint) = group(0);
    assert!(canonical(pow));
    assert_eq!(hint, recursion::dsl::transcript::canonicality_hint(pow));
    assert_eq!(pow & ((1 << shape.query_pow_bits) - 1), 0, "the query PoW witness must grind");

    for q in 0..shape.num_queries {
        let (v, hint) = group(q + 1);
        assert!(canonical(v), "query {q}");
        assert_eq!(hint, recursion::dsl::transcript::canonicality_hint(v), "query {q}");
        let mask = (1u64 << r.log_global_max_height) - 1;
        assert_eq!(
            (v & mask) as usize, r.indices[q],
            "query {q}'s low bits are the index its Merkle proof was checked against"
        );
    }
}

/// The four query-major segments carry exactly the words the round geometry implies: per query, per
/// round, per matrix a full opened row plus four salts, and four words per Merkle level. Nothing in
/// phases 0–4 reads them either, and an off-by-one here is a tape Task 6's program walks off the end
/// of — so the lengths are pinned against the geometry the *replay* derived from `open_inputs`' own
/// rule.
#[test]
fn the_query_segments_are_sized_by_the_round_geometry() {
    let (p, shape, key) = one_test_proof();
    let r = replay(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let seg = |s: recursion::witness::Segment| {
        tape.segments.iter().find(|(x, _, _)| *x == s).unwrap().2
    };
    use recursion::witness::{levels_for, Segment};

    // `coms_to_verify`' five rounds: random, main, quotient_chunks, preprocessed, permutation.
    assert_eq!(r.input_rounds.len(), 5);
    let per_query_rows: usize =
        r.input_rounds.iter().flat_map(|g| g.dims.iter()).map(|d| d.width + 4).sum();
    let per_query_levels: usize = r.input_rounds.iter().map(|g| levels_for(&g.dims)).sum();
    assert_eq!(seg(Segment::InputOpenings), shape.num_queries * per_query_rows);
    assert_eq!(seg(Segment::InputPaths), shape.num_queries * per_query_levels * 4);

    // The commit phase: `arity − 1` extension siblings a round, and one path per round.
    // `arity − 1` extension siblings (two words each) plus the four salts of the query's own row.
    let siblings: usize = r.log_arities.iter().map(|&a| ((1usize << a) - 1) * 2 + 4).sum();
    assert_eq!(seg(Segment::CommitPhaseOpenings), shape.num_queries * siblings);
    let mut log_current = r.log_global_max_height;
    let mut commit_levels = 0usize;
    for &a in &r.log_arities {
        log_current -= a;
        commit_levels += log_current.saturating_sub(2); // cap_height = 2
    }
    assert_eq!(seg(Segment::CommitPhasePaths), shape.num_queries * commit_levels * 4);
}

/// The strongest claim about the tape this task can make: the `CommitPhaseOpenings` and
/// `CommitPhasePaths` words really are a *single-path-per-query* witness for the round's
/// commitment — hash the leaf the tape describes, walk the path the tape carries, and the digest
/// reached is the cap entry the proof committed to.
///
/// This is what the plan's ruling on `restore_and_recompute_paths` asserts and nothing else here
/// checks: the two size tests would pass just as happily with the rounds and the queries nested the
/// other way round, or with the salts in the wrong place. The commit phase is the case to do it on
/// because each round commits exactly *one* matrix, so there are no shorter-height groups to inject
/// and the walk is `merkle_walk`'s plain form.
///
/// The gadgets are `crate::dsl::hash`'s, already differential against `p3-symmetric` and
/// `p3-merkle-tree` in `tests/transcript.rs`; what is under test is the tape's layout.
#[test]
fn a_commit_phase_leaf_and_its_restored_path_recompute_the_rounds_commitment() {
    use p3_field::BasedVectorSpace;
    use recursion::dsl::{hash, Builder, Digest, Felt};
    use recursion::isa::EF;

    let (p, shape, key) = one_test_proof();
    let r = replay(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let at = |s: recursion::witness::Segment| {
        tape.segments.iter().find(|(x, _, _)| *x == s).unwrap().1
    };
    let opens = at(recursion::witness::Segment::CommitPhaseOpenings);
    let paths = at(recursion::witness::Segment::CommitPhasePaths);
    let fri = &p.proof.batch.opening_proof.1;

    // Round 0: the tallest commit-phase tree, and the first round of every query's stride.
    let log_arity = r.log_arities[0];
    let arity = 1usize << log_arity;
    let levels = (r.log_global_max_height - log_arity) - 2 /* cap_height */;
    let open_stride: usize = r.log_arities.iter().map(|&a| ((1usize << a) - 1) * 2 + 4).sum();
    let mut path_stride = 0usize;
    let mut h = r.log_global_max_height;
    for &a in &r.log_arities {
        h -= a;
        path_stride += h.saturating_sub(2) * 4;
    }

    let mut b = Builder::new(Checkpoints::Off);
    let mut want: Vec<F> = Vec::new();
    for q in 0..shape.num_queries {
        // The leaf: `ExtensionMmcs` flattens the arity-wide row to base, then the hiding MMCS
        // appends the four salts the tape carries right after this round's siblings.
        let row: Vec<EF> = r.commit_rows[0][q][0].clone();
        assert_eq!(row.len(), arity);
        let mut msg: Vec<F> = <EF as BasedVectorSpace<F>>::flatten_to_base(row);
        let salt_at = opens + q * open_stride + (arity - 1) * 2;
        msg.extend_from_slice(&tape.words[salt_at..salt_at + 4]);

        let src = b.alloc(msg.len() as u64);
        for (i, v) in msg.iter().enumerate() {
            let c = b.constant(*v);
            b.store(src, i as i64, c);
        }
        let leaf = Digest(b.alloc(4));
        hash::sponge(&mut b, src, msg.len(), leaf);

        let sib_at = paths + q * path_stride;
        let sibs = b.alloc(4 * levels as u64);
        for i in 0..4 * levels {
            let c = b.constant(tape.words[sib_at + i]);
            b.store(sibs, i as i64, c);
        }
        let index = r.commit_group_indices[0][q];
        let bits: Vec<Felt> = (0..levels)
            .map(|k| b.constant(F::from_u64(((index >> k) & 1) as u64)))
            .collect();
        let root = Digest(b.alloc(4));
        hash::merkle_walk(&mut b, leaf, &bits, sibs, levels, root);
        for i in 0..4 {
            let v = b.load(root.0, i);
            b.public(v);
        }
        want.extend_from_slice(&fri.commit_phase_commits[0].roots()[index >> levels]);
    }
    let exec = execute(&b.finish(), &[], 100_000_000).expect("the walk runs");
    assert_eq!(exec.public, want, "round 0's restored paths must reach its committed cap");
}

/// The same claim for an *input* round, which is where it is hardest: an input round commits
/// matrices of several heights, so the walk carries a shorter-height group injected partway up
/// (`p3-merkle-tree-0.7.0/src/mmcs/batch.rs:240-262`).
///
/// The preprocessed round is the one to do it on: three matrices, two heights, exactly one
/// injection — and its commitment is the [`InnerKey`] the program carries as a constant, so this
/// also checks that the key really is the cap the proof was built against.
#[test]
fn an_input_rounds_leaf_group_and_restored_path_recompute_the_preprocessed_cap() {
    use recursion::dsl::{hash, Builder, Digest, Felt};
    use recursion::witness::levels_for;

    let (p, shape, key) = one_test_proof();
    let r = replay(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let opens = tape
        .segments
        .iter()
        .find(|(s, _, _)| *s == recursion::witness::Segment::InputOpenings)
        .unwrap()
        .1;
    let paths = tape
        .segments
        .iter()
        .find(|(s, _, _)| *s == recursion::witness::Segment::InputPaths)
        .unwrap()
        .1;

    // `coms_to_verify`' round order: random, main, quotient_chunks, preprocessed, permutation.
    const PRE: usize = 3;
    let dims = &r.input_rounds[PRE].dims;
    assert_eq!(dims.len(), shape.preprocessed_matrix_to_instance.len());
    let levels = levels_for(dims);

    // Group the matrices the way the leaf hash does: tallest first, everything whose padded height
    // equals the tallest's in the leaf, the rest injected at the level the walk reaches their height
    // at. `sorted_by_key(Reverse(height))` is stable, so matrices of equal height keep dims order —
    // which is the order their rows sit in on the tape.
    let tallest = dims.iter().map(|d| d.height).max().unwrap();
    let words_of = |m: usize| dims[m].width + 4; // the row and its four salts
    let offset_in_round = |m: usize| (0..m).map(words_of).sum::<usize>();
    let leaf_group: Vec<usize> = (0..dims.len()).filter(|&m| dims[m].height == tallest).collect();
    let short: Vec<usize> = (0..dims.len()).filter(|&m| dims[m].height != tallest).collect();
    assert_eq!(leaf_group.len(), 1, "the preprocessed round's tallest matrix is the poseidon2 table");
    assert_eq!(short.len(), 2, "range and nibble share the shorter height");
    let short_height = dims[short[0]].height;
    assert!(short.iter().all(|&m| dims[m].height == short_height));
    // `curr` is the layer width; after level `k` it is `tallest >> (k + 1)`.
    let after_level = (tallest.trailing_zeros() - short_height.trailing_zeros() - 1) as usize;
    // The two short matrices are adjacent in dims order, so their rows are one contiguous run.
    assert_eq!(short, vec![0, 1]);
    let short_cells: usize = short.iter().map(|&m| words_of(m)).sum();

    let per_query_rows: usize =
        r.input_rounds.iter().flat_map(|g| g.dims.iter()).map(|d| d.width + 4).sum();
    let round_at = |q: usize| {
        opens
            + q * per_query_rows
            + r.input_rounds[..PRE].iter().flat_map(|g| g.dims.iter()).map(|d| d.width + 4).sum::<usize>()
    };
    let per_query_levels: usize = r.input_rounds.iter().map(|g| levels_for(&g.dims)).sum();
    let path_at = |q: usize| {
        paths
            + q * per_query_levels * 4
            + r.input_rounds[..PRE].iter().map(|g| levels_for(&g.dims)).sum::<usize>() * 4
    };

    let mut b = Builder::new(Checkpoints::Off);
    let mut want: Vec<F> = Vec::new();
    for q in 0..shape.num_queries {
        let base = round_at(q);
        let tall = base + offset_in_round(leaf_group[0]);
        let leaf_words = words_of(leaf_group[0]);
        let src = b.alloc(leaf_words as u64);
        for i in 0..leaf_words {
            let c = b.constant(tape.words[tall + i]);
            b.store(src, i as i64, c);
        }
        let leaf = Digest(b.alloc(4));
        hash::sponge(&mut b, src, leaf_words, leaf);

        let rows = b.alloc(short_cells as u64);
        for i in 0..short_cells {
            let c = b.constant(tape.words[base + i]);
            b.store(rows, i as i64, c);
        }
        let sibs = b.alloc(4 * levels as u64);
        for i in 0..4 * levels {
            let c = b.constant(tape.words[path_at(q) + i]);
            b.store(sibs, i as i64, c);
        }
        let index = r.input_rounds[PRE].indices[q];
        let bits: Vec<Felt> = (0..levels)
            .map(|k| b.constant(F::from_u64(((index >> k) & 1) as u64)))
            .collect();
        let root = Digest(b.alloc(4));
        hash::merkle_walk_with_injections(
            &mut b,
            leaf,
            &bits,
            sibs,
            levels,
            &[hash::Injection { after_level, rows, n_cells: short_cells }],
            root,
        );
        for i in 0..4 {
            let v = b.load(root.0, i);
            b.public(v);
        }
        want.extend_from_slice(&key.cap[index >> levels]);
    }
    let exec = execute(&b.finish(), &[], 100_000_000).expect("the walk runs");
    assert_eq!(exec.public, want, "the preprocessed round's paths must reach the key's cap");
}

/// A proof of a *different* shape is refused at the header word that differs, before anything is
/// sized from it. Every word of the header is pinned, so the test walks all of them.
#[test]
fn a_header_word_that_disagrees_with_the_programs_shape_is_refused_at_that_word() {
    let (p, shape, key) = one_test_proof();
    let vp = verify_rv32(&shape, &key, Checkpoints::Off);
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let (_, start, len) = *tape.segments.iter().find(|(s, _, _)| *s == recursion::witness::Segment::Header).unwrap();
    assert_eq!(len, shape.header_words().len());
    for k in 0..len {
        let mut t = tape.clone();
        t.words[start + k] += F::ONE;
        match execute(&vp.program, &t.words, 100_000_000) {
            Err(ExecError::InverseOfZero { pc }) => assert_eq!(
                vp.program.checkpoint_at(pc),
                Some(format!("header word {k}").as_str()),
                "header word {k}"
            ),
            other => panic!("header word {k}: expected a refusal, got {other:?}"),
        }
    }
}

#[test]
fn a_tampered_main_commitment_diverges_at_the_zeta_checkpoint() {
    let (p, shape, key) = one_test_proof();
    let vp = verify_rv32(&shape, &key, Checkpoints::On);
    let mut tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let (_, start, _) = *tape
        .segments
        .iter()
        .find(|(s, _, _)| *s == recursion::witness::Segment::Commitments)
        .unwrap();
    tape.words[start] += F::ONE; // one lane of the main cap
    let r = replay(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let exec = execute(&vp.program, &tape.words, 100_000_000);
    match exec {
        Ok(e) => {
            // The transcript is bound: a tampered commitment must move every challenge drawn
            // after it, `zeta` included.
            let cp = recursion::programs::checkpoint_values(&vp, &e);
            assert_ne!(cp["zeta"], r.zeta, "a tampered commitment must move zeta");
            assert_ne!(cp["alpha"], r.alpha);
            assert_ne!(cp["lookup_alpha"], r.lookup_alpha);
            // It must also *fail an assertion* — but nothing this task builds depends on zeta
            // yet: phases 0–4 assert only the declared shape and the cross-AIR terminal sum,
            // neither of which a commitment word touches. The refusal is asserted where the
            // step that does the work lives, in Task 6's `tests/exit.rs` tamper table
            // (`Segment::Commitments` -> `"input opening root[main]"`).
        }
        Err(ExecError::InverseOfZero { pc }) => {
            let name = vp.program.checkpoint_at(pc).expect("every trap is named");
            println!("refused at {name}");
        }
        Err(other) => panic!("unexpected failure {other:?}"),
    }
}

