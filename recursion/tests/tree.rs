//! Tree aggregation (spec §3, §6): `rv32t` verifies two child rVM proofs of one compile-time
//! shape and publishes `[vk_c ‖ 2 ‖ B ‖ D_1 ‖ D_2]`, with `vk_c` computed in-program over the
//! hinted cap. Task 1a runs the program by emulation over real test-profile leaves (`rv32n` over
//! L = 1 bundle proof each, proved here and cached). Task 1b proves a depth-2 tree, and Task 2
//! verifies it through `verify_tree`.
mod common;

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use rand_zkvm::machine::{FriProfile, Proof as BundleProof};
use recursion::aggregate::{aggregate, aggregate_program, InnerVerifierKey};
use recursion::dsl::Checkpoints;
use recursion::emulator::{execute, ExecError, Execution};
use recursion::isa::{Op, Program, F};
use recursion::machine::{Machine, Proof, Tier};
use recursion::programs::{rv32t_int, rv32t_leaf, tree_step_program_digest, verify_rv32r, verify_rv32t};
use recursion::public_values::{public_digest, tree_step_words};
use recursion::shape::{inner_vk_digest, InnerKey, InnerShape, RvmKey, RvmShape};
use recursion::witness::{Segment, TapeError, WitnessTape, TREE_TAPE_PREAMBLE};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

const MAX_CYCLES: usize = 1 << 24;
const P: FriProfile = FriProfile::Test;
const B: &[u32; 8] = &common::TEST_BINDING;

/// Set only by the ignored generator (Task 1b): an in-suite run never starts a tier-19 proof
/// on a box that cannot hold it (R7). Leaves are exempt: tier 18, 15.64 GB live at rate ¼ (docs/07 §4).
static ALLOW_STEP_PROVING: AtomicBool = AtomicBool::new(false);

fn tree_file(name: &str) -> std::path::PathBuf {
    common::cache_dir().join("tree").join(format!("{name}.rvmproof"))
}

/// The cached proof `name` if it decodes and verifies at `n`, else `prove()`'s, verified and
/// stored: the bundle-fixture cache's discipline (`common::load_cached`), one level up.
fn load_or_prove(name: &str, program: &Program, n: u64, may_prove: bool, prove: impl FnOnce() -> Proof) -> Proof {
    let m = Machine::new(P);
    if let Some(p) = std::fs::read(tree_file(name)).ok().and_then(|b| postcard::from_bytes::<Proof>(&b).ok()) {
        if m.verify_n(program, &p, n).is_ok() {
            return p;
        }
    }
    assert!(may_prove, "{} is missing or stale: run `cargo test --release --test tree generate_test_tree_fixtures \
        -- --ignored --nocapture` on a host with the docs/08 §5 memory and copy tree/ into $RECURSION_FIXTURES", tree_file(name).display());
    let p = prove();
    m.verify_n(program, &p, n).expect("a freshly proved tree proof verifies");
    let path = tree_file(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, p.to_bytes()).unwrap();
    p
}

/// Four test-profile leaves, `rv32n` over bundle fixture k = 0..3 each (L = 1; 169 640 rows,
/// tier 18 — `tests/pins.json`'s `aggregate_test_n1_cpu_rows`).
struct Leaves {
    inner: InnerVerifierKey,
    program: Arc<Program>,
    shape: RvmShape,
    key: RvmKey,
    bundles: Vec<BundleProof>,
    proofs: Vec<Proof>,
}

fn leaves() -> &'static Leaves {
    static L: OnceLock<Leaves> = OnceLock::new();
    L.get_or_init(|| {
        let bundles: Vec<BundleProof> = common::bundle_proofs(P, 4).into_iter().map(|b| b.proof).collect();
        let p = &bundles[0];
        let shape = InnerShape::of(P, p.tier, p.program_log_height, p.input_log_height, p.keccak_log_height,
            p.sha256_log_height, p.public_log_height, p.mem_log_height);
        let key = InnerKey::of(P, &shape);
        let inner = InnerVerifierKey { shape, key };
        let program = Arc::new(aggregate_program(&inner));
        let proofs: Vec<Proof> = (0..4)
            .map(|k| {
                load_or_prove(&format!("Test-leaf-{k}"), &program, 1, true, || {
                    aggregate(&Machine::new(P), &inner, std::slice::from_ref(&bundles[k]), B, None)
                        .expect("a test leaf proves")
                        .proof
                })
            })
            .collect();
        let shape = RvmShape::of_proof(P, &program, &proofs[0]);
        assert!(proofs.iter().all(|p| shape.matches(p)), "the four leaves declare one shape (a fixed workload)");
        let key = RvmKey::of(P, &shape);
        Leaves { inner, program, shape, key, bundles, proofs }
    })
}

/// A proof's four public values, the interface digest it publishes.
fn d(p: &Proof) -> [F; 4] {
    std::array::from_fn(|k| F::from_u64(p.public_values[k]))
}

/// The host's step digest over `(a, b)` in that order, as the emulator's public words.
fn host_step(vk: &[F; 4], binding: &[u32; 8], a: &Proof, b: &Proof) -> Vec<F> {
    public_digest(&tree_step_words(vk, binding, &d(a), &d(b))).to_vec()
}

fn emulate_step(child: &RvmShape, program: &Program, a: &Proof, b: &Proof, binding: &[u32; 8]) -> Result<Execution, ExecError> {
    let tape = WitnessTape::build_tree_step(P, child, [a, b], binding).expect("children of the shape build a tape");
    execute(program, &tape.words, MAX_CYCLES)
}

/// The leaf program with one unreachable `HALT` appended (R5's foreign program): the same
/// execution, so the same declared heights and shape words; another digest, so another cap.
fn foreign_leaf_program(p: &Program) -> Program {
    let mut q = p.clone();
    let halt = q.instrs.last().cloned().expect("a program ends");
    assert_eq!(halt.op, Op::Halt, "the builder ends every program with HALT");
    q.instrs.push(halt);
    assert_eq!(recursion::machine::program_log_height(q.instrs.len()), recursion::machine::program_log_height(p.instrs.len()),
        "the extra word must not cross a program-table power of two");
    q
}

// ── Task 1a: the program, by emulation ───────────────────────────────────────────────────────

/// `rv32t`'s pre-loop state (the binding, the cap, the interface sponge and its cursor) lives in
/// absolute cells. Building is the replay's loop-invariant check.
#[test]
fn the_tree_step_builds_under_the_replays_loop_invariant() {
    let l = leaves();
    let a = verify_rv32t(&l.shape, Checkpoints::Off).program;
    let b = verify_rv32t(&l.shape, Checkpoints::Off).program;
    assert_eq!(a.digest(), b.digest(), "the build is deterministic");
    assert_eq!(rv32t_leaf(&l.shape, Checkpoints::Off).program.digest(), a.digest(), "rv32t_leaf is verify_rv32t, named for level 1");
    assert_eq!(rv32t_int(&l.shape, Checkpoints::Off).program.digest(), a.digest(), "rv32t_int is verify_rv32t, named for levels ≥ 2");
    assert_eq!(tree_step_program_digest(&l.shape), a.digest(), "what a chain pins is the checkpoints-off build");
    // Pinned at the test-profile leaf shape (2026-10-09, tree Task 1a): `rv32t_leaf`'s digest,
    // the test chain's `t_leaf_digest` (M4). Re-pinned at the rVM's rate ¼ (2026-10-09, docs/07,
    // tree Task R): the child's Merkle paths are one level shorter (was bf80794d…ff4d5389).
    assert_eq!(recursion::programs::digest_hex(&a), "2c586636c4c0f94cdf13b410154679d995eefad11e27371e0786e89e206ccd34", "rv32t_leaf's digest at the test leaf shape");
}

/// The program reads the child shape's words and never its committed program: a child program
/// that differs only past its `HALT` builds the identical step.
#[test]
fn the_tree_step_program_reads_the_child_shape_words_only() {
    let l = leaves();
    let foreign = Arc::new(foreign_leaf_program(&l.program));
    let other = RvmShape::of(P, &foreign, Tier(l.shape.tier), l.shape.reg_log_height, l.shape.ram_log_height,
        l.shape.poseidon2_log_height, l.shape.reduce_log_height);
    assert!(other.same_step_words(&l.shape), "one word past HALT moves no shape word");
    assert_ne!(foreign.digest(), l.program.digest());
    assert_ne!(RvmKey::of(P, &other), l.key, "another program is another cap");
    assert_eq!(verify_rv32t(&other, Checkpoints::Off).program.digest(), verify_rv32t(&l.shape, Checkpoints::Off).program.digest());
}

/// Two real leaves, in order: accepted, the whole tape consumed, and exactly the host's
/// `[vk_leaf ‖ 2 ‖ B ‖ D_0 ‖ D_1]` published. Measures C (the k = 1 self-verifier over one leaf,
/// less phase 8) and the step's overhead O = rows − 2C (docs/08 §2's band term).
#[test]
fn the_tree_step_accepts_two_real_leaves_and_publishes_the_host_digest() {
    let l = leaves();
    let vp = rv32t_leaf(&l.shape, Checkpoints::Off);
    let tape = WitnessTape::build_tree_step(P, &l.shape, [&l.proofs[0], &l.proofs[1]], B).unwrap();
    let exec = execute(&vp.program, &tape.words, MAX_CYCLES).expect("rv32t_leaf accepts two real leaves");
    assert_eq!(exec.hints_read, tape.len(), "the program consumes the whole tape");
    let vk_leaf = inner_vk_digest(&l.shape, &l.key);
    assert_eq!(exec.public, host_step(&vk_leaf, B, &l.proofs[0], &l.proofs[1]), "[vk_leaf ‖ 2 ‖ B ‖ D_0 ‖ D_1], exactly");

    let r = verify_rv32r(&l.shape, &l.key, Checkpoints::Off);
    let rt = WitnessTape::build_for_with_binding(P, &l.shape, &l.key, &l.proofs[0], B).unwrap();
    let rexec = execute(&r.program, &rt.words, MAX_CYCLES).expect("rv32r accepts the leaf");
    let phase8: usize = r.phase_rows.iter().filter(|(n, _)| n.starts_with("phase 8")).map(|(_, x)| *x).sum();
    let child = rexec.cpu_rows() - phase8;
    let rows = exec.cpu_rows();
    let overhead = rows as i64 - 2 * child as i64;
    let by_phase = |vp: &recursion::programs::VerifierProgram<RvmShape>, e: &Execution| -> Vec<(&'static str, usize)> {
        let mut at = 0;
        vp.phase_rows.iter().map(|&(name, n)| {
            let x = e.events.iter().filter(|ev| (at..at + n).contains(&(ev.pc as usize))).count();
            at += n;
            (name, x)
        }).collect()
    };
    eprintln!("TREE_TEST phases rv32t {:?}", by_phase(&vp, &exec));
    eprintln!("TREE_TEST phases rv32r {:?}", by_phase(&r, &rexec));
    eprintln!("TREE_TEST child {child} step_leaf {rows} overhead {overhead} tier {:?} program {} instrs",
        Tier::for_cycles(rows), vp.program.instrs.len());
    assert_eq!(child, common::pin("tree_test", "child_cpu_rows"));
    assert_eq!(rows, common::pin("tree_test", "step_leaf_cpu_rows"));
    assert_eq!(overhead, common::pin_i64("tree_test", "step_overhead"));
    assert_eq!(Tier::for_cycles(rows).unwrap().0, common::pin("tree_test", "step_leaf_tier"));
}

/// The counted loop runs one child's static reduce rows twice, so `verify_n(program, proof, 2)`
/// (spec §4) declares exactly the height `build_traces` produces. Extends
/// `tests/aggregate.rs`'s `the_reduce_height_is_canonical_in_the_program_and_n_at_the_test_profile`
/// to the tree step.
#[test]
fn the_reduce_height_is_canonical_in_the_tree_step_at_n2() {
    use recursion::machine::canonical_reduce_log_height;
    use recursion::tables::reduce::{fold_events, fold_rows, pow_events, pow_rows, program_rows, provider_rows, reduce_events, reduce_log_height, reduce_rows};
    let l = leaves();
    let t = rv32t_leaf(&l.shape, Checkpoints::Off).program;
    let r = verify_rv32r(&l.shape, &l.key, Checkpoints::Off).program;
    let per = program_rows(&t);
    assert_eq!(per, program_rows(&r), "the loop body is the self-verifier's pipeline: one child's reduce rows");
    let exec = emulate_step(&l.shape, &t, &l.proofs[0], &l.proofs[1], B).unwrap();
    let rows = (reduce_rows(&reduce_events(&exec.events)) + fold_rows(&fold_events(&exec.events)) + pow_rows(&pow_events(&exec.events))) as u64;
    assert_eq!(rows, 2 * per, "two children run the body's static rows twice");
    assert_eq!(canonical_reduce_log_height(&t, recursion::programs::TREE_ARITY),
        Some(reduce_log_height(rows as usize, provider_rows(&t.reduce_layout))),
        "verify_n(program, proof, 2)'s height is the one build_traces declares");
}

/// Review Focus 3: a tamper in either child's region is refused at `emit_proof`'s own named
/// step, on the loop's first pass (child 0) or its second (child 1). The names are the
/// self-verifier's (`tests/self_verify.rs`'s table) because the body is the same pipeline (R1).
#[test]
fn a_tamper_in_either_child_is_refused_at_the_named_step() {
    let l = leaves();
    let vp = rv32t_leaf(&l.shape, Checkpoints::Off);
    let honest = WitnessTape::build_tree_step(P, &l.shape, [&l.proofs[0], &l.proofs[1]], B).unwrap();
    let table = [
        (Segment::Header, "header word 0"),
        (Segment::PublicValues, "quotient identity[0]"),
        (Segment::Commitments, "quotient identity[0]"),
        (Segment::LookupTerminals, "lookup terminal sum"),
    ];
    for child in 0..2 {
        for (seg, want) in table {
            let r = honest.segment_refs().into_iter().find(|r| r.proof == child && r.segment == seg).expect("the segment exists");
            let mut t = honest.clone();
            t.words[r.start] += F::ONE;
            match execute(&vp.program, &t.words, MAX_CYCLES) {
                Err(ExecError::InverseOfZero { pc }) => {
                    assert_eq!(vp.program.checkpoint_at(pc), Some(want), "child {child}, {seg:?}: refused at the wrong step")
                }
                other => panic!("child {child}, {seg:?}: expected a refusal, got {:?}", other.map(|e| e.cpu_rows())),
            }
        }
    }
}

/// R5, first half: a wrong hinted cap under honest children is refused in-program. The
/// transcript observes the preprocessed cap in phase 2, so every later challenge moves, and the
/// first check that reads one is the quotient identity.
#[test]
fn a_wrong_hinted_cap_with_honest_children_is_refused_in_program() {
    let l = leaves();
    let vp = rv32t_leaf(&l.shape, Checkpoints::Off);
    let honest = WitnessTape::build_tree_step(P, &l.shape, [&l.proofs[0], &l.proofs[1]], B).unwrap();
    for k in [8usize, TREE_TAPE_PREAMBLE - 1] {
        let mut t = honest.clone();
        t.words[k] += F::ONE;
        match execute(&vp.program, &t.words, MAX_CYCLES) {
            Err(ExecError::InverseOfZero { pc }) => assert_eq!(vp.program.checkpoint_at(pc), Some("quotient identity[0]"), "cap word {}", k - 8),
            other => panic!("cap word {}: expected a refusal, got {:?}", k - 8, other.map(|e| e.cpu_rows())),
        }
    }
}

/// ZKQ-5's tie is the chain's recompute. The program accepts a swapped pair and a step made
/// under another binding, and each publishes a digest that the chain's cover-order,
/// chain-binding recompute never produces (Task 2 turns both into `TreeRootDigest`).
#[test]
fn swapped_children_and_another_binding_publish_digests_the_chain_never_computes() {
    let l = leaves();
    let t = rv32t_leaf(&l.shape, Checkpoints::Off).program;
    let vk_leaf = inner_vk_digest(&l.shape, &l.key);
    let want = host_step(&vk_leaf, B, &l.proofs[0], &l.proofs[1]);
    let swapped = emulate_step(&l.shape, &t, &l.proofs[1], &l.proofs[0], B).expect("both orders are valid in-program");
    assert_eq!(swapped.public, host_step(&vk_leaf, B, &l.proofs[1], &l.proofs[0]), "children are published in tape order");
    assert_ne!(swapped.public, want, "a swapped pair fails the cover-order recompute");
    let rebound = emulate_step(&l.shape, &t, &l.proofs[0], &l.proofs[1], &[7u32; 8]).expect("no in-program B_out == B_in (ZKQ-5)");
    assert_ne!(rebound.public, want, "a step made under another binding fails the recompute");
}

/// A child whose declared shape is not the step's is refused by the tape builder, before any
/// word is written (the self-verifier's `a_wrong_shape_proof_is_refused`, one level up).
#[test]
fn a_child_of_the_wrong_shape_is_refused_by_the_tape_builder() {
    let l = leaves();
    let wrong = RvmShape::of(P, &l.program, Tier(l.shape.tier), l.shape.reg_log_height, l.shape.ram_log_height + 1,
        l.shape.poseidon2_log_height, l.shape.reduce_log_height);
    assert_eq!(
        WitnessTape::build_tree_step(P, &wrong, [&l.proofs[0], &l.proofs[1]], B).err(),
        Some(TapeError::Replay(recursion::reference::ReplayError::Shape))
    );
}

/// The builder's pre-check runs over *both* children before any replay (Task 1a review minor):
/// child 0 matches the shape but is tampered, so its replay alone refuses it with a non-shape
/// error; child 1 declares another shape. Only the pre-check can answer `Shape` for the pair.
#[test]
fn the_tape_builder_shape_checks_both_children_before_replaying_either() {
    let l = leaves();
    let copy = |p: &Proof| postcard::from_bytes::<Proof>(&p.to_bytes()).unwrap();
    let mut tampered = copy(&l.proofs[0]);
    tampered.public_values[0] = (tampered.public_values[0] + 1) % F::ORDER_U64;
    assert!(l.shape.matches(&tampered), "a public-value tamper keeps the declared shape");
    let mut other = copy(&l.proofs[1]);
    other.ram_log_height += 1;
    assert!(!l.shape.matches(&other));
    let alone = WitnessTape::build_tree_step(P, &l.shape, [&tampered, &l.proofs[1]], B).err();
    assert!(matches!(alone, Some(TapeError::Replay(ref e)) if *e != recursion::reference::ReplayError::Shape),
        "the tampered child alone is refused by its replay, not the shape check: {alone:?}");
    assert_eq!(
        WitnessTape::build_tree_step(P, &l.shape, [&tampered, &other], B).err(),
        Some(TapeError::Replay(recursion::reference::ReplayError::Shape)),
        "child 1's shape is refused before child 0 is replayed"
    );
}

// ── Task 1b: the proved test tree ───────────────────────────────────────────────────────────

struct TestTree {
    t_leaf: Arc<Program>,
    steps: Vec<Proof>,
    /// S_T: an `rv32t_leaf` proof's declared shape, carrying `rv32t_leaf`'s program.
    s_step: RvmShape,
    t_int: Arc<Program>,
    root: Proof,
    /// The root's declared shape, carrying `rv32t_int`'s program. R3: its words must equal S_T's.
    s_root: RvmShape,
    foreign: Proof,
    s_foreign: RvmShape,
}

fn test_tree() -> &'static TestTree {
    static T: OnceLock<TestTree> = OnceLock::new();
    T.get_or_init(|| {
        let l = leaves();
        let may = ALLOW_STEP_PROVING.load(Ordering::SeqCst);
        let m = Machine::new(P);
        let prove_step = |child: &RvmShape, program: &Program, a: &Proof, b: &Proof| -> Proof {
            let tape = WitnessTape::build_tree_step(P, child, [a, b], B).unwrap();
            m.prove(program, &tape.words, None).expect("a test tree step proves").0
        };
        let t_leaf = Arc::new(rv32t_leaf(&l.shape, Checkpoints::Off).program);
        let steps: Vec<Proof> = (0..2)
            .map(|k| load_or_prove(&format!("Test-step-{k}"), &t_leaf, 2, may, || {
                prove_step(&l.shape, &t_leaf, &l.proofs[2 * k], &l.proofs[2 * k + 1])
            }))
            .collect();
        let s_step = RvmShape::of_proof(P, &t_leaf, &steps[0]);
        assert!(s_step.matches(&steps[1]), "both level-1 steps declare one shape");
        let t_int = Arc::new(rv32t_int(&s_step, Checkpoints::Off).program);
        let root = load_or_prove("Test-root", &t_int, 2, may, || prove_step(&s_step, &t_int, &steps[0], &steps[1]));
        let s_root = RvmShape::of_proof(P, &t_int, &root);
        let fprog = Arc::new(foreign_leaf_program(&l.program));
        let foreign = load_or_prove("Test-foreign-0", &fprog, 1, true, || {
            let tape = WitnessTape::build_n(P, &l.inner.shape, &l.inner.key, std::slice::from_ref(&l.bundles[0]), B).unwrap();
            m.prove(&fprog, &tape.words, None).expect("the foreign leaf proves").0
        });
        let s_foreign = RvmShape::of_proof(P, &fprog, &foreign);
        TestTree { t_leaf, steps, s_step, t_int, root, s_root, foreign, s_foreign }
    })
}

fn u64s(v: &[F]) -> Vec<u64> {
    v.iter().map(|f| f.as_canonical_u64()).collect()
}

/// The generator (R7): proves whatever `tree/` lacks. Run it once where docs/08 §5 says, then
/// copy `$RECURSION_FIXTURES/tree/` to every box that runs the suite.
#[test]
#[ignore = "tree Task 1b: proves the test tree's steps and root (tier 19, tests/pins.json tree_test.step_leaf_tier; 34.3 GB max RSS measured for a step, 33.2 GB for the root) — this 48 GB laptop, one proving process at a time"]
fn generate_test_tree_fixtures() {
    ALLOW_STEP_PROVING.store(true, Ordering::SeqCst);
    let t = test_tree();
    let l = leaves();
    for (name, p) in [("leaf-0", &l.proofs[0]), ("step-0", &t.steps[0]), ("root", &t.root), ("foreign-0", &t.foreign)] {
        eprintln!("TREE_TEST_FIXTURE {name}: tier {} reg {} ram {} poseidon2 {} reduce {} bytes {}",
            p.tier.0, p.reg_log_height, p.ram_log_height, p.poseidon2_log_height, p.reduce_log_height, p.size());
    }
}

/// The depth-2 tree, every level: each step and the root publish exactly the host's
/// `[vk_c ‖ 2 ‖ B ‖ D_a ‖ D_b]` in cover order, with level 1's `vk_c = vk_leaf` and level 2's
/// `vk_c = vk_t_leaf` (R2). The child keys are computed here, never read off a
/// `VerifierProgram` (whose `key` is a zero placeholder for `rv32t`). The root's rows, as
/// emulated, are pinned.
#[test]
fn the_test_tree_proves_and_every_level_publishes_the_host_digest() {
    let (l, t) = (leaves(), test_tree());
    let vk_leaf = inner_vk_digest(&l.shape, &l.key);
    let vk_t_leaf = inner_vk_digest(&t.s_step, &RvmKey::of(P, &t.s_step));
    for k in 0..2 {
        assert_eq!(t.steps[k].public_values, u64s(&host_step(&vk_leaf, B, &l.proofs[2 * k], &l.proofs[2 * k + 1])), "step {k}");
    }
    assert_eq!(t.root.public_values, u64s(&host_step(&vk_t_leaf, B, &t.steps[0], &t.steps[1])), "the root");
    let exec = emulate_step(&t.s_step, &t.t_int, &t.steps[0], &t.steps[1], B).expect("rv32t_int accepts the two steps");
    eprintln!("TREE_TEST_INT rows {} tier {} step_bytes {} root_bytes {}", exec.cpu_rows(), t.root.tier.0, t.steps[0].size(), t.root.size());
    assert_eq!(exec.cpu_rows(), common::pin("tree_test", "step_int_cpu_rows"));
    assert_eq!(t.root.tier.0, common::pin("tree_test", "step_int_tier"));
    assert_eq!(t.steps[0].size(), common::pin("tree_test", "step_proof_bytes"));
}

/// Review Focus 2 (R3): `rv32t_int` is built for S_T, the shape of an `rv32t_leaf` proof, and
/// must verify proofs of *itself* at level 3. Its own root declares S_T's words, so the root
/// twice over is a valid level-3 pair: accepted, publishing `vk_int`, which is not `vk_t_leaf`.
#[test]
#[ignore = "R3: the test-profile fixed point does not hold (docs/08 §5); max_depth 2"]
fn the_interior_step_verifies_its_own_output() {
    let t = test_tree();
    assert!(
        t.s_root.same_step_words(&t.s_step),
        "R3: rv32t_int's own proofs declare another shape: {:?} vs {:?}. Record both in docs/08 §5 and set the test \
         profile's max_depth to 2 (no third program)",
        t.s_root.header_words(),
        t.s_step.header_words()
    );
    let vk_int = inner_vk_digest(&t.s_root, &RvmKey::of(P, &t.s_root));
    let vk_t_leaf = inner_vk_digest(&t.s_step, &RvmKey::of(P, &t.s_step));
    assert_ne!(vk_int, vk_t_leaf, "level 2 and level 3 publish different child keys (R2)");
    let exec = emulate_step(&t.s_root, &t.t_int, &t.root, &t.root, B).expect("rv32t_int accepts two of its own proofs");
    assert_eq!(exec.public, host_step(&vk_int, B, &t.root, &t.root));
}

/// Review Focus 1 (R5, second half): children of a foreign program with identical shape words,
/// under that program's honest cap, pass every in-program check. The step publishes the key it
/// checked against, and the chain's recompute with the pinned `vk_leaf` refuses it. The children's
/// digests equal the honest leaf's (the same run), so `vk_c` is the only difference.
#[test]
fn a_foreign_program_child_pair_passes_in_program_and_fails_the_root_recompute() {
    let (l, t) = (leaves(), test_tree());
    assert!(t.s_foreign.same_step_words(&l.shape));
    assert_eq!(t.foreign.public_values, l.proofs[0].public_values, "the same run publishes the same digest");
    let step = rv32t_leaf(&l.shape, Checkpoints::Off).program;
    let exec = emulate_step(&t.s_foreign, &step, &t.foreign, &t.foreign, B).expect("accepted in-program");
    let vk_foreign = inner_vk_digest(&t.s_foreign, &RvmKey::of(P, &t.s_foreign));
    let vk_leaf = inner_vk_digest(&l.shape, &l.key);
    assert_ne!(vk_foreign, vk_leaf);
    assert_eq!(exec.public, host_step(&vk_foreign, B, &t.foreign, &t.foreign), "it publishes the key it checked against");
    assert_ne!(exec.public, host_step(&vk_leaf, B, &t.foreign, &t.foreign), "the chain's recompute refuses it (Task 2: TreeRootDigest)");
}

/// The two step programs' digests at the test-profile shapes (M4). History: first pinned by tree
/// Task 1b.
const T_LEAF_TEST: &str = "2c586636c4c0f94cdf13b410154679d995eefad11e27371e0786e89e206ccd34";
const T_INT_TEST: &str = "04b1677122526e51c0d278375b0c30ebd37f94ba8a2afed3cd3e019ecdc3c226";

#[test]
fn the_test_tree_program_digests_are_pinned() {
    let t = test_tree();
    let (a, b) = (recursion::programs::digest_hex(&t.t_leaf), recursion::programs::digest_hex(&t.t_int));
    eprintln!("TREE_TEST_DIGESTS t_leaf {a} t_int {b}");
    assert_ne!(a, b, "two programs");
    assert_eq!(a, T_LEAF_TEST, "rv32t_leaf at the test leaf shape");
    assert_eq!(b, T_INT_TEST, "rv32t_int at the test step shape");
}
