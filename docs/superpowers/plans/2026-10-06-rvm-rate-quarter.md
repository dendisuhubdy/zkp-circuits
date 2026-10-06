# rVM at Rate ¼ Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the rVM's own FRI profile to `log_blowup 2` with 92 queries and 24 query-grinding bits at Production (16 / 4 at Test), keeping the proven security floor the whitepaper's 80/8/20 gives under the paper's own theorem, so every LDE and Merkle tree the rVM prover holds halves.

**Architecture:** A `RvmFri` parameter object in `recursion/src/machine.rs` replaces the literal blowup and the inner profile's query numbers in the rVM's config; `VerifierShape` gains `log_blowup()` so the shape, the host replay, the tape and the self-verifier program read the blowup from the shape they are verifying (inner proofs 3, rVM proofs 2); the crate constant `LOG_BLOWUP` is retired. A pinned security test (`p3-security`, the estimator Plonky3 ships) gates the phase: the paper's closed-form unique-decoding bits and `p3-security`'s best proven bits at the new regime are both ≥ today's − 0.5.

**Tech Stack:** Rust 1.98.1, Plonky3 0.7.0 (`p3-*` pinned `=0.7.0`; `p3-security` 0.7.0 joins `recursion`'s dev-dependencies), the recursion crate (`recursion/`, its own package root), `cargo test --release`.

**Spec:** `docs/superpowers/specs/2026-10-06-rvm-rate-quarter-design.md` (read §0.1 and §1 first).

**Worktree:** `~/rand-worktrees/circuits-rate4`, branch `feat/rvm-rate-quarter`, off circuits `main` 3316e11 (phase 3 merged, still unpushed by its owner). `cargo` commands run from `~/rand-worktrees/circuits-rate4/recursion` unless a step says otherwise. Prefix every `cargo test` with `RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures` on the same line. Release builds and the self-verifier suites take minutes; use Bash timeouts of 600000 ms.

## Global Constraints

- The inner RV32 machine (`research/`), every wallet proof, the inner verifier key and `inner_vk_digest` do not change. `research/src/machine.rs`'s `generic_config` literal stays `log_blowup: 3`; only `FriProfile`'s doc comment gains a sentence.
- The aggregate programs (`rv32`, `rv32n`) emit byte-identical code: the production aggregate program digest (`docs/06` §5: `dc350ecf…`), `src/programs/verify_rv32.digest` (`cf5a350a…`), the admission vectors and `tests/pins.json` **do not move**; they are asserted (Task 3 Step 1) before any pin is re-recorded.
- `RvmFri::of(FriProfile::Production) == RvmFri { log_blowup: 2, num_queries: 92, query_pow_bits: 24 }`; `RvmFri::of(FriProfile::Test) == RvmFri { log_blowup: 2, num_queries: 16, query_pow_bits: 4 }`. The digits may move only if Task 1's security test demands it, and then the spec's §0.1 is amended in the same commit.
- `max_log_arity 3`, `log_final_poly_len 0`, `commit_proof_of_work_bits 0`, four hiding codewords: unchanged for both machines.
- A proof made at rate ⅛ is refused by the rate-¼ verifier with a named error (`VerifyError::Batch(_)` or the replay's `ReplayError`), never a panic.
- The crate constant `recursion::shape::LOG_BLOWUP` is deleted; `INNER_LOG_BLOWUP: usize = 3` replaces it for inner shapes only; every other reader takes `shape.log_blowup()`.
- Re-pinned values (`tests/verifier_key.rs`, `tests/self_verify.rs`) carry the before values in the comment, in each file's existing style.
- Measurements: this box (16 cores, 48 GB), `--features parallel`, `RAYON_NUM_THREADS=16`, raw stdout under `recursion/docs/measurements/2026-10-06-<what>.log`; projections labelled.
- Commit after every task with the repository's message style and these two trailer lines, verbatim: `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_01TApVdzvYt8Q8gayscHsdkV`. Pre-existing warnings (`ShapeKey` unused import in `src/witness.rs`, unused imports in `tests/{machine,precompiles}.rs`, etc.) are out of scope.

## Review Focus

1. **A rate-⅛ rVM proof against the rate-¼ verifier** (an old aggregate reaching a new node): must be a named refusal, never a panic or a wrong pass. Task 2 Step 3's `a_rate_eighth_proof_is_refused_by_name` covers it.
2. **The arity schedule at the new heights**: with every input height one lower, `fri_schedule` may produce a different round count and a final fold that lands exactly on `log_final_height = 2`; the replay's cross-check `Σ log_arities + log_blowup + 0 == log_global_max_height` must still hold for both machines. Task 3 Step 6 runs `tests/verifier.rs` (inner) and `tests/self_verify.rs` (rVM) round trips, and Step 4 adds a unit test on `fri_schedule` at blowup 2.
3. **A reduced opening landing at the blowup height** (`rv32.rs:912`, `:985`: "exists only for a constant trace"): the key is now `shape.log_blowup()`; no rVM instance has `degree_bits == 0`, so the branch stays dead, but the assertion message and key must agree with the shape. Task 3 Step 5 threads the value and Task 3 Step 6's self-verifier round trip exercises the code path.
4. **The Test profile also at rate ¼**: every existing rVM test that proves (`cheating`, `aggregate`, `exit`, `self_verify`, `machine`, `quotient_layout`) now runs the new code paths; a test that assumed `2^(3+1)`-row minimum matrices (`witness.rs:560`'s doc) must still hold at `2^(2+1)`. Task 4's full suite covers it; Task 3 Step 5 fixes the doc.
5. **The self-verifier's tape at 92 queries**: `Segment::QueryBits`, `InputOpenings` and `InputPaths` grow per query; `header_words` carries `num_queries`, so a shape built with the inner count would be refused at "header word k". Task 3 Step 6's `self_verify` round trips cover it (they build `RvmShape` through `RvmShape::of`, which must read `RvmFri`).

---

### Task 0: Baseline measurements on this branch (phase 3's tree)

**Files:**
- Create: `recursion/docs/measurements/2026-10-06-tier16-before.log`, `recursion/docs/measurements/2026-10-06-twin-before.log`

**Interfaces:** Produces the "before" column for Tasks 5 and 6: tier-16 synthetic peak live heap and prove wall; the exit twin's peak live heap, prove wall, verify time, proof bytes.

- [ ] **Step 1: Tier 16, 16 threads**

```bash
cd ~/rand-worktrees/circuits-rate4/recursion
RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures RAYON_NUM_THREADS=16 \
  cargo test --release --features parallel --test memprofile tier16_synthetic_threads -- --ignored --nocapture \
  2>&1 | tee docs/measurements/2026-10-06-tier16-before.log | grep "== tier16"
```
Expected: a `== tier16 synthetic:` line with `63762 rows, tier 16`, a peak live heap (docs/05 measured 6.41 GB before phase 3; phase 3 may have moved it) and a prove wall.

- [ ] **Step 2: The exit twin, 16 threads** (about 2.5 minutes; `docs/06` measured 26.88 GB)

```bash
RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures RAYON_NUM_THREADS=16 \
  cargo test --release --features parallel --test memprofile tier19_exit_twin -- --ignored --nocapture \
  2>&1 | tee docs/measurements/2026-10-06-twin-before.log | grep -E "== exit twin|prove done|^verify"
```
Expected: `== exit twin (tier 18): 169366 rows, tier 18, proof … B, prove … s; peak live heap … GB`, `prove done: … peak 26.9 GB` (±0.2), `verify … s`.

- [ ] **Step 3: Commit**

```bash
cd ~/rand-worktrees/circuits-rate4
git add recursion/docs/measurements/2026-10-06-tier16-before.log recursion/docs/measurements/2026-10-06-twin-before.log
git commit -q -m "recursion docs: memprofile baselines before the rate-¼ profile (tier-16 synthetic, the exit twin)

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TApVdzvYt8Q8gayscHsdkV"
```

---

### Task 1: The security gate — `tests/security.rs` over the rVM's real chip shapes

**Files:**
- Modify: `recursion/Cargo.toml` (`[dev-dependencies]`: add `p3-security = "=0.7.0"`)
- Create: `recursion/tests/security.rs`

**Interfaces:**
- Consumes: `recursion::machine::{chips, Machine, Tier, Challenge, Val, FriProfile}`; `Machine::verifier_key(program, tier, reduce_log_height) -> Arc<CommonData<Config>>` (its `.lookups: Vec<Vec<Lookup<Val>>>`); `recursion::shape::RvmShape::of(profile, &program, tier, reg, ram, poseidon2, reduce)` and `RvmShape::air_layout(i, &chip)`; `p3_batch_stark::symbolic::{get_symbolic_constraints, get_max_constraint_degree}` (vendored fork, signatures below); `p3-security` 0.7.0.
- Produces: the regime pair the test compares, as two local constants `OLD = (3, 80, 20)` and `NEW = (2, 92, 24)`; Task 2 replaces `NEW` with `RvmFri::of(FriProfile::Production)`.

- [ ] **Step 1: Add the dev-dependency**

In `recursion/Cargo.toml`, under `[dev-dependencies]` (after `tracing = "0.1"`), add:
```toml
# `tests/security.rs`: the soundness estimator Plonky3 ships, over this machine's real chip shapes
# (the same crate `research/src/machine.rs`'s `fri_soundness_tests` leans on through p3-fri).
p3-security = "=0.7.0"
```
Run: `cargo build --release --tests 2>&1 | tail -1` → `Finished` (the crate resolves from the registry; it has no path dependencies).

- [ ] **Step 2: Write the test (it passes against today's literals; it is the gate the rest of the phase must keep green)**

Create `recursion/tests/security.rs`:
```rust
//! The rate-¼ phase's gate (`docs/07-rvm-rate-quarter.md`, spec §0.1/§4): the rVM's own FRI
//! profile may move only to a regime whose proven security is not below today's, computed two ways
//! over this machine's *real* chip shapes at the production exit:
//!
//! 1. the whitepaper's closed-form unique-decoding bound, `q · log2(2 / (1 + ρ)) + g`
//!    (`randprotocol_implementation.tex`, "FRI soundness as instantiated");
//! 2. `p3-security`'s best proven regime (unique or list decoding, whichever binds higher), with the
//!    AIR, instance, batching and LogUp terms this batch actually has.
//!
//! Today's regime is the inner profile's (rate ⅛, 80 queries, 20 grinding bits); the new one is
//! `RvmFri::of(Production)`. The conjectured (random-words) bound and the legacy ethSTARK bound are
//! asserted too, as floors.
use std::sync::Arc;

use p3_field::Field;
use p3_fri::FriParameters;
use p3_lookup::LogUpGadget;
use p3_security::grinding::GrindingSites;
use p3_security::logup::{self, LogUpAir};
use p3_security::shape::{InstanceShape, StarkAirParams};
use p3_security::stark::{conjectured_security_report, proven_security_report};
use recursion::isa::{Instr, Op, Program, F};
use recursion::machine::{chips, Challenge, FriProfile, Machine, Tier, Val};
use recursion::shape::RvmShape;
use p3_field::PrimeCharacteristicRing;

/// (log_blowup, num_queries, query_pow_bits).
const OLD: (usize, usize, usize) = (3, 80, 20);
const NEW: (usize, usize, usize) = (2, 92, 24);

/// The production exit's declared heights (`docs/06` §3): cpu `2^20`, reg `2^21`, ram `2^21`,
/// poseidon2 `2^16`, reduce `2^18`, program `2^20`; the tallest *extended* table is `2^22`.
const PRODUCTION: (Tier, u8, u8, u8, u8) = (Tier(20), 21, 21, 16, 18);

fn regime(p: (usize, usize, usize)) -> p3_security::fri::FriRegime {
    let f: FriParameters<()> = FriParameters {
        log_blowup: p.0,
        log_final_poly_len: 0,
        max_log_arity: 3,
        num_queries: p.1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: p.2,
        mmcs: (),
    };
    f.security_regime()
}

/// The paper's closed-form unique-decoding bound.
fn paper_udr_bits(p: (usize, usize, usize)) -> f64 {
    let rho = 2f64.powi(-(p.0 as i32));
    p.1 as f64 * (2.0 / (1.0 + rho)).log2() + p.2 as f64
}

/// A two-instruction program: the chips' constraint systems do not depend on the program's words,
/// only the preprocessed table's contents do, and the security model reads the former.
fn toy() -> Arc<Program> {
    Arc::new(Program {
        instrs: vec![
            Instr { op: Op::Faddi, rd: 1, ra: 0, b: F::from_u64(7) },
            Instr { op: Op::Halt, rd: 0, ra: 0, b: F::ZERO },
        ],
        checkpoints: vec![],
        reduce_layout: vec![],
    })
}

/// The real shape of this machine's batch at the production exit, as `p3-security` wants it:
/// the AIR parameters over every chip (constraint count summed, degree and combo maxed), the
/// instance shape at the tallest extended height, the LogUp bus, and the committed-matrix count.
fn real_shape() -> (StarkAirParams, InstanceShape, LogUpAir) {
    let (tier, reg, ram, pos, red) = PRODUCTION;
    let program = toy();
    let shape = RvmShape::of(FriProfile::Production, &program, tier, reg, ram, pos, red);
    let m = Machine::new(FriProfile::Production);
    let common = m.verifier_key(&program, tier, red);
    let airs = chips(&program, tier, red);
    let gadget = LogUpGadget::new();
    let mut num_constraints = 0usize;
    let mut max_degree = 1usize;
    let mut num_interactions = 0usize;
    let mut max_message_width = 1usize;
    for (i, air) in airs.iter().enumerate() {
        let layout = shape.air_layout(i, air);
        let trace_len = 1usize << (shape.degree_bits[i] - 1); // ext_db − is_zk
        let (base, ext) = p3_batch_stark::symbolic::get_symbolic_constraints::<Val, Challenge, _, _>(
            air, layout, &common.lookups[i], &gadget,
        );
        num_constraints += base.len() + ext.len();
        max_degree = max_degree.max(p3_batch_stark::symbolic::get_max_constraint_degree::<Val, Challenge, _, _>(
            air, shape.air_layout(i, air), trace_len, &common.lookups[i], &gadget,
        ));
        for l in &common.lookups[i] {
            num_interactions += l.elements.len();
            max_message_width = max_message_width.max(l.elements.iter().map(|t| t.len()).max().unwrap_or(1));
        }
    }
    let n = airs.len();
    let with_lookups = shape.num_lookups.iter().filter(|&&k| k > 0).count();
    let preprocessed = shape.preprocessed_widths.iter().filter(|&&w| w > 0).count();
    let air = StarkAirParams { num_constraints, max_constraint_degree: max_degree, max_combo: max_degree };
    let inst = InstanceShape {
        log_trace_length: *shape.degree_bits.iter().max().unwrap(),
        modulus_bits: <Challenge as Field>::bits(),
        collision_resistance: 128,
        // random + main + quotient (one per instance since docs/05) + preprocessed + permutation.
        num_batched_functions: n + n + n + preprocessed + with_lookups,
    };
    let bus = LogUpAir { num_interactions, max_message_width };
    eprintln!("real shape: {air:?} {inst:?} {bus:?}");
    (air, inst, bus)
}

fn bits(p: (usize, usize, usize), air: &StarkAirParams, inst: &InstanceShape, bus: &LogUpAir) -> (f64, f64, f64, f64) {
    let r = regime(p);
    let g = GrindingSites::NONE;
    let term = logup::security_term(bus, inst, &g).expect("the batch has a LogUp bus");
    let proven = proven_security_report(&r, air, inst, &[term.clone()], &g);
    let conj = conjectured_security_report(&r, air, inst, &[term], &g);
    let (reg, bind) = proven.binding();
    eprintln!(
        "regime {p:?}: paper-UDR {:.2}, p3 proven {:.2} (binds {} in {reg:?}; UDR {:.2}), conjectured {:.2}, legacy {}",
        paper_udr_bits(p), proven.security_bits(), bind.label, proven.udr.security_bits(), conj.security_bits(),
        p.0 * p.1 + p.2
    );
    (paper_udr_bits(p), proven.security_bits(), conj.security_bits(), (p.0 * p.1 + p.2) as f64)
}

#[test]
fn the_new_rvm_profile_is_not_below_todays_proven_floor() {
    let (air, inst, bus) = real_shape();
    let (old_paper, old_p3, _, _) = bits(OLD, &air, &inst, &bus);
    let (new_paper, new_p3, new_conj, new_legacy) = bits(NEW, &air, &inst, &bus);
    // The calibration: today's regime reproduces the paper's ≈ 86 proven bits.
    assert!((old_paper - 86.4).abs() < 0.2, "the paper's own figure for 80/8/20: {old_paper:.2}");
    assert!(old_p3 >= 85.0, "p3-security at today's regime over the real shape: {old_p3:.2}");
    // The rule (spec §0.1): not below today's, both ways.
    assert!(new_paper >= old_paper - 0.5, "paper's unique-decoding bits fell: {new_paper:.2} < {old_paper:.2} − 0.5");
    assert!(new_p3 >= old_p3 - 0.5, "p3-security's proven bits fell: {new_p3:.2} < {old_p3:.2} − 0.5");
    assert!(new_conj >= 95.0, "conjectured (random-words) bits: {new_conj:.2}");
    assert!(new_legacy >= 100.0, "legacy ethSTARK bits: {new_legacy}");
}

#[test]
fn the_test_regime_keeps_its_shape() {
    // Rate ¼ with the suite's 16 queries and 4 bits: the same code paths as production, cheap.
    assert_eq!(regime((2, 16, 4)).log_blowup, 2);
}
```
If `shape.degree_bits`, `shape.num_lookups` or `shape.preprocessed_widths` are not `pub` fields on `RvmShape`, use the `VerifierShape` trait methods of the same names (`use recursion::shape::VerifierShape;`). If `get_symbolic_constraints`'s generic order differs (`<F, EF, A, LG>` is what the vendored `symbolic.rs:153` declares), follow the file.

- [ ] **Step 3: Run it; read the printed shape and the four numbers**

Run: `RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures cargo test --release --test security -- --nocapture 2>&1 | grep -E "real shape|regime|test result|panicked"`
Expected: both tests pass; the `regime (3, 80, 20)` line shows paper-UDR ≈ 86.4 and p3 proven ≈ 86 (the real shape's committed-matrix count and LogUp terms may move it by a bit or two; the assertion floor is 85.0); the `regime (2, 92, 24)` line shows paper-UDR ≈ 86.38 and p3 proven ≥ the old. **If the second assertion fails at (2, 92, 24)**, find the smallest `(2, q, 24)` with `q ≥ 92` that passes, set `NEW` to it, and record the measured lines in the report: the spec's §0.1 and the constants in Task 2 then take that digit (the controller amends the spec).

- [ ] **Step 4: Commit**

```bash
cd ~/rand-worktrees/circuits-rate4
git add recursion/Cargo.toml recursion/Cargo.lock recursion/tests/security.rs
git commit -q -m "recursion: tests/security.rs — the rate-¼ gate: the paper's unique-decoding bits and p3-security's proven bits at (2, 92, 24) are not below (3, 80, 20)'s over the real chip shapes

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TApVdzvYt8Q8gayscHsdkV"
```

---

### Task 2: `RvmFri` — the rVM's own FRI parameters, in the config and pinned

**Files:**
- Modify: `recursion/src/machine.rs:94-145` (`build_config`, `generic_config`, `key_config`, `make_config`), `:375-380` (`Machine::new`)
- Modify: `recursion/tests/machine.rs` (two new tests), `recursion/tests/security.rs` (`NEW` → `RvmFri::of`)

**Interfaces:**
- Produces: `recursion::machine::RvmFri { pub log_blowup: usize, pub num_queries: usize, pub query_pow_bits: usize }` with `pub const fn of(profile: FriProfile) -> RvmFri`; `Machine::with_fri(profile: FriProfile, fri: RvmFri) -> Machine` (tests' entry: a machine proving and verifying under an explicit regime, its key config at the same regime); `Machine::new(profile)` = `with_fri(profile, RvmFri::of(profile))`.
- Consumes: Task 1's test.

- [ ] **Step 1: Write the failing tests**

Append to `recursion/tests/machine.rs`:
```rust
#[test]
fn the_rvm_fri_parameters_are_pinned_per_profile() {
    use recursion::machine::RvmFri;
    assert_eq!(RvmFri::of(rand_zkvm::machine::FriProfile::Production), RvmFri { log_blowup: 2, num_queries: 92, query_pow_bits: 24 });
    assert_eq!(RvmFri::of(rand_zkvm::machine::FriProfile::Test), RvmFri { log_blowup: 2, num_queries: 16, query_pow_bits: 4 });
}

/// An aggregate made at the old rate ⅛ (the inner profile's numbers) reaching a rate-¼ verifier:
/// refused by name, never accepted, never a panic. The rate-⅛ machine proves under its own key
/// config (so its proof is internally consistent); the rate-¼ machine recomputes its own key and
/// FRI parameters and the proof fails against them.
#[test]
fn a_rate_eighth_proof_is_refused_by_name() {
    use recursion::machine::RvmFri;
    let mut p = toy_program();
    let halt = p.instrs.pop().unwrap();
    for r in [1, 2, 3] {
        p.instrs.push(instr(Op::Public, 0, r, 0));
    }
    p.instrs.push(halt);
    let profile = rand_zkvm::machine::FriProfile::Test;
    let old = Machine::with_fri(profile, RvmFri { log_blowup: 3, num_queries: 16, query_pow_bits: 4 });
    let (proof, _) = old.prove(&p, &[], None).unwrap();
    old.verify(&p, &proof).expect("consistent under its own regime");
    let new = Machine::new(profile);
    match new.verify(&p, &proof) {
        Err(VerifyError::Batch(msg)) => assert!(!msg.is_empty(), "a named refusal: {msg}"),
        Err(other) => panic!("refused, but not by the batch verifier: {other:?}"),
        Ok(()) => panic!("a rate-⅛ proof must not verify at rate ¼"),
    }
}
```
(`toy_program`, `instr`, `Machine`, `VerifyError`, `Op` are already in scope in that file.)

- [ ] **Step 2: Run them to see the compile failure**

Run: `RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures cargo test --release --test machine 2>&1 | grep -E "^error|cannot find|no function" | head -3`
Expected: `cannot find type RvmFri` / `no function or associated item named with_fri`.

- [ ] **Step 3: Implement**

In `recursion/src/machine.rs`, after `pub type Config = …;` (near line 33) add:
```rust
/// The rVM's own FRI parameters — not the inner RV32 machine's. The inner profile (research's
/// `FriProfile`: 80 queries, rate ⅛, 20 grinding bits) sizes the proofs this machine *verifies*;
/// these size the proofs it *makes*. Rate ¼ halves every LDE and tree the prover holds; twelve
/// more queries and four more grinding bits keep the proven floor where the paper's 80/8/20 put
/// it — under the paper's own unique-decoding theorem (92 × 0.678 + 24 = 86.4 bits) and under
/// `p3-security`'s list-decoding regime (88.0) alike; `tests/security.rs` pins both (docs/07).
/// Consensus-facing like the inner profile: the chain's `fri_profile` name binds both parameter
/// sets, and a proof made under another regime is refused by `verify` (`tests/machine.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RvmFri {
    pub log_blowup: usize,
    pub num_queries: usize,
    pub query_pow_bits: usize,
}

impl RvmFri {
    pub const fn of(profile: FriProfile) -> RvmFri {
        match profile {
            FriProfile::Test => RvmFri { log_blowup: 2, num_queries: 16, query_pow_bits: 4 },
            FriProfile::Production => RvmFri { log_blowup: 2, num_queries: 92, query_pow_bits: 24 },
        }
    }
}
```
Thread it through the config builders:
```rust
fn build_config(fri: RvmFri, mmcs_rng: SaltRng, pcs_rng: SaltRng) -> Config {
    …unchanged body…
    generic_config(fri, Dft::default(), val_mmcs, pcs_rng)
}

fn generic_config<D, M>(fri: RvmFri, dft: D, val_mmcs: M, pcs_rng: SaltRng) -> StarkConfig<…> where … {
    let challenge_mmcs = ExtensionMmcs::new(val_mmcs.clone());
    let p = p3_fri::FriParameters {
        log_blowup: fri.log_blowup,
        log_final_poly_len: 0,
        max_log_arity: 3,
        num_queries: fri.num_queries,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: fri.query_pow_bits,
        mmcs: challenge_mmcs,
    };
    let pcs = HidingFriPcs::new(dft, val_mmcs, p, 4, pcs_rng);
    StarkConfig::new(pcs, Challenger::new(permutation()))
}

fn key_config(fri: RvmFri) -> Config {
    let (mmcs_rng, pcs_rng) = key_rngs();
    build_config(fri, mmcs_rng, pcs_rng)
}

pub fn make_config(profile: FriProfile) -> Config {
    build_config(RvmFri::of(profile), SaltRng::fresh(), SaltRng::fresh())
}
```
`Machine` gains the field and the constructor:
```rust
pub struct Machine { pub config: Config, pub profile: FriProfile, pub fri: RvmFri, keys: Mutex<KeyCache> }

impl Machine {
    pub fn new(profile: FriProfile) -> Self {
        Self::with_fri(profile, RvmFri::of(profile))
    }

    /// A machine under an explicit regime — the tests' entry (a rate-⅛ proof to show refused;
    /// `docs/07`). Every machine a node or an aggregator runs is `new(profile)`'s.
    pub fn with_fri(profile: FriProfile, fri: RvmFri) -> Self {
        Self { config: build_config(fri, SaltRng::fresh(), SaltRng::fresh()), profile, fri, keys: Mutex::new(KeyCache::default()) }
    }
```
Every `key_config(self.profile)` in `machine.rs` becomes `key_config(self.fri)` (`verifier_key`, `prove_traces_with_layout`, `prove_on`; `grep -n "key_config(" src/machine.rs` lists them). The backend module (`src/backend.rs` or wherever `reference_config`/`cuda_config` call `generic_config`) passes `self.fri` / `RvmFri::of(profile)` the same way — `grep -rn "generic_config(" src/` finds the call sites.

Update the module doc at the top of `machine.rs`: the sentence "reuses the RV32 machine's exact proof-system configuration" becomes "reuses the RV32 machine's field, permutation and proof system; its FRI parameters are its own (`RvmFri`, rate ¼ since `docs/07`)".

- [ ] **Step 4: `tests/security.rs` reads the constant**

Replace `const NEW: (usize, usize, usize) = (2, 92, 24);` with
```rust
fn new_regime() -> (usize, usize, usize) {
    let f = recursion::machine::RvmFri::of(FriProfile::Production);
    (f.log_blowup, f.num_queries, f.query_pow_bits)
}
```
and the uses of `NEW` with `new_regime()`.

- [ ] **Step 5: Run the three test files**

Run: `RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures cargo test --release --test machine --test security --test verifier_key 2>&1 | grep -E "^test |test result|panicked" | grep -v " ok$"`
Expected: `the_rvm_fri_parameters_are_pinned_per_profile` and `a_rate_eighth_proof_is_refused_by_name` pass; `security` passes; **`tests/verifier_key.rs` FAILS** (the rVM key caps moved with the LDE height) — expected; Task 3 re-pins it after the aggregate pins are asserted. `the_toy_proves_and_verifies` and the other machine tests pass (the native prover and verifier agree with each other at rate ¼ already; only the program-side readers lag until Task 3).

- [ ] **Step 6: Commit**

```bash
cd ~/rand-worktrees/circuits-rate4
git add recursion/src/machine.rs recursion/tests/machine.rs recursion/tests/security.rs
git commit -q -m "recursion: RvmFri — the rVM's own FRI parameters (rate ¼, 92 queries, 24 grinding bits at Production); Machine::with_fri for the tests; a rate-⅛ proof refused by name

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TApVdzvYt8Q8gayscHsdkV"
```

---

### Task 3: The blowup comes from the shape — `LOG_BLOWUP` retired; replay, tape and programs follow; pins re-recorded

**Files:**
- Modify: `recursion/src/shape.rs:31-34` (the constant), `:112` (doc), `:260-261` and `:968-969` (query numbers), `:301-311` (profile recovery), `:352-355` and `:1021-1023` (`log_global_max_height`), `:445-470` (`fri_schedule`), `:655-700` (the trait), the two `impl VerifierShape` blocks
- Modify: `recursion/src/reference.rs:20-22` (imports), `:184-193` (`fri_params`), `:428-445`, `:505-520`, `:534-540`
- Modify: `recursion/src/programs/rv32.rs:24-28` (imports), `:469` (`h_of`), the two functions around `:912` and `:985`
- Modify: `recursion/src/witness.rs:555-562` (doc), `recursion/tests/verifier.rs:86`, `recursion/tests/shape.rs` (one new test)
- Modify (re-pins): `recursion/tests/verifier_key.rs`, `recursion/tests/self_verify.rs`

**Interfaces:**
- Consumes: Task 2's `RvmFri::of`.
- Produces: `recursion::shape::INNER_LOG_BLOWUP: usize = 3`; `VerifierShape::log_blowup(&self) -> usize`; `fri_schedule(degree_bits: &[usize], log_blowup: usize)`; `RvmShape.num_queries / query_pow_bits` from `RvmFri::of(profile)`.

- [ ] **Step 1: Assert the aggregate pins BEFORE touching anything (they must still pass at the end, unchanged)**

Run: `RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures cargo test --release --test verifier --test aggregate --test tape_n --test binding --test exit 2>&1 | grep -E "^test result|FAILED"`
Expected: all `ok` (these read inner proofs; Task 2 changed only the rVM's own prover config, which these programs do not depend on). Record the lines.

- [ ] **Step 2: Write the failing unit test for the schedule at blowup 2**

Append to `recursion/tests/shape.rs`:
```rust
/// The arity schedule follows the blowup it is given: the same degree bits one height lower at
/// every round, and the fold ends at the final height `log_blowup + 0`.
#[test]
fn the_fri_schedule_is_a_function_of_the_blowup() {
    use recursion::shape::{fri_schedule_for_tests, INNER_LOG_BLOWUP};
    // The toy rVM shape's extended degree bits at tier 8 (cpu 9, reg 10, ram 10, poseidon2 9, public 9, range 9, program 9).
    let bits = [9usize, 9, 10, 10, 9, 9, 9];
    let at_three = fri_schedule_for_tests(&bits, INNER_LOG_BLOWUP).unwrap();
    let at_two = fri_schedule_for_tests(&bits, 2).unwrap();
    assert_eq!(at_three.iter().sum::<usize>() + INNER_LOG_BLOWUP, 10 + INNER_LOG_BLOWUP, "folds from the tallest input height to the final height");
    assert_eq!(at_two.iter().sum::<usize>() + 2, 10 + 2);
    assert!(at_two.iter().all(|&a| a >= 1 && a <= 3), "arities stay within max_log_arity: {at_two:?}");
}
```
Run: `cargo test --release --test shape 2>&1 | grep -E "^error|cannot find" | head -2` → `cannot find function fri_schedule_for_tests` / `INNER_LOG_BLOWUP`.

- [ ] **Step 3: `shape.rs`**

- Replace lines 31-34:
```rust
/// The inner RV32 machine's `log_blowup`, from `research`'s `generic_config`
/// (`research/src/machine.rs`): a literal there and a literal here — `InnerShape::of` cannot read it
/// back off a `FriParameters` because the `Config`'s PCS keeps them private. Cross-checked against a
/// real inner proof by `tests/verifier.rs` (`Σ log_arities + INNER_LOG_BLOWUP == log_global_max_height`).
/// The rVM's own proofs are at `machine::RvmFri::of(profile).log_blowup` (rate ¼ since `docs/07`);
/// every reader takes the value from the shape it is reading, `VerifierShape::log_blowup`.
pub const INNER_LOG_BLOWUP: usize = 3;
```
- `:112` doc: "`degree_bits[i] + LOG_BLOWUP`" → "`degree_bits[i] + log_blowup`".
- `InnerShape::of` (`:252`): `let log_arities = fri_schedule(&degree_bits)?;` → `fri_schedule(&degree_bits, INNER_LOG_BLOWUP)?`.
- `InnerShape::log_global_max_height` (`:352-355`): `+ LOG_BLOWUP` → `+ INNER_LOG_BLOWUP`; fix the doc comment likewise.
- `fri_schedule` (`:449`): signature `fn fri_schedule(degree_bits: &[usize], log_blowup: usize) -> Result<Vec<usize>, ShapeError>`; the two uses of `LOG_BLOWUP` inside become `log_blowup`; the doc's "`degree_bits[i] + LOG_BLOWUP`" → "`degree_bits[i] + log_blowup`". Add, right after it:
```rust
/// [`fri_schedule`] for the tests (`tests/shape.rs`): the schedule is a function of the blowup.
pub fn fri_schedule_for_tests(degree_bits: &[usize], log_blowup: usize) -> Result<Vec<usize>, ShapeError> {
    fri_schedule(degree_bits, log_blowup)
}
```
- `RvmShape::try_of` (`:968-969`): `num_queries: profile.num_queries(), query_pow_bits: profile.pow_bits(),` → `num_queries: crate::machine::RvmFri::of(profile).num_queries, query_pow_bits: crate::machine::RvmFri::of(profile).query_pow_bits,`; its `fri_schedule(&degree_bits)?` call → `fri_schedule(&degree_bits, crate::machine::RvmFri::of(profile).log_blowup)?`.
- `RvmShape::log_global_max_height` (`:1021-1023`): `+ LOG_BLOWUP` → `+ crate::machine::RvmFri::of(self.profile).log_blowup`.
- The rVM shape's profile recovery, if it has one of its own (`grep -n "fn profile" src/shape.rs` shows `:308` for `InnerShape`; `RvmShape` stores `profile` as a field — leave `InnerShape::profile` as is: it matches the inner numbers, which did not change).
- The trait (`:655-700`): after `fn log_num_quotient_chunks(&self) -> &[usize];` add
```rust
    /// The FRI blowup of the proofs this shape reads (`docs/07`): the inner RV32 machine's
    /// `INNER_LOG_BLOWUP` (3) for inner proofs, `machine::RvmFri::of(profile).log_blowup` (2) for
    /// the rVM's own. Every height the replay, the tape and the program derive from a degree bit
    /// adds this and nothing else.
    fn log_blowup(&self) -> usize;
```
with `InnerShape` → `INNER_LOG_BLOWUP` and `RvmShape` → `crate::machine::RvmFri::of(self.profile).log_blowup`.
- Delete `pub const LOG_BLOWUP`. The compiler now lists every remaining reader.

- [ ] **Step 4: `reference.rs`**

- Imports (`:20-22`): drop `LOG_BLOWUP`, keep `CAP_HEIGHT, LOG_FINAL_POLY_LEN, MAX_LOG_ARITY`.
- `fri_params` (`:184-193`): `log_blowup: shape.log_blowup(),`.
- In `replay`, after `let n = shape.instances();` add `let log_blowup = shape.log_blowup();` and use it at `:435` (`+ log_blowup + LOG_FINAL_POLY_LEN`), `:439` (`+ log_blowup`), `:513` (`<< log_blowup`), `:539` (`let log_final_height = log_blowup + LOG_FINAL_POLY_LEN;`).

- [ ] **Step 5: `programs/rv32.rs` and `witness.rs`**

- Imports (`:24-28`): drop `LOG_BLOWUP`.
- `observe_claimed` (`:469`): `let h_of = |i: usize| shape.degree_bits()[i] + shape.log_blowup();`.
- The two functions that key an accumulator by the blowup height (`:912` `acc.get(&LOG_BLOWUP)`, `:985` `runs.contains_key(&LOG_BLOWUP)`): add a `log_blowup: usize` parameter to each (named `reduce_openings`/`reduce_openings_chip` or whatever the enclosing `fn` is — read the signature) and pass `shape.log_blowup()` from their callers in `verify_rv32_with`; the comments "at the blowup height" stay true.
- `witness.rs:560`: "`2^(LOG_BLOWUP + 1)` rows tall" → "`2^(log_blowup + 1)` rows tall (3 for inner proofs, 2 for the rVM's own)".
- `tests/verifier.rs:86`: `recursion::shape::LOG_BLOWUP` → `recursion::shape::INNER_LOG_BLOWUP`.

Run: `cargo build --release --tests 2>&1 | grep -E "^error" -A5 | head -30` → no errors (any remaining `LOG_BLOWUP` reader shows up here; fix it the same way).

- [ ] **Step 6: The aggregate pins still pass; the self-verifier round trips; read the new numbers**

Run (the gate from Step 1 again, plus `shape`): `RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures cargo test --release --test verifier --test aggregate --test tape_n --test binding --test exit --test shape 2>&1 | grep -E "^test result|FAILED"` → all `ok`.
Run: `RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures cargo test --release --test self_verify --test verifier_key -- --nocapture 2>&1 | grep -E "TOY_TIER8|BUSY|^test |panicked|left:|right:|no reduce|reduce:" | head -40`
Expected: `the_self_verifier_accepts_a_real_rvm_proof`, `a_wrong_shape_proof_is_refused`, `thirteen_tampered_rvm_proofs_are_refused_at_the_named_steps`, `the_self_verifier_is_straight_line_in_the_proofs_data`, `a_rewritten_commit_phase_pow_word_in_an_rvm_proof_is_refused` pass; the digest pin, the two `CycleReport` tuples (and possibly phase 5) fail printing `left:`; `verifier_key` fails printing the new caps (`Test no reduce: […]`, `Test reduce: […]`; Production prints the same caps — the key does not depend on queries or grinding). **If any other self_verify test fails** (a `TapeError`/`ExecError` at a named step), stop: a reader of the old blowup was missed; report BLOCKED with the step.

- [ ] **Step 7: Re-pin with the before values**

`tests/verifier_key.rs`: `WANT` and `WANT_REDUCE` take the printed caps; add above each, in the file's style: `/// Re-pinned for the rate-¼ profile (2026-10-06, docs/07): the preprocessed tables' LDE is half as tall, so the cap moved (was dd11c3f0972cfe5b, c8cc668625c3cda5, …)` and `(was 1465f60a95152d43, 208336379a094499, …)`. Keep the doc's note that both profiles share one cap.

`tests/self_verify.rs`: the digest at `:142` → the printed hex, with `// The rate-¼ profile (2026-10-06, docs/07): one Merkle level fewer per path at every height (was e9c9720d…).` appended to the comment above; the tuples at `:393` and `:398` → the printed ones, with a new paragraph in the file's style: `// The rate-¼ profile (2026-10-06, docs/07): the rVM proof's Merkle paths are one level shorter at every opened height and the final polynomial sits at height 2^2; toy … → …, busy … → … (was (101460, 6168, 250619, 103468, 24415) and (127322, 7802, 296262, 129722, 30375)).`; phase 5 at `:423`: if it moved, the new pair with one sentence; if not, one sentence saying the blowup does not reach the constraint evaluation.

- [ ] **Step 8: Run the program-side suite**

Run: `RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures cargo test --release --test self_verify --test verifier_key --test verifier --test aggregate --test dsl --test program --test precompiles --test transcript --test binding --test machine --test security --test quotient_layout 2>&1 | grep -E "^test result|FAILED"` → all `ok`, 0 failed.

- [ ] **Step 9: Commit**

```bash
cd ~/rand-worktrees/circuits-rate4
git add recursion/src recursion/tests
git commit -q -m "recursion: the blowup is the shape's — LOG_BLOWUP retired for INNER_LOG_BLOWUP + VerifierShape::log_blowup; replay, tape and the self-verifier read rVM proofs at rate ¼; rVM key caps and self_verify pins re-recorded; the aggregate pins unchanged

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TApVdzvYt8Q8gayscHsdkV"
```

---

### Task 4: The full suite, green

**Files:** none (a gate).

- [ ] **Step 1: Run**

```bash
cd ~/rand-worktrees/circuits-rate4/recursion
RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures cargo test --release --no-fail-fast -- --skip a_one_proof_aggregate_round_trips 2>&1 | tee /tmp/suite-rate4.log | grep -E "^test result|FAILED|panicked" | grep -v "not_panicked"
grep -E "^test result" /tmp/suite-rate4.log | awk '{p+=$4; f+=$6; i+=$8; n++} END {print "binaries",n,"passed",p,"failed",f,"ignored",i}'
```
Expected: `failed 0`; passed ≥ 294 + 4 (docs/06's count plus `security` ×2, `machine` ×2, `shape` ×1 = 299). Record the totals for Task 6.

- [ ] **Step 2: The ignored heavy tests that now fit** — not here (Task 5 decides which to run).

---

### Task 5: Measure — tier 16 and the exit twin after; the test N=2 aggregate if it fits

**Files:**
- Create: `recursion/docs/measurements/2026-10-06-tier16-after.log`, `…-twin-after.log`, and `…-aggregate-n2.log` if run

- [ ] **Step 1: Tier 16 after** — the Task 0 Step 1 command with `-after.log`. Expected: the same `63762 rows, tier 16`; a peak live heap well below Task 0's (every LDE halves; projection ≈ 0.5–0.6×), the prove wall down.

- [ ] **Step 2: The exit twin after** — the Task 0 Step 2 command with `-after.log`. Expected: `== exit twin (tier 18): 169366 rows, …` proved; `prove done: … peak ≈ 14 GB` (projection ≈ 0.5× of Task 0's); verify time within ±20 % of Task 0's (+15 % queries, one level fewer per path); proof bytes.

- [ ] **Step 3: The test N=2 aggregate, if the twin's peak × 2 fits 48 GB** (`docs/06` §3 projected ≈ 52 GB before this phase → ≈ 26 GB now). Find the ignored test: `grep -n "#\[ignore" -A2 tests/aggregate.rs | grep -E "fn |ignore" | head` — the two-proof test-profile aggregate (named like `two_test_profile_…` or `a_two_proof_…`). Run it under the heap profiler if it has one, else plainly with `/usr/bin/time -l` (macOS: `maximum resident set size` is NOT a memory number — record wall and outcome only, and the harness's own figures if the test prints them):
```bash
RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures RAYON_NUM_THREADS=16 \
  cargo test --release --features parallel --test aggregate <the test name> -- --ignored --nocapture 2>&1 | tee docs/measurements/2026-10-06-aggregate-n2.log | tail -5
```
If it is killed by the kernel, keep the log and say so; do not run N=3.

- [ ] **Step 4: Commit the logs**

```bash
cd ~/rand-worktrees/circuits-rate4
git add recursion/docs/measurements/2026-10-06-*after.log recursion/docs/measurements/2026-10-06-aggregate-n2.log 2>/dev/null; git add recursion/docs/measurements/
git commit -q -m "recursion docs: memprofile after the rate-¼ profile — tier-16 synthetic, the exit twin (and the test N=2 aggregate)

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TApVdzvYt8Q8gayscHsdkV"
```

---

### Task 6: Documentation

**Files:**
- Create: `recursion/docs/07-rvm-rate-quarter.md`
- Modify: `recursion/docs/06-phase3-fold-reduce.md` (§7 item 2, lines ~722-738), `recursion/docs/01-rvm-machine.md` (the "≥ 64 GB requirement … withdrawn" paragraph), `research/src/machine.rs:47-60` (`FriProfile` doc), `research/AGENTS.md:21-33` (the rVM paragraph)

- [ ] **Step 1: `docs/07-rvm-rate-quarter.md`** with these sections, every number from Tasks 0–5's logs/reports and `tests/security.rs`'s printed lines:

```markdown
# 07 — The rVM at rate ¼: its own FRI profile, at equal proven security

<one paragraph: what, why (docs/06 §3's LDE terms; §7 item 2), the choice 92/4/24>

## The security argument
<the two theorems (paper's UDR; p3-security's LDR), the table of §0.1 of the spec, then the
REAL-shape numbers `tests/security.rs` printed for (3,80,20) and (2,92,24): paper-UDR, p3 best
proven + what binds, conjectured, legacy; the rule the test pins; why 80/24 was withdrawn>

## What changed
<RvmFri; INNER_LOG_BLOWUP + VerifierShape::log_blowup; the replay/tape/program; the Test profile
also at rate ¼; what did not (inner machine, aggregate programs and digests, rows, tiers)>

## Measured
| | before (phase 3's tree) | after |
|---|---|---|
| tier-16 synthetic: peak live, prove wall, proof bytes | Task 0 | Task 5 |
| exit twin (tier 18): peak live, prove, verify, proof bytes | Task 0 | Task 5 |
| test N=2 aggregate | not run before (≈ 52 GB projected) | Task 5's outcome |
<ratios; the verify-time delta against +15 % queries and −1 level per path>

## What it means for the hardware plan
<docs/06 §3's projection table re-derived with the measured ratio, labelled projections:
production N=1 ≈ 110–130 → ≈ …; N=2, N=4; which host classes>

## What moved
| pin | before | after | where |
<rVM key caps (two), self-verifier digest, CycleReport tuples, phase 5, `RvmShape.num_queries`
92; and the list of pins asserted unchanged>

## Testing
<tests/security.rs (the gate), the machine tests, shape test, the suite count from Task 4>

## Out of scope, recorded
<spec §7>
```

- [ ] **Step 2: Pointers**

`docs/06` §7 item 2: after the sentence ending "the lever for §3's ≈ 110–130 GB, not for the cpu rows." append: " **Done (2026-10-06, `docs/07`):** at 92 queries and 24 grinding bits — equal to 80/8/20 under the paper's unique-decoding theorem (`92 × 0.678 + 24 = 86.4`), not the ~120 queries reasoned above, which is where the field term saturates; measured <twin before → after>."

`docs/01`, the withdrawn-requirement paragraph: append one sentence: "Since `docs/07` the rVM proves at rate ¼ (`machine::RvmFri`): every term in that list halves; the measured twin is <after> GB."

`research/src/machine.rs` `FriProfile` doc (after "Reverted 2026-09-12 on the zk audit's finding ZM1."): "    /// The recursion machine's *own* proofs take `recursion::machine::RvmFri` instead — rate ¼, 92\n    /// queries, 24 grinding bits at Production: the same ~86 proven bits under the same theorem\n    /// (`recursion/docs/07-rvm-rate-quarter.md`); this profile still sizes every inner proof." (Doc comment only — `research/` behaviour unchanged.)

`research/AGENTS.md`, the rVM paragraph (lines 21-33): one sentence recording the rate-¼ profile, the digits, and the measured twin.

- [ ] **Step 3: Commit**

```bash
cd ~/rand-worktrees/circuits-rate4
git add recursion/docs research/src/machine.rs research/AGENTS.md
git commit -q -m "recursion docs: docs/07 — the rVM at rate ¼, the security argument and the measured memory; docs/06 and docs/01 pointers; research's profile doc names RvmFri

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TApVdzvYt8Q8gayscHsdkV"
```

---

### Task 7: The whitepaper amendment (a branch in the whitepapers repository, not pushed)

**Files:** `/Users/dendisuhubdy/Github/randprotocol/whitepapers/randprotocol_implementation.tex` (lines ~136-142 the contribution list; ~755-770 the soundness section; ~780-784 the 80-query remark)

- [ ] **Step 1: Branch**

```bash
cd /Users/dendisuhubdy/Github/randprotocol/whitepapers && git status --short | head -3 && git checkout -b feat/rvm-rate-quarter
```
(If the tree is dirty with another session's work, report BLOCKED rather than committing over it.)

- [ ] **Step 2: Three edits**

1. The contribution item at ~line 138 ("FRI at 80 queries (approximately 86 proven bits, 260 conjectured, …)"): append ", and the aggregate (rVM) proof at rate $1/4$ with 92 queries and 24 grinding bits — the same $\approx 86$ proven bits under the same bound".
2. The soundness section's opening sentence (~757, "The production profile is rate $\rho = 1/8$ …"): after it add a sentence: "The recursion machine's own proofs (the block aggregate, Section~\ref{sec:roadmap}) use rate $\rho = 1/4$, $q = 92$, $g = 24$: by the same bound, $92 \log_2 \tfrac{2}{1.25} + 24 \approx 86.4$ proven bits, equal to the bundle proof's; the rate is halved for the aggregator's memory and the queries and grinding raised to hold the floor (measured in the recursion crate's \code{docs/07})."
3. The remark "The choice of 80 queries" (~780): append one sentence: "The aggregate proof's 92 queries at rate $1/4$ are the same choice made for the other machine: equality with the proven floor, not the conjectured minimum."
Check the document still compiles if a build script exists (`ls *.sh Makefile 2>/dev/null`; the memory notes `pandoc+tectonic` for other docs — if `tectonic` is installed, `tectonic randprotocol_implementation.tex` in a scratch copy; otherwise skip the build and say so).

- [ ] **Step 3: Commit on the branch (not pushed)**

```bash
git add randprotocol_implementation.tex
git commit -q -m "implementation: the aggregate (rVM) proof's FRI profile — rate 1/4, 92 queries, 24 grinding bits, the same ≈ 86 proven bits under the stated bound

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TApVdzvYt8Q8gayscHsdkV"
git checkout main
```
Report the branch name; publishing is the operator's.

---

### Task 8: Fullnode follow-through (after the circuits branch is merged to `main` and `main` is pushed to the `randprotocol` remote — phase 3's commits included)

**Precondition:** circuits `main` contains this branch and is on `org`; record its sha as `<PIN>`. Worktree: `git -C ~/Github/randprotocol/fullnode worktree add ~/rand-worktrees/fullnode-rate4 -b feat/rvm-rate-quarter-vendor main` (fullnode `main` may carry other sessions' merges; base on whatever `origin/main` is).

- [ ] **Step 1: Re-vendor**

```bash
cd ~/rand-worktrees/fullnode-rate4
RVM_SRC=~/Github/randprotocol/circuits/recursion deploy/sync-zkvm.sh ~/Github/randprotocol/circuits/research 2>&1 | tail -3
sed -i '' "s/^  CIRCUITS_PIN: .*/  CIRCUITS_PIN: <PIN>/" .github/workflows/ci.yml
```
If the sync refuses because `<PIN>` is not on a remote-tracking branch, fetch first (`git -C ~/Github/randprotocol/circuits fetch org`). If `rand-zkvm-cuda/` changed between the current `rev` and `<PIN>` the script says so; otherwise pass `CUDA_REV=<the current rev>` as the quotient-layout re-vendor did (`AGENTS.md` records that split). Update `deploy/sync-zkvm.sh`'s recursion-section history and echo to name `<PIN>` and the rate-¼ profile.

- [ ] **Step 2: Gates**

```bash
cargo build --release --workspace 2>&1 | tail -1
RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures cargo test --release -p randprotocol-rvm --no-fail-fast -- --skip round_trips --skip two_test_profile 2>&1 | grep -E "^test result" | awk '{p+=$4; f+=$6} END {print "passed",p,"failed",f}'
cargo test --release -p randprotocol-zkvm --test guest_provenance 2>&1 | grep "^test result"
RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures cargo test --release -p randprotocol-node agg_executor 2>&1 | grep "^test result" | head -1
```
Expected: `failed 0`; guest_provenance 14; agg_executor all passed (the aggregate program digest and admission vectors did not move; `admitted_tiers` untouched). The node's `warm_aggregation` log line, if a test prints it, shows a faster key build.

- [ ] **Step 3: Docs** — `docs/node-hardware.md` §4 (the measured twin and the re-projection; the aggregator's host class), `docs/compute-optimization.md` §4.1 (landed) and §4.4 (the ≤ 64 GB row: production N=1 projected ≈ …), `docs/aggregation.md` (one paragraph: a chain's `fri_profile` name binds the inner 80/8/20 and the rVM's 92/4/24, both constants of the vendored constraint set; the proven floor is the same ≈ 86 bits), `docs/cli.md`/`docs/rpc.md` where `fri_profile` is described (one clause), `AGENTS.md` (the top paragraph).

- [ ] **Step 4: Commit** with the two trailer lines; report the branch for merge and push.

---

## Self-review notes (done while writing)

- Spec §0.1 (the argument) → Task 1 (the gate) and Task 6 (docs/07); §1.1 → Task 2; §1.2–1.3 → Task 3; §1.4 (keys, refusal, node) → Task 3 Step 7, Task 2 Step 1's refusal test, Task 8; §2 → Tasks 1–3; §3 (governance) → Tasks 6, 7, 8; §4 (tests) → Tasks 1–4 (item 5's "assert before re-pin" is Task 3 Step 1 and Step 6); §5 (measurement) → Tasks 0, 5; §6 → Tasks 6, 8; §7 → docs/07 in Task 6.
- Names: `RvmFri { log_blowup, num_queries, query_pow_bits }`, `RvmFri::of`, `Machine::with_fri`, `INNER_LOG_BLOWUP`, `VerifierShape::log_blowup`, `fri_schedule(degree_bits, log_blowup)`, `fri_schedule_for_tests` — defined in Tasks 2–3, used by name afterwards.
- Review Focus 1 → Task 2 Step 1; 2 → Task 3 Steps 2 and 6; 3 → Task 3 Steps 5–6; 4 → Task 4; 5 → Task 3 Step 6.
- One known unknown the plan handles explicitly: if Task 1's real-shape report wants a digit other than (2, 92, 24), Task 1 Step 3 says how, and the controller amends the spec before Task 2.
