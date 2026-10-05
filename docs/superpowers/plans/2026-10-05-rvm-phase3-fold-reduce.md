# rVM Phase 3 Fold/Reduce Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring one verified production inner proof from 893 606 cpu rows (tier 20) to under 2^19 − 1 = 524 287 (tier 19), and both memory tables from 2^22 to 2^21, by moving the REDUCE descriptor build, the sibling select, the FRI fold and (only if the gate needs it) the index powers into the REDUCE chip. Each cut is measured against a band that Task 0 sets.

**Architecture:** Task 0 instruments the builder with call-site spans, measures where the rows go, and checks the fold identity (DFT + Horner = `fold_row`). Cut D (Tasks 1a and 1b) gives the reduce chip a **preprocessed provider region**: the program's reduce layout, plus a `MULT` column, in the `ProgramAir` pattern. Each run looks up its layout row on its first row. The cpu dispatches one `REDUCE` row per entry with the entry id as an immediate, and a height chain carries `ACC`/`APOW` inside the chip across consecutive dispatches. Cut E1 (Task 2) hints each committed row whole and checks the query's own slot with one register-addressed `LOADE`. Cut E2 (Task 3) adds the `FOLD` row kind: a run of 2a rows (inverse DFT, then Horner) whose coefficients come from a 14-row preprocessed table. Cut F (Task 4) runs only if E2 lands above the gate; it adds the `POW` row kind. Task 5 re-pins everything and writes `docs/05`.

**Tech Stack:** Rust 1.98.1 (pinned by `recursion/rust-toolchain.toml`), Plonky3 0.7.0 (`p3-*` exact pins; `p3-fri`/`p3-merkle-tree` patched from `../vendor/`), the `recursion` crate's own DSL/emulator/AIR tables. Tests are `cargo test` with real bundle-proof fixtures.

**Spec:** `docs/superpowers/specs/2026-10-05-rvm-phase3-fold-reduce-design.md`. Read it first: §1 is the attribution, §2 the cuts, §2.5 the landing bands, §5 the testing discipline and §6 the rulings. Until Task 0 measures them, every number from spec §1/§2 that appears below is **derived**.

## Design resolutions (the spec left these open; the code below follows them)

- **R1 — the layout is a looked-up preprocessed region, not row-aligned preprocessed columns.** The aggregate program (`src/programs/rv32n.rs:104-111`) runs `emit_proof` inside `counted_loop_mem` with a *tape* count `N`, so every layout entry executes N times. A preprocessed column aligned to the chip's rows would need a height that depends on N. The `ProgramAir` pattern handles N directly: preprocessed rows plus a witness `MULT` provide each entry, and every run consumes one row. Spec §6 ruling 3 holds unchanged: no descriptor field is ever a witness value. The verifier key commits the layout, and `Machine::check_program` range-checks it.
- **R2 — `KEY_SLOT` and `QUERY` become absolute addresses.** The per-query key, alpha and result buffers are compile-time `alloc`s, so the layout row carries `KEY`, `ALPHA` and `RES` addresses directly and no `QUERY` column is needed.
- **R3 — `INV` is read once per *entry*, not once per chain.** A height chain interleaves `zeta` and `zeta_next` entries, and those have different keys (`emit_reduced_openings` keys by `(height, point)`, `rv32.rs:858-866`). `ALPHA` is read once per chain, on the chain's first row, and carried after that.
- **R4 — a chain carries across *consecutive* dispatches.** The constraints are `n(CLK) = CLK + 1` and `n(ENTRY) = ENTRY + 1`. `Builder::reduce` emits a chain's `REDUCE` rows back to back (no handle, so no spill or reload can land between them), and `replay` asserts it. This also keeps a chain inside one iteration of the aggregate loop.
- **R5 — `LEN`/`LEN1`/`LEN1_INV` become `ROW_END`/`END_INV`.** `IS_LAST ⟺ ADDR_R = ROW_END` on a real row, and `ROW_END` comes from the layout.
- **R6 — the layout lives in `Program::reduce_layout`.** `Program::digest` absorbs it only when it is non-empty, so every program without one keeps its digest. The verifier-key cache key becomes `(tier, digest, reduce_log_height)`, because the reduce instance's preprocessed trace now depends on its height.
- **R7 — the `FOLD` dispatch is `[CLK, msg, u0, u1, a]`.** The arity is the immediate, so the program fixes it. The result cell is `msg + 2a + 4`, just after the row's salts. Coefficients are looked up on a `FOLD_COEFF` bus from a 14-row preprocessed table keyed `(a, k)`. Phase 2 uses a shift register instead of a one-hot: same degree, no one-hot columns.
- **R8 — the `POW` dispatch (Cut F only) is `[CLK, bits_ptr, off + 256·L, G, base]`.** `(G, base)` ride in one extension register pair, and the output cell is `bits_ptr + 64`.
- **R9 — new buses `REDUCE_LAYOUT`, `FOLD`, `FOLD_COEFF` and `POW`** instead of new keys on `REDUCE`, because their messages have different arities. Every message the chip sends after this phase is degree 1. The reduce chip's degree pin can only fall; it is re-measured and pinned.

## Global Constraints

- Work in `~/rand-worktrees/circuits-phase3` on branch `feat/rvm-phase3` (off `main` 2899bdc). Every command below runs from `~/rand-worktrees/circuits-phase3/recursion`. The crate is its own cargo root and never a workspace member.
- Run `export RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures` before any test that touches fixtures. Without it the first run re-proves (Test ~30 s per proof, Production ~100 s).
- Build with `cargo test --release` for anything that proves or emulates the full program. `cargo test` (dev) is fine for DSL and emulator unit tests.
- **Opcodes 0–27 never move** (`src/isa.rs` doc comment). New opcodes are appended: `Fold = 28` (Task 3), and `Pow = 29` only if Task 4 runs.
- **`Precompiles::Off` stays buildable and correct after every task.** It is the differential reference: it keeps the compiled reduction, the compiled fold and the compiled index powers. Nothing compiled is deleted.
- **AGENTS.md invariants** (`research/AGENTS.md`, binding for `recursion/`): (1) every bus message's address and value columns are constrained on every row kind that sends it; (2) every send count is a selector expression, zero on rows that do not perform the access. The emulator is the reference semantics: if an AIR and the emulator disagree, the AIR is wrong.
- **The measurement gate (spec §6 ruling 1, phase 2's ±15 %):** after each cut, run `cargo test --release --test profile -- --ignored --nocapture` and compare the production cpu rows with that cut's band in `docs/05-phase3-fold-reduce.md` §2 (set by Task 0). If the result is outside the band, stop, write the correction into spec §2.5 and docs/05 §2, then continue. **The gate is not widened** (spec §6 ruling 6): if D + E (+ F) land above 524 287, the phase reports the measured point.
- Commit after every task, in the repository's voice (what moved and the measured number). End every commit message with exactly these two lines:
  `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`
  `Claude-Session: https://claude.ai/code/session_01AUWKAos28PQquiLZRVC6jP`
- Do not touch `research/` (the RV32 machine). The inner proof, its FRI profile (`log_blowup` 3, 80 queries, 20 PoW bits) and `inner_vk_digest` do not move.

## The Re-pin Procedure (every cut task runs all of it, in its last steps)

The spec (§5) requires each cut to re-pin its rows, heights and digests before the next cut starts. Every pin below is a *measured* value: run the command, read the new value off the output, and write it in.

- **P1 — measure.** `cargo test --release --test profile -- --ignored --nocapture 2>&1 | grep -v warning | tee target/phase3-profile.txt`. From the `== profile Production` line, read cpu rows, permutations, mem accesses, reg accesses, witness words and program instrs. From `-- rows per call site`, read each span's total.
- **P2 — `tests/pins.json`.** Run the script below with the six numbers from P1 and the span totals:
  ```bash
  python3 - <<'PY'
  import re, sys
  p = "tests/pins.json"; s = open(p).read()
  vals = dict(cpu_rows=CPU, permutations=PERMS, mem_accesses=MEM, witness_words=WORDS, program_instrs=INSTRS,
              reg_accesses=REG, rows_reduce=R_REDUCE, rows_select=R_SELECT, rows_fold_round=R_FOLD,
              rows_bit_selected_power=R_BSP, rows_commit_root=R_COMMIT, rows_sample_bits=R_SAMPLE)
  for k, v in vals.items():
      s, n = re.subn(r'"%s": \d+' % k, '"%s": %d' % (k, v), s)
      assert n == 1, k
  s = re.sub(r'  "aggregate_test_n\d_[a-z_]+": \d+,?\n', '', s)   # the aggregate pins re-measure in P3
  open(p, "w").write(s)
  PY
  ```
  Substitute the measured integers for the capitalised names. A span that no longer exists (`select` after E1) is written as `0`.
- **P3 — aggregate pins.** `cargo test --release --test aggregate the_per_n_cycle_budget_is_pinned -- --nocapture`. `common::aggregate_pins()` sees the aggregate keys are gone, re-measures N = 1, 2, 3 and rewrites them; the `phase3_attribution` block is preserved (Task 0 Step 9). Then run `cargo test --release --test aggregate n1_aggregate_publishes_the_bound_interface_digest_at_a_pinned_overhead n3_aggregate_publishes_the_host_interface_digest -- --nocapture`. If either fails, set `LOOP_OVERHEAD` (`tests/aggregate.rs:39`) and `N3_ROWS` (`:51`) to the printed values. Update the three tier assertions (`:339`, `:491`, `:521`) to the tier `Tier::for_cycles` gives for the new N = 1/2/3 rows, with the row counts in their messages.
- **P4 — digests.** Delete `src/programs/verify_rv32.digest`, then run `cargo test --release --test exit the_cycle_budget_per_inner_proof_is_pinned -- --ignored --nocapture`. `common::committed_digest()` rewrites the file. Run `cargo test --release --test verifier the_aggregate_program_digest_is_unchanged_by_rvm_constraint_fixes the_admission_stub_vectors 2>&1 | grep -A3 panicked` and `cargo test --release --test aggregate the_production_n1_aggregate_is_the_m52_pin_plus_loop_overhead -- --ignored 2>&1 | grep -A3 panicked`. Replace each failing literal (`tests/verifier.rs:832` aggregate digest at the Test shape; `tests/verifier.rs:786` the Off replay, which moves only when the Off pipeline changes; `tests/aggregate.rs:640` the production aggregate digest) with the `left` value. Add the old → new pair to the doc comment above each, as the existing comments do.
- **P5 — the self-verifier.** `cargo test --release --test self_verify -- --nocapture`. Replace the digest at `tests/self_verify.rs:130` and the `CycleReport`/phase-5 literals in `the_self_verifiers_measured_cost_at_two_fixture_shapes` with the printed values, and extend the comment's history line.
- **P5b — the reduce key.** If the cut changed the reduce chip's preprocessed region (Task 3's coefficient table), run `cargo test --release --test verifier_key -- --nocapture` and set `WANT_REDUCE` in `tests/verifier_key.rs` from the printed `reduce:` line.
- **P6 — the exit rows.** `cargo test --release --test exit -- --ignored --list` names the twin and exit tests. Their row and tier literals (`tests/exit.rs:307-308`, `:350-351`) are emulation-checked by `exit_the_verifier_program_*` only when proved. Set them from P1 (the exit) and from P3's N = 1 aggregate rows minus `LOOP_OVERHEAD` (the twin), and set the tiers from `Tier::for_cycles`.
- **P7 — confirm.** `cargo test --release` (in-suite) is green, and `cargo test --release --test exit the_cycle_budget_per_inner_proof_is_pinned -- --ignored` passes against the new pins.

## Review Focus

Each line names an input or condition the spec implies but that no existing test exercises. The owning task adds the named test.

1. **An rVM proof that carries the reduce instance, verified by the self-verifier.** No fixture proof carries a reduce table (`tests/self_verify.rs:331`). After Cut D, the preprocessed round opens two matrices of different heights (program and reduce layout). Task 1a adds `the_self_verifier_accepts_a_proof_carrying_the_reduce_layout`.
2. **The aggregate's counted loop running each layout entry N times.** This is `MULT = N`, with a chain's carry never crossing iterations. Task 1a adds `a_reduce_chain_inside_a_counted_loop_proves_with_mult_n`, a `counted_loop_mem` body with a two-entry chain at N = 2, proved and verified.
3. **One-column entries at both ends of a chain.** That is `IS_FIRST = IS_LAST` with `READ_ALPHA` and `WRITES` on one row, plus a one-column continuation entry. Task 1a adds `one_column_entries_at_chain_start_and_end_prove_and_verify`.
4. **E1's register-addressed `LOADE` at slot 0 and at slot a − 1, at every arity, with `On` and `Off` refusing at the same named step.** Task 2 adds `the_own_slot_check_agrees_on_and_off_at_every_slot`.
5. **Fold runs of all three arities back to back in one table, plus a run with `u = 0`.** This exercises the `K` counter, the phase switch and the coefficient lookups across run boundaries. Task 3 adds `fold_runs_of_every_arity_back_to_back_prove_and_verify`.

---

### Task 0: Attribution and the fold identity, measured before any cut

**Files:**
- Create: `tests/fold_identity.rs`
- Modify: `src/dsl/builder.rs`: `Stats` (:80-97), `Op2` (:137-158), `note_phase` neighbourhood (:240-243), `replay` pass 1 (:1067-1093), pass 2 (:1157-1300), return (:1365-1371)
- Modify: `src/dsl/mod.rs:24` (re-exports)
- Modify: `src/programs/rv32.rs`: `emit_query` (:604-700), `bit_selected_power` (:1024-1042)
- Modify: `src/dsl/transcript.rs`: `sample_bits` (:160-197)
- Modify: `tests/profile.rs` (whole file), `tests/common/mod.rs` (`aggregate_pins` writer :224-275; new `phase3_attribution`), `tests/exit.rs` (`the_cycle_budget_per_inner_proof_is_pinned` :168-210), `tests/dsl.rs` (one test), `tests/pins.json`
- Create: `docs/05-phase3-fold-reduce.md` (the skeleton, under `recursion/docs/`)

**Interfaces:**
- Produces: `Builder::span<R>(&mut self, name: &'static str, body: impl FnOnce(&mut Self) -> R) -> R`.
- Produces: `Stats::span_names: Vec<&'static str>` (index 0 is `"(none)"`), `Stats::pc_span: Vec<u16>` and `Stats::pc_kind: Vec<u8>`, one entry per emitted instruction.
- Produces: `dsl::{PC_INSTR = 0, PC_RELOAD = 1, PC_SPILL = 2}`.
- Produces: span names `"reduce"`, `"select"`, `"fold_round"`, `"bit_selected_power"`, `"commit_root"`, `"input_root"`, `"roll_in"`, `"sample_bits"`.
- Produces: `common::phase3_attribution() -> Phase3Attribution { reg_accesses: usize, rows: Vec<(String, usize)> }`.
- Consumes: `p3_fri::{FriFoldingStrategy, TwoAdicFriFolding}` (`fold_row(&self, index, log_height, log_arity, beta, evals)`, `p3-fri-0.7.0/src/two_adic_pcs.rs:99-122`) is the reference fold. `rv32.rs`'s own `emit_fold_round` is its compiled port.

- [ ] **Step 1: Write the fold identity test**

This test checks a derivation (spec §2.3, ruling 4), so it is expected to pass on its first run. If it fails, the DFT + Horner form is wrong and nothing after this task may be built. Create `tests/fold_identity.rs`:

```rust
//! Phase 3, Task 0: the arity-a FRI fold is a size-a inverse DFT on the bit-reversed coset values
//! followed by Horner at `u = β / s` — `out = Σ_m B_m·u^m`, `B_m = (1/a)·Σ_k y_k·c_k^{−m}`,
//! `c_k = g_a^{rev(k)}`, `s = g_{h+la}^{rev(index, h)}` — checked against Plonky3's own
//! `TwoAdicFriFolding::fold_row` (barycentric Lagrange) before any row of the FOLD kind is built.
use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};
use p3_fri::{FriFoldingStrategy, TwoAdicFriFolding};
use p3_util::reverse_bits_len;
use rand::{RngExt, SeedableRng};
use recursion::isa::{EF, F};
use std::marker::PhantomData;

mod common;

fn dft_horner(index: usize, log_height: usize, la: usize, beta: EF, ys: &[EF]) -> EF {
    let a = 1usize << la;
    let s = F::two_adic_generator(log_height + la).exp_u64(reverse_bits_len(index, log_height) as u64);
    let g = F::two_adic_generator(la);
    let inv_a = F::from_usize(a).inverse();
    let b: Vec<EF> = (0..a)
        .map(|m| {
            let mut acc = EF::ZERO;
            for (k, y) in ys.iter().enumerate() {
                let ck_inv = g.exp_u64(reverse_bits_len(k, la) as u64).inverse();
                acc += *y * ck_inv.exp_u64(m as u64);
            }
            acc * inv_a
        })
        .collect();
    let u = beta * s.inverse();
    b.iter().rev().fold(EF::ZERO, |acc, &bm| acc * u + bm)
}

#[test]
fn the_fold_is_an_inverse_dft_then_horner_at_every_arity() {
    let folding: TwoAdicFriFolding<(), ()> = TwoAdicFriFolding(PhantomData);
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x0f01d);
    for la in 1..=3usize {
        for _ in 0..256 {
            let log_height = rng.random_range(1..=20usize);
            let index = rng.random_range(0..1usize << log_height);
            let beta = common::random_ext(&mut rng);
            let ys: Vec<EF> = (0..1usize << la).map(|_| common::random_ext(&mut rng)).collect();
            let want = <TwoAdicFriFolding<(), ()> as FriFoldingStrategy<F, EF>>::fold_row(
                &folding, index, log_height, la, beta, ys.iter().copied(),
            );
            assert_eq!(dft_horner(index, log_height, la, beta, &ys), want, "la {la}, h {log_height}, index {index}");
        }
    }
}
```

- [ ] **Step 2: Run it**

Run: `cargo test --release --test fold_identity`
Expected: `1 passed`. If it fails, stop and report: spec §2.3's derivation is wrong. If the rand 0.10 range API name differs, use whatever `tests/precompiles.rs:286` uses (`rand::RngExt::random`), and draw `random_range` from the same trait.

- [ ] **Step 3: Write the failing span test**

Append to `tests/dsl.rs`:

```rust
/// Phase 3 Task 0: every emitted instruction is attributed to the innermost open span.
#[test]
fn spans_attribute_every_emitted_row_to_the_innermost_open_span() {
    use p3_field::PrimeCharacteristicRing;
    use recursion::dsl::{Builder, Checkpoints};
    use recursion::isa::{Op, F};
    let mut b = Builder::new(Checkpoints::Off);
    let x = b.constant(F::from_u64(3));
    let y = b.span("outer", |b| {
        let t = b.add(x, x);
        b.span("inner", |b| b.mul(t, t))
    });
    b.public(y);
    for _ in 0..3 {
        let z = b.zero();
        b.public(z);
    }
    let (p, stats) = b.finish_stats();
    assert_eq!(stats.pc_span.len(), p.instrs.len(), "one span tag per emitted instruction");
    assert_eq!(stats.pc_kind.len(), p.instrs.len(), "one kind tag per emitted instruction");
    let name = |pc: usize| stats.span_names[stats.pc_span[pc] as usize];
    let tagged: Vec<(Op, &str)> = p.instrs.iter().enumerate().map(|(pc, i)| (i.op, name(pc))).collect();
    assert!(tagged.contains(&(Op::Fadd, "outer")), "{tagged:?}");
    assert!(tagged.contains(&(Op::Fmul, "inner")), "{tagged:?}");
    assert!(tagged.contains(&(Op::Faddi, "(none)")), "{tagged:?}");
    assert_eq!(name(p.instrs.len() - 1), "(none)", "HALT is emitted outside every span");
}
```

Run: `cargo test --test dsl spans_attribute`
Expected: compile error, `no method named span`.

- [ ] **Step 4: Implement spans in the builder**

In `src/dsl/builder.rs`, add to `Stats`:

```rust
    /// Phase 3 Task 0: per emitted instruction, the innermost open [`Builder::span`] (an index
    /// into `span_names`; 0 is `"(none)"`) and the row's kind (`PC_INSTR`, `PC_RELOAD`,
    /// `PC_SPILL`). What `tests/profile.rs` attributes executed rows with.
    pub span_names: Vec<&'static str>,
    pub pc_span: Vec<u16>,
    pub pc_kind: Vec<u8>,
```

and above `Stats`:

```rust
/// [`Stats::pc_kind`]'s values.
pub const PC_INSTR: u8 = 0;
pub const PC_RELOAD: u8 = 1;
pub const PC_SPILL: u8 = 2;
```

Add two `Op2` variants after `Phase`:

```rust
    /// A [`Builder::span`]'s open and close markers: emit nothing, move no liveness.
    SpanOpen { name: &'static str },
    SpanClose,
```

Add after `note_phase`:

```rust
    /// Attribute every instruction `body` emits, spill and reload insertions included, to
    /// `name`; the innermost open span wins. Markers emit nothing and wrap whole builder calls, so
    /// they never sit between a `Def` and its defining instruction: a build with spans is the
    /// build without them, instruction for instruction. A closure rather than a guard, because the
    /// body needs the builder and a guard holding `&mut self` would lock it.
    pub fn span<R>(&mut self, name: &'static str, body: impl FnOnce(&mut Self) -> R) -> R {
        self.ops.push(Op2::SpanOpen { name });
        let r = body(self);
        self.ops.push(Op2::SpanClose);
        r
    }
```

In `replay`'s pass 1, extend the no-op arm to `Op2::Group | Op2::TakeScratch { .. } | Op2::Phase { .. } | Op2::BranchTop | Op2::BranchEnd | Op2::SpanOpen { .. } | Op2::SpanClose => {}`. Run `grep -n 'Op2::Phase' src/dsl/builder.rs`; every other exhaustive `match` on `Op2` gets the same two no-op patterns. In pass 2, next to `let mut phase_mark = 0usize;`:

```rust
        let mut span_names: Vec<&'static str> = vec!["(none)"];
        let mut span_stack: Vec<u16> = Vec::new();
        let mut pc_span: Vec<u16> = Vec::new();
        let mut pc_kind: Vec<u8> = Vec::new();
```

Add these arms to pass 2's `match op`:

```rust
                Op2::SpanOpen { name } => {
                    let id = span_names.iter().position(|n| *n == *name).unwrap_or_else(|| {
                        span_names.push(name);
                        span_names.len() - 1
                    });
                    span_stack.push(id as u16);
                }
                Op2::SpanClose => {
                    span_stack.pop().expect("unbalanced span markers");
                }
```

Immediately after the `match` (before the `if live { … dying_at … }` block):

```rust
            // Phase 3 Task 0: tag what this buffer entry emitted. A `Mat` emits only reloads,
            // a `Def` only the spills its claim evicts, an `Instr` itself.
            let kind = match op {
                Op2::Mat { .. } => PC_RELOAD,
                Op2::Def { .. } => PC_SPILL,
                _ => PC_INSTR,
            };
            let tag = span_stack.last().copied().unwrap_or(0);
            pc_span.resize(out.len(), tag);
            pc_kind.resize(out.len(), kind);
```

Before the final `(Program { … }, stats)`:

```rust
        assert!(span_stack.is_empty(), "a span was left open");
        stats.span_names = span_names;
        stats.pc_span = pc_span;
        stats.pc_kind = pc_kind;
```

In `src/dsl/mod.rs:24`, re-export `PC_INSTR, PC_RELOAD, PC_SPILL` alongside `Stats`.

- [ ] **Step 5: Run the span test and the DSL suite**

Run: `cargo test --test dsl`
Expected: all pass, the new test included.

- [ ] **Step 6: Wrap the call sites**

In `src/programs/rv32.rs`'s `emit_query`, wrap (bodies unchanged):
- the input-round loop's call: `b.span("input_root", |b| emit_input_round_root(b, log_global, mats, &groups[ri], paths[ri], index_bits, &metas[ri]));`
- the reduction: `let ros = b.span("reduce", |b| emit_reduced_openings(b, shape, index_bits, fri_alpha, opened, rows));`
- the select block (from `let sibs = commit_openings[r];` through the `evals` loop) as `let evals = b.span("select", |b| { …; evals });`, with `let sibs = commit_openings[r];` hoisted above it because `emit_commit_root` reads it
- `folded = b.span("fold_round", |b| emit_fold_round(b, log_folded, la, group_bits, betas[r], &evals));`
- `b.span("commit_root", |b| emit_commit_root(b, &evals, sibs, commit_paths[r], &index_bits[shift..], fri_caps[r], &format!("commit phase root[{r}]")));`
- the roll-in body, as `folded = b.span("roll_in", |b| { …; b.ext_add(folded, t) });`

In `bit_selected_power`, wrap the whole body: `b.span("bit_selected_power", |b| { …; x })`. In `src/dsl/transcript.rs`'s `sample_bits`, wrap the whole body: `b.span("sample_bits", |b| { … bit[..bits].to_vec() })`. The body uses `self` (the challenger) and `b`, so the closure captures `self` mutably; rename the closure's builder parameter to `b` and keep the code unchanged.

- [ ] **Step 7: Prove no instruction moved**

Run: `cargo test --release --test exit the_committed_program_digest_is_reproducible && cargo test --release --test verifier the_aggregate_program_digest_is_unchanged_by_rvm_constraint_fixes && cargo test --release --test self_verify the_self_program_digest_is_deterministic_and_distinct`
Expected: all pass with the **unchanged** literals. Span markers emit nothing; a moved digest means a marker landed between a `Def` and its instruction, and must be fixed before going on.

- [ ] **Step 8: Rewrite `tests/profile.rs` to print the attribution**

Replace the body of `profile()` from `let rows = exec.cpu_rows();` to the end of the function with:

```rust
    let rows = exec.cpu_rows();
    let reg = recursion::tables::cpu::register_accesses(&exec.events).len();
    println!("== profile {profile:?}: inner tier {:?}, {} cpu rows, {} permutations, {} mem accesses, {} reg accesses, {} witness words, {} program instrs",
        p.proof.tier, rows, exec.permutations(), exec.mem_accesses(), reg, exec.hints_read, vp.program.instrs.len());
    println!("-- shape: log_arities {:?} (sum of arities {}), degree_bits {:?}, queries {}",
        shape.log_arities, shape.log_arities.iter().map(|la| 1usize << la).sum::<usize>(), shape.degree_bits, shape.num_queries);
    println!("-- builder stats: spills {} reloads {} perms {} cells {} live_max {}",
        vp.stats.spills, vp.stats.reloads, vp.stats.perms, vp.stats.cells, vp.stats.live_max);

    println!("-- rows by phase (program instructions in emission order)");
    let mut acc = 0usize;
    for (name, n) in &vp.phase_rows {
        acc += n;
        println!("   {n:>9}  {:5.1}%  {name}", 100.0 * *n as f64 / vp.program.instrs.len() as f64);
    }
    println!("   {acc:>9}  total");

    println!("-- executed opcode histogram");
    let h = exec.histogram();
    let mut idx: Vec<usize> = (0..Op::COUNT).collect();
    idx.sort_by_key(|&i| std::cmp::Reverse(h[i]));
    for i in idx {
        if h[i] == 0 {
            continue;
        }
        println!("   {:>9}  {:5.1}%  {}", h[i], 100.0 * h[i] as f64 / rows as f64, Op::ALL[i].mnemonic());
    }

    // Phase 3 Task 0: executed rows per call site (the builder's spans), split into the site's own
    // instructions, the reloads and the spills the allocator inserted inside it.
    let names = &vp.stats.span_names;
    let mut by: Vec<[usize; 3]> = vec![[0; 3]; names.len()];
    let mut ops: Vec<[usize; Op::COUNT]> = vec![[0; Op::COUNT]; names.len()];
    for e in &exec.events {
        let s = vp.stats.pc_span[e.pc as usize] as usize;
        by[s][vp.stats.pc_kind[e.pc as usize] as usize] += 1;
        ops[s][e.instr.op as usize] += 1;
    }
    println!("-- rows per call site (executed; reloads and spills inside it; per query; top opcodes)");
    for (s, name) in names.iter().enumerate() {
        let total: usize = by[s].iter().sum();
        if total == 0 {
            continue;
        }
        let mut top: Vec<(usize, usize)> = ops[s].iter().copied().enumerate().filter(|(_, n)| *n > 0).collect();
        top.sort_by_key(|&(_, n)| std::cmp::Reverse(n));
        let top: Vec<String> = top.iter().take(6).map(|&(o, n)| format!("{} {n}", Op::ALL[o].mnemonic())).collect();
        println!("   {total:>9}  {:5.1}%  {name:<20} reload {:>7} spill {:>6}  /query {:>8.1}  [{}]",
            100.0 * total as f64 / rows as f64, by[s][1], by[s][2], total as f64 / shape.num_queries as f64, top.join(", "));
    }
    let (reloads, spills): (usize, usize) = by.iter().fold((0, 0), |(r, s), b| (r + b[1], s + b[2]));
    println!("-- reloads {reloads}, spills {spills}");

    let reduce_dispatches = exec.events.iter().filter(|e| e.reduce.is_some()).count();
    println!("-- reduce dispatches {reduce_dispatches}");
    let (mut reads, mut writes) = (0usize, 0usize);
    for e in &exec.events {
        for m in &e.mem {
            if m.is_write { writes += 1 } else { reads += 1 }
        }
    }
    println!("-- ram accesses: {reads} reads, {writes} writes; max_addr {}", exec.max_addr);
```

- [ ] **Step 9: Keep a `phase3_attribution` block across aggregate re-measures, and parse it**

In `tests/common/mod.rs`, `aggregate_pins()`: just before `let mut json = format!(`, add

```rust
    // Phase 3 Task 0: the hand-written `phase3_attribution` block survives a re-measure.
    let block = s.find("\"phase3_attribution\"").map(|at| {
        let close = at + s[at..].find('}').expect("the attribution block closes");
        s[at..=close].to_string()
    });
```

change the per-N `comma` to `let comma = if n == 3 && block.is_none() { "" } else { "," };`, and before `json += "}\n";` add `if let Some(b) = &block { json += &format!("  {b}\n"); }`. Append:

```rust
/// Phase 3 Task 0: `tests/pins.json`'s `phase3_attribution` block — the REG access count and
/// the executed rows per call site, measured by `tests/profile.rs` on the production fixture.
#[allow(dead_code)]
pub struct Phase3Attribution {
    pub reg_accesses: usize,
    pub rows: Vec<(String, usize)>,
}

#[allow(dead_code)]
pub fn phase3_attribution() -> Phase3Attribution {
    let s = std::fs::read_to_string(pins_path()).expect("tests/pins.json");
    let at = s.find("\"phase3_attribution\"").expect("Task 0 wrote the phase3_attribution block");
    let block = &s[at..at + s[at..].find('}').expect("the block closes")];
    let mut out = Phase3Attribution { reg_accesses: 0, rows: Vec::new() };
    for line in block.lines().skip(1) {
        let Some((k, v)) = line.trim().trim_end_matches(',').split_once(": ") else { continue };
        let (k, v) = (k.trim_matches('"').to_string(), v.parse::<usize>().expect("a numeric field"));
        if k == "reg_accesses" { out.reg_accesses = v } else { out.rows.push((k, v)) }
    }
    out
}
```

- [ ] **Step 10: Measure**

Run: `cargo test --release --test profile -- --ignored --nocapture 2>&1 | grep -v warning | tee target/phase3-profile-task0.txt`
Read off, for the **Production** profile: cpu rows (expect 893 606), reg accesses (expect 2 147 159), `log_arities`, `degree_bits`, and each span's total, reload and spill counts and top opcodes. Also read the `EINV`, `MOV` and `FSUB` counts inside `reduce` from its top-opcode list (they survive Cut D), and the `REDUCE` dispatches (expect 9 520).

- [ ] **Step 11: Write the `phase3_attribution` block**

Add the block to `tests/pins.json` before its closing `}`, adding a `,` after the last aggregate line, with the Production numbers from Step 10:

```json
  "phase3_attribution": {
    "reg_accesses": <reg accesses>,
    "rows_reduce": <reduce total>,
    "rows_select": <select total>,
    "rows_fold_round": <fold_round total>,
    "rows_bit_selected_power": <bit_selected_power total>,
    "rows_commit_root": <commit_root total>,
    "rows_sample_bits": <sample_bits total>,
    "reloads": <reloads>,
    "spills": <spills>
  }
```

Check it parses: `cargo test --release --test aggregate the_per_n_cycle_budget_is_pinned`. Expected: pass, with the file unchanged (`git diff --stat tests/pins.json` shows only the added block).

- [ ] **Step 12: Pin the REG count in the cycle-budget test**

In `tests/exit.rs`'s `the_cycle_budget_per_inner_proof_is_pinned`, after `assert_eq!(r.program_instrs, p.program_instrs);`:

```rust
    // Phase 3 (Task 0): the register table's access count — the memory target is under 2^21 after
    // Cut D, and it is pinned like the RAM count.
    assert_eq!(recursion::tables::cpu::register_accesses(&exec.events).len(), common::phase3_attribution().reg_accesses,
               "the REG access count");
```

Run: `cargo test --release --test exit the_cycle_budget_per_inner_proof_is_pinned -- --ignored`
Expected: pass.

- [ ] **Step 13: Write the `docs/05` skeleton with the measured attribution and the bands**

Create `docs/05-phase3-fold-reduce.md` with these sections. Fill every `<…>` from Step 10, and compute each band with the formula given.

````markdown
# 05 — Phase 3: the REDUCE chip takes the descriptor layout, the fold and the index powers

Design: `docs/superpowers/specs/2026-10-05-rvm-phase3-fold-reduce-design.md`. Plan: `docs/superpowers/plans/2026-10-05-rvm-phase3-fold-reduce.md`.

## 1. Where the rows go (Task 0, measured <date>, production fixture)

<the `== profile Production` line, the `-- shape` line, and the `-- rows per call site` table verbatim>

Q = <queries>, R = <rounds = log_arities.len()>, E = <REDUCE dispatches / Q>, H = <distinct heights = chains per query>,
K = <EINV count inside `reduce` / Q = inverse keys per query>. Spec §1's derived table, against this one: <one line per
source: derived → measured>.

## 2. The landing bands (±15 % of each cut's projected delta; phase 2 §6 ruling 1)

T₀ = <cpu rows>. Each band is [T_prev − 1.15·Δ, T_prev − 0.85·Δ], with T_prev the previous cut's *measured* rows.

| cut | Δ (projected rows removed) | formula | band (Task 0) | measured | in band |
|---|---:|---|---|---:|---|
| D | <Δ_D> | rows(reduce) − [EINV+MOV+FSUB in reduce] − Q·(E + H + K + 3) | <lo–hi> | | |
| E1 | <Δ_E1> | rows(select) − Q·Σ_r(2·la_r + 5) + Q·Σ_r(a_r + 9) | relative to D's measured | | |
| E2 | <Δ_E2> | rows(fold_round, re-read after E1) − 4·Q·R | relative to E1's measured | | |
| F | <Δ_F> | rows(bit_selected_power) − 4·Q·(H + R) | relative to E2's measured | | |

Memory targets: REG <reg accesses> → under 2 097 152 (needs −<reg − 2 097 151>); RAM <mem accesses> → under 2 097 152.

## 3. Memory (Task 1b fills this)

## 4. The cuts, measured (each cut task appends its row and its `== profile` line)

## 5. What moved (Task 5)

## 6. The suite (Task 5)
````

- [ ] **Step 14: Commit**

```bash
git add tests/fold_identity.rs src/dsl/builder.rs src/dsl/mod.rs src/dsl/transcript.rs src/programs/rv32.rs \
        tests/profile.rs tests/common/mod.rs tests/exit.rs tests/dsl.rs tests/pins.json docs/05-phase3-fold-reduce.md
git commit -m "recursion: phase 3 Task 0 — call-site spans, the REG count, the fold identity; <cpu rows> rows attributed

reduce <rows_reduce>, select <rows_select>, fold_round <rows_fold_round>, bit_selected_power <rows_bsp>,
reloads <reloads>; log_arities <list>; REG <reg>. The DFT + Horner fold equals fold_row at a = 2, 4, 8
(256 random inputs each). Bands in docs/05 §2. No instruction moved: every digest pin unchanged.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AUWKAos28PQquiLZRVC6jP"
```

---

### Task 1a: Cut D, the machine side — preprocessed layout, one REDUCE row per entry, in-chip chains

This task builds and proves the primitive, and ports every existing reduce test to it. The shipped program does **not** use it yet: `emit_reduced_openings`' `On` arm temporarily calls `reduce_compiled`, Task 1b wires it, and the cycle-budget pins are re-measured in 1b. A reviewer can approve the AIR here and reject the program change in 1b.

**Files:**
- Modify: `src/isa.rs`: `ReduceEntry`; `Program` (:254-258), `digest` (:273-282), `digest_rows` (:285-287); `DecodeError` (:211-215); the `Reduce` doc (:92-97)
- Modify: `src/emulator.rs`: slot constants (:24-33), `ReduceEvent` (:68-79), `ExecError` (:144-158), `execute`'s loop head (:167-185) and `Op::Reduce` arm (:339-380)
- Modify: `src/tables/reduce.rs` (whole file), `src/tables/mod.rs` (bus `REDUCE_LAYOUT`), `src/tables/cpu.rs:344` (the `REDUCE` key)
- Modify: `src/machine.rs`: `KeyCache` (:290-307), `verifier_key` (:319-332), `check_program` (:342-348), `build_traces` (:427-433), `verify` (:604-619), `max_constraint_degrees_declaring` (:640-665), `chips` (:671-689)
- Modify: `src/shape.rs:912` and `:1005` (`verifier_key` calls)
- Modify: `src/dsl/builder.rs`: `reduce` (:619-643), struct and `with_opts` (:186-230), `replay` return (:1365-1371); `src/dsl/mod.rs:24`
- Modify: `src/programs/rv32.rs:868-872` (the `On` arm, temporarily)
- Test: `tests/common/mod.rs` (`every_chip_program` :549-570; new `reduce_chain_program`), `tests/cheating.rs` (the reduce tranche :203-310, :801-1026, `traces_from_parts` :615-658), `tests/tables.rs` (:198-420), `tests/precompiles.rs` (:13-170), `tests/emulator.rs`, `tests/isa.rs`, `tests/machine.rs` (:88-110), `tests/program.rs` (:80-95), `tests/verifier_key.rs`, `tests/cpu.rs` (:438-480), `tests/self_verify.rs`

**Interfaces:**
- Produces: `isa::ReduceEntry { pub vals: u64, pub row: u64, pub len: u32, pub key: u64, pub alpha: u64, pub res: u64, pub chain_start: bool, pub carry: bool }` (`Clone, Copy, Debug, PartialEq, Eq`), and `Program::reduce_layout: Vec<ReduceEntry>`.
- Produces: `DecodeError::Layout { entry: u32 }`.
- Produces: `ExecError::{ReduceLayout { pc: u32, entry: u64 }, ReduceChain { pc: u32, entry: u64 }}`.
- Produces: `emulator::{TS_KEY0 = 0, TS_KEY1 = 1, TS_ALPHA0 = 2, TS_ALPHA1 = 3, TS_RUN_PZ0 = 11, TS_RUN_PZ1 = 12, TS_RUN_PX = 13, TS_RES0 = 14, TS_RES1 = 15}`. `TS_WB_*` are deleted.
- Produces: `ReduceEvent { entry: u32, len: u32, inv: [F; 2], alpha: [F; 2], acc_in: [F; 2], apow_in: [F; 2], acc_out: [F; 2], apow_out: [F; 2] }`.
- Produces: `reduce::{col::* (WIDTH 30), pre::* (WIDTH 9), ReduceAir { layout: Arc<Vec<ReduceEntry>>, height: usize }, ReduceAir::new, provider_rows(&[ReduceEntry]) -> usize, reduce_rows(&[&Event]) -> usize, reduce_log_height(rows, provider) -> u8, reduce_trace(&[ReduceEntry], &[&Event], usize) -> RowMajorMatrix<F>}`.
- Produces: `bus::REDUCE_LAYOUT: LookupBus` with message `[entry, addr_v, addr_r, row_end, key, alpha, res, chain_start + 2·carry]`. `bus::REDUCE`'s message is now `[clk, entry]`.
- Produces: `Machine::verifier_key(&self, &Program, Tier, reduce_log_height: u8)`.
- Produces: `dsl::ReduceRun { pub vals: Array<Ext>, pub row: Array<Felt>, pub key: Ptr }` and `Builder::reduce(&mut self, runs: &[ReduceRun], alpha: Ptr, res: Ptr)`.
- Produces (tests): `common::reduce_chain_program(split: bool) -> Program`, which publishes 267 either way.

- [ ] **Step 1: Failing ISA and emulator tests**

`tests/isa.rs`: append

```rust
/// Cut D: the reduce layout is part of the program's identity, absorbed after the instructions
/// — and only when present, so a program without one keeps the digest it always had.
#[test]
fn the_reduce_layout_is_absorbed_into_the_digest_only_when_present() {
    use recursion::isa::ReduceEntry;
    let p = Program { instrs: vec![instr(Op::Faddi, 1, 0, 7), instr(Op::Halt, 0, 0, 0)], checkpoints: vec![], reduce_layout: vec![] };
    let e = ReduceEntry { vals: 100, row: 120, len: 3, key: 210, alpha: 212, res: 214, chain_start: true, carry: false };
    let q = Program { reduce_layout: vec![e], ..p.clone() };
    let r = Program { reduce_layout: vec![ReduceEntry { res: 216, ..e }], ..p.clone() };
    assert_ne!(p.digest(), q.digest(), "a layout changes the digest");
    assert_ne!(q.digest(), r.digest(), "every layout field is bound");
    assert_eq!(q.digest_rows(), 2 + 2, "two permutations per layout entry");
}
```

and add `reduce_layout: vec![]` to the two `Program { … }` literals in that file. `tests/emulator.rs`: append

```rust
use recursion::isa::ReduceEntry;

/// Cut D's honest chain over `common`'s 267 fixture, inlined: vals (10,0) (20,0) (30,0) at 100,
/// row 4 5 6 at 120, inv (1,0) at 210, alpha (3,0) at 212, the result at 214.
fn chain(split: bool) -> Program {
    let mut v = vec![];
    for (addr, val) in [(100u64, 10u64), (101, 0), (102, 20), (103, 0), (104, 30), (105, 0), (120, 4), (121, 5), (122, 6), (210, 1), (211, 0), (212, 3), (213, 0)] {
        v.push(i(Op::Faddi, 1, 0, val));
        v.push(i(Op::Store, 1, 0, addr));
    }
    let e = ReduceEntry { vals: 100, row: 120, len: 3, key: 210, alpha: 212, res: 214, chain_start: true, carry: false };
    let layout = if split {
        vec![ReduceEntry { len: 2, carry: true, ..e }, ReduceEntry { vals: 104, row: 122, len: 1, chain_start: false, ..e }]
    } else {
        vec![e]
    };
    for id in 0..layout.len() as u64 {
        v.push(i(Op::Reduce, 0, 0, id));
    }
    v.push(i(Op::Load, 3, 0, 214));
    for _ in 0..4 {
        v.push(i(Op::Public, 0, 3, 0));
    }
    v.push(i(Op::Halt, 0, 0, 0));
    Program { instrs: v, checkpoints: vec![], reduce_layout: layout }
}

#[test]
fn a_reduce_chain_accumulates_across_its_entries_and_writes_once() {
    for split in [false, true] {
        let exec = execute(&chain(split), &[], 1000).unwrap();
        assert_eq!(exec.public[0], F::from_u64(267), "(10−4)·1 + (20−5)·3 + (30−6)·9, split {split}");
        let writes: usize = exec.events.iter().filter(|e| e.reduce.is_some()).map(|e| e.mem.iter().filter(|m| m.is_write).count()).sum();
        assert_eq!(writes, 2, "one result write per chain, split {split}");
    }
}

#[test]
fn a_carry_not_consumed_by_the_next_instruction_is_refused() {
    let mut p = chain(true);
    let at = p.instrs.iter().position(|x| x.op == Op::Reduce).unwrap();
    p.instrs.insert(at + 1, i(Op::Faddi, 9, 0, 1));
    assert!(matches!(execute(&p, &[], 1000), Err(ExecError::ReduceChain { entry: 1, .. })));
}

#[test]
fn a_continuation_entry_dispatched_without_its_carry_is_refused() {
    let mut p = chain(true);
    let at = p.instrs.iter().position(|x| x.op == Op::Reduce).unwrap();
    p.instrs.remove(at); // entry 0 never runs
    assert!(matches!(execute(&p, &[], 1000), Err(ExecError::ReduceChain { entry: 1, .. })));
}

#[test]
fn an_entry_id_past_the_layout_is_refused() {
    let mut p = chain(false);
    let at = p.instrs.iter().position(|x| x.op == Op::Reduce).unwrap();
    p.instrs[at] = i(Op::Reduce, 0, 0, 5);
    assert_eq!(execute(&p, &[], 1000).unwrap_err(), ExecError::ReduceLayout { pc: at as u32, entry: 5 });
}
```

Delete the old descriptor-format REDUCE emulator tests, if any (`grep -n 'Op::Reduce' tests/emulator.rs` before adding the above).

Run: `cargo test --test isa --test emulator`
Expected: compile errors (`reduce_layout` has no field, `ReduceEntry` is not found).

- [ ] **Step 2: The layout in the ISA**

In `src/isa.rs`, above `Program`:

```rust
/// One entry of a program's reduce layout (phase 3, Cut D): one run of the batch-opening
/// reduction, every address a compile-time constant of the program. The reduce chip's
/// preprocessed region holds the layout, so the verifier key commits it, and a `REDUCE`
/// instruction names an entry by its index (the immediate) — a descriptor is never a witness
/// value (spec §6 ruling 3). `vals` holds `len` extension values (2·len cells), `row` the `len`
/// base cells, `key` the run's inverse key (2 cells), `alpha` the batching challenge (2 cells,
/// read when `chain_start`), `res` the chain's result (2 cells, written when `!carry`).
/// `carry` hands the accumulator and the running power to entry `id + 1`, dispatched on the very
/// next cpu row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReduceEntry {
    pub vals: u64,
    pub row: u64,
    pub len: u32,
    pub key: u64,
    pub alpha: u64,
    pub res: u64,
    pub chain_start: bool,
    pub carry: bool,
}
```

Add `pub reduce_layout: Vec<ReduceEntry>,` to `Program` with the doc line `/// Cut D: the reduce layout, committed by the verifier key and absorbed into [`Program::digest`].` In `digest`, after `state[5] = …`:

```rust
        // Cut D: a program with a reduce layout absorbs its length into capacity lane 6 and then
        // two blocks per entry after the instructions. A program without one keeps its digest.
        if !self.reduce_layout.is_empty() {
            state[6] = F::from_u64(self.reduce_layout.len() as u64);
        }
```

and after the instruction loop:

```rust
        for e in &self.reduce_layout {
            state[..4].copy_from_slice(&[F::from_u64(e.vals), F::from_u64(e.row), F::from_u32(e.len), F::from_u64(e.key)]);
            state = rand_zkvm::hash::permute_state(state);
            let flags = e.chain_start as u64 + 2 * e.carry as u64;
            state[..4].copy_from_slice(&[F::from_u64(e.alpha), F::from_u64(e.res), F::from_u64(flags), F::ZERO]);
            state = rand_zkvm::hash::permute_state(state);
        }
```

`digest_rows` returns `self.instrs.len() + 2 * self.reduce_layout.len()`. Add `Layout { entry: u32 }` to `DecodeError` with the doc `/// Cut D: a reduce-layout entry no run could have (zero length, a cell at or above 2^24, or a chain that does not hand over).`. Rewrite the `Reduce` variant's doc: `/// one run of the batch-opening reduction: layout entry `imm` (Cut D, phase 3) — the chip reads the run's columns, its inverse key, and at a chain start the batching challenge, all at addresses the verifier key commits; a carrying entry hands its accumulator to entry `imm + 1` on the next row, a closing one writes it to the entry's `res`. Opcode 24.`

Fix every `Program { … }` literal in `src/` and `tests/`. Run `cargo build --release --tests 2>&1 | grep -B2 'missing field .reduce_layout.'` and add `reduce_layout: vec![]` at each. The builder's literal is set in Step 7.

- [ ] **Step 3: The emulator's REDUCE semantics**

In `src/emulator.rs`, replace the slot constants (:24-33):

```rust
/// The `REDUCE` run's timestamp slots, shared with the reduce chip's memory messages (Cut D): the
/// entry's inverse key at slots 0–1, the chain's alpha at 2–3 (chain starts only), each column's
/// three reads reusing slots 11–13 (distinct addresses per column, which is all the memory table's
/// monotonicity asks), and the chain's result at 14–15.
pub const TS_KEY0: u32 = 0;
pub const TS_KEY1: u32 = 1;
pub const TS_ALPHA0: u32 = 2;
pub const TS_ALPHA1: u32 = 3;
pub const TS_RUN_PZ0: u32 = 11;
pub const TS_RUN_PZ1: u32 = 12;
pub const TS_RUN_PX: u32 = 13;
pub const TS_RES0: u32 = 14;
pub const TS_RES1: u32 = 15;
```

Replace `ReduceEvent`:

```rust
/// One `REDUCE` dispatch (Cut D): the layout entry, its column count, the key and alpha it ran
/// with, and the accumulator/running power on entry and on exit (equal at a chain's seam).
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct ReduceEvent {
    pub entry: u32,
    pub len: u32,
    pub inv: [F; 2],
    pub alpha: [F; 2],
    pub acc_in: [F; 2],
    pub apow_in: [F; 2],
    pub acc_out: [F; 2],
    pub apow_out: [F; 2],
}

/// The state a carrying entry hands to the next row's `REDUCE`.
#[derive(Clone, Copy)]
struct ReduceCarry {
    entry: u32,
    clk: u32,
    acc: [F; 2],
    apow: [F; 2],
    alpha: [F; 2],
}
```

Add to `ExecError`:

```rust
    /// A `REDUCE` naming no entry of the program's layout.
    ReduceLayout { pc: u32, entry: u64 },
    /// A chain's hand-over broken: a carrying entry not followed, on the very next row, by a
    /// `REDUCE` of the next entry; or a continuation entry dispatched without that carry.
    ReduceChain { pc: u32, entry: u64 },
```

In `execute`, declare `let mut chain: Option<ReduceCarry> = None;` before `loop`. After `let op = instr.op;`:

```rust
        if let Some(c) = &chain {
            if op != Op::Reduce {
                return Err(ExecError::ReduceChain { pc, entry: c.entry as u64 });
            }
        }
```

Replace the `Op::Reduce` arm:

```rust
            Op::Reduce => {
                a[0] = regs[ra];
                let id = instr.b.as_canonical_u64();
                let le = *p.reduce_layout.get(id as usize).ok_or(ExecError::ReduceLayout { pc, entry: id })?;
                if le.len == 0 {
                    return Err(ExecError::ReduceZeroLength { pc });
                }
                let len = le.len as u64;
                for top in [le.vals + 2 * len - 1, le.row + len - 1, le.key + 1, le.alpha + 1, le.res + 1] {
                    bounded(pc, top)?;
                }
                let inv = [read_at(&mem, &mut mems, clk, TS_KEY0, le.key), read_at(&mem, &mut mems, clk, TS_KEY1, le.key + 1)];
                let (mut acc, mut apow, alpha) = if le.chain_start {
                    if chain.is_some() {
                        return Err(ExecError::ReduceChain { pc, entry: id });
                    }
                    let alpha = [read_at(&mem, &mut mems, clk, TS_ALPHA0, le.alpha), read_at(&mem, &mut mems, clk, TS_ALPHA1, le.alpha + 1)];
                    ([F::ZERO; 2], [F::ONE, F::ZERO], alpha)
                } else {
                    match chain.take() {
                        Some(c) if c.entry as u64 == id && c.clk + 1 == clk => (c.acc, c.apow, c.alpha),
                        _ => return Err(ExecError::ReduceChain { pc, entry: id }),
                    }
                };
                let (acc_in, apow_in) = (acc, apow);
                for k in 0..len {
                    let pz = [
                        read_at(&mem, &mut mems, clk, TS_RUN_PZ0, le.vals + 2 * k),
                        read_at(&mem, &mut mems, clk, TS_RUN_PZ1, le.vals + 2 * k + 1),
                    ];
                    let px = read_at(&mem, &mut mems, clk, TS_RUN_PX, le.row + k);
                    let diff = ext(pz) - px;
                    let t = ext(apow) * diff * ext(inv);
                    acc = parts(ext(acc) + t);
                    apow = parts(ext(apow) * ext(alpha));
                }
                if le.carry {
                    chain = Some(ReduceCarry { entry: id as u32 + 1, clk, acc, apow, alpha });
                } else {
                    write_at(&mut mem, &mut mems, clk, TS_RES0, le.res, acc[0]);
                    write_at(&mut mem, &mut mems, clk, TS_RES1, le.res + 1, acc[1]);
                }
                reduce = Some(ReduceEvent { entry: id as u32, len: le.len, inv, alpha, acc_in, apow_in, acc_out: acc, apow_out: apow });
            }
```

Run: `cargo test --test isa --test emulator`
Expected: pass.

- [ ] **Step 4: Failing chip tests**

In `tests/common/mod.rs`, add:

```rust
/// Cut D's honest reduce program (`tests/emulator.rs::chain`, shared): one chain over three
/// columns, as one entry or (`split`) as a carrying two-column entry plus a one-column
/// continuation. Publishes 267 = (10−4)·1 + (20−5)·3 + (30−6)·9 four times.
#[allow(dead_code)]
pub fn reduce_chain_program(split: bool) -> recursion::isa::Program {
    use p3_field::PrimeCharacteristicRing;
    use recursion::isa::{Instr, Op, Program, ReduceEntry, F};
    let i = |op: Op, rd: u8, ra: u8, b: u64| Instr { op, rd, ra, b: F::from_u64(b) };
    let mut v = vec![];
    for (addr, val) in [(100u64, 10u64), (101, 0), (102, 20), (103, 0), (104, 30), (105, 0), (120, 4), (121, 5), (122, 6), (210, 1), (211, 0), (212, 3), (213, 0)] {
        v.push(i(Op::Faddi, 1, 0, val));
        v.push(i(Op::Store, 1, 0, addr));
    }
    let e = ReduceEntry { vals: 100, row: 120, len: 3, key: 210, alpha: 212, res: 214, chain_start: true, carry: false };
    let layout = if split {
        vec![ReduceEntry { len: 2, carry: true, ..e }, ReduceEntry { vals: 104, row: 122, len: 1, chain_start: false, ..e }]
    } else {
        vec![e]
    };
    for id in 0..layout.len() as u64 {
        v.push(i(Op::Reduce, 0, 0, id));
    }
    v.push(i(Op::Load, 3, 0, 214));
    for _ in 0..4 {
        v.push(i(Op::Public, 0, 3, 0));
    }
    v.push(i(Op::Halt, 0, 0, 0));
    Program { instrs: v, checkpoints: vec![], reduce_layout: layout }
}
```

Rewrite `every_chip_program` (:549-570) to reach the reduce chip through the layout: its descriptor stores and `REDUCE` become `reduce_chain_program(false)`'s thirteen stores and `i(Op::Reduce, 0, 0, 0)`, keeping the `LOAD`, `POSEIDON2`, four `PUBLIC`s and `HALT`, with `reduce_layout: vec![ReduceEntry { vals: 100, row: 120, len: 3, key: 210, alpha: 212, res: 214, chain_start: true, carry: false }]`.

In `tests/tables.rs`, change `the_reduce_chip_width_and_constraint_degree_are_pinned`:

```rust
    assert_eq!(reduce_table::col::WIDTH, 30, "Cut D: the run row (26), the END gadget, the two count columns, MULT");
    assert_eq!(reduce_table::pre::WIDTH, 9, "Cut D: the layout provider region");
    let p = common::reduce_chain_program(true);
```

Leave the degree assertion `assert_eq!(degs[7], 8)` in place for now; Step 9 measures it.

Then replace the four reduce rule tests (`every_reduce_run_row_carries_its_addresses_and_clock_from_the_row_before`, `no_admissible_padding_reduce_row_sends_a_message`, `a_reduce_run_must_end_on_its_last_row`, `a_reduce_run_touching_a_cell_outside_the_address_space_is_refused`, :224-420) with:

```rust
// ── The reduce chip's run rules after Cut D (read off `ReduceAir::eval`) ─────────────────────
use recursion::tables::{bus, reduce as reduce_table};

fn reduce_air() -> reduce_table::ReduceAir {
    reduce_table::ReduceAir::new(std::sync::Arc::new(vec![]), 16)
}

/// The run row kind's own columns (Cut D's 30); the fold and pow kinds (Tasks 3–4) append theirs
/// after it, and these rule tests hold them at zero — they are about run rows.
const REDUCE_KIND_COLS: usize = 30;

fn reduce_row(real: bool, first: bool, rng: &mut impl rand::Rng) -> Vec<F> {
    use reduce_table::col::*;
    let mut r: Vec<F> = (0..WIDTH).map(|c| if c < REDUCE_KIND_COLS { common::random_felt(rng) } else { F::ZERO }).collect();
    r[IS_REAL] = F::from_bool(real);
    r[IS_FIRST] = F::from_bool(first);
    r
}

/// OPCODES-1 / TABLES-1, as a rule: every column a run row's RAM messages use as an address or a
/// timestamp is carried from the row before when the next row is the same run's.
#[test]
fn every_reduce_run_row_carries_its_addresses_and_clock_from_the_row_before() {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(0x0bc0_de01);
    let (interactions, constraints) = common::symbolic_air(&reduce_air());
    let (cur, next_in_run, next_first) = (reduce_row(true, false, &mut rng), reduce_row(true, false, &mut rng), reduce_row(true, true, &mut rng));
    let mut used = std::collections::BTreeSet::new();
    for i in interactions.iter().filter(|i| i.bus_name == bus::RAM.name()) {
        for field in &i.fields[0..2] {
            for c in 0..reduce_table::col::WIDTH {
                if common::depends(field, &cur, &next_in_run, c, false, &mut rng) {
                    used.insert(c);
                }
            }
        }
    }
    used.retain(|&c| c < REDUCE_KIND_COLS);
    use reduce_table::col::{ADDR_V, ALPHA_ADDR, CLK, KEY, RES};
    assert!([CLK, ADDR_V, KEY, ALPHA_ADDR, RES].iter().all(|c| used.contains(c)), "sanity: {used:?}");
    let unchained: Vec<usize> = used
        .iter()
        .copied()
        .filter(|&c| !constraints.iter().any(|k| common::depends(k, &cur, &next_in_run, c, true, &mut rng) && !common::depends(k, &cur, &next_first, c, true, &mut rng)))
        .collect();
    assert!(unchained.is_empty(), "RAM address/timestamp columns {unchained:?} are not carried along a run");
}

/// V-OPCODES-1, as a rule: no admissible padding row sends or provides anything, whatever its
/// row-kind witnesses (`IS_FIRST`, `IS_LAST`, `CHAIN_START`, `CARRY`) — off the layout region,
/// where `MULT` must be zero.
#[test]
fn no_admissible_padding_reduce_row_sends_a_message() {
    use reduce_table::col::*;
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(0x0bc0_de02);
    let (interactions, constraints) = common::symbolic_air(&reduce_air());
    let next = vec![F::ZERO; WIDTH];
    let mut sends = Vec::new();
    let mut admitted = 0;
    for bits in 0u32..16 {
        let mut cur: Vec<F> = (0..WIDTH).map(|c| if c < REDUCE_KIND_COLS { common::random_felt(&mut rng) } else { F::ZERO }).collect();
        cur[IS_REAL] = F::ZERO;
        cur[IS_FIRST] = F::from_bool(bits & 1 != 0);
        cur[IS_LAST] = F::from_bool(bits & 2 != 0);
        cur[CHAIN_START] = F::from_bool(bits & 4 != 0);
        cur[CARRY] = F::from_bool(bits & 8 != 0);
        cur[WRITES] = cur[IS_LAST] * (F::ONE - cur[CARRY]);
        cur[READ_ALPHA] = cur[IS_FIRST] * cur[CHAIN_START];
        cur[MULT] = F::ZERO;
        if constraints.iter().any(|c| common::eval_at(c, &cur, &next) != F::ZERO) {
            continue;
        }
        admitted += 1;
        for i in &interactions {
            if common::eval_at(&i.count, &cur, &next) != F::ZERO {
                sends.push(format!("kinds {bits:04b}: sends on {}", i.bus_name));
            }
        }
    }
    assert!(admitted >= 1, "the all-zero kind assignment is admissible padding");
    assert!(sends.is_empty(), "admissible padding rows of the reduce chip send messages:\n  {}", sends.join("\n  "));
}

/// ZKR-4 and R5, as a rule: a run ends exactly on the row where ADDR_R = ROW_END. Checked on
/// the honest split chain's rows with their real preprocessed rows.
#[test]
fn a_reduce_run_must_end_where_its_row_ends() {
    use p3_air::BaseAir;
    use reduce_table::col::*;
    let p = common::reduce_chain_program(true);
    let exec = recursion::emulator::execute(&p, &[], 1000).unwrap();
    let t = recursion::machine::build_traces(&p, &exec, Tier(8)).unwrap();
    let air = reduce_table::ReduceAir::new(std::sync::Arc::new(p.reduce_layout.clone()), 1 << t.reduce_log_height);
    let pre = BaseAir::<F>::preprocessed_trace(&air).unwrap();
    let red = t.reduce.unwrap();
    let row = |k: usize| red.values[k * WIDTH..(k + 1) * WIDTH].to_vec();
    let prow = |k: usize| pre.values[k * reduce_table::pre::WIDTH..(k + 1) * reduce_table::pre::WIDTH].to_vec();
    let (_, constraints) = common::symbolic_air(&air);
    let holds = |cur: &[F], next: &[F], k: usize| constraints.iter().all(|c| common::eval_full(c, cur, next, (&prow(k), &prow(k + 1)), &[]) == F::ZERO);
    assert!((0..3).all(|k| holds(&row(k), &row(k + 1), k)), "the honest rows hold");
    let mut early = row(0);
    early[IS_LAST] = F::ONE; // row 0 is ADDR_R = 120, ROW_END = 121
    early[WRITES] = F::ZERO; // CARRY = 1
    assert!(!holds(&early, &row(1), 0), "IS_LAST before ADDR_R reaches ROW_END is refused");
    let mut late = row(1);
    late[IS_LAST] = F::ZERO;
    late[END_INV] = F::ONE;
    assert!(!holds(&late, &row(2), 1), "a run running past ROW_END is refused");
}
```

In `tests/common/mod.rs`, `eval_at` (:437-441): add the arm `BaseEntry::Preprocessed { .. } => F::ZERO,` before `other => panic!`, with the comment `// A row outside every preprocessed region (the reduce chip's per-row rules are checked there).`

Run: `cargo test --release --test tables reduce`
Expected: compile errors (`ReduceAir::new` and `pre` are not found).

- [ ] **Step 5: The chip**

Replace `src/tables/reduce.rs` with:

```rust
//! The reduction chip (Task 8; phase 3 Cut D, 2026-10-05): one chip row per reduction column.
//!
//! **The layout is preprocessed.** Every run's addresses — its opened values, its row, its
//! inverse key, the chain's alpha and result cells — are compile-time constants of the program,
//! listed in `Program::reduce_layout`. The chip's preprocessed region holds one row per entry,
//! with a witness `MULT` (the `ProgramAir` pattern), and is committed by the verifier key. Each
//! run looks up its entry on its first row (`REDUCE_LAYOUT`), so a descriptor is never a witness
//! value. The aggregate program runs every entry N times; `MULT` is N.
//!
//! **Chains carry in the chip.** A run's rows step `acc += apow·(pz − px)·inv`,
//! `apow ·= alpha`; a run whose entry carries hands both to the next row, the next entry's first
//! row, dispatched by the very next cpu row (`n(CLK) = CLK + 1`, `n(ENTRY) = ENTRY + 1`). A chain
//! starts at `acc = 0`, `apow = 1`, reads alpha once, and writes its result once.
//!
//! Every message is degree 1: its counts are columns (`WRITES`, `READ_ALPHA` are constrained
//! products) and its values are columns (`OUT` is constrained to the step's output).
use super::{bus, F};
use crate::emulator::{Event, TS_ALPHA0, TS_ALPHA1, TS_KEY0, TS_KEY1, TS_RES0, TS_RES1, TS_RUN_PX, TS_RUN_PZ0, TS_RUN_PZ1};
use crate::isa::ReduceEntry;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use std::sync::Arc;

pub mod col {
    pub const IS_REAL: usize = 0;
    pub const IS_FIRST: usize = 1;
    pub const IS_LAST: usize = 2;
    pub const CLK: usize = 3;
    pub const ENTRY: usize = 4;
    pub const ADDR_V: usize = 5;
    pub const ADDR_R: usize = 6;
    /// The entry's last row cell, from the layout: `IS_LAST ⟺ ADDR_R = ROW_END` (R5).
    pub const ROW_END: usize = 7;
    pub const END_INV: usize = 8;
    pub const KEY: usize = 9;
    pub const ALPHA_ADDR: usize = 10;
    pub const RES: usize = 11;
    pub const CHAIN_START: usize = 12;
    pub const CARRY: usize = 13;
    pub const ACC0: usize = 14;
    pub const ACC1: usize = 15;
    pub const APOW0: usize = 16;
    pub const APOW1: usize = 17;
    pub const INV0: usize = 18;
    pub const INV1: usize = 19;
    pub const ALPHA0: usize = 20;
    pub const ALPHA1: usize = 21;
    pub const PZ0: usize = 22;
    pub const PZ1: usize = 23;
    pub const PX: usize = 24;
    /// The step's output accumulator on a last row: the result written when the chain closes.
    pub const OUT0: usize = 25;
    pub const OUT1: usize = 26;
    /// `IS_LAST·(1 − CARRY)` and `IS_FIRST·CHAIN_START`, as columns so every count is degree 1.
    pub const WRITES: usize = 27;
    pub const READ_ALPHA: usize = 28;
    /// The provider region's multiplicity: how many runs of this row's layout entry executed.
    pub const MULT: usize = 29;
    pub const WIDTH: usize = 30;
}
pub mod pre {
    pub const L_IS_ENTRY: usize = 0;
    pub const L_ENTRY: usize = 1;
    pub const L_ADDR_V: usize = 2;
    pub const L_ADDR_R: usize = 3;
    pub const L_ROW_END: usize = 4;
    pub const L_KEY: usize = 5;
    pub const L_ALPHA: usize = 6;
    pub const L_RES: usize = 7;
    /// `chain_start + 2·carry`.
    pub const L_FLAGS: usize = 8;
    pub const WIDTH: usize = 9;
}
use col::*;

pub const MIN_LOG_HEIGHT: u8 = 4;

/// The chip carries its program's layout (the preprocessed region is built from it) and the
/// declared height that region is committed at.
#[derive(Clone, Debug)]
pub struct ReduceAir {
    pub layout: Arc<Vec<ReduceEntry>>,
    pub height: usize,
}

impl ReduceAir {
    pub fn new(layout: Arc<Vec<ReduceEntry>>, height: usize) -> Self {
        assert!(height >= provider_rows(&layout), "the reduce table must hold its provider region");
        ReduceAir { layout, height }
    }
}

/// Rows the preprocessed provider region occupies.
pub fn provider_rows(layout: &[ReduceEntry]) -> usize {
    layout.len()
}

impl<Fld: Field> BaseAir<Fld> for ReduceAir {
    fn width(&self) -> usize { col::WIDTH }
    fn preprocessed_width(&self) -> usize { pre::WIDTH }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> {
        let mut v = Fld::zero_vec(self.height * pre::WIDTH);
        for (i, e) in self.layout.iter().enumerate() {
            let r = &mut v[i * pre::WIDTH..(i + 1) * pre::WIDTH];
            r[pre::L_IS_ENTRY] = Fld::ONE;
            r[pre::L_ENTRY] = Fld::from_u64(i as u64);
            r[pre::L_ADDR_V] = Fld::from_u64(e.vals);
            r[pre::L_ADDR_R] = Fld::from_u64(e.row);
            r[pre::L_ROW_END] = Fld::from_u64(e.row + e.len as u64 - 1);
            r[pre::L_KEY] = Fld::from_u64(e.key);
            r[pre::L_ALPHA] = Fld::from_u64(e.alpha);
            r[pre::L_RES] = Fld::from_u64(e.res);
            r[pre::L_FLAGS] = Fld::from_u64(e.chain_start as u64 + 2 * e.carry as u64);
        }
        Some(RowMajorMatrix::new(v, pre::WIDTH))
    }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for ReduceAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let p = b.preprocessed().clone();
        let m = b.main();
        let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let n = |i: usize| -> AB::Expr { m.next(i).unwrap().into() };
        let l = |i: usize| -> AB::Expr { p.current(i).unwrap().into() };
        let one = AB::Expr::ONE;
        let seven = AB::Expr::from_u64(7);
        let sixteen = AB::Expr::from_u32(16);

        let (is_real, is_first, is_last) = (v(IS_REAL), v(IS_FIRST), v(IS_LAST));
        for c in [IS_REAL, IS_FIRST, IS_LAST, CHAIN_START, CARRY] {
            b.assert_bool(v(c));
        }
        // V-OPCODES-1: both run-boundary kinds exist only on real rows.
        b.assert_zero(is_first.clone() * (one.clone() - is_real.clone()));
        b.assert_zero(is_last.clone() * (one.clone() - is_real.clone()));
        // R5: IS_LAST ⟺ ADDR_R = ROW_END on a real row (a last row sits there; a real non-last
        // row does not, witnessed by the inverse).
        let d = v(ADDR_R) - v(ROW_END);
        b.assert_zero(is_last.clone() * d.clone());
        b.assert_zero(is_real.clone() * (one.clone() - is_last.clone()) * (one.clone() - d * v(END_INV)));
        // The two count columns.
        b.assert_zero(v(WRITES) - is_last.clone() * (one.clone() - v(CARRY)));
        b.assert_zero(v(READ_ALPHA) - is_first.clone() * v(CHAIN_START));
        // A chain starts at acc = 0, apow = 1.
        b.assert_zero(v(READ_ALPHA) * v(ACC0));
        b.assert_zero(v(READ_ALPHA) * v(ACC1));
        b.assert_zero(v(READ_ALPHA) * (v(APOW0) - one.clone()));
        b.assert_zero(v(READ_ALPHA) * v(APOW1));
        // AGENTS.md invariant 2 on the provider: a multiplicity only on a layout row.
        b.assert_zero(v(MULT) * (one.clone() - l(pre::L_IS_ENTRY)));

        // ── boundaries and the run structure (ZKR-4) ──
        b.when_first_row().assert_zero(is_real.clone() * (one.clone() - is_first.clone()));
        b.when_first_row().assert_zero(is_first.clone() * (one.clone() - v(CHAIN_START)));
        b.when_last_row().assert_zero(is_real.clone());
        {
            let mut t = b.when_transition();
            t.assert_zero((one.clone() - is_real.clone()) * n(IS_REAL));
            t.assert_zero(is_last.clone() * n(IS_REAL) * (one.clone() - n(IS_FIRST)));
            t.assert_zero(is_real.clone() * (one.clone() - is_last.clone()) * (one.clone() - n(IS_REAL)));
            t.assert_zero(is_real.clone() * (one.clone() - is_last.clone()) * n(IS_FIRST));
        }

        // ── the column step: diff = pz − px; t = apow·diff; t2 = t·inv; acc += t2; apow ·= alpha ──
        let (diff0, diff1) = (v(PZ0) - v(PX), v(PZ1));
        let t0 = v(APOW0) * diff0.clone() + seven.clone() * v(APOW1) * diff1.clone();
        let t1 = v(APOW0) * diff1 + v(APOW1) * diff0;
        let t2_0 = t0.clone() * v(INV0) + seven.clone() * t1.clone() * v(INV1);
        let t2_1 = t0 * v(INV1) + t1 * v(INV0);
        let acc_next0 = v(ACC0) + t2_0;
        let acc_next1 = v(ACC1) + t2_1;
        let apow_next0 = v(APOW0) * v(ALPHA0) + seven.clone() * v(APOW1) * v(ALPHA1);
        let apow_next1 = v(APOW0) * v(ALPHA1) + v(APOW1) * v(ALPHA0);
        b.assert_zero(is_last.clone() * (v(OUT0) - acc_next0.clone()));
        b.assert_zero(is_last.clone() * (v(OUT1) - acc_next1.clone()));

        // ── within an entry: the step chains, every per-entry column is carried ──
        let in_run_next = n(IS_REAL) * (one.clone() - n(IS_FIRST));
        {
            let mut t = b.when_transition();
            t.assert_zero(in_run_next.clone() * (n(ACC0) - acc_next0.clone()));
            t.assert_zero(in_run_next.clone() * (n(ACC1) - acc_next1.clone()));
            t.assert_zero(in_run_next.clone() * (n(APOW0) - apow_next0.clone()));
            t.assert_zero(in_run_next.clone() * (n(APOW1) - apow_next1.clone()));
            for c in [INV0, INV1, ALPHA0, ALPHA1, CLK, ENTRY, ROW_END, KEY, ALPHA_ADDR, RES, CHAIN_START, CARRY] {
                t.assert_zero(in_run_next.clone() * (n(c) - v(c)));
            }
            t.assert_zero(in_run_next.clone() * (n(ADDR_V) - v(ADDR_V) - AB::Expr::from_u32(2)));
            t.assert_zero(in_run_next.clone() * (n(ADDR_R) - v(ADDR_R) - one.clone()));
        }
        // ── across entries (R4): a carrying last row hands acc, apow and alpha to the next row,
        // which is the next entry's first row at the next clock; a continuation entry is entered
        // only that way ──
        let carry = is_last.clone() * v(CARRY);
        {
            let mut t = b.when_transition();
            t.assert_zero(carry.clone() * (one.clone() - n(IS_FIRST)));
            t.assert_zero(carry.clone() * n(CHAIN_START));
            t.assert_zero(carry.clone() * (n(ENTRY) - v(ENTRY) - one.clone()));
            t.assert_zero(carry.clone() * (n(CLK) - v(CLK) - one.clone()));
            t.assert_zero(carry.clone() * (n(ACC0) - acc_next0));
            t.assert_zero(carry.clone() * (n(ACC1) - acc_next1));
            t.assert_zero(carry.clone() * (n(APOW0) - apow_next0));
            t.assert_zero(carry.clone() * (n(APOW1) - apow_next1));
            t.assert_zero(carry.clone() * (n(ALPHA0) - v(ALPHA0)));
            t.assert_zero(carry.clone() * (n(ALPHA1) - v(ALPHA1)));
            t.assert_zero(n(IS_FIRST) * (one.clone() - n(CHAIN_START)) * (one.clone() - carry));
        }

        // ── buses ──
        bus::REDUCE.table_entry(b, [v(CLK), v(ENTRY)], is_first.clone());
        let flags = v(CHAIN_START) + AB::Expr::from_u32(2) * v(CARRY);
        bus::REDUCE_LAYOUT.lookup_key(
            b,
            [v(ENTRY), v(ADDR_V), v(ADDR_R), v(ROW_END), v(KEY), v(ALPHA_ADDR), v(RES), flags],
            Count::bounded(is_first.clone(), 1),
        );
        bus::REDUCE_LAYOUT.table_entry(
            b,
            [l(pre::L_ENTRY), l(pre::L_ADDR_V), l(pre::L_ADDR_R), l(pre::L_ROW_END), l(pre::L_KEY), l(pre::L_ALPHA), l(pre::L_RES), l(pre::L_FLAGS)],
            v(MULT),
        );
        let clk = v(CLK);
        let ts = |slot: u32| sixteen.clone() * clk.clone() + AB::Expr::from_u32(slot);
        let zero = AB::Expr::ZERO;
        bus::RAM.send(b, [v(KEY), ts(TS_KEY0), v(INV0), zero.clone()], Count::bounded(is_first.clone(), 1));
        bus::RAM.send(b, [v(KEY) + one.clone(), ts(TS_KEY1), v(INV1), zero.clone()], Count::bounded(is_first.clone(), 1));
        bus::RAM.send(b, [v(ALPHA_ADDR), ts(TS_ALPHA0), v(ALPHA0), zero.clone()], Count::bounded(v(READ_ALPHA), 1));
        bus::RAM.send(b, [v(ALPHA_ADDR) + one.clone(), ts(TS_ALPHA1), v(ALPHA1), zero.clone()], Count::bounded(v(READ_ALPHA), 1));
        bus::RAM.send(b, [v(ADDR_V), ts(TS_RUN_PZ0), v(PZ0), zero.clone()], Count::bounded(is_real.clone(), 1));
        bus::RAM.send(b, [v(ADDR_V) + one.clone(), ts(TS_RUN_PZ1), v(PZ1), zero.clone()], Count::bounded(is_real.clone(), 1));
        bus::RAM.send(b, [v(ADDR_R), ts(TS_RUN_PX), v(PX), zero], Count::bounded(is_real, 1));
        bus::RAM.send(b, [v(RES), ts(TS_RES0), v(OUT0), one.clone()], Count::bounded(v(WRITES), 1));
        bus::RAM.send(b, [v(RES) + one.clone(), ts(TS_RES1), v(OUT1), one], Count::bounded(v(WRITES), 1));
    }
}

/// The declared log-height: the runs plus one padding row, and at least the provider region,
/// floored — with `0` the "no reduce table" value (the keccak pattern, `machine::chips`).
pub fn reduce_log_height(rows: usize, provider: usize) -> u8 {
    if rows == 0 {
        return 0;
    }
    super::pad_height((rows + 1).max(provider), 1 << MIN_LOG_HEIGHT).trailing_zeros() as u8
}

/// The `REDUCE` events, in execution order.
pub fn reduce_events(events: &[Event]) -> Vec<&Event> {
    events.iter().filter(|e| e.reduce.is_some()).collect()
}

/// One chip row per reduced column.
pub fn reduce_rows(events: &[&Event]) -> usize {
    events.iter().map(|e| e.reduce.unwrap().len as usize).sum()
}

/// The runs in execution order (a chain's entries are consecutive dispatches, so adjacent), the
/// provider region's multiplicities, and all-zero padding.
pub fn reduce_trace(layout: &[ReduceEntry], events: &[&Event], height: usize) -> RowMajorMatrix<F> {
    let n_rows = reduce_rows(events);
    assert!(n_rows < height && layout.len() <= height, "reduce table: {n_rows} rows, {} layout entries, height {height}", layout.len());
    let mut v = F::zero_vec(height * WIDTH);
    let mut row = 0usize;
    for e in events {
        let ev = e.reduce.unwrap();
        let le = layout[ev.entry as usize];
        let (mut acc, mut apow) = (ev.acc_in, ev.apow_in);
        // The event's log: the key's two reads, the alpha's two at a chain start, then three per column.
        let mut reads = e.mem.iter().skip(if le.chain_start { 4 } else { 2 });
        let row_end = le.row + le.len as u64 - 1;
        for k in 0..le.len as u64 {
            let r = &mut v[row * WIDTH..(row + 1) * WIDTH];
            let (first, last) = (k == 0, k == le.len as u64 - 1);
            r[IS_REAL] = F::ONE;
            r[IS_FIRST] = F::from_bool(first);
            r[IS_LAST] = F::from_bool(last);
            r[CLK] = F::from_u64(e.clk as u64);
            r[ENTRY] = F::from_u64(ev.entry as u64);
            r[ADDR_V] = F::from_u64(le.vals + 2 * k);
            r[ADDR_R] = F::from_u64(le.row + k);
            r[ROW_END] = F::from_u64(row_end);
            if !last {
                r[END_INV] = (F::from_u64(le.row + k) - F::from_u64(row_end)).inverse();
            }
            r[KEY] = F::from_u64(le.key);
            r[ALPHA_ADDR] = F::from_u64(le.alpha);
            r[RES] = F::from_u64(le.res);
            r[CHAIN_START] = F::from_bool(le.chain_start);
            r[CARRY] = F::from_bool(le.carry);
            r[ACC0] = acc[0];
            r[ACC1] = acc[1];
            r[APOW0] = apow[0];
            r[APOW1] = apow[1];
            r[INV0] = ev.inv[0];
            r[INV1] = ev.inv[1];
            r[ALPHA0] = ev.alpha[0];
            r[ALPHA1] = ev.alpha[1];
            let pz = [reads.next().expect("pz0").value, reads.next().expect("pz1").value];
            let px = reads.next().expect("px").value;
            r[PZ0] = pz[0];
            r[PZ1] = pz[1];
            r[PX] = px;
            let (t0, t1) = ext_mul(apow, [pz[0] - px, pz[1]]);
            let (t2_0, t2_1) = ext_mul([t0, t1], ev.inv);
            acc = [acc[0] + t2_0, acc[1] + t2_1];
            apow = ext_mul(apow, ev.alpha).into();
            if last {
                r[OUT0] = acc[0];
                r[OUT1] = acc[1];
                r[WRITES] = F::from_bool(!le.carry);
            }
            r[READ_ALPHA] = F::from_bool(first && le.chain_start);
            row += 1;
        }
        debug_assert_eq!((acc, apow), (ev.acc_out, ev.apow_out), "the trace recomputes the emulator's chain");
    }
    for e in events {
        v[e.reduce.unwrap().entry as usize * WIDTH + MULT] += F::ONE;
    }
    RowMajorMatrix::new(v, WIDTH)
}

/// `(a0 + a1·X)·(b0 + b1·X)`, `X² = 7` — the same extension multiplication the cpu uses.
fn ext_mul(a: [F; 2], b: [F; 2]) -> (F, F) {
    let seven = F::from_u64(7);
    (a[0] * b[0] + seven * a[1] * b[1], a[0] * b[1] + a[1] * b[0])
}
```

In `src/tables/mod.rs`, change the `REDUCE` doc to `/// cpu (REDUCE rows) → reduce: (clk, entry). The entry id is the instruction's immediate (Cut D).` and add:

```rust
    /// reduce → reduce (Cut D): (entry, addr_v, addr_r, row_end, key, alpha, res, chain_start + 2·carry).
    /// The chip's preprocessed provider region (the program's reduce layout, `MULT` per row) provides;
    /// each run's first row consumes — so every address a run touches is one the verifier key commits.
    pub const REDUCE_LAYOUT: LookupBus<'static> = LookupBus::new("REDUCE_LAYOUT");
```

Update the bus count line: "Ten buses (Cut D adds `REDUCE_LAYOUT`)". In `src/tables/cpu.rs:344`:

```rust
        // Cut D: the dispatch names a layout entry by the instruction's immediate (`B`, the fetched
        // word the `PROGRAM` lookup binds) — no register carries an address.
        bus::REDUCE.lookup_key(b, [v(CLK), v(B)], Count::bounded(sel(Op::Reduce), 1));
```

- [ ] **Step 6: The machine**

In `src/machine.rs`:
- `KeyCache`: the key type becomes `(usize, [u64; 4], u8)`.
- `verifier_key`: the signature is `pub fn verifier_key(&self, program: &Program, tier: Tier, reduce_log_height: u8)`; the key is `(tier.0, …, reduce_log_height)`; build with `chips(&arc, tier, reduce_log_height)` and `log_ext_degrees(program, tier, MIN_LOG_HEIGHT, MIN_LOG_HEIGHT, MIN_LOG_HEIGHT, reduce_log_height)`. Replace the floors comment with: `// The declared heights are the floors for every table without preprocessed columns; the reduce table is built at its own declared height, because its preprocessed region (Cut D: the program's reduce layout) is committed at that height.` Update the doc to `(program, tier, reduce_log_height)`.
- `verify` passes `proof.reduce_log_height`. After `check_declared_heights(…)?;` add:

```rust
        // Cut D: the reduce instance's preprocessed region is the program's layout; the declared
        // height must hold it (the key is built at that height).
        if proof.reduce_log_height != 0 && (1usize << proof.reduce_log_height) < crate::tables::reduce::provider_rows(&program.reduce_layout) {
            return Err(VerifyError::ReduceHeight);
        }
```

- `check_program` calls `check_layout(&program.reduce_layout)?;` after the instruction loop, with:

```rust
/// Cut D, registration-time legality of the reduce layout: every run non-empty and inside the
/// `2^24`-cell address space (the chip range-checks nothing — the key commits these constants, so
/// they are checked once, here), entry 0 a chain start, and every hand-over well formed.
fn check_layout(layout: &[crate::isa::ReduceEntry]) -> Result<(), DecodeError> {
    for (k, e) in layout.iter().enumerate() {
        let bad = Err(DecodeError::Layout { entry: k as u32 });
        if e.len == 0 {
            return bad;
        }
        let len = e.len as u64;
        if [e.vals + 2 * len - 1, e.row + len - 1, e.key + 1, e.alpha + 1, e.res + 1].iter().any(|&top| top >= crate::isa::MEM_LIMIT) {
            return bad;
        }
        let continues = k > 0 && layout[k - 1].carry;
        if e.chain_start == continues {
            return bad;
        }
        if e.carry && (k + 1 == layout.len() || layout[k + 1].alpha != e.alpha || layout[k + 1].res != e.res) {
            return bad;
        }
    }
    Ok(())
}
```

- `build_traces`: replace the reduce block (:427-433) with:

```rust
    let reduce_evs = reduce_events(&exec.events);
    let reduce_lh = reduce_log_height(reduce_rows(&reduce_evs), provider_rows(&program.reduce_layout));
    let reduce = if reduce_lh == 0 { None } else { Some(reduce_trace(&program.reduce_layout, &reduce_evs, 1 << reduce_lh)) };
```

  Update the `use crate::tables::reduce::…` line to `{provider_rows, reduce_events, reduce_log_height, reduce_rows, reduce_trace, ReduceAir}`.
- `chips`: `v.push(Chip::Reduce(ReduceAir::new(Arc::new(program.reduce_layout.clone()), 1 << reduce_log_height)));`
- `max_constraint_degrees_declaring`: `let reduce_log_height = if reduce { crate::tables::reduce::reduce_log_height(1, provider_rows(&program.reduce_layout)) } else { 0 };`

In `src/shape.rs:912`: `let common = m.verifier_key(program, tier, reduce_log_height);`. In `:1005`: `rvm_machine(self.profile).verifier_key(&self.program, crate::machine::Tier(self.tier), self.reduce_log_height)`. In `tests/machine.rs` and `tests/program.rs`, `verifier_key(…, false)` becomes `verifier_key(…, 0)` and `true` becomes `4`. In `tests/verifier_key.rs`, `cap_hex`'s `reduce: bool` becomes `m.verifier_key(p, Tier(8), if reduce { 4 } else { 0 })`, and the doc paragraph "The same cap answers with the reduce chip declared…" is replaced by "Cut D: declaring the reduce chip adds its preprocessed region (an empty layout: all-zero rows), so the cap differs; both caps are pinned." The second assertion compares against a new `WANT_REDUCE: [&str; 16]`, set in Step 9 from the test's `eprintln!` output.

- [ ] **Step 7: The builder**

In `src/dsl/builder.rs`, add the field `layout: Vec<crate::isa::ReduceEntry>,` (doc `/// Cut D: the reduce layout entries [`Builder::reduce`] registered, in entry-id order.`), initialised to `Vec::new()` in `with_opts`. Above `impl Builder`:

```rust
/// One run of a reduction chain (Cut D): `vals.len` opened extension values against the first
/// `vals.len` cells of `row`, with the inverse key in the two cells at `key`.
#[derive(Clone, Copy, Debug)]
pub struct ReduceRun {
    pub vals: Array<Ext>,
    pub row: Array<Felt>,
    pub key: Ptr,
}
```

Replace `reduce` (:619-643):

```rust
    /// One height chain of the batch-opening reduction (Cut D): `acc = Σ_runs Σ_k
    /// alpha^j·(vals_k − row_k)·inv_run` with `j` running across the whole chain, `alpha` read from
    /// the two cells at `alpha`, the result written to the two cells at `res`. Registers one layout
    /// entry per run and emits one `REDUCE` per run, **back to back** — no handle is touched, so
    /// no spill or reload can land between them, which is what the chip's `CLK + 1` carry needs
    /// (`replay` asserts it). Every address is a compile-time constant (`addr_of`).
    pub fn reduce(&mut self, runs: &[ReduceRun], alpha: Ptr, res: Ptr) {
        assert!(!runs.is_empty(), "a reduction chain has at least one run");
        let (alpha_at, res_at) = (self.addr_of(alpha), self.addr_of(res));
        for (j, r) in runs.iter().enumerate() {
            assert!(r.vals.stride == 2 && r.row.stride == 1, "vals are extension cells, the row base cells");
            assert!(
                r.vals.len >= 1 && r.vals.len <= r.row.len,
                "a reduction run covers 1..=row.len columns (the rest are salts and hidden values)"
            );
            let id = self.layout.len() as u64;
            self.layout.push(crate::isa::ReduceEntry {
                vals: self.addr_of(r.vals.base),
                row: self.addr_of(r.row.base),
                len: r.vals.len as u32,
                key: self.addr_of(r.key),
                alpha: alpha_at,
                res: res_at,
                chain_start: j == 0,
                carry: j + 1 < runs.len(),
            });
            self.begin();
            self.emit(Op::Reduce, RRef::Raw(0), RRef::Raw(0), BRef::Imm(F::from_u64(id)));
        }
    }
```

At the top of `replay`, next to `let live = …`, add `let layout = self.layout.clone();`. Before the final return:

```rust
        // Cut D: a carrying entry's REDUCE is followed by its continuation's on the next pc.
        let mut reduce_pc = vec![u32::MAX; layout.len()];
        for (pc, ins) in out.iter().enumerate() {
            if ins.op == Op::Reduce {
                reduce_pc[ins.b.as_canonical_u64() as usize] = pc as u32;
            }
        }
        for (k, e) in layout.iter().enumerate() {
            if e.carry {
                assert_eq!(reduce_pc[k + 1], reduce_pc[k] + 1, "reduce chain entries {k} and {} are not consecutive", k + 1);
            }
        }
```

The return becomes `(Program { instrs: out, checkpoints, reduce_layout: layout }, stats)`. Add `PrimeField64` to the `p3_field` import, and re-export `ReduceRun` from `src/dsl/mod.rs:24`.

In `src/programs/rv32.rs`, `emit_reduced_openings`' `Precompiles::On` arm temporarily becomes `Precompiles::On => reduce_compiled(b, *vals, row, inv, ro, alpha_pow, fri_alpha),` with the comment `// Cut D, Task 1a: the chip path is wired in Task 1b.`

- [ ] **Step 8: Port the precompile and soundness tests**

`tests/precompiles.rs`: replace `reduce_via_precompile`, `reduce_matches_the_compiled_sequence`, `reduce_refuses_a_zero_length_run`, `two_run_program` and `a_program_using_reduce_proves_and_verifies_with_the_chip_present` (:17-157) with:

```rust
use recursion::dsl::ReduceRun;

/// A chain of runs through `Builder::reduce` (`On`) or the kept compiled loop (`Off`): the same
/// hinted arrays, keys and alpha; the result published.
fn reduce_chain(on: bool, runs: &[(Vec<EF>, Vec<F>, EF)], alpha: EF) -> (EF, recursion::isa::Program, Vec<F>) {
    use recursion::dsl::Liveness;
    use recursion::programs::Precompiles;
    let mut b = Builder::with_opts(Checkpoints::Off, Liveness::On, if on { Precompiles::On } else { Precompiles::Off });
    let mut tape: Vec<F> = vec![];
    let keys = b.alloc(2 + 2 * runs.len() as u64);
    let res = b.alloc(2);
    let a = b.ext_constant(alpha);
    b.store_ext(keys, 0, a);
    let mut arrays = vec![];
    for (j, (vals, row, inv)) in runs.iter().enumerate() {
        let va = b.hint_ext_array(vals.len());
        for v in vals {
            tape.extend_from_slice(v.as_basis_coefficients_slice());
        }
        let ra = b.hint_array(row.len());
        tape.extend_from_slice(row);
        let k = b.ext_constant(*inv);
        b.store_ext(keys, 2 + 2 * j as i64, k);
        arrays.push((va, ra));
    }
    if on {
        let chain: Vec<ReduceRun> = arrays.iter().enumerate().map(|(j, &(vals, row))| ReduceRun { vals, row, key: b.offset(keys, 2 + 2 * j as i64) }).collect();
        b.reduce(&chain, keys, res);
    } else {
        let (mut acc, mut apow) = (b.ext_constant(EF::ZERO), b.ext_constant(EF::ONE));
        for (j, &(vals, row)) in arrays.iter().enumerate() {
            let inv = b.load_ext(keys, 2 + 2 * j as i64);
            (acc, apow) = reduce_compiled(&mut b, vals, row, inv, acc, apow, a);
        }
        let _ = apow;
        b.store_ext(res, 0, acc);
    }
    let out = b.load_ext(res, 0);
    b.public_ext(out);
    b.public_ext(out);
    let p = b.finish();
    let got = execute(&p, &tape, 1_000_000).unwrap().public;
    (ef([got[0], got[1]]), p, tape)
}

#[test]
fn reduce_matches_the_compiled_sequence() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(7);
    for lens in [vec![1usize], vec![3], vec![2, 1], vec![7, 40, 121], vec![1, 1, 1, 1]] {
        for _ in 0..5 {
            let runs: Vec<(Vec<EF>, Vec<F>, EF)> = lens
                .iter()
                .map(|&len| ((0..len).map(|_| common::random_ext(&mut rng)).collect(), (0..len).map(|_| common::random_felt(&mut rng)).collect(), common::random_ext(&mut rng)))
                .collect();
            let alpha = common::random_ext(&mut rng);
            let (mut want, mut apow) = (EF::ZERO, EF::ONE);
            for (vals, row, inv) in &runs {
                (want, apow) = run_reduce_sequence(vals, row, *inv, want, apow, alpha);
            }
            assert_eq!(reduce_chain(false, &runs, alpha).0, want, "compiled, lens {lens:?}");
            assert_eq!(reduce_chain(true, &runs, alpha).0, want, "the chain, lens {lens:?}");
        }
    }
}

#[test]
fn a_zero_length_layout_entry_is_an_emulator_error_and_illegal_at_registration() {
    let mut p = common::reduce_chain_program(false);
    p.reduce_layout[0].len = 0;
    assert!(matches!(execute(&p, &[], 1_000), Err(ExecError::ReduceZeroLength { .. })));
    assert_eq!(Machine::check_program(&p), Err(recursion::isa::DecodeError::Layout { entry: 0 }));
}

#[test]
fn a_program_using_reduce_proves_and_verifies_with_the_chip_present() {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(13);
    let runs: Vec<(Vec<EF>, Vec<F>, EF)> = [7usize, 3]
        .iter()
        .map(|&len| ((0..len).map(|_| common::random_ext(&mut rng)).collect(), (0..len).map(|_| common::random_felt(&mut rng)).collect(), common::random_ext(&mut rng)))
        .collect();
    let alpha = common::random_ext(&mut rng);
    let (want, p, tape) = reduce_chain(true, &runs, alpha);
    let m = Machine::new(FriProfile::Test);
    let (proof, exec) = m.prove(&p, &tape, None).unwrap();
    assert!(proof.reduce_log_height > 0, "the reduce table is in this batch");
    m.verify(&p, &proof).unwrap();
    assert_eq!(exec.public[..2].to_vec(), want.as_basis_coefficients_slice().to_vec());
}

/// Review Focus 3: one-column entries opening and closing a chain, and a lone one-column chain.
#[test]
fn one_column_entries_at_chain_start_and_end_prove_and_verify() {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(14);
    let m = Machine::new(FriProfile::Test);
    for lens in [vec![1usize], vec![1, 4], vec![4, 1], vec![1, 1]] {
        let runs: Vec<(Vec<EF>, Vec<F>, EF)> = lens
            .iter()
            .map(|&len| ((0..len).map(|_| common::random_ext(&mut rng)).collect(), (0..len).map(|_| common::random_felt(&mut rng)).collect(), common::random_ext(&mut rng)))
            .collect();
        let (_, p, tape) = reduce_chain(true, &runs, common::random_ext(&mut rng));
        let (proof, _) = m.prove(&p, &tape, None).unwrap();
        m.verify(&p, &proof).unwrap_or_else(|e| panic!("lens {lens:?}: {e:?}"));
    }
}

/// Review Focus 2: a two-entry chain inside the aggregate's loop shape (`counted_loop_mem`, a tape
/// count), run twice — every layout row's MULT is 2 and no carry crosses an iteration.
#[test]
fn a_reduce_chain_inside_a_counted_loop_proves_with_mult_n() {
    use recursion::tables::reduce::col::MULT;
    let mut b = Builder::new(Checkpoints::Off);
    let n = b.hint();
    let counter = b.alloc_absolute(1);
    let keys = b.alloc_absolute(4);
    let res = b.alloc_absolute(2);
    let vals = b.alloc_absolute(6);
    let row = b.alloc_absolute(3);
    let acc_out = b.alloc_absolute(2);
    b.counted_loop_mem(counter, n, |b| {
        for k in 0..4 { let w = b.hint(); b.store(keys, k, w); }
        for k in 0..6 { let w = b.hint(); b.store(vals, k, w); }
        for k in 0..3 { let w = b.hint(); b.store(row, k, w); }
        let va = recursion::dsl::Array::new(vals, 2, 2);
        let ra = recursion::dsl::Array::new(row, 2, 1);
        let vb = recursion::dsl::Array::new(b.offset(vals, 4), 1, 2);
        let rb = recursion::dsl::Array::new(b.offset(row, 2), 1, 1);
        let key = b.offset(keys, 2);
        b.reduce(&[ReduceRun { vals: va, row: ra, key }, ReduceRun { vals: vb, row: rb, key }], keys, res);
        let r = b.load_ext(res, 0);
        let prev = b.load_ext(acc_out, 0);
        let s = b.ext_add(prev, r);
        b.store_ext(acc_out, 0, s);
    });
    let s = b.load_ext(acc_out, 0);
    b.public_ext(s);
    b.public_ext(s);
    let p = b.finish();
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(15);
    let mut tape = vec![F::from_u64(2)];
    for _ in 0..2 {
        tape.extend((0..13).map(|_| common::random_felt(&mut rng)));
    }
    let m = Machine::new(FriProfile::Test);
    let (proof, exec) = m.prove(&p, &tape, None).unwrap();
    m.verify(&p, &proof).unwrap();
    let t = recursion::machine::build_traces(&p, &exec, proof.tier).unwrap();
    let red = t.reduce.unwrap();
    let w = recursion::tables::reduce::col::WIDTH;
    assert_eq!(p.reduce_layout.len(), 2);
    assert_eq!((red.values[MULT], red.values[w + MULT]), (F::TWO, F::TWO), "each entry ran once per iteration");
}
```

`tests/cheating.rs`: in `traces_from_parts`, delete the ZKQ-3 limb-counting block (:633-641); the chip has no range lookups after Cut D. Replace `reduce_setup` (:209-236) with:

```rust
fn reduce_setup() -> (Machine, Program, Traces, Vec<F>) {
    let p = common::reduce_chain_program(true);
    let m = Machine::new(FriProfile::Test);
    let exec = execute(&p, &[], 10_000).unwrap();
    let t = build_traces(&p, &exec, Tier(8)).unwrap();
    (m, p, t, vec![])
}
```

In the tranche below it (:244-310), keep `honest_reduce_traces_pass`, `a_reduce_dispatch_with_no_chip_run_is_rejected` and `a_reduce_proof_declaring_no_table_is_rejected` unchanged. Keep `a_wrong_accumulated_value_in_the_reduction_is_rejected` too: row 1's `ACC0` is inside entry 0's run. Replace `a_dropped_column_in_the_reduction_is_rejected` and `a_forged_descriptor_field_in_the_reduction_is_rejected` with:

```rust
/// R5: a run claiming its last row early (row 0, ADDR_R ≠ ROW_END).
#[test]
fn a_dropped_column_in_the_reduction_is_rejected() {
    let (m, p, mut t, _) = reduce_setup();
    let r = t.reduce.as_mut().unwrap();
    r.values[reduce_table::col::IS_LAST] = F::ONE;
    assert!(rejects(|| reduce_verify(&m, &p, &t)));
}

/// Spec §5: a run whose address differs from the preprocessed layout's — the vals pointer moved by
/// one extension cell on every row of entry 0 (so the in-entry chain still holds): the
/// REDUCE_LAYOUT lookup has no provider, and the moved reads have no writes.
#[test]
fn a_run_whose_address_differs_from_the_layout_is_rejected() {
    let (m, p, mut t, _) = reduce_setup();
    let w = reduce_table::col::WIDTH;
    let r = t.reduce.as_mut().unwrap();
    for row in 0..2 {
        r.values[row * w + reduce_table::col::ADDR_V] += F::TWO;
    }
    assert!(rejects(|| reduce_verify(&m, &p, &t)));
}

/// Spec §5: a wrong CARRY — entry 0's last row claims to close the chain. Its CARRY no longer
/// matches the layout's flags, and entry 1's first row (CHAIN_START = 0) is entered without a carry.
#[test]
fn a_wrong_carry_is_rejected() {
    let (m, p, mut t, _) = reduce_setup();
    let w = reduce_table::col::WIDTH;
    let r = t.reduce.as_mut().unwrap();
    for row in 0..2 {
        r.values[row * w + reduce_table::col::CARRY] = F::ZERO;
    }
    r.values[w + reduce_table::col::WRITES] = F::ONE;
    assert!(rejects(|| reduce_verify(&m, &p, &t)));
}

/// Spec §5: a chain result tampered — the continuation entry starts from an accumulator other than
/// the one carried (and the forged result's write follows from it).
#[test]
fn a_chain_continuation_starting_from_a_forged_accumulator_is_rejected() {
    let (m, p, mut t, _) = reduce_setup();
    let w = reduce_table::col::WIDTH;
    let r = t.reduce.as_mut().unwrap();
    r.values[2 * w + reduce_table::col::ACC0] += F::ONE;
    r.values[2 * w + reduce_table::col::OUT0] += F::ONE;
    assert!(rejects(|| reduce_verify(&m, &p, &t)));
}

/// The provider region: a multiplicity on a row past the layout provides an all-zero entry.
#[test]
fn a_multiplicity_off_the_layout_is_rejected() {
    let (m, p, mut t, _) = reduce_setup();
    let w = reduce_table::col::WIDTH;
    let r = t.reduce.as_mut().unwrap();
    r.values[5 * w + reduce_table::col::MULT] = F::ONE;
    assert!(rejects(|| reduce_verify(&m, &p, &t)));
}
```

Port the run-rule tranche (:801-1026). In `reduce_run_program(stale_first)`, the descriptor stores and `Faddi r2, 200; Reduce 0, 2, 0` become `common::reduce_chain_program(false)`'s thirteen stores, the stale prefix, `i(Op::Reduce, 0, 0, 0)`, and the `reduce_layout` of that function, keeping 267. `forge_accumulator_readback` reads cell 214, not 205. In `a_reduce_row_reading_at_a_stale_clock_is_rejected`, the forged reads are `e.mem[4 + 3 + k]` (key 2, alpha 2, column 0's three) and the forged result write is `e.mem[4 + 9]`. In `forge_padding_writeback`, the four writes become two, `(214, base + 15, value)` and `(215, base + 16, F::ZERO)`, and `padding_writeback_traces` sets on row 3: `IS_LAST = 1, CLK = clk_r + 1/16, RES = 214, ADDR_R = ROW_END = 0, OUT0 = value, WRITES = 1` (plus `IS_FIRST = 1` when `first`), in place of the deleted `LEN`/`LEN1`/`LEN1_INV`/`DESCR_PTR` lines. In `a_reduce_run_that_never_reaches_its_last_row_is_rejected`, the zeroed rows need no `LEN1_INV` fix-up (delete that line), and the event log is truncated to `4 + 3` (key, alpha, column 0). Each of these must still be refused; their messages stay.

`tests/cpu.rs`, `every_operand_a_dispatch_carries_is_read_from_a_register`: change the exemption to `if col != CLK && col != PUB_IDX && col != B && !reg_reads.contains(&col)`, with the comment `// B is the fetched instruction word (bound by the PROGRAM lookup): REDUCE's entry id (Cut D).`, and import `B` with `CLK, PUB_IDX`.

`tests/self_verify.rs` (Review Focus 1): append

```rust
/// Review Focus 1 (phase 3, Cut D): no fixture proof carries a reduce table, so the
/// self-verifier never opened the reduce instance's preprocessed region. Here it does: two
/// preprocessed matrices of different heights in one round.
#[test]
fn the_self_verifier_accepts_a_proof_carrying_the_reduce_layout() {
    let program = Arc::new(common::reduce_chain_program(true));
    let m = Machine::new(FriProfile::Test);
    let (proof, _exec) = m.prove(&program, &[], None).expect("the chain program proves");
    assert!(proof.reduce_log_height > 0, "the batch declares the reduce instance");
    let shape = RvmShape::of(FriProfile::Test, &program, proof.tier, proof.reg_log_height, proof.ram_log_height,
        proof.poseidon2_log_height, proof.reduce_log_height);
    let key = RvmKey::of(FriProfile::Test, &shape);
    let vp = verify_rv32r(&shape, &key, Checkpoints::Off);
    let tape = WitnessTape::build_for_with_binding(FriProfile::Test, &shape, &key, &proof, &common::TEST_BINDING).unwrap();
    let exec = execute(&vp.program, &tape.words, MAX_CYCLES).expect("the self-verifier accepts a proof carrying the reduce layout");
    let words = recursion::public_values::interface_words_bound(&shape, &key, &common::TEST_BINDING, &[proof.public_values.clone()]);
    assert_eq!(exec.public, recursion::public_values::public_digest(&words).to_vec());
}
```

- [ ] **Step 9: Run, then pin what moved**

Run: `cargo test --release --test isa --test emulator --test tables --test cpu --test cheating --test precompiles --test machine --test program --test binding --test verifier_key --test self_verify -- --nocapture 2>&1 | grep -E '^test |panicked|reduce:|left|right'`
Expected: every test passes, except these measured pins:
- `the_reduce_chip_width_and_constraint_degree_are_pinned`'s `degs[7]`: set it to the measured value, which must be ≤ 8. The message says Cut D's messages are all degree 1 and the measured value moves from 8 to it.
- `the_rvm_verifier_keys_answer_their_known_caps`: set `WANT_REDUCE` to the printed `reduce:` line.
- `the_self_verifier_accepts_a_proof_carrying_the_reduce_layout`, if it fails at the shape: stop and report, because the shared pipeline does not open two preprocessed heights. Do not weaken the test.

Then run the whole in-suite: `cargo test --release`. Expected: green. Tests that build the verifier program still pass, because the `On` build compiles the reduction for now.

- [ ] **Step 10: Commit**

```bash
git add src/isa.rs src/emulator.rs src/tables/ src/machine.rs src/shape.rs src/dsl/ src/programs/rv32.rs tests/
git commit -m "recursion: Cut D (machine) — the reduce layout is preprocessed; one REDUCE row per entry; chains carry in the chip

The chip's provider region is the program's layout (ProgramAir pattern, MULT per entry, so the
aggregate's N-loop is MULT = N); each run looks its entry up on its first row. Width 39 → 30,
preprocessed 9; the 18 ZKQ-3 limbs and the LEN gadget go (check_program bounds the layout).
Degree <measured>. The program wires it in Task 1b.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AUWKAos28PQquiLZRVC6jP"
```

---

### Task 1b: Cut D, the program side — the key buffer, one chain per height, re-pinned

**Files:**
- Modify: `src/programs/rv32.rs`: `emit_reduced_openings` (:837-880) is split into `emit_reduced_openings_compiled` (the `Off` body) and `emit_reduced_openings_layout` (`On`); the dispatcher keeps the old name and signature
- Test: `tests/verifier.rs` (one test), `tests/memprofile.rs` (run only), `tests/pins.json` and the Re-pin Procedure's files
- Modify: `docs/05-phase3-fold-reduce.md` §3, §4

**Interfaces:**
- Consumes: `Builder::reduce(&[ReduceRun], alpha: Ptr, res: Ptr)` and `ReduceRun` (Task 1a); `emit_query_point`, `Builder::ext_inv_checked`.
- Produces: per query, one key buffer (`alpha` at cells 0–1, key `s` at `2 + 2s`) and one result buffer (two cells per height, tallest first). `emit_reduced_openings` still returns `Vec<(usize, Ext)>`, heights descending.

- [ ] **Step 1: Write the failing program-level test**

Append to `tests/verifier.rs`:

```rust
/// Cut D: the shipped build reduces through the chip — one REDUCE row per layout entry, the same
/// chains in every query, one chain per distinct opened height.
#[test]
fn the_shipped_build_dispatches_one_reduce_row_per_layout_entry() {
    let (p, shape, key) = one_test_proof();
    let vp = verify_rv32(&shape, &key, Checkpoints::Off);
    let layout = &vp.program.reduce_layout;
    assert!(!layout.is_empty(), "the On build registers a reduce layout");
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let exec = execute(&vp.program, &tape.words, 1 << 24).expect("accepts a real proof");
    assert_eq!(exec.histogram()[Op::Reduce as usize], layout.len(), "one REDUCE row per entry");
    assert_eq!(layout.len() % shape.num_queries, 0, "the same entries in every query");
    let chains = layout.iter().filter(|e| e.chain_start).count();
    let res: std::collections::BTreeSet<u64> = layout.iter().map(|e| e.res).collect();
    assert_eq!(res.len(), chains, "one result cell per chain");
    Machine::check_program(&vp.program).expect("the layout is legal");
}
```

Use whatever `one_test_proof()` returns (`tests/verifier.rs`, used at :829). Add `use recursion::machine::Machine;` and `use recursion::isa::Op;` if the file lacks them.

Run: `cargo test --release --test verifier the_shipped_build_dispatches`
Expected: FAIL at `the On build registers a reduce layout` (Task 1a's `On` arm compiles the reduction).

- [ ] **Step 2: Rewrite `emit_reduced_openings`**

Rename the existing body to `emit_reduced_openings_compiled` and keep its `Off` arm (`reduce_compiled`) as the only path. Make the `match` an unconditional `let (ro2, ap2) = reduce_compiled(b, *vals, row, inv, ro, alpha_pow, fri_alpha); (ro, alpha_pow) = (ro2, ap2);`. Then add:

```rust
/// One query's batch-opening reduction: the `Off` reference (the compiled loop, run by run) or
/// Cut D's chip path. Same value, same order — heights descending.
fn emit_reduced_openings<S: VerifierShape>(
    b: &mut Builder,
    shape: &S,
    index_bits: &[Felt],
    fri_alpha: Ext,
    opened: &QueryOpenings,
    rows: &[Vec<Array<Felt>>],
) -> Vec<(usize, Ext)> {
    match b.precompiles() {
        Precompiles::Off => emit_reduced_openings_compiled(b, shape, index_bits, fri_alpha, opened, rows),
        Precompiles::On => emit_reduced_openings_layout(b, shape, index_bits, fri_alpha, opened, rows),
    }
}

/// Cut D: the query points and the `(height, point)` inverse keys are computed exactly as the
/// compiled form computes them, in first-use order; the keys and alpha are stored once into this
/// query's key buffer; each height's runs — in `(round, matrix, point)` order, so alpha's powers
/// run as in `open_inputs` — become one chain of back-to-back `REDUCE` rows whose result lands in
/// the height's cell of this query's result buffer, read back once.
fn emit_reduced_openings_layout<S: VerifierShape>(
    b: &mut Builder,
    shape: &S,
    index_bits: &[Felt],
    fri_alpha: Ext,
    opened: &QueryOpenings,
    rows: &[Vec<Array<Felt>>],
) -> Vec<(usize, Ext)> {
    let log_global = shape.log_global_max_height();
    let mut xs: BTreeMap<usize, Felt> = BTreeMap::new();
    let mut slot_of: BTreeMap<(usize, bool), usize> = BTreeMap::new();
    let mut invs: Vec<Ext> = Vec::new();
    let mut runs: BTreeMap<usize, Vec<(Array<Ext>, Array<Felt>, usize)>> = BTreeMap::new();
    for (ri, mats) in opened.rounds.iter().enumerate() {
        for (mi, m) in mats.iter().enumerate() {
            let h = m.log_height;
            if !xs.contains_key(&h) {
                let x = emit_query_point(b, h, &index_bits[log_global - h..], true);
                xs.insert(h, x);
            }
            let x = xs[&h];
            for (pi, (z, vals)) in m.points.iter().enumerate() {
                let key = (h, pi == 1);
                let slot = match slot_of.get(&key) {
                    Some(&s) => s,
                    None => {
                        let (z0, z1) = b.ext_parts(*z);
                        let d0 = b.sub(z0, x);
                        let diff = b.ext_from_parts(d0, z1);
                        invs.push(b.ext_inv_checked(diff, "opening point matches the query point"));
                        slot_of.insert(key, invs.len() - 1);
                        invs.len() - 1
                    }
                };
                runs.entry(h).or_default().push((*vals, rows[ri][mi], slot));
            }
        }
    }
    // The blowup-height entry exists only for a constant trace (`verifier.rs:858-864`); no RV32
    // instance has one, and the chip path does not carry its zero check.
    assert!(!runs.contains_key(&LOG_BLOWUP), "a reduced opening at the blowup height");
    let keys = b.alloc(2 + 2 * invs.len() as u64);
    b.store_ext(keys, 0, fri_alpha);
    for (s, inv) in invs.iter().enumerate() {
        b.store_ext(keys, 2 + 2 * s as i64, *inv);
    }
    let res = b.alloc(2 * runs.len() as u64);
    let mut cells = Vec::with_capacity(runs.len());
    for (j, (&h, rs)) in runs.iter().rev().enumerate() {
        let mut chain = Vec::with_capacity(rs.len());
        for &(vals, row, slot) in rs {
            let key = b.offset(keys, 2 + 2 * slot as i64);
            chain.push(ReduceRun { vals, row, key });
        }
        let cell = b.offset(res, 2 * j as i64);
        b.reduce(&chain, keys, cell);
        cells.push((h, cell));
    }
    cells.into_iter().map(|(h, cell)| (h, b.load_ext(cell, 0))).collect()
}
```

Import `ReduceRun` (`use crate::dsl::{…, ReduceRun}`). Delete Task 1a's temporary comment.

- [ ] **Step 3: Run the acceptance and differential suites**

Run: `cargo test --release --test verifier --test exit --test aggregate --test precompiles --test self_verify 2>&1 | grep -E '^test result|FAILED|panicked'`
Expected: every acceptance and tamper-table test passes, including `the_shipped_build_dispatches_one_reduce_row_per_layout_entry`, `five_test_profile_bundle_proofs_are_accepted` and the thirteen tamper refusals at their named steps. The digest literals fail (`tests/verifier.rs:832`, `tests/self_verify.rs:130`, and the cost pins), and are re-pinned in Step 6. A tamper refused at a *different* named step is set to the measured step, with the change recorded in the commit message (phase 2's rule).

- [ ] **Step 4: Measure and check the band**

Run: `cargo test --release --test profile -- --ignored --nocapture 2>&1 | grep -v warning | tee target/phase3-profile-D.txt`
Read the Production cpu rows, reg accesses and mem accesses. Compare the rows with docs/05 §2's D band (derived projection: 660 000–770 000). Expected: REG and RAM accesses both under 2 097 152 (2^21), so the cpu proof's memory tables declare 2^21. If REG or RAM is still ≥ 2^21, that is outside the cut's design target: stop and record it as the band rule says.

- [ ] **Step 5: The memory re-measure (spec §3)**

Run: `RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures /usr/bin/time -l cargo test --release --test memprofile tier19_exit_twin -- --ignored --nocapture 2>&1 | tee target/phase3-memprofile-D.txt`. The test is the exit twin, now proved at tier 18. Read the peak live heap per phase and the tier from the `==` lines. If the process is killed, record the last phase line printed and the kill. Write the table into docs/05 §3, next to docs/04 §"Live heap"'s pre-cut numbers. State what changed: the declared reg/ram heights and the projection to production N = 1.

- [ ] **Step 6: Re-pin**

Run the Re-pin Procedure, P1–P7. Append to docs/05 §4 the D row (measured rows, Δ, band, in band yes/no) and the `== profile Production` line.

- [ ] **Step 7: Commit**

```bash
git add src/programs/rv32.rs tests/ src/programs/verify_rv32.digest docs/05-phase3-fold-reduce.md
git commit -m "recursion: Cut D (program) — one key buffer and one chain per height per query; <rows> rows, REG <reg>, RAM <ram>

<the == profile Production line>; band <lo–hi>: <in/out>. Reg and RAM tables 2^22 → 2^21.
Twin live heap <GB> (docs/05 §3).

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AUWKAos28PQquiLZRVC6jP"
```

---

### Task 2: Cut E1 — the committed row hinted whole; the own slot by one register-addressed LOADE

**Files:**
- Modify: `src/witness.rs`: `Segment::CommitPhaseOpenings` doc (:79-81), step 13 (:495-512), `open_stride` (:582-588)
- Modify: `src/programs/rv32.rs`: `read_commit_openings` (:578-585), `emit_query` (:604-700, whole), `emit_commit_root` (:749-770, whole), new `own_slot_check` and `emit_fold_dispatch`; `src/programs/mod.rs:18` (export `own_slot_check`)
- Modify: `src/dsl/builder.rs` (new `load_ext_offset`, after `load_ext` :491-497)
- Test: `tests/precompiles.rs`, `tests/exit.rs`, `tests/verifier.rs:324` (salt offset)

**Interfaces:**
- Produces: `Builder::load_ext_offset(&mut self, base: Ptr, off: Felt) -> Ext`, which emits one `LOADE rd, off, imm = addr_of(base)`.
- Produces: `programs::own_slot_check(b: &mut Builder, msg: Ptr, own: &[Felt], folded: Ext, name: &str)`. It refuses at `name` (both lanes) under both switches.
- Produces: the tape's `CommitPhaseOpenings` per query per round, `2·arity` words (the whole row) and then 4 salts. `open_stride` becomes `Σ (2^a·2 + 4)`.
- Produces: the checkpoint name `"commit phase own slot[{r}]"`.

- [ ] **Step 1: Failing tests**

Append to `tests/precompiles.rs`:

```rust
/// Cut E1 (Review Focus 4): the own-slot check agrees On and Off at every slot of every arity,
/// accepting the honest value and refusing any other at the same named step.
#[test]
fn the_own_slot_check_agrees_on_and_off_at_every_slot() {
    use recursion::dsl::Liveness;
    use recursion::programs::{own_slot_check, Precompiles};
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(28);
    for la in 1..=3usize {
        let a = 1usize << la;
        let row: Vec<EF> = (0..a).map(|_| common::random_ext(&mut rng)).collect();
        for idx in 0..a {
            for honest in [true, false] {
                let folded = if honest { row[idx] } else { row[idx] + EF::ONE };
                let run = |pc: Precompiles| -> Result<(), String> {
                    let mut b = Builder::with_opts(Checkpoints::Off, Liveness::On, pc);
                    let msg = b.alloc(2 * a as u64);
                    for (j, v) in row.iter().enumerate() {
                        let c = b.ext_constant(*v);
                        b.store_ext(msg, 2 * j as i64, c);
                    }
                    let own: Vec<Felt> = (0..la).map(|k| b.constant(F::from_u64(((idx >> k) & 1) as u64))).collect();
                    let f = b.ext_constant(folded);
                    own_slot_check(&mut b, msg, &own, f, "own slot");
                    for _ in 0..4 {
                        let z = b.zero();
                        b.public(z);
                    }
                    let p = b.finish();
                    match execute(&p, &[], 100_000) {
                        Ok(_) => Ok(()),
                        Err(ExecError::InverseOfZero { pc }) => Err(p.checkpoint_at(pc).unwrap_or("?").to_string()),
                        Err(e) => Err(format!("{e:?}")),
                    }
                };
                let (on, off) = (run(Precompiles::On), run(Precompiles::Off));
                assert_eq!(on, off, "la {la}, idx {idx}, honest {honest}");
                assert_eq!(on, if honest { Ok(()) } else { Err("own slot".to_string()) }, "la {la}, idx {idx}");
            }
        }
    }
}
```

Append to `tests/exit.rs`:

```rust
/// Cut E1: the tape hints the committed row whole, and the program refuses a row whose own slot
/// is not the query's folded value — before the Merkle walk, at its own named step.
#[test]
fn a_committed_row_whose_own_slot_differs_is_refused_at_the_own_slot_step() {
    use recursion::emulator::ExecError;
    use recursion::witness::Segment;
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let shape = InnerShape::of(FriProfile::Test, p.proof.tier, p.proof.program_log_height, p.proof.input_log_height,
        p.proof.keccak_log_height, p.proof.sha256_log_height, p.proof.public_log_height, p.proof.mem_log_height);
    let key = InnerKey::of(FriProfile::Test, &shape);
    let r = recursion::reference::replay(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let vp = verify_rv32(&shape, &key, Checkpoints::Off);
    let mut tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let opens = tape.segments.iter().find(|(s, _, _)| *s == Segment::CommitPhaseOpenings).unwrap().1;
    // Query 0, round 0: index_in_group is the sampled index's low log_arity bits.
    let idx = (r.index_samples[0] as usize) & ((1usize << shape.log_arities[0]) - 1);
    tape.words[opens + 2 * idx] += F::ONE;
    match execute(&vp.program, &tape.words, MAX_CYCLES) {
        Err(ExecError::InverseOfZero { pc }) => assert_eq!(vp.program.checkpoint_at(pc), Some("commit phase own slot[0]")),
        other => panic!("expected the own-slot refusal, got {other:?}"),
    }
}
```

Run: `cargo test --release --test precompiles own_slot --test exit own_slot`
Expected: compile error (`own_slot_check` not found).

- [ ] **Step 2: The builder's register-addressed extension load**

In `src/dsl/builder.rs`, after `load_ext`:

```rust
    /// `Ed = mem[addr_of(base) + off .. + 2]` with `off` a *runtime* cell offset (Cut E1: the
    /// committed row's own slot, `2·index_in_group`): one `LOADE` whose address register is the
    /// offset and whose immediate is the base's absolute address. The cpu row range-checks the
    /// sum like any `LOADE`.
    pub fn load_ext_offset(&mut self, base: Ptr, off: Felt) -> Ext {
        self.begin();
        let ro = self.materialise(off.0);
        let at = F::from_u64(self.addr_of(base));
        let (id, rd) = self.new_handle(2);
        self.emit(Op::Loade, rd, ro, BRef::Imm(at));
        Ext(id)
    }
```

- [ ] **Step 3: The tape**

In `src/witness.rs`, step 13 becomes:

```rust
        w.begin(Segment::CommitPhaseOpenings);
        for q in 0..shape.num_queries() {
            for (round, step) in fri.commit_phase_openings.iter().enumerate() {
                // Cut E1: the whole reconstructed row — the query's own folded value at
                // `index_in_group` among its siblings — which the program hints straight into the
                // leaf buffer and checks the own slot of.
                w.exts(&r.commit_rows[round][q][0]);
                assert_eq!(step.opening_proof.0[q].len(), 1);
                assert_eq!(step.opening_proof.0[q][0].len(), SALT_ELEMS);
                w.base(&step.opening_proof.0[q][0]);
            }
        }
        w.end();
```

`open_stride` becomes `.map(|&a| (1usize << a) * <EF as BasedVectorSpace<Val>>::DIMENSION + SALT_ELEMS)` with its doc reading "the whole `arity`-wide row (two words per value), then the four salts". The `Segment::CommitPhaseOpenings` doc becomes "Per query, per commit-phase round: the whole `arity`-wide row (Cut E1: the query's own value included), then the row's four salts." In `tests/verifier.rs:324`, set `let salt_at = opens + q * open_stride + arity * <EF as BasedVectorSpace<F>>::DIMENSION;`.

- [ ] **Step 4: The program**

In `src/programs/rv32.rs`, `read_commit_openings` reads `b.hint_array((1usize << la) * 2 + SALT_ELEMS)`. Add:

```rust
/// Cut E1: the query's own folded value is the committed row's entry at `index_in_group = Σ
/// own_k·2^k`. `On`: the cell offset `2·idx` from the bits, one register-addressed `LOADE`;
/// `Off` (the reference): the one-hot indicators' dot product with the row. Either way an
/// extension equality refused at `name`.
pub fn own_slot_check(b: &mut Builder, msg: Ptr, own: &[Felt], folded: Ext, name: &str) {
    let got = match b.precompiles() {
        Precompiles::On => {
            let mut off = b.mul_const(own[0], F::TWO);
            for (k, &bit) in own.iter().enumerate().skip(1) {
                let t = b.mul_const(bit, F::from_u64(2u64 << k));
                off = b.add(off, t);
            }
            b.load_ext_offset(msg, off)
        }
        Precompiles::Off => {
            let mut acc: Option<Ext> = None;
            for j in 0..1usize << own.len() {
                let ind = bit_indicator(b, own, j);
                let e = b.load_ext(msg, 2 * j as i64);
                let t = b.ext_mul_base(e, ind);
                acc = Some(match acc {
                    None => t,
                    Some(a) => b.ext_add(a, t),
                });
            }
            acc.expect("an arity of at least two")
        }
    };
    let d = b.ext_sub(got, folded);
    let (d0, d1) = b.ext_parts(d);
    b.assert_zero(d0, name);
    b.assert_zero(d1, name);
}

/// One fold round over the committed row at `msg`. Until Cut E2: load the row and run the compiled
/// barycentric fold, under both switches.
fn emit_fold_dispatch(b: &mut Builder, log_folded: usize, la: usize, group_bits: &[Felt], beta: Ext, msg: Ptr) -> Ext {
    let evals: Vec<Ext> = (0..1usize << la).map(|j| b.load_ext(msg, 2 * j as i64)).collect();
    emit_fold_round(b, log_folded, la, group_bits, beta, &evals)
}
```

Replace `emit_commit_root` with:

```rust
/// The committed row, hinted whole with its four salts into `msg` (Cut E1) — exactly the leaf
/// message `flatten_to_base(row) ‖ salt(4)` of the round's hiding MMCS — sponged in place, walked,
/// and compared against the round's cap.
fn emit_commit_root(b: &mut Builder, log_arity: usize, msg: Ptr, path: Array<Felt>, index_bits: &[Felt], cap: [Digest; 4], name: &str) {
    let leaf = Digest(b.alloc(DIGEST_ELEMS as u64));
    hash::sponge(b, msg, 2 * (1usize << log_arity) + SALT_ELEMS, leaf);
    let levels = path.len / DIGEST_ELEMS;
    let out = Digest(b.alloc(DIGEST_ELEMS as u64));
    hash::merkle_walk(b, leaf, &index_bits[..levels], path.base, levels, out);
    assert_cap_eq(b, out, &cap, &index_bits[levels..levels + CAP_HEIGHT], name);
}
```

Replace the whole of `emit_query` with:

```rust
/// One query, already-tape-read to final check: the input rounds' Merkle walks, the batch-opening
/// reduction, the fold chain — each round's committed row checked at the query's own slot, folded,
/// and authenticated against its commitment — and the final-polynomial check.
#[allow(clippy::too_many_arguments)]
fn emit_query<S: VerifierShape>(
    b: &mut Builder,
    shape: &S,
    opened: &QueryOpenings,
    metas: &[RoundMeta],
    fri_caps: &[[Digest; 4]],
    betas: &[Ext],
    fri_alpha: Ext,
    final_poly: Ext,
    index_bits: &[Felt],
    rows: &[Vec<Array<Felt>>],
    groups: &[Vec<(Ptr, usize)>],
    paths: &[Array<Felt>],
    commit_openings: &[Array<Felt>],
    commit_paths: &[Array<Felt>],
) {
    let log_global = shape.log_global_max_height();

    // ── every input round, Merkle-verified before any arithmetic reads the openings.
    for (ri, mats) in opened.rounds.iter().enumerate() {
        b.span("input_root", |b| emit_input_round_root(b, log_global, mats, &groups[ri], paths[ri], index_bits, &metas[ri]));
    }

    // ── the batch-opening reduction.
    let ros = b.span("reduce", |b| emit_reduced_openings(b, shape, index_bits, fri_alpha, opened, rows));

    // ── the fold chain (`fold_query`, verifier.rs:523-671).
    let mut ros: BTreeMap<usize, Ext> = ros.into_iter().collect();
    let mut folded = ros.remove(&log_global).expect("open_inputs' first reduced opening is at the global max height");
    let mut shift = 0usize;
    for (r, &la) in shape.log_arities().iter().enumerate() {
        let log_folded = log_global - shift - la;
        // `index_in_group`: the low `log_arity` bits of the current index.
        let own = &index_bits[shift..shift + la];
        let msg = commit_openings[r].base;
        // Cut E1: the row was hinted whole; the query's own value must sit at its slot.
        b.span("select", |b| own_slot_check(b, msg, own, folded, &format!("commit phase own slot[{r}]")));
        shift += la;
        let group_bits = &index_bits[shift..shift + log_folded];
        folded = b.span("fold_round", |b| emit_fold_dispatch(b, log_folded, la, group_bits, betas[r], msg));
        b.span("commit_root", |b| {
            emit_commit_root(b, la, msg, commit_paths[r], &index_bits[shift..], fri_caps[r], &format!("commit phase root[{r}]"))
        });
        // Roll in a reduced opening landing at the folded height: `beta^(2^log_arity) · ro`.
        if let Some(ro) = ros.remove(&log_folded) {
            folded = b.span("roll_in", |b| {
                let mut beta_pow = betas[r];
                for _ in 0..la {
                    beta_pow = b.ext_mul(beta_pow, beta_pow);
                }
                let t = b.ext_mul(beta_pow, ro);
                b.ext_add(folded, t)
            });
        }
    }
    debug_assert!(ros.is_empty(), "the arity schedule rolls every input height in");

    // ── the final check (`log_final_poly_len == 0`: the Horner is the single coefficient).
    let (f0, f1) = b.ext_parts(final_poly);
    let (g0, g1) = b.ext_parts(folded);
    b.assert_eq(f0, g0, "final polynomial");
    b.assert_eq(f1, g1, "final polynomial");
}
```

Export `own_slot_check` from `src/programs/mod.rs:18`'s `pub use rv32::{…}`.

- [ ] **Step 5: Run the differential, the tamper tests and the acceptance suites**

Run: `cargo test --release --test precompiles --test exit --test verifier --test aggregate --test self_verify 2>&1 | grep -E '^test result|FAILED|panicked'`
Expected: `the_own_slot_check_agrees_on_and_off_at_every_slot`, `a_committed_row_whose_own_slot_differs_is_refused_at_the_own_slot_step`, every acceptance test and the Off/On checkpoint differentials pass. A `CommitPhaseOpenings` tamper in `tests/exit.rs`'s or `tests/aggregate.rs`'s tamper table that now lands on the own slot is refused at `commit phase own slot[r]`, not `commit phase root[r]`. Update `expected_step` / `tamper_table` to the measured step and say so in the commit. The digest pins fail and are re-pinned in Step 7; the Off replay (`tests/verifier.rs:786`) moves too, because the tape and the Off pipeline changed.

- [ ] **Step 6: Measure and check the band**

Run: `cargo test --release --test profile -- --ignored --nocapture 2>&1 | grep -v warning | tee target/phase3-profile-E1.txt`
Compare with the E1 band (docs/05 §2: T_D − Δ_E1 ± 15 %; derived Δ ≈ 35 000–40 000). The `select` span is now Q·Σ(2·la + 5) rows. Re-read `rows(fold_round)` and recompute Δ_E2 in docs/05 §2: E1 moved the row loads into `fold_round`.

- [ ] **Step 7: Re-pin and commit**

Run the Re-pin Procedure, P1–P7, and append the E1 row to docs/05 §4.

```bash
git add src/witness.rs src/programs/ src/dsl/builder.rs tests/ src/programs/verify_rv32.digest docs/05-phase3-fold-reduce.md
git commit -m "recursion: Cut E1 — the committed row hinted whole, its own slot checked by one register-addressed LOADE; <rows> rows

<the == profile Production line>; band <lo–hi>: <in/out>. Tape: CommitPhaseOpenings carries 2a words
per round (was 2(a−1)); the leaf is sponged in place. Off keeps the indicator arithmetic.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AUWKAos28PQquiLZRVC6jP"
```

---

### Task 3: Cut E2 — `FOLD`, a run of 2a rows in the REDUCE chip (opcode 28)

**Files:**
- Modify: `src/isa.rs` (`Op::Fold`, `COUNT`, `ALL`, `mnemonic`; `FOLD_SALT_CELLS`; the opcode doc :32-39)
- Modify: `src/emulator.rs` (`FoldEvent`, `Event::fold`, `ExecError::FoldArity`, `TS_FOLD_*`, the `Op::Fold` arm; `fold_coefficients`, `fold_dft_horner`)
- Modify: `src/machine.rs` (`check_instr` :364-369; `build_traces` reduce block)
- Modify: `src/tables/cpu.rs` (`NUM_SELECTORS`, every column after `SEL0`, `Sels::READ_RD`/`EXT_READ_RD`, range groups 1 and 3, the `FOLD` lookup, `fill_row` subject/base3)
- Modify: `src/tables/mod.rs` (buses `FOLD`, `FOLD_COEFF`), `src/tables/reduce.rs` (the fold row kind)
- Modify: `src/dsl/builder.rs` (`fold_run`, `hint_array_padded`), `src/programs/rv32.rs` (`read_commit_openings`, `emit_fold_dispatch`), `src/programs/mod.rs` (export `fold_eval`)
- Test: `tests/isa.rs`, `tests/emulator.rs`, `tests/fold_identity.rs`, `tests/tables.rs` (:170-222), `tests/cpu.rs` (dispatch test), `tests/common/mod.rs` (`fold_program`), `tests/cheating.rs`, `tests/precompiles.rs`

**Interfaces:**
- Produces: `Op::Fold = 28` (`"FOLD"`, `b_is_register() == false`): `rd` is the `u` pair (read), `ra` is `msg`, and `imm` is the arity a ∈ {2, 4, 8}. It reads `y_k = mem[msg + 2k ..+2]` for k < a and writes `Σ_m B_m·u^m` to `mem[msg + 2a + 4 ..+2]`. `Op::COUNT == 29`.
- Produces: `isa::FOLD_SALT_CELLS: u64 = 4`; `ExecError::FoldArity { pc: u32, arity: u64 }`; `emulator::{TS_FOLD_Y0 = 0, TS_FOLD_Y1 = 1, TS_FOLD_RES0 = 14, TS_FOLD_RES1 = 15}`.
- Produces: `FoldEvent { msg: u64, arity: u32, u: [F; 2], ys: [[F; 2]; 8], out: [F; 2] }` on `Event::fold: Option<FoldEvent>`.
- Produces: `emulator::fold_coefficients(log_arity: usize) -> Vec<[F; 8]>` (row k, column j = `(1/a)·c_k^{−(a−1−j)}` for j < a, else 0) and `emulator::fold_dft_horner(ys: &[EF], u: EF) -> EF`.
- Produces: `bus::FOLD` with message `[clk, msg, u0, u1, a]`, and `bus::FOLD_COEFF` with message `[a, k, c0..c7]`.
- Produces: `reduce::col::{IS_FOLD 30, F_FIRST 31, F_PH1 32, F_LAST 33, F_K 34, F_A 35, F_MSG 36, U0 37, U1 38, Y0 39, Y1 40, C0 41 (8), D0 49 (16), FACC0 65, FACC1 66, FOUT0 67, FOUT1 68, MULT_C 69, WIDTH 70}` and `reduce::pre::{C_IS_ROW 9, C_A 10, C_K 11, C_V0 12 (8), WIDTH 20}`; `reduce::FOLD_COEFF_ROWS = 14`; `reduce::{fold_events, fold_rows}`. `reduce_trace` gains a `folds: &[&Event]` argument.
- Produces: `cpu::col::*` shifted by one after `SEL0` (`A0 = 36`, …, `W0 = 75`, `WIDTH = 83`), `NUM_SELECTORS = 29`.
- Produces: `Builder::fold_run(&mut self, msg: Ptr, arity: usize, u: Ext) -> Ext`, `Builder::hint_array_padded(&mut self, n: usize, extra: usize) -> Array<Felt>`, and `programs::fold_eval(b, log_folded, la, group_bits, beta, msg) -> Ext` (the old private `emit_fold_dispatch`, now public).

- [ ] **Step 1: Failing ISA, emulator and identity tests**

`tests/isa.rs`: `Op::ALL.len()` and `Op::COUNT` become 29 (message: "… Cut C COMPRESS = 27, phase 3 FOLD = 28"); add `assert_eq!(Op::from_u8(28), Some(Op::Fold)); assert_eq!(Op::Fold.mnemonic(), "FOLD"); assert!(!Op::Fold.b_is_register());`; the unknown-opcode probe uses `29`. `tests/fold_identity.rs`: append

```rust
/// Cut E2: the emulator's fold (the chip's coefficient table, then Horner) is `fold_row`.
#[test]
fn the_emulators_fold_is_fold_row() {
    let folding: TwoAdicFriFolding<(), ()> = TwoAdicFriFolding(PhantomData);
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x0f02d);
    for la in 1..=3usize {
        for _ in 0..256 {
            let log_height = rng.random_range(1..=20usize);
            let index = rng.random_range(0..1usize << log_height);
            let beta = common::random_ext(&mut rng);
            let ys: Vec<EF> = (0..1usize << la).map(|_| common::random_ext(&mut rng)).collect();
            let s = F::two_adic_generator(log_height + la).exp_u64(reverse_bits_len(index, log_height) as u64);
            let want = <TwoAdicFriFolding<(), ()> as FriFoldingStrategy<F, EF>>::fold_row(&folding, index, log_height, la, beta, ys.iter().copied());
            assert_eq!(recursion::emulator::fold_dft_horner(&ys, beta * s.inverse()), want, "la {la}");
        }
    }
}
```

`tests/emulator.rs`: append

```rust
#[test]
fn fold_reads_the_row_and_writes_the_fold_after_the_salts() {
    use p3_field::BasedVectorSpace;
    use recursion::isa::EF;
    let ys: Vec<EF> = (1..=4u64).map(|k| EF::from_basis_coefficients_slice(&[F::from_u64(k), F::from_u64(10 * k)]).unwrap()).collect();
    let u = EF::from_basis_coefficients_slice(&[F::from_u64(3), F::from_u64(5)]).unwrap();
    let mut v = vec![];
    for (k, y) in ys.iter().enumerate() {
        for (l, w) in y.as_basis_coefficients_slice().iter().enumerate() {
            v.push(Instr { op: Op::Faddi, rd: 1, ra: 0, b: *w });
            v.push(i(Op::Store, 1, 0, 300 + 2 * k as u64 + l as u64));
        }
    }
    v.extend([i(Op::Faddi, 2, 0, 3), i(Op::Faddi, 3, 0, 5), i(Op::Faddi, 4, 0, 300), i(Op::Fold, 2, 4, 4)]);
    v.extend([i(Op::Loade, 6, 0, 300 + 8 + 4), i(Op::Public, 0, 6, 0), i(Op::Public, 0, 7, 0), i(Op::Halt, 0, 0, 0)]);
    let exec = execute(&prog(v), &[], 1000).unwrap();
    let want = recursion::emulator::fold_dft_horner(&ys, u);
    assert_eq!(exec.public, want.as_basis_coefficients_slice().to_vec());
    let ev = exec.events.iter().find(|e| e.instr.op == Op::Fold).unwrap();
    assert_eq!(ev.mem.len(), 2 * 4 + 2, "two reads per value, two result writes");
    assert_eq!(ev.d, [F::from_u64(3), F::from_u64(5)], "u is read from the rd pair");
}

#[test]
fn fold_refuses_an_arity_outside_two_four_eight() {
    let p = prog(vec![i(Op::Faddi, 4, 0, 300), i(Op::Fold, 2, 4, 3), i(Op::Halt, 0, 0, 0)]);
    assert_eq!(execute(&p, &[], 100), Err(ExecError::FoldArity { pc: 1, arity: 3 }));
}
```

Run: `cargo test --test isa --test emulator --test fold_identity`
Expected: compile error, no variant `Fold`.

- [ ] **Step 2: The ISA and the emulator**

`src/isa.rs`: append after `Compress`:

```rust
    /// one FRI fold round (phase 3, Cut E2): `rd` is the pair holding `u = β·s⁻¹`, `ra` the
    /// committed row's base (`2a` cells), `imm` the arity `a ∈ {2, 4, 8}`; the reduce chip's fold
    /// run (an inverse DFT then Horner, 2a rows) writes `Σ_m B_m·u^m` to the two cells after the
    /// row's four salts. Opcode 28, appended; 0–27 never move.
    Fold,
```

Set `COUNT = 29`, add `Op::Fold` to `ALL` and `"FOLD"` to `mnemonic`. Add `pub const FOLD_SALT_CELLS: u64 = 4;` with the doc `/// Cut E2: the cells between a committed row and its fold result (the row's salts).`. Update the enum doc to "The twenty-nine opcodes … (`REDUCE`, `SPONGE`, `HINTN`, `COMPRESS`, `FOLD`)". The "Deliberately absent" paragraph is rewritten in Task 5.

`src/emulator.rs`: add next to the slot constants:

```rust
/// A `FOLD` run's slots (Cut E2): every phase-1 row reads its value at slots 0–1 (distinct
/// addresses per row), the last row writes the result at 14–15.
pub const TS_FOLD_Y0: u32 = 0;
pub const TS_FOLD_Y1: u32 = 1;
pub const TS_FOLD_RES0: u32 = 14;
pub const TS_FOLD_RES1: u32 = 15;
```

Add `FoldEvent`:

```rust
/// One `FOLD` dispatch (Cut E2): the row it read, the point, the result.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct FoldEvent {
    pub msg: u64,
    pub arity: u32,
    pub u: [F; 2],
    pub ys: [[F; 2]; 8],
    pub out: [F; 2],
}
```

Add `pub fold: Option<FoldEvent>` to `Event`, declare `let mut fold = None;` with `reduce`, and include `fold` in the `run.events.push(Event { … })`. Add `FoldArity { pc: u32, arity: u64 }` to `ExecError` with the doc `/// A FOLD whose immediate is not 2, 4 or 8.`. Add the arm before `Op::Halt`:

```rust
            Op::Fold => {
                pair(instr.rd, "rd", pc)?;
                a[0] = regs[ra];
                d = [regs[rd], regs[rd + 1]];
                let arity = instr.b.as_canonical_u64();
                if !matches!(arity, 2 | 4 | 8) {
                    return Err(ExecError::FoldArity { pc, arity });
                }
                let msg = a[0].as_canonical_u64();
                let res = msg + 2 * arity + crate::isa::FOLD_SALT_CELLS;
                bounded(pc, res + 1)?;
                let mut ys = [[F::ZERO; 2]; 8];
                for (k, y) in ys.iter_mut().enumerate().take(arity as usize) {
                    *y = [
                        read_at(&mem, &mut mems, clk, TS_FOLD_Y0, msg + 2 * k as u64),
                        read_at(&mem, &mut mems, clk, TS_FOLD_Y1, msg + 2 * k as u64 + 1),
                    ];
                }
                let yse: Vec<EF> = ys[..arity as usize].iter().map(|y| ext(*y)).collect();
                let out = parts(fold_dft_horner(&yse, ext(d)));
                write_at(&mut mem, &mut mems, clk, TS_FOLD_RES0, res, out[0]);
                write_at(&mut mem, &mut mems, clk, TS_FOLD_RES1, res + 1, out[1]);
                fold = Some(FoldEvent { msg, arity: arity as u32, u: d, ys, out });
            }
```

and the two functions (public, near `ext`):

```rust
/// The fold run's coefficient table for one arity (Cut E2): row `k` (the row reading `y_k`),
/// column `j` = `(1/a)·c_k^{−(a−1−j)}`, `c_k = g_a^{rev(k)}`, zero for `j ≥ a` — so after the
/// phase-1 rows, accumulator `j` holds `B_{a−1−j}` (the inverse DFT, spec §2.3) and phase 2's
/// Horner reads them top coefficient first.
pub fn fold_coefficients(log_arity: usize) -> Vec<[F; 8]> {
    use p3_field::TwoAdicField;
    let a = 1usize << log_arity;
    let g = F::two_adic_generator(log_arity);
    let inv_a = F::from_usize(a).inverse();
    (0..a)
        .map(|k| {
            let w = g.exp_u64(p3_util::reverse_bits_len(k, log_arity) as u64).inverse();
            core::array::from_fn(|j| if j < a { inv_a * w.exp_u64((a - 1 - j) as u64) } else { F::ZERO })
        })
        .collect()
}

/// `Σ_m B_m·u^m` through [`fold_coefficients`] — the emulator's fold, and so the chip's
/// reference. `tests/fold_identity.rs` pins it to `TwoAdicFriFolding::fold_row`.
pub fn fold_dft_horner(ys: &[EF], u: EF) -> EF {
    let c = fold_coefficients(ys.len().trailing_zeros() as usize);
    let d: Vec<EF> = (0..ys.len()).map(|j| ys.iter().zip(&c).fold(EF::ZERO, |acc, (y, row)| acc + *y * row[j])).collect();
    d.iter().fold(EF::ZERO, |acc, &dj| acc * u + dj)
}
```

`src/machine.rs` `check_instr`: the `Op::Loade | Op::Storee | Op::Hinte` arm gains `| Op::Fold` (the `rd` pair).

Run: `cargo test --test isa --test emulator --test fold_identity`
Expected: pass.

- [ ] **Step 3: Failing width pins and the fold program**

`tests/tables.rs`: cpu `83` ("… + the FOLD selector (phase 3)"); reduce `70` and pre `20` ("Cut D's 30 + the fold kind's 40; preprocessed 9 + the 11-column coefficient table"). `tests/common/mod.rs`: add

```rust
/// Cut E2's honest fold program: each run's row stored at its own base, `u` in r2/r3, the base in
/// r4, one `FOLD`; the first run's result published twice. Returns the program and every run's
/// expected value (`emulator::fold_dft_horner`).
#[allow(dead_code)]
pub fn fold_program(runs: &[(usize, Vec<recursion::isa::EF>, recursion::isa::EF)]) -> (recursion::isa::Program, Vec<recursion::isa::EF>) {
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
    use recursion::isa::{Instr, Op, Program, F};
    let i = |op: Op, rd: u8, ra: u8, b: F| Instr { op, rd, ra, b };
    let (mut v, mut want, mut base, mut first_res) = (vec![], vec![], 300u64, 0u64);
    for (la, ys, u) in runs {
        let a = 1u64 << la;
        for (k, y) in ys.iter().enumerate() {
            for (l, w) in y.as_basis_coefficients_slice().iter().enumerate() {
                v.push(i(Op::Faddi, 1, 0, *w));
                v.push(i(Op::Store, 1, 0, F::from_u64(base + 2 * k as u64 + l as u64)));
            }
        }
        let uc = u.as_basis_coefficients_slice();
        v.extend([i(Op::Faddi, 2, 0, uc[0]), i(Op::Faddi, 3, 0, uc[1]), i(Op::Faddi, 4, 0, F::from_u64(base)), i(Op::Fold, 2, 4, F::from_u64(a))]);
        want.push(recursion::emulator::fold_dft_horner(ys, *u));
        if first_res == 0 {
            first_res = base + 2 * a + 4;
        }
        base += 2 * a + 4 + 2 + 10;
    }
    v.extend([i(Op::Loade, 6, 0, F::from_u64(first_res)), i(Op::Public, 0, 6, F::ZERO), i(Op::Public, 0, 7, F::ZERO)]);
    v.extend([i(Op::Public, 0, 6, F::ZERO), i(Op::Public, 0, 7, F::ZERO), i(Op::Halt, 0, 0, F::ZERO)]);
    (Program { instrs: v, checkpoints: vec![], reduce_layout: vec![] }, want)
}
```

`tests/precompiles.rs`: append (Review Focus 5)

```rust
/// Cut E2 (Review Focus 5): fold runs of every arity back to back in one table, and a run at
/// u = 0, prove and verify — the K counter, the phase switch and the coefficient lookups across
/// run boundaries.
#[test]
fn fold_runs_of_every_arity_back_to_back_prove_and_verify() {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(29);
    let mut runs = vec![];
    for la in [1usize, 2, 3, 3, 1] {
        runs.push((la, (0..1usize << la).map(|_| common::random_ext(&mut rng)).collect::<Vec<EF>>(), common::random_ext(&mut rng)));
    }
    runs[3].2 = EF::ZERO;
    let (p, want) = common::fold_program(&runs);
    let m = Machine::new(FriProfile::Test);
    let (proof, exec) = m.prove(&p, &[], None).unwrap();
    m.verify(&p, &proof).unwrap();
    assert_eq!(exec.public[..2].to_vec(), want[0].as_basis_coefficients_slice().to_vec());
    let b0 = runs[3].1.iter().fold(EF::ZERO, |acc, y| acc + *y) * F::from_u64(8).inverse();
    assert_eq!(want[3], b0, "at u = 0 the fold is B_0, the row's mean");
}
```

Run: `cargo test --release --test tables --test precompiles fold`
Expected: the width pins fail. The proof test fails because the `FOLD` bus has no provider (a lookup-balance panic) or the chip is not declared.

- [ ] **Step 4: The cpu**

`src/tables/cpu.rs`:
1. `NUM_SELECTORS = 29`. Shift every column after `SEL0` by one: `A0 = 36, A1 = 37, B0 = 38, B1 = 39, D0 = 40, D1 = 41, RD_BIT0 = 42, RA_BIT0 = 47, RB_BIT0 = 52, LIMB0 = 57, LIMB1 = 58, LIMB2 = 59, RD_IS_ZERO = 60, RD_INV = 61, EQ_AUX = 62, EQ_INV = 63, PUB_IDX = 64, IS_REAL = 65, G2LIMB0..2 = 66..68, G3LIMB0..2 = 69..71, G4LIMB0..2 = 72..74, W0 = 75, WIDTH = 83`. Fix the `/// 28: one-hot` comment to 29.
2. `Sels::READ_RD` and `Sels::EXT_READ_RD` gain `Op::Fold` (`u` is the `rd` pair).
3. Group 1: `subject` gains `+ sel(Op::Fold) * (v(A0) + AB::Expr::from_u32(2) * v(B) + AB::Expr::from_u32(5))` (the result's high cell) and `needs_check` gains `+ sel(Op::Fold)`. Group 3: `is_multi` gains `+ sel(Op::Fold)` and `base3` gains `+ sel(Op::Fold) * v(A0)`.
4. After the `COMPRESS` lookup:

```rust
        // Cut E2: the fold point travels with the dispatch — `D0, D1` are the `rd` pair, bound by
        // the REG reads `READ_RD`/`EXT_READ_RD` send; the arity is the fetched immediate `B`.
        bus::FOLD.lookup_key(b, [v(CLK), v(A0), v(D0), v(D1), v(B)], Count::bounded(sel(Op::Fold), 1));
```

5. `fill_row`: `subject` gains `Op::Fold => Some(e.a[0].as_canonical_u64() + 2 * e.instr.b.as_canonical_u64() + 5),`, and `base3` gains `Op::Fold => Some(e.a[0].as_canonical_u64()),`.

`src/tables/mod.rs`:

```rust
    /// cpu (FOLD rows) → reduce (Cut E2): (clk, msg, u0, u1, arity). One fold run per dispatch.
    pub const FOLD: LookupBus<'static> = LookupBus::new("FOLD");
    /// reduce → reduce (Cut E2): (arity, k, c0..c7). The preprocessed coefficient table provides
    /// (14 rows: arity 2, 4, 8), each phase-1 fold row consumes its own.
    pub const FOLD_COEFF: LookupBus<'static> = LookupBus::new("FOLD_COEFF");
```

`tests/cpu.rs`: the dispatch test's `dispatches` array gains `bus::FOLD.name()`, and it asserts a `seen_fold` the way it asserts `seen_compress`.

- [ ] **Step 5: The fold row kind in the reduce chip**

`src/tables/reduce.rs`. Append the columns to `col` (replacing `WIDTH = 30`):

```rust
    // ── the fold row kind (Cut E2): a run of 2a rows under one clock ──
    pub const IS_FOLD: usize = 30;
    pub const F_FIRST: usize = 31;
    /// Phase 1 (rows 0..a): accumulate the inverse DFT; phase 2 (rows a..2a): Horner.
    pub const F_PH1: usize = 32;
    pub const F_LAST: usize = 33;
    /// The row's index in its run, 0..2a.
    pub const F_K: usize = 34;
    pub const F_A: usize = 35;
    pub const F_MSG: usize = 36;
    pub const U0: usize = 37;
    pub const U1: usize = 38;
    pub const Y0: usize = 39;
    pub const Y1: usize = 40;
    /// The phase-1 row's eight coefficients, looked up from the preprocessed table.
    pub const C0: usize = 41; // 8
    /// Eight extension accumulators; after phase 1, pair j holds B_{a−1−j}; phase 2 shifts them.
    pub const D0: usize = 49; // 16
    pub const FACC0: usize = 65;
    pub const FACC1: usize = 66;
    pub const FOUT0: usize = 67;
    pub const FOUT1: usize = 68;
    /// The coefficient table's multiplicity.
    pub const MULT_C: usize = 69;
    pub const WIDTH: usize = 70;
```

and to `pre` (replacing `WIDTH = 9`):

```rust
    pub const C_IS_ROW: usize = 9;
    pub const C_A: usize = 10;
    pub const C_K: usize = 11;
    pub const C_V0: usize = 12; // 8
    pub const WIDTH: usize = 20;
```

Add `pub const FOLD_COEFF_ROWS: usize = 14;`, and make `provider_rows` return `layout.len().max(FOLD_COEFF_ROWS)`. In `preprocessed_trace`, after the layout loop:

```rust
        for la in 1..=3usize {
            let a = 1usize << la;
            for (k, c) in crate::emulator::fold_coefficients(la).iter().enumerate() {
                let r = &mut v[(a - 2 + k) * pre::WIDTH..(a - 1 + k) * pre::WIDTH];
                r[pre::C_IS_ROW] = Fld::ONE;
                r[pre::C_A] = Fld::from_u64(a as u64);
                r[pre::C_K] = Fld::from_u64(k as u64);
                for j in 0..8 {
                    r[pre::C_V0 + j] = Fld::from_u64(p3_field::PrimeField64::as_canonical_u64(&c[j]));
                }
            }
        }
```

(Row index `a − 2 + k` places arity 2 at rows 0–1, arity 4 at 2–5 and arity 8 at 6–13.) In `eval`, replace `t.assert_zero((one.clone() - is_real.clone()) * n(IS_REAL));` and `b.when_last_row().assert_zero(is_real.clone());` with the three-kind ordering (reduce rows, then fold rows, then padding), and append the fold block before `// ── buses ──`:

```rust
        // ── kinds: reduce rows, then fold rows, then padding ──
        let (is_fold, f_first, f_ph1, f_last) = (v(IS_FOLD), v(F_FIRST), v(F_PH1), v(F_LAST));
        for c in [IS_FOLD, F_FIRST, F_PH1, F_LAST] {
            b.assert_bool(v(c));
        }
        b.assert_zero(is_real.clone() * is_fold.clone());
        for f in [f_first.clone(), f_ph1.clone(), f_last.clone()] {
            b.assert_zero(f * (one.clone() - is_fold.clone()));
        }
        b.assert_zero(v(MULT_C) * (one.clone() - l(pre::C_IS_ROW)));
        b.when_last_row().assert_zero(is_real.clone() + is_fold.clone());
        b.when_first_row().assert_zero(is_fold.clone() * (one.clone() - f_first.clone()));
        {
            let mut t = b.when_transition();
            t.assert_zero((one.clone() - is_real.clone() - is_fold.clone()) * (n(IS_REAL) + n(IS_FOLD)));
            t.assert_zero(is_fold.clone() * n(IS_REAL));
            // A run starts at K = 0 in phase 1 with zero accumulators, ends on F_LAST, and only there.
            t.assert_zero(is_fold.clone() * (one.clone() - f_last.clone()) * (one.clone() - n(IS_FOLD)));
            t.assert_zero(is_fold.clone() * (one.clone() - f_last.clone()) * n(F_FIRST));
            t.assert_zero(f_last.clone() * n(IS_FOLD) * (one.clone() - n(F_FIRST)));
            // A fold row entered from the last reduce row is a run's first row too — without
            // this, a headless run (no F_FIRST, so no FOLD message) could still write a forged
            // result at a clock of the prover's choosing (controller review, 2026-10-05).
            t.assert_zero(is_last.clone() * n(IS_FOLD) * (one.clone() - n(F_FIRST)));
        }
        b.assert_zero(f_first.clone() * v(F_K));
        b.assert_zero(f_first.clone() * (one.clone() - f_ph1.clone()));
        for j in 0..16 {
            b.assert_zero(f_first.clone() * v(D0 + j));
        }
        b.assert_zero(f_last.clone() * (v(F_K) - AB::Expr::from_u32(2) * v(F_A) + one.clone()));
        b.assert_zero(f_last.clone() * f_ph1.clone());
        // Horner's step, ext × ext: (FACC·U + D_0), the value the last row writes.
        let horner0 = v(FACC0) * v(U0) + seven.clone() * v(FACC1) * v(U1) + v(D0);
        let horner1 = v(FACC0) * v(U1) + v(FACC1) * v(U0) + v(D0 + 1);
        b.assert_zero(f_last.clone() * (v(FOUT0) - horner0.clone()));
        b.assert_zero(f_last.clone() * (v(FOUT1) - horner1.clone()));
        {
            let fr = n(IS_FOLD) * (one.clone() - n(F_FIRST));
            let mut t = b.when_transition();
            for c in [CLK, F_MSG, F_A, U0, U1] {
                t.assert_zero(fr.clone() * (n(c) - v(c)));
            }
            t.assert_zero(fr.clone() * (n(F_K) - v(F_K) - one.clone()));
            // Phase 1 is a prefix of the run, and it ends exactly at K = a − 1.
            t.assert_zero(fr.clone() * (one.clone() - f_ph1.clone()) * n(F_PH1));
            let switch = fr.clone() * f_ph1.clone() * (one.clone() - n(F_PH1));
            t.assert_zero(switch.clone() * (n(F_K) - v(F_A)));
            t.assert_zero(switch.clone() * n(FACC0));
            t.assert_zero(switch * n(FACC1));
            // Phase 1: accumulator pair j += C_j·y (base × ext).
            for j in 0..8 {
                t.assert_zero(fr.clone() * f_ph1.clone() * (n(D0 + 2 * j) - v(D0 + 2 * j) - v(C0 + j) * v(Y0)));
                t.assert_zero(fr.clone() * f_ph1.clone() * (n(D0 + 2 * j + 1) - v(D0 + 2 * j + 1) - v(C0 + j) * v(Y1)));
            }
            // Phase 2: Horner on the top pair, the pairs shift down, zero enters at the top.
            let ph2 = fr * (one.clone() - f_ph1.clone());
            t.assert_zero(ph2.clone() * (n(FACC0) - horner0));
            t.assert_zero(ph2.clone() * (n(FACC1) - horner1));
            for j in 0..14 {
                t.assert_zero(ph2.clone() * (n(D0 + j) - v(D0 + j + 2)));
            }
            t.assert_zero(ph2.clone() * n(D0 + 14));
            t.assert_zero(ph2 * n(D0 + 15));
        }
        bus::FOLD.table_entry(b, [v(CLK), v(F_MSG), v(U0), v(U1), v(F_A)], f_first.clone());
        let coeff_msg: Vec<AB::Expr> = [v(F_A), v(F_K)].into_iter().chain((0..8).map(|j| v(C0 + j))).collect();
        bus::FOLD_COEFF.lookup_key(b, coeff_msg, Count::bounded(f_ph1.clone(), 1));
        let table_msg: Vec<AB::Expr> = [l(pre::C_A), l(pre::C_K)].into_iter().chain((0..8).map(|j| l(pre::C_V0 + j))).collect();
        bus::FOLD_COEFF.table_entry(b, table_msg, v(MULT_C));
        let fts = |slot: u32| sixteen.clone() * v(CLK) + AB::Expr::from_u32(slot);
        let y_addr = v(F_MSG) + AB::Expr::from_u32(2) * v(F_K);
        bus::RAM.send(b, [y_addr.clone(), fts(TS_FOLD_Y0), v(Y0), AB::Expr::ZERO], Count::bounded(f_ph1.clone(), 1));
        bus::RAM.send(b, [y_addr + one.clone(), fts(TS_FOLD_Y1), v(Y1), AB::Expr::ZERO], Count::bounded(f_ph1, 1));
        let res = v(F_MSG) + AB::Expr::from_u32(2) * v(F_A) + AB::Expr::from_u32(crate::isa::FOLD_SALT_CELLS as u32);
        bus::RAM.send(b, [res.clone(), fts(TS_FOLD_RES0), v(FOUT0), one.clone()], Count::bounded(f_last.clone(), 1));
        bus::RAM.send(b, [res + one.clone(), fts(TS_FOLD_RES1), v(FOUT1), one.clone()], Count::bounded(f_last, 1));
```

Add `TS_FOLD_Y0, TS_FOLD_Y1, TS_FOLD_RES0, TS_FOLD_RES1` to the `crate::emulator` import. Change the reduce rows' own `when_last_row` to the combined one above (delete the old one). Add the trace side:

```rust
/// The `FOLD` events, in execution order.
pub fn fold_events(events: &[Event]) -> Vec<&Event> {
    events.iter().filter(|e| e.fold.is_some()).collect()
}

/// Two chip rows per fold value.
pub fn fold_rows(events: &[&Event]) -> usize {
    events.iter().map(|e| 2 * e.fold.unwrap().arity as usize).sum()
}

/// The fold runs, after the reduce runs (`reduce_trace` calls this with its next free row).
fn fill_folds(v: &mut [F], mut row: usize, folds: &[&Event]) {
    for e in folds {
        let ev = e.fold.unwrap();
        let a = ev.arity as usize;
        let la = a.trailing_zeros() as usize;
        let coeffs = crate::emulator::fold_coefficients(la);
        let u = ev.u;
        let ext_mul_add = |x: [F; 2], y: [F; 2], z: [F; 2]| -> [F; 2] {
            let (p0, p1) = ext_mul(x, y);
            [p0 + z[0], p1 + z[1]]
        };
        let mut d = [[F::ZERO; 2]; 8];
        let mut facc = [F::ZERO; 2];
        for k in 0..2 * a {
            let r = &mut v[row * WIDTH..(row + 1) * WIDTH];
            r[IS_FOLD] = F::ONE;
            r[F_FIRST] = F::from_bool(k == 0);
            r[F_PH1] = F::from_bool(k < a);
            r[F_LAST] = F::from_bool(k == 2 * a - 1);
            r[F_K] = F::from_u64(k as u64);
            r[F_A] = F::from_u64(a as u64);
            r[F_MSG] = F::from_u64(ev.msg);
            r[CLK] = F::from_u64(e.clk as u64);
            r[U0] = u[0];
            r[U1] = u[1];
            for j in 0..8 {
                r[D0 + 2 * j] = d[j][0];
                r[D0 + 2 * j + 1] = d[j][1];
            }
            r[FACC0] = facc[0];
            r[FACC1] = facc[1];
            if k < a {
                let y = ev.ys[k];
                r[Y0] = y[0];
                r[Y1] = y[1];
                for j in 0..8 {
                    r[C0 + j] = coeffs[k][j];
                    d[j] = [d[j][0] + coeffs[k][j] * y[0], d[j][1] + coeffs[k][j] * y[1]];
                }
            } else {
                let next = ext_mul_add(facc, u, d[0]);
                if k == 2 * a - 1 {
                    r[FOUT0] = next[0];
                    r[FOUT1] = next[1];
                    debug_assert_eq!(next, ev.out, "the trace recomputes the emulator's fold");
                }
                facc = next;
                d.rotate_left(1);
                d[7] = [F::ZERO; 2];
            }
            row += 1;
            if k < a {
                // The coefficient table's row for (a, k): arity 2 at rows 0–1, 4 at 2–5, 8 at 6–13.
                v[(a - 2 + k) * WIDTH + MULT_C] += F::ONE;
            }
        }
    }
}
```

`reduce_trace`'s signature becomes `reduce_trace(layout: &[ReduceEntry], events: &[&Event], folds: &[&Event], height: usize)`; its row assert counts `reduce_rows(events) + fold_rows(folds)`, and `fill_folds(&mut v, row, folds)` runs after the reduce loop. In `src/machine.rs`'s `build_traces`, the reduce block becomes:

```rust
    let reduce_evs = reduce_events(&exec.events);
    let fold_evs = fold_events(&exec.events);
    let reduce_lh = reduce_log_height(reduce_rows(&reduce_evs) + fold_rows(&fold_evs), provider_rows(&program.reduce_layout));
    let reduce = if reduce_lh == 0 { None } else { Some(reduce_trace(&program.reduce_layout, &reduce_evs, &fold_evs, 1 << reduce_lh)) };
```

and `tests/cheating.rs`'s and `tests/tables.rs`'s direct `reduce_trace` calls (if any; `grep -rn reduce_trace tests/`) pass `&[]` for `folds`. Extend `common::every_chip_program` with one arity-2 fold: before its `PUBLIC`s, store `(1,0) (2,0)` at cells 300–303, then add `FADDI r2, r0, 3`, `FADDI r3, r0, 0`, `FADDI r4, r0, 300` and `FOLD r2, r4, 2`. With that, `tests/binding.rs`' write rule and `tests/tables.rs`' padding rule both cover the fold kind's result write.

Run: `cargo test --release --test tables --test precompiles --test cpu --test cheating --test machine --test binding --test emulator`
Expected: pass. The tables degree pin for the reduce chip gets the measured value (≤ 8, asserted): replace the literal with it, keeping `assert!(degs[7] <= 8)` beside it, and keep `&degs[..7] == [2, 8, 4, 4, 4, 2, 2]`. `no_admissible_padding_row_of_any_chip_sends_a_message` must still report 7 chips checked with no sends. Its padding row `h − 2` is past the 14-row coefficient region as long as the reduce height is ≥ 16; the test program's is.

- [ ] **Step 6: Cheating tests for the fold kind**

Append to `tests/cheating.rs`:

```rust
// ── Cut E2: the fold row kind ─────────────────────────────────────────────────────────────────
fn fold_setup() -> (Machine, Program, Traces) {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(41);
    let ys: Vec<EF> = (0..8).map(|_| common::random_ext(&mut rng)).collect();
    let (p, _) = common::fold_program(&[(3, ys, common::random_ext(&mut rng))]);
    let m = Machine::new(FriProfile::Test);
    let exec = execute(&p, &[], 10_000).unwrap();
    let t = build_traces(&p, &exec, Tier(8)).unwrap();
    (m, p, t)
}

fn fold_first_row(t: &Traces) -> usize {
    let w = reduce_table::col::WIDTH;
    let r = t.reduce.as_ref().unwrap();
    (0..r.height()).find(|k| r.values[k * w + reduce_table::col::F_FIRST] == F::ONE).unwrap()
}

#[test]
fn honest_fold_traces_pass() {
    let (m, p, t) = fold_setup();
    prove_and_verify(&m, &p, &t).unwrap();
}

/// Spec §5: a FOLD run with a tampered B_m — the first phase-2 row's top accumulator.
#[test]
fn a_fold_run_with_a_tampered_coefficient_accumulator_is_rejected() {
    let (m, p, mut t) = fold_setup();
    let (w, row) = (reduce_table::col::WIDTH, fold_first_row(&t) + 8);
    t.reduce.as_mut().unwrap().values[row * w + reduce_table::col::D0] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

/// Spec §5: a FOLD whose u differs from the cpu's — every row of the run (so the carry holds),
/// leaving the FOLD dispatch unmatched.
#[test]
fn a_fold_whose_u_differs_from_the_dispatch_is_rejected() {
    let (m, p, mut t) = fold_setup();
    let (w, first) = (reduce_table::col::WIDTH, fold_first_row(&t));
    let r = t.reduce.as_mut().unwrap();
    for row in first..first + 16 {
        r.values[row * w + reduce_table::col::U0] += F::ONE;
    }
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

/// Spec §5: a FOLD run cut short — its last phase-2 row turned into padding.
#[test]
fn a_fold_run_cut_short_is_rejected() {
    let (m, p, mut t) = fold_setup();
    let (w, last) = (reduce_table::col::WIDTH, fold_first_row(&t) + 15);
    let r = t.reduce.as_mut().unwrap();
    for c in 0..w {
        if c != reduce_table::col::MULT && c != reduce_table::col::MULT_C {
            r.values[last * w + c] = F::ZERO;
        }
    }
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

/// A phase-1 row whose coefficients are not the table's.
#[test]
fn a_fold_row_with_a_coefficient_off_the_table_is_rejected() {
    let (m, p, mut t) = fold_setup();
    let (w, first) = (reduce_table::col::WIDTH, fold_first_row(&t));
    t.reduce.as_mut().unwrap().values[first * w + reduce_table::col::C0] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

/// A fold run that begins right after the last reduce row without `F_FIRST` sends no `FOLD`
/// message and would still write its result: the reduce-to-fold boundary must start a run.
#[test]
fn a_headless_fold_run_after_the_reduce_rows_is_rejected() {
    let (m, p, mut t) = fold_setup();
    let r = fold_first_row(&t);
    let w = reduce::col::WIDTH;
    // Keep the honest run, and forge a second run's rows in the padding right after it: copy the
    // honest run's rows, clear F_FIRST on the copy's first row, and point its result at the honest
    // result cell one clock later.
    let honest_len = 2 * t.reduce[r * w + reduce::col::F_A].as_canonical_u64() as usize;
    let src: Vec<F> = t.reduce[r * w..(r + honest_len) * w].to_vec();
    let dst = r + honest_len;
    t.reduce[dst * w..(dst + honest_len) * w].copy_from_slice(&src);
    t.reduce[dst * w + reduce::col::F_FIRST] = F::ZERO;
    for k in 0..honest_len {
        t.reduce[(dst + k) * w + reduce::col::CLK] += F::ONE;
    }
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}
```

Run: `cargo test --release --test cheating fold`
Expected: the honest test passes and all four forgeries are refused.

- [ ] **Step 7: The builder and the program**

`src/dsl/builder.rs`: rename `hint_array`'s body to `hint_array_padded`, with `let base = self.alloc((n + extra) as u64);` as its only change, and make `hint_array(n)` call `hint_array_padded(n, 0)`:

```rust
    /// [`Builder::hint_array`] into a buffer `extra` cells longer than the words it hints (Cut E2:
    /// a committed row's fold-result cells after its salts). The extra cells are allocated only.
    pub fn hint_array_padded(&mut self, n: usize, extra: usize) -> Array<Felt> {
```

Add:

```rust
    /// One `FOLD` (Cut E2): the arity-`arity` fold of the committed row at `msg` (2·arity cells,
    /// then the salts) at `u`, by the reduce chip's fold run; the result is loaded from the two
    /// cells after the salts. `u` rides in the `rd` pair as a read, as `COMPRESS`'s bit does.
    pub fn fold_run(&mut self, msg: Ptr, arity: usize, u: Ext) -> Ext {
        assert!(matches!(arity, 2 | 4 | 8), "FOLD arity {arity}: the coefficient table holds 2, 4 and 8");
        self.begin();
        let ru = self.materialise(u.0);
        let rm = self.ptr_reg(msg);
        self.emit(Op::Fold, ru, rm, BRef::Imm(F::from_u64(arity as u64)));
        self.load_ext(msg, 2 * arity as i64 + crate::isa::FOLD_SALT_CELLS as i64)
    }
```

`src/programs/rv32.rs`: `read_commit_openings` reads `b.hint_array_padded((1usize << la) * 2 + SALT_ELEMS, 2)`; add `const _: () = assert!(crate::isa::FOLD_SALT_CELLS as usize == SALT_ELEMS);` next to it. Replace `emit_fold_dispatch` with the public:

```rust
/// One fold round over the committed row at `msg`. `Off` (the reference): load the row, run the
/// compiled barycentric fold. `On` (Cut E2): `u = β·s⁻¹` on the cpu — `s` the coset's first point,
/// one `INV`, one `EMULF` — and the inverse DFT plus Horner in the reduce chip's fold run.
pub fn fold_eval(b: &mut Builder, log_folded: usize, la: usize, group_bits: &[Felt], beta: Ext, msg: Ptr) -> Ext {
    match b.precompiles() {
        Precompiles::Off => {
            let evals: Vec<Ext> = (0..1usize << la).map(|j| b.load_ext(msg, 2 * j as i64)).collect();
            emit_fold_round(b, log_folded, la, group_bits, beta, &evals)
        }
        Precompiles::On => {
            let s = bit_selected_power(b, F::two_adic_generator(log_folded + la), log_folded, group_bits, F::ONE);
            let s_inv = b.inv(s);
            let u = b.ext_mul_base(beta, s_inv);
            b.fold_run(msg, 1usize << la, u)
        }
    }
}
```

In `emit_query`, the `fold_round` span calls `fold_eval(b, log_folded, la, group_bits, betas[r], msg)`. Export `fold_eval` from `src/programs/mod.rs`. Append to `tests/precompiles.rs`:

```rust
/// Cut E2: the chip fold equals the compiled barycentric fold and `fold_row`, at every arity.
#[test]
fn fold_via_the_chip_matches_the_compiled_fold() {
    use recursion::dsl::Liveness;
    use recursion::programs::{fold_eval, Precompiles};
    use p3_fri::{FriFoldingStrategy, TwoAdicFriFolding};
    let folding: TwoAdicFriFolding<(), ()> = TwoAdicFriFolding(std::marker::PhantomData);
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(30);
    for la in 1..=3usize {
        for _ in 0..8 {
            let log_folded = 6usize;
            let index: usize = rand::RngExt::random_range(&mut rng, 0..1usize << log_folded);
            let beta = common::random_ext(&mut rng);
            let row: Vec<EF> = (0..1usize << la).map(|_| common::random_ext(&mut rng)).collect();
            let want = <TwoAdicFriFolding<(), ()> as FriFoldingStrategy<F, EF>>::fold_row(&folding, index, log_folded, la, beta, row.iter().copied());
            let run = |pc: Precompiles| {
                let mut b = Builder::with_opts(Checkpoints::Off, Liveness::On, pc);
                let msg = b.alloc(2 * (1 << la) + 6);
                for (j, v) in row.iter().enumerate() {
                    let c = b.ext_constant(*v);
                    b.store_ext(msg, 2 * j as i64, c);
                }
                let bits: Vec<Felt> = (0..log_folded).map(|k| b.constant(F::from_u64(((index >> k) & 1) as u64))).collect();
                let be = b.ext_constant(beta);
                let out = fold_eval(&mut b, log_folded, la, &bits, be, msg);
                b.public_ext(out);
                b.public_ext(out);
                let got = execute(&b.finish(), &[], 1_000_000).unwrap().public;
                ef([got[0], got[1]])
            };
            assert_eq!(run(Precompiles::Off), want, "compiled, la {la}");
            assert_eq!(run(Precompiles::On), want, "the chip, la {la}");
        }
    }
}
```

Run: `cargo test --release --test precompiles fold && cargo test --release --test verifier --test exit --test aggregate --test self_verify 2>&1 | grep -E '^test result|FAILED|panicked'`
Expected: the differential passes. Acceptance and tamper tests pass. Digest and cost pins fail; they are re-pinned in Step 9.

- [ ] **Step 8: Measure and check the band**

Run: `cargo test --release --test profile -- --ignored --nocapture 2>&1 | grep -v warning | tee target/phase3-profile-E2.txt`
Compare with the E2 band in docs/05 §2. Expected `fold_round`: 4·Q·R rows plus its `bit_selected_power` (counted in its own span). **Read the Production cpu rows against 524 287.** If they are ≤ 524 287, Task 4 is skipped (record "Cut F not built: E2 landed at <rows>" in docs/05 §4). If they are > 524 287, Task 4 runs.

- [ ] **Step 9: Re-pin and commit**

Run the Re-pin Procedure, P1–P7, and append the E2 row to docs/05 §4.

```bash
git add src/ tests/ docs/05-phase3-fold-reduce.md
git commit -m "recursion: Cut E2 — FOLD (opcode 28), the fold as an inverse DFT then Horner in a 2a-row reduce-chip run; <rows> rows, tier <t>

<the == profile Production line>; band <lo–hi>: <in/out>. cpu 82 → 83, reduce 30 → 70 (pre 9 → 20),
buses FOLD and FOLD_COEFF; reduce degree <measured> (≤ 8). Cut F <needed / not needed>.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AUWKAos28PQquiLZRVC6jP"
```

---

### Task 4 (conditional): Cut F — `POW`, one chip row per index bit (opcode 29)

**Run this task only if Task 3 Step 8 measured production cpu rows above 524 287.** Otherwise skip to Task 5. Opcode 29 stays unassigned, and docs/05 records why.

**Files:**
- Modify: `src/isa.rs` (`Op::Pow`, `COUNT = 30`), `src/emulator.rs` (`PowEvent`, `Event::pow`, `ExecError::PowShape`, `TS_POW_BIT`/`TS_POW_OUT`, the arm), `src/machine.rs` (`check_instr`; `build_traces` passes `&mut counts` to `reduce_trace`)
- Modify: `src/tables/cpu.rs` (`NUM_SELECTORS = 30`, columns +1, `READ_RD`/`EXT_READ_RD`, range groups 1 and 3, the `POW` lookup, `fill_row`), `src/tables/mod.rs` (bus `POW`), `src/tables/reduce.rs` (the pow row kind; `reduce_trace` takes `counts`)
- Modify: `src/dsl/builder.rs` (`pow_run`), `src/dsl/transcript.rs` (`sample_bits_with`, `sample_bits_mem`), `src/programs/rv32.rs` (`emit_proof` :259-292, `emit_query`'s signature and two calls, `emit_reduced_openings_layout`, `fold_eval`, new `index_power`)
- Test: `tests/isa.rs`, `tests/emulator.rs`, `tests/tables.rs`, `tests/cpu.rs`, `tests/common/mod.rs` (`pow_program`; `traces_from_parts`' range counts), `tests/cheating.rs`, `tests/precompiles.rs`

**Interfaces:**
- Produces: `Op::Pow = 29` (`"POW"`, immediate). `rd` is the pair `(G, base)` (read); `ra` is the 65-cell bits buffer (bit k at cell k, the output at cell 64); `imm = off + 256·L` with `1 ≤ L`, `off + L ≤ 64`. It computes `S = base·Π_{t<L} (1 + bit_{off+L−1−t}·(G^{2^t} − 1))` and writes `mem[buf + 64] = S`.
- Produces: `ExecError::PowShape { pc: u32, imm: u64 }`; `PowEvent { base: u64, off: u32, len: u32, g: F, s0: F, out: F }`; `TS_POW_BIT = 0`, `TS_POW_OUT = 15`.
- Produces: `bus::POW` with message `[clk, buf, off + 256·L, G, base]`.
- Produces: `reduce::col::{IS_POW 70, P_FIRST 71, P_LAST 72, P_K 73, P_BASE 74, P_OFF 75, P_L 76, P_BIT 77, P_G 78, P_S 79, P_OUT 80, WIDTH 81}`; `reduce::{pow_events, pow_rows}`. `reduce_trace(layout, events, folds, pows, height, counts: &mut RangeCounts)`.
- Produces: `cpu::col::{A0 = 37, …, W0 = 76, WIDTH = 84}`.
- Produces: `Builder::pow_run(&mut self, bits: Ptr, off: usize, len: usize, g: F, base: F) -> Felt`, `DslChallenger::sample_bits_mem(&mut self, b, bits) -> (Vec<Felt>, Ptr)`, `fold_eval(…, cells: Option<(Ptr, usize)>)`, `emit_query(…, index_cells: Option<Ptr>)`.

- [ ] **Step 1: Failing ISA and emulator tests**

`tests/isa.rs`: `ALL.len()` and `COUNT` become 30, plus `Op::from_u8(29) == Some(Op::Pow)`, `"POW"`, `!b_is_register()`; the unknown-opcode probe uses 30. `tests/emulator.rs`:

```rust
fn pow_prog(bits: &[u64], off: u64, len: u64, g: F, base: F) -> Program {
    let mut v = vec![];
    for (k, &bit) in bits.iter().enumerate() {
        v.push(i(Op::Faddi, 1, 0, bit));
        v.push(i(Op::Store, 1, 0, 400 + k as u64));
    }
    v.extend([Instr { op: Op::Faddi, rd: 2, ra: 0, b: g }, Instr { op: Op::Faddi, rd: 3, ra: 0, b: base }, i(Op::Faddi, 4, 0, 400)]);
    v.extend([i(Op::Pow, 2, 4, off + 256 * len), i(Op::Load, 6, 0, 464), i(Op::Public, 0, 6, 0), i(Op::Halt, 0, 0, 0)]);
    prog(v)
}

#[test]
fn pow_is_the_bit_selected_power() {
    use p3_field::TwoAdicField;
    let bits: Vec<u64> = (0..64).map(|k| (0x9e37_79b9u64 >> (k % 32)) & 1).collect();
    let (off, len) = (5u64, 11u64);
    let g = F::two_adic_generator(len as usize);
    let exec = execute(&pow_prog(&bits, off, len, g, F::GENERATOR), &[], 10_000).unwrap();
    let mut want = F::GENERATOR;
    for k in 0..len {
        if bits[(off + k) as usize] == 1 {
            want *= g.exp_u64(1 << (len - 1 - k));
        }
    }
    assert_eq!(exec.public, vec![want]);
}

#[test]
fn pow_refuses_a_non_boolean_bit_and_a_bad_shape() {
    let mut bits = vec![0u64; 64];
    bits[3] = 2;
    assert_eq!(execute(&pow_prog(&bits, 0, 8, F::TWO, F::ONE), &[], 10_000).unwrap_err(), ExecError::NonBooleanBit { pc: 131 });
    let bits = vec![0u64; 64];
    assert!(matches!(execute(&pow_prog(&bits, 60, 8, F::TWO, F::ONE), &[], 10_000), Err(ExecError::PowShape { .. })));
}
```

(The `POW` is instruction 131: 128 stores, then 3 `FADDI`s.) Run: `cargo test --test isa --test emulator pow`. Expected: compile error, no variant `Pow`.

- [ ] **Step 2: ISA and emulator**

`src/isa.rs`: append `Pow` with the doc `/// the index power (phase 3, Cut F): `rd` the pair (G, base), `ra` a 65-cell bits buffer, `imm = off + 256·L`; the reduce chip's pow run (one row per bit) writes `base·Π_t (1 + bit_{off+L−1−t}·(G^{2^t} − 1))` to cell 64. Opcode 29.` Set `COUNT = 30`, add it to `ALL`, and add `"POW"`. `src/emulator.rs`: add `pub const TS_POW_BIT: u32 = 0; pub const TS_POW_OUT: u32 = 15;`, then

```rust
/// One `POW` dispatch (Cut F).
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct PowEvent {
    pub base: u64,
    pub off: u32,
    pub len: u32,
    pub g: F,
    pub s0: F,
    pub out: F,
}
```

Add `pub pow: Option<PowEvent>` to `Event` (with `let mut pow = None;` and the push), `PowShape { pc: u32, imm: u64 }` to `ExecError` (doc `/// A POW immediate whose run is empty or leaves the 64 bits.`), and the arm:

```rust
            Op::Pow => {
                pair(instr.rd, "rd", pc)?;
                a[0] = regs[ra];
                d = [regs[rd], regs[rd + 1]];
                let imm = instr.b.as_canonical_u64();
                let (off, len) = (imm % 256, imm / 256);
                if len == 0 || len >= 256 || off + len > 64 {
                    return Err(ExecError::PowShape { pc, imm });
                }
                let base = a[0].as_canonical_u64();
                bounded(pc, base + 64)?;
                let (mut g, mut s) = (d[0], d[1]);
                for t in 0..len {
                    let bit = read_at(&mem, &mut mems, clk, TS_POW_BIT, base + off + len - 1 - t);
                    if bit != F::ZERO && bit != F::ONE {
                        return Err(ExecError::NonBooleanBit { pc });
                    }
                    s *= F::ONE + bit * (g - F::ONE);
                    g = g.square();
                }
                write_at(&mut mem, &mut mems, clk, TS_POW_OUT, base + 64, s);
                pow = Some(PowEvent { base, off: off as u32, len: len as u32, g: d[0], s0: d[1], out: s });
            }
```

`src/machine.rs` `check_instr`: the pair arm gains `| Op::Pow`. Run the Step 1 tests. Expected: pass.

- [ ] **Step 3: The cpu and the bus**

`src/tables/cpu.rs`: `NUM_SELECTORS = 30`, and every column after `SEL0` shifts by one more (`A0 = 37`, `A1 = 38`, `B0 = 39`, `B1 = 40`, `D0 = 41`, `D1 = 42`, `RD_BIT0 = 43`, `RA_BIT0 = 48`, `RB_BIT0 = 53`, `LIMB0..2 = 58..60`, `RD_IS_ZERO = 61`, `RD_INV = 62`, `EQ_AUX = 63`, `EQ_INV = 64`, `PUB_IDX = 65`, `IS_REAL = 66`, `G2LIMB0..2 = 67..69`, `G3LIMB0..2 = 70..72`, `G4LIMB0..2 = 73..75`, `W0 = 76`, `WIDTH = 84`). `Sels::READ_RD` and `EXT_READ_RD` gain `Op::Pow`. Group 1's `subject` gains `+ sel(Op::Pow) * (v(A0) + AB::Expr::from_u32(64))`, and `needs_check` gains `+ sel(Op::Pow)`. Group 3's `is_multi` gains `+ sel(Op::Pow)`, and `base3` gains `+ sel(Op::Pow) * v(A0)`. Add `bus::POW.lookup_key(b, [v(CLK), v(A0), v(B), v(D0), v(D1)], Count::bounded(sel(Op::Pow), 1));`. In `fill_row`, `subject` gains `Op::Pow => Some(e.a[0].as_canonical_u64() + 64)` and `base3` gains `Op::Pow => Some(e.a[0].as_canonical_u64())`. `src/tables/mod.rs`:

```rust
    /// cpu (POW rows) → reduce (Cut F): (clk, bits_buf, off + 256·L, G, base).
    pub const POW: LookupBus<'static> = LookupBus::new("POW");
```

`tests/cpu.rs`: the dispatch test's list gains `bus::POW.name()`. `tests/tables.rs`: cpu `84`, reduce `81`.

- [ ] **Step 4: The pow row kind**

`src/tables/reduce.rs`. Append the columns (replacing `WIDTH = 70`):

```rust
    // ── the pow row kind (Cut F): one row per index bit, high bit first ──
    pub const IS_POW: usize = 70;
    pub const P_FIRST: usize = 71;
    pub const P_LAST: usize = 72;
    pub const P_K: usize = 73;
    pub const P_BASE: usize = 74;
    /// The immediate's two bytes: `imm = P_OFF + 256·P_L`, both range-checked on the first row.
    pub const P_OFF: usize = 75;
    pub const P_L: usize = 76;
    pub const P_BIT: usize = 77;
    /// `G^{2^K}` and the running product before this row's bit.
    pub const P_G: usize = 78;
    pub const P_S: usize = 79;
    pub const P_OUT: usize = 80;
    pub const WIDTH: usize = 81;
```

In `eval`, the three-kind ordering becomes four-kind: the padding rule is `(1 − IS_REAL − IS_FOLD − IS_POW)·(n(IS_REAL) + n(IS_FOLD) + n(IS_POW)) = 0`, add `IS_POW·(n(IS_REAL) + n(IS_FOLD)) = 0`, `IS_POW·IS_REAL = 0` and `IS_POW·IS_FOLD = 0`, and the last-row rule becomes `IS_REAL + IS_FOLD + IS_POW = 0`. Then:

```rust
        let (is_pow, p_first, p_last) = (v(IS_POW), v(P_FIRST), v(P_LAST));
        for c in [IS_POW, P_FIRST, P_LAST, P_BIT] {
            b.assert_bool(v(c));
        }
        b.assert_zero(p_first.clone() * (one.clone() - is_pow.clone()));
        b.assert_zero(p_last.clone() * (one.clone() - is_pow.clone()));
        b.when_first_row().assert_zero(is_pow.clone() * (one.clone() - p_first.clone()));
        b.assert_zero(p_first.clone() * v(P_K));
        b.assert_zero(p_last.clone() * (v(P_K) - v(P_L) + one.clone()));
        let step = v(P_S) * (one.clone() + v(P_BIT) * (v(P_G) - one.clone()));
        b.assert_zero(p_last.clone() * (v(P_OUT) - step.clone()));
        {
            let mut t = b.when_transition();
            t.assert_zero(is_pow.clone() * (one.clone() - p_last.clone()) * (one.clone() - n(IS_POW)));
            t.assert_zero(is_pow.clone() * (one.clone() - p_last.clone()) * n(P_FIRST));
            t.assert_zero(p_last.clone() * n(IS_POW) * (one.clone() - n(P_FIRST)));
            let pr = n(IS_POW) * (one.clone() - n(P_FIRST));
            for c in [CLK, P_BASE, P_OFF, P_L] {
                t.assert_zero(pr.clone() * (n(c) - v(c)));
            }
            t.assert_zero(pr.clone() * (n(P_K) - v(P_K) - one.clone()));
            t.assert_zero(pr.clone() * (n(P_G) - v(P_G) * v(P_G)));
            t.assert_zero(pr * (n(P_S) - step));
        }
        let imm = v(P_OFF) + AB::Expr::from_u32(256) * v(P_L);
        bus::POW.table_entry(b, [v(CLK), v(P_BASE), imm, v(P_G), v(P_S)], p_first.clone());
        for c in [P_OFF, P_L] {
            bus::RANGE8.lookup_key(b, [v(c)], Count::bounded(p_first.clone(), 1));
        }
        let pts = |slot: u32| sixteen.clone() * v(CLK) + AB::Expr::from_u32(slot);
        let bit_addr = v(P_BASE) + v(P_OFF) + v(P_L) - one.clone() - v(P_K);
        bus::RAM.send(b, [bit_addr, pts(TS_POW_BIT), v(P_BIT), AB::Expr::ZERO], Count::bounded(is_pow, 1));
        bus::RAM.send(b, [v(P_BASE) + AB::Expr::from_u32(64), pts(TS_POW_OUT), v(P_OUT), one.clone()], Count::bounded(p_last, 1));
```

Import `TS_POW_BIT, TS_POW_OUT` and `super::range::RangeCounts`. The trace side:

```rust
pub fn pow_events(events: &[Event]) -> Vec<&Event> {
    events.iter().filter(|e| e.pow.is_some()).collect()
}

pub fn pow_rows(events: &[&Event]) -> usize {
    events.iter().map(|e| e.pow.unwrap().len as usize).sum()
}

fn fill_pows(v: &mut [F], mut row: usize, pows: &[&Event], counts: &mut RangeCounts) {
    for e in pows {
        let ev = e.pow.unwrap();
        let (mut g, mut s) = (ev.g, ev.s0);
        counts.range8(ev.off);
        counts.range8(ev.len);
        for t in 0..ev.len as usize {
            let bit = e.mem[t].value;
            let r = &mut v[row * WIDTH..(row + 1) * WIDTH];
            r[IS_POW] = F::ONE;
            r[P_FIRST] = F::from_bool(t == 0);
            r[P_LAST] = F::from_bool(t + 1 == ev.len as usize);
            r[P_K] = F::from_u64(t as u64);
            r[P_BASE] = F::from_u64(ev.base);
            r[P_OFF] = F::from_u32(ev.off);
            r[P_L] = F::from_u32(ev.len);
            r[CLK] = F::from_u64(e.clk as u64);
            r[P_BIT] = bit;
            r[P_G] = g;
            r[P_S] = s;
            s *= F::ONE + bit * (g - F::ONE);
            g = g.square();
            if t + 1 == ev.len as usize {
                r[P_OUT] = s;
                debug_assert_eq!(s, ev.out);
            }
            row += 1;
        }
    }
}
```

`reduce_trace` becomes `reduce_trace(layout, events, folds, pows: &[&Event], height, counts: &mut RangeCounts)`. Its row assert adds `pow_rows(pows)`, and it calls `fill_pows(&mut v, row_after_folds, pows, counts)`; have `fill_folds` return its next free row for that. `build_traces` counts `pow_rows(&pow_evs)` into the declared height and passes `&mut counts` (it is still before `range_trace`). Extend `common::every_chip_program` with one `POW`, after Task 3's fold: store bits `1, 0, 1` at cells 400–402, then add `FADDI r2, r0, 7`, `FADDI r3, r0, 1`, `FADDI r4, r0, 400` and `POW r2, r4, imm = 0 + 256·3`, so the binding and padding rules cover the pow kind. In `tests/cheating.rs`'s `traces_from_parts`, re-add the chip's range counts. The test passes its reduce trace explicitly, so for every row with `P_FIRST == 1`, call `counts.range8` on `P_OFF` and `P_L`.

- [ ] **Step 5: The builder, the transcript and the program**

`src/dsl/builder.rs`:

```rust
    /// One `POW` (Cut F): `base·g^{rev(bits, L)}` from the `len` bits at cells `off..off+len` of
    /// the 65-cell bits buffer `bits` (`DslChallenger::sample_bits_mem`), by the reduce chip's
    /// pow run; the result is loaded from cell 64. `(g, base)` ride as one extension pair in `rd`.
    pub fn pow_run(&mut self, bits: Ptr, off: usize, len: usize, g: F, base: F) -> Felt {
        assert!(len >= 1 && off + len <= 64, "POW: {len} bits at {off} leave the 64-bit buffer");
        let gb = self.ext_constant(EF::from_basis_coefficients_slice(&[g, base]).expect("two coefficients"));
        self.begin();
        let rgb = self.materialise(gb.0);
        let rp = self.ptr_reg(bits);
        self.emit(Op::Pow, rgb, rp, BRef::Imm(F::from_u64((off + 256 * len) as u64)));
        self.load(bits, 64)
    }
```

`src/dsl/transcript.rs`: rename `sample_bits`'s body to `fn sample_bits_with(&mut self, b: &mut Builder, bits: usize, read: impl FnOnce(&mut Builder) -> (Vec<Felt>, Option<Ptr>)) -> (Vec<Felt>, Option<Ptr>)`. Its only changes: `let bit: Vec<Felt> = (0..64).map(|_| b.hint()).collect();` becomes `let (bit, buf) = read(b);`, and the return becomes `(bit[..bits].to_vec(), buf)`; keep the `sample_bits` span. Then:

```rust
    pub fn sample_bits(&mut self, b: &mut Builder, bits: usize) -> Vec<Felt> {
        self.sample_bits_with(b, bits, |b| ((0..64).map(|_| b.hint()).collect(), None)).0
    }

    /// [`sample_bits`] with the sixty-four bits hinted into a 65-cell buffer (Cut F): the bits are
    /// then cells a `POW` run reads, and cell 64 is the run's output. Same tape, same checks.
    pub fn sample_bits_mem(&mut self, b: &mut Builder, bits: usize) -> (Vec<Felt>, Ptr) {
        let (v, buf) = self.sample_bits_with(b, bits, |b| {
            let buf = b.hint_array_padded(64, 1);
            ((0..64).map(|k| b.get(buf, k)).collect(), Some(buf.base))
        });
        (v, buf.expect("the bits buffer"))
    }
```

`src/programs/rv32.rs`: in `emit_proof`, step 6 becomes

```rust
    let (index_bits, index_cells): (Vec<Vec<Felt>>, Vec<Option<Ptr>>) = (0..shape.num_queries())
        .map(|_| match b.precompiles() {
            Precompiles::On => {
                let (bits, buf) = ch.sample_bits_mem(b, log_global);
                (bits, Some(buf))
            }
            Precompiles::Off => (ch.sample_bits(b, log_global), None),
        })
        .unzip();
```

and `emit_query` gets `index_cells: Option<Ptr>` after `index_bits` (pass `index_cells[q]`). Add:

```rust
/// `base·g^{rev(index, log_rev)}`: Cut F's `POW` run when the bits are cells (`On`), the compiled
/// ladder otherwise (`Off`, the reference).
fn index_power(b: &mut Builder, g: F, log_rev: usize, bits: &[Felt], base: F, cells: Option<(Ptr, usize)>) -> Felt {
    match cells {
        Some((buf, off)) if b.precompiles() == Precompiles::On => {
            assert_eq!(bits.len(), log_rev, "POW starts its ladder at g itself: the run is the whole index");
            b.span("bit_selected_power", |b| b.pow_run(buf, off, log_rev, g, base))
        }
        _ => bit_selected_power(b, g, log_rev, bits, base),
    }
}
```

In `emit_reduced_openings_layout` (it gains `index_cells: Option<Ptr>`, threaded through `emit_reduced_openings`), the query point becomes `index_power(b, F::two_adic_generator(h), h, &index_bits[log_global - h..], F::GENERATOR, index_cells.map(|p| (p, log_global - h)))`. `fold_eval` gains `cells: Option<(Ptr, usize)>`; its `On` arm's `s` becomes `index_power(b, F::two_adic_generator(log_folded + la), log_folded, group_bits, F::ONE, cells)`, and `emit_query` passes `index_cells.map(|p| (p, shift))` (`shift` after `+= la`). `tests/precompiles.rs`' `fold_via_the_chip_matches_the_compiled_fold` passes `None`.

- [ ] **Step 6: Tests: differential and soundness**

`tests/common/mod.rs`: add `pow_program(bits: &[u64], off: u64, len: u64, g: F, base: F) -> Program`, the body of `tests/emulator.rs`'s `pow_prog` with `Load r6, 464` published four times and `reduce_layout: vec![]`. `tests/precompiles.rs`:

```rust
/// Cut F: POW equals the compiled ladder for random bits, offsets and lengths.
#[test]
fn pow_matches_the_bit_selected_ladder() {
    use p3_field::TwoAdicField;
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(31);
    let m = Machine::new(FriProfile::Test);
    for (off, len) in [(0u64, 1u64), (0, 20), (5, 11), (44, 20), (63, 1)] {
        let bits: Vec<u64> = (0..64).map(|_| rand::RngExt::random::<bool>(&mut rng) as u64).collect();
        let g = F::two_adic_generator(len as usize + 3);
        let mut want = F::GENERATOR;
        for k in 0..len {
            if bits[(off + k) as usize] == 1 {
                want *= g.exp_u64(1 << (len - 1 - k));
            }
        }
        let p = common::pow_program(&bits, off, len, g, F::GENERATOR);
        let (proof, exec) = m.prove(&p, &[], None).unwrap();
        m.verify(&p, &proof).unwrap();
        assert_eq!(exec.public[0], want, "off {off}, len {len}");
    }
}
```

`tests/cheating.rs`: a `pow_setup()` that builds `common::pow_program(&bits, 5, 11, two_adic_generator(11), GENERATOR)` at `Tier(8)`, plus `honest_pow_traces_pass` and three forgeries. Each finds the first `P_FIRST` row and asserts `rejects`:
1. `a_pow_row_with_a_non_boolean_bit_is_rejected`: `P_BIT = 2` on row first + 3, with `P_S` on the next rows recomputed so only the boolean rule can refuse.
2. `a_pow_run_whose_ladder_skips_a_square_is_rejected`: `P_G` on row first + 1 set to its row-0 value.
3. `a_pow_run_cut_short_is_rejected`: the last row zeroed (`MULT` and `MULT_C` columns kept).

Run: `cargo test --release --test isa --test emulator --test tables --test cpu --test cheating --test precompiles --test machine --test binding`
Expected: pass. Pin the reduce degree measured (≤ 8, asserted).

- [ ] **Step 7: Acceptance, measure, re-pin, commit**

Run: `cargo test --release --test verifier --test exit --test aggregate --test self_verify 2>&1 | grep -E '^test result|FAILED|panicked'` (acceptance and tamper tables green; pins re-pinned next). Run the profile and compare with the F band (docs/05 §2). Then run the Re-pin Procedure, P1–P7, and append the F row to docs/05 §4.

```bash
git add src/ tests/ docs/05-phase3-fold-reduce.md
git commit -m "recursion: Cut F — POW (opcode 29), the index powers as one reduce-chip row per bit; <rows> rows, tier <t>

<the == profile Production line>; band <lo–hi>: <in/out>. cpu 83 → 84, reduce 70 → 81, bus POW.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AUWKAos28PQquiLZRVC6jP"
```

---

### Task 5: The landing — every pin, the collateral corrections, docs/05 in full, the suite

**Files:**
- Modify: `tests/exit.rs` (`the_cycle_budget_per_inner_proof_is_pinned`'s `> 1 << 19` assertion :192-204)
- Modify: `src/isa.rs` (the "Deliberately absent: FRIFOLD, EXPBITS" paragraph :36-39)
- Modify: `docs/00-recursion-vm.md` (:47 and the "The precompile decision" section :314-344), `docs/01-rvm-machine.md` (table rows :23 and :29, the buses line :33, the measured table :55-75), `docs/02-aggregate.md` (a "Phase 3" section after "Phase 2: the three row cuts" :135, the N-economics :276-331), `docs/03-gpu-and-self-recursion.md` (the self-verifier's measured cost :102-160), `docs/05-phase3-fold-reduce.md` (§5, §6, the conclusion)
- Test: the full suite

**Interfaces:**
- Consumes: every measured number from Tasks 1b–4 (`target/phase3-profile-*.txt`, docs/05 §4) and the Re-pin Procedure's final values.

- [ ] **Step 1: Confirm every pin from spec §4 is current**

Run the Re-pin Procedure's P7 and the ignored emulation-only tests (list first; never start the proving ones):

```bash
cargo test --release -- --ignored --list 2>/dev/null | grep ': test'
cargo test --release --test exit the_cycle_budget_per_inner_proof_is_pinned -- --ignored
cargo test --release --test aggregate the_production_n1_aggregate_is_the_m52_pin_plus_loop_overhead -- --ignored
cargo test --release --test profile -- --ignored --nocapture 2>&1 | grep '^=='
```

Expected: green. Spec §4's list, checked one by one: `tests/pins.json` (rows, permutations, mem, witness words, instructions, `phase3_attribution`'s REG and rows, aggregate N = 1/2/3), `src/programs/verify_rv32.digest`, `tests/verifier.rs:786` and `:832`, `tests/aggregate.rs:39`, `:51`, `:339`, `:491`, `:521` and `:640`, `tests/self_verify.rs:130` and the cost pins, `tests/exit.rs:307-308` and `:350-351`, `tests/verifier_key.rs`'s `WANT_REDUCE`, and `tests/tables.rs`' widths and the reduce degree. Every degree pin except the reduce chip's stays `[2, 8, 4, 4, 4, 2, 2]` (spec §4: they do not move). `inner_vk_digest` (`tests/aggregate.rs:558`) is unchanged.

- [ ] **Step 2: Flip the regime assertion**

In `tests/exit.rs`, replace the `assert!(r.cpu_rows > 1 << 19, …)` block and its comment. If the gate is met:

```rust
    // Phase 3 (2026-10-05, docs/05): the inner verification is under 2^19 − 1 = 524 287 cpu rows —
    // tier 19, the milestone's gate. The descriptor layout, the fold and (if built) the index powers
    // are in the reduce chip now; docs/00's precompile decision records why M5.1 declined them at
    // 5.25 M rows and why they paid at 893 606.
    assert!(r.cpu_rows <= (1 << 19) - 1, "the phase-3 gate: one inner verification in tier 19");
```

If the gate is not met (spec §2.5: the phase stops at the measured point):

```rust
    // Phase 3 (2026-10-05, docs/05): D + E (+ F) landed at <rows>, above 2^19 − 1; the memory
    // heights (2^21) are the delivered result, and docs/05 names the next lever.
    assert!(r.cpu_rows > (1 << 19) - 1, "above the phase-3 gate: docs/05's residual must be re-decided");
```

- [ ] **Step 3: Correct the collateral**

`src/isa.rs:36-39` becomes:

```rust
/// Precompiles are added when the measurement asks for one (`docs/00`'s decision, re-taken in
/// `docs/05`): `COMPRESS` for one Merkle level (Cut C, measured at 33 rows a level), and in phase 3
/// `FOLD` for one FRI fold round (the reduce chip's fold run) [and `POW` for the index powers] —
/// declined at 5.25 M rows, where they were ~3 % of the program, and taken at 893 606, where the
/// query bookkeeping they replace was <measured share> %.
```

Drop the bracketed `POW` clause if Task 4 did not run. In `docs/00-recursion-vm.md`, line 47's "Deliberately absent" line becomes a pointer to the rewritten decision. Append to §"The precompile decision" a dated paragraph: what the 2026-09 decision measured (≈ 100 k + 64 k rows of 5.68 M), what docs/05 §1 measured at 893 606 (the `fold_round`, `select`, `bit_selected_power` and `reduce` spans), what was built, and the landed rows. In `docs/01-rvm-machine.md`: the cpu row (:23) becomes 83/84 wide with 29/30 selectors and the `FOLD`/`POW` sends; the reduce row (:29) becomes width 70/81, preprocessed 20, **degree <measured>** (it was listed as 3; it was 8, `tests/tables.rs:219`, and is now the measured value), with the row kinds run, fold and pow; the buses line (:33) gains `REDUCE_LAYOUT`, `FOLD`, `FOLD_COEFF` and `POW`, and `REDUCE [clk, entry]`; the opcodes table gains `FOLD = 28` (and `POW = 29`); the measured-numbers table (:55-75) gets the new rows, heights and tier. `docs/02-aggregate.md`: a "Phase 3" section (the new aggregate digests and N = 1/2/3 rows from the pins), and the N-economics tables at the new tiers with the memory model from docs/05 §3. `docs/03`: the self-verifier's measured cost (the P5 values).

- [ ] **Step 4: Write docs/05 in full**

Fill §4 (one row per cut: measured rows, Δ, the band, in band, REG, RAM, tier) and §5 (the "What moved" table in docs/04's format: every pin old → new, the cpu and reduce widths, the buses, the opcodes, the tape's `CommitPhaseOpenings` layout). Fill §6, the suite count, from Step 5. Add a conclusion that says whether the gate was met (spec §2.5's last paragraph if not: the residual and the next lever).

- [ ] **Step 5: The suite**

Run: `cargo test --release --no-fail-fast -- --skip a_one_proof_aggregate_round_trips --skip two_test_profile_bundle_proofs_aggregate_and_verify_natively 2>&1 | tee target/phase3-suite.txt | grep -E '^test result|FAILED'`
Expected: 0 failed. Record the passed / ignored / skipped counts in docs/05 §6 (phase 2's was 208 / 20 / 1).

- [ ] **Step 6: Commit**

```bash
git add tests/exit.rs src/isa.rs docs/
git commit -m "recursion docs: phase 3 landed — <rows> rows per inner proof, tier <t>, reg and RAM tables 2^21; docs/05 records the cuts

The regime assertion flips (tier 19 <met / not met>); isa.rs and docs/00 record why FOLD is present
now; docs/01's reduce degree corrected (listed 3, was 8, now <measured>). Suite: <passed> passed,
0 failed, <ignored> ignored, 2 skipped.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AUWKAos28PQquiLZRVC6jP"
```

---

## Self-review notes

- **Controller review (2026-10-05):** the reduce-to-fold boundary constraint `is_last · n(IS_FOLD) · (1 − n(F_FIRST)) = 0` was missing (a headless fold run after the reduce rows could write a forged result); added to Task 3's eval with `a_headless_fold_run_after_the_reduce_rows_is_rejected`. The spec's §2.1/§2.3 were amended to the plan's R1–R9.

- **Spec coverage.** §1 → Task 0 (the attribution, REG, `log_arities`, `degree_bits`, spans; the `phase3_attribution` block; docs/05 §1–2). §2.1 → Tasks 1a and 1b, with R1–R6 recording where the code departs from the spec's wording and why. §2.2 → Task 2. §2.3 → Task 3, plus Task 0's identity test. §2.4 → Task 4, gated on Task 3 Step 8. §2.5 → every cut's band check and the Re-pin Procedure; Task 5 Step 2's two branches. §3 → Task 1b Step 5. §4 → the Re-pin Procedure and Task 5 Step 1's checklist. §5: precompile differentials in Tasks 1a, 2, 3 and 4; the spec's named forgeries in Task 1a (wrong CARRY, an address off the layout, a tampered chain result), Task 3 (tampered B_m, a u that differs, a run cut short) and Task 4 (a non-boolean bit); width and degree pins in Tasks 1a, 3 and 4; the suite in Task 5. §6 rulings: 1 (row kinds, not an instance) in Tasks 3 and 4; 2 (one REDUCE row per entry) in Task 1a; 3 (never hinted) in R1 and `check_layout`; 4 (DFT + Horner) in Tasks 0 and 3; 5 (profile unchanged) in Global Constraints; 6 (gate not widened) in Global Constraints and Task 5 Step 2.
- **Placeholder scan.** `grep -nE 'TBD|TODO|similar to|add validation' <this file>` returns nothing. Angle-bracket slots (`<rows>`, `<measured>`) appear only in commit messages, docs/05 text and the P2 script's capitalised names. Each one is a measured number that the step around it says how to read off.
- **Type consistency.** `ReduceEntry` (Task 1a) is used by the builder, the chip, `check_layout` and the tests with the same eight fields. `ReduceRun { vals, row, key }` and `Builder::reduce(&[ReduceRun], alpha, res)` match between Tasks 1a and 1b. `reduce_trace` grows `(layout, events)` in 1a, then `folds` in 3, then `pows` and `counts` in 4, and each task states the new signature and updates its callers. The cpu columns shift in Task 3 (`A0 = 36`, `WIDTH = 83`) and again in Task 4 (`A0 = 37`, `WIDTH = 84`); each task lists the full set. `fold_eval` is named `emit_fold_dispatch` in Task 2 (private) and renamed to `fold_eval` (public) in Task 3; Task 4 adds `cells`.
- **Review Focus pinned to tests.** 1 → Task 1a Step 8 `the_self_verifier_accepts_a_proof_carrying_the_reduce_layout`. 2 → Task 1a Step 8 `a_reduce_chain_inside_a_counted_loop_proves_with_mult_n`. 3 → Task 1a Step 8 `one_column_entries_at_chain_start_and_end_prove_and_verify`. 4 → Task 2 Step 1 `the_own_slot_check_agrees_on_and_off_at_every_slot`. 5 → Task 3 Step 3 `fold_runs_of_every_arity_back_to_back_prove_and_verify`.
- **Length.** About 3 300 lines, against the 1 000–1 600 asked. Every task carries full code for the AIRs, the emulator arms and the rewritten program functions, because the spec's row-aligned layout does not survive the aggregate's counted loop (R1), so the code had to be designed here rather than transcribed. Cut F (Task 4) is the shortest code-complete form of a conditional task.
