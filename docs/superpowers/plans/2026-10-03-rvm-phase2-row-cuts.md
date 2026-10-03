# rVM Phase 2 Row Cuts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring one verified inner bundle proof from 2 047 268 cpu rows (tier 21) to about 790 000 (tier 20) with three measured cuts, and record the prover's live-heap profile so the aggregator hardware class is set from live memory, not Linux RSS.

**Architecture:** Three independent cuts to the recursion VM, cheapest-to-prove first: (A) the verifier program hints each height group's opened rows straight into the buffer the leaf sponge reads, so the per-cell copy disappears (program + tape only); (B) a `HINTN` cpu row kind that writes eight tape words to eight RAM cells in one row; (C) a `COMPRESS` row kind of the Poseidon2 chip that does a Merkle level — the child select and the permutation — in one cpu row and one chip row. Every cut is re-measured by `tests/profile.rs` and re-pinned before the next starts. A fourth, independent task adds the `parallel` feature with the fullnode's two-crate Plonky3 patch.

**Tech Stack:** Rust 1.98.1 (pinned by `recursion/rust-toolchain.toml`), Plonky3 0.7.0 (`p3-*` crates, exact pins), the `recursion` crate's own DSL/emulator/AIR tables; tests are `cargo test` with real bundle-proof fixtures.

**Spec:** `docs/superpowers/specs/2026-10-03-rvm-phase2-row-cuts-design.md` (read it first; §1 is the measurement every number here comes from, §2 the cuts, §5 the testing discipline, §6 the rulings).

## Global Constraints

- Work in `~/rand-worktrees/circuits-phase2` on branch `feat/rvm-phase2`; every command below runs from `~/rand-worktrees/circuits-phase2/recursion` (the crate is its own cargo root — never a workspace member).
- `export RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures` before any test that touches fixtures: 13 Test and 50 Production constraint-set-8 proofs are cached there; without it the first run re-proves (Test ~30 s each, Production ~100 s each).
- Build with `cargo test --release` for anything that proves or emulates the full program; `cargo test` (dev, opt-level 1) is fine for unit tests of the DSL/emulator.
- **Opcodes 0–25 never move** (`src/isa.rs` doc comment). New opcodes are appended: `Hintn = 26`, `Compress = 27`.
- **`Precompiles::Off` stays buildable and correct** after every task — it is the differential reference. Nothing compiled is deleted.
- **AGENTS.md invariants** (`research/AGENTS.md`, binding for `recursion/` too): (1) every bus message's address and value columns are constrained on every row kind that sends it; (2) every send count is a selector expression, zero on rows that do not perform the access. The emulator is the reference semantics: if an AIR and the emulator disagree, the AIR is wrong.
- **The measurement gate (spec §6 ruling 1):** after each cut run `cargo test --release --test profile -- --ignored --nocapture` and compare the production row count to the spec §2.4 projection; outside ±15 % → stop, write the correction into the spec §2.4, then continue.
- Commit after every task with a message in the repository's voice (what moved, the measured number, the fullnode issue if any). Attribution line: `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Do not touch `research/` (the RV32 machine, constraint set 8) except `research/AGENTS.md`'s recursion paragraph in Task 4.

## Review Focus

1. **Program and tape disagree after Cut A** (a matrix read in the wrong group order): the only test is acceptance of *real* proofs at both profiles — Task 1 runs `tests/exit.rs`'s in-suite test-profile suite and the `#[ignore]`d fifty-production suite, and the tamper suites (a tamper must still be refused at a named step).
2. **`hint_array` tails** — `n` of 1, 7, 8, 9, 16, 17, 121 words: the tape must be consumed exactly `n` words, no more (Task 2's Off-vs-On test asserts `hints_read == n` and cell-for-cell equality).
3. **`HINTN` at the top of the address space** — base `2^24 − 8` is legal (top cell `2^24 − 1`), base `2^24 − 7` is not: the emulator refuses it, and a trace with forged limbs claiming it is refused by the AIR (Task 2's cheating tests).
4. **`COMPRESS` with the bit set and clear at every level, and a one-level walk** — the differential against `MerkleTreeMmcs::verify_batch` must run under `Precompiles::On` with random index bits (Task 3 re-runs `tests/transcript.rs`'s path test with the switch on), and the walk with injections must agree with the compiled form (Task 3's precompiles test).
5. **A non-boolean bit reaching the chip** — the emulator must refuse it as a build error (`ExecError::NonBooleanBit`), and a chip row carrying `BIT = 2` must be refused by `Machine::verify` (Task 3's cheating test).

---

### Task 1: Cut A — hint opened rows straight into the height-group sponge buffer

**Files:**
- Modify: `src/shape.rs` (add `height_groups`)
- Modify: `src/programs/rv32.rs` (`read_input_openings`, `emit_input_round_root`, `emit_query`'s plumbing)
- Modify: `src/witness.rs` (step 11, `Segment::InputOpenings`)
- Test: `tests/shape.rs` (new, unit test for `height_groups`), `tests/exit.rs` (existing, run), `tests/profile.rs` (existing, run)

**Interfaces:**
- Produces: `pub fn height_groups(log_heights: &[usize]) -> Vec<Vec<usize>>` in `src/shape.rs` — distinct heights in descending order; each inner `Vec` is the matrix indices at that height in ascending index order (the reference's stable `sorted_by_key(Reverse(height))`). Used by the program (`rv32.rs`) and the tape (`witness.rs`) so the two cannot drift.
- Produces: `read_input_openings` returns `(Vec<Vec<Array<Felt>>>, Vec<Vec<(Ptr, usize)>>)` — per round the per-matrix **views** (same indexing as today, `rows[ri][mi]`), and per round the group buffers `(base, n_cells)` in group order.

- [ ] **Step 1: Write the failing unit test for `height_groups`**

Create `tests/shape.rs`:

```rust
//! `height_groups`: the one function the program and the tape both call to order a round's
//! matrices into height groups (Cut A), so the two cannot disagree.
use recursion::shape::height_groups;

#[test]
fn height_groups_are_tallest_first_and_stable_within_a_height() {
    // Heights by matrix index: 13, 15, 17, 16, 9, 9, 17, 11, 3 (the cs8 inner shape's degree bits).
    let groups = height_groups(&[13, 15, 17, 16, 9, 9, 17, 11, 3]);
    assert_eq!(groups, vec![vec![2, 6], vec![3], vec![1], vec![0], vec![7], vec![4, 5], vec![8]]);
}

#[test]
fn a_single_height_is_one_group_in_index_order() {
    assert_eq!(height_groups(&[5, 5, 5]), vec![vec![0, 1, 2]]);
}

#[test]
fn an_empty_round_has_no_groups() {
    assert!(height_groups(&[]).is_empty());
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --test shape`
Expected: compile error, `height_groups` not found in `recursion::shape`.

- [ ] **Step 3: Implement `height_groups` in `src/shape.rs`**

Add next to `MatrixOpening`:

```rust
/// A round's matrices grouped by log-height, tallest group first, each group in ascending
/// matrix-index order — `MerkleTreeMmcs::verify_batch`'s `sorted_by_key(Reverse(height))`
/// (stable) and so the order the leaf sponge hashes a group's `row ‖ salt` runs in. Cut A: the
/// program hints each group straight into one buffer in this order, and the tape
/// (`WitnessTape::build`, segment 11) emits the rows in the same order; both call this and
/// nothing else, so they cannot drift.
pub fn height_groups(log_heights: &[usize]) -> Vec<Vec<usize>> {
    let mut heights: Vec<usize> = log_heights.to_vec();
    heights.sort_unstable_by(|a, b| b.cmp(a));
    heights.dedup();
    heights
        .into_iter()
        .map(|h| (0..log_heights.len()).filter(|&i| log_heights[i] == h).collect())
        .collect()
}
```

- [ ] **Step 4: Run the unit test**

Run: `cargo test --test shape`
Expected: 3 passed.

- [ ] **Step 5: Rewrite `read_input_openings` to hint per group and return views + buffers**

In `src/programs/rv32.rs`, replace `read_input_openings`:

```rust
/// One query's run of `Segment::InputOpenings`: per round, per height group (tallest first,
/// `shape::height_groups`), the group's matrices' `row ‖ salt` runs hinted **straight into one
/// contiguous buffer** — the buffer the leaf sponge (or the injection sponge) hashes, so no copy
/// is made later (Cut A). Returns the per-matrix views, indexed `[round][matrix]` exactly as
/// before, and the per-round group buffers `(base, n_cells)` in group order.
fn read_input_openings(b: &mut Builder, opened: &QueryOpenings) -> (Vec<Vec<Array<Felt>>>, Vec<Vec<(Ptr, usize)>>) {
    let mut rows = Vec::with_capacity(opened.rounds.len());
    let mut groups = Vec::with_capacity(opened.rounds.len());
    for mats in &opened.rounds {
        let heights: Vec<usize> = mats.iter().map(|m| m.log_height).collect();
        let mut views: Vec<Option<Array<Felt>>> = vec![None; mats.len()];
        let mut bufs = Vec::new();
        for group in crate::shape::height_groups(&heights) {
            let lens: Vec<usize> = group.iter().map(|&m| mats[m].points[0].1.len + SALT_ELEMS).collect();
            let total: usize = lens.iter().sum();
            let buf = b.hint_array(total);
            let mut off = 0i64;
            for (&m, &len) in group.iter().zip(&lens) {
                views[m] = Some(Array::new(b.offset(buf.base, off), len, 1));
                off += len as i64;
            }
            bufs.push((buf.base, total));
        }
        rows.push(views.into_iter().map(|v| v.expect("every matrix is in exactly one group")).collect());
        groups.push(bufs);
    }
    (rows, groups)
}
```

`Array<Felt>` needs `Clone` for `vec![None; n]` — it derives `Clone, Copy, Debug` already (`dsl/mod.rs`).

- [ ] **Step 6: Make `emit_input_round_root` use the group buffers instead of `concat`**

Change its signature to take `groups: &[(Ptr, usize)]` (this round's buffers, group order) in place of `rows: &[Array<Felt>]`, and replace the `concat` closure and its two uses:

```rust
fn emit_input_round_root(
    b: &mut Builder,
    log_global: usize,
    mats: &[MatrixOpening],
    groups: &[(Ptr, usize)],
    path: Array<Felt>,
    index_bits: &[Felt],
    meta: &RoundMeta,
) {
    let max_h = mats.iter().map(|m| m.log_height).max().expect("a round has matrices");
    let levels = max_h - CAP_HEIGHT;
    let bits_reduced = log_global - max_h;
    let heights: Vec<usize> = mats.iter().map(|m| m.log_height).collect();
    let mut distinct = heights.clone();
    distinct.sort_unstable_by(|a, bb| bb.cmp(a));
    distinct.dedup();
    debug_assert_eq!(distinct.len(), groups.len(), "one buffer per height group");
    // Cut A: the tallest group's rows were hinted straight into `groups[0]`; the leaf sponge
    // runs over that buffer in place. No copy.
    let (leaf_msg, n) = groups[0];
    let leaf = Digest(b.alloc(DIGEST_ELEMS as u64));
    hash::sponge(b, leaf_msg, n, leaf);
    let injections: Vec<hash::Injection> = distinct[1..]
        .iter()
        .zip(&groups[1..])
        .map(|(&h, &(buf, n))| hash::Injection { after_level: max_h - h - 1, rows: buf, n_cells: n })
        .collect();
    let out = Digest(b.alloc(DIGEST_ELEMS as u64));
    hash::merkle_walk_with_injections(b, leaf, &index_bits[bits_reduced..bits_reduced + levels], path.base, levels, &injections, out);
    assert_cap_eq(b, out, &meta.cap, &index_bits[bits_reduced + levels..bits_reduced + levels + CAP_HEIGHT],
                  &format!("input opening root[{}]", meta.name));
}
```

Update the two callers: where `emit_proof`/the query loop calls `read_input_openings`, destructure `let (rows, groups) = read_input_openings(b, &opened);` and pass `&groups[ri]` to `emit_input_round_root` (in `emit_query`, add a `groups: &[Vec<(Ptr, usize)>]` parameter next to `rows`). `emit_reduced_openings` keeps taking `rows` — the views.

- [ ] **Step 7: Make the tape emit segment 11 in group order**

In `src/witness.rs`, step 11 (`w.begin(Segment::InputOpenings)`): the per-matrix dims are `r.input_rounds[round].dims` (`Vec<Dimensions>`, `height` a power of two). Replace the inner `for (m, row)` loop:

```rust
        // 11 ── per query, per input round, per *height group* (tallest first — `shape::height_groups`,
        // the same call the program makes in `read_input_openings`), per matrix: the opened row
        // then its four salts, which is the leaf message the hiding MMCS hashes
        // (`hiding_mmcs.rs:232-275`). Cut A: the program hints a group straight into the buffer
        // its sponge reads, so the tape lays a group out contiguously.
        w.begin(Segment::InputOpenings);
        for q in 0..shape.num_queries() {
            for (round, geom) in r.input_rounds.iter().enumerate() {
                let opening = &fri.input_openings[round];
                let salts = &opening.opening_proof.0[q];
                let log_heights: Vec<usize> = geom.dims.iter().map(|d| p3_util::log2_strict_usize(d.height)).collect();
                for group in crate::shape::height_groups(&log_heights) {
                    for m in group {
                        let row = &opening.opened_values[q][m];
                        assert_eq!(salts[m].len(), SALT_ELEMS);
                        w.base(row);
                        w.base(&salts[m]);
                    }
                }
            }
        }
        w.end();
```

Check that `geom.dims[m].height` is the matrix's *padded* height the program's `MatrixOpening::log_height` is derived from (`InnerShape::of` → look at how `log_height` is set in `shape.rs`; if it is `degree_bits + 1` for the hiding doubling or similar, use the same source — the two orderings must be computed from the same numbers). If `p3_util` is not already imported in `witness.rs`, add `use p3_util::log2_strict_usize;` (it is a dependency).

Also update the segment's doc comment on `Segment::InputOpenings` (around `witness.rs:57-74`) to say "per height group".

- [ ] **Step 8: Build, run the in-suite exit tests and the tamper table**

Run: `cargo test --release --test exit`
Expected: `five_test_profile_bundle_proofs_are_accepted` and `thirteen_tampered_test_profile_proofs_are_refused_at_the_named_step` pass. If a tamper is now refused at a *different* named step than the table expects, the program's checks run in a different order after the regrouping — update `tamper_table()`'s expected step for that segment to the measured one and record the change in the commit message (the table uses measured steps by design: see the "two test-level deviations" paragraph in `docs/00`).

- [ ] **Step 9: Run the production suites and the aggregate differentials**

Run: `cargo test --release --test exit -- --ignored --nocapture fifty` and `cargo test --release --test aggregate`
Expected: all green. `the_production_n1_aggregate_is_the_m52_pin_plus_loop_overhead` and `the_cycle_budget_per_inner_proof_is_pinned` will **fail on the pin** (rows moved) — that is expected here; Task 4 re-pins. Confirm every other assertion passes (the digest-equality ones in particular).

- [ ] **Step 10: Measure**

Run: `cargo test --release --test profile -- --ignored --nocapture 2>&1 | grep -v warning`
Record production cpu rows. Projection: ≈ 1 711 000 (−336 000). Gate: 1 455 000–1 968 000. Paste the two `== profile` lines and the phase table into the commit message.

- [ ] **Step 11: Run the whole in-suite test set**

Run: `cargo test --release`
Expected: everything green except the two pin tests named in Step 9 (`#[ignore]`d, so they do not run here anyway).

- [ ] **Step 12: Commit**

```bash
git add src/shape.rs src/programs/rv32.rs src/witness.rs tests/shape.rs
git commit -m "recursion: Cut A — opened rows hinted straight into the height-group sponge buffer

<the measured == profile lines and phase table>

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: Cut B — `HINTN`, eight tape words into eight cells in one cpu row

**Files:**
- Modify: `src/isa.rs` (opcode 26)
- Modify: `src/emulator.rs` (the `Hintn` arm)
- Modify: `src/tables/cpu.rs` (columns `W0..W7`, `NUM_SELECTORS`, `Sels`, `eval`, `fill_row`)
- Modify: `src/dsl/builder.rs` (`hint_array`'s `Precompiles::On` path)
- Test: `tests/isa.rs` (opcode pin), `tests/tables.rs` (width pin), `tests/cpu.rs` (binding test's `Witness` bound), `tests/precompiles.rs` (Off-vs-On), `tests/cheating.rs` (two range tests), `tests/emulator.rs` (tape exhaustion, address bound)

**Interfaces:**
- Produces: `Op::Hintn` (`= 26`, mnemonic `"HINTN"`, `b_is_register() == false`): `mem[ra + imm .. ra + imm + 8] = the next eight witness words`. Emulator error `HintExhausted { pc }` if fewer than eight words remain; `AddressOutOfRange` if `ra + imm + 7 ≥ 2^24`.
- Produces: `cpu::col::W0` (8 consecutive columns), `cpu::col::WIDTH == 81`.

- [ ] **Step 1: Write the failing opcode-pin and emulator tests**

In `tests/isa.rs`, find the test that pins `Op::ALL`'s discriminants (grep `COUNT` / `from_u8`) and extend its expectations: `Op::COUNT == 27`, `Op::from_u8(26) == Some(Op::Hintn)`, `Op::Hintn.mnemonic() == "HINTN"`, `!Op::Hintn.b_is_register()`. Add to `tests/emulator.rs`:

```rust
#[test]
fn hintn_writes_eight_witness_words_at_ra_plus_imm() {
    let p = Program { instrs: vec![
        i(Op::Faddi, 1, 0, 100),            // r1 = 100
        i(Op::Hintn, 0, 1, 4),              // mem[104..112] = w[0..8]
        i(Op::Load, 2, 1, 4),               // r2 = mem[104]
        i(Op::Load, 3, 1, 11),              // r3 = mem[111]
        i(Op::Public, 0, 2, 0), i(Op::Public, 0, 3, 0), i(Op::Halt, 0, 0, 0),
    ], checkpoints: vec![] };
    let tape: Vec<F> = (1..=8).map(F::from_u64).collect();
    let exec = execute(&p, &tape, 100).unwrap();
    assert_eq!(exec.public, vec![F::from_u64(1), F::from_u64(8)]);
    assert_eq!(exec.hints_read, 8);
    let hintn = &exec.events[1];
    assert_eq!(hintn.mem.len(), 8, "eight RAM writes");
    assert!(hintn.mem.iter().all(|m| m.is_write));
    assert_eq!(hintn.mem[0].addr, 104);
    assert_eq!(hintn.mem[7].addr, 111);
    assert_eq!(hintn.mem[7].value, F::from_u64(8));
}

#[test]
fn hintn_with_seven_words_left_is_hint_exhausted() {
    let p = Program { instrs: vec![i(Op::Faddi, 1, 0, 100), i(Op::Hintn, 0, 1, 0), i(Op::Halt, 0, 0, 0)], checkpoints: vec![] };
    let tape: Vec<F> = (1..=7).map(F::from_u64).collect();
    assert_eq!(execute(&p, &tape, 100), Err(ExecError::HintExhausted { pc: 1 }));
}

#[test]
fn hintn_whose_top_cell_is_at_two_to_the_twentyfour_is_refused() {
    let p = Program { instrs: vec![i(Op::Faddi, 1, 0, (1 << 24) - 7), i(Op::Hintn, 0, 1, 0), i(Op::Halt, 0, 0, 0)], checkpoints: vec![] };
    let tape: Vec<F> = (1..=8).map(F::from_u64).collect();
    assert_eq!(execute(&p, &tape, 100), Err(ExecError::AddressOutOfRange { pc: 1, addr: 1 << 24 }));
    // One lower is the last legal base.
    let p = Program { instrs: vec![i(Op::Faddi, 1, 0, (1 << 24) - 8), i(Op::Hintn, 0, 1, 0), i(Op::Halt, 0, 0, 0)], checkpoints: vec![] };
    assert!(execute(&p, &tape, 100).is_ok());
}
```

(`i(...)` is the test file's existing `Instr` helper; copy it if `tests/emulator.rs` lacks one: `fn i(op: Op, rd: u8, ra: u8, b: u64) -> Instr { Instr { op, rd, ra, b: F::from_u64(b) } }`.)

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --test isa --test emulator`
Expected: compile error, no variant `Hintn`.

- [ ] **Step 3: Add the opcode and the emulator arm**

`src/isa.rs`: append after `Sponge`:

```rust
    /// `mem[ra + imm .. ra + imm + 8] = the next eight witness words` — eight `HINT; STORE` pairs
    /// in one row (Cut B, 2026-10-03). The words ride on the cpu row's `W0..W7`, free witness
    /// exactly as `HINT`'s `D0` is; `rd` is unused. Opcode 26, appended; 0–25 never move.
    Hintn,
```

`Op::COUNT = 27`, add `Op::Hintn` to `ALL`, `"HINTN"` to `mnemonic`. `b_is_register` is unchanged (false). Update the doc comment on the enum ("The twenty-four opcodes" → "twenty-eight after Cuts B and C" when Task 3 lands; say twenty-seven now).

`src/emulator.rs`: add an arm before `Op::Halt`:

```rust
            Op::Hintn => {
                a[0] = regs[ra];
                let base = (a[0] + instr.b).as_canonical_u64();
                bounded(pc, base + 7)?;
                if run.hints_read + 8 > witness.len() {
                    return Err(ExecError::HintExhausted { pc });
                }
                for k in 0..8u64 {
                    let w = witness[run.hints_read + k as usize];
                    write(&mut mem, &mut mems, clk, base + k, w);
                }
                run.hints_read += 8;
            }
```

Check `bounded`'s contract: it refuses `addr >= MEM_LIMIT`; `base + 7 < 2^24` implies every cell is in range because `base` itself is a canonical value below `2^64 − 2^32`, so `base + k` cannot wrap — but a `base` near `p` would put `base + 7` *above* `2^24` and be refused, which is the point. Keep the `write` helper's timestamp slots: `write(.., clk, addr, v)` uses slot = position in `mems` (check `write`/`ts` at `emulator.rs:474-492`; the eight writes must land at slots 0..7 — if `write` assigns `ts(clk, mems.len())`, they do).

- [ ] **Step 4: Run the emulator tests**

Run: `cargo test --test isa --test emulator`
Expected: pass.

- [ ] **Step 5: Write the failing table-width and binding tests**

`tests/tables.rs`: change the cpu width pin to `81` with the message `"72 + the HINTN selector + its eight word columns (Cut B)"`. `tests/cpu.rs`: in `every_value_the_cpu_row_writes_is_bound_on_every_opcode`, the `Bound::Witness` arm `matches!(op, Op::Hint | Op::Hinte)` → add `| Op::Hintn`. If the file has a `DECLARED` table of expected bounds per opcode, add `(Op::Hintn, &[(W0, Witness), …, (W7, Witness)])` following its format.

Run: `cargo test --release --test tables --test cpu`
Expected: width pin fails (`72 != 81`); the binding test fails on `Hintn` (no RAM sends yet) or panics on a missing selector column.

- [ ] **Step 6: The cpu table — columns, selectors, constraints, sends, trace**

`src/tables/cpu.rs`:

1. `NUM_SELECTORS = 27`. Every column constant after `SEL0` shifts by one: `A0 = 34`, … recompute all (`A0..D1` 34–39, `RD_BIT0 = 40`, `RA_BIT0 = 45`, `RB_BIT0 = 50`, `LIMB0..2` 55–57, `RD_IS_ZERO 58`, `RD_INV 59`, `EQ_AUX 60`, `EQ_INV 61`, `PUB_IDX 62`, `IS_REAL 63`, `G2LIMB0..2` 64–66, `G3LIMB0..2` 67–69, `G4LIMB0..2` 70–72), then append:

```rust
    /// Cut B: the eight witness words a `HINTN` row writes to `A0 + B .. A0 + B + 8` — free
    /// witness columns, as `D0` is on a `HINT` row; zero on every other row kind is *not*
    /// required (they are read by nothing else), but the trace builder leaves them zero.
    pub const W0: usize = 73; // 8
    pub const WIDTH: usize = 81;
```

2. In `eval`: the address range check — group 1's subject gains `+ sel(Op::Hintn) * (v(A0) + v(B) + AB::Expr::from_u32(7))` and `needs_check` gains `+ sel(Op::Hintn)`; group 3 (`is_multi`, `base3`) gains `sel(Op::Hintn)` with base `v(A0) + v(B)`. The RAM sends, after the STOREE lines:

```rust
        // Cut B: HINTN's eight writes at slots 0..7, the words free witness (invariant 1: the
        // address is the range-checked `A0 + B + k`, the value the row's own `W_k`).
        for k in 0..8u32 {
            bus::RAM.send(b, [v(A0) + v(B) + AB::Expr::from_u32(k), ts(k), v(W0 + k as usize), one.clone()], count(sel(Op::Hintn)));
        }
```

`uses_ra` keeps `Hintn` (it reads `ra`): nothing to change there. `WRITE_RD` does **not** gain it.

3. In `fill_row`: `subject` gains `Op::Hintn => Some(e.mem[0].addr + 7)`, `base3` gains `Op::Hintn => Some(e.mem[0].addr)`, and after the operand columns:

```rust
    if e.instr.op == Op::Hintn {
        for k in 0..8 {
            r[W0 + k] = e.mem[k].value;
        }
    }
```

4. `register_accesses`: `uses_ra` is computed from `!matches!(op, Jmp | Hint | Hinte | Halt)` — `Hintn` reads `ra`, so no change.

- [ ] **Step 7: Run the table tests, then the whole cheating suite**

Run: `cargo test --release --test tables --test cpu --test cheating --test machine`
Expected: all pass (the binding test now sees eight RAM writes bound as `Witness`).

- [ ] **Step 8: Write the failing DSL differential test**

Add to `tests/precompiles.rs`:

```rust
/// Cut B: `hint_array(n)` under `Precompiles::On` (HINTN blocks + a compiled tail) reads exactly
/// `n` words into the same cells the compiled form does, for every tail length.
#[test]
fn hint_array_via_hintn_matches_the_compiled_pairs() {
    use recursion::dsl::{Builder, Checkpoints, Liveness};
    use recursion::programs::Precompiles;
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(26);
    for n in [1usize, 7, 8, 9, 16, 17, 121] {
        let tape: Vec<F> = (0..n + 3).map(|_| common::random_felt(&mut rng)).collect(); // 3 spare words
        let run = |pc: Precompiles| {
            let mut b = Builder::with_opts(Checkpoints::Off, Liveness::On, pc);
            let arr = b.hint_array(n);
            for k in 0..n {
                let v = b.get(arr, k);
                b.public(v);
            }
            let p = b.finish();
            let exec = execute(&p, &tape, 1_000_000).unwrap();
            (exec.public, exec.hints_read, exec.cpu_rows())
        };
        let (off, off_read, off_rows) = run(Precompiles::Off);
        let (on, on_read, on_rows) = run(Precompiles::On);
        assert_eq!(on, off, "n = {n}");
        assert_eq!(on, tape[..n].to_vec(), "n = {n}: the first n words, in order");
        assert_eq!((off_read, on_read), (n, n), "exactly n words consumed either way");
        assert_eq!(on_rows, off_rows - (n / 8) * 16 + (n / 8), "n = {n}: 16 rows per full block become 1");
    }
}
```

Run: `cargo test --release --test precompiles hint_array`
Expected: the row-count assertion fails (On still emits the pairs).

- [ ] **Step 9: The DSL — `hint_array`'s On path**

In `src/dsl/builder.rs`, `hint_array`:

```rust
    /// `n` witness words, read in order into `n` fresh cells. `Precompiles::On` (Cut B): one
    /// `HINTN` per full block of eight at immediate offset `8·j`, then `HINT; STORE` pairs for the
    /// `n mod 8` tail — the tail stays compiled because a block always consumes eight words, and
    /// the tape has exactly `n`. `Precompiles::Off`: the pairs throughout (the reference).
    pub fn hint_array(&mut self, n: usize) -> Array<Felt> {
        let base = self.alloc(n as u64);
        let holder = self.ptrs[base.0 as usize].holder;
        self.begin();
        let rp = self.materialise(holder);
        let s = self.take_scratch(1);
        let blocks = if self.precompiles() == Precompiles::On { n / 8 } else { 0 };
        for j in 0..blocks {
            self.emit(Op::Hintn, RRef::Raw(0), rp, BRef::Imm(imm(8 * j as i64)));
        }
        for k in 8 * blocks..n {
            self.emit(Op::Hint, RRef::scratch(s), RRef::Raw(0), BRef::Imm(F::ZERO));
            self.emit(Op::Store, RRef::scratch(s), rp, BRef::Imm(imm(k as i64)));
        }
        Array::new(base, n, 1)
    }
```

Check that `self.ptrs[base].delta` is zero for a fresh `alloc` (it is — `offset` is what adds deltas); if the builder folds a delta into `imm` elsewhere for `LOAD`, mirror it (`imm(delta + 8·j)`).

- [ ] **Step 10: Run the differential and the full suite**

Run: `cargo test --release --test precompiles` then `cargo test --release`
Expected: green (the pin tests are `#[ignore]`d).

- [ ] **Step 11: Cheating tests for the two range groups**

Add to `tests/cheating.rs` after the sponge tests, following `an_address_above_two_to_the_twentyfour_with_forged_limbs_is_rejected`'s construction (an honest execution's traces edited by hand — read that test first and reuse its helpers):

```rust
fn hintn_setup() -> (Machine, Program, Traces) {
    let p = Program { instrs: vec![
        i(Op::Faddi, 1, 0, 100),
        i(Op::Hintn, 0, 1, 0),
        i(Op::Load, 2, 1, 7),
        i(Op::Public, 0, 2, 0),
        i(Op::Halt, 0, 0, 0),
    ], checkpoints: vec![] };
    let tape: Vec<F> = (1..=8).map(F::from_u64).collect();
    let m = Machine::new(FriProfile::Test);
    let exec = execute(&p, &tape, 100).unwrap();
    let t = build_traces(&p, &exec, Tier(8)).unwrap();
    (m, p, t)
}

#[test]
fn honest_hintn_traces_pass() {
    let (m, p, t) = hintn_setup();
    prove_and_verify(&m, &p, &t).unwrap();
}

/// The HINTN row's base moved to `p − 1` (so `A0 + B + 7 = 6`, in range by the top alone) with the
/// group-3 base limbs forged to spell 0: the RANGE8 lookups on the forged limbs, or the
/// `base3 − limbs3` identity, refuse it — the ZKQ-3 property, on the new row kind.
#[test]
fn a_hintn_base_just_below_zero_with_forged_limbs_is_rejected() {
    let (m, p, mut t) = hintn_setup();
    let w = cpu::col::WIDTH;
    let row = (0..t.cpu.height()).find(|r| t.cpu.values[r * w + cpu::col::SEL0 + Op::Hintn as usize] == F::ONE).unwrap();
    t.cpu.values[row * w + cpu::col::A0] = -F::ONE; // p − 1, with B = 0
    for c in [cpu::col::G3LIMB0, cpu::col::G3LIMB1, cpu::col::G3LIMB2] {
        t.cpu.values[row * w + c] = F::ZERO;
    }
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

/// The top cell at `2^24`: base `2^24 − 7` with the group-1 limbs forged to spell `2^24 − 1`.
#[test]
fn a_hintn_run_ending_at_two_to_the_twentyfour_with_forged_limbs_is_rejected() {
    let (m, p, mut t) = hintn_setup();
    let w = cpu::col::WIDTH;
    let row = (0..t.cpu.height()).find(|r| t.cpu.values[r * w + cpu::col::SEL0 + Op::Hintn as usize] == F::ONE).unwrap();
    t.cpu.values[row * w + cpu::col::A0] = F::from_u64((1 << 24) - 7);
    let top = (1u64 << 24) - 1;
    for (k, c) in [cpu::col::LIMB0, cpu::col::LIMB1, cpu::col::LIMB2].iter().enumerate() {
        t.cpu.values[row * w + c] = F::from_u64((top >> (8 * k)) & 0xff);
    }
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}
```

Run: `cargo test --release --test cheating hintn`
Expected: honest passes, both forgeries refused. (If the RAM table's own consistency refuses the forgery before the range check does — the moved address has no matching write/read — that is still a refusal; the test asserts refusal, not the step.)

- [ ] **Step 12: Measure**

Run: `cargo test --release --test profile -- --ignored --nocapture 2>&1 | grep -v warning`
Projection: ≈ 1 321 000 production rows (−390 000 from Task 1's number). Gate ±15 % of the delta.

- [ ] **Step 13: Commit**

```bash
git add src/isa.rs src/emulator.rs src/tables/cpu.rs src/dsl/builder.rs tests/
git commit -m "recursion: Cut B — HINTN, eight tape words into eight cells in one cpu row (opcode 26)

<measured profile lines>

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: Cut C — `COMPRESS`, a Merkle level as one cpu row and one Poseidon2-chip row

**Files:**
- Modify: `src/isa.rs` (opcode 27)
- Modify: `src/emulator.rs` (`PermEvent` kind, the `Compress` arm, `ExecError::NonBooleanBit`)
- Modify: `src/tables/mod.rs` (bus `COMPRESS`)
- Modify: `src/tables/poseidon2.rs` (row kind `IS_COMPRESS`, column `BIT`, sends, trace)
- Modify: `src/tables/cpu.rs` (selector, `B_REG`, `READ_RD`, range groups, the `COMPRESS` lookup send, `fill_row`)
- Modify: `src/dsl/builder.rs` (`compress_step`), `src/dsl/hash.rs` (`merkle_walk_with_injections`, `compress` On paths)
- Test: `tests/isa.rs`, `tests/tables.rs`, `tests/emulator.rs`, `tests/transcript.rs`, `tests/precompiles.rs`, `tests/cheating.rs`, `tests/poseidon2.rs`

**Interfaces:**
- Produces: `Op::Compress` (`= 27`, `"COMPRESS"`, `b_is_register() == true`): with `bit = regs[rd] ∈ {0,1}`, `d = mem[regs[ra]..+4]`, `s = mem[regs[rb]..+4]`, writes `mem[regs[ra]..+4] = permute(bit == 0 ? [d‖s] : [s‖d])[0..4]`.
- Produces: `PermEvent { ptr, input, output, kind: PermKind }` with `pub enum PermKind { Perm, Sponge { src: u64 }, Compress { sib: u64, bit: bool } }` replacing `src: Option<u64>`.
- Produces: `bus::COMPRESS: LookupBus` with message `[clk, state_ptr, sib_ptr, bit]`; `poseidon2::col::{IS_COMPRESS, BIT}`, `poseidon2::col::WIDTH == 343`; `cpu::col::WIDTH == 82`, `NUM_SELECTORS == 28`.
- Produces: `Builder::compress_step(&mut self, state: Ptr, sib: Ptr, bit: Felt)`.

- [ ] **Step 1: Failing ISA and emulator tests**

`tests/isa.rs`: `Op::COUNT == 28`, `from_u8(27) == Some(Op::Compress)`, mnemonic `"COMPRESS"`, `b_is_register()` true. `tests/emulator.rs`:

```rust
#[test]
fn compress_orders_the_children_by_the_bit_and_keeps_four_lanes() {
    let (d, s): (Vec<F>, Vec<F>) = ((1..=4).map(F::from_u64).collect(), (11..=14).map(F::from_u64).collect());
    let run = |bit: u64| {
        let mut instrs = vec![i(Op::Faddi, 1, 0, 64), i(Op::Faddi, 2, 0, 80), i(Op::Faddi, 3, 0, bit)];
        for k in 0..4 { instrs.push(i(Op::Faddi, 4, 0, 1 + k)); instrs.push(i(Op::Store, 4, 1, k)); }
        for k in 0..4 { instrs.push(i(Op::Faddi, 4, 0, 11 + k)); instrs.push(i(Op::Store, 4, 2, k)); }
        instrs.push(ir(Op::Compress, 3, 1, 2));
        for k in 0..4 { instrs.push(i(Op::Load, 5, 1, k)); instrs.push(i(Op::Public, 0, 5, 0)); }
        instrs.push(i(Op::Halt, 0, 0, 0));
        execute(&Program { instrs, checkpoints: vec![] }, &[], 1000).unwrap()
    };
    let want = |input: [F; 8]| rand_zkvm::hash::permute_state(input)[..4].to_vec();
    let ds: [F; 8] = core::array::from_fn(|k| if k < 4 { d[k] } else { s[k - 4] });
    let sd: [F; 8] = core::array::from_fn(|k| if k < 4 { s[k] } else { d[k - 4] });
    assert_eq!(run(0).public, want(ds));
    assert_eq!(run(1).public, want(sd));
    let ev = run(1).events.iter().find(|e| e.instr.op == Op::Compress).cloned().unwrap();
    assert_eq!(ev.mem.len(), 12, "4 + 4 reads, 4 writes");
    assert_eq!(ev.d[0], F::ONE, "the bit is read from rd into D0");
    match ev.perm.unwrap().kind { PermKind::Compress { sib: 80, bit: true } => {}, k => panic!("{k:?}") }
}

#[test]
fn compress_refuses_a_non_boolean_bit() {
    let p = Program { instrs: vec![i(Op::Faddi, 1, 0, 64), i(Op::Faddi, 2, 0, 80), i(Op::Faddi, 3, 0, 2), ir(Op::Compress, 3, 1, 2), i(Op::Halt, 0, 0, 0)], checkpoints: vec![] };
    assert_eq!(execute(&p, &[], 100), Err(ExecError::NonBooleanBit { pc: 3 }));
}
```

(`ir(op, rd, ra, rb)` is the register-operand helper from `tests/cheating.rs:18`; copy it.)

Run: `cargo test --test isa --test emulator` → compile error (no `Compress`).

- [ ] **Step 2: ISA, `PermKind`, the emulator arm**

`src/isa.rs`: append `Compress` (doc: "one Merkle level: `bit = rd`, state at `ra` (4 cells), sibling at `rb` (4 cells); the Poseidon2 chip's third row kind; opcode 27"); `COUNT = 28`; `ALL`; `"COMPRESS"`; add `Op::Compress` to `b_is_register`.

`src/emulator.rs`: replace `PermEvent.src: Option<u64>` by `pub kind: PermKind` with

```rust
/// Which row kind of the Poseidon2 chip a permutation event is.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum PermKind {
    /// `POSEIDON2`: the eight cells at `ptr`, in place.
    Perm,
    /// `SPONGE`: four cells at `src` into lanes 0–3, the state's lanes 4–7 kept, eight written.
    Sponge { src: u64 },
    /// `COMPRESS` (Cut C): `[state(4) ‖ sib(4)]` when `bit` is clear, `[sib ‖ state]` when set;
    /// lanes 0–3 of the output written back to `ptr`.
    Compress { sib: u64, bit: bool },
}
```

Fix every constructor and match (`Op::Poseidon2` arm → `kind: PermKind::Perm`, `Op::Sponge` → `PermKind::Sponge { src }`, `tables/poseidon2.rs`'s `poseidon2_trace`, and any test building a `PermEvent` — `grep -rn "src: " tests/ src/`). Add `ExecError::NonBooleanBit { pc: u32 }`. The arm:

```rust
            Op::Compress => {
                let rb = reg_b(&instr, pc)? as usize;
                a[0] = regs[ra];
                b_val[0] = regs[rb];
                d[0] = regs[rd];
                let bit = if d[0] == F::ZERO { false } else if d[0] == F::ONE { true } else { return Err(ExecError::NonBooleanBit { pc }) };
                let (ptr, sib) = (a[0].as_canonical_u64(), b_val[0].as_canonical_u64());
                bounded(pc, ptr + 3)?;
                bounded(pc, sib + 3)?;
                let dg: [F; 4] = core::array::from_fn(|k| read(&mem, &mut mems, clk, ptr + k as u64));
                let sb: [F; 4] = core::array::from_fn(|k| read(&mem, &mut mems, clk, sib + k as u64));
                let input: [F; 8] = core::array::from_fn(|k| match (bit, k < 4) {
                    (false, true) => dg[k], (false, false) => sb[k - 4],
                    (true, true) => sb[k], (true, false) => dg[k - 4],
                });
                let output = rand_zkvm::hash::permute_state(input);
                for k in 0..4 {
                    write(&mut mem, &mut mems, clk, ptr + k as u64, output[k]);
                }
                perm = Some(PermEvent { ptr, input, output, kind: PermKind::Compress { sib, bit } });
            }
```

Read order matters for the timestamp slots: the chip's sends are state reads at slots 0–3, sibling reads at 4–7, writes at 8–11 — but `write` here assigns the slot from `mems.len()` (= 8, 9, 10, 11 after eight reads) — confirm with `emulator.rs:468-492`'s `read`/`write`/`ts` helpers and make the chip's `eval` use the same slot numbers.

Run: `cargo test --test isa --test emulator` → pass.

- [ ] **Step 3: Failing width pins and a failing chip test**

`tests/tables.rs`: cpu `82` ("+ the COMPRESS selector"), poseidon2 `343` ("+ IS_COMPRESS, BIT"). `tests/poseidon2.rs` (the chip's equality contract, read it first): add a test that builds the trace of the emulator run from Step 1 (`bit = 1`) with `build_traces` at `Tier(8)` and proves + verifies it (`Machine::new(FriProfile::Test)` and the file's existing prove/verify helpers).

Run: `cargo test --release --test tables --test poseidon2` → the pins fail; the proof test fails (no `COMPRESS` bus provider → lookup imbalance panic, caught by the test's `rejects`-style wrapper or a plain `unwrap` failing — either is the red).

- [ ] **Step 4: The bus, the chip's third row kind, the cpu side**

`src/tables/mod.rs`:

```rust
    /// cpu (COMPRESS rows) → poseidon2: (clk, state_ptr, sib_ptr, bit). Cut C: one Merkle level.
    pub const COMPRESS: LookupBus<'static> = LookupBus::new("COMPRESS");
```

`src/tables/poseidon2.rs`: columns `IS_COMPRESS = X3_0 + 86`, `BIT = IS_COMPRESS + 1`, `WIDTH = BIT + 1` (343). In `eval`:

```rust
        let is_compress = v(IS_COMPRESS);
        b.assert_bool(is_compress.clone());
        b.assert_eq(is_perm.clone() + is_sponge.clone() + is_compress.clone(), is_real.clone());
        // Invariant 1: SRC_PTR is a message column of SPONGE and COMPRESS; zero elsewhere. BIT is
        // COMPRESS's alone, boolean there and zero elsewhere.
        b.assert_zero((one.clone() - is_sponge.clone() - is_compress.clone()) * v(SRC_PTR));
        b.assert_bool(v(BIT));
        b.assert_zero((one.clone() - is_compress.clone()) * v(BIT));
```

(replace the existing two-kind `assert_eq` and `SRC_PTR` zero rule with these). After the SPONGE sends:

```rust
        // ── COMPRESS (Cut C): the ordered pair is the permutation input; the RAM reads carry the
        // unordered children as degree-2 expressions of IN and BIT, so no extra value columns ──
        bus::COMPRESS.table_entry(b, [clk.clone(), ptr.clone(), v(SRC_PTR), v(BIT)], is_compress.clone());
        let bit = v(BIT);
        for k in 0..4 {
            // d_k = IN[k] + bit·(IN[4+k] − IN[k]);  s_k = IN[4+k] + bit·(IN[k] − IN[4+k]).
            let d_k = v(IN0 + k) + bit.clone() * (v(IN0 + 4 + k) - v(IN0 + k));
            let s_k = v(IN0 + 4 + k) + bit.clone() * (v(IN0 + k) - v(IN0 + 4 + k));
            let ts_d = sixteen.clone() * clk.clone() + AB::Expr::from_u32(k as u32);
            let ts_s = sixteen.clone() * clk.clone() + AB::Expr::from_u32(4 + k as u32);
            let ts_w = sixteen.clone() * clk.clone() + AB::Expr::from_u32(8 + k as u32);
            bus::RAM.send(b, [ptr.clone() + AB::Expr::from_u32(k as u32), ts_d, d_k, AB::Expr::ZERO], Count::bounded(is_compress.clone(), 1));
            bus::RAM.send(b, [v(SRC_PTR) + AB::Expr::from_u32(k as u32), ts_s, s_k, AB::Expr::ZERO], Count::bounded(is_compress.clone(), 1));
            bus::RAM.send(b, [ptr.clone() + AB::Expr::from_u32(k as u32), ts_w, v(OUT0 + k), one.clone()], Count::bounded(is_compress.clone(), 1));
        }
```

Check the chip's pinned max constraint degree in `tests/tables.rs` (4): a LogUp message of degree 2 adds one to the lookup constraint's degree — if the pin moves to 5, the quotient chunk count for the chip doubles; prefer to keep degree ≤ 4. If the pin moves, add two columns `D0..D3`/`S0..S3`? No — add **eight** columns `CH0..CH7` holding the unordered children, constrain `IN[k] = CH[k] + BIT·(CH[4+k] − CH[k])`, `IN[4+k] = CH[4+k] − BIT·(CH[4+k] − CH[k])` (degree 2 *constraints*, degree 1 messages), and send `CH` on the bus; width becomes 351. Record which was needed in the commit message.

`poseidon2_trace`: for `PermKind::Compress { sib, bit }` set `IS_COMPRESS = 1`, `SRC_PTR = sib`, `BIT = bit as u64`; `IN` is the event's (already ordered) `input`.

`src/tables/cpu.rs`: `NUM_SELECTORS = 28`, shift every post-`SEL0` constant by one more (`A0 = 35`, …, `W0 = 74`, `WIDTH = 82`). `Sels::B_REG` and `Sels::READ_RD` gain `Op::Compress`. Range groups in `eval`: group 1 subject `+ sel(Op::Compress) * (v(A0) + 3)`, `needs_check + sel(Op::Compress)`; group 2 (`subject2`, `limbs2`, its lookups): gate on `sel(Op::Sponge) + sel(Op::Compress)` with subject `B0 + 3` for both; group 3 `is_multi`/`base3` gain `sel(Op::Compress)` with base `A0`; group 4 gate `sel(Op::Sponge) + sel(Op::Compress)`, base `B0`. The dispatch:

```rust
        bus::COMPRESS.lookup_key(b, [v(CLK), v(A0), v(B0), v(D0)], Count::bounded(sel(Op::Compress), 1));
```

`fill_row`: `subject` gains `Op::Compress => Some(e.a[0].as_canonical_u64() + 3)`; the group-2 block `if e.instr.op == Op::Sponge` becomes `matches!(e.instr.op, Op::Sponge | Op::Compress)`; `base3` gains `Op::Compress => Some(e.a[0]…)`; `base4` likewise. `register_accesses` needs no change (`B_REG`/`READ_RD` drive it).

Run: `cargo test --release --test tables --test poseidon2 --test cpu --test cheating --test machine` → pass (the binding test iterates `Op::ALL`, so `Compress` is checked: `D0` is bound by the `REG` read of `rd`).

- [ ] **Step 5: Failing DSL tests — the walk under `Precompiles::On`**

`tests/transcript.rs::a_restored_merkle_path_verifies_in_the_dsl_exactly_where_p3_verifies_it` builds its `Builder` with some options — parameterise it over `Precompiles::{Off, On}` (a loop in the test body or a second test `..._with_the_compress_precompile`). Add to `tests/precompiles.rs`:

```rust
/// Cut C: the walk with injections under `Precompiles::On` (one COMPRESS per level) computes the
/// compiled walk's digest, for random leaves, siblings and index bits, 1..=12 levels, with and
/// without an injection — and costs one cpu row per level plus the dispatch of the injection.
#[test]
fn merkle_walk_via_compress_matches_the_compiled_walk() {
    use recursion::dsl::{hash, Builder, Checkpoints, Digest, Liveness};
    use recursion::programs::Precompiles;
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(27);
    for levels in 1..=12usize {
        for with_injection in [false, true] {
            let leaf: Vec<F> = (0..4).map(|_| common::random_felt(&mut rng)).collect();
            let sibs: Vec<F> = (0..4 * levels).map(|_| common::random_felt(&mut rng)).collect();
            let bits: Vec<bool> = (0..levels).map(|_| rng.random()).collect();
            let inj: Vec<F> = (0..9).map(|_| common::random_felt(&mut rng)).collect();
            let run = |pc: Precompiles| {
                let mut b = Builder::with_opts(Checkpoints::Off, Liveness::On, pc);
                let leaf_p = b.alloc(4);
                for (k, v) in leaf.iter().enumerate() { let c = b.constant(*v); b.store(leaf_p, k as i64, c); }
                let sib_p = b.alloc(4 * levels as u64);
                for (k, v) in sibs.iter().enumerate() { let c = b.constant(*v); b.store(sib_p, k as i64, c); }
                let bit_f: Vec<_> = bits.iter().map(|&t| b.constant(F::from_bool(t))).collect();
                let inj_p = b.alloc(9);
                for (k, v) in inj.iter().enumerate() { let c = b.constant(*v); b.store(inj_p, k as i64, c); }
                let injections = if with_injection && levels >= 2 {
                    vec![hash::Injection { after_level: levels / 2, rows: inj_p, n_cells: 9 }]
                } else { vec![] };
                let out = Digest(b.alloc(4));
                hash::merkle_walk_with_injections(&mut b, Digest(leaf_p), &bit_f, sib_p, levels, &injections, out);
                for k in 0..4 { let v = b.load(out.0, k); b.public(v); }
                let exec = execute(&b.finish(), &[], 1_000_000).unwrap();
                (exec.public, exec.histogram()[Op::Compress as usize])
            };
            let (off, _) = run(Precompiles::Off);
            let (on, compress_rows) = run(Precompiles::On);
            assert_eq!(on, off, "levels {levels}, injection {with_injection}");
            let expected_compress = levels + usize::from(with_injection && levels >= 2);
            assert_eq!(compress_rows, expected_compress, "one COMPRESS per level and per injection");
        }
    }
}
```

Run: `cargo test --release --test precompiles merkle_walk` → fails (no `compress_step`, zero COMPRESS rows).

- [ ] **Step 6: `Builder::compress_step` and the hash On paths**

`src/dsl/builder.rs`, next to `sponge_absorb`:

```rust
    /// One `COMPRESS` instruction (Cut C): the four-cell digest at `state` and the four-cell
    /// sibling at `sib`, ordered by `bit`, permuted by the poseidon2 chip, lanes 0–3 written back
    /// over `state`. `bit` must be boolean — the emulator refuses anything else as a build error.
    pub fn compress_step(&mut self, state: Ptr, sib: Ptr, bit: Felt) {
        self.begin();
        let ra = self.ptr_reg(state);
        let rb = self.ptr_reg(sib);
        let rd = self.materialise(self.slot_of(bit)); // the register holding `bit` (see `raw_reg`)
        self.emit(Op::Compress, rd, ra, bref_of(rb));
        self.stats.perms += 1;
    }
```

Use whatever the builder's existing API is for "the register a `Felt` handle currently lives in" (`raw_reg(t)` in `select_children` does exactly this inside a `raw_group`; `materialise(holder)` is the handle-level call — read `builder.rs` around `raw_reg`/`materialise` and pick the one that works outside a raw group).

`src/dsl/hash.rs`: in `merkle_walk_with_injections`, branch on `b.precompiles()`: `Off` → the existing body, unchanged; `On`:

```rust
    // Cut C: the running digest lives in four dedicated cells (`cur`); one COMPRESS per level
    // selects the children by the bit and writes the parent back over `cur`. An injection is
    // sponged into a scratch digest and compressed in with the bit clear — `[digest ‖ sponge]`,
    // the reference's fixed order (`mmcs/batch.rs:245-262`).
    let cur = b.alloc(DIGEST_ELEMS as u64);
    b.copy_cells(cur, 0, leaf.0, 0, DIGEST_ELEMS);
    let zero = b.zero();
    for (l, &bit) in index_bits.iter().enumerate().take(levels) {
        let sib = b.offset(siblings, (l * DIGEST_ELEMS) as i64);
        b.compress_step(cur, sib, bit);
        for inj in injections.iter().filter(|i| i.after_level == l) {
            let tmp = Digest(b.alloc(DIGEST_ELEMS as u64));
            sponge(b, inj.rows, inj.n_cells, tmp);
            b.compress_step(cur, tmp.0, zero);
        }
    }
    b.copy_cells(out.0, 0, cur, 0, DIGEST_ELEMS);
```

(`sponge` under `On` uses the hash scratch — `cur` and `tmp` are separate allocations, so the aliasing rule in the module doc holds.) `compress` (the standalone): under `On`, `copy left → out (if not aliased), compress_step(out, right, zero)`; under `Off` unchanged. Grep `compress(` and `compress_into_state(` call sites in `src/programs/*.rs` and `src/dsl/*.rs` to make sure every caller is still correct under both switches (the cap compare `assert_cap_eq` compares, it does not compress — check).

Run: `cargo test --release --test precompiles --test transcript` → pass.

- [ ] **Step 7: Full suite**

Run: `cargo test --release` → green (ignore the two pin tests).

- [ ] **Step 8: Cheating tests — one per new invariant**

Add to `tests/cheating.rs`, with a `compress_setup()` that runs Step 1's `bit = 1` program through `build_traces` at `Tier(8)`:

```rust
#[test] fn honest_compress_traces_pass() { let (m, p, t) = compress_setup(); prove_and_verify(&m, &p, &t).unwrap(); }

/// BIT = 2 on the chip row: `assert_bool(BIT)` refuses it.
#[test]
fn a_compress_row_with_a_non_boolean_bit_is_rejected() {
    let (m, p, mut t) = compress_setup();
    let w = poseidon2::col::WIDTH;
    let row = (0..t.poseidon2.height()).find(|r| t.poseidon2.values[r * w + poseidon2::col::IS_COMPRESS] == F::ONE).unwrap();
    t.poseidon2.values[row * w + poseidon2::col::BIT] = F::from_u64(2);
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

/// The chip row's BIT flipped against the cpu row's D0: the COMPRESS bus message no longer
/// matches, or the RAM reads (now claiming swapped children) no longer match their writes.
#[test]
fn a_compress_row_whose_bit_disagrees_with_the_dispatch_is_rejected() {
    let (m, p, mut t) = compress_setup();
    let w = poseidon2::col::WIDTH;
    let row = (0..t.poseidon2.height()).find(|r| t.poseidon2.values[r * w + poseidon2::col::IS_COMPRESS] == F::ONE).unwrap();
    t.poseidon2.values[row * w + poseidon2::col::BIT] = F::ZERO;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

/// The row claims the plain kind with BIT still set: `(1 − IS_COMPRESS)·BIT = 0` refuses it.
#[test]
fn a_compress_row_claiming_the_plain_kind_is_rejected() {
    let (m, p, mut t) = compress_setup();
    let w = poseidon2::col::WIDTH;
    let row = (0..t.poseidon2.height()).find(|r| t.poseidon2.values[r * w + poseidon2::col::IS_COMPRESS] == F::ONE).unwrap();
    t.poseidon2.values[row * w + poseidon2::col::IS_COMPRESS] = F::ZERO;
    t.poseidon2.values[row * w + poseidon2::col::IS_PERM] = F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

/// The sibling pointer moved by one cell: the four sibling reads find no matching writes.
#[test]
fn a_compress_row_reading_the_sibling_from_the_wrong_address_is_rejected() {
    let (m, p, mut t) = compress_setup();
    let w = poseidon2::col::WIDTH;
    let row = (0..t.poseidon2.height()).find(|r| t.poseidon2.values[r * w + poseidon2::col::IS_COMPRESS] == F::ONE).unwrap();
    t.poseidon2.values[row * w + poseidon2::col::SRC_PTR] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

/// A padding row with IS_COMPRESS set: `MULT = IS_REAL` and the kind sum refuse it.
#[test]
fn a_padding_row_claiming_compress_is_rejected() {
    let (m, p, mut t) = compress_setup();
    let w = poseidon2::col::WIDTH;
    let row = (0..t.poseidon2.height()).rev().find(|r| t.poseidon2.values[r * w + poseidon2::col::IS_REAL] == F::ZERO).unwrap();
    t.poseidon2.values[row * w + poseidon2::col::IS_COMPRESS] = F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}
```

Also the table-driven R6 invariants test (`tests/tables.rs`, "every written value bound, no padding sends" — grep `padding sends`): extend its row-kind list with `IS_COMPRESS` if it enumerates kinds explicitly.

Run: `cargo test --release --test cheating compress --test tables` → honest passes, every forgery refused.

- [ ] **Step 9: Measure**

Run: `cargo test --release --test profile -- --ignored --nocapture 2>&1 | grep -v warning`
Projection: ≈ 790 000 production rows (−530 000 from Task 2's number), **tier 20**. Gate ±15 % of the delta. Also note the new `POSEIDON2`/`COMPRESS`/`SPONGE` histogram lines and RAM accesses.

- [ ] **Step 10: Commit**

```bash
git add src/ tests/
git commit -m "recursion: Cut C — COMPRESS, a Merkle level as one cpu row and one Poseidon2-chip row (opcode 27)

<measured profile lines; the chip's degree note from Step 4>

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: Re-pin everything that moved and write the record

**Files:**
- Modify: `tests/pins.json` (regenerated), `tests/exit.rs` (row literals, `Tier(19)`→ the measured tier for the twin, `Tier(21)` → `Tier(20)` for the exit), `tests/aggregate.rs` (`LOOP_OVERHEAD`, `N3_ROWS`, tier assertions), `src/programs/verify_rv32.digest` (regenerated), `tests/pins.json`
- Modify: `docs/00-recursion-vm.md` ("Where the rows go" — append the new measurement), `docs/01-rvm-machine.md` (table widths/heights/tier), `docs/02-aggregate.md` (N-economics at the new tiers; admission vectors' `aggregate_program_digest`), `research/AGENTS.md` (the recursion paragraph)
- Create: `docs/04-phase2-row-cuts.md`

- [ ] **Step 1: Regenerate the pins**

```bash
rm tests/pins.json
cargo test --release --test exit the_cycle_budget_per_inner_proof_is_pinned -- --ignored --nocapture
cargo test --release --test aggregate -- --ignored --nocapture 2>&1 | grep -i 'rows\|overhead\|digest'
```

`pins()` writes `tests/pins.json` when absent (`tests/common/mod.rs`). The aggregate pins (`aggregate_test_n{1,2,3}_*`) are written by the aggregate tests' pin path — read `common::measure_aggregate` and the `#[ignore]`d aggregate tests to see which one writes them, and run it. Then fix `tests/exit.rs:304/345`'s literals and tier assertions and `tests/aggregate.rs`'s `LOOP_OVERHEAD`/`N3_ROWS` to the printed values; regenerate `src/programs/verify_rv32.digest` the way `the_committed_program_digest_is_reproducible` expects (read it: it either writes the file when absent or asserts — delete and re-run if the former).

- [ ] **Step 2: Run every ignored test that is emulation-only**

```bash
cargo test --release -- --ignored --nocapture 2>&1 | grep -E '^test |rows|digest' 
```

Skip (Ctrl-C is not available to a subagent, so **list them with `--list` first and run by name**) the proving ones: `twin_*`, `exit_the_verifier_program_*`, `two_test_profile_*`, `production_n1_aggregate_proves_*`, `tier19_exit_twin`, `a_forged_stored_high_lane_in_the_aggregate_verifier_is_refused`. Everything else green.

- [ ] **Step 3: Write `docs/04-phase2-row-cuts.md`**

Structure (fill every number from the three measured `profile` runs and the pins):

```markdown
# 04 — Phase 2 row cuts: the inner verifier at tier 20, and the prover's live heap

Design: `docs/superpowers/specs/2026-10-03-rvm-phase2-row-cuts-design.md`. Plan: `.../plans/2026-10-03-rvm-phase2-row-cuts.md`.

## The measurement that gated it
<the spec §1 tables, verbatim, labelled "before">

## The three cuts, each measured
| stage | cpu rows (prod.) | Δ | projection | RAM accesses | permutations | tier |
| before (cs8) | 2 047 268 | — | — | 2 851 913 | 54 515 | 21 |
| A: hint into the group buffer | … | … | −336 000 | … | … | … |
| B: HINTN | … | … | −390 000 | … | … | … |
| C: COMPRESS | … | … | −530 000 | … | … | **20** |
<the final per-phase and per-opcode tables from profile.rs>

## What moved
<program digest old → new; aggregate program digest old → new; widths 72→82, 341→343; the tape's segment 11 order; pins.json>

## The N-economics at the new tiers (derived from the measured N=1 and the loop overhead)
<N=1 tier 20, N=2 tier 21, N=4 tier 22, with the oracle model's memory at each>

## The prover's live heap (Task 5 fills this section)
```

- [ ] **Step 4: Update the older records**

`docs/00` "Where the rows go": add a dated paragraph pointing at docs/04 and `tests/profile.rs`. `docs/01`: the tables (cpu 82, poseidon2 343, the third row kind, the new buses `COMPRESS` — nine buses), the measured-numbers table (new rows/heights/tier), the production-exit requirement paragraph (now tier 20; memory per docs/04 §live heap). `docs/02`: the N-economics tables' tiers and the admission vectors' digests. `research/AGENTS.md`: the recursion paragraph's row count and tier.

- [ ] **Step 5: Commit**

```bash
git add tests/pins.json tests/exit.rs tests/aggregate.rs src/programs/verify_rv32.digest docs/ ../research/AGENTS.md
git commit -m "recursion: phase 2 re-pinned — <N> rows per inner proof, tier 20; docs/04 records the three cuts

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: The live-heap record (the measurement is already running)

**Files:**
- Modify: `docs/04-phase2-row-cuts.md` (§ "The prover's live heap")
- Source: `/private/tmp/claude-501/-Users-dendisuhubdy-Github-randprotocol/c88907b2-a154-4173-bbc0-449b9c3f54c7/scratchpad/mem/tier19.log` (the tier-19 exit twin under `tests/memprofile.rs`, started 2026-10-03; `/usr/bin/time -l` wraps it, so the last lines carry the macOS maximum RSS)

- [ ] **Step 1: Extract the phase table**

```bash
L=/private/tmp/claude-501/-Users-dendisuhubdy-Github-randprotocol/c88907b2-a154-4173-bbc0-449b9c3f54c7/scratchpad/mem/tier19.log
grep -E '^\[.*\] [+-] |^\[.*\]   - ' $L | grep -v 'infer\|verify constraints' | cut -c1-140   # top-level spans with Δlive and seconds
grep '# sample' $L | awk '{print $5, $8, $11}' | sort -n | tail -1                               # peak live / rss sample
grep -E '^==|maximum resident|real' $L
```

- [ ] **Step 2: Write the section**

Table: span → Δlive GB → seconds, for `randomize polys`, each `coset_lde_batch_with_transform` summed per commit, `first digest layer`, `compute quotient` (per instance), the quotient commit, the random commitment, `open`/`query phase`. Then: peak live heap, macOS max RSS, the Linux 94.2 GB figure for the same shape, the ratio, and the conclusion the spec §3.2 lays out (which branch applies). State the live model: `peak ≈ k × committed-oracle` with `k` measured; project tier 21 before the cuts and tier 20 after.

- [ ] **Step 3: Commit**

```bash
git add docs/04-phase2-row-cuts.md
git commit -m "recursion docs: the tier-19 prover's live heap, by phase — <peak> GB live against 94.2 GB Linux RSS

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 6: The `parallel` feature, with the fullnode's two-crate Plonky3 patch

**Files:**
- Create: `vendor/p3-fri/` and `vendor/p3-merkle-tree/` at the **circuits repository root** (`~/rand-worktrees/circuits-phase2/vendor/`), copied from `~/Github/randprotocol/fullnode/vendor/p3-fri` and `.../p3-merkle-tree` (crates.io 0.7.0 source plus the "RandProtocol patch (2026-10-01)" in `hiding_pcs.rs` and `hiding_mmcs.rs`; `diff -r` against `~/.cargo/registry/src/index.crates.io-*/p3-{fri,merkle-tree}-0.7.0/src` shows exactly those two files differ)
- Create: `vendor/PROVENANCE.md` (what the two copies are, the upstream issue Plonky3 #2363 / PR #2368, the fullnode path they were copied from and its commit)
- Modify: `recursion/Cargo.toml` (`[patch.crates-io]`, the `parallel` feature, `p3-maybe-rayon` optional dependency)
- Test: `tests/backend.rs` or `tests/machine.rs` (the toy proves and verifies with the feature on), `tests/exit.rs` twin timed on 1 and 16 threads

**Interfaces:**
- Produces: `cargo test --release --features parallel …` builds the prover with rayon; `RAYON_NUM_THREADS=N` sets the pool. Proofs verify with the stock (non-parallel) verifier — the config, transcript and FRI parameters are unchanged (the `docs/03` postcard-retype discipline).

- [ ] **Step 1: Copy the patched crates and record provenance**

```bash
cd ~/rand-worktrees/circuits-phase2
mkdir -p vendor && cp -R ~/Github/randprotocol/fullnode/vendor/p3-fri vendor/ && cp -R ~/Github/randprotocol/fullnode/vendor/p3-merkle-tree vendor/
diff -rq ~/.cargo/registry/src/index.crates.io-*/p3-fri-0.7.0/src vendor/p3-fri/src        # expect: hiding_pcs.rs only
diff -rq ~/.cargo/registry/src/index.crates.io-*/p3-merkle-tree-0.7.0/src vendor/p3-merkle-tree/src   # expect: hiding_mmcs.rs only
rm -rf vendor/p3-fri/target vendor/p3-merkle-tree/target 2>/dev/null
```

Write `vendor/PROVENANCE.md` (ten lines: the two crates, version 0.7.0, the single patched file each, the reason — the hiding RNG spin lock held across rayon work deadlocks a stolen `commit`, upstream Plonky3 #2363 / #2368 — the fullnode commit copied from (`git -C ~/Github/randprotocol/fullnode log -1 --format=%h -- vendor/p3-fri`), and that research/ does not use them yet).

- [ ] **Step 2: Wire the feature**

`recursion/Cargo.toml`:

```toml
# Plonky3's own `parallel` feature (rayon) for the prover, off by default: the proofs it makes are
# the same proofs (same config, transcript and FRI parameters — `docs/03`'s retype discipline),
# made on every core. Needs the two patched crates under `../vendor/` (hiding RNG lock forked,
# never held across rayon work — upstream Plonky3 #2363; the fullnode's patch, copied verbatim).
parallel = ["dep:p3-maybe-rayon", "p3-maybe-rayon/parallel", "dep:rayon"]
```

under `[features]`; under `[dependencies]`: `p3-maybe-rayon = { version = "=0.7.0", optional = true }` and `rayon = { version = "1", optional = true }`; and at the end of the file:

```toml
[patch.crates-io]
p3-fri = { path = "../vendor/p3-fri" }
p3-merkle-tree = { path = "../vendor/p3-merkle-tree" }
```

The patch applies to every build of this package root (feature on or off) — it is behaviour-identical when single-threaded, and having one source tree is the point.

- [ ] **Step 3: Both builds still prove and verify**

```bash
cargo test --release --test backend --test machine                       # feature off
cargo test --release --features parallel --test backend --test machine   # feature on
```

Expected: green both ways. If `Cargo.lock` changes (it will — the patch entries), commit it.

- [ ] **Step 4: Time the twin on 1 and 16 threads**

```bash
export RECURSION_FIXTURES=$HOME/rand-agg-512-results/out/fixtures
RAYON_NUM_THREADS=1  cargo test --release --features parallel --test exit twin -- --ignored --nocapture 2>&1 | grep '^twin'
RAYON_NUM_THREADS=16 cargo test --release --features parallel --test exit twin -- --ignored --nocapture 2>&1 | grep '^twin'
```

(Each run is one tier-19 proof: ~30 min single-threaded on this box, hopefully ~4–6 min on 16.) Record `prove`/`verify` seconds and the `/usr/bin/time -l` maximum RSS if wrapped. Compare with Task 5's single-threaded live-heap peak: rayon's per-thread scratch may raise the peak — say by how much.

- [ ] **Step 5: Record and commit**

Add a "Threads" paragraph to `docs/04-phase2-row-cuts.md` (the two wall times, the speed-up, the memory delta) and note the feature in `docs/03-gpu-and-self-recursion.md`'s backend section.

```bash
git add vendor/ recursion/Cargo.toml recursion/Cargo.lock docs/
git commit -m "recursion: the parallel feature — Plonky3 rayon with the fullnode's hiding-RNG patch vendored; the tier-19 twin at 1 and 16 threads: <t1> s → <t16> s

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Self-review notes

- Spec §2.1 → Task 1; §2.2 → Task 2; §2.3 → Task 3; §2.4's gate → each task's Measure step; §3 → Tasks 5–6; §4 → Task 4; §5's test list → Tasks 1–3's test steps (differential program-level: Task 1 Steps 8–9 and every task's full-suite step; primitive-level: Task 3 Step 5; cheating: Tasks 2 Step 11, 3 Step 8; table invariants: Tasks 2 Step 5, 3 Steps 3/8; measurement: every Measure step; memory: Task 5).
- Names used across tasks: `shape::height_groups` (T1), `Op::Hintn`/`cpu::col::W0` (T2, T3 shifts the index), `Op::Compress`, `PermKind`, `bus::COMPRESS`, `poseidon2::col::{IS_COMPRESS, BIT}`, `Builder::compress_step` (T3). Column indices in T2 Step 6 are superseded by T3 Step 4's shift of one more — T3 restates them.
- Review Focus 1–5 are pinned in: T1 Steps 8–9; T2 Step 8; T2 Steps 1 and 11; T3 Steps 5 (both tests); T3 Steps 1 and 8.
