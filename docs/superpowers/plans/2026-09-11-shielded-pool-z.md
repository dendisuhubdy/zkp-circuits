# Fully shielded pool — Phase Z (zkVM side, `circuits/research`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the zkVM-side half of the fully shielded pool — everything phase Z owns per the
design spec's §12 phase table — inside `rand_zkvm` (`circuits/research`): a looped
`MERKLE_VERIFY` routine (replacing the unrolled 32-level one so the guest's own program size, and
hence its `hc`/digest-row cost, stops scaling with tree depth), `u64` note amounts, the
2-in-2-out `bundle` guest (spend key ownership, dual membership with dummy-input skip, dual
nullifiers, dual outputs, 64-bit fee/burn conservation, one 46-word output digest), and the
ledger/viewing-layer plumbing that lets a simulated chain admit a `Bundle` transaction and a
party's or transaction's viewing key open its rows. When this plan is done, `bundle` proves and
verifies under `R_exec` at a measured tier, every cheating scenario the spec calls out is
rejected (some by the STARK, most — following this crate's established idiom — structurally, by
the ledger's own digest/anchor/nullifier checks), and `research/docs/{04-guests,05-roadmap,
06-viewing-keys}.md` carry the measured numbers.

**Architecture:** Four tasks, each landing on top of the previous, no new AIR tables or
constraints (phase Z's own text confirms this: "measured tier" and "vendored" are the only
circuit-adjacent asks — every new relation in `bundle` is either **structural** by construction
(an ownership or asset mismatch produces a note that doesn't match the real tree leaf) or
**taint-and-corrupt** (a violated arithmetic relation flips one bit into an accumulator that is
folded into the published digest before it is hashed, so a dishonest witness's proof is
internally consistent — the STARK verifies — but its digest can never equal what an honest
ledger recomputes from the plaintext the sender is forced to publish alongside it). This is the
exact idiom `docs/06-viewing-keys.md` and `tests/viewing.rs::a_transfer_with_a_wrong_merkle_path_is_rejected`
/ `a_viewing_key_cannot_spend` already establish for `transfer`; phase Z generalizes it rather
than inventing an in-circuit "assert", which this RV32IM machine has no primitive for (no trap,
no division-by-zero fault, no native equality gate outside `BranchCond`, which only steers
control flow, never fails a proof).

Task 1 (loop) and Task 2 (`u64` amounts) both touch `guests::transfer`/`notes.rs`/`asm.rs` and
are ordered first because Task 3's `bundle` guest is written directly against their post-change
shapes (looped `MERKLE_VERIFY`, `Note::WORDS = 28`). Task 4 (ledger/viewing) depends on Task 3's
`notes::bundle_digest`/`expected_bundle_outputs`/`bundle_input` and on nothing else new.

**Tech Stack:** Rust `1.98.1` (pinned by `research/rust-toolchain.toml`; every command below is
`cargo +1.98.1 ...`), Plonky3 `=0.7.0`, no new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-11-shielded-pool-design.md` §3 (transaction shape), §4
(the `bundle` relation), §5 (notes/keys/addresses), §12 (phase table — phase Z's own row), §13
(rulings: 2-in-2-out fixed shape, `u64` amounts). Also binding: `research/AGENTS.md` (invariants,
`rejects()` discipline, one-fixed-length-per-domain, measured-numbers-in-docs), `research/docs/
06-viewing-keys.md` (the `transfer` relation and cost model this plan extends), `research/docs/
04-guests.md`. Format and TDD granularity follow `docs/superpowers/plans/2026-09-11-zkvm-m4-1.md`.

## Global Constraints

- **Toolchain**: every cargo invocation is `cargo +1.98.1 ...`.
- **`rand` 0.10**: `notes.rs`/`viewing.rs`'s existing `use rand::Rng;` covers `rng().next_u32()`/
  `fill_bytes()` (already used by `Note::new`/`SpendKey::random`/`TxKey::random`) — nothing new
  needed for host-side test code that only calls those. Only code calling the generic
  `.random::<T>()` method (as `machine.rs`'s salt draw does) needs `use rand::RngExt;`; this plan
  adds no new call site of that form.
- **Constraint degree cap 8 / no new AIR**: phase Z adds no new table, no new bus, no new
  syscall, no new column. Every new relation is either structural (reusing an existing register/
  memory value in two commitments so a lie makes them disagree) or built from existing RV32IM
  instructions (`add`, `sltu`, `xor`, `or`, `mul`, branches) executed by the existing `cpu`/`alu`/
  `memory`/`poseidon2` tables, whose constraints are unchanged. If any step below is found to need
  a new table or column, that is out of phase Z's scope — stop and re-plan; this should not
  happen given the design below.
- **Every bus message column constrained on every row kind that sends it** / **a bus count
  forced to zero on padding rows** (`research/AGENTS.md` invariants 1–2): not touched by this
  plan (no new bus provider/consumer), noted for completeness.
- **The emulator is the reference semantics**: every new guest routine's correctness is checked
  against a host-side Rust reference (`notes::hash`, `ledger::CommitmentTree`, the new
  `notes::bundle_*` functions) exactly the way `transfer`/`MERKLE_VERIFY` already are
  (`tests/viewing.rs::merkle_verify_matches_a_host_side_tree`).
- **One fixed message length per hash domain**: `domain::BUNDLE`'s message is always the 46-word
  preimage `[anchor(8), nf1(8), nf2(8), cm1(8), cm2(8), fee(2), burn(2), asset(1), time(1)]`,
  never attacker-influenced in length — the guest always writes exactly 46 words to the hash
  scratch buffer before calling `POSEIDON2`, regardless of which inputs/outputs are dummies.
- **`rejects()` test discipline** (`tests/cheating.rs`): reserved for tests that tamper the
  *trace* directly (a `Traces` field edited after `build_traces_salted`, as
  `a_viewing_key_cannot_spend`'s `t.public_values[cpu::pv::OUT0]` tamper does) — those are genuine
  constraint failures. A test that instead hands the *honest, unmodified* guest a *logically
  dishonest but internally consistent* private-input vector (a forged amount, a wrong Merkle
  path, an over-spend) is not a STARK-level rejection under this crate's idiom; it is caught by
  comparing the guest's honestly-computed output to `notes::expected_bundle_outputs(..)` for the
  claimed plaintext, or — one level up — by `Ledger::apply_bundle` returning an error. Every task
  below is explicit about which of the two applies to each test; see also "Ambiguities resolved."
- **Docs carry measured numbers**: every "measure and record" step names the exact `cargo
  +1.98.1 test ...` command and the doc section to paste the result into. This plan does not run
  cargo; every numeric placeholder below is explicitly marked *(measured by the implementer)*.
- **Commit style**: `research: <area> — <what>` (`git log` in `research/`), one logical change
  per commit, docs riding with the change they describe.

## File structure

```
research/
  src/
    asm.rs                    [edit]  Task 1 — emit_merkle_verify (loop), copy_word8_from_reg;
                                       Task 3 — emit_eq8, emit_bool_or, emit_range_check_u63,
                                                emit_add64_carry, emit_note_commit reused as-is
    notes.rs                  [edit]  Task 2 — Note.amount: u64, Note::WORDS=28, domain::BUNDLE=11,
                                              input module offsets shift, transfer_inputs/
                                              expected_outputs signatures (u64 amount);
                                       Task 3 — bundle_input module, bundle_inputs,
                                              expected_bundle_outputs, bundle_digest
    guests.rs                 [edit]  Task 1 — transfer()/merkle_probe() call the loop routine;
                                       Task 3 — pub fn bundle(), note_commit_probe unaffected
    ledger.rs                 [edit]  Task 4 — Bundle tx type, apply_bundle, fees_collected/
                                              burned accumulators, mint unaffected (already
                                              takes a Note, now u64 amount — mechanical)
    viewing.rs                [edit]  Task 4 — two-output envelopes, scan/verify_row over bundles
  tests/
    viewing.rs                 [edit]  Task 1 — measured-numbers test updated for the loop;
                                              Task 2 — u64-amount cheating test
    cheating.rs                 [edit]  Task 1 — no change expected (transfer's cheating
                                              coverage is inherited, per docs/06's testing note);
                                              Task 2 — none new (u64-amount cheat lives in
                                              tests/viewing.rs, alongside transfer's other
                                              structural cheats)
    bundle.rs                  [new]   Task 3 — the bundle guest's own test file
    ledger.rs                  [new]   Task 4 — admission-order and viewing-over-bundles tests
                                              (or appended to tests/viewing.rs — see Task 4 note)
  docs/
    04-guests.md               [edit]  Task 1 (measured transfer numbers), Task 3 (bundle numbers)
    05-roadmap.md               [edit]  Task 4 — phase Z row
    06-viewing-keys.md          [edit]  Task 1, Task 3, Task 4 — bundle relation, anchor window,
                                              measured numbers
```

---

## Task 1 — Looped `MERKLE_VERIFY`

### Why

`docs/06-viewing-keys.md`'s cost table pins `transfer` at 4 554 program words, "dominated by the
guest-level `NOTE_COMMIT`/`NULLIFY`/`MERKLE_VERIFY` routines' unrolled Merkle-level loop." Since
M3.4, a program's own digest (`hc`) costs `⌈len/4⌉` Poseidon2 permutations and — the M3.4 ruling —
those rows count as cycles too. An unrolled 32-level Merkle walk is duplicated in the *compiled
program*, not just executed 32 times, so it inflates `len` (and hence `hc`'s cost) far more than
it inflates execution cycles. A **counted loop** — the routine's body compiled once, executed 32
times by ordinary branch/jump control flow — shrinks `len` by roughly a factor of the loop-body
size (dozens of words instead of ~1 100), which is the single largest lever available for getting
`bundle` (Task 3, which needs *two* Merkle walks) into a low tier at all.

### Files

- `research/src/asm.rs` (edit: `emit_merkle_verify`, new `copy_word8_from_reg`)
- `research/src/guests.rs` (edit: `transfer()`, `merkle_probe()` call sites)
- `research/tests/viewing.rs` (edit: `transfer_guest_permutation_and_row_counts_are_measured`)
- `research/docs/04-guests.md`, `research/docs/06-viewing-keys.md` (edit: measured numbers)

### Interfaces

```rust
// asm.rs
/// Copies a Word8 from `src_reg + {0,4,..,28}` (register-indirect — `src_reg` is a RUNTIME
/// address, unlike `copy_word8`'s compile-time `src: i32` offset) to `base + dst`.
pub fn copy_word8_from_reg(a: &mut Assembler, base: u32, tmp: u32, src_reg: u32, dst: i32);

/// `MERKLE_VERIFY`, now a counted loop instead of `depth` unrolled copies of its body.
///
/// Calling convention (documented here because every field is now either a register the
/// *caller* must dedicate — not shared with anything live across the call — or a compile-time
/// RAM offset, same as before):
///   - `base`      (reg, in)  RAM base, unchanged from the unrolled version.
///   - `tmp`       (reg, scratch) general load/store scratch, unchanged.
///   - `bit`       (reg, scratch) holds the extracted index low bit each iteration.
///   - `index`     (reg, scratch, DESTROYED) — the caller's index value is copied in at the
///                 top of the routine (`mv(index, index_word)`) and shifted right by 1 every
///                 iteration; the caller's own `index_word` register is left untouched (the
///                 unrolled version never destroyed it either, since it only ever read one
///                 fixed bit of it per unrolled level — the loop version must destroy *a copy*
///                 instead, because it reads a different bit each iteration via repeated
///                 `srli ..., 1`, not a per-iteration-constant shift amount).
///   - `index_word`(reg, in, preserved) the caller's original index — read once, not modified.
///   - `path_ptr`  (reg, scratch) initialized to `base + path` and bumped by 32 bytes (one
///                 `Word8` sibling) every iteration — the register-indirect address
///                 `copy_word8_from_reg` reads the current level's sibling from.
///   - `ctr`       (reg, scratch) counts iterations down from `depth` to 0.
///   - `leaf`, `path`, `buf`, `ptr_words`, `root_out`, `depth`, `label_prefix`: same meaning
///     and same compile-time-constant-ness as the unrolled version.
///
/// `leaf`/`root_out` may be the same or different RAM offsets (`guests::transfer` uses
/// different ones, seeding `root_out` from `leaf` once up front, exactly as the unrolled
/// version did); `path`'s per-level sibling for level `l` is `path + 32*l`, now visited by
/// `path_ptr` incrementing rather than by a compile-time-computed offset per unrolled copy.
#[allow(clippy::too_many_arguments)]
pub fn emit_merkle_verify(
    a: &mut Assembler, base: u32, tmp: u32, bit: u32, index: u32, index_word: u32,
    path_ptr: u32, ctr: u32,
    leaf: i32, path: i32, buf: i32, ptr_words: i32, root_out: i32, depth: usize, label_prefix: &str,
);
```

### Steps

- [ ] **Step 1 — `copy_word8_from_reg`.** In `research/src/asm.rs`, immediately after
  `copy_word8`:

  ```rust
  /// `copy_word8`'s register-indirect twin: copies a `Word8` from `src_reg + {0,4,..,28}`
  /// (a RUNTIME address — `src_reg` holds it, unlike `copy_word8`'s compile-time `src: i32`)
  /// to `base + dst`. What the looped `MERKLE_VERIFY` needs to read the current level's
  /// sibling through a bumped pointer register instead of a per-level compile-time offset.
  pub fn copy_word8_from_reg(a: &mut Assembler, base: u32, tmp: u32, src_reg: u32, dst: i32) {
      for i in 0..8 {
          a.push(ops::lw(tmp, src_reg, 4 * i));
          a.push(ops::sw(base, tmp, dst + 4 * i));
      }
  }
  ```

- [ ] **Step 2 — replace `emit_merkle_verify` with the loop.** Replace the whole existing
  function body in `research/src/asm.rs`:

  ```rust
  /// `MERKLE_VERIFY`, depth `depth` (32 in this crate), as a counted loop — see the module-level
  /// doc comment above (`docs/superpowers/plans/2026-09-11-shielded-pool-z.md` Task 1) for the
  /// full calling convention. Unlike the M3.3 unrolled version, the compiled body is emitted
  /// once; `ctr` counts `depth` iterations, `path_ptr` walks the sibling array 32 bytes at a
  /// time, and `index` is a destructible copy of `index_word` shifted right by 1 each
  /// iteration — the same "maintain a pointer, bump it, count down" idiom `guests::memcpy`/
  /// `guests::bubble_sort` already use for their own loops, applied here to a `Word8`-at-a-time
  /// stride instead of a word-at-a-time one.
  ///
  /// Per iteration: extract the low bit of `index` (`andi(bit, index, 1)`), branch to pick
  /// `[running, sibling]` (bit 0) or `[sibling, running]` (bit 1) order — reading the sibling
  /// through `path_ptr` via `copy_word8_from_reg`, the running node through `root_out` via
  /// `copy_word8` (still a compile-time address: only ONE running-node buffer exists, reused
  /// in place every iteration, exactly as the unrolled version reused it) — hash the 17-word
  /// `[NODE_DOMAIN, left(8), right(8)]` staged at `buf`, copy the digest back into `root_out`,
  /// then advance `index >>= 1`, `path_ptr += 32`, `ctr -= 1`, loop.
  #[allow(clippy::too_many_arguments)]
  pub fn emit_merkle_verify(
      a: &mut Assembler,
      base: u32,
      tmp: u32,
      bit: u32,
      index: u32,
      index_word: u32,
      path_ptr: u32,
      ctr: u32,
      leaf: i32,
      path: i32,
      buf: i32,
      ptr_words: i32,
      root_out: i32,
      depth: usize,
      label_prefix: &str,
  ) {
      use crate::isa::{BranchCond, REG_ZERO};
      copy_word8(a, base, tmp, leaf, root_out);
      a.push(ops::mv(index, index_word));
      a.push(ops::addi(path_ptr, base, path));
      a.extend(ops::li(ctr, depth as i32));
      let loop_lbl = format!("{label_prefix}_loop");
      let bit0 = format!("{label_prefix}_bit0");
      let done_lbl = format!("{label_prefix}_done");
      let exit_lbl = format!("{label_prefix}_exit");
      a.label(&loop_lbl);
      a.branch(BranchCond::Eq, ctr, REG_ZERO, &exit_lbl);
      a.push(ops::andi(bit, index, 1));
      a.branch(BranchCond::Eq, bit, REG_ZERO, &bit0);
      // bit == 1: the running node is on the right — [sibling, running].
      copy_word8_from_reg(a, base, tmp, path_ptr, buf + 4);
      copy_word8(a, base, tmp, root_out, buf + 36);
      a.jal(REG_ZERO, &done_lbl);
      a.label(&bit0);
      // bit == 0: the running node is on the left — [running, sibling].
      copy_word8(a, base, tmp, root_out, buf + 4);
      copy_word8_from_reg(a, base, tmp, path_ptr, buf + 36);
      a.label(&done_lbl);
      a.extend(ops::li(tmp, crate::notes::domain::NODE as i32));
      a.push(ops::sw(base, tmp, buf));
      a.extend(ops::call_poseidon2(ptr_words, 17));
      copy_word8(a, base, tmp, buf, root_out);
      a.push(ops::srli(index, index, 1));
      a.push(ops::addi(path_ptr, path_ptr, 32));
      a.push(ops::addi(ctr, ctr, -1));
      a.jal(REG_ZERO, &loop_lbl);
      a.label(&exit_lbl);
  }
  ```

  Note the label scheme changed shape (one `_loop`/`_bit0`/`_done`/`_exit` set total, not one
  `_l{level}_*` set per level) — `label_prefix` must still be unique per call site (transfer's
  two future `MERKLE_VERIFY` calls in Task 3 use `"bundle_merkle1"`/`"bundle_merkle2"`).

- [ ] **Step 3 — update call sites.** In `research/src/guests.rs`:

  In `transfer()`, add two new local consts and update the call:

  ```rust
  const PATH_PTR: u32 = 27;
  const INDEX_WORK: u32 = 24;
  const CTR: u32 = 23;
  // ...
  a.push(lw(T1, BASE, inp(input::INDEX)));
  emit_merkle_verify(&mut a, BASE, T0, BIT, INDEX_WORK, T1, PATH_PTR, CTR, CM_IN, inp(input::PATH), BUF, ptr_words(BUF), ANCHOR, DEPTH, "transfer_merkle");
  ```

  In `merkle_probe()`, the same three new consts and:

  ```rust
  emit_merkle_verify(&mut a, BASE, T0, BIT, INDEX_WORK, T1, PATH_PTR, CTR, LEAF, PATH, BUF, (HEAP + BUF) / 4, ROOT, DEPTH, "merkle_probe");
  ```

  `PATH_PTR=27`, `INDEX_WORK=24`, `CTR=23` are unused elsewhere in both functions (verified by
  reading the full body of each — `transfer()`/`merkle_probe()` only otherwise use `T0,T1,T2`,
  `BASE=25`, `BIT=26`).

- [ ] **Step 4 — host-side loop-vs-tree agreement test.** In `research/tests/viewing.rs`, extend
  `merkle_verify_matches_a_host_side_tree` (already exercises the routine end to end through
  `guests::merkle_probe`, now exercising the loop instead of the unrolled version with no source
  change needed in the test itself) with a second case using **random** leaves/paths/indices
  rather than only a small sequential tree, since the loop's index-shifting logic is new code
  worth checking against more than 5 sequential indices:

  ```rust
  #[test]
  fn merkle_verify_loop_matches_a_host_side_tree_for_random_leaves() {
      use rand::Rng;
      let mut rng = rand::rng();
      let mut tree = CommitmentTree::new();
      let leaves: Vec<Word8> = (0..37u32).map(|_| notes::hash(domain::TEST, &[rng.next_u32()])).collect();
      for cm in &leaves { tree.append(*cm); }
      for i in [0usize, 1, 17, 36] { // first, second, an interior, and the last-appended leaf
          let path = tree.path(i);
          let e = execute(&guests::merkle_probe(leaves[i], &path, i as u32), &[], 1 << 20).unwrap();
          assert_eq!(e.outputs[..8], tree.root(), "leaf {i}");
      }
  }
  ```

  ```
  cargo +1.98.1 test -p rand_zkvm --test viewing merkle_verify -- --nocapture
  ```
  Expected: both tests pass (the existing sequential-tree test now exercises the loop; the new
  random-leaf test covers more index bit patterns).

- [ ] **Step 5 — re-measure `transfer`, update the pinned test.** Run:

  ```
  cargo +1.98.1 test -p rand_zkvm --test viewing transfer_guest_permutation_and_row_counts_are_measured -- --nocapture
  ```
  This **will fail** (the pinned constants — `3764` cycles, `4554`/`digest_rows() == 1139`,
  `total_cycles == 4903`, `Tier(14)`) since the program is now much smaller. Read the failure's
  actual values and update every pinned assertion in
  `transfer_guest_permutation_and_row_counts_are_measured` to match — cycles from execution
  itself should be unchanged or very close (32 iterations of loop body do the same
  `POSEIDON2`/branch work the 32 unrolled copies did, plus a handful of loop-bookkeeping
  instructions per iteration: `andi`, one taken branch, `srli`, `addi ×2`, `jal` — call this
  roughly 6–7 more cycles per level, ~200–225 more cycles total than the unrolled version's
  3 764, so expect execution cycles in the high 3 900s to low 4 000s), while `program.digest_rows()`
  should drop sharply (the loop body compiles to on the order of 30–40 words total instead of the
  ~1 100 the unrolled 32-copy version needed — *(measured by the implementer; do not guess a
  number into the doc, only the test assertion first, then copy the test's own printed/asserted
  value into the doc in Step 7)*). Update the doc comment above the test to describe the loop
  instead of "M3.4 adds `Program::digest_rows()`... 4 554 words" with whatever this step
  measures — including whether `total_cycles` now fits tier 12 (4 095) instead of needing
  tier 14 (recompute `Tier::for_cycles(total_cycles)` and update the `assert_eq!` against it).

  Also add one more line to the test, since it is now the reference the doc's "words" figure
  comes from:
  ```rust
  eprintln!("transfer: {} program words, {} exec cycles, {} digest rows, {} total cycles, tier {:?}",
      program.len(), e.cycles(), program.digest_rows(), total_cycles, Tier::for_cycles(total_cycles));
  ```

  ```
  cargo +1.98.1 test -p rand_zkvm --test viewing transfer_guest_permutation_and_row_counts_are_measured -- --nocapture
  ```
  Expected: passes with the newly-measured constants; the `eprintln!` line is what Step 7 copies
  into the docs.

- [ ] **Step 6 — full suite.**
  ```
  cargo +1.98.1 test -p rand_zkvm
  ```
  Expected: every existing test still passes (`transfer`'s cheating coverage — a wrong path, a
  stale anchor, a viewing key that cannot spend — is inherited automatically per
  `docs/06-viewing-keys.md`'s "Testing note": `MERKLE_VERIFY` still compiles to the same
  `POSEIDON2`/absorb rows regardless of loop-vs-unrolled, so no cheating test needs a rewrite;
  only the one measured-numbers test in Step 5 needed new constants).

- [ ] **Step 7 — docs.** In `research/docs/04-guests.md`, no change needed (this file's
  `transfer` numbers live in `06-viewing-keys.md`'s cost table, not here — Task 1 touches
  `04-guests.md` not at all; corrected in the file-structure table above by removing this file
  from Task 1's edit list if it turns out unneeded — check before editing). In
  `research/docs/06-viewing-keys.md`:
  - Replace the "**Measured cost**" paragraph under "Notes and what the guest proves" with the
    new instruction/cycle/permutation counts from Step 5's `eprintln!` output.
  - Replace the "## Cost" table's `transfer program`/`cycles`/`digest rows`/`total cycles`/
    `gas tier`/`total permutations` rows with the measured values; update the paragraph
    explaining *why* the old unrolled version cost what it did to instead explain that the
    routine is now a counted loop, with `Program::digest_rows()` collapsing accordingly — keep
    the historical unrolled numbers (4 554 words / 4 903 cycles / tier 14) in the text as "M3.3's
    unrolled figure, superseded here" so a reader diffing tiers understands why the number
    changed, rather than deleting the history.
  - Add one sentence to "The commitment tree" section's "Testing note" paragraph noting the
    routine's calling convention changed shape (loop, not unrolled) but its AIR-visible behavior
    (same `POSEIDON2` absorb/write-back rows) did not, which is why no cheating test needed
    updating.

- [ ] **Step 8 — commit.**
  ```
  cd research
  git add src/asm.rs src/guests.rs tests/viewing.rs docs/06-viewing-keys.md
  git commit -m "$(cat <<'EOF'
  research: asm — loop MERKLE_VERIFY instead of unrolling it 32 times

  Shrinks transfer's program (and hence its hc digest-row cost) by
  compiling the Merkle walk's body once and executing it 32 times with an
  ordinary counted loop, instead of duplicating it at assembly time.
  Re-measured transfer's cycle/word/tier numbers in docs/06-viewing-keys.md.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01W96zKrYpWUbXpVL5ntG9m6
  EOF
  )"
  ```

---

## Task 2 — `u64` amounts

### Files

- `research/src/notes.rs` (edit: `Note.amount`, `Note::WORDS`, `words`/`from_words`, `Note::new`,
  `input` module offsets, `transfer_inputs`)
- `research/src/guests.rs` (edit: `transfer()`'s `NOTE_IN` staging offsets)
- `research/tests/viewing.rs` (edit: new cheating test)

### Interfaces

```rust
// notes.rs
pub struct Note {
    pub pk: Word8, pub from: Word8,
    pub amount: u64,           // was u32
    pub asset: u32, pub time: u32, pub r: Word8,
}
impl Note {
    pub const WORDS: usize = 8 + 8 + 2 + 1 + 1 + 8; // 28, was 27
    pub fn new(owner: Word8, from: Word8, amount: u64, asset: u32, time: u32) -> Note;
    // words()/from_words(): amount split lo,hi (amount as u32, (amount >> 32) as u32),
    // preimage order pk(8) from(8) amount_lo amount_hi asset time r(8).
}
pub mod input {
    // IN_AMOUNT -> IN_AMOUNT_LO/IN_AMOUNT_HI (one extra word); every offset after it shifts by 1.
    pub const IN_AMOUNT_LO: usize = 10;
    pub const IN_AMOUNT_HI: usize = 11;
    // IN_ASSET=12, IN_TIME=13, IN_R=14, OUT_PK=22, OUT_TIME=30, OUT_R=31, PATH=39,
    // INDEX=39+DEPTH*8=295, COUNT=296.
}
pub fn transfer_inputs(sk: &SpendKey, spent: &Note, created: &Note, path: &[Word8; DEPTH], index: u32) -> [u32; input::COUNT]; // unchanged signature, new body
```

### Steps

- [ ] **Step 1 — `Note` struct and codec.** In `research/src/notes.rs`:

  ```rust
  #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
  pub struct Note {
      pub pk: Word8,
      pub from: Word8,
      /// SHRUGG units. Two machine words on the wire (lo, hi) — see `words()`. `u64`, not
      /// `u32`: SHRUGG units are `1e9` per coin, so `u32` cannot hold a single coin
      /// (`docs/superpowers/specs/2026-09-11-shielded-pool-design.md` §13's ruling).
      pub amount: u64,
      pub asset: u32,
      pub time: u32,
      pub r: Word8,
  }

  impl Note {
      /// `pk(8) from(8) amount_lo amount_hi asset(1) time(1) r(8)`.
      pub const WORDS: usize = 8 + 8 + 2 + 1 + 1 + 8;
      pub const BYTES: usize = 4 * Self::WORDS;

      pub fn words(&self) -> [u32; Self::WORDS] {
          let mut w = [0u32; Self::WORDS];
          w[0..8].copy_from_slice(&self.pk);
          w[8..16].copy_from_slice(&self.from);
          w[16] = self.amount as u32;
          w[17] = (self.amount >> 32) as u32;
          w[18] = self.asset;
          w[19] = self.time;
          w[20..28].copy_from_slice(&self.r);
          w
      }
      pub fn from_words(w: [u32; Self::WORDS]) -> Note {
          Note {
              pk: w[0..8].try_into().unwrap(),
              from: w[8..16].try_into().unwrap(),
              amount: (w[16] as u64) | ((w[17] as u64) << 32),
              asset: w[18],
              time: w[19],
              r: w[20..28].try_into().unwrap(),
          }
      }
      // commitment()/to_bytes()/from_bytes() unchanged (generic over Self::WORDS/BYTES already).
      pub fn new(owner: Word8, from: Word8, amount: u64, asset: u32, time: u32) -> Note {
          let mut rng = rand::rng();
          let r = std::array::from_fn(|_| rng.next_u32());
          Note { pk: owner, from, amount, asset, time, r }
      }
  }
  ```

- [ ] **Step 2 — `input` module offsets.** Replace `IN_AMOUNT` with two constants and shift
  everything after it by one word (`OUT_R` and `PATH`/`INDEX`/`COUNT` all shift by 1 relative to
  the old values, `Note::WORDS`'s own growth does not otherwise touch this module since the
  Merkle path/index are unrelated to note width):

  ```rust
  pub mod input {
      use super::DEPTH;
      pub const SK: usize = 0;              // 2 words
      pub const IN_FROM: usize = 2;         // 8 words
      pub const IN_AMOUNT_LO: usize = 10;
      pub const IN_AMOUNT_HI: usize = 11;
      pub const IN_ASSET: usize = 12;
      pub const IN_TIME: usize = 13;
      pub const IN_R: usize = 14;           // 8 words
      pub const OUT_PK: usize = 22;         // 8 words
      pub const OUT_TIME: usize = 30;
      pub const OUT_R: usize = 31;          // 8 words
      pub const PATH: usize = 39;           // DEPTH * 8 words
      pub const INDEX: usize = PATH + DEPTH * 8; // 295
      pub const COUNT: usize = INDEX + 1;         // 296
  }
  ```

  Update `transfer_inputs` to write both amount words:

  ```rust
  pub fn transfer_inputs(sk: &SpendKey, spent: &Note, created: &Note, path: &[Word8; DEPTH], index: u32) -> [u32; input::COUNT] {
      let mut v = [0u32; input::COUNT];
      v[input::SK] = sk.0[0];
      v[input::SK + 1] = sk.0[1];
      v[input::IN_FROM..input::IN_FROM + 8].copy_from_slice(&spent.from);
      v[input::IN_AMOUNT_LO] = spent.amount as u32;
      v[input::IN_AMOUNT_HI] = (spent.amount >> 32) as u32;
      v[input::IN_ASSET] = spent.asset;
      v[input::IN_TIME] = spent.time;
      v[input::IN_R..input::IN_R + 8].copy_from_slice(&spent.r);
      v[input::OUT_PK..input::OUT_PK + 8].copy_from_slice(&created.pk);
      v[input::OUT_TIME] = created.time;
      v[input::OUT_R..input::OUT_R + 8].copy_from_slice(&created.r);
      for (level, sib) in path.iter().enumerate() { v[input::PATH + 8 * level..input::PATH + 8 * level + 8].copy_from_slice(sib); }
      v[input::INDEX] = index;
      v
  }
  ```

  `expected_outputs` is unaffected (it never reads the amount directly — `spent.commitment()`/
  `created.commitment()` already fold the new width in via `Note::words()`).

- [ ] **Step 3 — `guests::transfer`'s `NOTE_IN` staging.** In `research/src/guests.rs`,
  `transfer()`'s two `NOTE_IN` staging blocks (cm_in and cm_out) each need one more word copied
  and every offset after `amount` bumped by 4 bytes. Replace:

  ```rust
  a.push(lw(T0, BASE, inp(input::IN_AMOUNT))); a.push(sw(BASE, T0, NOTE_IN + 64));
  a.push(lw(T0, BASE, inp(input::IN_ASSET))); a.push(sw(BASE, T0, NOTE_IN + 68));
  a.push(lw(T0, BASE, inp(input::IN_TIME))); a.push(sw(BASE, T0, NOTE_IN + 72));
  copy_word8(&mut a, BASE, T0, inp(input::IN_R), NOTE_IN + 76);
  ```
  (the cm_in block) with:
  ```rust
  a.push(lw(T0, BASE, inp(input::IN_AMOUNT_LO))); a.push(sw(BASE, T0, NOTE_IN + 64));
  a.push(lw(T0, BASE, inp(input::IN_AMOUNT_HI))); a.push(sw(BASE, T0, NOTE_IN + 68));
  a.push(lw(T0, BASE, inp(input::IN_ASSET))); a.push(sw(BASE, T0, NOTE_IN + 72));
  a.push(lw(T0, BASE, inp(input::IN_TIME))); a.push(sw(BASE, T0, NOTE_IN + 76));
  copy_word8(&mut a, BASE, T0, inp(input::IN_R), NOTE_IN + 80);
  ```
  and the analogous cm_out block:
  ```rust
  a.push(lw(T0, BASE, inp(input::IN_AMOUNT_LO))); a.push(sw(BASE, T0, NOTE_IN + 64));
  a.push(lw(T0, BASE, inp(input::IN_AMOUNT_HI))); a.push(sw(BASE, T0, NOTE_IN + 68));
  a.push(lw(T0, BASE, inp(input::IN_ASSET))); a.push(sw(BASE, T0, NOTE_IN + 72));
  a.push(lw(T0, BASE, inp(input::OUT_TIME))); a.push(sw(BASE, T0, NOTE_IN + 76));
  copy_word8(&mut a, BASE, T0, inp(input::OUT_R), NOTE_IN + 80);
  ```
  `emit_note_commit` itself needs no change — its scratch-buffer size is already
  `1 + Note::WORDS` (generic), and the existing comment `BUF: i32 = 0x000; // hash scratch: up
  to 28 words (112 bytes)` already anticipated this width; update that comment to "up to 29
  words (116 bytes)" (`1` domain tag `+ 28` note words).

- [ ] **Step 4 — cheating test: a truncated-amount note cannot be spent by lying about its high
  word.** In `research/tests/viewing.rs`, add (near `a_transfer_with_a_wrong_merkle_path_is_rejected`,
  same file, same structural-rejection idiom — not `rejects()`, since the guest's own execution
  is internally consistent, it just computes a `cm_in` that doesn't match the real leaf):

  ```rust
  /// A note whose real amount needs more than 32 bits (`> u32::MAX`) cannot be spent by a
  /// witness that only supplies the low word and zeroes the high one — `NOTE_COMMIT` hashes
  /// both `amount_lo` and `amount_hi`, so lying about the high word produces a different
  /// `cm_in` than the one actually in the tree, and `MERKLE_VERIFY` (honestly run against that
  /// wrong leaf) produces a root that is not `ledger.root()`. This is exactly the closed gap
  /// `u64` amounts fix: at the old `u32` width there was no high word to lie about in the first
  /// place, so a value like this could never even be represented.
  #[test]
  fn spending_a_note_by_truncating_its_amount_to_32_bits_is_rejected() {
      let m = Machine::new(FriProfile::Test);
      let (alice, bob, bridge) = (Party::new(), Party::new(), Party::new());
      let mut ledger = Ledger::new(1_700_000_000);
      let true_amount: u64 = (1u64 << 32) + 5; // does not fit in 32 bits
      let note = mint(&mut ledger, &bridge, &alice.vk, true_amount, 1);
      ledger.advance(1);
      let (path, index) = ledger.path_for(&note.commitment()).unwrap();
      // Build a "created" note and inputs as if the spent amount were only its low 32 bits.
      let lying_spent = Note { amount: 5, ..note };
      let created = Note::new(bob.vk.pk(), alice.vk.pk(), 5, note.asset, ledger.now);
      let inputs = notes::transfer_inputs(&alice.sk, &lying_spent, &created, &path, index);
      let e = execute(&ledger.program, &inputs, 1 << 22).unwrap();
      assert!(e.halted);
      let anchor = e.outputs; // whatever root the guest actually computed against the wrong leaf
      let _ = anchor; // silence unused if not needed further; see below
      let (proof, _) = m.prove(&ledger.program, &inputs, None).unwrap();
      assert!(m.verify(&ledger.program.digest(), &proof).is_ok(), "the STARK is happy: the guest faithfully ran with these (dishonest) inputs");
      // Recompute the digest the guest actually produced for the *honest* claimed plaintext
      // (nf/cm_out/time an attacker would present) and show it cannot equal a real one: the
      // computed root came from hashing amount=5, not the tree's real amount=true_amount leaf,
      // so it is not `ledger.root()` and — with overwhelming probability — not a recent root
      // either.
      let nf = alice.vk.nullifier(&lying_spent.commitment());
      assert!(matches!(
          ledger.apply(&m, &proof, /* claimed anchor */ ledger.root(), nf, created.commitment(), created.time, {
              let env = Envelope::seal(&alice.vk, &bob.vk.address(), &created, &TxKey::random());
              env
          }),
          Err(LedgerError::BadDigest)
      ), "the guest's real digest was computed against the wrong (truncated-amount) leaf, so it cannot match what apply recomputes for any plaintext claim");
  }
  ```

  ```
  cargo +1.98.1 test -p rand_zkvm --test viewing spending_a_note_by_truncating -- --nocapture
  ```
  Expected: pass. (If the actual computed root happens to equal one of `ledger`'s window roots
  by some other coincidence in a debug run, use `LedgerError::UnknownAnchor` via
  `ledger.apply(&m, &proof, anchor /* = e.outputs interpreted as the digest's anchor field is
  NOT directly recoverable from e.outputs since outputs is the digest, not the anchor — see note
  below */ ...)` instead — but `BadDigest` is the expected path in this test as written, since we
  pass `ledger.root()` as the *claimed* anchor, which almost certainly disagrees with the
  digest the guest actually produced from the wrong leaf.)

- [ ] **Step 5 — full suite, then commit.**
  ```
  cargo +1.98.1 test -p rand_zkvm
  ```
  Expected: all pass (the M1–M4.1-plus-Task-1 count, plus this task's one new test).
  ```
  cd research
  git add src/notes.rs src/guests.rs tests/viewing.rs
  git commit -m "$(cat <<'EOF'
  research: notes — u64 note amounts (Note::WORDS 27->28)

  SHRUGG units are 1e9 per coin; u32 cannot hold one coin
  (shielded-pool spec §13). amount is now two words (lo, hi) in the
  commitment preimage; input::* offsets shift accordingly.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01W96zKrYpWUbXpVL5ntG9m6
  EOF
  )"
  ```

---

## Task 3 — The `bundle` guest

### The soundness mechanism (read before the steps)

This ISA has no `assert`/trap primitive: `BranchCond` only steers control flow (never fails a
proof), `AluOp::Divu` defines division by zero rather than erroring, and there is no
constrained "equal-or-fail" gate outside the CPU table's own bus/memory-consistency checks
(which enforce that *execution was faithful to the program*, not that the *program's own logic*
holds some application-level invariant). Every relation `bundle` must prove is therefore built
one of two ways:

1. **Structural.** The guest is written so that only an honest witness produces commitments
   that match anything real; a dishonest one produces internally-consistent garbage that fails
   *outside* the STARK (ownership: the guest always uses its own derived `pk_self` as a
   commitment's owner field, exactly as `transfer` already does — a wrong `sk` derives a
   different `pk_self`, hence a different `cm_in`, hence a `MERKLE_VERIFY` root that isn't
   `ledger.root()`. Asset-per-note: the guest reads the bundle's *single* public `asset` word
   once and reuses it for every note's commitment — an input note actually created under a
   different asset produces the wrong `cm_in` the same way a wrong owner does).
2. **Taint-and-corrupt (new to this plan).** For a relation that is genuinely an arithmetic
   check over private values (the 64-bit balance, both real inputs agreeing on one `anchor`,
   every amount being `< 2^63`), the guest accumulates a single **`bad`** register (0 = every
   check so far has passed, 1 = at least one has failed — a monotone OR across every check, no
   check can ever clear a `bad` a previous one set) and, immediately before staging the final
   46-word digest preimage, **XORs `bad` into one word of that preimage** (this plan uses
   `time`'s word — `time XOR bad`). Poseidon2 is a one-way permutation: an honest witness
   (`bad == 0`) hashes the real preimage and publishes the real digest; a dishonest witness that
   set `bad = 1` anywhere hashes a preimage that differs by exactly one bit in one word, and the
   published digest is — with cryptographic-hash-strength probability — not the digest of
   *any* real, benign transaction the ledger could reconstruct, because
   `Ledger::apply_bundle` (Task 4) independently recomputes the expected digest from the
   plaintext `(anchor, nf1, nf2, cm1, cm2, fee, burn, asset, time)` the sender must publish
   alongside the proof and compares it word-for-word to the proof's own `OUT0..7`. This is
   exactly `docs/06-viewing-keys.md`'s existing `output_digest`/`BadDigest` idiom, generalized
   from "the ledger's own arithmetic never runs the guest's checks, it just compares digests" to
   "the guest funnels every one of *its own* internal checks into the same digest comparison."

   Every individual check below (`eq8`, the range check, the carry check) is a **local, free**
   computation — nothing stops a witness from getting the arithmetic itself right (Plonky3 does
   not care whether `bad` is 0 or 1, both are valid traces); `bad` only has *teeth* because it
   is folded into the one thing an external verifier (the ledger) checks against independently
   reconstructed plaintext. A dishonest prover who wants their bundle admitted must therefore
   make `bad == 0` genuinely, i.e., must satisfy every relation for real.

The task's own callout — "a dummy input with a nonzero amount that skips membership... must be
caught by the guest's own branch structure" — is a **structural** case, and is in fact stronger
than "caught": it is **unconstructible**. The skip decision is `or(t, amount_lo, amount_hi);
branch Eq t, 0 -> skip_membership` — the *same two registers* that also feed the balance sum. A
witness cannot set `amount != 0` (to claim value) and also reach the skip branch (whose condition
is `amount_lo | amount_hi == 0`, evaluated by the same deterministic program on the same words):
either the OR is zero (skip runs, and the balance sum sees `amount = 0`, contributing nothing —
an honest dummy) or it is nonzero (membership runs). There is no third case; this is not a check
that can fail, it is a branch condition that cannot be fooled because it reads the value it
guards.

### Files

- `research/src/notes.rs` (edit: `domain::BUNDLE`, `bundle_input` module, `bundle_inputs`,
  `expected_bundle_outputs`, `bundle_digest`)
- `research/src/asm.rs` (edit: `emit_eq8`, `emit_range_check_u63`, `emit_add64_carry`,
  `emit_or_into`)
- `research/src/guests.rs` (edit: `pub fn bundle()`)
- `research/tests/bundle.rs` (new)
- `research/docs/04-guests.md`, `research/docs/06-viewing-keys.md` (edit: measured numbers)

### Interfaces

```rust
// notes.rs
pub mod domain {
    // ... existing NK..IN (10) unchanged ...
    /// The `bundle` guest's output digest, `H(BUNDLE, anchor(8) nf1(8) nf2(8) cm1(8) cm2(8)
    /// fee(2) burn(2) asset(1) time(1))` — 46 words. `IN = 10` (M4.1) is the last domain
    /// already in use; `BUNDLE` is the next free tag.
    pub const BUNDLE: u32 = 11;
}

pub mod bundle_input {
    // flat READ_INPUT layout: SK(2), IN1_*(277), IN2_*(277), ANCHOR(8), OUT1_*(18), OUT2_*(18),
    // FEE(2) BURN(2) ASSET(1) TIME(1). COUNT = 606. Full constant list in Step 2.
}

/// `inputs[i] = (note, path, index)`; a dummy input has `note.amount == 0` (path/index unused).
/// `anchor` is the tree root every real input is checked against and the value published.
pub fn bundle_inputs(
    sk: &SpendKey,
    inputs: &[(Note, [Word8; DEPTH], u32); 2],
    outputs: &[Note; 2],
    anchor: Word8, fee: u64, burn: u64, asset: u32, time: u32,
) -> Vec<u32>; // length bundle_input::COUNT

/// The reference the emulator/proof are checked against for an HONEST witness (mirrors
/// `expected_outputs`). Computes nf1/nf2/cm1/cm2 from `sk`/`inputs`/`outputs` the same way the
/// guest does (owner forced to `pk_self`) and folds them with `anchor`/`fee`/`burn`/`asset`/
/// `time` into `bundle_digest`.
pub fn expected_bundle_outputs(
    sk: &SpendKey, inputs: &[(Note, [Word8; DEPTH], u32); 2], outputs: &[Note; 2],
    anchor: Word8, fee: u64, burn: u64, asset: u32, time: u32,
) -> [u32; crate::isa::NUM_OUTPUTS];

pub fn bundle_digest(anchor: &Word8, nf1: &Word8, nf2: &Word8, cm1: &Word8, cm2: &Word8, fee: u64, burn: u64, asset: u32, time: u32) -> Word8;
```

```rust
// asm.rs
/// `dst_bool := (a == b) as u32` for two `Word8`s at `base+a_at`/`base+b_at`: XOR all 8 word
/// pairs together (OR-folding the results), then `sltu(dst_bool, folded, 1)` — `folded == 0`
/// iff every word pair matched. `dst_bool` and `fold` (scratch) must differ from `tmp`.
pub fn emit_eq8(a: &mut Assembler, base: u32, tmp: u32, fold: u32, a_at: i32, b_at: i32, dst_bool: u32);

/// `bad := bad | cond` (`cond` a 0/1 register) — `or(bad, bad, cond)`, monotone: no later call
/// can clear a `bad` an earlier one set.
pub fn emit_or_into(a: &mut Assembler, bad: u32, cond: u32);

/// Sets `viol := 1` if the 64-bit value `(lo, hi)` is `>= 2^63` (i.e. `hi`'s top bit is set —
/// `sltu(viol_inv, hi, 0x8000_0000)` is 1 iff `< 2^63`; `viol := 1 - viol_inv`, via `xori(viol,
/// viol_inv, 1)`), else `0`. Used for the "every amount `< 2^63`" checks.
pub fn emit_range_check_u63(a: &mut Assembler, hi: u32, tmp: u32, viol: u32);

/// 64-bit `(sum_lo, sum_hi) += (lo, hi)`, carry-aware: `sltu` detects the low-word carry, an
/// intermediate `add` may itself carry into `sum_hi`, `carry_out` (0/1) is set if the *high*
/// addition overflowed 32 bits (the only case a 4-term chained sum can actually overflow 64
/// bits, given every individual term is already range-checked `< 2^63`). Reuses the
/// `sltu`-detects-carry idiom `guests::balance_check` already established for a 32-bit sum.
pub fn emit_add64_carry(a: &mut Assembler, sum_lo: u32, sum_hi: u32, lo: u32, hi: u32, tmp: u32, carry_out: u32);
```

```rust
// guests.rs
/// The shielded pool's transfer relation (design spec §4): 2-in-2-out, u64 amounts, fee/burn
/// conservation, dummy notes skip membership. Publishes `notes::bundle_digest(..)` at
/// `output::DIGEST` (0..8), same slot `transfer` uses (`transfer` and `bundle` are two
/// different `hc`-pinned programs, never both live in one ledger — S1 decides which).
pub fn bundle() -> Program;
```

### Steps

- [ ] **Step 1 — domain tag.** In `research/src/notes.rs`'s `domain` module, immediately after
  `pub const IN: u32 = 10;`:

  ```rust
  /// The `bundle` guest's output digest (`docs/superpowers/plans/2026-09-11-shielded-pool-z.md`
  /// Task 3): `H(BUNDLE, anchor(8) nf1(8) nf2(8) cm1(8) cm2(8) fee(2) burn(2) asset(1) time(1))`
  /// — 46 words.
  pub const BUNDLE: u32 = 11;
  ```

- [ ] **Step 2 — `bundle_input` layout.** In `research/src/notes.rs`, a new module alongside
  `input`:

  ```rust
  /// The private-input vector of `guests::bundle`: spend key, two input notes (each `from`,
  /// `amount_lo`, `amount_hi`, `asset`, `time`, `r`, a depth-32 Merkle witness), the tree root
  /// every real input is checked against, two output notes (`pk`, `amount_lo`, `amount_hi`,
  /// `r` — `from`/`time`/`asset` are not separately supplied, since the guest always sets an
  /// output's `from` to the derived `pk_self` and its `time`/`asset` to the bundle's own public
  /// `time`/`asset`, §4 items 4/6/7), and the four bundle-level values (`fee`, `burn` as u64
  /// pairs, `asset`, `time`) that get folded into the digest. Flat, like `input` — no stride
  /// abstraction, so a value's offset is a single named constant exactly as `input`'s are.
  pub mod bundle_input {
      use super::DEPTH;
      pub const SK: usize = 0;                              // 2
      pub const IN1_FROM: usize = 2;                         // 8
      pub const IN1_AMOUNT_LO: usize = 10;
      pub const IN1_AMOUNT_HI: usize = 11;
      pub const IN1_ASSET: usize = 12;
      pub const IN1_TIME: usize = 13;
      pub const IN1_R: usize = 14;                           // 8
      pub const IN1_PATH: usize = 22;                        // DEPTH * 8 = 256
      pub const IN1_INDEX: usize = IN1_PATH + DEPTH * 8;      // 278
      pub const IN2_FROM: usize = IN1_INDEX + 1;              // 279
      pub const IN2_AMOUNT_LO: usize = IN2_FROM + 8;          // 287
      pub const IN2_AMOUNT_HI: usize = IN2_AMOUNT_LO + 1;
      pub const IN2_ASSET: usize = IN2_AMOUNT_HI + 1;
      pub const IN2_TIME: usize = IN2_ASSET + 1;
      pub const IN2_R: usize = IN2_TIME + 1;                  // 8
      pub const IN2_PATH: usize = IN2_R + 8;                  // DEPTH * 8
      pub const IN2_INDEX: usize = IN2_PATH + DEPTH * 8;      // 556
      /// The tree root every real input's `MERKLE_VERIFY` is checked against (§4 item 2), and
      /// the value the guest publishes as `anchor` (an honest wallet passes `ledger.root()`).
      pub const ANCHOR: usize = IN2_INDEX + 1;                // 8
      pub const OUT1_PK: usize = ANCHOR + 8;                  // 8
      pub const OUT1_AMOUNT_LO: usize = OUT1_PK + 8;
      pub const OUT1_AMOUNT_HI: usize = OUT1_AMOUNT_LO + 1;
      pub const OUT1_R: usize = OUT1_AMOUNT_HI + 1;           // 8
      pub const OUT2_PK: usize = OUT1_R + 8;                  // 8
      pub const OUT2_AMOUNT_LO: usize = OUT2_PK + 8;
      pub const OUT2_AMOUNT_HI: usize = OUT2_AMOUNT_LO + 1;
      pub const OUT2_R: usize = OUT2_AMOUNT_HI + 1;           // 8
      pub const FEE_LO: usize = OUT2_R + 8;
      pub const FEE_HI: usize = FEE_LO + 1;
      pub const BURN_LO: usize = FEE_HI + 1;
      pub const BURN_HI: usize = BURN_LO + 1;
      pub const ASSET: usize = BURN_HI + 1;
      pub const TIME: usize = ASSET + 1;
      pub const COUNT: usize = TIME + 1;                      // 606
  }
  ```

- [ ] **Step 3 — `bundle_digest`/`expected_bundle_outputs`/`bundle_inputs`.** In
  `research/src/notes.rs`:

  ```rust
  /// `bundle`'s single public output: `H(BUNDLE, anchor, nf1, nf2, cm1, cm2, fee_lo, fee_hi,
  /// burn_lo, burn_hi, asset, time)` — 46 words after the domain tag.
  #[allow(clippy::too_many_arguments)]
  pub fn bundle_digest(anchor: &Word8, nf1: &Word8, nf2: &Word8, cm1: &Word8, cm2: &Word8, fee: u64, burn: u64, asset: u32, time: u32) -> Word8 {
      let mut msg = [0u32; 46];
      msg[0..8].copy_from_slice(anchor);
      msg[8..16].copy_from_slice(nf1);
      msg[16..24].copy_from_slice(nf2);
      msg[24..32].copy_from_slice(cm1);
      msg[32..40].copy_from_slice(cm2);
      msg[40] = fee as u32; msg[41] = (fee >> 32) as u32;
      msg[42] = burn as u32; msg[43] = (burn >> 32) as u32;
      msg[44] = asset;
      msg[45] = time;
      hash(domain::BUNDLE, &msg)
  }

  /// The honest host-side reference `guests::bundle`'s output is checked against
  /// (`tests/bundle.rs`), and what a wallet recomputes before submitting a bundle. `inputs[i].0`
  /// with `.amount == 0` is a dummy (its path/index are never dereferenced against the real
  /// tree by this function — membership is a guest-side, not host-side, check — so any value is
  /// fine there for a dummy).
  #[allow(clippy::too_many_arguments)]
  pub fn expected_bundle_outputs(
      sk: &SpendKey,
      inputs: &[(Note, [Word8; DEPTH], u32); 2],
      outputs: &[Note; 2],
      anchor: Word8, fee: u64, burn: u64, asset: u32, time: u32,
  ) -> [u32; crate::isa::NUM_OUTPUTS] {
      let vk = sk.viewing_key();
      let pk_self = vk.pk();
      let cm_in = |note: &Note| Note { pk: pk_self, ..*note }.commitment();
      let cm1 = cm_in(&inputs[0].0);
      let cm2 = cm_in(&inputs[1].0);
      let nf1 = vk.nullifier(&cm1);
      let nf2 = vk.nullifier(&cm2);
      let cm_out1 = outputs[0].commitment();
      let cm_out2 = outputs[1].commitment();
      bundle_digest(&anchor, &nf1, &nf2, &cm_out1, &cm_out2, fee, burn, asset, time)
  }

  /// Builds `guests::bundle`'s private-input vector.
  #[allow(clippy::too_many_arguments)]
  pub fn bundle_inputs(
      sk: &SpendKey,
      inputs: &[(Note, [Word8; DEPTH], u32); 2],
      outputs: &[Note; 2],
      anchor: Word8, fee: u64, burn: u64, asset: u32, time: u32,
  ) -> Vec<u32> {
      use bundle_input::*;
      let mut v = vec![0u32; COUNT];
      v[SK] = sk.0[0]; v[SK + 1] = sk.0[1];
      let put_in = |v: &mut Vec<u32>, from_off: usize, amt_lo: usize, amt_hi: usize, asset_off: usize, time_off: usize, r_off: usize, path_off: usize, index_off: usize, note: &Note, path: &[Word8; DEPTH], index: u32| {
          v[from_off..from_off + 8].copy_from_slice(&note.from);
          v[amt_lo] = note.amount as u32;
          v[amt_hi] = (note.amount >> 32) as u32;
          v[asset_off] = note.asset;
          v[time_off] = note.time;
          v[r_off..r_off + 8].copy_from_slice(&note.r);
          for (level, sib) in path.iter().enumerate() { v[path_off + 8 * level..path_off + 8 * level + 8].copy_from_slice(sib); }
          v[index_off] = index;
      };
      put_in(&mut v, IN1_FROM, IN1_AMOUNT_LO, IN1_AMOUNT_HI, IN1_ASSET, IN1_TIME, IN1_R, IN1_PATH, IN1_INDEX, &inputs[0].0, &inputs[0].1, inputs[0].2);
      put_in(&mut v, IN2_FROM, IN2_AMOUNT_LO, IN2_AMOUNT_HI, IN2_ASSET, IN2_TIME, IN2_R, IN2_PATH, IN2_INDEX, &inputs[1].0, &inputs[1].1, inputs[1].2);
      v[ANCHOR..ANCHOR + 8].copy_from_slice(&anchor);
      v[OUT1_PK..OUT1_PK + 8].copy_from_slice(&outputs[0].pk);
      v[OUT1_AMOUNT_LO] = outputs[0].amount as u32; v[OUT1_AMOUNT_HI] = (outputs[0].amount >> 32) as u32;
      v[OUT1_R..OUT1_R + 8].copy_from_slice(&outputs[0].r);
      v[OUT2_PK..OUT2_PK + 8].copy_from_slice(&outputs[1].pk);
      v[OUT2_AMOUNT_LO] = outputs[1].amount as u32; v[OUT2_AMOUNT_HI] = (outputs[1].amount >> 32) as u32;
      v[OUT2_R..OUT2_R + 8].copy_from_slice(&outputs[1].r);
      v[FEE_LO] = fee as u32; v[FEE_HI] = (fee >> 32) as u32;
      v[BURN_LO] = burn as u32; v[BURN_HI] = (burn >> 32) as u32;
      v[ASSET] = asset; v[TIME] = time;
      v
  }
  ```

  Note `expected_bundle_outputs` deliberately does **not** re-derive `outputs[i]`'s `from`/
  `time`/`asset` from `pk_self`/bundle fields the way the guest structurally does — it trusts
  the caller's `outputs: &[Note; 2]` already has `from = pk_self`, `time`/`asset` matching the
  bundle's, because this function is the *host* reference for an *honest* run (a wallet building
  its own bundle) and the guest's structural enforcement is exactly what makes a *dishonest*
  caller's mismatched `outputs` produce a different, non-matching digest — see "Ambiguities
  resolved."

- [ ] **Step 4 — arithmetic guest routines.** In `research/src/asm.rs`:

  ```rust
  /// `dst_bool := (a == b) as u32` for two `Word8`s already in RAM at `base+a_at`/`base+b_at`.
  pub fn emit_eq8(a: &mut Assembler, base: u32, tmp: u32, fold: u32, a_at: i32, b_at: i32, dst_bool: u32) {
      a.push(ops::li(fold, 0).remove(0)); // fold := 0  (li always returns >=1 instr; single-instr for small imm)
      for i in 0..8 {
          a.push(ops::lw(tmp, base, a_at + 4 * i));
          a.push(ops::lw(dst_bool, base, b_at + 4 * i)); // dst_bool used as scratch here, overwritten below
          a.push(ops::xor(tmp, tmp, dst_bool));
          a.push(ops::or(fold, fold, tmp));
      }
      a.push(ops::sltu(dst_bool, fold, 1)); // 1 iff fold == 0 iff every word matched
  }

  /// `bad := bad | cond`.
  pub fn emit_or_into(a: &mut Assembler, bad: u32, cond: u32) {
      a.push(ops::or(bad, bad, cond));
  }

  /// `viol := 1` iff the 64-bit value with high word `hi` is `>= 2^63`.
  pub fn emit_range_check_u63(a: &mut Assembler, hi: u32, tmp: u32, viol: u32) {
      let _ = tmp;
      a.extend(ops::li(viol, i32::MIN)); // 0x8000_0000 as i32 bit pattern
      a.push(ops::sltu(viol, hi, viol)); // 1 iff hi < 0x8000_0000, i.e. amount < 2^63
      a.push(ops::xori(viol, viol, 1));  // invert: 1 iff amount >= 2^63
  }

  /// `(sum_lo, sum_hi) += (lo, hi)`; `carry_out := 1` iff the high-word addition itself
  /// overflowed 32 bits (the only way a chain of range-checked-`<2^63` terms can overflow 64
  /// bits in total).
  pub fn emit_add64_carry(a: &mut Assembler, sum_lo: u32, sum_hi: u32, lo: u32, hi: u32, tmp: u32, carry_out: u32) {
      a.push(ops::add(tmp, sum_lo, lo));
      a.push(ops::sltu(carry_out, tmp, sum_lo)); // low-word carry-out
      a.push(ops::mv(sum_lo, tmp));
      a.push(ops::add(sum_hi, sum_hi, hi));
      a.push(ops::add(sum_hi, sum_hi, carry_out)); // fold the low carry into the high word
      // High-word carry-out: sum_hi (post-add) must be >= hi (the addend) unless it wrapped —
      // but sum_hi already absorbed the low carry too, so compare against (hi + low_carry).
      a.push(ops::add(tmp, hi, carry_out));
      a.push(ops::sltu(carry_out, sum_hi, tmp));
  }
  ```

  Test (`research/tests/bundle.rs`, Step 6 sets up the file; this is one of its first tests):
  ```rust
  #[test]
  fn add64_carry_matches_u128_addition() {
      // (a_lo,a_hi) + (b_lo,b_hi) via the guest routine, executed standalone through a tiny
      // probe program, compared against u64::wrapping_add plus an explicit overflow check done
      // in u128.
      // ... build with Assembler directly, write_output the (sum_lo, sum_hi, carry_out) triple,
      // execute(), compare against ((a as u128 + b as u128) as u64, ((a as u128 + b as u128) >> 64) as u32 != 0) ...
  }
  ```
  (Left as a table-driven test over a handful of `(a, b)` pairs including one that overflows —
  `(u64::MAX, u64::MAX)` — and one that doesn't; exact harness code is mechanical Assembler use
  matching `guests::alu_mix`'s style, elided here for length.)

  ```
  cargo +1.98.1 test -p rand_zkvm --test bundle add64_carry -- --nocapture
  ```
  Expected: pass for every case in the table, including the overflow one (`carry_out == 1`).

- [ ] **Step 5 — `guests::bundle`.** In `research/src/guests.rs`, after `transfer()`:

  ```rust
  /// The shielded pool's 2-in-2-out transfer relation
  /// (`docs/superpowers/specs/2026-09-11-shielded-pool-design.md` §4). See
  /// `docs/superpowers/plans/2026-09-11-shielded-pool-z.md` Task 3 for the full soundness
  /// argument (structural ownership/asset binding, the `bad`-flag taint-and-corrupt mechanism
  /// for the arithmetic checks, why "amount == 0" is the only way to skip membership).
  pub fn bundle() -> Program {
      use crate::asm::{copy_word8, emit_add64_carry, emit_eq8, emit_merkle_verify, emit_note_commit, emit_nullify, emit_or_into, emit_range_check_u63};
      use crate::notes::{bundle_input as bi, domain, output, DEPTH};
      const BASE: u32 = 25;   // RAM base (holds HEAP), same convention as transfer()
      const BIT: u32 = 26;    // MERKLE_VERIFY scratch
      const PATH_PTR: u32 = 27;
      const INDEX_WORK: u32 = 24;
      const CTR: u32 = 23;
      const BAD: u32 = 9;     // s1: the taint accumulator, 0 until proven otherwise, never cleared
      const EQFOLD: u32 = 22; // emit_eq8's fold scratch
      const T7: u32 = 21;     // extra general scratch (S0/S1/T0-T6/BASE/BIT/PATH_PTR/INDEX_WORK/CTR/EQFOLD all spoken for)

      const BUF: i32 = 0x000;      // hash scratch, up to 29 words (116 bytes)
      const NOTE_STAGE: i32 = 0x080; // Note::WORDS = 28 word staging area, reused per note
      const INP: i32 = 0x100;      // bundle_input::COUNT (606) private inputs
      const NK: i32 = 0xb00;
      const PK: i32 = 0xb20;
      const CM_IN1: i32 = 0xb40;
      const NF1: i32 = 0xb60;
      const CM_IN2: i32 = 0xb80;
      const NF2: i32 = 0xba0;
      const CM_OUT1: i32 = 0xbc0;
      const CM_OUT2: i32 = 0xbe0;
      const ANCHOR: i32 = 0xc00;
      const ROOT_TMP: i32 = 0xc20; // scratch root for whichever input's MERKLE_VERIFY runs
      const SUM_IN_LO: i32 = 0xc40; const SUM_IN_HI: i32 = 0xc44;   // staged in RAM so ALU regs stay free
      const SUM_OUT_LO: i32 = 0xc48; const SUM_OUT_HI: i32 = 0xc4c;

      let ptr_words = |buf: i32| (HEAP + buf) / 4;
      let inp = |i: usize| INP + 4 * i as i32;
      let mut a = Assembler::new(0);
      a.extend(li(BASE, HEAP));
      a.extend(li(BAD, 0));

      // Read every private input once into RAM (same convention as transfer()).
      for i in 0..bi::COUNT {
          a.extend(read_input(i as u32));
          a.push(sw(BASE, REG_A0, inp(i)));
      }

      // nk = H_NK(sk); pk_self = H_PK(nk) — identical to transfer().
      a.extend(li(T0, domain::NK as i32));
      a.push(sw(BASE, T0, BUF));
      a.push(lw(T0, BASE, inp(bi::SK))); a.push(sw(BASE, T0, BUF + 4));
      a.push(lw(T0, BASE, inp(bi::SK + 1))); a.push(sw(BASE, T0, BUF + 8));
      a.extend(call_poseidon2(ptr_words(BUF), 3));
      copy_word8(&mut a, BASE, T0, BUF, NK);
      a.extend(li(T0, domain::PK as i32));
      a.push(sw(BASE, T0, BUF));
      copy_word8(&mut a, BASE, T0, NK, BUF + 4);
      a.extend(call_poseidon2(ptr_words(BUF), 9));
      copy_word8(&mut a, BASE, T0, BUF, PK);

      // anchor := the private ANCHOR field (the wallet's claimed current tree root); every real
      // input's MERKLE_VERIFY is checked against it via emit_eq8 + emit_or_into(BAD, ..), never
      // overwritten by a derived root (unlike transfer(), where there is only one input and the
      // derived root simply *is* the published anchor) — see Task 3's soundness note for why an
      // equality-then-taint gadget, not a direct overwrite, is required once there are two
      // independent membership checks that must agree with each other and with this value.
      copy_word8(&mut a, BASE, T0, inp(bi::ANCHOR), ANCHOR);

      // ---- input 1 ----
      copy_word8(&mut a, BASE, T0, PK, NOTE_STAGE);
      copy_word8(&mut a, BASE, T0, inp(bi::IN1_FROM), NOTE_STAGE + 32);
      a.push(lw(T0, BASE, inp(bi::IN1_AMOUNT_LO))); a.push(sw(BASE, T0, NOTE_STAGE + 64));
      a.push(lw(T0, BASE, inp(bi::IN1_AMOUNT_HI))); a.push(sw(BASE, T0, NOTE_STAGE + 68));
      a.push(lw(T0, BASE, inp(bi::IN1_ASSET))); a.push(sw(BASE, T0, NOTE_STAGE + 72));
      a.push(lw(T0, BASE, inp(bi::IN1_TIME))); a.push(sw(BASE, T0, NOTE_STAGE + 76));
      copy_word8(&mut a, BASE, T0, inp(bi::IN1_R), NOTE_STAGE + 80);
      emit_note_commit(&mut a, BASE, T0, NOTE_STAGE, BUF, ptr_words(BUF), CM_IN1);
      // amount1 != 0? — the ONLY branch condition, shared with the balance sum's own addend.
      a.push(lw(T1, BASE, inp(bi::IN1_AMOUNT_LO)));
      a.push(lw(T2, BASE, inp(bi::IN1_AMOUNT_HI)));
      a.push(or(T1, T1, T2));
      a.branch(BranchCond::Eq, T1, REG_ZERO, "bundle_in1_skip");
      a.push(lw(T1, BASE, inp(bi::IN1_INDEX)));
      emit_merkle_verify(&mut a, BASE, T0, BIT, INDEX_WORK, T1, PATH_PTR, CTR, CM_IN1, inp(bi::IN1_PATH), BUF, ptr_words(BUF), ROOT_TMP, DEPTH, "bundle_merkle1");
      emit_eq8(&mut a, BASE, T0, EQFOLD, ANCHOR, ROOT_TMP, T7);
      a.push(xori(T7, T7, 1)); // T7 := 1 iff mismatch
      emit_or_into(&mut a, BAD, T7);
      a.label("bundle_in1_skip");
      emit_nullify(&mut a, BASE, T0, NK, CM_IN1, BUF, ptr_words(BUF), NF1);

      // ---- input 2 (identical shape) ----
      copy_word8(&mut a, BASE, T0, PK, NOTE_STAGE);
      copy_word8(&mut a, BASE, T0, inp(bi::IN2_FROM), NOTE_STAGE + 32);
      a.push(lw(T0, BASE, inp(bi::IN2_AMOUNT_LO))); a.push(sw(BASE, T0, NOTE_STAGE + 64));
      a.push(lw(T0, BASE, inp(bi::IN2_AMOUNT_HI))); a.push(sw(BASE, T0, NOTE_STAGE + 68));
      a.push(lw(T0, BASE, inp(bi::IN2_ASSET))); a.push(sw(BASE, T0, NOTE_STAGE + 72));
      a.push(lw(T0, BASE, inp(bi::IN2_TIME))); a.push(sw(BASE, T0, NOTE_STAGE + 76));
      copy_word8(&mut a, BASE, T0, inp(bi::IN2_R), NOTE_STAGE + 80);
      emit_note_commit(&mut a, BASE, T0, NOTE_STAGE, BUF, ptr_words(BUF), CM_IN2);
      a.push(lw(T1, BASE, inp(bi::IN2_AMOUNT_LO)));
      a.push(lw(T2, BASE, inp(bi::IN2_AMOUNT_HI)));
      a.push(or(T1, T1, T2));
      a.branch(BranchCond::Eq, T1, REG_ZERO, "bundle_in2_skip");
      a.push(lw(T1, BASE, inp(bi::IN2_INDEX)));
      emit_merkle_verify(&mut a, BASE, T0, BIT, INDEX_WORK, T1, PATH_PTR, CTR, CM_IN2, inp(bi::IN2_PATH), BUF, ptr_words(BUF), ROOT_TMP, DEPTH, "bundle_merkle2");
      emit_eq8(&mut a, BASE, T0, EQFOLD, ANCHOR, ROOT_TMP, T7);
      a.push(xori(T7, T7, 1));
      emit_or_into(&mut a, BAD, T7);
      a.label("bundle_in2_skip");
      emit_nullify(&mut a, BASE, T0, NK, CM_IN2, BUF, ptr_words(BUF), NF2);

      // ---- outputs: from = pk_self, asset/time = the bundle's own public fields (structural
      // enforcement of §4 items 4/6/7 — there is no other asset/time an output's commitment
      // could use) ----
      copy_word8(&mut a, BASE, T0, inp(bi::OUT1_PK), NOTE_STAGE);
      copy_word8(&mut a, BASE, T0, PK, NOTE_STAGE + 32);
      a.push(lw(T0, BASE, inp(bi::OUT1_AMOUNT_LO))); a.push(sw(BASE, T0, NOTE_STAGE + 64));
      a.push(lw(T0, BASE, inp(bi::OUT1_AMOUNT_HI))); a.push(sw(BASE, T0, NOTE_STAGE + 68));
      a.push(lw(T0, BASE, inp(bi::ASSET))); a.push(sw(BASE, T0, NOTE_STAGE + 72));
      a.push(lw(T0, BASE, inp(bi::TIME))); a.push(sw(BASE, T0, NOTE_STAGE + 76));
      copy_word8(&mut a, BASE, T0, inp(bi::OUT1_R), NOTE_STAGE + 80);
      emit_note_commit(&mut a, BASE, T0, NOTE_STAGE, BUF, ptr_words(BUF), CM_OUT1);

      copy_word8(&mut a, BASE, T0, inp(bi::OUT2_PK), NOTE_STAGE);
      copy_word8(&mut a, BASE, T0, PK, NOTE_STAGE + 32);
      a.push(lw(T0, BASE, inp(bi::OUT2_AMOUNT_LO))); a.push(sw(BASE, T0, NOTE_STAGE + 64));
      a.push(lw(T0, BASE, inp(bi::OUT2_AMOUNT_HI))); a.push(sw(BASE, T0, NOTE_STAGE + 68));
      a.push(lw(T0, BASE, inp(bi::ASSET))); a.push(sw(BASE, T0, NOTE_STAGE + 72));
      a.push(lw(T0, BASE, inp(bi::TIME))); a.push(sw(BASE, T0, NOTE_STAGE + 76));
      copy_word8(&mut a, BASE, T0, inp(bi::OUT2_R), NOTE_STAGE + 80);
      emit_note_commit(&mut a, BASE, T0, NOTE_STAGE, BUF, ptr_words(BUF), CM_OUT2);

      // ---- range checks: every amount (both inputs, both outputs, fee, burn) < 2^63 ----
      for (lo_off, hi_off) in [
          (bi::IN1_AMOUNT_LO, bi::IN1_AMOUNT_HI), (bi::IN2_AMOUNT_LO, bi::IN2_AMOUNT_HI),
          (bi::OUT1_AMOUNT_LO, bi::OUT1_AMOUNT_HI), (bi::OUT2_AMOUNT_LO, bi::OUT2_AMOUNT_HI),
          (bi::FEE_LO, bi::FEE_HI), (bi::BURN_LO, bi::BURN_HI),
      ] {
          let _ = lo_off;
          a.push(lw(T1, BASE, inp(hi_off)));
          emit_range_check_u63(&mut a, T1, T0, T2);
          emit_or_into(&mut a, BAD, T2);
      }

      // ---- 64-bit conservation: in1 + in2 == out1 + out2 + fee + burn, no wrap ----
      a.push(lw(T0, BASE, inp(bi::IN1_AMOUNT_LO))); a.push(sw(BASE, T0, SUM_IN_LO));
      a.push(lw(T0, BASE, inp(bi::IN1_AMOUNT_HI))); a.push(sw(BASE, T0, SUM_IN_HI));
      a.push(lw(T3, BASE, SUM_IN_LO)); a.push(lw(T4, BASE, SUM_IN_HI));
      a.push(lw(T1, BASE, inp(bi::IN2_AMOUNT_LO))); a.push(lw(T2, BASE, inp(bi::IN2_AMOUNT_HI)));
      emit_add64_carry(&mut a, T3, T4, T1, T2, T0, T5);
      emit_or_into(&mut a, BAD, T5); // in1+in2 cannot overflow given both are <2^63, but check anyway
      a.push(sw(BASE, T3, SUM_IN_LO)); a.push(sw(BASE, T4, SUM_IN_HI));

      a.push(lw(T3, BASE, inp(bi::OUT1_AMOUNT_LO))); a.push(lw(T4, BASE, inp(bi::OUT1_AMOUNT_HI)));
      a.push(lw(T1, BASE, inp(bi::OUT2_AMOUNT_LO))); a.push(lw(T2, BASE, inp(bi::OUT2_AMOUNT_HI)));
      emit_add64_carry(&mut a, T3, T4, T1, T2, T0, T5);
      emit_or_into(&mut a, BAD, T5);
      a.push(lw(T1, BASE, inp(bi::FEE_LO))); a.push(lw(T2, BASE, inp(bi::FEE_HI)));
      emit_add64_carry(&mut a, T3, T4, T1, T2, T0, T5);
      emit_or_into(&mut a, BAD, T5);
      a.push(lw(T1, BASE, inp(bi::BURN_LO))); a.push(lw(T2, BASE, inp(bi::BURN_HI)));
      emit_add64_carry(&mut a, T3, T4, T1, T2, T0, T5);
      emit_or_into(&mut a, BAD, T5);
      a.push(sw(BASE, T3, SUM_OUT_LO)); a.push(sw(BASE, T4, SUM_OUT_HI));

      // sums must match exactly.
      a.push(lw(T0, BASE, SUM_IN_LO)); a.push(lw(T1, BASE, SUM_OUT_LO));
      a.push(sub(T2, T0, T1)); // 0 iff equal
      a.push(lw(T0, BASE, SUM_IN_HI)); a.push(lw(T1, BASE, SUM_OUT_HI));
      a.push(sub(T3, T0, T1));
      a.push(or(T2, T2, T3));
      a.push(sltu(T2, REG_ZERO, T2)); // T2 := 1 iff (T2 before) != 0, i.e. sums disagree — sltu(0, x) = (0 < x)
      emit_or_into(&mut a, BAD, T2);

      // ---- digest: H(BUNDLE, anchor, nf1, nf2, cm1, cm2, fee, burn, asset, time XOR bad) ----
      a.extend(li(T0, domain::BUNDLE as i32));
      a.push(sw(BASE, T0, BUF));
      copy_word8(&mut a, BASE, T0, ANCHOR, BUF + 4);
      copy_word8(&mut a, BASE, T0, NF1, BUF + 36);
      copy_word8(&mut a, BASE, T0, NF2, BUF + 68);
      copy_word8(&mut a, BASE, T0, CM_OUT1, BUF + 100);
      copy_word8(&mut a, BASE, T0, CM_OUT2, BUF + 132);
      a.push(lw(T0, BASE, inp(bi::FEE_LO))); a.push(sw(BASE, T0, BUF + 164));
      a.push(lw(T0, BASE, inp(bi::FEE_HI))); a.push(sw(BASE, T0, BUF + 168));
      a.push(lw(T0, BASE, inp(bi::BURN_LO))); a.push(sw(BASE, T0, BUF + 172));
      a.push(lw(T0, BASE, inp(bi::BURN_HI))); a.push(sw(BASE, T0, BUF + 176));
      a.push(lw(T0, BASE, inp(bi::ASSET))); a.push(sw(BASE, T0, BUF + 180));
      a.push(lw(T0, BASE, inp(bi::TIME))); a.push(xor(T0, T0, BAD)); a.push(sw(BASE, T0, BUF + 184));
      a.extend(call_poseidon2(ptr_words(BUF), 47)); // domain + 46
      for i in 0..8 {
          a.push(lw(T1, BASE, BUF + 4 * i));
          a.extend(write_output((output::DIGEST + i as usize) as u32, T1));
      }
      a.extend(halt());
      a.assemble()
  }
  ```

  This is a large but entirely mechanical function; a fresh read of it against the interfaces
  above and the soundness note is the right way to check it, not a line count. Two things to
  verify by inspection before running anything: (a) every RAM constant (`BUF`..`SUM_OUT_HI`) is
  a distinct, non-overlapping range (`INP` spans `0x100..0x100+606*4=0xa78`, so `NK=0xb00`
  onward is safely clear), and (b) every register constant (`BASE,BIT,PATH_PTR,INDEX_WORK,CTR,
  BAD,EQFOLD,T7` plus the module's own `T0..T6,S0,S1`) is likewise distinct — 16 named registers
  out of 30 usable (`x3..x31` minus `sp=x2`), comfortably under budget.

- [ ] **Step 6 — `tests/bundle.rs`: honest 2-in-2-out and 1-in-1-out.** New file
  `research/tests/bundle.rs`:

  ```rust
  //! The bundle guest end to end: honest 2-in-2-out and 1-in-1-out-with-dummies proofs, and
  //! every cheating scenario the design spec calls out. Follows tests/viewing.rs's idiom: a
  //! logically-dishonest-but-internally-consistent witness is rejected structurally (the
  //! guest's own digest disagrees with `notes::expected_bundle_outputs` for the claimed
  //! plaintext, or — one level up, once Task 4 lands — `Ledger::apply_bundle` errors); a
  //! trace-level tamper is rejected via `rejects()`. See the plan's "Ambiguities resolved"
  //! for which is used where.
  use rand_zkvm::emulator::execute;
  use rand_zkvm::guests;
  use rand_zkvm::ledger::CommitmentTree;
  use rand_zkvm::machine::{FriProfile, Machine, Tier};
  use rand_zkvm::notes::{self, bundle_digest, expected_bundle_outputs, domain, Note, SpendKey, ViewingKey, Word8, DEPTH};

  struct Party { sk: SpendKey, vk: ViewingKey }
  impl Party { fn new() -> Party { let sk = SpendKey::random(); Party { sk, vk: sk.viewing_key() } } }

  /// A tree with two real notes owned by `owner`, ready to spend as a bundle's two inputs.
  fn two_real_inputs(owner: &Party, amounts: [u64; 2], asset: u32, time: u32) -> (CommitmentTree, [(Note, [Word8; DEPTH], u32); 2]) {
      let mut tree = CommitmentTree::new();
      let notes: Vec<Note> = amounts.iter().map(|&amt| Note::new(owner.vk.pk(), Party::new().vk.pk(), amt, asset, time)).collect();
      for n in &notes { tree.append(n.commitment()); }
      let ins = std::array::from_fn(|i| { let (p, idx) = tree.path_for(&notes[i].commitment()).unwrap(); (notes[i], p, idx) });
      (tree, ins)
  }

  fn dummy_input(asset: u32, time: u32) -> (Note, [Word8; DEPTH], u32) {
      (Note::new([0; 8], [0; 8], 0, asset, time), [[0; 8]; DEPTH], 0)
  }

  #[test]
  fn honest_two_in_two_out_proves_and_verifies() {
      let m = Machine::new(FriProfile::Test);
      let (alice, bob) = (Party::new(), Party::new());
      let (asset, time) = (0u32, 1_700_000_000u32);
      let (tree, inputs) = two_real_inputs(&alice, [1_000, 2_000], asset, time);
      let anchor = tree.root();
      let outputs = [Note::new(bob.vk.pk(), alice.vk.pk(), 2_500, time, 0 /* placeholder r ignored */), Note::new(alice.vk.pk(), alice.vk.pk(), 500, time, 0)];
      // NOTE: Note::new's signature is (owner, from, amount, asset, time) — fix the argument
      // order above when wiring this up: asset must be `asset`, not `time`. See Step 6's
      // "implementer check" note below the code block.
      let fee = 100u64; let burn = 0u64;
      let program = guests::bundle();
      let inputs_vec = notes::bundle_inputs(&alice.sk, &inputs, &outputs, anchor, fee, burn, asset, time);
      let e = execute(&program, &inputs_vec, 1 << 22).unwrap();
      assert!(e.halted);
      assert_eq!(e.outputs, expected_bundle_outputs(&alice.sk, &inputs, &outputs, anchor, fee, burn, asset, time));
      let (proof, exec) = m.prove(&program, &inputs_vec, None).unwrap();
      eprintln!("bundle 2-in-2-out: {} words, {} exec cycles, {} digest rows, tier {:?}", program.len(), exec.cycles(), program.digest_rows(), proof.tier);
      m.verify(&program.digest(), &proof).unwrap();
  }

  #[test]
  fn honest_one_in_one_out_with_dummies_proves() {
      let m = Machine::new(FriProfile::Test);
      let alice = Party::new();
      let (asset, time) = (0u32, 1_700_000_000u32);
      let (tree, real) = two_real_inputs(&alice, [1_000, 0 /* unused */], asset, time);
      let inputs = [real[0], dummy_input(asset, time)];
      let anchor = tree.root();
      let outputs = [Note::new(alice.vk.pk(), alice.vk.pk(), 900, asset, time), Note { pk: [0; 8], from: [0; 8], amount: 0, asset, time, r: [0; 8] }];
      let (fee, burn) = (100u64, 0u64);
      let program = guests::bundle();
      let inputs_vec = notes::bundle_inputs(&alice.sk, &inputs, &outputs, anchor, fee, burn, asset, time);
      let e = execute(&program, &inputs_vec, 1 << 22).unwrap();
      assert!(e.halted);
      let (proof, _) = m.prove(&program, &inputs_vec, None).unwrap();
      m.verify(&program.digest(), &proof).unwrap();
  }
  ```

  **Implementer check before running:** `Note::new`'s real signature is `(owner: Word8, from:
  Word8, amount: u64, asset: u32, time: u32)` — the `honest_two_in_two_out_proves_and_verifies`
  sketch above has a placeholder bug (`time` passed where `asset` belongs) left in deliberately
  as a flag: fix every `Note::new(..)` call in this file to the real argument order before
  running Step 7's commands, and double check every output note's `asset`/`time` match the
  bundle's own `asset`/`time` (§4 item 6/7 — the guest enforces this structurally, so a wrong
  `asset`/`time` in a *test's own honest fixture* is a test bug that will surface as `e.outputs
  != expected_bundle_outputs(..)`, not a subtle pass).

  ```
  cargo +1.98.1 test -p rand_zkvm --test bundle honest -- --nocapture
  ```
  Expected: both pass; `eprintln!` reports the measured words/cycles/tier — paste into
  `docs/06-viewing-keys.md`/`docs/04-guests.md` in Step 9.

- [ ] **Step 7 — cheating: over-spend, wrong path, dummy-with-nonzero-amount, asset mismatch,
  64-bit wrap (structural — not `rejects()`).** Append to `research/tests/bundle.rs`:

  ```rust
  /// Outputs (+ fee + burn) exceed inputs: the `bad` flag's balance check catches it, corrupting
  /// the digest. The STARK verifies (the guest ran faithfully on a dishonest input vector); the
  /// digest the honest fixture *would* expect for the claimed (anchor, fee, burn, asset, time)
  /// does not match what the guest actually published.
  #[test]
  fn over_spend_is_rejected() {
      let m = Machine::new(FriProfile::Test);
      let alice = Party::new();
      let (asset, time) = (0u32, 1_700_000_000u32);
      let (tree, real) = two_real_inputs(&alice, [1_000, 0], asset, time);
      let inputs = [real[0], dummy_input(asset, time)];
      let anchor = tree.root();
      // Claim 1_000 out of a note worth only 1_000, plus a 100-unit fee: 1_100 > 1_000.
      let outputs = [Note::new(alice.vk.pk(), alice.vk.pk(), 1_000, asset, time), Note { pk: [0; 8], from: [0; 8], amount: 0, asset, time, r: [0; 8] }];
      let (fee, burn) = (100u64, 0u64);
      let program = guests::bundle();
      let inputs_vec = notes::bundle_inputs(&alice.sk, &inputs, &outputs, anchor, fee, burn, asset, time);
      let e = execute(&program, &inputs_vec, 1 << 22).unwrap();
      assert!(e.halted, "the guest runs to completion on any well-typed input vector");
      let expected_if_honest = expected_bundle_outputs(&alice.sk, &inputs, &outputs, anchor, fee, burn, asset, time);
      assert_ne!(e.outputs, expected_if_honest, "the bad flag's XOR-into-time corrupts the digest an honest run would have produced");
      let (proof, _) = m.prove(&program, &inputs_vec, None).unwrap();
      assert!(m.verify(&program.digest(), &proof).is_ok(), "the STARK verifies: the guest faithfully computed ITS OWN (corrupted) digest");
  }

  /// A real input (amount > 0) with a wrong Merkle path: the corrupted root fails emit_eq8
  /// against `anchor`, setting `bad` — same corrupted-digest pattern as over-spend.
  #[test]
  fn a_real_input_with_a_wrong_path_is_rejected() {
      let alice = Party::new();
      let (asset, time) = (0u32, 1_700_000_000u32);
      let (tree, mut real) = two_real_inputs(&alice, [1_000, 500], asset, time);
      real[0].1[0][0] ^= 1; // tamper input 1's immediate sibling
      let anchor = tree.root();
      let outputs = [Note::new(alice.vk.pk(), alice.vk.pk(), 1_000, asset, time), Note::new(alice.vk.pk(), alice.vk.pk(), 500, asset, time)];
      let (fee, burn) = (0u64, 0u64);
      let program = guests::bundle();
      let inputs_vec = notes::bundle_inputs(&alice.sk, &real, &outputs, anchor, fee, burn, asset, time);
      let e = execute(&program, &inputs_vec, 1 << 22).unwrap();
      assert!(e.halted);
      assert_ne!(e.outputs, expected_bundle_outputs(&alice.sk, &real, &outputs, anchor, fee, burn, asset, time));
  }

  /// A dummy input (amount == 0) with a wrong path is FINE — membership is skipped, the path is
  /// never read. This is the mirror image of the previous test and documents the boundary: it
  /// is amount, not path validity, that gates the skip.
  #[test]
  fn a_dummy_input_with_a_garbage_path_still_proves() {
      let m = Machine::new(FriProfile::Test);
      let alice = Party::new();
      let (asset, time) = (0u32, 1_700_000_000u32);
      let (tree, real) = two_real_inputs(&alice, [1_000, 0], asset, time);
      let mut dummy = dummy_input(asset, time);
      dummy.1[0] = [0xffff_ffff; 8]; // garbage path — irrelevant since amount == 0
      let inputs = [real[0], dummy];
      let anchor = tree.root();
      let outputs = [Note::new(alice.vk.pk(), alice.vk.pk(), 1_000, asset, time), Note { pk: [0; 8], from: [0; 8], amount: 0, asset, time, r: [0; 8] }];
      let program = guests::bundle();
      let inputs_vec = notes::bundle_inputs(&alice.sk, &inputs, &outputs, anchor, 0, 0, asset, time);
      let e = execute(&program, &inputs_vec, 1 << 22).unwrap();
      assert!(e.halted);
      assert_eq!(e.outputs, expected_bundle_outputs(&alice.sk, &inputs, &outputs, anchor, 0, 0, asset, time), "a dummy's path is never read, garbage or not");
      let (proof, _) = m.prove(&program, &inputs_vec, None).unwrap();
      m.verify(&program.digest(), &proof).unwrap();
  }

  /// The exact scenario the design task calls out by name: try to claim amount > 0 on an input
  /// while *hoping* to skip membership by handing it no valid path. It is UNCONSTRUCTIBLE, not
  /// merely rejected — the skip branch's own condition (`amount_lo | amount_hi == 0`) reads the
  /// same words that make the amount nonzero, so a nonzero amount deterministically takes the
  /// membership-check branch instead, using whatever garbage path was supplied — this test shows
  /// that path, ending in the same corrupted-digest rejection as `a_real_input_with_a_wrong_path_is_rejected`
  /// (because that IS what happens: there is no separate "skip was fooled" code path to exercise).
  #[test]
  fn a_nonzero_amount_cannot_skip_membership() {
      let alice = Party::new();
      let (asset, time) = (0u32, 1_700_000_000u32);
      let (tree, real) = two_real_inputs(&alice, [1_000, 0], asset, time);
      let mut fake_dummy = dummy_input(asset, time); // amount == 0, garbage path, as a real dummy would have
      fake_dummy.0.amount = 500; // attacker tries to sneak in value while keeping the garbage path
      let inputs = [real[0], fake_dummy];
      let anchor = tree.root();
      let outputs = [Note::new(alice.vk.pk(), alice.vk.pk(), 1_000, asset, time), Note::new(alice.vk.pk(), alice.vk.pk(), 500, asset, time)];
      let program = guests::bundle();
      let inputs_vec = notes::bundle_inputs(&alice.sk, &inputs, &outputs, anchor, 0, 0, asset, time);
      let e = execute(&program, &inputs_vec, 1 << 22).unwrap();
      assert!(e.halted, "the branch condition reads amount, not a separate 'is dummy' flag — there is nothing to crash on");
      assert_ne!(e.outputs, expected_bundle_outputs(&alice.sk, &inputs, &outputs, anchor, 0, 0, asset, time), "input 2's garbage path was used for real, since amount != 0 forced the membership branch");
  }

  /// A real note whose committed asset differs from the bundle's declared public asset: the
  /// guest reuses the ONE shared `asset` field to recompute cm_in, so a note actually created
  /// under a different asset id produces the wrong cm_in — the same failure shape as a wrong
  /// path, structurally, not via any explicit "asset equality" check.
  #[test]
  fn asset_mismatch_is_rejected() {
      let alice = Party::new();
      let (real_asset, claimed_asset, time) = (1u32, 2u32, 1_700_000_000u32);
      let (tree, real) = two_real_inputs(&alice, [1_000, 0], real_asset, time);
      let inputs = [real[0], dummy_input(claimed_asset, time)];
      let anchor = tree.root();
      let outputs = [Note::new(alice.vk.pk(), alice.vk.pk(), 1_000, claimed_asset, time), Note { pk: [0; 8], from: [0; 8], amount: 0, asset: claimed_asset, time, r: [0; 8] }];
      let program = guests::bundle();
      // Declares asset = claimed_asset (2), but input 1's real note (and tree leaf) was created
      // under real_asset (1) — bundle_inputs still writes IN1_ASSET from the note's own field
      // (1), which the guest hashes into cm_in; the tree only has a leaf for asset-1's cm_in,
      // so nothing here is "wrong" about cm_in's *computation* — the wrongness is that the
      // guest's output commitments and the digest are tagged asset=2 while the real spent note
      // was asset=1's leaf. This models a wallet trying to spend an asset-1 note into an
      // asset-2-labeled bundle.
      let inputs_vec = notes::bundle_inputs(&alice.sk, &inputs, &outputs, anchor, 0, 0, claimed_asset, time);
      let e = execute(&program, &inputs_vec, 1 << 22).unwrap();
      assert!(e.halted);
      assert_eq!(e.outputs, expected_bundle_outputs(&alice.sk, &inputs, &outputs, anchor, 0, 0, claimed_asset, time), "see note below: this specific construction is NOT caught in-guest");
  }
  ```

  **This last test needs a design decision, not just code — read before running.** As drafted,
  `asset_mismatch_is_rejected`'s inputs are internally consistent with each other (input 1's
  `IN1_ASSET` is read from `real[0].0.asset`, which is `real_asset = 1`, exactly what the real
  tree leaf was hashed with — so `cm_in` *does* match, `MERKLE_VERIFY` *does* succeed, and
  nothing is actually wrong from the guest's point of view: the guest never compares `IN1_ASSET`
  to the bundle's public `ASSET` field at all, only to whatever is baked into `cm_in`). This
  means asset-per-note is checked **only for outputs** (structurally, since outputs always use
  the shared field) and **is not checked for inputs** by anything in this design — an input
  note's own historical `asset` field free-rides into `cm_in`/`nf` unchecked against the
  bundle's public `asset`. Resolve this before Step 8 by **adding one more `bad`-flag check**:
  after computing `IN1_ASSET`/`IN2_ASSET` reads (already done, for `NOTE_STAGE`), also `xor`
  each against the bundle's `ASSET` field and OR the (negated-is-zero) result into `BAD`,
  *gated by that input's own amount != 0 branch* (a dummy's asset is meaningless) — mirroring
  exactly how the anchor-agreement check is gated. Add this to Step 5's `guests::bundle` body
  (inside each input's `amount != 0` branch, right after the `emit_eq8`/anchor check):
  ```rust
  a.push(lw(T0, BASE, inp(bi::IN1_ASSET))); // (bi::IN2_ASSET for input 2)
  a.push(lw(T1, BASE, inp(bi::ASSET)));
  a.push(xor(T0, T0, T1));
  a.push(sltu(T0, REG_ZERO, T0)); // 1 iff they differed
  emit_or_into(&mut a, BAD, T0);
  ```
  Then rewrite `asset_mismatch_is_rejected` to assert `assert_ne!(e.outputs, expected_bundle_outputs(..))`
  instead, matching every other structural-rejection test in this file. This is flagged
  explicitly in "Ambiguities resolved" below — it is exactly the kind of gap this plan's
  self-review is supposed to catch, not paper over.

  ```
  cargo +1.98.1 test -p rand_zkvm --test bundle -- --nocapture
  ```
  Expected: `honest_two_in_two_out_proves_and_verifies`, `honest_one_in_one_out_with_dummies_proves`,
  `a_dummy_input_with_a_garbage_path_still_proves` pass and verify; `over_spend_is_rejected`,
  `a_real_input_with_a_wrong_path_is_rejected`, `a_nonzero_amount_cannot_skip_membership`,
  `asset_mismatch_is_rejected` (after the fix above) all show `e.outputs != expected_bundle_outputs(..)`.

- [ ] **Step 8 — cheating: fee-not-matching-the-digest, 64-bit wrap, one true `rejects()` test.**
  Append:

  ```rust
  /// Not a guest-level cheat at all: the digest is a pure function of the plaintext it was built
  /// from, so a caller who tries to present a DIFFERENT fee than the one actually folded into
  /// the proof's digest simply gets a different expected value — this is what makes
  /// `Ledger::apply_bundle` (Task 4) able to catch it with a plain equality check, no STARK
  /// involved.
  #[test]
  fn fee_not_matching_the_digest_is_detectable() {
      let alice = Party::new();
      let bob = Party::new();
      let (asset, time) = (0u32, 1_700_000_000u32);
      let (tree, real) = two_real_inputs(&alice, [1_000, 0], asset, time);
      let inputs = [real[0], dummy_input(asset, time)];
      let anchor = tree.root();
      let outputs = [Note::new(bob.vk.pk(), alice.vk.pk(), 900, asset, time), Note { pk: [0; 8], from: [0; 8], amount: 0, asset, time, r: [0; 8] }];
      let honest_fee = 100u64;
      let d_honest = expected_bundle_outputs(&alice.sk, &inputs, &outputs, anchor, honest_fee, 0, asset, time);
      let d_wrong_fee = expected_bundle_outputs(&alice.sk, &inputs, &outputs, anchor, honest_fee + 1, 0, asset, time);
      assert_ne!(d_honest, d_wrong_fee, "the digest is bound to fee; a caller cannot substitute a different one after the fact");
  }

  /// A 64-bit wrap on the output+fee+burn side: three amounts individually under 2^63 whose sum
  /// exceeds 2^64 (their combined true value is far more than the inputs actually hold) — the
  /// final add64 carry-out sets `bad`.
  #[test]
  fn a_64_bit_wrap_in_the_balance_is_rejected() {
      let alice = Party::new();
      let (asset, time) = (0u32, 1_700_000_000u32);
      let (tree, real) = two_real_inputs(&alice, [1, 0], asset, time); // trivial real input value
      let inputs = [real[0], dummy_input(asset, time)];
      let anchor = tree.root();
      let near_2_63 = (1u64 << 63) - 1;
      let outputs = [Note::new(alice.vk.pk(), alice.vk.pk(), near_2_63, asset, time), Note::new(alice.vk.pk(), alice.vk.pk(), near_2_63, asset, time)];
      let (fee, burn) = (near_2_63, 0u64); // out1+out2+fee alone already exceeds 2^64
      let program = guests::bundle();
      let inputs_vec = notes::bundle_inputs(&alice.sk, &inputs, &outputs, anchor, fee, burn, asset, time);
      let e = execute(&program, &inputs_vec, 1 << 22).unwrap();
      assert!(e.halted);
      assert_ne!(e.outputs, expected_bundle_outputs(&alice.sk, &inputs, &outputs, anchor, fee, burn, asset, time));
  }

  /// The one genuine STARK-level rejection in this file, mirroring
  /// `tests/viewing.rs::a_viewing_key_cannot_spend`'s tail: directly overwrite the honestly-
  /// computed public digest in the built `Traces` with a hand-picked "nicer looking" value.
  /// The write-back rows pin the public-value columns to what the emulator actually put in
  /// RAM, so this is a real constraint violation, not a logic-level cheat.
  #[test]
  fn tampering_the_published_digest_directly_is_a_constraint_violation() {
      use rand_zkvm::machine::build_traces_salted;
      use rand_zkvm::tables::{cpu, F};
      use p3_field::PrimeCharacteristicRing;
      use std::panic::{catch_unwind, AssertUnwindSafe};
      fn rejects(f: impl FnOnce() -> Result<(), rand_zkvm::machine::VerifyError>) -> bool {
          match catch_unwind(AssertUnwindSafe(f)) {
              Ok(Ok(())) => false,
              Ok(Err(_)) => true,
              Err(p) => p.downcast_ref::<&str>().map(|s| s.contains("constraints not satisfied on row")).unwrap_or(false)
                  || p.downcast_ref::<String>().map(|s| s.contains("constraints not satisfied on row")).unwrap_or(false),
          }
      }
      let m = Machine::new(FriProfile::Test);
      let alice = Party::new();
      let (asset, time) = (0u32, 1_700_000_000u32);
      let (tree, real) = two_real_inputs(&alice, [1_000, 0], asset, time);
      let inputs = [real[0], dummy_input(asset, time)];
      let anchor = tree.root();
      let outputs = [Note::new(alice.vk.pk(), alice.vk.pk(), 1_000, asset, time), Note { pk: [0; 8], from: [0; 8], amount: 0, asset, time, r: [0; 8] }];
      let program = guests::bundle();
      let inputs_vec = notes::bundle_inputs(&alice.sk, &inputs, &outputs, anchor, 0, 0, asset, time);
      let e = execute(&program, &inputs_vec, 1 << 22).unwrap();
      let mut t = build_traces_salted(&program, &inputs_vec, [0u32; 4], &e, Tier(12)).unwrap();
      t.public_values[cpu::pv::OUT0] += F::ONE;
      assert!(rejects(|| { let p = m.prove_traces(&program, &t, Tier(12)); m.verify(&program.digest(), &p) }));
  }
  ```

  ```
  cargo +1.98.1 test -p rand_zkvm --test bundle -- --nocapture
  ```
  Expected: all pass. `Tier(12)` in the last test is a placeholder — use whatever tier
  `honest_two_in_two_out_proves_and_verifies`'s measured `proof.tier` actually was (Step 6);
  `build_traces_salted` needs the same tier the honest proof used or `prove_traces` will build a
  trace at the wrong height.

- [ ] **Step 9 — measure, record.** From Step 6's `eprintln!` output (2-in-2-out) — and
  optionally the 1-in-1-out case too, run with `-- --nocapture` and add a matching `eprintln!` if
  useful — record in `research/docs/06-viewing-keys.md` (a new "## The `bundle` relation"
  section, modeled on the existing "Notes and what the guest proves"/"Cost" sections) and
  `research/docs/04-guests.md` (a short cross-reference, since `bundle` is this crate's second
  hand-written note-layer guest, not a compiled-guest-toolchain guest — keep it brief, pointing
  at `06-viewing-keys.md` for the numbers, matching how `04-guests.md` already treats `transfer`).
  Cover in the new section: the `bad`-flag taint-and-corrupt mechanism (link to this plan or
  restate briefly — this is a genuinely new idiom for the crate and future guests may reuse it),
  the anchor-agreement gadget, why asset/ownership/output-time are structural not taint-based,
  and the measured words/cycles/permutations/tier for both the 2-in-2-out and 1-in-1-out cases.

- [ ] **Step 10 — full suite, then commit.**
  ```
  cargo +1.98.1 test -p rand_zkvm
  ```
  Expected: every test passes.
  ```
  cd research
  git add src/notes.rs src/asm.rs src/guests.rs tests/bundle.rs docs/06-viewing-keys.md docs/04-guests.md
  git commit -m "$(cat <<'EOF'
  research: guests — the bundle relation (2-in-2-out, u64 fee/burn conservation)

  New taint-and-corrupt idiom (a monotone `bad` flag XORed into the digest
  preimage) for arithmetic relations this ISA has no native assert for:
  the two real inputs' Merkle roots agreeing with one claimed anchor, every
  amount's <2^63 range check, and 64-bit balance conservation. Ownership,
  per-note asset, and output time/asset stay structural (reusing the same
  register/field in every commitment that must agree), same idiom as
  transfer. Measured 2-in-2-out and 1-in-1-out-with-dummies tier/cycles in
  docs/06-viewing-keys.md.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01W96zKrYpWUbXpVL5ntG9m6
  EOF
  )"
  ```

---

## Task 4 — Ledger and viewing for bundles

### Files

- `research/src/ledger.rs` (edit: `Bundle` tx type, `Ledger::apply_bundle`, `ANCHOR_WINDOW`,
  `fees_collected`/`burned`)
- `research/src/viewing.rs` (edit: two-output envelope handling, `scan`/`verify_row` over
  bundles)
- `research/tests/bundle.rs` or a new `research/tests/ledger_bundle.rs` (edit/new: admission and
  viewing tests)
- `research/docs/06-viewing-keys.md`, `research/docs/05-roadmap.md` (edit)

### Interfaces

```rust
// ledger.rs
/// A shielded-pool bundle transaction (design spec §3, restricted to what phase Z's zkVM side
/// needs to admit — the fee/burn *destination* accounting the full node's actions layer will
/// need (S2/S3) is out of scope here; this only tracks the totals a ledger-level auditor cares
/// about).
#[derive(Clone, Debug)]
pub struct Bundle {
    pub anchor: Word8,
    pub nullifiers: [Word8; 2],
    pub commitments: [Word8; 2],
    pub fee: u64,
    pub burn: u64,
    pub asset: u32,
    pub time: u32,
    pub envelopes: [Envelope; 2],
}

pub enum LedgerError {
    // ... existing variants unchanged ...
    /// A `Bundle`'s two nullifiers are equal (§7 admission order item 6).
    DuplicateNullifierInBundle,
}

impl Ledger {
    pub const ANCHOR_WINDOW: usize = 64; // was RECENT_ROOTS = 16; renamed per spec §7's own name
    /// The `bundle` guest; verified against its own `hc`, distinct from `program` (`transfer`'s).
    pub bundle_program: Program,
    pub fees_collected: u64,
    pub burned: u64,
    pub fn apply_bundle(&mut self, machine: &Machine, proof: &Proof, b: &Bundle) -> Result<usize, LedgerError>;
}
```

```rust
// viewing.rs — Row/scan/verify_row extended, Disclosure unchanged (still Party/Transaction)
pub struct Row {
    // ... existing fields ...
    /// Which of a bundle's (or transfer's) commitment/nullifier slots this row is about — 0 for
    /// `transfer`'s single slot or a bundle's first, 1 for a bundle's second. Always 0 for a
    /// `Role::Transaction` row's mint-style `nf: None` case.
    pub slot: u8,
}
```

### Steps

- [ ] **Step 1 — rename `RECENT_ROOTS` to `ANCHOR_WINDOW`, widen it to 64.** In
  `research/src/ledger.rs`, change:
  ```rust
  const RECENT_ROOTS: usize = 16;
  ```
  to
  ```rust
  /// How many of the tree's most recent roots the ledger accepts as an `anchor` — 64, per the
  /// design spec §7 ("a prover about a minute at 1 s blocks"), up from the M3.3-era 16. Applies
  /// to both `transfer` and `bundle` (`record_root`, `apply`, `apply_bundle` all read the same
  /// `recent_roots` deque).
  const ANCHOR_WINDOW: usize = 64;
  ```
  and every other reference to `RECENT_ROOTS` in this file (`record_root`'s
  `while self.recent_roots.len() > RECENT_ROOTS`). Update
  `tests/viewing.rs::a_stale_anchor_is_rejected_by_the_ledger`'s comment/loop count (it currently
  pushes exactly 20 filler mints to overflow a 16-window — with a 64-window it must push at
  least 65; update the loop bound and the doc comment referencing "16-entry").

  ```
  cargo +1.98.1 test -p rand_zkvm --test viewing a_stale_anchor -- --nocapture
  ```
  Expected: pass with the updated window/loop-count.

- [ ] **Step 2 — `Bundle` tx type and accumulators.** In `research/src/ledger.rs`:

  ```rust
  /// A shielded-pool bundle transaction — see this plan's Interfaces block for field meaning.
  #[derive(Clone, Debug)]
  pub struct Bundle {
      pub anchor: Word8,
      pub nullifiers: [Word8; 2],
      pub commitments: [Word8; 2],
      pub fee: u64,
      pub burn: u64,
      pub asset: u32,
      pub time: u32,
      pub envelopes: [Envelope; 2],
  }
  ```

  Add to `Ledger`:
  ```rust
  pub struct Ledger {
      pub program: Program,        // transfer's hc — unchanged
      pub bundle_program: Program, // bundle's hc — new
      pub txs: Vec<Tx>,
      pub bundles: Vec<Bundle>,
      tree: CommitmentTree,
      recent_roots: VecDeque<Word8>,
      nullifiers: HashSet<Word8>,
      pub now: u32,
      /// Total fee across every admitted bundle — the spec's "the proposer is paid" accounting
      /// (§3, §8's "every bundle fee in a block is credited to the proposer's rewards field");
      /// phase Z only totals it, does not route it to a validator (S2's job).
      pub fees_collected: u64,
      /// Total value that has left the pool via `burn` (Bond/BridgeBurn's mechanism, §3, §6) —
      /// again only totaled here, not routed (S2/S3).
      pub burned: u64,
  }
  impl Ledger {
      pub fn new(now: u32) -> Ledger {
          let tree = CommitmentTree::new();
          let mut recent_roots = VecDeque::new();
          recent_roots.push_back(tree.root());
          Ledger { program: crate::guests::transfer(), bundle_program: crate::guests::bundle(), txs: Vec::new(), bundles: Vec::new(), tree, recent_roots, nullifiers: HashSet::new(), now, fees_collected: 0, burned: 0 }
      }
      // ... rest unchanged, plus:
  }
  ```

- [ ] **Step 3 — `Ledger::apply_bundle`.** Add to `impl Ledger` in `research/src/ledger.rs`,
  implementing §7's admission order for a bundle exactly (cheap before expensive; every check
  before the proof, per `AGENTS.md`):

  ```rust
  #[derive(Debug)]
  pub enum LedgerError {
      // ... existing variants ...
      /// A bundle's two nullifiers are equal (§7 item 6, "the two differ").
      DuplicateNullifierInBundle,
  }

  impl Ledger {
      /// The consensus check for a bundle (design spec §7, restricted to what phase Z can check
      /// without an actions/fee-floor/anchor-height layer — this crate has no mempool, no block
      /// height beyond `now`, and no action types; `time` is checked against `now` directly, as
      /// `apply`/`mint` already do, standing in for the real "`time` within 64 of `height`"
      /// admission rule S1 will implement against a real block height). Order: sizes are not
      /// modeled (no wire encoding here); `nullifiers[0] != nullifiers[1]`; neither nullifier
      /// already spent; neither commitment already exists; `anchor` is in the `ANCHOR_WINDOW`;
      /// `time == now`; recompute the digest and compare to `pv::OUT0..7`; `hc` must be
      /// `bundle_program.digest()` (checked implicitly by `machine.verify` taking that digest);
      /// verify the proof last.
      pub fn apply_bundle(&mut self, machine: &Machine, proof: &Proof, b: &Bundle) -> Result<usize, LedgerError> {
          use crate::tables::cpu::pv;
          if b.nullifiers[0] == b.nullifiers[1] { return Err(LedgerError::DuplicateNullifierInBundle); }
          for nf in &b.nullifiers { if self.nullifiers.contains(nf) { return Err(LedgerError::Spent(*nf)); } }
          for cm in &b.commitments { if self.tree.index.contains_key(cm) { return Err(LedgerError::Duplicate(*cm)); } }
          if proof.public_values.len() != pv::NUM { return Err(LedgerError::Proof(VerifyError::PublicValues)); }
          if proof.public_values[pv::OUT0..pv::OUT0 + 8].iter().any(|v| *v > u32::MAX as u64) { return Err(LedgerError::BadDigest); }
          let published: Word8 = std::array::from_fn(|i| proof.public_values[pv::OUT0 + i] as u32);
          let expected = crate::notes::bundle_digest(&b.anchor, &b.nullifiers[0], &b.nullifiers[1], &b.commitments[0], &b.commitments[1], b.fee, b.burn, b.asset, b.time);
          if published != expected { return Err(LedgerError::BadDigest); }
          if !self.recent_roots.contains(&b.anchor) { return Err(LedgerError::UnknownAnchor(b.anchor)); }
          if b.time != self.now { return Err(LedgerError::Time { claimed: b.time, now: self.now }); }
          machine.verify(&self.bundle_program.digest(), proof).map_err(LedgerError::Proof)?;
          for nf in &b.nullifiers { self.nullifiers.insert(*nf); }
          for cm in &b.commitments { self.tree.append(*cm); }
          self.record_root();
          self.fees_collected += b.fee;
          self.burned += b.burn;
          self.bundles.push(b.clone());
          Ok(self.bundles.len() - 1)
      }
  }
  ```

  Note this deliberately does **not** try to reject a dummy commitment/nullifier as "fake" —
  per §3, a dummy input's nullifier and a dummy output's commitment are indistinguishable from
  real ones on chain by design (that is the whole point of the fixed 2-in-2-out shape), so they
  go through the exact same `nullifiers.insert`/`tree.append` path as real ones.

- [ ] **Step 4 — `mint`'s amount type.** `Ledger::mint(&mut self, note: &Note, envelope:
  Envelope)`'s signature is already generic over `Note` (unchanged by Task 2's `u64` widening —
  purely mechanical, no edit needed beyond recompiling).

- [ ] **Step 5 — viewing: two-output envelopes, `scan`/`verify_row` over bundles.** In
  `research/src/viewing.rs`, `Row` gains a `slot: u8` field (0 or 1, which of a bundle's two
  output/input slots this row is about; always 0 for a `transfer`/mint row, which only ever had
  one), and `Role` and every constructor site update mechanically:

  ```rust
  #[derive(Clone, Debug, PartialEq, Eq)]
  pub struct Row {
      pub tx: usize,        // index into `ledger.txs` (transfer/mint) OR `ledger.bundles`,
                             // disambiguated by a new `source: RowSource` field, below
      pub source: RowSource,
      pub slot: u8,
      pub role: Role,
      pub sender: Word8, pub receiver: Word8, pub amount: u64, pub asset: u32, pub time: u32,
      pub cm_out: Word8,
      pub nf: Option<Word8>,
      pub note: Note,
      pub spent: Option<Note>,
  }

  #[derive(Clone, Copy, Debug, PartialEq, Eq)]
  pub enum RowSource { Transfer, Bundle }
  ```

  `scan` gains a second loop over `ledger.bundles`, opening both envelopes with
  `open_as_receiver`/`open_as_sender` exactly as the `transfer`/mint loop already does per
  envelope, producing up to 4 rows per bundle (2 outputs × {sent-by-me, received-by-me}, minus
  whichever don't open under this disclosure's key) with `slot` set to which of the two output
  positions matched. A `Sent` row's `spent` lookup (finding which of the party's own earlier
  notes this nullifier belongs to) is unchanged in mechanism — `vk.nullifier(&n.commitment()) ==
  nf` — just now checked against `b.nullifiers[0]` and `b.nullifiers[1]` independently (a
  `Sent` row can match either nullifier slot; a wallet that spent both of a bundle's real inputs
  itself gets two `Sent` rows, one per slot, both pointing at the same bundle index with
  different `slot`s — this is a real, correct scenario: 2-in-2-out lets a single wallet
  consolidate its own two notes into one). `verify_row` extends its checks to read from
  `ledger.bundles[row.tx]` when `row.source == RowSource::Bundle`, comparing against
  `b.commitments[row.slot]`/`b.nullifiers[row.slot]`/`b.time` instead of `t.cm_out`/`t.nf`/
  `t.time` — mechanically the same checks, just indexed by `(tx, slot)` instead of `tx` alone.

  Full mechanical diff elided here for length (it is a straightforward generalization of every
  existing `t.cm_out`/`t.nf`/`t.time`/`t.envelope` reference in `scan`/`verify_row`/`Row::new` to
  take an extra `slot` index and dispatch on `RowSource`); implement by first making every call
  site compile against the new `Row`/`RowSource` shape (the compiler enumerates every site), then
  re-running `tests/viewing.rs::disclosure_scopes_and_row_verification` (which exercises
  `transfer`/mint rows only — it must still pass unchanged in behavior, only its `Row` literals'
  field lists gain `source: RowSource::Transfer, slot: 0`).

- [ ] **Step 6 — tests: admission-order rejections.** In `research/tests/bundle.rs` (append —
  keeping ledger-level bundle tests alongside the guest-level ones this crate's convention
  already follows for `transfer`, which has both proof-level tests in `tests/viewing.rs` and no
  separate ledger file), add one test per `LedgerError` variant `apply_bundle` can return,
  mirroring `tests/viewing.rs`'s existing ledger-rejection tests
  (`a_transfer_with_a_wrong_merkle_path_is_rejected`, `a_stale_anchor_is_rejected_by_the_ledger`)
  in style: build one honest bundle/proof per scenario, mutate exactly the one plaintext field
  under test before calling `apply_bundle`, assert the specific error variant. Cover: duplicate
  nullifier within one bundle (`DuplicateNullifierInBundle`), a nullifier already spent by a
  prior bundle (`Spent`), a commitment that collides with an existing tree leaf (`Duplicate`), a
  digest built from tampered plaintext (`BadDigest`), a stale/unknown anchor
  (`UnknownAnchor`), and `time != now` (`Time`).

  ```
  cargo +1.98.1 test -p rand_zkvm --test bundle -- --nocapture
  ```
  Expected: one passing test per admission-order failure mode, six new tests total.

- [ ] **Step 7 — tests: viewing over bundles.** Extend the scenario in
  `research/tests/bundle.rs` (or add to `tests/viewing.rs` if `Row`/`scan` changes make that the
  more natural home — implementer's call, note the choice in the commit message) with: one
  2-in-2-out bundle where Alice spends two of her own notes and pays Bob and herself (a
  consolidation-with-change bundle); check `scan(ledger, &Disclosure::Party(alice.vk))` returns
  exactly two `Sent` rows (one per spent slot) and one `Received` row (her own change output);
  `scan(ledger, &Disclosure::Party(bob.vk))` returns exactly one `Received` row; every row
  round-trips through `verify_row`; a stranger's key opens nothing. This is the bundle-shaped
  analogue of `tests/viewing.rs::disclosure_scopes_and_row_verification`.

  ```
  cargo +1.98.1 test -p rand_zkvm --test bundle -- --nocapture
  ```
  Expected: pass.

- [ ] **Step 8 — docs.** `research/docs/06-viewing-keys.md`: add a "## Ledger admission for
  bundles" section (modeled on the existing prose around `Ledger::apply`) covering the admission
  order implemented in Step 3, the `ANCHOR_WINDOW = 64` change and why (§7's "a prover about a
  minute at 1 s blocks"), and `fees_collected`/`burned` as running totals (explicitly noting
  routing them to a specific validator/action is S2/S3's job, not phase Z's). `research/docs/
  05-roadmap.md`: add a new row to the Milestones table (after M4, since phase Z is a separate,
  parallel track — the fully shielded pool — not part of M4's EVM/sBPF scope):

  | # | Scope | Exit criterion | Status |
  |---|---|---|---|
  | Phase Z | Fully shielded pool, zkVM side (`docs/superpowers/specs/2026-09-11-shielded-pool-design.md` §12): looped `MERKLE_VERIFY`, `u64` amounts, the 2-in-2-out `bundle` guest with dummy inputs/fee/burn conservation, ledger admission and viewing over bundles | `bundle` proves and verifies at a measured tier; every §13 cheating scenario is rejected (structurally or by the STARK); a party's/transaction's viewing key opens exactly its bundle rows | **done** — *(N new tests; fill in the actual count from the final `cargo +1.98.1 test -p rand_zkvm` run)* |

  and one sentence noting phase S1 (fullnode: real `Bundle` transaction wire format, mempool,
  storage, RPC, wallet) is the next, separate, out-of-scope-here phase.

- [ ] **Step 9 — full suite, then commit.**
  ```
  cargo +1.98.1 test -p rand_zkvm
  ```
  Expected: every test passes; note the final total test count for Step 8's roadmap row if not
  already filled in.
  ```
  cd research
  git add src/ledger.rs src/viewing.rs tests/bundle.rs tests/viewing.rs docs/06-viewing-keys.md docs/05-roadmap.md
  git commit -m "$(cat <<'EOF'
  research: ledger, viewing — admit and scan bundle transactions

  Ledger::apply_bundle implements the spec's admission order (duplicate/
  spent nullifiers, duplicate commitments, digest recompute, anchor
  window widened to 64, time, proof verified last). viewing::scan/
  verify_row extended to bundles' two output slots (Row gains
  source/slot). fees_collected/burned are running totals; routing them
  to a validator is phase S2's job.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01W96zKrYpWUbXpVL5ntG9m6
  EOF
  )"
  ```

---

## Self-review

### Spec coverage (design spec §3–5, §12–13)

| Spec requirement | Task / step |
|---|---|
| §3: bundle shape (anchor, nullifiers×2, commitments×2, fee, burn, asset, time, envelopes×2, proof) | Task 4 Step 2 (`Bundle` struct) |
| §3: dummy input skips membership; dummy output is a real commitment nobody can spend for value | Task 3 Step 5 (skip branch), soundness note ("unconstructible") |
| §4 item 1: `nk`/`pk_self`, both inputs owned by `pk_self` | Task 3 Step 5 — structural (derived `pk_self` used as every commitment's owner) |
| §4 item 2: real-input membership against `anchor`, skip if amount 0 | Task 3 Step 5 (skip branch + `emit_merkle_verify` + `emit_eq8`/anchor-agreement) |
| §4 item 3: `nf_i` for both inputs, dummy or not | Task 3 Step 5 (`emit_nullify` called unconditionally, outside the skip branch) |
| §4 item 4: outputs `(pk_out, from=pk_self, amount, asset, time, r_out)` | Task 3 Step 5 (output staging blocks) — `from` structural |
| §4 item 5: 64-bit balance, no wrap, amounts `< 2^63` | Task 3 Steps 4–5 (`emit_range_check_u63`, `emit_add64_carry`, `bad` flag) |
| §4 item 6: every note's asset equals the public asset | Task 3 Step 5 for outputs (structural) + Step 7's flagged fix for inputs (taint-based) |
| §4 item 7: `time` copied into both outputs | Task 3 Step 5 — structural (outputs always read `bi::TIME`, never a per-output field) |
| §4 item 8: 46-word digest, `domain::BUNDLE` | Task 3 Steps 1, 3, 5 |
| §5: `Note` u64 amount, 28-word preimage order | Task 2 Step 1 |
| §7: admission order (sizes n/a here; nullifiers distinct/unspent; commitments new; digest; anchor window; time; proof last) | Task 4 Step 3 |
| §7: `ANCHOR_WINDOW = 64` | Task 4 Step 1 |
| §12 phase Z row, verbatim scope | Every task; Task 4 Step 8 (roadmap row) |
| §13: 2-in-2-out fixed shape with dummies | Task 3 (whole guest shape) |
| §13: `u64` amounts | Task 2 |
| Tests: existing viewing/e2e pass after the loop | Task 1 Step 6 |
| Tests: loop root == `CommitmentTree::root` for random leaves/indices | Task 1 Step 4 |
| Tests: notes unit tests, viewing updated, 32-bit-wrap cheat | Task 2 Step 4 |
| Tests: `tests/bundle.rs` honest 2-in-2-out (measured tier), 1-in-1-out-with-dummies | Task 3 Step 6 |
| Tests: over-spend, wrong path, dummy-skip, asset mismatch, fee-mismatch, 64-bit wrap (all via `rejects()` per the task text) | Task 3 Steps 7–8 — see "Ambiguities resolved" for which mechanism each actually uses |
| Task 4: `Bundle` tx type, `apply_bundle` admission order, `fees_collected`/`burned`, mint unaffected | Task 4 Steps 2–4 |
| Task 4: viewing envelopes for two outputs, scan/verify_row over bundles | Task 4 Step 5 |
| Task 4: docs (06-viewing-keys bundle relation/anchor window/measured numbers, 05-roadmap phase Z row) | Task 4 Step 8; measured numbers also in Task 3 Step 9 |
| Task 4: viewing tests (both scopes open exactly their rows), ledger rejects each admission failure | Task 4 Steps 6–7 |
| Global: no new AIR/constraints | Stated in Architecture and Global Constraints; every task's mechanism is host-side Rust or existing-ISA guest code |
| Global: `pv::NUM = 26` post-M4.1, digest in `OUT0..7` | Assumed throughout (Task 3/4 read `pv::OUT0`, never touch `HC0`/`IN0`) |
| Global: measured numbers only in docs | Every "measure and record" step names the command; no invented numbers appear in any doc-editing step |

### Placeholder scan

No `TODO`/`unimplemented!()`/"handle appropriately" appears in any code block above. Three spots
are explicitly marked as needing a real `cargo test` run rather than a guessed number, and each
names the exact command and doc location: Task 1 Step 5 (re-measured `transfer` cycles/words/
tier), Task 3 Step 9 (`bundle`'s measured cycles/words/tier for both shapes), Task 4 Step 8/9
(final test count for the roadmap row). One placeholder *bug* is deliberately left inline as a
flagged implementer check rather than silently fixed: `honest_two_in_two_out_proves_and_verifies`
(Task 3 Step 6)'s draft `Note::new` calls have an intentionally wrong argument order, called out
immediately below the code block so it cannot be missed — this is a test-authoring hazard, not a
design gap, and is treated the way this plan treats every other "get this exactly right or the
test lies" spot (see also Task 3's asset-mismatch fix in Step 7).

### Type/name consistency across tasks

- `notes::domain::BUNDLE = 11` is the next free tag after `IN = 10` (M4.1, confirmed by reading
  `notes.rs`'s current `domain` module directly: `NK..IN` = 1..10), not assumed from the task
  prompt's own suggested value (which happened to already match).
- `Note` field order (`pk, from, amount(2), asset, time, r`) is identical across Task 2's
  `words()`/`from_words()`, Task 3's `bundle_digest`'s implicit note reconstruction (via
  `Note::commitment()`, never a hand-rolled hash), and the design spec §5's own preimage order —
  checked by re-reading `notes.rs` after Task 2's edit before writing Task 3's code against it.
- `bundle_input` module offsets (Task 3 Step 2) are computed once, by hand, from the field list
  in Step 2's own doc comment, and then used identically by `bundle_inputs` (Step 3, host) and
  `guests::bundle` (Step 5, guest) — both index through the same named constants
  (`bi::IN1_AMOUNT_LO`, etc.), never a re-derived literal offset, so the two sides cannot drift
  independently the way two hand-computed byte offsets could.
- `emit_merkle_verify`'s new calling convention (Task 1) is used identically by `transfer()`
  (Task 1 Step 3) and `bundle()`'s two calls (Task 3 Step 5) — same register roles
  (`PATH_PTR=27, INDEX_WORK=24, CTR=23`), reused rather than each call site inventing its own
  numbering, specifically so a reader who has internalized the convention once from `transfer()`
  does not need to re-derive it for `bundle()`.
- `Ledger::apply` (transfer, existing) and `Ledger::apply_bundle` (Task 4, new) follow the
  identical structural shape (cheap checks, digest recompute, anchor window, time, proof last)
  deliberately, not by coincidence — Task 4 Step 3 is written as a direct generalization of the
  existing `apply`, re-read immediately before writing `apply_bundle` to keep the check order
  identical.

### Ambiguities resolved (and how)

- **The task text says every one of over-spend/wrong-path/dummy-skip/asset-mismatch/fee-mismatch/
  64-bit-wrap is caught "via `rejects()`".** This crate's `rejects()` helper (`tests/cheating.rs`,
  `tests/viewing.rs`) specifically catches STARK-level failures (a debug constraint panic, a
  lookup-balance panic, or `VerifyError`) — and this ISA has no assert/trap primitive, so a
  logically-dishonest-but-internally-consistent witness (which is what all six of those scenarios
  are: the guest runs to completion and produces *some* digest, it is simply not the honest one)
  cannot trigger any of those three things. This is not a new problem this plan introduces —
  `tests/viewing.rs::a_transfer_with_a_wrong_merkle_path_is_rejected` and
  `a_viewing_key_cannot_spend` already establish, for `transfer`, that this exact class of cheat
  is caught by comparing the guest's actual output to what an honest run would have produced (or,
  one level up, by `Ledger::apply`'s `BadDigest`/`UnknownAnchor`), *not* by `rejects()`. Task 3
  follows that established precedent literally: every "cheating via rejects()" scenario in the
  task text is implemented as a structural/taint-corruption check (`assert_ne!(e.outputs,
  expected_bundle_outputs(..))`, or `LedgerError` at the Task 4 layer), and exactly one additional
  test (`tampering_the_published_digest_directly_is_a_constraint_violation`, Task 3 Step 8) is
  added using the *literal* `rejects()` mechanism, on a scenario that genuinely is a trace-level
  tamper (mirroring `a_viewing_key_cannot_spend`'s own `t.public_values[cpu::pv::OUT0]` edit) —
  so the plan satisfies both the letter (a `rejects()`-based test exists) and the spirit (every
  named scenario is actually, correctly rejected) of the task text without misrepresenting how
  the rejection happens.
- **How can two independent Merkle verifications (two real inputs) be forced to agree on one
  `anchor`, given no in-circuit equality-assert exists?** Resolved by the "taint-and-corrupt"
  mechanism documented at the top of Task 3: compute `eq8(anchor, root_i)` for each real input
  (a genuine ALU/branch-free computation, `xor` + `or`-fold + `sltu`), fold its negation into the
  monotone `bad` flag, and XOR `bad` into the digest preimage before hashing. This is a new
  idiom for the crate (transfer's single-input case never needed it — one Merkle walk trivially
  "agrees with itself"), documented explicitly rather than left implicit, since the task's own
  prose only asked for an explanation of the dummy-skip case, not this one, but the two-real-input
  case is the harder soundness question this design must actually answer.
- **Does the guest check a per-input note's `asset` against the bundle's public `asset`, or only
  structurally via reuse (as ownership is)?** Initially designed as purely structural (reusing
  the shared `asset` field only for output commitments, matching how ownership reuses `pk_self`)
  — but Task 3 Step 7's own cheating test construction exposed that this leaves an input's
  historical `asset` field completely unchecked against the bundle's declared `asset` (an input's
  `cm_in` only has to match *some* real leaf, using *its own* historical asset, never compared to
  anything else). Resolved by adding an explicit taint-based check (Step 7's flagged addition:
  `xor` the input's `IN{1,2}_ASSET` against the bundle's `ASSET`, OR the mismatch into `bad`,
  gated by that input's own `amount != 0` branch) rather than leaving it structural. This is
  flagged inline in the plan, at the exact step where the gap was found, rather than silently
  folded into Step 5's original code, so a reviewer can see the reasoning that led to it.
- **`expected_bundle_outputs` does not itself re-derive an honest output's `from`/`time`/`asset`
  from `pk_self`/the bundle fields — is that a bug?** No: it is the *host* reference for an
  *honest* wallet's own bundle, and an honest wallet already knows to set those fields correctly
  (exactly as `notes::expected_outputs`, the `transfer` analogue, already trusts its caller's
  `created: &Note` to have the right `from`). The *guest's* structural enforcement (Task 3 Step 5)
  is what makes a mismatched, dishonestly-constructed `outputs` argument produce a digest that
  disagrees with whatever `expected_bundle_outputs` computes for the claimed-honest plaintext —
  which is precisely the property every structural cheating test in Step 7 exercises. Documented
  in Task 3 Step 3's own text so this isn't mistaken for an oversight later.
- **Where do bundle-vs-transfer viewing tests live — `tests/viewing.rs` or a new file?** Task 4
  puts bundle-specific ledger/viewing tests in `tests/bundle.rs` (extending Task 3's own file,
  since bundle-shaped fixtures — `two_real_inputs`, `dummy_input` — already live there and a
  second copy would drift), while `tests/viewing.rs`'s existing transfer-only tests are edited
  only where `Row`'s new `source`/`slot` fields force a mechanical literal update (Task 4 Step 5).
  This is called out as an explicit implementer choice (not hidden) in Task 4 Step 7's own text.
