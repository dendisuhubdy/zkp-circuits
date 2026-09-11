# AGENTS.md — `research` (rand_zkvm)

The Rand reference zkVM: an RV32I subset under a zero-knowledge batch STARK
(Plonky3 0.7, Goldilocks), proved as eight AIR tables exchanging facts over
twelve LogUp buses (M4.1 added `input` and the `INPUT_DIGEST`/`INPUT_READ`
buses), plus the M1.5 viewing-key layer (notes, envelopes, scoped
disclosure, simulated ledger). Design docs are `docs/01–06`; the README has
the reading order.

## Commands

- `cargo test` — the whole suite (164 tests: 163 pass, 1 ignored).
  Everything uses `FriProfile::Test`; measured, `tests/bundle.rs` takes
  ~231 s (seven proofs: five guest-level, plus one shared by every
  ledger-level test and one for the 1-real-1-dummy shape),
  `tests/viewing.rs` ~206 s, `tests/e2e.rs` ~103 s, `tests/cheating.rs`
  ~26 s and `tests/zk.rs` ~19 s. All green is the bar before any commit.
- `cargo run --release` — the narrated demo, 5–6 min wall time (one
  production-profile proof). The test suite covers everything it shows; don't
  run it casually.
- The toolchain is pinned by `rust-toolchain.toml`; let `rustup` pick it up.

## Invariants that have actually been broken here

Check both on **every new table or row kind** — M2's sub-word loads/stores
first of all:

1. **Every bus message column must be constrained on every row kind that
   sends it.** M1 shipped with a store's `MEM_VAL` unpinned: a witness could
   store a value no register ever held and read it back as genuine memory
   contents (fixed in `2c8a39d`; regression test
   `storing_a_value_that_was_never_in_a_register_is_rejected` in
   `tests/cheating.rs`).
2. **A bus count must be forced to zero wherever the message columns are
   unconstrained** — the ALU padding-row forgery; see the INVARIANT comment
   in `src/tables/alu.rs`.
3. **`lw`/`sw`/`addi` immediates are real 12-bit signed RISC-V I-type
   fields** (`Instr::encode`'s `i_type` masks to `imm & 0xfff`; `decode`
   sign-extends it back via `sext(.., 12)`) — any hand-assembled guest's
   compile-time RAM offset outside `[-2048, 2047]` *from whatever value the
   base register holds* silently wraps, addressing the wrong cell, with no
   error at assembly, execution, or proving time (a wrapped write and its
   matching wrapped read can even round-trip "correctly" in isolation,
   which is what made this so easy to miss — see shielded pool phase Z Task
   3's report). `transfer`'s layout happens to stay under `0x6a0`; `bundle`'s
   606-word private-input vector plus derived-value scratch does not, and is
   fixed by loading `BASE` from `HEAP + 0x600` and shifting every RAM
   constant by `-0x600` (`docs/06-viewing-keys.md`'s "The `bundle` relation"
   section). Any new hand-written guest with a RAM footprint wider than
   ~4 KB from one base register needs the same trick.

The emulator (`src/emulator.rs`) is the reference semantics: if the AIR and
the emulator disagree, the AIR is wrong.

## Testing and docs discipline

- Cheating tests use `rejects()` (`tests/cheating.rs`): a per-instance
  constraint-checker panic (`CONSTRAINT_PANIC`), a global lookup-balance
  panic (`LOOKUP_BALANCE_PANIC` — the only mechanism that can catch an
  unpaid table multiplicity on a table with no row-level validity marker of
  its own, e.g. the nibble table), or a verify error counts as a rejection.
  A trace-builder `assert!` or any other panic means the test tripped on
  something else — it must fail, not pass for the wrong reason.
- Docs carry measured numbers (guest instruction/cycle counts, tier table,
  test counts in the README and `docs/05-roadmap.md`). When a guest or the
  suite changes, re-measure and update the docs in the same change.

## Known development placeholders — not bugs, don't "fix" them

- `PERM_SEED` Poseidon2 round constants (a fixed development seed, not the
  published `GOLDILOCKS_POSEIDON2_RC_8_*` constants — swapping them is a
  config change, not a rewrite); `machine::KEY_SEED` similarly (M3.4: the
  verifier-key config's fixed seed, replacing the old program-derived one
  now that the preprocessed trace no longer depends on the program);
  statistical (not perfect) ZK from Plonky3 0.7's hiding PCS; `hc`
  binding-but-not-hiding (M3.4: still true — `hc` is now an in-circuit
  digest, not a verifier-side commitment, but it still has no hiding salt
  of its own, see `docs/03-privacy.md`).
- **One fixed message length per hash domain** (padding-free sponge). Every
  `PaddingFreeSponge` absorb this crate does — `notes::hash`'s
  domain-tagged calls, `hash::sponge_hash`, the M3.4 program digest — must
  keep each domain's message at a length fixed by the call site (never
  attacker-influenced), because a padding-free sponge cannot distinguish a
  message from itself with trailing zero words appended within the same
  rate block. `notes.rs`'s domain table documents this per domain; the
  M3.4 program digest closes the one domain where the *length itself*
  would otherwise have been attacker-chosen (the program's word count) by
  absorbing `len` into the sponge's own capacity lanes before any word
  content, making two different lengths produce different digests by
  construction rather than by convention.

## Commits

Style: `research: <area> — <what>` (see `git log`). One logical fix per
commit; docs updates ride with the change they describe.
