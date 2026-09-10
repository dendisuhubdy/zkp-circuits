# AGENTS.md — `research` (rand_zkvm)

The Rand reference zkVM: an RV32I subset under a zero-knowledge batch STARK
(Plonky3 0.7, Goldilocks), proved as six AIR tables exchanging facts over
eight LogUp buses, plus the M1.5 viewing-key layer (notes, envelopes, scoped
disclosure, simulated ledger). Design docs are `docs/01–06`; the README has
the reading order.

## Commands

- `cargo test` — the whole suite (55 tests). Everything uses
  `FriProfile::Test`; the two proof-backed viewing tests take ~70 s and
  `tests/zk.rs` ~50 s. All green is the bar before any commit.
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

- `Arx8` (a 4-round ChaCha sponge) and the 64-bit key/commitment/nullifier
  widths: stand-ins for the M3 Poseidon2 chip and 256-bit values.
- `PERM_SEED` Poseidon2 round constants; statistical (not perfect) ZK from
  Plonky3 0.7's hiding PCS; `hc` binding-but-not-hiding; `READ_INPUT`
  existential (unbound witness).
- The transfer guest's `cm_in` is a public output until M3's `MERKLE_VERIFY`.

## Commits

Style: `research: <area> — <what>` (see `git log`). One logical fix per
commit; docs updates ride with the change they describe.
