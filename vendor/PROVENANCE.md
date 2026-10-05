# vendor/ — two patched Plonky3 crates

- `p3-fri` 0.7.0 and `p3-merkle-tree` 0.7.0: the crates.io sources, each with exactly one file changed —
  `p3-fri/src/hiding_pcs.rs` and `p3-merkle-tree/src/hiding_mmcs.rs` ("RandProtocol patch (2026-10-01)").
- Why: the hiding PCS and hiding MMCS hold a spin lock on their RNG across rayon work; a worker waiting on a
  stolen job can steal another `commit` and spin on its own lock for ever. The patch forks a child RNG under
  the lock and never holds it across rayon work. Upstream: Plonky3 issue #2363, PR #2368.
- Copied verbatim (`diff -r` clean) from `randprotocol/fullnode` `vendor/`: `p3-fri` at fullnode commit 4d5b0391,
  `p3-merkle-tree` at 0e70ddc4 (fullnode HEAD c69a0b0f).
- Used by `recursion/` (its `[patch.crates-io]`, every build; the `parallel` feature turns rayon on).
  `research/` does not use them yet. Drop both once a Plonky3 release carries #2368.

## p3-batch-stark 0.7.0 — the quotient-layout fork (2026-10-04)

- The crates.io source (`src/`, `README.md`, `CHANGELOG.md`), less `tests/`, `benches/`, `Cargo.lock`
  and the workspace-inheriting manifest, which `Cargo.toml` here spells out. Changed files, each
  marked `RandProtocol patch (2026-10-04): quotient layout`: `src/layout.rs` (new: `QuotientLayout`),
  `src/lib.rs` (exports), `src/prover.rs` (`prove_batch_with_layout`; the per-instance quotient
  matrix), `src/verifier/mod.rs` (`verify_batch_with_layout`,
  `commitments_with_opening_points_with_layout`; the per-instance quotient round).
- Why: `docs/superpowers/specs/2026-10-04-rvm-quotient-layout-design.md` and
  `recursion/docs/05-quotient-layout.md` — one committed matrix per instance's quotient chunks
  instead of one per chunk, the prover's largest memory term. No upstream issue; `PerChunk` is
  upstream's behaviour byte for byte and is what every caller but the rVM gets.
- Used by `recursion/` (its `[patch.crates-io]`). `research/` is not patched: the RV32 machine
  keeps crates.io's crate and the `PerChunk` layout.
- Review: `diff -r --exclude Cargo.toml --exclude Cargo.lock --exclude tests --exclude benches
  $(ls -d ~/.cargo/registry/src/*/p3-batch-stark-0.7.0) vendor/p3-batch-stark` shows exactly the
  marked hunks.
