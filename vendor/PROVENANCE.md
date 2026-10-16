# vendor/ — three patched Plonky3 crates

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
- Used by `recursion/` (its `[patch.crates-io]`) and, since 2026-10-15, by `research/` (its
  `[patch.crates-io]`, for the self-check switch below): the RV32 machine keeps the `PerChunk` layout —
  upstream byte for byte — through every entry point it calls. The fullnode already built both
  machines against this fork (its own `[patch.crates-io]`), so this makes `research`'s standalone build
  the same build.
- Review: `diff -r --exclude Cargo.toml --exclude Cargo.lock --exclude tests --exclude benches
  --exclude .cargo-ok --exclude .cargo_vcs_info.json --exclude Cargo.toml.orig --exclude .gitignore
  --exclude target $(ls -d ~/.cargo/registry/src/*/p3-batch-stark-0.7.0) vendor/p3-batch-stark`
  shows exactly the marked hunks (and `Only in vendor/p3-batch-stark/src: layout.rs`, the new file).
- Tests: the in-crate `layout_tests` (`src/prover.rs`) and `recursion/tests/quotient_layout.rs`.
  The manifest carries a marked `[dev-dependencies]` block (Plonky3 `=0.7.0` crates and `rand
  =0.10.2`, the recursion crate's pin) because upstream's own `#[cfg(test)]` modules need it;
  `vendor/` has no toolchain file, so run `cargo +1.98.1 test --release` inside the fork. The
  `Cargo.lock` that creates is git-ignored (`.gitignore`) and never committed.
- Measured record: `recursion/docs/05-quotient-layout.md`.

### The self-check switch (2026-10-15, audit finding CS9-2)

- Changed files, each marked `RandProtocol patch (2026-10-15): self-check switch`: `src/prover.rs`
  (`SelfCheck`, `prove_batch_with_layout_and_self_check`; `prove_batch` and `prove_batch_with_layout`
  delegate to it with `SelfCheck::Enforce`), `src/lib.rs` (exports), `Cargo.toml` (description).
- What: upstream's prover runs two `#[cfg(debug_assertions)]` self-checks before it commits — the
  per-instance `check_constraints` and `p3_lookup::debug_util::check_lookups` — and panics on a trace
  that does not satisfy the AIR. `SelfCheck::Skip` turns both off for one call, at run time, so a
  *forged* trace can be proved in a debug build and the verifier's typed error is what a forgery test
  sees (`research/tests/modq_cheating.rs`, three tests that passed only under `--release`). Every
  existing entry point enforces, so an honest prover's behaviour is unchanged in both profiles; a
  release build has no self-check either way. Not a soundness lever: the verifier is the check.
- Caller: `research`'s `Machine::prove_traces_without_self_check`, behind the `cheating` feature; no
  prover path reaches it. The fullnode's copy of this fork needs the hunk only to stay one source tree
  (its build never enables `cheating`).
- Review: the same `diff -r` as above now also shows these marked hunks in `src/prover.rs` and
  `src/lib.rs`.
