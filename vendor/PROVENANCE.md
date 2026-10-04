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
