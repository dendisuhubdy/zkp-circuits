# AGENTS.md — `research` (rand_zkvm)

The Rand reference zkVM: an RV32I subset under a zero-knowledge batch STARK
(Plonky3 0.7, Goldilocks), proved as eight AIR tables plus either of two
optional hash chips — nine with a keccak table, nine with a sha256 one, ten with
both — exchanging facts over
fourteen LogUp buses (M4.1 added `input` and the `INPUT_DIGEST`/`INPUT_READ`
buses; M4.2 added `keccak` and the `KECCAK` bus, and made that one table
optional per proof: `Proof::keccak_log_height = 0` means the batch has no
keccak instance at all; M4.4 added `sha256` and the `SHA256` bus on exactly
those terms and independently, `Proof::sha256_log_height = 0`), plus the M1.5
viewing-key
layer (notes, envelopes, scoped disclosure, simulated ledger). Design docs
are `docs/01–06`; the README has the reading order.

## Commands

- `cargo test` — the whole suite (293 tests: 290 pass, 3 ignored).
  Everything uses `FriProfile::Test`; measured in one run at the end of M4.4's
  chip tasks, `tests/bundle.rs` takes ~230 s (six proofs:
  four guest-level, plus one shared by every ledger-level test and one for
  the 1-real-1-dummy shape), `tests/viewing.rs` ~212 s, `tests/e2e.rs`
  ~108 s, `tests/cheating.rs` ~43 s, `tests/zk.rs` ~19 s,
  `tests/tables.rs` ~11 s, `tests/keccak.rs` ~1 s (its chip-alone
  harness proves a 128-row table, so it is cheap despite 2 612 columns) and
  `tests/sha256.rs` ~1 s (same trick, a 64-row block). M4.4's four sBPF test
  files (`tests/sbpf_isa.rs`, `sbpf_interp.rs`, `sbpf_elf.rs`, `sbpf_abi.rs`,
  38 tests, one `#[ignore]`d until the SPL Token ELF is committed) prove
  nothing and so cost well under a second between them — the interpreter is
  checked against `solana-sbpf` 0.11.1 natively, before anything reaches the
  machine.
  All green is the bar before any commit. A proof that *does* call `KECCAK` is markedly larger than a
  keccak-free one — the chip is 2 612 + 99 columns and FRI openings scale with
  a batch's column count, so carrying it costs ~1.91 MB at the production
  profile — 80 queries since the 2026-09-12 audit revert; it was ~705 KB at
  the 27 queries M4.2 measured (`docs/03-privacy.md`'s profile table and M4.2
  measurement). That is a known cost of
  using the syscall, not a regression to chase; a guest that makes no `KECCAK`
  call does not pay it, because the table is left out of the batch entirely.
  M4.4's `SHA256` costs the same way and a quarter as much — the chip is
  466 + 10 columns, measured at +92 307 bytes at `FriProfile::Test` and
  +400 563 at the production profile (same guest, same tier, instance in versus
  out: `tests/e2e.rs::
  a_declared_sha256_table_costs_about_a_hundred_kilobytes_at_the_test_profile`
  and its `#[ignore]`d production twin). Both tables are optional and
  independent, so a guest pays for the hash it actually calls.
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
   sign-extends it back via `sext(.., 12)`). Since the 2026-09-12 audit
   (ZM3) `encode` *asserts* every field width — an out-of-range I-/S-type
   immediate, shift amount, branch or `jal` offset, or a `lui`/`auipc` with
   low bits set, now panics at the choke point instead of being silently
   truncated into wrong code. That catches the literal-constant case; it
   does **not** catch the one below, which is about an offset that is in
   range but applied to the wrong base: any hand-assembled guest's
   compile-time RAM offset outside `[-2048, 2047]` *from whatever value the
   base register holds* silently wraps, addressing the wrong cell, with no
   error at assembly, execution, or proving time (a wrapped write and its
   matching wrapped read can even round-trip "correctly" in isolation,
   which is what made this so easy to miss — see shielded pool phase Z Task
   3's report). `transfer`'s layout happens to stay under `0x6a0`; `bundle`'s
   612-word private-input vector plus derived-value scratch does not, and is
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
