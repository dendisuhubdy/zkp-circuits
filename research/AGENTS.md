# AGENTS.md — `research` (rand_zkvm)

The Rand reference zkVM: an RV32I subset under a zero-knowledge batch STARK
(Plonky3 0.7, Goldilocks), proved as nine AIR tables plus either of two
optional hash chips — ten with a keccak table, ten with a sha256 one, eleven
with both — exchanging facts over
sixteen LogUp buses (M4.1 added `input` and the `INPUT_DIGEST`/`INPUT_READ`
buses; M4.2 added `keccak` and the `KECCAK` bus, and made that one table
optional per proof: `Proof::keccak_log_height = 0` means the batch has no
keccak instance at all; M4.4 added `sha256` and the `SHA256` bus on exactly
those terms and independently, `Proof::sha256_log_height = 0`; constraint set 6
added `public` and the `PUBLIC_DIGEST`/`PUBLIC_READ` pair — the **ninth
mandatory** table, not a fourth optional one, since every proof commits to a
public input segment even when it is empty), plus the M1.5
viewing-key
layer (notes, envelopes, scoped disclosure, simulated ledger). Design docs
are `docs/01–06`; the README has the reading order.

**The sibling `recursion/` crate is the recursion VM (rVM), complete through
M5.4 and merged on 2026-09-16** (`271679d`): the field-native 26-instruction
ISA + emulator + DSL; the eight-instance batch machine (`machine/`) proving the
$N$-generic aggregate program that verifies $N$ of *this* crate's proofs in one
recursive STARK — $1{,}968{,}619$ cpu rows per inner proof after three
measurement-gated cuts (liveness, `REDUCE`, `SPONGE`), tier 21; the
chain-facing `aggregate`/`verify_aggregate` API the fullnode's `shrugg-rvm`
vendors; the proving-backend split (`Backend::{Reference, Cuda}`, zero new
kernels — the RV32 CUDA crate covers the rVM's instances as-is); and the
self-verifier, written with its measured requirement. Its measured records are
`recursion/docs/00` (ISA/emulator/verifier), `01` (the machine), `02` (the
aggregate economics), `03` (GPU + self-recursion, the 11-row big-machine
runbook); plans/specs in `docs/superpowers/`. **Open only on hardware**: the
PTX first build and the production N re-measurement, blocked on a fleet GPU
node (80 GB device, ≥ 160 GB host; `PTX_BUILD.md`); the deferred proofs
(M5.2's tier-21 exit, N≥2 twins, the self-proof) run on ≥ 64 GB after
chain-side aggregation lands, per the user's 2026-09-15 ruling. `recursion/` is
its own cargo package root (never a workspace member — that would void
`research`'s `[profile.*]` tables); commands run from inside it.

**`rand-guest`, the sibling guest toolchain, is done through Task 7 and merged
on 2026-09-18** — v0.4 piece 1 of 3 (the RPC track took v0.3 first; the two
translator specs, `sbpf2rv` and `evm2rv`, are pieces 2 and 3): one binary,
`build`/`check`/`pack`/`run`/`info`, replacing the four former per-guest
Makefiles and `mkimage.py` (`guests-compiled/README.md`). `build` drives
`rustc` for a Rust guest or `clang` for a C one (`rust-lld` linking, from the
pinned toolchain's own sysroot via `rustup +1.98.1 component add
llvm-tools`) — `c-fib`, the fifth guest, exercises the C path end to end at
**25 words / 116 cycles**. The four pins (`fib`, `keccak256`, `evm`, `sbpf`)
are unchanged: `evm`/`sbpf` gate byte for byte, `fib`/`keccak256` (legacy flat
binaries predating the tool) gate on `base_pc`/`words`/`digest()` instead,
since `build` only ever writes the image-container form. `check` runs the
machine's own decoder over every text word — a 16-bit RVC encoding, an
undecodable opcode/funct/shamt, `FENCE`, a CSR instruction, `EBREAK`, and an
`ecall` whose statically-known `a7` names no syscall the machine implements
are each a distinct, named finding, not lumped together — and the cap is
measured against the *loader's own* word count (text plus the `li`/`sw` data
prologue it synthesises), never estimated from the data word count, since an
`li` is one word or two depending on the constant. **The one trap**: a guest
with a data segment needs its own `.ld` with `ORIGIN` raised past that
prologue (`evm.ld`, `sbpf.ld`: `guest.ld` with the origin moved), and
`rand-guest` picks the one `.ld` file it finds in the guest's own directory —
more than one, and it refuses to guess rather than picking wrong.

**Constraint set 6 in one paragraph**, because it is what most recently moved
under everyone's feet: `SYS_READ_PUBLIC = 6` reads a second, independently
indexed input vector bound to `H_PUB = pv::PUB0..PUB7`, which — unlike `H_IN` —
is **unsalted**, so `Machine::verify_public(hc, public_words, proof)` recomputes
it natively from words a caller supplies and compares. `pv::NUM` is 34,
`tables::cpu::col::WIDTH` is 275, and `Machine::verifier_key` is a **6-tuple**
(`tier, program, input, keccak, sha256, public`). This is a hard fork for
proofs, and the node is **not** re-vendored here.

Two things in `deploy/sync-zkvm.sh` will need editing when it is, and they are
its only two patches (everything else rides along in the wholesale rsync —
`pv::NUM` included, which needs no anchor of its own):

1. the `log_ext_degrees_pub` wrapper is inserted against the **exact
   `Machine::verifier_key` signature line**, and that line has gained three
   parameters since the script was written (M4.2's `keccak_log_height`, M4.4's
   `sha256_log_height`, and now `public_log_height`). The script `assert`s its
   anchor and aborts the sync rather than silently no-op'ing, so this fails
   loudly — but it does fail.
2. the `crate::notes::domain::(HC|IN)` → `crate::hash::{HC_DOMAIN, IN_DOMAIN}`
   inlining, which exists because `notes.rs` is not vendored. Constraint set 6
   adds a **third** such reference, `crate::notes::domain::PUB` (= 15), in
   `src/hash.rs` (`public_digest`'s header) and `src/tables/cpu.rs` (the
   pubdigest region's in-circuit copy of the same constant). The existing
   pattern does not cover it, and nothing asserts on it, so the next sync
   compiles the node against a `notes` module that is not there. Extend the
   inlining to `PUB_DOMAIN` in the same edit.

## Commands

- `cargo test` — the whole suite (**395 tests: 389 pass, 6 ignored**).
  Everything uses `FriProfile::Test`; measured in one 2026-09-13 run of the
  constraint-set-6 tree (**1 032 s wall — 17.2 min — and 23.1 GiB peak
  resident**, on a machine that was otherwise quiet apart from a running
  fullnode, so the figures are close to a best case rather than the upper
  bounds M4.3's own run reported; the M4.3 + M4.4 tree was 365 tests in 959 s
  and 22.4 GiB, and the public segment's mandatory instance is most of the
  difference in both). **Both figures are plain `cargo test` — the debug
  profile**, which is the command this file documents and the one the numbers
  must be compared under: `--release` turns off `debug_assertions` and with it
  the per-instance constraint checker `tests/cheating.rs`'s `rejects()` helper
  depends on, so it is both much faster and a weaker run, and its timings are
  not comparable with these. In this run `tests/e2e.rs` takes ~459 s — M4.3's tier-16 EVM-call
  proof dominates it (~438 s to prove and ~14 s to verify when run alone,
  overlapped here with the file's other tests) — `tests/bundle.rs` ~244 s (six
  proofs: four guest-level, plus one shared by every ledger-level test and one
  for the 1-real-1-dummy shape), `tests/viewing.rs` ~236 s, `tests/cheating.rs`
  ~41 s, `tests/zk.rs` ~20 s, `tests/tables.rs` ~11 s, `tests/isa.rs` ~7 s
  (M4.3's image-container tests prove two small programs, one of which reads
  its own data segment back), `tests/keccak.rs` ~0.9 s (its chip-alone harness
  proves a 128-row table, so it is cheap despite 2 612 columns) and
  `tests/sha256.rs` ~0.4 s (same trick, a 64-row block). The ten host-only
  files cost well under a second between them, because they prove nothing:
  M4.3's four EVM suites — `tests/evm_u256.rs` (6), `tests/evm_storage.rs`
  (13), `tests/evm_interp.rs` (17), `tests/evm_abi.rs` (8) — run `evm-core`
  natively over `evm::HostRef`, and M4.4's four sBPF files —
  `tests/sbpf_isa.rs` (6), `sbpf_interp.rs` (20), `sbpf_elf.rs` (11),
  `sbpf_abi.rs` (21), **58 tests** — check the interpreter against
  `solana-sbpf`
  0.11.1 before anything reaches the machine, including loading the committed
  SPL Token ELF and running a real `Transfer` through it. `tests/emulator.rs`
  (25) and `tests/asm.rs` (11) are the same kind of thing. `tests/cheating.rs`
  is the largest single file at 111, of which constraint set 6 added 17 against
  the `public` table and its digest region. (The wall-clock and memory figures
  above were measured on the 394-test tree, before the final review added the
  last of those 17 — a ~2 s cheating test; nothing else about the run changed.)

  Of the six `#[ignore]`d tests, three are production-profile proof-size
  measurements, one is the sBPF cycle-breakdown measurement, and two are the
  milestones' exit proofs, **neither of which passes on this hardware, for two
  different reasons**:
  `tests/e2e.rs::compiled_evm_erc20_transfer_proves_at_tier_18` is M4.3's, and
  it needs more memory than a 48 GB machine grants (≥ 28.5 GB resident at
  SIGKILL over three attempts, resident set still growing; `docs/04-guests.md`
  has the command and the ≥ 64 GB figure) — the in-suite EVM proof is a
  smaller call through the same binary at tier 16.
  `tests/e2e.rs::compiled_sbpf_spl_token_transfer_proves_and_verifies` is
  M4.4's, and since constraint set 6 it is `#[ignore]`d for **the same reason
  as the EVM one** rather than its own: the guest went from 1 753 945 cycles
  (above every tier) to **694 498**, which fits `Tier(20)` — but a tier-20
  batch is four times the cpu rows of that tier-18 EVM proof, so it needs more
  than the 48 GB here, not less. It was not attempted on this machine; run it
  on a **≥ 64 GB** one with `-- --ignored`.
  Each ignore message carries its own measurement and `docs/04-guests.md` the
  breakdowns; do not treat either as a flake to retry. **Do not "fix" the sBPF
  one by declaring `program_hash` rather than computing it** — that was
  unsound, because `H_IN` is hiding and a digest the guest does not recompute
  is bound to nothing (`docs/03-privacy.md`) — and note that it is now *moot*
  rather than merely forbidden: the public segment is how that was made sound.
  The ELF is a public input, `H_PUB` binds it, `Machine::verify_public` checks
  it, and the guest hashes no program at all (design spec §9,
  `docs/04-guests.md`'s "The `sbpf` guest"). What is still open is the tier —
  18 needs a bulk public-read syscall for the tape, spec §9.5.

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
- `cargo +1.98.1 test --features reference-backend --test backend` — the CPU-twin
  backend suite, feature-gated and so invisible to the default `cargo test`.
  `backend_proof_has_the_same_shape_as_a_cpu_proof` has been unpassable since
  H_IN was salted per proving call in M4.1: it asserts `a.public_values ==
  b.public_values` across two independently-salted proving calls (`prove_with`
  and `prove` on the same guest), and each draws its own salt, so the equality
  fails by construction. This is a pre-existing failure, not a regression, and
  not this milestone's to fix.
- `cargo run --release` — the narrated demo, ~6-7 minutes wall time (thirteen
  proofs — one production-profile proof). The test suite covers everything it
  shows; don't run it casually.
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

## `evm-core` is tested on the host and compiled into the guest

`guests-compiled/evm-core` (M4.3) is a `no_std` library with its own
workspace root, generic over a two-method `Host` trait (the Keccak-f[1600]
permutation and the Poseidon2 sponge). It is a **normal dependency** of this
crate, not a dev-dependency, because `src/evm.rs` — the host side: `HostRef`,
`SparseTree`, `EvmCall`, the ERC-20 fixtures — is part of the library's public
API, and `tests/evm_*.rs` link `rand_zkvm` as an external crate.

The rule that follows: **every change to `evm-core` is tested natively here
and only then rebuilt into the guest.** `tests/evm_{u256,storage,interp,abi}.rs`
run the same code the committed `guests-compiled/bin/evm.bin` contains, over
`HostRef`'s reference primitives, differentially against `revm 43.0.2` and
`num-bigint`. An interpreter cannot be debugged through proofs; if a host test
and the guest disagree, the difference is the target build, not the semantics.

After editing `evm-core`, rebuild the committed image in place, from
`rand-guest/`:

    cargo +1.98.1 run -- build ../guests-compiled/evm --out ../guests-compiled/bin/evm.bin --max-words 65535

— straight into `guests-compiled/bin/`, since `src/guests.rs` includes
`guests-compiled/bin/evm.bin`; an image left anywhere else means the tests
measure the *previous* binary (which has happened). `build` writes the
`.sha256` pin beside it. The guest's own linker script (`evm.ld`, `ORIGIN`
raised for the loader's data prologue) is found by `rand-guest`, and the
rustflags — one of which needs the checkout's absolute path — are generated by
it (`rand-guest/src/build.rs`'s `flags`), not written in the guest.

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
