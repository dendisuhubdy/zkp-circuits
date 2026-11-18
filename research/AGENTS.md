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
M5.4** (M5.4 merged on 2026-09-16, `271679d`) **and phase 2's row cuts**
(2026-10-04, branch `feat/rvm-phase2`, `recursion/docs/04`) **and phase 3's
fold-reduce cuts** (2026-10-05, branch `feat/rvm-phase3`, `recursion/docs/06`): the field-native
ISA — 26 instructions at M5.4, 28 since phase 2, 30 since phase 3 — + emulator + DSL; the eight-instance batch machine (`machine/`) proving the
$N$-generic aggregate program that verifies $N$ of *this* crate's proofs in one
recursive STARK — $585{,}686$ cpu rows per inner proof, tier 20 (both memory
tables $2^{21}$), after M5.2's
three measurement-gated cuts (liveness, `REDUCE`, `SPONGE`: $1{,}968{,}619$,
tier 21), phase 2's three (2026-10-03: opened rows hinted into the
height-group sponge buffers, `HINTN` = 26, `COMPRESS` = 27 — from
$2{,}047{,}268$ at constraint set 8 to $893{,}606$; `recursion/docs/04`) and
phase 3's four (2026-10-05: the reduction's layout preprocessed in the reduce
chip, the own slot by one `LOADE`, `FOLD` = 28, `POW` = 29 — 61 399 rows short
of the $2^{19}$ gate, which was not widened; `recursion/docs/06`) **and tree aggregation** (2026-10, branch
`feat/tree-aggregation`, `recursion/docs/08`): `rv32t`, the 2-to-1 step over a compile-time child
shape with the child key a published tape value, `verify_tree`'s bottom-up recompute, and a
production depth-2 tree to be measured on the 256 GB droplet (pending; not yet run — the test
tree is proved on the laptop); the
chain-facing `aggregate`/`verify_aggregate` API the fullnode's `shrugg-rvm`
vendors; the proving-backend split (`Backend::{Reference, Cuda}`, zero new
kernels — the RV32 CUDA crate covers the rVM's instances as-is); and the
self-verifier, written with its measured requirement. Its measured records are
`recursion/docs/00` (ISA/emulator/verifier), `01` (the machine), `02` (the
aggregate economics), `03` (GPU + self-recursion, the 11-row big-machine
runbook), `04` (phase 2's row cuts and the prover's measured live heap), `05` (the
quotient layout), `06` (phase 3's cuts; the tier-18 twin proves on 48 GB at
26.88 GB live), `07` (the rVM's own FRI profile at rate ¼ — `RvmFri`: 92 queries, 24
grinding bits, 86.38 proven bits against 80/8/20's 86.41 under the paper's theorem; the twin at
15.64 GB live, the production N=1 projected at ≈ 64–75 GB), `08` (tree aggregation: the child and
step measured by emulation, the test tree proved); plans/specs in `docs/superpowers/`. **Open only on hardware**: the
PTX first build and the production N re-measurement, blocked on a fleet GPU
node (80 GB device, ≥ 160 GB host; `PTX_BUILD.md`); the deferred proofs
(M5.2's exit — tier 20 since phase 2 —, N≥2 twins, the self-proof) run on the
big machine (the measured live heap, not the withdrawn ≥ 64 GB oracle class,
sizes it: `recursion/docs/04`) after
chain-side aggregation lands, per the user's 2026-09-15 ruling. `recursion/` is
its own cargo package root (never a workspace member — that would void
`research`'s `[profile.*]` tables); commands run from inside it. The quotient-layout fork (2026-10-05,
`recursion/docs/05-quotient-layout.md`, `vendor/p3-batch-stark`): rVM proofs commit one quotient
matrix per instance; `machine::QUOTIENT_LAYOUT`; the RV32 machine and the aggregate program digest
`c90b3f0a…` unchanged; measured 9.09 → 6.41 GB peak live heap (−29 %) at tier 16.

**`rand-guest`, the sibling guest toolchain, is done through Task 7 (2026-09-18),
on branch `feat/rand-guest`** — v0.4 piece 1 of 3 (the RPC track took v0.3 first; the two
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
more than one, and it refuses to guess rather than picking wrong. **The second
trap is the compiler** (ZKVM-101, 2026-11-17): `check` has one rule that is not
about the machine, `TailScratch` — a far tail call (`auipc t1 ; jalr zero, t1`)
into code that reads `t1` first. clang 21.1.6's RISC-V outliner emits that for
`minsize` functions and the image then computes with a code address; the pinned
23.1.1 and 18.1.8 did not, in anything checked. `RAND_GUEST_CLANG_UNPINNED=1` is therefore a way to get
a *refused* build on such a clang, never a way to get a trusted image, and CI
(`.github/workflows/coverage.yml`) installs the pinned clang from LLVM's release
by digest rather than taking the runner's.

**`sbpf2rv`, piece 2 of the two translator specs above, is done through Task 7
(2026-09-18)**: an ahead-of-time sBPF → RV32 translator, emitting one
C function per sBPF function into a shim crate `rand-guest build` compiles, so the proof executes
the program directly instead of interpreting it one instruction at a time. Nothing is refused at
translation — unknown syscalls, CPI, bad registers, bad opcodes and bad jumps all become
scanner warnings plus the interpreter's own runtime trap, matching `interp.rs`'s own
raise-only-on-execution rule. Three accepted divergences, each erring on the safe side (the
README lists them): any `callx` target outside the set the scanner found gives `BadJump` (where
the interpreter might run real code; fuzzed 117-for-117 sound); a run that passes the compute budget
halts at the next check (an entry, a loop head, an exit) rather than at the instruction, so its
halt kind can differ, never its status or public words; and an image refuses (`BadElf`, status 2) any
ELF that loads to a program other than the one it was translated from. The committed SPL Token `Transfer`, `MintTo`, `Burn`,
`InitializeAccount`, `InitializeAccount3`, `GetAccountDataSize` and `AmountToUiAmount` all
match the interpreter word for word — the eight public output words and the halt — at **64 465**
of the 65 535-word cap (ZKVM-116, 2026-11-18: eighteen syscalls on both sides, Solana's
compute-unit costs on the meter, sysvars on the public tape, return data in the output digest). Translated execution itself is about 2.4–2.5× cheaper per sBPF
instruction, but the harness `sbpf-core::abi` shares with the interpreter is about 98% of every
run's cycles, and the ELF guard adds 73 k (copying the loaded program into a buffer and hashing it
with `POSEIDON2`), so the translated SPL Token transfer is 766 k cycles against the interpreter's 694 k;
both stay in tier 20, and translation only pays for compute-heavy programs. Software Ed25519 (RFC 8032) and secp256k1 recovery exist in
`sbpf-rt/` but ship unlinked — both cost tens of millions of cycles, above any tier, and the
interpreter traps both syscalls for parity — as a coprocessor backlog for a future machine
milestone. Trust: the ELF is on the public tape, so `H_PUB` binds it (`public_output` has no ELF
in its preimage, and `program_id` comes from the instruction region); the image bakes the text and
the digest of the loaded program (text, rodata, addresses, entry) and refuses any other, so `hc`
binds the loaded program — everything a run can observe of the ELF, on either side, so two ELFs
that load to the same program run identically and both are accepted. Whether `hc` is
the faithful translation is checked by rebuilding with the pinned toolchain (Rust 1.98.1, clang
23.1.1, `cc` 1.4.6) and comparing `hc`; the chain does not record the ELF's hash. A real proof of
the translated transfer was attempted once and stopped by a 24 GB watchdog at 30.77 GB peak — the
harness sets the tier, so it is deferred to a machine with at least 64 GB, like the interpreter's
own tier-20 proof. `sbpf2rv/README.md` has the full walkthrough
(commands and their real output) and every measured number; the design spec is
`docs/superpowers/specs/2026-09-18-sbpf-to-rv32-translator-design.md`.

**`evm2rv`, piece 3 of the two translator specs above, is done through Task 9
(2026-09-18)**: an ahead-of-time EVM → RV32 translator. It turns Solidity runtime bytecode into C
over `evm-rt/` in a shim crate `rand-guest build` compiles, reusing `evm-core::abi`'s harness, so
the input vector and the eight output words are the interpreter's. Stage two (register lifting,
the default) runs the ERC-20 transfer in 70 295 cycles against the interpreter's 128 872 (`evm.bin` f056f928…, hc 08740025…, 20 077 words; 66 235 against 124 606 over 19 637 words before ZKVM-103/104 put the call, the log data and the gas into the output), both
tier 18, at 12 162 program words; the three ERC-20 calls and five more vectors (a revert, out of gas three ways, the exact limit) match the
interpreter word for word, and 10 000-case fuzz corpora (plain and opaque, both stages) show no
divergence. The observable contract is the status, the eight words and `gas_used`, never the halt
kind. `gas_used` is in the `Outcome` the shim returns and, since ZKVM-104, in the `EVM_OUT` preimage,
so a translation whose gas differs from the interpreter's has different output words. Three accepted divergences: block-head gas can change the halt kind; the translation runs
`CHAINID` (a baked `--chain-id`), `ORIGIN` (= `CALLER`) and calls to precompiles 1–9, which the
interpreter traps; and the code guard. The guard: the logic is baked into the image but `CODECOPY`
reads the input code, so `contract.c` carries a `POSEIDON2` digest of the source bytecode and the
shim refuses any other code (status 2, `gas_used` 0, `OutOfBounds`), so `hc` binds the code; it
costs 1 008 cycles. The nine block-context opcodes trap until a public binding is designed (a user
decision). All nine precompiles are software; ecrecover, bn256 mul, the pairing and large modexp
and blake2f exceed 2^20 cycles and are the coprocessor backlog. The harness is about 60% of a
transfer. Trust: rebuild with Rust 1.98.1, clang 23.1.1 (the generated `build.rs` refuses any other
unless `RAND_GUEST_CLANG_UNPINNED=1`) and `cc` 1.4.6 and compare `hc`; the chain does not record
the bytecode's hash. Not yet proven on a 48 GB laptop (the stage-one attempt died at 24.7 GB);
deferred to a machine with at least 64 GB. The image is over chain 12's 4 096-word cap, so
deploying it needs a genesis with a larger `max_program_words`. `evm2rv/README.md` has the
walkthrough with real output; the spec is
`docs/superpowers/specs/2026-09-18-evm-to-rv32-translator-design.md`.

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
  not comparable with these. (Since 2026-10-15 — audit CS9-2 — `research` builds
  `p3-batch-stark` from `../vendor/p3-batch-stark`, the quotient-layout fork `recursion/` and the
  fullnode already use, for its `SelfCheck` switch: `Machine::prove_traces_without_self_check`
  (`cheating` feature) proves a *forged* trace set with that checker off, so the verifier's typed
  error is what `tests/modq_cheating.rs` asserts on, in debug as in release. Every honest path
  still enforces the checker; `PerChunk` is upstream byte for byte, so no proof or key moved.) In this run `tests/e2e.rs` takes ~459 s — M4.3's tier-16 EVM-call
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
  (above every tier) to **694 498** (685 749 since ZKVM-116), which fits `Tier(20)` — but a tier-20
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
  `backend_proof_has_the_same_shape_as_a_cpu_proof` was unpassable from M4.1 (when
  `H_IN` was salted per proving call) until ZKVM-118: it compared all of
  `public_values` across two independently salted proofs. It now compares every
  public value but the eight salted `H_IN` words, and asserts those differ.
- `cargo test --features parallel` (add `--release` for the timings below) — the same suite with
  Plonky3's rayon on. Opt-in; see "The `parallel` feature" below for what it guarantees, what it
  does not, and the measured times. The serial figures above stay the reference for plain
  `cargo test`.
- `cargo run --release` — the narrated demo, ~6-7 minutes wall time (thirteen
  proofs — one production-profile proof). The test suite covers everything it
  shows; don't run it casually.
- The toolchain is pinned by `rust-toolchain.toml`; let `rustup` pick it up.

## The `parallel` feature

`parallel = ["dep:p3-maybe-rayon", "p3-maybe-rayon/parallel"]` (ZKVM-109, 2026-11-17) turns on
Plonky3's rayon for the DFTs, Merkle commits, quotient evaluation and FRI of every prove and verify
in this crate. It is **off by default** and should stay so: a default feature of this crate is
switched on in every crate that depends on it (`recursion`, `rand-guest`, `evm2rv`, `sbpf2rv`, and
the fullnode's vendored copy), and a single-threaded build is what a debugging session and a
memory-tight host want. `recursion`'s `parallel` forwards to it. `rand-guest`, `evm2rv` and `sbpf2rv` forward
nothing: none of their commands proves (only a test or two each does — `rand-guest/tests/prove.rs`,
`evm2rv/tests/proof.rs`, `sbpf2rv/tests/parity.rs`), and each is its own package root, so
`research`'s `[patch.crates-io]` does not reach it — turning rayon on there would also need the
vendor patch entries in that crate's manifest, or it runs upstream's deadlock-prone lock. It needs the two
lock-patched crates in `../vendor` (`p3-fri`, `p3-merkle-tree`; `../vendor/PROVENANCE.md`), which
this crate's `[patch.crates-io]` takes for every build — that patch stops a spin lock deadlocking
under rayon and does nothing else.

**The contract is "keys and digests unchanged, every proof verifies" — not "the same bytes".**

- Keys: `tests/verifier_key.rs`'s pinned `commitment`/`common` digests were taken from the serial
  build and pass unchanged with the feature on. Program, input and public digests are computed
  outside Plonky3 and cannot move.
- Proofs: `tests/parallel.rs` proves and verifies under the feature and checks that a seeded proof's
  main and permutation commitments are the same from run to run on any thread count.
- **A seeded proof does not reproduce on more than one thread.** Do not write a test, a fixture or a
  protocol step that assumes it does. Two steps depend on scheduling, both upstream Plonky3 0.7.0:
  1. *Quotient blinding seed order.* The batch prover computes each instance's quotient inside a
     parallel iterator (`../vendor/p3-batch-stark/src/prover.rs`, `per_instance`) and calls
     `pcs.get_quotient_ldes` there; each call forks its blinding RNG from the one shared PCS RNG
     (`../vendor/p3-fri/src/hiding_pcs.rs`, `fork_rng`), so which instance gets which child seed is
     whichever worker takes the lock first. The quotient commitment moves, and everything after it.
  2. *The query proof-of-work witness.* `DuplexChallenger::grind` searches with rayon's
     `find_map_any` (`p3-challenger-0.7.0/src/grinding_challenger.rs`), which returns a valid
     witness, not the smallest; the witness is absorbed, so the query indices move.
  Measured: the serial build and the feature at `RAYON_NUM_THREADS=1` give byte-identical seeded
  proofs; at 16 threads every proof differs; with both steps made sequential in a throwaway patch,
  ten of ten 16-thread proofs equalled the serial bytes, and with either one left in they did not.
  Neither is patched (a ruling of 2026-11-17): no key, digest or test depends on proof bytes, every
  real prove draws OS entropy anyway (`make_config`), and the fullnode's prover has run the RV32
  machine under rayon since it gained its own `parallel` feature. The `#[ignore]`d diagnostic in
  `tests/parallel.rs` re-measures all of this; its doc comment has the three commands.

Measured 2026-11-17, constraint set 10, `--release`, 48 GB MacBook (Apple M4 Max), rayon's default
16 threads; prove time alone as the tests print it, two runs where two are given:

| proof | serial | `--features parallel` | command (append `--features parallel` after `--release`) |
| --- | --- | --- | --- |
| tier 10, `fib(10)`, Production | 7.10 s, 7.05 s | 1.39 s, 1.59 s | `cargo test --release --test e2e measure_production_profile_at_tier_10_and_12 -- --ignored --nocapture` |
| tier 12, `fib(650)`, Production | 29.17 s, 29.05 s | 4.57 s, 4.87 s | the same |
| tier 16, the EVM storage call, Test | 481.3 s | 76.7 s | `cargo test --release --test e2e compiled_evm_storage_read_write_and_return_proves_and_verifies -- --nocapture` |

The whole suite under `cargo test --release --features parallel --no-fail-fast -- --test-threads=1
--skip compiled_evm_storage_read_write_and_return_proves_and_verifies` (that one test is the 22 GB
row above, run on its own): **817 passed, 0 failed, 11 ignored** over 51 test binaries in 1 861 s
wall, 11.7 GB peak resident — one test at a time, because rayon already fills the cores and it keeps
the peak to one proof's. `tests/modq_cheating.rs` is half of it (940 s). This is a release run, so
`debug_assertions` is off and it is the weaker run the note under `cargo test` above describes; it is
not comparable with the 1 032 s debug figure there.

Verify is faster too (tier 12: 1.14 s → 0.42 s; the tier-16 call: 18.0 s → 6.2 s). **Memory is not
smaller, and at tier 16 it is larger**: the EVM call peaked at 18.1 GB resident serially and 22.0 GB
under the feature (`/usr/bin/time -l`), so the feature does not by itself fit a proving suite onto a
smaller host.

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
  config change, not a rewrite; the replacement table is committed and
  tested but unused, `src/poseidon2_constants_next.rs`, and
  `docs/05-roadmap.md` "ZKVM-107" lists the cut — do not point live code
  at it outside that cut); `machine::KEY_SEED` similarly (M3.4: the
  verifier-key config's fixed seed, replacing the old program-derived one
  now that the preprocessed trace no longer depends on the program —
  constraint set 7 replaced the seed itself with `key_derivation_v2`'s
  labels, HCS-1: the keys no longer depend on `rand`'s `StdRng` stream);
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
